package mailinglist

import (
	"database/sql"
	"fmt"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

// Store persists encrypted subscriber records in their own SQLite file,
// deliberately separate from IDUNA's main truestore.db — a leaked or
// mis-copied backup of the main store never carries this table with it.
// Every column that could identify a person is ciphertext; nothing here is
// ever written as plaintext.
type Store struct {
	db *sql.DB
}

const schema = `
CREATE TABLE IF NOT EXISTS vault_meta (
	id                INTEGER PRIMARY KEY CHECK (id = 1),
	salt              BLOB NOT NULL,
	canary_ciphertext BLOB NOT NULL,
	canary_nonce      BLOB NOT NULL
);

CREATE TABLE IF NOT EXISTS subscribers (
	id                INTEGER PRIMARY KEY AUTOINCREMENT,
	email_ciphertext  BLOB     NOT NULL,
	email_nonce       BLOB     NOT NULL,
	consent_version   TEXT     NOT NULL,
	consented_at      DATETIME NOT NULL,
	mailchimp_synced  INTEGER  NOT NULL DEFAULT 0,
	created_at        DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- S245-03: per-instance, admin-settable email-provider config, encrypted the
-- same way subscriber emails are (values are ciphertext, decrypted only via
-- the already-unlocked Vault) -- a real alternative to the MAILCHIMP_API_KEY
-- env var, settable without a redeploy. Single-row (id=1), same shape as
-- vault_meta above.
CREATE TABLE IF NOT EXISTS mailchimp_settings (
	id                  INTEGER PRIMARY KEY CHECK (id = 1),
	api_key_ciphertext  BLOB     NOT NULL,
	api_key_nonce       BLOB     NOT NULL,
	list_id_ciphertext  BLOB     NOT NULL,
	list_id_nonce       BLOB     NOT NULL,
	updated_at          DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);
`

// Open opens (creating if absent) the mailing-list SQLite file at path and
// ensures its schema exists. The file itself contains only ciphertext for
// any subscriber PII — see package doc.
func Open(path string) (*Store, error) {
	db, err := sql.Open("sqlite", path+"?_foreign_keys=on&_journal_mode=WAL&_busy_timeout=5000")
	if err != nil {
		return nil, fmt.Errorf("open mailinglist db: %w", err)
	}
	if _, err := db.Exec(schema); err != nil {
		db.Close()
		return nil, fmt.Errorf("migrate mailinglist db: %w", err)
	}
	// Added 2026-07-19 (SECTION 163): tags which signup source/list a
	// subscriber came from (e.g. "stinkies" vs "general"). ALTER TABLE ADD
	// COLUMN on a pre-existing db from before this date will hit here once;
	// "duplicate column" is the expected, ignorable outcome after that.
	if _, err := db.Exec(`ALTER TABLE subscribers ADD COLUMN source TEXT NOT NULL DEFAULT 'general'`); err != nil {
		if !strings.Contains(err.Error(), "duplicate column") {
			db.Close()
			return nil, fmt.Errorf("migrate mailinglist db (add source column): %w", err)
		}
	}
	return &Store{db: db}, nil
}

func (s *Store) Close() error { return s.db.Close() }

// Initialized reports whether the vault salt/canary have been set up yet.
func (s *Store) Initialized() (bool, error) {
	var n int
	err := s.db.QueryRow(`SELECT COUNT(*) FROM vault_meta WHERE id = 1`).Scan(&n)
	if err != nil {
		return false, err
	}
	return n > 0, nil
}

// InitVault stores the salt + canary for a brand-new vault. Refuses to
// overwrite an existing one — call ResetVault explicitly (and deliberately)
// if you really mean to invalidate all existing encrypted data.
func (s *Store) InitVault(salt, canaryCiphertext, canaryNonce []byte) error {
	initialized, err := s.Initialized()
	if err != nil {
		return err
	}
	if initialized {
		return fmt.Errorf("vault already initialized — refusing to overwrite (existing subscriber data would become permanently unreadable)")
	}
	_, err = s.db.Exec(
		`INSERT INTO vault_meta (id, salt, canary_ciphertext, canary_nonce) VALUES (1, ?, ?, ?)`,
		salt, canaryCiphertext, canaryNonce,
	)
	return err
}

// VaultMeta returns the stored salt + canary for Unlock to verify against.
func (s *Store) VaultMeta() (salt, canaryCiphertext, canaryNonce []byte, err error) {
	err = s.db.QueryRow(`SELECT salt, canary_ciphertext, canary_nonce FROM vault_meta WHERE id = 1`).
		Scan(&salt, &canaryCiphertext, &canaryNonce)
	return
}

// AddSubscriber records one encrypted email. consentVersion identifies which
// exact privacy-policy/consent-copy revision the subscriber agreed to (see
// OKEMILY/privacy.html) — required for GDPR accountability (being able to
// prove what someone actually consented to, not just that they clicked
// something at some point). source tags which signup list/product this came
// from (e.g. "stinkies", "general") — internal bookkeeping only, distinct
// from which Mailchimp audience the subscriber gets synced to.
func (s *Store) AddSubscriber(emailCiphertext, emailNonce []byte, consentVersion, source string) (int64, error) {
	if source == "" {
		source = "general"
	}
	res, err := s.db.Exec(
		`INSERT INTO subscribers (email_ciphertext, email_nonce, consent_version, consented_at, source) VALUES (?, ?, ?, ?, ?)`,
		emailCiphertext, emailNonce, consentVersion, time.Now().UTC(), source,
	)
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

// MarkMailchimpSynced flags a subscriber row as successfully forwarded to
// Mailchimp — best-effort bookkeeping only, never blocks the subscribe path.
func (s *Store) MarkMailchimpSynced(id int64) error {
	_, err := s.db.Exec(`UPDATE subscribers SET mailchimp_synced = 1 WHERE id = ?`, id)
	return err
}

// CountBySource returns how many subscribers exist for a given source tag
// (e.g. "freehoodie", "stinkies"). Reads only the plaintext source column —
// never touches email_ciphertext, works even while the vault is locked, and
// is safe to expose publicly (a count reveals no PII).
func (s *Store) CountBySource(source string) (int, error) {
	var n int
	err := s.db.QueryRow(`SELECT COUNT(*) FROM subscribers WHERE source = ?`, source).Scan(&n)
	return n, err
}

// Count returns the total subscriber count across every source -- for the
// Back Office dashboard (founder, live: "dashboard can show email signups
// stats"). Same PII-free reasoning as CountBySource: plaintext source/count
// only, never touches email_ciphertext.
func (s *Store) Count() (int, error) {
	var n int
	err := s.db.QueryRow(`SELECT COUNT(*) FROM subscribers`).Scan(&n)
	return n, err
}

// SourceCount is one row of CountsBySource's breakdown.
type SourceCount struct {
	Source string
	Count  int
}

// CountsBySource returns subscriber counts grouped by source, highest first,
// for the Back Office dashboard's signup breakdown.
func (s *Store) CountsBySource() ([]SourceCount, error) {
	rows, err := s.db.Query(`SELECT source, COUNT(*) AS n FROM subscribers GROUP BY source ORDER BY n DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []SourceCount
	for rows.Next() {
		var sc SourceCount
		if err := rows.Scan(&sc.Source, &sc.Count); err != nil {
			return nil, err
		}
		out = append(out, sc)
	}
	return out, rows.Err()
}

// SubscriberRecord is one exported subscriber row — S245-02's real dump
// shape. EmailCiphertext/EmailNonce are handed to the caller undecrypted;
// ListForExport itself never touches the vault, keeping this Store method
// usable (and testable) with no live vault at all — the handler is the one
// real place that decrypts, using its own already-unlocked Vault.
type SubscriberRecord struct {
	ID              int64
	EmailCiphertext []byte
	EmailNonce      []byte
	ConsentVersion  string
	ConsentedAt     time.Time
	Source          string
	MailchimpSynced bool
}

// ListForExport returns every subscriber row, oldest first, for a real
// export dump (S245-02 — "saves your list in IDUNA in case you need to
// export it later"). Ciphertext, not plaintext — see SubscriberRecord.
func (s *Store) ListForExport() ([]SubscriberRecord, error) {
	rows, err := s.db.Query(
		`SELECT id, email_ciphertext, email_nonce, consent_version, consented_at, source, mailchimp_synced
		 FROM subscribers ORDER BY id ASC`,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []SubscriberRecord
	for rows.Next() {
		var rec SubscriberRecord
		var synced int
		if err := rows.Scan(&rec.ID, &rec.EmailCiphertext, &rec.EmailNonce, &rec.ConsentVersion, &rec.ConsentedAt, &rec.Source, &synced); err != nil {
			return nil, err
		}
		rec.MailchimpSynced = synced != 0
		out = append(out, rec)
	}
	return out, rows.Err()
}

// SetMailchimpSettings stores (or replaces) the single per-instance Mailchimp
// config row. Ciphertext in, ciphertext stored — encryption happens in the
// caller (the handler, via the already-unlocked Vault), matching every other
// encrypted value in this package.
func (s *Store) SetMailchimpSettings(apiKeyCiphertext, apiKeyNonce, listIDCiphertext, listIDNonce []byte) error {
	_, err := s.db.Exec(
		`INSERT INTO mailchimp_settings (id, api_key_ciphertext, api_key_nonce, list_id_ciphertext, list_id_nonce, updated_at)
		 VALUES (1, ?, ?, ?, ?, ?)
		 ON CONFLICT(id) DO UPDATE SET
		   api_key_ciphertext = excluded.api_key_ciphertext,
		   api_key_nonce      = excluded.api_key_nonce,
		   list_id_ciphertext = excluded.list_id_ciphertext,
		   list_id_nonce      = excluded.list_id_nonce,
		   updated_at         = excluded.updated_at`,
		apiKeyCiphertext, apiKeyNonce, listIDCiphertext, listIDNonce, time.Now().UTC(),
	)
	return err
}

// MailchimpSettings returns the stored per-instance Mailchimp config
// ciphertext, or ok=false if nothing has been configured yet (the normal
// state for EINHORN's own instance, which stays on the MAILCHIMP_API_KEY
// env var — see MailingListHandler's own resolution order).
func (s *Store) MailchimpSettings() (apiKeyCiphertext, apiKeyNonce, listIDCiphertext, listIDNonce []byte, ok bool, err error) {
	row := s.db.QueryRow(
		`SELECT api_key_ciphertext, api_key_nonce, list_id_ciphertext, list_id_nonce FROM mailchimp_settings WHERE id = 1`,
	)
	err = row.Scan(&apiKeyCiphertext, &apiKeyNonce, &listIDCiphertext, &listIDNonce)
	if err == sql.ErrNoRows {
		return nil, nil, nil, nil, false, nil
	}
	if err != nil {
		return nil, nil, nil, nil, false, err
	}
	return apiKeyCiphertext, apiKeyNonce, listIDCiphertext, listIDNonce, true, nil
}
