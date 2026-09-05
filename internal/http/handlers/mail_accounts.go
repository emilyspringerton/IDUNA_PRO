package handlers

import (
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"idunapro/internal/mailaccounts"
)

// MailAccountsHandler exposes real CarePyre Stalwart mailbox provisioning from the admin
// console. Founder real-time, 2026-09-05: "ok we need a way to provision accounts from the
// carepyre admin console is that possible?" -- followed by an explicit scope decision: "For now
// admins can provision because sign up is just open" (i.e. console self-signup is currently
// open, so mailbox provisioning specifically stays admin-gated, matching
// docs/EMAIL_NORTHSTAR.md's own existing v0 decision: staff-provisioned mailboxes, no public
// self-signup for email).
//
// Stalwart itself is the only source of truth for which mailboxes EXIST -- this handler stays a
// thin proxy to its real JMAP management API (internal/mailaccounts) for that. What changed
// 2026-09-05 (founder real-time: "after a user provisions their account an admin can provision an
// email for them and then the webmail for that user should just work we can still reveal their
// password for webmail use somehow"): a NEW, separate table (mail_account_credentials, see its
// own migration comment) links a mailbox to an IDUNA_PRO local_uid and holds its real password
// ENCRYPTED at rest -- a deliberate, explicit reversal of this file's own earlier "a generated
// password is returned once and never persisted anywhere" stance, made because the founder asked
// for exactly this retrievability. WebmailHandler reads this table to auto-connect a user's
// webmail session with no manual "Connect" step; this handler's own reveal-password route lets an
// admin see it again later (e.g. to hand a user their password for a non-web mail client).
//
// Routes (all require Bearer JWT + users.admin, via middleware.RequireAuth + this handler's own
// requirePerm):
//
//	GET   /api/v1/mail-accounts                      list real mailboxes (each annotated with
//	                                                  local_uid when one is assigned)
//	POST  /api/v1/mail-accounts                      create one -- {"username", "domain"
//	                                                  (optional), "local_uid" (optional)}; when
//	                                                  local_uid is set, the mailbox is
//	                                                  auto-connected for that user's webmail
//	GET   /api/v1/mail-accounts/{uid}/reveal-password reveal the stored password for a user's
//	                                                  assigned mailbox
type MailAccountsHandler struct {
	Client *mailaccounts.Client
	DB     *sql.DB
	// CredentialsKey encrypts/decrypts mail_account_credentials.password_enc (see
	// internal/mailaccounts/crypto.go). Empty means credential linking/reveal is unavailable --
	// mailbox creation still works, it just isn't tied to a local_uid.
	CredentialsKey []byte
}

func (h *MailAccountsHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if h.Client == nil || !h.Client.Configured() {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "mail account provisioning not configured"})
		return
	}
	if !hasPermission(r, "users.admin") {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "forbidden"})
		return
	}

	path := strings.TrimPrefix(r.URL.Path, "/api/v1/mail-accounts")
	path = strings.TrimPrefix(path, "/")

	if path == "" {
		switch r.Method {
		case http.MethodGet:
			h.list(w, r)
		case http.MethodPost:
			h.create(w, r)
		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
		return
	}

	if strings.HasSuffix(path, "/reveal-password") {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		uid, err := strconv.Atoi(strings.TrimSuffix(path, "/reveal-password"))
		if err != nil {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "not found"})
			return
		}
		h.revealPassword(w, r, uid)
		return
	}

	writeJSON(w, http.StatusNotFound, map[string]string{"error": "not found"})
}

func (h *MailAccountsHandler) list(w http.ResponseWriter, r *http.Request) {
	accounts, err := h.Client.ListAccounts(r.Context())
	if err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": err.Error()})
		return
	}

	// Annotate each account with the local_uid it's assigned to (if any), so the admin console
	// can show "who owns this mailbox" without a second round trip.
	uidByEmail := map[string]int{}
	if h.DB != nil {
		rows, err := h.DB.QueryContext(r.Context(), `SELECT local_uid, email FROM mail_account_credentials`)
		if err == nil {
			defer rows.Close()
			for rows.Next() {
				var uid int
				var email string
				if rows.Scan(&uid, &email) == nil {
					uidByEmail[strings.ToLower(email)] = uid
				}
			}
		}
	}
	out := make([]mailAccountWithOwner, 0, len(accounts))
	for _, a := range accounts {
		item := mailAccountWithOwner{Account: a}
		if uid, ok := uidByEmail[strings.ToLower(a.EmailAddress)]; ok {
			item.LocalUID = &uid
		}
		out = append(out, item)
	}
	writeJSON(w, http.StatusOK, out)
}

type mailAccountWithOwner struct {
	mailaccounts.Account
	LocalUID *int `json:"local_uid,omitempty"`
}

type createMailAccountRequest struct {
	Username string `json:"username"`
	Domain   string `json:"domain"`
	// Password is optional -- if omitted, a real, random 20-character password is generated
	// server-side and returned in the response (this is the expected, normal path for the
	// console's own "Create mailbox" button; an admin who wants to set a specific password by
	// hand can still pass one).
	Password string `json:"password"`
	// LocalUID, when set, links the new mailbox to that IDUNA_PRO user (mail_account_credentials)
	// so their webmail auto-connects -- founder real-time, 2026-09-05: "after a user provisions
	// their account an admin can provision an email for them and then the webmail for that user
	// should just work."
	LocalUID *int `json:"local_uid"`
}

type createMailAccountResponse struct {
	ID       string `json:"id"`
	Email    string `json:"email"`
	Password string `json:"password"`
}

func (h *MailAccountsHandler) create(w http.ResponseWriter, r *http.Request) {
	var req createMailAccountRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON"})
		return
	}
	req.Username = strings.TrimSpace(strings.ToLower(req.Username))
	req.Domain = strings.TrimSpace(strings.ToLower(req.Domain))
	if req.Username == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "username is required"})
		return
	}
	if strings.ContainsAny(req.Username, "@ \t") {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "username must be the local part only, not a full email address"})
		return
	}
	if req.LocalUID != nil && h.CredentialsKey == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "mailbox-to-user linking not configured (MAIL_CREDENTIALS_KEY unset)"})
		return
	}

	password := req.Password
	if password == "" {
		var err error
		password, err = mailaccounts.GenerateSecret()
		if err != nil {
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
	}

	domain := req.Domain
	if domain == "" {
		domain = h.Client.DefaultDomain
	}

	id, err := h.Client.CreateAccount(r.Context(), req.Username, domain, password)
	if err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": err.Error()})
		return
	}
	email := req.Username + "@" + domain

	if req.LocalUID != nil {
		if err := h.storeCredential(r, *req.LocalUID, email, password); err != nil {
			// The real Stalwart mailbox was already created successfully at this point -- report
			// the linking failure honestly rather than pretending the whole call failed, since a
			// retry would try (and likely fail) to create a duplicate mailbox.
			writeJSON(w, http.StatusCreated, map[string]any{
				"id": id, "email": email, "password": password,
				"warning": "mailbox created, but could not link it to the user for webmail auto-connect: " + err.Error(),
			})
			return
		}
	}

	writeJSON(w, http.StatusCreated, createMailAccountResponse{
		ID:       id,
		Email:    email,
		Password: password,
	})
}

func (h *MailAccountsHandler) storeCredential(r *http.Request, uid int, email, password string) error {
	if h.DB == nil {
		return errNoCredentialsStore
	}
	enc, err := mailaccounts.EncryptSecret(h.CredentialsKey, password)
	if err != nil {
		return err
	}
	now := time.Now().UTC()
	_, err = h.DB.ExecContext(r.Context(), `
		INSERT INTO mail_account_credentials (local_uid, email, password_enc, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?)
		ON CONFLICT(local_uid) DO UPDATE SET
			email = excluded.email,
			password_enc = excluded.password_enc,
			updated_at = excluded.updated_at
	`, uid, email, enc, now, now)
	return err
}

var errNoCredentialsStore = errors.New("no database configured for mail account credentials")

// revealPassword -- founder real-time, 2026-09-05: "we can still reveal their password for
// webmail use somehow." Decrypts and returns the real password an admin-linked mailbox was
// created with, so an admin can hand it to the user for a non-web mail client (or re-check it
// themselves) without knowing it from anywhere else.
func (h *MailAccountsHandler) revealPassword(w http.ResponseWriter, r *http.Request, uid int) {
	if h.DB == nil || h.CredentialsKey == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "mailbox-to-user linking not configured"})
		return
	}
	var email, enc string
	err := h.DB.QueryRowContext(r.Context(),
		`SELECT email, password_enc FROM mail_account_credentials WHERE local_uid = ?`, uid).Scan(&email, &enc)
	if err == sql.ErrNoRows {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "no mailbox linked to this user"})
		return
	}
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	password, err := mailaccounts.DecryptSecret(h.CredentialsKey, enc)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"email": email, "password": password})
}
