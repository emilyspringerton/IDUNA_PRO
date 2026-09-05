-- Founder real-time, 2026-09-05: "after a user provisions their account an admin can provision
-- an email for them and then the webmail for that user should just work we can still reveal
-- their password for webmail use somehow."
--
-- Real gap this closes: webmail.go's own connections map was in-memory only, keyed by local_uid,
-- populated ONLY when a user manually POSTed their own Stalwart email+password to
-- /api/v1/mail/connect -- an admin-provisioned mailbox (mail_accounts.go) had no link back to a
-- local_uid at all, so a freshly-provisioned user still had to be handed a password out of band
-- and type it in themselves before webmail worked. This table is that missing link: one row per
-- local_uid an admin has assigned a mailbox to, holding the real Stalwart password ENCRYPTED at
-- rest (AES-256-GCM, see internal/mailaccounts/crypto.go) so it can be decrypted server-side to
-- auto-connect that user's webmail session AND re-shown to an admin on demand ("reveal password")
-- -- a deliberate, explicit reversal of this repo's earlier "generated mailbox passwords are
-- never persisted" stance (mail_accounts.go's own header comment), made because the founder asked
-- for exactly this retrievability. Never store this plaintext -- password_enc is
-- base64(nonce || ciphertext), decryptable only with MAIL_CREDENTIALS_KEY (server-side env var).
--
-- local_uid is deliberately NOT a foreign key, matching sip_accounts' own migration comment: for
-- the same reason (local_users is projected from an append-only event log, not a normal mutable
-- table).
CREATE TABLE IF NOT EXISTS mail_account_credentials (
    id           INTEGER  PRIMARY KEY AUTOINCREMENT,
    local_uid    INTEGER  NOT NULL UNIQUE,
    email        VARCHAR(255) NOT NULL,
    password_enc TEXT     NOT NULL,
    created_at   DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at   DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- Reuses users.admin, same reasoning as sip_accounts' own migration comment: internal tooling for
-- whoever already manages users, not a separate product surface needing its own permission.
