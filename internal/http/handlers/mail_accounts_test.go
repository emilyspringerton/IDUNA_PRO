package handlers_test

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	_ "modernc.org/sqlite"

	"idunapro/internal/auth/jwt"
	"idunapro/internal/http/handlers"
	"idunapro/internal/http/middleware"
	"idunapro/internal/mailaccounts"
)

// CP-HIPAA-1: a provider (mail-accounts.provision, a real, least-privilege role distinct from
// users.admin) can now reach MailAccountsHandler -- these tests cover the real access-control
// changes that made that safe: providers must always link a mailbox to a participant, and their
// reveal-password view is scoped to only the mailboxes they themselves created (HIPAA's own
// "minimum necessary" principle), never every participant in the system.

func newTestMailAccountsHandler(t *testing.T, keys *jwt.Keys) (http.Handler, *sql.DB) {
	t.Helper()
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	t.Cleanup(func() { db.Close() })

	if _, err := db.Exec(`
		CREATE TABLE mail_account_credentials (
			id           INTEGER  PRIMARY KEY AUTOINCREMENT,
			local_uid    INTEGER  NOT NULL UNIQUE,
			email        VARCHAR(255) NOT NULL,
			password_enc TEXT     NOT NULL,
			created_by   INTEGER,
			created_at   DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
			updated_at   DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
		);
	`); err != nil {
		t.Fatalf("create schema: %v", err)
	}

	h := &handlers.MailAccountsHandler{
		// Configured() only checks these fields are non-empty -- no real network call happens
		// for any of the code paths these tests exercise.
		Client:         &mailaccounts.Client{BaseURL: "https://mail.example.test", AdminUser: "admin", AdminPass: "x", DefaultDomain: "example.test"},
		DB:             db,
		CredentialsKey: []byte("a-real-test-credentials-key"),
	}
	return middleware.RequireAuth(keys)(h), db
}

func mailAccountsToken(t *testing.T, keys *jwt.Keys, localUID int, perms ...string) string {
	t.Helper()
	claims := map[string]any{
		"sub":       "local:" + strconv.Itoa(localUID),
		"local_uid": localUID,
		"exp":       time.Now().Add(time.Hour).Unix(),
	}
	if len(perms) > 0 {
		claims["permissions"] = perms
	}
	tok, err := jwt.Sign(keys, claims)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	return tok
}

func TestMailAccountsHandler_ForbiddenWithoutEitherPermission(t *testing.T) {
	keys, _ := jwt.GenerateKeys()
	h, _ := newTestMailAccountsHandler(t, keys)
	token := mailAccountsToken(t, keys, 1) // no users.admin, no mail-accounts.provision

	req := httptest.NewRequest(http.MethodGet, "/api/v1/mail-accounts", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("expected 403 with neither permission, got %d: %s", rr.Code, rr.Body.String())
	}
}

func TestMailAccountsHandler_ProviderMustLinkLocalUID(t *testing.T) {
	keys, _ := jwt.GenerateKeys()
	h, _ := newTestMailAccountsHandler(t, keys)
	token := mailAccountsToken(t, keys, 1, "mail-accounts.provision")

	body, _ := json.Marshal(map[string]string{"username": "participant1"})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/mail-accounts", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 when a provider omits local_uid, got %d: %s", rr.Code, rr.Body.String())
	}
}

func TestMailAccountsHandler_RevealPassword_ScopedToCreator(t *testing.T) {
	keys, _ := jwt.GenerateKeys()
	h, db := newTestMailAccountsHandler(t, keys)

	// Two mailboxes, created by two different providers (uid 10 and uid 20).
	if _, err := db.Exec(`INSERT INTO mail_account_credentials (local_uid, email, password_enc, created_by) VALUES (100, 'p1@example.test', 'enc1', 10)`); err != nil {
		t.Fatalf("seed: %v", err)
	}
	if _, err := db.Exec(`INSERT INTO mail_account_credentials (local_uid, email, password_enc, created_by) VALUES (200, 'p2@example.test', 'enc2', 20)`); err != nil {
		t.Fatalf("seed: %v", err)
	}

	providerToken := mailAccountsToken(t, keys, 10, "mail-accounts.provision")
	adminToken := mailAccountsToken(t, keys, 1, "users.admin")

	// Provider 10 can reveal their own participant's mailbox.
	own := httptest.NewRequest(http.MethodGet, "/api/v1/mail-accounts/100/reveal-password", nil)
	own.Header.Set("Authorization", "Bearer "+providerToken)
	rrOwn := httptest.NewRecorder()
	h.ServeHTTP(rrOwn, own)
	// The stored "enc1" isn't real AES-GCM ciphertext, so decryption fails downstream (500) --
	// what matters here is that the access-control check itself let the request through (not a
	// 403), proving the scoping logic identified provider 10 as the real creator.
	if rrOwn.Code == http.StatusForbidden {
		t.Fatalf("provider should be allowed to reveal a mailbox they created, got 403: %s", rrOwn.Body.String())
	}

	// Provider 10 CANNOT reveal provider 20's participant's mailbox.
	other := httptest.NewRequest(http.MethodGet, "/api/v1/mail-accounts/200/reveal-password", nil)
	other.Header.Set("Authorization", "Bearer "+providerToken)
	rrOther := httptest.NewRecorder()
	h.ServeHTTP(rrOther, other)
	if rrOther.Code != http.StatusForbidden {
		t.Fatalf("expected 403 revealing another provider's mailbox, got %d: %s", rrOther.Code, rrOther.Body.String())
	}

	// users.admin can reveal anyone's.
	admin := httptest.NewRequest(http.MethodGet, "/api/v1/mail-accounts/200/reveal-password", nil)
	admin.Header.Set("Authorization", "Bearer "+adminToken)
	rrAdmin := httptest.NewRecorder()
	h.ServeHTTP(rrAdmin, admin)
	if rrAdmin.Code == http.StatusForbidden {
		t.Fatalf("users.admin should be able to reveal any mailbox, got 403: %s", rrAdmin.Body.String())
	}
}
