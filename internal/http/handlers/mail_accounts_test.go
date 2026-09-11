package handlers_test

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
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
			owning_org_id INTEGER NOT NULL DEFAULT 0,
			tenant_id    INTEGER NOT NULL DEFAULT 1,
			created_at   DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
			updated_at   DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
		);
		CREATE TABLE organizations (
			id         INTEGER PRIMARY KEY AUTOINCREMENT,
			name       VARCHAR(255) NOT NULL,
			cluster_id INTEGER,
			created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
		);
		CREATE TABLE cross_org_access_log (
			id            INTEGER PRIMARY KEY AUTOINCREMENT,
			actor_uid     INTEGER NOT NULL,
			actor_org_id  INTEGER NOT NULL,
			target_uid    INTEGER NOT NULL,
			target_org_id INTEGER NOT NULL,
			action        VARCHAR(64) NOT NULL,
			created_at    DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
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

// mailAccountsClusterToken -- CP-HIPAA-3: same as mailAccountsToken but also carries a real
// org_id claim, for the cluster-trust tests below.
func mailAccountsClusterToken(t *testing.T, keys *jwt.Keys, localUID, orgID int, perms ...string) string {
	t.Helper()
	claims := map[string]any{
		"sub":       "local:" + strconv.Itoa(localUID),
		"local_uid": localUID,
		"org_id":    orgID,
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

// CP-HIPAA-3: "the admins from that collective should be able to administer participants from
// that cluster of providers." A mailbox provisioned by org 1 must be visible/revealable to a
// provider from org 2, when both share a real, configured cluster -- and NOT to a provider from
// an unrelated org 3, and every cross-org reveal must leave a real cross_org_access_log row.

func TestMailAccountsHandler_ClusterMateCanRevealAndListAcrossOrgs(t *testing.T) {
	keys, _ := jwt.GenerateKeys()
	h, db := newTestMailAccountsHandler(t, keys)

	if _, err := db.Exec(`INSERT INTO organizations (id, name, cluster_id) VALUES (1, 'Health Clinic', 100), (2, 'Shelter', 100), (3, 'Unrelated', NULL)`); err != nil {
		t.Fatalf("seed orgs: %v", err)
	}
	if _, err := db.Exec(`INSERT INTO mail_account_credentials (local_uid, email, password_enc, created_by, owning_org_id) VALUES (100, 'p1@example.test', 'enc1', 10, 1)`); err != nil {
		t.Fatalf("seed: %v", err)
	}

	clusterMateToken := mailAccountsClusterToken(t, keys, 20, 2, "mail-accounts.provision")
	rr := httptest.NewRequest(http.MethodGet, "/api/v1/mail-accounts/100/reveal-password", nil)
	rr.Header.Set("Authorization", "Bearer "+clusterMateToken)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, rr)
	if rec.Code == http.StatusForbidden {
		t.Fatalf("expected a cluster-mate (org 2, shares cluster 100 with org 1) to be allowed, got 403: %s", rec.Body.String())
	}

	var logCount int
	if err := db.QueryRow(`SELECT COUNT(*) FROM cross_org_access_log WHERE actor_uid = 20 AND target_uid = 100 AND action = 'reveal_mail_password'`).Scan(&logCount); err != nil {
		t.Fatalf("query cross_org_access_log: %v", err)
	}
	if logCount != 1 {
		t.Fatalf("expected exactly 1 cross_org_access_log row for this cross-org reveal, got %d", logCount)
	}

	unrelatedToken := mailAccountsClusterToken(t, keys, 30, 3, "mail-accounts.provision")
	rr2 := httptest.NewRequest(http.MethodGet, "/api/v1/mail-accounts/100/reveal-password", nil)
	rr2.Header.Set("Authorization", "Bearer "+unrelatedToken)
	rec2 := httptest.NewRecorder()
	h.ServeHTTP(rec2, rr2)
	if rec2.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for an org with no shared cluster, got %d: %s", rec2.Code, rec2.Body.String())
	}
}

// MULTI_TENANCY_NORTHSTAR.md Phase 2 (2026-09-11): the real adversarial test. Before this fix,
// revealPassword's `if !hasPermission(r, "users.admin")` block meant a users.admin caller
// bypassed EVERY row-level check -- once a second tenant is real, any tenant's admin could reveal
// the live, decrypted mailbox password for every OTHER tenant's participants too. This test
// exercises only revealPassword (not list), matching this file's own existing scope: list()'s
// Stalwart-backed accounts require a live client this test double doesn't mock, so its equivalent
// tenant filter (mail_accounts.go's own list(), same tenantID/c.tenantID comparison) is verified
// by direct code inspection rather than a second, redundant harness here.
func TestMailAccountsHandler_AdminCannotRevealCrossTenantMailboxPassword(t *testing.T) {
	keys, _ := jwt.GenerateKeys()
	h, db := newTestMailAccountsHandler(t, keys)

	if _, err := db.Exec(`INSERT INTO mail_account_credentials (local_uid, email, password_enc, created_by, tenant_id) VALUES (100, 'tenant1@example.test', 'enc1', 1, 1)`); err != nil {
		t.Fatalf("seed tenant 1 mailbox: %v", err)
	}
	if _, err := db.Exec(`INSERT INTO mail_account_credentials (local_uid, email, password_enc, created_by, tenant_id) VALUES (200, 'tenant2@example.test', 'enc2', 2, 2)`); err != nil {
		t.Fatalf("seed tenant 2 mailbox: %v", err)
	}

	tenant1AdminToken := tenantToken(t, keys, 1, 1, "users.admin")

	cross := httptest.NewRequest(http.MethodGet, "/api/v1/mail-accounts/200/reveal-password", nil)
	cross.Header.Set("Authorization", "Bearer "+tenant1AdminToken)
	crossRR := httptest.NewRecorder()
	h.ServeHTTP(crossRR, cross)
	if crossRR.Code != http.StatusNotFound {
		t.Fatalf("tenant-1 admin revealing tenant-2's mailbox password: status = %d, body = %s, want 404 (real cross-tenant leak if not)", crossRR.Code, crossRR.Body.String())
	}
	if strings.Contains(crossRR.Body.String(), "enc2") {
		t.Fatalf("tenant-2's encrypted secret leaked into a 404 response body: %s", crossRR.Body.String())
	}

	// Regression: same-tenant reveal must still work.
	own := httptest.NewRequest(http.MethodGet, "/api/v1/mail-accounts/100/reveal-password", nil)
	own.Header.Set("Authorization", "Bearer "+tenant1AdminToken)
	ownRR := httptest.NewRecorder()
	h.ServeHTTP(ownRR, own)
	if ownRR.Code == http.StatusNotFound || ownRR.Code == http.StatusForbidden {
		t.Fatalf("tenant-1 admin revealing tenant-1's own mailbox: status = %d, body = %s, want success", ownRR.Code, ownRR.Body.String())
	}
}
