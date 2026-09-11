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
)

func newTestSipAccountsDB(t *testing.T) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	_, err = db.Exec(`CREATE TABLE sip_accounts (
		id          INTEGER  PRIMARY KEY AUTOINCREMENT,
		local_uid   INTEGER  NOT NULL UNIQUE,
		extension   VARCHAR(32) NOT NULL,
		sip_server  VARCHAR(255) NOT NULL,
		sip_port    INTEGER  NOT NULL DEFAULT 5060,
		created_by  INTEGER,
		owning_org_id INTEGER NOT NULL DEFAULT 0,
		tenant_id   INTEGER NOT NULL DEFAULT 1,
		created_at  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
		updated_at  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
	)`)
	if err != nil {
		t.Fatalf("create sip_accounts table: %v", err)
	}
	// MULTI_TENANCY_NORTHSTAR.md Phase 2: local_users is the authoritative source
	// localUserTenantID (used by upsert's tenant gate) reads from -- a minimal stand-in for the
	// real table's own tenant_id column, not the full userlog-backed schema.
	if _, err := db.Exec(`CREATE TABLE local_users (
		local_uid INTEGER PRIMARY KEY,
		tenant_id INTEGER NOT NULL DEFAULT 1
	)`); err != nil {
		t.Fatalf("create local_users table: %v", err)
	}
	if _, err := db.Exec(`
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
		t.Fatalf("create organizations/cross_org_access_log schema: %v", err)
	}
	return db
}

func sipAccountsHandlerWithAuth(keys *jwt.Keys, db *sql.DB) http.Handler {
	h := &handlers.SipAccountsHandler{DB: db}
	return middleware.RequireAuth(keys)(h)
}

func sipAccountsSignToken(t *testing.T, keys *jwt.Keys, localUID int, perms ...string) string {
	t.Helper()
	claims := map[string]any{
		"sub":       "local:1",
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

// sipAccountsClusterToken -- CP-HIPAA-3: same as sipAccountsSignToken but also carries a real
// org_id claim.
func sipAccountsClusterToken(t *testing.T, keys *jwt.Keys, localUID, orgID int, perms ...string) string {
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

// TestSipAccounts_SelfReadNeedsNoAdminPermission -- CP-SIP-1244543543's own "see their sip
// information" ask: any authenticated user can read their OWN assigned SIP account, no
// users.admin needed.
func TestSipAccounts_SelfReadNeedsNoAdminPermission(t *testing.T) {
	keys, err := jwt.GenerateKeys()
	if err != nil {
		t.Fatalf("generate keys: %v", err)
	}
	db := newTestSipAccountsDB(t)
	if _, err := db.Exec(`INSERT INTO sip_accounts (local_uid, extension, sip_server, sip_port) VALUES (5, '1000', '198.58.107.85', 5060)`); err != nil {
		t.Fatalf("seed sip_accounts: %v", err)
	}
	h := sipAccountsHandlerWithAuth(keys, db)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/sip-accounts/me", nil)
	req.Header.Set("Authorization", "Bearer "+sipAccountsSignToken(t, keys, 5))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("self-read: status = %d, body = %s, want 200", w.Code, w.Body.String())
	}
	var got map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got["extension"] != "1000" {
		t.Errorf("extension = %v, want 1000", got["extension"])
	}
}

// TestSipAccounts_SelfReadNoAccountYet -- a real, honest 404 (not a crash or an empty 200) for
// a user with no SIP account assigned yet.
func TestSipAccounts_SelfReadNoAccountYet(t *testing.T) {
	keys, err := jwt.GenerateKeys()
	if err != nil {
		t.Fatalf("generate keys: %v", err)
	}
	db := newTestSipAccountsDB(t)
	h := sipAccountsHandlerWithAuth(keys, db)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/sip-accounts/me", nil)
	req.Header.Set("Authorization", "Bearer "+sipAccountsSignToken(t, keys, 42))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusNotFound {
		t.Fatalf("no account yet: status = %d, want 404", w.Code)
	}
}

// TestSipAccounts_CannotReadSomeoneElses -- self-read means SELF, not any authenticated caller
// reading any other user's SIP info.
func TestSipAccounts_CannotReadSomeoneElses(t *testing.T) {
	keys, err := jwt.GenerateKeys()
	if err != nil {
		t.Fatalf("generate keys: %v", err)
	}
	db := newTestSipAccountsDB(t)
	if _, err := db.Exec(`INSERT INTO sip_accounts (local_uid, extension, sip_server, sip_port) VALUES (5, '1000', '198.58.107.85', 5060)`); err != nil {
		t.Fatalf("seed sip_accounts: %v", err)
	}
	h := sipAccountsHandlerWithAuth(keys, db)

	// Caller is local_uid 6, asking for /me -- gets THEIR OWN (nonexistent) record, never uid 5's.
	req := httptest.NewRequest(http.MethodGet, "/api/v1/sip-accounts/me", nil)
	req.Header.Set("Authorization", "Bearer "+sipAccountsSignToken(t, keys, 6))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusNotFound {
		t.Fatalf("different caller: status = %d, want 404 (their own, unassigned record)", w.Code)
	}
}

// TestSipAccounts_QRPayload -- CAREPYRE-42143124: the real, honest provisioning shape a
// scanning Android Config screen would auto-fill from -- extension/server/port/transport, and
// deliberately NOT a password field (sip_accounts never stores one, see sip_accounts.go's own
// header comment on why).
func TestSipAccounts_QRPayload(t *testing.T) {
	keys, err := jwt.GenerateKeys()
	if err != nil {
		t.Fatalf("generate keys: %v", err)
	}
	db := newTestSipAccountsDB(t)
	if _, err := db.Exec(`INSERT INTO sip_accounts (local_uid, extension, sip_server, sip_port) VALUES (5, '1000', '198.58.107.85', 5060)`); err != nil {
		t.Fatalf("seed sip_accounts: %v", err)
	}
	h := sipAccountsHandlerWithAuth(keys, db)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/sip-accounts/me/qr", nil)
	req.Header.Set("Authorization", "Bearer "+sipAccountsSignToken(t, keys, 5))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("qr payload: status = %d, body = %s, want 200", w.Code, w.Body.String())
	}
	var got map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got["scheme"] != "carepyre-sip-v1" {
		t.Errorf("scheme = %v, want carepyre-sip-v1", got["scheme"])
	}
	if got["extension"] != "1000" || got["sip_server"] != "198.58.107.85" || got["transport"] != "UDP" {
		t.Errorf("unexpected payload: %+v", got)
	}
	if _, hasPassword := got["password"]; hasPassword {
		t.Errorf("qr payload must never include a password field -- sip_accounts doesn't store one, got: %+v", got)
	}
}

// TestSipAccounts_QRPayloadIsSelfOnly -- same real ownership boundary as /me: a caller only ever
// gets THEIR OWN provisioning payload.
func TestSipAccounts_QRPayloadIsSelfOnly(t *testing.T) {
	keys, err := jwt.GenerateKeys()
	if err != nil {
		t.Fatalf("generate keys: %v", err)
	}
	db := newTestSipAccountsDB(t)
	if _, err := db.Exec(`INSERT INTO sip_accounts (local_uid, extension, sip_server, sip_port) VALUES (5, '1000', '198.58.107.85', 5060)`); err != nil {
		t.Fatalf("seed sip_accounts: %v", err)
	}
	h := sipAccountsHandlerWithAuth(keys, db)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/sip-accounts/me/qr", nil)
	req.Header.Set("Authorization", "Bearer "+sipAccountsSignToken(t, keys, 6))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusNotFound {
		t.Fatalf("different caller: status = %d, want 404 (their own, unassigned record)", w.Code)
	}
}

// TestSipAccounts_ListRequiresAdmin -- the admin list route rejects a caller with no
// users.admin permission.
func TestSipAccounts_ListRequiresAdmin(t *testing.T) {
	keys, err := jwt.GenerateKeys()
	if err != nil {
		t.Fatalf("generate keys: %v", err)
	}
	db := newTestSipAccountsDB(t)
	h := sipAccountsHandlerWithAuth(keys, db)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/sip-accounts", nil)
	req.Header.Set("Authorization", "Bearer "+sipAccountsSignToken(t, keys, 6))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusForbidden {
		t.Fatalf("list without users.admin: status = %d, want 403", w.Code)
	}
}

// TestSipAccounts_AdminUpsertAndList -- a real, full admin flow: assign a SIP account to a
// user, then see it in the list, then update it (upsert, not insert-only).
func TestSipAccounts_AdminUpsertAndList(t *testing.T) {
	keys, err := jwt.GenerateKeys()
	if err != nil {
		t.Fatalf("generate keys: %v", err)
	}
	db := newTestSipAccountsDB(t)
	h := sipAccountsHandlerWithAuth(keys, db)
	adminToken := sipAccountsSignToken(t, keys, 0, "users.admin")

	body, _ := json.Marshal(map[string]any{"extension": "1000", "sip_server": "198.58.107.85", "sip_port": 5060})
	req := httptest.NewRequest(http.MethodPut, "/api/v1/sip-accounts/7", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+adminToken)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("admin upsert: status = %d, body = %s, want 200", w.Code, w.Body.String())
	}

	// Real upsert -- re-assigning the same user to a different extension updates in place,
	// it doesn't error or create a second row (local_uid is UNIQUE).
	body2, _ := json.Marshal(map[string]any{"extension": "1001", "sip_server": "198.58.107.85", "sip_port": 5060})
	req2 := httptest.NewRequest(http.MethodPut, "/api/v1/sip-accounts/7", bytes.NewReader(body2))
	req2.Header.Set("Authorization", "Bearer "+adminToken)
	w2 := httptest.NewRecorder()
	h.ServeHTTP(w2, req2)
	if w2.Code != http.StatusOK {
		t.Fatalf("admin re-upsert: status = %d, body = %s, want 200", w2.Code, w2.Body.String())
	}

	listReq := httptest.NewRequest(http.MethodGet, "/api/v1/sip-accounts", nil)
	listReq.Header.Set("Authorization", "Bearer "+adminToken)
	listW := httptest.NewRecorder()
	h.ServeHTTP(listW, listReq)
	if listW.Code != http.StatusOK {
		t.Fatalf("admin list: status = %d, want 200", listW.Code)
	}
	var got []map[string]any
	if err := json.Unmarshal(listW.Body.Bytes(), &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("expected exactly 1 row (upsert, not insert-only), got %d: %+v", len(got), got)
	}
	if got[0]["extension"] != "1001" {
		t.Errorf("extension = %v, want 1001 (the re-upserted value)", got[0]["extension"])
	}
}

// TestSipProvisioning_MintAndFetchRoundTrip -- founder real-time, 2026-09-05: "make the sip
// phone register with just that URL." Real, full round trip: mint a capability URL through the
// authenticated /me/provisioning-url route, then fetch it through the SEPARATE, unauthenticated
// SipProvisioningFetchHandler (simulating the native app, which has no bearer token) and confirm
// it returns the real password.
func TestSipProvisioning_MintAndFetchRoundTrip(t *testing.T) {
	keys, err := jwt.GenerateKeys()
	if err != nil {
		t.Fatalf("generate keys: %v", err)
	}
	db := newTestSipAccountsDB(t)
	if _, err := db.Exec(`INSERT INTO sip_accounts (local_uid, extension, sip_server, sip_port) VALUES (7, '1000', '198.58.107.85', 5060)`); err != nil {
		t.Fatalf("seed sip_accounts: %v", err)
	}

	provisioningKey := []byte("test-provisioning-key-not-a-real-secret")
	sipAccountsH := &handlers.SipAccountsHandler{
		DB:              db,
		ProvisioningKey: provisioningKey,
		PublicBaseURL:   "https://carepyre.org",
	}
	protected := middleware.RequireAuth(keys)(sipAccountsH)

	mintReq := httptest.NewRequest(http.MethodGet, "/api/v1/sip-accounts/me/provisioning-url", nil)
	mintReq.Header.Set("Authorization", "Bearer "+sipAccountsSignToken(t, keys, 7))
	mintW := httptest.NewRecorder()
	protected.ServeHTTP(mintW, mintReq)
	if mintW.Code != http.StatusOK {
		t.Fatalf("mint: status = %d, body = %s, want 200", mintW.Code, mintW.Body.String())
	}
	var mintResp struct {
		URL string `json:"url"`
	}
	if err := json.Unmarshal(mintW.Body.Bytes(), &mintResp); err != nil {
		t.Fatalf("unmarshal mint response: %v", err)
	}
	if !strings.HasPrefix(mintResp.URL, "https://carepyre.org/api/v1/sip-provisioning/") {
		t.Fatalf("minted URL = %q, want it to start with the public base URL + real path", mintResp.URL)
	}
	token := strings.TrimPrefix(mintResp.URL, "https://carepyre.org/api/v1/sip-provisioning/")

	fetchH := &handlers.SipProvisioningFetchHandler{
		DB:                    db,
		ProvisioningKey:       provisioningKey,
		SipSecretsByExtension: map[string]string{"1000": "real-test-password-123"},
	}
	fetchReq := httptest.NewRequest(http.MethodGet, "/api/v1/sip-provisioning/"+token, nil)
	fetchW := httptest.NewRecorder()
	fetchH.ServeHTTP(fetchW, fetchReq)
	if fetchW.Code != http.StatusOK {
		t.Fatalf("fetch: status = %d, body = %s, want 200 -- no bearer token was sent, confirming this route needs none", fetchW.Code, fetchW.Body.String())
	}
	var payload map[string]any
	if err := json.Unmarshal(fetchW.Body.Bytes(), &payload); err != nil {
		t.Fatalf("unmarshal fetch response: %v", err)
	}
	if payload["password"] != "real-test-password-123" {
		t.Errorf("password = %v, want the real configured secret", payload["password"])
	}
	if payload["extension"] != "1000" {
		t.Errorf("extension = %v, want 1000", payload["extension"])
	}
	if payload["scheme"] != "carepyre-sip-v2" {
		t.Errorf("scheme = %v, want carepyre-sip-v2 (distinct from the password-less v1 QR payload)", payload["scheme"])
	}

	// A tampered token (wrong signature) must be rejected -- this is the entire security
	// boundary of this endpoint, worth a real, explicit negative test.
	tamperedReq := httptest.NewRequest(http.MethodGet, "/api/v1/sip-provisioning/"+token+"deadbeef", nil)
	tamperedW := httptest.NewRecorder()
	fetchH.ServeHTTP(tamperedW, tamperedReq)
	if tamperedW.Code == http.StatusOK {
		t.Fatalf("tampered token was accepted -- real security bug")
	}
}

// CP-HIPAA-2: sip-accounts.provision gets the same real minimum-necessary treatment as
// mail-accounts.provision -- a provider can only provision/see/remove SIP accounts for
// participants they themselves already manage.

func newTestSipAccountsDBWithMailCreds(t *testing.T) *sql.DB {
	t.Helper()
	db := newTestSipAccountsDB(t)
	if _, err := db.Exec(`CREATE TABLE mail_account_credentials (
		id           INTEGER  PRIMARY KEY AUTOINCREMENT,
		local_uid    INTEGER  NOT NULL UNIQUE,
		email        VARCHAR(255) NOT NULL,
		password_enc TEXT     NOT NULL,
		created_by   INTEGER,
		owning_org_id INTEGER NOT NULL DEFAULT 0,
		tenant_id    INTEGER NOT NULL DEFAULT 1,
		created_at   DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
		updated_at   DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
	)`); err != nil {
		t.Fatalf("create mail_account_credentials table: %v", err)
	}
	return db
}

func TestSipAccounts_ProviderCannotUpsertForUnrelatedParticipant(t *testing.T) {
	keys, _ := jwt.GenerateKeys()
	db := newTestSipAccountsDBWithMailCreds(t)
	h := sipAccountsHandlerWithAuth(keys, db)
	providerToken := sipAccountsSignToken(t, keys, 10, "sip-accounts.provision")

	body, _ := json.Marshal(map[string]any{"extension": "2000", "sip_server": "198.58.107.85", "sip_port": 5060})
	req := httptest.NewRequest(http.MethodPut, "/api/v1/sip-accounts/999", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+providerToken)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("expected 403 provisioning SIP for a participant the provider doesn't manage, got %d: %s", rr.Code, rr.Body.String())
	}
}

func TestSipAccounts_ProviderCanProvisionForOwnParticipant(t *testing.T) {
	keys, _ := jwt.GenerateKeys()
	db := newTestSipAccountsDBWithMailCreds(t)
	h := sipAccountsHandlerWithAuth(keys, db)
	providerToken := sipAccountsSignToken(t, keys, 10, "sip-accounts.provision")

	if _, err := db.Exec(`INSERT INTO mail_account_credentials (local_uid, email, password_enc, created_by) VALUES (100, 'p@example.test', 'enc', 10)`); err != nil {
		t.Fatalf("seed: %v", err)
	}

	body, _ := json.Marshal(map[string]any{"extension": "2000", "sip_server": "198.58.107.85", "sip_port": 5060})
	req := httptest.NewRequest(http.MethodPut, "/api/v1/sip-accounts/100", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+providerToken)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200 provisioning SIP for the provider's own participant, got %d: %s", rr.Code, rr.Body.String())
	}
}

func TestSipAccounts_ListScopedToOwnCreations(t *testing.T) {
	keys, _ := jwt.GenerateKeys()
	db := newTestSipAccountsDBWithMailCreds(t)
	h := sipAccountsHandlerWithAuth(keys, db)

	if _, err := db.Exec(`INSERT INTO sip_accounts (local_uid, extension, sip_server, sip_port, created_by) VALUES (100, '2000', 'x', 5060, 10)`); err != nil {
		t.Fatalf("seed: %v", err)
	}
	if _, err := db.Exec(`INSERT INTO sip_accounts (local_uid, extension, sip_server, sip_port, created_by) VALUES (200, '2001', 'x', 5060, 20)`); err != nil {
		t.Fatalf("seed: %v", err)
	}

	providerToken := sipAccountsSignToken(t, keys, 10, "sip-accounts.provision")
	req := httptest.NewRequest(http.MethodGet, "/api/v1/sip-accounts", nil)
	req.Header.Set("Authorization", "Bearer "+providerToken)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("list: status = %d, body = %s", rr.Code, rr.Body.String())
	}
	var got []map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("expected exactly 1 SIP account (the provider's own), got %d: %+v", len(got), got)
	}
}

func TestSipAccounts_RemoveScopedToOwnCreations(t *testing.T) {
	keys, _ := jwt.GenerateKeys()
	db := newTestSipAccountsDBWithMailCreds(t)
	h := sipAccountsHandlerWithAuth(keys, db)

	if _, err := db.Exec(`INSERT INTO sip_accounts (local_uid, extension, sip_server, sip_port, created_by) VALUES (200, '2001', 'x', 5060, 20)`); err != nil {
		t.Fatalf("seed: %v", err)
	}

	providerToken := sipAccountsSignToken(t, keys, 10, "sip-accounts.provision")
	req := httptest.NewRequest(http.MethodDelete, "/api/v1/sip-accounts/200", nil)
	req.Header.Set("Authorization", "Bearer "+providerToken)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	// CP-HIPAA-3: remove() now checks the real relationship (own creation, or a shared cluster)
	// UP FRONT via callerProvisionsParticipant -- same helper upsert already uses -- and returns
	// a real, explicit 403 for "not yours to touch" rather than a 404 that could also mean
	// "doesn't exist." Neither org here has a cluster configured, so this is correctly denied.
	if rr.Code != http.StatusForbidden {
		t.Fatalf("expected 403 removing a SIP account created by an unrelated provider, got %d: %s", rr.Code, rr.Body.String())
	}
}

// CP-HIPAA-3: "the admins from that collective should be able to administer participants from
// that cluster of providers." A SIP account provisioned by org 1 must be manageable by a
// provider from org 2, when both share a real, configured cluster.
func TestSipAccounts_ClusterMateCanProvisionAndList(t *testing.T) {
	keys, _ := jwt.GenerateKeys()
	db := newTestSipAccountsDBWithMailCreds(t)
	h := sipAccountsHandlerWithAuth(keys, db)

	if _, err := db.Exec(`INSERT INTO organizations (id, name, cluster_id) VALUES (1, 'Health Clinic', 100), (2, 'Shelter', 100)`); err != nil {
		t.Fatalf("seed orgs: %v", err)
	}
	if _, err := db.Exec(`INSERT INTO mail_account_credentials (local_uid, email, password_enc, created_by, owning_org_id) VALUES (100, 'p@example.test', 'enc', 10, 1)`); err != nil {
		t.Fatalf("seed mail credential: %v", err)
	}

	clusterMateToken := sipAccountsClusterToken(t, keys, 20, 2, "sip-accounts.provision")
	body, _ := json.Marshal(map[string]any{"extension": "3000", "sip_server": "198.58.107.85", "sip_port": 5060})
	req := httptest.NewRequest(http.MethodPut, "/api/v1/sip-accounts/100", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+clusterMateToken)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200 -- a cluster-mate should be able to provision SIP for org 1's own participant, got %d: %s", rr.Code, rr.Body.String())
	}

	listReq := httptest.NewRequest(http.MethodGet, "/api/v1/sip-accounts", nil)
	listReq.Header.Set("Authorization", "Bearer "+clusterMateToken)
	listRR := httptest.NewRecorder()
	h.ServeHTTP(listRR, listReq)
	if listRR.Code != http.StatusOK {
		t.Fatalf("list: status = %d, body = %s", listRR.Code, listRR.Body.String())
	}
	var got []map[string]any
	if err := json.Unmarshal(listRR.Body.Bytes(), &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("expected exactly 1 SIP account visible to the cluster-mate, got %d: %+v", len(got), got)
	}
}

// MULTI_TENANCY_NORTHSTAR.md Phase 2 (2026-09-11): the real adversarial test. Before this fix,
// list() had no tenant filter at all and upsert()/remove() let a users.admin caller act on ANY
// uid's SIP account -- once a second tenant is real, any tenant's admin could see, silently
// hijack (upsert), or delete another tenant's phone extension outright.
func TestSipAccounts_AdminCannotSeeOrTouchCrossTenantAccount(t *testing.T) {
	keys, _ := jwt.GenerateKeys()
	db := newTestSipAccountsDB(t)
	h := sipAccountsHandlerWithAuth(keys, db)

	if _, err := db.Exec(`INSERT INTO local_users (local_uid, tenant_id) VALUES (100, 1), (200, 2)`); err != nil {
		t.Fatalf("seed local_users: %v", err)
	}
	if _, err := db.Exec(`INSERT INTO sip_accounts (local_uid, extension, sip_server, sip_port, tenant_id) VALUES (100, '1000', 'x', 5060, 1)`); err != nil {
		t.Fatalf("seed tenant 1 sip account: %v", err)
	}
	if _, err := db.Exec(`INSERT INTO sip_accounts (local_uid, extension, sip_server, sip_port, tenant_id) VALUES (200, '2000', 'x', 5060, 2)`); err != nil {
		t.Fatalf("seed tenant 2 sip account: %v", err)
	}

	adminToken := tenantToken(t, keys, 1, 1, "users.admin")

	// list() must never surface tenant 2's SIP account to a tenant-1 admin.
	listReq := httptest.NewRequest(http.MethodGet, "/api/v1/sip-accounts", nil)
	listReq.Header.Set("Authorization", "Bearer "+adminToken)
	listRR := httptest.NewRecorder()
	h.ServeHTTP(listRR, listReq)
	if listRR.Code != http.StatusOK {
		t.Fatalf("list: status = %d, body = %s", listRR.Code, listRR.Body.String())
	}
	var got []map[string]any
	if err := json.Unmarshal(listRR.Body.Bytes(), &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(got) != 1 || got[0]["local_uid"].(float64) != 100 {
		t.Fatalf("tenant-1 admin list: expected exactly tenant 1's own account only, got %+v", got)
	}

	// upsert() must 404, not silently hijack, a tenant-2 uid's extension.
	hijackBody, _ := json.Marshal(map[string]any{"extension": "9999", "sip_server": "evil.example", "sip_port": 5060})
	upsertReq := httptest.NewRequest(http.MethodPut, "/api/v1/sip-accounts/200", bytes.NewReader(hijackBody))
	upsertReq.Header.Set("Authorization", "Bearer "+adminToken)
	upsertRR := httptest.NewRecorder()
	h.ServeHTTP(upsertRR, upsertReq)
	if upsertRR.Code != http.StatusNotFound {
		t.Fatalf("tenant-1 admin upsert on tenant-2 uid: status = %d, body = %s, want 404 (real cross-tenant hijack if not)", upsertRR.Code, upsertRR.Body.String())
	}

	// remove() must 404, not delete, a tenant-2 row.
	removeReq := httptest.NewRequest(http.MethodDelete, "/api/v1/sip-accounts/200", nil)
	removeReq.Header.Set("Authorization", "Bearer "+adminToken)
	removeRR := httptest.NewRecorder()
	h.ServeHTTP(removeRR, removeReq)
	if removeRR.Code != http.StatusNotFound {
		t.Fatalf("tenant-1 admin remove on tenant-2 uid: status = %d, body = %s, want 404 (real cross-tenant deletion if not)", removeRR.Code, removeRR.Body.String())
	}

	var stillThere int
	if err := db.QueryRow(`SELECT COUNT(*) FROM sip_accounts WHERE local_uid = 200 AND extension = '2000'`).Scan(&stillThere); err != nil {
		t.Fatalf("verify survival: %v", err)
	}
	if stillThere != 1 {
		t.Fatalf("tenant-2's SIP account was modified or deleted by a tenant-1 admin -- real cross-tenant breach")
	}

	// Regression: same-tenant upsert (uid 100, tenant 1, WITH a matching local_users row) must
	// still succeed -- proving the fix didn't just make every admin action 404.
	sameTenantBody, _ := json.Marshal(map[string]any{"extension": "1001", "sip_server": "x", "sip_port": 5060})
	sameTenantReq := httptest.NewRequest(http.MethodPut, "/api/v1/sip-accounts/100", bytes.NewReader(sameTenantBody))
	sameTenantReq.Header.Set("Authorization", "Bearer "+adminToken)
	sameTenantRR := httptest.NewRecorder()
	h.ServeHTTP(sameTenantRR, sameTenantReq)
	if sameTenantRR.Code != http.StatusOK {
		t.Fatalf("tenant-1 admin upsert on own tenant's uid: status = %d, body = %s, want 200", sameTenantRR.Code, sameTenantRR.Body.String())
	}
}
