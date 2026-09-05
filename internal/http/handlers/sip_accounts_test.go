package handlers_test

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
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
		created_at  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
		updated_at  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
	)`)
	if err != nil {
		t.Fatalf("create sip_accounts table: %v", err)
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
