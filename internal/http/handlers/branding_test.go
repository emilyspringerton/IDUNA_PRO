package handlers_test

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	_ "modernc.org/sqlite"

	"idunapro/internal/auth/jwt"
	"idunapro/internal/http/handlers"
	"idunapro/internal/http/middleware"
)

// CP-WHITELABEL-1: GET is public (no auth wrapper at all, matching main.go's own
// "GET /api/v1/branding" registration); PUT is branding.admin-gated.

func newTestBrandingHandler(t *testing.T) (*handlers.BrandingHandler, *sql.DB) {
	t.Helper()
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	if _, err := db.Exec(`
		CREATE TABLE branding_settings (
			id            INTEGER PRIMARY KEY CHECK (id = 1),
			app_name      VARCHAR(255) NOT NULL DEFAULT 'IDUNA Pro',
			tagline       VARCHAR(255) NOT NULL DEFAULT '',
			primary_color VARCHAR(16)  NOT NULL DEFAULT '#3fa9dc',
			accent_color  VARCHAR(16)  NOT NULL DEFAULT '#f5a623',
			logo_data_uri TEXT,
			updated_at    DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
		);
	`); err != nil {
		t.Fatalf("create schema: %v", err)
	}
	return &handlers.BrandingHandler{DB: db}, db
}

func TestBrandingHandler_GetDefaultsWhenUnconfigured(t *testing.T) {
	h, _ := newTestBrandingHandler(t)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/branding", nil)
	rr := httptest.NewRecorder()
	h.Get(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rr.Code, rr.Body.String())
	}
	var got map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got["app_name"] != "IDUNA Pro" {
		t.Fatalf("expected the generic default app_name, got %+v", got)
	}
}

func TestBrandingHandler_PutRequiresBrandingAdmin(t *testing.T) {
	h, _ := newTestBrandingHandler(t)
	keys := mustKeys(t)
	protected := middleware.RequireAuth(keys)(middleware.RequirePermission("branding.admin")(http.HandlerFunc(h.Put)))

	body, _ := json.Marshal(map[string]string{"app_name": "CarePyre"})
	req := httptest.NewRequest(http.MethodPut, "/api/v1/branding", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+tokenWithPerms(t, keys, 1)) // no permission
	rr := httptest.NewRecorder()
	protected.ServeHTTP(rr, req)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("expected 403 without branding.admin, got %d: %s", rr.Code, rr.Body.String())
	}
}

func TestBrandingHandler_PutAndGetRoundtrip(t *testing.T) {
	h, _ := newTestBrandingHandler(t)
	keys, _ := jwt.GenerateKeys()
	protected := middleware.RequireAuth(keys)(middleware.RequirePermission("branding.admin")(http.HandlerFunc(h.Put)))

	body, _ := json.Marshal(map[string]string{
		"app_name":      "CarePyre",
		"tagline":       "From the Ashes of Crisis to Sovereign Infrastructure",
		"primary_color": "#3fa9dc",
		"accent_color":  "#f0663a",
	})
	req := httptest.NewRequest(http.MethodPut, "/api/v1/branding", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+tokenWithPerms(t, keys, 1, "branding.admin"))
	rr := httptest.NewRecorder()
	protected.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("put: status = %d, body = %s", rr.Code, rr.Body.String())
	}

	getReq := httptest.NewRequest(http.MethodGet, "/api/v1/branding", nil)
	getRR := httptest.NewRecorder()
	h.Get(getRR, getReq)
	var got map[string]any
	if err := json.Unmarshal(getRR.Body.Bytes(), &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got["app_name"] != "CarePyre" || got["accent_color"] != "#f0663a" {
		t.Fatalf("expected roundtripped CarePyre branding, got %+v", got)
	}
}

func mustKeys(t *testing.T) *jwt.Keys {
	t.Helper()
	keys, err := jwt.GenerateKeys()
	if err != nil {
		t.Fatalf("generate keys: %v", err)
	}
	return keys
}

func tokenWithPerms(t *testing.T, keys *jwt.Keys, localUID int, perms ...string) string {
	t.Helper()
	claims := map[string]any{
		"sub":       "local:" + itoaTest(localUID),
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
