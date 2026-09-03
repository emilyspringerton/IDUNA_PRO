package handlers_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"idunapro/internal/auth/jwt"
	"idunapro/internal/http/handlers"
)

func makeTestKeysRefresh(t *testing.T) *jwt.Keys {
	t.Helper()
	k, err := jwt.GenerateKeys()
	if err != nil {
		t.Fatalf("GenerateKeys: %v", err)
	}
	return k
}

func signTestToken(t *testing.T, keys *jwt.Keys, extra map[string]any) string {
	t.Helper()
	claims := map[string]any{
		"sub":         "local:1",
		"email":       "test@example.com",
		"permissions": []string{"iduna.me.read"},
		"iss":         "https://iam.test",
		"aud":         "farthq-ecosystem",
		"exp":         time.Now().UTC().Add(8 * time.Hour).Unix(),
	}
	for k, v := range extra {
		claims[k] = v
	}
	tok, err := jwt.Sign(keys, claims)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	return tok
}

func TestRefreshSuccess(t *testing.T) {
	keys := makeTestKeysRefresh(t)
	h := &handlers.RefreshHandler{Keys: keys, Issuer: "https://iam.test"}

	token := signTestToken(t, keys, nil)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/refresh", bytes.NewReader(nil))
	req.Header.Set("Authorization", "Bearer "+token)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("want 200, got %d: %s", rr.Code, rr.Body.String())
	}
	var resp struct {
		Token     string `json:"token"`
		ExpiresAt int64  `json:"expires_at"`
	}
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp.Token == "" {
		t.Error("expected non-empty token in response")
	}
	if resp.ExpiresAt == 0 {
		t.Error("expected non-zero expires_at")
	}
	// New token should be verifiable.
	newClaims, err := jwt.Verify(keys, resp.Token)
	if err != nil {
		t.Fatalf("new token verify failed: %v", err)
	}
	if newClaims["sub"] != "local:1" {
		t.Errorf("sub not preserved: got %v", newClaims["sub"])
	}
}

func TestRefreshPreservesClaims(t *testing.T) {
	keys := makeTestKeysRefresh(t)
	h := &handlers.RefreshHandler{Keys: keys, Issuer: "https://iam.test"}

	token := signTestToken(t, keys, map[string]any{"email": "emily@einhorn.io"})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/refresh", bytes.NewReader(nil))
	req.Header.Set("Authorization", "Bearer "+token)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("want 200, got %d", rr.Code)
	}
	var resp struct{ Token string `json:"token"` }
	json.NewDecoder(rr.Body).Decode(&resp)
	newClaims, _ := jwt.Verify(keys, resp.Token)
	if newClaims["email"] != "emily@einhorn.io" {
		t.Errorf("email not preserved: got %v", newClaims["email"])
	}
}

func TestRefreshMethodNotAllowed(t *testing.T) {
	keys := makeTestKeysRefresh(t)
	h := &handlers.RefreshHandler{Keys: keys}
	req := httptest.NewRequest(http.MethodGet, "/api/v1/auth/refresh", nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusMethodNotAllowed {
		t.Errorf("want 405, got %d", rr.Code)
	}
}

func TestRefreshMissingToken(t *testing.T) {
	keys := makeTestKeysRefresh(t)
	h := &handlers.RefreshHandler{Keys: keys}
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/refresh", bytes.NewReader(nil))
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Errorf("want 401, got %d", rr.Code)
	}
}

func TestRefreshInvalidToken(t *testing.T) {
	keys := makeTestKeysRefresh(t)
	h := &handlers.RefreshHandler{Keys: keys}
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/refresh", bytes.NewReader(nil))
	req.Header.Set("Authorization", "Bearer notavalidjwt")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Errorf("want 401, got %d", rr.Code)
	}
}

func TestRefreshExpiredToken(t *testing.T) {
	keys := makeTestKeysRefresh(t)
	h := &handlers.RefreshHandler{Keys: keys}
	token := signTestToken(t, keys, map[string]any{
		"exp": time.Now().UTC().Add(-1 * time.Hour).Unix(), // already expired
	})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/refresh", bytes.NewReader(nil))
	req.Header.Set("Authorization", "Bearer "+token)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Errorf("want 401 for expired token, got %d", rr.Code)
	}
}

func TestRefreshNewExpiry(t *testing.T) {
	keys := makeTestKeysRefresh(t)
	h := &handlers.RefreshHandler{Keys: keys}
	token := signTestToken(t, keys, nil)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/refresh", bytes.NewReader(nil))
	req.Header.Set("Authorization", "Bearer "+token)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("want 200, got %d", rr.Code)
	}
	var resp struct{ ExpiresAt int64 `json:"expires_at"` }
	json.NewDecoder(rr.Body).Decode(&resp)
	minExpiry := time.Now().Add(7 * time.Hour).Unix()
	if resp.ExpiresAt < minExpiry {
		t.Errorf("expires_at too soon: got %d, want >= %d", resp.ExpiresAt, minExpiry)
	}
}
