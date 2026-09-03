package handlers_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"idunapro/internal/auth/jwt"
	"idunapro/internal/http/handlers"
)

func TestHealthHandler(t *testing.T) {
	h := &handlers.HealthHandler{}
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest("GET", "/health", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
	var resp map[string]any
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("json decode: %v", err)
	}
	if resp["ok"] != true {
		t.Errorf("ok: expected true, got %v", resp["ok"])
	}
	if resp["service"] != "iduna" {
		t.Errorf("service: expected iduna, got %v", resp["service"])
	}
}

func TestJWKSHandler(t *testing.T) {
	k, err := jwt.GenerateKeys()
	if err != nil {
		t.Fatalf("generate keys: %v", err)
	}
	h := &handlers.JWKSHandler{Keys: k}
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest("GET", "/.well-known/jwks.json", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
	if cc := rr.Header().Get("Cache-Control"); cc == "" {
		t.Error("expected Cache-Control header")
	}
	var resp map[string]any
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("json decode: %v", err)
	}
	keys, ok := resp["keys"].([]any)
	if !ok || len(keys) == 0 {
		t.Fatal("expected keys array in JWKS response")
	}
}
