package jwt_test

import (
	"testing"
	"time"

	"idunapro/internal/auth/jwt"
)

func TestSignAndVerify(t *testing.T) {
	k, err := jwt.GenerateKeys()
	if err != nil {
		t.Fatalf("GenerateKeys: %v", err)
	}
	claims := map[string]any{
		"sub": "user-123",
		"exp": float64(time.Now().Add(time.Hour).Unix()),
		"iss": "iduna",
	}
	token, err := jwt.Sign(k, claims)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	got, err := jwt.Verify(k, token)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if got["sub"] != "user-123" {
		t.Errorf("sub: got %v, want user-123", got["sub"])
	}
}

func TestVerifyExpired(t *testing.T) {
	k, err := jwt.GenerateKeys()
	if err != nil {
		t.Fatalf("GenerateKeys: %v", err)
	}
	claims := map[string]any{
		"sub": "user-123",
		"exp": float64(time.Now().Add(-time.Hour).Unix()),
	}
	token, err := jwt.Sign(k, claims)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	_, err = jwt.Verify(k, token)
	if err == nil {
		t.Fatal("expected error for expired token, got nil")
	}
}

func TestWrongKey(t *testing.T) {
	k1, _ := jwt.GenerateKeys()
	k2, _ := jwt.GenerateKeys()
	claims := map[string]any{
		"sub": "user-abc",
		"exp": float64(time.Now().Add(time.Hour).Unix()),
	}
	token, _ := jwt.Sign(k1, claims)
	_, err := jwt.Verify(k2, token)
	if err == nil {
		t.Fatal("expected error when verifying with wrong key")
	}
}

func TestJWKS(t *testing.T) {
	k, _ := jwt.GenerateKeys()
	set := k.JWKS()
	keys, ok := set["keys"].([]any)
	if !ok || len(keys) == 0 {
		t.Fatal("JWKS: expected keys array")
	}
	entry := keys[0].(map[string]any)
	if entry["kty"] != "EC" {
		t.Errorf("kty: got %v, want EC", entry["kty"])
	}
	if entry["alg"] != "ES256" {
		t.Errorf("alg: got %v, want ES256", entry["alg"])
	}
}
