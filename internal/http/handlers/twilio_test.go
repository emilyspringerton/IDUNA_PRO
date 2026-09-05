package handlers_test

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"idunapro/internal/auth/jwt"
	"idunapro/internal/http/handlers"
	"idunapro/internal/http/middleware"
	"idunapro/internal/twilio"
)

func twilioSignToken(t *testing.T, keys *jwt.Keys, perms ...string) string {
	t.Helper()
	claims := map[string]any{"sub": "local:0", "exp": time.Now().Add(time.Hour).Unix()}
	if len(perms) > 0 {
		claims["permissions"] = perms
	}
	tok, err := jwt.Sign(keys, claims)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	return tok
}

// TestTwilioHandler_RequiresTwilioAdminPermission -- a caller with no twilio.admin (even with
// other real permissions) is rejected, matching CP-SIP-242414's own "user roles iam" ask: this
// is a real, separate permission from users.admin, not folded into it.
func TestTwilioHandler_RequiresTwilioAdminPermission(t *testing.T) {
	keys, err := jwt.GenerateKeys()
	if err != nil {
		t.Fatalf("generate keys: %v", err)
	}
	h := middleware.RequireAuth(keys)(&handlers.TwilioHandler{Client: twilio.NewClient("AC1", "SK1", "secret1")})

	req := httptest.NewRequest(http.MethodGet, "/api/v1/twilio/status", nil)
	req.Header.Set("Authorization", "Bearer "+twilioSignToken(t, keys, "users.admin"))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusForbidden {
		t.Fatalf("status without twilio.admin: status = %d, want 403", w.Code)
	}
}

// TestTwilioHandler_NotConfigured -- a real, honest 503 (not a panic or a confusing empty
// response) when no real Twilio credentials are set for this deployment.
func TestTwilioHandler_NotConfigured(t *testing.T) {
	keys, err := jwt.GenerateKeys()
	if err != nil {
		t.Fatalf("generate keys: %v", err)
	}
	h := middleware.RequireAuth(keys)(&handlers.TwilioHandler{Client: twilio.NewClient("", "", "")})

	req := httptest.NewRequest(http.MethodGet, "/api/v1/twilio/status", nil)
	req.Header.Set("Authorization", "Bearer "+twilioSignToken(t, keys, "twilio.admin"))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("status with no credentials configured: status = %d, want 503", w.Code)
	}
}
