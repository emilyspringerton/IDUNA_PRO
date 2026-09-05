package handlers_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"

	"idunapro/internal/auth/jwt"
	"idunapro/internal/http/handlers"
	"idunapro/internal/http/middleware"
	"idunapro/internal/userlog"
)

func changePasswordHandlerWithAuth(t *testing.T, keys *jwt.Keys, proj *stubUserProjector) (http.Handler, *userlog.FileEventLog) {
	t.Helper()
	eventLog, err := userlog.NewFileEventLog(t.TempDir())
	if err != nil {
		t.Fatalf("NewFileEventLog: %v", err)
	}
	t.Cleanup(func() { _ = eventLog.Close() })
	h := &handlers.ChangePasswordHandler{Log: eventLog, Proj: proj}
	return middleware.RequireAuth(keys)(h), eventLog
}

func changePasswordRequest(t *testing.T, h http.Handler, keys *jwt.Keys, localUID int, current, newPass string) *httptest.ResponseRecorder {
	t.Helper()
	token, err := jwt.Sign(keys, map[string]any{
		"sub":       "local:1",
		"local_uid": localUID,
		"exp":       time.Now().Add(time.Hour).Unix(),
	})
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	body, _ := json.Marshal(map[string]string{"current_password": current, "new_password": newPass})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/change-password", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	return w
}

// TestChangePassword_SelfServiceWithoutAdminPermission is the real, decisive regression test
// for the found-live gap CP-SIP-1244543543 named directly: a regular local user (no
// users.admin) previously had no way to change their own password at all, since
// PATCH /api/v1/users/{uid} requires users.admin with no self-access carve-out.
func TestChangePassword_SelfServiceWithoutAdminPermission(t *testing.T) {
	keys, err := jwt.GenerateKeys()
	if err != nil {
		t.Fatalf("generate keys: %v", err)
	}
	proj := &stubUserProjector{byUID: map[int]*userlog.LocalUser{
		1: {LocalUID: 1, Email: "user@example.com", Status: "active",
			PasswordHash: mustHash(t, "old-real-password")},
	}}
	h, eventLog := changePasswordHandlerWithAuth(t, keys, proj)

	// No users.admin permission on this JWT at all -- proves this route needs none.
	w := changePasswordRequest(t, h, keys, 1, "old-real-password", "a-real-new-password")
	if w.Code != http.StatusOK {
		t.Fatalf("change password: status = %d, body = %s, want 200", w.Code, w.Body.String())
	}
	// Real, meaningful verification: read back the actual event this handler appended (the
	// stub projector's own Apply is a no-op, same as this package's other handler tests already
	// work around -- see TestLocalAuthHandler_EmitsEvents) and confirm its real bcrypt hash
	// verifies against the NEW password and NOT the old one.
	recs, err := eventLog.ReadFrom(context.Background(), 0, 10)
	if err != nil {
		t.Fatalf("ReadFrom: %v", err)
	}
	if len(recs) != 1 || recs[0].Event.Type != userlog.EventUserPasswordReset {
		t.Fatalf("expected 1 local_user.password_reset event, got %+v", recs)
	}
	var data userlog.UserPasswordResetData
	if err := json.Unmarshal(recs[0].Event.Data, &data); err != nil {
		t.Fatalf("unmarshal event data: %v", err)
	}
	if err := bcrypt.CompareHashAndPassword([]byte(data.PasswordHash), []byte("a-real-new-password")); err != nil {
		t.Fatalf("emitted hash does not match the new password: %v", err)
	}
	if err := bcrypt.CompareHashAndPassword([]byte(data.PasswordHash), []byte("old-real-password")); err == nil {
		t.Fatalf("emitted hash still matches the OLD password")
	}
}

// TestChangePassword_WrongCurrentPasswordRejected -- a real, honest verification: you must know
// the CURRENT password to change it, a valid JWT alone is not enough.
func TestChangePassword_WrongCurrentPasswordRejected(t *testing.T) {
	keys, err := jwt.GenerateKeys()
	if err != nil {
		t.Fatalf("generate keys: %v", err)
	}
	proj := &stubUserProjector{byUID: map[int]*userlog.LocalUser{
		1: {LocalUID: 1, Email: "user@example.com", Status: "active",
			PasswordHash: mustHash(t, "the-real-password")},
	}}
	h, _ := changePasswordHandlerWithAuth(t, keys, proj)

	w := changePasswordRequest(t, h, keys, 1, "totally-wrong-guess", "a-real-new-password")
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("wrong current password: status = %d, want 401", w.Code)
	}
}

// TestChangePassword_RejectsShortNewPassword -- a real, minimal strength floor.
func TestChangePassword_RejectsShortNewPassword(t *testing.T) {
	keys, err := jwt.GenerateKeys()
	if err != nil {
		t.Fatalf("generate keys: %v", err)
	}
	proj := &stubUserProjector{byUID: map[int]*userlog.LocalUser{
		1: {LocalUID: 1, Email: "user@example.com", Status: "active",
			PasswordHash: mustHash(t, "the-real-password")},
	}}
	h, _ := changePasswordHandlerWithAuth(t, keys, proj)

	w := changePasswordRequest(t, h, keys, 1, "the-real-password", "short")
	if w.Code != http.StatusBadRequest {
		t.Fatalf("too-short new password: status = %d, want 400", w.Code)
	}
}
