package handlers_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"golang.org/x/crypto/bcrypt"

	"idunapro/internal/auth/jwt"
	"idunapro/internal/http/handlers"
	"idunapro/internal/userlog"
)

// stubUserProjector implements userlog.UserProjector with an in-memory user set, for real,
// direct testing of the email+password login handlers (LocalAuthHandler, PortalHandler's own
// LocalLogin) without a real SQL projector.
type stubUserProjector struct {
	byEmail map[string]*userlog.LocalUser
}

func (s *stubUserProjector) Apply(context.Context, userlog.Record) error       { return nil }
func (s *stubUserProjector) Cursor(context.Context) (uint64, error)            { return 0, nil }
func (s *stubUserProjector) AdvanceCursor(context.Context, uint64) error       { return nil }
func (s *stubUserProjector) GetByUID(context.Context, int) (*userlog.LocalUser, error) {
	return nil, nil
}
func (s *stubUserProjector) GetByEmail(_ context.Context, email string) (*userlog.LocalUser, error) {
	return s.byEmail[email], nil
}
func (s *stubUserProjector) ListUsers(context.Context, int) ([]userlog.LocalUser, error) {
	return nil, nil
}
func (s *stubUserProjector) NextUID(context.Context) (int, error) { return 1, nil }

func mustHash(t *testing.T, password string) string {
	t.Helper()
	h, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.MinCost)
	if err != nil {
		t.Fatalf("bcrypt.GenerateFromPassword: %v", err)
	}
	return string(h)
}

// TestLocalAuthHandler_EmitsEvents -- S226-03: a real success and a real failure (wrong
// password) both land in the unified log with the right event Type, and the failure event
// never contains the raw password.
func TestLocalAuthHandler_EmitsEvents(t *testing.T) {
	keys, err := jwt.GenerateKeys()
	if err != nil {
		t.Fatalf("generate keys: %v", err)
	}
	proj := &stubUserProjector{byEmail: map[string]*userlog.LocalUser{
		"alice@example.com": {LocalUID: 1, Email: "alice@example.com", Status: "active",
			PasswordHash: mustHash(t, "correct-horse-battery-staple")},
	}}
	eventLog, err := userlog.NewFileEventLog(t.TempDir())
	if err != nil {
		t.Fatalf("NewFileEventLog: %v", err)
	}
	t.Cleanup(func() { _ = eventLog.Close() })
	h := &handlers.LocalAuthHandler{Keys: keys, Proj: proj, EventLog: eventLog}

	post := func(email, password string) int {
		body, _ := json.Marshal(map[string]string{"email": email, "password": password})
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, httptest.NewRequest(http.MethodPost, "/api/v1/auth/local", bytes.NewReader(body)))
		return rr.Code
	}

	if code := post("alice@example.com", "correct-horse-battery-staple"); code != http.StatusOK {
		t.Fatalf("success login: status = %d, want 200", code)
	}
	if code := post("alice@example.com", "wrong-password-attempt"); code != http.StatusUnauthorized {
		t.Fatalf("failed login: status = %d, want 401", code)
	}

	recs, err := eventLog.ReadFrom(context.Background(), 0, 10)
	if err != nil {
		t.Fatalf("ReadFrom: %v", err)
	}
	if len(recs) != 2 {
		t.Fatalf("expected 2 events, got %d", len(recs))
	}
	if recs[0].Event.Type != "iduna:auth.local.success" {
		t.Errorf("event 0 Type = %q, want iduna:auth.local.success", recs[0].Event.Type)
	}
	if recs[1].Event.Type != "iduna:auth.local.failure" {
		t.Errorf("event 1 Type = %q, want iduna:auth.local.failure", recs[1].Event.Type)
	}
	if bytes.Contains(recs[1].Event.Data, []byte("wrong-password-attempt")) {
		t.Errorf("failure event must never contain the raw password, got: %s", recs[1].Event.Data)
	}
}
