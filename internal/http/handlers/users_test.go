package handlers_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"idunapro/internal/auth/jwt"
	"idunapro/internal/http/handlers"
	"idunapro/internal/http/middleware"
	"idunapro/internal/userlog"
)

// fakeUserProjector is a minimal, real (not a no-op) in-memory UserProjector -- unlike
// stubUserProjector (built only for the local-auth login tests, whose Apply is a deliberate
// no-op), createUser's own real flow round-trips through Apply+GetByUID to build its response,
// so this test needs a projector that actually applies EventUserCreated.
type fakeUserProjector struct {
	byUID map[int]*userlog.LocalUser
	next  int
}

func (p *fakeUserProjector) Apply(_ context.Context, rec userlog.Record) error {
	if rec.Event.Type != userlog.EventUserCreated {
		return nil
	}
	var d userlog.UserCreatedData
	if err := json.Unmarshal(rec.Event.Data, &d); err != nil {
		return err
	}
	p.byUID[d.LocalUID] = &userlog.LocalUser{
		LocalUID: d.LocalUID, Email: d.Email, DisplayName: d.DisplayName,
		PasswordHash: d.PasswordHash, Status: "active",
	}
	return nil
}
func (p *fakeUserProjector) Cursor(context.Context) (uint64, error)      { return 0, nil }
func (p *fakeUserProjector) AdvanceCursor(context.Context, uint64) error { return nil }
func (p *fakeUserProjector) GetByUID(_ context.Context, uid int) (*userlog.LocalUser, error) {
	return p.byUID[uid], nil
}
func (p *fakeUserProjector) GetByEmail(_ context.Context, email string) (*userlog.LocalUser, error) {
	for _, u := range p.byUID {
		if u.Email == email {
			return u, nil
		}
	}
	return nil, nil
}
func (p *fakeUserProjector) ListUsers(context.Context, int) ([]userlog.LocalUser, error) {
	out := make([]userlog.LocalUser, 0, len(p.byUID))
	for _, u := range p.byUID {
		out = append(out, *u)
	}
	return out, nil
}
func (p *fakeUserProjector) NextUID(context.Context) (int, error) {
	p.next++
	return p.next, nil
}
func (p *fakeUserProjector) ScrubPII(context.Context, int) error { return nil }

// CP-HIPAA-1: a provider (mail-accounts.provision) can now create a participant's local user
// record -- the real, necessary first half of "providers can create email accounts for
// participants" (a mailbox needs a local_uid to link to). These tests cover the real
// access-control change: create is now reachable by either permission, but list/update/delete
// stay users.admin-only, so a provider still can't browse or manage every other participant.

func newTestUsersHandler(t *testing.T, keys *jwt.Keys) http.Handler {
	t.Helper()
	eventLog, err := userlog.NewFileEventLog(t.TempDir())
	if err != nil {
		t.Fatalf("NewFileEventLog: %v", err)
	}
	t.Cleanup(func() { _ = eventLog.Close() })
	proj := &fakeUserProjector{byUID: map[int]*userlog.LocalUser{}}
	h := &handlers.UsersHandler{Log: eventLog, Proj: proj}
	return middleware.RequireAuth(keys)(h)
}

func TestUsersHandler_ProviderCanCreateAParticipant(t *testing.T) {
	keys, _ := jwt.GenerateKeys()
	h := newTestUsersHandler(t, keys)
	token := mailAccountsToken(t, keys, 1, "mail-accounts.provision") // no users.admin

	body, _ := json.Marshal(map[string]string{"email": "participant@example.com", "password": "a-real-password", "display_name": "Participant One"})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/users", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusCreated {
		t.Fatalf("expected 201 creating a participant as a provider, got %d: %s", rr.Code, rr.Body.String())
	}
}

func TestUsersHandler_ProviderCannotListUsers(t *testing.T) {
	keys, _ := jwt.GenerateKeys()
	h := newTestUsersHandler(t, keys)
	token := mailAccountsToken(t, keys, 1, "mail-accounts.provision") // no users.admin

	req := httptest.NewRequest(http.MethodGet, "/api/v1/users", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("expected 403 listing all users as a provider (minimum necessary -- not their call to browse every participant), got %d: %s", rr.Code, rr.Body.String())
	}
}

func TestUsersHandler_NeitherPermissionCannotCreate(t *testing.T) {
	keys, _ := jwt.GenerateKeys()
	h := newTestUsersHandler(t, keys)
	token := mailAccountsToken(t, keys, 1) // neither permission

	body, _ := json.Marshal(map[string]string{"email": "nope@example.com", "password": "a-real-password"})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/users", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("expected 403 creating a user with neither permission, got %d: %s", rr.Code, rr.Body.String())
	}
}
