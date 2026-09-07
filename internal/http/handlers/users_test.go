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
	switch rec.Event.Type {
	case userlog.EventUserCreated:
		var d userlog.UserCreatedData
		if err := json.Unmarshal(rec.Event.Data, &d); err != nil {
			return err
		}
		p.byUID[d.LocalUID] = &userlog.LocalUser{
			LocalUID: d.LocalUID, Email: d.Email, DisplayName: d.DisplayName,
			PasswordHash: d.PasswordHash, Status: "active",
		}
	case userlog.EventUserStatusChanged:
		var d userlog.UserStatusChangedData
		if err := json.Unmarshal(rec.Event.Data, &d); err != nil {
			return err
		}
		if u := p.byUID[d.LocalUID]; u != nil {
			u.Status = d.NewStatus
		}
	case userlog.EventUserAdminChanged:
		var d userlog.UserAdminChangedData
		if err := json.Unmarshal(rec.Event.Data, &d); err != nil {
			return err
		}
		if u := p.byUID[d.LocalUID]; u != nil {
			u.IsAdmin = d.IsAdmin
		}
	case userlog.EventUserOperatorAdminChanged:
		var d userlog.UserOperatorAdminChangedData
		if err := json.Unmarshal(rec.Event.Data, &d); err != nil {
			return err
		}
		if u := p.byUID[d.LocalUID]; u != nil {
			u.IsOperatorAdmin = d.IsOperatorAdmin
		}
	case userlog.EventUserProviderChanged:
		var d userlog.UserProviderChangedData
		if err := json.Unmarshal(rec.Event.Data, &d); err != nil {
			return err
		}
		if u := p.byUID[d.LocalUID]; u != nil {
			u.IsProvider = d.IsProvider
		}
	case userlog.EventUserProviderAdminChanged:
		var d userlog.UserProviderAdminChangedData
		if err := json.Unmarshal(rec.Event.Data, &d); err != nil {
			return err
		}
		if u := p.byUID[d.LocalUID]; u != nil {
			u.IsProviderAdmin = d.IsProviderAdmin
		}
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

// CP-HIPAA-2: the real 4-tier hierarchy -- Top Admin, Operator Admin, Provider Admin, Provider
// Operator. These tests cover the one restriction the founder named directly: an Operator Admin
// cannot modify or disable another admin-tier account (only a Top Admin can), plus the narrower
// field scope a Provider-Admin-only caller gets.

func newTierTestHandler(t *testing.T, keys *jwt.Keys, seed map[int]*userlog.LocalUser) http.Handler {
	t.Helper()
	eventLog, err := userlog.NewFileEventLog(t.TempDir())
	if err != nil {
		t.Fatalf("NewFileEventLog: %v", err)
	}
	t.Cleanup(func() { _ = eventLog.Close() })
	proj := &fakeUserProjector{byUID: seed}
	h := &handlers.UsersHandler{Log: eventLog, Proj: proj}
	return middleware.RequireAuth(keys)(h)
}

func patchUser(t *testing.T, h http.Handler, token string, uid int, body map[string]any) *httptest.ResponseRecorder {
	t.Helper()
	b, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPatch, "/api/v1/users/"+itoaTest(uid), bytes.NewReader(b))
	req.Header.Set("Authorization", "Bearer "+token)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	return rr
}

func itoaTest(n int) string {
	b, _ := json.Marshal(n)
	return string(b)
}

func TestUsersHandler_OperatorAdminCannotSuspendAnotherOperatorAdmin(t *testing.T) {
	keys, _ := jwt.GenerateKeys()
	seed := map[int]*userlog.LocalUser{
		2: {LocalUID: 2, Email: "op1@example.com", Status: "active", IsOperatorAdmin: true},
		3: {LocalUID: 3, Email: "op2@example.com", Status: "active", IsOperatorAdmin: true},
	}
	h := newTierTestHandler(t, keys, seed)
	// Caller is uid 2, an Operator Admin (users.admin, no admins.manage).
	token := mailAccountsToken(t, keys, 2, "users.admin")

	rr := patchUser(t, h, token, 3, map[string]any{"status": "suspended"})
	if rr.Code != http.StatusForbidden {
		t.Fatalf("expected 403 -- an Operator Admin must not be able to suspend another Operator Admin, got %d: %s", rr.Code, rr.Body.String())
	}
}

func TestUsersHandler_TopAdminCanSuspendAnOperatorAdmin(t *testing.T) {
	keys, _ := jwt.GenerateKeys()
	seed := map[int]*userlog.LocalUser{
		3: {LocalUID: 3, Email: "op2@example.com", Status: "active", IsOperatorAdmin: true},
	}
	h := newTierTestHandler(t, keys, seed)
	// Caller holds admins.manage -- the real Top Admin marker.
	token := mailAccountsToken(t, keys, 1, "users.admin", "admins.manage")

	rr := patchUser(t, h, token, 3, map[string]any{"status": "suspended"})
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200 -- a Top Admin must be able to suspend an Operator Admin, got %d: %s", rr.Code, rr.Body.String())
	}
}

func TestUsersHandler_OperatorAdminCannotGrantAdminTierRoles(t *testing.T) {
	keys, _ := jwt.GenerateKeys()
	seed := map[int]*userlog.LocalUser{
		5: {LocalUID: 5, Email: "regular@example.com", Status: "active"},
	}
	h := newTierTestHandler(t, keys, seed)
	token := mailAccountsToken(t, keys, 2, "users.admin") // Operator Admin, no admins.manage

	rr := patchUser(t, h, token, 5, map[string]any{"is_operator_admin": true})
	if rr.Code != http.StatusForbidden {
		t.Fatalf("expected 403 -- an Operator Admin must not be able to grant admin-tier roles, got %d: %s", rr.Code, rr.Body.String())
	}
}

func TestUsersHandler_ProviderAdminCanOnlyToggleProviderRole(t *testing.T) {
	keys, _ := jwt.GenerateKeys()
	seed := map[int]*userlog.LocalUser{
		7: {LocalUID: 7, Email: "participant@example.com", Status: "active"},
	}
	h := newTierTestHandler(t, keys, seed)
	token := mailAccountsToken(t, keys, 6, "providers.manage") // Provider Admin, no users.admin

	// Allowed: granting the Provider Operator role.
	rr := patchUser(t, h, token, 7, map[string]any{"is_provider": true})
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200 -- a Provider Admin should be able to grant the provider role, got %d: %s", rr.Code, rr.Body.String())
	}
	if !seed[7].IsProvider {
		t.Fatal("expected uid 7's IsProvider to be set after the grant")
	}

	// Forbidden: everything else, e.g. suspending the account.
	rr2 := patchUser(t, h, token, 7, map[string]any{"status": "suspended"})
	if rr2.Code != http.StatusForbidden {
		t.Fatalf("expected 403 -- a Provider Admin must not be able to change status, got %d: %s", rr2.Code, rr2.Body.String())
	}
}
