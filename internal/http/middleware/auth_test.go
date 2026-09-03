package middleware_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"idunapro/internal/auth"
	"idunapro/internal/auth/jwt"
	"idunapro/internal/http/middleware"
)

// fakeAgentStatus is a minimal middleware.AgentStatusChecker fake -- an
// in-memory agent-ID -> agent map, for exercising RequireCookieAuth's live
// status re-check without a full store.IAMStore implementation.
type fakeAgentStatus struct {
	agents map[string]*auth.Agent // agent ID -> agent
}

func (f *fakeAgentStatus) GetAgentByID(_ context.Context, agentID string) (*auth.Agent, error) {
	a, ok := f.agents[agentID]
	if !ok {
		return nil, errors.New("agent not found")
	}
	return a, nil
}

func TestRequireAuth_NoHeader(t *testing.T) {
	k, _ := jwt.GenerateKeys()
	handler := middleware.RequireAuth(k)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
	}))
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, httptest.NewRequest("GET", "/", nil))
	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", rr.Code)
	}
}

func TestRequireAuth_ValidToken(t *testing.T) {
	k, _ := jwt.GenerateKeys()
	claims := map[string]any{
		"sub": "u1",
		"exp": float64(time.Now().Add(time.Hour).Unix()),
	}
	token, _ := jwt.Sign(k, claims)

	handler := middleware.RequireAuth(k)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sub := middleware.SubjectFromContext(r.Context())
		if sub != "u1" {
			t.Errorf("sub: got %q, want u1", sub)
		}
		w.WriteHeader(200)
	}))
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != 200 {
		t.Errorf("expected 200, got %d", rr.Code)
	}
}

func TestRequirePermission_Missing(t *testing.T) {
	k, _ := jwt.GenerateKeys()
	claims := map[string]any{
		"sub":         "u1",
		"permissions": []any{"iduna.me.read"},
		"exp":         float64(time.Now().Add(time.Hour).Unix()),
	}
	token, _ := jwt.Sign(k, claims)

	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200) })
	handler := middleware.RequireAuth(k)(middleware.RequirePermission("iduna.admin")(inner))

	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusForbidden {
		t.Errorf("expected 403, got %d", rr.Code)
	}
}

func TestRequireCookieAuth_NoRefreshWhenFresh(t *testing.T) {
	k, _ := jwt.GenerateKeys()
	sessionTTL := time.Hour
	claims := map[string]any{
		"sub": "u1",
		"exp": float64(time.Now().Add(sessionTTL).Unix()), // fresh: full TTL remaining
	}
	token, _ := jwt.Sign(k, claims)

	handler := middleware.RequireCookieAuth(k, nil, "/admin/login", sessionTTL)(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200) }))

	req := httptest.NewRequest("GET", "/admin", nil)
	req.AddCookie(&http.Cookie{Name: "iduna_session", Value: token})
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != 200 {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
	if got := rr.Result().Cookies(); len(got) != 0 {
		t.Errorf("expected no refreshed cookie for a fresh session, got %d Set-Cookie header(s)", len(got))
	}
}

func TestRequireCookieAuth_RefreshesWhenStale(t *testing.T) {
	k, _ := jwt.GenerateKeys()
	sessionTTL := time.Hour
	origExp := time.Now().Add(10 * time.Minute) // within the < TTL/2 refresh window
	claims := map[string]any{
		"sub": "u1",
		"exp": float64(origExp.Unix()),
	}
	token, _ := jwt.Sign(k, claims)

	handler := middleware.RequireCookieAuth(k, nil, "/admin/login", sessionTTL)(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200) }))

	req := httptest.NewRequest("GET", "/admin", nil)
	req.AddCookie(&http.Cookie{Name: "iduna_session", Value: token})
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != 200 {
		t.Fatalf("expected 200 (request in flight should succeed even while refreshing), got %d", rr.Code)
	}
	cookies := rr.Result().Cookies()
	if len(cookies) != 1 || cookies[0].Name != "iduna_session" {
		t.Fatalf("expected exactly one refreshed iduna_session cookie, got %+v", cookies)
	}
	newClaims, err := jwt.Verify(k, cookies[0].Value)
	if err != nil {
		t.Fatalf("refreshed cookie did not verify: %v", err)
	}
	newExp := int64(newClaims["exp"].(float64))
	if newExp <= origExp.Unix() {
		t.Errorf("refreshed exp %d should be later than original exp %d", newExp, origExp.Unix())
	}
	if sub, _ := newClaims["sub"].(string); sub != "u1" {
		t.Errorf("refreshed token lost claims: sub=%q", sub)
	}
}

func TestRequireCookieAuth_NoRefreshWhenTTLZero(t *testing.T) {
	k, _ := jwt.GenerateKeys()
	claims := map[string]any{
		"sub": "u1",
		"exp": float64(time.Now().Add(time.Minute).Unix()), // about to expire
	}
	token, _ := jwt.Sign(k, claims)

	handler := middleware.RequireCookieAuth(k, nil, "/admin/login", 0)(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200) }))

	req := httptest.NewRequest("GET", "/admin", nil)
	req.AddCookie(&http.Cookie{Name: "iduna_session", Value: token})
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if got := rr.Result().Cookies(); len(got) != 0 {
		t.Errorf("sessionTTL=0 should disable refresh entirely, got %d Set-Cookie header(s)", len(got))
	}
}

func TestRequireCookieAuth_ExpiredRedirects(t *testing.T) {
	k, _ := jwt.GenerateKeys()
	claims := map[string]any{
		"sub": "u1",
		"exp": float64(time.Now().Add(-time.Minute).Unix()), // already expired
	}
	token, _ := jwt.Sign(k, claims)

	handler := middleware.RequireCookieAuth(k, nil, "/admin/login", time.Hour)(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200) }))

	req := httptest.NewRequest("GET", "/admin", nil)
	req.Header.Set("Accept", "text/html")
	req.AddCookie(&http.Cookie{Name: "iduna_session", Value: token})
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusSeeOther {
		t.Fatalf("expected 303 redirect for expired session, got %d", rr.Code)
	}
	if loc := rr.Header().Get("Location"); loc != "/admin/login?next=%2Fadmin" {
		t.Errorf("unexpected redirect location: %q", loc)
	}
}

func TestRequirePermission_Present(t *testing.T) {
	k, _ := jwt.GenerateKeys()
	claims := map[string]any{
		"sub":         "u1",
		"permissions": []any{"iduna.admin", "iduna.me.read"},
		"exp":         float64(time.Now().Add(time.Hour).Unix()),
	}
	token, _ := jwt.Sign(k, claims)

	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200) })
	handler := middleware.RequireAuth(k)(middleware.RequirePermission("iduna.admin")(inner))

	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != 200 {
		t.Errorf("expected 200, got %d", rr.Code)
	}
}

// TestRequireCookieAuth_SuspendedAgentSessionRejected is the regression test
// for the vulnerability disclosed 2026-08-25 ("Mid-Piano Presents: The Memory
// Ceremony"): a suspend correctly blocked new logins, but did nothing to a
// session already handed out -- a suspended admin with an open tab could
// keep clicking, including using that same admin access to un-suspend
// itself right back. This test fails against the pre-fix RequireCookieAuth
// (which never re-checked live agent status) and passes against the fix.
func TestRequireCookieAuth_SuspendedAgentSessionRejected(t *testing.T) {
	k, _ := jwt.GenerateKeys()
	agentID := "agent-boots"
	claims := map[string]any{
		"sub":         agentID,
		"agent_name":  "BOOTS",
		"permissions": []any{"iduna.admin"},
		"exp":         float64(time.Now().Add(time.Hour).Unix()),
	}
	token, _ := jwt.Sign(k, claims)

	store := &fakeAgentStatus{agents: map[string]*auth.Agent{
		agentID: {ID: agentID, Name: "BOOTS", Status: "ACTIVE", Permissions: []string{"iduna.admin"}},
	}}
	handler := middleware.RequireCookieAuth(k, store, "/admin/login", time.Hour)(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200) }))

	// Step 1: the session is issued while the agent is ACTIVE -- it works,
	// same as any normal admin request.
	req := httptest.NewRequest("GET", "/admin", nil)
	req.AddCookie(&http.Cookie{Name: "iduna_session", Value: token})
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != 200 {
		t.Fatalf("expected 200 while agent is ACTIVE, got %d", rr.Code)
	}

	// Step 2: the agent gets suspended (e.g. its secret leaked) -- but the
	// browser still holds the exact same, still-cryptographically-valid
	// session cookie from step 1. Nothing about the token itself changed.
	store.agents[agentID].Status = "SUSPENDED"

	req2 := httptest.NewRequest("GET", "/admin", nil)
	req2.AddCookie(&http.Cookie{Name: "iduna_session", Value: token})
	rr2 := httptest.NewRecorder()
	handler.ServeHTTP(rr2, req2)

	if rr2.Code == 200 {
		t.Fatalf("suspended agent's pre-existing session must NOT still work (this is the vulnerability) -- got 200")
	}
	// Also confirm the dead session's cookie gets cleared, not just this one
	// request rejected, so the browser stops re-presenting it.
	cleared := false
	for _, c := range rr2.Result().Cookies() {
		if c.Name == "iduna_session" && c.MaxAge < 0 {
			cleared = true
		}
	}
	if !cleared {
		t.Errorf("expected the dead session cookie to be cleared on rejection, got %+v", rr2.Result().Cookies())
	}
}

// TestRequireCookieAuth_RevokedPermissionTakesEffectImmediately covers the
// related half of the same fix: permissions are re-derived from live grants
// on every request, not trusted from the token's snapshot at login, so a
// revoked permission also stops working on the very next click.
func TestRequireCookieAuth_RevokedPermissionTakesEffectImmediately(t *testing.T) {
	k, _ := jwt.GenerateKeys()
	agentID := "agent-x"
	claims := map[string]any{
		"sub":         agentID,
		"permissions": []any{"iduna.admin"}, // stale snapshot from login time
		"exp":         float64(time.Now().Add(time.Hour).Unix()),
	}
	token, _ := jwt.Sign(k, claims)

	store := &fakeAgentStatus{agents: map[string]*auth.Agent{
		// Live grants no longer include iduna.admin, even though the token does.
		agentID: {ID: agentID, Name: "X", Status: "ACTIVE", Permissions: []string{}},
	}}
	handler := middleware.RequireCookieAuth(k, store, "/admin/login", time.Hour)(
		middleware.RequirePermission("iduna.admin")(
			http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200) })))

	req := httptest.NewRequest("GET", "/admin", nil)
	req.AddCookie(&http.Cookie{Name: "iduna_session", Value: token})
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Errorf("expected 403 once the live grant is gone (even though the token's own claims still say iduna.admin), got %d", rr.Code)
	}
}

// TestRequireCookieAuth_HumanGoogleSessionNotTreatedAsAgent is the
// regression test for a real bug found wiring up the notebook portal's
// human SSO cookie login the same session as the two tests above: a human
// Google-login session (GoogleAuthHandler's own claims -- "sub" is a user
// ID, never an agent ID, and always carries "email") was being run through
// the SAME iamStore.GetAgentByID live-recheck built for agent sessions.
// GetAgentByID only looks in the agents table, so it always misses for a
// human user's "sub" -- every human cookie session would be incorrectly
// bounced back to login on every single request, indistinguishable from a
// suspended agent. This test fails against that version (302/303 + cleared
// cookie instead of 200) and passes against the fix (iamStore is only
// consulted when the session claims don't carry "email").
func TestRequireCookieAuth_HumanGoogleSessionNotTreatedAsAgent(t *testing.T) {
	k, _ := jwt.GenerateKeys()
	userID := "user-founder"
	claims := map[string]any{
		"sub":         userID,
		"email":       "founder@example.com",
		"permissions": []any{"devportal.access"},
		"exp":         float64(time.Now().Add(time.Hour).Unix()),
	}
	token, _ := jwt.Sign(k, claims)

	// Deliberately empty -- no agent named userID exists (nor should one:
	// this is a human user ID, not an agent ID). If RequireCookieAuth ever
	// calls GetAgentByID for this session, it MUST miss.
	store := &fakeAgentStatus{agents: map[string]*auth.Agent{}}
	handler := middleware.RequireCookieAuth(k, store, "/portal/login", time.Hour)(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200) }))

	req := httptest.NewRequest("GET", "/portal", nil)
	req.AddCookie(&http.Cookie{Name: "iduna_session", Value: token})
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != 200 {
		t.Fatalf("human Google-login session must not be treated as an agent session (no matching agent row exists to find) -- got %d", rr.Code)
	}
}
