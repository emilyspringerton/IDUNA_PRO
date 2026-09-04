package handlers_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"idunapro/internal/auth/jwt"
	"idunapro/internal/http/handlers"
	"idunapro/internal/http/middleware"
	"idunapro/internal/userlog"
)

func meRequest(t *testing.T, h http.Handler, keys *jwt.Keys, sub string) *httptest.ResponseRecorder {
	t.Helper()
	token, err := jwt.Sign(keys, map[string]any{
		"sub": sub,
		"exp": time.Now().Add(time.Hour).Unix(),
	})
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	req := httptest.NewRequest(http.MethodGet, "/api/v1/identities/me", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	return w
}

// TestMeHandler_LocalUser_ResolvesRealIdentity is the real, decisive regression test for the
// found-live gap (cruise-queue card 9988): a local-auth JWT's sub ("local:<uid>") used to 404
// unconditionally against MeHandler because it queried the wrong table entirely.
func TestMeHandler_LocalUser_ResolvesRealIdentity(t *testing.T) {
	keys, err := jwt.GenerateKeys()
	if err != nil {
		t.Fatalf("generate keys: %v", err)
	}
	proj := &stubUserProjector{byUID: map[int]*userlog.LocalUser{
		1: {LocalUID: 1, Email: "alice@example.com", DisplayName: "Alice", Status: "active"},
	}}
	h := middleware.RequireAuth(keys)(&handlers.MeHandler{Proj: proj})

	w := meRequest(t, h, keys, "local:1")
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200, body = %s", w.Code, w.Body.String())
	}
	var resp struct {
		Identity struct {
			ID       string `json:"id"`
			Email    string `json:"email"`
			Gamertag string `json:"gamertag"`
		} `json:"identity"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.Identity.Email != "alice@example.com" {
		t.Errorf("email = %q, want alice@example.com", resp.Identity.Email)
	}
	if resp.Identity.ID != "local:1" {
		t.Errorf("id = %q, want local:1", resp.Identity.ID)
	}
}

func TestMeHandler_LocalUser_UnknownUID_404s(t *testing.T) {
	keys, err := jwt.GenerateKeys()
	if err != nil {
		t.Fatalf("generate keys: %v", err)
	}
	proj := &stubUserProjector{byUID: map[int]*userlog.LocalUser{}}
	h := middleware.RequireAuth(keys)(&handlers.MeHandler{Proj: proj})

	w := meRequest(t, h, keys, "local:999")
	if w.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404, body = %s", w.Code, w.Body.String())
	}
}

func TestMeHandler_LocalUser_Webmaster_GetsKanbanAccess(t *testing.T) {
	keys, err := jwt.GenerateKeys()
	if err != nil {
		t.Fatalf("generate keys: %v", err)
	}
	proj := &stubUserProjector{byUID: map[int]*userlog.LocalUser{
		0: {LocalUID: 0, Email: "webmaster@example.com", Status: "active"},
	}}
	h := middleware.RequireAuth(keys)(&handlers.MeHandler{Proj: proj})

	w := meRequest(t, h, keys, "local:0")
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200, body = %s", w.Code, w.Body.String())
	}
	var resp struct {
		RBAC struct {
			EffectivePermissions []string `json:"effective_permissions"`
		} `json:"rbac"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	found := false
	for _, p := range resp.RBAC.EffectivePermissions {
		if p == "kanban.access" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected webmaster's own /me response to carry kanban.access, got %v", resp.RBAC.EffectivePermissions)
	}
}

func TestMeHandler_LocalUser_NoProjector_404sNotPanics(t *testing.T) {
	keys, err := jwt.GenerateKeys()
	if err != nil {
		t.Fatalf("generate keys: %v", err)
	}
	h := middleware.RequireAuth(keys)(&handlers.MeHandler{}) // Proj deliberately nil

	w := meRequest(t, h, keys, "local:1")
	if w.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404 (not a panic), body = %s", w.Code, w.Body.String())
	}
}
