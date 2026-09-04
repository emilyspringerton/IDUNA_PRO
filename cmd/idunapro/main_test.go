package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestRunLogin_Success_PrintsToken(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/auth/local" {
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
		var req loginRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Fatalf("decode request: %v", err)
		}
		if req.Email != "test@example.com" || req.Password != "correcthorsebattery" {
			t.Fatalf("unexpected credentials: %+v", req)
		}
		json.NewEncoder(w).Encode(loginResponse{Token: "real-jwt-here", Sub: "local:1", UID: 1})
	}))
	defer srv.Close()

	code := runLogin(srv.URL, "test@example.com", "correcthorsebattery")
	if code != 0 {
		t.Fatalf("expected exit code 0, got %d", code)
	}
}

func TestRunLogin_BadCredentials_ReturnsNonZero(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()

	code := runLogin(srv.URL, "test@example.com", "wrongpassword")
	if code == 0 {
		t.Fatal("expected a non-zero exit code for bad credentials")
	}
}

func TestRunLogin_Unreachable_ReturnsNonZero(t *testing.T) {
	code := runLogin("http://127.0.0.1:1", "test@example.com", "x")
	if code == 0 {
		t.Fatal("expected a non-zero exit code for an unreachable host")
	}
}

func TestRunKanbanList_Success(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/kanban/cards" {
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
		if r.Header.Get("Authorization") != "Bearer real-token" {
			t.Fatalf("expected real bearer token, got %q", r.Header.Get("Authorization"))
		}
		json.NewEncoder(w).Encode([]kanbanCard{
			{ID: 1, Title: "Real card one", Queue: "backlog"},
			{ID: 2, Title: "Real card two", Queue: "priority"},
		})
	}))
	defer srv.Close()

	code := runKanbanList(srv.URL, "real-token", "")
	if code != 0 {
		t.Fatalf("expected exit code 0, got %d", code)
	}
}

func TestRunKanbanList_QueueFilterPassedThrough(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("queue") != "cruise" {
			t.Fatalf("expected queue=cruise in the real query string, got %q", r.URL.RawQuery)
		}
		json.NewEncoder(w).Encode([]kanbanCard{})
	}))
	defer srv.Close()

	code := runKanbanList(srv.URL, "real-token", "cruise")
	if code != 0 {
		t.Fatalf("expected exit code 0, got %d", code)
	}
}

func TestRunKanbanList_Unauthorized_ReturnsNonZero(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer srv.Close()

	code := runKanbanList(srv.URL, "bad-token", "")
	if code == 0 {
		t.Fatal("expected a non-zero exit code for a forbidden request")
	}
}

func TestRunKanbanList_Unreachable_ReturnsNonZero(t *testing.T) {
	code := runKanbanList("http://127.0.0.1:1", "real-token", "")
	if code == 0 {
		t.Fatal("expected a non-zero exit code for an unreachable host")
	}
}

func TestRunWhoami_Success(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/identities/me" {
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
		if r.Header.Get("Authorization") != "Bearer real-token" {
			t.Fatalf("expected real bearer token, got %q", r.Header.Get("Authorization"))
		}
		var resp meResponse
		resp.Identity.ID = "local:1"
		resp.Identity.Email = "alice@example.com"
		resp.Identity.Gamertag = "alice"
		resp.Identity.Status = "active"
		resp.RBAC.EffectivePermissions = []string{"iduna.me.read", "kanban.access"}
		json.NewEncoder(w).Encode(resp)
	}))
	defer srv.Close()

	code := runWhoami(srv.URL, "real-token")
	if code != 0 {
		t.Fatalf("expected exit code 0, got %d", code)
	}
}

func TestRunWhoami_Unauthorized_ReturnsNonZero(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()

	code := runWhoami(srv.URL, "bad-token")
	if code == 0 {
		t.Fatal("expected a non-zero exit code for an unauthorized request")
	}
}

func TestRunWhoami_Unreachable_ReturnsNonZero(t *testing.T) {
	code := runWhoami("http://127.0.0.1:1", "real-token")
	if code == 0 {
		t.Fatal("expected a non-zero exit code for an unreachable host")
	}
}

func TestJoinOrNone(t *testing.T) {
	if got := joinOrNone(nil); got != "(none)" {
		t.Fatalf("joinOrNone(nil) = %q, want (none)", got)
	}
	if got := joinOrNone([]string{"a", "b"}); got != "a, b" {
		t.Fatalf("joinOrNone([a b]) = %q, want %q", got, "a, b")
	}
}
