package store_test

import (
	"context"
	"testing"

	"idunapro/internal/auth"
	"idunapro/internal/store"
)

// setupAgentLifecycleStore opens an in-memory SQLite DB, runs the real
// migrations (translated MySQL->SQLite), and creates one owner user so
// CreateAgent's owner_user_id FK-equivalent has something valid to point at.
func setupAgentLifecycleStore(t *testing.T) (*store.SQLiteStore, string) {
	t.Helper()
	db, err := store.OpenSQLite(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })

	if err := store.RunSQLiteMigrations(db, "../../migrations/truestore"); err != nil {
		t.Fatalf("run migrations: %v", err)
	}

	s := store.NewSQLiteStore(db)
	ctx := context.Background()
	owner, _, err := s.GetOrCreateUserByGoogleSubject(ctx, "test-google-sub", "owner@example.com")
	if err != nil {
		t.Fatalf("create owner user: %v", err)
	}
	return s, owner.IDString
}

// TestCreateAgent_StartsPending verifies the FRONT_DOOR_FUNNEL §7 step 1 fix:
// agents created via the Back Office (CreateAgent) now start PENDING, not
// ACTIVE, since at creation time they have no credential and no permissions.
func TestCreateAgent_StartsPending(t *testing.T) {
	s, ownerID := setupAgentLifecycleStore(t)
	ctx := context.Background()

	agent, err := s.CreateAgent(ctx, ownerID, "TEST-AGENT", "ops_agent", "test-operator")
	if err != nil {
		t.Fatalf("CreateAgent: %v", err)
	}
	if agent.Status != "PENDING" {
		t.Fatalf("expected new agent status PENDING, got %q", agent.Status)
	}

	agents, err := s.ListAgents(ctx)
	if err != nil {
		t.Fatalf("ListAgents: %v", err)
	}
	var found *auth.Agent
	for i := range agents {
		if agents[i].ID == agent.ID {
			found = &agents[i]
			break
		}
	}
	if found == nil {
		t.Fatalf("created agent %s not found in ListAgents (migrations seed other system agents too)", agent.ID)
	}
	if found.Status != "PENDING" {
		t.Errorf("ListAgents: expected PENDING, got %q", found.Status)
	}
	if found.HasCredential {
		t.Errorf("fresh agent should not have a credential yet")
	}
	if len(found.Permissions) != 0 {
		t.Errorf("fresh agent should have no permissions yet, got %v", found.Permissions)
	}
}

// TestAgentLifecycle_ActivatesOnlyWhenBothConditionsMet verifies the core
// FRONT_DOOR_FUNNEL rule: an agent flips PENDING->ACTIVE only once it has
// BOTH a credential AND at least one permission -- neither alone is enough.
func TestAgentLifecycle_ActivatesOnlyWhenBothConditionsMet(t *testing.T) {
	s, ownerID := setupAgentLifecycleStore(t)
	ctx := context.Background()

	agent, err := s.CreateAgent(ctx, ownerID, "TEST-AGENT-2", "ops_agent", "test-operator")
	if err != nil {
		t.Fatalf("CreateAgent: %v", err)
	}

	assertStatus := func(want string) {
		t.Helper()
		agents, err := s.ListAgents(ctx)
		if err != nil {
			t.Fatalf("ListAgents: %v", err)
		}
		for _, a := range agents {
			if a.ID == agent.ID {
				if a.Status != want {
					t.Fatalf("expected status %q, got %q", want, a.Status)
				}
				return
			}
		}
		t.Fatalf("agent %s not found in ListAgents", agent.ID)
	}

	assertStatus("PENDING")

	// Permission alone: still PENDING (no credential yet).
	if err := s.GrantAgentPermission(ctx, agent.ID, "fatbaby.read", "test-operator"); err != nil {
		t.Fatalf("GrantAgentPermission: %v", err)
	}
	assertStatus("PENDING")

	// Credential added on top of the existing permission: now ACTIVE.
	if err := s.SetAgentCredential(ctx, agent.ID, "test-plaintext-secret", "test-operator"); err != nil {
		t.Fatalf("SetAgentCredential: %v", err)
	}
	assertStatus("ACTIVE")

	// Revoking the only permission does not walk the status back down --
	// governance (enforcement) is separate from onboarding (lifecycle), same
	// as the doc argues in §4: revocation is a governance-side concern.
	if err := s.RevokeAgentPermission(ctx, agent.ID, "fatbaby.read", "test-operator"); err != nil {
		t.Fatalf("RevokeAgentPermission: %v", err)
	}
	assertStatus("ACTIVE")

	// Authenticating now fails anyway, since AuthenticateAgent checks live
	// agent_permissions via GetAgentPermissions/effective grants, not status.
	authed, err := s.AuthenticateAgent(ctx, "TEST-AGENT-2", "test-plaintext-secret")
	if err != nil {
		t.Fatalf("AuthenticateAgent: %v", err)
	}
	if len(authed.Permissions) != 0 {
		t.Errorf("expected zero effective permissions after revoke, got %v", authed.Permissions)
	}
}

// TestSetAgentCredential_AloneDoesNotActivate verifies a credential without
// any permission leaves the agent PENDING (inert either way, but honestly so).
func TestSetAgentCredential_AloneDoesNotActivate(t *testing.T) {
	s, ownerID := setupAgentLifecycleStore(t)
	ctx := context.Background()

	agent, err := s.CreateAgent(ctx, ownerID, "TEST-AGENT-3", "ops_agent", "test-operator")
	if err != nil {
		t.Fatalf("CreateAgent: %v", err)
	}
	if err := s.SetAgentCredential(ctx, agent.ID, "another-secret", "test-operator"); err != nil {
		t.Fatalf("SetAgentCredential: %v", err)
	}

	agents, err := s.ListAgents(ctx)
	if err != nil {
		t.Fatalf("ListAgents: %v", err)
	}
	for _, a := range agents {
		if a.ID == agent.ID {
			if a.Status != "PENDING" {
				t.Fatalf("expected PENDING (credential only, no permission), got %q", a.Status)
			}
			if !a.HasCredential {
				t.Errorf("expected HasCredential true")
			}
			return
		}
	}
	t.Fatalf("agent not found")
}

// TestGrantAgentPermission_UnknownPermissionErrors verifies granting a
// permission name that doesn't exist in the permissions table fails loudly
// instead of silently no-op'ing (which would let an admin believe a grant
// succeeded when it didn't).
func TestGrantAgentPermission_UnknownPermissionErrors(t *testing.T) {
	s, ownerID := setupAgentLifecycleStore(t)
	ctx := context.Background()

	agent, err := s.CreateAgent(ctx, ownerID, "TEST-AGENT-4", "ops_agent", "test-operator")
	if err != nil {
		t.Fatalf("CreateAgent: %v", err)
	}
	if err := s.GrantAgentPermission(ctx, agent.ID, "does.not.exist", "test-operator"); err == nil {
		t.Fatalf("expected error granting unknown permission, got nil")
	}
}
