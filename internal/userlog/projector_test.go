package userlog

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"idunapro/internal/store"
)

func setupSQLiteProjector(t *testing.T) *SQLiteProjector {
	t.Helper()
	db, err := store.OpenSQLite(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })

	// Create the tables that the migration would create.
	_, err = db.Exec(`
		CREATE TABLE IF NOT EXISTS local_users (
			local_uid     INTEGER NOT NULL PRIMARY KEY,
			email         TEXT    NOT NULL,
			display_name  TEXT    NOT NULL DEFAULT '',
			password_hash TEXT    NOT NULL DEFAULT '',
			status        TEXT    NOT NULL DEFAULT 'active',
			is_admin      INTEGER NOT NULL DEFAULT 0,
			is_provider   INTEGER NOT NULL DEFAULT 0,
			is_operator_admin INTEGER NOT NULL DEFAULT 0,
			is_provider_admin INTEGER NOT NULL DEFAULT 0,
			is_community_tools_enabled INTEGER NOT NULL DEFAULT 0,
			org_id INTEGER NOT NULL DEFAULT 0,
			tenant_id INTEGER NOT NULL DEFAULT 1,
			created_at    TEXT    NOT NULL DEFAULT CURRENT_TIMESTAMP,
			updated_at    TEXT    NOT NULL DEFAULT CURRENT_TIMESTAMP,
			UNIQUE (email)
		);
		CREATE TABLE IF NOT EXISTS local_user_projector_cursor (
			id       INTEGER NOT NULL PRIMARY KEY DEFAULT 1,
			last_seq INTEGER NOT NULL DEFAULT 0
		);
		INSERT OR IGNORE INTO local_user_projector_cursor (id, last_seq) VALUES (1, 0);
	`)
	if err != nil {
		t.Fatal(err)
	}
	return NewSQLiteProjector(db)
}

func makeRec(seq uint64, evType string, data any) Record {
	raw, _ := json.Marshal(data)
	return Record{
		Sequence:   seq,
		AppendedAt: time.Now().UTC(),
		Event: Event{
			ID:   "test-" + evType,
			Type: evType,
			Data: json.RawMessage(raw),
		},
	}
}

func TestSQLiteProjector_CreateAndGet(t *testing.T) {
	proj := setupSQLiteProjector(t)
	ctx := context.Background()

	rec := makeRec(1, EventUserCreated, UserCreatedData{
		LocalUID:     0,
		Email:        "webmaster@localhost",
		DisplayName:  "webmaster",
		PasswordHash: "hash123",
	})
	if err := proj.Apply(ctx, rec); err != nil {
		t.Fatal(err)
	}

	u, err := proj.GetByUID(ctx, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	if u == nil {
		t.Fatal("expected user, got nil")
	}
	if u.Email != "webmaster@localhost" {
		t.Errorf("email: want webmaster@localhost, got %s", u.Email)
	}
	if u.Status != "active" {
		t.Errorf("status: want active, got %s", u.Status)
	}
}

func TestSQLiteProjector_UpdateDisplayName(t *testing.T) {
	proj := setupSQLiteProjector(t)
	ctx := context.Background()

	proj.Apply(ctx, makeRec(1, EventUserCreated, UserCreatedData{LocalUID: 1, Email: "a@b.com", DisplayName: "old"}))
	name := "new name"
	proj.Apply(ctx, makeRec(2, EventUserUpdated, UserUpdatedData{LocalUID: 1, DisplayName: &name}))

	u, _ := proj.GetByUID(ctx, 0, 1)
	if u.DisplayName != "new name" {
		t.Errorf("display_name: want 'new name', got %s", u.DisplayName)
	}
}

func TestSQLiteProjector_StatusChanged(t *testing.T) {
	proj := setupSQLiteProjector(t)
	ctx := context.Background()

	proj.Apply(ctx, makeRec(1, EventUserCreated, UserCreatedData{LocalUID: 2, Email: "c@d.com"}))
	proj.Apply(ctx, makeRec(2, EventUserStatusChanged, UserStatusChangedData{LocalUID: 2, OldStatus: "active", NewStatus: "suspended"}))

	// GetByUID filters status!='deleted'; suspended users are still returned.
	u, err := proj.GetByUID(ctx, 0, 2)
	if err != nil {
		t.Fatalf("GetByUID: %v", err)
	}
	if u == nil {
		t.Fatal("suspended user should still be returned by GetByUID (only deleted is hidden)")
	}
	if u.Status != "suspended" {
		t.Errorf("status: want suspended, got %s", u.Status)
	}
}

func TestSQLiteProjector_Deleted(t *testing.T) {
	proj := setupSQLiteProjector(t)
	ctx := context.Background()

	proj.Apply(ctx, makeRec(1, EventUserCreated, UserCreatedData{LocalUID: 3, Email: "del@x.com"}))
	proj.Apply(ctx, makeRec(2, EventUserDeleted, UserDeletedData{LocalUID: 3}))

	u, _ := proj.GetByUID(ctx, 0, 3)
	if u != nil {
		t.Error("deleted user should not be returned by GetByUID")
	}
}

func TestSQLiteProjector_ScrubPII(t *testing.T) {
	proj := setupSQLiteProjector(t)
	ctx := context.Background()

	proj.Apply(ctx, makeRec(1, EventUserCreated, UserCreatedData{
		LocalUID: 5, Email: "real@example.com", DisplayName: "Real Name", PasswordHash: "realhash",
	}))
	proj.Apply(ctx, makeRec(2, EventUserDeleted, UserDeletedData{LocalUID: 5}))

	if err := proj.ScrubPII(ctx, 0, 5); err != nil {
		t.Fatalf("ScrubPII: %v", err)
	}

	// GetByUID itself already hides deleted users (see TestSQLiteProjector_Deleted above) --
	// that's a query-level filter, not proof the real column values are gone. Read the raw row
	// directly to confirm ScrubPII actually overwrote them, not just that they're hidden.
	var email, displayName, passwordHash, status string
	err := proj.db.QueryRowContext(ctx,
		`SELECT email, display_name, password_hash, status FROM local_users WHERE local_uid = ?`, 5,
	).Scan(&email, &displayName, &passwordHash, &status)
	if err != nil {
		t.Fatalf("query raw row: %v", err)
	}
	if email != redactionMarker || displayName != redactionMarker || passwordHash != redactionMarker {
		t.Errorf("expected all PII columns redacted, got email=%q display_name=%q password_hash=%q", email, displayName, passwordHash)
	}
	if status != "deleted" {
		t.Errorf("expected status to remain 'deleted' (ScrubPII must not touch it), got %q", status)
	}
}

func TestSQLiteProjector_CursorAdvance(t *testing.T) {
	proj := setupSQLiteProjector(t)
	ctx := context.Background()

	cur, _ := proj.Cursor(ctx)
	if cur != 0 {
		t.Errorf("initial cursor: want 0, got %d", cur)
	}
	proj.AdvanceCursor(ctx, 42)
	cur, _ = proj.Cursor(ctx)
	if cur != 42 {
		t.Errorf("cursor after advance: want 42, got %d", cur)
	}
}

func TestSQLiteProjector_NextUID(t *testing.T) {
	proj := setupSQLiteProjector(t)
	ctx := context.Background()

	uid, _ := proj.NextUID(ctx)
	if uid != 1 {
		t.Errorf("NextUID on empty table: want 1, got %d", uid)
	}
	proj.Apply(ctx, makeRec(1, EventUserCreated, UserCreatedData{LocalUID: 0, Email: "w@m.com"}))
	proj.Apply(ctx, makeRec(2, EventUserCreated, UserCreatedData{LocalUID: 1, Email: "u@m.com"}))
	uid, _ = proj.NextUID(ctx)
	if uid != 2 {
		t.Errorf("NextUID after 2 users: want 2, got %d", uid)
	}
}

func TestSQLiteProjector_GetByEmail(t *testing.T) {
	proj := setupSQLiteProjector(t)
	ctx := context.Background()

	proj.Apply(ctx, makeRec(1, EventUserCreated, UserCreatedData{LocalUID: 5, Email: "email@test.com"}))
	u, err := proj.GetByEmail(ctx, 0, "email@test.com")
	if err != nil || u == nil {
		t.Errorf("GetByEmail: got nil/err: %v", err)
	}
	if u.LocalUID != 5 {
		t.Errorf("uid: want 5, got %d", u.LocalUID)
	}
}

// ── MULTI_TENANCY_NORTHSTAR.md Phase 1 (2026-09-11) -- real tenant isolation, proven at the
// projector level, not just that the new parameter is accepted. Two users seeded under two
// different real tenant ids; every read must genuinely filter, not just compile.

func seedTwoTenants(t *testing.T, proj *SQLiteProjector) {
	t.Helper()
	ctx := context.Background()
	proj.Apply(ctx, makeRec(1, EventUserCreated, UserCreatedData{
		LocalUID: 10, Email: "tenant1@example.com", DisplayName: "Tenant One", TenantID: 1,
	}))
	proj.Apply(ctx, makeRec(2, EventUserCreated, UserCreatedData{
		LocalUID: 20, Email: "tenant2@example.com", DisplayName: "Tenant Two", TenantID: 2,
	}))
}

func TestSQLiteProjector_TenantIsolation_GetByUID(t *testing.T) {
	proj := setupSQLiteProjector(t)
	seedTwoTenants(t, proj)
	ctx := context.Background()

	u, err := proj.GetByUID(ctx, 1, 20)
	if err != nil {
		t.Fatalf("GetByUID: %v", err)
	}
	if u != nil {
		t.Fatalf("expected tenant 1 to NOT see tenant 2's uid 20 via GetByUID, got: %+v", u)
	}

	u, err = proj.GetByUID(ctx, 2, 20)
	if err != nil || u == nil {
		t.Fatalf("expected tenant 2 to see its own uid 20 via GetByUID, got nil/err: %v", err)
	}
	if u.Email != "tenant2@example.com" {
		t.Errorf("email: want tenant2@example.com, got %s", u.Email)
	}
}

func TestSQLiteProjector_TenantIsolation_GetByEmail(t *testing.T) {
	proj := setupSQLiteProjector(t)
	seedTwoTenants(t, proj)
	ctx := context.Background()

	u, err := proj.GetByEmail(ctx, 1, "tenant2@example.com")
	if err != nil {
		t.Fatalf("GetByEmail: %v", err)
	}
	if u != nil {
		t.Fatalf("expected tenant 1 to NOT find tenant 2's own email via GetByEmail, got: %+v", u)
	}
}

func TestSQLiteProjector_TenantIsolation_ListUsers(t *testing.T) {
	proj := setupSQLiteProjector(t)
	seedTwoTenants(t, proj)
	ctx := context.Background()

	tenant1Users, err := proj.ListUsers(ctx, 1, 0)
	if err != nil {
		t.Fatalf("ListUsers: %v", err)
	}
	for _, u := range tenant1Users {
		if u.LocalUID == 20 {
			t.Fatalf("expected tenant 1's own ListUsers to never include tenant 2's uid 20, got: %+v", tenant1Users)
		}
	}
	found1 := false
	for _, u := range tenant1Users {
		if u.LocalUID == 10 {
			found1 = true
		}
	}
	if !found1 {
		t.Fatalf("expected tenant 1's own ListUsers to include its own uid 10, got: %+v", tenant1Users)
	}
}

func TestSQLiteProjector_TenantIsolation_ScrubPIIRefusesCrossTenant(t *testing.T) {
	proj := setupSQLiteProjector(t)
	seedTwoTenants(t, proj)
	ctx := context.Background()

	// ScrubPII with the WRONG tenant id must not touch the row at all -- no matching WHERE
	// clause means zero rows affected (ExecContext itself returns no error either way, so the
	// real proof is that the target's own data survives).
	if err := proj.ScrubPII(ctx, 1, 20); err != nil {
		t.Fatalf("ScrubPII: %v", err)
	}
	u, err := proj.GetByUID(ctx, 2, 20)
	if err != nil || u == nil {
		t.Fatalf("expected tenant 2's uid 20 to still exist, got nil/err: %v", err)
	}
	if u.Email != "tenant2@example.com" {
		t.Fatalf("expected a wrong-tenant ScrubPII call to leave tenant 2's real email untouched, got %q", u.Email)
	}
}
