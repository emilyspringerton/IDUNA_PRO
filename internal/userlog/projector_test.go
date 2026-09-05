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

	u, err := proj.GetByUID(ctx, 0)
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

	u, _ := proj.GetByUID(ctx, 1)
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
	u, err := proj.GetByUID(ctx, 2)
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

	u, _ := proj.GetByUID(ctx, 3)
	if u != nil {
		t.Error("deleted user should not be returned by GetByUID")
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
	u, err := proj.GetByEmail(ctx, "email@test.com")
	if err != nil || u == nil {
		t.Errorf("GetByEmail: got nil/err: %v", err)
	}
	if u.LocalUID != 5 {
		t.Errorf("uid: want 5, got %d", u.LocalUID)
	}
}
