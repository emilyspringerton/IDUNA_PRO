package userlog

import (
	"context"
	"time"
)

// LocalUser is the read model for a password-authenticated IDUNA user.
// uid=0 is reserved for webmaster (root).
type LocalUser struct {
	LocalUID     int
	Email        string
	DisplayName  string
	PasswordHash string
	Status       string // "active" | "suspended" | "deleted"
	// IsAdmin -- CP-SIP-ADMIN-124323 ("IDUNAPRO admin accounts have the chicken and egg
	// problem i need an admin account to create admin accounts how do we achieve admin
	// genesis?"). Real, DB-backed admin flag, checked by localUserPermissions alongside the
	// existing LocalUID==0 (webmaster) special case -- uid=0 is still always admin (backward
	// compatible), but this is the real, general mechanism for granting it to anyone else.
	// Genesis (the very first non-webmaster admin) is granted via `idunapro admin-grant
	// <email>`, a local CLI command with direct DB access -- no chicken-and-egg API call
	// needed. Every admin after that can be granted via the real API
	// (PATCH /api/v1/users/{uid} {"is_admin": true}, itself gated on users.admin).
	IsAdmin   bool
	CreatedAt time.Time
	UpdatedAt time.Time
}

// UserProjector is the interface both SQLite and MySQL projectors implement.
// It consumes Records from the EventLog and exposes a consistent SQL read model.
type UserProjector interface {
	// Apply folds one record from the event log into the SQL projection.
	Apply(ctx context.Context, rec Record) error

	// Cursor returns the sequence number of the last successfully applied record.
	Cursor(ctx context.Context) (uint64, error)

	// AdvanceCursor updates the stored cursor to seq.
	AdvanceCursor(ctx context.Context, seq uint64) error

	// GetByUID returns the user with the given local_uid. Returns nil, nil if not found.
	GetByUID(ctx context.Context, uid int) (*LocalUser, error)

	// GetByEmail returns the user with the given email. Returns nil, nil if not found.
	GetByEmail(ctx context.Context, email string) (*LocalUser, error)

	// ListUsers returns up to limit users ordered by local_uid asc.
	// Pass limit=0 for no limit (returns all).
	ListUsers(ctx context.Context, limit int) ([]LocalUser, error)

	// NextUID returns max(local_uid)+1 so callers can assign new UIDs sequentially.
	NextUID(ctx context.Context) (int, error)
}

// ── event type constants ────────────────────────────────────────────────────

const (
	EventUserCreated       = "local_user.created"
	EventUserUpdated       = "local_user.updated"
	EventUserPasswordReset = "local_user.password_reset"
	EventUserStatusChanged = "local_user.status_changed"
	EventUserDeleted       = "local_user.deleted"
	// EventUserAdminChanged -- CP-SIP-ADMIN-124323. One event type for both grant and revoke
	// (IsAdmin true/false), matching UserStatusChangedData's own old/new shape rather than
	// inventing a separate event per direction.
	EventUserAdminChanged = "local_user.admin_changed"
)

// ── event payload types ──────────────────────────────────────────────────────

type UserCreatedData struct {
	LocalUID     int    `json:"local_uid"`
	Email        string `json:"email"`
	DisplayName  string `json:"display_name"`
	PasswordHash string `json:"password_hash"`
}

type UserUpdatedData struct {
	LocalUID    int     `json:"local_uid"`
	Email       *string `json:"email,omitempty"`
	DisplayName *string `json:"display_name,omitempty"`
}

type UserPasswordResetData struct {
	LocalUID     int    `json:"local_uid"`
	PasswordHash string `json:"password_hash"`
}

type UserStatusChangedData struct {
	LocalUID  int    `json:"local_uid"`
	OldStatus string `json:"old_status"`
	NewStatus string `json:"new_status"`
}

type UserAdminChangedData struct {
	LocalUID int  `json:"local_uid"`
	IsAdmin  bool `json:"is_admin"`
}

type UserDeletedData struct {
	LocalUID int `json:"local_uid"`
}
