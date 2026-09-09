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
	IsAdmin bool
	// IsProvider -- CP-HIPAA-1 ("we can allow providers to create email accounts for
	// participants"). A real, least-privilege role distinct from IsAdmin: grants
	// mail-accounts.provision (see localUserPermissions) without the rest of the admin
	// permission set. Same DB-backed bool / grant-event / PATCH-API pattern IsAdmin already
	// established, no separate genesis mechanism needed since granting it always requires an
	// existing users.admin holder.
	IsProvider bool
	// IsOperatorAdmin / IsProviderAdmin -- CP-HIPAA-2, the real 3rd/4th tiers of the RBAC
	// hierarchy (see 202609070004_local_users_tiered_admin_roles.sql for the full model).
	// IsOperatorAdmin: same practical permission set as IsAdmin, except cannot modify/disable
	// another admin-tier account (enforced via the "admins.manage" permission, which only
	// IsAdmin/uid=0 actually carries -- see localUserPermissions).
	// IsProviderAdmin: provisions like IsProvider, plus can grant/revoke IsProvider on others
	// (the "providers.manage" permission).
	IsOperatorAdmin bool
	IsProviderAdmin bool
	// IsCommunityToolsEnabled -- founder real-time, 2026-09-09: a real, per-account feature
	// flag, deliberately SEPARATE from the 4-tier admin/provider RBAC hierarchy above (Top
	// Admin/Operator Admin/Provider Admin/Provider Operator are all staff-tier roles; this
	// flag is for ORDINARY community-participant accounts, gating "community tools" -- v0's
	// own real first one is the resume/CV builder, internal/http/handlers/
	// community_tools.go). Same real DB-backed bool / grant-event / PATCH-API pattern
	// IsAdmin/IsProvider already established (see localUserPermissions in
	// internal/http/handlers/local_auth.go for how this becomes the real
	// "community-tools.access" permission), granted by any users.admin holder -- no separate
	// grant-UI/permission needed, since it's a plain per-account toggle, not a new admin tier.
	IsCommunityToolsEnabled bool
	// OrgID -- CP-HIPAA-3 (founder real-time: "there may be a several organizations who have
	// service agreements with each other... the admins from that collective should be able to
	// administer participants from that cluster of providers"). Dual real meaning by role, same
	// field either way: for a Provider/Provider Admin/Operator Admin/Top Admin, the organization
	// THEY work for; for a participant, the organization that onboarded them (stamped
	// automatically from the creating provider's own OrgID at account-creation time -- see
	// UserCreatedData.OrgID and users.go's own createUser -- "batteries included happy path": a
	// provider never picks an org by hand, it's inherited). 0 = no organization assigned, the
	// safe, backward-compatible default -- see 202609070007_local_users_org_id.sql's own doc
	// comment for why 0 must never "share a cluster" with anything, including another 0.
	OrgID     int
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

	// ScrubPII overwrites email/display_name/password_hash for uid with a fixed redaction
	// marker directly in the SQL projection (internal/gdpr's own real erasure pipeline --
	// founder real-time, 2026-09-07: "build gdpr into iduna pro... data delete request
	// pipeline"). Real, found-live gap this closes: the existing EventUserDeleted/
	// UserDeletedData flow (Apply, above) only ever sets status='deleted' -- the row's own
	// email/display_name/password_hash columns are untouched, so a "deleted" user's real PII
	// still sits in this table forever. Does NOT touch local_uid, status, or timestamps --
	// this is a redaction, not a row delete (other tables may still reference local_uid).
	ScrubPII(ctx context.Context, uid int) error
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
	// EventUserProviderChanged -- CP-HIPAA-1. Same grant/revoke-in-one-event-type shape as
	// EventUserAdminChanged.
	EventUserProviderChanged = "local_user.provider_changed"
	// EventUserOperatorAdminChanged / EventUserProviderAdminChanged -- CP-HIPAA-2, the 3rd/4th
	// RBAC tiers. Same grant/revoke-in-one-event-type shape as the two above.
	EventUserOperatorAdminChanged = "local_user.operator_admin_changed"
	EventUserProviderAdminChanged = "local_user.provider_admin_changed"
	// EventUserCommunityToolsChanged -- founder real-time, 2026-09-09. Same grant/revoke-in-
	// one-event-type shape as the tiers above, gating a plain per-account feature flag rather
	// than an RBAC tier (see LocalUser.IsCommunityToolsEnabled's own doc comment).
	EventUserCommunityToolsChanged = "local_user.community_tools_changed"
	// EventUserOrgChanged -- CP-HIPAA-3. An admin (re)assigning an existing user's organization
	// after the fact, distinct from the "stamped automatically at creation" path
	// (UserCreatedData.OrgID) -- e.g. correcting a mis-onboarded participant, or moving a
	// provider to a different organization.
	EventUserOrgChanged = "local_user.org_changed"
)

// ── event payload types ──────────────────────────────────────────────────────

type UserCreatedData struct {
	LocalUID     int    `json:"local_uid"`
	Email        string `json:"email"`
	DisplayName  string `json:"display_name"`
	PasswordHash string `json:"password_hash"`
	// OrgID -- CP-HIPAA-3: stamped once, at creation time, from the creating provider's own
	// OrgID ("batteries included happy path" -- see users.go's own createUser). 0 (the JSON
	// zero-value, correctly absent/defaulted on every event appended before this field existed)
	// means no organization -- same safe default LocalUser.OrgID's own doc comment describes.
	OrgID int `json:"org_id,omitempty"`
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

type UserProviderChangedData struct {
	LocalUID   int  `json:"local_uid"`
	IsProvider bool `json:"is_provider"`
}

type UserOperatorAdminChangedData struct {
	LocalUID        int  `json:"local_uid"`
	IsOperatorAdmin bool `json:"is_operator_admin"`
}

type UserProviderAdminChangedData struct {
	LocalUID        int  `json:"local_uid"`
	IsProviderAdmin bool `json:"is_provider_admin"`
}

type UserCommunityToolsChangedData struct {
	LocalUID                int  `json:"local_uid"`
	IsCommunityToolsEnabled bool `json:"is_community_tools_enabled"`
}

type UserOrgChangedData struct {
	LocalUID int `json:"local_uid"`
	OrgID    int `json:"org_id"`
}

type UserDeletedData struct {
	LocalUID int `json:"local_uid"`
}
