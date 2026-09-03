package store

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"idunapro/internal/auth"
)

// Sentinel errors for ClaimHandle.
var (
	// ErrHandleAlreadySet is returned when a user who already has a gamertag
	// tries to claim another one — gamertags are permanent (VS0_IDENTITY_GATE.md).
	ErrHandleAlreadySet = errors.New("user already has a gamertag")
	// ErrHandleTaken is returned when the requested gamertag belongs to
	// another user already.
	ErrHandleTaken = errors.New("gamertag already taken")
)

// GFDTier is a GoblinFoxDragon subscription tier definition.
type GFDTier struct {
	TierID     string   `json:"tier_id"`
	Name       string   `json:"name"`
	MonthlyUSD float64  `json:"monthly_usd"`
	AnnualUSD  float64  `json:"annual_usd"`
	Features   []string `json:"features"`
}

// IAMStore defines the persistence interface for IDUNA IAM operations.
type IAMStore interface {
	// GetOrCreateUserByGoogleSubject looks up a user by google_subject.
	// If the user does not exist, it creates one with PENDING status.
	// The bool return value is true when the user was newly created.
	GetOrCreateUserByGoogleSubject(ctx context.Context, googleSub, email string) (*auth.User, bool, error)

	// GetUserByID returns a user by their string UUID.
	GetUserByID(ctx context.Context, id string) (*auth.User, error)

	// GetEffectivePermissions returns the distinct set of permission names
	// granted to the user through their assigned roles, sorted lexicographically.
	GetEffectivePermissions(ctx context.Context, userID string) ([]string, error)

	// AppendIAMEvent inserts a row into iam_event_stream.
	AppendIAMEvent(ctx context.Context, eventType, aggregateType, aggregateID, operatorID string, payload []byte) error

	// UpdateUserStatus changes the user's status and emits a corresponding IAM event.
	UpdateUserStatus(ctx context.Context, userID, status, operatorID string) error

	// --- VS0 ceremony: honor code + gamertag (HQ-SPEC front-door funnel) ---

	// AcceptHonorCode records the user's acceptance of the given honor code
	// version/sha/text and emits a HonorCodeAccepted event.
	AcceptHonorCode(ctx context.Context, userID string, version int, sha, text, operatorID string) error

	// ClaimHandle sets a user's permanent gamertag. Returns ErrHandleAlreadySet
	// if the user already has one (gamertags are immutable once claimed) and
	// ErrHandleTaken if another user already holds that exact handle.
	ClaimHandle(ctx context.Context, userID, handle, operatorID string) error

	// IsHandleAvailable reports whether the given gamertag is unclaimed.
	IsHandleAvailable(ctx context.Context, handle string) (bool, error)

	// --- Admin operations ---

	// ListUsers returns up to limit users ordered by created_at desc.
	ListUsers(ctx context.Context, limit int) ([]auth.User, error)

	// AssignRole grants a role to a user, emitting a RoleAssigned event.
	AssignRole(ctx context.Context, userID, roleID, operatorID string) error

	// RevokeRole removes a role from a user, emitting a RoleRevoked event.
	RevokeRole(ctx context.Context, userID, roleID, operatorID string) error

	// ListRoles returns all defined roles.
	ListRoles(ctx context.Context) ([]auth.Role, error)

	// ListAgents returns all agents ordered by created_at desc.
	ListAgents(ctx context.Context) ([]auth.Agent, error)

	// CreateAgent inserts a new agent with status=PENDING and emits an
	// AgentCreated event. It stays PENDING (inert: cannot authenticate, holds
	// no capabilities) until GrantAgentPermission and SetAgentCredential have
	// both been called at least once, at which point it flips to ACTIVE.
	CreateAgent(ctx context.Context, ownerUserID, name, agentType, operatorID string) (*auth.Agent, error)

	// GrantAgentPermission grants a named permission to an agent, emitting an
	// AgentPermissionGranted event. If the agent is PENDING and now has both a
	// credential and at least one permission, it flips to ACTIVE.
	GrantAgentPermission(ctx context.Context, agentID, permissionName, operatorID string) error

	// RevokeAgentPermission removes a named permission from an agent, emitting
	// an AgentPermissionRevoked event.
	RevokeAgentPermission(ctx context.Context, agentID, permissionName, operatorID string) error

	// UpsertClusterHeartbeat upserts a federated Emily cluster heartbeat record.
	// Called by emily-agent every 60 s so IDUNA can track which clusters are alive.
	UpsertClusterHeartbeat(ctx context.Context, h auth.ClusterHeartbeat) error

	// ListActiveClusterHeartbeats returns clusters whose last_seen is within the
	// given staleness window. Pass 5*time.Minute for normal federation queries.
	ListActiveClusterHeartbeats(ctx context.Context, maxAge time.Duration) ([]auth.ClusterHeartbeat, error)

	// UpdateAgentStatus changes an agent's status and emits an event.
	UpdateAgentStatus(ctx context.Context, agentID, status, operatorID string) error

	// --- Agent M2M credentials (spec HQ-SPEC-IAM-095 §3.1) ---

	// SetAgentCredential stores a bcrypt hash of the given plaintext secret for the
	// agent. The previous credential (if any) is replaced. operatorID is recorded in
	// the resulting IAM event for audit.
	SetAgentCredential(ctx context.Context, agentID, plaintextSecret, operatorID string) error

	// AuthenticateAgent looks up an agent by name, verifies the plaintext secret
	// against its stored bcrypt hash, and returns the agent with its effective
	// permissions. Returns a non-nil error when authentication fails (name not found,
	// no credential set, wrong secret, or agent not ACTIVE).
	AuthenticateAgent(ctx context.Context, agentName, plaintextSecret string) (*auth.Agent, error)

	// GetAgentByID returns an agent's CURRENT status and permissions by ID, no
	// secret check. Used to re-verify a still-active admin session against
	// live state on every request (a session cookie only proves who was
	// ACTIVE at issuance -- it says nothing about now). Returns a non-nil
	// error when the agent no longer exists at all.
	GetAgentByID(ctx context.Context, agentID string) (*auth.Agent, error)

	// ListIAMEvents returns the most recent limit events from iam_event_stream.
	ListIAMEvents(ctx context.Context, limit int) ([]auth.IAMEvent, error)

	// --- Apples (HQ-SPEC-IAM-096) ---

	// AppendApple inserts a golden documentation record and emits ApplePublished to iam_event_stream.
	AppendApple(ctx context.Context, apple auth.AppleRecord) (id int64, err error)

	// ListApples returns up to limit apples, most recent first.
	// Pass empty strings to omit a filter; pass 0 for limit to use the default (50).
	ListApples(ctx context.Context, agentID, sourceRepo, appleType string, limit int) ([]auth.AppleRecord, error)

	// GetApple returns a single apple by its integer ID.
	GetApple(ctx context.Context, id int64) (*auth.AppleRecord, error)

	// PatchAppleMetadata merges the given keys into an existing apple's metadata
	// JSON (shallow merge; existing keys not present in updates are preserved,
	// keys present in updates overwrite). Used for async post-hoc enrichment
	// (S147-02/03: gpt2_fingerprint, model_fingerprint) — never for the apple's
	// core fields (title/body/type), which remain append-only-in-spirit.
	// Emits AppleEnriched to iam_event_stream. Returns sql.ErrNoRows if id
	// doesn't exist.
	PatchAppleMetadata(ctx context.Context, id int64, updates map[string]json.RawMessage) error

	// DailyTokenStats returns per-day token usage aggregated from Apple metadata.
	// Each entry sums json_extract(metadata, '$.tokens_used') for all Apples recorded
	// on that UTC date. Returns the last `days` calendar days (most recent last).
	// Days with no Apple activity appear with tokens=0.
	DailyTokenStats(ctx context.Context, days int) ([]auth.DailyTokenStat, error)

	// --- Push tokens (MJOLNIR FCM — HQ-SPEC-IAM-097) ---

	// UpsertPushToken inserts or updates an FCM device token for the given agent.
	// Deduplication key is (agent_name, fingerprint).
	UpsertPushToken(ctx context.Context, token auth.PushToken) error

	// GetPushToken returns the most recently registered FCM token for agent_name.
	// Returns nil, nil if no token is registered.
	GetPushToken(ctx context.Context, agentName string) (*auth.PushToken, error)

	// --- Camera observations (MJOLNIR intelligence — HQ-SPEC-IAM-098) ---

	// CreateCameraObservation inserts a new pending observation and returns its ID.
	CreateCameraObservation(ctx context.Context, obs auth.CameraObservation) (int64, error)

	// UpdateCameraObservation sets analysis, apple_id, status, and processed_at for an observation.
	UpdateCameraObservation(ctx context.Context, id int64, analysis string, appleID int64, status string) error

	// GetCameraObservation returns a single observation by ID.
	GetCameraObservation(ctx context.Context, id int64) (*auth.CameraObservation, error)

	// ListCameraObservations returns up to limit observations for agentName.
	// Pass status="" to return all statuses; otherwise filters by status.
	// Returns newest first.
	ListCameraObservations(ctx context.Context, agentName, status string, limit int) ([]auth.CameraObservation, error)

	// --- HEIMDAL sprints (sprint planning interface — HQ-SPEC-IAM-099) ---

	// CreateSprintItem inserts a new pending sprint and returns its ID.
	CreateSprintItem(ctx context.Context, item auth.SprintItem) (int64, error)

	// UpdateSprintItem sets criteria, roadmapID, status, apple_id, and updated_at.
	UpdateSprintItem(ctx context.Context, id int64, criteriaJSON, roadmapID, status string, appleID int64) error

	// GetSprintItem returns a single sprint by ID.
	GetSprintItem(ctx context.Context, id int64) (*auth.SprintItem, error)

	// ListSprintItems returns up to limit sprints. Pass agentName="" for all agents.
	// Pass status="" to return all statuses. Returns newest first.
	ListSprintItems(ctx context.Context, agentName, status string, limit int) ([]auth.SprintItem, error)

	// --- Subscriptions (Emily+ subscription gate — S23-04) ---

	// GetUserSubscription returns the most recent subscription for userID.
	// Returns nil, nil when no subscription exists.
	GetUserSubscription(ctx context.Context, userID string) (*auth.Subscription, error)

	// UpsertUserSubscription inserts or updates a subscription for userID.
	// Uses userID as the unique key — one subscription record per user.
	UpsertUserSubscription(ctx context.Context, sub auth.Subscription) error

	// --- GFD subscription tiers (S124-02) ---

	// ListSubscriptionTiers returns all active GFD subscription tiers.
	ListSubscriptionTiers(ctx context.Context) ([]GFDTier, error)

	// GetGFDUserTier returns the current GFD tier for a user, or nil if unset.
	GetGFDUserTier(ctx context.Context, userID string) (*string, error)

	// SetGFDUserTier sets the tier_id on the user's subscription row.
	SetGFDUserTier(ctx context.Context, userID, tierID string) error

	// RecordStripeEvent records a Stripe webhook event (idempotent by event ID).
	RecordStripeEvent(ctx context.Context, eventID, eventType, userID, payload string) error

	// --- Check-in monitors (heartbeat/dead-man-switch alerting) ---

	// CreateMonitor inserts a new monitor and returns its ID.
	CreateMonitor(ctx context.Context, m auth.Monitor) (int64, error)

	// GetMonitorBySlug returns a monitor by its unique check-in slug.
	GetMonitorBySlug(ctx context.Context, slug string) (*auth.Monitor, error)

	// GetMonitorByID returns a monitor by its integer ID.
	GetMonitorByID(ctx context.Context, id int64) (*auth.Monitor, error)

	// ListMonitors returns all monitors for the given owner (pass "" for all).
	ListMonitors(ctx context.Context, owner string) ([]auth.Monitor, error)

	// UpdateMonitor updates name, kind, timeout, grace, and alert config by ID.
	UpdateMonitor(ctx context.Context, m auth.Monitor) error

	// RecordCheckin updates last_checkin_at, sets status=healthy, clears alerted_at.
	RecordCheckin(ctx context.Context, slug string, now time.Time) error

	// MarkMonitorAlerted sets alerted_at and status=failing on the monitor.
	MarkMonitorAlerted(ctx context.Context, id int64, now time.Time) error

	// RecoverMonitor clears alerted_at and sets status=healthy without a check-in.
	RecoverMonitor(ctx context.Context, id int64, now time.Time) error

	// ListOverdueMonitors returns monitors that have exceeded their timeout
	// (kind-sensitive: deadman uses no grace) and have not yet been alerted.
	ListOverdueMonitors(ctx context.Context, now time.Time) ([]auth.Monitor, error)

	// DeleteMonitor removes a monitor by ID.
	DeleteMonitor(ctx context.Context, id int64) error
}
