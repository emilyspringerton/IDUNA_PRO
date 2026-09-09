package handlers

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"

	"idunapro/internal/http/middleware"
	"idunapro/internal/userlog"
)

// UsersHandler handles user CRUD at /api/v1/users and /api/v1/users/{uid}.
//
// Routes (all require Bearer JWT via middleware.RequireAuth):
//
//	POST   /api/v1/users            create user           requires users.admin OR
//	                                                      mail-accounts.provision (CP-HIPAA-1)
//	GET    /api/v1/users            list users            requires users.admin
//	GET    /api/v1/users/{uid}      get user              requires users.admin OR sub=local:{uid}
//	PATCH  /api/v1/users/{uid}      update user           requires users.admin
//	DELETE /api/v1/users/{uid}      soft-delete user      requires users.admin
type UsersHandler struct {
	Log  userlog.EventLog
	Proj userlog.UserProjector
	// DB -- CP-HIPAA-3: real, direct SQL access for the organizations/cluster-trust lookup
	// (orgsShareCluster) and the cross_org_access_log audit insert (logCrossOrgAccess). Nil-safe:
	// with no DB wired, orgsShareCluster always fails closed (no cluster-based access at all),
	// same "feature unavailable, not a panic" convention MailAccountsHandler.CredentialsKey
	// already establishes.
	DB *sql.DB
}

// ── wire helpers ─────────────────────────────────────────────────────────────

// ServeHTTP dispatches by method and path suffix.
func (h *UsersHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Strip /api/v1/users prefix.
	path := strings.TrimPrefix(r.URL.Path, "/api/v1/users")
	path = strings.TrimPrefix(path, "/")

	if path == "" || path == "/" {
		switch r.Method {
		case http.MethodPost:
			// CP-HIPAA-1: a provider (mail-accounts.provision) can also create a participant's
			// local user record -- the real, necessary first half of "providers can create email
			// accounts for participants" (a mailbox needs a local_uid to link to; only
			// users.admin could ever create one before). createUser itself takes no is_admin/
			// is_provider/status input, so a provider-only caller can't escalate anything via
			// this route -- listUsers/updateUser/deleteUser stay users.admin-only below,
			// unchanged, so a provider still can't browse or manage every OTHER participant.
			if hasPermission(r, "users.admin") || hasPermission(r, "mail-accounts.provision") {
				h.createUser(w, r)
			} else {
				writeJSON(w, http.StatusForbidden, map[string]string{"error": "forbidden"})
			}
		case http.MethodGet:
			h.requirePerm(w, r, "users.admin", h.listUsers)
		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
		return
	}

	// /api/v1/users/{uid}
	uidStr := strings.TrimSuffix(path, "/")
	uid, err := strconv.Atoi(uidStr)
	if err != nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "not found"})
		return
	}

	switch r.Method {
	case http.MethodGet:
		h.getUser(w, r, uid)
	case http.MethodPatch:
		// CP-HIPAA-2/CP-HIPAA-3: a Provider Admin (providers.manage) or a plain Provider Operator
		// (mail-accounts.provision) can also reach this route -- a Provider Admin's real,
		// necessary way to grant/revoke the Provider Operator role on someone else, and a
		// Provider Operator's real, necessary way to reset a participant's password within a
		// shared trusted cluster ("the service navigator at the shelter... needs to be able to
		// password reset that participant"). updateUser itself enforces which FIELDS a
		// provider-tier caller (no users.admin) may touch and which TARGETS anyone below Top
		// Admin may touch (never another admin-tier account) -- see its own tier-guard logic.
		if hasPermission(r, "users.admin") || hasPermission(r, "providers.manage") || hasPermission(r, "mail-accounts.provision") {
			h.updateUser(w, r, uid)
		} else {
			writeJSON(w, http.StatusForbidden, map[string]string{"error": "forbidden"})
		}
	case http.MethodDelete:
		h.requirePerm(w, r, "users.admin", func(w http.ResponseWriter, r *http.Request) {
			h.deleteUser(w, r, uid)
		})
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// ── create ───────────────────────────────────────────────────────────────────

type createUserRequest struct {
	Email       string `json:"email"`
	Password    string `json:"password"`
	DisplayName string `json:"display_name"`
}

func (h *UsersHandler) createUser(w http.ResponseWriter, r *http.Request) {
	var req createUserRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON"})
		return
	}
	req.Email = strings.TrimSpace(strings.ToLower(req.Email))
	if req.Email == "" || req.Password == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "email and password required"})
		return
	}

	existing, err := h.Proj.GetByEmail(r.Context(), req.Email)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if existing != nil {
		writeJSON(w, http.StatusConflict, map[string]string{"error": "email already exists"})
		return
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	nextUID, err := h.Proj.NextUID(r.Context())
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	operatorUID := operatorUIDFromContext(r)
	// CP-HIPAA-3 "batteries included happy path": the new participant's own OrgID is stamped
	// automatically from the creating provider's own org_id JWT claim -- the provider never
	// picks an organization by hand, it's inherited from whoever's actually onboarding this
	// person. A caller with no org_id (0, the default) produces a participant with no org_id
	// either -- correctly opts them out of any cluster-wide access until an admin assigns one.
	payload, _ := json.Marshal(userlog.UserCreatedData{
		LocalUID:     nextUID,
		Email:        req.Email,
		DisplayName:  req.DisplayName,
		PasswordHash: string(hash),
		OrgID:        callerOrgID(r),
	})
	ev := userlog.Event{
		ID:          uuid.New().String(),
		Type:        userlog.EventUserCreated,
		Source:      "idunapro/api",
		OccurredAt:  time.Now().UTC(),
		OperatorUID: operatorUID,
		Data:        json.RawMessage(payload),
	}
	records, err := h.Log.Append(r.Context(), ev)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if err := h.Proj.Apply(r.Context(), records[0]); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	_ = h.Proj.AdvanceCursor(r.Context(), records[0].Sequence)

	user, _ := h.Proj.GetByUID(r.Context(), nextUID)
	writeJSON(w, http.StatusCreated, userToJSON(user))
}

// ── list ─────────────────────────────────────────────────────────────────────

func (h *UsersHandler) listUsers(w http.ResponseWriter, r *http.Request) {
	limit := 100
	if s := r.URL.Query().Get("limit"); s != "" {
		if n, err := strconv.Atoi(s); err == nil && n > 0 {
			limit = n
		}
	}
	users, err := h.Proj.ListUsers(r.Context(), limit)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	out := make([]map[string]any, len(users))
	for i, u := range users {
		out[i] = userToJSON(&u)
	}
	writeJSON(w, http.StatusOK, out)
}

// ── get ──────────────────────────────────────────────────────────────────────

func (h *UsersHandler) getUser(w http.ResponseWriter, r *http.Request, uid int) {
	// Allow self-read (sub=local:{uid}) or users.admin.
	if !hasPermission(r, "users.admin") {
		callerUID := callerLocalUID(r)
		if callerUID == nil || *callerUID != uid {
			writeJSON(w, http.StatusForbidden, map[string]string{"error": "forbidden"})
			return
		}
	}
	user, err := h.Proj.GetByUID(r.Context(), uid)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if user == nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "not found"})
		return
	}
	writeJSON(w, http.StatusOK, userToJSON(user))
}

// ── update ───────────────────────────────────────────────────────────────────

type updateUserRequest struct {
	Email       *string `json:"email,omitempty"`
	DisplayName *string `json:"display_name,omitempty"`
	Password    *string `json:"password,omitempty"`
	Status      *string `json:"status,omitempty"`
	// IsAdmin -- CP-SIP-ADMIN-124323: the real, ongoing (post-genesis) way one admin grants or
	// revokes admin on another user, gated the same as every other field here (this whole
	// route already requires users.admin -- see ServeHTTP's own dispatch).
	IsAdmin *bool `json:"is_admin,omitempty"`
	// IsProvider -- CP-HIPAA-1: grants/revokes the least-privilege "Provider Operator" role
	// (mail-accounts.provision/sip-accounts.provision only). Settable by users.admin OR
	// providers.manage (a Provider Admin) -- see updateUser's own tier-guard logic.
	IsProvider *bool `json:"is_provider,omitempty"`
	// IsOperatorAdmin / IsProviderAdmin -- CP-HIPAA-2, the 3rd/4th RBAC tiers. Granting either
	// (like IsAdmin) requires admins.manage (Top Admin only) -- see updateUser's tier guard.
	IsOperatorAdmin *bool `json:"is_operator_admin,omitempty"`
	IsProviderAdmin *bool `json:"is_provider_admin,omitempty"`
	// OrgID -- CP-HIPAA-3: (re)assigns which organization this user belongs to (provider) or was
	// onboarded by (participant). users.admin-gated, same tier as ordinary user management (NOT
	// admins.manage-gated -- this doesn't grant any elevated PERMISSION tier, only changes
	// cluster-trust SCOPE, a real, deliberate distinction from is_admin/is_operator_admin/
	// is_provider_admin above).
	OrgID *int `json:"org_id,omitempty"`
	// IsCommunityToolsEnabled -- founder real-time, 2026-09-09: the real, plain per-account
	// feature flag gating "community tools" (the resume/CV builder, v0's own real first one).
	// Settable by users.admin, same as ordinary user management -- deliberately NOT
	// admins.manage-gated, since it grants no elevated RBAC tier, only access to one
	// participant-facing feature (the same real distinction OrgID's own doc comment already
	// draws for cluster-trust scope vs. permission tier).
	IsCommunityToolsEnabled *bool `json:"is_community_tools_enabled,omitempty"`
}

func (h *UsersHandler) updateUser(w http.ResponseWriter, r *http.Request, uid int) {
	if uid == 0 && !callerIsUID0(r) {
		// Only webmaster can modify uid=0.
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "cannot modify webmaster via API"})
		return
	}

	existing, err := h.Proj.GetByUID(r.Context(), uid)
	if err != nil || existing == nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "not found"})
		return
	}

	var req updateUserRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON"})
		return
	}

	// CP-HIPAA-2/CP-HIPAA-3 tier guard. Real, load-bearing access-control logic -- see
	// localUserPermissions' own doc comment for the full 4-tier model, and orgsShareCluster's
	// own doc comment for the cluster-trust model this also enforces.
	isTopAdmin := hasPermission(r, "admins.manage")
	isUsersAdmin := hasPermission(r, "users.admin") // true for both Top and Operator Admin
	isProviderAdmin := hasPermission(r, "providers.manage")
	isProviderTier := hasPermission(r, "mail-accounts.provision") // Provider Operator OR Provider Admin

	targetIsAdminTier := existing.LocalUID == 0 || existing.IsAdmin || existing.IsOperatorAdmin
	if targetIsAdminTier && !isTopAdmin {
		// Operator Admin cannot modify or disable another admin-tier account (Top or Operator) --
		// the one real restriction the founder named directly ("mid level operator admins cant
		// disable other operator admins"). A Provider Admin obviously can't reach an admin-tier
		// account either.
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "forbidden: only a top admin can modify an admin-tier account"})
		return
	}

	// Granting/revoking admin-tier roles themselves is Top-Admin-only, matching
	// CP-SIP-ADMIN-124323's own "admin genesis" caution -- an Operator or Provider Admin cannot
	// mint a new peer or promote anyone into the admin tiers.
	if (req.IsAdmin != nil || req.IsOperatorAdmin != nil || req.IsProviderAdmin != nil) && !isTopAdmin {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "forbidden: only a top admin can grant or revoke an admin-tier role"})
		return
	}

	// OrgID reassignment is users.admin-gated (Top or Operator Admin), not a provider action --
	// changing which org someone belongs to is real, internal platform-operator bookkeeping.
	if req.OrgID != nil && !isUsersAdmin {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "forbidden: only an admin can reassign a user's organization"})
		return
	}

	// IsCommunityToolsEnabled -- founder real-time, 2026-09-09: users.admin-gated, same tier as
	// OrgID above (it grants no elevated RBAC tier, only access to one participant-facing
	// feature -- see updateUserRequest's own doc comment on this field).
	if req.IsCommunityToolsEnabled != nil && !isUsersAdmin {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "forbidden: only an admin can change a user's community-tools access"})
		return
	}

	// CP-HIPAA-3: the real worked example this section exists for -- "the service navigator at
	// the shelter that participant stays at needs to be able to password reset that
	// participant... we will assume the provider cluster is a trusted network for now." A
	// provider-tier caller (Operator OR Admin, not just providers.manage) may reset a
	// participant's PASSWORD -- and ONLY the password, nothing else -- when their own
	// organization shares a cluster with the participant's own owning organization. isCrossOrg
	// is computed once here (used both to gate the request and to decide whether this specific
	// action needs a real cross_org_access_log row below).
	isCrossOrgPasswordReset := false
	if (isProviderTier || isProviderAdmin) && !isUsersAdmin && req.Password != nil {
		callerOrg := callerOrgID(r)
		if !orgsShareCluster(r.Context(), h.DB, callerOrg, existing.OrgID) {
			writeJSON(w, http.StatusForbidden, map[string]string{"error": "forbidden: password reset requires the same organization or a shared trusted cluster"})
			return
		}
		isCrossOrgPasswordReset = callerOrg != existing.OrgID
	}

	// A provider-tier caller (Operator OR Admin, providers.manage and/or mail-accounts.provision
	// -- checked independently since a hand-crafted token may legitimately carry only one) may
	// touch AT MOST: is_provider (Provider Admin only, providers.manage) and password (both
	// tiers, cluster-gated above) -- every other field here (email, display_name, status,
	// org_id, and the admin-tier fields already checked above) stays out of scope for this tier,
	// a deliberate, narrow first slice ("it doesn't need to be totally granular yet... but
	// building towards that").
	if (isProviderTier || isProviderAdmin) && !isUsersAdmin {
		if req.Email != nil || req.DisplayName != nil || req.Status != nil {
			writeJSON(w, http.StatusForbidden, map[string]string{"error": "forbidden: a provider may only reset a participant's password or (Provider Admin only) grant/revoke the provider role"})
			return
		}
		if req.IsProvider != nil && !isProviderAdmin {
			writeJSON(w, http.StatusForbidden, map[string]string{"error": "forbidden: only a provider admin may grant or revoke the provider role"})
			return
		}
	}

	operatorUID := operatorUIDFromContext(r)
	now := time.Now().UTC()
	ctx := r.Context()

	// Field updates (email / display_name).
	if req.Email != nil || req.DisplayName != nil {
		if req.Email != nil {
			*req.Email = strings.TrimSpace(strings.ToLower(*req.Email))
		}
		payload, _ := json.Marshal(userlog.UserUpdatedData{
			LocalUID:    uid,
			Email:       req.Email,
			DisplayName: req.DisplayName,
		})
		ev := userlog.Event{
			ID:          uuid.New().String(),
			Type:        userlog.EventUserUpdated,
			Source:      "idunapro/api",
			OccurredAt:  now,
			OperatorUID: operatorUID,
			Data:        json.RawMessage(payload),
		}
		recs, err := h.Log.Append(ctx, ev)
		if err != nil {
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		_ = h.Proj.Apply(ctx, recs[0])
		_ = h.Proj.AdvanceCursor(ctx, recs[0].Sequence)
	}

	// Password change.
	if req.Password != nil {
		hash, err := bcrypt.GenerateFromPassword([]byte(*req.Password), bcrypt.DefaultCost)
		if err != nil {
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		payload, _ := json.Marshal(userlog.UserPasswordResetData{
			LocalUID:     uid,
			PasswordHash: string(hash),
		})
		ev := userlog.Event{
			ID:          uuid.New().String(),
			Type:        userlog.EventUserPasswordReset,
			Source:      "idunapro/api",
			OccurredAt:  now,
			OperatorUID: operatorUID,
			Data:        json.RawMessage(payload),
		}
		recs, err := h.Log.Append(ctx, ev)
		if err != nil {
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		_ = h.Proj.Apply(ctx, recs[0])
		_ = h.Proj.AdvanceCursor(ctx, recs[0].Sequence)

		// CP-HIPAA-3: "we need intense logging to ensure against fraud waste and abuse." A real,
		// dedicated audit row for exactly the sensitive case the cluster-trust model creates --
		// an actor from a DIFFERENT organization than the participant's own resetting their
		// password, only possible because both organizations share a cluster. A same-org reset
		// (the common case -- a provider resetting their own participant) is not logged here,
		// same reasoning cross_org_access_log's own migration comment gives.
		if isCrossOrgPasswordReset {
			logCrossOrgAccess(ctx, h.DB, operatorUID, callerOrgID(r), uid, existing.OrgID, "password_reset")
		}
	}

	// Status change.
	if req.Status != nil {
		validStatuses := map[string]bool{"active": true, "suspended": true}
		if !validStatuses[*req.Status] {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid status; valid values: active, suspended"})
			return
		}
		payload, _ := json.Marshal(userlog.UserStatusChangedData{
			LocalUID:  uid,
			OldStatus: existing.Status,
			NewStatus: *req.Status,
		})
		ev := userlog.Event{
			ID:          uuid.New().String(),
			Type:        userlog.EventUserStatusChanged,
			Source:      "idunapro/api",
			OccurredAt:  now,
			OperatorUID: operatorUID,
			Data:        json.RawMessage(payload),
		}
		recs, err := h.Log.Append(ctx, ev)
		if err != nil {
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		_ = h.Proj.Apply(ctx, recs[0])
		_ = h.Proj.AdvanceCursor(ctx, recs[0].Sequence)
	}

	// Admin grant/revoke (CP-SIP-ADMIN-124323). uid=0 is already always admin regardless of
	// this field -- a real, harmless no-op if someone tries to toggle it there.
	if req.IsAdmin != nil {
		payload, _ := json.Marshal(userlog.UserAdminChangedData{
			LocalUID: uid,
			IsAdmin:  *req.IsAdmin,
		})
		ev := userlog.Event{
			ID:          uuid.New().String(),
			Type:        userlog.EventUserAdminChanged,
			Source:      "idunapro/api",
			OccurredAt:  now,
			OperatorUID: operatorUID,
			Data:        json.RawMessage(payload),
		}
		recs, err := h.Log.Append(ctx, ev)
		if err != nil {
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		_ = h.Proj.Apply(ctx, recs[0])
		_ = h.Proj.AdvanceCursor(ctx, recs[0].Sequence)
	}

	// Provider Operator grant/revoke (CP-HIPAA-1). Same shape as the admin grant/revoke block
	// above. Reachable by users.admin OR providers.manage (a Provider Admin) -- see this
	// function's own tier guard above for what else providers.manage is (and isn't) allowed to
	// touch.
	if req.IsProvider != nil {
		payload, _ := json.Marshal(userlog.UserProviderChangedData{
			LocalUID:   uid,
			IsProvider: *req.IsProvider,
		})
		ev := userlog.Event{
			ID:          uuid.New().String(),
			Type:        userlog.EventUserProviderChanged,
			Source:      "idunapro/api",
			OccurredAt:  now,
			OperatorUID: operatorUID,
			Data:        json.RawMessage(payload),
		}
		recs, err := h.Log.Append(ctx, ev)
		if err != nil {
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		_ = h.Proj.Apply(ctx, recs[0])
		_ = h.Proj.AdvanceCursor(ctx, recs[0].Sequence)
	}

	// Operator Admin grant/revoke (CP-HIPAA-2). Top-Admin-only -- already enforced above.
	if req.IsOperatorAdmin != nil {
		payload, _ := json.Marshal(userlog.UserOperatorAdminChangedData{
			LocalUID:        uid,
			IsOperatorAdmin: *req.IsOperatorAdmin,
		})
		ev := userlog.Event{
			ID:          uuid.New().String(),
			Type:        userlog.EventUserOperatorAdminChanged,
			Source:      "idunapro/api",
			OccurredAt:  now,
			OperatorUID: operatorUID,
			Data:        json.RawMessage(payload),
		}
		recs, err := h.Log.Append(ctx, ev)
		if err != nil {
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		_ = h.Proj.Apply(ctx, recs[0])
		_ = h.Proj.AdvanceCursor(ctx, recs[0].Sequence)
	}

	// Provider Admin grant/revoke (CP-HIPAA-2). Top-Admin-only -- already enforced above.
	if req.IsProviderAdmin != nil {
		payload, _ := json.Marshal(userlog.UserProviderAdminChangedData{
			LocalUID:        uid,
			IsProviderAdmin: *req.IsProviderAdmin,
		})
		ev := userlog.Event{
			ID:          uuid.New().String(),
			Type:        userlog.EventUserProviderAdminChanged,
			Source:      "idunapro/api",
			OccurredAt:  now,
			OperatorUID: operatorUID,
			Data:        json.RawMessage(payload),
		}
		recs, err := h.Log.Append(ctx, ev)
		if err != nil {
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		_ = h.Proj.Apply(ctx, recs[0])
		_ = h.Proj.AdvanceCursor(ctx, recs[0].Sequence)
	}

	// Organization (re)assignment (CP-HIPAA-3). users.admin-gated -- already enforced above.
	if req.OrgID != nil {
		payload, _ := json.Marshal(userlog.UserOrgChangedData{
			LocalUID: uid,
			OrgID:    *req.OrgID,
		})
		ev := userlog.Event{
			ID:          uuid.New().String(),
			Type:        userlog.EventUserOrgChanged,
			Source:      "idunapro/api",
			OccurredAt:  now,
			OperatorUID: operatorUID,
			Data:        json.RawMessage(payload),
		}
		recs, err := h.Log.Append(ctx, ev)
		if err != nil {
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		_ = h.Proj.Apply(ctx, recs[0])
		_ = h.Proj.AdvanceCursor(ctx, recs[0].Sequence)
	}

	// Community-tools feature flag grant/revoke. users.admin-gated -- already enforced above.
	if req.IsCommunityToolsEnabled != nil {
		payload, _ := json.Marshal(userlog.UserCommunityToolsChangedData{
			LocalUID:                uid,
			IsCommunityToolsEnabled: *req.IsCommunityToolsEnabled,
		})
		ev := userlog.Event{
			ID:          uuid.New().String(),
			Type:        userlog.EventUserCommunityToolsChanged,
			Source:      "idunapro/api",
			OccurredAt:  now,
			OperatorUID: operatorUID,
			Data:        json.RawMessage(payload),
		}
		recs, err := h.Log.Append(ctx, ev)
		if err != nil {
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		_ = h.Proj.Apply(ctx, recs[0])
		_ = h.Proj.AdvanceCursor(ctx, recs[0].Sequence)
	}

	updated, _ := h.Proj.GetByUID(ctx, uid)
	if updated == nil {
		updated = existing
	}
	writeJSON(w, http.StatusOK, userToJSON(updated))
}

// ── delete ───────────────────────────────────────────────────────────────────

func (h *UsersHandler) deleteUser(w http.ResponseWriter, r *http.Request, uid int) {
	if uid == 0 {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "cannot delete webmaster (uid=0)"})
		return
	}
	existing, err := h.Proj.GetByUID(r.Context(), uid)
	if err != nil || existing == nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "not found"})
		return
	}

	// CP-HIPAA-2 tier guard: an Operator Admin cannot delete another admin-tier account -- same
	// restriction updateUser enforces for mutation, see localUserPermissions' own doc comment.
	if (existing.IsAdmin || existing.IsOperatorAdmin) && !hasPermission(r, "admins.manage") {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "forbidden: only a top admin can delete an admin-tier account"})
		return
	}

	payload, _ := json.Marshal(userlog.UserDeletedData{LocalUID: uid})
	ev := userlog.Event{
		ID:          uuid.New().String(),
		Type:        userlog.EventUserDeleted,
		Source:      "idunapro/api",
		OccurredAt:  time.Now().UTC(),
		OperatorUID: operatorUIDFromContext(r),
		Data:        json.RawMessage(payload),
	}
	recs, err := h.Log.Append(r.Context(), ev)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	_ = h.Proj.Apply(r.Context(), recs[0])
	_ = h.Proj.AdvanceCursor(r.Context(), recs[0].Sequence)

	w.WriteHeader(http.StatusNoContent)
}

// ── helpers ───────────────────────────────────────────────────────────────────

func userToJSON(u *userlog.LocalUser) map[string]any {
	return map[string]any{
		"local_uid":    u.LocalUID,
		"email":        u.Email,
		"display_name": u.DisplayName,
		"status":       u.Status,
		// is_admin -- CP-SIP-ADMIN-124323: real, so an admin console can show who already
		// holds admin without guessing from local_uid==0 alone.
		"is_admin":          u.LocalUID == 0 || u.IsAdmin,
		"is_operator_admin": u.IsOperatorAdmin,
		"is_provider":       u.IsProvider,
		"is_provider_admin": u.IsProviderAdmin,
		"org_id":            u.OrgID,
		"created_at":        u.CreatedAt.Format(time.RFC3339),
		"updated_at":        u.UpdatedAt.Format(time.RFC3339),
	}
}

func (h *UsersHandler) requirePerm(w http.ResponseWriter, r *http.Request, perm string, next http.HandlerFunc) {
	if !hasPermission(r, perm) {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "forbidden"})
		return
	}
	next(w, r)
}

// hasPermission checks whether the JWT in the request context has a given permission.
func hasPermission(r *http.Request, perm string) bool {
	perms := middleware.PermissionsFromContext(r.Context())
	for _, p := range perms {
		if p == perm {
			return true
		}
	}
	return false
}

// operatorUIDFromContext extracts the local_uid from the JWT claims, 0 if absent.
func operatorUIDFromContext(r *http.Request) int {
	claims := middleware.ClaimsFromContext(r.Context())
	if claims == nil {
		return 0
	}
	if uid, ok := claims["local_uid"]; ok {
		switch v := uid.(type) {
		case float64:
			return int(v)
		case int:
			return v
		}
	}
	return 0
}

// callerLocalUID returns the local_uid from the JWT claims, or nil if not a local user.
func callerLocalUID(r *http.Request) *int {
	claims := middleware.ClaimsFromContext(r.Context())
	if claims == nil {
		return nil
	}
	if uid, ok := claims["local_uid"]; ok {
		switch v := uid.(type) {
		case float64:
			n := int(v)
			return &n
		case int:
			return &v
		}
	}
	return nil
}

func callerIsUID0(r *http.Request) bool {
	uid := callerLocalUID(r)
	return uid != nil && *uid == 0
}

// callerOrgID -- CP-HIPAA-3: extracts org_id from the JWT claims (baked in at login, see
// LocalAuthHandler's own claims map), 0 if absent -- 0 is the same "no organization assigned"
// sentinel LocalUser.OrgID's own doc comment establishes.
func callerOrgID(r *http.Request) int {
	claims := middleware.ClaimsFromContext(r.Context())
	if claims == nil {
		return 0
	}
	if v, ok := claims["org_id"]; ok {
		switch t := v.(type) {
		case float64:
			return int(t)
		case int:
			return t
		}
	}
	return 0
}

// orgsShareCluster -- CP-HIPAA-3 (founder real-time: "there may be a several organizations who
// have service agreements with each other... the admins from that collective should be able to
// administer participants from that cluster of providers... we will assume the provider cluster
// is a trusted network for now until we bring the service to multiple markets"). Real, load-
// bearing cluster-trust check: two organizations "share a cluster" if they're the literal same
// real organization, OR both carry the same real, non-null organizations.cluster_id.
//
// org 0 (unassigned) NEVER shares with anything, including another 0 -- a real, deliberate,
// safe-by-default rule: without this, every account created before organizations existed (every
// real account in this codebase as of this migration) would trivially "share" with every other
// unassigned account, silently granting brand-new cross-account access nobody asked for. Nil DB
// fails closed the same way (no cluster-based access at all without real org data to check
// against) -- same "feature unavailable, not a panic" convention this file's own DB field doc
// comment already establishes.
//
// Deliberately a bare int comparison, not a many-to-many join table -- "we will assume the
// provider cluster is a trusted network for now" reads as one flat trust boundary per real
// deployment/market today. A genuine org_cluster_membership table with per-relationship
// permissions is the real, later "zero-ish trust" granularity step the founder's own message
// explicitly named as a future direction, not built here.
func orgsShareCluster(ctx context.Context, db *sql.DB, orgA, orgB int) bool {
	if orgA == 0 || orgB == 0 {
		return false
	}
	if orgA == orgB {
		return true
	}
	if db == nil {
		return false
	}
	var clusterA, clusterB sql.NullInt64
	if err := db.QueryRowContext(ctx, `SELECT cluster_id FROM organizations WHERE id = ?`, orgA).Scan(&clusterA); err != nil {
		return false
	}
	if err := db.QueryRowContext(ctx, `SELECT cluster_id FROM organizations WHERE id = ?`, orgB).Scan(&clusterB); err != nil {
		return false
	}
	return clusterA.Valid && clusterB.Valid && clusterA.Int64 == clusterB.Int64
}

// logCrossOrgAccess -- CP-HIPAA-3 (founder real-time: "we need intense logging to ensure against
// fraud waste and abuse"). Real, direct insert into the dedicated cross_org_access_log table
// (see its own migration comment for why this is a real SQL table, not a generic event). Best-
// effort: a logging failure must never block the real action it's recording (same "audit the
// real thing that happened, don't let the audit trail become a new outage vector" reasoning
// every other fire-and-forget log call in this codebase already follows) -- the error is
// swallowed deliberately, not silently masking a bug elsewhere.
func logCrossOrgAccess(ctx context.Context, db *sql.DB, actorUID, actorOrgID, targetUID, targetOrgID int, action string) {
	if db == nil {
		return
	}
	_, _ = db.ExecContext(ctx,
		`INSERT INTO cross_org_access_log (actor_uid, actor_org_id, target_uid, target_org_id, action) VALUES (?, ?, ?, ?, ?)`,
		actorUID, actorOrgID, targetUID, targetOrgID, action)
}
