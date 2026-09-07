package handlers

import (
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
		// CP-HIPAA-2: a Provider Admin (providers.manage) can also reach this route -- the real,
		// necessary way they grant/revoke the Provider Operator role on someone else. updateUser
		// itself enforces which FIELDS a providers.manage-only caller (no users.admin) may touch
		// (is_provider only) and which TARGETS anyone below Top Admin may touch (never another
		// admin-tier account) -- see its own tier-guard logic.
		if hasPermission(r, "users.admin") || hasPermission(r, "providers.manage") {
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
	payload, _ := json.Marshal(userlog.UserCreatedData{
		LocalUID:     nextUID,
		Email:        req.Email,
		DisplayName:  req.DisplayName,
		PasswordHash: string(hash),
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

	// CP-HIPAA-2 tier guard. Real, load-bearing access-control logic -- see localUserPermissions'
	// own doc comment for the full 4-tier model this enforces.
	isTopAdmin := hasPermission(r, "admins.manage")
	isUsersAdmin := hasPermission(r, "users.admin") // true for both Top and Operator Admin
	isProviderAdmin := hasPermission(r, "providers.manage")

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

	// A Provider-Admin-only caller (providers.manage but not users.admin) may ONLY grant/revoke
	// the Provider Operator role -- every other field here (email, password, status, and the
	// admin-tier fields already checked above) is out of scope for that tier.
	if isProviderAdmin && !isUsersAdmin {
		if req.Email != nil || req.DisplayName != nil || req.Password != nil || req.Status != nil {
			writeJSON(w, http.StatusForbidden, map[string]string{"error": "forbidden: a provider admin may only grant or revoke the provider role"})
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
