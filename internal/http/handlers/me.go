package handlers

import (
	"net/http"
	"strconv"
	"strings"

	"idunapro/internal/http/middleware"
	"idunapro/internal/store"
	"idunapro/internal/userlog"
)

// MeHandler handles GET /api/v1/identities/me.
type MeHandler struct {
	Store     store.IAMStore
	Proj      userlog.UserProjector // real, found-live gap fix: local-auth users live here, not Store
	Authority string                // base URL used in authority_signature_cluster
}

// localUserIdentity resolves a "local:<uid>" subject against the real local_users projection
// (the same store.LocalAuthHandler itself reads) and builds the same real identity/rbac/meta
// shape ServeHTTP returns for a Google/M2M subject. Real, found-live gap fixed (2026-09-04,
// cruise-queue card 9988): sub for a local-auth JWT is "local:<uid>" (LocalAuthHandler's own
// convention), but h.Store.GetUserByID queries the SEPARATE `users` table by its own real `id`
// column -- local-auth accounts have no row there at all (local_users is its own real,
// separate projection, confirmed directly), so /me 404'd for every local-auth session,
// unconditionally, since this handler shipped.
func (h *MeHandler) localUserIdentity(w http.ResponseWriter, r *http.Request, sub string) {
	uidStr := strings.TrimPrefix(sub, "local:")
	uid, err := strconv.Atoi(uidStr)
	if err != nil {
		writeJSON(w, http.StatusNotFound, map[string]any{
			"code":    "NOT_FOUND",
			"message": "identity not found",
		})
		return
	}
	u, err := h.Proj.GetByUID(r.Context(), uid)
	if err != nil || u == nil {
		writeJSON(w, http.StatusNotFound, map[string]any{
			"code":    "NOT_FOUND",
			"message": "identity not found",
		})
		return
	}

	authority := h.Authority
	if authority == "" {
		authority = "https://iam.farthq.internal"
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"identity": map[string]any{
			"id":       sub,
			"email":    u.Email,
			"gamertag": u.DisplayName,
			"status":   u.Status,
		},
		"rbac": map[string]any{
			"assigned_roles":        []string{},
			"effective_permissions": localUserPermissions(u),
		},
		"meta": map[string]any{
			"server_epoch":                epochNow(),
			"authority_signature_cluster": authority + "/.well-known/jwks.json",
		},
	})
}

func (h *MeHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.NotFound(w, r)
		return
	}

	sub := middleware.SubjectFromContext(r.Context())
	if sub == "" {
		writeJSON(w, http.StatusUnauthorized, map[string]any{
			"code":    "UNAUTHORIZED",
			"message": "missing subject",
		})
		return
	}

	if strings.HasPrefix(sub, "local:") {
		if h.Proj == nil {
			writeJSON(w, http.StatusNotFound, map[string]any{
				"code":    "NOT_FOUND",
				"message": "identity not found",
			})
			return
		}
		h.localUserIdentity(w, r, sub)
		return
	}

	claims := middleware.ClaimsFromContext(r.Context())
	user, err := h.Store.GetUserByID(r.Context(), sub)
	if err != nil {
		writeJSON(w, http.StatusNotFound, map[string]any{
			"code":    "NOT_FOUND",
			"message": "identity not found",
		})
		return
	}

	perms, err := h.Store.GetEffectivePermissions(r.Context(), sub)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{
			"code":    "INTERNAL",
			"message": "failed to resolve permissions",
		})
		return
	}

	// Derive assigned roles from the JWT claims so we don't need an extra query.
	var assignedRoles []string
	if roles, ok := claims["roles"].([]any); ok {
		for _, r := range roles {
			if s, ok := r.(string); ok {
				assignedRoles = append(assignedRoles, s)
			}
		}
	}
	if len(assignedRoles) == 0 {
		assignedRoles = user.Roles
	}

	authority := h.Authority
	if authority == "" {
		authority = "https://iam.farthq.internal"
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"identity": map[string]any{
			"id":       user.IDString,
			"email":    user.Email,
			"gamertag": user.Handle,
			"status":   user.Status,
		},
		"rbac": map[string]any{
			"assigned_roles":        assignedRoles,
			"effective_permissions": perms,
		},
		"meta": map[string]any{
			"server_epoch":                epochNow(),
			"authority_signature_cluster": authority + "/.well-known/jwks.json",
		},
	})
}
