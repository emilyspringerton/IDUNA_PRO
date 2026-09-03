package handlers

import (
	"net/http"

	"idunapro/internal/http/middleware"
	"idunapro/internal/store"
)

// MeHandler handles GET /api/v1/identities/me.
type MeHandler struct {
	Store     store.IAMStore
	Authority string // base URL used in authority_signature_cluster
}

func (h *MeHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.NotFound(w, r)
		return
	}

	claims := middleware.ClaimsFromContext(r.Context())
	sub := middleware.SubjectFromContext(r.Context())
	if sub == "" {
		writeJSON(w, http.StatusUnauthorized, map[string]any{
			"code":    "UNAUTHORIZED",
			"message": "missing subject",
		})
		return
	}

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
			"assigned_roles":       assignedRoles,
			"effective_permissions": perms,
		},
		"meta": map[string]any{
			"server_epoch":              epochNow(),
			"authority_signature_cluster": authority + "/.well-known/jwks.json",
		},
	})
}
