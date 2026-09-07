package handlers

import (
	"database/sql"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
)

// OrganizationsHandler exposes real, minimal CRUD for the organizations table (CP-HIPAA-3,
// founder real-time: "there may be a several organizations who have service agreements with
// each other in that case the admins from that collective should be able to administer
// participants from that cluster of providers"). Internal, platform-operator tooling -- which
// agencies exist, which market/cluster each belongs to -- users.admin-gated throughout, same
// "internal tooling for whoever already manages users" category sip_accounts.go's own migration
// comment already establishes. No provider or provider admin ever reaches this handler; a
// provider's own org_id is set automatically when an admin assigns it via PATCH /api/v1/users/
// {uid} {"org_id": N}, or inherited automatically for a participant they onboard (users.go's own
// createUser) -- "batteries included happy path," organizations themselves are the one real
// piece of setup an admin does by hand.
//
// Routes (all require Bearer JWT + users.admin):
//
//	GET  /api/v1/organizations       list every organization
//	POST /api/v1/organizations       create one -- {"name", "cluster_id" (optional)}
//	PATCH /api/v1/organizations/{id} reassign cluster_id -- {"cluster_id": N or null}
type OrganizationsHandler struct {
	DB *sql.DB
}

type organization struct {
	ID        int    `json:"id"`
	Name      string `json:"name"`
	ClusterID *int   `json:"cluster_id,omitempty"`
	CreatedAt string `json:"created_at"`
}

func (h *OrganizationsHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if h.DB == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "organizations not available"})
		return
	}
	if !hasPermission(r, "users.admin") {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "forbidden"})
		return
	}

	path := strings.TrimPrefix(r.URL.Path, "/api/v1/organizations")
	path = strings.TrimPrefix(path, "/")

	if path == "" {
		switch r.Method {
		case http.MethodGet:
			h.list(w, r)
		case http.MethodPost:
			h.create(w, r)
		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
		return
	}

	id, err := strconv.Atoi(strings.TrimSuffix(path, "/"))
	if err != nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "not found"})
		return
	}
	if r.Method != http.MethodPatch {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	h.updateCluster(w, r, id)
}

func (h *OrganizationsHandler) list(w http.ResponseWriter, r *http.Request) {
	rows, err := h.DB.QueryContext(r.Context(), `SELECT id, name, cluster_id, created_at FROM organizations ORDER BY id`)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	defer rows.Close()
	out := []organization{}
	for rows.Next() {
		var o organization
		var clusterID sql.NullInt64
		if err := rows.Scan(&o.ID, &o.Name, &clusterID, &o.CreatedAt); err != nil {
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		if clusterID.Valid {
			v := int(clusterID.Int64)
			o.ClusterID = &v
		}
		out = append(out, o)
	}
	writeJSON(w, http.StatusOK, out)
}

type createOrgRequest struct {
	Name      string `json:"name"`
	ClusterID *int   `json:"cluster_id"`
}

func (h *OrganizationsHandler) create(w http.ResponseWriter, r *http.Request) {
	var req createOrgRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON"})
		return
	}
	req.Name = strings.TrimSpace(req.Name)
	if req.Name == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "name is required"})
		return
	}
	res, err := h.DB.ExecContext(r.Context(),
		`INSERT INTO organizations (name, cluster_id) VALUES (?, ?)`, req.Name, req.ClusterID)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	id, _ := res.LastInsertId()
	writeJSON(w, http.StatusCreated, organization{ID: int(id), Name: req.Name, ClusterID: req.ClusterID})
}

type updateOrgClusterRequest struct {
	ClusterID *int `json:"cluster_id"`
}

// updateCluster -- CP-HIPAA-3: real, deliberate v0 scope: the only field an admin ever needs to
// change after an organization exists is which cluster it belongs to (renaming an org, or
// deleting one, are real, separate, not-yet-needed operations -- named honestly, not built).
// Passing {"cluster_id": null} removes an organization from its cluster entirely (no cross-org
// trust for anyone in it until reassigned).
func (h *OrganizationsHandler) updateCluster(w http.ResponseWriter, r *http.Request, id int) {
	var req updateOrgClusterRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON"})
		return
	}
	res, err := h.DB.ExecContext(r.Context(), `UPDATE organizations SET cluster_id = ? WHERE id = ?`, req.ClusterID, id)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "not found"})
		return
	}
	writeJSON(w, http.StatusOK, organization{ID: id, ClusterID: req.ClusterID})
}
