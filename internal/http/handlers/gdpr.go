package handlers

import (
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"strconv"
	"strings"

	"idunapro/internal/gdpr"
)

// GDPRHandler exposes the Article 15/17/20 data subject request pipeline (internal/gdpr) over
// HTTP -- founder real-time, 2026-09-07: "build gdpr into iduna pro multi tennant with data
// exporting and data delete request pipeline dont focus on the cookie confirm widget at this
// time."
//
// Routes (all require Bearer JWT via middleware.RequireAuth):
//
//	POST /api/v1/gdpr/export                 self-service export; users.admin required to pass a
//	                                          local_uid other than the caller's own
//	POST /api/v1/gdpr/delete                 self-service delete; same admin-on-behalf-of rule
//	GET  /api/v1/gdpr/requests                caller's own request history
//	GET  /api/v1/gdpr/requests?all=1          every request, requires users.admin
//	GET  /api/v1/gdpr/requests/{id}/download  download a completed export file (requester or
//	                                          users.admin only)
type GDPRHandler struct {
	Deps      gdpr.Deps
	ExportDir string
}

type gdprActRequest struct {
	// LocalUID -- omit for a self-service request; only users.admin may pass a value that
	// differs from the caller's own local_uid (acting on someone else's behalf).
	LocalUID *int `json:"local_uid,omitempty"`
}

func (h *GDPRHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/api/v1/gdpr")
	path = strings.TrimPrefix(path, "/")

	switch {
	case path == "export" && r.Method == http.MethodPost:
		h.export(w, r)
	case path == "delete" && r.Method == http.MethodPost:
		h.delete(w, r)
	case path == "requests" && r.Method == http.MethodGet:
		h.listRequests(w, r)
	case strings.HasPrefix(path, "requests/") && strings.HasSuffix(path, "/download") && r.Method == http.MethodGet:
		idStr := strings.TrimSuffix(strings.TrimPrefix(path, "requests/"), "/download")
		id, err := strconv.ParseInt(idStr, 10, 64)
		if err != nil {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "not found"})
			return
		}
		h.download(w, r, id)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// resolveTarget returns the local_uid this request targets: the caller's own uid by default, or
// a different uid from the request body if the caller holds users.admin. Writes a response and
// returns ok=false if the caller is unauthenticated or lacks admin for an on-behalf-of request.
// Also returns the caller's own tenantID (MULTI_TENANCY_NORTHSTAR.md Phase 1) -- gdpr.Export/
// Delete verify the target genuinely belongs to THIS tenant before touching anything, closing a
// real, found-live gap where an on-behalf-of request had no tenant check anywhere in the chain
// (see internal/gdpr/gdpr.go's own ErrNotFound doc comment for the full write-up).
func (h *GDPRHandler) resolveTarget(w http.ResponseWriter, r *http.Request) (target, caller, tenantID int, ok bool) {
	callerUID := callerLocalUID(r)
	if callerUID == nil {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "forbidden"})
		return 0, 0, 0, false
	}
	tenantID = callerTenantID(r)

	target = *callerUID
	if r.ContentLength != 0 {
		var req gdprActRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON"})
			return 0, 0, 0, false
		}
		if req.LocalUID != nil {
			target = *req.LocalUID
		}
	}

	if target != *callerUID && !hasPermission(r, "users.admin") {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "forbidden"})
		return 0, 0, 0, false
	}
	return target, *callerUID, tenantID, true
}

func (h *GDPRHandler) export(w http.ResponseWriter, r *http.Request) {
	target, caller, tenantID, ok := h.resolveTarget(w, r)
	if !ok {
		return
	}
	result, err := gdpr.Export(r.Context(), h.Deps, tenantID, target, caller, h.ExportDir)
	if errors.Is(err, gdpr.ErrNotFound) {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "not found"})
		return
	}
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, result)
}

func (h *GDPRHandler) delete(w http.ResponseWriter, r *http.Request) {
	target, caller, tenantID, ok := h.resolveTarget(w, r)
	if !ok {
		return
	}
	result, err := gdpr.Delete(r.Context(), h.Deps, tenantID, target, caller)
	if errors.Is(err, gdpr.ErrNotFound) {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "not found"})
		return
	}
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, result)
}

func (h *GDPRHandler) listRequests(w http.ResponseWriter, r *http.Request) {
	if r.URL.Query().Get("all") != "" {
		if !hasPermission(r, "users.admin") {
			writeJSON(w, http.StatusForbidden, map[string]string{"error": "forbidden"})
			return
		}
		reqs, err := gdpr.ListRequests(r.Context(), h.Deps.DB, callerTenantID(r))
		if err != nil {
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		writeJSON(w, http.StatusOK, reqs)
		return
	}

	callerUID := callerLocalUID(r)
	if callerUID == nil {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "forbidden"})
		return
	}
	reqs, err := gdpr.ListRequestsForUser(r.Context(), h.Deps.DB, *callerUID)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, reqs)
}

func (h *GDPRHandler) download(w http.ResponseWriter, r *http.Request, id int64) {
	var localUID, rowTenantID int
	var status, exportPath string
	err := h.Deps.DB.QueryRowContext(r.Context(),
		`SELECT local_uid, status, COALESCE(export_path,''), tenant_id FROM gdpr_requests WHERE id = ? AND request_type = 'export'`,
		id,
	).Scan(&localUID, &status, &exportPath, &rowTenantID)
	if err == sql.ErrNoRows {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "not found"})
		return
	}
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	// MULTI_TENANCY_NORTHSTAR.md Phase 2: the real tenant boundary, checked BEFORE the admin
	// bypass below and for every caller -- this is a REAL exported PII FILE, not just metadata
	// (see ListRequests's own doc comment for why this got the full fix). Same 404-not-403 idiom:
	// a cross-tenant probe by request id gets byte-for-byte the same response as a genuinely
	// nonexistent id.
	if rowTenantID != callerTenantID(r) {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "not found"})
		return
	}

	callerUID := callerLocalUID(r)
	if !hasPermission(r, "users.admin") && (callerUID == nil || *callerUID != localUID) {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "forbidden"})
		return
	}
	if status != "completed" || exportPath == "" {
		writeJSON(w, http.StatusConflict, map[string]string{"error": "export not ready"})
		return
	}

	b, err := os.ReadFile(exportPath)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Disposition", "attachment; filename=gdpr-export.json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(b)
}
