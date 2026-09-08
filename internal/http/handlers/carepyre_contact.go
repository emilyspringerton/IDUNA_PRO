package handlers

import (
	"database/sql"
	"encoding/json"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"

	"idunapro/internal/http/middleware"
)

// CarePyreContactHandler serves carepyre.org's public "Contact Us" form AND the admin-facing
// list/resolve/delete routes over it. Moved here from plain IDUNA (founder real-time,
// 2026-09-08: "move the contact form to idunapro") so this data lives in the same service/DB as
// CarePyre's own tiered RBAC and GDPR pipeline, gated by a real, named permission
// (contacts.manage) instead of IDUNA's much broader, catch-all iduna.admin population -- the
// same minimum-necessary principle CP-HIPAA-1's provider-role scoping already established.
//
// The public submit route is unauthenticated by design (a visitor has no IDUNA_PRO identity) --
// CORS-scoped + rate-limited, same shape the old IDUNA handler used. The admin routes require
// Bearer JWT + contacts.manage (Top Admin only for now, see localUserPermissions).
//
// Retention: a submission is never auto-deleted while status="new". Once an admin marks one
// resolved (PATCH .../{id} {"status":"resolved"}), cmd/carepyre-contact-purge deletes it 90 days
// later -- see that tool's own doc comment. This handler also allows an admin to delete a
// submission immediately (DELETE .../{id}), for a real, honored deletion request that shouldn't
// have to wait out the 90-day window.
type CarePyreContactHandler struct {
	DB          *sql.DB
	AllowOrigin []string // exact-match allowlist, e.g. "https://carepyre.org"
	Limiter     *middleware.IPRateLimiter
}

func (h *CarePyreContactHandler) RegisterPublic(mux *http.ServeMux) {
	submit := http.HandlerFunc(h.submit)
	if h.Limiter != nil {
		mux.Handle("POST /api/v1/carepyre/contact", middleware.AuthRateLimit(h.Limiter)(submit))
	} else {
		mux.Handle("POST /api/v1/carepyre/contact", submit)
	}
	mux.HandleFunc("OPTIONS /api/v1/carepyre/contact", h.preflight)
}

func (h *CarePyreContactHandler) corsOrigin(r *http.Request) string {
	origin := r.Header.Get("Origin")
	for _, allowed := range h.AllowOrigin {
		if origin == allowed {
			return origin
		}
	}
	return ""
}

func (h *CarePyreContactHandler) preflight(w http.ResponseWriter, r *http.Request) {
	if origin := h.corsOrigin(r); origin != "" {
		w.Header().Set("Access-Control-Allow-Origin", origin)
		w.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
	}
	w.WriteHeader(http.StatusNoContent)
}

type carepyreContactRequest struct {
	Name    string `json:"name"`
	Email   string `json:"email"`
	Message string `json:"message"`
}

func (h *CarePyreContactHandler) submit(w http.ResponseWriter, r *http.Request) {
	if origin := h.corsOrigin(r); origin != "" {
		w.Header().Set("Access-Control-Allow-Origin", origin)
	}

	if h.DB == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{"error": "contact form unavailable"})
		return
	}

	var req carepyreContactRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid request body"})
		return
	}

	name := strings.TrimSpace(req.Name)
	email := strings.TrimSpace(req.Email)
	message := strings.TrimSpace(req.Message)

	if name == "" || len(name) > 120 {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "name is required"})
		return
	}
	if !emailRe.MatchString(email) || len(email) > 254 {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "a valid email address is required"})
		return
	}
	if message == "" || len(message) > 4000 {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "message is required (max 4000 characters)"})
		return
	}

	if _, err := h.DB.Exec(
		`INSERT INTO carepyre_contact_submissions (name, email, message) VALUES (?, ?, ?)`,
		name, email, message,
	); err != nil {
		log.Printf("[carepyre_contact] insert failed: %v", err)
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "internal error"})
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{"status": "ok"})
}

// --- admin: list / resolve / delete (contacts.manage) ---

type carepyreSubmission struct {
	ID         int64   `json:"id"`
	Name       string  `json:"name"`
	Email      string  `json:"email"`
	Message    string  `json:"message"`
	Status     string  `json:"status"`
	CreatedAt  string  `json:"created_at"`
	ResolvedAt *string `json:"resolved_at,omitempty"`
}

// ServeHTTP handles the admin surface at /api/v1/carepyre/contact-submissions[/{id}]. Registered
// separately from RegisterPublic so main.go can wrap it in RequireAuth while the public submit
// route above stays open.
func (h *CarePyreContactHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if !hasPermission(r, "contacts.manage") {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "forbidden"})
		return
	}
	if h.DB == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{"error": "db not available"})
		return
	}

	path := strings.TrimPrefix(r.URL.Path, "/api/v1/carepyre/contact-submissions")
	path = strings.TrimPrefix(path, "/")

	if path == "" {
		if r.Method != http.MethodGet {
			writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
			return
		}
		h.list(w, r)
		return
	}

	id, err := strconv.ParseInt(path, 10, 64)
	if err != nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "not found"})
		return
	}
	switch r.Method {
	case http.MethodPatch:
		h.resolve(w, r, id)
	case http.MethodDelete:
		h.delete(w, r, id)
	default:
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
	}
}

func (h *CarePyreContactHandler) list(w http.ResponseWriter, r *http.Request) {
	rows, err := h.DB.QueryContext(r.Context(),
		`SELECT id, name, email, message, status, created_at, resolved_at
		 FROM carepyre_contact_submissions ORDER BY id DESC LIMIT 200`)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to list submissions: " + err.Error()})
		return
	}
	defer rows.Close()

	var out []carepyreSubmission
	for rows.Next() {
		var s carepyreSubmission
		var resolvedAt sql.NullString
		if err := rows.Scan(&s.ID, &s.Name, &s.Email, &s.Message, &s.Status, &s.CreatedAt, &resolvedAt); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to scan submission: " + err.Error()})
			return
		}
		if resolvedAt.Valid {
			s.ResolvedAt = &resolvedAt.String
		}
		out = append(out, s)
	}
	writeJSON(w, http.StatusOK, map[string]any{"submissions": out})
}

type carepyreResolveRequest struct {
	Status string `json:"status"`
}

// resolve sets status="resolved" and stamps resolved_at, starting cmd/carepyre-contact-purge's
// 90-day clock. Also supports moving a submission back to "new" (resolved_at cleared) in case an
// admin marked one resolved by mistake.
func (h *CarePyreContactHandler) resolve(w http.ResponseWriter, r *http.Request, id int64) {
	var req carepyreResolveRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
		return
	}
	switch req.Status {
	case "resolved":
		if _, err := h.DB.ExecContext(r.Context(),
			`UPDATE carepyre_contact_submissions SET status = 'resolved', resolved_at = ? WHERE id = ?`,
			time.Now().UTC().Format("2006-01-02 15:04:05"), id,
		); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
	case "new":
		if _, err := h.DB.ExecContext(r.Context(),
			`UPDATE carepyre_contact_submissions SET status = 'new', resolved_at = NULL WHERE id = ?`, id,
		); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
	default:
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "status must be \"resolved\" or \"new\""})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"status": "ok"})
}

// delete honors an immediate deletion request rather than waiting out the 90-day post-resolution
// purge window -- privacy.html's own "Deletion" right, applied to contact-form submitters, not
// just IDUNA_PRO accounts.
func (h *CarePyreContactHandler) delete(w http.ResponseWriter, r *http.Request, id int64) {
	if _, err := h.DB.ExecContext(r.Context(), `DELETE FROM carepyre_contact_submissions WHERE id = ?`, id); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"status": "ok"})
}
