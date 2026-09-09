// Package handlers — CommunityToolsHandler serves CarePyre's own "community tools"
// area (founder real-time, 2026-09-09: "build it into carepyre... as part of the
// community tools but we want it to be gated so that accounts need a feature flag
// set"), v0's own real first tool: a resume/CV builder + verifier against the real
// JSON Resume standard. See CarePyre/docs/COMMUNITY_TOOLS_RESUME_NORTHSTAR.md for the
// full design.
//
// Every route here is gated by RequirePermission("community-tools.access") at
// registration (main.go), which is itself driven by LocalUser.IsCommunityToolsEnabled
// (see localUserPermissions in local_auth.go) — a plain per-account admin-settable
// flag, deliberately separate from the 4-tier admin/provider RBAC.
package handlers

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"idunapro/internal/resume"
)

// CommunityToolsHandler serves /api/v1/community-tools/resume.
type CommunityToolsHandler struct {
	DB *sql.DB
}

func (h *CommunityToolsHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// callerLocalUID -- the real, existing, already-established helper (users.go),
	// reading the `local_uid` JWT claim directly, reused here rather than a second,
	// independent parse of the `sub` claim.
	uidPtr := callerLocalUID(r)
	if uidPtr == nil {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
		return
	}
	uid := *uidPtr
	switch r.Method {
	case http.MethodGet:
		h.get(w, r, uid)
	case http.MethodPut:
		h.put(w, r, uid)
	default:
		http.NotFound(w, r)
	}
}

// get returns the caller's own real resume document (an empty, real JSON Resume shell
// if they haven't saved one yet, not a 404: an empty resume is a real, valid, editable
// starting state, not an error).
func (h *CommunityToolsHandler) get(w http.ResponseWriter, r *http.Request, uid int) {
	res, err := loadResume(r.Context(), h.DB, uid)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, res)
}

// put replaces the caller's own resume document wholesale (v0's own real, deliberate
// scope: one full-document PUT, not field-level PATCH — matching this feature's own
// real "one resume per user" v0 boundary, NORTHSTAR §6 Phase 1). Real, honest
// ownership check needs nothing beyond the JWT subject itself: a caller can only ever
// read/write the resume keyed by THEIR OWN local_uid, never another user's — no
// separate admin-override path exists for this feature (unlike users.go's own
// cross-org provider access), the same real, deliberate v0 boundary "one resume per
// authenticated user" already implies.
func (h *CommunityToolsHandler) put(w http.ResponseWriter, r *http.Request, uid int) {
	var res resume.Resume
	if err := json.NewDecoder(r.Body).Decode(&res); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON"})
		return
	}
	if err := saveResume(r.Context(), h.DB, uid, &res); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, res)
}

// CommunityToolsVerifyHandler serves /api/v1/community-tools/resume/verify — a real,
// separate handler (not a sub-route dispatch inside CommunityToolsHandler) matching
// the established convention other multi-route features in this repo already use
// (e.g. RefreshHandler alongside the main auth handlers) for a route this narrow.
type CommunityToolsVerifyHandler struct {
	DB *sql.DB
}

func (h *CommunityToolsVerifyHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.NotFound(w, r)
		return
	}
	uidPtr := callerLocalUID(r)
	if uidPtr == nil {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
		return
	}
	res, err := loadResume(r.Context(), h.DB, *uidPtr)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, resume.Verify(res))
}

func loadResume(ctx context.Context, db *sql.DB, uid int) (*resume.Resume, error) {
	var data string
	row := db.QueryRowContext(ctx, `SELECT data FROM resumes WHERE local_uid=?`, uid)
	err := row.Scan(&data)
	if errors.Is(err, sql.ErrNoRows) {
		// No saved resume yet — a real, valid, empty starting document, not an error.
		return &resume.Resume{}, nil
	}
	if err != nil {
		return nil, err
	}
	var res resume.Resume
	if err := json.Unmarshal([]byte(data), &res); err != nil {
		return nil, err
	}
	return &res, nil
}

func saveResume(ctx context.Context, db *sql.DB, uid int, res *resume.Resume) error {
	raw, err := json.Marshal(res)
	if err != nil {
		return err
	}
	now := time.Now().UTC().Format(time.RFC3339)
	_, err = db.ExecContext(ctx,
		`INSERT INTO resumes (local_uid, data, created_at, updated_at) VALUES (?, ?, ?, ?)
		 ON CONFLICT(local_uid) DO UPDATE SET data=excluded.data, updated_at=excluded.updated_at`,
		uid, string(raw), now, now,
	)
	return err
}
