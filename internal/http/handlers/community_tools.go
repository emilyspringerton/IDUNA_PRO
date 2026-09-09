// Package handlers — CommunityToolsHandler serves CarePyre's own "community tools"
// area (founder real-time, 2026-09-09: "build it into carepyre... as part of the
// community tools but we want it to be gated so that accounts need a feature flag
// set"), v0's own real first tool: a resume/CV builder + verifier against the real
// JSON Resume standard, plus real, named Target resume variants (bespoke, tailored
// subsets of the master resume for a specific opportunity — see
// internal/resume/target.go's own doc comment for the full design). See
// CarePyre/docs/COMMUNITY_TOOLS_RESUME_NORTHSTAR.md for the full feature design.
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
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"

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
	assignResumeIDs(&res)
	if err := saveResume(r.Context(), h.DB, uid, &res); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, res)
}

// assignResumeIDs gives every Work/Education/Skill/Award entry missing an ID a real,
// fresh one — server-side, so the client never needs a UUID library of its own (see
// resume.Work.ID's own doc comment for why a stable ID matters: Target's own real
// selection lists reference these). An entry that already has an ID (the caller sent
// back an existing entry unchanged, or with edited field values but the same real
// identity) keeps it — reassigning it on every save would silently break every real
// Target that already references it.
func assignResumeIDs(res *resume.Resume) {
	for i := range res.Work {
		if res.Work[i].ID == "" {
			res.Work[i].ID = uuid.New().String()
		}
	}
	for i := range res.Education {
		if res.Education[i].ID == "" {
			res.Education[i].ID = uuid.New().String()
		}
	}
	for i := range res.Skills {
		if res.Skills[i].ID == "" {
			res.Skills[i].ID = uuid.New().String()
		}
	}
	for i := range res.Awards {
		if res.Awards[i].ID == "" {
			res.Awards[i].ID = uuid.New().String()
		}
	}
}

// CommunityToolsBasicsHandler serves PATCH /api/v1/community-tools/resume/basics — founder
// real-time, 2026-09-09: "ensure that all of the features we have have good api because i am
// going to ask agents to work with those primitives to start intelligently managing the
// resume using agentic ai." A real, agent-friendly PARTIAL update of just Basics
// (name/label/email/phone/summary/etc.) without resending the entire resume document (every
// Work/Education/Skill/Award entry untouched) — the real friction the whole-document PUT-only
// design (CommunityToolsHandler.put) has for a caller that only wants to fix one field. Relies
// on encoding/json's own real, native "unmarshal onto an already-populated value" semantics to
// do the merge: a JSON key ABSENT from the request body leaves that field's existing value
// untouched; a key PRESENT (including an explicit "" ) overwrites it. No hand-written
// *string-pointer-per-field patch struct needed (the convention users.go's updateUserRequest
// uses) — encoding/json already gives real, correct partial-merge semantics for free when the
// destination is a real, already-populated Go value rather than a fresh zero one.
type CommunityToolsBasicsHandler struct {
	DB *sql.DB
}

func (h *CommunityToolsBasicsHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPatch {
		http.NotFound(w, r)
		return
	}
	uidPtr := callerLocalUID(r)
	if uidPtr == nil {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
		return
	}
	uid := *uidPtr
	body, err := io.ReadAll(r.Body)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid body"})
		return
	}
	res, err := loadResume(r.Context(), h.DB, uid)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if err := json.Unmarshal(body, &res.Basics); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON"})
		return
	}
	if err := saveResume(r.Context(), h.DB, uid, res); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, res)
}

// entryOps describes how to address one ID'd list-of-entries field on a Resume (Work,
// Education, Skill, or Award) generically enough that CommunityToolsEntryHandler[T] below can
// serve all four with one real implementation instead of four hand-duplicated copies — the
// same real generics-over-duplication judgment call target.go's own filterByID[T] already made.
type entryOps[T any] struct {
	get   func(*resume.Resume) []T
	set   func(*resume.Resume, []T)
	getID func(*T) string
	setID func(*T, string)
}

// CommunityToolsEntryHandler serves the real per-entry primitives an agent (or any client) can
// use instead of a whole-document PUT: POST {prefix} to create ONE new entry (server-assigns a
// fresh ID regardless of anything the caller sent — the same real "never trust a client-supplied
// ID on create" caution assignResumeIDs' own doc comment already establishes), PATCH
// {prefix}/{id} to merge partial fields onto ONE existing entry (see CommunityToolsBasicsHandler's
// own doc comment for the real encoding/json partial-merge reasoning, identical here), and
// DELETE {prefix}/{id} to remove one entry. One real, shared implementation via Go generics,
// registered four times in main.go (Work/Education/Skill/Award) with a different entryOps[T]
// and Prefix each — see CommunityToolsTargetsHandler's own sibling single-target
// create/patch/delete methods for the analogous primitives over Targets.
type CommunityToolsEntryHandler[T any] struct {
	DB     *sql.DB
	Prefix string // this handler's own exact base path, e.g. "/api/v1/community-tools/resume/work"
	Ops    entryOps[T]
}

// NewCommunityToolsWorkHandler/Education/Skills/Awards -- real, exported constructors, one per
// entry type, so main.go (a different package) never needs direct access to the unexported
// entryOps machinery above. Each fully wires DB/Prefix/Ops together — a caller that forgets to
// set Ops (a real, live bug this fixes: main.go's own first draft built these structs with only
// DB/Prefix set, leaving Ops a zero-value struct of nil funcs — compiles fine, panics the first
// time any of get/set/getID/setID is actually called) simply can't happen anymore.
func NewCommunityToolsWorkHandler(db *sql.DB) *CommunityToolsEntryHandler[resume.Work] {
	return &CommunityToolsEntryHandler[resume.Work]{
		DB:     db,
		Prefix: "/api/v1/community-tools/resume/work",
		Ops: entryOps[resume.Work]{
			get:   func(r *resume.Resume) []resume.Work { return r.Work },
			set:   func(r *resume.Resume, list []resume.Work) { r.Work = list },
			getID: func(w *resume.Work) string { return w.ID },
			setID: func(w *resume.Work, id string) { w.ID = id },
		},
	}
}

func NewCommunityToolsEducationHandler(db *sql.DB) *CommunityToolsEntryHandler[resume.Education] {
	return &CommunityToolsEntryHandler[resume.Education]{
		DB:     db,
		Prefix: "/api/v1/community-tools/resume/education",
		Ops: entryOps[resume.Education]{
			get:   func(r *resume.Resume) []resume.Education { return r.Education },
			set:   func(r *resume.Resume, list []resume.Education) { r.Education = list },
			getID: func(e *resume.Education) string { return e.ID },
			setID: func(e *resume.Education, id string) { e.ID = id },
		},
	}
}

func NewCommunityToolsSkillsHandler(db *sql.DB) *CommunityToolsEntryHandler[resume.Skill] {
	return &CommunityToolsEntryHandler[resume.Skill]{
		DB:     db,
		Prefix: "/api/v1/community-tools/resume/skills",
		Ops: entryOps[resume.Skill]{
			get:   func(r *resume.Resume) []resume.Skill { return r.Skills },
			set:   func(r *resume.Resume, list []resume.Skill) { r.Skills = list },
			getID: func(s *resume.Skill) string { return s.ID },
			setID: func(s *resume.Skill, id string) { s.ID = id },
		},
	}
}

func NewCommunityToolsAwardsHandler(db *sql.DB) *CommunityToolsEntryHandler[resume.Award] {
	return &CommunityToolsEntryHandler[resume.Award]{
		DB:     db,
		Prefix: "/api/v1/community-tools/resume/awards",
		Ops: entryOps[resume.Award]{
			get:   func(r *resume.Resume) []resume.Award { return r.Awards },
			set:   func(r *resume.Resume, list []resume.Award) { r.Awards = list },
			getID: func(a *resume.Award) string { return a.ID },
			setID: func(a *resume.Award, id string) { a.ID = id },
		},
	}
}

func (h *CommunityToolsEntryHandler[T]) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	uidPtr := callerLocalUID(r)
	if uidPtr == nil {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
		return
	}
	uid := *uidPtr

	id := strings.TrimPrefix(r.URL.Path, h.Prefix)
	id = strings.TrimPrefix(id, "/")

	if id == "" {
		if r.Method != http.MethodPost {
			http.NotFound(w, r)
			return
		}
		h.create(w, r, uid)
		return
	}
	switch r.Method {
	case http.MethodPatch:
		h.patch(w, r, uid, id)
	case http.MethodDelete:
		h.delete(w, r, uid, id)
	default:
		http.NotFound(w, r)
	}
}

func (h *CommunityToolsEntryHandler[T]) create(w http.ResponseWriter, r *http.Request, uid int) {
	var entry T
	if err := json.NewDecoder(r.Body).Decode(&entry); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON"})
		return
	}
	res, err := loadResume(r.Context(), h.DB, uid)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	h.Ops.setID(&entry, uuid.New().String())
	h.Ops.set(res, append(h.Ops.get(res), entry))
	if err := saveResume(r.Context(), h.DB, uid, res); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusCreated, entry)
}

func (h *CommunityToolsEntryHandler[T]) patch(w http.ResponseWriter, r *http.Request, uid int, id string) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid body"})
		return
	}
	res, err := loadResume(r.Context(), h.DB, uid)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	list := h.Ops.get(res)
	for i := range list {
		if h.Ops.getID(&list[i]) != id {
			continue
		}
		if err := json.Unmarshal(body, &list[i]); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON"})
			return
		}
		h.Ops.setID(&list[i], id) // guard: the id itself is never patchable via the request body
		h.Ops.set(res, list)
		if err := saveResume(r.Context(), h.DB, uid, res); err != nil {
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		writeJSON(w, http.StatusOK, list[i])
		return
	}
	writeJSON(w, http.StatusNotFound, map[string]string{"error": "not found"})
}

func (h *CommunityToolsEntryHandler[T]) delete(w http.ResponseWriter, r *http.Request, uid int, id string) {
	res, err := loadResume(r.Context(), h.DB, uid)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	list := h.Ops.get(res)
	out := list[:0:0] // a real, fresh backing array — never alias the original slice's storage
	found := false
	for _, item := range list {
		if h.Ops.getID(&item) == id {
			found = true
			continue
		}
		out = append(out, item)
	}
	if !found {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "not found"})
		return
	}
	h.Ops.set(res, out)
	if err := saveResume(r.Context(), h.DB, uid, res); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"deleted": true})
}

// CommunityToolsExportHandler serves /api/v1/community-tools/resume/export.pdf — the real
// "Layer 3" export the founder's own original framing described (NORTHSTAR §3) and the
// console.html "Preview & templates" panel's own screen-only rendering named as honestly not
// done when it shipped: a real, downloadable, ATS-safe PDF FILE, not a browser preview. See
// resume.RenderPDF's own doc comment for the full real reasoning (one real, plain,
// single-column, real-selectable-text template — structure, not color, is what actually
// matters for ATS parsing).
type CommunityToolsExportHandler struct {
	DB *sql.DB
}

func (h *CommunityToolsExportHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
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
	writeResumePDF(w, res, "resume")
}

// writeResumePDF -- the one real, shared render-and-respond step both CommunityToolsExportHandler
// (master resume) and CommunityToolsTargetsHandler's own export.pdf sub-route (a resolved
// target) reduce to. `baseName` is a plain, human name (e.g. a Target's own real, user-
// controlled `Name` field) with NO extension — pdfFilename below owns turning it into a real,
// safe, complete "*.pdf" filename. Real, deliberate, found-before-shipping caution: a
// Target's own real, user-controlled name (e.g. one containing a literal `"` or newline)
// going straight into an HTTP response header value is a real header-injection/malformed-
// response risk, the identical class of bug this same session's own console.html work already
// found and fixed once (esc() into an HTML attribute) — caught here by reasoning about it
// directly before it ever shipped, not found live.
func writeResumePDF(w http.ResponseWriter, res *resume.Resume, baseName string) {
	pdfBytes, err := resume.RenderPDF(res)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/pdf")
	w.Header().Set("Content-Disposition", `attachment; filename="`+pdfFilename(baseName)+`"`)
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(pdfBytes)
}

// pdfFilename -- real, narrow allowlist over `base` (letters, digits, hyphen, underscore),
// everything else (including a literal quote or a newline, the real header-injection risk
// this exists to close) collapsed to a hyphen, then the real, fixed ".pdf" extension appended
// — never taken from caller input, so the result is always a real, valid, single-extension
// filename regardless of what's in `base`. Falls back to the real, safe default "resume.pdf"
// if the sanitized result is empty (a name that was ENTIRELY unsafe characters, e.g. all
// emoji) or absurdly long (a real, honest DoS-shaped guard, not just a cosmetic one).
func pdfFilename(base string) string {
	var b strings.Builder
	for _, r := range base {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '_':
			b.WriteRune(r)
		default:
			b.WriteRune('-')
		}
		if b.Len() >= 80 {
			break
		}
	}
	out := strings.Trim(b.String(), "-")
	if out == "" {
		return "resume.pdf"
	}
	return out + ".pdf"
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

// CommunityToolsTargetsHandler serves the real Target (bespoke resume variant) family of
// routes — /api/v1/community-tools/resume/targets (GET list / PUT replace-whole-list, the
// same real "one document, whole-replace" convention CommunityToolsHandler's own PUT already
// establishes for the master resume — a Target list is small and edited as a set, not
// field-by-field), plus two real per-target sub-routes: GET .../targets/{id}/resolved (the
// real, filtered resume view resume.Resolve produces) and POST .../targets/{id}/verify
// (real verification run against that RESOLVED view, not the master — catching e.g. "this
// target hides every real work entry, it now fails has-work-or-education," a real, honest
// signal the master's own verify can't give).
type CommunityToolsTargetsHandler struct {
	DB *sql.DB
}

func (h *CommunityToolsTargetsHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	uidPtr := callerLocalUID(r)
	if uidPtr == nil {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
		return
	}
	uid := *uidPtr

	path := strings.TrimPrefix(r.URL.Path, "/api/v1/community-tools/resume/targets")
	path = strings.TrimPrefix(path, "/")

	if path == "" {
		switch r.Method {
		case http.MethodGet:
			h.list(w, r, uid)
		case http.MethodPut:
			h.replace(w, r, uid)
		// POST -- founder real-time, 2026-09-09: "ensure that all of the features we have have
		// good api because i am going to ask agents to work with those primitives." A real,
		// agent-friendly "create ONE new target" primitive alongside the existing whole-list
		// PUT — an agent adding a single bespoke resume no longer needs to fetch, mutate, and
		// resend every OTHER target it isn't touching.
		case http.MethodPost:
			h.create(w, r, uid)
		default:
			http.NotFound(w, r)
		}
		return
	}

	// {id}/resolved, {id}/verify, or {id}/export.pdf -- the three real sub-route shapes with a
	// fixed suffix, matching sip_accounts.go's own established "TrimPrefix, then compare the
	// remaining segments" convention rather than a full path-templating router (this repo has
	// none). A bare {id} (no suffix) is the real single-target PATCH/DELETE primitives below.
	if strings.HasSuffix(path, "/resolved") {
		id := strings.TrimSuffix(path, "/resolved")
		if r.Method != http.MethodGet {
			http.NotFound(w, r)
			return
		}
		h.resolved(w, r, uid, id)
		return
	}
	if strings.HasSuffix(path, "/verify") {
		id := strings.TrimSuffix(path, "/verify")
		if r.Method != http.MethodPost {
			http.NotFound(w, r)
			return
		}
		h.verifyTarget(w, r, uid, id)
		return
	}
	if strings.HasSuffix(path, "/export.pdf") {
		id := strings.TrimSuffix(path, "/export.pdf")
		if r.Method != http.MethodGet {
			http.NotFound(w, r)
			return
		}
		h.exportTarget(w, r, uid, id)
		return
	}
	switch r.Method {
	case http.MethodPatch:
		h.patchOne(w, r, uid, path)
	case http.MethodDelete:
		h.deleteOne(w, r, uid, path)
	default:
		http.NotFound(w, r)
	}
}

// create -- POST .../resume/targets, the real single-target counterpart to replace's own
// whole-list PUT. Server-assigns a fresh id regardless of anything in the request body — the
// same never-trust-a-client-supplied-id-on-create caution CommunityToolsEntryHandler.create's
// own doc comment already names.
func (h *CommunityToolsTargetsHandler) create(w http.ResponseWriter, r *http.Request, uid int) {
	var t resume.Target
	if err := json.NewDecoder(r.Body).Decode(&t); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON"})
		return
	}
	targets, err := loadTargets(r.Context(), h.DB, uid)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	t.ID = uuid.New().String()
	targets = append(targets, t)
	if err := saveTargets(r.Context(), h.DB, uid, targets); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusCreated, t)
}

// patchOne -- PATCH .../resume/targets/{id}, a real partial-merge update of one target (e.g. an
// agent tweaking just SummaryOverride, or adding one more work id to IncludedWorkIDs) without
// resending the whole target list. Relies on the same real encoding/json "unmarshal onto an
// already-populated value" merge semantics CommunityToolsBasicsHandler's own doc comment
// explains — including a real, useful three-way distinction for SummaryOverride/LabelOverride
// specifically: the JSON key ABSENT leaves the existing override untouched, present as `null`
// explicitly CLEARS it (a real, deliberate "remove this override" action), present as a string
// sets it — exactly resume.Target's own *string-pointer contract, now reachable via a real
// partial PATCH instead of only a full-document PUT.
func (h *CommunityToolsTargetsHandler) patchOne(w http.ResponseWriter, r *http.Request, uid int, id string) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid body"})
		return
	}
	targets, err := loadTargets(r.Context(), h.DB, uid)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	for i := range targets {
		if targets[i].ID != id {
			continue
		}
		if err := json.Unmarshal(body, &targets[i]); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON"})
			return
		}
		targets[i].ID = id // guard: the id itself is never patchable via the request body
		if err := saveTargets(r.Context(), h.DB, uid, targets); err != nil {
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		writeJSON(w, http.StatusOK, targets[i])
		return
	}
	writeJSON(w, http.StatusNotFound, map[string]string{"error": "target not found"})
}

// deleteOne -- DELETE .../resume/targets/{id}, the real single-target counterpart to removing
// an entry by simply omitting it from a whole-list PUT.
func (h *CommunityToolsTargetsHandler) deleteOne(w http.ResponseWriter, r *http.Request, uid int, id string) {
	targets, err := loadTargets(r.Context(), h.DB, uid)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	out := targets[:0:0] // a real, fresh backing array -- never alias the original slice's storage
	found := false
	for _, t := range targets {
		if t.ID == id {
			found = true
			continue
		}
		out = append(out, t)
	}
	if !found {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "target not found"})
		return
	}
	if err := saveTargets(r.Context(), h.DB, uid, out); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"deleted": true})
}

func (h *CommunityToolsTargetsHandler) list(w http.ResponseWriter, r *http.Request, uid int) {
	targets, err := loadTargets(r.Context(), h.DB, uid)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, targets)
}

// replace -- real, deliberate whole-list PUT: the client sends back the complete desired set
// of targets (an entry with no `id` is a real, new target — server-assigns one, the same real
// convention assignResumeIDs above already establishes for master-resume entries; an entry
// with an existing `id` is an edit; an id from the OLD list simply absent from the new one is
// a real delete — no separate DELETE route needed for a list this small, matching this
// handler's own header comment).
func (h *CommunityToolsTargetsHandler) replace(w http.ResponseWriter, r *http.Request, uid int) {
	var targets []resume.Target
	if err := json.NewDecoder(r.Body).Decode(&targets); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON"})
		return
	}
	for i := range targets {
		if targets[i].ID == "" {
			targets[i].ID = uuid.New().String()
		}
	}
	if err := saveTargets(r.Context(), h.DB, uid, targets); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, targets)
}

func (h *CommunityToolsTargetsHandler) resolved(w http.ResponseWriter, r *http.Request, uid int, id string) {
	master, target, err := loadMasterAndTarget(r.Context(), h.DB, uid, id)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if target == nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "target not found"})
		return
	}
	writeJSON(w, http.StatusOK, resume.Resolve(master, target))
}

func (h *CommunityToolsTargetsHandler) verifyTarget(w http.ResponseWriter, r *http.Request, uid int, id string) {
	master, target, err := loadMasterAndTarget(r.Context(), h.DB, uid, id)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if target == nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "target not found"})
		return
	}
	writeJSON(w, http.StatusOK, resume.Verify(resume.Resolve(master, target)))
}

func (h *CommunityToolsTargetsHandler) exportTarget(w http.ResponseWriter, r *http.Request, uid int, id string) {
	master, target, err := loadMasterAndTarget(r.Context(), h.DB, uid, id)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if target == nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "target not found"})
		return
	}
	writeResumePDF(w, resume.Resolve(master, target), target.Name)
}

func loadMasterAndTarget(ctx context.Context, db *sql.DB, uid int, targetID string) (*resume.Resume, *resume.Target, error) {
	master, err := loadResume(ctx, db, uid)
	if err != nil {
		return nil, nil, err
	}
	targets, err := loadTargets(ctx, db, uid)
	if err != nil {
		return nil, nil, err
	}
	for i := range targets {
		if targets[i].ID == targetID {
			return master, &targets[i], nil
		}
	}
	return master, nil, nil
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

// loadTargets/saveTargets -- real, direct siblings of loadResume/saveResume above, over the
// SAME `resumes` row's own separate `targets` column (see migration
// 202609090002_resume_targets.sql's own doc comment for why this is a sibling column, not a
// separate table). A row that doesn't exist yet (the caller never saved a master resume, or
// even a resume, before managing targets) real-honestly returns an empty target list, not an
// error -- the same "no data yet is a valid starting state" convention loadResume's own
// zero-value fallback already establishes.
func loadTargets(ctx context.Context, db *sql.DB, uid int) ([]resume.Target, error) {
	var data string
	row := db.QueryRowContext(ctx, `SELECT targets FROM resumes WHERE local_uid=?`, uid)
	err := row.Scan(&data)
	if errors.Is(err, sql.ErrNoRows) {
		return []resume.Target{}, nil
	}
	if err != nil {
		return nil, err
	}
	var targets []resume.Target
	if err := json.Unmarshal([]byte(data), &targets); err != nil {
		return nil, err
	}
	return targets, nil
}

// saveTargets -- real, honest UPSERT: if the caller has never saved a master resume at all
// yet, this still needs to create the real `resumes` row (with a real, valid, empty '{}'
// master document) so the `targets` column has somewhere to live — real, deliberate
// dependency-order choice (targets are a real VIEW over a master resume, so a row must exist),
// not an oversight.
func saveTargets(ctx context.Context, db *sql.DB, uid int, targets []resume.Target) error {
	raw, err := json.Marshal(targets)
	if err != nil {
		return err
	}
	now := time.Now().UTC().Format(time.RFC3339)
	_, err = db.ExecContext(ctx,
		`INSERT INTO resumes (local_uid, data, targets, created_at, updated_at) VALUES (?, '{}', ?, ?, ?)
		 ON CONFLICT(local_uid) DO UPDATE SET targets=excluded.targets, updated_at=excluded.updated_at`,
		uid, string(raw), now, now,
	)
	return err
}
