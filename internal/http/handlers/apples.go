package handlers

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"idunapro/internal/auth"
	"idunapro/internal/http/middleware"
	"idunapro/internal/store"
	"idunapro/internal/userlog"
)

// ApplesHandler handles /api/v1/apples routes.
// POST  /api/v1/apples                  requires apples.write
// GET   /api/v1/apples                  requires apples.read
// GET   /api/v1/apples/{id}             requires apples.read
// PATCH /api/v1/apples/{id}             requires apples.write; merges
//
//	enrichableFields into metadata
//	(S147 async enrichment: gpt2_fingerprint,
//	model_fingerprint, astrology)
//
// GET   /api/v1/apples/stats/daily-tokens?days=7  requires apples.read
type ApplesHandler struct {
	Store        store.IAMStore
	ApplesGitDir string           // path to APPLES git repo; if set, every new Apple is auto-synced
	EventLog     userlog.EventLog // optional (S226-04); nil skips event emission entirely
}

// applesGitSyncMu serializes syncAppleToGit's git commands across concurrent
// callers — a package-level mutex (2026-09-02, "codify the plumbing":
// KanbanHandler now files real Apples too, for a manual kanban "done" move,
// reusing this exact same real sync function rather than a second copy —
// see kanban.go's own doc comment). Each Apple POST/kanban-done-move spawns
// syncAppleToGit as its own goroutine (fire-and-forget by design — see that
// func's doc comment); without this lock, two Apples landing within the
// same window can race `git commit`/`git push` against the same working
// tree, and the loser's push was rejected (non-fast-forward) with no retry
// -- a silently dropped sync. This is a real, fixable concurrency bug
// regardless of how much of the historical gap it explains: 9226 of 9908
// Apples were found missing from the mirror (scattered throughout the
// whole ID range, not one contiguous block) before a one-time backfill
// (APPLES commit 699bdd5, 2026-07-16). Previously a field on ApplesHandler
// itself (`gitSyncMu`) -- promoted to package-level so every real caller of
// syncAppleToGit, not just ApplesHandler's own, shares the identical real
// serialization guarantee against the identical real working tree.
var applesGitSyncMu sync.Mutex

func (h *ApplesHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Strip /api/v1/apples prefix and check for sub-paths.
	path := strings.TrimPrefix(r.URL.Path, "/api/v1/apples")
	path = strings.TrimPrefix(path, "/")

	if path == "" {
		switch r.Method {
		case http.MethodPost:
			h.create(w, r)
		case http.MethodGet:
			h.list(w, r)
		default:
			http.NotFound(w, r)
		}
		return
	}

	if path == "stats/daily-tokens" {
		if r.Method == http.MethodGet {
			h.dailyTokenStats(w, r)
		} else {
			http.NotFound(w, r)
		}
		return
	}

	// path is the id segment
	id, err := strconv.ParseInt(path, 10, 64)
	if err != nil || id <= 0 {
		writeJSON(w, http.StatusBadRequest, map[string]any{
			"code":    "BAD_REQUEST",
			"message": "invalid apple id",
		})
		return
	}
	switch r.Method {
	case http.MethodGet:
		h.get(w, r, id)
	case http.MethodPatch:
		h.enrich(w, r, id)
	default:
		http.NotFound(w, r)
	}
}

// enrichableFields is the closed set of metadata keys PATCH may set — async
// post-hoc enrichment only (S147), never the apple's core content.
var enrichableFields = map[string]bool{
	"gpt2_fingerprint":  true,
	"model_fingerprint": true,
	"astrology":         true, // S147-04, unused until a data source is chosen
}

// metadataHasField reports whether raw metadata JSON has a non-null value
// for key — used by list() to expose has_gpt2_fingerprint (S147-02) so the
// enrichment worker can find candidate Apples without an N GET-per-Apple
// scan. A missing key and a key explicitly set to null both count as
// "doesn't have it" — enrichment should retry both cases identically.
func metadataHasField(raw []byte, key string) bool {
	if len(raw) == 0 {
		return false
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(raw, &m); err != nil {
		return false
	}
	v, ok := m[key]
	if !ok {
		return false
	}
	return string(v) != "null"
}

// PATCH /api/v1/apples/{id} — merge enrichment fields into metadata.
// Body: {"gpt2_fingerprint": {...}, "model_fingerprint": "..."} — any subset
// of enrichableFields. Requires apples.write (same permission as create;
// enrichment is not a lesser trust tier, it's a later write to the same
// audit-trail record).
func (h *ApplesHandler) enrich(w http.ResponseWriter, r *http.Request, id int64) {
	claims := middleware.ClaimsFromContext(r.Context())
	if !hasClaimPermission(claims, "apples.write") {
		writeJSON(w, http.StatusForbidden, map[string]any{
			"code":    "FORBIDDEN",
			"message": "apples.write permission required",
		})
		return
	}

	var body map[string]json.RawMessage
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{
			"code":    "BAD_REQUEST",
			"message": "invalid JSON body",
		})
		return
	}
	if len(body) == 0 {
		writeJSON(w, http.StatusBadRequest, map[string]any{
			"code":    "BAD_REQUEST",
			"message": "at least one field required",
		})
		return
	}
	for k := range body {
		if !enrichableFields[k] {
			writeJSON(w, http.StatusBadRequest, map[string]any{
				"code":    "BAD_REQUEST",
				"message": fmt.Sprintf("field %q is not enrichable via PATCH", k),
			})
			return
		}
	}

	if err := h.Store.PatchAppleMetadata(r.Context(), id, body); err != nil {
		writeJSON(w, http.StatusNotFound, map[string]any{
			"code":    "NOT_FOUND",
			"message": err.Error(),
		})
		return
	}
	if h.ApplesGitDir != "" {
		// Re-sync so the git mirror reflects the enrichment too — same file
		// path (id+type), so this overwrites rather than duplicates.
		if updated, err := h.Store.GetApple(r.Context(), id); err == nil {
			go syncAppleToGit(h.ApplesGitDir, *updated)
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"id": id, "enriched": true})
}

// appleSignature is appended to every Apple's body at the single POST /api/v1/apples
// choke point (rather than in each of emily.cli/emily-agent/obs-watcher/emily observe/
// emily changelog add) so it's guaranteed on every Apple regardless of which caller filed
// it — same lesson as the 2026-08-10 session-tag audit (don't rely on independent callers
// remembering, enforce at the shared point every path already funnels through). Founder
// real-time standing order, 2026-08-20.
const appleSignature = "⚓ ☃"

// signAppleBody appends appleSignature to body if not already present (idempotent —
// PATCH-driven re-syncs to git call syncAppleToGit with an already-signed body).
func signAppleBody(body string) string {
	if strings.Contains(body, appleSignature) {
		return body
	}
	return strings.TrimRight(body, "\n") + "\n\n" + appleSignature
}

// POST /api/v1/apples
func (h *ApplesHandler) create(w http.ResponseWriter, r *http.Request) {
	claims := middleware.ClaimsFromContext(r.Context())
	if !hasClaimPermission(claims, "apples.write") {
		writeJSON(w, http.StatusForbidden, map[string]any{
			"code":    "FORBIDDEN",
			"message": "apples.write permission required",
		})
		return
	}

	agentID := middleware.SubjectFromContext(r.Context())
	if agentID == "" {
		writeJSON(w, http.StatusUnauthorized, map[string]any{
			"code":    "UNAUTHORIZED",
			"message": "missing subject",
		})
		return
	}

	var body struct {
		SourceRepo string          `json:"source_repo"`
		RunID      string          `json:"run_id"`
		AppleType  string          `json:"apple_type"`
		Title      string          `json:"title"`
		Body       string          `json:"body"`
		Metadata   json.RawMessage `json:"metadata"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{
			"code":    "BAD_REQUEST",
			"message": "invalid JSON body",
		})
		return
	}
	if body.SourceRepo == "" || body.RunID == "" || body.AppleType == "" || body.Title == "" || body.Body == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{
			"code":    "BAD_REQUEST",
			"message": "source_repo, run_id, apple_type, title, and body are required",
		})
		return
	}

	apple := auth.AppleRecord{
		AgentID:    agentID,
		SourceRepo: body.SourceRepo,
		RunID:      body.RunID,
		AppleType:  body.AppleType,
		Title:      body.Title,
		Body:       signAppleBody(body.Body),
		Metadata:   []byte(body.Metadata),
	}
	id, err := h.Store.AppendApple(r.Context(), apple)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{
			"code":    "INTERNAL",
			"message": "failed to store apple",
		})
		return
	}
	if h.ApplesGitDir != "" {
		apple.ID = id
		go syncAppleToGit(h.ApplesGitDir, apple)
	}
	emitAuthEvent(r.Context(), h.EventLog, "iduna:apples.create", "iduna-apples", map[string]any{
		"apple_id": id, "agent_id": agentID, "source_repo": body.SourceRepo, "apple_type": body.AppleType,
	})
	writeJSON(w, http.StatusCreated, map[string]any{
		"id":          id,
		"recorded_at": time.Now().UTC().Format(time.RFC3339Nano),
	})
}

// GET /api/v1/apples
func (h *ApplesHandler) list(w http.ResponseWriter, r *http.Request) {
	claims := middleware.ClaimsFromContext(r.Context())
	if !hasClaimPermission(claims, "apples.read") && !hasClaimPermission(claims, "apples.admin") {
		writeJSON(w, http.StatusForbidden, map[string]any{
			"code":    "FORBIDDEN",
			"message": "apples.read permission required",
		})
		return
	}

	q := r.URL.Query()
	agentID := q.Get("agent_id")
	sourceRepo := q.Get("source_repo")
	appleType := q.Get("apple_type")
	limit := 50
	if l := q.Get("limit"); l != "" {
		if n, err := strconv.Atoi(l); err == nil && n > 0 {
			limit = n
		}
	}

	apples, err := h.Store.ListApples(r.Context(), agentID, sourceRepo, appleType, limit)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{
			"code":    "INTERNAL",
			"message": "failed to list apples",
		})
		return
	}

	type appleListItem struct {
		ID                 int64  `json:"id"`
		AgentID            string `json:"agent_id"`
		SourceRepo         string `json:"source_repo"`
		RunID              string `json:"run_id"`
		AppleType          string `json:"apple_type"`
		Title              string `json:"title"`
		RecordedAt         string `json:"recorded_at"`
		HasGpt2Fingerprint bool   `json:"has_gpt2_fingerprint"`
	}
	items := make([]appleListItem, 0, len(apples))
	for _, a := range apples {
		items = append(items, appleListItem{
			ID:                 a.ID,
			AgentID:            a.AgentID,
			SourceRepo:         a.SourceRepo,
			RunID:              a.RunID,
			AppleType:          a.AppleType,
			Title:              a.Title,
			RecordedAt:         a.RecordedAt.UTC().Format(time.RFC3339Nano),
			HasGpt2Fingerprint: metadataHasField(a.Metadata, "gpt2_fingerprint"),
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{"apples": items})
}

// GET /api/v1/apples/{id}
func (h *ApplesHandler) get(w http.ResponseWriter, r *http.Request, id int64) {
	claims := middleware.ClaimsFromContext(r.Context())
	if !hasClaimPermission(claims, "apples.read") && !hasClaimPermission(claims, "apples.admin") {
		writeJSON(w, http.StatusForbidden, map[string]any{
			"code":    "FORBIDDEN",
			"message": "apples.read permission required",
		})
		return
	}

	apple, err := h.Store.GetApple(r.Context(), id)
	if err != nil {
		writeJSON(w, http.StatusNotFound, map[string]any{
			"code":    "NOT_FOUND",
			"message": "apple not found",
		})
		return
	}

	var meta any
	if len(apple.Metadata) > 0 && string(apple.Metadata) != "null" {
		_ = json.Unmarshal(apple.Metadata, &meta)
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"id":          apple.ID,
		"agent_id":    apple.AgentID,
		"source_repo": apple.SourceRepo,
		"run_id":      apple.RunID,
		"apple_type":  apple.AppleType,
		"title":       apple.Title,
		"body":        apple.Body,
		"metadata":    meta,
		"recorded_at": apple.RecordedAt.UTC().Format(time.RFC3339Nano),
	})
}

// GET /api/v1/apples/stats/daily-tokens?days=7
// Returns daily token usage aggregated from Apple metadata for sparkline display.
// Response: {"days": 7, "stats": [{"date":"2026-06-14","tokens":12345}, ...]}
func (h *ApplesHandler) dailyTokenStats(w http.ResponseWriter, r *http.Request) {
	claims := middleware.ClaimsFromContext(r.Context())
	if !hasClaimPermission(claims, "apples.read") && !hasClaimPermission(claims, "apples.admin") {
		writeJSON(w, http.StatusForbidden, map[string]any{
			"code":    "FORBIDDEN",
			"message": "apples.read permission required",
		})
		return
	}

	days := 7
	if d := r.URL.Query().Get("days"); d != "" {
		if n, err := strconv.Atoi(d); err == nil && n > 0 && n <= 90 {
			days = n
		}
	}

	stats, err := h.Store.DailyTokenStats(r.Context(), days)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{
			"code":    "INTERNAL",
			"message": "failed to aggregate token stats",
		})
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"days":  days,
		"stats": stats,
	})
}

// syncAppleToGit writes the Apple as a JSON file to gitDir, updates MANIFEST.json,
// commits both, and pushes. Runs as a goroutine; all failures are logged and non-fatal.
// A no-op if gitDir is empty -- callers that don't have a real ApplesGitDir configured
// (or don't want git sync for this particular Apple) can call this unconditionally.
// The git command sequence (add/commit/push) is serialized via applesGitSyncMu — see its
// own doc comment — since concurrent Apple creation must not race commits/pushes against
// the same working tree, regardless of which real caller (ApplesHandler, KanbanHandler)
// triggered it.
func syncAppleToGit(gitDir string, apple auth.AppleRecord) {
	if gitDir == "" {
		return
	}
	today := time.Now().UTC().Format("20060102")

	// File write can happen before the lock — each Apple writes a distinct
	// path, so this part is already concurrency-safe.
	dir := filepath.Join(gitDir, today)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		log.Printf("[apples-git] mkdir %s: %v", dir, err)
		return
	}
	fname := fmt.Sprintf("%d_%s.json", apple.ID, strings.ReplaceAll(apple.AppleType, "_", "-"))
	fpath := filepath.Join(dir, fname)

	var metaAny any
	if len(apple.Metadata) > 0 && string(apple.Metadata) != "null" {
		_ = json.Unmarshal(apple.Metadata, &metaAny)
	}
	record := map[string]any{
		"id":          apple.ID,
		"agent_id":    apple.AgentID,
		"apple_type":  apple.AppleType,
		"source_repo": apple.SourceRepo,
		"run_id":      apple.RunID,
		"title":       apple.Title,
		"body":        apple.Body,
		"metadata":    metaAny,
		"archived_at": time.Now().UTC().Format(time.RFC3339),
	}
	data, err := json.MarshalIndent(record, "", "  ")
	if err != nil {
		log.Printf("[apples-git] marshal apple: %v", err)
		return
	}
	if err := os.WriteFile(fpath, append(data, '\n'), 0o644); err != nil {
		log.Printf("[apples-git] write %s: %v", fpath, err)
		return
	}

	// Everything from here on touches shared state (MANIFEST.json, the git
	// index, the branch ref) — serialize across concurrent syncAppleToGit
	// goroutines.
	applesGitSyncMu.Lock()
	defer applesGitSyncMu.Unlock()

	appleGitUpdateManifest(gitDir, apple, today)

	title := apple.Title
	if len(title) > 60 {
		title = title[:60]
	}
	commitMsg := fmt.Sprintf("apple: #%d %s — %s", apple.ID, apple.AppleType, title)
	// gitDir is ApplesGitDir (the separate APPLES repo, not IDUNA itself) -- session tag
	// always lives under EMILY_ROOT specifically. Real gap found and fixed 2026-08-10
	// (founder: "ensure the entire monorepo always gets that session id in all commits").
	if tag := currentSessionTag(emilyRootDefault()); tag != "" {
		commitMsg = commitMsg + "\n\nSession: " + tag
	}
	gitEnv := append(os.Environ(),
		"GIT_AUTHOR_NAME=iduna", "GIT_AUTHOR_EMAIL=iduna@einhorn.internal",
		"GIT_COMMITTER_NAME=iduna", "GIT_COMMITTER_EMAIL=iduna@einhorn.internal",
	)
	addCmd := exec.Command("git", "-C", gitDir, "add", "-A")
	addCmd.Env = gitEnv
	if out, err := addCmd.CombinedOutput(); err != nil {
		log.Printf("[apples-git] git add: %v\n%s", err, out)
		return
	}
	commitCmd := exec.Command("git", "-C", gitDir, "commit", "-m", commitMsg)
	commitCmd.Env = gitEnv
	if out, err := commitCmd.CombinedOutput(); err != nil {
		log.Printf("[apples-git] git commit: %v\n%s", err, out)
		return
	}

	// Push, with one retry: rebase onto whatever landed on the remote since
	// our last fetch (e.g. a manual push, or — before gitSyncMu existed — a
	// racing sync) and try again once. This is the fix for the historical
	// silent-drop failure mode: a rejected push used to just log and return.
	if err := gitPushWithRetry("apples-git", gitDir, gitEnv); err != nil {
		log.Printf("[apples-git] git push failed after retry: %v", err)
		return
	}
	log.Printf("[apples-git] synced Apple #%d → %s/%s", apple.ID, today, fname)
}

// gitPushWithRetry pushes gitDir's current branch. On rejection (most likely
// non-fast-forward), it pulls with --rebase and retries once. Caller must
// already hold its own real sync mutex (gitSyncMu for apples, backlogFileMu
// for kanban -- two distinct working trees, never the same lock). logPrefix
// names which real caller this is for in the log line (real bug found
// writing kanban.go's own tests: this used to hardcode "[apples-git]"
// unconditionally, so a kanban-triggered push failure logged under the
// wrong subsystem's name).
func gitPushWithRetry(logPrefix, gitDir string, gitEnv []string) error {
	pushCmd := exec.Command("git", "-C", gitDir, "push")
	pushCmd.Env = gitEnv
	if out, err := pushCmd.CombinedOutput(); err == nil {
		return nil
	} else {
		log.Printf("[%s] git push rejected, retrying after rebase: %v\n%s", logPrefix, err, out)
	}

	pullCmd := exec.Command("git", "-C", gitDir, "pull", "--rebase")
	pullCmd.Env = gitEnv
	if out, err := pullCmd.CombinedOutput(); err != nil {
		return fmt.Errorf("pull --rebase: %w\n%s", err, out)
	}

	retryCmd := exec.Command("git", "-C", gitDir, "push")
	retryCmd.Env = gitEnv
	if out, err := retryCmd.CombinedOutput(); err != nil {
		return fmt.Errorf("push retry: %w\n%s", err, out)
	}
	return nil
}

// appleGitUpdateManifest reads MANIFEST.json, appends the new entry, and writes it back.
// Best-effort: failures are logged, sync continues.
func appleGitUpdateManifest(gitDir string, apple auth.AppleRecord, date string) {
	type manifestEntry struct {
		ID         int64  `json:"id"`
		Type       string `json:"type"`
		Title      string `json:"title"`
		SourceRepo string `json:"source_repo"`
		Date       string `json:"date"`
		ArchivedAt string `json:"archived_at"`
	}
	type manifest struct {
		GeneratedAt string          `json:"generated_at"`
		Repo        string          `json:"repo"`
		Count       int             `json:"count"`
		Apples      []manifestEntry `json:"apples"`
	}

	manifestPath := filepath.Join(gitDir, "MANIFEST.json")
	var m manifest
	if raw, err := os.ReadFile(manifestPath); err == nil {
		_ = json.Unmarshal(raw, &m)
	}
	if m.Repo == "" {
		m.Repo = "APPLES"
	}
	for _, e := range m.Apples {
		if e.ID == apple.ID {
			return // idempotent
		}
	}
	title := apple.Title
	if len(title) > 140 {
		title = title[:140]
	}
	m.Apples = append(m.Apples, manifestEntry{
		ID:         apple.ID,
		Type:       apple.AppleType,
		Title:      title,
		SourceRepo: apple.SourceRepo,
		Date:       date,
		ArchivedAt: time.Now().UTC().Format(time.RFC3339),
	})
	m.Count = len(m.Apples)
	m.GeneratedAt = time.Now().UTC().Format(time.RFC3339)

	data, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		log.Printf("[apples-git] manifest marshal: %v", err)
		return
	}
	if err := os.WriteFile(manifestPath, append(data, '\n'), 0o644); err != nil {
		log.Printf("[apples-git] manifest write: %v", err)
	}
}

// hasClaimPermission checks the "permissions" claim in the JWT for a specific permission.
// This duplicates the logic in middleware but allows the handler to check multiple
// permissions without middleware wrapping each route individually.
func hasClaimPermission(claims map[string]any, perm string) bool {
	if claims == nil {
		return false
	}
	perms, ok := claims["permissions"]
	if !ok {
		return false
	}
	switch v := perms.(type) {
	case []any:
		for _, p := range v {
			if s, ok := p.(string); ok && s == perm {
				return true
			}
		}
	case []string:
		for _, s := range v {
			if s == perm {
				return true
			}
		}
	}
	return false
}

// emilyRootDefault / currentSessionTag: duplicated in every Go module that makes automated git
// commits (emily.cli/cmd/session.go, EMILY/emily-agent/integration.go, here) since they're
// separate go.work modules with no existing shared package for this small a concern -- all read
// the exact same var/current-session.json file (written by `emily session new`), so behavior
// stays centralized on the data side even though the code is duplicated. Real gap found and
// fixed 2026-08-10 (founder: "ensure the entire monorepo always gets that session id in all
// commits").
func emilyRootDefault() string {
	if v := os.Getenv("EMILY_ROOT"); v != "" {
		return v
	}
	return "/home/fatbaby/EMILY"
}

func currentSessionTag(emilyRoot string) string {
	data, err := os.ReadFile(filepath.Join(emilyRoot, "var", "current-session.json"))
	if err != nil {
		return ""
	}
	var rec struct {
		Tag string `json:"tag"`
	}
	if err := json.Unmarshal(data, &rec); err != nil {
		return ""
	}
	return rec.Tag
}
