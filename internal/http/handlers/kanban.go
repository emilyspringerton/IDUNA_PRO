package handlers

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"

	"idunapro/internal/auth"
	"idunapro/internal/backlog"
	"idunapro/internal/http/middleware"
	"idunapro/internal/store"
)

// KanbanHandler is the prioritization layer on top of EMILY/BACKLOG.md's own
// sprint sections. Founder real-time, built up across several messages: "ok
// lets build a kanban layer on top of our sprints that lets us assign
// priority for the next open dev to picj up - for now it can be simple 2
// tiers of special next queues priority and cruise" -> "it allows us to
// drag from backlog into 1 of the 2 priority queues backlog numbers stay
// the same it gets a kanban tracking something" -> "gui kanban interface 3
// columns in iduna" -> "i can ask the ai agent to work from the priority or
// cruise backlog".
//
// backlog_item_id (e.g. "S202-27") is the real BACKLOG.md item id -- this
// table only tracks which of the 3 columns (backlog/priority/cruise) a
// card sits in and its position within that column, never a copy of the
// item's own text. BACKLOG.md itself stays the one authoritative source of
// the item's actual content/status.
//
//	GET    /api/v1/kanban/cards[?queue=priority]
//	  -> [{"id":1,"backlog_item_id":"S202-27","title":"...","queue":"priority","position":0,...}]
//	POST   /api/v1/kanban/cards   {"backlog_item_id":"S202-27","title":"..."}
//	  -> 201, {"id":1}  (queue defaults to "backlog")
//	PATCH  /api/v1/kanban/cards/{id}   {"queue":"priority","position":2}
//	  -> 200  (the "drag" action -- moves a card between columns and/or reorders within one)
//	DELETE /api/v1/kanban/cards/{id}
//	  -> 204
// BacklogPath, when set, turns on eventual-consistency sync with
// EMILY/BACKLOG.md itself (founder real-time, 2026-09-02: "if it gets
// added to backlog via the kanban interface it needs to wind up in the
// golden backlog file in git and as we work it needs to all stay in sync
// -- for example when we finish something it needs to move off the kanban
// board"). Two real, independent directions, both best-effort/fire-and-
// forget (never blocks or fails the real DB write a caller is waiting on):
//
//  1. create(): a new card whose backlog_item_id isn't already a real
//     line in BACKLOG.md gets one appended for real, committed, and
//     pushed (see syncNewItemToBacklogGit) -- the same real
//     git-add/commit/push-with-retry idiom apples.go's own
//     syncAppleToGit already established, not a new pattern.
//  2. list(): any card whose backlog_item_id is confirmed CHECKED in the
//     live file is deleted from kanban_cards before being returned --
//     "finishing something moves it off the board" for real, not just
//     visually.
//
// Empty BacklogPath disables both (kanban still works as pure metadata,
// the original design) -- a real, deliberate off switch, not an oversight.
//
// Real THIRD direction added 2026-09-02, same conversation: PATCH ...
// {"queue":"done"} is a real, special action, not a literal 4th board
// column ("we dont have a done column" -- founder's own words) -- it
// (a) relocates the item's own full real text in BACKLOG.md into a
// standing archive section, checkbox flipped to [x], (b) files a real
// Apple via Store.AppendApple (the exact same call create() itself makes
// -- one real code path for "file an Apple," not a second one for manual
// kanban completions), titled/bodied with real context about the actual
// task, not a bare placeholder, and (c) deletes the card. Store/
// ApplesGitDir empty disables this path too (falls back to a plain
// queue update, same as any other real queue value) -- same real,
// deliberate off-switch convention as BacklogPath above.
type KanbanHandler struct {
	DB           *sql.DB
	BacklogPath  string
	Store        store.IAMStore
	ApplesGitDir string
	// SourceRepoName labels the Apple filed on a "done" board move (see fileCompletionApple).
	// IDUNA's own instance of this handler always meant "EMILY" here -- IDUNA_PRO is a real,
	// generic product a customer runs for their OWN project, so this is a real, honest,
	// configurable field instead of a hardcoded org name. Empty defaults to "kanban".
	SourceRepoName string
}

// kanbanArchiveSectionHeading is the one standing, real section a "done"
// kanban move relocates an item's own full text into -- the real
// counterpart to kanbanIntakeSectionHeading below, for the OTHER real
// direction (an item leaving active work, not entering it). Mirrors
// EMILY/CLAUDE.md's own already-documented DONE.md concept ("Archived
// completed items") in spirit, kept inside BACKLOG.md itself rather than a
// second file so ExtractItemRaw/ByID never need to reconcile two real
// files as one logical backlog.
const kanbanArchiveSectionHeading = "## SECTION 9001: ARCHIVE (completed via kanban board move)"

// backlogFileMu serializes writes to BACKLOG.md + its git add/commit/push
// across concurrent create() calls -- a distinct mutex from apples.go's own
// gitSyncMu since it guards a different working tree (EMILY, not APPLES).
var backlogFileMu sync.Mutex

// kanbanIntakeSectionHeading is the one standing, real section every
// kanban-originated new item lands under -- deliberately NOT guessing
// which existing topical SECTION a card typed into the kanban UI belongs
// to (kanban.go's own doc comment already establishes IDs and containing
// section numbers as independent, real, unrelated numbers elsewhere in
// this file). A human/agent can re-file an entry into a more fitting
// section later; this just guarantees it's real, in git, and never lost.
const kanbanIntakeSectionHeading = "## SECTION 9000: ADDED VIA IDUNA KANBAN INTERFACE (eventual-consistency intake)"

type kanbanCard struct {
	ID            int64  `json:"id"`
	BacklogItemID string `json:"backlog_item_id"`
	Title         string `json:"title"`
	Queue         string `json:"queue"`
	Position      int    `json:"position"`
	CreatedAt     string `json:"created_at"`
	UpdatedAt     string `json:"updated_at"`
}

var validKanbanQueues = map[string]bool{"backlog": true, "priority": true, "cruise": true}

func (h *KanbanHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if h.DB == nil {
		http.Error(w, "kanban not available", http.StatusServiceUnavailable)
		return
	}
	claims := middleware.ClaimsFromContext(r.Context())
	if claims == nil {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	switch r.Method {
	case http.MethodGet:
		h.list(w, r)
	case http.MethodPost:
		h.create(w, r)
	case http.MethodPatch:
		h.update(w, r)
	case http.MethodDelete:
		h.delete(w, r)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (h *KanbanHandler) list(w http.ResponseWriter, r *http.Request) {
	queue := r.URL.Query().Get("queue")
	var rows *sql.Rows
	var err error
	if queue != "" {
		if !validKanbanQueues[queue] {
			http.Error(w, "queue must be one of: backlog, priority, cruise", http.StatusBadRequest)
			return
		}
		rows, err = h.DB.QueryContext(r.Context(),
			`SELECT id, backlog_item_id, title, queue, position, created_at, updated_at
			 FROM kanban_cards WHERE queue = ? ORDER BY position ASC, id ASC`, queue)
	} else {
		rows, err = h.DB.QueryContext(r.Context(),
			`SELECT id, backlog_item_id, title, queue, position, created_at, updated_at
			 FROM kanban_cards ORDER BY queue ASC, position ASC, id ASC`)
	}
	if err != nil {
		http.Error(w, "db error", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	out := []kanbanCard{}
	for rows.Next() {
		var c kanbanCard
		if err := rows.Scan(&c.ID, &c.BacklogItemID, &c.Title, &c.Queue, &c.Position, &c.CreatedAt, &c.UpdatedAt); err != nil {
			continue
		}
		out = append(out, c)
	}
	rows.Close()

	out = h.removeCompletedCards(r, out)

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(out)
}

// removeCompletedCards: "when we finish something it needs to move off the
// kanban board" (founder real-time, 2026-09-02) -- any card whose
// backlog_item_id is confirmed CHECKED in the live BACKLOG.md is deleted
// from kanban_cards for real (not just hidden), then excluded from this
// response, so the board reflects "done" the moment the file does. A card
// whose id isn't found at all in the file (renamed section, moved,
// deleted) is left alone -- only a POSITIVE checked confirmation removes
// anything, never an absence. Best-effort: a backlog read failure just
// returns cards unfiltered, logged, same as every other best-effort path
// in this file.
func (h *KanbanHandler) removeCompletedCards(r *http.Request, cards []kanbanCard) []kanbanCard {
	if h.BacklogPath == "" || len(cards) == 0 {
		return cards
	}
	items, err := backlog.ParseFile(h.BacklogPath)
	if err != nil {
		log.Printf("[kanban] read backlog for completed-card check: %v", err)
		return cards
	}
	byID := backlog.ByID(items)

	kept := make([]kanbanCard, 0, len(cards))
	for _, c := range cards {
		if it, ok := byID[c.BacklogItemID]; ok && it.Checked {
			if _, err := h.DB.ExecContext(r.Context(), `DELETE FROM kanban_cards WHERE id = ?`, c.ID); err != nil {
				log.Printf("[kanban] failed to remove completed card id=%d (%s): %v", c.ID, c.BacklogItemID, err)
				kept = append(kept, c) // couldn't remove it -- still show it rather than silently drop
				continue
			}
			log.Printf("[kanban] %s marked done in BACKLOG.md -- removed from the board", c.BacklogItemID)
			continue
		}
		kept = append(kept, c)
	}
	return kept
}

func (h *KanbanHandler) create(w http.ResponseWriter, r *http.Request) {
	var body struct {
		BacklogItemID string `json:"backlog_item_id"`
		Title         string `json:"title"`
		Queue         string `json:"queue"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "invalid JSON", http.StatusBadRequest)
		return
	}
	body.BacklogItemID = strings.TrimSpace(body.BacklogItemID)
	body.Title = strings.TrimSpace(body.Title)
	if h.BacklogPath != "" {
		body.BacklogItemID = resolveBareSectionID(h.BacklogPath, body.BacklogItemID)
	}
	if body.BacklogItemID == "" || len(body.BacklogItemID) > 32 {
		http.Error(w, "backlog_item_id required, max 32 chars", http.StatusBadRequest)
		return
	}
	if body.Title == "" {
		http.Error(w, "title required", http.StatusBadRequest)
		return
	}
	if len(body.Title) > 200 {
		body.Title = body.Title[:200]
	}
	if body.Queue == "" {
		body.Queue = "backlog"
	}
	if !validKanbanQueues[body.Queue] {
		http.Error(w, "queue must be one of: backlog, priority, cruise", http.StatusBadRequest)
		return
	}

	// New cards land at the end of their column -- real next-position lookup,
	// not just 0, so a fresh card doesn't jump ahead of everything already
	// ranked there.
	var maxPos sql.NullInt64
	_ = h.DB.QueryRowContext(r.Context(), `SELECT MAX(position) FROM kanban_cards WHERE queue = ?`, body.Queue).Scan(&maxPos)
	nextPos := 0
	if maxPos.Valid {
		nextPos = int(maxPos.Int64) + 1
	}

	res, err := h.DB.ExecContext(r.Context(),
		`INSERT INTO kanban_cards (backlog_item_id, title, queue, position) VALUES (?, ?, ?, ?)`,
		body.BacklogItemID, body.Title, body.Queue, nextPos)
	if err != nil {
		http.Error(w, "db error", http.StatusInternalServerError)
		return
	}
	id, _ := res.LastInsertId()
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	// backlog_item_id echoed back real and resolved -- the only way a caller who submitted a
	// bare section reference (see resolveBareSectionID's own doc comment) finds out which real
	// id actually got assigned.
	_ = json.NewEncoder(w).Encode(map[string]any{"id": id, "backlog_item_id": body.BacklogItemID})

	// Fire-and-forget: never let a slow/failed git sync hold up the response
	// a caller (the kanban page's own fetch, or a real bearer-auth agent
	// caller) is waiting on for the DB write, which has already succeeded.
	if h.BacklogPath != "" {
		go h.syncNewItemToBacklogGitIfMissing(body.BacklogItemID, body.Title)
	}
}

// bareSectionRe matches a manually-typed backlog_item_id that names only a section number
// ("S203"), not a specific item within it ("S203-04"). Anchored full-string match -- a real,
// already-specific id like "S203-04" or a non-numeric id like "GFD-SYNC" must fall through
// unresolved and untouched.
var bareSectionRe = regexp.MustCompile(`^S(\d+)$`)

// realSectionItemRe extracts the item-number suffix from every real id already under a given
// section, so resolveBareSectionID can find the next free one -- deliberately narrower than
// backlog.Parse's own itemRe (which also has to accept non-numeric ids like "GFD-SYNC"): this
// one only needs the "S<section>-<number>" shape, since that's the only shape a bare "S<section>"
// request could plausibly continue.
func realSectionItemRe(section string) *regexp.Regexp {
	return regexp.MustCompile(`^S` + section + `-(\d+)$`)
}

// resolveBareSectionID closes the real, live-found UX gap SECTION 235/S235-01 named: a manual
// kanban add-card required a caller to already know and correctly guess an unused
// "S<section>-<item>" id up front -- guessing wrong (as genuinely happened live, 2026-09-02:
// a new card for "fix PAPERCRAFT build in ci" collided with an existing, unrelated S203-04)
// silently overwrote nothing in the DB (kanban_cards has no UNIQUE constraint on
// backlog_item_id) but DID create two real kanban cards claiming the same backlog line, and
// confused BACKLOG.md's own eventual-consistency sync the moment either one tried to reconcile.
//
// Founder: "the -27 part of the item doesnt need to be specify you can but if you just say
// S203 then you can do that but you shouldnt have to." Real fix: accept a bare "S<section>"
// reference and auto-assign the next real, actually-unused item number under that section by
// reading the live BACKLOG.md (backlog.ParseFile) -- the same file this handler's own sync
// already treats as the one authoritative source, not a second guess. Only fires on the exact
// bare-section shape (bareSectionRe); a caller who already gave a full, specific id (the
// existing, still-fully-supported path) is returned completely unchanged.
//
// A read failure (missing file, permission issue) or a section with zero existing real items
// both fall back to "<section>-01" rather than erroring the whole create -- honest best-effort,
// matching every other real backlog-file interaction in this handler.
func resolveBareSectionID(backlogPath, rawID string) string {
	m := bareSectionRe.FindStringSubmatch(rawID)
	if m == nil {
		return rawID
	}
	section := m[1]
	itemRe := realSectionItemRe(section)
	maxN := 0
	if items, err := backlog.ParseFile(backlogPath); err == nil {
		for _, it := range items {
			if sm := itemRe.FindStringSubmatch(it.ID); sm != nil {
				if n, convErr := strconv.Atoi(sm[1]); convErr == nil && n > maxN {
					maxN = n
				}
			}
		}
	}
	next := maxN + 1
	if next <= 99 {
		return fmt.Sprintf("S%s-%02d", section, next)
	}
	return fmt.Sprintf("S%s-%d", section, next)
}

// syncNewItemToBacklogGitIfMissing checks the live file first (best-effort
// -- a read failure just skips the sync, logged, same as every other
// best-effort path here) and only appends+commits+pushes if id genuinely
// isn't already a real line in BACKLOG.md. A card created for an id that
// DOES already exist (the normal case -- most cards track a real item
// already written by a human/agent session) is a real no-op here, exactly
// as it should be: BACKLOG.md already has it, nothing to sync.
func (h *KanbanHandler) syncNewItemToBacklogGitIfMissing(id, title string) {
	items, err := backlog.ParseFile(h.BacklogPath)
	if err != nil {
		log.Printf("[kanban-git] read backlog: %v", err)
		return
	}
	if _, exists := backlog.ByID(items)[id]; exists {
		return
	}

	backlogFileMu.Lock()
	defer backlogFileMu.Unlock()

	// Re-check under the lock -- a concurrent create() for the same id
	// could have already appended it while this goroutine was waiting.
	items, err = backlog.ParseFile(h.BacklogPath)
	if err != nil {
		log.Printf("[kanban-git] re-read backlog: %v", err)
		return
	}
	if _, exists := backlog.ByID(items)[id]; exists {
		return
	}

	data, err := os.ReadFile(h.BacklogPath)
	if err != nil {
		log.Printf("[kanban-git] read %s: %v", h.BacklogPath, err)
		return
	}
	text := string(data)

	sessTag := currentSessionTag(emilyRootDefault())
	sessSuffix := ""
	if sessTag != "" {
		sessSuffix = "\n  (" + sessTag + ")"
	}
	entry := fmt.Sprintf("- [ ] **%s: %s** Added via the IDUNA kanban interface, not yet triaged into a real section.%s\n", id, title, sessSuffix)

	if !strings.Contains(text, kanbanIntakeSectionHeading) {
		if !strings.HasSuffix(text, "\n") {
			text += "\n"
		}
		text += "\n" + kanbanIntakeSectionHeading + "\n\n"
	}
	if !strings.HasSuffix(text, "\n") {
		text += "\n"
	}
	text += entry

	if err := os.WriteFile(h.BacklogPath, []byte(text), 0o644); err != nil {
		log.Printf("[kanban-git] write %s: %v", h.BacklogPath, err)
		return
	}

	commitMsg := fmt.Sprintf("backlog: + %s (added via IDUNA kanban interface)", id)
	if err := commitAndPushBacklog(h.BacklogPath, commitMsg); err != nil {
		log.Printf("[kanban-git] %v", err)
		return
	}
	log.Printf("[kanban-git] synced new backlog item %s → BACKLOG.md", id)
}

// commitAndPushBacklog runs the real git add/commit/push sequence against
// BACKLOG.md's own repo (its containing directory), tagged with the
// current real session (same real convention `syncAppleToGit`'s own
// commits already use). Shared by syncNewItemToBacklogGitIfMissing above
// and completeCard below -- one real git-plumbing helper, not two copies
// (2026-09-02, "process improvements... make the plumbing more codified").
// Caller must already hold backlogFileMu.
func commitAndPushBacklog(backlogPath, commitMsg string) error {
	emilyRoot := filepath.Dir(backlogPath)
	if sessTag := currentSessionTag(emilyRootDefault()); sessTag != "" {
		commitMsg += "\n\nsession: " + sessTag
	}
	gitEnv := append(os.Environ(),
		"GIT_AUTHOR_NAME=iduna", "GIT_AUTHOR_EMAIL=iduna@einhorn.internal",
		"GIT_COMMITTER_NAME=iduna", "GIT_COMMITTER_EMAIL=iduna@einhorn.internal",
	)
	addCmd := exec.Command("git", "-C", emilyRoot, "add", "BACKLOG.md")
	addCmd.Env = gitEnv
	if out, err := addCmd.CombinedOutput(); err != nil {
		return fmt.Errorf("git add: %w\n%s", err, out)
	}
	commitCmd := exec.Command("git", "-C", emilyRoot, "commit", "-m", commitMsg)
	commitCmd.Env = gitEnv
	if out, err := commitCmd.CombinedOutput(); err != nil {
		return fmt.Errorf("git commit: %w\n%s", err, out)
	}
	if err := gitPushWithRetry("kanban-git", emilyRoot, gitEnv); err != nil {
		return fmt.Errorf("git push failed after retry: %w", err)
	}
	return nil
}

func (h *KanbanHandler) update(w http.ResponseWriter, r *http.Request) {
	id, ok := kanbanIDFromPath(r.URL.Path)
	if !ok {
		http.Error(w, "invalid card id", http.StatusBadRequest)
		return
	}
	var body struct {
		Queue    *string `json:"queue"`
		Position *int    `json:"position"`
		Title    *string `json:"title"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "invalid JSON", http.StatusBadRequest)
		return
	}
	if body.Queue == nil && body.Position == nil && body.Title == nil {
		http.Error(w, "nothing to update -- provide queue, position, and/or title", http.StatusBadRequest)
		return
	}
	if body.Queue != nil && *body.Queue == "done" {
		h.completeCard(w, r, id)
		return
	}
	if body.Queue != nil && !validKanbanQueues[*body.Queue] {
		http.Error(w, "queue must be one of: backlog, priority, cruise", http.StatusBadRequest)
		return
	}

	sets := []string{"updated_at = CURRENT_TIMESTAMP"}
	args := []any{}
	if body.Queue != nil {
		sets = append(sets, "queue = ?")
		args = append(args, *body.Queue)
	}
	if body.Position != nil {
		sets = append(sets, "position = ?")
		args = append(args, *body.Position)
	}
	if body.Title != nil {
		t := strings.TrimSpace(*body.Title)
		if t == "" {
			http.Error(w, "title cannot be blank", http.StatusBadRequest)
			return
		}
		if len(t) > 200 {
			t = t[:200]
		}
		sets = append(sets, "title = ?")
		args = append(args, t)
	}
	args = append(args, id)

	res, err := h.DB.ExecContext(r.Context(),
		"UPDATE kanban_cards SET "+strings.Join(sets, ", ")+" WHERE id = ?", args...)
	if err != nil {
		http.Error(w, "db error", http.StatusInternalServerError)
		return
	}
	if n, _ := res.RowsAffected(); n == 0 {
		http.Error(w, "card not found", http.StatusNotFound)
		return
	}
	w.WriteHeader(http.StatusOK)
}

// completeCard is PATCH .../cards/{id} {"queue":"done"} -- see KanbanHandler's
// own doc comment for the full real design. Real, honest degraded paths,
// never a hard failure over a missing optional dependency: no Store/
// ApplesGitDir configured skips the Apple; no matching BACKLOG.md line
// found skips the file move (still files the Apple, noting that honestly
// in its own body) -- either way the card itself is always real,
// genuinely removed from the board, since that's the one thing the
// founder's own "done" ask is unconditionally about.
func (h *KanbanHandler) completeCard(w http.ResponseWriter, r *http.Request, id int64) {
	var backlogItemID, title string
	err := h.DB.QueryRowContext(r.Context(),
		`SELECT backlog_item_id, title FROM kanban_cards WHERE id = ?`, id).Scan(&backlogItemID, &title)
	if err == sql.ErrNoRows {
		http.Error(w, "card not found", http.StatusNotFound)
		return
	}
	if err != nil {
		http.Error(w, "db error", http.StatusInternalServerError)
		return
	}

	archived := false
	if h.BacklogPath != "" {
		archived = h.archiveBacklogItem(backlogItemID)
	}

	if h.Store != nil {
		go h.fileCompletionApple(backlogItemID, title, archived)
	}

	if _, err := h.DB.ExecContext(r.Context(), `DELETE FROM kanban_cards WHERE id = ?`, id); err != nil {
		http.Error(w, "db error", http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusOK)
}

// archiveBacklogItem moves backlogItemID's own real, complete text (every
// continuation line included, via backlog.ExtractItemRaw) out of wherever
// it currently sits in BACKLOG.md, flips its checkbox to [x], and appends
// it under the standing kanbanArchiveSectionHeading -- founder real-time:
// "it should be moved to a different section of the backlog for archive."
// Returns whether a real matching line was actually found and moved (false
// is a real, honest "nothing to move," not an error -- a card whose id
// never made it into the file, e.g. the S203-04 collision found earlier
// this session, has nothing to archive).
func (h *KanbanHandler) archiveBacklogItem(id string) bool {
	backlogFileMu.Lock()
	defer backlogFileMu.Unlock()

	data, err := os.ReadFile(h.BacklogPath)
	if err != nil {
		log.Printf("[kanban-git] read %s: %v", h.BacklogPath, err)
		return false
	}
	text := string(data)

	raw, start, end, found := backlog.ExtractItemRaw(text, id)
	if !found {
		log.Printf("[kanban-git] %s has no real BACKLOG.md line to archive -- skipping the file move", id)
		return false
	}

	checked := strings.Replace(raw, "- [ ] **"+id+":", "- [x] **"+id+":", 1)
	newText := text[:start] + text[end:]
	if !strings.HasSuffix(newText, "\n") {
		newText += "\n"
	}
	if !strings.Contains(newText, kanbanArchiveSectionHeading) {
		newText += "\n" + kanbanArchiveSectionHeading + "\n\n"
	}
	if !strings.HasSuffix(newText, "\n") {
		newText += "\n"
	}
	newText += strings.TrimRight(checked, "\n") + "\n"

	if err := os.WriteFile(h.BacklogPath, []byte(newText), 0o644); err != nil {
		log.Printf("[kanban-git] write %s: %v", h.BacklogPath, err)
		return false
	}
	commitMsg := fmt.Sprintf("backlog: ✓ %s (marked done + archived via IDUNA kanban board)", id)
	if err := commitAndPushBacklog(h.BacklogPath, commitMsg); err != nil {
		log.Printf("[kanban-git] %v", err)
		return false
	}
	log.Printf("[kanban-git] archived completed backlog item %s", id)
	return true
}

// fileCompletionApple posts a real Apple recording a manual kanban "done"
// move -- founder real-time: "we still need to file the apple for moving
// it to done, say manual kanban move or something in the apple ... to get
// more of the context of the actual task." Reuses Store.AppendApple, the
// EXACT SAME real call create() itself makes -- one real code path for
// "file an Apple," never a second, parallel one for this case -- and
// syncAppleToGit for the identical real git-mirror behavior every other
// Apple gets. AppleType "backlog_completion" is the real, already-
// established type for exactly this shape (see IDUNA/CLAUDE.md's own
// Apple type list).
// kanbanSourceRepoOr returns name, or "kanban" if it's empty -- a real, generic fallback for a
// product instance that hasn't configured SourceRepoName, rather than assuming any particular
// org's own project name (IDUNA's own instance of this file always hardcoded "EMILY" here).
func kanbanSourceRepoOr(name string) string {
	if name == "" {
		return "kanban"
	}
	return name
}

func (h *KanbanHandler) fileCompletionApple(backlogItemID, title string, archived bool) {
	shortTitle := title
	if len(shortTitle) > 60 {
		shortTitle = shortTitle[:60]
	}
	body := fmt.Sprintf(
		"Manual kanban move: %s (%s) moved to Done on the IDUNA kanban board, not through the normal implement-then-file-an-Apple flow.",
		backlogItemID, title)
	if archived {
		body += " Its own real BACKLOG.md line was checked off and relocated into the standing archive section."
	} else {
		body += " No matching BACKLOG.md line was found to archive (filed here for the audit trail regardless)."
	}
	apple := auth.AppleRecord{
		AgentID:    "iduna-kanban",
		SourceRepo: kanbanSourceRepoOr(h.SourceRepoName),
		RunID:      currentSessionTag(emilyRootDefault()),
		AppleType:  "backlog_completion",
		Title:      "Manual kanban move: " + shortTitle,
		Body:       signAppleBody(body),
	}
	appleID, err := h.Store.AppendApple(context.Background(), apple)
	if err != nil {
		log.Printf("[kanban-git] failed to file completion apple for %s: %v", backlogItemID, err)
		return
	}
	apple.ID = appleID
	syncAppleToGit(h.ApplesGitDir, apple)
	log.Printf("[kanban-git] filed completion Apple #%d for %s", appleID, backlogItemID)
}

func (h *KanbanHandler) delete(w http.ResponseWriter, r *http.Request) {
	id, ok := kanbanIDFromPath(r.URL.Path)
	if !ok {
		http.Error(w, "invalid card id", http.StatusBadRequest)
		return
	}
	res, err := h.DB.ExecContext(r.Context(), `DELETE FROM kanban_cards WHERE id = ?`, id)
	if err != nil {
		http.Error(w, "db error", http.StatusInternalServerError)
		return
	}
	if n, _ := res.RowsAffected(); n == 0 {
		http.Error(w, "card not found", http.StatusNotFound)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// kanbanIDFromPath extracts the numeric id from /api/v1/kanban/cards/{id}.
func kanbanIDFromPath(path string) (int64, bool) {
	parts := strings.Split(strings.Trim(path, "/"), "/")
	if len(parts) == 0 {
		return 0, false
	}
	last := parts[len(parts)-1]
	id, err := strconv.ParseInt(last, 10, 64)
	if err != nil || id <= 0 {
		return 0, false
	}
	return id, true
}
