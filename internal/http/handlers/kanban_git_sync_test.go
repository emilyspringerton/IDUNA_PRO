package handlers_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"idunapro/internal/auth/jwt"
	"idunapro/internal/http/handlers"
	"idunapro/internal/http/middleware"

	"github.com/google/uuid"
)

// newTestBacklogGitRepo sets up a real git repo (git init + one commit) with
// a real BACKLOG.md, and returns the path to that file. No remote is
// configured -- the real code's own git push is expected to fail here
// (logged, non-fatal, fire-and-forget), same as it would on any box with a
// transient network problem; the commit itself still lands locally either
// way, which is what these tests actually verify.
func newTestBacklogGitRepo(t *testing.T, seed string) string {
	t.Helper()
	dir := t.TempDir()
	run := func(args ...string) {
		cmd := exec.Command("git", append([]string{"-C", dir}, args...)...)
		cmd.Env = append(os.Environ(),
			"GIT_AUTHOR_NAME=test", "GIT_AUTHOR_EMAIL=test@test.internal",
			"GIT_COMMITTER_NAME=test", "GIT_COMMITTER_EMAIL=test@test.internal",
		)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
	}
	run("init")
	path := filepath.Join(dir, "BACKLOG.md")
	if err := os.WriteFile(path, []byte(seed), 0o644); err != nil {
		t.Fatalf("write seed backlog: %v", err)
	}
	run("add", "BACKLOG.md")
	run("commit", "-m", "seed")
	return path
}

func gitLog(t *testing.T, repoDir string) string {
	t.Helper()
	cmd := exec.Command("git", "-C", repoDir, "log", "--oneline")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git log: %v\n%s", err, out)
	}
	return string(out)
}

// TestKanbanCreate_SyncsNewItemToBacklogGit -- the real "kanban -> file"
// direction (founder real-time, 2026-09-02: "if it gets added to backlog
// via the kanban interface it needs to wind up in the golden backlog file
// in git"). A card created for an id NOT already in BACKLOG.md gets a real
// line appended and a real git commit, asynchronously -- polled for since
// the sync itself is a fire-and-forget goroutine by design (never blocks
// the real HTTP response the DB write already succeeded for).
func TestKanbanCreate_SyncsNewItemToBacklogGit(t *testing.T) {
	backlogPath := newTestBacklogGitRepo(t, "# BACKLOG\n\n## SECTION 1: EXISTING (2026-09-02)\n\n- [ ] **S1-01: an existing item.** Real body.\n")
	repoDir := filepath.Dir(backlogPath)

	keys, _ := jwt.GenerateKeys()
	db := newTestKanbanDB(t)
	token := makeAgentToken(t, keys, uuid.New().String(), nil)
	h := middleware.RequireAuth(keys)(&handlers.KanbanHandler{DB: db, BacklogPath: backlogPath})

	postKanbanCard(t, h, token, "S202-200", "A real item added via kanban", "priority")

	deadline := time.Now().Add(3 * time.Second)
	var content string
	for time.Now().Before(deadline) {
		data, err := os.ReadFile(backlogPath)
		if err != nil {
			t.Fatalf("read backlog: %v", err)
		}
		content = string(data)
		if strings.Contains(content, "S202-200") {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}

	if !strings.Contains(content, "S202-200: A real item added via kanban") {
		t.Fatalf("expected BACKLOG.md to contain the new real item, got:\n%s", content)
	}
	if !strings.Contains(content, "ADDED VIA IDUNA KANBAN INTERFACE") {
		t.Errorf("expected the real kanban intake section heading, got:\n%s", content)
	}
	// The pre-existing item must be untouched.
	if !strings.Contains(content, "S1-01: an existing item.") {
		t.Errorf("expected the pre-existing item to survive untouched, got:\n%s", content)
	}

	log := gitLog(t, repoDir)
	if !strings.Contains(log, "S202-200") {
		t.Errorf("expected a real git commit mentioning S202-200, got log:\n%s", log)
	}
}

// TestKanbanCreate_ExistingItemIsNotDuplicated -- a card created for an id
// that's ALREADY a real line in BACKLOG.md must not touch the file at all.
func TestKanbanCreate_ExistingItemIsNotDuplicated(t *testing.T) {
	backlogPath := newTestBacklogGitRepo(t, "## SECTION 1: EXISTING (2026-09-02)\n\n- [ ] **S1-01: an existing item.** Real body.\n")

	keys, _ := jwt.GenerateKeys()
	db := newTestKanbanDB(t)
	token := makeAgentToken(t, keys, uuid.New().String(), nil)
	h := middleware.RequireAuth(keys)(&handlers.KanbanHandler{DB: db, BacklogPath: backlogPath})

	postKanbanCard(t, h, token, "S1-01", "an existing item", "")

	// Give any (incorrect, if it happened) async write a moment, then assert
	// the file is byte-for-byte unchanged.
	time.Sleep(200 * time.Millisecond)
	data, err := os.ReadFile(backlogPath)
	if err != nil {
		t.Fatalf("read backlog: %v", err)
	}
	got := string(data)
	if strings.Count(got, "S1-01") != 1 {
		t.Errorf("expected exactly 1 occurrence of S1-01 (no duplicate append), got %d:\n%s", strings.Count(got, "S1-01"), got)
	}
}

// TestKanbanList_RemovesCardsForCompletedItems -- "when we finish something
// it needs to move off the kanban board" (founder real-time, 2026-09-02).
func TestKanbanList_RemovesCardsForCompletedItems(t *testing.T) {
	backlogPath := newTestBacklogGitRepo(t,
		"## SECTION 1: FIRST (2026-09-02)\n\n"+
			"- [ ] **S1-01: still open.** Real body.\n"+
			"- [x] **S1-02: already done.** Real body.\n")

	keys, _ := jwt.GenerateKeys()
	db := newTestKanbanDB(t)
	token := makeAgentToken(t, keys, uuid.New().String(), nil)
	h := middleware.RequireAuth(keys)(&handlers.KanbanHandler{DB: db, BacklogPath: backlogPath})

	postKanbanCard(t, h, token, "S1-01", "still open", "")
	doneID := postKanbanCard(t, h, token, "S1-02", "already done", "")

	cards := listKanbanCards(t, h, token, "")
	if len(cards) != 1 {
		t.Fatalf("expected exactly 1 card left (the open one), got %d: %+v", len(cards), cards)
	}
	if cards[0].BacklogItemID != "S1-01" {
		t.Errorf("expected the surviving card to be S1-01, got %q", cards[0].BacklogItemID)
	}

	// Real double-check: the completed card's row is actually gone from the
	// DB, not just hidden from this one response.
	all := listKanbanCards(t, h, token, "")
	for _, c := range all {
		if c.ID == doneID {
			t.Errorf("expected card id=%d (S1-02) to be deleted, but it's still present", doneID)
		}
	}
}

// TestKanbanCreate_BareSectionResolvesToRealID -- S235-01, end to end: a manually-typed bare
// section reference ("S203") gets resolved to a real, actually-unused item id before the card is
// ever inserted, and the real id (not the bare one the caller typed) is what BACKLOG.md's own
// eventual-consistency sync appends.
func TestKanbanCreate_BareSectionResolvesToRealID(t *testing.T) {
	backlogPath := newTestBacklogGitRepo(t,
		"# BACKLOG\n\n## SECTION 203: TEST (2026-09-03)\n\n"+
			"- [ ] **S203-04: an unrelated, already-existing item -- the exact real collision this\n"+
			"  fix prevents.** Real body.\n")

	keys, _ := jwt.GenerateKeys()
	db := newTestKanbanDB(t)
	token := makeAgentToken(t, keys, uuid.New().String(), nil)
	h := middleware.RequireAuth(keys)(&handlers.KanbanHandler{DB: db, BacklogPath: backlogPath})

	payload := map[string]string{"backlog_item_id": "S203", "title": "fix PAPERCRAFT build in ci"}
	b, _ := json.Marshal(payload)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/kanban/cards", bytes.NewReader(b))
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create status = %d, body = %s", rec.Code, rec.Body.String())
	}
	var resp struct {
		ID            int64  `json:"id"`
		BacklogItemID string `json:"backlog_item_id"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode create response: %v", err)
	}
	// S203-04 already exists -- the next real, unused number is S203-05, never the collision
	// this whole feature exists to prevent.
	if resp.BacklogItemID != "S203-05" {
		t.Fatalf("resolved backlog_item_id = %q, want S203-05", resp.BacklogItemID)
	}

	cards := listKanbanCards(t, h, token, "")
	if len(cards) != 1 || cards[0].BacklogItemID != "S203-05" {
		t.Fatalf("expected exactly 1 card with backlog_item_id S203-05, got: %+v", cards)
	}

	deadline := time.Now().Add(3 * time.Second)
	var content string
	for time.Now().Before(deadline) {
		data, err := os.ReadFile(backlogPath)
		if err != nil {
			t.Fatalf("read backlog: %v", err)
		}
		content = string(data)
		if strings.Contains(content, "S203-05") {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if !strings.Contains(content, "S203-05: fix PAPERCRAFT build in ci") {
		t.Fatalf("expected BACKLOG.md to contain the real resolved item, got:\n%s", content)
	}
}
