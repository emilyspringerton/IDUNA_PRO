package handlers_test

import (
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"idunapro/internal/auth/jwt"
	"idunapro/internal/http/handlers"
	"idunapro/internal/http/middleware"

	"github.com/google/uuid"
)

// TestKanbanComplete_ArchivesRealItemAndFilesApple -- the real "done" move
// (founder real-time, 2026-09-02: "we still need to file the apple for
// moving it to done ... it should be moved to a different section of the
// backlog for archive"). PATCH {"queue":"done"} should: relocate the
// item's own real text into the standing archive section with its
// checkbox flipped, file a real completion Apple with real task context,
// and remove the card.
func TestKanbanComplete_ArchivesRealItemAndFilesApple(t *testing.T) {
	backlogPath := newTestBacklogGitRepo(t,
		"## SECTION 1: FIRST (2026-09-02)\n\n"+
			"- [ ] **S1-01: a real task to complete.** Real body, with a real\n"+
			"  continuation line.\n"+
			"- [ ] **S1-02: a different, unrelated task.** Real body.\n")

	keys, _ := jwt.GenerateKeys()
	db := newTestKanbanDB(t)
	token := makeAgentToken(t, keys, uuid.New().String(), nil)
	store := &stubApplesStore{appendID: 42}
	h := middleware.RequireAuth(keys)(&handlers.KanbanHandler{
		DB: db, BacklogPath: backlogPath, Store: store, ApplesGitDir: "",
	})

	cardID := postKanbanCard(t, h, token, "S1-01", "a real task to complete", "priority")

	req := httptest.NewRequest(http.MethodPatch, "/api/v1/kanban/cards/"+strconv.FormatInt(cardID, 10),
		strings.NewReader(`{"queue":"done"}`))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}

	// Real card removal -- poll briefly since the Apple itself files async,
	// but the card row and file write happen synchronously in completeCard.
	cards := listKanbanCards(t, h, token, "")
	if len(cards) != 0 {
		t.Fatalf("expected the completed card to be gone, got %d: %+v", len(cards), cards)
	}

	data, err := os.ReadFile(backlogPath)
	if err != nil {
		t.Fatalf("read backlog: %v", err)
	}
	content := string(data)
	if !strings.Contains(content, "- [x] **S1-01: a real task to complete.**") {
		t.Errorf("expected S1-01 checked off in the archive, got:\n%s", content)
	}
	if !strings.Contains(content, "ARCHIVE (completed via kanban board move)") {
		t.Errorf("expected the real archive section heading, got:\n%s", content)
	}
	if strings.Contains(content, "- [ ] **S1-01") {
		t.Errorf("expected S1-01's OLD unchecked line to be gone (moved, not duplicated), got:\n%s", content)
	}
	if !strings.Contains(content, "S1-02: a different, unrelated task.") {
		t.Errorf("expected the unrelated S1-02 item to survive untouched, got:\n%s", content)
	}

	// Real Apple, real context, not a bare placeholder.
	deadline := time.Now().Add(2 * time.Second)
	for len(store.apples) == 0 && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if len(store.apples) != 1 {
		t.Fatalf("expected exactly 1 real Apple filed, got %d", len(store.apples))
	}
	apple := store.apples[0]
	if apple.AppleType != "backlog_completion" {
		t.Errorf("AppleType = %q, want backlog_completion", apple.AppleType)
	}
	if !strings.Contains(apple.Title, "Manual kanban move") {
		t.Errorf("expected the Apple title to say 'Manual kanban move', got %q", apple.Title)
	}
	if !strings.Contains(apple.Title, "a real task to complete") {
		t.Errorf("expected the Apple title to carry real task context, got %q", apple.Title)
	}
	if !strings.Contains(apple.Body, "S1-01") {
		t.Errorf("expected the Apple body to name the real backlog item id, got %q", apple.Body)
	}
}

// TestKanbanComplete_NoMatchingBacklogLineStillFilesAppleAndRemovesCard --
// a real, honest degraded path: a card whose id never made it into
// BACKLOG.md (e.g. the real S203-04 collision found earlier this session)
// should still complete cleanly.
func TestKanbanComplete_NoMatchingBacklogLineStillFilesAppleAndRemovesCard(t *testing.T) {
	backlogPath := newTestBacklogGitRepo(t, "## SECTION 1: FIRST (2026-09-02)\n\n- [ ] **S1-01: unrelated.** Real body.\n")

	keys, _ := jwt.GenerateKeys()
	db := newTestKanbanDB(t)
	token := makeAgentToken(t, keys, uuid.New().String(), nil)
	store := &stubApplesStore{appendID: 7}
	h := middleware.RequireAuth(keys)(&handlers.KanbanHandler{
		DB: db, BacklogPath: backlogPath, Store: store, ApplesGitDir: "",
	})

	// Real, direct DB insert -- deliberately bypassing the HTTP create()
	// path (and its own async create-time backlog sync, see S234-04),
	// since this test is specifically about a card whose id has no real
	// backlog line to begin with and must stay that way for the duration
	// of the test, not race against create()'s own fire-and-forget sync.
	res, err := db.Exec(`INSERT INTO kanban_cards (backlog_item_id, title, queue, position) VALUES (?, ?, ?, ?)`,
		"S999-99", "no matching backlog line", "backlog", 0)
	if err != nil {
		t.Fatalf("direct insert: %v", err)
	}
	cardID, _ := res.LastInsertId()

	req := httptest.NewRequest(http.MethodPatch, "/api/v1/kanban/cards/"+strconv.FormatInt(cardID, 10),
		strings.NewReader(`{"queue":"done"}`))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200 even with no matching backlog line, got %d: %s", rr.Code, rr.Body.String())
	}

	cards := listKanbanCards(t, h, token, "")
	if len(cards) != 0 {
		t.Fatalf("expected the card to be removed regardless, got %d", len(cards))
	}

	deadline := time.Now().Add(2 * time.Second)
	for len(store.apples) == 0 && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if len(store.apples) != 1 {
		t.Fatalf("expected the Apple to still be filed for the audit trail, got %d", len(store.apples))
	}
	if !strings.Contains(store.apples[0].Body, "No matching BACKLOG.md line") {
		t.Errorf("expected the Apple body to honestly note the missing file match, got %q", store.apples[0].Body)
	}
}
