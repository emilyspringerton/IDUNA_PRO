package handlers_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"idunapro/internal/auth/jwt"
	"idunapro/internal/http/handlers"
	"idunapro/internal/http/middleware"

	"github.com/google/uuid"
)

type kanbanInboxItemOut struct {
	ID           string `json:"id"`
	Title        string `json:"title"`
	Checked      bool   `json:"checked"`
	Section      int    `json:"section"`
	SectionTitle string `json:"section_title"`
	Line         int    `json:"line"`
}

func writeTestBacklog(t *testing.T, contents string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "BACKLOG.md")
	if err := os.WriteFile(path, []byte(contents), 0o644); err != nil {
		t.Fatalf("write test backlog: %v", err)
	}
	return path
}

const testBacklogSample = `## SECTION 1: FIRST (2026-09-02)

- [ ] **S1-01: an open item, no card yet.** Real body text.
- [x] **S1-02: an already-done item.** Should never appear in the inbox.
- [ ] **S1-03: an open item that already has a real kanban card.** Should be
  excluded from the inbox too, since it's already sorted.
`

func TestKanbanInbox_ExcludesCompletedAndAlreadyCardedItems(t *testing.T) {
	keys, _ := jwt.GenerateKeys()
	db := newTestKanbanDB(t)
	token := makeAgentToken(t, keys, uuid.New().String(), nil)
	backlogPath := writeTestBacklog(t, testBacklogSample)

	kanbanH := kanbanHandlerWithAuth(keys, db)
	postKanbanCard(t, kanbanH, token, "S1-03", "already carded", "priority")

	h := middleware.RequireAuth(keys)(&handlers.KanbanInboxHandler{DB: db, BacklogPath: backlogPath})
	req := httptest.NewRequest(http.MethodGet, "/admin/kanban/api/inbox", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}
	var items []kanbanInboxItemOut
	if err := json.Unmarshal(rr.Body.Bytes(), &items); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(items) != 1 {
		t.Fatalf("expected exactly 1 real inbox item (S1-01 only), got %d: %+v", len(items), items)
	}
	if items[0].ID != "S1-01" {
		t.Errorf("expected S1-01, got %q", items[0].ID)
	}
	if items[0].Section != 1 {
		t.Errorf("expected Section 1, got %d", items[0].Section)
	}
}

func TestKanbanInbox_RequiresAuth(t *testing.T) {
	keys, _ := jwt.GenerateKeys()
	db := newTestKanbanDB(t)
	backlogPath := writeTestBacklog(t, testBacklogSample)

	h := middleware.RequireAuth(keys)(&handlers.KanbanInboxHandler{DB: db, BacklogPath: backlogPath})
	req := httptest.NewRequest(http.MethodGet, "/admin/kanban/api/inbox", nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 with no token, got %d", rr.Code)
	}
}

func TestKanbanInbox_MissingBacklogFileIsHonestError(t *testing.T) {
	keys, _ := jwt.GenerateKeys()
	db := newTestKanbanDB(t)
	token := makeAgentToken(t, keys, uuid.New().String(), nil)

	h := middleware.RequireAuth(keys)(&handlers.KanbanInboxHandler{DB: db, BacklogPath: "/nonexistent/BACKLOG.md"})
	req := httptest.NewRequest(http.MethodGet, "/admin/kanban/api/inbox", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusServiceUnavailable {
		t.Errorf("expected 503 for a missing backlog file, got %d", rr.Code)
	}
}
