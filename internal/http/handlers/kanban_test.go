package handlers_test

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	_ "modernc.org/sqlite"

	"idunapro/internal/auth/jwt"
	"idunapro/internal/http/handlers"
	"idunapro/internal/http/middleware"

	"github.com/google/uuid"
)

func newTestKanbanDB(t *testing.T) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	_, err = db.Exec(`CREATE TABLE kanban_cards (
		id              INTEGER  PRIMARY KEY AUTOINCREMENT,
		backlog_item_id VARCHAR(32) NOT NULL,
		title           VARCHAR(200) NOT NULL,
		queue           VARCHAR(16) NOT NULL DEFAULT 'backlog',
		position        INTEGER NOT NULL DEFAULT 0,
		created_at      DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
		updated_at      DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
	)`)
	if err != nil {
		t.Fatalf("create kanban_cards table: %v", err)
	}
	return db
}

func kanbanHandlerWithAuth(keys *jwt.Keys, db *sql.DB) http.Handler {
	h := &handlers.KanbanHandler{DB: db}
	return middleware.RequireAuth(keys)(h)
}

type kanbanCardOut struct {
	ID            int64  `json:"id"`
	BacklogItemID string `json:"backlog_item_id"`
	Title         string `json:"title"`
	Queue         string `json:"queue"`
	Position      int    `json:"position"`
}

func postKanbanCard(t *testing.T, h http.Handler, token, backlogItemID, title, queue string) int64 {
	t.Helper()
	payload := map[string]string{"backlog_item_id": backlogItemID, "title": title}
	if queue != "" {
		payload["queue"] = queue
	}
	b, _ := json.Marshal(payload)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/kanban/cards", bytes.NewReader(b))
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create status = %d, body = %s", rec.Code, rec.Body.String())
	}
	var resp struct {
		ID int64 `json:"id"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode create response: %v", err)
	}
	return resp.ID
}

func listKanbanCards(t *testing.T, h http.Handler, token, queueFilter string) []kanbanCardOut {
	t.Helper()
	url := "/api/v1/kanban/cards"
	if queueFilter != "" {
		url += "?queue=" + queueFilter
	}
	req := httptest.NewRequest(http.MethodGet, url, nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("list status = %d, body = %s", rec.Code, rec.Body.String())
	}
	var out []kanbanCardOut
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode list response: %v", err)
	}
	return out
}

func TestKanban_CreateDefaultsToBacklogQueue(t *testing.T) {
	keys, _ := jwt.GenerateKeys()
	db := newTestKanbanDB(t)
	token := makeAgentToken(t, keys, uuid.New().String(), nil)
	h := kanbanHandlerWithAuth(keys, db)

	postKanbanCard(t, h, token, "S202-27", "Body blocking", "")

	cards := listKanbanCards(t, h, token, "")
	if len(cards) != 1 {
		t.Fatalf("want 1 card, got %d", len(cards))
	}
	if cards[0].Queue != "backlog" {
		t.Errorf("expected default queue 'backlog', got %q", cards[0].Queue)
	}
	if cards[0].BacklogItemID != "S202-27" || cards[0].Title != "Body blocking" {
		t.Errorf("unexpected card content: %+v", cards[0])
	}
}

func TestKanban_MoveCardBetweenQueues(t *testing.T) {
	keys, _ := jwt.GenerateKeys()
	db := newTestKanbanDB(t)
	token := makeAgentToken(t, keys, uuid.New().String(), nil)
	h := kanbanHandlerWithAuth(keys, db)

	id := postKanbanCard(t, h, token, "S202-27", "Body blocking", "")

	body, _ := json.Marshal(map[string]any{"queue": "priority"})
	req := httptest.NewRequest(http.MethodPatch, "/api/v1/kanban/cards/"+jsonInt(id), bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("patch status = %d, body = %s", rec.Code, rec.Body.String())
	}

	priorityCards := listKanbanCards(t, h, token, "priority")
	if len(priorityCards) != 1 || priorityCards[0].ID != id {
		t.Fatalf("expected the card to now be in the priority queue, got %+v", priorityCards)
	}
	backlogCards := listKanbanCards(t, h, token, "backlog")
	if len(backlogCards) != 0 {
		t.Fatalf("expected the backlog queue to be empty after the move, got %+v", backlogCards)
	}
}

// TestKanban_PatchPositionReordersColumn -- S207-68 ("i should have the
// ability to sort the cards in a column"). The kanban board's own UI
// (kanban_page.go) reorders a column entirely via repeated
// PATCH .../cards/{id} {"queue":..., "position":...} calls -- this proves
// that real contract end to end: three cards land in position order 0,1,2
// on creation, a real PATCH re-numbers all three to the reverse order, and
// GET reflects the new order, not creation order.
func TestKanban_PatchPositionReordersColumn(t *testing.T) {
	keys, _ := jwt.GenerateKeys()
	db := newTestKanbanDB(t)
	token := makeAgentToken(t, keys, uuid.New().String(), nil)
	h := kanbanHandlerWithAuth(keys, db)

	idA := postKanbanCard(t, h, token, "S207-01", "Card A", "priority")
	idB := postKanbanCard(t, h, token, "S207-02", "Card B", "priority")
	idC := postKanbanCard(t, h, token, "S207-03", "Card C", "priority")

	before := listKanbanCards(t, h, token, "priority")
	if len(before) != 3 || before[0].ID != idA || before[1].ID != idB || before[2].ID != idC {
		t.Fatalf("expected creation order A,B,C before reorder, got %+v", before)
	}

	// Reverse the order: C=0, B=1, A=2.
	for newPos, id := range []int64{idC, idB, idA} {
		body, _ := json.Marshal(map[string]any{"queue": "priority", "position": newPos})
		req := httptest.NewRequest(http.MethodPatch, "/api/v1/kanban/cards/"+jsonInt(id), bytes.NewReader(body))
		req.Header.Set("Authorization", "Bearer "+token)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("patch position for card %d: status = %d, body = %s", id, rec.Code, rec.Body.String())
		}
	}

	after := listKanbanCards(t, h, token, "priority")
	if len(after) != 3 || after[0].ID != idC || after[1].ID != idB || after[2].ID != idA {
		t.Fatalf("expected reversed order C,B,A after reorder, got %+v", after)
	}
}

func TestKanban_QueueFilterScopesList(t *testing.T) {
	keys, _ := jwt.GenerateKeys()
	db := newTestKanbanDB(t)
	token := makeAgentToken(t, keys, uuid.New().String(), nil)
	h := kanbanHandlerWithAuth(keys, db)

	postKanbanCard(t, h, token, "S202-27", "Body blocking", "priority")
	postKanbanCard(t, h, token, "S202-28", "Ant hero rig", "cruise")
	postKanbanCard(t, h, token, "S202-29", "Kanban layer", "priority")

	priorityCards := listKanbanCards(t, h, token, "priority")
	if len(priorityCards) != 2 {
		t.Fatalf("want 2 priority cards, got %d: %+v", len(priorityCards), priorityCards)
	}
	cruiseCards := listKanbanCards(t, h, token, "cruise")
	if len(cruiseCards) != 1 || cruiseCards[0].BacklogItemID != "S202-28" {
		t.Fatalf("want 1 cruise card (S202-28), got %+v", cruiseCards)
	}
}

func TestKanban_NewCardLandsAtEndOfItsColumn(t *testing.T) {
	keys, _ := jwt.GenerateKeys()
	db := newTestKanbanDB(t)
	token := makeAgentToken(t, keys, uuid.New().String(), nil)
	h := kanbanHandlerWithAuth(keys, db)

	postKanbanCard(t, h, token, "S202-27", "first", "priority")
	postKanbanCard(t, h, token, "S202-28", "second", "priority")

	cards := listKanbanCards(t, h, token, "priority")
	if len(cards) != 2 {
		t.Fatalf("want 2 cards, got %d", len(cards))
	}
	if cards[0].Position >= cards[1].Position {
		t.Errorf("expected the second card to land after the first (position %d >= %d)", cards[0].Position, cards[1].Position)
	}
}

func TestKanban_RejectsInvalidQueue(t *testing.T) {
	keys, _ := jwt.GenerateKeys()
	db := newTestKanbanDB(t)
	token := makeAgentToken(t, keys, uuid.New().String(), nil)
	h := kanbanHandlerWithAuth(keys, db)

	body, _ := json.Marshal(map[string]string{"backlog_item_id": "S202-27", "title": "x", "queue": "not-a-real-queue"})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/kanban/cards", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 for invalid queue", rec.Code)
	}
}

func TestKanban_DeleteRemovesCard(t *testing.T) {
	keys, _ := jwt.GenerateKeys()
	db := newTestKanbanDB(t)
	token := makeAgentToken(t, keys, uuid.New().String(), nil)
	h := kanbanHandlerWithAuth(keys, db)

	id := postKanbanCard(t, h, token, "S202-27", "Body blocking", "")

	req := httptest.NewRequest(http.MethodDelete, "/api/v1/kanban/cards/"+jsonInt(id), nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("delete status = %d, body = %s", rec.Code, rec.Body.String())
	}

	cards := listKanbanCards(t, h, token, "")
	if len(cards) != 0 {
		t.Fatalf("expected the card to be gone, got %+v", cards)
	}
}

func TestKanban_DeleteUnknownCardReturns404(t *testing.T) {
	keys, _ := jwt.GenerateKeys()
	db := newTestKanbanDB(t)
	token := makeAgentToken(t, keys, uuid.New().String(), nil)
	h := kanbanHandlerWithAuth(keys, db)

	req := httptest.NewRequest(http.MethodDelete, "/api/v1/kanban/cards/999", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404 for an unknown card id", rec.Code)
	}
}

func TestKanban_RequiresAuth(t *testing.T) {
	keys, _ := jwt.GenerateKeys()
	db := newTestKanbanDB(t)
	h := kanbanHandlerWithAuth(keys, db)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/kanban/cards", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401 (no token)", rec.Code)
	}
}

func TestKanban_RejectsMissingBacklogItemID(t *testing.T) {
	keys, _ := jwt.GenerateKeys()
	db := newTestKanbanDB(t)
	token := makeAgentToken(t, keys, uuid.New().String(), nil)
	h := kanbanHandlerWithAuth(keys, db)

	body, _ := json.Marshal(map[string]string{"title": "no id given"})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/kanban/cards", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 for a missing backlog_item_id", rec.Code)
	}
}
