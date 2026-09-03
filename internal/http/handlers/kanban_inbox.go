package handlers

import (
	"database/sql"
	"encoding/json"
	"net/http"

	"idunapro/internal/backlog"
	"idunapro/internal/http/middleware"
)

// KanbanInboxHandler is the real bridge between EMILY/BACKLOG.md and the
// kanban board (founder real-time, 2026-09-02: "get the backlog working
// with the kanban" -- the board and kanban_cards table were both real, but
// completely disconnected from the actual backlog text; every card had to
// be hand-typed with no live connection at all).
//
// GET /admin/kanban/api/inbox
//
//	-> [{"id":"S233-01","title":"...","checked":false,"section":233,"section_title":"...","line":123}]
//
// Real, deliberate, read-time projection (see internal/backlog's own doc
// comment): BACKLOG.md is re-parsed on every request (cheap enough for a
// low-traffic admin page; no second store, no caching needed yet). Only
// real, OPEN items ("- [ ]") with no existing kanban_cards row are
// returned -- founder real-time, same conversation: "for now we wont see
// the completed stuff on the kanban to save dom nodes we can view that
// data elsewhere for now." An item that already has a card is presumed
// already sorted into a real queue and shouldn't also show up as
// "un-sorted" inbox noise.
type KanbanInboxHandler struct {
	DB          *sql.DB
	BacklogPath string
}

func (h *KanbanInboxHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if h.DB == nil || h.BacklogPath == "" {
		http.Error(w, "kanban inbox not available", http.StatusServiceUnavailable)
		return
	}
	claims := middleware.ClaimsFromContext(r.Context())
	if claims == nil {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	items, err := backlog.ParseFile(h.BacklogPath)
	if err != nil {
		http.Error(w, "failed to read backlog: "+err.Error(), http.StatusServiceUnavailable)
		return
	}

	rows, err := h.DB.QueryContext(r.Context(), `SELECT backlog_item_id FROM kanban_cards`)
	if err != nil {
		http.Error(w, "db error", http.StatusInternalServerError)
		return
	}
	defer rows.Close()
	carded := map[string]bool{}
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err == nil {
			carded[id] = true
		}
	}

	out := make([]backlog.Item, 0, len(items))
	for _, it := range items {
		if it.Checked || carded[it.ID] {
			continue
		}
		out = append(out, it)
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(out)
}
