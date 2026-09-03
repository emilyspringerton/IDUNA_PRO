package handlers

import (
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"idunapro/internal/auth"
	"idunapro/internal/store"
)

// AgentsHandler serves:
//
//	GET  /api/v1/agents              — list agents (?type=emily_cluster, ?active=true)
//	GET  /api/v1/agents/{id}         — get single agent
//	POST /api/v1/agents/heartbeat    — upsert cluster heartbeat
//
// Requires a valid JWT (any agent or local user). Returns JSON.
type AgentsHandler struct {
	Store store.IAMStore
}

func (h *AgentsHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/api/v1/agents")
	path = strings.Trim(path, "/")

	if r.Method == http.MethodPost && path == "heartbeat" {
		h.heartbeat(w, r)
		return
	}
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if path != "" {
		h.getOne(w, r, path)
		return
	}
	h.list(w, r)
}

func (h *AgentsHandler) list(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	q := r.URL.Query()
	typeFilter := q.Get("type")
	activeOnly := q.Get("active") == "true"

	// When ?active=true is requested, use the heartbeat table for live clusters.
	if activeOnly && typeFilter == "emily_cluster" {
		heartbeats, err := h.Store.ListActiveClusterHeartbeats(ctx, 5*time.Minute)
		if err != nil {
			http.Error(w, `{"error":"failed to list heartbeats"}`, http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(clusterListResponse{Clusters: toClusterViews(heartbeats)})
		return
	}

	agents, err := h.Store.ListAgents(ctx)
	if err != nil {
		http.Error(w, `{"error":"failed to list agents"}`, http.StatusInternalServerError)
		return
	}
	if typeFilter != "" {
		filtered := agents[:0]
		for _, a := range agents {
			if a.Type == typeFilter {
				filtered = append(filtered, a)
			}
		}
		agents = filtered
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(agentListResponse{Agents: toAgentViews(agents)})
}

func (h *AgentsHandler) getOne(w http.ResponseWriter, r *http.Request, id string) {
	ctx := r.Context()
	agents, err := h.Store.ListAgents(ctx)
	if err != nil {
		http.Error(w, `{"error":"store error"}`, http.StatusInternalServerError)
		return
	}
	for _, a := range agents {
		if a.ID == id || a.Name == id {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(toAgentView(a))
			return
		}
	}
	http.Error(w, `{"error":"agent not found"}`, http.StatusNotFound)
}

// heartbeat handles POST /api/v1/agents/heartbeat.
// Request body: {"agent_id","cluster_id","capabilities":[],"load_score"}.
func (h *AgentsHandler) heartbeat(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var req struct {
		AgentID      string   `json:"agent_id"`
		ClusterID    string   `json:"cluster_id"`
		Capabilities []string `json:"capabilities"`
		LoadScore    float64  `json:"load_score"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"bad request body"}`, http.StatusBadRequest)
		return
	}
	if req.AgentID == "" || req.ClusterID == "" {
		http.Error(w, `{"error":"agent_id and cluster_id are required"}`, http.StatusBadRequest)
		return
	}
	hb := auth.ClusterHeartbeat{
		AgentID:      req.AgentID,
		ClusterID:    req.ClusterID,
		Capabilities: req.Capabilities,
		LoadScore:    req.LoadScore,
		LastSeen:     time.Now().UTC(),
	}
	if err := h.Store.UpsertClusterHeartbeat(ctx, hb); err != nil {
		http.Error(w, `{"error":"upsert failed"}`, http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"status": "ok", "last_seen": hb.LastSeen.Format(time.RFC3339)})
}

// ── view types ────────────────────────────────────────────────────────────────

type agentView struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Type        string   `json:"type"`
	Status      string   `json:"status"`
	Permissions []string `json:"permissions,omitempty"`
	CreatedAt   string   `json:"created_at"`
}

type agentListResponse struct {
	Agents []agentView `json:"agents"`
}

type clusterView struct {
	AgentID      string   `json:"agent_id"`
	ClusterID    string   `json:"cluster_id"`
	Capabilities []string `json:"capabilities"`
	LoadScore    float64  `json:"load_score"`
	LastSeen     string   `json:"last_seen"`
}

type clusterListResponse struct {
	Clusters []clusterView `json:"clusters"`
}

func toAgentView(a auth.Agent) agentView {
	return agentView{
		ID:          a.ID,
		Name:        a.Name,
		Type:        a.Type,
		Status:      a.Status,
		Permissions: a.Permissions,
		CreatedAt:   a.CreatedAt.UTC().Format("2006-01-02T15:04:05Z"),
	}
}

func toAgentViews(agents []auth.Agent) []agentView {
	out := make([]agentView, len(agents))
	for i, a := range agents {
		out[i] = toAgentView(a)
	}
	return out
}

func toClusterView(h auth.ClusterHeartbeat) clusterView {
	caps := h.Capabilities
	if caps == nil {
		caps = []string{}
	}
	return clusterView{
		AgentID:      h.AgentID,
		ClusterID:    h.ClusterID,
		Capabilities: caps,
		LoadScore:    h.LoadScore,
		LastSeen:     h.LastSeen.UTC().Format(time.RFC3339),
	}
}

func toClusterViews(hbs []auth.ClusterHeartbeat) []clusterView {
	out := make([]clusterView, len(hbs))
	for i, h := range hbs {
		out[i] = toClusterView(h)
	}
	return out
}
