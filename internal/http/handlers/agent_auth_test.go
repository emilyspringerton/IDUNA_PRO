package handlers_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"idunapro/internal/auth"
	"idunapro/internal/auth/jwt"
	"idunapro/internal/http/handlers"
	"idunapro/internal/userlog"
)

// stubAgentStore implements the minimal subset of store.IAMStore needed by AgentAuthHandler.
type stubAgentStore struct {
	noopGFDTiers
	noopMonitors
	agents map[string]*auth.Agent // name → agent
	errMsg string                 // non-empty → return this error from AuthenticateAgent
}

func (s *stubAgentStore) AuthenticateAgent(_ context.Context, name, _ string) (*auth.Agent, error) {
	if s.errMsg != "" {
		return nil, errors.New(s.errMsg)
	}
	a, ok := s.agents[name]
	if !ok {
		return nil, errors.New("agent not found")
	}
	return a, nil
}

// Unused methods — satisfy the interface with no-ops.
func (s *stubAgentStore) GetOrCreateUserByGoogleSubject(context.Context, string, string) (*auth.User, bool, error) {
	return nil, false, nil
}
func (s *stubAgentStore) GetUserByID(context.Context, string) (*auth.User, error)     { return nil, nil }
func (s *stubAgentStore) GetEffectivePermissions(context.Context, string) ([]string, error) {
	return nil, nil
}
func (s *stubAgentStore) AppendIAMEvent(context.Context, string, string, string, string, []byte) error {
	return nil
}
func (s *stubAgentStore) UpdateUserStatus(context.Context, string, string, string) error { return nil }
func (s *stubAgentStore) ListUsers(context.Context, int) ([]auth.User, error) { return nil, nil }
func (s *stubAgentStore) AssignRole(context.Context, string, string, string) error       { return nil }
func (s *stubAgentStore) RevokeRole(context.Context, string, string, string) error       { return nil }
func (s *stubAgentStore) ListRoles(context.Context) ([]auth.Role, error)                  { return nil, nil }
func (s *stubAgentStore) ListAgents(context.Context) ([]auth.Agent, error)                { return nil, nil }
func (s *stubAgentStore) CreateAgent(context.Context, string, string, string, string) (*auth.Agent, error) {
	return nil, nil
}
func (s *stubAgentStore) GrantAgentPermission(context.Context, string, string, string) error {
	return nil
}
func (s *stubAgentStore) RevokeAgentPermission(context.Context, string, string, string) error {
	return nil
}
func (s *stubAgentStore) AcceptHonorCode(context.Context, string, int, string, string, string) error {
	return nil
}
func (s *stubAgentStore) ClaimHandle(context.Context, string, string, string) error { return nil }
func (s *stubAgentStore) IsHandleAvailable(context.Context, string) (bool, error)   { return true, nil }
func (s *stubAgentStore) UpdateAgentStatus(context.Context, string, string, string) error { return nil }
func (s *stubAgentStore) ListIAMEvents(context.Context, int) ([]auth.IAMEvent, error)     { return nil, nil }
func (s *stubAgentStore) SetAgentCredential(context.Context, string, string, string) error {
	return nil
}
func (s *stubAgentStore) AppendApple(context.Context, auth.AppleRecord) (int64, error) {
	return 0, nil
}
func (s *stubAgentStore) ListApples(context.Context, string, string, string, int) ([]auth.AppleRecord, error) {
	return nil, nil
}
func (s *stubAgentStore) GetApple(context.Context, int64) (*auth.AppleRecord, error) {
	return nil, nil
}
func (s *stubAgentStore) PatchAppleMetadata(context.Context, int64, map[string]json.RawMessage) error {
	return nil
}
func (s *stubAgentStore) UpsertPushToken(context.Context, auth.PushToken) error { return nil }
func (s *stubAgentStore) GetPushToken(context.Context, string) (*auth.PushToken, error) {
	return nil, nil
}
func (s *stubAgentStore) CreateCameraObservation(context.Context, auth.CameraObservation) (int64, error) {
	return 0, nil
}
func (s *stubAgentStore) UpdateCameraObservation(context.Context, int64, string, int64, string) error {
	return nil
}
func (s *stubAgentStore) GetCameraObservation(context.Context, int64) (*auth.CameraObservation, error) {
	return nil, nil
}
func (s *stubAgentStore) ListCameraObservations(context.Context, string, string, int) ([]auth.CameraObservation, error) {
	return nil, nil
}
func (s *stubAgentStore) CreateSprintItem(context.Context, auth.SprintItem) (int64, error) { return 0, nil }
func (s *stubAgentStore) UpdateSprintItem(context.Context, int64, string, string, string, int64) error {
	return nil
}
func (s *stubAgentStore) GetSprintItem(context.Context, int64) (*auth.SprintItem, error) { return nil, nil }
func (s *stubAgentStore) ListSprintItems(context.Context, string, string, int) ([]auth.SprintItem, error) {
	return nil, nil
}
func (s *stubAgentStore) DailyTokenStats(context.Context, int) ([]auth.DailyTokenStat, error) {
	return nil, nil
}
func (s *stubAgentStore) GetUserSubscription(context.Context, string) (*auth.Subscription, error) {
	return nil, nil
}
func (s *stubAgentStore) UpsertUserSubscription(context.Context, auth.Subscription) error { return nil }
func (s *stubAgentStore) UpsertClusterHeartbeat(context.Context, auth.ClusterHeartbeat) error {
	return nil
}
func (s *stubAgentStore) ListActiveClusterHeartbeats(context.Context, time.Duration) ([]auth.ClusterHeartbeat, error) {
	return nil, nil
}
func (s *stubAgentStore) GetAgentByID(_ context.Context, agentID string) (*auth.Agent, error) {
	for _, a := range s.agents {
		if a.ID == agentID {
			return a, nil
		}
	}
	return nil, errors.New("agent not found")
}

func TestAgentAuthHandler_Success(t *testing.T) {
	k, err := jwt.GenerateKeys()
	if err != nil {
		t.Fatalf("generate keys: %v", err)
	}
	store := &stubAgentStore{agents: map[string]*auth.Agent{
		"EMILY": {ID: "agent-1", Name: "EMILY", Type: "LLM_AGENT", Status: "ACTIVE",
			Permissions: []string{"fatbaby.read", "fatbaby.operator"}},
	}}
	h := &handlers.AgentAuthHandler{Keys: k, Store: store, Issuer: "https://test.internal"}

	body, _ := json.Marshal(map[string]string{"agent_name": "EMILY", "agent_secret": "sk-emily"})
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest("POST", "/api/v1/auth/agent", bytes.NewReader(body)))

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body: %s", rr.Code, rr.Body.String())
	}
	var resp map[string]any
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("json decode: %v", err)
	}
	if resp["access_token"] == "" {
		t.Error("expected access_token in response")
	}
	if resp["token_type"] != "Bearer" {
		t.Errorf("token_type = %q, want Bearer", resp["token_type"])
	}
}

func TestAgentAuthHandler_BadCredentials(t *testing.T) {
	k, _ := jwt.GenerateKeys()
	store := &stubAgentStore{errMsg: "invalid agent secret"}
	h := &handlers.AgentAuthHandler{Keys: k, Store: store}

	body, _ := json.Marshal(map[string]string{"agent_name": "EMILY", "agent_secret": "wrong"})
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest("POST", "/api/v1/auth/agent", bytes.NewReader(body)))

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", rr.Code)
	}
	if !strings.Contains(rr.Body.String(), "AGENT_AUTH_FAILED") {
		t.Errorf("body missing AGENT_AUTH_FAILED: %s", rr.Body.String())
	}
}

func TestAgentAuthHandler_MissingFields(t *testing.T) {
	k, _ := jwt.GenerateKeys()
	store := &stubAgentStore{}
	h := &handlers.AgentAuthHandler{Keys: k, Store: store}

	body, _ := json.Marshal(map[string]string{"agent_name": "EMILY"}) // missing secret
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest("POST", "/api/v1/auth/agent", bytes.NewReader(body)))

	if rr.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", rr.Code)
	}
}

// TestAgentAuthHandler_EmitsEvents -- S226-02: real success/failure events actually land in the
// unified logging backend, and the failure event never carries the raw agent_secret.
func TestAgentAuthHandler_EmitsEvents(t *testing.T) {
	k, err := jwt.GenerateKeys()
	if err != nil {
		t.Fatalf("generate keys: %v", err)
	}
	store := &stubAgentStore{agents: map[string]*auth.Agent{
		"EMILY": {ID: "agent-1", Name: "EMILY", Type: "LLM_AGENT", Status: "ACTIVE",
			Permissions: []string{"fatbaby.read"}},
	}}
	eventLog, err := userlog.NewFileEventLog(t.TempDir())
	if err != nil {
		t.Fatalf("NewFileEventLog: %v", err)
	}
	t.Cleanup(func() { _ = eventLog.Close() })
	h := &handlers.AgentAuthHandler{Keys: k, Store: store, EventLog: eventLog}

	// A real success.
	body, _ := json.Marshal(map[string]string{"agent_name": "EMILY", "agent_secret": "sk-emily"})
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest("POST", "/api/v1/auth/agent", bytes.NewReader(body)))
	if rr.Code != http.StatusOK {
		t.Fatalf("success request: status = %d, want 200: %s", rr.Code, rr.Body.String())
	}

	// A real failure -- an unknown agent.
	body, _ = json.Marshal(map[string]string{"agent_name": "GHOST", "agent_secret": "top-secret-value"})
	rr = httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest("POST", "/api/v1/auth/agent", bytes.NewReader(body)))
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("failure request: status = %d, want 401", rr.Code)
	}

	recs, err := eventLog.ReadFrom(context.Background(), 0, 10)
	if err != nil {
		t.Fatalf("ReadFrom: %v", err)
	}
	if len(recs) != 2 {
		t.Fatalf("expected 2 events, got %d", len(recs))
	}
	if recs[0].Event.Type != "iduna:auth.agent.success" {
		t.Errorf("event 0 Type = %q, want iduna:auth.agent.success", recs[0].Event.Type)
	}
	if recs[1].Event.Type != "iduna:auth.agent.failure" {
		t.Errorf("event 1 Type = %q, want iduna:auth.agent.failure", recs[1].Event.Type)
	}
	if strings.Contains(string(recs[1].Event.Data), "top-secret-value") {
		t.Errorf("failure event must never contain the raw agent_secret, got: %s", recs[1].Event.Data)
	}
	if !strings.Contains(string(recs[1].Event.Data), "GHOST") {
		t.Errorf("failure event should record the attempted agent_name, got: %s", recs[1].Event.Data)
	}
}

func TestAgentAuthHandler_WrongMethod(t *testing.T) {
	k, _ := jwt.GenerateKeys()
	store := &stubAgentStore{}
	h := &handlers.AgentAuthHandler{Keys: k, Store: store}

	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest("GET", "/api/v1/auth/agent", nil))

	if rr.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404", rr.Code)
	}
}
