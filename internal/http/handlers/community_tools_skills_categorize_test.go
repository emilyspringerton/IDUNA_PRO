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
	"idunapro/internal/resume"
)

// Founder real-time, 2026-09-10, direct employer-scan feedback on the rendered resume: "Skills
// section is a dump -- it's alphabetical chaos... I think we need to build google vertex AI into
// it like we have for the DragonsNShit item builder so that vertex can auto organize the skills
// for us." These tests cover the real access-control gate and the real "nothing to categorize"
// no-op path -- the actual Vertex call itself needs a live, gcloud-authenticated network call
// (this sandbox has no active gcloud account) and is NOT exercised here; see
// community_tools_skills_categorize_internal_test.go for the real, network-free unit coverage of
// the response-parsing/normalization logic that call's result goes through.

func newTestSkillsCategorizeHandlers(t *testing.T, keys *jwt.Keys) (http.Handler, http.Handler, *sql.DB) {
	t.Helper()
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	t.Cleanup(func() { db.Close() })

	if _, err := db.Exec(`
		CREATE TABLE resumes (
			local_uid  INTEGER PRIMARY KEY,
			data       TEXT NOT NULL DEFAULT '{}',
			targets    TEXT NOT NULL DEFAULT '[]',
			created_at TEXT NOT NULL,
			updated_at TEXT NOT NULL
		);
	`); err != nil {
		t.Fatalf("create schema: %v", err)
	}

	crud := &handlers.CommunityToolsHandler{DB: db}
	categorize := &handlers.CommunityToolsSkillsCategorizeHandler{DB: db}
	crudProtected := middleware.RequireAuth(keys)(middleware.RequirePermission("community-tools.access")(crud))
	categorizeProtected := middleware.RequireAuth(keys)(middleware.RequirePermission("community-tools.access")(categorize))
	return crudProtected, categorizeProtected, db
}

func TestCommunityToolsSkillsCategorizeHandler_ForbiddenWithoutFlag(t *testing.T) {
	keys, _ := jwt.GenerateKeys()
	_, categorize, _ := newTestSkillsCategorizeHandlers(t, keys)
	token := communityToolsToken(t, keys, 1) // no community-tools.access permission

	req := httptest.NewRequest(http.MethodPost, "/api/v1/community-tools/resume/skills/categorize", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rr := httptest.NewRecorder()
	categorize.ServeHTTP(rr, req)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("expected 403 without community-tools.access, got %d: %s", rr.Code, rr.Body.String())
	}
}

func TestCommunityToolsSkillsCategorizeHandler_GetMethodNotAllowed(t *testing.T) {
	keys, _ := jwt.GenerateKeys()
	_, categorize, _ := newTestSkillsCategorizeHandlers(t, keys)
	token := communityToolsToken(t, keys, 1, "community-tools.access")

	req := httptest.NewRequest(http.MethodGet, "/api/v1/community-tools/resume/skills/categorize", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rr := httptest.NewRecorder()
	categorize.ServeHTTP(rr, req)
	if rr.Code != http.StatusNotFound {
		t.Fatalf("expected 404 for a non-POST method, got %d", rr.Code)
	}
}

func TestCommunityToolsSkillsCategorizeHandler_NoSkillsIsARealNoOp(t *testing.T) {
	keys, _ := jwt.GenerateKeys()
	_, categorize, _ := newTestSkillsCategorizeHandlers(t, keys)
	token := communityToolsToken(t, keys, 1, "community-tools.access")

	// No resume saved at all yet -- loadResume's own real "empty, valid starting document"
	// behavior means this must succeed as a genuine no-op, never attempt a Vertex call (which
	// would fail in this sandbox with no gcloud account) and never error.
	req := httptest.NewRequest(http.MethodPost, "/api/v1/community-tools/resume/skills/categorize", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rr := httptest.NewRecorder()
	categorize.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200 real no-op with zero skills, got %d: %s", rr.Code, rr.Body.String())
	}
	var skills []resume.Skill
	if err := json.Unmarshal(rr.Body.Bytes(), &skills); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(skills) != 0 {
		t.Fatalf("expected zero skills back, got %+v", skills)
	}
}

func TestCommunityToolsSkillsCategorizeHandler_AllSkillsAlreadyCategorizedIsARealNoOp(t *testing.T) {
	keys, _ := jwt.GenerateKeys()
	crud, categorize, _ := newTestSkillsCategorizeHandlers(t, keys)
	token := communityToolsToken(t, keys, 1, "community-tools.access")

	// Every skill already has a real Category -- re-running "Auto-organize with AI" must be a
	// genuine no-op (never overwrite a manual override, never attempt a Vertex call at all) since
	// there is nothing left uncategorized to send.
	body, _ := json.Marshal(resume.Resume{
		Skills: []resume.Skill{
			{Name: "Golang", Category: "Backend & APIs"},
			{Name: "React", Category: "Frontend"},
		},
	})
	putReq := httptest.NewRequest(http.MethodPut, "/api/v1/community-tools/resume", bytes.NewReader(body))
	putReq.Header.Set("Authorization", "Bearer "+token)
	putRR := httptest.NewRecorder()
	crud.ServeHTTP(putRR, putReq)
	if putRR.Code != http.StatusOK {
		t.Fatalf("PUT: expected 200, got %d: %s", putRR.Code, putRR.Body.String())
	}

	req := httptest.NewRequest(http.MethodPost, "/api/v1/community-tools/resume/skills/categorize", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rr := httptest.NewRecorder()
	categorize.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200 real no-op when every skill already has a category, got %d: %s", rr.Code, rr.Body.String())
	}
	var skills []resume.Skill
	if err := json.Unmarshal(rr.Body.Bytes(), &skills); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(skills) != 2 || skills[0].Category != "Backend & APIs" || skills[1].Category != "Frontend" {
		t.Fatalf("expected both pre-existing categories to survive untouched, got %+v", skills)
	}
}

func TestCommunityToolsSkillsCategorizeHandler_IsScopedToCallerOwnUID(t *testing.T) {
	keys, _ := jwt.GenerateKeys()
	crud, categorize, _ := newTestSkillsCategorizeHandlers(t, keys)
	tokenA := communityToolsToken(t, keys, 1, "community-tools.access")
	tokenB := communityToolsToken(t, keys, 2, "community-tools.access")

	body, _ := json.Marshal(resume.Resume{Skills: []resume.Skill{{Name: "Golang", Category: "Backend & APIs"}}})
	putReq := httptest.NewRequest(http.MethodPut, "/api/v1/community-tools/resume", bytes.NewReader(body))
	putReq.Header.Set("Authorization", "Bearer "+tokenA)
	putRR := httptest.NewRecorder()
	crud.ServeHTTP(putRR, putReq)
	if putRR.Code != http.StatusOK {
		t.Fatalf("PUT (user A): expected 200, got %d", putRR.Code)
	}

	// User B has no saved resume of their own -- must see zero skills, never user A's.
	req := httptest.NewRequest(http.MethodPost, "/api/v1/community-tools/resume/skills/categorize", nil)
	req.Header.Set("Authorization", "Bearer "+tokenB)
	rr := httptest.NewRecorder()
	categorize.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}
	var skills []resume.Skill
	if err := json.Unmarshal(rr.Body.Bytes(), &skills); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(skills) != 0 {
		t.Fatalf("expected user B to see zero skills (never user A's), got %+v", skills)
	}
}
