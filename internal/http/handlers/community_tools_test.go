package handlers_test

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	_ "modernc.org/sqlite"

	"idunapro/internal/auth/jwt"
	"idunapro/internal/http/handlers"
	"idunapro/internal/http/middleware"
	"idunapro/internal/resume"
)

// Founder real-time, 2026-09-09: "build it into carepyre... community tools... gated so that
// accounts need a feature flag set." These tests cover the real access-control gate
// (community-tools.access, itself driven by the per-account IsCommunityToolsEnabled flag) and
// the real resume CRUD + verify round trip, matching this monorepo's own established test
// pattern for a bearer-token-gated handler (mail_accounts_test.go's own newTestMailAccountsHandler
// shape).

func newTestCommunityToolsHandlers(t *testing.T, keys *jwt.Keys) (http.Handler, http.Handler, http.Handler, *sql.DB) {
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
	verify := &handlers.CommunityToolsVerifyHandler{DB: db}
	targets := &handlers.CommunityToolsTargetsHandler{DB: db}
	crudProtected := middleware.RequireAuth(keys)(middleware.RequirePermission("community-tools.access")(crud))
	verifyProtected := middleware.RequireAuth(keys)(middleware.RequirePermission("community-tools.access")(verify))
	targetsProtected := middleware.RequireAuth(keys)(middleware.RequirePermission("community-tools.access")(targets))
	return crudProtected, verifyProtected, targetsProtected, db
}

func communityToolsToken(t *testing.T, keys *jwt.Keys, localUID int, perms ...string) string {
	t.Helper()
	claims := map[string]any{
		"sub":       "local:" + strconv.Itoa(localUID),
		"local_uid": localUID,
		"exp":       time.Now().Add(time.Hour).Unix(),
	}
	if len(perms) > 0 {
		claims["permissions"] = perms
	}
	tok, err := jwt.Sign(keys, claims)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	return tok
}

func TestCommunityToolsHandler_ForbiddenWithoutFlag(t *testing.T) {
	keys, _ := jwt.GenerateKeys()
	crud, _, _, _ := newTestCommunityToolsHandlers(t, keys)
	// No "community-tools.access" permission -- the real, direct consequence of
	// IsCommunityToolsEnabled being false/unset on this account.
	token := communityToolsToken(t, keys, 1)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/community-tools/resume", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rr := httptest.NewRecorder()
	crud.ServeHTTP(rr, req)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("expected 403 without community-tools.access, got %d: %s", rr.Code, rr.Body.String())
	}
}

func TestCommunityToolsHandler_GetWithNoSavedResumeReturnsEmptyShell(t *testing.T) {
	keys, _ := jwt.GenerateKeys()
	crud, _, _, _ := newTestCommunityToolsHandlers(t, keys)
	token := communityToolsToken(t, keys, 1, "community-tools.access")

	req := httptest.NewRequest(http.MethodGet, "/api/v1/community-tools/resume", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rr := httptest.NewRecorder()
	crud.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200 for a real, valid empty starting state (not 404), got %d: %s", rr.Code, rr.Body.String())
	}
	var res resume.Resume
	if err := json.Unmarshal(rr.Body.Bytes(), &res); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if res.Basics.Name != "" {
		t.Errorf("expected a genuinely empty resume, got Basics.Name=%q", res.Basics.Name)
	}
}

func TestCommunityToolsHandler_PutThenGetRoundTrips(t *testing.T) {
	keys, _ := jwt.GenerateKeys()
	crud, _, _, _ := newTestCommunityToolsHandlers(t, keys)
	token := communityToolsToken(t, keys, 1, "community-tools.access")

	body, _ := json.Marshal(resume.Resume{
		Basics: resume.Basics{Name: "Jordan Rivera", Email: "jordan@example.com", Phone: "555-0100"},
	})
	putReq := httptest.NewRequest(http.MethodPut, "/api/v1/community-tools/resume", bytes.NewReader(body))
	putReq.Header.Set("Authorization", "Bearer "+token)
	putRR := httptest.NewRecorder()
	crud.ServeHTTP(putRR, putReq)
	if putRR.Code != http.StatusOK {
		t.Fatalf("PUT: expected 200, got %d: %s", putRR.Code, putRR.Body.String())
	}

	getReq := httptest.NewRequest(http.MethodGet, "/api/v1/community-tools/resume", nil)
	getReq.Header.Set("Authorization", "Bearer "+token)
	getRR := httptest.NewRecorder()
	crud.ServeHTTP(getRR, getReq)
	var res resume.Resume
	if err := json.Unmarshal(getRR.Body.Bytes(), &res); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if res.Basics.Name != "Jordan Rivera" || res.Basics.Email != "jordan@example.com" {
		t.Fatalf("expected the real saved resume to round-trip exactly, got: %+v", res.Basics)
	}
}

func TestCommunityToolsHandler_PutIsScopedToCallerOwnUID(t *testing.T) {
	keys, _ := jwt.GenerateKeys()
	crud, _, _, _ := newTestCommunityToolsHandlers(t, keys)
	tokenA := communityToolsToken(t, keys, 1, "community-tools.access")
	tokenB := communityToolsToken(t, keys, 2, "community-tools.access")

	bodyA, _ := json.Marshal(resume.Resume{Basics: resume.Basics{Name: "User A"}})
	reqA := httptest.NewRequest(http.MethodPut, "/api/v1/community-tools/resume", bytes.NewReader(bodyA))
	reqA.Header.Set("Authorization", "Bearer "+tokenA)
	crud.ServeHTTP(httptest.NewRecorder(), reqA)

	getReqB := httptest.NewRequest(http.MethodGet, "/api/v1/community-tools/resume", nil)
	getReqB.Header.Set("Authorization", "Bearer "+tokenB)
	rrB := httptest.NewRecorder()
	crud.ServeHTTP(rrB, getReqB)
	var resB resume.Resume
	if err := json.Unmarshal(rrB.Body.Bytes(), &resB); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resB.Basics.Name == "User A" {
		t.Fatal("a real, distinct user's own resume request must never see another user's saved data")
	}
}

func TestCommunityToolsVerifyHandler_RealRoundTrip(t *testing.T) {
	keys, _ := jwt.GenerateKeys()
	crud, verify, _, _ := newTestCommunityToolsHandlers(t, keys)
	token := communityToolsToken(t, keys, 1, "community-tools.access")

	// An incomplete resume (no phone, no work/education) should fail real verification.
	body, _ := json.Marshal(resume.Resume{Basics: resume.Basics{Name: "Jordan Rivera", Email: "jordan@example.com"}})
	putReq := httptest.NewRequest(http.MethodPut, "/api/v1/community-tools/resume", bytes.NewReader(body))
	putReq.Header.Set("Authorization", "Bearer "+token)
	crud.ServeHTTP(httptest.NewRecorder(), putReq)

	verifyReq := httptest.NewRequest(http.MethodPost, "/api/v1/community-tools/resume/verify", nil)
	verifyReq.Header.Set("Authorization", "Bearer "+token)
	rr := httptest.NewRecorder()
	verify.ServeHTTP(rr, verifyReq)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200 (verify itself succeeds even when the resume fails checks), got %d: %s", rr.Code, rr.Body.String())
	}
	var result resume.VerifyResult
	if err := json.Unmarshal(rr.Body.Bytes(), &result); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if result.Passed {
		t.Fatal("expected a real, incomplete resume (no phone, no work/education) to fail verification")
	}
}

// ---- Target (bespoke resume variant) tests -- founder real-time, 2026-09-09: "like we have a
// base set of things... history and skills etc we need some way to start building more bespoke
// resumes for specific opportunities." ----

func saveMasterResumeWithTwoJobs(t *testing.T, crud http.Handler, token string) resume.Resume {
	t.Helper()
	body, _ := json.Marshal(resume.Resume{
		Basics: resume.Basics{Name: "Jordan Rivera", Email: "jordan@example.com", Phone: "555-0100", Summary: "Master summary"},
		Work: []resume.Work{
			{Name: "Acme Corp", Position: "Line Cook", StartDate: "2022-03"},
			{Name: "Beta Diner", Position: "Server", StartDate: "2020-01", EndDate: "2022-01"},
		},
	})
	req := httptest.NewRequest(http.MethodPut, "/api/v1/community-tools/resume", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	rr := httptest.NewRecorder()
	crud.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("saving the master resume failed: %d %s", rr.Code, rr.Body.String())
	}
	var saved resume.Resume
	if err := json.Unmarshal(rr.Body.Bytes(), &saved); err != nil {
		t.Fatalf("decode: %v", err)
	}
	// Real, live-verified assumption every test below relies on: assignResumeIDs actually
	// assigned a real, non-empty ID to each work entry.
	if len(saved.Work) != 2 || saved.Work[0].ID == "" || saved.Work[1].ID == "" {
		t.Fatalf("expected both work entries to get real, non-empty server-assigned IDs, got: %+v", saved.Work)
	}
	return saved
}

func TestCommunityToolsTargetsHandler_ForbiddenWithoutFlag(t *testing.T) {
	keys, _ := jwt.GenerateKeys()
	_, _, targets, _ := newTestCommunityToolsHandlers(t, keys)
	token := communityToolsToken(t, keys, 1)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/community-tools/resume/targets", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rr := httptest.NewRecorder()
	targets.ServeHTTP(rr, req)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("expected 403 without community-tools.access, got %d: %s", rr.Code, rr.Body.String())
	}
}

func TestCommunityToolsTargetsHandler_ListWithNoneSavedReturnsEmptyList(t *testing.T) {
	keys, _ := jwt.GenerateKeys()
	_, _, targets, _ := newTestCommunityToolsHandlers(t, keys)
	token := communityToolsToken(t, keys, 1, "community-tools.access")

	req := httptest.NewRequest(http.MethodGet, "/api/v1/community-tools/resume/targets", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rr := httptest.NewRecorder()
	targets.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200 for a real, valid empty starting state, got %d: %s", rr.Code, rr.Body.String())
	}
	var got []resume.Target
	if err := json.Unmarshal(rr.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("expected zero targets with none saved, got: %+v", got)
	}
}

func TestCommunityToolsTargetsHandler_ReplaceAssignsIDsAndPersists(t *testing.T) {
	keys, _ := jwt.GenerateKeys()
	crud, _, targets, _ := newTestCommunityToolsHandlers(t, keys)
	token := communityToolsToken(t, keys, 1, "community-tools.access")
	master := saveMasterResumeWithTwoJobs(t, crud, token)

	body, _ := json.Marshal([]resume.Target{
		{Name: "Kitchen jobs", IncludedWorkIDs: []string{master.Work[0].ID}},
	})
	putReq := httptest.NewRequest(http.MethodPut, "/api/v1/community-tools/resume/targets", bytes.NewReader(body))
	putReq.Header.Set("Authorization", "Bearer "+token)
	putRR := httptest.NewRecorder()
	targets.ServeHTTP(putRR, putReq)
	if putRR.Code != http.StatusOK {
		t.Fatalf("PUT targets: expected 200, got %d: %s", putRR.Code, putRR.Body.String())
	}
	var saved []resume.Target
	if err := json.Unmarshal(putRR.Body.Bytes(), &saved); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(saved) != 1 || saved[0].ID == "" {
		t.Fatalf("expected the new target to get a real, server-assigned ID, got: %+v", saved)
	}

	getReq := httptest.NewRequest(http.MethodGet, "/api/v1/community-tools/resume/targets", nil)
	getReq.Header.Set("Authorization", "Bearer "+token)
	getRR := httptest.NewRecorder()
	targets.ServeHTTP(getRR, getReq)
	var listed []resume.Target
	if err := json.Unmarshal(getRR.Body.Bytes(), &listed); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(listed) != 1 || listed[0].Name != "Kitchen jobs" {
		t.Fatalf("expected the saved target to really persist and be listed back, got: %+v", listed)
	}
}

func TestCommunityToolsTargetsHandler_ResolvedReturnsOnlySelectedEntries(t *testing.T) {
	keys, _ := jwt.GenerateKeys()
	crud, _, targets, _ := newTestCommunityToolsHandlers(t, keys)
	token := communityToolsToken(t, keys, 1, "community-tools.access")
	master := saveMasterResumeWithTwoJobs(t, crud, token)

	body, _ := json.Marshal([]resume.Target{
		{Name: "Kitchen jobs", IncludedWorkIDs: []string{master.Work[0].ID}},
	})
	putReq := httptest.NewRequest(http.MethodPut, "/api/v1/community-tools/resume/targets", bytes.NewReader(body))
	putReq.Header.Set("Authorization", "Bearer "+token)
	putRR := httptest.NewRecorder()
	targets.ServeHTTP(putRR, putReq)
	var saved []resume.Target
	json.Unmarshal(putRR.Body.Bytes(), &saved)
	targetID := saved[0].ID

	resolvedReq := httptest.NewRequest(http.MethodGet, "/api/v1/community-tools/resume/targets/"+targetID+"/resolved", nil)
	resolvedReq.Header.Set("Authorization", "Bearer "+token)
	resolvedRR := httptest.NewRecorder()
	targets.ServeHTTP(resolvedRR, resolvedReq)
	if resolvedRR.Code != http.StatusOK {
		t.Fatalf("GET resolved: expected 200, got %d: %s", resolvedRR.Code, resolvedRR.Body.String())
	}
	var resolved resume.Resume
	if err := json.Unmarshal(resolvedRR.Body.Bytes(), &resolved); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(resolved.Work) != 1 || resolved.Work[0].Name != "Acme Corp" {
		t.Fatalf("expected the resolved view to show only the real, included Acme Corp entry, got: %+v", resolved.Work)
	}
	if resolved.Basics.Name != "Jordan Rivera" {
		t.Errorf("Basics should pass through unfiltered in the resolved view, got %q", resolved.Basics.Name)
	}
}

func TestCommunityToolsTargetsHandler_ResolvedUnknownIDReturns404(t *testing.T) {
	keys, _ := jwt.GenerateKeys()
	_, _, targets, _ := newTestCommunityToolsHandlers(t, keys)
	token := communityToolsToken(t, keys, 1, "community-tools.access")

	req := httptest.NewRequest(http.MethodGet, "/api/v1/community-tools/resume/targets/does-not-exist/resolved", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rr := httptest.NewRecorder()
	targets.ServeHTTP(rr, req)
	if rr.Code != http.StatusNotFound {
		t.Fatalf("expected 404 for an unknown target ID, got %d: %s", rr.Code, rr.Body.String())
	}
}

func TestCommunityToolsTargetsHandler_VerifyRunsAgainstResolvedNotMaster(t *testing.T) {
	keys, _ := jwt.GenerateKeys()
	crud, _, targets, _ := newTestCommunityToolsHandlers(t, keys)
	token := communityToolsToken(t, keys, 1, "community-tools.access")
	// The master resume passes verification for real (both work entries present, all
	// required fields filled) -- saveMasterResumeWithTwoJobs already establishes that.
	_ = saveMasterResumeWithTwoJobs(t, crud, token)

	// A real target that includes NEITHER work entry -- it should FAIL verification
	// (has-work-or-education) even though the real master resume itself passes.
	body, _ := json.Marshal([]resume.Target{{Name: "Empty target"}})
	putReq := httptest.NewRequest(http.MethodPut, "/api/v1/community-tools/resume/targets", bytes.NewReader(body))
	putReq.Header.Set("Authorization", "Bearer "+token)
	putRR := httptest.NewRecorder()
	targets.ServeHTTP(putRR, putReq)
	var saved []resume.Target
	json.Unmarshal(putRR.Body.Bytes(), &saved)
	targetID := saved[0].ID

	verifyReq := httptest.NewRequest(http.MethodPost, "/api/v1/community-tools/resume/targets/"+targetID+"/verify", nil)
	verifyReq.Header.Set("Authorization", "Bearer "+token)
	verifyRR := httptest.NewRecorder()
	targets.ServeHTTP(verifyRR, verifyReq)
	if verifyRR.Code != http.StatusOK {
		t.Fatalf("POST verify: expected 200, got %d: %s", verifyRR.Code, verifyRR.Body.String())
	}
	var result resume.VerifyResult
	if err := json.Unmarshal(verifyRR.Body.Bytes(), &result); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if result.Passed {
		t.Fatal("expected a target with zero real work/education entries selected to fail verification, " +
			"proving verify runs against the real RESOLVED view, not the (passing) master resume")
	}
}

func TestCommunityToolsTargetsHandler_TargetsAreScopedToCallerOwnUID(t *testing.T) {
	keys, _ := jwt.GenerateKeys()
	_, _, targets, _ := newTestCommunityToolsHandlers(t, keys)
	tokenA := communityToolsToken(t, keys, 1, "community-tools.access")
	tokenB := communityToolsToken(t, keys, 2, "community-tools.access")

	bodyA, _ := json.Marshal([]resume.Target{{Name: "User A's target"}})
	putReqA := httptest.NewRequest(http.MethodPut, "/api/v1/community-tools/resume/targets", bytes.NewReader(bodyA))
	putReqA.Header.Set("Authorization", "Bearer "+tokenA)
	targets.ServeHTTP(httptest.NewRecorder(), putReqA)

	getReqB := httptest.NewRequest(http.MethodGet, "/api/v1/community-tools/resume/targets", nil)
	getReqB.Header.Set("Authorization", "Bearer "+tokenB)
	rrB := httptest.NewRecorder()
	targets.ServeHTTP(rrB, getReqB)
	var listedB []resume.Target
	if err := json.Unmarshal(rrB.Body.Bytes(), &listedB); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(listedB) != 0 {
		t.Fatalf("a real, distinct user's own target list must never see another user's saved targets, got: %+v", listedB)
	}
}
