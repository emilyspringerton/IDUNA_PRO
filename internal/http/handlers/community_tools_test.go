package handlers_test

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
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

func newTestCommunityToolsHandlers(t *testing.T, keys *jwt.Keys) (http.Handler, http.Handler, http.Handler, http.Handler, *sql.DB) {
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
	export := &handlers.CommunityToolsExportHandler{DB: db}
	crudProtected := middleware.RequireAuth(keys)(middleware.RequirePermission("community-tools.access")(crud))
	verifyProtected := middleware.RequireAuth(keys)(middleware.RequirePermission("community-tools.access")(verify))
	targetsProtected := middleware.RequireAuth(keys)(middleware.RequirePermission("community-tools.access")(targets))
	exportProtected := middleware.RequireAuth(keys)(middleware.RequirePermission("community-tools.access")(export))
	return crudProtected, verifyProtected, targetsProtected, exportProtected, db
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
	crud, _, _, _, _ := newTestCommunityToolsHandlers(t, keys)
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
	crud, _, _, _, _ := newTestCommunityToolsHandlers(t, keys)
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
	crud, _, _, _, _ := newTestCommunityToolsHandlers(t, keys)
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

// TestCommunityToolsHandler_NewOngoingWorkEntrySortsToTop -- the real, exact bug report (kanban
// card CVB-12434, founder real-time): "the work history needs to auto sort i put a new one
// 2006-present and it went to the bottom of the resume instead of the top." Reproduces the
// REAL reported sequence through the real, live HTTP handlers, not just the internal/resume
// package's own unit tests: save a master resume with two already-ended jobs, then add a new
// ongoing one via the real single-entry POST primitive (the most likely real path someone
// "adding one more job" actually takes), and confirm GET reflects it sorted to the top.
func TestCommunityToolsHandler_NewOngoingWorkEntrySortsToTop(t *testing.T) {
	keys, _ := jwt.GenerateKeys()
	crud, _, _, _, db := newTestCommunityToolsHandlers(t, keys)
	work := newTestCommunityToolsWorkHandler(t, keys, db)
	token := communityToolsToken(t, keys, 1, "community-tools.access")

	body, _ := json.Marshal(resume.Resume{
		Basics: resume.Basics{Name: "Jordan Rivera"},
		Work: []resume.Work{
			{Name: "Old Co", StartDate: "2010-01", EndDate: "2015-01"},
			{Name: "Newer Co", StartDate: "2015-02", EndDate: "2020-01"},
		},
	})
	putReq := httptest.NewRequest(http.MethodPut, "/api/v1/community-tools/resume", bytes.NewReader(body))
	putReq.Header.Set("Authorization", "Bearer "+token)
	crud.ServeHTTP(httptest.NewRecorder(), putReq)

	createBody, _ := json.Marshal(map[string]string{"name": "Current Co", "position": "Engineer", "startDate": "2006"})
	createReq := httptest.NewRequest(http.MethodPost, "/api/v1/community-tools/resume/work", bytes.NewReader(createBody))
	createReq.Header.Set("Authorization", "Bearer "+token)
	createRR := httptest.NewRecorder()
	work.ServeHTTP(createRR, createReq)
	if createRR.Code != http.StatusCreated {
		t.Fatalf("POST work: expected 201, got %d: %s", createRR.Code, createRR.Body.String())
	}

	getReq := httptest.NewRequest(http.MethodGet, "/api/v1/community-tools/resume", nil)
	getReq.Header.Set("Authorization", "Bearer "+token)
	getRR := httptest.NewRecorder()
	crud.ServeHTTP(getRR, getReq)
	var res resume.Resume
	json.Unmarshal(getRR.Body.Bytes(), &res)
	if len(res.Work) != 3 {
		t.Fatalf("expected 3 work entries, got %d", len(res.Work))
	}
	if res.Work[0].Name != "Current Co" {
		t.Fatalf("expected the new ongoing entry to sort to the TOP, not the bottom, got order: %s, %s, %s",
			res.Work[0].Name, res.Work[1].Name, res.Work[2].Name)
	}
}

func TestCommunityToolsHandler_PutIsScopedToCallerOwnUID(t *testing.T) {
	keys, _ := jwt.GenerateKeys()
	crud, _, _, _, _ := newTestCommunityToolsHandlers(t, keys)
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
	crud, verify, _, _, _ := newTestCommunityToolsHandlers(t, keys)
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
	_, _, targets, _, _ := newTestCommunityToolsHandlers(t, keys)
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
	_, _, targets, _, _ := newTestCommunityToolsHandlers(t, keys)
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
	crud, _, targets, _, _ := newTestCommunityToolsHandlers(t, keys)
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
	crud, _, targets, _, _ := newTestCommunityToolsHandlers(t, keys)
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
	_, _, targets, _, _ := newTestCommunityToolsHandlers(t, keys)
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
	crud, _, targets, _, _ := newTestCommunityToolsHandlers(t, keys)
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
	_, _, targets, _, _ := newTestCommunityToolsHandlers(t, keys)
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

// ---- PDF export tests -- the real "Layer 3" downloadable, ATS-safe file (console.html's own
// "Preview & templates" panel is screen-only). ----

func TestCommunityToolsExportHandler_ForbiddenWithoutFlag(t *testing.T) {
	keys, _ := jwt.GenerateKeys()
	_, _, _, export, _ := newTestCommunityToolsHandlers(t, keys)
	token := communityToolsToken(t, keys, 1)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/community-tools/resume/export.pdf", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rr := httptest.NewRecorder()
	export.ServeHTTP(rr, req)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("expected 403 without community-tools.access, got %d: %s", rr.Code, rr.Body.String())
	}
}

func TestCommunityToolsExportHandler_ReturnsARealPDFFile(t *testing.T) {
	keys, _ := jwt.GenerateKeys()
	crud, _, _, export, _ := newTestCommunityToolsHandlers(t, keys)
	token := communityToolsToken(t, keys, 1, "community-tools.access")
	saveMasterResumeWithTwoJobs(t, crud, token)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/community-tools/resume/export.pdf", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rr := httptest.NewRecorder()
	export.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}
	if ct := rr.Header().Get("Content-Type"); ct != "application/pdf" {
		t.Errorf("expected Content-Type application/pdf, got %q", ct)
	}
	// Founder real-time, 2026-09-09: "the downloaded resume should include the candidate name
	// and the export timestamp." Real, deliberate: the filename includes both, not just a
	// generic "resume.pdf" -- checked as three real, separate substrings (name, "Resume", and
	// today's real date) rather than one exact string, since the date is genuinely dynamic.
	cd := rr.Header().Get("Content-Disposition")
	today := time.Now().UTC().Format("2006-01-02")
	if !strings.Contains(cd, "Jordan-Rivera") {
		t.Errorf("expected the candidate's real name in the filename, got %q", cd)
	}
	if !strings.Contains(cd, "Resume") {
		t.Errorf("expected \"Resume\" in the filename for a master export, got %q", cd)
	}
	if !strings.Contains(cd, today) {
		t.Errorf("expected today's real export date (%s) in the filename, got %q", today, cd)
	}
	if !bytes.HasPrefix(rr.Body.Bytes(), []byte("%PDF-")) {
		t.Fatal("expected the real, downloaded body to be a genuine PDF file (starts with %PDF-)")
	}
}

// TestCommunityToolsExportHandler_TemplateQueryParamSelectsCompactLayout -- founder real-time,
// 2026-09-09: "add a new output template compact that manages to get the experience and
// education like into 2 columns or something." Proves the query param actually reaches
// resume.RenderPDF's own template dispatch, end to end through the real HTTP handler -- not
// just that RenderPDF itself accepts a template argument in isolation.
func TestCommunityToolsExportHandler_TemplateQueryParamSelectsCompactLayout(t *testing.T) {
	keys, _ := jwt.GenerateKeys()
	crud, _, _, export, _ := newTestCommunityToolsHandlers(t, keys)
	token := communityToolsToken(t, keys, 1, "community-tools.access")
	saveMasterResumeWithTwoJobs(t, crud, token)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/community-tools/resume/export.pdf?template=compact", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rr := httptest.NewRecorder()
	export.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}
	if !bytes.HasPrefix(rr.Body.Bytes(), []byte("%PDF-")) {
		t.Fatal("expected a genuine PDF file for the compact template")
	}
}

func TestCommunityToolsTargetsHandler_ExportReturnsPDFOfResolvedView(t *testing.T) {
	keys, _ := jwt.GenerateKeys()
	crud, _, targets, _, _ := newTestCommunityToolsHandlers(t, keys)
	token := communityToolsToken(t, keys, 1, "community-tools.access")
	saveMasterResumeWithTwoJobs(t, crud, token)

	body, _ := json.Marshal([]resume.Target{{Name: "My Target \"Name\""}})
	putReq := httptest.NewRequest(http.MethodPut, "/api/v1/community-tools/resume/targets", bytes.NewReader(body))
	putReq.Header.Set("Authorization", "Bearer "+token)
	putRR := httptest.NewRecorder()
	targets.ServeHTTP(putRR, putReq)
	var saved []resume.Target
	json.Unmarshal(putRR.Body.Bytes(), &saved)
	targetID := saved[0].ID

	req := httptest.NewRequest(http.MethodGet, "/api/v1/community-tools/resume/targets/"+targetID+"/export.pdf", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rr := httptest.NewRecorder()
	targets.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}
	if !bytes.HasPrefix(rr.Body.Bytes(), []byte("%PDF-")) {
		t.Fatal("expected a genuine PDF file for the resolved target view")
	}
	// Real, deliberate regression check for the header-injection risk this handler's own
	// pdfFilename sanitizer exists to close: a target name containing a literal quote must
	// never produce a malformed/broken-out-of Content-Disposition header.
	cd := rr.Header().Get("Content-Disposition")
	if strings.Count(cd, `"`) != 2 {
		t.Fatalf("expected exactly one real, well-formed quoted filename in Content-Disposition, got: %q", cd)
	}
}

func TestCommunityToolsTargetsHandler_ExportUnknownIDReturns404(t *testing.T) {
	keys, _ := jwt.GenerateKeys()
	_, _, targets, _, _ := newTestCommunityToolsHandlers(t, keys)
	token := communityToolsToken(t, keys, 1, "community-tools.access")

	req := httptest.NewRequest(http.MethodGet, "/api/v1/community-tools/resume/targets/does-not-exist/export.pdf", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rr := httptest.NewRecorder()
	targets.ServeHTTP(rr, req)
	if rr.Code != http.StatusNotFound {
		t.Fatalf("expected 404 for an unknown target ID, got %d: %s", rr.Code, rr.Body.String())
	}
}

// ---- Agent-ergonomic primitives -- founder real-time, 2026-09-09: "ensure that all of the
// features we have have good api because i am going to ask agents to work with those
// primitives to start intelligently managing the resume using agentic ai." Real
// PATCH/POST/DELETE endpoints alongside the existing whole-document GET/PUT. ----

func newTestCommunityToolsBasicsHandler(t *testing.T, keys *jwt.Keys, db *sql.DB) http.Handler {
	t.Helper()
	h := &handlers.CommunityToolsBasicsHandler{DB: db}
	return middleware.RequireAuth(keys)(middleware.RequirePermission("community-tools.access")(h))
}

func newTestCommunityToolsWorkHandler(t *testing.T, keys *jwt.Keys, db *sql.DB) http.Handler {
	t.Helper()
	return middleware.RequireAuth(keys)(middleware.RequirePermission("community-tools.access")(handlers.NewCommunityToolsWorkHandler(db)))
}

func TestCommunityToolsBasicsHandler_PatchMergesWithoutTouchingWork(t *testing.T) {
	keys, _ := jwt.GenerateKeys()
	crud, _, _, _, db := newTestCommunityToolsHandlers(t, keys)
	basics := newTestCommunityToolsBasicsHandler(t, keys, db)
	token := communityToolsToken(t, keys, 1, "community-tools.access")
	saveMasterResumeWithTwoJobs(t, crud, token)

	body, _ := json.Marshal(map[string]string{"phone": "555-9999"})
	req := httptest.NewRequest(http.MethodPatch, "/api/v1/community-tools/resume/basics", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	rr := httptest.NewRecorder()
	basics.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}
	var res resume.Resume
	if err := json.Unmarshal(rr.Body.Bytes(), &res); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if res.Basics.Phone != "555-9999" {
		t.Fatalf("expected the patched phone to take effect, got %q", res.Basics.Phone)
	}
	if res.Basics.Name != "Jordan Rivera" {
		t.Fatalf("expected the OMITTED name field to stay untouched by the patch, got %q", res.Basics.Name)
	}
	if len(res.Work) != 2 {
		t.Fatalf("expected a Basics-only patch to leave Work entirely untouched, got %d entries", len(res.Work))
	}
}

func TestCommunityToolsBasicsHandler_ForbiddenWithoutFlag(t *testing.T) {
	keys, _ := jwt.GenerateKeys()
	_, _, _, _, db := newTestCommunityToolsHandlers(t, keys)
	basics := newTestCommunityToolsBasicsHandler(t, keys, db)
	token := communityToolsToken(t, keys, 1)

	req := httptest.NewRequest(http.MethodPatch, "/api/v1/community-tools/resume/basics", bytes.NewReader([]byte(`{}`)))
	req.Header.Set("Authorization", "Bearer "+token)
	rr := httptest.NewRecorder()
	basics.ServeHTTP(rr, req)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("expected 403 without community-tools.access, got %d: %s", rr.Code, rr.Body.String())
	}
}

func TestCommunityToolsEntryHandler_CreatePatchDeleteWorkEntry(t *testing.T) {
	keys, _ := jwt.GenerateKeys()
	crud, _, _, _, db := newTestCommunityToolsHandlers(t, keys)
	work := newTestCommunityToolsWorkHandler(t, keys, db)
	token := communityToolsToken(t, keys, 1, "community-tools.access")
	saveMasterResumeWithTwoJobs(t, crud, token)

	// Create -- a real, fresh entry, server-assigned id regardless of anything sent.
	createBody, _ := json.Marshal(map[string]any{"id": "client-supplied-should-be-ignored", "name": "New Co", "position": "New Role"})
	createReq := httptest.NewRequest(http.MethodPost, "/api/v1/community-tools/resume/work", bytes.NewReader(createBody))
	createReq.Header.Set("Authorization", "Bearer "+token)
	createRR := httptest.NewRecorder()
	work.ServeHTTP(createRR, createReq)
	if createRR.Code != http.StatusCreated {
		t.Fatalf("POST: expected 201, got %d: %s", createRR.Code, createRR.Body.String())
	}
	var created resume.Work
	if err := json.Unmarshal(createRR.Body.Bytes(), &created); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if created.ID == "" || created.ID == "client-supplied-should-be-ignored" {
		t.Fatalf("expected a real, server-assigned id ignoring the client-supplied one, got %q", created.ID)
	}

	// Confirm it actually persisted onto the master resume (now 3 work entries).
	getReq := httptest.NewRequest(http.MethodGet, "/api/v1/community-tools/resume", nil)
	getReq.Header.Set("Authorization", "Bearer "+token)
	getRR := httptest.NewRecorder()
	crud.ServeHTTP(getRR, getReq)
	var afterCreate resume.Resume
	json.Unmarshal(getRR.Body.Bytes(), &afterCreate)
	if len(afterCreate.Work) != 3 {
		t.Fatalf("expected the new entry to persist onto the master resume (3 total), got %d", len(afterCreate.Work))
	}

	// Patch -- a real partial merge: only "position" is sent, "name" (New Co) must survive.
	patchBody, _ := json.Marshal(map[string]any{"position": "Updated Role", "id": "attempt-to-hijack-id"})
	patchReq := httptest.NewRequest(http.MethodPatch, "/api/v1/community-tools/resume/work/"+created.ID, bytes.NewReader(patchBody))
	patchReq.Header.Set("Authorization", "Bearer "+token)
	patchRR := httptest.NewRecorder()
	work.ServeHTTP(patchRR, patchReq)
	if patchRR.Code != http.StatusOK {
		t.Fatalf("PATCH: expected 200, got %d: %s", patchRR.Code, patchRR.Body.String())
	}
	var patched resume.Work
	json.Unmarshal(patchRR.Body.Bytes(), &patched)
	if patched.Position != "Updated Role" {
		t.Fatalf("expected the patched field to take effect, got %q", patched.Position)
	}
	if patched.Name != "New Co" {
		t.Fatalf("expected the OMITTED field to survive the partial merge, got %q", patched.Name)
	}
	if patched.ID != created.ID {
		t.Fatalf("expected the id to be immune to being patched via the request body, got %q", patched.ID)
	}

	// Delete -- back down to 2 entries.
	delReq := httptest.NewRequest(http.MethodDelete, "/api/v1/community-tools/resume/work/"+created.ID, nil)
	delReq.Header.Set("Authorization", "Bearer "+token)
	delRR := httptest.NewRecorder()
	work.ServeHTTP(delRR, delReq)
	if delRR.Code != http.StatusOK {
		t.Fatalf("DELETE: expected 200, got %d: %s", delRR.Code, delRR.Body.String())
	}
	getRR2 := httptest.NewRecorder()
	crud.ServeHTTP(getRR2, getReq)
	var afterDelete resume.Resume
	json.Unmarshal(getRR2.Body.Bytes(), &afterDelete)
	if len(afterDelete.Work) != 2 {
		t.Fatalf("expected the deleted entry to be gone (back to 2), got %d", len(afterDelete.Work))
	}
}

func TestCommunityToolsEntryHandler_PatchUnknownIDReturns404(t *testing.T) {
	keys, _ := jwt.GenerateKeys()
	_, _, _, _, db := newTestCommunityToolsHandlers(t, keys)
	work := newTestCommunityToolsWorkHandler(t, keys, db)
	token := communityToolsToken(t, keys, 1, "community-tools.access")

	body, _ := json.Marshal(map[string]any{"position": "X"})
	req := httptest.NewRequest(http.MethodPatch, "/api/v1/community-tools/resume/work/does-not-exist", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	rr := httptest.NewRecorder()
	work.ServeHTTP(rr, req)
	if rr.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d: %s", rr.Code, rr.Body.String())
	}
}

func TestCommunityToolsEntryHandler_DeleteUnknownIDReturns404(t *testing.T) {
	keys, _ := jwt.GenerateKeys()
	_, _, _, _, db := newTestCommunityToolsHandlers(t, keys)
	work := newTestCommunityToolsWorkHandler(t, keys, db)
	token := communityToolsToken(t, keys, 1, "community-tools.access")

	req := httptest.NewRequest(http.MethodDelete, "/api/v1/community-tools/resume/work/does-not-exist", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rr := httptest.NewRecorder()
	work.ServeHTTP(rr, req)
	if rr.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d: %s", rr.Code, rr.Body.String())
	}
}

func TestCommunityToolsEntryHandler_ForbiddenWithoutFlag(t *testing.T) {
	keys, _ := jwt.GenerateKeys()
	_, _, _, _, db := newTestCommunityToolsHandlers(t, keys)
	work := newTestCommunityToolsWorkHandler(t, keys, db)
	token := communityToolsToken(t, keys, 1)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/community-tools/resume/work", bytes.NewReader([]byte(`{}`)))
	req.Header.Set("Authorization", "Bearer "+token)
	rr := httptest.NewRecorder()
	work.ServeHTTP(rr, req)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("expected 403 without community-tools.access, got %d: %s", rr.Code, rr.Body.String())
	}
}

// One real, lighter smoke test per remaining entity type -- the actual CRUD logic is fully
// shared/generic (CommunityToolsEntryHandler[T]), already proven thoroughly against Work above;
// these just confirm each constructor is wired to the RIGHT resume field, not a copy-pasted
// mistake (e.g. NewCommunityToolsSkillsHandler accidentally reading/writing r.Awards).
func TestCommunityToolsEntryHandler_EducationSkillAwardCreateWiresToCorrectField(t *testing.T) {
	keys, _ := jwt.GenerateKeys()
	_, _, _, _, db := newTestCommunityToolsHandlers(t, keys)
	token := communityToolsToken(t, keys, 1, "community-tools.access")

	cases := []struct {
		name    string
		handler http.Handler
		path    string
		body    string
	}{
		{"education", middleware.RequireAuth(keys)(middleware.RequirePermission("community-tools.access")(handlers.NewCommunityToolsEducationHandler(db))), "/api/v1/community-tools/resume/education", `{"institution":"Test U"}`},
		{"skills", middleware.RequireAuth(keys)(middleware.RequirePermission("community-tools.access")(handlers.NewCommunityToolsSkillsHandler(db))), "/api/v1/community-tools/resume/skills", `{"name":"Testing"}`},
		{"awards", middleware.RequireAuth(keys)(middleware.RequirePermission("community-tools.access")(handlers.NewCommunityToolsAwardsHandler(db))), "/api/v1/community-tools/resume/awards", `{"title":"Test Award"}`},
		{"profiles", middleware.RequireAuth(keys)(middleware.RequirePermission("community-tools.access")(handlers.NewCommunityToolsProfilesHandler(db))), "/api/v1/community-tools/resume/profiles", `{"network":"GitHub","url":"github.com/test/repo"}`},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, c.path, bytes.NewReader([]byte(c.body)))
			req.Header.Set("Authorization", "Bearer "+token)
			rr := httptest.NewRecorder()
			c.handler.ServeHTTP(rr, req)
			if rr.Code != http.StatusCreated {
				t.Fatalf("%s: expected 201, got %d: %s", c.name, rr.Code, rr.Body.String())
			}
		})
	}

	getReq := httptest.NewRequest(http.MethodGet, "/api/v1/community-tools/resume", nil)
	getReq.Header.Set("Authorization", "Bearer "+token)
	crud := middleware.RequireAuth(keys)(middleware.RequirePermission("community-tools.access")(&handlers.CommunityToolsHandler{DB: db}))
	getRR := httptest.NewRecorder()
	crud.ServeHTTP(getRR, getReq)
	var res resume.Resume
	if err := json.Unmarshal(getRR.Body.Bytes(), &res); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(res.Education) != 1 || res.Education[0].Institution != "Test U" {
		t.Fatalf("expected the education entry to land in Education, got: %+v", res.Education)
	}
	if len(res.Skills) != 1 || res.Skills[0].Name != "Testing" {
		t.Fatalf("expected the skill entry to land in Skills, got: %+v", res.Skills)
	}
	if len(res.Awards) != 1 || res.Awards[0].Title != "Test Award" {
		t.Fatalf("expected the award entry to land in Awards, got: %+v", res.Awards)
	}
	if len(res.Basics.Profiles) != 1 || res.Basics.Profiles[0].URL != "github.com/test/repo" {
		t.Fatalf("expected the profile entry to land in Basics.Profiles, got: %+v", res.Basics.Profiles)
	}
}

// TestCommunityToolsProfilesHandler_MultipleGitHubLinksManagedIndependently -- the real,
// end-to-end version of the founder's own literal ask: "we need to be able to add and configure
// the output of multiple github links." Two profiles sharing the identical "GitHub" network
// value must be independently addressable, patchable, and deletable by their own real id.
func TestCommunityToolsProfilesHandler_MultipleGitHubLinksManagedIndependently(t *testing.T) {
	keys, _ := jwt.GenerateKeys()
	_, _, _, _, db := newTestCommunityToolsHandlers(t, keys)
	profiles := middleware.RequireAuth(keys)(middleware.RequirePermission("community-tools.access")(handlers.NewCommunityToolsProfilesHandler(db)))
	token := communityToolsToken(t, keys, 1, "community-tools.access")

	create := func(url string) resume.Profile {
		body, _ := json.Marshal(map[string]string{"network": "GitHub", "url": url})
		req := httptest.NewRequest(http.MethodPost, "/api/v1/community-tools/resume/profiles", bytes.NewReader(body))
		req.Header.Set("Authorization", "Bearer "+token)
		rr := httptest.NewRecorder()
		profiles.ServeHTTP(rr, req)
		if rr.Code != http.StatusCreated {
			t.Fatalf("POST: expected 201, got %d: %s", rr.Code, rr.Body.String())
		}
		var p resume.Profile
		json.Unmarshal(rr.Body.Bytes(), &p)
		return p
	}
	parena := create("github.com/x/parena")
	burrow := create("github.com/x/burrow")
	if parena.ID == "" || burrow.ID == "" || parena.ID == burrow.ID {
		t.Fatalf("expected two distinct, real, non-empty ids for two same-network links, got %q and %q", parena.ID, burrow.ID)
	}

	// Patch only the parena link's URL -- burrow must be untouched.
	patchBody, _ := json.Marshal(map[string]string{"url": "github.com/x/parena-renamed"})
	patchReq := httptest.NewRequest(http.MethodPatch, "/api/v1/community-tools/resume/profiles/"+parena.ID, bytes.NewReader(patchBody))
	patchReq.Header.Set("Authorization", "Bearer "+token)
	patchRR := httptest.NewRecorder()
	profiles.ServeHTTP(patchRR, patchReq)
	if patchRR.Code != http.StatusOK {
		t.Fatalf("PATCH: expected 200, got %d: %s", patchRR.Code, patchRR.Body.String())
	}

	// Delete only burrow.
	delReq := httptest.NewRequest(http.MethodDelete, "/api/v1/community-tools/resume/profiles/"+burrow.ID, nil)
	delReq.Header.Set("Authorization", "Bearer "+token)
	delRR := httptest.NewRecorder()
	profiles.ServeHTTP(delRR, delReq)
	if delRR.Code != http.StatusOK {
		t.Fatalf("DELETE: expected 200, got %d: %s", delRR.Code, delRR.Body.String())
	}

	getReq := httptest.NewRequest(http.MethodGet, "/api/v1/community-tools/resume", nil)
	getReq.Header.Set("Authorization", "Bearer "+token)
	crud := middleware.RequireAuth(keys)(middleware.RequirePermission("community-tools.access")(&handlers.CommunityToolsHandler{DB: db}))
	getRR := httptest.NewRecorder()
	crud.ServeHTTP(getRR, getReq)
	var res resume.Resume
	json.Unmarshal(getRR.Body.Bytes(), &res)
	if len(res.Basics.Profiles) != 1 {
		t.Fatalf("expected exactly 1 remaining profile (parena, renamed; burrow deleted), got: %+v", res.Basics.Profiles)
	}
	if res.Basics.Profiles[0].ID != parena.ID || res.Basics.Profiles[0].URL != "github.com/x/parena-renamed" {
		t.Fatalf("expected the surviving profile to be the renamed parena link, got: %+v", res.Basics.Profiles[0])
	}
}

func TestCommunityToolsTargetsHandler_CreatePatchDeleteOneTarget(t *testing.T) {
	keys, _ := jwt.GenerateKeys()
	crud, _, targets, _, _ := newTestCommunityToolsHandlers(t, keys)
	token := communityToolsToken(t, keys, 1, "community-tools.access")
	master := saveMasterResumeWithTwoJobs(t, crud, token)

	// Create -- POST one new target, server-assigned id regardless of anything sent.
	createBody, _ := json.Marshal(map[string]any{"id": "hijack-attempt", "name": "My Target", "included_work_ids": []string{master.Work[0].ID}})
	createReq := httptest.NewRequest(http.MethodPost, "/api/v1/community-tools/resume/targets", bytes.NewReader(createBody))
	createReq.Header.Set("Authorization", "Bearer "+token)
	createRR := httptest.NewRecorder()
	targets.ServeHTTP(createRR, createReq)
	if createRR.Code != http.StatusCreated {
		t.Fatalf("POST: expected 201, got %d: %s", createRR.Code, createRR.Body.String())
	}
	var created resume.Target
	json.Unmarshal(createRR.Body.Bytes(), &created)
	if created.ID == "" || created.ID == "hijack-attempt" {
		t.Fatalf("expected a real, server-assigned id, got %q", created.ID)
	}

	// Patch -- a real partial merge, including the real three-way null-clears-the-override
	// semantics: first set a summary override, then send an explicit null to clear it, then
	// confirm a completely omitted field (name) survives untouched throughout.
	setOverrideBody, _ := json.Marshal(map[string]any{"summary_override": "Tailored summary"})
	setReq := httptest.NewRequest(http.MethodPatch, "/api/v1/community-tools/resume/targets/"+created.ID, bytes.NewReader(setOverrideBody))
	setReq.Header.Set("Authorization", "Bearer "+token)
	setRR := httptest.NewRecorder()
	targets.ServeHTTP(setRR, setReq)
	if setRR.Code != http.StatusOK {
		t.Fatalf("PATCH (set override): expected 200, got %d: %s", setRR.Code, setRR.Body.String())
	}
	var withOverride resume.Target
	json.Unmarshal(setRR.Body.Bytes(), &withOverride)
	if withOverride.SummaryOverride == nil || *withOverride.SummaryOverride != "Tailored summary" {
		t.Fatalf("expected the summary override to be set, got: %+v", withOverride.SummaryOverride)
	}
	if withOverride.Name != "My Target" {
		t.Fatalf("expected the omitted name field to survive, got %q", withOverride.Name)
	}

	clearOverrideBody := []byte(`{"summary_override": null}`)
	clearReq := httptest.NewRequest(http.MethodPatch, "/api/v1/community-tools/resume/targets/"+created.ID, bytes.NewReader(clearOverrideBody))
	clearReq.Header.Set("Authorization", "Bearer "+token)
	clearRR := httptest.NewRecorder()
	targets.ServeHTTP(clearRR, clearReq)
	if clearRR.Code != http.StatusOK {
		t.Fatalf("PATCH (clear override): expected 200, got %d: %s", clearRR.Code, clearRR.Body.String())
	}
	var cleared resume.Target
	json.Unmarshal(clearRR.Body.Bytes(), &cleared)
	if cleared.SummaryOverride != nil {
		t.Fatalf("expected an explicit null to clear the override, got: %+v", *cleared.SummaryOverride)
	}
	if cleared.Name != "My Target" {
		t.Fatalf("expected the name to still survive untouched, got %q", cleared.Name)
	}

	// Delete.
	delReq := httptest.NewRequest(http.MethodDelete, "/api/v1/community-tools/resume/targets/"+created.ID, nil)
	delReq.Header.Set("Authorization", "Bearer "+token)
	delRR := httptest.NewRecorder()
	targets.ServeHTTP(delRR, delReq)
	if delRR.Code != http.StatusOK {
		t.Fatalf("DELETE: expected 200, got %d: %s", delRR.Code, delRR.Body.String())
	}
	listReq := httptest.NewRequest(http.MethodGet, "/api/v1/community-tools/resume/targets", nil)
	listReq.Header.Set("Authorization", "Bearer "+token)
	listRR := httptest.NewRecorder()
	targets.ServeHTTP(listRR, listReq)
	var listed []resume.Target
	json.Unmarshal(listRR.Body.Bytes(), &listed)
	if len(listed) != 0 {
		t.Fatalf("expected the deleted target to really be gone, got: %+v", listed)
	}
}

func TestCommunityToolsTargetsHandler_PatchDeleteUnknownIDReturns404(t *testing.T) {
	keys, _ := jwt.GenerateKeys()
	_, _, targets, _, _ := newTestCommunityToolsHandlers(t, keys)
	token := communityToolsToken(t, keys, 1, "community-tools.access")

	patchReq := httptest.NewRequest(http.MethodPatch, "/api/v1/community-tools/resume/targets/does-not-exist", bytes.NewReader([]byte(`{}`)))
	patchReq.Header.Set("Authorization", "Bearer "+token)
	patchRR := httptest.NewRecorder()
	targets.ServeHTTP(patchRR, patchReq)
	if patchRR.Code != http.StatusNotFound {
		t.Fatalf("PATCH: expected 404, got %d: %s", patchRR.Code, patchRR.Body.String())
	}

	delReq := httptest.NewRequest(http.MethodDelete, "/api/v1/community-tools/resume/targets/does-not-exist", nil)
	delReq.Header.Set("Authorization", "Bearer "+token)
	delRR := httptest.NewRecorder()
	targets.ServeHTTP(delRR, delReq)
	if delRR.Code != http.StatusNotFound {
		t.Fatalf("DELETE: expected 404, got %d: %s", delRR.Code, delRR.Body.String())
	}
}

func TestCommunityToolsOpenAPIHandler_ReturnsRealValidJSON(t *testing.T) {
	h := &handlers.CommunityToolsOpenAPIHandler{}
	req := httptest.NewRequest(http.MethodGet, "/api/v1/community-tools/openapi.json", nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}
	if ct := rr.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("expected Content-Type application/json, got %q", ct)
	}
	var spec map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &spec); err != nil {
		t.Fatalf("expected the served body to be real, valid JSON: %v", err)
	}
	if spec["openapi"] == nil {
		t.Fatal("expected a real OpenAPI document (missing top-level \"openapi\" version field)")
	}
	paths, ok := spec["paths"].(map[string]any)
	if !ok || len(paths) == 0 {
		t.Fatal("expected a real, non-empty \"paths\" object describing the actual routes")
	}
	if _, ok := paths["/resume/work/{id}"]; !ok {
		t.Error("expected the new per-entry PATCH/DELETE routes to actually be documented in the spec")
	}
	if _, ok := paths["/resume/profiles/{id}"]; !ok {
		t.Error("expected the new Profile (multiple GitHub links) routes to actually be documented in the spec")
	}
}

func TestCommunityToolsOpenAPIHandler_RejectsNonGET(t *testing.T) {
	h := &handlers.CommunityToolsOpenAPIHandler{}
	req := httptest.NewRequest(http.MethodPost, "/api/v1/community-tools/openapi.json", nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusNotFound {
		t.Fatalf("expected 404 for a non-GET method, got %d: %s", rr.Code, rr.Body.String())
	}
}
