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

func newTestCommunityToolsHandlers(t *testing.T, keys *jwt.Keys) (http.Handler, http.Handler, *sql.DB) {
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
			created_at TEXT NOT NULL,
			updated_at TEXT NOT NULL
		);
	`); err != nil {
		t.Fatalf("create schema: %v", err)
	}

	crud := &handlers.CommunityToolsHandler{DB: db}
	verify := &handlers.CommunityToolsVerifyHandler{DB: db}
	crudProtected := middleware.RequireAuth(keys)(middleware.RequirePermission("community-tools.access")(crud))
	verifyProtected := middleware.RequireAuth(keys)(middleware.RequirePermission("community-tools.access")(verify))
	return crudProtected, verifyProtected, db
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
	crud, _, _ := newTestCommunityToolsHandlers(t, keys)
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
	crud, _, _ := newTestCommunityToolsHandlers(t, keys)
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
	crud, _, _ := newTestCommunityToolsHandlers(t, keys)
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
	crud, _, _ := newTestCommunityToolsHandlers(t, keys)
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
	crud, verify, _ := newTestCommunityToolsHandlers(t, keys)
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
