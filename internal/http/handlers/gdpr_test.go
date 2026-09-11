package handlers_test

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	_ "modernc.org/sqlite"

	"idunapro/internal/auth/jwt"
	"idunapro/internal/gdpr"
	"idunapro/internal/http/handlers"
	"idunapro/internal/http/middleware"
	"idunapro/internal/userlog"
)

func newTestGDPRHandler(t *testing.T, keys *jwt.Keys) (http.Handler, *sql.DB) {
	t.Helper()
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	t.Cleanup(func() { db.Close() })

	if _, err := db.Exec(`
		CREATE TABLE local_users (
			local_uid     INTEGER NOT NULL PRIMARY KEY,
			email         TEXT    NOT NULL,
			display_name  TEXT    NOT NULL DEFAULT '',
			password_hash TEXT    NOT NULL DEFAULT '',
			status        TEXT    NOT NULL DEFAULT 'active',
			is_admin      INTEGER NOT NULL DEFAULT 0,
			is_provider   INTEGER NOT NULL DEFAULT 0,
			is_operator_admin INTEGER NOT NULL DEFAULT 0,
			is_provider_admin INTEGER NOT NULL DEFAULT 0,
			is_community_tools_enabled INTEGER NOT NULL DEFAULT 0,
			org_id INTEGER NOT NULL DEFAULT 0,
			tenant_id INTEGER NOT NULL DEFAULT 1,
			created_at    TEXT    NOT NULL DEFAULT CURRENT_TIMESTAMP,
			updated_at    TEXT    NOT NULL DEFAULT CURRENT_TIMESTAMP,
			UNIQUE (email)
		);
		CREATE TABLE local_user_projector_cursor (
			id       INTEGER NOT NULL PRIMARY KEY DEFAULT 1,
			last_seq INTEGER NOT NULL DEFAULT 0
		);
		INSERT OR IGNORE INTO local_user_projector_cursor (id, last_seq) VALUES (1, 0);
		CREATE TABLE gdpr_requests (
			id             INTEGER  PRIMARY KEY AUTOINCREMENT,
			local_uid      INTEGER  NOT NULL,
			request_type   VARCHAR(16) NOT NULL,
			status         VARCHAR(16) NOT NULL DEFAULT 'pending',
			requested_by   INTEGER  NOT NULL,
			export_path    VARCHAR(500),
			result_summary TEXT,
			error_message  TEXT,
			tenant_id      INTEGER  NOT NULL DEFAULT 1,
			created_at     DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
			completed_at   DATETIME
		);
	`); err != nil {
		t.Fatalf("create schema: %v", err)
	}

	log, err := userlog.NewFileEventLog(t.TempDir())
	if err != nil {
		t.Fatalf("NewFileEventLog: %v", err)
	}
	t.Cleanup(func() { log.Close() })
	proj := userlog.NewSQLiteProjector(db)

	rec, err := log.Append(context.Background(), userlog.Event{
		ID:   "e1",
		Type: userlog.EventUserCreated,
		Data: mustJSONGDPR(t, userlog.UserCreatedData{LocalUID: 1, Email: "self@example.com", TenantID: 1}),
	})
	if err != nil {
		t.Fatalf("seed uid1: %v", err)
	}
	_ = proj.Apply(context.Background(), rec[0])
	rec2, err := log.Append(context.Background(), userlog.Event{
		ID:   "e2",
		Type: userlog.EventUserCreated,
		Data: mustJSONGDPR(t, userlog.UserCreatedData{LocalUID: 2, Email: "other@example.com", TenantID: 1}),
	})
	if err != nil {
		t.Fatalf("seed uid2: %v", err)
	}
	_ = proj.Apply(context.Background(), rec2[0])

	h := &handlers.GDPRHandler{
		Deps:      gdpr.Deps{DB: db, Log: log, Proj: proj},
		ExportDir: filepath.Join(t.TempDir(), "exports"),
	}
	return middleware.RequireAuth(keys)(h), db
}

func mustJSONGDPR(t *testing.T, v any) json.RawMessage {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return b
}

func gdprToken(t *testing.T, keys *jwt.Keys, localUID int, perms ...string) string {
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

func TestGDPRHandler_SelfServiceExport(t *testing.T) {
	keys, _ := jwt.GenerateKeys()
	h, _ := newTestGDPRHandler(t, keys)
	token := gdprToken(t, keys, 1)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/gdpr/export", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("export: status = %d, body = %s", rr.Code, rr.Body.String())
	}
	var resp gdpr.Request
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if resp.LocalUID != 1 || resp.Status != "completed" {
		t.Fatalf("unexpected response: %+v", resp)
	}
}

func TestGDPRHandler_CannotActOnAnotherUserWithoutAdmin(t *testing.T) {
	keys, _ := jwt.GenerateKeys()
	h, _ := newTestGDPRHandler(t, keys)
	token := gdprToken(t, keys, 1) // no users.admin

	body, _ := json.Marshal(map[string]int{"local_uid": 2})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/gdpr/delete", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("expected 403 acting on another user without users.admin, got %d: %s", rr.Code, rr.Body.String())
	}
}

func TestGDPRHandler_AdminCanDeleteOnBehalfOfAnotherUser(t *testing.T) {
	keys, _ := jwt.GenerateKeys()
	h, db := newTestGDPRHandler(t, keys)
	token := gdprToken(t, keys, 1, "users.admin")

	body, _ := json.Marshal(map[string]int{"local_uid": 2})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/gdpr/delete", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("admin delete on behalf of uid 2: status = %d, body = %s", rr.Code, rr.Body.String())
	}

	var email string
	if err := db.QueryRow(`SELECT email FROM local_users WHERE local_uid = 2`).Scan(&email); err != nil {
		t.Fatalf("query raw row: %v", err)
	}
	if email == "other@example.com" {
		t.Error("expected uid 2's email to be scrubbed after admin-triggered delete")
	}
}

func TestGDPRHandler_ListRequestsScopedToSelfWithoutAdmin(t *testing.T) {
	keys, _ := jwt.GenerateKeys()
	h, db := newTestGDPRHandler(t, keys)
	token := gdprToken(t, keys, 1)

	if _, err := db.Exec(`INSERT INTO gdpr_requests (local_uid, request_type, status, requested_by) VALUES (2, 'export', 'completed', 2)`); err != nil {
		t.Fatalf("seed other user's request: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, "/api/v1/gdpr/export", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	h.ServeHTTP(httptest.NewRecorder(), req) // creates 1 request for uid 1

	listReq := httptest.NewRequest(http.MethodGet, "/api/v1/gdpr/requests", nil)
	listReq.Header.Set("Authorization", "Bearer "+token)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, listReq)
	if rr.Code != http.StatusOK {
		t.Fatalf("list requests: status = %d, body = %s", rr.Code, rr.Body.String())
	}
	var reqs []gdpr.Request
	if err := json.Unmarshal(rr.Body.Bytes(), &reqs); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(reqs) != 1 || reqs[0].LocalUID != 1 {
		t.Fatalf("expected exactly the caller's own 1 request, got %+v", reqs)
	}

	// Without users.admin, ?all=1 is forbidden.
	allReq := httptest.NewRequest(http.MethodGet, "/api/v1/gdpr/requests?all=1", nil)
	allReq.Header.Set("Authorization", "Bearer "+token)
	rr2 := httptest.NewRecorder()
	h.ServeHTTP(rr2, allReq)
	if rr2.Code != http.StatusForbidden {
		t.Fatalf("expected ?all=1 without users.admin to be forbidden, got %d", rr2.Code)
	}
}

func TestGDPRHandler_DownloadRequiresRequesterOrAdmin(t *testing.T) {
	keys, _ := jwt.GenerateKeys()
	h, _ := newTestGDPRHandler(t, keys)
	ownerToken := gdprToken(t, keys, 1)
	otherToken := gdprToken(t, keys, 2)

	exportReq := httptest.NewRequest(http.MethodPost, "/api/v1/gdpr/export", nil)
	exportReq.Header.Set("Authorization", "Bearer "+ownerToken)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, exportReq)
	if rr.Code != http.StatusOK {
		t.Fatalf("export: status = %d, body = %s", rr.Code, rr.Body.String())
	}
	var resp gdpr.Request
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	downloadPath := "/api/v1/gdpr/requests/" + strconv.FormatInt(resp.ID, 10) + "/download"

	forbidden := httptest.NewRequest(http.MethodGet, downloadPath, nil)
	forbidden.Header.Set("Authorization", "Bearer "+otherToken)
	rrF := httptest.NewRecorder()
	h.ServeHTTP(rrF, forbidden)
	if rrF.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for a non-owner non-admin download, got %d", rrF.Code)
	}

	allowed := httptest.NewRequest(http.MethodGet, downloadPath, nil)
	allowed.Header.Set("Authorization", "Bearer "+ownerToken)
	rrOK := httptest.NewRecorder()
	h.ServeHTTP(rrOK, allowed)
	if rrOK.Code != http.StatusOK {
		t.Fatalf("expected 200 for owner download, got %d: %s", rrOK.Code, rrOK.Body.String())
	}
}

// TestGDPRHandler_AdminCannotActOnCrossTenantUser -- the real, found-live gap fix
// (MULTI_TENANCY_NORTHSTAR.md Phase 1, 2026-09-11): before this, a users.admin holder could
// export or delete ANY local_uid given in the request body, with no tenant check anywhere in the
// chain. A tenant-1 admin (no tenant_id claim on this test's own token -> callerTenantID's real
// "default to 1" fallback) must not be able to touch uid 3, seeded under tenant 2.
func TestGDPRHandler_AdminCannotActOnCrossTenantUser(t *testing.T) {
	keys, _ := jwt.GenerateKeys()
	h, db := newTestGDPRHandler(t, keys)

	log, err := userlog.NewFileEventLog(t.TempDir())
	if err != nil {
		t.Fatalf("NewFileEventLog: %v", err)
	}
	t.Cleanup(func() { log.Close() })
	proj := userlog.NewSQLiteProjector(db)
	rec, err := log.Append(context.Background(), userlog.Event{
		ID:   "e3",
		Type: userlog.EventUserCreated,
		Data: mustJSONGDPR(t, userlog.UserCreatedData{LocalUID: 3, Email: "tenant2@example.com", TenantID: 2}),
	})
	if err != nil {
		t.Fatalf("seed uid3 (tenant 2): %v", err)
	}
	if err := proj.Apply(context.Background(), rec[0]); err != nil {
		t.Fatalf("apply uid3 seed: %v", err)
	}

	token := gdprToken(t, keys, 1, "users.admin") // tenant 1 (default, no explicit claim)

	body, _ := json.Marshal(map[string]int{"local_uid": 3})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/gdpr/delete", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusNotFound {
		t.Fatalf("expected 404 deleting a cross-tenant user via GDPR delete, got %d: %s", rr.Code, rr.Body.String())
	}

	var email string
	if err := db.QueryRow(`SELECT email FROM local_users WHERE local_uid = 3`).Scan(&email); err != nil {
		t.Fatalf("query raw row: %v", err)
	}
	if email != "tenant2@example.com" {
		t.Fatalf("expected the cross-tenant user's real email to survive untouched, got %q", email)
	}
}

// MULTI_TENANCY_NORTHSTAR.md Phase 2 (2026-09-11): the real adversarial test for the residual
// this session's own Phase 1 pass had named but under-scoped -- re-inspection found download()
// served the actual completed export FILE, not just metadata, with zero tenant check for a
// users.admin caller. A tenant-2 user's own export must not be downloadable by a tenant-1 admin.
func TestGDPRHandler_DownloadCrossTenantExportReturns404(t *testing.T) {
	keys, _ := jwt.GenerateKeys()
	h, db := newTestGDPRHandler(t, keys)

	log, err := userlog.NewFileEventLog(t.TempDir())
	if err != nil {
		t.Fatalf("NewFileEventLog: %v", err)
	}
	t.Cleanup(func() { log.Close() })
	proj := userlog.NewSQLiteProjector(db)
	rec, err := log.Append(context.Background(), userlog.Event{
		ID:   "e3",
		Type: userlog.EventUserCreated,
		Data: mustJSONGDPR(t, userlog.UserCreatedData{LocalUID: 3, Email: "tenant2@example.com", TenantID: 2}),
	})
	if err != nil {
		t.Fatalf("seed uid3 (tenant 2): %v", err)
	}
	if err := proj.Apply(context.Background(), rec[0]); err != nil {
		t.Fatalf("apply uid3 seed: %v", err)
	}

	// Tenant-2's own uid 3 self-exports -- a real, completed export request under tenant 2.
	tenant2Token := tenantToken(t, keys, 3, 2)
	exportReq := httptest.NewRequest(http.MethodPost, "/api/v1/gdpr/export", nil)
	exportReq.Header.Set("Authorization", "Bearer "+tenant2Token)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, exportReq)
	if rr.Code != http.StatusOK {
		t.Fatalf("tenant-2 self-export: status = %d, body = %s", rr.Code, rr.Body.String())
	}
	var resp gdpr.Request
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	downloadPath := "/api/v1/gdpr/requests/" + strconv.FormatInt(resp.ID, 10) + "/download"

	// A tenant-1 admin (no tenant_id claim -> callerTenantID's real "default to 1" fallback) tries
	// to download tenant-2's completed export file by its (small, sequential, guessable) id.
	tenant1AdminToken := gdprToken(t, keys, 1, "users.admin")
	crossReq := httptest.NewRequest(http.MethodGet, downloadPath, nil)
	crossReq.Header.Set("Authorization", "Bearer "+tenant1AdminToken)
	crossRR := httptest.NewRecorder()
	h.ServeHTTP(crossRR, crossReq)
	if crossRR.Code != http.StatusNotFound {
		t.Fatalf("tenant-1 admin downloading tenant-2's export: status = %d, body = %s, want 404 (real cross-tenant PII leak if not)", crossRR.Code, crossRR.Body.String())
	}
	if strings.Contains(crossRR.Body.String(), "tenant2@example.com") {
		t.Fatalf("tenant-2's real exported PII leaked into a 404 response body: %s", crossRR.Body.String())
	}

	// Regression: tenant-2's own caller can still download their own export.
	ownReq := httptest.NewRequest(http.MethodGet, downloadPath, nil)
	ownReq.Header.Set("Authorization", "Bearer "+tenant2Token)
	ownRR := httptest.NewRecorder()
	h.ServeHTTP(ownRR, ownReq)
	if ownRR.Code != http.StatusOK {
		t.Fatalf("tenant-2 downloading their own export: status = %d, body = %s, want 200", ownRR.Code, ownRR.Body.String())
	}
}

// TestGDPRHandler_ListRequestsAllScopedToCallerTenant -- the other half of the same residual:
// ?all=1 must never surface another tenant's request metadata (which local_uid requested what,
// when) to an admin outside that tenant.
func TestGDPRHandler_ListRequestsAllScopedToCallerTenant(t *testing.T) {
	keys, _ := jwt.GenerateKeys()
	h, db := newTestGDPRHandler(t, keys)

	// uid 1/2 are already seeded under tenant 1 by newTestGDPRHandler. Insert a real tenant-2
	// request directly (mirrors how a genuine second tenant's data already exists in production).
	if _, err := db.Exec(`INSERT INTO gdpr_requests (local_uid, request_type, status, requested_by, tenant_id) VALUES (99, 'export', 'completed', 99, 2)`); err != nil {
		t.Fatalf("seed tenant-2 request: %v", err)
	}

	tenant1Token := gdprToken(t, keys, 1, "users.admin")
	own := httptest.NewRequest(http.MethodPost, "/api/v1/gdpr/export", nil)
	own.Header.Set("Authorization", "Bearer "+tenant1Token)
	ownRR := httptest.NewRecorder()
	h.ServeHTTP(ownRR, own)
	if ownRR.Code != http.StatusOK {
		t.Fatalf("tenant-1 self-export (to have a real tenant-1 row to find): status = %d, body = %s", ownRR.Code, ownRR.Body.String())
	}

	listReq := httptest.NewRequest(http.MethodGet, "/api/v1/gdpr/requests?all=1", nil)
	listReq.Header.Set("Authorization", "Bearer "+tenant1Token)
	listRR := httptest.NewRecorder()
	h.ServeHTTP(listRR, listReq)
	if listRR.Code != http.StatusOK {
		t.Fatalf("?all=1: status = %d, body = %s", listRR.Code, listRR.Body.String())
	}
	var all []gdpr.Request
	if err := json.Unmarshal(listRR.Body.Bytes(), &all); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	for _, req := range all {
		if req.LocalUID == 99 {
			t.Fatalf("tenant-1 admin's ?all=1 surfaced a tenant-2 request (local_uid 99) -- real cross-tenant metadata leak: %+v", all)
		}
	}
	if len(all) == 0 {
		t.Fatalf("expected at least the real tenant-1 request to be visible, got none")
	}
}
