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
		Data: mustJSONGDPR(t, userlog.UserCreatedData{LocalUID: 1, Email: "self@example.com"}),
	})
	if err != nil {
		t.Fatalf("seed uid1: %v", err)
	}
	_ = proj.Apply(context.Background(), rec[0])
	rec2, err := log.Append(context.Background(), userlog.Event{
		ID:   "e2",
		Type: userlog.EventUserCreated,
		Data: mustJSONGDPR(t, userlog.UserCreatedData{LocalUID: 2, Email: "other@example.com"}),
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
