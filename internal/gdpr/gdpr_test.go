package gdpr_test

import (
	"context"
	"database/sql"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	_ "modernc.org/sqlite"

	"idunapro/internal/gdpr"
	"idunapro/internal/userlog"
)

func setupDeps(t *testing.T) (gdpr.Deps, *sql.DB) {
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
		CREATE TABLE sip_accounts (
			local_uid  INTEGER NOT NULL,
			extension  TEXT NOT NULL,
			sip_server TEXT NOT NULL,
			sip_port   INTEGER NOT NULL,
			updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
		);
	`); err != nil {
		t.Fatalf("create schema: %v", err)
	}

	dir := t.TempDir()
	log, err := userlog.NewFileEventLog(filepath.Join(dir, "events"))
	if err != nil {
		t.Fatalf("NewFileEventLog: %v", err)
	}
	t.Cleanup(func() { log.Close() })

	proj := userlog.NewSQLiteProjector(db)

	rec, err := log.Append(context.Background(), userlog.Event{
		ID:   "e1",
		Type: userlog.EventUserCreated,
		Data: mustJSON(t, userlog.UserCreatedData{
			LocalUID: 5, Email: "subject@example.com", DisplayName: "Real Name", PasswordHash: "realhash",
		}),
	})
	if err != nil {
		t.Fatalf("seed Append: %v", err)
	}
	if err := proj.Apply(context.Background(), rec[0]); err != nil {
		t.Fatalf("seed Apply: %v", err)
	}

	if _, err := db.Exec(`INSERT INTO sip_accounts (local_uid, extension, sip_server, sip_port) VALUES (5, '1001', 'sip.example.com', 5060)`); err != nil {
		t.Fatalf("seed sip_accounts: %v", err)
	}

	return gdpr.Deps{DB: db, Log: log, Proj: proj}, db
}

func mustJSON(t *testing.T, v any) json.RawMessage {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return b
}

func TestExport_WritesRealBundleAndCompletesRequest(t *testing.T) {
	deps, db := setupDeps(t)
	exportDir := t.TempDir()

	req, err := gdpr.Export(context.Background(), deps, 5, 5, exportDir)
	if err != nil {
		t.Fatalf("Export: %v", err)
	}
	if req.Status != "completed" {
		t.Fatalf("expected status completed, got %q (error=%q)", req.Status, req.ErrorMessage)
	}
	if req.ExportPath == "" {
		t.Fatal("expected a non-empty export path")
	}

	b, err := os.ReadFile(req.ExportPath)
	if err != nil {
		t.Fatalf("read export file: %v", err)
	}
	var bundle gdpr.ExportBundle
	if err := json.Unmarshal(b, &bundle); err != nil {
		t.Fatalf("unmarshal export bundle: %v", err)
	}
	if bundle.Profile == nil || bundle.Profile.Email != "subject@example.com" {
		t.Fatalf("expected profile with real email in export, got %+v", bundle.Profile)
	}
	if len(bundle.EventHistory) == 0 {
		t.Fatal("expected at least one event in the exported history")
	}
	if len(bundle.Extensions["sip_accounts"]) != 1 {
		t.Fatalf("expected 1 sip_accounts row in export, got %d", len(bundle.Extensions["sip_accounts"]))
	}

	var count int
	if err := db.QueryRow(`SELECT COUNT(*) FROM gdpr_requests WHERE id = ? AND status = 'completed'`, req.ID).Scan(&count); err != nil {
		t.Fatalf("query request row: %v", err)
	}
	if count != 1 {
		t.Fatal("expected a completed request row in gdpr_requests")
	}
}

func TestDelete_ErasesPIIAndScrubsExtensions(t *testing.T) {
	deps, db := setupDeps(t)

	req, err := gdpr.Delete(context.Background(), deps, 5, 5)
	if err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if req.Status != "completed" {
		t.Fatalf("expected status completed, got %q (error=%q)", req.Status, req.ErrorMessage)
	}
	if !strings.Contains(req.ResultSummary, "sip_accounts") {
		t.Errorf("expected result summary to mention sip_accounts, got %q", req.ResultSummary)
	}

	u, err := deps.Proj.GetByUID(context.Background(), 5)
	if err != nil {
		t.Fatalf("GetByUID: %v", err)
	}
	if u != nil {
		t.Fatal("expected GetByUID to hide the now-deleted user")
	}

	var email string
	if err := db.QueryRow(`SELECT email FROM local_users WHERE local_uid = 5`).Scan(&email); err != nil {
		t.Fatalf("query raw row: %v", err)
	}
	if email == "subject@example.com" {
		t.Error("expected email column to be scrubbed, but the original value survives")
	}

	var sipCount int
	if err := db.QueryRow(`SELECT COUNT(*) FROM sip_accounts WHERE local_uid = 5`).Scan(&sipCount); err != nil {
		t.Fatalf("query sip_accounts: %v", err)
	}
	if sipCount != 0 {
		t.Errorf("expected sip_accounts rows for uid 5 to be deleted, got %d remaining", sipCount)
	}
}

func TestListRequests_ScopesByUser(t *testing.T) {
	deps, db := setupDeps(t)

	if _, err := gdpr.Export(context.Background(), deps, 5, 5, t.TempDir()); err != nil {
		t.Fatalf("Export: %v", err)
	}
	if _, err := db.Exec(`INSERT INTO gdpr_requests (local_uid, request_type, status, requested_by) VALUES (9, 'export', 'completed', 9)`); err != nil {
		t.Fatalf("seed other user's request: %v", err)
	}

	mine, err := gdpr.ListRequestsForUser(context.Background(), db, 5)
	if err != nil {
		t.Fatalf("ListRequestsForUser: %v", err)
	}
	if len(mine) != 1 {
		t.Fatalf("expected exactly 1 request for uid 5, got %d", len(mine))
	}

	all, err := gdpr.ListRequests(context.Background(), db)
	if err != nil {
		t.Fatalf("ListRequests: %v", err)
	}
	if len(all) != 2 {
		t.Fatalf("expected 2 requests total, got %d", len(all))
	}
}
