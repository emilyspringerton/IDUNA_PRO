// Package gdpr implements IDUNA_PRO's real data subject request pipeline -- Article 15/20
// (access / portability, "export everything you hold about me") and Article 17 (erasure,
// "delete everything you hold about me"). Founder real-time, 2026-09-07: "build gdpr into iduna
// pro multi tennant with data exporting and data delete request pipeline dont focus on the
// cookie confirm widget at this time."
//
// Real, load-bearing finding this package exists BECAUSE of: IDUNA_PRO's own local-user identity
// is event-sourced (internal/userlog) -- an append-only NDJSON log that a SQL projection is
// built from. The projector's own existing EventUserDeleted handling only ever sets
// status='deleted' in the projection; it does NOT touch the projection's own email/
// display_name/password_hash columns, and it does nothing at all to the raw event log files,
// which still hold the original PII forever (Append never rewrites a line once written). A
// "GDPR delete" that only appended that existing event and called it done would be misleading --
// see internal/userlog's own new RedactUser/ScrubPII (this session's own real fix for that gap)
// for the actual erasure mechanism this package calls.
package gdpr

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"idunapro/internal/userlog"
)

// Deps wires the real state this package needs -- no interface abstraction beyond what already
// exists (userlog.EventLog/UserProjector), matching how the rest of this codebase's own
// handlers are wired (concrete *sql.DB, concrete *userlog.FileEventLog).
type Deps struct {
	DB   *sql.DB
	Log  *userlog.FileEventLog
	Proj userlog.UserProjector
}

// Request mirrors the gdpr_requests table (migrations/truestore/202609070001_gdpr_requests.sql).
type Request struct {
	ID            int64  `json:"id"`
	LocalUID      int    `json:"local_uid"`
	RequestType   string `json:"request_type"` // "export" | "delete"
	Status        string `json:"status"`       // "pending" | "completed" | "failed"
	RequestedBy   int    `json:"requested_by"`
	ExportPath    string `json:"export_path,omitempty"`
	ResultSummary string `json:"result_summary,omitempty"`
	ErrorMessage  string `json:"error_message,omitempty"`
	CreatedAt     string `json:"created_at"`
	CompletedAt   string `json:"completed_at,omitempty"`
}

// ExportBundle is the real, structured, machine-readable export this package produces for
// Article 15/20 -- everything IDUNA_PRO actually holds about one local user. Deliberately
// excludes live secret VALUES (the mailbox password in mail_account_credentials, if that
// CarePyre-originated extension table exists on this tenant) -- a static export file is a worse
// place for a live credential to sit than the existing admin reveal-password endpoint it would
// duplicate; ExtensionData names that the row exists without repeating the secret.
type ExportBundle struct {
	LocalUID     int                `json:"local_uid"`
	Profile      *userlog.LocalUser `json:"profile"`
	EventHistory []userlog.Record   `json:"event_history"`
	Extensions   map[string][]any   `json:"extensions,omitempty"` // e.g. "sip_accounts": [...], "mail_accounts": [...]
	ExportedAt   time.Time          `json:"exported_at"`
}

// Export runs the real Article 15/20 pipeline: records a request row, gathers everything this
// instance holds about localUID, writes it as a real JSON file, and marks the request completed
// (or failed, with a real error_message -- never left stuck at "pending").
func Export(ctx context.Context, deps Deps, localUID, requestedBy int, exportDir string) (*Request, error) {
	req, err := createRequest(ctx, deps.DB, localUID, "export", requestedBy)
	if err != nil {
		return nil, err
	}

	bundle, err := buildExportBundle(ctx, deps, localUID)
	if err != nil {
		return failRequest(ctx, deps.DB, req, fmt.Errorf("build export: %w", err))
	}

	if err := os.MkdirAll(exportDir, 0o700); err != nil {
		return failRequest(ctx, deps.DB, req, fmt.Errorf("create export dir: %w", err))
	}
	path := filepath.Join(exportDir, fmt.Sprintf("gdpr-export-uid%d-req%d.json", localUID, req.ID))
	b, err := json.MarshalIndent(bundle, "", "  ")
	if err != nil {
		return failRequest(ctx, deps.DB, req, fmt.Errorf("marshal export: %w", err))
	}
	if err := os.WriteFile(path, b, 0o600); err != nil {
		return failRequest(ctx, deps.DB, req, fmt.Errorf("write export file: %w", err))
	}

	req.Status = "completed"
	req.ExportPath = path
	if _, err := deps.DB.ExecContext(ctx,
		`UPDATE gdpr_requests SET status = 'completed', export_path = ?, completed_at = CURRENT_TIMESTAMP WHERE id = ?`,
		path, req.ID); err != nil {
		return nil, fmt.Errorf("gdpr: mark export request completed: %w", err)
	}
	return req, nil
}

// Delete runs the real Article 17 pipeline: records a request row, appends the existing
// EventUserDeleted event (preserves the current admin-facing status/audit behavior, unchanged),
// then does the actual erasure this package exists for -- redacts the raw event log
// (userlog.FileEventLog.RedactUser), scrubs the SQL projection's own PII columns
// (UserProjector.ScrubPII), and removes rows from any per-tenant PII-bearing extension tables
// that reference this uid (sip_accounts, mail_account_credentials -- CarePyre-originated
// extensions that may or may not exist on a given tenant; missing tables are not an error).
func Delete(ctx context.Context, deps Deps, localUID, requestedBy int) (*Request, error) {
	req, err := createRequest(ctx, deps.DB, localUID, "delete", requestedBy)
	if err != nil {
		return nil, err
	}

	if err := appendDeletedEvent(ctx, deps, localUID, requestedBy); err != nil {
		return failRequest(ctx, deps.DB, req, fmt.Errorf("append deletion event: %w", err))
	}

	redactedEvents, err := deps.Log.RedactUser(ctx, localUID)
	if err != nil {
		return failRequest(ctx, deps.DB, req, fmt.Errorf("redact event log: %w", err))
	}

	if err := deps.Proj.ScrubPII(ctx, localUID); err != nil {
		return failRequest(ctx, deps.DB, req, fmt.Errorf("scrub projection: %w", err))
	}

	extRemoved := scrubExtensionTables(ctx, deps.DB, localUID)

	summary := fmt.Sprintf("redacted %d event log record(s); scrubbed SQL projection", redactedEvents)
	if len(extRemoved) > 0 {
		summary += fmt.Sprintf("; removed rows from: %s", strings.Join(extRemoved, ", "))
	}

	req.Status = "completed"
	req.ResultSummary = summary
	if _, err := deps.DB.ExecContext(ctx,
		`UPDATE gdpr_requests SET status = 'completed', result_summary = ?, completed_at = CURRENT_TIMESTAMP WHERE id = ?`,
		summary, req.ID); err != nil {
		return nil, fmt.Errorf("gdpr: mark delete request completed: %w", err)
	}
	return req, nil
}

func createRequest(ctx context.Context, db *sql.DB, localUID int, requestType string, requestedBy int) (*Request, error) {
	res, err := db.ExecContext(ctx,
		`INSERT INTO gdpr_requests (local_uid, request_type, status, requested_by) VALUES (?, ?, 'pending', ?)`,
		localUID, requestType, requestedBy)
	if err != nil {
		return nil, fmt.Errorf("gdpr: create request row: %w", err)
	}
	id, err := res.LastInsertId()
	if err != nil {
		return nil, fmt.Errorf("gdpr: read new request id: %w", err)
	}
	return &Request{ID: id, LocalUID: localUID, RequestType: requestType, Status: "pending", RequestedBy: requestedBy}, nil
}

func failRequest(ctx context.Context, db *sql.DB, req *Request, cause error) (*Request, error) {
	req.Status = "failed"
	req.ErrorMessage = cause.Error()
	if _, err := db.ExecContext(ctx,
		`UPDATE gdpr_requests SET status = 'failed', error_message = ?, completed_at = CURRENT_TIMESTAMP WHERE id = ?`,
		req.ErrorMessage, req.ID); err != nil {
		return nil, fmt.Errorf("gdpr: record failure (original cause: %v): %w", cause, err)
	}
	return req, nil
}

// ListRequests returns every GDPR request, newest first (admin view / audit trail).
func ListRequests(ctx context.Context, db *sql.DB) ([]Request, error) {
	return queryRequests(ctx, db, `SELECT id, local_uid, request_type, status, requested_by, COALESCE(export_path,''), COALESCE(result_summary,''), COALESCE(error_message,''), created_at, COALESCE(completed_at,'') FROM gdpr_requests ORDER BY id DESC`)
}

// ListRequestsForUser returns a specific user's own requests, newest first (self-service view).
func ListRequestsForUser(ctx context.Context, db *sql.DB, localUID int) ([]Request, error) {
	return queryRequests(ctx, db,
		`SELECT id, local_uid, request_type, status, requested_by, COALESCE(export_path,''), COALESCE(result_summary,''), COALESCE(error_message,''), created_at, COALESCE(completed_at,'') FROM gdpr_requests WHERE local_uid = ? ORDER BY id DESC`,
		localUID)
}

func queryRequests(ctx context.Context, db *sql.DB, query string, args ...any) ([]Request, error) {
	rows, err := db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Request
	for rows.Next() {
		var r Request
		if err := rows.Scan(&r.ID, &r.LocalUID, &r.RequestType, &r.Status, &r.RequestedBy, &r.ExportPath, &r.ResultSummary, &r.ErrorMessage, &r.CreatedAt, &r.CompletedAt); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}
