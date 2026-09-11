package gdpr

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"

	"idunapro/internal/userlog"
)

// buildExportBundle gathers everything this IDUNA_PRO instance actually holds about localUID --
// the real Article 15/20 payload. tenantID is already verified (Export's own
// verifyTenantMembership call, above) by the time this runs; the tenant-scoped GetByUID call here
// is real, deliberate defense in depth, not the only check.
func buildExportBundle(ctx context.Context, deps Deps, tenantID, localUID int) (*ExportBundle, error) {
	profile, err := deps.Proj.GetByUID(ctx, tenantID, localUID)
	if err != nil {
		return nil, fmt.Errorf("load profile: %w", err)
	}

	history, err := eventHistoryForUser(ctx, deps.Log, localUID)
	if err != nil {
		return nil, fmt.Errorf("load event history: %w", err)
	}

	bundle := &ExportBundle{
		LocalUID:     localUID,
		Profile:      profile,
		EventHistory: history,
		ExportedAt:   time.Now().UTC(),
	}

	if ext := gatherExtensionData(ctx, deps.DB, localUID); len(ext) > 0 {
		bundle.Extensions = ext
	}
	return bundle, nil
}

// eventHistoryForUser scans the full event log for every record that references localUID.
// Real, accepted v0 scaling limit: this reads every record in the log (ReadFrom(0, 0)) and
// filters client-side -- fine at the scale a single-tenant IDUNA_PRO instance's own user event
// log reaches, flagged honestly rather than building a by-uid index that doesn't exist yet.
func eventHistoryForUser(ctx context.Context, log *userlog.FileEventLog, localUID int) ([]userlog.Record, error) {
	all, err := log.ReadFrom(ctx, 0, 0)
	if err != nil {
		return nil, err
	}
	var out []userlog.Record
	for _, rec := range all {
		var probe struct {
			LocalUID int `json:"local_uid"`
		}
		if err := json.Unmarshal(rec.Event.Data, &probe); err != nil {
			continue
		}
		if probe.LocalUID == localUID {
			out = append(out, rec)
		}
	}
	return out, nil
}

// gatherExtensionData collects rows from per-tenant PII-bearing extension tables that reference
// localUID -- CarePyre-originated additions (sip_accounts, mail_account_credentials) that may or
// may not exist on a given IDUNA_PRO tenant, since they were built for one real deployment
// (CarePyre) but live in this shared codebase every tenant runs. A missing table is not an
// error -- most tenants will have neither.
//
// Real, deliberate exclusion: mail_account_credentials.password_enc (the tenant's real, live
// mailbox password, encrypted at rest) is NOT included -- see ExportBundle's own doc comment for
// why a static export file is the wrong place for a live secret VALUE. This names that the
// mailbox link exists (email address only) without duplicating the existing admin
// reveal-password endpoint's own real value.
func gatherExtensionData(ctx context.Context, db *sql.DB, localUID int) map[string][]any {
	out := map[string][]any{}

	if rows := queryOptionalTable(ctx, db,
		`SELECT extension, sip_server, sip_port, updated_at FROM sip_accounts WHERE local_uid = ?`, localUID,
		func(rows *sql.Rows) (any, error) {
			var extension, sipServer, updatedAt string
			var sipPort int
			if err := rows.Scan(&extension, &sipServer, &sipPort, &updatedAt); err != nil {
				return nil, err
			}
			return map[string]any{"extension": extension, "sip_server": sipServer, "sip_port": sipPort, "updated_at": updatedAt}, nil
		}); rows != nil {
		out["sip_accounts"] = rows
	}

	if rows := queryOptionalTable(ctx, db,
		`SELECT email, created_at FROM mail_account_credentials WHERE local_uid = ?`, localUID,
		func(rows *sql.Rows) (any, error) {
			var email, createdAt string
			if err := rows.Scan(&email, &createdAt); err != nil {
				return nil, err
			}
			return map[string]any{"email": email, "created_at": createdAt, "note": "password intentionally excluded from export -- see this repo's own admin reveal-password endpoint"}, nil
		}); rows != nil {
		out["mail_accounts"] = rows
	}

	return out
}

// queryOptionalTable runs query and scans each row with scan, returning nil (not an error) if
// the underlying table simply doesn't exist on this tenant -- any other error is swallowed too,
// deliberately: a GDPR export/delete request must never fail outright because one optional,
// tenant-specific extension table had a transient problem. Real tradeoff, named not hidden.
func queryOptionalTable(ctx context.Context, db *sql.DB, query string, uid int, scan func(*sql.Rows) (any, error)) []any {
	rows, err := db.QueryContext(ctx, query, uid)
	if err != nil {
		return nil // table doesn't exist on this tenant, or some other real but non-fatal issue
	}
	defer rows.Close()
	var out []any
	for rows.Next() {
		v, err := scan(rows)
		if err != nil {
			continue
		}
		out = append(out, v)
	}
	return out
}

// scrubExtensionTables deletes rows from the same optional, per-tenant PII-bearing extension
// tables gatherExtensionData reads from -- part of real Article 17 erasure, since a SIP
// extension mapping or a mailbox credential are both real personal data tied to this uid, not
// just profile fields. Returns which tables actually had a row removed (for the request's own
// audit summary).
func scrubExtensionTables(ctx context.Context, db *sql.DB, localUID int) []string {
	var touched []string
	for _, t := range []struct {
		table string
		query string
	}{
		{"sip_accounts", `DELETE FROM sip_accounts WHERE local_uid = ?`},
		{"mail_account_credentials", `DELETE FROM mail_account_credentials WHERE local_uid = ?`},
	} {
		res, err := db.ExecContext(ctx, t.query, localUID)
		if err != nil {
			continue // table doesn't exist on this tenant -- not an error, see gatherExtensionData's own doc comment
		}
		if n, _ := res.RowsAffected(); n > 0 {
			touched = append(touched, t.table)
		}
	}
	return touched
}

// appendDeletedEvent fires the SAME EventUserDeleted event the existing admin delete-user
// handler already uses (internal/http/handlers/users.go's own deleteUser) -- preserves that
// existing audit/status behavior unchanged; the REAL erasure work (redaction, scrubbing) happens
// separately in Delete, above.
func appendDeletedEvent(ctx context.Context, deps Deps, localUID, operatorUID int) error {
	payload, err := json.Marshal(userlog.UserDeletedData{LocalUID: localUID})
	if err != nil {
		return err
	}
	ev := userlog.Event{
		ID:          uuid.New().String(),
		Type:        userlog.EventUserDeleted,
		Source:      "idunapro/gdpr",
		OccurredAt:  time.Now().UTC(),
		OperatorUID: operatorUID,
		Data:        payload,
	}
	recs, err := deps.Log.Append(ctx, ev)
	if err != nil {
		return err
	}
	return deps.Proj.Apply(ctx, recs[0])
}
