package userlog

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

// SQLiteProjector implements UserProjector against a SQLite database.
// The local_users table and local_user_projector_cursor table must already
// exist (created by migration 202606180001_local_users.sql).
type SQLiteProjector struct {
	db *sql.DB
}

// NewSQLiteProjector creates a projector backed by the given SQLite *sql.DB.
func NewSQLiteProjector(db *sql.DB) *SQLiteProjector {
	return &SQLiteProjector{db: db}
}

func (p *SQLiteProjector) Apply(ctx context.Context, rec Record) error {
	switch rec.Event.Type {
	case EventUserCreated:
		var d UserCreatedData
		if err := json.Unmarshal(rec.Event.Data, &d); err != nil {
			return fmt.Errorf("sqlite projector apply created: %w", err)
		}
		now := rec.AppendedAt.Format(time.RFC3339)
		_, err := p.db.ExecContext(ctx,
			`INSERT OR IGNORE INTO local_users
			 (local_uid, email, display_name, password_hash, status, created_at, updated_at)
			 VALUES (?, ?, ?, ?, 'active', ?, ?)`,
			d.LocalUID, d.Email, d.DisplayName, d.PasswordHash, now, now,
		)
		return err

	case EventUserUpdated:
		var d UserUpdatedData
		if err := json.Unmarshal(rec.Event.Data, &d); err != nil {
			return fmt.Errorf("sqlite projector apply updated: %w", err)
		}
		now := rec.AppendedAt.Format(time.RFC3339)
		if d.Email != nil {
			if _, err := p.db.ExecContext(ctx,
				`UPDATE local_users SET email=?, updated_at=? WHERE local_uid=?`,
				*d.Email, now, d.LocalUID,
			); err != nil {
				return err
			}
		}
		if d.DisplayName != nil {
			if _, err := p.db.ExecContext(ctx,
				`UPDATE local_users SET display_name=?, updated_at=? WHERE local_uid=?`,
				*d.DisplayName, now, d.LocalUID,
			); err != nil {
				return err
			}
		}
		return nil

	case EventUserPasswordReset:
		var d UserPasswordResetData
		if err := json.Unmarshal(rec.Event.Data, &d); err != nil {
			return fmt.Errorf("sqlite projector apply password_reset: %w", err)
		}
		now := rec.AppendedAt.Format(time.RFC3339)
		_, err := p.db.ExecContext(ctx,
			`UPDATE local_users SET password_hash=?, updated_at=? WHERE local_uid=?`,
			d.PasswordHash, now, d.LocalUID,
		)
		return err

	case EventUserStatusChanged:
		var d UserStatusChangedData
		if err := json.Unmarshal(rec.Event.Data, &d); err != nil {
			return fmt.Errorf("sqlite projector apply status_changed: %w", err)
		}
		now := rec.AppendedAt.Format(time.RFC3339)
		_, err := p.db.ExecContext(ctx,
			`UPDATE local_users SET status=?, updated_at=? WHERE local_uid=?`,
			d.NewStatus, now, d.LocalUID,
		)
		return err

	case EventUserDeleted:
		var d UserDeletedData
		if err := json.Unmarshal(rec.Event.Data, &d); err != nil {
			return fmt.Errorf("sqlite projector apply deleted: %w", err)
		}
		now := rec.AppendedAt.Format(time.RFC3339)
		_, err := p.db.ExecContext(ctx,
			`UPDATE local_users SET status='deleted', updated_at=? WHERE local_uid=?`,
			now, d.LocalUID,
		)
		return err

	default:
		// Unknown event types are silently skipped — forward compatibility.
		return nil
	}
}

func (p *SQLiteProjector) Cursor(ctx context.Context) (uint64, error) {
	var seq uint64
	err := p.db.QueryRowContext(ctx, `SELECT last_seq FROM local_user_projector_cursor WHERE id=1`).Scan(&seq)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, nil
	}
	return seq, err
}

func (p *SQLiteProjector) AdvanceCursor(ctx context.Context, seq uint64) error {
	_, err := p.db.ExecContext(ctx,
		`UPDATE local_user_projector_cursor SET last_seq=? WHERE id=1`,
		seq,
	)
	return err
}

func (p *SQLiteProjector) GetByUID(ctx context.Context, uid int) (*LocalUser, error) {
	return p.scanUser(p.db.QueryRowContext(ctx,
		`SELECT local_uid, email, display_name, password_hash, status, created_at, updated_at
		 FROM local_users WHERE local_uid=? AND status != 'deleted'`,
		uid,
	))
}

func (p *SQLiteProjector) GetByEmail(ctx context.Context, email string) (*LocalUser, error) {
	return p.scanUser(p.db.QueryRowContext(ctx,
		`SELECT local_uid, email, display_name, password_hash, status, created_at, updated_at
		 FROM local_users WHERE email=? AND status != 'deleted'`,
		email,
	))
}

func (p *SQLiteProjector) ListUsers(ctx context.Context, limit int) ([]LocalUser, error) {
	q := `SELECT local_uid, email, display_name, password_hash, status, created_at, updated_at
	      FROM local_users WHERE status != 'deleted' ORDER BY local_uid ASC`
	var rows *sql.Rows
	var err error
	if limit > 0 {
		rows, err = p.db.QueryContext(ctx, q+" LIMIT ?", limit)
	} else {
		rows, err = p.db.QueryContext(ctx, q)
	}
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return p.scanRows(rows)
}

func (p *SQLiteProjector) NextUID(ctx context.Context) (int, error) {
	var max sql.NullInt64
	err := p.db.QueryRowContext(ctx, `SELECT MAX(local_uid) FROM local_users`).Scan(&max)
	if err != nil {
		return 0, err
	}
	if !max.Valid {
		return 1, nil // no users yet; first non-root uid is 1
	}
	return int(max.Int64) + 1, nil
}

func (p *SQLiteProjector) scanUser(row *sql.Row) (*LocalUser, error) {
	var u LocalUser
	var createdStr, updatedStr string
	err := row.Scan(
		&u.LocalUID, &u.Email, &u.DisplayName, &u.PasswordHash, &u.Status,
		&createdStr, &updatedStr,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	u.CreatedAt, _ = time.Parse(time.RFC3339, createdStr)
	u.UpdatedAt, _ = time.Parse(time.RFC3339, updatedStr)
	return &u, nil
}

func (p *SQLiteProjector) scanRows(rows *sql.Rows) ([]LocalUser, error) {
	var out []LocalUser
	for rows.Next() {
		var u LocalUser
		var createdStr, updatedStr string
		if err := rows.Scan(
			&u.LocalUID, &u.Email, &u.DisplayName, &u.PasswordHash, &u.Status,
			&createdStr, &updatedStr,
		); err != nil {
			return nil, err
		}
		u.CreatedAt, _ = time.Parse(time.RFC3339, createdStr)
		u.UpdatedAt, _ = time.Parse(time.RFC3339, updatedStr)
		out = append(out, u)
	}
	return out, rows.Err()
}
