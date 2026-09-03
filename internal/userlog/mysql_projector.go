package userlog

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

// MySQLProjector implements UserProjector against a MySQL database.
// Uses the same schema as SQLiteProjector; timestamps stored as DATETIME NOT NULL.
type MySQLProjector struct {
	db *sql.DB
}

// NewMySQLProjector creates a projector backed by the given MySQL *sql.DB.
func NewMySQLProjector(db *sql.DB) *MySQLProjector {
	return &MySQLProjector{db: db}
}

func (p *MySQLProjector) Apply(ctx context.Context, rec Record) error {
	switch rec.Event.Type {
	case EventUserCreated:
		var d UserCreatedData
		if err := json.Unmarshal(rec.Event.Data, &d); err != nil {
			return fmt.Errorf("mysql projector apply created: %w", err)
		}
		now := rec.AppendedAt.UTC().Format("2006-01-02 15:04:05")
		_, err := p.db.ExecContext(ctx,
			`INSERT IGNORE INTO local_users
			 (local_uid, email, display_name, password_hash, status, created_at, updated_at)
			 VALUES (?, ?, ?, ?, 'active', ?, ?)`,
			d.LocalUID, d.Email, d.DisplayName, d.PasswordHash, now, now,
		)
		return err

	case EventUserUpdated:
		var d UserUpdatedData
		if err := json.Unmarshal(rec.Event.Data, &d); err != nil {
			return fmt.Errorf("mysql projector apply updated: %w", err)
		}
		now := rec.AppendedAt.UTC().Format("2006-01-02 15:04:05")
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
			return fmt.Errorf("mysql projector apply password_reset: %w", err)
		}
		now := rec.AppendedAt.UTC().Format("2006-01-02 15:04:05")
		_, err := p.db.ExecContext(ctx,
			`UPDATE local_users SET password_hash=?, updated_at=? WHERE local_uid=?`,
			d.PasswordHash, now, d.LocalUID,
		)
		return err

	case EventUserStatusChanged:
		var d UserStatusChangedData
		if err := json.Unmarshal(rec.Event.Data, &d); err != nil {
			return fmt.Errorf("mysql projector apply status_changed: %w", err)
		}
		now := rec.AppendedAt.UTC().Format("2006-01-02 15:04:05")
		_, err := p.db.ExecContext(ctx,
			`UPDATE local_users SET status=?, updated_at=? WHERE local_uid=?`,
			d.NewStatus, now, d.LocalUID,
		)
		return err

	case EventUserDeleted:
		var d UserDeletedData
		if err := json.Unmarshal(rec.Event.Data, &d); err != nil {
			return fmt.Errorf("mysql projector apply deleted: %w", err)
		}
		now := rec.AppendedAt.UTC().Format("2006-01-02 15:04:05")
		_, err := p.db.ExecContext(ctx,
			`UPDATE local_users SET status='deleted', updated_at=? WHERE local_uid=?`,
			now, d.LocalUID,
		)
		return err

	default:
		return nil
	}
}

func (p *MySQLProjector) Cursor(ctx context.Context) (uint64, error) {
	var seq uint64
	err := p.db.QueryRowContext(ctx, `SELECT last_seq FROM local_user_projector_cursor WHERE id=1`).Scan(&seq)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, nil
	}
	return seq, err
}

func (p *MySQLProjector) AdvanceCursor(ctx context.Context, seq uint64) error {
	_, err := p.db.ExecContext(ctx,
		`UPDATE local_user_projector_cursor SET last_seq=? WHERE id=1`,
		seq,
	)
	return err
}

func (p *MySQLProjector) GetByUID(ctx context.Context, uid int) (*LocalUser, error) {
	return p.scanUser(p.db.QueryRowContext(ctx,
		`SELECT local_uid, email, display_name, password_hash, status, created_at, updated_at
		 FROM local_users WHERE local_uid=? AND status != 'deleted'`,
		uid,
	))
}

func (p *MySQLProjector) GetByEmail(ctx context.Context, email string) (*LocalUser, error) {
	return p.scanUser(p.db.QueryRowContext(ctx,
		`SELECT local_uid, email, display_name, password_hash, status, created_at, updated_at
		 FROM local_users WHERE email=? AND status != 'deleted'`,
		email,
	))
}

func (p *MySQLProjector) ListUsers(ctx context.Context, limit int) ([]LocalUser, error) {
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

func (p *MySQLProjector) NextUID(ctx context.Context) (int, error) {
	var max sql.NullInt64
	err := p.db.QueryRowContext(ctx, `SELECT MAX(local_uid) FROM local_users`).Scan(&max)
	if err != nil {
		return 0, err
	}
	if !max.Valid {
		return 1, nil
	}
	return int(max.Int64) + 1, nil
}

func (p *MySQLProjector) scanUser(row *sql.Row) (*LocalUser, error) {
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
	// MySQL with parseTime=true returns time.Time; without it returns string.
	// We handle both: try RFC3339 first, then MySQL DATETIME format.
	u.CreatedAt = parseMyTime(createdStr)
	u.UpdatedAt = parseMyTime(updatedStr)
	return &u, nil
}

func (p *MySQLProjector) scanRows(rows *sql.Rows) ([]LocalUser, error) {
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
		u.CreatedAt = parseMyTime(createdStr)
		u.UpdatedAt = parseMyTime(updatedStr)
		out = append(out, u)
	}
	return out, rows.Err()
}

func parseMyTime(s string) time.Time {
	for _, layout := range []string{time.RFC3339, "2006-01-02 15:04:05", "2006-01-02T15:04:05Z"} {
		if t, err := time.Parse(layout, s); err == nil {
			return t.UTC()
		}
	}
	return time.Time{}
}
