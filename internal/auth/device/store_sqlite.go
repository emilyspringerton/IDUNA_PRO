package device

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"time"

	"idunapro/internal/auth"
)

// SQLiteStore implements Store for an embedded SQLite database.
// It is identical in behaviour to MySQLStore but adapts the two MySQL-specific
// patterns that appear in the device flow:
//   - UTC_TIMESTAMP(6) → pass time.Now().UTC() as a parameter
//   - ON DUPLICATE KEY UPDATE → INSERT OR REPLACE
type SQLiteStore struct{ db *sql.DB }

// NewSQLiteDeviceStore wraps an open SQLite *sql.DB for the device flow.
func NewSQLiteDeviceStore(db *sql.DB) *SQLiteStore { return &SQLiteStore{db: db} }

func (s *SQLiteStore) InsertDeviceRequest(ctx context.Context, req *Request) error {
	now := time.Now().UTC().Format(time.RFC3339Nano)
	res, err := s.db.ExecContext(ctx, `INSERT INTO device_auth_requests
(stream_id,device_code_hash,user_code_norm,user_code_display,status,created_at,expires_at,poll_interval_ms)
VALUES (?,?,?,?,'pending',?,?,?)`,
		req.StreamID, req.DeviceCodeHash[:], req.UserCodeNorm, req.UserCodeDisplay,
		now, req.ExpiresAt, req.PollIntervalMS)
	if err != nil {
		return err
	}
	req.ID, _ = res.LastInsertId()
	return nil
}

func (s *SQLiteStore) GetDeviceRequestByDeviceHash(ctx context.Context, deviceHash [32]byte) (*Request, error) {
	row := s.db.QueryRowContext(ctx,
		`SELECT id,stream_id,user_code_norm,user_code_display,status,expires_at,
		        poll_interval_ms,last_poll_at,authorized_user_id,exchange_code_plain,exchange_code_expires_at
		 FROM device_auth_requests WHERE device_code_hash=?`, deviceHash[:])
	var req Request
	if err := row.Scan(&req.ID, &req.StreamID, &req.UserCodeNorm, &req.UserCodeDisplay,
		&req.Status, &req.ExpiresAt, &req.PollIntervalMS, &req.LastPollAt,
		&req.AuthorizedUserID, &req.ExchangePlain, &req.ExchangeExpires); err != nil {
		return nil, err
	}
	return &req, nil
}

func (s *SQLiteStore) GetDeviceRequestByUserCode(ctx context.Context, userCodeNorm string) (*Request, error) {
	row := s.db.QueryRowContext(ctx,
		`SELECT id,stream_id,status,expires_at FROM device_auth_requests WHERE user_code_norm=?`, userCodeNorm)
	var req Request
	if err := row.Scan(&req.ID, &req.StreamID, &req.Status, &req.ExpiresAt); err != nil {
		return nil, err
	}
	return &req, nil
}

func (s *SQLiteStore) UpdatePollState(ctx context.Context, requestID int64, lastPollAt time.Time) error {
	_, err := s.db.ExecContext(ctx,
		`UPDATE device_auth_requests SET last_poll_at=?, poll_count=poll_count+1 WHERE id=?`,
		lastPollAt, requestID)
	return err
}

func (s *SQLiteStore) AuthorizeRequest(ctx context.Context, requestID int64, userID []byte, ipHash [32]byte, uaHash [32]byte, now time.Time) error {
	_, err := s.db.ExecContext(ctx,
		`UPDATE device_auth_requests
		 SET status='authorized', authorized_user_id=?, authorized_at=?, authorized_ip_hash=?, authorized_ua_hash=?
		 WHERE id=?`, userID, now, ipHash[:], uaHash[:], requestID)
	return err
}

func (s *SQLiteStore) UpsertExchangeForRequest(ctx context.Context, req *Request, exchange *Exchange) error {
	now := time.Now().UTC().Format(time.RFC3339Nano)
	// SQLite does not have ON DUPLICATE KEY UPDATE; use INSERT OR REPLACE.
	// The device_request_id is the natural unique key here.
	_, err := s.db.ExecContext(ctx,
		`INSERT OR REPLACE INTO exchange_codes
		 (exchange_code_hash, exchange_code_plain, user_id, device_request_id, created_at, expires_at, consumed_at)
		 VALUES (?, ?, ?, ?, ?, ?, NULL)`,
		exchange.ExchangeHash[:], exchange.ExchangePlain, exchange.UserID,
		exchange.DeviceRequest, now, exchange.ExpiresAt)
	if err != nil {
		return err
	}
	_, err = s.db.ExecContext(ctx,
		`UPDATE device_auth_requests
		 SET exchange_code_plain=?, exchange_code_hash=?, exchange_code_expires_at=?
		 WHERE id=?`,
		exchange.ExchangePlain, exchange.ExchangeHash[:], exchange.ExpiresAt, exchange.DeviceRequest)
	return err
}

func (s *SQLiteStore) GetExchangeByPlainOrHash(ctx context.Context, code string, hash [32]byte) (*Exchange, error) {
	row := s.db.QueryRowContext(ctx,
		`SELECT id, exchange_code_hash, exchange_code_plain, user_id, device_request_id, expires_at, consumed_at
		 FROM exchange_codes
		 WHERE exchange_code_hash=? OR exchange_code_plain=?
		 ORDER BY id DESC LIMIT 1`, hash[:], code)
	var ex Exchange
	var hashBytes []byte
	if err := row.Scan(&ex.ID, &hashBytes, &ex.ExchangePlain, &ex.UserID,
		&ex.DeviceRequest, &ex.ExpiresAt, &ex.ConsumedAt); err != nil {
		return nil, err
	}
	copy(ex.ExchangeHash[:], hashBytes)
	return &ex, nil
}

func (s *SQLiteStore) ConsumeExchange(ctx context.Context, exchangeID int64, deviceRequestID int64, now time.Time) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback() //nolint:errcheck
	res, err := tx.ExecContext(ctx,
		`UPDATE exchange_codes SET consumed_at=? WHERE id=? AND consumed_at IS NULL`, now, exchangeID)
	if err != nil {
		return err
	}
	aff, _ := res.RowsAffected()
	if aff == 0 {
		return errors.New("already consumed")
	}
	if _, err := tx.ExecContext(ctx,
		`UPDATE device_auth_requests SET status='consumed', exchange_code_plain=NULL WHERE id=?`,
		deviceRequestID); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *SQLiteStore) LoadUserForToken(ctx context.Context, userID []byte) (*auth.User, error) {
	row := s.db.QueryRowContext(ctx,
		`SELECT id, COALESCE(gamertag,''), status, roles_json,
		        honor_accepted_current, honor_code_sha, honor_code_version, COALESCE(honor_code_text,'')
		 FROM users WHERE id=?`, string(userID))
	var out auth.User
	var rolesJSON []byte
	var idStr string
	if err := row.Scan(&idStr, &out.Handle, &out.Status, &rolesJSON,
		&out.HonorAccepted, &out.HonorCurrentSHA, &out.HonorCurrentVer, &out.HonorCurrentText); err != nil {
		return nil, err
	}
	copy(out.ID[:], []byte(idStr))
	_ = json.Unmarshal(rolesJSON, &out.Roles)
	return &out, nil
}

func (s *SQLiteStore) AppendEvent(ctx context.Context, streamType, streamID, eventType string, payload []byte, occurredAt time.Time) error {
	now := time.Now().UTC().Format(time.RFC3339Nano)
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO event_store
		 (stream_type, stream_id, event_type, payload_json, occurred_at, created_at)
		 VALUES (?, ?, ?, ?, ?, ?)`,
		streamType, streamID, eventType, payload, occurredAt, now)
	return err
}
