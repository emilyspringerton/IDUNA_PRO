package store

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"idunapro/internal/auth"
	"idunapro/internal/util"
)

// MySQLStore implements IAMStore against a MySQL 8 database.
type MySQLStore struct {
	db *sql.DB
}

// NewMySQLStore creates a new MySQLStore backed by the provided *sql.DB.
func NewMySQLStore(db *sql.DB) *MySQLStore {
	return &MySQLStore{db: db}
}

// GetOrCreateUserByGoogleSubject looks up a user by google_subject; if missing,
// inserts a new PENDING user and emits a UserCreated IAM event.
func (s *MySQLStore) GetOrCreateUserByGoogleSubject(ctx context.Context, googleSub, email string) (*auth.User, bool, error) {
	u, err := s.getUserByGoogleSubject(ctx, googleSub)
	if err == nil {
		return u, false, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return nil, false, err
	}

	// User not found — create one.
	id, err := util.NewUUID()
	if err != nil {
		return nil, false, err
	}
	now := time.Now().UTC()
	_, err = s.db.ExecContext(ctx,
		`INSERT INTO users (id, email, google_subject, status, roles_json, created_at, updated_at)
		 VALUES (?, ?, ?, 'PENDING', JSON_ARRAY(), ?, ?)`,
		id, email, googleSub, now, now,
	)
	if err != nil {
		// Possible race — another request may have inserted concurrently.
		u2, err2 := s.getUserByGoogleSubject(ctx, googleSub)
		if err2 == nil {
			return u2, false, nil
		}
		return nil, false, err
	}

	payload, _ := json.Marshal(map[string]string{"email": email, "google_subject": googleSub})
	_ = s.AppendIAMEvent(ctx, "UserCreated", "USER", id, "", payload)

	u, err = s.getUserByID(ctx, id)
	if err != nil {
		return nil, false, err
	}
	return u, true, nil
}

// GetUserByID returns a user by their string UUID.
func (s *MySQLStore) GetUserByID(ctx context.Context, id string) (*auth.User, error) {
	return s.getUserByID(ctx, id)
}

// GetEffectivePermissions returns all distinct permission names granted to the
// user through their assigned roles, sorted lexicographically.
func (s *MySQLStore) GetEffectivePermissions(ctx context.Context, userID string) ([]string, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT DISTINCT p.name
		FROM user_roles ur
		JOIN role_permissions rp ON rp.role_id = ur.role_id
		JOIN permissions p       ON p.id = rp.permission_id
		WHERE ur.user_id = ?`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var perms []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return nil, err
		}
		perms = append(perms, name)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	// Append cap.query.full when user has active Emily+ subscription.
	sub, _ := s.GetUserSubscription(ctx, userID)
	if sub.IsActive() {
		perms = append(perms, "cap.query.full")
	}

	sort.Strings(perms)
	return perms, nil
}

// AppendIAMEvent inserts a row into iam_event_stream.
func (s *MySQLStore) AppendIAMEvent(ctx context.Context, eventType, aggregateType, aggregateID, operatorID string, payload []byte) error {
	if payload == nil {
		payload = []byte("null")
	}
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO iam_event_stream (event_type, aggregate_type, aggregate_id, operator_id, payload, recorded_at)
		 VALUES (?, ?, ?, ?, ?, ?)`,
		eventType, aggregateType, aggregateID, operatorID, payload, time.Now().UTC(),
	)
	return err
}

// UpdateUserStatus changes the user's status and emits a UserSuspended or
// UserActivated IAM event.
func (s *MySQLStore) UpdateUserStatus(ctx context.Context, userID, status, operatorID string) error {
	_, err := s.db.ExecContext(ctx,
		`UPDATE users SET status=?, updated_at=NOW(6) WHERE id=?`,
		status, userID,
	)
	if err != nil {
		return err
	}

	eventType := "UserStatusChanged"
	switch status {
	case "SUSPENDED":
		eventType = "UserSuspended"
	case "ACTIVE":
		eventType = "UserActivated"
	}
	payload, _ := json.Marshal(map[string]string{"status": status})
	_ = s.AppendIAMEvent(ctx, eventType, "USER", userID, operatorID, payload)
	return nil
}

func (s *MySQLStore) AcceptHonorCode(ctx context.Context, userID string, version int, sha, text, operatorID string) error {
	_, err := s.db.ExecContext(ctx,
		`UPDATE users SET honor_accepted_current=1, honor_code_sha=?, honor_code_version=?, honor_code_text=?, updated_at=NOW(6) WHERE id=?`,
		sha, version, text, userID,
	)
	if err != nil {
		return err
	}
	payload, _ := json.Marshal(map[string]any{"version": version, "sha256": sha})
	_ = s.AppendIAMEvent(ctx, "HonorCodeAccepted", "USER", userID, operatorID, payload)
	return nil
}

func (s *MySQLStore) ClaimHandle(ctx context.Context, userID, handle, operatorID string) error {
	var existing string
	err := s.db.QueryRowContext(ctx, `SELECT COALESCE(gamertag,'') FROM users WHERE id=?`, userID).Scan(&existing)
	if err != nil {
		return err
	}
	if existing != "" {
		return ErrHandleAlreadySet
	}
	_, err = s.db.ExecContext(ctx,
		`UPDATE users SET gamertag=?, updated_at=NOW(6) WHERE id=?`,
		handle, userID,
	)
	if err != nil {
		if mysqlIsDuplicateKeyErr(err) {
			return ErrHandleTaken
		}
		return err
	}
	payload, _ := json.Marshal(map[string]string{"handle": handle})
	_ = s.AppendIAMEvent(ctx, "GamertagClaimed", "USER", userID, operatorID, payload)
	return nil
}

func (s *MySQLStore) IsHandleAvailable(ctx context.Context, handle string) (bool, error) {
	var count int
	err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM users WHERE gamertag=?`, handle).Scan(&count)
	if err != nil {
		return false, err
	}
	return count == 0, nil
}

// mysqlIsDuplicateKeyErr reports whether err is a MySQL duplicate-key
// violation (error 1062), without importing the mysql driver package here.
func mysqlIsDuplicateKeyErr(err error) bool {
	return err != nil && strings.Contains(err.Error(), "Error 1062")
}

// --- Admin operations ---

// ListUsers returns up to limit users ordered by created_at desc.
func (s *MySQLStore) ListUsers(ctx context.Context, limit int) ([]auth.User, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, COALESCE(email,''), COALESCE(gamertag,''), status,
		       COALESCE(roles_json, JSON_ARRAY()),
		       honor_accepted_current, COALESCE(honor_code_sha,''), honor_code_version, COALESCE(honor_code_text,'')
		FROM users ORDER BY created_at DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanUsers(rows)
}

// AssignRole grants a role to a user.
func (s *MySQLStore) AssignRole(ctx context.Context, userID, roleID, operatorID string) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT IGNORE INTO user_roles (user_id, role_id) VALUES (?, ?)`, userID, roleID)
	if err != nil {
		return err
	}
	payload, _ := json.Marshal(map[string]string{"role_id": roleID})
	_ = s.AppendIAMEvent(ctx, "RoleAssigned", "USER", userID, operatorID, payload)
	return nil
}

// RevokeRole removes a role from a user.
func (s *MySQLStore) RevokeRole(ctx context.Context, userID, roleID, operatorID string) error {
	_, err := s.db.ExecContext(ctx,
		`DELETE FROM user_roles WHERE user_id=? AND role_id=?`, userID, roleID)
	if err != nil {
		return err
	}
	payload, _ := json.Marshal(map[string]string{"role_id": roleID})
	_ = s.AppendIAMEvent(ctx, "RoleRevoked", "USER", userID, operatorID, payload)
	return nil
}

// ListRoles returns all defined roles.
func (s *MySQLStore) ListRoles(ctx context.Context) ([]auth.Role, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, name, COALESCE(description,'') FROM roles ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var roles []auth.Role
	for rows.Next() {
		var r auth.Role
		if err := rows.Scan(&r.ID, &r.Name, &r.Description); err != nil {
			return nil, err
		}
		roles = append(roles, r)
	}
	return roles, rows.Err()
}

// ListAgents returns all agents ordered by created_at desc.
func (s *MySQLStore) ListAgents(ctx context.Context) ([]auth.Agent, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, owner_user_id, name, type, status, created_at, updated_at, COALESCE(api_key_hash,'')
		FROM agents ORDER BY created_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var agents []auth.Agent
	for rows.Next() {
		var a auth.Agent
		var apiKeyHash string
		if err := rows.Scan(&a.ID, &a.OwnerUserID, &a.Name, &a.Type, &a.Status, &a.CreatedAt, &a.UpdatedAt, &apiKeyHash); err != nil {
			return nil, err
		}
		a.HasCredential = apiKeyHash != ""
		agents = append(agents, a)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	for i := range agents {
		perms, err := s.GetAgentPermissions(ctx, agents[i].ID)
		if err != nil {
			return nil, err
		}
		agents[i].Permissions = perms
	}
	return agents, nil
}

// CreateAgent inserts a new agent and emits an AgentCreated event.
func (s *MySQLStore) CreateAgent(ctx context.Context, ownerUserID, name, agentType, operatorID string) (*auth.Agent, error) {
	id, err := util.NewUUID()
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	_, err = s.db.ExecContext(ctx,
		`INSERT INTO agents (id, owner_user_id, name, type, status, created_at, updated_at)
		 VALUES (?, ?, ?, ?, 'PENDING', ?, ?)`,
		id, ownerUserID, name, agentType, now, now,
	)
	if err != nil {
		return nil, err
	}
	payload, _ := json.Marshal(map[string]string{"name": name, "type": agentType, "owner": ownerUserID})
	_ = s.AppendIAMEvent(ctx, "AgentCreated", "AGENT", id, operatorID, payload)
	return &auth.Agent{
		ID:          id,
		OwnerUserID: ownerUserID,
		Name:        name,
		Type:        agentType,
		Status:      "PENDING",
		CreatedAt:   now,
		UpdatedAt:   now,
	}, nil
}

// maybeActivateAgent flips a PENDING agent to ACTIVE once it has both a
// credential (api_key_hash set) and at least one granted permission. No-op
// for agents in any other status (already ACTIVE, SUSPENDED, etc).
func (s *MySQLStore) maybeActivateAgent(ctx context.Context, agentID, operatorID string) error {
	var status string
	var apiKeyHash string
	err := s.db.QueryRowContext(ctx,
		`SELECT status, COALESCE(api_key_hash,'') FROM agents WHERE id=?`, agentID).Scan(&status, &apiKeyHash)
	if err != nil {
		return err
	}
	if status != "PENDING" || apiKeyHash == "" {
		return nil
	}
	var permCount int
	if err := s.db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM agent_permissions WHERE agent_id=?`, agentID).Scan(&permCount); err != nil {
		return err
	}
	if permCount == 0 {
		return nil
	}
	_, err = s.db.ExecContext(ctx,
		`UPDATE agents SET status='ACTIVE', updated_at=? WHERE id=?`, time.Now().UTC(), agentID)
	if err != nil {
		return err
	}
	_ = s.AppendIAMEvent(ctx, "AgentActivated", "AGENT", agentID, operatorID, nil)
	return nil
}

// GrantAgentPermission grants a named permission to an agent, emitting an
// AgentPermissionGranted event, then activates the agent if it now qualifies.
func (s *MySQLStore) GrantAgentPermission(ctx context.Context, agentID, permissionName, operatorID string) error {
	var permID string
	if err := s.db.QueryRowContext(ctx,
		`SELECT id FROM permissions WHERE name=?`, permissionName).Scan(&permID); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return fmt.Errorf("permission %q not found", permissionName)
		}
		return err
	}
	_, err := s.db.ExecContext(ctx,
		`INSERT IGNORE INTO agent_permissions (agent_id, permission_id, granted_at) VALUES (?, ?, ?)`,
		agentID, permID, time.Now().UTC())
	if err != nil {
		return err
	}
	payload, _ := json.Marshal(map[string]string{"permission": permissionName})
	_ = s.AppendIAMEvent(ctx, "AgentPermissionGranted", "AGENT", agentID, operatorID, payload)
	return s.maybeActivateAgent(ctx, agentID, operatorID)
}

// RevokeAgentPermission removes a named permission from an agent, emitting an
// AgentPermissionRevoked event.
func (s *MySQLStore) RevokeAgentPermission(ctx context.Context, agentID, permissionName, operatorID string) error {
	var permID string
	if err := s.db.QueryRowContext(ctx,
		`SELECT id FROM permissions WHERE name=?`, permissionName).Scan(&permID); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return fmt.Errorf("permission %q not found", permissionName)
		}
		return err
	}
	_, err := s.db.ExecContext(ctx,
		`DELETE FROM agent_permissions WHERE agent_id=? AND permission_id=?`, agentID, permID)
	if err != nil {
		return err
	}
	payload, _ := json.Marshal(map[string]string{"permission": permissionName})
	_ = s.AppendIAMEvent(ctx, "AgentPermissionRevoked", "AGENT", agentID, operatorID, payload)
	return nil
}

// UpdateAgentStatus changes an agent's status and emits an event.
func (s *MySQLStore) UpdateAgentStatus(ctx context.Context, agentID, status, operatorID string) error {
	_, err := s.db.ExecContext(ctx,
		`UPDATE agents SET status=?, updated_at=NOW(6) WHERE id=?`, status, agentID)
	if err != nil {
		return err
	}
	eventType := "AgentStatusChanged"
	if status == "SUSPENDED" {
		eventType = "AgentSuspended"
	}
	payload, _ := json.Marshal(map[string]string{"status": status})
	_ = s.AppendIAMEvent(ctx, eventType, "AGENT", agentID, operatorID, payload)
	return nil
}

// UpsertClusterHeartbeat upserts a cluster heartbeat record (INSERT ... ON DUPLICATE KEY UPDATE).
func (s *MySQLStore) UpsertClusterHeartbeat(ctx context.Context, h auth.ClusterHeartbeat) error {
	caps := strings.Join(h.Capabilities, ",")
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO cluster_heartbeats (agent_id, cluster_id, capabilities, load_score, last_seen)
		VALUES (?, ?, ?, ?, ?)
		ON DUPLICATE KEY UPDATE
			cluster_id   = VALUES(cluster_id),
			capabilities = VALUES(capabilities),
			load_score   = VALUES(load_score),
			last_seen    = VALUES(last_seen)
	`, h.AgentID, h.ClusterID, caps, h.LoadScore, h.LastSeen.UTC())
	return err
}

// ListActiveClusterHeartbeats returns clusters whose last_seen is within maxAge.
func (s *MySQLStore) ListActiveClusterHeartbeats(ctx context.Context, maxAge time.Duration) ([]auth.ClusterHeartbeat, error) {
	cutoff := time.Now().UTC().Add(-maxAge)
	rows, err := s.db.QueryContext(ctx, `
		SELECT agent_id, cluster_id, capabilities, load_score, last_seen
		FROM cluster_heartbeats
		WHERE last_seen >= ?
		ORDER BY load_score ASC, last_seen DESC
	`, cutoff)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []auth.ClusterHeartbeat
	for rows.Next() {
		var h auth.ClusterHeartbeat
		var caps string
		if err := rows.Scan(&h.AgentID, &h.ClusterID, &caps, &h.LoadScore, &h.LastSeen); err != nil {
			return nil, err
		}
		if caps != "" {
			h.Capabilities = strings.Split(caps, ",")
		}
		out = append(out, h)
	}
	return out, rows.Err()
}

// ListIAMEvents returns the most recent limit events from iam_event_stream.
func (s *MySQLStore) ListIAMEvents(ctx context.Context, limit int) ([]auth.IAMEvent, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT event_id, event_type, aggregate_type, aggregate_id,
		       COALESCE(operator_id,''), COALESCE(payload,'null'), recorded_at
		FROM iam_event_stream ORDER BY event_id DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var events []auth.IAMEvent
	for rows.Next() {
		var e auth.IAMEvent
		if err := rows.Scan(&e.EventID, &e.EventType, &e.AggregateType, &e.AggregateID,
			&e.OperatorID, &e.Payload, &e.RecordedAt); err != nil {
			return nil, err
		}
		events = append(events, e)
	}
	return events, rows.Err()
}

// --- internal helpers ---

func (s *MySQLStore) getUserByGoogleSubject(ctx context.Context, googleSub string) (*auth.User, error) {
	row := s.db.QueryRowContext(ctx, `
		SELECT id, COALESCE(email,''), COALESCE(gamertag,''), status,
		       COALESCE(roles_json, JSON_ARRAY()),
		       honor_accepted_current, COALESCE(honor_code_sha,''), honor_code_version, COALESCE(honor_code_text,'')
		FROM users WHERE google_subject=?`, googleSub)
	return scanUser(row)
}

func (s *MySQLStore) getUserByID(ctx context.Context, id string) (*auth.User, error) {
	row := s.db.QueryRowContext(ctx, `
		SELECT id, COALESCE(email,''), COALESCE(gamertag,''), status,
		       COALESCE(roles_json, JSON_ARRAY()),
		       honor_accepted_current, COALESCE(honor_code_sha,''), honor_code_version, COALESCE(honor_code_text,'')
		FROM users WHERE id=?`, id)
	return scanUser(row)
}

func scanUsers(rows *sql.Rows) ([]auth.User, error) {
	var users []auth.User
	for rows.Next() {
		var u auth.User
		var idStr string
		var rolesJSON []byte
		if err := rows.Scan(
			&idStr, &u.Email, &u.Handle, &u.Status, &rolesJSON,
			&u.HonorAccepted, &u.HonorCurrentSHA, &u.HonorCurrentVer, &u.HonorCurrentText,
		); err != nil {
			return nil, err
		}
		u.IDString = idStr
		copy(u.ID[:], []byte(idStr))
		_ = json.Unmarshal(rolesJSON, &u.Roles)
		users = append(users, u)
	}
	return users, rows.Err()
}

func scanUser(row *sql.Row) (*auth.User, error) {
	var u auth.User
	var idStr string
	var rolesJSON []byte
	if err := row.Scan(
		&idStr,
		&u.Email,
		&u.Handle,
		&u.Status,
		&rolesJSON,
		&u.HonorAccepted,
		&u.HonorCurrentSHA,
		&u.HonorCurrentVer,
		&u.HonorCurrentText,
	); err != nil {
		return nil, err
	}
	u.IDString = idStr
	// Also populate the legacy [16]byte ID for compatibility with device flow.
	copy(u.ID[:], []byte(idStr))
	_ = json.Unmarshal(rolesJSON, &u.Roles)
	return &u, nil
}

// hashAgentSecret returns a hex-encoded SHA-256 hash of the plaintext secret,
// salted with the agent ID to prevent rainbow-table attacks.
// M2M API keys are long random strings, so SHA-256 is appropriate (bcrypt
// is unnecessary and would add an external dependency).
func hashAgentSecret(agentID, plaintext string) string {
	h := sha256.New()
	h.Write([]byte(agentID))
	h.Write([]byte(":"))
	h.Write([]byte(plaintext))
	return hex.EncodeToString(h.Sum(nil))
}

// SetAgentCredential stores a SHA-256 hash of the plaintext secret for the agent.
func (s *MySQLStore) SetAgentCredential(ctx context.Context, agentID, plaintextSecret, operatorID string) error {
	hash := hashAgentSecret(agentID, plaintextSecret)
	_, err := s.db.ExecContext(ctx,
		`UPDATE agents SET api_key_hash=?, updated_at=? WHERE id=?`,
		hash, time.Now().UTC(), agentID,
	)
	if err != nil {
		return fmt.Errorf("set agent credential: %w", err)
	}
	payload, _ := json.Marshal(map[string]string{"agent_id": agentID})
	_ = s.AppendIAMEvent(ctx, "AgentCredentialSet", "AGENT", agentID, operatorID, payload)
	return s.maybeActivateAgent(ctx, agentID, operatorID)
}

// AuthenticateAgent verifies agent name + secret and returns the agent with
// its effective permissions. Returns error when name not found, no credential
// set, wrong secret, or agent not ACTIVE.
func (s *MySQLStore) AuthenticateAgent(ctx context.Context, agentName, plaintextSecret string) (*auth.Agent, error) {
	row := s.db.QueryRowContext(ctx,
		`SELECT id, owner_user_id, name, type, status, COALESCE(api_key_hash,'')
		 FROM agents WHERE name=?`, agentName)
	var a auth.Agent
	var storedHash string
	if err := row.Scan(&a.ID, &a.OwnerUserID, &a.Name, &a.Type, &a.Status, &storedHash); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, fmt.Errorf("agent not found")
		}
		return nil, err
	}
	if a.Status != "ACTIVE" {
		return nil, fmt.Errorf("agent is not active (status=%s)", a.Status)
	}
	if storedHash == "" {
		return nil, fmt.Errorf("no credential provisioned for agent %q", agentName)
	}
	expected := hashAgentSecret(a.ID, plaintextSecret)
	if storedHash != expected {
		return nil, fmt.Errorf("invalid agent secret")
	}
	perms, err := s.GetAgentPermissions(ctx, a.ID)
	if err != nil {
		return nil, fmt.Errorf("get agent permissions: %w", err)
	}
	a.Permissions = perms
	return &a, nil
}

func (s *MySQLStore) GetAgentByID(ctx context.Context, agentID string) (*auth.Agent, error) {
	row := s.db.QueryRowContext(ctx,
		`SELECT id, owner_user_id, name, type, status FROM agents WHERE id=?`, agentID)
	var a auth.Agent
	if err := row.Scan(&a.ID, &a.OwnerUserID, &a.Name, &a.Type, &a.Status); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, fmt.Errorf("agent not found")
		}
		return nil, err
	}
	perms, err := s.GetAgentPermissions(ctx, a.ID)
	if err != nil {
		return nil, fmt.Errorf("get agent permissions: %w", err)
	}
	a.Permissions = perms
	return &a, nil
}

// --- Apples (HQ-SPEC-IAM-096) ---

// AppendApple inserts a golden documentation record and emits ApplePublished to iam_event_stream.
// The insert and event emission run inside a single transaction.
func (s *MySQLStore) AppendApple(ctx context.Context, apple auth.AppleRecord) (int64, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback() //nolint:errcheck

	metadata := apple.Metadata
	if metadata == nil {
		metadata = []byte("null")
	}
	res, err := tx.ExecContext(ctx,
		`INSERT INTO apples (agent_id, source_repo, run_id, apple_type, title, body, metadata, recorded_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		apple.AgentID, apple.SourceRepo, apple.RunID, apple.AppleType,
		apple.Title, apple.Body, metadata, time.Now().UTC(),
	)
	if err != nil {
		return 0, fmt.Errorf("insert apple: %w", err)
	}
	id, err := res.LastInsertId()
	if err != nil {
		return 0, fmt.Errorf("last insert id: %w", err)
	}

	payload, _ := json.Marshal(map[string]any{
		"apple_id":    id,
		"source_repo": apple.SourceRepo,
		"run_id":      apple.RunID,
		"apple_type":  apple.AppleType,
		"title":       apple.Title,
	})
	_, err = tx.ExecContext(ctx,
		`INSERT INTO iam_event_stream (event_type, aggregate_type, aggregate_id, operator_id, payload, recorded_at)
		 VALUES (?, ?, ?, ?, ?, ?)`,
		"ApplePublished", "AGENT", apple.AgentID, apple.AgentID, payload, time.Now().UTC(),
	)
	if err != nil {
		return 0, fmt.Errorf("append iam event: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return 0, fmt.Errorf("commit: %w", err)
	}
	return id, nil
}

// ListApples returns up to limit apples ordered by recorded_at DESC.
// Empty filter strings are ignored. limit <= 0 defaults to 50, max 500.
func (s *MySQLStore) ListApples(ctx context.Context, agentID, sourceRepo, appleType string, limit int) ([]auth.AppleRecord, error) {
	if limit <= 0 {
		limit = 50
	}
	if limit > 500 {
		limit = 500
	}
	q := `SELECT id, agent_id, source_repo, run_id, apple_type, title, COALESCE(metadata,'null'), recorded_at
	      FROM apples WHERE 1=1`
	args := []any{}
	if agentID != "" {
		q += " AND agent_id = ?"
		args = append(args, agentID)
	}
	if sourceRepo != "" {
		q += " AND source_repo = ?"
		args = append(args, sourceRepo)
	}
	if appleType != "" {
		q += " AND apple_type = ?"
		args = append(args, appleType)
	}
	q += " ORDER BY recorded_at DESC LIMIT ?"
	args = append(args, limit)

	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var apples []auth.AppleRecord
	for rows.Next() {
		var a auth.AppleRecord
		if err := rows.Scan(&a.ID, &a.AgentID, &a.SourceRepo, &a.RunID, &a.AppleType, &a.Title, &a.Metadata, &a.RecordedAt); err != nil {
			return nil, err
		}
		apples = append(apples, a)
	}
	return apples, rows.Err()
}

// GetApple returns a single apple by its integer ID, including body and metadata.
func (s *MySQLStore) GetApple(ctx context.Context, id int64) (*auth.AppleRecord, error) {
	row := s.db.QueryRowContext(ctx,
		`SELECT id, agent_id, source_repo, run_id, apple_type, title, body, COALESCE(metadata,'null'), recorded_at
		 FROM apples WHERE id = ?`, id)
	var a auth.AppleRecord
	if err := row.Scan(&a.ID, &a.AgentID, &a.SourceRepo, &a.RunID, &a.AppleType, &a.Title, &a.Body, &a.Metadata, &a.RecordedAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, fmt.Errorf("apple %d not found", id)
		}
		return nil, err
	}
	return &a, nil
}

func (s *MySQLStore) PatchAppleMetadata(ctx context.Context, id int64, updates map[string]json.RawMessage) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback() //nolint:errcheck

	var raw []byte
	if err := tx.QueryRowContext(ctx, `SELECT COALESCE(metadata,'null') FROM apples WHERE id = ?`, id).Scan(&raw); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return fmt.Errorf("apple %d not found", id)
		}
		return fmt.Errorf("select metadata: %w", err)
	}

	merged := map[string]json.RawMessage{}
	if len(raw) > 0 && string(raw) != "null" {
		if err := json.Unmarshal(raw, &merged); err != nil {
			return fmt.Errorf("existing metadata not a JSON object, cannot merge: %w", err)
		}
	}
	for k, v := range updates {
		merged[k] = v
	}
	mergedRaw, err := json.Marshal(merged)
	if err != nil {
		return fmt.Errorf("marshal merged metadata: %w", err)
	}

	res, err := tx.ExecContext(ctx, `UPDATE apples SET metadata = ? WHERE id = ?`, mergedRaw, id)
	if err != nil {
		return fmt.Errorf("update metadata: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return fmt.Errorf("apple %d not found", id)
	}

	keys := make([]string, 0, len(updates))
	for k := range updates {
		keys = append(keys, k)
	}
	payload, _ := json.Marshal(map[string]any{"apple_id": id, "keys": keys})
	_, err = tx.ExecContext(ctx,
		`INSERT INTO iam_event_stream
		 (event_type, aggregate_type, aggregate_id, operator_id, payload, recorded_at)
		 VALUES (?, ?, ?, ?, ?, CURRENT_TIMESTAMP(6))`,
		"AppleEnriched", "AGENT", "system", "system", payload,
	)
	if err != nil {
		return fmt.Errorf("append iam event: %w", err)
	}
	return tx.Commit()
}

// GetAgentPermissions returns the effective permissions for an agent via
// its agent_permissions join table.
// --- Push tokens ---

func (s *MySQLStore) UpsertPushToken(ctx context.Context, token auth.PushToken) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO push_tokens (agent_name, platform, fcm_token, fingerprint)
		 VALUES (?, ?, ?, ?)
		 ON DUPLICATE KEY UPDATE
		   fcm_token = VALUES(fcm_token),
		   platform = VALUES(platform),
		   last_used_at = CURRENT_TIMESTAMP(6)`,
		token.AgentName, token.Platform, token.FCMToken, token.Fingerprint,
	)
	return err
}

func (s *MySQLStore) GetPushToken(ctx context.Context, agentName string) (*auth.PushToken, error) {
	row := s.db.QueryRowContext(ctx,
		`SELECT id, agent_name, platform, fcm_token, COALESCE(fingerprint,''), registered_at, last_used_at
		 FROM push_tokens WHERE agent_name = ?
		 ORDER BY last_used_at DESC LIMIT 1`, agentName)
	var t auth.PushToken
	if err := row.Scan(&t.ID, &t.AgentName, &t.Platform, &t.FCMToken, &t.Fingerprint, &t.RegisteredAt, &t.LastUsedAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	return &t, nil
}

func (s *MySQLStore) CreateCameraObservation(ctx context.Context, obs auth.CameraObservation) (int64, error) {
	res, err := s.db.ExecContext(ctx,
		`INSERT INTO camera_observations (agent_name, image_data, media_type, prompt, status, created_at)
		 VALUES (?, ?, ?, ?, 'pending', NOW())`,
		obs.AgentName, obs.ImageData, obs.MediaType, obs.Prompt,
	)
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

func (s *MySQLStore) UpdateCameraObservation(ctx context.Context, id int64, analysis string, appleID int64, status string) error {
	_, err := s.db.ExecContext(ctx,
		`UPDATE camera_observations SET analysis=?, apple_id=?, status=?, processed_at=NOW() WHERE id=?`,
		analysis, appleID, status, id,
	)
	return err
}

func (s *MySQLStore) GetCameraObservation(ctx context.Context, id int64) (*auth.CameraObservation, error) {
	row := s.db.QueryRowContext(ctx,
		`SELECT id, agent_name, image_data, media_type, COALESCE(prompt,''), COALESCE(analysis,''),
		        COALESCE(apple_id,0), status, created_at, processed_at
		 FROM camera_observations WHERE id=?`, id)
	var obs auth.CameraObservation
	var processedAt sql.NullTime
	if err := row.Scan(&obs.ID, &obs.AgentName, &obs.ImageData, &obs.MediaType,
		&obs.Prompt, &obs.Analysis, &obs.AppleID, &obs.Status, &obs.CreatedAt, &processedAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	if processedAt.Valid {
		obs.ProcessedAt = &processedAt.Time
	}
	return &obs, nil
}

func (s *MySQLStore) ListCameraObservations(ctx context.Context, agentName, status string, limit int) ([]auth.CameraObservation, error) {
	if limit <= 0 {
		limit = 50
	}
	var rows *sql.Rows
	var err error
	if status != "" {
		rows, err = s.db.QueryContext(ctx,
			`SELECT id, agent_name, image_data, media_type, COALESCE(prompt,''), COALESCE(analysis,''),
			        COALESCE(apple_id,0), status, created_at, processed_at
			 FROM camera_observations WHERE agent_name=? AND status=?
			 ORDER BY created_at DESC LIMIT ?`, agentName, status, limit)
	} else {
		rows, err = s.db.QueryContext(ctx,
			`SELECT id, agent_name, image_data, media_type, COALESCE(prompt,''), COALESCE(analysis,''),
			        COALESCE(apple_id,0), status, created_at, processed_at
			 FROM camera_observations WHERE agent_name=?
			 ORDER BY created_at DESC LIMIT ?`, agentName, limit)
	}
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []auth.CameraObservation
	for rows.Next() {
		var obs auth.CameraObservation
		var processedAt sql.NullTime
		if err := rows.Scan(&obs.ID, &obs.AgentName, &obs.ImageData, &obs.MediaType,
			&obs.Prompt, &obs.Analysis, &obs.AppleID, &obs.Status, &obs.CreatedAt, &processedAt); err != nil {
			return nil, err
		}
		if processedAt.Valid {
			obs.ProcessedAt = &processedAt.Time
		}
		out = append(out, obs)
	}
	return out, rows.Err()
}

func (s *MySQLStore) CreateSprintItem(ctx context.Context, item auth.SprintItem) (int64, error) {
	res, err := s.db.ExecContext(ctx,
		`INSERT INTO heimdal_sprints (agent_name, requirement, criteria_json, status, created_at, updated_at)
		 VALUES (?, ?, '[]', 'pending', NOW(), NOW())`,
		item.AgentName, item.Requirement,
	)
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

func (s *MySQLStore) UpdateSprintItem(ctx context.Context, id int64, criteriaJSON, roadmapID, status string, appleID int64) error {
	_, err := s.db.ExecContext(ctx,
		`UPDATE heimdal_sprints SET criteria_json=?, roadmap_id=?, status=?, apple_id=?, updated_at=NOW() WHERE id=?`,
		criteriaJSON, roadmapID, status, appleID, id,
	)
	return err
}

func (s *MySQLStore) GetSprintItem(ctx context.Context, id int64) (*auth.SprintItem, error) {
	row := s.db.QueryRowContext(ctx,
		`SELECT id, agent_name, requirement, criteria_json, COALESCE(roadmap_id,''), status,
		        COALESCE(apple_id,0), created_at, updated_at
		 FROM heimdal_sprints WHERE id=?`, id)
	var item auth.SprintItem
	if err := row.Scan(&item.ID, &item.AgentName, &item.Requirement, &item.CriteriaJSON,
		&item.RoadmapID, &item.Status, &item.AppleID, &item.CreatedAt, &item.UpdatedAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	return &item, nil
}

func (s *MySQLStore) ListSprintItems(ctx context.Context, agentName, status string, limit int) ([]auth.SprintItem, error) {
	if limit <= 0 {
		limit = 50
	}
	query := `SELECT id, agent_name, requirement, criteria_json, COALESCE(roadmap_id,''), status,
	                 COALESCE(apple_id,0), created_at, updated_at
	          FROM heimdal_sprints`
	var args []any
	var where []string
	if agentName != "" {
		where = append(where, "agent_name=?")
		args = append(args, agentName)
	}
	if status != "" {
		where = append(where, "status=?")
		args = append(args, status)
	}
	if len(where) > 0 {
		query += " WHERE " + strings.Join(where, " AND ")
	}
	query += " ORDER BY created_at DESC LIMIT ?"
	args = append(args, limit)

	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []auth.SprintItem
	for rows.Next() {
		var item auth.SprintItem
		if err := rows.Scan(&item.ID, &item.AgentName, &item.Requirement, &item.CriteriaJSON,
			&item.RoadmapID, &item.Status, &item.AppleID, &item.CreatedAt, &item.UpdatedAt); err != nil {
			return nil, err
		}
		out = append(out, item)
	}
	return out, rows.Err()
}

// GetUserSubscription returns the active subscription for userID, or nil if none.
func (s *MySQLStore) GetUserSubscription(ctx context.Context, userID string) (*auth.Subscription, error) {
	row := s.db.QueryRowContext(ctx, `
		SELECT id, user_id, plan, status, expires_at, created_at, updated_at
		FROM user_subscriptions WHERE user_id = ? ORDER BY id DESC LIMIT 1`, userID)
	var sub auth.Subscription
	var expiresAt sql.NullTime
	err := row.Scan(&sub.ID, &sub.UserID, &sub.Plan, &sub.Status,
		&expiresAt, &sub.CreatedAt, &sub.UpdatedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if expiresAt.Valid {
		sub.ExpiresAt = expiresAt.Time
	}
	return &sub, nil
}

// UpsertUserSubscription inserts or updates the subscription for sub.UserID.
func (s *MySQLStore) UpsertUserSubscription(ctx context.Context, sub auth.Subscription) error {
	var expiresAt *time.Time
	if !sub.ExpiresAt.IsZero() {
		t := sub.ExpiresAt.UTC()
		expiresAt = &t
	}
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO user_subscriptions (user_id, plan, status, expires_at)
		VALUES (?, ?, ?, ?)
		ON DUPLICATE KEY UPDATE
			plan       = VALUES(plan),
			status     = VALUES(status),
			expires_at = VALUES(expires_at),
			updated_at = NOW()`,
		sub.UserID, sub.Plan, sub.Status, expiresAt)
	return err
}

// DailyTokenStats aggregates tokens_used from Apple metadata for the last `days` days.
func (s *MySQLStore) DailyTokenStats(ctx context.Context, days int) ([]auth.DailyTokenStat, error) {
	if days <= 0 {
		days = 7
	}
	rows, err := s.db.QueryContext(ctx, `
		SELECT
			DATE(recorded_at) AS day,
			COALESCE(SUM(CAST(JSON_EXTRACT(metadata, '$.tokens_used') AS UNSIGNED)), 0) AS tokens
		FROM apples
		WHERE recorded_at >= DATE_SUB(NOW(), INTERVAL ? DAY)
		GROUP BY day
		ORDER BY day ASC`,
		days)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	byDate := make(map[string]int64, days)
	for rows.Next() {
		var day string
		var tokens int64
		if err := rows.Scan(&day, &tokens); err != nil {
			return nil, err
		}
		byDate[day] = tokens
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	stats := make([]auth.DailyTokenStat, days)
	for i := range stats {
		d := time.Now().UTC().AddDate(0, 0, -(days-1-i)).Format("2006-01-02")
		stats[i] = auth.DailyTokenStat{Date: d, Tokens: byDate[d]}
	}
	return stats, nil
}

func (s *MySQLStore) GetAgentPermissions(ctx context.Context, agentID string) ([]string, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT p.name FROM permissions p
		 JOIN agent_permissions ap ON ap.permission_id = p.id
		 WHERE ap.agent_id = ?
		 ORDER BY p.name`, agentID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var perms []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return nil, err
		}
		perms = append(perms, name)
	}
	return perms, rows.Err()
}

// ── GFD subscription tiers (S124-02) — MySQL stubs ───────────────────────────
// MySQL is used for bob-agent schema admin. GFD tier operations target SQLite (truestore).
// These stubs satisfy the IAMStore interface.

func (s *MySQLStore) ListSubscriptionTiers(_ context.Context) ([]GFDTier, error) {
	return nil, nil
}

func (s *MySQLStore) GetGFDUserTier(_ context.Context, _ string) (*string, error) {
	return nil, nil
}

func (s *MySQLStore) SetGFDUserTier(_ context.Context, _, _ string) error { return nil }

func (s *MySQLStore) RecordStripeEvent(_ context.Context, _, _, _, _ string) error { return nil }

// ── Monitors — MySQL stubs ────────────────────────────────────────────────────
// Monitor operations target SQLite (truestore). These stubs satisfy IAMStore.

func (s *MySQLStore) CreateMonitor(_ context.Context, _ auth.Monitor) (int64, error) {
	return 0, nil
}
func (s *MySQLStore) GetMonitorBySlug(_ context.Context, _ string) (*auth.Monitor, error) {
	return nil, nil
}
func (s *MySQLStore) GetMonitorByID(_ context.Context, _ int64) (*auth.Monitor, error) {
	return nil, nil
}
func (s *MySQLStore) ListMonitors(_ context.Context, _ string) ([]auth.Monitor, error) {
	return nil, nil
}
func (s *MySQLStore) UpdateMonitor(_ context.Context, _ auth.Monitor) error          { return nil }
func (s *MySQLStore) RecordCheckin(_ context.Context, _ string, _ time.Time) error   { return nil }
func (s *MySQLStore) MarkMonitorAlerted(_ context.Context, _ int64, _ time.Time) error { return nil }
func (s *MySQLStore) RecoverMonitor(_ context.Context, _ int64, _ time.Time) error   { return nil }
func (s *MySQLStore) ListOverdueMonitors(_ context.Context, _ time.Time) ([]auth.Monitor, error) {
	return nil, nil
}
func (s *MySQLStore) DeleteMonitor(_ context.Context, _ int64) error { return nil }
