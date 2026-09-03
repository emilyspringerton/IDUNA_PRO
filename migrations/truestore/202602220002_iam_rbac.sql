-- IAM RBAC tables for IDUNA

CREATE TABLE IF NOT EXISTS users (
  id               VARCHAR(36)  NOT NULL PRIMARY KEY,
  email            VARCHAR(255) NOT NULL UNIQUE,
  google_subject   VARCHAR(255) NOT NULL UNIQUE,
  gamertag         VARCHAR(64)  NULL UNIQUE,
  status           ENUM('ACTIVE','SUSPENDED','BANNED','PENDING') NOT NULL DEFAULT 'PENDING',
  roles_json       JSON         NULL,
  honor_accepted_current  TINYINT(1)   NOT NULL DEFAULT 0,
  honor_code_sha          VARCHAR(64)  NOT NULL DEFAULT '',
  honor_code_version      INT          NOT NULL DEFAULT 0,
  honor_code_text         TEXT         NULL,
  created_at       TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
  updated_at       TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS roles (
  id          VARCHAR(36)  NOT NULL PRIMARY KEY,
  name        VARCHAR(64)  NOT NULL UNIQUE,
  description VARCHAR(255) NOT NULL DEFAULT '',
  created_at  TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS permissions (
  id          VARCHAR(36)  NOT NULL PRIMARY KEY,
  name        VARCHAR(128) NOT NULL UNIQUE,
  description VARCHAR(255) NOT NULL DEFAULT '',
  created_at  TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS user_roles (
  user_id     VARCHAR(36) NOT NULL,
  role_id     VARCHAR(36) NOT NULL,
  assigned_at TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
  PRIMARY KEY (user_id, role_id),
  CONSTRAINT fk_user_roles_user FOREIGN KEY (user_id) REFERENCES users(id),
  CONSTRAINT fk_user_roles_role FOREIGN KEY (role_id) REFERENCES roles(id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS role_permissions (
  role_id       VARCHAR(36) NOT NULL,
  permission_id VARCHAR(36) NOT NULL,
  granted_at    TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
  PRIMARY KEY (role_id, permission_id),
  CONSTRAINT fk_role_perms_role FOREIGN KEY (role_id) REFERENCES roles(id),
  CONSTRAINT fk_role_perms_perm FOREIGN KEY (permission_id) REFERENCES permissions(id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS agents (
  id            VARCHAR(36)  NOT NULL PRIMARY KEY,
  owner_user_id VARCHAR(36)  NOT NULL,
  name          VARCHAR(128) NOT NULL UNIQUE,
  type          VARCHAR(64)  NOT NULL DEFAULT '',
  status        ENUM('ACTIVE','SUSPENDED','DECOMMISSIONED') NOT NULL DEFAULT 'ACTIVE',
  created_at    TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
  updated_at    TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6),
  CONSTRAINT fk_agents_owner FOREIGN KEY (owner_user_id) REFERENCES users(id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS agent_permissions (
  agent_id      VARCHAR(36) NOT NULL,
  permission_id VARCHAR(36) NOT NULL,
  granted_at    TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
  PRIMARY KEY (agent_id, permission_id),
  CONSTRAINT fk_agent_perms_agent FOREIGN KEY (agent_id) REFERENCES agents(id),
  CONSTRAINT fk_agent_perms_perm  FOREIGN KEY (permission_id) REFERENCES permissions(id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS iam_event_stream (
  event_id       BIGINT      NOT NULL AUTO_INCREMENT PRIMARY KEY,
  event_type     VARCHAR(128) NOT NULL,
  aggregate_type ENUM('USER','ROLE','PERMISSION','AGENT') NOT NULL,
  aggregate_id   VARCHAR(36)  NOT NULL,
  operator_id    VARCHAR(36)  NOT NULL DEFAULT '',
  payload        JSON         NULL,
  recorded_at    TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
  KEY idx_iam_events_aggregate (aggregate_type, aggregate_id),
  KEY idx_iam_events_type      (event_type),
  KEY idx_iam_events_recorded  (recorded_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- -------------------------------------------------------
-- Seed default roles
-- -------------------------------------------------------
INSERT IGNORE INTO roles (id, name, description) VALUES
  ('00000001-0000-4000-8000-000000000001', 'super_admin',  'Full system access'),
  ('00000001-0000-4000-8000-000000000002', 'admin',        'Administrative access'),
  ('00000001-0000-4000-8000-000000000003', 'operator',     'Operational access'),
  ('00000001-0000-4000-8000-000000000004', 'analyst',      'Read-only analysis access'),
  ('00000001-0000-4000-8000-000000000005', 'agent_owner',  'Owns and manages agents');

-- -------------------------------------------------------
-- Seed default permissions
-- -------------------------------------------------------
INSERT IGNORE INTO permissions (id, name, description) VALUES
  ('00000002-0000-4000-8000-000000000001', 'iduna.admin',         'Full IDUNA administration'),
  ('00000002-0000-4000-8000-000000000002', 'iduna.me.read',       'Read own identity profile'),
  ('00000002-0000-4000-8000-000000000003', 'fatbaby.read',        'Read Fatbaby pipeline data'),
  ('00000002-0000-4000-8000-000000000004', 'fatbaby.write',       'Write Fatbaby pipeline data'),
  ('00000002-0000-4000-8000-000000000005', 'secwatch.read',       'Read secwatch data'),
  ('00000002-0000-4000-8000-000000000006', 'secwatch.execute',    'Execute secwatch operations'),
  ('00000002-0000-4000-8000-000000000007', 'governance.admin',    'Governance administration');

-- -------------------------------------------------------
-- Assign all permissions to super_admin
-- -------------------------------------------------------
INSERT IGNORE INTO role_permissions (role_id, permission_id) VALUES
  ('00000001-0000-4000-8000-000000000001', '00000002-0000-4000-8000-000000000001'),
  ('00000001-0000-4000-8000-000000000001', '00000002-0000-4000-8000-000000000002'),
  ('00000001-0000-4000-8000-000000000001', '00000002-0000-4000-8000-000000000003'),
  ('00000001-0000-4000-8000-000000000001', '00000002-0000-4000-8000-000000000004'),
  ('00000001-0000-4000-8000-000000000001', '00000002-0000-4000-8000-000000000005'),
  ('00000001-0000-4000-8000-000000000001', '00000002-0000-4000-8000-000000000006'),
  ('00000001-0000-4000-8000-000000000001', '00000002-0000-4000-8000-000000000007');

-- -------------------------------------------------------
-- Assign iduna.me.read to all roles
-- -------------------------------------------------------
INSERT IGNORE INTO role_permissions (role_id, permission_id) VALUES
  ('00000001-0000-4000-8000-000000000002', '00000002-0000-4000-8000-000000000002'),
  ('00000001-0000-4000-8000-000000000003', '00000002-0000-4000-8000-000000000002'),
  ('00000001-0000-4000-8000-000000000004', '00000002-0000-4000-8000-000000000002'),
  ('00000001-0000-4000-8000-000000000005', '00000002-0000-4000-8000-000000000002');
