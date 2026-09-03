-- Apples: golden documentation records from recursive self-improvement runs.
-- Append-only. Never update or delete rows.
-- Spec: HQ-SPEC-IAM-096

CREATE TABLE IF NOT EXISTS `apples` (
    `id`             BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    `agent_id`       VARCHAR(36)     NOT NULL COMMENT 'FK to agents.id — who wrote this',
    `source_repo`    VARCHAR(255)    NOT NULL COMMENT 'e.g. prrject-fatbaby, emily, iduna',
    `run_id`         VARCHAR(128)    NOT NULL COMMENT 'unique run/iteration identifier (git sha, cron trace_id, etc.)',
    `apple_type`     VARCHAR(64)     NOT NULL COMMENT 'improvement | observation | incident | release | audit',
    `title`          VARCHAR(255)    NOT NULL,
    `body`           MEDIUMTEXT      NOT NULL COMMENT 'markdown — the full golden doc content',
    `metadata`       JSON            NULL     COMMENT 'arbitrary structured context: gear, version, signal counts, etc.',
    `recorded_at`    TIMESTAMP(6)    NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    PRIMARY KEY (`id`),
    INDEX `idx_apples_agent`      (`agent_id`),
    INDEX `idx_apples_repo`       (`source_repo`),
    INDEX `idx_apples_type`       (`apple_type`),
    INDEX `idx_apples_recorded`   (`recorded_at`),
    INDEX `idx_apples_run_id`     (`run_id`),
    CONSTRAINT `fk_apples_agent` FOREIGN KEY (`agent_id`) REFERENCES `agents` (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- -------------------------------------------------------
-- Permissions for the Apples feature
-- -------------------------------------------------------
INSERT IGNORE INTO permissions (id, name, description) VALUES
  ('00000002-0000-4000-8000-000000000010', 'apples.write', 'Submit golden documentation records'),
  ('00000002-0000-4000-8000-000000000011', 'apples.read',  'Read Apple records and list'),
  ('00000002-0000-4000-8000-000000000012', 'apples.admin', 'Full access including bulk query and export');

-- super_admin gets apples.admin (and transitively all apples.* via full access)
INSERT IGNORE INTO role_permissions (role_id, permission_id) VALUES
  ('00000001-0000-4000-8000-000000000001', '00000002-0000-4000-8000-000000000010'),
  ('00000001-0000-4000-8000-000000000001', '00000002-0000-4000-8000-000000000011'),
  ('00000001-0000-4000-8000-000000000001', '00000002-0000-4000-8000-000000000012');

-- analyst role gets apples.read
INSERT IGNORE INTO role_permissions (role_id, permission_id) VALUES
  ('00000001-0000-4000-8000-000000000004', '00000002-0000-4000-8000-000000000011');
