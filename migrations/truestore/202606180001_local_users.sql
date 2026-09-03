-- local_users: password-authenticated human accounts.
-- uid=0 is reserved for webmaster (root). All other uids are assigned sequentially.
CREATE TABLE IF NOT EXISTS local_users (
    local_uid     INT           NOT NULL PRIMARY KEY,
    email         VARCHAR(255)  NOT NULL,
    display_name  VARCHAR(255)  NOT NULL DEFAULT '',
    password_hash VARCHAR(255)  NOT NULL DEFAULT '',
    status        VARCHAR(32)   NOT NULL DEFAULT 'active',
    created_at    TIMESTAMP     NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at    TIMESTAMP     NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    UNIQUE KEY uniq_local_user_email (email)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Tracks the last user-event-log sequence applied to local_users (projector cursor).
-- Row id=1 is the only row; last_seq=0 means nothing applied yet.
CREATE TABLE IF NOT EXISTS local_user_projector_cursor (
    id       INT    NOT NULL PRIMARY KEY DEFAULT 1,
    last_seq BIGINT NOT NULL DEFAULT 0
);

INSERT IGNORE INTO local_user_projector_cursor (id, last_seq) VALUES (1, 0);
