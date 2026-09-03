CREATE TABLE IF NOT EXISTS device_auth_requests (
  id BIGINT PRIMARY KEY AUTO_INCREMENT,
  stream_id CHAR(36) NOT NULL,
  device_code_hash VARBINARY(32) NOT NULL UNIQUE,
  user_code_norm VARCHAR(16) NOT NULL UNIQUE,
  user_code_display VARCHAR(16) NOT NULL,
  status ENUM('pending','authorized','consumed','expired','denied') NOT NULL DEFAULT 'pending',
  created_at TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
  expires_at TIMESTAMP(6) NOT NULL,
  poll_interval_ms INT NOT NULL DEFAULT 2000,
  last_poll_at TIMESTAMP(6) NULL,
  poll_count INT NOT NULL DEFAULT 0,
  authorized_user_id VARBINARY(16) NULL,
  authorized_at TIMESTAMP(6) NULL,
  authorized_ip_hash VARBINARY(32) NULL,
  authorized_ua_hash VARBINARY(32) NULL,
  exchange_code_hash VARBINARY(32) NULL,
  exchange_code_plain VARCHAR(128) NULL,
  exchange_code_expires_at TIMESTAMP(6) NULL,
  KEY idx_device_auth_status_expires (status, expires_at)
);

CREATE TABLE IF NOT EXISTS exchange_codes (
  id BIGINT PRIMARY KEY AUTO_INCREMENT,
  exchange_code_hash VARBINARY(32) NOT NULL UNIQUE,
  exchange_code_plain VARCHAR(128) NULL,
  user_id VARBINARY(16) NOT NULL,
  device_request_id BIGINT NOT NULL,
  created_at TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
  expires_at TIMESTAMP(6) NOT NULL,
  consumed_at TIMESTAMP(6) NULL,
  KEY idx_exchange_codes_user_created (user_id, created_at),
  UNIQUE KEY uq_exchange_device_request (device_request_id),
  CONSTRAINT fk_exchange_device FOREIGN KEY (device_request_id) REFERENCES device_auth_requests(id)
);

CREATE TABLE IF NOT EXISTS event_store (
  id BIGINT PRIMARY KEY AUTO_INCREMENT,
  stream_type VARCHAR(64) NOT NULL,
  stream_id VARCHAR(64) NOT NULL,
  event_type VARCHAR(128) NOT NULL,
  payload_json JSON NOT NULL,
  occurred_at TIMESTAMP(6) NOT NULL,
  created_at TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
  KEY idx_event_stream (stream_type, stream_id, id)
);
