-- Agent M2M credentials: adds api_key_hash to allow programmatic token issuance
-- via POST /api/v1/auth/agent (spec HQ-SPEC-IAM-095 §3.1).
-- The key is stored as a bcrypt hash; the raw secret is never persisted.

ALTER TABLE agents
  ADD COLUMN api_key_hash VARCHAR(255) NULL DEFAULT NULL COMMENT 'bcrypt hash of the agent API key; NULL = no M2M credential provisioned';

-- Index for key-lookup by agent name (used during M2M auth to find the agent row
-- before hash verification; name is UNIQUE so this is effectively a covering index).
-- (The UNIQUE constraint on agents.name already creates an index, so no new index needed.)
