-- Widen agents.status to include PENDING (FRONT_DOOR_FUNNEL.md §7 step 1).
--
-- Verified live 2026-07-23: /admin/agents' "Register New Agent" form calls
-- CreateAgent, which inserted status='ACTIVE' unconditionally, with zero
-- api_key_hash and zero agent_permissions rows. Such an agent cannot
-- authenticate (AuthenticateAgent requires a non-empty api_key_hash) and
-- cannot do anything even if it could (no rows in agent_permissions) -- it
-- looked live and wasn't.
--
-- From this migration forward, CreateAgent inserts 'PENDING' instead. An
-- agent flips to 'ACTIVE' only once it has both a credential
-- (SetAgentCredential) and at least one granted permission
-- (GrantAgentPermission) -- see maybeActivateAgent in internal/store.
--
-- cmd/bootstrap's config/agents.json path is unaffected: it seeds rows
-- directly (never calls CreateAgent) and every already-registered agent
-- keeps its default 'ACTIVE' status untouched.
ALTER TABLE agents
  MODIFY COLUMN status ENUM('ACTIVE','SUSPENDED','DECOMMISSIONED','PENDING') NOT NULL DEFAULT 'ACTIVE';
