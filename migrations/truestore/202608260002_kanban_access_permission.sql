-- kanban.access gates the bearer-token API half of the kanban
-- prioritization layer (/api/v1/kanban/cards, internal/http/handlers/
-- kanban.go) -- the CLI/agent path ("i can ask the ai agent to work from
-- the priority or cruise backlog"), distinct from the browser board
-- (/admin/kanban), which reuses iduna.admin like every other Back Office
-- page. A new, narrower permission rather than iduna.admin for this path
-- deliberately -- principle of least privilege: an automated agent reading/
-- writing the kanban queue has no business also holding full Back Office
-- admin rights. Granted to EMILY-PRIME in config/agents.json -- the agent
-- that would actually pick "work from priority" style direction.
INSERT OR IGNORE INTO permissions(id, name, description) VALUES
    ('00000002-0000-4000-8000-000000000041', 'kanban.access', 'Read/write the kanban prioritization queue (GET/POST/PATCH/DELETE /api/v1/kanban/cards)');
