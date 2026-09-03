-- Kanban prioritization layer on top of EMILY/BACKLOG.md's own sprint
-- sections (S200-04-style tooling this session already built for CI
-- status). Founder real-time, built up across several messages: "ok lets
-- build a kanban layer on top of our sprints that lets us assign priority
-- for the next open dev to picj up - for now it can be simple 2 tiers of
-- special next queues priority and cruise" -> "it allows us to drag from
-- backlog into 1 of the 2 priority queues backlog numbers stay the same it
-- gets a kanban tracking something" -> "gui kanban interface 3 columns in
-- iduna" -> "i can ask the ai agent to work from the priority or cruise
-- backlog" -> "theoretically 2 agents could work in paralell without as
-- much risk of colliding priorities".
--
-- backlog_item_id is the real BACKLOG.md item id (e.g. "S202-27") --
-- deliberately NOT a foreign key into any table, since BACKLOG.md itself
-- is the git-authoritative source of truth (this table only tracks WHICH
-- queue a card is in, never duplicates the item's own text/status). Kept
-- as free text rather than validated against a live parse of BACKLOG.md,
-- same "don't couple to a moving document's exact structure" reasoning
-- golden-docs-index.md's own append-only convention already uses.
--
-- queue: 'backlog' (the default column -- not yet prioritized into either
-- special queue) | 'priority' | 'cruise'. position is a real per-column
-- sort order (lower = higher in the column), maintained by the drag-drop
-- UI's own reorder calls -- not a timestamp-derived ordering, so a card
-- can be manually ranked within its queue independent of when it was added.
CREATE TABLE IF NOT EXISTS kanban_cards (
    id              INTEGER  PRIMARY KEY AUTOINCREMENT,
    backlog_item_id VARCHAR(32) NOT NULL,   -- e.g. "S202-27" -- the real BACKLOG.md item id
    title           VARCHAR(200) NOT NULL,  -- short label, not the full BACKLOG.md prose
    queue           VARCHAR(16) NOT NULL DEFAULT 'backlog', -- 'backlog' | 'priority' | 'cruise'
    position        INTEGER NOT NULL DEFAULT 0,
    created_at      DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at      DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_kanban_cards_queue ON kanban_cards(queue, position);

-- Reuses iduna.admin (RequirePermission, same gate as /admin itself) rather
-- than a new dedicated permission -- this is internal sprint-planning
-- tooling for whoever already runs the Back Office, not a separate
-- product surface like the devportal (202608250001_devportal_permissions.sql),
-- which deliberately DOES get its own narrower permission.
