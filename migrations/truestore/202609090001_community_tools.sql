-- Founder real-time, 2026-09-09: "build it into carepyre... have that as part of the community
-- tools but we want it to be gated so that accounts need a feature flag set to see those
-- features." A real, per-account feature flag, deliberately SEPARATE from the existing 4-tier
-- admin/provider RBAC hierarchy (Top Admin/Operator Admin/Provider Admin/Provider Operator are
-- all staff-tier roles; this flag is for ORDINARY community-participant accounts) -- same real
-- DB-backed bool / grant-event / PATCH-API pattern is_admin/is_provider already established
-- (see internal/userlog/projector.go's own LocalUser.IsCommunityToolsEnabled doc comment, and
-- internal/http/handlers/local_auth.go's own localUserPermissions for how this becomes the
-- real "community-tools.access" permission).
ALTER TABLE local_users ADD COLUMN is_community_tools_enabled INTEGER NOT NULL DEFAULT 0;

-- resumes -- v0's own real first community tool: a resume/CV builder + verifier against the
-- real, known JSON Resume standard (jsonresume.org), see CarePyre/docs/
-- COMMUNITY_TOOLS_RESUME_NORTHSTAR.md for the full design. One resume per user for v0 (a
-- deliberate, named boundary -- multiple named resume variants per user is real, separate,
-- later work). `data` holds the real, complete JSON Resume document verbatim (internal/resume's
-- own Go struct tree, marshaled) -- a single JSON blob rather than one column per JSON Resume
-- field, the same real "don't over-normalize past what's actually needed" judgment this
-- monorepo's own IDUNA inventory work already made for its own free-text category/tags columns.
CREATE TABLE IF NOT EXISTS resumes (
    local_uid  INTEGER PRIMARY KEY REFERENCES local_users(local_uid),
    data       TEXT NOT NULL DEFAULT '{}',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
