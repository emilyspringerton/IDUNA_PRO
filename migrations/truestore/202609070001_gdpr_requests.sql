-- Real GDPR data subject request pipeline (founder real-time, 2026-09-07: "build gdpr into
-- iduna pro multi tennant with data exporting and data delete request pipeline dont focus on
-- the cookie confirm widget at this time"). Tracks Article 15/20 (access/portability) and
-- Article 17 (erasure) requests as real, auditable rows -- not a fire-and-forget action with no
-- record of who asked for what and when.
--
-- Real, checked design note: request_type/status are TEXT, not a foreign-keyed lookup table --
-- same "small, fixed, code-owned enum" convention sip_accounts/tenants already use in this
-- exact codebase, not a new pattern.
--
-- status lifecycle: "pending" (row created, not yet processed) -> "completed" (real result
-- produced -- export_path holds a real file for "export", or result_summary describes what was
-- erased for "delete") -> "failed" (error_message holds the real cause). Both request types are
-- processed synchronously in this v0 (matches the tenant-provisioning handler's own precedent --
-- a low-frequency, user/admin-triggered action that can afford to block until the real outcome
-- is known, rather than a fire-and-forget "queued" status nobody can act on yet).
CREATE TABLE IF NOT EXISTS gdpr_requests (
    id             INTEGER  PRIMARY KEY AUTOINCREMENT,
    local_uid      INTEGER  NOT NULL,
    request_type   VARCHAR(16) NOT NULL, -- 'export' | 'delete'
    status         VARCHAR(16) NOT NULL DEFAULT 'pending',
    requested_by   INTEGER  NOT NULL, -- local_uid of whoever triggered it -- the subject themselves, or an admin acting on their behalf (both real, legitimate GDPR request originators)
    export_path    VARCHAR(500),
    result_summary TEXT,
    error_message  TEXT,
    created_at     DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    completed_at   DATETIME
);

CREATE INDEX IF NOT EXISTS idx_gdpr_requests_local_uid ON gdpr_requests (local_uid);

-- Reuses users.admin for the admin-facing "list all requests" / "act on someone else's behalf"
-- routes -- same "internal tooling for whoever already manages users" category sip_accounts'
-- own migration comment already reasons through. A user's OWN export/delete request needs no
-- special permission beyond ordinary authentication (RequireAuth) -- it's their own data.
