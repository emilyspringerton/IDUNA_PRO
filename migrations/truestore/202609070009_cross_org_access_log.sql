-- CP-HIPAA-3 (founder real-time: "we need intense logging to ensure against fraud waste and
-- abuse"). A real, dedicated, directly-queryable audit trail for exactly the sensitive case the
-- cluster-trust model creates: an actor from one organization touching a participant onboarded
-- by a DIFFERENT organization (only possible at all because both share a cluster -- see
-- organizations.cluster_id). Deliberately a real SQL table, not folded into the general
-- userlog/unified event log -- same real reasoning gdpr_requests (202609070001) is its own table
-- rather than a generic event: a fraud/waste/abuse review needs "show me every cross-org touch
-- of participant X" or "every cross-org action actor Y has ever taken" to be a plain, fast,
-- directly-indexed SQL query, not a full event-log replay.
--
-- Same-org actions (a provider managing their own participant) and users.admin/operator-admin
-- actions (unrestricted by design, not cross-org in the sense this table cares about) are NOT
-- logged here -- this table's own real job is exactly the boundary the cluster-trust model
-- introduces, not a general-purpose activity log every other event source already covers.
CREATE TABLE IF NOT EXISTS cross_org_access_log (
    id            INTEGER  PRIMARY KEY AUTOINCREMENT,
    actor_uid     INTEGER  NOT NULL,
    actor_org_id  INTEGER  NOT NULL,
    target_uid    INTEGER  NOT NULL,
    target_org_id INTEGER  NOT NULL,
    action        VARCHAR(64) NOT NULL, -- e.g. "password_reset", "reveal_mail_password", "reveal_sip_provisioning"
    created_at    DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_cross_org_access_log_target ON cross_org_access_log (target_uid);
CREATE INDEX IF NOT EXISTS idx_cross_org_access_log_actor ON cross_org_access_log (actor_uid);

-- Reuses users.admin for reading this log back (a real audit/FWA-review surface, same internal-
-- tooling category as sip_accounts.go's own migration comment already establishes) -- no new
-- permission invented for a read-only report only platform operators need today.
