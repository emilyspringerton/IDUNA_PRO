-- CarePyre landing page (carepyre.org) "Contact Us" form -- moved here from plain IDUNA
-- (founder real-time, 2026-09-08: "move the contact form to idunapro") so it lives in the same
-- service/DB as CarePyre's own tiered RBAC and GDPR pipeline, rather than IDUNA's general
-- backbone DB gated by a broader, unrelated `iduna.admin` population. The old IDUNA table
-- (IDUNA/migrations/truestore/202608100001_carepyre_contact_submissions.sql) is left in place,
-- frozen and no longer written to -- a conservative choice, not a decision that the data is
-- disposable; a one-time copy migrates its existing rows into this table (see
-- IDUNA_PRO/cmd/carepyre-contact-migrate).
--
-- Two real, checked design decisions this table adds that the old one never had:
--   1. `status` + `resolved_at` -- needed for a real retention policy (founder real-time,
--      2026-09-08: submissions purge 90 days after being marked resolved, not kept forever).
--      No purge logic lives in this migration -- see cmd/carepyre-contact-purge.
--   2. Access is gated by a new `contacts.manage` permission (Top-Admin-only for now, see
--      localUserPermissions in internal/http/handlers/local_auth.go) instead of IDUNA's
--      catch-all `iduna.admin` -- deliberately built as a real, separate, named permission so it
--      can be extended to Operator Admin or a new Provider-tier role later without a rewrite.
--
-- Plaintext at rest, same as every other real operational table in this store -- true
-- encryption-at-rest doesn't defend against the actual threat here (a compelled/subpoenaed
-- disclosure, since this service must decrypt the row to render it in the admin console
-- regardless); access control + retention are the real defenses, not a reversible cipher.
CREATE TABLE IF NOT EXISTS carepyre_contact_submissions (
    id          BIGINT       NOT NULL AUTO_INCREMENT PRIMARY KEY,
    name        VARCHAR(120) NOT NULL,
    email       VARCHAR(254) NOT NULL,
    message     VARCHAR(4000) NOT NULL,
    status      VARCHAR(32)  NOT NULL DEFAULT 'new',
    created_at  TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP,
    resolved_at TIMESTAMP    NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE INDEX idx_carepyre_contact_submissions_created_at ON carepyre_contact_submissions(created_at);
-- Drives cmd/carepyre-contact-purge's own query (status='resolved' AND resolved_at < cutoff).
CREATE INDEX idx_carepyre_contact_submissions_status_resolved ON carepyre_contact_submissions(status, resolved_at);
