-- Phase 1 of real, row-level multi-tenancy (docs/MULTI_TENANCY_NORTHSTAR.md). Founder real-time:
-- "idunapro needs to become truely multi tenant currently its just a fork of iduna for carepyre."
-- Checked directly, confirmed true: zero tenant_id anywhere in this codebase; one process, one
-- database, one JWT key, for everyone.
--
-- This is the real, first, minimal `tenants` table -- deliberately not the full control-plane
-- model (trial lifecycle, billing) IDUNA/docs/EMILY_FOR_BUSINESS_NORTHSTAR.md scopes for internal
-- IDUNA; this is IDUNA_PRO's own in-process authority, checked on every request, not a tracking
-- table read out-of-band. Seeded with exactly one real row: this instance's own current, only
-- real tenant (CarePyre) -- every existing account in this database genuinely IS this tenant's
-- data, not an unassigned sentinel (contrast 202609070008_owning_org_columns.sql's own `DEFAULT
-- 0`, which means "no organization," a real, different, WITHIN-tenant concept).
CREATE TABLE IF NOT EXISTS tenants (
    id         BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    name       VARCHAR(255)    NOT NULL,
    created_at TIMESTAMP       NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

INSERT IGNORE INTO tenants (id, name) VALUES (1, 'CarePyre');
