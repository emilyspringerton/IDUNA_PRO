-- Phase 2 of real, row-level multi-tenancy (docs/MULTI_TENANCY_NORTHSTAR.md), closing a real gap
-- found by direct code inspection right after Phase 1 shipped (local_users only): both
-- mail_accounts.go and sip_accounts.go already do real, careful Go-side filtering by
-- owning_org_id/created_by for a NON-admin (provider-only) caller -- but a users.admin caller
-- bypasses that filtering entirely (list() has no WHERE clause at all; revealPassword()/upsert()/
-- remove() skip the ownership check outright for admins). Exactly the same vulnerability shape
-- the GDPR fix (internal/gdpr/gdpr.go, same day) closed for local_users itself: once a second
-- tenant is real, ANY tenant's admin would see, and could reveal the live decrypted password for,
-- every OTHER tenant's mailbox credentials -- and could upsert or delete any other tenant's SIP
-- extension outright.
--
-- Same DEFAULT 1 idiom as 202609110002_local_users_tenant_id.sql (a real fact about every existing
-- row, not an "unassigned" sentinel like owning_org_id's own DEFAULT 0) -- but backfilled via a
-- real join back to local_users.tenant_id rather than a bare constant, since local_uid is a real
-- foreign key into local_users in both tables and that's the authoritative source of truth for
-- "which tenant does this row actually belong to" (falls back to 1 only for the
-- theoretically-orphaned case of a credential/SIP row whose local_uid no longer exists).
ALTER TABLE mail_account_credentials ADD COLUMN tenant_id INTEGER NOT NULL DEFAULT 1;
ALTER TABLE sip_accounts ADD COLUMN tenant_id INTEGER NOT NULL DEFAULT 1;

UPDATE mail_account_credentials
SET tenant_id = COALESCE(
	(SELECT tenant_id FROM local_users WHERE local_users.local_uid = mail_account_credentials.local_uid),
	1
);

UPDATE sip_accounts
SET tenant_id = COALESCE(
	(SELECT tenant_id FROM local_users WHERE local_users.local_uid = sip_accounts.local_uid),
	1
);
