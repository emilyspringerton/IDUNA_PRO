-- Phase 2 of real, row-level multi-tenancy (docs/MULTI_TENANCY_NORTHSTAR.md), continued from
-- 202609111001_mail_and_sip_tenant_id.sql. Closes a gap this session's own GDPR fix
-- (internal/gdpr/gdpr.go's ErrNotFound doc comment) had already NAMED but under-scoped: it called
-- gdpr_requests.tenant_id absence a "?all=1 lists every tenant's request METADATA (not PII
-- values)" residual. Direct re-inspection of GDPRHandler.download() found that's an
-- understatement -- download() looks up a gdpr_requests row by bare id, and for a users.admin
-- caller applies NO ownership/tenant check at all before serving the real, completed export
-- file's full contents (everything ExportBundle holds: profile, event history, extension rows) --
-- not just metadata. A tenant-A admin could enumerate small sequential request ids and download
-- another tenant's users' actual PII export files outright.
--
-- Same DEFAULT 1 + real-join backfill idiom as 202609111001 -- gdpr_requests.local_uid is a real
-- foreign key into local_users, the authoritative source for which tenant a request actually
-- belongs to.
ALTER TABLE gdpr_requests ADD COLUMN tenant_id INTEGER NOT NULL DEFAULT 1;

UPDATE gdpr_requests
SET tenant_id = COALESCE(
	(SELECT tenant_id FROM local_users WHERE local_users.local_uid = gdpr_requests.local_uid),
	1
);
