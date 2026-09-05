-- mailinglist.export gates GET /api/v1/mailing-list/export (S245-02) --
-- a real, dedicated permission rather than iduna.admin, matching the
-- established least-privilege precedent (kanban.access,
-- devportal.access): this is the one mailing-list route that returns
-- real subscriber PII (decrypted emails), so it gets its own narrower
-- gate. Unlike devportal.access, this one IS granted to super_admin
-- here -- founder-only PII the admin role should already be trusted
-- with by default, not a separately-onboarded developer tool.
INSERT OR IGNORE INTO permissions(id, name, description) VALUES
    ('00000002-0000-4000-8000-000000000042', 'mailinglist.export', 'Export the decrypted mailing-list subscriber roster (GET /api/v1/mailing-list/export)');

INSERT OR IGNORE INTO role_permissions (role_id, permission_id) VALUES
    ('00000001-0000-4000-8000-000000000001', '00000002-0000-4000-8000-000000000042');
