-- mailinglist.admin gates GET/PUT /api/v1/mailing-list/settings/mailchimp
-- (S245-03: per-instance, admin-configurable email-provider settings, not
-- an env var). A separate permission from mailinglist.export -- that one
-- reads subscriber PII, this one reads/writes provider config, distinct
-- least-privilege scopes matching this table's own established convention.
-- Granted to super_admin, same reasoning as mailinglist.export: a founder-
-- controlled instance setting, not a separately-onboarded developer tool.
INSERT OR IGNORE INTO permissions(id, name, description) VALUES
    ('00000002-0000-4000-8000-000000000043', 'mailinglist.admin', 'Configure the mailing-list email-provider settings (GET/PUT /api/v1/mailing-list/settings/mailchimp)');

INSERT OR IGNORE INTO role_permissions (role_id, permission_id) VALUES
    ('00000001-0000-4000-8000-000000000001', '00000002-0000-4000-8000-000000000043');
