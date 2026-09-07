-- CP-WHITELABEL-1: real, general per-instance branding config -- founder real-time, 2026-09-07:
-- "it needs to be both white labeled first then made into carepyre." Single-row settings table
-- (id fixed at 1), same "one config row per instance" idiom mailinglist's own Mailchimp settings
-- already use. Every field has a safe, generic default so an instance that never configures
-- branding still renders a real, working (if plain) console -- CarePyre becomes the first
-- tenant to set these away from the defaults, not a special case in the schema.
CREATE TABLE IF NOT EXISTS branding_settings (
    id            INTEGER      PRIMARY KEY CHECK (id = 1),
    app_name      VARCHAR(255) NOT NULL DEFAULT 'IDUNA Pro',
    tagline       VARCHAR(255) NOT NULL DEFAULT '',
    primary_color VARCHAR(16)  NOT NULL DEFAULT '#3fa9dc',
    accent_color  VARCHAR(16)  NOT NULL DEFAULT '#f5a623',
    logo_data_uri TEXT,
    updated_at    DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP
);
