-- Kanban CP-SIP-1244543543 ("we are going to need the console screens for the admins and for
-- the users of the platform to reset their password and see their sip information").
--
-- Real, minimal mapping from an IDUNA_PRO local user to the real Asterisk PJSIP extension an
-- admin has manually provisioned for them (PARENA/ops/asterisk/pjsip_carepyre_phone.conf's own
-- extension "1000" today) -- this table is METADATA only, it does not itself create or reload
-- any Asterisk config. Real, honest v0 boundary, named explicitly, not glossed over: dynamic
-- per-user Asterisk endpoint provisioning (AMI- or config-file-driven) is real, separate,
-- substantially bigger work, not attempted here -- an admin still creates the real extension in
-- Asterisk by hand (or via a future sudo-queue script) and then records the mapping here so the
-- owning user can see their own real connection details in the console.
--
-- local_uid is deliberately NOT a foreign key (this codebase's own established convention --
-- see kanban_cards' own migration comment on why backlog_item_id stays free text) -- local_users
-- itself is projected from an append-only event log, not a normal mutable table, so a live FK
-- constraint against it doesn't fit that model.
CREATE TABLE IF NOT EXISTS sip_accounts (
    id          INTEGER  PRIMARY KEY AUTOINCREMENT,
    local_uid   INTEGER  NOT NULL UNIQUE,
    extension   VARCHAR(32) NOT NULL,
    sip_server  VARCHAR(255) NOT NULL,
    sip_port    INTEGER  NOT NULL DEFAULT 5060,
    created_at  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- Reuses users.admin (the existing gate on /api/v1/users' own admin routes) for assigning/
-- editing SIP accounts -- this is the same real "internal tooling for whoever already manages
-- users" category kanban_cards' own migration comment already reasons through for iduna.admin,
-- not a separate product surface that needs its own narrower permission.
