-- CP-HIPAA-3: owning_org_id snapshots the CREATOR's own org_id at the moment a mailbox/SIP
-- account is provisioned -- same real "snapshot at creation time" idiom created_by already
-- established (202609070003/202609070005), not a live join back to whatever org the creator
-- currently belongs to (a provider changing organizations later must never silently move every
-- participant they ever onboarded to their new org). 0 = no organization (the creator had none
-- assigned, or created it before this column existed) -- same safe, backward-compatible default
-- org_id itself uses.
ALTER TABLE mail_account_credentials ADD COLUMN owning_org_id INTEGER NOT NULL DEFAULT 0;
ALTER TABLE sip_accounts ADD COLUMN owning_org_id INTEGER NOT NULL DEFAULT 0;
