-- CP-HIPAA-2 (founder real-time, 2026-09-07: "give the same treatment for sip [as mail
-- accounts]"). Mirrors mail_account_credentials.created_by exactly (202609070003): tracks which
-- local_uid provisioned each SIP extension mapping, so a Provider Operator/Admin's list/upsert/
-- remove access is scoped to the SIP accounts THEY created -- HIPAA's own minimum-necessary
-- principle, not just the mailbox side of the participant's account. NULL for rows created
-- before this column existed (users.admin-only, unaffected -- SipAccountsHandler only applies
-- the created_by filter for a caller who lacks users.admin).
ALTER TABLE sip_accounts ADD COLUMN created_by INTEGER;
