-- CP-HIPAA-1: providers (mail-accounts.provision, a real, distinct, least-privilege role from
-- users.admin -- see 202609070002_local_users_is_provider.sql) can now create participant
-- mailboxes. HIPAA's own "minimum necessary" principle means a provider should only ever see or
-- reveal the password of mailboxes THEY created for THEIR participants, not every participant's
-- mailbox in the system (that broader view stays users.admin-only). created_by records which
-- local_uid provisioned each linked mailbox; NULL for rows created before this column existed
-- (users.admin-only, unaffected -- MailAccountsHandler only ever applies the created_by filter
-- for a caller who lacks users.admin).
ALTER TABLE mail_account_credentials ADD COLUMN created_by INTEGER;
