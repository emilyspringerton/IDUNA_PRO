-- Backfill: config/agents.json's own header comment says "All agent IDs
-- must match migration 202606030001_system_seeds.sql" — but three agents
-- added to that file after the original seed migration (EDIS-CUSTODIAN,
-- EMILY-TRAINING, EDIS-WOOCOMMERCE) were never given a matching `agents`
-- table row, so cmd/bootstrap's step 3 (secret provisioning) has silently
-- failed for all three ("not found in agents table") since each landed.
-- Found the same way as 202607170001/202607170002: running cmd/bootstrap
-- fresh while registering NORN (S141-04), which has the identical gap for
-- itself — fixed here alongside the pre-existing three rather than
-- separately, since it's the same bug.

INSERT IGNORE INTO agents (id, owner_user_id, name, type, status, created_at, updated_at) VALUES
  ('00000003-0000-4000-8000-000000000007',
   '00000000-0000-4000-8000-000000000001',
   'EDIS-CUSTODIAN', 'provisioner_agent', 'ACTIVE',
   CURRENT_TIMESTAMP(6), CURRENT_TIMESTAMP(6)),

  ('00000003-0000-4000-8000-000000000008',
   '00000000-0000-4000-8000-000000000001',
   'EMILY-TRAINING', 'training_agent', 'ACTIVE',
   CURRENT_TIMESTAMP(6), CURRENT_TIMESTAMP(6)),

  ('00000003-0000-4000-8000-000000000009',
   '00000000-0000-4000-8000-000000000001',
   'EDIS-WOOCOMMERCE', 'provisioner_agent', 'ACTIVE',
   CURRENT_TIMESTAMP(6), CURRENT_TIMESTAMP(6)),

  ('00000003-0000-4000-8000-000000000010',
   '00000000-0000-4000-8000-000000000001',
   'NORN', 'kernel_agent', 'ACTIVE',
   CURRENT_TIMESTAMP(6), CURRENT_TIMESTAMP(6));
