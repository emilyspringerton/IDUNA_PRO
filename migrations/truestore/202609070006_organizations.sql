-- CP-HIPAA-3 (founder real-time, 2026-09-07): real, multi-organization "provider cluster" trust
-- model. Concrete worked example driving this: "a health care provider giving a participant
-- services creates an email account for a user -- the service navigator at the shelter that
-- participant stays at needs to be able to password reset that participant to do the work of a
-- service navigator... it doesn't need to be totally granular yet ... but building towards that
-- with a batteries included happy path wouldnt be a bad idea ... we will assume the provider
-- cluster is a trusted network for now until we bring the service to multiple markets."
--
-- An organization is a real, distinct provider agency (a hospital, a shelter, a case-management
-- nonprofit). cluster_id is deliberately a bare, nullable int, not a many-to-many join table --
-- "we will assume the provider cluster is a trusted network for now" reads as one flat trust
-- boundary per deployment/market today, not overlapping cluster memberships; two organizations
-- sharing the same real, non-null cluster_id trust each other completely for participant
-- administration (see local_users.org_id and *_accounts.owning_org_id, following migrations).
-- A real, later step toward "zero-ish trust" (per the founder's own explicit framing) would
-- replace this with a genuine org_cluster_membership join table and per-relationship
-- permissions -- named here as the deliberate next granularity step, not built now.
CREATE TABLE IF NOT EXISTS organizations (
    id         INTEGER  PRIMARY KEY AUTOINCREMENT,
    name       VARCHAR(255) NOT NULL,
    cluster_id INTEGER, -- NULL = not in any cluster (no cross-org trust at all, the safe default)
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- Reuses users.admin -- creating/managing organizations is real, internal platform-operator
-- tooling (which agencies exist, which market/cluster each belongs to), not something any
-- provider or provider admin does themselves, same "internal tooling for whoever already
-- manages users" category sip_accounts.go's own migration comment already reasons through.
