# NORTHSTAR — IDUNA_PRO Multi-Tenancy (Phase 0 for Emily For Business)

*Spec-only, 2026-09-11. Founder real-time: "idunapro needs to become truely multi tenant currently
its just a fork of iduna for carepyre." No code changes in this pass — this document names the
real, checked gap and the real, sequenced plan to close it. See
`IDUNA/docs/EMILY_FOR_BUSINESS_NORTHSTAR.md` for the strategic "why" this blocks; this document is
the concrete "how," scoped to this repo's own actual code.*

## The real, checked gap — this is not a refactor, it's an unbuilt architectural layer

Checked directly against this repo's own source, not assumed:

- **Zero `tenant_id` anywhere.** `grep -rn "tenant_id\|org_id\|organization_id"
  internal/store/*.go` returns nothing for `tenant_id`. The `org_id`/`organization_id` hits that
  DO exist (`organizations.go`, `202609070006_organizations.sql` onward) are a **within-tenant**
  concept — CarePyre's own real, internal "several agencies with service agreements" hierarchy
  (CP-HIPAA-3), scoped entirely inside CarePyre's own single SQLite database. They do not, and
  were never meant to, separate one customer's data from another's. Real, useful prior art for
  the MECHANISM (see "owning_org_id" below), wrong LAYER for the problem.
- **One SQLite file, one process, one JWT signing key, one set of `LocalUser` rows — for
  everyone.** `main.go`'s own `getenv("SQLITE_PATH", filepath.Join("var", "iduna.db"))` and
  `getenv("KEY_FILE", "./idunapro-key.json")` are per-PROCESS, not per-CUSTOMER. Every real
  account in the live database today (`var/iduna.db`) is a CarePyre user — there is no code path
  by which a second, unrelated customer's data could even exist without colliding with CarePyre's
  own `local_users`/`resumes`/`sip_accounts`/etc. rows.
- **CarePyre is hardcoded directly into the Go source, not configured.** Ten files reference
  `carepyre`/`CarePyre` by name (`main.go`, `internal/gdpr/*.go`, `internal/twilio/client.go`,
  `internal/resume/{verify,model,pdf}.go`, `internal/mailaccounts/client.go`, plus tests).
  `main.go` alone has `mail.carepyre.org`/`carepyre.org` as literal default values baked into
  `getenv` calls, a `CarePyreContactHandler` mounted unconditionally at a fixed path, and the
  entire Community Tools resume feature's own domain vocabulary assumes one deployment. This is
  the real, literal meaning of "just a fork of IDUNA for CarePyre" — not a metaphor.
- **`docs/EMILY_FOR_BUSINESS_NORTHSTAR.md`'s own "IDUNA_PRO v0" section already named DB-per-
  install as the intended mechanism** ("a tenant is structurally just: a new `SQLITE_PATH`, a
  fresh migration run... on a distinct port") — but that was scoped for internal IDUNA managing
  provisioning of separate **processes**, one per tenant. That model works for a handful of
  high-touch trial customers provisioned by a human/script. It does NOT work for "an agent
  vibe-codes a new API surface for tenant #4,000 in ten seconds" — spinning up a whole new OS
  process, port, and systemd unit per tenant is real, unavoidable operational weight that a
  genuinely self-serve, agent-native platform can't carry at that pace. **This document's real
  job is naming the alternative: single-process, row-level tenant isolation**, which DB-per-
  install can still coexist with for a small number of dedicated/enterprise/HIPAA-tier customers
  who need real physical isolation (CarePyre itself is a plausible first candidate to KEEP on its
  own dedicated instance, once row-level multi-tenancy exists for everyone else).

## What "genuinely multi-tenant" has to mean here — named precisely, not left abstract

1. **A first-class `tenants` table**, owned by IDUNA_PRO itself (not just tracked externally by
   internal IDUNA's own control-plane concept from `EMILY_FOR_BUSINESS_NORTHSTAR.md` — that
   control-plane table tracks trial lifecycle/billing; THIS table is the real, in-process
   authority IDUNA_PRO's own request-handling code checks against on every single request).
2. **Every tenant-owned row gets a real `tenant_id` column** — `local_users`, `agents` (the
   `config/agents.json`-seeded M2M identities), `sip_accounts`, `mail_account_credentials`,
   `resumes`, `kanban_cards`, `organizations` (which becomes a real WITHIN-tenant concept,
   unchanged in its own semantics — a tenant can still have several CP-HIPAA-3-style internal
   orgs), `compliance_recordings`, `carepyre_contact_submissions` (renamed to something tenant-
   neutral, e.g. `contact_submissions`), every table this repo's own 28 migrations have built so
   far. Real, direct precedent for the MECHANISM already exists in this exact codebase:
   `202609070008_owning_org_columns.sql`'s `owning_org_id INTEGER NOT NULL DEFAULT 0` — the same
   "add a scoping column, backfill a real default for existing rows, enforce it going forward"
   shape, one layer up.
3. **JWTs carry a real `tenant_id` claim**, checked on every authenticated request alongside the
   existing `permissions[]`/`local_uid`/`sub` claims — a JWT minted for tenant A must never
   authorize a read/write against tenant B's rows, full stop, regardless of what `local_uid` or
   `permissions` it happens to carry. This is the real security boundary the whole rest of this
   document exists to protect; everything else is plumbing in service of this one guarantee.
4. **Every DB query gets tenant-scoped**, not by convention (a developer remembering to add
   `WHERE tenant_id = ?` by hand on every query, in every handler, forever) but by a real,
   enforced mechanism — see "Enforcement mechanism" below. Convention-only scoping is a real,
   well-known class of vulnerability (an agent — human or AI — WILL eventually forget one query),
   and "an agent forgot a WHERE clause" is a materially different, worse failure mode for a
   platform whose whole pitch is "agents build APIs on this" than for a hand-reviewed internal
   tool.
5. **Per-tenant configuration replaces hardcoded constants** — `mail.carepyre.org`-style defaults
   become real, tenant-row-stored settings (domain, branding, feature flags), the same real shape
   `branding.go`'s own existing white-label mechanism already partially proves out (checked: it's
   currently a single global settings row, not tenant-keyed — needs the same `tenant_id`
   treatment as everything else).
6. **A tenant's own JWT signing key stays per-tenant, or the JWKS endpoint becomes tenant-aware.**
   Real, open, load-bearing decision named here, not resolved: either (a) every tenant on a
   shared IDUNA_PRO process shares ONE signing key (`idunapro-key.json`) and JWKS endpoint, with
   `tenant_id` as just another claim inside a token from that one shared key — simpler, but a key
   compromise affects every tenant simultaneously, and a tenant's own external services (if they
   ever want to verify an IDUNA_PRO-issued JWT independently) can't scope trust to just their own
   tenant; or (b) per-tenant keys, a real per-tenant JWKS document, more isolation, more real
   complexity (key generation/rotation/storage becomes a genuine per-tenant operation, not a
   one-time boot-time file). Recommendation, not a decision: start with (a) for the shared-process
   tier (fast, matches "vibe code an API in ten seconds"), reserve (b) for the dedicated-instance
   tier (CarePyre-class customers who already get DB-per-install-style isolation for other
   reasons).

## Enforcement mechanism — where "genuinely multi-tenant" actually gets guaranteed, not hoped for

Three real, concrete candidates, not chosen between here (a real engineering decision once this
doc gets picked up):

1. **A `store` package wrapper that injects `tenant_id` into every query automatically** — e.g. a
   `TenantScopedDB` type wrapping `*sql.DB`, exposing the same `Query`/`Exec` surface but
   rewriting/validating that a `tenant_id = ?` predicate is present (or appending one to a
   builder-constructed query) before it ever reaches SQLite. Real, direct benefit: a handler
   author (including an agent) literally cannot write a cross-tenant query without going out of
   their way to bypass the wrapper — the safe path is also the easy path, the same "batteries
   included happy path" judgment call `organizations.go`'s own doc comment already names for a
   different feature.
2. **SQLite's own `ATTACH DATABASE`-per-tenant, one shared connection pool, transaction-scoped
   attach/detach** — closer in spirit to physical DB-per-install (real, total data isolation at
   the SQLite-file level) while still being one OS process. Real, honest cost: `ATTACH`/`DETACH`
   per request has real overhead and real concurrency-safety questions under Go's own
   `database/sql` connection-pooling model that would need real, careful verification before
   trusting it — not obviously simpler than option 1 despite sounding more "isolated."
3. **Postgres row-level security (RLS) policies**, if/when this repo's own real, already-supported
   MySQL/Postgres backend path (`store.go`'s dual SQLite/MySQL support, referenced in `main.go`)
   is extended to Postgres specifically — a real, battle-tested, database-ENFORCED mechanism
   (the policy lives in the schema itself, not application code) that a naive `WHERE`-clause bug
   literally cannot bypass. Real, honest cost: this repo's own DB-per-install-friendly SQLite
   default would need a real Postgres migration path for any tenant wanting this guarantee,
   itself unbuilt.

Recommendation, not a decision: (1) first (fastest to ship, works identically on SQLite and
MySQL, no new backend dependency), with (3) named as the real, stronger long-term option once a
Postgres backend exists for other reasons anyway.

## Real, phased plan

**Phase 0 — this document.** Named, not built.

**Phase 1 — the `tenants` table + JWT claim + `TenantScopedDB` wrapper (or equivalent), applied to
ONE real table first** (`local_users` is the natural first candidate — every other tenant-owned
row already hangs off a `local_uid` foreign key, so making `local_users` itself tenant-aware is
the load-bearing first cut). Real, concrete Definition of Done: two tenants, two sets of
`local_users` rows, in the SAME database, verified live that a tenant-A JWT genuinely cannot read
or list a tenant-B user via any existing `/api/v1/users` route — not just "the code looks right,"
a real, adversarial test that tries the cross-tenant read and confirms it's refused.

**Phase 2 — extend `tenant_id` to every remaining tenant-owned table**, one migration per table
(matching this repo's own established migration discipline — never edit an applied migration,
always add a new one), each with its own real cross-tenant-read-refused test, not a bulk
find-and-replace trusted without per-table verification.

**Phase 3 — per-tenant configuration** (domain/branding/feature flags), replacing the hardcoded
`carepyre`/`CarePyre` references named above one at a time — CarePyre itself becomes tenant #1 in
the new model, not a special case the code still needs to know the name of.

**Phase 4 — the shared-vs-dedicated JWT-signing-key decision** (see above), whichever direction
gets chosen, plus real load/soak testing of the enforcement mechanism under concurrent multi-
tenant traffic — a security boundary that hasn't been tested under real concurrency isn't
verified, it's assumed.

**Phase 5 (stretch, not scoped in detail here)**: the "console.okemily.com self-serve signup ->
new tenant row, zero human involved" pipeline `EMILY_FOR_BUSINESS_NORTHSTAR.md` already names as
unbuilt — once Phase 1-4 exist, this becomes "insert one `tenants` row" instead of "provision a
whole new process," which is the entire reason this document argues for row-level isolation over
purely DB-per-install.

## Real, honest, explicitly out of scope for this document

- The control-plane side (internal IDUNA's own `tenants`/`trials` tracking table, billing,
  `console.okemily.com` itself) — that's `EMILY_FOR_BUSINESS_NORTHSTAR.md`'s own scope, this
  document is IDUNA_PRO's internal architecture only.
- The PARENA-mod extensibility hook contract (`on-register-extra-fields` etc.) named in
  `EMILY_FOR_BUSINESS_NORTHSTAR.md`'s own "Extensibility" section — real, separate, unbuilt work,
  orthogonal to tenant isolation (a hook mod would itself need to be tenant-scoped once both
  exist, a real, small follow-up question for whoever builds the hook contract).
- Whether CarePyre migrates onto the new shared multi-tenant model or stays on its own dedicated
  instance permanently — a real, later decision, not blocked on anything in this document either
  way (a dedicated instance is just "one tenant, forever," which the new model supports trivially
  as a special case).

## Related

- `IDUNA/docs/EMILY_FOR_BUSINESS_NORTHSTAR.md` — the strategic "why," the control-plane model,
  and the extensibility story this document's own Phase 1-4 unblocks.
- `IDUNA_PRO/internal/http/handlers/organizations.go` — real, existing prior art for the
  scoping-column MECHANISM (`owning_org_id`), at the wrong layer for tenant isolation itself.
- `IDUNA_PRO/CLAUDE.md` — this repo's own current status; update once Phase 1 lands.
