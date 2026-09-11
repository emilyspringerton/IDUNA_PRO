# IDUNA_PRO

## What this is

The real, standalone, multi-tenant-deployable core of `IDUNA`: Google OAuth + local password
auth, ES256 JWT issuance/refresh/JWKS, M2M agent auth, hierarchical RBAC, an append-only audit
ledger, and a unified Splunk-shaped logging backend. Extracted 2026-09-03 (`EMILY/BACKLOG.md`
S243-06/S243-07) — read `IDUNA/docs/EMILY_FOR_BUSINESS_NORTHSTAR.md` before assuming scope here;
it has the full extraction plan, categorization, control-plane model, and the real, phased
extensibility plan (PARENA mods via BURROW's Go emission target, not PARENA's C target — see
that doc's own "real, decisive, checked difference" note).

## Status

Real V0, live-verified (not just `go build`/`go test`): boots against a fresh SQLite file,
migrations run clean, `/health`/`/.well-known/jwks.json`/`/api/v1/auth/register`/
`/api/v1/auth/local`/`/api/v1/identities/me` all confirmed working end to end. **Real gap fixed
2026-09-04**: `/api/v1/identities/me` used to 404 unconditionally for a local-auth JWT's
subject (`local:<N>`) — inherited from IDUNA itself. Fixed by teaching `MeHandler` to resolve
`local:` subjects through the real `userlog.UserProjector`, same lookup the login handler
already uses. See `README.md`'s own section on this.

**Real, shipped (2026-09-03, S243-08)**: the kanban board — generalized, DB-backed, reachable
via both a cookie-authenticated browser UI (`/admin/kanban`) and a bearer-token API
(`/api/v1/kanban/cards`) against the same handler. Optional markdown-file sync via
`BACKLOG_PATH` (unset by default — pure DB-backed board otherwise). Live-verified end to end:
card create/list/done via the bearer API, card create via the cookie session, real Apple filed
on a "done" move.

**Real, shipped (2026-09-05, S245-05)**: the mailing-list vault subsystem, extracted from IDUNA
verbatim (`internal/mailinglist` had zero cross-imports to begin with) — real signup/count/
unlock/init routes, S245-01's opt-in config/file-key unlock mode (`MAILING_LIST_KEY_FILE`, no
operator needed after a redeploy), S245-02's export endpoint (`mailinglist.export` permission),
and S245-03's per-instance admin-configurable Mailchimp settings (`mailinglist.admin`
permission — stored settings win over the env-var fallback once the vault is unlocked).
Generalized on the way out: no hardcoded AllowOrigin/per-product MailchimpLists (those were the
real, checked EINHORN-specific parts) — a tenant sets `MAILING_LIST_ALLOW_ORIGIN` instead. Live-
verified: fresh-SQLite boot, migrations applied (`mailinglist.export`/`mailinglist.admin` both
present), `/health` OK.

**Real, shipped (2026-09-05, S245-04)**: the "consoleify" settings page at `/admin/mailing-list`
— real subscriber count/sync status (new `Store.SyncedCount`), the Mailchimp settings form, and
CSV/JSON export, all reusing the S245-01/02/03 handler methods directly (no duplicated logic).
Same cookie-vs-bearer dual-entry-point split as the kanban board.

Not yet built: the extensibility hook contract (PARENA mods via `burrow build`), a docs site,
an online editor, `console.okemily.com`, or the tenant-provisioning control plane (all real,
separately scoped in the NORTHSTAR doc above).

**Real, shipped (2026-09-09)**: Community Tools — CarePyre's own real, gated feature area
(founder real-time: "build it into carepyre... community tools... gated so that accounts need a
feature flag set"). New `LocalUser.IsCommunityToolsEnabled` (a plain, per-account feature flag,
deliberately separate from the 4-tier admin/provider RBAC), driving a new
`"community-tools.access"` permission; `internal/resume` (a real JSON Resume-schema-mirrored Go
data model + a real, itemized 2-layer verify function); `internal/http/handlers/
community_tools.go` (`GET`/`PUT /api/v1/community-tools/resume`,
`POST /api/v1/community-tools/resume/verify`, scoped to the caller's own `local_uid`, no
cross-user path). See `CarePyre/docs/COMMUNITY_TOOLS_RESUME_NORTHSTAR.md` for the full design.
Live-verified: fresh-SQLite boot, the new migration applies cleanly, `/health` OK. Frontend UI
lives in `CarePyre/console.html`.

**Real, shipped same day**: named Target resume variants (`internal/resume/target.go`,
`GET`/`PUT /api/v1/community-tools/resume/targets`, `.../targets/{id}/resolved`,
`.../targets/{id}/verify`) — bespoke, tailored show/hide selections over the master's own real
Work/Education/Skill/Award entries plus optional summary/headline overrides, never a duplicate of
the underlying data.

**Real, shipped same day (Layer 3 PDF export)**: `internal/resume/pdf.go`'s `RenderPDF` — a real,
downloadable, ATS-safe PDF file (`github.com/go-pdf/fpdf`, pure Go, no cgo), closing the gap this
feature named honestly as not-done when its screen-only preview templates first shipped. Two
routes: `GET .../resume/export.pdf` (master) and `GET .../resume/targets/{id}/export.pdf` (a
resolved Target). A found-before-shipping header-injection risk (a Target's own user-controlled
`Name` going straight into the `Content-Disposition` header) was closed with an allowlist
filename sanitizer (`pdfFilename`) — live-verified against a real fresh-SQLite-booted binary,
including a target literally named `Kitchen Jobs "Special"` to confirm the header stays
well-formed. See `CarePyre/docs/COMMUNITY_TOOLS_RESUME_NORTHSTAR.md` §4d for the full writeup.

**Real, shipped same day (agent-ergonomic API primitives + OpenAPI spec, + multi-GitHub-links
support)**: `PATCH /resume/basics`, `POST`/`PATCH`/`DELETE /resume/{work,education,skills,
awards,profiles}[/{id}]`, and the analogous single-target primitives on `.../targets` — real
partial-update primitives alongside the existing whole-document PUT, built specifically so an
autonomous agent can make one small edit without resending everything (`encoding/json`'s own
"merge onto an already-populated value" semantics do the work — no hand-written per-field patch
struct needed). New `GET /api/v1/community-tools/openapi.json`, a real, complete, `go:embed`-ded
OpenAPI 3.0 document covering every route. New `resume.Profile.ID` + `Target.IncludedProfileIDs`
close a real, previously-silent gap: `basics.profiles` (GitHub/LinkedIn/portfolio links) existed
in the data model since day one but rendered nowhere (no UI, no PDF, no screen preview) and had
no stable id to select into a Target — all three now fixed. See
`CarePyre/docs/COMMUNITY_TOOLS_RESUME_NORTHSTAR.md` §4e/§4f for the full writeup.

**Real, shipped same day (Compact PDF template + candidate name/timestamp in exports)**:
`resume.RenderPDF` now takes a `template` argument — "classic" (unchanged, ATS-safe) or the new
"compact", a real, deliberately opt-in two-column layout (Experience/Education side by side via
a manually-positioned `colState` helper) that frees vertical space for a fuller Skills section,
at the honest, named cost of the same ATS multi-column parsing risk "classic" exists to avoid.
Every generated PDF now carries a real footer (candidate name + export timestamp, via fpdf's own
`SetFooterFunc`) and a filename that includes both, not just a generic name. Verified by
decompressing the real PDF's own FlateDecode content stream and confirming "Experience"/
"Education" render at genuinely distinct x-coordinates. See
`CarePyre/docs/COMMUNITY_TOOLS_RESUME_NORTHSTAR.md` §4h for the full writeup.

**Real, shipped (auto-linking + markdown links in the summary, header left/right layout)**:
email and profile URLs render as real, clickable links in PDF exports (auto-adding `https://` to
a bare domain), `basics.summary` supports a real, narrow `[text](url)` markdown subset via
fpdf's own `Write`/`WriteLinkString`, and a shared `safeHref` rejects `javascript:`/`data:`/
`vbscript:`/`file:` schemes outright. The Compact template's header also now puts name/label
left and contact/links right, freeing vertical space. See
`CarePyre/docs/COMMUNITY_TOOLS_RESUME_NORTHSTAR.md` §4h/§4j for the full writeup.

**Real, shipped (Skills categorization + Vertex AI auto-organize, 2026-09-10)**: direct
employer-scan feedback — "Skills section is a dump, it's alphabetical chaos" — closed with a new
`Skill.Category` field, `resume.GroupSkillsByCategory` (one real, shared bucketing choke point
both `pdf.go` and `console.html`'s screen preview use, kept in lockstep), and a real
`POST /resume/skills/categorize` endpoint reusing IDUNA's own GFD Item Builder Vertex AI pattern
exactly (gcloud ADC, `gemini-2.5-flash`, `responseMimeType: application/json`) to auto-bucket any
uncategorized skill into one of six founder-named categories. Idempotent by design — only ever
touches skills with an empty Category, never overwrites a manual choice. See
`CarePyre/docs/COMMUNITY_TOOLS_RESUME_NORTHSTAR.md` §4k for the full writeup, including the
honest note that the live Vertex network call itself wasn't exercised end to end in this sandbox
(no active `gcloud` account here) — closed instead with real, network-free unit coverage of the
response-parsing logic plus a live-reverified fresh-SQLite boot.

**Real, shipped, 2026-09-11: Multi-Tenancy Phase 1 — real row-level tenant isolation on
`local_users`.** Founder real-time: "idunapro needs to become truely multi tenant currently its
just a fork of iduna for carepyre." `docs/MULTI_TENANCY_NORTHSTAR.md` named the real, sequenced
plan; Phase 1 is now real and live-verified, not just spec: new `tenants` table (seeded with
tenant 1 = CarePyre), a new `local_users.tenant_id` column, an explicit `tenantID int` parameter
on every scoped `userlog.UserProjector` method (`GetByUID`/`GetByEmail`/`ListUsers`/`ScrubPII` —
compiler-enforced, not read implicitly from context), a new `tenant_id` JWT claim (minted by
`local_auth.go`/`register.go`), and a new `callerTenantID(r)` helper threaded through every real
`local_users`-touching handler. A real, found-live security gap was closed in the same pass, not
deferred: `internal/gdpr`'s own Export/Delete pipeline took a bare `local_uid` with no tenant
check anywhere in the chain — a tenant-A admin could otherwise export or permanently PII-scrub a
tenant-B user via the GDPR routes, entirely bypassing the new `UserProjector` scoping. Fixed via a
new `verifyTenantMembership` check (and `gdpr.ErrNotFound`, mapped to a real 404) run before
either pipeline touches anything. Real, live-verified end to end against the actual running
binary (not just `go test`): registered two real users, moved one into a second, hand-inserted
tenant, and confirmed `GET /api/v1/users` only lists the caller's own tenant, `GET /api/v1/users/
{cross-tenant-uid}` returns a genuine 404 (never a distinguishable 403), and `POST /api/v1/gdpr/
export` for a cross-tenant target also 404s with the target's real data provably untouched. New
tests at every layer (`internal/userlog`, `internal/gdpr`, `internal/http/handlers`) including a
real trip-wire test pinning the documented, temporary "no tenant_id claim defaults to tenant 1"
fallback (agent/cookie tokens don't carry the claim yet — Phase 2/4's job) so a future change to
it fails loudly instead of drifting silently. `go build`/`go vet`/`go test ./...` all clean.
Real, honest, deliberately out of scope for Phase 1 (see the NORTHSTAR doc's own Phase 2+): every
other tenant-owned table (`sip_accounts`, `mail_account_credentials`, `resumes`, `organizations`,
etc.), per-tenant email uniqueness (still a global constraint), and a `tenant_id` claim for
Google-OAuth/M2M-agent tokens.

**Real, shipped same day: Multi-Tenancy Phase 2's first slice — `mail_account_credentials` +
`sip_accounts`.** Found by direct inspection right after Phase 1 landed: both tables already had
real Go-side filtering by `owning_org_id`/`created_by` for a non-admin caller, but a `users.admin`
caller bypassed it entirely — `mail_accounts.go`'s `list()` had no `WHERE` clause at all,
`revealPassword()` returned a live, decrypted mailbox password to any admin regardless of tenant,
and `sip_accounts.go`'s `upsert()`/`remove()` let an admin hijack or delete any tenant's phone
extension. Same vulnerability class as the GDPR gap, one layer down. Fixed with a new `tenant_id`
column on both tables (migration `202609111001_mail_and_sip_tenant_id.sql`, backfilled via a real
join to `local_users.tenant_id`), a new `localUserTenantID` helper (for `sip_accounts.upsert`'s
insert-or-update case, where no existing row's own `tenant_id` can be checked yet), and the same
404-not-403 idiom throughout. New adversarial tests at the Go-test level
(`TestMailAccountsHandler_AdminCannotRevealCrossTenantMailboxPassword`,
`TestSipAccounts_AdminCannotSeeOrTouchCrossTenantAccount`) plus live verification against the
actual running binary: two real tenants, `GET /api/v1/sip-accounts` correctly scoped, cross-tenant
`PUT`/`DELETE /api/v1/sip-accounts/{uid}` both 404 with the target row provably untouched, and a
cross-tenant `GET /api/v1/mail-accounts/{uid}/reveal-password` returning 404 instead of leaking the
real password. `go build`/`go vet`/`go test ./...` all clean. Remaining Phase 2 tables named, not
yet audited: `resumes`/`resume_targets`/`community_tools`, `gdpr_requests` (`?all=1` residual),
`branding_settings`, `compliance_recordings`.

**Real, shipped since (2026-09-07, SAGA audit catch-up)** — this Status section had fallen behind
the repo's own real scope; see `README.md`'s own matching catch-up section for the full writeup:
organizations/cluster trust model (`organizations.go`), white-label branding (`branding.go`),
compliance-recording storage (`compliance_recording.go`), the GDPR export/erasure pipeline
(`internal/gdpr/`), and the 4-tier RBAC model (Top Admin/Operator Admin/Provider Admin/Provider
Operator). All live-routed in `main.go`, all with real tests.

## Stack

Go 1.25, `GOWORK=off` (standalone module, not part of the monorepo's `go.work`) — same real,
checked reason IDUNA itself runs `GOWORK=off` in its own CI: this repo needs to build and test
completely independently, with no sibling-repo dependency.

## Related Repos

- `IDUNA` — the source repo this was extracted from; also the real control plane that will
  provision/track `IDUNA_PRO` tenant trials (not built yet).
- `EMILY_FOR_BUSINESS` — licensing (`LICENSE.md`/`TRADEMARK.md`) for this and sibling products.
- `PARENA`/`BURROW` — the real extensibility mechanism (PARENA mods compiled via `burrow build`
  to native Go, zero cgo/FFI) once built.
- `JEWEL` — real precedent for an online PARENA editor, needs real adaptation (C-target vs.
  Go-target execution model) before it fits this repo's own extensibility story.
- `EMILY` — RSI loop / backlog coordination for cross-repo work.

## Founder Real-Time Direction

Whenever the founder gives real-time direction — a new ask, a correction, a "can we also..." —
route it through `emily observe -s info "Founder real-time: <summary>"` first, even if it isn't
this repo's usual domain, then sprint-plan it into `EMILY/BACKLOG.md` (`emily backlog curate`,
scoped into a real SECTION/sub-item, not just a one-line log), and only then implement. See
`EMILY/docs/THE_EMILY_WAY.md` Principle 18 ("Pave the Cow Paths").

## Apple Filing Protocol

After any meaningful change, file an Apple:
```bash
emily apples post -t completion -repo IDUNA_PRO "<title>" "<body with commit hash>"
```
Then mark the item done in `EMILY/BACKLOG.md` and commit.

## CHANGELOG Protocol

After any meaningful change, update CHANGELOG.md:
```bash
emily changelog add IDUNA_PRO "<what changed>"
# or manually: append a dated bullet under ## YYYY-MM-DD in IDUNA_PRO/CHANGELOG.md
```

## Frame-Break Reframing

Founder-sourced prompting technique (REDGARDEN/NORTHSTAR.md §28, full origin in
REDGARDEN/docs2/MULTI_AGENT_RD_RESEARCH_NOTES.md §5): given a request, name the underlying
structural/systemic pattern it's one instance of — one level of abstraction up — as an added
lens during planning/triage/judgment calls. Use it to spot the general case behind a specific
ask. It augments judgment, it does not replace doing the work: direct, concrete execution of
the literal task asked for still happens every time.

## Commit Protocol (standing instruction)

Always commit and push completed work immediately — don't wait to be asked. This is the default for every repo in this monorepo.

Every commit — human-written or produced by automated code paths (git-commit helpers in emily-agent, emily.cli, IDUNA handlers, etc.) — must carry the active `emily session` fingerprint as a `session: <tag>` trailer (blank line, then the trailer). This was silently missing from several independently-implemented automated commit helpers across the monorepo until an audit on 2026-08-10 (founder, real-time: "where in the fuck is my llm session id anywhere"). If you add a new automated git-commit code path anywhere, wire in the session tag the same way — don't assume an existing helper already does it.
