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

Not yet built: the extensibility hook contract (PARENA mods via `burrow build`), a docs site,
an online editor, `console.okemily.com`, or the tenant-provisioning control plane (all real,
separately scoped in the NORTHSTAR doc above).

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
