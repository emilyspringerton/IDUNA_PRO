# IDUNA_PRO

The real, standalone, multi-tenant-deployable core of [IDUNA](https://github.com/emilyspringerton/IDUNA):
Google OAuth + local password auth, ES256 JWT issuance/refresh/JWKS, M2M agent auth, hierarchical
RBAC, an append-only audit ledger ("Apples"), and a unified Splunk-shaped logging backend.

Extracted 2026-09-03 per real founder direction ("we pull some of the more custom stuff out of
iduna and the code goes right into the emily for business product IDUNA_PRO"). Full extraction
plan, categorization, and control-plane model:
[`IDUNA/docs/EMILY_FOR_BUSINESS_NORTHSTAR.md`](https://github.com/emilyspringerton/IDUNA/blob/main/docs/EMILY_FOR_BUSINESS_NORTHSTAR.md).

Licensed under [The Emily License v0](https://github.com/emilyspringerton/EMILY_FOR_BUSINESS/blob/main/LICENSE.md)
(source-available; cannot be offered as a platform/hosted service or redistributed without a
separate commercial agreement) — see also that repo's
[`TRADEMARK.md`](https://github.com/emilyspringerton/EMILY_FOR_BUSINESS/blob/main/TRADEMARK.md).

## What's here, real and tested

- `internal/auth` — Google OAuth verification, ES256 JWT (`internal/auth/jwt`, hand-rolled on
  `crypto/ecdsa`, no external JWT library), M2M agent auth, device flow (`internal/auth/device`).
- `internal/store` — SQLite (embedded, zero external deps) and MySQL backends behind one
  `store.IAMStore` interface; migrations run clean against a fresh, empty database.
- `internal/userlog` — the unified, Splunk-HEC-shaped logging backend (ingest + search), plus
  the local-user event log/projector.
- `internal/http/handlers` — Google/local/agent/device auth, JWT refresh, self-serve
  registration, `/me`, users CRUD, agents list, Apples audit ledger, unified log ingest/search.
- `internal/http/middleware` — JWT auth, permission checks, rate limiting.

Live-verified this session (not just `go build`/`go test`): booted the real binary against a
fresh SQLite file, confirmed `/health`, `/.well-known/jwks.json` (a real ES256 key), a real
self-serve `POST /api/v1/auth/register` issuing a real JWT, and `POST /api/v1/auth/local`
correctly rejecting bad credentials.

## Real gap, fixed (2026-09-04, cruise-queue card 9988)

`GET /api/v1/identities/me` used to look up every subject via `store.GetUserByID`, which only
understands Google-OAuth-style UUID user IDs — a local-auth JWT's subject (`local:<N>`) never
resolved, so a self-serve-registered user got `404 identity not found` from `/me`
unconditionally. Real root cause, confirmed by reading both stores directly: local-auth
accounts live in the separate `local_users` projection, not the `users` table `GetUserByID`
queries — they never had a row there at all. Fixed: `MeHandler` now dispatches on a `local:`
prefix and resolves through `userlog.UserProjector.GetByUID` instead, the same real lookup the
login handler itself already uses. Live-verified end to end against a real, freshly-booted
instance (real register → real login → real `/me`), not just unit tests.

## Kanban board — human/agent interop

`internal/backlog`/`kanban.go`/`kanban_page.go`/`kanban_inbox.go` are here, generalized: a real,
DB-backed board (drag-and-drop + click-to-reorder columns, S207-68) reachable two ways against
the exact same handler — a human via the cookie-authenticated `/admin/kanban` browser UI, or an
agent via the bearer-token `/api/v1/kanban/cards` API (`kanban.access` permission). One shared
code path, two real entry points — the actual point of this being a core integration surface.

`BACKLOG_PATH` unset (this binary's own default) means a pure, generic board: no markdown sync,
no Inbox pane, no auto-archive-on-done — just cards, columns, and positions. Set `BACKLOG_PATH`
to opt into syncing against your own markdown-checkbox file (`- [ ] **ID: title**` lines) — the
same real parser IDUNA itself uses against `EMILY/BACKLOG.md`, just pointed at your own file. A
"done" move always files a real Apple (`backlog_completion`), tagged with `KANBAN_SOURCE_REPO_NAME`
if set (defaults to `"kanban"`).

`admin_login.go` came along with the kanban board — it turned out not to import
`internal/mailinglist` at all (checked directly), so the board's own cookie-session login page
didn't need inventing from scratch.

## What's deliberately NOT here

Per the real extraction plan's own categorization: the rest of the Back Office admin UI (user/
role management pages), the developer portal, blog/tyler/promptoverse/mailinglist/drive/vault,
every game-specific handler (mmo/redgarden/shankpit/papercraft/racer), HEIMDAL, push tokens.
Each of these is a real, later, separate decision — not silently dropped.

## Extensibility — real plan, not yet built

See `IDUNA/docs/EMILY_FOR_BUSINESS_NORTHSTAR.md`'s own "Extensibility — PARENA mods" section for
how a customer extends IDUNA_PRO for their own product's login/identity needs without forking
this Go source.

## Running it

```bash
go build -o idunapro .
SQLITE_PATH=./var/iduna.db ./idunapro   # embedded SQLite, migrations run automatically
# or: MYSQL_DSN=... ./idunapro          # MySQL mode
```

Env vars mirror IDUNA's own (`JWT_ISSUER`, `BASE_URL`, `GOOGLE_CLIENT_ID`, `KEY_FILE`,
`IDUNA_HEC_TOKEN`, `APPLES_GIT_DIR`, `ADDR`, default `:8081`) plus two new to this repo:
`BACKLOG_PATH` (kanban markdown sync, unset by default) and `KANBAN_SOURCE_REPO_NAME` (Apple
`source_repo` label for kanban "done" moves, defaults to `"kanban"`).
