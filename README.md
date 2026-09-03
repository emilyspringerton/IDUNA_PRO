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

## Real, honest, found gap — not fixed here

`GET /api/v1/identities/me` looks up a subject by `store.GetUserByID`, which only understands
Google-OAuth-style UUID user IDs — a local-auth JWT's subject (`local:<N>`) doesn't resolve,
so a self-serve-registered user currently gets `404 identity not found` from `/me`. This is a
**pre-existing gap inherited from IDUNA itself**, not introduced by this extraction (confirmed
by reading `store.GetUserByID`'s own implementation) — but it matters more here, since a real
product built on self-serve/local auth (not Google OAuth) will hit it immediately. Real, named
next step: unify the local-user and OAuth-user identity models, or teach `/me` to dispatch on
the `local:` prefix.

## What's deliberately NOT here

Per the real extraction plan's own categorization: the Back Office admin UI, developer portal,
blog/tyler/promptoverse/mailinglist/drive/vault, every game-specific handler (mmo/redgarden/
shankpit/papercraft/racer), the kanban-over-BACKLOG.md bridge, HEIMDAL, push tokens. Each of
these is a real, later, separate decision — not silently dropped.

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
`IDUNA_HEC_TOKEN`, `APPLES_GIT_DIR`, `ADDR`, default `:8081`).
