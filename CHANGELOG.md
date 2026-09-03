# Changelog

## 2026-09-03

- Real V0: extracted from `IDUNA` per founder direction ("we pull some of the more custom stuff
  out of iduna and the code goes right into the emily for business product IDUNA_PRO"). Core
  packages copied verbatim (`internal/auth`, `internal/store`, `internal/userlog`,
  `internal/util`, `internal/http/middleware`) plus core handlers (Google/local/agent/device
  auth, JWT refresh, self-serve registration, `/me`, users, agents, Apples, unified logging) —
  checked directly first: zero cross-imports from these into any excluded custom package
  (blog/tyler/promptoverse/mailinglist/vault/drive/statuspage/backlog). New standalone `go.mod`
  (module `idunapro`, `GOWORK=off`), new `main.go` wiring only the extracted handlers, 7 core
  migration files copied (device_auth, iam_rbac, agent_credentials, apples, local_users,
  missing_agents_table_rows, agent_pending_status) — the EINHORN-specific `system_seeds.sql` and
  `cluster_heartbeats.sql` were deliberately left out. `go build`/`vet`/`test ./...` clean.
  **Live-verified**, not just compiled: booted the real binary against a fresh SQLite file
  (migrations ran clean, created exactly the expected core tables and none of the excluded
  ones), confirmed `/health`, a real ES256 key from `/.well-known/jwks.json`, a real self-serve
  `POST /api/v1/auth/register` issuing a real JWT, and `POST /api/v1/auth/local` correctly
  rejecting bad credentials. **Real, honest, found gap, not fixed here**: `GET
  /api/v1/identities/me` doesn't resolve a local-auth JWT's subject (`local:<N>`) — confirmed
  this is a pre-existing gap inherited from IDUNA's own `store.GetUserByID` implementation, not
  introduced by this extraction, but named because it matters more for a self-serve-auth-first
  product. Full extraction plan/categorization/control-plane model:
  `IDUNA/docs/EMILY_FOR_BUSINESS_NORTHSTAR.md`. (sess-20260902-2008-ed50169e)
