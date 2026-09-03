# Changelog

## 2026-09-03 (2)

- S243-08: real kanban board added, generalized as a human/agent integration point. Founder
  real-time: "build the kanban into IDUNA_PRO its a good affordance for interop between human
  and agents - we will probably build tools on top of the IDUNA_PRO like this is one of the
  core integration points." Copied `internal/backlog` (a real, generic markdown-checkbox parser
  — takes any file path, not hardcoded to `EMILY/BACKLOG.md`) and `kanban.go`/`kanban_page.go`/
  `kanban_inbox.go` verbatim: every BACKLOG.md-specific behavior (bare-section resolution, git
  auto-commit, Inbox sync) was already gated behind an empty-string check on `BacklogPath` in
  the source — confirmed by reading the code, not assumed — so leaving `BACKLOG_PATH` unset
  (this binary's own default) yields a pure, generic, DB-backed board with zero markdown
  coupling. Two real fixes for genuine product-context gaps found: (1) `fileCompletionApple`
  hardcoded `SourceRepo: "EMILY"` — now a real, configurable `KANBAN_SOURCE_REPO_NAME` env var,
  defaulting to `"kanban"`; (2) the board's own user-visible copy text and the Inbox pane's
  503-not-configured message were rewritten to be product-neutral instead of naming EMILY/
  BACKLOG.md. `admin_login.go` came along too — checked its imports directly and found it does
  NOT depend on `internal/mailinglist` (only `auth/jwt`, `store`, `userlog`, all already core),
  unlike `admin.go` itself — so the board's real cookie-session login page didn't need
  inventing from scratch. Two new core migrations (`kanban_cards`, `kanban_access_permission`),
  both self-contained SQLite DDL. `go build/vet/test ./...` clean. **Live-verified end to end**:
  booted the real binary, minted a real agent JWT with `kanban.access`, created/listed/moved a
  card to Done via the bearer API — confirmed the resulting Apple's `source_repo` reads `kanban`
  (not `EMILY`) and the card was actually removed from the table; separately logged in via
  `/admin/login` (real cookie session), loaded the real `/admin/kanban` page (S207-68's own
  drag-sort JS intact), and created a card through the cookie-authenticated admin API — the same
  underlying handler serving both a human and an agent caller, the actual point of this feature.
  (sess-20260902-2008-ed50169e)

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
