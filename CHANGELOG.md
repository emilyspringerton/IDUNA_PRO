# Changelog

## 2026-09-04 (3)
- feat(cmd/idunapro): new `idunapro whoami <base-url> <token>` subcommand (cruise-queue card
  9988) -- real, now-unblocked next step, closed the same session as the `/api/v1/identities/me`
  local-auth fix above (every `login`-minted local-auth token would have gotten a bare 404 from
  `whoami` before that fix landed). Pure fetch-and-print against the real `/me` endpoint, same
  "no ambiguous response to interpret" reasoning `kanban list` already established for staying
  entirely Go-native, no new PARENA decision function needed. 4 new tests (success, unauthorized,
  unreachable, the `joinOrNone` formatting helper). `go build`/`go vet`/`go test ./...` clean,
  `gofmt` clean. Live-verified with the actual compiled binary against a real, freshly-booted
  instance: real register → real `idunapro login` → real `idunapro whoami`, correct identity
  printed.

## 2026-09-04 (2)
- fix(identities/me): real, found-live gap closed (cruise-queue card 9988, the real, standing
  blocker on the `idunapro whoami` CLI subcommand) -- `GET /api/v1/identities/me` 404'd
  unconditionally for every local-auth session. Root cause, checked directly: a local-auth
  JWT's `sub` is `"local:<uid>"` (`LocalAuthHandler`'s own convention), but `MeHandler` always
  called `h.Store.GetUserByID(ctx, sub)`, which queries the separate `users` table by its own
  real `id` column -- local-auth accounts live in `local_users` instead (a real, separate
  projection, confirmed directly), and have never had a row in `users` at all. Fixed:
  `MeHandler` now branches on a `"local:"` prefix, resolving through the same
  `userlog.UserProjector.GetByUID` the login handler itself already uses, and builds the same
  real `identity`/`rbac`/`meta` response shape from the real `LocalUser` row +
  `localUserPermissions` (the exact webmaster-kanban-access fix from earlier this session).
  4 new tests (real identity resolution, unknown UID 404, webmaster's own kanban.access showing
  up, and a nil-projector 404-not-panic guard). `go build`/`go vet`/`go test ./...` clean across
  the whole repo, `gofmt` clean. Live-verified end to end against a real, freshly-booted
  instance (fresh SQLite DB, real `/api/v1/auth/register` + `/api/v1/auth/local`, real
  `/api/v1/identities/me` call) -- not just unit tests: the real local user's own email,
  gamertag, status, and permissions all came back correctly, where this previously 404'd
  unconditionally. This was the real, named, standing blocker on the `idunapro whoami` CLI
  subcommand (cruise-queue card 9988) -- that subcommand itself is real, separate, still
  unbuilt follow-up, not shipped in this same pass.

## 2026-09-04 (1)
- feat(cmd/idunapro): two new real subcommands, `login` and `kanban list` (cruise-queue card
  9988, "the fuller multi-subcommand CLI itself" -- the gap every prior status update on this
  card named explicitly). Both stay Go-native (no new PARENA decision function): `login` is a
  pure network call with no ambiguous response to interpret, and `kanban list` is pure
  fetch-and-print, unlike `health`'s own real need to interpret an HTTP-status-plus-body-flag
  pair. `login <base-url> <email> <password>` prints the real JWT to stdout (stateless v0, no
  credential cache file -- `token=$(idunapro login ...)` is the intended usage). `kanban list
  <base-url> <token> [queue]` fetches `/api/v1/kanban/cards` and prints a real aligned table.
  7 new tests (httptest-mocked success/failure/unreachable-host paths for both). `go build/vet/
  test ./...` clean.
  Real, found-live bug fixed in the same pass: the bearer-token kanban API requires
  `kanban.access`, but `localUserPermissions` never granted it to ANY local user --
  webmaster (uid=0) included -- only a Google-OAuth user with a DB role row could ever reach it.
  Added to uid=0's own permission list (matching `devportal.access`'s own established
  "hand-grant to the two real local accounts" precedent); whether non-webmaster local users
  should also get it is a real, separate, founder-level product question, not decided here.
  2 new tests confirm webmaster's own JWT now carries it and a regular user's own JWT still
  doesn't. Live-verified end to end against a real running instance: real self-serve
  registration, real login, real kanban card creation, and the actual compiled `idunapro`
  binary correctly listing and queue-filtering the resulting real board.

## 2026-09-03 (5)
- feat: cmd/idunapro's health check simplified -- HealthMessage/HealthExitCode (compiled from
  PARENA/stdlib/idunapro/cli_mod.prn's new HealthStatus enum design, BURROW commit dd406c5)
  replace InterpretHealthResponse/ExitCodeForHealth wholesale. The old design needed
  healthErrorMessage, a Go-side switch reading a real burrowgen.HealthError's exported .Tag
  field directly, since BURROW's Go target couldn't match on a user defenum's own variant yet --
  that workaround is gone entirely now that it can. runHealth is now a pure "fetch bytes, print
  what PARENA decided" shell: PARENA owns the pass/fail decision AND the presentation message.
  internal/burrowgen/idunapro_cli_gen.go regenerated via a real `burrow build`; its own test
  file updated to match the new function names (TestClassifyHealth/TestHealthMessage/
  TestHealthExitCode). `go build/vet/test ./...` all clean. Live-verified against IDUNA's
  actual running :8080 (healthy -> exit 0, "IDUNA_PRO instance is healthy") and an unreachable
  host (exit 1). session: sess-20260902-2008-ed50169e

## 2026-09-03 (4)
- docs: real scoping pass for kanban priority-queue card WOTAN-997 ("WOTAN account signups via email/password have them confirm the password type it twice have the field like hidden with the eye thing"), applying THE_EMILY_WAY.md's own new Principle 19. New docs/WOTAN_SIGNUP_UI_SCOPING.md. Real, checked-live finding: no email/password signup HTML form exists anywhere in this monorepo today -- register.go's own real POST /api/v1/auth/register API has zero frontend, IDUNA's own portal.go password field is a login form not signup, WOTAN's own tournaments.html signup is email-only (mailing list, no password field), and IDUNA_PRO has no static-file-serving capability at all. Real, phased plan: decide hosting (IDUNA_PRO serves it directly vs WOTAN/okemily.com calls the API cross-origin, a real, small, undecided architectural question), then build the real form (email/password/confirm/show-hide toggle). No code written -- scoped, not swallowed whole.

## 2026-09-03 (3)
- feat: cmd/idunapro -- `runHealth` now presents a real `burrowgen.HealthError` (BadStatus/NotOk, a real defenum, PARENA/stdlib/idunapro/cli_mod.prn) instead of a bare error string, via a new `healthErrorMessage` host-side switch on the enum's own real, exported `.Tag` field -- BURROW's Go target still can't `match` on a user defenum itself, so the host does the presentation mapping directly, same real split this CLI's own design already established. Regenerated `internal/burrowgen/idunapro_cli_gen.go` from the updated PARENA source. `go build`/`go test ./...` clean, zero regressions. Live-verified against IDUNA's actual running `:8080` (healthy -> exit 0) and an unreachable host (exit 1). (sess-20260902-2008-ed50169e)

## 2026-09-03 (2)
- feat: cmd/idunapro -- real, honest v0 CLI proof-of-concept for kanban cruise-queue card 9988 ('emily for business CLI written in GO with BURROW'). One real subcommand, 'idunapro health <base-url>': the real HTTP GET + JSON parse stays here (Go host), but the actual decision (what a health-check response means, what exit code it earns) is real PARENA source (PARENA/stdlib/idunapro/cli_mod.prn) compiled via 'burrow build -o *.go' into internal/burrowgen/idunapro_cli_gen.go -- the first real proof this session's own newly-shipped match/Result BURROW port works end to end both constructing AND consuming a Result. No cgo/FFI boundary, same real precedent DUNG's own burrowgen usage set. Live-verified against IDUNA's actual running :8080 instance (healthy -> exit 0) and an unreachable host (exit 1). go test ./... all green, zero regressions. Real, honest scope: one subcommand, not a CLI framework -- BURROW's Go target still needs defenum/loop/Vec/struct construction before a fuller CLI is worth building. (sess-20260902-2008-ed50169e)

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
