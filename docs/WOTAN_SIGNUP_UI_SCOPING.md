# Scoping note — WOTAN account signup UI (password confirm + show/hide)

Real, direct scoping pass for kanban priority-queue card `WOTAN-997`: *"WOTAN account signups
via email/password have them confirm the password type it twice have the field like hidden with
the eye thing."* Per `THE_EMILY_WAY.md`'s own new Principle 19 (kanban `GOLDENOPS-001`): checked
what already exists before building, found this is genuinely bigger than the literal ask alone —
scoped here, returned to `BACKLOG.md` as real sub-tasks rather than attempted whole in one pass.

## Real, checked-live finding: no signup HTML exists anywhere yet

Searched this whole monorepo directly, not assumed: **no email/password signup HTML form exists
today**, for WOTAN or otherwise. What's real and already there:
- `IDUNA_PRO/internal/http/handlers/register.go` — a real, working, JSON-only
  `POST /api/v1/auth/register` endpoint (email + password + optional display name, bcrypt-hashed,
  issues a real JWT) — but genuinely zero HTML/frontend calling it.
- `IDUNA/internal/http/handlers/portal.go` — a real password field, but it's a LOGIN form
  (`autocomplete="current-password"`, one field), not a signup form needing confirmation.
- `OKEMILY/tournaments.html` (the real WOTAN page) — a real signup form, but email-only (a
  mailing-list capture, no password field at all).
- **IDUNA_PRO has no static-file-serving capability at all** — checked directly, no
  `http.FileServer`/`ServeFile` anywhere in its own HTTP setup.

## What this means for the literal ask

`WOTAN-997`'s own request (confirm-password, a show/hide "eye" toggle) is a real, small UX
detail — but there is no existing signup PAGE to add it to. Building it means:
1. A real, minimal signup page (email, password, confirm-password with a show/hide toggle) — the
   actual literal ask, once a page exists to put it on.
2. A real, open, NOT-yet-decided question: where does this page live? Two real options — (a)
   IDUNA_PRO serves it directly (needs real static-file serving added, a genuinely new capability
   for that service), or (b) WOTAN/`okemily.com` hosts the HTML and calls IDUNA_PRO's API
   cross-origin (needs real CORS configuration on the API side, also not present today). This is
   a real, small architectural decision, not resolved here.

## Real, phased plan (none started)

**Phase 1** — decide hosting (per the open question above), then add whichever real, small piece
is missing (static serving in IDUNA_PRO, or CORS headers on `register.go`).

**Phase 2** — the real signup form itself: email, password, confirm-password (client-side match
check before submit), a real show/hide toggle on both password fields (a standard, small,
well-understood UI pattern — no real design risk here, the only real blocker was Phase 1's own
missing page to put it on).

## Related

- `IDUNA_PRO/internal/http/handlers/register.go` — the real, existing API this form would call.
- `EMILY/docs/THE_EMILY_WAY.md` Principle 19 — the real, new standing procedure this scoping note
  follows.
