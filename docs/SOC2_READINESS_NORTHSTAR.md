# SOC 2 Readiness — Emily for Business / IDUNA_PRO (2026-09-07)

## Where this comes from

Founder real-time, 2026-09-07: "anything we can do to get ahead of soc 2 compliance in case that
becomes a thing we want soc 2 on the whole emily for business platform including the platform
idunapro offering." Same honest-scoping discipline every other `*_NORTHSTAR.md` in this monorepo
follows: **this document is not a SOC 2 report and does not claim SOC 2 compliance.** SOC 2 is a
real audit performed by a licensed, independent CPA firm against the AICPA's Trust Services
Criteria over an observation period (Type II) or a point in time (Type I) — no amount of code
changes makes a system "SOC 2 compliant" without that real, external audit. What this document
does: maps what IDUNA_PRO/Emily for Business already has today against the five Trust Services
Criteria, and names the real, concrete gaps an eventual audit would actually ask about — so the
groundwork (evidence, controls, documentation) exists before a real auditor engagement, rather
than starting from zero.

## The five Trust Services Criteria, mapped honestly

### 1. Security (the only criterion every SOC 2 report must include)

**Real, already built:**
- ES256 JWT auth (hand-rolled on `crypto/ecdsa`, no external JWT library), M2M agent auth,
  device flow, Google OAuth + local password (bcrypt).
- Hierarchical RBAC, now a real 4-tier model (Top Admin / Operator Admin / Provider Admin /
  Provider Operator — CP-HIPAA-2, this same session) with server-enforced least-privilege
  scoping, not just UI-level hiding.
- An append-only "Apples" audit ledger and a unified Splunk-shaped logging backend
  (`internal/userlog`'s own event log, `LogsHandler`) — real audit-trail infrastructure, a
  concrete SOC 2 evidence source for "who did what, when."
- Self-service PGP/S-MIME encryption-at-rest for CarePyre mailboxes, TLS in transit everywhere.
- Real, working GDPR-style data export/erasure pipeline (`internal/gdpr`, this same session) —
  redaction-in-place that preserves audit-log structural integrity, a genuinely harder bar than
  most systems clear.

**Real, honest gaps:**
- No formal, written risk assessment or asset inventory.
- No vulnerability scanning / penetration testing has ever been run against this codebase or its
  live deployments.
- No documented incident response plan (who does what when something goes wrong) — Apples/
  logging give you the forensic trail, but there's no runbook for actually responding.
- No employee/contractor background-check or security-training program (mostly a
  people/process gap, not a code gap — this monorepo doesn't have "employees" in the traditional
  sense yet).
- No documented change-management process beyond this repo's own commit/Apple/changelog
  discipline (real and consistent, but never written up as a formal policy an auditor could
  review).
- No secrets-management / key-rotation policy beyond "env vars, rotate manually" (`MAIL_
  CREDENTIALS_KEY`, `JWT_SECRET`, etc.) — functional, not formally documented or rotated on a
  schedule.

### 2. Availability

**Real, already built:** systemd `--user` service supervision, health-check endpoints
(`/health`), the tenant-provisioning control plane's own port-allocation + health-poll pattern.

**Real, honest gaps:** no formal uptime SLA, no documented disaster-recovery/backup-restore
procedure (SQLite files are real and present on disk, but there's no tested restore drill), no
monitoring/alerting stack (no Prometheus/Grafana/PagerDuty-equivalent anywhere in this
monorepo) — an outage is discovered by a human noticing, not paged.

### 3. Processing Integrity

**Real, already built:** the event-sourced `userlog` architecture itself is a strong processing-
integrity story (every mutation is a real, append-only, replayable event; the SQL projection is
derived, not authoritative) — a genuinely above-average design for this criterion specifically.

**Real, honest gaps:** no automated data-validation/reconciliation checks between the event log
and its projections (an auditor would want evidence the two can't silently drift), no documented
input-validation standard beyond what's visible in each handler's own code.

### 4. Confidentiality

**Real, already built:** encryption at rest (opt-in, PGP/S-MIME for mail), encryption in transit
(TLS), least-privilege RBAC (CP-HIPAA-1/CP-HIPAA-2), minimum-necessary scoping enforced
server-side (provider-created-by filtering on mailboxes and SIP accounts).

**Real, honest gaps:** no formal data-classification policy (what's "confidential" vs. merely
"internal" isn't written down anywhere), no DLP (data loss prevention) tooling, encryption at
rest is opt-in rather than default/enforced (a deliberate founder decision per CP-HIPAA-1 —
"forcefully encourage... not require" — but an auditor would flag it as a real gap regardless of
the reasoning).

### 5. Privacy

**Real, already built:** a draft Privacy Policy (`CarePyre/privacy.html`, this same session)
naming real data practices; the GDPR export/deletion pipeline doubles as real technical
infrastructure for privacy-rights requests generally, not just EU-specific.

**Real, honest gaps:** no formal Data Processing Agreement (DPA) template for customers/tenants,
no documented data-retention SCHEDULE (the Privacy Policy describes the policy in prose, but
there's no automated enforcement — e.g. auto-purging logs after N days), no third-party
sub-processor list (a real SOC 2 Privacy-criterion requirement once any external vendor —
Twilio, a cloud host, etc. — touches customer data).

## Real, concrete next steps (not started, honestly named)

1. **Written information security policy** — the single most commonly-requested SOC 2 artifact
   this monorepo doesn't have at all. A real, standalone doc naming roles/responsibilities,
   acceptable use, incident response, and change management — mostly writing down practices that
   already exist informally, not inventing new ones.
2. **A vendor/sub-processor registry** — every third-party service that touches customer data
   (Twilio, the mail host, any cloud provider) named in one place with what data each one sees.
3. **A basic monitoring/alerting layer** — even a minimal uptime-ping + log-based alert would
   close a real, named Availability gap cheaply.
4. **A real backup/restore drill** — prove the SQLite-file backup story actually works by
   restoring from one, not just assuming it would.
5. **Engage a real SOC 2 readiness assessor or auditor** when the founder decides to actually
   pursue a report — this document is preparation, not a substitute for that real, external
   process.

## Related

- `CarePyre/docs/HIPAA_COMPLIANCE_NORTHSTAR.md` — the same real, honest-gaps discipline applied
  to HIPAA instead of SOC 2, built the same day; several controls (RBAC tiers, minimum-necessary
  scoping, encryption encouragement) serve both frameworks simultaneously.
- `internal/gdpr` — the real data export/erasure pipeline underpinning the Privacy criterion.
- `IDUNA/docs/EMILY_FOR_BUSINESS_NORTHSTAR.md` — the platform-level product scoping this
  document's "whole Emily for Business platform" framing refers to.
