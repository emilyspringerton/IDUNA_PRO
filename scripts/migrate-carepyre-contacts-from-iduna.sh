#!/usr/bin/env bash
# One-time data migration: copies every row out of IDUNA's own
# carepyre_contact_submissions table (var/iduna.db there) into this repo's new
# home for that data (migrations/truestore/202609080001_carepyre_contact_submissions.sql).
# Founder real-time, 2026-09-08: "move the contact form to idunapro."
#
# Safe to re-run: an INSERT...WHERE NOT EXISTS guard (matching on name/email/message/created_at
# together, not a schema-level UNIQUE constraint this table deliberately doesn't carry) means a
# second run does not duplicate rows already copied. Every migrated row gets status='new' regardless of
# how old it is -- there is no historical "resolved" state recorded on the old table, and
# defaulting to 'new' is the safe choice: it means an admin has to actively triage it before the
# 90-day post-resolution purge clock (cmd/carepyre-contact-purge) can ever start on it, rather
# than silently starting a countdown on data nobody has looked at yet.
#
# This does NOT touch or drop the old IDUNA table -- it is left in place, frozen, as a read-only
# historical backup, a deliberate, conservative choice (see the new migration's own doc comment).
#
# Usage:
#   cd /home/fatbaby/IDUNA_PRO && ./scripts/migrate-carepyre-contacts-from-iduna.sh
#   IDUNA_DB=/path/to/iduna.db IDUNA_PRO_DB=/path/to/iduna.db ./scripts/migrate-carepyre-contacts-from-iduna.sh
set -euo pipefail

IDUNA_DB="${IDUNA_DB:-/home/fatbaby/IDUNA/var/iduna.db}"
IDUNA_PRO_DB="${IDUNA_PRO_DB:-/home/fatbaby/IDUNA_PRO/var/iduna.db}"

if [ ! -f "$IDUNA_DB" ]; then
    echo "error: source DB not found at $IDUNA_DB" >&2
    exit 1
fi
if [ ! -f "$IDUNA_PRO_DB" ]; then
    echo "error: destination DB not found at $IDUNA_PRO_DB -- run IDUNA_PRO's own migrations first" >&2
    exit 1
fi

before=$(sqlite3 "$IDUNA_PRO_DB" "SELECT COUNT(*) FROM carepyre_contact_submissions;")

sqlite3 "$IDUNA_PRO_DB" <<SQL
ATTACH DATABASE '$IDUNA_DB' AS src;
INSERT INTO carepyre_contact_submissions (name, email, message, status, created_at)
SELECT s.name, s.email, s.message, 'new', s.created_at
FROM src.carepyre_contact_submissions s
WHERE NOT EXISTS (
    SELECT 1 FROM carepyre_contact_submissions d
    WHERE d.name = s.name AND d.email = s.email AND d.message = s.message AND d.created_at = s.created_at
);
DETACH DATABASE src;
SQL

after=$(sqlite3 "$IDUNA_PRO_DB" "SELECT COUNT(*) FROM carepyre_contact_submissions;")

echo "✓ migrated $((after - before)) row(s) (before=$before, after=$after)"
echo "  IDUNA's own copy at $IDUNA_DB was left untouched."
