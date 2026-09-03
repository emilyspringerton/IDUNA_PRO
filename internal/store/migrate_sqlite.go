package store

import (
	"regexp"
	"strings"
)

// mysqlToSQLite translates a MySQL DDL/DML statement to SQLite-compatible SQL.
//
// The translation is intentionally narrow: it handles only the patterns that
// actually appear in the IDUNA migrations. It is not a general MySQL→SQLite
// converter. New patterns should be added here when a new migration introduces them.
//
// Translations applied (in order):
//  1. Remove ENGINE=... DEFAULT CHARSET=... table options
//  2. BIGINT [UNSIGNED] ... AUTO_INCREMENT → INTEGER AUTOINCREMENT (for PK columns)
//  3. AUTO_INCREMENT (non-PK context) → AUTOINCREMENT
//  4. TIMESTAMP(6) → TEXT (SQLite stores timestamps as ISO-8601 TEXT)
//  5. DEFAULT CURRENT_TIMESTAMP(6) → DEFAULT CURRENT_TIMESTAMP
//  6. ON UPDATE CURRENT_TIMESTAMP(6) → (removed; updated_at is set in Go code)
//  7. ENUM(...) → TEXT
//  8. INSERT IGNORE → INSERT OR IGNORE
//  9. TINYINT(1) → INTEGER
// 10. Remove CONSTRAINT ... FOREIGN KEY ... REFERENCES ... lines
//     (foreign keys are enforced in application logic; SQLite requires PRAGMA
//     foreign_keys=ON per-connection which adds coupling we don't need here)
// 11. Trailing commas before closing paren left by removed lines are cleaned up
// 12. ALTER TABLE ... MODIFY COLUMN ... is dropped entirely (not valid SQLite
//     syntax; SQLite columns are untyped after ENUM→TEXT translation, so
//     widening a MySQL ENUM's allowed values needs no SQLite-side change)
// 13. Bare TIMESTAMP / ON UPDATE CURRENT_TIMESTAMP (no (6) precision) get the
//     same treatment as rules 4 and 6 -- some migrations omit the precision
func mysqlToSQLite(sql string) string {
	// Split into statements and translate each independently.
	stmts := splitStatements(sql)
	out := make([]string, 0, len(stmts))
	for _, s := range stmts {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		out = append(out, translateStatement(s))
	}
	return strings.Join(out, ";\n")
}

func translateStatement(s string) string {
	// ALTER TABLE ... MODIFY COLUMN ... has no SQLite equivalent and isn't
	// needed there: ENUM columns already translated to untyped TEXT, so
	// widening the MySQL-side allowed value set is a no-op for SQLite.
	if reAlterModifyColumn.MatchString(s) {
		return ""
	}

	// Backtick identifiers → unquoted (SQLite is happy with unquoted or double-quoted).
	s = reBacktick.ReplaceAllString(s, "")

	// INSERT IGNORE → INSERT OR IGNORE
	s = reInsertIgnore.ReplaceAllString(s, "INSERT OR IGNORE")

	// Remove ENGINE=InnoDB ... and charset options (end of CREATE TABLE body).
	s = reEngine.ReplaceAllString(s, "")

	// BIGINT [UNSIGNED] NOT NULL AUTO_INCREMENT PRIMARY KEY (inline)
	// → INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT
	s = reBigintAutoIncrementPK.ReplaceAllString(s, "INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT")

	// BIGINT [UNSIGNED] NOT NULL AUTO_INCREMENT (separate PRIMARY KEY clause)
	// → INTEGER NOT NULL  (PRIMARY KEY clause in table body handles rowid assignment)
	s = reBigintAutoIncrementOnly.ReplaceAllString(s, "INTEGER NOT NULL")

	// Remaining AUTO_INCREMENT → AUTOINCREMENT
	s = reAutoIncrement.ReplaceAllString(s, "AUTOINCREMENT")

	// MEDIUMTEXT → TEXT
	s = reMediumText.ReplaceAllString(s, "TEXT")

	// TIMESTAMP(6) → TEXT
	s = reTimestamp6.ReplaceAllString(s, "TEXT")

	// ON UPDATE must be removed BEFORE the bare CURRENT_TIMESTAMP(6) rule strips the (6).
	s = reOnUpdateTS.ReplaceAllString(s, "")

	// Bare ON UPDATE CURRENT_TIMESTAMP (no (6) precision) has no SQLite
	// equivalent either -- same removal, for migrations that used bare
	// TIMESTAMP instead of TIMESTAMP(6). Must also run before reTimestampBare
	// below turns the remaining bare TIMESTAMP token into TEXT.
	s = reOnUpdateTSBare.ReplaceAllString(s, "")

	// DEFAULT CURRENT_TIMESTAMP(6) → DEFAULT CURRENT_TIMESTAMP
	s = reDefaultCurrentTS6.ReplaceAllString(s, "DEFAULT CURRENT_TIMESTAMP")

	// Bare TIMESTAMP (no (6) precision) → TEXT. Must run after reTimestamp6
	// so it only catches genuinely bare occurrences (TIMESTAMP(6) is already
	// gone by this point).
	s = reTimestampBare.ReplaceAllString(s, "TEXT")

	// CURRENT_TIMESTAMP(6) anywhere else (e.g. in VALUES) → CURRENT_TIMESTAMP
	s = reTimestamp6Bare.ReplaceAllString(s, "CURRENT_TIMESTAMP")

	// ENUM('A','B',...) → TEXT
	s = reEnum.ReplaceAllString(s, "TEXT")

	// TINYINT(1) → INTEGER
	s = reTinyint1.ReplaceAllString(s, "INTEGER")

	// MySQL column COMMENT 'text' — remove; SQLite does not support it.
	s = reColumnComment.ReplaceAllString(s, "")

	// Remove CONSTRAINT ... FOREIGN KEY ... lines entirely.
	// These lines appear inside CREATE TABLE blocks.
	s = removeForeignKeyLines(s)

	// Remove trailing commas before closing paren (left by removed FK lines).
	s = cleanTrailingCommas(s)

	return s
}

var (
	reInsertIgnore = regexp.MustCompile(`(?i)\bINSERT\s+IGNORE\b`)

	// Strip ENGINE=... table options but leave the closing ) intact.
	reEngine = regexp.MustCompile(`(?im)\s+ENGINE\s*=\s*\S+.*$`)

	// BIGINT|INTEGER [UNSIGNED] ... PRIMARY KEY AUTO_INCREMENT → INTEGER PRIMARY KEY AUTOINCREMENT
	// SQLite requires AUTOINCREMENT to immediately follow PRIMARY KEY, so any
	// ordering of NOT NULL/AUTO_INCREMENT/PRIMARY KEY around the integer type
	// collapses to the one legal form.
	reBigintAutoIncrementPK = regexp.MustCompile(`(?i)\b(?:BIGINT|INTEGER)(?:\s+UNSIGNED)?\s+(?:NOT\s+NULL\s+)?(?:AUTO_INCREMENT\s+PRIMARY\s+KEY|PRIMARY\s+KEY\s+AUTO_INCREMENT)`)

	// BIGINT|INTEGER [UNSIGNED] NOT NULL AUTO_INCREMENT (without inline PRIMARY KEY — it's defined separately).
	// Convert to INTEGER NOT NULL; strip AUTO_INCREMENT — SQLite rowid handles it via PRIMARY KEY clause.
	reBigintAutoIncrementOnly = regexp.MustCompile(`(?i)\b(?:BIGINT|INTEGER)(?:\s+UNSIGNED)?\s+NOT\s+NULL\s+AUTO_INCREMENT\b`)

	// Remaining AUTO_INCREMENT → AUTOINCREMENT (shouldn't appear after the above but be safe).
	reAutoIncrement = regexp.MustCompile(`(?i)\bAUTO_INCREMENT\b`)

	reTimestamp6        = regexp.MustCompile(`(?i)\bTIMESTAMP\(6\)`)
	reDefaultCurrentTS6 = regexp.MustCompile(`(?i)\bDEFAULT\s+CURRENT_TIMESTAMP\(6\)`)
	// CURRENT_TIMESTAMP(6) used as a bare value expression (e.g. in INSERT VALUES).
	reTimestamp6Bare    = regexp.MustCompile(`(?i)\bCURRENT_TIMESTAMP\(6\)`)
	reOnUpdateTS        = regexp.MustCompile(`(?i)\s*ON\s+UPDATE\s+CURRENT_TIMESTAMP\(6\)`)
	// Bare variants (no (6) precision) of the same two patterns.
	reOnUpdateTSBare = regexp.MustCompile(`(?i)\s*ON\s+UPDATE\s+CURRENT_TIMESTAMP\b`)
	reTimestampBare  = regexp.MustCompile(`(?i)\bTIMESTAMP\b`)
	reEnum              = regexp.MustCompile(`(?i)\bENUM\([^)]+\)`)
	reTinyint1          = regexp.MustCompile(`(?i)\bTINYINT\(1\)`)

	// MySQL text types that map to SQLite TEXT.
	reMediumText = regexp.MustCompile(`(?i)\bMEDIUMTEXT\b`)

	// Backtick identifiers → plain identifiers (SQLite uses double-quotes; unquoted also works).
	reBacktick = regexp.MustCompile("`")

	reConstraintFK = regexp.MustCompile(`(?i)^\s*CONSTRAINT\s+\S+\s+FOREIGN\s+KEY\b.*$`)

	reAlterModifyColumn = regexp.MustCompile(`(?im)^\s*ALTER\s+TABLE\s+\S+\s+MODIFY\s+COLUMN\b`)

	// MySQL inline KEY / INDEX / UNIQUE KEY / INDEX definitions inside CREATE TABLE.
	// SQLite does not support inline index definitions; strip them.
	// Critical uniqueness constraints are expressed via UNIQUE on column definitions.
	reInlineKey = regexp.MustCompile(`(?i)^\s*(?:(?:UNIQUE\s+)?KEY|INDEX)\s+\S+\s*\(.*\)\s*,?\s*$`)

	// MySQL column COMMENT 'text' syntax — SQLite does not support it.
	reColumnComment = regexp.MustCompile(`(?i)\s+COMMENT\s+'[^']*'`)

	reTrailingCommaBeforeParen = regexp.MustCompile(`,\s*\)`)
)

func removeForeignKeyLines(s string) string {
	lines := strings.Split(s, "\n")
	kept := lines[:0]
	for _, line := range lines {
		if reConstraintFK.MatchString(line) || reInlineKey.MatchString(line) {
			continue
		}
		kept = append(kept, line)
	}
	return strings.Join(kept, "\n")
}

// cleanTrailingCommas removes commas immediately before a closing paren that
// result from deleting lines inside a CREATE TABLE body.
func cleanTrailingCommas(s string) string {
	// Handle ", )" patterns left when a line is removed.
	// Repeat until stable (multiple consecutive removed lines).
	prev := ""
	for prev != s {
		prev = s
		s = reTrailingCommaBeforeParen.ReplaceAllString(s, ")")
	}
	return s
}

// splitStatements splits a SQL file into individual statements on semicolons,
// handling string literals and -- line comments (semicolons inside both are ignored).
// Does not handle block comments or $$ delimiters — not needed for these migrations.
func splitStatements(sql string) []string {
	var stmts []string
	var buf strings.Builder
	inSingle := false
	inDouble := false
	inLineComment := false

	for i := 0; i < len(sql); i++ {
		ch := sql[i]

		if inLineComment {
			buf.WriteByte(ch)
			if ch == '\n' {
				inLineComment = false
			}
			continue
		}

		// Detect start of line comment (only outside string literals).
		if ch == '-' && !inSingle && !inDouble && i+1 < len(sql) && sql[i+1] == '-' {
			inLineComment = true
			buf.WriteByte(ch)
			continue
		}

		switch {
		case ch == '\'' && !inDouble:
			inSingle = !inSingle
		case ch == '"' && !inSingle:
			inDouble = !inDouble
		case ch == ';' && !inSingle && !inDouble:
			stmt := strings.TrimSpace(buf.String())
			if stmt != "" {
				stmts = append(stmts, stmt)
			}
			buf.Reset()
			continue
		}
		buf.WriteByte(ch)
	}
	if stmt := strings.TrimSpace(buf.String()); stmt != "" {
		stmts = append(stmts, stmt)
	}
	return stmts
}
