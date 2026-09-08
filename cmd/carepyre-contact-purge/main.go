// cmd/carepyre-contact-purge deletes carepyre_contact_submissions rows that have been marked
// "resolved" for at least 90 days (founder real-time, 2026-09-08, deciding the retention policy
// this repo's own CarePyre contact-form home never had before: "90 days after resolved").
// Deliberately does NOT touch anything still status="new" -- an unresolved submission is never
// auto-deleted, however old.
//
// Intended to run on a schedule via a user-level systemd timer (no sudo needed -- see
// scripts/carepyre-contact-purge.service/.timer, same real, already-established pattern
// IDUNA/scripts/promptoverse-thumbnails.service/.timer uses), not continuously in-process.
// Idempotent and safe to run more often than needed: a run that finds nothing overdue is a
// no-op, not an error.
//
// Usage:
//
//	cd /home/fatbaby/IDUNA_PRO && go run ./cmd/carepyre-contact-purge
//	SQLITE_PATH=var/iduna.db go run ./cmd/carepyre-contact-purge   (explicit, matches default)
//	MYSQL_DSN="..." go run ./cmd/carepyre-contact-purge            (MySQL mode)
//	go run ./cmd/carepyre-contact-purge -dry-run                   (report count, delete nothing)
package main

import (
	"database/sql"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"time"

	_ "github.com/go-sql-driver/mysql"

	"idunapro/internal/store"
)

func main() {
	dryRun := flag.Bool("dry-run", false, "report how many rows would be deleted, without deleting")
	retentionDays := flag.Int("retention-days", 90, "days after resolved_at before a submission is purged")
	flag.Parse()

	db, err := openStore()
	if err != nil {
		log.Fatalf("open store: %v", err)
	}
	defer db.Close()

	cutoff := time.Now().UTC().AddDate(0, 0, -*retentionDays).Format("2006-01-02 15:04:05")

	if *dryRun {
		var n int
		if err := db.QueryRow(
			`SELECT COUNT(*) FROM carepyre_contact_submissions WHERE status = 'resolved' AND resolved_at < ?`,
			cutoff,
		).Scan(&n); err != nil {
			log.Fatalf("count overdue rows: %v", err)
		}
		fmt.Printf("dry-run: %d submission(s) resolved before %s would be purged\n", n, cutoff)
		return
	}

	res, err := db.Exec(
		`DELETE FROM carepyre_contact_submissions WHERE status = 'resolved' AND resolved_at < ?`,
		cutoff,
	)
	if err != nil {
		log.Fatalf("purge: %v", err)
	}
	n, _ := res.RowsAffected()
	fmt.Printf("✓ purged %d submission(s) resolved before %s\n", n, cutoff)
}

// openStore mirrors main.go's own dual-mode (MySQL if MYSQL_DSN is set, else embedded SQLite)
// connection logic exactly, same as cmd/admin-grant, so this tool always talks to the same real
// database the running server does.
func openStore() (*sql.DB, error) {
	if dsn := os.Getenv("MYSQL_DSN"); dsn != "" {
		db, err := sql.Open("mysql", dsn)
		if err != nil {
			return nil, err
		}
		if err := db.Ping(); err != nil {
			return nil, err
		}
		return db, nil
	}
	root := getenv("IDUNA_PRO_ROOT", ".")
	dbPath := getenv("SQLITE_PATH", filepath.Join(root, "var", "iduna.db"))
	return store.OpenSQLite(dbPath)
}

func getenv(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}
