// cmd/admin-grant is the real admin-genesis CLI (CP-SIP-ADMIN-124323, "IDUNAPRO admin accounts
// have the chicken and egg problem i need an admin account to create admin accounts"). Grants
// the is_admin flag on an EXISTING local_users account by email via direct DB access -- no
// running server, no existing-admin JWT needed, exactly the bootstrap path
// migrations/truestore/202609050004_local_users_is_admin.sql already named when it added the
// column: "no API call (and so no existing-admin JWT) needed to bootstrap." Every SUBSEQUENT
// admin grant/revoke should go through the real API instead (PATCH /api/v1/users/{uid}
// {"is_admin": true/false}, itself gated on users.admin, see internal/http/handlers/users.go) --
// this tool is for the very first admin (or recovering access), not ongoing management.
//
// Deliberately does NOT create the user account itself, and never touches password_hash -- a
// real person's password is theirs to set, not this tool's to invent or store on their behalf.
// They need to self-register first (POST /api/v1/auth/register), then this promotes the
// resulting account.
//
// Safe against the projector: internal/userlog's own SQLite/MySQL projectors only ever advance
// forward from a cursor (checked directly -- neither has any rebuild-from-scratch code path), so
// this direct write is never at risk of being silently reverted by a later event replay.
//
// Usage:
//
//	cd /home/fatbaby/IDUNA_PRO && go run ./cmd/admin-grant someone@example.com
//	SQLITE_PATH=var/iduna.db go run ./cmd/admin-grant someone@example.com   (explicit, matches default)
//	MYSQL_DSN="..." go run ./cmd/admin-grant someone@example.com           (MySQL mode)
//
// Idempotent: already-admin (or uid=0, always admin by default) reports as such, not an error.
package main

import (
	"database/sql"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"

	_ "github.com/go-sql-driver/mysql"

	"idunapro/internal/store"
)

func main() {
	flag.Parse()
	args := flag.Args()
	if len(args) != 1 {
		fmt.Fprintln(os.Stderr, "usage: admin-grant <email>")
		os.Exit(1)
	}
	email := strings.TrimSpace(strings.ToLower(args[0]))
	if email == "" {
		fmt.Fprintln(os.Stderr, "error: email required")
		os.Exit(1)
	}

	db, err := openStore()
	if err != nil {
		log.Fatalf("open store: %v", err)
	}
	defer db.Close()

	var localUID int
	var displayName string
	var isAdmin int
	err = db.QueryRow(`SELECT local_uid, display_name, is_admin FROM local_users WHERE email = ?`, email).
		Scan(&localUID, &displayName, &isAdmin)
	if err == sql.ErrNoRows {
		fmt.Fprintf(os.Stderr,
			"error: no local_users account for %q yet -- they need to self-register first "+
				"(POST /api/v1/auth/register), then re-run this\n", email)
		os.Exit(1)
	}
	if err != nil {
		log.Fatalf("query local_users: %v", err)
	}

	if localUID == 0 {
		fmt.Printf("%s (uid 0) is already admin by default -- uid=0 is always the webmaster/root admin, no grant needed\n", email)
		return
	}
	if isAdmin != 0 {
		fmt.Printf("%s (uid %d, %q) is already an admin -- nothing to do\n", email, localUID, displayName)
		return
	}

	if _, err := db.Exec(`UPDATE local_users SET is_admin = 1 WHERE local_uid = ?`, localUID); err != nil {
		log.Fatalf("grant admin: %v", err)
	}
	fmt.Printf("✓ granted admin to %s (uid %d, %q)\n", email, localUID, displayName)
}

// openStore mirrors main.go's own dual-mode (MySQL if MYSQL_DSN is set, else embedded SQLite)
// connection logic exactly, so this tool always talks to the same real database the running
// server does -- no separate config surface to drift out of sync.
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
