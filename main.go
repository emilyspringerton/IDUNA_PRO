// IDUNA_PRO is the real, standalone, multi-tenant-deployable core of IDUNA -- Google OAuth +
// local password auth, ES256 JWT issuance/refresh/JWKS, M2M agent auth, hierarchical RBAC, the
// Apples-style append-only audit ledger, and the unified Splunk-shaped logging backend. Extracted
// 2026-09-03 (EMILY/BACKLOG.md S243-06) per real founder direction ("we pull some of the more
// custom stuff out of iduna and the code goes right into the emily for business product
// IDUNA_PRO"), from the real, checked categorization in
// IDUNA/docs/EMILY_FOR_BUSINESS_NORTHSTAR.md's own "IDUNA_PRO — a real extraction plan" section.
//
// Deliberately NOT here (see that NORTHSTAR doc for the full list and reasoning): the full Back
// Office admin UI (`admin.go`), the developer portal, blog/tyler/promptoverse/drive/vault, every
// game-specific handler (mmo/redgarden/shankpit/papercraft/racer), HEIMDAL, push tokens. Each is
// a real, later, separate decision -- not silently dropped, just not extracted yet.
//
// mailinglist WAS on that "not here" list -- extracted 2026-09-05 (S245-05) once S245-01/02/03
// existed as real APIs in IDUNA and this repo's own admin surface (S243-08's kanban board)
// needed a settings page to sit alongside (S245-04). Generalized on the way out: no hardcoded
// AllowOrigin/per-product MailchimpLists (the real, checked EINHORN-specific parts) -- a tenant
// configures its own origin via MAILING_LIST_ALLOW_ORIGIN instead. Copied, not reinvented:
// internal/mailinglist is package-identical to IDUNA's own (zero cross-imports to begin with,
// so the port needed no internal changes at all), internal/http/handlers/mailinglist.go only
// needed its two "iduna/..." import paths rewritten to "idunapro/...".
//
// The kanban board (S243-08, founder real-time: "build the kanban into IDUNA_PRO its a good
// affordance for interop between human and agents... one of the core integration points") IS
// here, generalized: `internal/backlog`/`kanban.go`/`kanban_page.go`/`kanban_inbox.go` are real,
// checked-generic (they parse ANY markdown-checkbox file at a configurable path, not
// EMILY/BACKLOG.md specifically) and copied verbatim. `admin_login.go` came along too -- it
// turned out NOT to import internal/mailinglist at all (only auth/jwt, store, userlog, all
// already core), so the kanban board's own real cookie-session login page didn't need to be
// invented from scratch. `BACKLOG_PATH` unset (this binary's own default) means a pure,
// generic, DB-backed board with no markdown sync at all -- opt into sync only if you want it.
//
// One real, structural, honestly-named gap inherited from the source repo, not solved here:
// store.IAMStore is one large interface spanning every feature (including ones NOT extracted,
// e.g. GFD subscription tiers, check-in monitors) -- internal/http/handlers/stub_gfd_test.go's
// own no-op stubs exist because of this. Narrowing IAMStore into per-feature interfaces is real,
// separate, unstarted work; every method needed by the handlers actually wired below is real and
// used, the unused ones just ride along on the same interface for now.
package main

import (
	"context"
	"database/sql"
	"encoding/hex"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	_ "github.com/go-sql-driver/mysql"

	"idunapro/internal/auth/device"
	authjwt "idunapro/internal/auth/jwt"
	"idunapro/internal/http/handlers"
	"idunapro/internal/http/middleware"
	"idunapro/internal/mailinglist"
	"idunapro/internal/store"
	"idunapro/internal/userlog"
	"idunapro/internal/util"
)

func main() {
	var db *sql.DB
	var iamStore store.IAMStore

	dsn := os.Getenv("MYSQL_DSN")
	if dsn != "" {
		var err error
		db, err = sql.Open("mysql", dsn)
		if err != nil {
			log.Fatal(err)
		}
		defer db.Close()
		if err := db.Ping(); err != nil {
			log.Fatal(err)
		}
		iamStore = store.NewMySQLStore(db)
		log.Println("store: MySQL")
	} else {
		dbPath := getenv("SQLITE_PATH", filepath.Join("var", "iduna.db"))
		var err error
		db, err = store.OpenSQLite(dbPath)
		if err != nil {
			log.Fatalf("open sqlite: %v", err)
		}
		defer db.Close()

		root := getenv("IDUNA_PRO_ROOT", ".")
		migrationsDir := filepath.Join(root, "migrations", "truestore")
		if err := store.RunSQLiteMigrations(db, migrationsDir); err != nil {
			log.Fatalf("sqlite migrations: %v", err)
		}

		iamStore = store.NewSQLiteStore(db)
		log.Printf("store: SQLite (embedded) at %s", dbPath)
	}

	issuer := getenv("JWT_ISSUER", "https://iam.farthq.internal")
	baseURL := getenv("BASE_URL", "http://localhost:8081")
	googleClientID := os.Getenv("GOOGLE_CLIENT_ID")

	keyFile := getenv("KEY_FILE", "./idunapro-key.json")
	keys, err := authjwt.LoadOrGenerateKeys(keyFile)
	if err != nil {
		log.Fatalf("loading ES256 keys: %v", err)
	}

	root := getenv("IDUNA_PRO_ROOT", ".")

	// User event log + projector -- the same shape IDUNA itself uses (real, existing local-user
	// auth flow, not new design).
	userEventLogDir := filepath.Join(root, "var", "user-events")
	uel, err := userlog.NewFileEventLog(userEventLogDir)
	if err != nil {
		log.Fatalf("user event log: %v", err)
	}
	defer uel.Close()

	var userProj userlog.UserProjector
	if dsn != "" {
		userProj = userlog.NewMySQLProjector(db)
	} else {
		userProj = userlog.NewSQLiteProjector(db)
	}

	// Unified logging backend (Splunk-shaped: POST /services/collector, GET
	// /services/search/jobs) -- a real, sellable feature in its own right per the NORTHSTAR
	// doc's own "what's real today" section.
	unifiedLogDir := filepath.Join(root, "var", "eventlog")
	unifiedLog, err := userlog.NewFileEventLog(unifiedLogDir)
	if err != nil {
		log.Fatalf("unified event log: %v", err)
	}
	defer unifiedLog.Close()

	// Device flow.
	var deviceStore device.Store
	if dsn != "" {
		deviceStore = device.NewMySQLStore(db)
	} else {
		deviceStore = device.NewSQLiteDeviceStore(db)
	}
	svc := device.NewService(deviceStore)
	deviceH := &handlers.DeviceHandler{
		Svc:            svc,
		StartLimiter:   util.NewWindowRateLimiter(10, time.Minute),
		ConfirmLimiter: util.NewWindowRateLimiter(20, time.Minute),
		JWTSecret:      []byte(os.Getenv("JWT_SECRET")),
		BaseURL:        baseURL,
	}

	googleAuthH := &handlers.GoogleAuthHandler{GoogleClientID: googleClientID, Keys: keys, Store: iamStore, Issuer: issuer, EventLog: unifiedLog}
	agentAuthH := &handlers.AgentAuthHandler{Keys: keys, Store: iamStore, Issuer: issuer, EventLog: unifiedLog}
	meH := &handlers.MeHandler{Store: iamStore, Proj: userProj, Authority: baseURL}
	jwksH := &handlers.JWKSHandler{Keys: keys}
	healthH := &handlers.HealthHandler{}
	applesH := &handlers.ApplesHandler{Store: iamStore, ApplesGitDir: os.Getenv("APPLES_GIT_DIR"), EventLog: unifiedLog}
	agentsH := &handlers.AgentsHandler{Store: iamStore}
	usersH := &handlers.UsersHandler{Log: uel, Proj: userProj}
	localAuthH := &handlers.LocalAuthHandler{Keys: keys, Proj: userProj, Issuer: issuer, EventLog: unifiedLog}
	registerH := &handlers.RegisterHandler{Keys: keys, Log: uel, Proj: userProj, Store: iamStore, Issuer: issuer}
	logsH := &handlers.LogsHandler{Store: unifiedLog, HECToken: getenv("IDUNA_HEC_TOKEN", "")}
	adminLoginH := &handlers.AdminLoginHandler{Store: iamStore, Keys: keys, Issuer: issuer, EventLog: unifiedLog}

	// Kanban board -- see this file's own header comment. BACKLOG_PATH unset (the default) means
	// a pure, generic, DB-backed board: no markdown sync, no Inbox, no auto-archive-on-done.
	backlogPath := os.Getenv("BACKLOG_PATH")
	kanbanH := &handlers.KanbanHandler{
		DB:             db,
		BacklogPath:    backlogPath,
		Store:          iamStore,
		ApplesGitDir:   os.Getenv("APPLES_GIT_DIR"),
		SourceRepoName: getenv("KANBAN_SOURCE_REPO_NAME", ""),
	}
	kanbanInboxH := &handlers.KanbanInboxHandler{DB: db, BacklogPath: backlogPath}

	// Mailing-list vault -- S245-05 extraction from IDUNA (this file's own header comment used
	// to list mailinglist under "deliberately not here"; that's now out of date). Generalized:
	// no hardcoded AllowOrigin/per-product MailchimpLists the way IDUNA's own okemily.com
	// wiring has -- those were the real, checked EINHORN-specific parts S245-05 named, so a
	// tenant configures its own origin via env instead. Starts locked, same passphrase-path
	// default as IDUNA; a tenant can opt into S245-01's file-key mode via MAILING_LIST_KEY_FILE
	// for unattended-restart signups.
	mailingListDBPath := getenv("MAILING_LIST_DB_PATH", filepath.Join(root, "var", "mailinglist.db"))
	mailingListStore, err := mailinglist.Open(mailingListDBPath)
	if err != nil {
		log.Fatalf("mailinglist: failed to open store: %v", err)
	}
	mailingListVault := mailinglist.NewVault()
	var mailchimpClient *mailinglist.MailchimpClient
	if mcKey := os.Getenv("MAILCHIMP_API_KEY"); mcKey != "" {
		mailchimpClient = mailinglist.NewMailchimpClient(mcKey, os.Getenv("MAILCHIMP_LIST_ID"))
		log.Printf("mailinglist: mailchimp sync configured (env)")
	}
	var mailingListAllowOrigin []string
	if raw := os.Getenv("MAILING_LIST_ALLOW_ORIGIN"); raw != "" {
		mailingListAllowOrigin = strings.Split(raw, ",")
	}
	mailingListH := &handlers.MailingListHandler{
		Store:       mailingListStore,
		Vault:       mailingListVault,
		Mailchimp:   mailchimpClient,
		AllowOrigin: mailingListAllowOrigin,
		Limiter:     middleware.NewIPRateLimiter(5),
	}
	if keyFilePath := os.Getenv("MAILING_LIST_KEY_FILE"); keyFilePath != "" {
		if err := mailingListAutoUnlock(mailingListStore, mailingListVault, keyFilePath); err != nil {
			log.Fatalf("mailinglist: file-key auto-unlock failed: %v", err)
		}
		log.Printf("mailinglist: vault auto-unlocked from key file %s", keyFilePath)
	} else {
		log.Printf("mailinglist: vault locked — run cmd/mailing-list-unlock to accept signups")
	}

	mux := http.NewServeMux()

	mux.Handle("/api/v1/auth/google", googleAuthH)
	mux.Handle("/api/v1/auth/agent", agentAuthH)
	mux.Handle("/api/v1/auth/refresh", &handlers.RefreshHandler{Keys: keys, Issuer: issuer})
	mux.Handle("/api/v1/identities/me", middleware.RequireAuth(keys)(middleware.RequirePermission("iduna.me.read")(meH)))
	mux.Handle("/.well-known/jwks.json", jwksH)
	mux.Handle("/api/v1/jwks", jwksH)
	mux.Handle("/health", healthH)

	applesProtected := middleware.RequireAuth(keys)(applesH)
	mux.Handle("/api/v1/apples", applesProtected)
	mux.Handle("/api/v1/apples/", applesProtected)

	usersProtected := middleware.RequireAuth(keys)(usersH)
	mux.Handle("/api/v1/users", usersProtected)
	mux.Handle("/api/v1/users/", usersProtected)

	agentsProtected := middleware.RequireAuth(keys)(agentsH)
	mux.Handle("/api/v1/agents", agentsProtected)
	mux.Handle("/api/v1/agents/", agentsProtected)

	authLimiter := middleware.NewIPRateLimiter(10)
	authRateLimit := middleware.AuthRateLimit(authLimiter)
	mux.Handle("/api/v1/auth/local", authRateLimit(localAuthH))
	mux.Handle("/api/v1/auth/register", authRateLimit(registerH))

	deviceH.Register(mux)

	handlers.RegisterLogsRoutes(mux, logsH, keys)

	// Admin login (cookie session) -- public, needed so the browser can reach it at all.
	mux.Handle("/admin/login", adminLoginH)
	mux.Handle("/admin/logout", adminLoginH)

	// Kanban board: browser UI (cookie-auth, iduna.admin) and bearer-API (kanban.access) both
	// share the SAME KanbanHandler instance -- one real code path for the actual card
	// operations, two real entry points (a human via the browser, an agent via the API), which
	// is the whole real point of this being "a core integration point" between the two.
	kanbanPageProtected := middleware.RequireCookieAuth(keys, iamStore, "/admin/login", handlers.AdminSessionTTL)(middleware.RequirePermission("iduna.admin")(&handlers.KanbanPageHandler{}))
	mux.Handle("/admin/kanban", kanbanPageProtected)
	kanbanAdminAPIProtected := middleware.RequireCookieAuth(keys, iamStore, "/admin/login", handlers.AdminSessionTTL)(middleware.RequirePermission("iduna.admin")(kanbanH))
	mux.Handle("/admin/kanban/api/cards", kanbanAdminAPIProtected)
	mux.Handle("/admin/kanban/api/cards/", kanbanAdminAPIProtected)
	mux.Handle("/admin/kanban/api/inbox", middleware.RequireCookieAuth(keys, iamStore, "/admin/login", handlers.AdminSessionTTL)(middleware.RequirePermission("iduna.admin")(kanbanInboxH)))
	kanbanAPIProtected := middleware.RequireAuth(keys)(middleware.RequirePermission("kanban.access")(kanbanH))
	mux.Handle("/api/v1/kanban/cards", kanbanAPIProtected)
	mux.Handle("/api/v1/kanban/cards/", kanbanAPIProtected)

	// Mailing-list routes — see this file's own wiring comment above.
	mailingListH.Register(mux)
	mux.Handle("/api/v1/mailing-list/export",
		middleware.RequireAuth(keys)(middleware.RequirePermission("mailinglist.export")(http.HandlerFunc(mailingListH.Export))))
	mailingListSettingsProtected := middleware.RequireAuth(keys)(middleware.RequirePermission("mailinglist.admin")(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			mailingListH.GetMailchimpSettings(w, r)
		case http.MethodPut:
			mailingListH.PutMailchimpSettings(w, r)
		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
	})))
	mux.Handle("/api/v1/mailing-list/settings/mailchimp", mailingListSettingsProtected)

	// Replay unapplied user events on startup (same real, established pattern IDUNA itself uses).
	if err := userlog.ReplayUnapplied(context.Background(), uel, userProj); err != nil {
		log.Printf("user event replay: %v (continuing)", err)
	}

	addr := getenv("ADDR", ":8081")
	log.Printf("idunapro listening on %s", addr)
	log.Fatal(http.ListenAndServe(addr, mux))
}

func getenv(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

// mailingListAutoUnlock implements S245-01's config/file-key vault mode: on first boot (vault
// not yet initialized) it generates a fresh key, writes it to keyFilePath (0600), and
// initializes the vault with it; on every subsequent boot it reads the existing key file back
// and unlocks with it. Ported verbatim from IDUNA's own main.go as part of the S245-05
// extraction.
func mailingListAutoUnlock(store *mailinglist.Store, v *mailinglist.Vault, keyFilePath string) error {
	initialized, err := store.Initialized()
	if err != nil {
		return fmt.Errorf("check vault init state: %w", err)
	}
	if !initialized {
		key, err := mailinglist.NewFileKey()
		if err != nil {
			return err
		}
		canaryCT, canaryNonce, err := mailinglist.NewCanaryFromKey(key)
		if err != nil {
			return err
		}
		if err := store.InitVault([]byte{}, canaryCT, canaryNonce); err != nil {
			return fmt.Errorf("init vault: %w", err)
		}
		if err := os.WriteFile(keyFilePath, []byte(hex.EncodeToString(key)+"\n"), 0o600); err != nil {
			return fmt.Errorf("write key file: %w", err)
		}
	}

	_, canaryCT, canaryNonce, err := store.VaultMeta()
	if err != nil {
		return fmt.Errorf("read vault meta: %w", err)
	}
	return v.UnlockFromKeyFile(keyFilePath, canaryCT, canaryNonce)
}
