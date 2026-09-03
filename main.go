// IDUNA_PRO is the real, standalone, multi-tenant-deployable core of IDUNA -- Google OAuth +
// local password auth, ES256 JWT issuance/refresh/JWKS, M2M agent auth, hierarchical RBAC, the
// Apples-style append-only audit ledger, and the unified Splunk-shaped logging backend. Extracted
// 2026-09-03 (EMILY/BACKLOG.md S243-06) per real founder direction ("we pull some of the more
// custom stuff out of iduna and the code goes right into the emily for business product
// IDUNA_PRO"), from the real, checked categorization in
// IDUNA/docs/EMILY_FOR_BUSINESS_NORTHSTAR.md's own "IDUNA_PRO — a real extraction plan" section.
//
// Deliberately NOT here (see that NORTHSTAR doc for the full list and reasoning): the Back
// Office admin UI (`admin.go`/`admin_login.go`, coupled to internal/mailinglist), the developer
// portal, blog/tyler/promptoverse/mailinglist/drive/vault, every game-specific handler
// (mmo/redgarden/shankpit/papercraft/racer), kanban-over-BACKLOG.md, HEIMDAL, push tokens. Each
// is a real, later, separate decision -- not silently dropped, just not extracted yet.
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
	"log"
	"net/http"
	"os"
	"path/filepath"
	"time"

	_ "github.com/go-sql-driver/mysql"

	"idunapro/internal/auth/device"
	authjwt "idunapro/internal/auth/jwt"
	"idunapro/internal/http/handlers"
	"idunapro/internal/http/middleware"
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
	meH := &handlers.MeHandler{Store: iamStore, Authority: baseURL}
	jwksH := &handlers.JWKSHandler{Keys: keys}
	healthH := &handlers.HealthHandler{}
	applesH := &handlers.ApplesHandler{Store: iamStore, ApplesGitDir: os.Getenv("APPLES_GIT_DIR"), EventLog: unifiedLog}
	agentsH := &handlers.AgentsHandler{Store: iamStore}
	usersH := &handlers.UsersHandler{Log: uel, Proj: userProj}
	localAuthH := &handlers.LocalAuthHandler{Keys: keys, Proj: userProj, Issuer: issuer, EventLog: unifiedLog}
	registerH := &handlers.RegisterHandler{Keys: keys, Log: uel, Proj: userProj, Store: iamStore, Issuer: issuer}
	logsH := &handlers.LogsHandler{Store: unifiedLog, HECToken: getenv("IDUNA_HEC_TOKEN", "")}

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
