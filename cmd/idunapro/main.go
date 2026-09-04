// Command idunapro is the real, honest v0 first slice of "the CLI for Emily for Business and
// IDUNA_PRO" (kanban cruise-queue card 9988: "emily for business CLI written in GO with
// BURROW"). Real "mods first everything" split: this Go host owns everything BURROW's Go
// emission target genuinely can't do yet -- os.Args parsing, the real HTTP call to a customer's
// own IDUNA_PRO instance, stdout/stderr, process exit codes. The actual DECISION logic (what a
// health-check response means, what exit code it earns, and what message to print) is real
// PARENA source (PARENA/stdlib/idunapro/cli_mod.prn), compiled via `burrow build ... -o *.go`
// into internal/burrowgen/idunapro_cli_gen.go and called directly here -- no cgo/FFI boundary,
// the same real precedent DUNG's own burrowgen usage already established.
//
// Real v0 scope grows here (cruise-queue card 9988's own still-open "the fuller multi-subcommand
// CLI itself" gap, named explicitly across every prior status update in EMILY/BACKLOG.md): two
// more real subcommands, `idunapro login` and `idunapro kanban list`, both genuinely useful
// against a real running IDUNA_PRO instance. Neither needed a new PARENA decision function --
// `login` is a pure network call with no ambiguous response to interpret (either the server
// returns a token or it doesn't), and `kanban list` is pure fetch-and-print, so both stay
// entirely Go-native, matching this file's own established "Go owns everything BURROW's target
// genuinely can't do yet, or doesn't need to" split. Growing the PARENA-decision-logic side
// further (a defenum-based decision for `kanban list`'s own queue-filter validation, say) is
// real, separate, later work -- not attempted here, since a plain string comparison needs no
// real decision-interpretation the way health's own HTTP-status-plus-body-flag pair did.
package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"text/tabwriter"
	"time"

	"idunapro/internal/burrowgen"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}

	switch os.Args[1] {
	case "health":
		if len(os.Args) < 3 {
			fmt.Fprintln(os.Stderr, "usage: idunapro health <base-url>")
			os.Exit(2)
		}
		os.Exit(runHealth(os.Args[2]))
	case "login":
		if len(os.Args) < 5 {
			fmt.Fprintln(os.Stderr, "usage: idunapro login <base-url> <email> <password>")
			os.Exit(2)
		}
		os.Exit(runLogin(os.Args[2], os.Args[3], os.Args[4]))
	case "kanban":
		if len(os.Args) < 3 {
			usage()
			os.Exit(2)
		}
		switch os.Args[2] {
		case "list":
			if len(os.Args) < 5 {
				fmt.Fprintln(os.Stderr, "usage: idunapro kanban list <base-url> <token> [queue]")
				os.Exit(2)
			}
			queue := ""
			if len(os.Args) >= 6 {
				queue = os.Args[5]
			}
			os.Exit(runKanbanList(os.Args[3], os.Args[4], queue))
		default:
			usage()
			os.Exit(2)
		}
	case "whoami":
		if len(os.Args) < 4 {
			fmt.Fprintln(os.Stderr, "usage: idunapro whoami <base-url> <token>")
			os.Exit(2)
		}
		os.Exit(runWhoami(os.Args[2], os.Args[3]))
	default:
		usage()
		os.Exit(2)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: idunapro health <base-url>")
	fmt.Fprintln(os.Stderr, "       idunapro login <base-url> <email> <password>")
	fmt.Fprintln(os.Stderr, "       idunapro kanban list <base-url> <token> [queue]")
	fmt.Fprintln(os.Stderr, "       idunapro whoami <base-url> <token>")
}

// healthBody mirrors IDUNA/IDUNA_PRO's own real /health endpoint response shape
// ({"ok": true, ...}) -- see internal/http/handlers' own health handler for the source of truth.
type healthBody struct {
	OK bool `json:"ok"`
}

// runHealth makes the real HTTP GET, then hands the real decision -- what to print, what exit
// code to return -- entirely to the PARENA-compiled HealthMessage/HealthExitCode pair. This
// host does no interpretation of its own beyond parsing the wire response into the two scalars
// the PARENA decision function actually needs (status code, body-ok flag).
//
// Real, third-pass simplification (2026-09-03, cruise-queue card 9988's own next-named
// prerequisite, closed the same day it was named): BURROW's Go target just shipped real
// `match`-on-a-user-defenum support, so PARENA can now decide the presentation message too, not
// just the pass/fail outcome -- the prior Result/HealthError design (and this host's own
// healthErrorMessage Tag-reading workaround) is gone. This function is now a pure "fetch bytes,
// print what PARENA decided" shell.
func runHealth(baseURL string) int {
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Get(baseURL + "/health")
	if err != nil {
		fmt.Fprintf(os.Stderr, "idunapro: could not reach %s: %v\n", baseURL, err)
		return 1
	}
	defer resp.Body.Close()

	var body healthBody
	_ = json.NewDecoder(resp.Body).Decode(&body) // a real non-200/malformed body just leaves OK false

	statusCode := int32(resp.StatusCode)
	message := burrowgen.HealthMessage(statusCode, body.OK)
	exitCode := burrowgen.HealthExitCode(statusCode, body.OK)
	if exitCode == 0 {
		fmt.Println(message)
	} else {
		fmt.Fprintln(os.Stderr, message)
	}
	return int(exitCode)
}

// loginRequest/loginResponse mirror internal/http/handlers.localAuthRequest/localAuthResponse's
// own real wire shape exactly (POST /api/v1/auth/local).
type loginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type loginResponse struct {
	Token     string `json:"token"`
	ExpiresAt int64  `json:"expires_at"`
	Sub       string `json:"sub"`
	UID       int    `json:"uid"`
}

// runLogin authenticates against a real IDUNA_PRO instance's own local-auth endpoint and prints
// the resulting JWT to stdout on success -- a deliberately minimal, stateless v0 (no local
// credential cache file): `token=$(idunapro login <url> <email> <password>)` is the real,
// intended usage, matching plain Unix CLI convention rather than inventing a new config
// directory this early. A real, non-error, non-token line ("logged in as ...") goes to stderr so
// stdout capture stays exactly the raw token, nothing else.
func runLogin(baseURL, email, password string) int {
	reqBody, err := json.Marshal(loginRequest{Email: email, Password: password})
	if err != nil {
		fmt.Fprintf(os.Stderr, "idunapro: internal error building request: %v\n", err)
		return 1
	}
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Post(baseURL+"/api/v1/auth/local", "application/json", bytes.NewReader(reqBody))
	if err != nil {
		fmt.Fprintf(os.Stderr, "idunapro: could not reach %s: %v\n", baseURL, err)
		return 1
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		fmt.Fprintf(os.Stderr, "idunapro: login failed (HTTP %d) -- check email/password\n", resp.StatusCode)
		return 1
	}
	var body loginResponse
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		fmt.Fprintf(os.Stderr, "idunapro: could not parse login response: %v\n", err)
		return 1
	}
	if body.Token == "" {
		fmt.Fprintln(os.Stderr, "idunapro: login response had no token")
		return 1
	}
	fmt.Fprintf(os.Stderr, "idunapro: logged in as %s (uid=%d)\n", body.Sub, body.UID)
	fmt.Println(body.Token)
	return 0
}

// kanbanCard mirrors internal/http/handlers.kanbanCard's own real JSON shape exactly (GET
// /api/v1/kanban/cards).
type kanbanCard struct {
	ID            int64  `json:"id"`
	BacklogItemID string `json:"backlog_item_id"`
	Title         string `json:"title"`
	Queue         string `json:"queue"`
	Position      int    `json:"position"`
	CreatedAt     string `json:"created_at"`
	UpdatedAt     string `json:"updated_at"`
}

// runKanbanList fetches and prints the real kanban board (optionally filtered to one queue) as
// a plain aligned table. A pure fetch-and-print operation -- no ambiguous response to interpret
// the way health's own HTTP-status-plus-body-flag pair needed, so this stays Go-native rather
// than growing a new PARENA decision function for it.
func runKanbanList(baseURL, token, queue string) int {
	url := baseURL + "/api/v1/kanban/cards"
	if queue != "" {
		url += "?queue=" + queue
	}
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		fmt.Fprintf(os.Stderr, "idunapro: internal error building request: %v\n", err)
		return 1
	}
	req.Header.Set("Authorization", "Bearer "+token)

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		fmt.Fprintf(os.Stderr, "idunapro: could not reach %s: %v\n", baseURL, err)
		return 1
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		fmt.Fprintf(os.Stderr, "idunapro: kanban list failed (HTTP %d) -- check the token and its kanban.access permission\n", resp.StatusCode)
		return 1
	}
	var cards []kanbanCard
	if err := json.NewDecoder(resp.Body).Decode(&cards); err != nil {
		fmt.Fprintf(os.Stderr, "idunapro: could not parse kanban response: %v\n", err)
		return 1
	}
	if len(cards) == 0 {
		fmt.Println("(no cards)")
		return 0
	}
	tw := tabwriter.NewWriter(os.Stdout, 0, 2, 2, ' ', 0)
	fmt.Fprintln(tw, "ID\tQUEUE\tTITLE")
	for _, c := range cards {
		fmt.Fprintf(tw, "%d\t%s\t%s\n", c.ID, c.Queue, c.Title)
	}
	tw.Flush()
	return 0
}

// meResponse mirrors handlers.MeHandler's own real GET /api/v1/identities/me response shape.
type meResponse struct {
	Identity struct {
		ID       string `json:"id"`
		Email    string `json:"email"`
		Gamertag string `json:"gamertag"`
		Status   string `json:"status"`
	} `json:"identity"`
	RBAC struct {
		AssignedRoles        []string `json:"assigned_roles"`
		EffectivePermissions []string `json:"effective_permissions"`
	} `json:"rbac"`
}

// runWhoami (cruise-queue card 9988, real, now-unblocked next subcommand): pure fetch-and-print
// against GET /api/v1/identities/me, same real "no ambiguous response to interpret" reasoning
// runKanbanList's own header comment already gives for staying Go-native -- there's no PARENA
// decision to make here, just a real HTTP call and a real, readable summary of what came back.
// Was blocked until MeHandler learned to resolve a local-auth "local:<uid>" subject for real
// (this same session's own fix) -- every local-auth token this CLI's own `login` subcommand
// mints would have gotten a bare 404 before that.
func runWhoami(baseURL, token string) int {
	req, err := http.NewRequest(http.MethodGet, baseURL+"/api/v1/identities/me", nil)
	if err != nil {
		fmt.Fprintf(os.Stderr, "idunapro: internal error building request: %v\n", err)
		return 1
	}
	req.Header.Set("Authorization", "Bearer "+token)

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		fmt.Fprintf(os.Stderr, "idunapro: could not reach %s: %v\n", baseURL, err)
		return 1
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		fmt.Fprintf(os.Stderr, "idunapro: whoami failed (HTTP %d) -- check the token\n", resp.StatusCode)
		return 1
	}
	var me meResponse
	if err := json.NewDecoder(resp.Body).Decode(&me); err != nil {
		fmt.Fprintf(os.Stderr, "idunapro: could not parse identity response: %v\n", err)
		return 1
	}
	fmt.Printf("id:          %s\n", me.Identity.ID)
	fmt.Printf("email:       %s\n", me.Identity.Email)
	fmt.Printf("gamertag:    %s\n", me.Identity.Gamertag)
	fmt.Printf("status:      %s\n", me.Identity.Status)
	fmt.Printf("roles:       %s\n", joinOrNone(me.RBAC.AssignedRoles))
	fmt.Printf("permissions: %s\n", joinOrNone(me.RBAC.EffectivePermissions))
	return 0
}

func joinOrNone(items []string) string {
	if len(items) == 0 {
		return "(none)"
	}
	out := items[0]
	for _, s := range items[1:] {
		out += ", " + s
	}
	return out
}
