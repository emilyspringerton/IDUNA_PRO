// Command idunapro is the real, honest v0 first slice of "the CLI for Emily for Business and
// IDUNA_PRO" (kanban cruise-queue card 9988: "emily for business CLI written in GO with
// BURROW"). Real "mods first everything" split: this Go host owns everything BURROW's Go
// emission target genuinely can't do yet -- os.Args parsing, the real HTTP call to a customer's
// own IDUNA_PRO instance, stdout/stderr, process exit codes. The actual DECISION logic (what a
// health-check response means, what exit code it earns) is real PARENA source
// (PARENA/stdlib/idunapro/cli_mod.prn), compiled via `burrow build ... -o *.go` into
// internal/burrowgen/idunapro_cli_gen.go and called directly here -- no cgo/FFI boundary, the
// same real precedent DUNG's own burrowgen usage already established.
//
// Real, honest v0 scope: one subcommand, `idunapro health <base-url>`. Growing this into a
// fuller CLI (auth, kanban, apples, subscriptions...) is real, separate, later work -- this is
// the narrowest real slice that proves the whole pipeline (PARENA decision logic compiled via
// BURROW's Go target, called from a real Go host binary, doing a real network call) end to end.
package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
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
	default:
		usage()
		os.Exit(2)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: idunapro health <base-url>")
}

// healthBody mirrors IDUNA/IDUNA_PRO's own real /health endpoint response shape
// ({"ok": true, ...}) -- see internal/http/handlers' own health handler for the source of truth.
type healthBody struct {
	OK bool `json:"ok"`
}

// runHealth makes the real HTTP GET, then hands the real decision -- what to print, what exit
// code to return -- to the PARENA-compiled ExitCodeForHealth/InterpretHealthResponse pair. This
// host does no interpretation of its own beyond parsing the wire response into the two scalars
// the PARENA decision function actually needs (status code, body-ok flag).
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

	outcome := burrowgen.InterpretHealthResponse(int32(resp.StatusCode), body.OK)
	if outcome.Tag == 1 {
		fmt.Println(outcome.Value.(string))
	} else {
		fmt.Fprintln(os.Stderr, outcome.Value.(string))
	}
	return int(burrowgen.ExitCodeForHealth(int32(resp.StatusCode), body.OK))
}
