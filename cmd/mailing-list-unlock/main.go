// cmd/mailing-list-unlock is the only supported way to unlock (or, once,
// initialize) the okemily.com mailing-list vault. It prompts for the
// passphrase interactively with echo disabled — never accept it as a CLI
// argument or flag, which would leak into shell history and `ps` output.
//
// Usage:
//
//	mailing-list-unlock              # unlock (after every IDUNA restart)
//	mailing-list-unlock -init        # one-time setup — only works once
//
// Talks to IDUNA over loopback only (http://127.0.0.1:8080 by default);
// the underlying endpoints reject any non-loopback caller regardless.
package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"os"

	"golang.org/x/term"
)

func main() {
	initFlag := flag.Bool("init", false, "one-time vault setup (fails if already initialized)")
	base := flag.String("base", "http://127.0.0.1:8080", "IDUNA base URL (loopback only)")
	flag.Parse()

	fmt.Fprint(os.Stderr, "Mailing-list vault passphrase: ")
	passBytes, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Fprintln(os.Stderr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error reading passphrase: %v\n", err)
		os.Exit(1)
	}
	passphrase := string(passBytes)
	if passphrase == "" {
		fmt.Fprintln(os.Stderr, "empty passphrase, aborting")
		os.Exit(1)
	}

	if *initFlag {
		fmt.Fprint(os.Stderr, "Confirm passphrase: ")
		confirmBytes, err := term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Fprintln(os.Stderr)
		if err != nil || string(confirmBytes) != passphrase {
			fmt.Fprintln(os.Stderr, "passphrases did not match, aborting")
			os.Exit(1)
		}
	}

	path := "/api/v1/mailing-list/unlock"
	if *initFlag {
		path = "/api/v1/mailing-list/init"
	}

	body, _ := json.Marshal(map[string]string{"passphrase": passphrase})
	resp, err := http.Post(*base+path, "application/json", bytes.NewReader(body))
	if err != nil {
		fmt.Fprintf(os.Stderr, "request failed: %v\n", err)
		os.Exit(1)
	}
	defer resp.Body.Close()

	var out map[string]any
	json.NewDecoder(resp.Body).Decode(&out)

	if resp.StatusCode != http.StatusOK {
		fmt.Fprintf(os.Stderr, "failed (%d): %v\n", resp.StatusCode, out["error"])
		os.Exit(1)
	}
	fmt.Println(out["status"])
}
