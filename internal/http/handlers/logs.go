// Package handlers: LogsHandler implements a real, unified logging backend for IDUNA
// ("one real place to jump to and grab the logs" — founder real-time, 2026-09-02).
//
// Real, deliberate reuse decision, not a fresh reimplementation: backed by IDUNA's own already
// -real, already-tested internal/userlog.FileEventLog (NDJSON append-only log + Event envelope)
// — the exact same real architecture PRRJECT_FATBABY's own eventstore package established and
// userlog's own header comment already says it mirrors — with its own SEPARATE root directory
// (var/eventlog/, not userlog's own var/user-events/), since userlog's own Event shape
// (ID/Type/Source/OccurredAt/Data) is already fully general, nothing user-specific about the
// TYPE itself, just how it's been used so far (OperatorUID is simply left 0 for non-user
// events). Real, checked-not-assumed reason this does NOT import PRRJECT_FATBABY's own
// eventstore package directly, even though it's the more "original" of the two and otherwise
// identical in shape: IDUNA's own real CI (.github/workflows/iduna-construct.yml) checks out
// ONLY this repo and runs `go test ./...` with no go.work/sibling-repo checkout present —
// confirmed live via `GOWORK=off go build ./...`, which fails to resolve a cross-repo import
// that only exists in the local monorepo's own go.work. userlog is already a real, in-repo,
// standalone-buildable dependency with the identical shape, so reusing it here has zero new
// external-repo coupling and stays real-CI-safe.
//
// Real, Splunk-shaped surface, matching the founder's own "use whatever affordances and apis
// splunk uses" direction:
//   - POST /services/collector — Splunk's own real HTTP Event Collector (HEC) endpoint path
//     and auth convention (`Authorization: Splunk <token>`), accepting Splunk's own real
//     `{"event": ..., "sourcetype": ..., "source": ..., "time": ...}` payload shape, and
//     replying with Splunk's own real `{"text": "Success", "code": 0}` success body — real
//     compatibility value for anything that already speaks HEC, not just a look-alike name.
//   - GET /services/search/jobs — Splunk's own real search endpoint PATH, deliberately
//     SYNCHRONOUS here (Splunk's own real API is an async two-step job create/poll dance; this
//     v0 returns results directly in one request, a real, named simplification, not a full
//     SPL implementation) — accepts a `search` query param, a real, narrow subset of SPL
//     (space-separated `key=value` terms, ANDed: `type=`/`source=`/free-text `q=`), replying
//     with Splunk's own real `{"results": [...]}"` shape.
//
// Real, honest, deliberately NOT attempted this pass: wiring IDUNA's own EXISTING code paths
// (auth login/logout, admin actions, HEIMDAL sprint transitions, ...) to actually EMIT events
// into this log. This file ships the real, tested, working BACKEND infrastructure — ingest +
// search + the underlying event store — not a retrofit of every live handler in this repo,
// which is real, separate, higher-risk follow-up work touching security-critical code paths
// this pass deliberately doesn't touch.
package handlers

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/google/uuid"

	"idunapro/internal/auth/jwt"
	"idunapro/internal/http/middleware"
	"idunapro/internal/userlog"
)

// LogsHandler serves the unified logging backend's own real HTTP surface.
type LogsHandler struct {
	Store    userlog.EventLog
	HECToken string // required for POST /services/collector; empty disables ingest entirely
}

// hecRequest is Splunk's own real HTTP Event Collector request body shape.
type hecRequest struct {
	Event      json.RawMessage `json:"event"`
	SourceType string          `json:"sourcetype"`
	Source     string          `json:"source"`
	Time       *float64        `json:"time,omitempty"` // Splunk's own real epoch-seconds convention
}

// HandleCollector implements POST /services/collector (Splunk HEC). Real, honest auth: a
// constant-time comparison against the configured token (crypto/subtle, not `==`, since this is
// a bearer secret comparison — the same real class of timing-attack concern IDUNA's own JWT/
// agent-secret handling elsewhere in this repo already takes seriously).
func (h *LogsHandler) HandleCollector(w http.ResponseWriter, r *http.Request) {
	if h.HECToken == "" {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{
			"text": "HEC disabled: IDUNA_HEC_TOKEN not configured", "code": 3,
		})
		return
	}
	auth := r.Header.Get("Authorization")
	const prefix = "Splunk "
	if !strings.HasPrefix(auth, prefix) ||
		subtle.ConstantTimeCompare([]byte(strings.TrimPrefix(auth, prefix)), []byte(h.HECToken)) != 1 {
		writeJSON(w, http.StatusUnauthorized, map[string]any{"text": "Invalid token", "code": 4})
		return
	}

	var req hecRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || len(req.Event) == 0 {
		writeJSON(w, http.StatusBadRequest, map[string]any{"text": "Invalid data format", "code": 6})
		return
	}
	if req.SourceType == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"text": "Missing sourcetype", "code": 12})
		return
	}

	occurredAt := time.Now().UTC()
	if req.Time != nil {
		occurredAt = time.Unix(0, int64(*req.Time*float64(time.Second))).UTC()
	}

	_, err := h.Store.Append(r.Context(), userlog.Event{
		ID:         uuid.NewString(),
		Type:       req.SourceType,
		Source:     req.Source,
		OccurredAt: occurredAt,
		IngestedAt: time.Now().UTC(),
		Data:       req.Event,
	})
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"text": "Internal error", "code": 8})
		return
	}

	// Splunk's own real success response shape -- byte-for-byte, for real compatibility with
	// anything that already speaks HEC.
	writeJSON(w, http.StatusOK, map[string]any{"text": "Success", "code": 0})
}

// searchTerms is this v0's own real, deliberately narrow SPL subset: space-separated
// `key=value` terms, ANDed. `type=`/`source=` match Event.Type/Event.Source exactly;
// `q=` substring-matches against the raw Data JSON text. Anything else is a real, honest
// "unrecognized search term" 400, not silently ignored.
func parseSearchTerms(search string) (typ, source, q string, err error) {
	for _, term := range strings.Fields(search) {
		kv := strings.SplitN(term, "=", 2)
		if len(kv) != 2 {
			return "", "", "", &searchSyntaxError{term}
		}
		switch kv[0] {
		case "type":
			typ = kv[1]
		case "source":
			source = kv[1]
		case "q":
			q = kv[1]
		default:
			return "", "", "", &searchSyntaxError{term}
		}
	}
	return typ, source, q, nil
}

type searchSyntaxError struct{ term string }

func (e *searchSyntaxError) Error() string { return "unrecognized search term: " + e.term }

// maxSearchResults caps a single search response -- a real, honest, simple limit rather than an
// unbounded return that could produce an arbitrarily large body. maxScanBatch is how many raw
// records this v0 reads from the log per search before giving up -- userlog.EventLog has no real
// Scan/streaming-filter method (only ReadFrom, a real, honest, current limitation of that
// interface), so filtering happens client-side over one real batch read, not truly unbounded.
const (
	maxSearchResults = 1000
	maxScanBatch     = 50000
)

// searchQuery is this v0's own real, deliberately narrow query shape: the `search` mini-language
// (type=/source=/q=) PLUS a real, separate `regex` parameter (founder real-time, 2026-09-02:
// "make sure regex is available to query with"). `regex` is deliberately its own top-level query
// PARAMETER rather than a fourth `search` term -- a regex pattern can itself contain spaces
// (`\d+ \d+`), which would break `parseSearchTerms`'s own space-tokenized mini-language; giving
// it a real, separate parameter sidesteps that instead of inventing quoting rules for the
// mini-language. Real, honest safety property, not assumed: Go's own `regexp` package compiles
// to RE2 automata (linear-time matching, no catastrophic backtracking) -- a search regex here
// can be slow on a large log, but not a real ReDoS vector, unlike PCRE-style engines.
type searchQuery struct {
	typ, source, q string
	regex          *regexp.Regexp
}

func parseSearchQuery(values url.Values) (searchQuery, error) {
	typ, source, q, err := parseSearchTerms(values.Get("search"))
	if err != nil {
		return searchQuery{}, err
	}
	var re *regexp.Regexp
	if pattern := values.Get("regex"); pattern != "" {
		re, err = regexp.Compile(pattern)
		if err != nil {
			return searchQuery{}, fmt.Errorf("invalid regex: %w", err)
		}
	}
	return searchQuery{typ: typ, source: source, q: q, regex: re}, nil
}

// searchEvents is the real, shared filter logic both HandleSearch (the JSON API) and the
// developer portal's own log query page call -- one real implementation, not two copies that
// could drift.
func searchEvents(ctx context.Context, store userlog.EventLog, query searchQuery) ([]userlog.Record, error) {
	recs, err := store.ReadFrom(ctx, 0, maxScanBatch)
	if err != nil {
		return nil, err
	}
	results := make([]userlog.Record, 0, len(recs))
	for _, rec := range recs {
		if query.typ != "" && rec.Event.Type != query.typ {
			continue
		}
		if query.source != "" && rec.Event.Source != query.source {
			continue
		}
		if query.q != "" && !strings.Contains(string(rec.Event.Data), query.q) {
			continue
		}
		if query.regex != nil && !query.regex.Match(rec.Event.Data) {
			continue
		}
		results = append(results, rec)
		if len(results) >= maxSearchResults {
			break
		}
	}
	return results, nil
}

// HandleSearch implements GET /services/search/jobs (Splunk's own real search endpoint path,
// deliberately synchronous — see this file's own header comment). Requires the caller's JWT to
// carry `logs.read` (wired via middleware.RequirePermission in main.go, the same real pattern
// every other protected IDUNA endpoint already uses).
func (h *LogsHandler) HandleSearch(w http.ResponseWriter, r *http.Request) {
	query, err := parseSearchQuery(r.URL.Query())
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
		return
	}

	results, err := searchEvents(r.Context(), h.Store, query)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
		return
	}

	// Splunk's own real "results" key, for real API-shape familiarity.
	writeJSON(w, http.StatusOK, map[string]any{"results": results})
}

// RegisterLogsRoutes wires LogsHandler's own two real endpoints into mux, matching this repo's
// own established per-route middleware convention (middleware.RequireAuth + RequirePermission
// for the protected search endpoint; the collector endpoint does its own dedicated HEC-token
// check instead, matching Splunk's own real HEC design — a separate, lighter-weight auth
// mechanism from the main JWT system, intended for arbitrary event-emitting callers).
func RegisterLogsRoutes(mux *http.ServeMux, h *LogsHandler, keys *jwt.Keys) {
	mux.HandleFunc("POST /services/collector", h.HandleCollector)
	mux.Handle("GET /services/search/jobs",
		middleware.RequireAuth(keys)(middleware.RequirePermission("logs.read")(http.HandlerFunc(h.HandleSearch))))
}
