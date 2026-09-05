package handlers

import (
	"encoding/csv"
	"encoding/json"
	"log"
	"net"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"idunapro/internal/http/middleware"
	"idunapro/internal/mailinglist"
)

// CurrentConsentVersion identifies the exact privacy-policy/consent copy
// shown on OKEMILY's signup form. Bump this (and the copy on the page) any
// time the consent language materially changes — old subscriber rows keep
// the version they actually agreed to, never silently reattributed.
const CurrentConsentVersion = "okemily-v1-2026-07-17"

var emailRe = regexp.MustCompile(`^[^\s@]+@[^\s@]+\.[^\s@]+$`)

// MailingListHandler serves the public subscribe endpoint (CORS-scoped,
// rate-limited, fails closed while the vault is locked) and the loopback-only
// unlock/init endpoints an operator drives via cmd/mailing-list-unlock.
type MailingListHandler struct {
	Store       *mailinglist.Store
	Vault       *mailinglist.Vault
	Mailchimp   *mailinglist.MailchimpClient
	AllowOrigin []string // exact-match allowlist, e.g. "https://okemily.com"
	Limiter     *middleware.IPRateLimiter
	// MailchimpLists maps a subscribeRequest.List value to a dedicated
	// Mailchimp audience ID, for signups that must stay off the general
	// list (e.g. a single-product waitlist). Unset or unrecognized List
	// values fall back to Mailchimp's default ListID. See SECTION 163.
	MailchimpLists map[string]string
}

func (h *MailingListHandler) Register(mux *http.ServeMux) {
	subscribe := http.HandlerFunc(h.subscribe)
	if h.Limiter != nil {
		mux.Handle("POST /api/v1/mailing-list/subscribe", middleware.AuthRateLimit(h.Limiter)(subscribe))
	} else {
		mux.Handle("POST /api/v1/mailing-list/subscribe", subscribe)
	}
	mux.HandleFunc("OPTIONS /api/v1/mailing-list/subscribe", h.preflight)
	mux.HandleFunc("GET /api/v1/mailing-list/count", h.count)
	mux.HandleFunc("OPTIONS /api/v1/mailing-list/count", h.preflight)
	mux.HandleFunc("POST /api/v1/mailing-list/unlock", h.unlock)
	mux.HandleFunc("POST /api/v1/mailing-list/init", h.init)
}

// AdminSummary -- S245-04's settings-page data source: real subscriber
// count/sync status, PII-free (same reasoning as Store.Count/CountBySource).
// Registered in main.go behind cookie auth + iduna.admin, alongside the
// kanban board's own admin surface.
func (h *MailingListHandler) AdminSummary(w http.ResponseWriter, r *http.Request) {
	total, err := h.Store.Count()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "internal error"})
		return
	}
	synced, err := h.Store.SyncedCount()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "internal error"})
		return
	}
	bySource, err := h.Store.CountsBySource()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "internal error"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"total":        total,
		"synced":       synced,
		"vault_locked": h.Vault.Locked(),
		"by_source":    bySource,
	})
}

// Export is the S245-02 endpoint (registered separately in main.go, behind
// RequireAuth + RequirePermission("mailinglist.export") — unlike Register's
// routes above, this one needs a real JWT-bearer identity, not the loopback
// CLI trust model unlock/init use). GET /api/v1/mailing-list/export
// (?format=csv|json, default json). Decrypts each stored subscriber via the
// already-unlocked Vault; fails closed (503) while the vault is locked,
// same as subscribe.
func (h *MailingListHandler) Export(w http.ResponseWriter, r *http.Request) {
	if h.Vault.Locked() {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{
			"error": "vault is locked — export unavailable until unlocked",
		})
		return
	}

	records, err := h.Store.ListForExport()
	if err != nil {
		log.Printf("[mailinglist] export: list failed: %v", err)
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "internal error"})
		return
	}

	type exportedSubscriber struct {
		ID              int64  `json:"id"`
		Email           string `json:"email"`
		ConsentVersion  string `json:"consent_version"`
		ConsentedAt     string `json:"consented_at"`
		Source          string `json:"source"`
		MailchimpSynced bool   `json:"mailchimp_synced"`
	}
	out := make([]exportedSubscriber, 0, len(records))
	for _, rec := range records {
		plain, err := h.Vault.Decrypt(rec.EmailCiphertext, rec.EmailNonce)
		if err != nil {
			// One row's ciphertext/nonce corrupted or mismatched must not
			// abort the whole export — every other real subscriber still
			// deserves to come out. Logged with the id, not the ciphertext.
			log.Printf("[mailinglist] export: decrypt failed for subscriber id=%d: %v", rec.ID, err)
			continue
		}
		out = append(out, exportedSubscriber{
			ID:              rec.ID,
			Email:           string(plain),
			ConsentVersion:  rec.ConsentVersion,
			ConsentedAt:     rec.ConsentedAt.UTC().Format(time.RFC3339),
			Source:          rec.Source,
			MailchimpSynced: rec.MailchimpSynced,
		})
	}

	if strings.EqualFold(r.URL.Query().Get("format"), "csv") {
		w.Header().Set("Content-Type", "text/csv")
		w.Header().Set("Content-Disposition", `attachment; filename="mailinglist-export.csv"`)
		cw := csv.NewWriter(w)
		_ = cw.Write([]string{"id", "email", "consent_version", "consented_at", "source", "mailchimp_synced"})
		for _, s := range out {
			_ = cw.Write([]string{
				strconv.FormatInt(s.ID, 10), s.Email, s.ConsentVersion, s.ConsentedAt, s.Source,
				strconv.FormatBool(s.MailchimpSynced),
			})
		}
		cw.Flush()
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{"subscribers": out, "count": len(out)})
}

// GET /api/v1/mailing-list/count?list=<source> — public, CORS-scoped like
// subscribe. Returns only a count, no PII, works even while the vault is
// locked (source is a plaintext column — see Store.CountBySource). Built
// for landing-page copy like "X of 25 free spots left" that needs to stay
// honest without exposing anything about who signed up.
func (h *MailingListHandler) count(w http.ResponseWriter, r *http.Request) {
	if origin := h.corsOrigin(r); origin != "" {
		w.Header().Set("Access-Control-Allow-Origin", origin)
	}
	source := strings.TrimSpace(r.URL.Query().Get("list"))
	if source == "" {
		source = "general"
	}
	n, err := h.Store.CountBySource(source)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "internal error"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"list": source, "count": n})
}

func (h *MailingListHandler) corsOrigin(r *http.Request) string {
	origin := r.Header.Get("Origin")
	for _, allowed := range h.AllowOrigin {
		if origin == allowed {
			return origin
		}
	}
	return ""
}

func (h *MailingListHandler) preflight(w http.ResponseWriter, r *http.Request) {
	if origin := h.corsOrigin(r); origin != "" {
		w.Header().Set("Access-Control-Allow-Origin", origin)
		w.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
	}
	w.WriteHeader(http.StatusNoContent)
}

type subscribeRequest struct {
	Email   string `json:"email"`
	Consent bool   `json:"consent"`
	// List optionally names a dedicated signup list distinct from the
	// general okemily.com mailing list (e.g. "stinkies" for the VS0 hoodie
	// waitlist) — see MailingListHandler.MailchimpLists.
	List string `json:"list"`
}

// POST /api/v1/mailing-list/subscribe — public, rate-limited (see main.go
// wiring), CORS-restricted to the OKEMILY origin(s).
func (h *MailingListHandler) subscribe(w http.ResponseWriter, r *http.Request) {
	if origin := h.corsOrigin(r); origin != "" {
		w.Header().Set("Access-Control-Allow-Origin", origin)
	}

	var req subscribeRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid request body"})
		return
	}
	email := strings.TrimSpace(req.Email)
	if !req.Consent {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "consent is required"})
		return
	}
	if !emailRe.MatchString(email) {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid email address"})
		return
	}

	if h.Vault.Locked() {
		// Fails closed — this is the accepted trade-off for "never at rest
		// unencrypted": signups pause until a human runs the unlock CLI.
		// Nothing else in IDUNA is affected (see mailinglist package doc).
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{
			"error": "signups are temporarily paused — please try again shortly",
		})
		return
	}

	ciphertext, nonce, err := h.Vault.Encrypt([]byte(email))
	if err != nil {
		log.Printf("[mailinglist] encrypt failed: %v", err)
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "internal error"})
		return
	}

	source := strings.TrimSpace(req.List)
	if source == "" {
		source = "general"
	}

	id, err := h.Store.AddSubscriber(ciphertext, nonce, CurrentConsentVersion, source)
	if err != nil {
		log.Printf("[mailinglist] store failed: %v", err)
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "internal error"})
		return
	}

	// Best-effort Mailchimp sync using the plaintext already in hand from
	// this request — never decrypted back out of storage for this. Failure
	// here does not fail the request; IDUNA's own store already has it.
	// Dedicated-list signups (source != "general") sync to their own
	// audience when one is configured; falls back to the default list
	// (still tagged by `source` in IDUNA's own store either way) so a
	// signup never silently goes nowhere just because a product-specific
	// Mailchimp audience hasn't been created yet.
	if mc := h.resolveMailchimpClient(); mc != nil {
		targetList := mc.ListID
		if source != "general" {
			if listID, ok := h.MailchimpLists[source]; ok && listID != "" {
				targetList = listID
			} else {
				log.Printf("[mailinglist] no dedicated mailchimp list configured for source=%q — syncing to default list instead", source)
			}
		}
		if err := mc.SubscribeToList(email, targetList); err != nil {
			log.Printf("[mailinglist] mailchimp sync failed for subscriber id=%d source=%q: %v", id, source, err)
		} else if err := h.Store.MarkMailchimpSynced(id); err != nil {
			log.Printf("[mailinglist] failed to mark synced id=%d: %v", id, err)
		}
	}

	writeJSON(w, http.StatusOK, map[string]any{"status": "ok"})
}

// resolveMailchimpClient implements S245-03's real resolution order: a
// per-instance setting stored in the vault-backed Store (admin-configurable,
// no redeploy needed) takes priority over h.Mailchimp, the env-var-configured
// fallback every existing instance (including EINHORN's own) already relies
// on. Returns nil if neither is available -- callers already treat that as
// "no Mailchimp sync this request", the same as before this feature existed.
func (h *MailingListHandler) resolveMailchimpClient() *mailinglist.MailchimpClient {
	if h.Vault.Locked() {
		return h.Mailchimp
	}
	apiKeyCT, apiKeyNonce, listIDCT, listIDNonce, ok, err := h.Store.MailchimpSettings()
	if err != nil {
		log.Printf("[mailinglist] failed to read stored mailchimp settings: %v", err)
		return h.Mailchimp
	}
	if !ok {
		return h.Mailchimp
	}
	apiKey, err1 := h.Vault.Decrypt(apiKeyCT, apiKeyNonce)
	listID, err2 := h.Vault.Decrypt(listIDCT, listIDNonce)
	if err1 != nil || err2 != nil {
		log.Printf("[mailinglist] stored mailchimp settings present but failed to decrypt (api_key err=%v, list_id err=%v) — falling back to env config", err1, err2)
		return h.Mailchimp
	}
	return mailinglist.NewMailchimpClient(string(apiKey), string(listID))
}

type mailchimpSettingsRequest struct {
	APIKey string `json:"api_key"`
	ListID string `json:"list_id"`
}

// GetMailchimpSettings — GET /api/v1/mailing-list/settings/mailchimp
// (registered in main.go behind RequireAuth + RequirePermission
// ("mailinglist.admin")). Never returns the API key itself, even to an
// authorized caller — same write-only-secret posture as agent secret
// rotation elsewhere in IDUNA. list_id isn't secret, so it's returned as-is.
func (h *MailingListHandler) GetMailchimpSettings(w http.ResponseWriter, r *http.Request) {
	_, _, listIDCT, listIDNonce, ok, err := h.Store.MailchimpSettings()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "internal error"})
		return
	}
	if !ok {
		writeJSON(w, http.StatusOK, map[string]any{"configured": false})
		return
	}
	if h.Vault.Locked() {
		writeJSON(w, http.StatusOK, map[string]any{"configured": true, "list_id": nil,
			"note": "vault is locked — list_id will show once unlocked"})
		return
	}
	listID, err := h.Vault.Decrypt(listIDCT, listIDNonce)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "internal error"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"configured": true, "list_id": string(listID)})
}

// PutMailchimpSettings — PUT /api/v1/mailing-list/settings/mailchimp. Both
// fields required together (no partial update) to avoid ever leaving a
// stored config half-set between an old key and a new list, or vice versa.
func (h *MailingListHandler) PutMailchimpSettings(w http.ResponseWriter, r *http.Request) {
	if h.Vault.Locked() {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{
			"error": "vault is locked — cannot store settings until unlocked",
		})
		return
	}
	var req mailchimpSettingsRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid request body"})
		return
	}
	if req.APIKey == "" || req.ListID == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "api_key and list_id are both required"})
		return
	}

	apiKeyCT, apiKeyNonce, err := h.Vault.Encrypt([]byte(req.APIKey))
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "internal error"})
		return
	}
	listIDCT, listIDNonce, err := h.Vault.Encrypt([]byte(req.ListID))
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "internal error"})
		return
	}
	if err := h.Store.SetMailchimpSettings(apiKeyCT, apiKeyNonce, listIDCT, listIDNonce); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "internal error"})
		return
	}
	log.Printf("[mailinglist] mailchimp settings updated (list_id=%s)", req.ListID)
	writeJSON(w, http.StatusOK, map[string]any{"status": "ok"})
}

type unlockRequest struct {
	Passphrase string `json:"passphrase"`
}

func requireLoopback(w http.ResponseWriter, r *http.Request) bool {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	ip := net.ParseIP(host)
	if ip == nil || !ip.IsLoopback() {
		http.Error(w, "forbidden — loopback only", http.StatusForbidden)
		return false
	}
	return true
}

// POST /api/v1/mailing-list/unlock — loopback-only. Driven by
// cmd/mailing-list-unlock, which prompts for the passphrase interactively
// (never as a CLI arg — that would leak via `ps`/shell history) and POSTs it
// here over localhost only; never exposed through nginx/the public domain.
func (h *MailingListHandler) unlock(w http.ResponseWriter, r *http.Request) {
	if !requireLoopback(w, r) {
		return
	}
	var req unlockRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid request body"})
		return
	}

	salt, canaryCT, canaryNonce, err := h.Store.VaultMeta()
	if err != nil {
		writeJSON(w, http.StatusPreconditionRequired, map[string]any{"error": "vault not initialized — run: mailing-list-unlock -init"})
		return
	}

	if err := h.Vault.Unlock(req.Passphrase, salt, canaryCT, canaryNonce); err != nil {
		writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "incorrect passphrase"})
		return
	}
	log.Printf("[mailinglist] vault unlocked")
	writeJSON(w, http.StatusOK, map[string]any{"status": "unlocked"})
}

// POST /api/v1/mailing-list/init — loopback-only, one-time setup. Refuses to
// run if a vault already exists (Store.InitVault enforces this) so it can
// never be used to accidentally overwrite and permanently orphan existing
// encrypted subscriber rows.
func (h *MailingListHandler) init(w http.ResponseWriter, r *http.Request) {
	if !requireLoopback(w, r) {
		return
	}
	var req unlockRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid request body"})
		return
	}
	if len(req.Passphrase) < 12 {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "passphrase must be at least 12 characters"})
		return
	}

	salt, err := mailinglist.NewSalt()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "internal error"})
		return
	}
	canaryCT, canaryNonce, err := mailinglist.NewCanary(req.Passphrase, salt)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "internal error"})
		return
	}
	if err := h.Store.InitVault(salt, canaryCT, canaryNonce); err != nil {
		writeJSON(w, http.StatusConflict, map[string]any{"error": err.Error()})
		return
	}
	if err := h.Vault.Unlock(req.Passphrase, salt, canaryCT, canaryNonce); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "init succeeded but unlock failed — this should never happen"})
		return
	}
	log.Printf("[mailinglist] vault initialized and unlocked")
	writeJSON(w, http.StatusOK, map[string]any{"status": "initialized and unlocked"})
}
