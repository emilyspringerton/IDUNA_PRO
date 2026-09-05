package handlers

import (
	"crypto/hmac"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// SipAccountsHandler serves the real IDUNA_PRO<->Asterisk-extension mapping (kanban
// CP-SIP-1244543543, "console screens for the admins and for the users of the platform to ...
// see their sip information"). Real, honest v0 boundary: this table records METADATA an admin
// enters after manually provisioning a real Asterisk extension (PARENA/ops/asterisk/
// pjsip_carepyre_phone.conf) -- it does not itself create, edit, or reload any Asterisk config.
// Dynamic per-user endpoint provisioning is real, separate, substantially bigger work, named
// but not attempted here.
//
// Routes (all require Bearer JWT via middleware.RequireAuth):
//
//	GET             /api/v1/sip-accounts/me                 self, any authenticated caller
//	GET             /api/v1/sip-accounts/me/qr               self, any authenticated caller -- QR onboarding payload
//	GET             /api/v1/sip-accounts/me/provisioning-url  self, any authenticated caller -- see below
//	GET             /api/v1/sip-accounts                     list, requires users.admin
//	PUT             /api/v1/sip-accounts/{uid}                upsert, requires users.admin
//	DELETE          /api/v1/sip-accounts/{uid}                remove, requires users.admin
type SipAccountsHandler struct {
	DB *sql.DB
	// ProvisioningKey signs the capability tokens /me/provisioning-url mints. Real, deliberate
	// HMAC (not a DB-stored per-user token): the token is a self-contained,
	// verify-without-a-lookup credential ("local_uid.hex(HMAC(key, local_uid))"), same
	// tradeoff class the already-deployed Linphone provisioning URLs made explicit in their own
	// header comment (a capability URL, like an unlisted calendar feed -- anyone who has the
	// exact URL can use it, it isn't discoverable by guessing). Required for
	// /me/provisioning-url to work; empty means the route 503s rather than minting an
	// unsigned/guessable token.
	ProvisioningKey []byte
	// PublicBaseURL is the real, public origin the minted URL points at (e.g.
	// "https://carepyre.org") -- the actual fetch is served by SipProvisioningFetchHandler,
	// mounted separately (no bearer auth -- the token itself is the auth) since the native app
	// fetches it directly, not through an authenticated session.
	PublicBaseURL string
	// SipSecretsByExtension holds the real PJSIP password for each real, provisioned extension
	// (currently just "1000" -- see EMILY/var/carepyre-phone-secret.env, the same real value,
	// passed in via env var at boot, never hand-typed into this DB). A real, deliberate reversal
	// of this file's own earlier "sip_accounts is metadata only, no password" decision -- see
	// this handler's own /me/provisioning-url doc comment for why: founder real-time, 2026-09-05,
	// "make the sip phone register with just that URL" needs the real secret embedded somewhere,
	// and an operator-supplied env var (same pattern MAIL_STALWART_ADMIN_PASSWORD/Twilio
	// credentials already use in this exact codebase) keeps it out of both this DB and any
	// hand-typed web form.
	SipSecretsByExtension map[string]string
}

// mintProvisioningToken and verifyProvisioningToken implement the real, self-contained HMAC
// capability token described on SipAccountsHandler.ProvisioningKey's own doc comment.
func mintProvisioningToken(key []byte, localUID int) string {
	uidStr := strconv.Itoa(localUID)
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(uidStr))
	sig := hex.EncodeToString(mac.Sum(nil))
	return base64.RawURLEncoding.EncodeToString([]byte(uidStr)) + "." + sig
}

// VerifyProvisioningToken is exported so SipProvisioningFetchHandler (a separate, public,
// unauthenticated handler -- see its own file) can validate a token without needing a shared
// import of this handler's own private fields.
func VerifyProvisioningToken(key []byte, token string) (localUID int, ok bool) {
	parts := strings.SplitN(token, ".", 2)
	if len(parts) != 2 {
		return 0, false
	}
	uidBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return 0, false
	}
	mac := hmac.New(sha256.New, key)
	mac.Write(uidBytes)
	expected := hex.EncodeToString(mac.Sum(nil))
	if !hmac.Equal([]byte(expected), []byte(parts[1])) {
		return 0, false
	}
	uid, err := strconv.Atoi(string(uidBytes))
	if err != nil {
		return 0, false
	}
	return uid, true
}

// sipProvisioningPayload -- CAREPYRE-42143124 ("how batteries included can we make the qr code
// onboarding with the sip phone? get it working for what we have going so far"), Phase 1 of the
// real, phased plan in CarePyre/docs/SIP_QR_ONBOARDING_NORTHSTAR.md: the real, structured data an
// Android Config screen needs to auto-fill from a scanned QR code, everything this table
// actually HAS. Real, honest, deliberately-named boundary, not an oversight: no `password` field
// -- sip_accounts is metadata only (see this file's own header comment), the real PJSIP auth
// secret lives solely in Asterisk's own config, never in this DB. A user still enters their own
// password by hand after scanning; only extension/server/port/transport are ever encoded here.
// Transport is a real, honest constant ("UDP") rather than a DB column: every real CarePyre
// extension provisioned so far (PARENA/ops/asterisk/pjsip_carepyre_phone.conf) uses Asterisk's
// own PJSIP default transport, and sip_accounts has no transport column to read a real per-user
// value from even if one existed.
type sipProvisioningPayload struct {
	Scheme    string `json:"scheme"` // versioned, so a future Android build can reject a payload shape it doesn't understand instead of silently mis-parsing one
	Extension string `json:"extension"`
	SipServer string `json:"sip_server"`
	SipPort   int    `json:"sip_port"`
	Transport string `json:"transport"`
}

type sipAccount struct {
	LocalUID  int    `json:"local_uid"`
	Extension string `json:"extension"`
	SipServer string `json:"sip_server"`
	SipPort   int    `json:"sip_port"`
	UpdatedAt string `json:"updated_at"`
}

func (h *SipAccountsHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if h.DB == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "sip accounts not available"})
		return
	}

	path := strings.TrimPrefix(r.URL.Path, "/api/v1/sip-accounts")
	path = strings.TrimPrefix(path, "/")

	if path == "me" {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		h.getMine(w, r)
		return
	}

	if path == "me/qr" {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		h.getMineQR(w, r)
		return
	}

	if path == "me/provisioning-url" {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		h.getMineProvisioningURL(w, r)
		return
	}

	if path == "" {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		h.requirePerm(w, r, "users.admin", h.list)
		return
	}

	uid, err := strconv.Atoi(strings.TrimSuffix(path, "/"))
	if err != nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "not found"})
		return
	}
	switch r.Method {
	case http.MethodPut:
		h.requirePerm(w, r, "users.admin", func(w http.ResponseWriter, r *http.Request) {
			h.upsert(w, r, uid)
		})
	case http.MethodDelete:
		h.requirePerm(w, r, "users.admin", func(w http.ResponseWriter, r *http.Request) {
			h.remove(w, r, uid)
		})
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (h *SipAccountsHandler) requirePerm(w http.ResponseWriter, r *http.Request, perm string, next http.HandlerFunc) {
	if !hasPermission(r, perm) {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "forbidden"})
		return
	}
	next(w, r)
}

func (h *SipAccountsHandler) getMine(w http.ResponseWriter, r *http.Request) {
	uid := callerLocalUID(r)
	if uid == nil {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "forbidden"})
		return
	}
	acct, err := h.scan(h.DB.QueryRowContext(r.Context(),
		`SELECT local_uid, extension, sip_server, sip_port, updated_at FROM sip_accounts WHERE local_uid = ?`, *uid))
	if err == sql.ErrNoRows {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "no SIP account assigned yet -- ask an admin"})
		return
	}
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, acct)
}

// getMineQR -- CAREPYRE-42143124: same real ownership check as getMine (a caller can only ever
// fetch their OWN provisioning payload, never someone else's SIP extension), reusing the exact
// same query rather than a second hand-written one that could drift out of sync with it.
func (h *SipAccountsHandler) getMineQR(w http.ResponseWriter, r *http.Request) {
	uid := callerLocalUID(r)
	if uid == nil {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "forbidden"})
		return
	}
	acct, err := h.scan(h.DB.QueryRowContext(r.Context(),
		`SELECT local_uid, extension, sip_server, sip_port, updated_at FROM sip_accounts WHERE local_uid = ?`, *uid))
	if err == sql.ErrNoRows {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "no SIP account assigned yet -- ask an admin"})
		return
	}
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, sipProvisioningPayload{
		Scheme:    "carepyre-sip-v1",
		Extension: acct.Extension,
		SipServer: acct.SipServer,
		SipPort:   acct.SipPort,
		Transport: "UDP",
	})
}

// getMineProvisioningURL -- founder real-time, 2026-09-05: "can you set up provisioning URL
// from the console for users under my sip and make the sip phone register with just that URL?"
// Mints a real, self-contained capability URL (see SipAccountsHandler.ProvisioningKey's own doc
// comment) pointing at SipProvisioningFetchHandler -- a SEPARATE, unauthenticated route the
// native app fetches directly (no bearer token available to a freshly-installed app that hasn't
// logged in yet). Matches the exact real precedent CarePyre/ops/linphone-provisioning-template.xml's
// own header comment already named as the right follow-up: "a per-user, authenticated [to MINT,
// not to FETCH] provisioning endpoint... rather than more static files under more random paths."
func (h *SipAccountsHandler) getMineProvisioningURL(w http.ResponseWriter, r *http.Request) {
	if len(h.ProvisioningKey) == 0 || h.PublicBaseURL == "" {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "provisioning URLs not configured"})
		return
	}
	uid := callerLocalUID(r)
	if uid == nil {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "forbidden"})
		return
	}
	// Real, honest check: only mint a URL for a caller who actually has a real sip_accounts row
	// -- minting one for someone with no assigned extension would just produce a URL that 404s
	// when fetched, a confusing dead end rather than a clear "ask an admin" message now.
	if _, err := h.scan(h.DB.QueryRowContext(r.Context(),
		`SELECT local_uid, extension, sip_server, sip_port, updated_at FROM sip_accounts WHERE local_uid = ?`, *uid)); err == sql.ErrNoRows {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "no SIP account assigned yet -- ask an admin"})
		return
	} else if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	token := mintProvisioningToken(h.ProvisioningKey, *uid)
	writeJSON(w, http.StatusOK, map[string]string{
		"url": strings.TrimRight(h.PublicBaseURL, "/") + "/api/v1/sip-provisioning/" + token,
	})
}

func (h *SipAccountsHandler) list(w http.ResponseWriter, r *http.Request) {
	rows, err := h.DB.QueryContext(r.Context(),
		`SELECT local_uid, extension, sip_server, sip_port, updated_at FROM sip_accounts ORDER BY local_uid`)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	defer rows.Close()
	out := []sipAccount{}
	for rows.Next() {
		var a sipAccount
		if err := rows.Scan(&a.LocalUID, &a.Extension, &a.SipServer, &a.SipPort, &a.UpdatedAt); err != nil {
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		out = append(out, a)
	}
	writeJSON(w, http.StatusOK, out)
}

type upsertSipAccountRequest struct {
	Extension string `json:"extension"`
	SipServer string `json:"sip_server"`
	SipPort   int    `json:"sip_port"`
}

func (h *SipAccountsHandler) upsert(w http.ResponseWriter, r *http.Request, uid int) {
	var req upsertSipAccountRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON"})
		return
	}
	req.Extension = strings.TrimSpace(req.Extension)
	req.SipServer = strings.TrimSpace(req.SipServer)
	if req.Extension == "" || req.SipServer == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "extension and sip_server are required"})
		return
	}
	if req.SipPort == 0 {
		req.SipPort = 5060
	}
	now := time.Now().UTC()
	_, err := h.DB.ExecContext(r.Context(), `
		INSERT INTO sip_accounts (local_uid, extension, sip_server, sip_port, updated_at)
		VALUES (?, ?, ?, ?, ?)
		ON CONFLICT(local_uid) DO UPDATE SET
			extension = excluded.extension,
			sip_server = excluded.sip_server,
			sip_port = excluded.sip_port,
			updated_at = excluded.updated_at
	`, uid, req.Extension, req.SipServer, req.SipPort, now)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	acct, err := h.scan(h.DB.QueryRowContext(r.Context(),
		`SELECT local_uid, extension, sip_server, sip_port, updated_at FROM sip_accounts WHERE local_uid = ?`, uid))
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, acct)
}

func (h *SipAccountsHandler) remove(w http.ResponseWriter, r *http.Request, uid int) {
	res, err := h.DB.ExecContext(r.Context(), `DELETE FROM sip_accounts WHERE local_uid = ?`, uid)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "not found"})
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *SipAccountsHandler) scan(row *sql.Row) (sipAccount, error) {
	var a sipAccount
	err := row.Scan(&a.LocalUID, &a.Extension, &a.SipServer, &a.SipPort, &a.UpdatedAt)
	return a, err
}
