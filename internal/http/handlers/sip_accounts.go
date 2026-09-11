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
// CP-HIPAA-2 (founder real-time, 2026-09-07: "give the same treatment for sip [as mail
// accounts]"): a caller holding sip-accounts.provision (Provider Operator or Provider Admin) can
// also reach list/upsert/remove, scoped to the SIP accounts THEY created
// (sip_accounts.created_by, mirroring mail_account_credentials' own real minimum-necessary
// scoping). A provider-only caller may only upsert an extension for a uid they already provision
// a mailbox or SIP account for -- never an arbitrary participant.
//
// Routes (all require Bearer JWT via middleware.RequireAuth):
//
//	GET             /api/v1/sip-accounts/me                 self, any authenticated caller
//	GET             /api/v1/sip-accounts/me/qr               self, any authenticated caller -- QR onboarding payload
//	GET             /api/v1/sip-accounts/me/provisioning-url  self, any authenticated caller -- see below
//	GET             /api/v1/sip-accounts/me/webphone-credentials  self, any authenticated caller -- see below
//	GET             /api/v1/sip-accounts                     list, requires users.admin OR sip-accounts.provision (scoped)
//	PUT             /api/v1/sip-accounts/{uid}                upsert, requires users.admin OR sip-accounts.provision (scoped)
//	DELETE          /api/v1/sip-accounts/{uid}                remove, requires users.admin OR sip-accounts.provision (scoped)
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
	// WebphoneSecretsByExtension holds the real PJSIP password for each real, provisioned
	// "<extension>web" WebRTC endpoint (see PARENA/ops/asterisk/pjsip_carepyre_webphone.conf and
	// sudo-queue/72-provision-web-extension.sh), keyed by the BASE extension (e.g. "1000", not
	// "1000web") to match SipSecretsByExtension's own keying convention. Founder real-time,
	// 2026-09-06: "i am expecting to only see the web sip phone if there is an extension
	// configured for that user and then if its not 1000 im still expecting it to work" -- this
	// is what makes the console's embedded Web Phone work for ANY provisioned user, not just the
	// one extension (1000/1000web) that existed before this.
	WebphoneSecretsByExtension map[string]string
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

	if path == "me/webphone-credentials" {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		h.getMineWebphoneCredentials(w, r)
		return
	}

	if path == "" {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		h.requireProvisionPerm(w, r, h.list)
		return
	}

	uid, err := strconv.Atoi(strings.TrimSuffix(path, "/"))
	if err != nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "not found"})
		return
	}
	switch r.Method {
	case http.MethodPut:
		h.requireProvisionPerm(w, r, func(w http.ResponseWriter, r *http.Request) {
			h.upsert(w, r, uid)
		})
	case http.MethodDelete:
		h.requireProvisionPerm(w, r, func(w http.ResponseWriter, r *http.Request) {
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

// requireProvisionPerm -- CP-HIPAA-2: the admin routes below are reachable by users.admin OR
// sip-accounts.provision (Provider Operator/Admin); each handler function applies its own
// minimum-necessary scoping for a provider-only caller (see list/upsert/remove below).
func (h *SipAccountsHandler) requireProvisionPerm(w http.ResponseWriter, r *http.Request, next http.HandlerFunc) {
	if !hasPermission(r, "users.admin") && !hasPermission(r, "sip-accounts.provision") {
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

// getMineWebphoneCredentials -- founder real-time, 2026-09-06: "i am expecting to only see the
// web sip phone if there is an extension configured for that user and then if its not 1000 im
// still expecting it to work ... is that reasonable?" Real, honest yes: unlike the native
// provisioning-URL flow (which has to be unauthenticated, since a freshly-installed app has no
// bearer token yet), the console embedding the Web Phone iframe is ALREADY an authenticated
// session -- so this can just be a plain, bearer-authenticated self-read, no HMAC capability
// token needed. Returns the real "<extension>web" identity + its own real PJSIP password
// (WebphoneSecretsByExtension, keyed by the base extension -- see that field's own doc comment)
// so the console can auto-register the embedded webphone with zero manual typing, for WHICHEVER
// extension this caller actually has -- not hardcoded to 1000.
func (h *SipAccountsHandler) getMineWebphoneCredentials(w http.ResponseWriter, r *http.Request) {
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
	password := h.WebphoneSecretsByExtension[acct.Extension]
	if password == "" {
		// Real, honest gap: this user has a real extension assigned, but no matching WebRTC
		// endpoint has been provisioned for it yet (see sudo-queue/72-provision-web-extension.sh)
		// -- surfaced plainly rather than returning an empty password the browser would just
		// fail to register with anyway.
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "no web phone configured for this extension yet -- ask an admin"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{
		"extension": acct.Extension + "web",
		"domain":    "carepyre.org",
		"password":  password,
	})
}

func (h *SipAccountsHandler) list(w http.ResponseWriter, r *http.Request) {
	// CP-HIPAA-2/CP-HIPAA-3 minimum-necessary scoping: a provider-only caller (no users.admin)
	// sees the SIP accounts THEY created, OR any SIP account whose owning organization shares a
	// trusted cluster with their own -- same real principle mail_accounts.go's own list already
	// enforces. Fetches every row and filters in Go (this table is small, real, bounded
	// per-deployment data, not a scale concern) rather than a second, harder-to-read SQL query
	// per caller tier.
	isAdmin := hasPermission(r, "users.admin")
	var callerUID *int
	callerOrg := 0
	if !isAdmin {
		callerUID = callerLocalUID(r)
		if callerUID == nil {
			writeJSON(w, http.StatusForbidden, map[string]string{"error": "forbidden"})
			return
		}
		callerOrg = callerOrgID(r)
	}

	// MULTI_TENANCY_NORTHSTAR.md Phase 2 (2026-09-11): the real tenant boundary, applied to BOTH
	// admin and non-admin callers -- unlike the ownCreation/clusterMate check below (a WITHIN-tenant
	// minimum-necessary scoping users.admin is deliberately allowed to bypass), a caller must never
	// see another tenant's SIP extension at all. Every sip_accounts row has a real local_uid (its
	// own primary key), so unlike mail_account_credentials there's no "unlinked, no tenant to check"
	// carve-out needed here.
	tenantID := callerTenantID(r)

	rows, err := h.DB.QueryContext(r.Context(),
		`SELECT local_uid, extension, sip_server, sip_port, updated_at, created_by, owning_org_id, tenant_id FROM sip_accounts ORDER BY local_uid`)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	defer rows.Close()
	out := []sipAccount{}
	for rows.Next() {
		var a sipAccount
		var createdBy sql.NullInt64
		var owningOrgID, rowTenantID int
		if err := rows.Scan(&a.LocalUID, &a.Extension, &a.SipServer, &a.SipPort, &a.UpdatedAt, &createdBy, &owningOrgID, &rowTenantID); err != nil {
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		if rowTenantID != tenantID {
			continue
		}
		if !isAdmin {
			ownCreation := createdBy.Valid && callerUID != nil && int(createdBy.Int64) == *callerUID
			clusterMate := orgsShareCluster(r.Context(), h.DB, callerOrg, owningOrgID)
			if !ownCreation && !clusterMate {
				continue
			}
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

	// MULTI_TENANCY_NORTHSTAR.md Phase 2: the real tenant boundary, checked for BOTH admin and
	// non-admin callers, BEFORE the admin bypass below -- a sip_accounts row may not exist yet for
	// this uid (upsert is insert-or-update), so this can't be checked against an existing row's own
	// tenant_id the way list()/remove() can; local_users is the authoritative source of the
	// target's real tenant instead. 404, not 403, and ONLY when the target's tenant is actually
	// known and different: this is deliberately narrower than "the uid must exist in local_users at
	// all" -- CP-HIPAA-2's own existing, deliberate 403 ("not yours to touch," distinguishable from
	// "doesn't exist" -- see remove()'s own established precedent) for a genuinely unrelated
	// participant must not be swallowed into an ambiguous 404 just because this uid has no
	// local_users row (e.g. hasn't self-registered yet, but a provider is still allowed to try and
	// correctly get a real, disclosed 403 for it).
	tenantID := callerTenantID(r)
	if rowTenantID, ok := localUserTenantID(r.Context(), h.DB, uid); ok && rowTenantID != tenantID {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "not found"})
		return
	}

	callerUID := operatorUIDFromContext(r)
	callerOrg := callerOrgID(r)
	if !hasPermission(r, "users.admin") {
		// CP-HIPAA-2/CP-HIPAA-3: a provider-only caller may only upsert a SIP extension for a
		// participant they already provision -- either an existing SIP account or mailbox they
		// created, or one whose owning organization shares a trusted cluster with their own
		// ("the admins from that collective should be able to administer participants from that
		// cluster of providers"). Never a genuinely unrelated uid.
		if !h.callerProvisionsParticipant(r, callerUID, callerOrg, uid) {
			writeJSON(w, http.StatusForbidden, map[string]string{"error": "forbidden: you may only provision SIP for a participant you already manage or a cluster-mate's participant"})
			return
		}
	}

	now := time.Now().UTC()
	// owning_org_id is only ever set on the FIRST insert (ON CONFLICT never touches it, same
	// "snapshot at creation, never live-updated" idiom mail_account_credentials.owning_org_id
	// already establishes) -- a cluster-mate updating an existing extension must not silently
	// reassign its owning organization to their own.
	_, err := h.DB.ExecContext(r.Context(), `
		INSERT INTO sip_accounts (local_uid, extension, sip_server, sip_port, created_by, owning_org_id, tenant_id, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(local_uid) DO UPDATE SET
			extension = excluded.extension,
			sip_server = excluded.sip_server,
			sip_port = excluded.sip_port,
			updated_at = excluded.updated_at
	`, uid, req.Extension, req.SipServer, req.SipPort, callerUID, callerOrg, tenantID, now)
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

// callerProvisionsParticipant -- CP-HIPAA-2/CP-HIPAA-3: true if callerUID already provisions
// uid's mailbox or SIP account (this participant is genuinely "theirs"), OR if uid's mailbox/SIP
// account has an owning organization that shares a trusted cluster with callerOrg (a real
// cluster-mate relationship). False otherwise -- a provider-only caller with neither relationship
// can't bootstrap one via SIP upsert.
func (h *SipAccountsHandler) callerProvisionsParticipant(r *http.Request, callerUID, callerOrg, uid int) bool {
	var count int
	if err := h.DB.QueryRowContext(r.Context(),
		`SELECT COUNT(*) FROM sip_accounts WHERE local_uid = ? AND created_by = ?`, uid, callerUID,
	).Scan(&count); err == nil && count > 0 {
		return true
	}
	if err := h.DB.QueryRowContext(r.Context(),
		`SELECT COUNT(*) FROM mail_account_credentials WHERE local_uid = ? AND created_by = ?`, uid, callerUID,
	).Scan(&count); err == nil && count > 0 {
		return true
	}
	var sipOrg, mailOrg sql.NullInt64
	_ = h.DB.QueryRowContext(r.Context(), `SELECT owning_org_id FROM sip_accounts WHERE local_uid = ?`, uid).Scan(&sipOrg)
	if sipOrg.Valid && orgsShareCluster(r.Context(), h.DB, callerOrg, int(sipOrg.Int64)) {
		return true
	}
	_ = h.DB.QueryRowContext(r.Context(), `SELECT owning_org_id FROM mail_account_credentials WHERE local_uid = ?`, uid).Scan(&mailOrg)
	if mailOrg.Valid && orgsShareCluster(r.Context(), h.DB, callerOrg, int(mailOrg.Int64)) {
		return true
	}
	return false
}

func (h *SipAccountsHandler) remove(w http.ResponseWriter, r *http.Request, uid int) {
	if !hasPermission(r, "users.admin") {
		// CP-HIPAA-2/CP-HIPAA-3: a provider-only caller can remove a SIP account they created,
		// or a cluster-mate's -- same relationship callerProvisionsParticipant already checks
		// for upsert, reused here rather than a third, separately-maintained scoping query.
		callerUID := callerLocalUID(r)
		if callerUID == nil {
			writeJSON(w, http.StatusForbidden, map[string]string{"error": "forbidden"})
			return
		}
		if !h.callerProvisionsParticipant(r, *callerUID, callerOrgID(r), uid) {
			writeJSON(w, http.StatusForbidden, map[string]string{"error": "forbidden"})
			return
		}
	}
	// MULTI_TENANCY_NORTHSTAR.md Phase 2: folding "AND tenant_id = ?" directly into the DELETE
	// (rather than a separate lookup-then-check) means a cross-tenant target naturally falls out
	// as RowsAffected==0 -- the exact same 404 a genuinely nonexistent uid already produced below,
	// with no separate branch needed and no way to distinguish the two cases from the response.
	res, err := h.DB.ExecContext(r.Context(), `DELETE FROM sip_accounts WHERE local_uid = ? AND tenant_id = ?`, uid, callerTenantID(r))
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
