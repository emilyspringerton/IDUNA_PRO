package handlers

import (
	"database/sql"
	"net/http"
	"strings"
)

// SipProvisioningFetchHandler serves the real, public (no bearer auth) capability-URL endpoint
// SipAccountsHandler.getMineProvisioningURL mints. Founder real-time, 2026-09-05: "make the sip
// phone register with just that URL" -- the native app fetches this directly on first launch,
// before it has ever logged in or obtained a bearer token, so this route cannot be behind
// middleware.RequireAuth the way every other sip-accounts route is. The token itself IS the
// auth (HMAC-signed, unguessable, same real capability-URL security class the already-deployed
// Linphone provisioning URLs use -- see CarePyre/ops/linphone-provisioning-template.xml's own
// header comment).
//
// Real, deliberate difference from GET /api/v1/sip-accounts/me/qr (the authenticated,
// in-console QR payload): THIS endpoint includes the real PJSIP password. That's the whole
// point of "register with just that URL" -- zero manual fields left for the user to type. The
// tradeoff is real and named, not hidden: whoever has the exact URL can register as this
// extension. Mitigated the same way the Linphone precedent already accepted: the token is
// unguessable (HMAC-SHA256 over a real random key, not sequential or derivable from anything
// public), and it isn't printed or logged anywhere after the console mints it once.
//
// Route: GET /api/v1/sip-provisioning/{token}   -- mounted WITHOUT middleware.RequireAuth in main.go
type SipProvisioningFetchHandler struct {
	DB                    *sql.DB
	ProvisioningKey       []byte
	SipSecretsByExtension map[string]string
}

// sipProvisioningFetchPayload -- same real shape as sipProvisioningPayload (sip_accounts.go)
// plus the one real field that flow deliberately omits: Password. Scheme bumped to v2 so a
// future native build can tell the two payload shapes apart by design, not by guessing whether
// a "password" key happens to be present.
type sipProvisioningFetchPayload struct {
	Scheme    string `json:"scheme"`
	Extension string `json:"extension"`
	SipServer string `json:"sip_server"`
	SipPort   int    `json:"sip_port"`
	Transport string `json:"transport"`
	Password  string `json:"password"`
}

func (h *SipProvisioningFetchHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if h.DB == nil || len(h.ProvisioningKey) == 0 {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "sip provisioning not available"})
		return
	}
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	token := strings.TrimPrefix(r.URL.Path, "/api/v1/sip-provisioning/")
	token = strings.TrimSuffix(token, "/")
	if token == "" {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "not found"})
		return
	}
	uid, ok := VerifyProvisioningToken(h.ProvisioningKey, token)
	if !ok {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "not found"})
		return
	}

	var extension, sipServer string
	var sipPort int
	err := h.DB.QueryRowContext(r.Context(),
		`SELECT extension, sip_server, sip_port FROM sip_accounts WHERE local_uid = ?`, uid,
	).Scan(&extension, &sipServer, &sipPort)
	if err == sql.ErrNoRows {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "not found"})
		return
	}
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	password := h.SipSecretsByExtension[extension]
	if password == "" {
		// Real, honest gap surfaced rather than silently returning an empty password the phone
		// would just fail to register with anyway: this extension has no real secret configured
		// on this server (SIP_SECRETS_JSON, see main.go's own wiring comment).
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "no credential configured for this extension -- ask an admin"})
		return
	}

	writeJSON(w, http.StatusOK, sipProvisioningFetchPayload{
		Scheme:    "carepyre-sip-v2",
		Extension: extension,
		SipServer: sipServer,
		SipPort:   sipPort,
		Transport: "UDP",
		Password:  password,
	})
}
