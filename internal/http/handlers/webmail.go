package handlers

import (
	"database/sql"
	"encoding/json"
	"net/http"
	"strings"
	"sync"

	"idunapro/internal/mailaccounts"
)

// WebmailHandler serves a real, minimal webmail feature -- founder real-time, 2026-09-05:
// "minimal custom webmail in the console and then we will evolve the sip phone app to be a
// universal communication app... build it into that after we get the webmail working." Real,
// deliberately narrow v0: Inbox only (no other folders), plain-text bodies only (no
// HTML/attachments), single-recipient send only. Available to ANY authenticated console user,
// not admin-gated -- unlike MailAccountsHandler (provisioning), this is the per-user feature a
// real mailbox owner uses, matching the founder's own framing ("for a non admin account").
//
// Real, honest architecture note: Stalwart's OAuth server has no client_credentials grant (see
// internal/mailaccounts/client.go's own header comment), so there's no way for this server to
// act "as" a user's mailbox without that user's own real email+password. Real, minimal v0
// design: a user "connects" their mailbox once per server-process-lifetime by submitting their
// own Stalwart credential; it's held in this handler's own in-memory map, keyed by their
// IDUNA_PRO local_uid, NEVER written to disk or the local DB from THIS path.
//
// 2026-09-05 update (founder real-time: "after a user provisions their account an admin can
// provision an email for them and then the webmail for that user should just work"): when an
// admin links a mailbox to a local_uid via MailAccountsHandler, the real password is persisted
// ENCRYPTED in mail_account_credentials (see that migration's own header comment). This handler
// now falls back to that table on a cache miss -- decrypts once, caches the result in the same
// in-memory map used by the manual-connect path, and the user's webmail just works with zero
// manual "Connect" step. A user who connects manually (e.g. an untethered mailbox not linked to
// their uid) still works exactly as before; nothing here is written back to the DB.
//
// Routes (all require Bearer JWT via middleware.RequireAuth):
//
//	GET   /api/v1/mail/status            self -- {"connected": bool, "email": "..."}
//	POST  /api/v1/mail/connect           self -- {"email": "...", "password": "..."}
//	GET   /api/v1/mail/messages          self -- real Inbox list, newest first
//	GET   /api/v1/mail/messages/{id}     self -- one real full message
//	POST  /api/v1/mail/send              self -- {"to": "...", "subject": "...", "body": "..."}
type WebmailHandler struct {
	BaseURL string // e.g. "https://mail.carepyre.org"

	// DB and CredentialsKey enable the admin-provisioned auto-connect path above. Both nil/empty
	// means this handler behaves exactly as it did before 2026-09-05: manual connect only.
	DB             *sql.DB
	CredentialsKey []byte

	mu          sync.RWMutex
	connections map[int]webmailConnection
}

// autoConnect looks up a persisted, admin-linked mailbox credential for uid and, if found,
// decrypts it and caches it in the in-memory connections map -- the same map the manual /connect
// path populates. Returns ok=false (never an error the caller need surface) when there's simply
// nothing to auto-connect, which is the normal case for any user without an admin-linked mailbox.
func (h *WebmailHandler) autoConnect(uid int) (webmailConnection, bool) {
	if h.DB == nil || len(h.CredentialsKey) == 0 {
		return webmailConnection{}, false
	}
	var email, enc string
	err := h.DB.QueryRow(`SELECT email, password_enc FROM mail_account_credentials WHERE local_uid = ?`, uid).Scan(&email, &enc)
	if err != nil {
		return webmailConnection{}, false
	}
	password, err := mailaccounts.DecryptSecret(h.CredentialsKey, enc)
	if err != nil {
		return webmailConnection{}, false
	}
	conn := webmailConnection{Email: email, Password: password}
	h.mu.Lock()
	if h.connections == nil {
		h.connections = map[int]webmailConnection{}
	}
	h.connections[uid] = conn
	h.mu.Unlock()
	return conn, true
}

type webmailConnection struct {
	Email    string
	Password string
}

func (h *WebmailHandler) client(uid int) (*mailaccounts.Client, string, bool) {
	h.mu.RLock()
	conn, ok := h.connections[uid]
	h.mu.RUnlock()
	if !ok {
		conn, ok = h.autoConnect(uid)
		if !ok {
			return nil, "", false
		}
	}
	return &mailaccounts.Client{
		BaseURL:   h.BaseURL,
		AdminUser: conn.Email,
		AdminPass: conn.Password,
	}, conn.Email, true
}

func (h *WebmailHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	uid := callerLocalUID(r)
	if uid == nil {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "forbidden"})
		return
	}
	path := strings.TrimPrefix(r.URL.Path, "/api/v1/mail")
	path = strings.TrimPrefix(path, "/")

	switch {
	case path == "status" && r.Method == http.MethodGet:
		h.status(w, *uid)
	case path == "connect" && r.Method == http.MethodPost:
		h.connect(w, r, *uid)
	case path == "messages" && r.Method == http.MethodGet:
		h.listMessages(w, r, *uid)
	case strings.HasPrefix(path, "messages/") && r.Method == http.MethodGet:
		h.getMessage(w, r, *uid, strings.TrimPrefix(path, "messages/"))
	case path == "send" && r.Method == http.MethodPost:
		h.send(w, r, *uid)
	default:
		http.Error(w, "not found", http.StatusNotFound)
	}
}

func (h *WebmailHandler) status(w http.ResponseWriter, uid int) {
	h.mu.RLock()
	conn, ok := h.connections[uid]
	h.mu.RUnlock()
	if !ok {
		conn, ok = h.autoConnect(uid)
	}
	if !ok {
		writeJSON(w, http.StatusOK, map[string]any{"connected": false})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"connected": true, "email": conn.Email})
}

type connectRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

func (h *WebmailHandler) connect(w http.ResponseWriter, r *http.Request, uid int) {
	var req connectRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON"})
		return
	}
	req.Email = strings.TrimSpace(req.Email)
	if req.Email == "" || req.Password == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "email and password are required"})
		return
	}
	// Real, deliberate validation: actually try to list the Inbox once (a real, minimal
	// operation any valid credential can do) rather than just storing whatever was typed --
	// a wrong password should fail loudly right now, not silently on the next page load.
	testClient := &mailaccounts.Client{BaseURL: h.BaseURL, AdminUser: req.Email, AdminPass: req.Password}
	if _, err := testClient.ListInbox(r.Context()); err != nil {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "could not connect: " + err.Error()})
		return
	}
	h.mu.Lock()
	if h.connections == nil {
		h.connections = map[int]webmailConnection{}
	}
	h.connections[uid] = webmailConnection{Email: req.Email, Password: req.Password}
	h.mu.Unlock()
	writeJSON(w, http.StatusOK, map[string]any{"connected": true, "email": req.Email})
}

func (h *WebmailHandler) listMessages(w http.ResponseWriter, r *http.Request, uid int) {
	c, _, ok := h.client(uid)
	if !ok {
		writeJSON(w, http.StatusPreconditionRequired, map[string]string{"error": "not connected -- POST /api/v1/mail/connect first"})
		return
	}
	messages, err := c.ListInbox(r.Context())
	if err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, messages)
}

func (h *WebmailHandler) getMessage(w http.ResponseWriter, r *http.Request, uid int, id string) {
	c, _, ok := h.client(uid)
	if !ok {
		writeJSON(w, http.StatusPreconditionRequired, map[string]string{"error": "not connected -- POST /api/v1/mail/connect first"})
		return
	}
	msg, err := c.GetMessage(r.Context(), id)
	if err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, msg)
}

type sendRequest struct {
	To      string `json:"to"`
	Subject string `json:"subject"`
	Body    string `json:"body"`
}

func (h *WebmailHandler) send(w http.ResponseWriter, r *http.Request, uid int) {
	c, _, ok := h.client(uid)
	if !ok {
		writeJSON(w, http.StatusPreconditionRequired, map[string]string{"error": "not connected -- POST /api/v1/mail/connect first"})
		return
	}
	var req sendRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON"})
		return
	}
	req.To = strings.TrimSpace(req.To)
	if req.To == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "to is required"})
		return
	}
	if err := c.SendMessage(r.Context(), req.To, req.Subject, req.Body); err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"sent": true})
}
