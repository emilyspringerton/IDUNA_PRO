package handlers

import (
	"encoding/json"
	"net/http"
	"strings"

	"idunapro/internal/mailaccounts"
)

// MailAccountsHandler exposes real CarePyre Stalwart mailbox provisioning from the admin
// console. Founder real-time, 2026-09-05: "ok we need a way to provision accounts from the
// carepyre admin console is that possible?" -- followed by an explicit scope decision: "For now
// admins can provision because sign up is just open" (i.e. console self-signup is currently
// open, so mailbox provisioning specifically stays admin-gated, matching
// docs/EMAIL_NORTHSTAR.md's own existing v0 decision: staff-provisioned mailboxes, no public
// self-signup for email).
//
// No local database table -- Stalwart itself is the only source of truth for which mailboxes
// exist; this handler is a pure, thin proxy to its real JMAP management API
// (internal/mailaccounts). Same real "password never stored here" discipline
// sip_accounts.go's own header comment already established for this repo: a generated password
// is returned once in the create response and never persisted anywhere in IDUNA_PRO's own DB.
//
// Routes (all require Bearer JWT + users.admin, via middleware.RequireAuth + this handler's own
// requirePerm):
//
//	GET   /api/v1/mail-accounts   list real mailboxes
//	POST  /api/v1/mail-accounts   create one -- {"username": "...", "domain": "..." (optional)}
type MailAccountsHandler struct {
	Client *mailaccounts.Client
}

func (h *MailAccountsHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if h.Client == nil || !h.Client.Configured() {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "mail account provisioning not configured"})
		return
	}
	if !hasPermission(r, "users.admin") {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "forbidden"})
		return
	}
	switch r.Method {
	case http.MethodGet:
		h.list(w, r)
	case http.MethodPost:
		h.create(w, r)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (h *MailAccountsHandler) list(w http.ResponseWriter, r *http.Request) {
	accounts, err := h.Client.ListAccounts(r.Context())
	if err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, accounts)
}

type createMailAccountRequest struct {
	Username string `json:"username"`
	Domain   string `json:"domain"`
	// Password is optional -- if omitted, a real, random 20-character password is generated
	// server-side and returned in the response (this is the expected, normal path for the
	// console's own "Create mailbox" button; an admin who wants to set a specific password by
	// hand can still pass one).
	Password string `json:"password"`
}

type createMailAccountResponse struct {
	ID       string `json:"id"`
	Email    string `json:"email"`
	Password string `json:"password"`
}

func (h *MailAccountsHandler) create(w http.ResponseWriter, r *http.Request) {
	var req createMailAccountRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON"})
		return
	}
	req.Username = strings.TrimSpace(strings.ToLower(req.Username))
	req.Domain = strings.TrimSpace(strings.ToLower(req.Domain))
	if req.Username == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "username is required"})
		return
	}
	if strings.ContainsAny(req.Username, "@ \t") {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "username must be the local part only, not a full email address"})
		return
	}

	password := req.Password
	if password == "" {
		var err error
		password, err = mailaccounts.GenerateSecret()
		if err != nil {
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
	}

	domain := req.Domain
	if domain == "" {
		domain = h.Client.DefaultDomain
	}

	id, err := h.Client.CreateAccount(r.Context(), req.Username, domain, password)
	if err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": err.Error()})
		return
	}

	writeJSON(w, http.StatusCreated, createMailAccountResponse{
		ID:       id,
		Email:    req.Username + "@" + domain,
		Password: password,
	})
}
