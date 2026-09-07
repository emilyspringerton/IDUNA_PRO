package handlers

import (
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

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
// Stalwart itself is the only source of truth for which mailboxes EXIST -- this handler stays a
// thin proxy to its real JMAP management API (internal/mailaccounts) for that. What changed
// 2026-09-05 (founder real-time: "after a user provisions their account an admin can provision an
// email for them and then the webmail for that user should just work we can still reveal their
// password for webmail use somehow"): a NEW, separate table (mail_account_credentials, see its
// own migration comment) links a mailbox to an IDUNA_PRO local_uid and holds its real password
// ENCRYPTED at rest -- a deliberate, explicit reversal of this file's own earlier "a generated
// password is returned once and never persisted anywhere" stance, made because the founder asked
// for exactly this retrievability. WebmailHandler reads this table to auto-connect a user's
// webmail session with no manual "Connect" step; this handler's own reveal-password route lets an
// admin see it again later (e.g. to hand a user their password for a non-web mail client).
//
// CP-HIPAA-1 (founder real-time, 2026-09-07: "we can allow providers to create email accounts
// for participants"): a caller holding the new, least-privilege mail-accounts.provision
// permission (see localUserPermissions) can also reach every route here, alongside users.admin.
// A provider MUST link every mailbox they create to a participant's local_uid (create rejects an
// unlinked request from a provider-only caller with 400) -- HIPAA's own "minimum necessary"
// principle means a provider's list/reveal-password views are scoped to only the mailboxes THEY
// created (mail_account_credentials.created_by), never every participant in the system; a
// users.admin caller keeps the unrestricted, system-wide view unchanged.
//
// Routes (all require Bearer JWT + users.admin OR mail-accounts.provision, via
// middleware.RequireAuth + this handler's own requirePerm):
//
//	GET   /api/v1/mail-accounts                      list real mailboxes (each annotated with
//	                                                  local_uid when one is assigned); scoped to
//	                                                  the caller's own provisioned mailboxes for
//	                                                  a provider-only caller
//	POST  /api/v1/mail-accounts                      create one -- {"username", "domain"
//	                                                  (optional), "local_uid" (optional, REQUIRED
//	                                                  for a provider-only caller)}; when
//	                                                  local_uid is set, the mailbox is
//	                                                  auto-connected for that user's webmail
//	GET   /api/v1/mail-accounts/{uid}/reveal-password reveal the stored password for a user's
//	                                                  assigned mailbox; a provider-only caller
//	                                                  may only reveal mailboxes they created
type MailAccountsHandler struct {
	Client *mailaccounts.Client
	DB     *sql.DB
	// CredentialsKey encrypts/decrypts mail_account_credentials.password_enc (see
	// internal/mailaccounts/crypto.go). Empty means credential linking/reveal is unavailable --
	// mailbox creation still works, it just isn't tied to a local_uid.
	CredentialsKey []byte
}

func (h *MailAccountsHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if h.Client == nil || !h.Client.Configured() {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "mail account provisioning not configured"})
		return
	}
	if !hasPermission(r, "users.admin") && !hasPermission(r, "mail-accounts.provision") {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "forbidden"})
		return
	}

	path := strings.TrimPrefix(r.URL.Path, "/api/v1/mail-accounts")
	path = strings.TrimPrefix(path, "/")

	if path == "" {
		switch r.Method {
		case http.MethodGet:
			h.list(w, r)
		case http.MethodPost:
			h.create(w, r)
		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
		return
	}

	if strings.HasSuffix(path, "/reveal-password") {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		uid, err := strconv.Atoi(strings.TrimSuffix(path, "/reveal-password"))
		if err != nil {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "not found"})
			return
		}
		h.revealPassword(w, r, uid)
		return
	}

	writeJSON(w, http.StatusNotFound, map[string]string{"error": "not found"})
}

func (h *MailAccountsHandler) list(w http.ResponseWriter, r *http.Request) {
	accounts, err := h.Client.ListAccounts(r.Context())
	if err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": err.Error()})
		return
	}

	// Annotate each account with the local_uid it's assigned to (if any), so the admin console
	// can show "who owns this mailbox" without a second round trip.
	type credRow struct {
		localUID    int
		createdBy   sql.NullInt64
		owningOrgID int
	}
	credByEmail := map[string]credRow{}
	if h.DB != nil {
		rows, err := h.DB.QueryContext(r.Context(), `SELECT local_uid, email, created_by, owning_org_id FROM mail_account_credentials`)
		if err == nil {
			defer rows.Close()
			for rows.Next() {
				var c credRow
				var email string
				if rows.Scan(&c.localUID, &email, &c.createdBy, &c.owningOrgID) == nil {
					credByEmail[strings.ToLower(email)] = c
				}
			}
		}
	}

	// CP-HIPAA-1/CP-HIPAA-3 minimum-necessary scoping: a provider-only caller (no users.admin)
	// sees mailboxes THEY created, OR any mailbox whose owning organization shares a trusted
	// cluster with the caller's own organization ("the admins from that collective should be
	// able to administer participants from that cluster of providers") -- an unlinked mailbox,
	// or one from neither category, is invisible to them, not just unannotated.
	isAdmin := hasPermission(r, "users.admin")
	var callerUID *int
	callerOrg := 0
	if !isAdmin {
		callerUID = callerLocalUID(r)
		callerOrg = callerOrgID(r)
	}

	out := make([]mailAccountWithOwner, 0, len(accounts))
	for _, a := range accounts {
		c, linked := credByEmail[strings.ToLower(a.EmailAddress)]
		if !isAdmin {
			ownCreation := linked && c.createdBy.Valid && callerUID != nil && int(c.createdBy.Int64) == *callerUID
			clusterMate := linked && orgsShareCluster(r.Context(), h.DB, callerOrg, c.owningOrgID)
			if !ownCreation && !clusterMate {
				continue
			}
		}
		item := mailAccountWithOwner{Account: a}
		if linked {
			uid := c.localUID
			item.LocalUID = &uid
		}
		out = append(out, item)
	}
	writeJSON(w, http.StatusOK, out)
}

type mailAccountWithOwner struct {
	mailaccounts.Account
	LocalUID *int `json:"local_uid,omitempty"`
}

type createMailAccountRequest struct {
	Username string `json:"username"`
	Domain   string `json:"domain"`
	// Password is optional -- if omitted, a real, random 20-character password is generated
	// server-side and returned in the response (this is the expected, normal path for the
	// console's own "Create mailbox" button; an admin who wants to set a specific password by
	// hand can still pass one).
	Password string `json:"password"`
	// LocalUID, when set, links the new mailbox to that IDUNA_PRO user (mail_account_credentials)
	// so their webmail auto-connects -- founder real-time, 2026-09-05: "after a user provisions
	// their account an admin can provision an email for them and then the webmail for that user
	// should just work."
	LocalUID *int `json:"local_uid"`
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
	if req.LocalUID != nil && h.CredentialsKey == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "mailbox-to-user linking not configured (MAIL_CREDENTIALS_KEY unset)"})
		return
	}
	// CP-HIPAA-1: a provider-only caller (no users.admin) must always link the mailbox to a
	// participant -- an unlinked mailbox would be permanently invisible to them afterward (see
	// list's own minimum-necessary scoping above), which is almost certainly not what they meant.
	if req.LocalUID == nil && !hasPermission(r, "users.admin") {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "local_uid is required when provisioning as a provider (not users.admin)"})
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
	email := req.Username + "@" + domain

	if req.LocalUID != nil {
		if err := h.storeCredential(r, *req.LocalUID, email, password); err != nil {
			// The real Stalwart mailbox was already created successfully at this point -- report
			// the linking failure honestly rather than pretending the whole call failed, since a
			// retry would try (and likely fail) to create a duplicate mailbox.
			writeJSON(w, http.StatusCreated, map[string]any{
				"id": id, "email": email, "password": password,
				"warning": "mailbox created, but could not link it to the user for webmail auto-connect: " + err.Error(),
			})
			return
		}
	}

	writeJSON(w, http.StatusCreated, createMailAccountResponse{
		ID:       id,
		Email:    email,
		Password: password,
	})
}

func (h *MailAccountsHandler) storeCredential(r *http.Request, uid int, email, password string) error {
	if h.DB == nil {
		return errNoCredentialsStore
	}
	enc, err := mailaccounts.EncryptSecret(h.CredentialsKey, password)
	if err != nil {
		return err
	}
	now := time.Now().UTC()
	createdBy := operatorUIDFromContext(r)
	// CP-HIPAA-3: owning_org_id snapshots the CREATOR's own org_id at provisioning time (same
	// "snapshot, don't live-join" idiom created_by already established) -- the real fact a
	// cluster-mate provider's own list/reveal-password access is scoped against.
	owningOrgID := callerOrgID(r)
	_, err = h.DB.ExecContext(r.Context(), `
		INSERT INTO mail_account_credentials (local_uid, email, password_enc, created_by, owning_org_id, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(local_uid) DO UPDATE SET
			email = excluded.email,
			password_enc = excluded.password_enc,
			updated_at = excluded.updated_at
	`, uid, email, enc, createdBy, owningOrgID, now, now)
	return err
}

var errNoCredentialsStore = errors.New("no database configured for mail account credentials")

// revealPassword -- founder real-time, 2026-09-05: "we can still reveal their password for
// webmail use somehow." Decrypts and returns the real password an admin-linked mailbox was
// created with, so an admin can hand it to the user for a non-web mail client (or re-check it
// themselves) without knowing it from anywhere else.
func (h *MailAccountsHandler) revealPassword(w http.ResponseWriter, r *http.Request, uid int) {
	if h.DB == nil || h.CredentialsKey == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "mailbox-to-user linking not configured"})
		return
	}
	var email, enc string
	var createdBy sql.NullInt64
	var owningOrgID int
	err := h.DB.QueryRowContext(r.Context(),
		`SELECT email, password_enc, created_by, owning_org_id FROM mail_account_credentials WHERE local_uid = ?`, uid).Scan(&email, &enc, &createdBy, &owningOrgID)
	if err == sql.ErrNoRows {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "no mailbox linked to this user"})
		return
	}
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	// CP-HIPAA-1/CP-HIPAA-3 minimum-necessary scoping: a provider-only caller may reveal a
	// password for a mailbox they themselves created, OR one whose owning organization shares a
	// trusted cluster with their own -- the real "service navigator" cross-org case, logged
	// below since revealing a live credential is more sensitive than a password reset.
	if !hasPermission(r, "users.admin") {
		callerUID := callerLocalUID(r)
		ownCreation := callerUID != nil && createdBy.Valid && int(createdBy.Int64) == *callerUID
		callerOrg := callerOrgID(r)
		clusterMate := orgsShareCluster(r.Context(), h.DB, callerOrg, owningOrgID)
		if !ownCreation && !clusterMate {
			writeJSON(w, http.StatusForbidden, map[string]string{"error": "forbidden"})
			return
		}
		if !ownCreation && clusterMate && callerUID != nil {
			logCrossOrgAccess(r.Context(), h.DB, *callerUID, callerOrg, uid, owningOrgID, "reveal_mail_password")
		}
	}
	password, err := mailaccounts.DecryptSecret(h.CredentialsKey, enc)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"email": email, "password": password})
}
