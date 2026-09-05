package handlers

import (
	"database/sql"
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
//	GET             /api/v1/sip-accounts/me      self, any authenticated caller
//	GET             /api/v1/sip-accounts         list, requires users.admin
//	PUT             /api/v1/sip-accounts/{uid}   upsert, requires users.admin
//	DELETE          /api/v1/sip-accounts/{uid}   remove, requires users.admin
type SipAccountsHandler struct {
	DB *sql.DB
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
