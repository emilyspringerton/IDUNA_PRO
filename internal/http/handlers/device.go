package handlers

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net"
	"net/http"
	"strings"
	"time"

	"idunapro/internal/auth/device"
	"idunapro/internal/util"
)

type ApiError struct {
	Code      string      `json:"code"`
	Message   string      `json:"message"`
	HonorCode interface{} `json:"honor_code,omitempty"`
}

type DeviceHandler struct {
	Svc            *device.Service
	StartLimiter   *util.WindowRateLimiter
	ConfirmLimiter *util.WindowRateLimiter
	JWTSecret      []byte
	BaseURL        string
}

func (h *DeviceHandler) Register(mux *http.ServeMux) {
	mux.HandleFunc("/auth/device/start", h.handleStart)
	mux.HandleFunc("/auth/device/poll", h.handlePoll)
	mux.HandleFunc("/auth/token/exchange", h.handleExchange)
	mux.HandleFunc("/device", h.handleDevicePage)
	mux.HandleFunc("/device/confirm", h.handleDeviceConfirm)
}

func (h *DeviceHandler) handleStart(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.NotFound(w, r)
		return
	}
	if !h.StartLimiter.Allow(clientIP(r), time.Now().UTC()) {
		writeAPIError(w, http.StatusTooManyRequests, "RATE_LIMITED", "Too many requests.", nil)
		return
	}
	resp, err := h.Svc.Start(r.Context(), strings.TrimSuffix(h.BaseURL, "/")+"/device")
	if err != nil {
		writeAPIError(w, 500, "INTERNAL", "internal error", nil)
		return
	}
	writeJSON(w, 200, resp)
}

func (h *DeviceHandler) handlePoll(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.NotFound(w, r)
		return
	}
	var req struct{ DeviceCode string `json:"device_code"` }
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeAPIError(w, 400, "BAD_REQUEST", "invalid json", nil)
		return
	}
	resp, err := h.Svc.Poll(r.Context(), req.DeviceCode)
	if err != nil {
		switch err {
		case device.ErrInvalidOrExpired:
			writeAPIError(w, 400, "DEVICE_CODE_INVALID_OR_EXPIRED", "Invalid or expired device code.", nil)
		case device.ErrPollingTooFast:
			w.Header().Set("Retry-After", "2")
			writeAPIError(w, 429, "POLLING_TOO_FAST", "Wait before polling again.", nil)
		default:
			writeAPIError(w, 500, "INTERNAL", "internal error", nil)
		}
		return
	}
	writeJSON(w, 200, resp)
}

func (h *DeviceHandler) handleExchange(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.NotFound(w, r)
		return
	}
	var req struct{ ExchangeCode string `json:"exchange_code"` }
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeAPIError(w, 400, "BAD_REQUEST", "invalid json", nil)
		return
	}
	usr, err := h.Svc.Exchange(r.Context(), req.ExchangeCode)
	if err != nil {
		switch err {
		case device.ErrExchangeInvalid:
			writeAPIError(w, 400, "EXCHANGE_CODE_INVALID", "Invalid exchange code.", nil)
		case device.ErrHonorCodeRequired:
			writeAPIError(w, 403, "HONOR_CODE_REQUIRED", "Honor code acceptance required.", map[string]any{"sha256": usr.HonorCurrentSHA, "version": usr.HonorCurrentVer, "text": usr.HonorCurrentText})
		case device.ErrHandleRequired:
			writeAPIError(w, 403, "HANDLE_REQUIRED", "Handle is required.", nil)
		case device.ErrAccountSuspended:
			writeAPIError(w, 403, "ACCOUNT_SUSPENDED", "Account suspended.", nil)
		default:
			writeAPIError(w, 500, "INTERNAL", "internal error", nil)
		}
		return
	}
	token := signHS256(h.JWTSecret, map[string]any{"sub": hex.EncodeToString(usr.ID[:]), "handle": usr.Handle, "roles": usr.Roles, "aud": "kikoryu", "iss": "iduna", "exp": time.Now().UTC().Add(time.Hour).Unix()})
	writeJSON(w, 200, map[string]any{"access_token": token, "expires_in": 3600, "me": map[string]any{"id": hex.EncodeToString(usr.ID[:]), "handle": usr.Handle, "status": usr.Status, "roles": usr.Roles}})
}

func signHS256(secret []byte, claims map[string]any) string {
	head, _ := json.Marshal(map[string]string{"alg": "HS256", "typ": "JWT"})
	body, _ := json.Marshal(claims)
	h := base64.RawURLEncoding.EncodeToString(head)
	b := base64.RawURLEncoding.EncodeToString(body)
	msg := h + "." + b
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(msg))
	sig := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	return msg + "." + sig
}

func (h *DeviceHandler) handleDevicePage(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.NotFound(w, r)
		return
	}
	if currentUserID(r) == nil {
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write([]byte(`<!doctype html><html><body><h1>Link your device</h1><form method="POST" action="/device/confirm"><label>Enter code</label><input name="user_code" placeholder="F4K7-9Q2M" /><button type="submit">Confirm</button></form></body></html>`))
}

func (h *DeviceHandler) handleDeviceConfirm(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.NotFound(w, r)
		return
	}
	uid := currentUserID(r)
	if uid == nil {
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}
	if !h.ConfirmLimiter.Allow("sess:"+hex.EncodeToString(uid[:]), time.Now().UTC()) {
		writeAPIError(w, 429, "RATE_LIMITED", "Too many attempts.", nil)
		return
	}
	userCode := r.FormValue("user_code")
	ipHash := sha256.Sum256([]byte(clientIP(r)))
	uaHash := sha256.Sum256([]byte(r.UserAgent()))
	if err := h.Svc.Confirm(r.Context(), userCode, *uid, ipHash, uaHash); err != nil {
		writeAPIError(w, 400, "DEVICE_CODE_INVALID_OR_EXPIRED", "Invalid or expired code.", nil)
		return
	}
	writeJSON(w, 200, map[string]bool{"ok": true})
}

func currentUserID(r *http.Request) *[16]byte {
	raw := r.Header.Get("X-User-ID")
	if len(raw) != 32 {
		return nil
	}
	b, err := hex.DecodeString(raw)
	if err != nil || len(b) != 16 {
		return nil
	}
	var out [16]byte
	copy(out[:], b)
	return &out
}

func clientIP(r *http.Request) string {
	h := r.Header.Get("X-Forwarded-For")
	if h != "" {
		return strings.TrimSpace(strings.Split(h, ",")[0])
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
func writeAPIError(w http.ResponseWriter, status int, code, msg string, honor any) {
	writeJSON(w, status, ApiError{Code: code, Message: msg, HonorCode: honor})
}
