package handlers

import (
	"encoding/json"
	"net/http"
	"strings"

	"idunapro/internal/twilio"
)

// TwilioHandler serves the real, credentials-protected Twilio operations the CarePyre Console
// needs (kanban CP-SIP-242414/TWILLIO-API-124, "we can do all of the operations from the
// carepyre console side"). The real API Key SID/Secret live server-side only (env vars, see
// main.go) -- the browser never sees them, only this handler's own JSON responses.
//
// Routes (all require Bearer JWT + the twilio.admin permission):
//
//	GET  /api/v1/twilio/status   balance + trunks + phone numbers, read-only
//	POST /api/v1/twilio/trunk    create a real Elastic SIP Trunk
type TwilioHandler struct {
	Client *twilio.Client
}

func (h *TwilioHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if !hasPermission(r, "twilio.admin") {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "forbidden"})
		return
	}
	if !h.Client.Configured() {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "twilio not configured on this deployment"})
		return
	}

	path := strings.TrimPrefix(r.URL.Path, "/api/v1/twilio")
	path = strings.TrimPrefix(path, "/")

	switch {
	case path == "status" && r.Method == http.MethodGet:
		h.status(w, r)
	case path == "trunk" && r.Method == http.MethodPost:
		h.createTrunk(w, r)
	default:
		http.Error(w, "not found", http.StatusNotFound)
	}
}

type twilioStatusResponse struct {
	Balance      *twilio.Balance      `json:"balance"`
	Trunks       []twilio.Trunk       `json:"trunks"`
	PhoneNumbers []twilio.PhoneNumber `json:"phone_numbers"`
	// Errors surfaces a per-call failure honestly (e.g. one real Twilio outage/rate-limit on
	// just one of the three calls) instead of failing the whole status response for a partial
	// real-world hiccup elsewhere.
	Errors map[string]string `json:"errors,omitempty"`
}

func (h *TwilioHandler) status(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	out := twilioStatusResponse{Errors: map[string]string{}}

	if bal, err := h.Client.GetBalance(ctx); err != nil {
		out.Errors["balance"] = err.Error()
	} else {
		out.Balance = bal
	}
	if trunks, err := h.Client.ListTrunks(ctx); err != nil {
		out.Errors["trunks"] = err.Error()
	} else {
		out.Trunks = trunks
	}
	if nums, err := h.Client.ListPhoneNumbers(ctx); err != nil {
		out.Errors["phone_numbers"] = err.Error()
	} else {
		out.PhoneNumbers = nums
	}
	if len(out.Errors) == 0 {
		out.Errors = nil
	}
	writeJSON(w, http.StatusOK, out)
}

type createTrunkRequest struct {
	FriendlyName string `json:"friendly_name"`
	DomainName   string `json:"domain_name"`
}

func (h *TwilioHandler) createTrunk(w http.ResponseWriter, r *http.Request) {
	var req createTrunkRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON"})
		return
	}
	if req.FriendlyName == "" || req.DomainName == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "friendly_name and domain_name are required"})
		return
	}
	trunk, err := h.Client.CreateTrunk(r.Context(), req.FriendlyName, req.DomainName)
	if err != nil {
		// Real, honest passthrough -- a Twilio compliance block (or any other real Twilio
		// error) reaches the console as the actual message, not a generic failure.
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, trunk)
}
