package handlers

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	"github.com/google/uuid"

	googleverify "idunapro/internal/auth/google"
	"idunapro/internal/auth/jwt"
	"idunapro/internal/store"
	"idunapro/internal/userlog"
)

// emitAuthEvent appends a real, honest, best-effort event to the unified logging backend
// (S226-02: "wire real IDUNA code paths to actually emit events" — S226-01 shipped the
// ingest/search infrastructure only). Real, deliberate design, matching this repo's own
// established fire-and-forget-logging precedent (apples.go's own syncAppleToGit, a background
// goroutine whose own failure never blocks the real HTTP response): `log` may be nil (existing
// callers/tests that don't wire one get ZERO behavior change, not a nil-pointer panic), and any
// real Append error is silently dropped — a logging-backend outage must never break the actual
// auth flow it's trying to observe. `data` is marshaled defensively; a marshal failure (should
// never happen for the small, hand-built maps every real call site here passes) also just skips
// the event rather than risking a panic on a security-critical path.
func emitAuthEvent(ctx context.Context, log userlog.EventLog, eventType, source string, data map[string]any) {
	if log == nil {
		return
	}
	raw, err := json.Marshal(data)
	if err != nil {
		return
	}
	now := time.Now().UTC()
	_, _ = log.Append(ctx, userlog.Event{
		ID:         uuid.NewString(),
		Type:       eventType,
		Source:     source,
		OccurredAt: now,
		IngestedAt: now,
		Data:       raw,
	})
}

// GoogleAuthHandler handles POST /api/v1/auth/google.
type GoogleAuthHandler struct {
	GoogleClientID string
	Keys           *jwt.Keys
	Store          store.IAMStore
	Issuer         string
	EventLog       userlog.EventLog // optional (S226-02); nil skips event emission entirely
}

func (h *GoogleAuthHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.NotFound(w, r)
		return
	}

	var body struct {
		IDToken string `json:"id_token"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.IDToken == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{
			"code":    "BAD_REQUEST",
			"message": "id_token is required",
		})
		return
	}

	gClaims, err := googleverify.Verify(r.Context(), body.IDToken, h.GoogleClientID)
	if err != nil {
		emitAuthEvent(r.Context(), h.EventLog, "iduna:auth.google.failure", "iduna-auth", map[string]any{
			"reason": "id_token_invalid",
		})
		writeJSON(w, http.StatusUnauthorized, map[string]any{
			"code":    "ID_TOKEN_INVALID",
			"message": err.Error(),
		})
		return
	}

	user, _, err := h.Store.GetOrCreateUserByGoogleSubject(r.Context(), gClaims.Sub, gClaims.Email)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{
			"code":    "INTERNAL",
			"message": "failed to resolve identity",
		})
		return
	}

	if user.Status == "SUSPENDED" || user.Status == "BANNED" {
		emitAuthEvent(r.Context(), h.EventLog, "iduna:auth.google.failure", "iduna-auth", map[string]any{
			"reason": "identity_suspended",
			"sub":    user.IDString,
			"status": user.Status,
		})
		writeJSON(w, http.StatusForbidden, map[string]any{
			"code":    "IDENTITY_SUSPENDED",
			"message": "identity is suspended or banned",
		})
		return
	}

	perms, err := h.Store.GetEffectivePermissions(r.Context(), user.IDString)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{
			"code":    "INTERNAL",
			"message": "failed to resolve permissions",
		})
		return
	}

	issuer := h.Issuer
	if issuer == "" {
		issuer = "https://iam.farthq.internal"
	}

	exp := time.Now().UTC().Add(time.Hour)
	jwtClaims := map[string]any{
		"sub":         user.IDString,
		"email":       user.Email,
		"gamertag":    user.Handle,
		"roles":       user.Roles,
		"permissions": perms,
		"iss":         issuer,
		"aud":         "farthq-ecosystem",
		"exp":         exp.Unix(),
	}

	token, err := jwt.Sign(h.Keys, jwtClaims)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{
			"code":    "INTERNAL",
			"message": "failed to sign token",
		})
		return
	}

	// Also set a real, HttpOnly iduna_session cookie -- the same cookie
	// name/shape admin_login.go's own agent flow already uses, so
	// RequireCookieAuth (internal/http/middleware/auth.go) works
	// identically for a human Google session as it already does for an
	// agent Back Office session, no new middleware needed. Existing
	// bearer-token consumers (Prompt-o-verse's own localStorage-based
	// widget, internal/promptoverse/render.go) are unaffected -- the
	// JSON body below is unchanged, this is additive. Real, concrete
	// need: gating a whole reverse-proxied multi-page app (the
	// notebook portal) behind login has to survive a plain browser
	// navigation/nginx auth_request subrequest, which only a cookie
	// does -- a bearer token in localStorage is invisible to both.
	http.SetCookie(w, &http.Cookie{
		Name:     "iduna_session",
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   3600,
	})

	emitAuthEvent(r.Context(), h.EventLog, "iduna:auth.google.success", "iduna-auth", map[string]any{
		"sub":   user.IDString,
		"email": user.Email,
	})
	writeJSON(w, http.StatusOK, map[string]any{
		"success":      true,
		"token_type":   "Bearer",
		"access_token": token,
		"expires_in":   3600,
	})
}

// AgentAuthHandler handles POST /api/v1/auth/agent — machine-to-machine
// credential exchange (spec HQ-SPEC-IAM-095 §3.1).
//
// Request body: {"agent_name": "EMILY", "agent_secret": "<raw key>"}
// Response:     {"access_token": "<JWT>", "token_type": "Bearer", "expires_in": 3600}
//
// The agent must be ACTIVE and have a credential set (via SetAgentCredential).
// The returned JWT embeds the agent's effective permissions so downstream
// services can enforce capability-level access control without calling IDUNA.
type AgentAuthHandler struct {
	Keys     *jwt.Keys
	Store    store.IAMStore
	Issuer   string
	EventLog userlog.EventLog // optional (S226-02); nil skips event emission entirely
}

func (h *AgentAuthHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.NotFound(w, r)
		return
	}
	var body struct {
		AgentName   string `json:"agent_name"`
		AgentSecret string `json:"agent_secret"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.AgentName == "" || body.AgentSecret == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{
			"code":    "BAD_REQUEST",
			"message": "agent_name and agent_secret are required",
		})
		return
	}

	agent, err := h.Store.AuthenticateAgent(r.Context(), body.AgentName, body.AgentSecret)
	if err != nil {
		// Real, deliberate: log the attempted agent_name only, NEVER agent_secret (a real
		// credential) -- this is a security audit trail, not a place to leak the very secrets
		// it's meant to help investigate misuse of.
		emitAuthEvent(r.Context(), h.EventLog, "iduna:auth.agent.failure", "iduna-auth", map[string]any{
			"agent_name": body.AgentName,
		})
		writeJSON(w, http.StatusUnauthorized, map[string]any{
			"code":    "AGENT_AUTH_FAILED",
			"message": "invalid agent credentials",
		})
		return
	}

	issuer := h.Issuer
	if issuer == "" {
		issuer = "https://iam.farthq.internal"
	}
	exp := time.Now().UTC().Add(time.Hour)
	jwtClaims := map[string]any{
		"sub":         agent.ID,
		"agent_name":  agent.Name,
		"agent_type":  agent.Type,
		"permissions": agent.Permissions,
		"iss":         issuer,
		"aud":         "farthq-ecosystem",
		"exp":         exp.Unix(),
	}
	token, err := jwt.Sign(h.Keys, jwtClaims)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{
			"code":    "INTERNAL",
			"message": "failed to sign token",
		})
		return
	}
	emitAuthEvent(r.Context(), h.EventLog, "iduna:auth.agent.success", "iduna-auth", map[string]any{
		"agent_id":   agent.ID,
		"agent_name": agent.Name,
	})
	writeJSON(w, http.StatusOK, map[string]any{
		"success":      true,
		"token_type":   "Bearer",
		"access_token": token,
		"expires_in":   3600,
	})
}
