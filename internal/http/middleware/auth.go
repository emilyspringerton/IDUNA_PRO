package middleware

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"time"

	"idunapro/internal/auth"
	"idunapro/internal/auth/jwt"
)

// AgentStatusChecker is the minimal slice of store.IAMStore RequireCookieAuth
// needs -- a narrow interface rather than the full store, so callers (and
// tests) don't need a complete IAMStore implementation just to check one
// agent's live status. store.IAMStore satisfies this automatically.
type AgentStatusChecker interface {
	GetAgentByID(ctx context.Context, agentID string) (*auth.Agent, error)
}

type contextKey string

const claimsKey contextKey = "jwt_claims"

// RequireAuth returns middleware that validates an ES256 Bearer token.
// On success it stores the claims map in the request context.
func RequireAuth(keys *jwt.Keys) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			authHeader := r.Header.Get("Authorization")
			if !strings.HasPrefix(authHeader, "Bearer ") {
				writeUnauthorized(w)
				return
			}
			token := strings.TrimPrefix(authHeader, "Bearer ")
			claims, err := jwt.Verify(keys, token)
			if err != nil {
				writeUnauthorized(w)
				return
			}
			ctx := context.WithValue(r.Context(), claimsKey, claims)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// RequireCookieAuth is like RequireAuth but also accepts an iduna_session cookie.
// When auth fails for a browser request (Accept: text/html), it redirects to loginURL.
//
// sessionTTL enables sliding-expiration refresh: once less than half of sessionTTL
// remains before the cookie's JWT expires, a fresh cookie with a new full-TTL expiry
// is issued transparently on the response. Without this, a still-active admin session
// hits a silent hard cutoff at exactly sessionTTL after login — the next click just
// bounces to the login page with no explanation, which reads as an unexplained/
// "unexpected" logout during a long working session. Pass 0 to disable refresh.
//
// iamStore, when non-nil, re-verifies the session against LIVE agent state on every
// request: signature/expiry alone only prove who was ACTIVE at login, not who is
// ACTIVE now. Without this check, suspending an agent blocks new logins but does
// nothing to a session it already handed out — a suspended agent with an open tab
// keeps working, and (holding iduna.admin) can un-suspend itself right back. Found
// and disclosed 2026-08-25 (see the "Mid-Piano Presents: The Memory Ceremony" blog
// post published ahead of this fix). Pass nil only from tests that don't exercise
// this path; every real caller must pass the live store.
func RequireCookieAuth(keys *jwt.Keys, iamStore AgentStatusChecker, loginURL string, sessionTTL time.Duration) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			token := bearerOrCookie(r)
			if token == "" {
				redirectOrJSON(w, r, loginURL)
				return
			}
			claims, err := jwt.Verify(keys, token)
			if err != nil {
				redirectOrJSON(w, r, loginURL)
				return
			}
			// Live-status re-check only applies to AGENT sessions (the
			// admin Back Office flow this was built for). GetAgentByID
			// only looks in the agents table, so calling it with a human
			// Google-login user's "sub" would always miss and
			// incorrectly bounce every human cookie session to the
			// login page -- found wiring up the notebook portal's own
			// human SSO cookie login the same session this live-recheck
			// was added. Only GoogleAuthHandler's claims carry "email";
			// no agent-issued token (admin_login.go, AgentAuthHandler)
			// ever does, so its presence is the real discriminator here.
			_, isHumanSession := claims["email"]
			if iamStore != nil && !isHumanSession {
				agentID, _ := claims["sub"].(string)
				agent, err := iamStore.GetAgentByID(r.Context(), agentID)
				if err != nil || agent.Status != "ACTIVE" {
					// The session outlived the agent's real standing -- kill the
					// cookie too, not just this request, so the browser stops
					// re-presenting a dead session on every subsequent click.
					clearSessionCookie(w)
					redirectOrJSON(w, r, loginURL)
					return
				}
				// Re-derive permissions from live grants, not the token's
				// snapshot-at-login -- a revoked permission should stop working
				// on the next click too, same as a suspension.
				claims["permissions"] = agent.Permissions
			}
			if sessionTTL > 0 {
				refreshCookieIfStale(w, keys, claims, sessionTTL)
			}
			ctx := context.WithValue(r.Context(), claimsKey, claims)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// refreshCookieIfStale re-signs claims with a fresh sessionTTL expiry and sets a new
// iduna_session cookie when less than half of sessionTTL remains on the current token.
// Silently no-ops on any error — a failed refresh just means the original cookie's own
// (still-valid) expiry applies, never a hard failure for the request in flight.
func refreshCookieIfStale(w http.ResponseWriter, keys *jwt.Keys, claims map[string]any, sessionTTL time.Duration) {
	exp, ok := claims["exp"]
	if !ok {
		return
	}
	var expUnix int64
	switch v := exp.(type) {
	case float64:
		expUnix = int64(v)
	case int64:
		expUnix = v
	default:
		return
	}
	remaining := time.Until(time.Unix(expUnix, 0))
	if remaining <= 0 || remaining > sessionTTL/2 {
		return
	}
	newExp := time.Now().UTC().Add(sessionTTL)
	claims["exp"] = newExp.Unix()
	token, err := jwt.Sign(keys, claims)
	if err != nil {
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:     "iduna_session",
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   int(sessionTTL.Seconds()),
	})
}

// clearSessionCookie expires the iduna_session cookie immediately -- same
// shape as AdminLoginHandler.logout, duplicated rather than imported to
// avoid a handlers<->middleware import cycle.
func clearSessionCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:   "iduna_session",
		Value:  "",
		Path:   "/",
		MaxAge: -1,
	})
}

func bearerOrCookie(r *http.Request) string {
	if auth := r.Header.Get("Authorization"); strings.HasPrefix(auth, "Bearer ") {
		return strings.TrimPrefix(auth, "Bearer ")
	}
	if c, err := r.Cookie("iduna_session"); err == nil && c.Value != "" {
		return c.Value
	}
	return ""
}

func redirectOrJSON(w http.ResponseWriter, r *http.Request, loginURL string) {
	if loginURL != "" && strings.Contains(r.Header.Get("Accept"), "text/html") {
		target := loginURL
		if path := r.URL.RequestURI(); path != "/" && path != loginURL {
			target += "?next=" + url.QueryEscape(path)
		}
		http.Redirect(w, r, target, http.StatusSeeOther)
		return
	}
	writeUnauthorized(w)
}

// RequirePermission returns middleware that checks the "permissions" claim
// contains the required permission string. Returns 403 if not present.
func RequirePermission(perm string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			claims := ClaimsFromContext(r.Context())
			if !hasPermission(claims, perm) {
				writeForbidden(w)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// ClaimsFromContext returns the JWT claims stored in the context, or nil.
func ClaimsFromContext(ctx context.Context) map[string]any {
	v, _ := ctx.Value(claimsKey).(map[string]any)
	return v
}

// PermissionsFromContext returns the "permissions" slice from the JWT stored in context.
func PermissionsFromContext(ctx context.Context) []string {
	claims := ClaimsFromContext(ctx)
	if claims == nil {
		return nil
	}
	perms, _ := claims["permissions"]
	switch v := perms.(type) {
	case []any:
		out := make([]string, 0, len(v))
		for _, p := range v {
			if s, ok := p.(string); ok {
				out = append(out, s)
			}
		}
		return out
	case []string:
		return v
	}
	return nil
}

// SubjectFromContext returns the "sub" claim from the JWT stored in context.
func SubjectFromContext(ctx context.Context) string {
	claims := ClaimsFromContext(ctx)
	if claims == nil {
		return ""
	}
	sub, _ := claims["sub"].(string)
	return sub
}

func hasPermission(claims map[string]any, perm string) bool {
	if claims == nil {
		return false
	}
	perms, ok := claims["permissions"]
	if !ok {
		return false
	}
	switch v := perms.(type) {
	case []any:
		for _, p := range v {
			if s, ok := p.(string); ok && s == perm {
				return true
			}
		}
	case []string:
		for _, s := range v {
			if s == perm {
				return true
			}
		}
	}
	return false
}

func writeUnauthorized(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusUnauthorized)
	_, _ = w.Write([]byte(`{"code":"UNAUTHORIZED","message":"valid Bearer token required"}`))
}

func writeForbidden(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusForbidden)
	_, _ = w.Write([]byte(`{"code":"FORBIDDEN","message":"insufficient permissions"}`))
}
