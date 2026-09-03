package handlers

import (
	"net/http"
	"strings"
	"time"

	authjwt "idunapro/internal/auth/jwt"
)

// RefreshHandler handles POST /api/v1/auth/refresh.
//
// Accepts a valid, non-expired ES256 JWT in the Authorization header
// (Bearer <token>). Verifies the token against the IDUNA key set and
// issues a new 8-hour JWT with the same claims (all claims forwarded
// except exp and iat, which are reset).
type RefreshHandler struct {
	Keys   *authjwt.Keys
	Issuer string
}

type refreshResponse struct {
	Token     string `json:"token"`
	ExpiresAt int64  `json:"expires_at"`
}

func (h *RefreshHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	tokenStr := bearerToken(r)
	usedCookie := false
	if tokenStr == "" {
		// Cookie-only sessions (the notebook portal's Google SSO flow --
		// see auth.go's GoogleAuthHandler) have no localStorage bearer
		// token to put in an Authorization header in the first place;
		// the iduna_session cookie IS the credential there. Fall back to
		// it so a cookie-only browser session can still refresh itself
		// on the same 20-minute timer the promptoverse widget already
		// uses for its bearer-token sessions, rather than silently
		// expiring after 1 hour with no way to renew.
		if c, err := r.Cookie("iduna_session"); err == nil && c.Value != "" {
			tokenStr = c.Value
			usedCookie = true
		}
	}
	if tokenStr == "" {
		writeJSON(w, http.StatusUnauthorized, map[string]string{
			"code":    "MISSING_TOKEN",
			"message": "Authorization: Bearer <token> required",
		})
		return
	}

	claims, err := authjwt.Verify(h.Keys, tokenStr)
	if err != nil {
		writeJSON(w, http.StatusUnauthorized, map[string]string{
			"code":    "TOKEN_INVALID",
			"message": err.Error(),
		})
		return
	}

	// Build a new claims map copying all forwarded claims, then reset exp/iat.
	newClaims := make(map[string]any, len(claims)+2)
	for k, v := range claims {
		newClaims[k] = v
	}
	exp := time.Now().UTC().Add(8 * time.Hour)
	newClaims["exp"] = exp.Unix()
	newClaims["iat"] = time.Now().UTC().Unix()
	if h.Issuer != "" {
		newClaims["iss"] = h.Issuer
	}

	token, err := authjwt.Sign(h.Keys, newClaims)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{
			"code":    "SIGN_FAILED",
			"message": "failed to sign token",
		})
		return
	}

	// Keep the iduna_session cookie (auth.go's GoogleAuthHandler is what
	// first sets it) in sync with the refreshed token -- a cookie-only
	// notebook-portal session (usedCookie above) has no other way to
	// renew itself, and a browser session that also carries the cookie
	// alongside its bearer token would otherwise have the cookie expire
	// out from under it 1 hour in while the bearer token stays valid via
	// this same endpoint. Only touch the cookie when one was actually
	// presented -- a pure bearer client (an agent, a script) that never
	// had a cookie session shouldn't be handed one it never asked for.
	if usedCookie {
		http.SetCookie(w, &http.Cookie{
			Name:     "iduna_session",
			Value:    token,
			Path:     "/",
			HttpOnly: true,
			SameSite: http.SameSiteLaxMode,
			MaxAge:   int(time.Until(exp).Seconds()),
		})
	} else if c, err := r.Cookie("iduna_session"); err == nil && c.Value != "" {
		http.SetCookie(w, &http.Cookie{
			Name:     "iduna_session",
			Value:    token,
			Path:     "/",
			HttpOnly: true,
			SameSite: http.SameSiteLaxMode,
			MaxAge:   int(time.Until(exp).Seconds()),
		})
	}

	writeJSON(w, http.StatusOK, refreshResponse{
		Token:     token,
		ExpiresAt: exp.Unix(),
	})
}

// bearerToken extracts the token from "Authorization: Bearer <token>".
func bearerToken(r *http.Request) string {
	hdr := r.Header.Get("Authorization")
	if hdr == "" {
		return ""
	}
	const prefix = "bearer "
	if !strings.HasPrefix(strings.ToLower(hdr), prefix) {
		return ""
	}
	return strings.TrimSpace(hdr[len(prefix):])
}

