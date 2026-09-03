package handlers

import (
	"net/http"

	"idunapro/internal/auth/jwt"
)

// JWKSHandler handles GET /.well-known/jwks.json.
type JWKSHandler struct {
	Keys *jwt.Keys
}

func (h *JWKSHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Cache-Control", "public, max-age=3600")
	writeJSON(w, http.StatusOK, h.Keys.JWKS())
}
