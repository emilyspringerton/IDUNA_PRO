package handlers

import (
	"net/http"
	"time"
)

// HealthHandler handles GET /health.
type HealthHandler struct{}

func (h *HealthHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.NotFound(w, r)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":      true,
		"service": "iduna",
		"time":    time.Now().UTC().Format(time.RFC3339),
	})
}

// epochNow returns the current Unix epoch in seconds.
func epochNow() int64 {
	return time.Now().Unix()
}
