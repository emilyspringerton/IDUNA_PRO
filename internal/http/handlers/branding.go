package handlers

import (
	"database/sql"
	"encoding/json"
	"net/http"
	"strings"
)

// BrandingHandler exposes real, minimal white-label configuration (CP-WHITELABEL-1, founder
// real-time: "it needs to be both white labeled first then made into carepyre") -- one console
// codebase, one API, per-instance name/tagline/colors/logo instead of anything hardcoded to a
// single tenant. GET is deliberately PUBLIC (no Bearer JWT required): the login screen itself
// needs to render branded before anyone has a token. PUT is branding.admin-gated at the mux
// level (main.go registers "GET /api/v1/branding" and "PUT /api/v1/branding" as two separate,
// separately-protected routes on the same path -- Go 1.22+ stdlib ServeMux method patterns).
//
// CarePyre is the first real tenant of this, not a special case in the schema: its console.html
// fetches this endpoint at load and applies the result as CSS custom properties + document
// title, falling back to its own existing hardcoded values if the fetch fails or the instance
// never configured branding (see console.html's own applyBranding()).
type BrandingHandler struct {
	DB *sql.DB
}

type brandingResponse struct {
	AppName      string `json:"app_name"`
	Tagline      string `json:"tagline"`
	PrimaryColor string `json:"primary_color"`
	AccentColor  string `json:"accent_color"`
	LogoDataURI  string `json:"logo_data_uri,omitempty"`
}

var defaultBranding = brandingResponse{
	AppName:      "IDUNA Pro",
	PrimaryColor: "#3fa9dc",
	AccentColor:  "#f5a623",
}

func (h *BrandingHandler) Get(w http.ResponseWriter, r *http.Request) {
	if h.DB == nil {
		writeJSON(w, http.StatusOK, defaultBranding)
		return
	}
	var b brandingResponse
	var logo sql.NullString
	err := h.DB.QueryRowContext(r.Context(),
		`SELECT app_name, tagline, primary_color, accent_color, logo_data_uri FROM branding_settings WHERE id = 1`,
	).Scan(&b.AppName, &b.Tagline, &b.PrimaryColor, &b.AccentColor, &logo)
	if err == sql.ErrNoRows {
		writeJSON(w, http.StatusOK, defaultBranding)
		return
	}
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if logo.Valid {
		b.LogoDataURI = logo.String
	}
	writeJSON(w, http.StatusOK, b)
}

type putBrandingRequest struct {
	AppName      string `json:"app_name"`
	Tagline      string `json:"tagline"`
	PrimaryColor string `json:"primary_color"`
	AccentColor  string `json:"accent_color"`
	LogoDataURI  string `json:"logo_data_uri"`
}

func (h *BrandingHandler) Put(w http.ResponseWriter, r *http.Request) {
	if h.DB == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "branding not available"})
		return
	}
	var req putBrandingRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON"})
		return
	}
	req.AppName = strings.TrimSpace(req.AppName)
	if req.AppName == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "app_name is required"})
		return
	}
	if req.PrimaryColor == "" {
		req.PrimaryColor = defaultBranding.PrimaryColor
	}
	if req.AccentColor == "" {
		req.AccentColor = defaultBranding.AccentColor
	}
	_, err := h.DB.ExecContext(r.Context(), `
		INSERT INTO branding_settings (id, app_name, tagline, primary_color, accent_color, logo_data_uri, updated_at)
		VALUES (1, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
		ON CONFLICT(id) DO UPDATE SET
			app_name = excluded.app_name,
			tagline = excluded.tagline,
			primary_color = excluded.primary_color,
			accent_color = excluded.accent_color,
			logo_data_uri = excluded.logo_data_uri,
			updated_at = CURRENT_TIMESTAMP
	`, req.AppName, req.Tagline, req.PrimaryColor, req.AccentColor, nullableString(req.LogoDataURI))
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, brandingResponse{
		AppName:      req.AppName,
		Tagline:      req.Tagline,
		PrimaryColor: req.PrimaryColor,
		AccentColor:  req.AccentColor,
		LogoDataURI:  req.LogoDataURI,
	})
}

func nullableString(s string) sql.NullString {
	if s == "" {
		return sql.NullString{}
	}
	return sql.NullString{String: s, Valid: true}
}
