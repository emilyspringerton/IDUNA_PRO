// Ported from IDUNA (kanban card 21312343124, "QR CODE GENERATOR - IDUNA INTEGRATED ALLOW US TO
// UPDATE A URL ON IDUNA BACKEND qr.okemily.com"), then reused here per the founder's own
// real-time follow-up: "in carepyre if there is a resume configured can we generate some
// business card tools powered by the qr code stuff port it to IDUNAPRO."
//
// A dynamic QR code registry: every QR image this generates encodes this server's OWN stable
// redirect URL (BASE_URL + "/q/" + slug), never the real destination directly. That's the entire
// point -- once printed/placed, the QR image itself can never change, but PATCHing target_url
// retargets every already-printed copy instantly, with zero reprinting. Real, first consumer
// here: business_card.go's own UpsertBySlug call, one QR code per user ("card-<uid>") pointing
// at that user's own /card/{uid}.vcf.
//
//	GET    /admin/qr/api/codes            -> list every code (admin)
//	POST   /admin/qr/api/codes            {"slug":"","target_url":"...","label":"..."} -> create
//	                                       (blank slug auto-generates one)
//	PATCH  /admin/qr/api/codes/{slug}     {"target_url":"...","label":"..."} -> retarget in place
//	DELETE /admin/qr/api/codes/{slug}     -> remove
//	GET    /admin/qr/api/codes/{slug}/image.png  -> live-rendered QR PNG (admin preview)
//
//	GET    /q/{slug}          -> 302 to target_url, real hit_count++ (public, no auth)
//	GET    /q/{slug}.png      -> the same PNG, public (no auth)
package handlers

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strings"

	qrcode "github.com/skip2/go-qrcode"

	"idunapro/internal/http/middleware"
)

var validQRSlug = regexp.MustCompile(`^[a-z][a-z0-9-]{1,63}$`)

type qrCode struct {
	ID          int64  `json:"id"`
	Slug        string `json:"slug"`
	TargetURL   string `json:"target_url"`
	Label       string `json:"label"`
	HitCount    int64  `json:"hit_count"`
	CreatedBy   string `json:"created_by"`
	RedirectURL string `json:"redirect_url"`
	ImageURL    string `json:"image_url"`
	CreatedAt   string `json:"created_at"`
	UpdatedAt   string `json:"updated_at"`
}

// QRHandler is the admin CRUD surface (gated by iduna.admin, same as kanban).
type QRHandler struct {
	DB      *sql.DB
	BaseURL string // e.g. https://console.carepyre.org -- used to build redirect_url/image_url
	// and the literal payload encoded into the QR image itself.
}

func (h *QRHandler) redirectURL(slug string) string {
	return strings.TrimRight(h.BaseURL, "/") + "/q/" + slug
}

func (h *QRHandler) imageURL(slug string) string {
	return strings.TrimRight(h.BaseURL, "/") + "/q/" + slug + ".png"
}

func (h *QRHandler) toDTO(id int64, slug, targetURL, label string, hitCount int64, createdBy, createdAt, updatedAt string) qrCode {
	return qrCode{
		ID: id, Slug: slug, TargetURL: targetURL, Label: label, HitCount: hitCount, CreatedBy: createdBy,
		RedirectURL: h.redirectURL(slug), ImageURL: h.imageURL(slug), CreatedAt: createdAt, UpdatedAt: updatedAt,
	}
}

func (h *QRHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if h.DB == nil {
		http.Error(w, "qr codes not available", http.StatusServiceUnavailable)
		return
	}
	w.Header().Set("Cache-Control", "no-store")

	path := strings.TrimPrefix(r.URL.Path, "/admin/qr/api/codes")
	path = strings.Trim(path, "/")

	switch {
	case path == "" && r.Method == http.MethodGet:
		h.list(w, r)
	case path == "" && r.Method == http.MethodPost:
		h.create(w, r)
	case strings.HasSuffix(path, "/image.png") && r.Method == http.MethodGet:
		h.image(w, r, strings.TrimSuffix(path, "/image.png"))
	case r.Method == http.MethodPatch:
		h.update(w, r, path)
	case r.Method == http.MethodDelete:
		h.delete(w, r, path)
	default:
		http.Error(w, "not found", http.StatusNotFound)
	}
}

func (h *QRHandler) list(w http.ResponseWriter, r *http.Request) {
	rows, err := h.DB.QueryContext(r.Context(),
		`SELECT id, slug, target_url, label, hit_count, created_by, created_at, updated_at FROM qr_codes ORDER BY created_at DESC`)
	if err != nil {
		http.Error(w, "db error", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	out := []qrCode{}
	for rows.Next() {
		var id, hitCount int64
		var slug, targetURL, label, createdBy, createdAt, updatedAt string
		if err := rows.Scan(&id, &slug, &targetURL, &label, &hitCount, &createdBy, &createdAt, &updatedAt); err != nil {
			continue
		}
		out = append(out, h.toDTO(id, slug, targetURL, label, hitCount, createdBy, createdAt, updatedAt))
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(out)
}

func validTargetURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return fmt.Errorf("target_url must be a full absolute URL (https://...)")
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return fmt.Errorf("target_url must be http or https")
	}
	return nil
}

// generateQRSlug mints a short random slug -- letter-first per validQRSlug so it never collides
// with a reserved word and stays URL-safe with no encoding concerns.
func generateQRSlug(ctx context.Context, db *sql.DB) (string, error) {
	const alphabet = "abcdefghijklmnopqrstuvwxyz0123456789"
	const maxAttempts = 20
	for i := 0; i < maxAttempts; i++ {
		buf := make([]byte, 7)
		if _, err := rand.Read(buf); err != nil {
			return "", fmt.Errorf("generate slug: %w", err)
		}
		b := make([]byte, 7)
		for j, v := range buf {
			b[j] = alphabet[int(v)%len(alphabet)]
		}
		candidate := "q" + string(b)
		var exists int
		err := db.QueryRowContext(ctx, `SELECT 1 FROM qr_codes WHERE slug = ? LIMIT 1`, candidate).Scan(&exists)
		if err == sql.ErrNoRows {
			return candidate, nil
		} else if err != nil {
			return "", fmt.Errorf("check slug collision: %w", err)
		}
	}
	return "", fmt.Errorf("could not find an unused slug after %d attempts", maxAttempts)
}

func (h *QRHandler) create(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Slug      string `json:"slug"`
		TargetURL string `json:"target_url"`
		Label     string `json:"label"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "invalid JSON", http.StatusBadRequest)
		return
	}
	body.Slug = strings.TrimSpace(strings.ToLower(body.Slug))
	body.TargetURL = strings.TrimSpace(body.TargetURL)
	body.Label = strings.TrimSpace(body.Label)
	if len(body.Label) > 200 {
		body.Label = body.Label[:200]
	}
	if err := validTargetURL(body.TargetURL); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if body.Slug == "" {
		generated, err := generateQRSlug(r.Context(), h.DB)
		if err != nil {
			http.Error(w, "could not generate a slug", http.StatusInternalServerError)
			return
		}
		body.Slug = generated
	} else if !validQRSlug.MatchString(body.Slug) {
		http.Error(w, "slug must be lowercase letters/digits/hyphens, 2-64 chars, starting with a letter", http.StatusBadRequest)
		return
	}

	createdBy := ""
	if claims := middleware.ClaimsFromContext(r.Context()); claims != nil {
		createdBy, _ = claims["sub"].(string)
	}

	res, err := h.DB.ExecContext(r.Context(),
		`INSERT INTO qr_codes (slug, target_url, label, created_by) VALUES (?, ?, ?, ?)`,
		body.Slug, body.TargetURL, body.Label, createdBy)
	if err != nil {
		if strings.Contains(err.Error(), "UNIQUE") {
			http.Error(w, "slug already in use", http.StatusConflict)
			return
		}
		http.Error(w, "db error", http.StatusInternalServerError)
		return
	}
	id, _ := res.LastInsertId()

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(h.toDTO(id, body.Slug, body.TargetURL, body.Label, 0, createdBy, "", ""))
}

func (h *QRHandler) update(w http.ResponseWriter, r *http.Request, slug string) {
	if slug == "" {
		http.Error(w, "slug required", http.StatusBadRequest)
		return
	}
	var body struct {
		TargetURL *string `json:"target_url"`
		Label     *string `json:"label"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "invalid JSON", http.StatusBadRequest)
		return
	}
	if body.TargetURL == nil && body.Label == nil {
		http.Error(w, "nothing to update", http.StatusBadRequest)
		return
	}
	if body.TargetURL != nil {
		trimmed := strings.TrimSpace(*body.TargetURL)
		if err := validTargetURL(trimmed); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		body.TargetURL = &trimmed
		if _, err := h.DB.ExecContext(r.Context(),
			`UPDATE qr_codes SET target_url = ?, updated_at = CURRENT_TIMESTAMP WHERE slug = ?`, *body.TargetURL, slug); err != nil {
			http.Error(w, "db error", http.StatusInternalServerError)
			return
		}
	}
	if body.Label != nil {
		trimmed := strings.TrimSpace(*body.Label)
		if len(trimmed) > 200 {
			trimmed = trimmed[:200]
		}
		if _, err := h.DB.ExecContext(r.Context(),
			`UPDATE qr_codes SET label = ?, updated_at = CURRENT_TIMESTAMP WHERE slug = ?`, trimmed, slug); err != nil {
			http.Error(w, "db error", http.StatusInternalServerError)
			return
		}
	}

	dto, err := h.getDTO(r.Context(), slug)
	if err == sql.ErrNoRows {
		http.Error(w, "qr code not found", http.StatusNotFound)
		return
	} else if err != nil {
		http.Error(w, "db error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(dto)
}

func (h *QRHandler) getDTO(ctx context.Context, slug string) (qrCode, error) {
	var id, hitCount int64
	var targetURL, label, createdBy, createdAt, updatedAt string
	err := h.DB.QueryRowContext(ctx,
		`SELECT id, target_url, label, hit_count, created_by, created_at, updated_at FROM qr_codes WHERE slug = ?`, slug,
	).Scan(&id, &targetURL, &label, &hitCount, &createdBy, &createdAt, &updatedAt)
	if err != nil {
		return qrCode{}, err
	}
	return h.toDTO(id, slug, targetURL, label, hitCount, createdBy, createdAt, updatedAt), nil
}

func (h *QRHandler) delete(w http.ResponseWriter, r *http.Request, slug string) {
	if slug == "" {
		http.Error(w, "slug required", http.StatusBadRequest)
		return
	}
	res, err := h.DB.ExecContext(r.Context(), `DELETE FROM qr_codes WHERE slug = ?`, slug)
	if err != nil {
		http.Error(w, "db error", http.StatusInternalServerError)
		return
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		http.Error(w, "qr code not found", http.StatusNotFound)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *QRHandler) image(w http.ResponseWriter, r *http.Request, slug string) {
	renderQRPNG(w, r.Context(), h.DB, h.redirectURL, slug)
}

// renderQRPNG is shared by the admin preview endpoint (QRHandler.image, authenticated) and the
// public /q/{slug}.png endpoint (QRRedirectHandler.ServeHTTP, unauthenticated) -- one real
// rendering path, not two copies that could drift.
func renderQRPNG(w http.ResponseWriter, ctx context.Context, db *sql.DB, redirectURL func(string) string, slug string) {
	if slug == "" {
		http.Error(w, "slug required", http.StatusBadRequest)
		return
	}
	var exists int
	if err := db.QueryRowContext(ctx, `SELECT 1 FROM qr_codes WHERE slug = ? LIMIT 1`, slug).Scan(&exists); err == sql.ErrNoRows {
		http.Error(w, "qr code not found", http.StatusNotFound)
		return
	} else if err != nil {
		http.Error(w, "db error", http.StatusInternalServerError)
		return
	}
	png, err := qrcode.Encode(redirectURL(slug), qrcode.Medium, 512)
	if err != nil {
		http.Error(w, "could not render qr image", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "image/png")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write(png)
}

// UpsertBySlug is the real, programmatic (non-HTTP) entry point business_card.go uses --
// create-or-retarget a QR code by a caller-chosen deterministic slug (e.g. "card-42"),
// bypassing the admin-cookie-gated HTTP surface above entirely, since the caller here (an
// ordinary community-tools user creating their OWN business card) already passed its own real
// auth (community-tools.access) in a different handler -- this is a plain Go call, not a second
// HTTP round-trip through an admin-only gate that caller could never pass.
func (h *QRHandler) UpsertBySlug(ctx context.Context, slug, targetURL, label, createdBy string) (*qrCode, error) {
	if !validQRSlug.MatchString(slug) {
		return nil, fmt.Errorf("invalid slug %q", slug)
	}
	if err := validTargetURL(targetURL); err != nil {
		return nil, err
	}
	if len(label) > 200 {
		label = label[:200]
	}

	existing, err := h.getDTO(ctx, slug)
	switch {
	case err == sql.ErrNoRows:
		res, err := h.DB.ExecContext(ctx,
			`INSERT INTO qr_codes (slug, target_url, label, created_by) VALUES (?, ?, ?, ?)`,
			slug, targetURL, label, createdBy)
		if err != nil {
			return nil, fmt.Errorf("insert qr code: %w", err)
		}
		id, _ := res.LastInsertId()
		dto := h.toDTO(id, slug, targetURL, label, 0, createdBy, "", "")
		return &dto, nil
	case err != nil:
		return nil, fmt.Errorf("check existing qr code: %w", err)
	default:
		if _, err := h.DB.ExecContext(ctx,
			`UPDATE qr_codes SET target_url = ?, label = ?, updated_at = CURRENT_TIMESTAMP WHERE slug = ?`,
			targetURL, label, slug); err != nil {
			return nil, fmt.Errorf("update qr code: %w", err)
		}
		updated, err := h.getDTO(ctx, slug)
		if err != nil {
			return nil, err
		}
		_ = existing // existing fetched only to detect create-vs-update; its own fields unused beyond that
		return &updated, nil
	}
}

// QRRedirectHandler is the real, public thing a phone camera actually hits -- no auth, mounted
// at /q/{slug} and /q/{slug}.png.
type QRRedirectHandler struct {
	DB      *sql.DB
	BaseURL string
}

func (h *QRRedirectHandler) redirectURL(slug string) string {
	return strings.TrimRight(h.BaseURL, "/") + "/q/" + slug
}

func (h *QRRedirectHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if h.DB == nil {
		http.Error(w, "qr codes not available", http.StatusServiceUnavailable)
		return
	}
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	slug := strings.Trim(strings.TrimPrefix(r.URL.Path, "/q/"), "/")

	if strings.HasSuffix(slug, ".png") {
		renderQRPNG(w, r.Context(), h.DB, h.redirectURL, strings.TrimSuffix(slug, ".png"))
		return
	}

	var targetURL string
	err := h.DB.QueryRowContext(r.Context(), `SELECT target_url FROM qr_codes WHERE slug = ?`, slug).Scan(&targetURL)
	if err == sql.ErrNoRows {
		http.Error(w, "not found", http.StatusNotFound)
		return
	} else if err != nil {
		http.Error(w, "db error", http.StatusInternalServerError)
		return
	}
	go func() {
		_, _ = h.DB.Exec(`UPDATE qr_codes SET hit_count = hit_count + 1 WHERE slug = ?`, slug)
	}()
	http.Redirect(w, r, targetURL, http.StatusFound)
}
