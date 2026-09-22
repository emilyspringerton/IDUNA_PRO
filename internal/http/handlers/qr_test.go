package handlers_test

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	_ "modernc.org/sqlite"

	"idunapro/internal/auth/jwt"
	"idunapro/internal/http/handlers"
	"idunapro/internal/http/middleware"

	"github.com/google/uuid"
)

func newTestQRDB(t *testing.T) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	_, err = db.Exec(`CREATE TABLE qr_codes (
		id           INTEGER  PRIMARY KEY AUTOINCREMENT,
		slug         VARCHAR(64)   NOT NULL,
		target_url   VARCHAR(2000) NOT NULL,
		label        VARCHAR(200)  NOT NULL DEFAULT '',
		hit_count    INTEGER  NOT NULL DEFAULT 0,
		created_by   VARCHAR(100)  NOT NULL DEFAULT '',
		created_at   DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
		updated_at   DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
	)`)
	if err != nil {
		t.Fatalf("create qr_codes table: %v", err)
	}
	if _, err := db.Exec(`CREATE UNIQUE INDEX idx_qr_codes_slug ON qr_codes(slug)`); err != nil {
		t.Fatalf("create slug index: %v", err)
	}
	return db
}

func qrHandlerWithAuth(keys *jwt.Keys, db *sql.DB, baseURL string) http.Handler {
	h := &handlers.QRHandler{DB: db, BaseURL: baseURL}
	return middleware.RequireAuth(keys)(h)
}

type qrCodeOut struct {
	ID          int64  `json:"id"`
	Slug        string `json:"slug"`
	TargetURL   string `json:"target_url"`
	Label       string `json:"label"`
	HitCount    int64  `json:"hit_count"`
	RedirectURL string `json:"redirect_url"`
	ImageURL    string `json:"image_url"`
}

func postQR(t *testing.T, h http.Handler, token, slug, targetURL, label string) qrCodeOut {
	t.Helper()
	payload := map[string]string{"slug": slug, "target_url": targetURL, "label": label}
	b, _ := json.Marshal(payload)
	req := httptest.NewRequest(http.MethodPost, "/admin/qr/api/codes", bytes.NewReader(b))
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create status = %d, body = %s", rec.Code, rec.Body.String())
	}
	var out qrCodeOut
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode create response: %v", err)
	}
	return out
}

func TestQR_CreateWithExplicitSlug(t *testing.T) {
	keys, _ := jwt.GenerateKeys()
	db := newTestQRDB(t)
	token := makeAgentToken(t, keys, uuid.New().String(), nil)
	h := qrHandlerWithAuth(keys, db, "https://okemily.com")

	out := postQR(t, h, token, "my-flyer", "https://example.com/landing", "Trade show flyer")
	if out.Slug != "my-flyer" {
		t.Fatalf("expected explicit slug preserved, got %q", out.Slug)
	}
	if out.RedirectURL != "https://okemily.com/q/my-flyer" {
		t.Fatalf("unexpected redirect_url: %q", out.RedirectURL)
	}
	if out.ImageURL != "https://okemily.com/q/my-flyer.png" {
		t.Fatalf("unexpected image_url: %q", out.ImageURL)
	}
}

func TestQR_CreateWithBlankSlugAutoGenerates(t *testing.T) {
	keys, _ := jwt.GenerateKeys()
	db := newTestQRDB(t)
	token := makeAgentToken(t, keys, uuid.New().String(), nil)
	h := qrHandlerWithAuth(keys, db, "https://okemily.com")

	out := postQR(t, h, token, "", "https://example.com/landing", "")
	if out.Slug == "" {
		t.Fatal("expected a non-empty auto-generated slug")
	}
	if out.Slug[0] < 'a' || out.Slug[0] > 'z' {
		t.Fatalf("auto-generated slug must start with a lowercase letter, got %q", out.Slug)
	}
}

func TestQR_RejectsInvalidTargetURL(t *testing.T) {
	keys, _ := jwt.GenerateKeys()
	db := newTestQRDB(t)
	token := makeAgentToken(t, keys, uuid.New().String(), nil)
	h := qrHandlerWithAuth(keys, db, "https://okemily.com")

	for _, bad := range []string{"", "not a url", "ftp://example.com/x", "/relative/path"} {
		payload, _ := json.Marshal(map[string]string{"target_url": bad})
		req := httptest.NewRequest(http.MethodPost, "/admin/qr/api/codes", bytes.NewReader(payload))
		req.Header.Set("Authorization", "Bearer "+token)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("target_url %q: status = %d, want 400", bad, rec.Code)
		}
	}
}

func TestQR_RejectsDuplicateSlug(t *testing.T) {
	keys, _ := jwt.GenerateKeys()
	db := newTestQRDB(t)
	token := makeAgentToken(t, keys, uuid.New().String(), nil)
	h := qrHandlerWithAuth(keys, db, "https://okemily.com")

	postQR(t, h, token, "taken", "https://example.com/a", "")
	payload, _ := json.Marshal(map[string]string{"slug": "taken", "target_url": "https://example.com/b"})
	req := httptest.NewRequest(http.MethodPost, "/admin/qr/api/codes", bytes.NewReader(payload))
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusConflict {
		t.Fatalf("status = %d, want 409 for a duplicate slug", rec.Code)
	}
}

// TestQR_UpdateRetargetsWithoutChangingSlug -- the entire real point of this feature: PATCHing
// target_url must change where the SAME slug (and therefore the same already-printed QR image)
// points, not create a new one.
func TestQR_UpdateRetargetsWithoutChangingSlug(t *testing.T) {
	keys, _ := jwt.GenerateKeys()
	db := newTestQRDB(t)
	token := makeAgentToken(t, keys, uuid.New().String(), nil)
	h := qrHandlerWithAuth(keys, db, "https://okemily.com")

	created := postQR(t, h, token, "retarget-me", "https://example.com/old", "")

	payload, _ := json.Marshal(map[string]string{"target_url": "https://example.com/new"})
	req := httptest.NewRequest(http.MethodPatch, "/admin/qr/api/codes/retarget-me", bytes.NewReader(payload))
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("update status = %d, body = %s", rec.Code, rec.Body.String())
	}
	var out qrCodeOut
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode update response: %v", err)
	}
	if out.Slug != created.Slug {
		t.Fatalf("slug must not change on update, got %q want %q", out.Slug, created.Slug)
	}
	if out.TargetURL != "https://example.com/new" {
		t.Fatalf("target_url not retargeted, got %q", out.TargetURL)
	}
}

func TestQR_DeleteRemovesCode(t *testing.T) {
	keys, _ := jwt.GenerateKeys()
	db := newTestQRDB(t)
	token := makeAgentToken(t, keys, uuid.New().String(), nil)
	h := qrHandlerWithAuth(keys, db, "https://okemily.com")

	postQR(t, h, token, "to-delete", "https://example.com/x", "")

	req := httptest.NewRequest(http.MethodDelete, "/admin/qr/api/codes/to-delete", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("delete status = %d", rec.Code)
	}

	listReq := httptest.NewRequest(http.MethodGet, "/admin/qr/api/codes", nil)
	listReq.Header.Set("Authorization", "Bearer "+token)
	listRec := httptest.NewRecorder()
	h.ServeHTTP(listRec, listReq)
	var codes []qrCodeOut
	_ = json.Unmarshal(listRec.Body.Bytes(), &codes)
	for _, c := range codes {
		if c.Slug == "to-delete" {
			t.Fatal("deleted slug still present in list")
		}
	}
}

func TestQR_AdminImageEndpointReturnsPNG(t *testing.T) {
	keys, _ := jwt.GenerateKeys()
	db := newTestQRDB(t)
	token := makeAgentToken(t, keys, uuid.New().String(), nil)
	h := qrHandlerWithAuth(keys, db, "https://okemily.com")

	postQR(t, h, token, "image-check", "https://example.com/x", "")

	req := httptest.NewRequest(http.MethodGet, "/admin/qr/api/codes/image-check/image.png", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("image status = %d, body = %s", rec.Code, rec.Body.String())
	}
	if ct := rec.Header().Get("Content-Type"); ct != "image/png" {
		t.Fatalf("expected image/png, got %q", ct)
	}
	if !bytes.HasPrefix(rec.Body.Bytes(), []byte("\x89PNG\r\n\x1a\n")) {
		t.Fatal("response body is not a real PNG (missing PNG magic bytes)")
	}
}

func TestQRRedirect_RealRedirectAndHitCount(t *testing.T) {
	keys, _ := jwt.GenerateKeys()
	db := newTestQRDB(t)
	token := makeAgentToken(t, keys, uuid.New().String(), nil)
	adminH := qrHandlerWithAuth(keys, db, "https://okemily.com")
	postQR(t, adminH, token, "redirect-me", "https://example.com/final-destination", "")

	redirectH := &handlers.QRRedirectHandler{DB: db, BaseURL: "https://okemily.com"}

	req := httptest.NewRequest(http.MethodGet, "/q/redirect-me", nil)
	rec := httptest.NewRecorder()
	redirectH.ServeHTTP(rec, req)
	if rec.Code != http.StatusFound {
		t.Fatalf("redirect status = %d, want 302", rec.Code)
	}
	if loc := rec.Header().Get("Location"); loc != "https://example.com/final-destination" {
		t.Fatalf("unexpected Location: %q", loc)
	}

	// hit_count increments fire-and-forget in a goroutine -- poll briefly for it rather than
	// asserting instantly, matching how the handler itself is documented to behave.
	var hitCount int64
	for i := 0; i < 50; i++ {
		_ = db.QueryRow(`SELECT hit_count FROM qr_codes WHERE slug = 'redirect-me'`).Scan(&hitCount)
		if hitCount > 0 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if hitCount != 1 {
		t.Fatalf("expected hit_count = 1 after one redirect, got %d", hitCount)
	}
}

func TestQRRedirect_UnknownSlugIs404(t *testing.T) {
	db := newTestQRDB(t)
	redirectH := &handlers.QRRedirectHandler{DB: db, BaseURL: "https://okemily.com"}

	req := httptest.NewRequest(http.MethodGet, "/q/does-not-exist", nil)
	rec := httptest.NewRecorder()
	redirectH.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", rec.Code)
	}
}

func TestQRRedirect_PublicPNGEndpoint(t *testing.T) {
	keys, _ := jwt.GenerateKeys()
	db := newTestQRDB(t)
	token := makeAgentToken(t, keys, uuid.New().String(), nil)
	adminH := qrHandlerWithAuth(keys, db, "https://okemily.com")
	postQR(t, adminH, token, "public-png", "https://example.com/x", "")

	redirectH := &handlers.QRRedirectHandler{DB: db, BaseURL: "https://okemily.com"}
	req := httptest.NewRequest(http.MethodGet, "/q/public-png.png", nil)
	rec := httptest.NewRecorder()
	redirectH.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Header().Get("Content-Type"), "image/png") {
		t.Fatalf("expected image/png, got %q", rec.Header().Get("Content-Type"))
	}
}

func TestQR_RequiresAuth(t *testing.T) {
	keys, _ := jwt.GenerateKeys()
	db := newTestQRDB(t)
	h := middleware.RequireAuth(keys)(&handlers.QRHandler{DB: db, BaseURL: "https://okemily.com"})

	req := httptest.NewRequest(http.MethodGet, "/admin/qr/api/codes", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401 with no token", rec.Code)
	}
}
