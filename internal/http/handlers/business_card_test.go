package handlers_test

import (
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	_ "modernc.org/sqlite"

	"idunapro/internal/auth/jwt"
	"idunapro/internal/http/handlers"
	"idunapro/internal/http/middleware"
)

func newBusinessCardTestDB(t *testing.T) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	if _, err := db.Exec(`
		CREATE TABLE resumes (
			local_uid  INTEGER PRIMARY KEY,
			data       TEXT NOT NULL DEFAULT '{}',
			targets    TEXT NOT NULL DEFAULT '[]',
			created_at TEXT NOT NULL,
			updated_at TEXT NOT NULL
		);
		CREATE TABLE qr_codes (
			id           INTEGER  PRIMARY KEY AUTOINCREMENT,
			slug         VARCHAR(64)   NOT NULL,
			target_url   VARCHAR(2000) NOT NULL,
			label        VARCHAR(200)  NOT NULL DEFAULT '',
			hit_count    INTEGER  NOT NULL DEFAULT 0,
			created_by   VARCHAR(100)  NOT NULL DEFAULT '',
			created_at   DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
			updated_at   DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
		);
		CREATE UNIQUE INDEX idx_qr_codes_slug ON qr_codes(slug);
	`); err != nil {
		t.Fatalf("create schema: %v", err)
	}
	return db
}

func seedResume(t *testing.T, db *sql.DB, uid int, dataJSON string) {
	t.Helper()
	_, err := db.Exec(`INSERT INTO resumes (local_uid, data, created_at, updated_at) VALUES (?, ?, datetime('now'), datetime('now'))`, uid, dataJSON)
	if err != nil {
		t.Fatalf("seed resume: %v", err)
	}
}

func TestBusinessCard_RequiresConfiguredResume(t *testing.T) {
	keys, _ := jwt.GenerateKeys()
	db := newBusinessCardTestDB(t)
	qrH := &handlers.QRHandler{DB: db, BaseURL: "https://console.carepyre.org"}
	h := middleware.RequireAuth(keys)(&handlers.BusinessCardHandler{DB: db, QR: qrH, PublicBaseURL: "https://console.carepyre.org"})

	token := communityToolsToken(t, keys, 1, "community-tools.access")
	req := httptest.NewRequest(http.MethodPost, "/api/v1/community-tools/business-card", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusConflict {
		t.Fatalf("status = %d, want 409 for no resume configured, body=%s", rec.Code, rec.Body.String())
	}
}

func TestBusinessCard_CreatesAndRetargetsQRCode(t *testing.T) {
	keys, _ := jwt.GenerateKeys()
	db := newBusinessCardTestDB(t)
	seedResume(t, db, 1, `{"basics":{"name":"Ada Lovelace","email":"ada@example.com","phone":"+15551234567","url":"https://example.com"}}`)
	qrH := &handlers.QRHandler{DB: db, BaseURL: "https://console.carepyre.org"}
	h := middleware.RequireAuth(keys)(&handlers.BusinessCardHandler{DB: db, QR: qrH, PublicBaseURL: "https://console.carepyre.org"})

	token := communityToolsToken(t, keys, 1, "community-tools.access")
	req := httptest.NewRequest(http.MethodPost, "/api/v1/community-tools/business-card", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body=%s", rec.Code, rec.Body.String())
	}
	var first map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &first); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if first["slug"] != "card-1" {
		t.Fatalf("expected deterministic slug card-1, got %v", first["slug"])
	}
	if first["target_url"] != "https://console.carepyre.org/card/1.vcf" {
		t.Fatalf("unexpected target_url: %v", first["target_url"])
	}

	// A second call must UPSERT the same slug (retarget, never a second/duplicate row) -- the
	// entire real point of a deterministic per-user slug.
	rec2 := httptest.NewRecorder()
	req2 := httptest.NewRequest(http.MethodPost, "/api/v1/community-tools/business-card", nil)
	req2.Header.Set("Authorization", "Bearer "+token)
	h.ServeHTTP(rec2, req2)
	if rec2.Code != http.StatusOK {
		t.Fatalf("second call status = %d", rec2.Code)
	}
	var count int
	if err := db.QueryRow(`SELECT COUNT(*) FROM qr_codes WHERE slug = 'card-1'`).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("expected exactly one qr_codes row for card-1, got %d", count)
	}
}

func TestBusinessCard_RequiresAuth(t *testing.T) {
	keys, _ := jwt.GenerateKeys()
	db := newBusinessCardTestDB(t)
	qrH := &handlers.QRHandler{DB: db, BaseURL: "https://console.carepyre.org"}
	h := middleware.RequireAuth(keys)(&handlers.BusinessCardHandler{DB: db, QR: qrH, PublicBaseURL: "https://console.carepyre.org"})

	req := httptest.NewRequest(http.MethodPost, "/api/v1/community-tools/business-card", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401 with no token", rec.Code)
	}
}

func TestBusinessCardVCard_RealVCardContent(t *testing.T) {
	db := newBusinessCardTestDB(t)
	seedResume(t, db, 1, `{"basics":{"name":"Ada Lovelace","email":"ada@example.com","phone":"+15551234567","url":"https://example.com","label":"Engineer"}}`)
	h := &handlers.BusinessCardVCardHandler{DB: db}

	req := httptest.NewRequest(http.MethodGet, "/card/1.vcf", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body=%s", rec.Code, rec.Body.String())
	}
	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/vcard") {
		t.Fatalf("unexpected Content-Type: %q", ct)
	}
	body := rec.Body.String()
	for _, want := range []string{
		"BEGIN:VCARD", "VERSION:3.0",
		"FN:Ada Lovelace", "N:Lovelace;Ada;;;",
		"EMAIL;TYPE=INTERNET:ada@example.com",
		"TEL;TYPE=CELL:+15551234567",
		"URL:https://example.com",
		"TITLE:Engineer",
		"END:VCARD",
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("expected vCard to contain %q, got:\n%s", want, body)
		}
	}
}

func TestBusinessCardVCard_UnconfiguredResumeIs404(t *testing.T) {
	db := newBusinessCardTestDB(t)
	h := &handlers.BusinessCardVCardHandler{DB: db}

	req := httptest.NewRequest(http.MethodGet, "/card/999.vcf", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404 for a user with no resume configured", rec.Code)
	}
}

func TestBusinessCardVCard_EscapesSpecialCharacters(t *testing.T) {
	db := newBusinessCardTestDB(t)
	// A name containing a comma and semicolon -- real vCard structured-field metacharacters
	// that must be escaped, not left to break parsing.
	seedResume(t, db, 1, `{"basics":{"name":"Smith, Jr.; Bob"}}`)
	h := &handlers.BusinessCardVCardHandler{DB: db}

	req := httptest.NewRequest(http.MethodGet, "/card/1.vcf", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, `FN:Smith\, Jr.\; Bob`) {
		t.Fatalf("expected escaped FN, got:\n%s", body)
	}
}
