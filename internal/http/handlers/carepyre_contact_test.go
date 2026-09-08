package handlers_test

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	_ "modernc.org/sqlite"

	"idunapro/internal/auth/jwt"
	"idunapro/internal/http/handlers"
	"idunapro/internal/http/middleware"
)

func newTestCarepyreContactDB(t *testing.T) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	_, err = db.Exec(`CREATE TABLE carepyre_contact_submissions (
		id          INTEGER PRIMARY KEY AUTOINCREMENT,
		name        VARCHAR(120) NOT NULL,
		email       VARCHAR(254) NOT NULL,
		message     VARCHAR(4000) NOT NULL,
		status      VARCHAR(32) NOT NULL DEFAULT 'new',
		created_at  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
		resolved_at DATETIME
	)`)
	if err != nil {
		t.Fatalf("create table: %v", err)
	}
	return db
}

func carepyreContactToken(t *testing.T, keys *jwt.Keys, perms ...string) string {
	t.Helper()
	claims := map[string]any{
		"sub": "local:1",
		"exp": time.Now().Add(time.Hour).Unix(),
	}
	if len(perms) > 0 {
		claims["permissions"] = perms
	}
	tok, err := jwt.Sign(keys, claims)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	return tok
}

func TestCarePyreContact_PublicSubmit(t *testing.T) {
	db := newTestCarepyreContactDB(t)
	h := &handlers.CarePyreContactHandler{DB: db, AllowOrigin: []string{"https://carepyre.org"}}
	mux := http.NewServeMux()
	h.RegisterPublic(mux)

	body, _ := json.Marshal(map[string]string{"name": "Alex", "email": "alex@example.com", "message": "Need help."})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/carepyre/contact", bytes.NewReader(body))
	req.Header.Set("Origin", "https://carepyre.org")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	var n int
	if err := db.QueryRow(`SELECT COUNT(*) FROM carepyre_contact_submissions`).Scan(&n); err != nil {
		t.Fatalf("count: %v", err)
	}
	if n != 1 {
		t.Fatalf("expected 1 row, got %d", n)
	}
}

func TestCarePyreContact_PublicSubmit_RejectsBadEmail(t *testing.T) {
	db := newTestCarepyreContactDB(t)
	h := &handlers.CarePyreContactHandler{DB: db}
	mux := http.NewServeMux()
	h.RegisterPublic(mux)

	body, _ := json.Marshal(map[string]string{"name": "Alex", "email": "not-an-email", "message": "hi"})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/carepyre/contact", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400, body = %s", rec.Code, rec.Body.String())
	}
}

func TestCarePyreContact_AdminList_RequiresContactsManage(t *testing.T) {
	keys, err := jwt.GenerateKeys()
	if err != nil {
		t.Fatalf("generate keys: %v", err)
	}
	db := newTestCarepyreContactDB(t)
	if _, err := db.Exec(`INSERT INTO carepyre_contact_submissions (name, email, message) VALUES ('Alex', 'alex@example.com', 'hi')`); err != nil {
		t.Fatalf("seed: %v", err)
	}
	h := &handlers.CarePyreContactHandler{DB: db}
	protected := middleware.RequireAuth(keys)(h)

	// No contacts.manage permission -> forbidden.
	req := httptest.NewRequest(http.MethodGet, "/api/v1/carepyre/contact-submissions", nil)
	req.Header.Set("Authorization", "Bearer "+carepyreContactToken(t, keys))
	rec := httptest.NewRecorder()
	protected.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("no-permission status = %d, want 403, body = %s", rec.Code, rec.Body.String())
	}

	// With contacts.manage -> real list.
	req2 := httptest.NewRequest(http.MethodGet, "/api/v1/carepyre/contact-submissions", nil)
	req2.Header.Set("Authorization", "Bearer "+carepyreContactToken(t, keys, "contacts.manage"))
	rec2 := httptest.NewRecorder()
	protected.ServeHTTP(rec2, req2)
	if rec2.Code != http.StatusOK {
		t.Fatalf("with-permission status = %d, body = %s", rec2.Code, rec2.Body.String())
	}
	var out struct {
		Submissions []struct {
			ID    int64  `json:"id"`
			Email string `json:"email"`
		} `json:"submissions"`
	}
	if err := json.Unmarshal(rec2.Body.Bytes(), &out); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(out.Submissions) != 1 || out.Submissions[0].Email != "alex@example.com" {
		t.Fatalf("unexpected submissions: %+v", out.Submissions)
	}
}

func TestCarePyreContact_ResolveAndPurgeEligibility(t *testing.T) {
	keys, err := jwt.GenerateKeys()
	if err != nil {
		t.Fatalf("generate keys: %v", err)
	}
	db := newTestCarepyreContactDB(t)
	res, err := db.Exec(`INSERT INTO carepyre_contact_submissions (name, email, message) VALUES ('Alex', 'alex@example.com', 'hi')`)
	if err != nil {
		t.Fatalf("seed: %v", err)
	}
	id, _ := res.LastInsertId()

	h := &handlers.CarePyreContactHandler{DB: db}
	protected := middleware.RequireAuth(keys)(h)
	token := carepyreContactToken(t, keys, "contacts.manage")

	body, _ := json.Marshal(map[string]string{"status": "resolved"})
	req := httptest.NewRequest(http.MethodPatch, "/api/v1/carepyre/contact-submissions/"+itoa(id), bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	protected.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("resolve status = %d, body = %s", rec.Code, rec.Body.String())
	}

	var status string
	var resolvedAt sql.NullString
	if err := db.QueryRow(`SELECT status, resolved_at FROM carepyre_contact_submissions WHERE id = ?`, id).Scan(&status, &resolvedAt); err != nil {
		t.Fatalf("query: %v", err)
	}
	if status != "resolved" || !resolvedAt.Valid {
		t.Fatalf("expected resolved with resolved_at set, got status=%q resolved_at.Valid=%v", status, resolvedAt.Valid)
	}

	// DELETE honors an immediate deletion request rather than waiting for the purge tool.
	delReq := httptest.NewRequest(http.MethodDelete, "/api/v1/carepyre/contact-submissions/"+itoa(id), nil)
	delReq.Header.Set("Authorization", "Bearer "+token)
	delRec := httptest.NewRecorder()
	protected.ServeHTTP(delRec, delReq)
	if delRec.Code != http.StatusOK {
		t.Fatalf("delete status = %d, body = %s", delRec.Code, delRec.Body.String())
	}
	var n int
	if err := db.QueryRow(`SELECT COUNT(*) FROM carepyre_contact_submissions`).Scan(&n); err != nil {
		t.Fatalf("count: %v", err)
	}
	if n != 0 {
		t.Fatalf("expected 0 rows after delete, got %d", n)
	}
}

func itoa(n int64) string {
	return fmt.Sprintf("%d", n)
}
