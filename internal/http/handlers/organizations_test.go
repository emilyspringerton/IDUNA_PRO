package handlers_test

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	_ "modernc.org/sqlite"

	"idunapro/internal/auth/jwt"
	"idunapro/internal/http/handlers"
	"idunapro/internal/http/middleware"
)

// CP-HIPAA-3: real, minimal admin tooling for the organizations/cluster-trust model -- create an
// organization, list them, and (re)assign which cluster one belongs to.

func newTestOrganizationsHandler(t *testing.T, keys *jwt.Keys) (http.Handler, *sql.DB) {
	t.Helper()
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	if _, err := db.Exec(`
		CREATE TABLE organizations (
			id         INTEGER PRIMARY KEY AUTOINCREMENT,
			name       VARCHAR(255) NOT NULL,
			cluster_id INTEGER,
			created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
		);
	`); err != nil {
		t.Fatalf("create schema: %v", err)
	}
	h := &handlers.OrganizationsHandler{DB: db}
	return middleware.RequireAuth(keys)(h), db
}

func TestOrganizationsHandler_ForbiddenWithoutUsersAdmin(t *testing.T) {
	keys, _ := jwt.GenerateKeys()
	h, _ := newTestOrganizationsHandler(t, keys)
	token := mailAccountsToken(t, keys, 1, "mail-accounts.provision") // provider, not admin

	req := httptest.NewRequest(http.MethodGet, "/api/v1/organizations", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for a non-admin caller, got %d: %s", rr.Code, rr.Body.String())
	}
}

func TestOrganizationsHandler_CreateListAndReassignCluster(t *testing.T) {
	keys, _ := jwt.GenerateKeys()
	h, _ := newTestOrganizationsHandler(t, keys)
	token := mailAccountsToken(t, keys, 1, "users.admin")

	body, _ := json.Marshal(map[string]any{"name": "Health Clinic"})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/organizations", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusCreated {
		t.Fatalf("create: status = %d, body = %s", rr.Code, rr.Body.String())
	}
	var created map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &created); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	id := int(created["id"].(float64))

	listReq := httptest.NewRequest(http.MethodGet, "/api/v1/organizations", nil)
	listReq.Header.Set("Authorization", "Bearer "+token)
	listRR := httptest.NewRecorder()
	h.ServeHTTP(listRR, listReq)
	if listRR.Code != http.StatusOK {
		t.Fatalf("list: status = %d, body = %s", listRR.Code, listRR.Body.String())
	}
	var orgs []map[string]any
	if err := json.Unmarshal(listRR.Body.Bytes(), &orgs); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(orgs) != 1 || orgs[0]["name"] != "Health Clinic" {
		t.Fatalf("expected exactly the 1 created org in the list, got %+v", orgs)
	}

	clusterBody, _ := json.Marshal(map[string]any{"cluster_id": 100})
	clusterReq := httptest.NewRequest(http.MethodPatch, "/api/v1/organizations/"+itoaTest(id), bytes.NewReader(clusterBody))
	clusterReq.Header.Set("Authorization", "Bearer "+token)
	clusterRR := httptest.NewRecorder()
	h.ServeHTTP(clusterRR, clusterReq)
	if clusterRR.Code != http.StatusOK {
		t.Fatalf("reassign cluster: status = %d, body = %s", clusterRR.Code, clusterRR.Body.String())
	}

	listRR2 := httptest.NewRecorder()
	h.ServeHTTP(listRR2, listReq)
	var orgs2 []map[string]any
	if err := json.Unmarshal(listRR2.Body.Bytes(), &orgs2); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if orgs2[0]["cluster_id"] != float64(100) {
		t.Fatalf("expected cluster_id to be reassigned to 100, got %+v", orgs2[0])
	}
}
