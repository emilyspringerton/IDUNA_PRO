package handlers_test

import (
	"bytes"
	"database/sql"
	"net/http"
	"net/http/httptest"
	"testing"

	_ "modernc.org/sqlite"

	"idunapro/internal/auth/jwt"
	"idunapro/internal/http/handlers"
	"idunapro/internal/http/middleware"
)

// CP-COMPLIANCE-REC-1: recording/replacing the "this call may be recorded" consent audio.

func newTestComplianceRecordingHandler(t *testing.T, keys *jwt.Keys) http.Handler {
	t.Helper()
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	if _, err := db.Exec(`
		CREATE TABLE compliance_recordings (
			id           INTEGER PRIMARY KEY CHECK (id = 1),
			content_type VARCHAR(64) NOT NULL,
			audio_data   BLOB NOT NULL,
			uploaded_by  INTEGER NOT NULL,
			updated_at   DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
		);
	`); err != nil {
		t.Fatalf("create schema: %v", err)
	}
	h := &handlers.ComplianceRecordingHandler{DB: db}
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			h.Get(w, r)
		case http.MethodPut:
			h.Put(w, r)
		}
	})
	return middleware.RequireAuth(keys)(middleware.RequirePermission("compliance.recording.manage")(inner))
}

func TestComplianceRecording_GetNotFoundWhenUnconfigured(t *testing.T) {
	keys := mustKeys(t)
	h := newTestComplianceRecordingHandler(t, keys)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/compliance/recording", nil)
	req.Header.Set("Authorization", "Bearer "+tokenWithPerms(t, keys, 1, "compliance.recording.manage"))
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusNotFound {
		t.Fatalf("expected 404 before any upload, got %d: %s", rr.Code, rr.Body.String())
	}
}

func TestComplianceRecording_RequiresPermission(t *testing.T) {
	keys := mustKeys(t)
	h := newTestComplianceRecordingHandler(t, keys)
	req := httptest.NewRequest(http.MethodPut, "/api/v1/compliance/recording", bytes.NewReader([]byte("fake-audio-bytes")))
	req.Header.Set("Authorization", "Bearer "+tokenWithPerms(t, keys, 1)) // no permission
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d: %s", rr.Code, rr.Body.String())
	}
}

func TestComplianceRecording_UploadAndFetchRoundtrip(t *testing.T) {
	keys := mustKeys(t)
	h := newTestComplianceRecordingHandler(t, keys)
	token := tokenWithPerms(t, keys, 7, "compliance.recording.manage")

	audio := []byte("fake-webm-opus-audio-bytes")
	putReq := httptest.NewRequest(http.MethodPut, "/api/v1/compliance/recording", bytes.NewReader(audio))
	putReq.Header.Set("Authorization", "Bearer "+token)
	putReq.Header.Set("Content-Type", "audio/webm;codecs=opus")
	putRR := httptest.NewRecorder()
	h.ServeHTTP(putRR, putReq)
	if putRR.Code != http.StatusOK {
		t.Fatalf("put: status = %d, body = %s", putRR.Code, putRR.Body.String())
	}

	getReq := httptest.NewRequest(http.MethodGet, "/api/v1/compliance/recording", nil)
	getReq.Header.Set("Authorization", "Bearer "+token)
	getRR := httptest.NewRecorder()
	h.ServeHTTP(getRR, getReq)
	if getRR.Code != http.StatusOK {
		t.Fatalf("get: status = %d, body = %s", getRR.Code, getRR.Body.String())
	}
	if getRR.Header().Get("Content-Type") != "audio/webm;codecs=opus" {
		t.Fatalf("expected the stored content-type to roundtrip, got %q", getRR.Header().Get("Content-Type"))
	}
	if !bytes.Equal(getRR.Body.Bytes(), audio) {
		t.Fatalf("expected the exact uploaded bytes back, got %d bytes", getRR.Body.Len())
	}

	// A second upload REPLACES the single active recording (id=1 upsert), not appends.
	audio2 := []byte("a-newer-recording-replacing-the-first")
	putReq2 := httptest.NewRequest(http.MethodPut, "/api/v1/compliance/recording", bytes.NewReader(audio2))
	putReq2.Header.Set("Authorization", "Bearer "+token)
	putRR2 := httptest.NewRecorder()
	h.ServeHTTP(putRR2, putReq2)
	if putRR2.Code != http.StatusOK {
		t.Fatalf("second put: status = %d, body = %s", putRR2.Code, putRR2.Body.String())
	}
	getRR2 := httptest.NewRecorder()
	h.ServeHTTP(getRR2, getReq)
	if !bytes.Equal(getRR2.Body.Bytes(), audio2) {
		t.Fatalf("expected the replaced recording, got %d bytes", getRR2.Body.Len())
	}
}
