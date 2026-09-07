package handlers

import (
	"database/sql"
	"io"
	"net/http"
)

// ComplianceRecordingHandler stores the single, per-instance "this call may be recorded"
// consent-announcement audio (CP-COMPLIANCE-REC-1) -- closes the real, named gap CAREPYRE-9311
// left open ("the announcement .wav doesn't exist in this repo yet... Playback fails silently
// until it's added"). Recording it is now self-service from the console instead of needing an
// engineer to hand-produce an audio file: an admin uses the browser's own microphone
// (MediaRecorder) to record the announcement, or uploads an existing file, and it's stored here.
//
// Real, honest, deliberately-not-automatic remaining step: getting this into the live Asterisk
// box requires converting to a telephony-ready format (8kHz mono) and copying into its sounds
// directory -- a separate sudo-queue script (see CarePyre/sudo-queue's own compliance-recording
// deploy script), since it touches the live PBX. This handler's job is just making the audio
// exist and be retrievable in the first place, not wiring it into the dialplan.
//
// Both routes are compliance.recording.manage-gated (granted to Top/Operator Admin, same
// "internal platform-operator tooling" tier organizations.go and twilio.admin already use).
type ComplianceRecordingHandler struct {
	DB *sql.DB
}

func (h *ComplianceRecordingHandler) Get(w http.ResponseWriter, r *http.Request) {
	if h.DB == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "not available"})
		return
	}
	var contentType string
	var data []byte
	err := h.DB.QueryRowContext(r.Context(),
		`SELECT content_type, audio_data FROM compliance_recordings WHERE id = 1`,
	).Scan(&contentType, &data)
	if err == sql.ErrNoRows {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "no compliance recording uploaded yet"})
		return
	}
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", contentType)
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(data)
}

func (h *ComplianceRecordingHandler) Put(w http.ResponseWriter, r *http.Request) {
	if h.DB == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "not available"})
		return
	}
	contentType := r.Header.Get("Content-Type")
	if contentType == "" {
		contentType = "audio/webm"
	}
	data, err := io.ReadAll(io.LimitReader(r.Body, 16*1024*1024))
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "failed to read audio body"})
		return
	}
	if len(data) == 0 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "empty audio body"})
		return
	}
	uploadedBy := operatorUIDFromContext(r)
	_, err = h.DB.ExecContext(r.Context(), `
		INSERT INTO compliance_recordings (id, content_type, audio_data, uploaded_by, updated_at)
		VALUES (1, ?, ?, ?, CURRENT_TIMESTAMP)
		ON CONFLICT(id) DO UPDATE SET
			content_type = excluded.content_type,
			audio_data   = excluded.audio_data,
			uploaded_by  = excluded.uploaded_by,
			updated_at   = CURRENT_TIMESTAMP
	`, contentType, data, uploadedBy)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "bytes": len(data)})
}
