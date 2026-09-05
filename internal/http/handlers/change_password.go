package handlers

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"

	"idunapro/internal/userlog"
)

// ChangePasswordHandler handles POST /api/v1/auth/change-password -- the real, missing
// self-service piece kanban CP-SIP-1244543543 named directly ("users of the platform to reset
// their password"). Real, found-live gap: PATCH /api/v1/users/{uid} already supports changing a
// password, but that route requires the users.admin permission with no self-access carve-out
// (unlike GET /api/v1/users/{uid}, which already allows sub=local:{uid}) -- a regular local user
// (localUserPermissions' own non-uid-0 tier: iduna.me.read/users.read.self/devportal.access, no
// users.admin) has no real way to change their own password today. This is a real, generic
// product gap in IDUNA_PRO itself, not CarePyre-specific branding -- any "whitelabelable back
// office" deployment needs this.
//
// Real, deliberate v0 scope: a "change my own password" flow (current password + new password),
// not a "forgot password" email-reset flow -- IDUNA_PRO has no outbound-email capability wired
// up yet (a real, separate, named gap), so a self-service reset that doesn't require already
// knowing the old password isn't attempted here.
type ChangePasswordHandler struct {
	Log  userlog.EventLog
	Proj userlog.UserProjector
}

type changePasswordRequest struct {
	CurrentPassword string `json:"current_password"`
	NewPassword     string `json:"new_password"`
}

func (h *ChangePasswordHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	uid := callerLocalUID(r)
	if uid == nil {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "forbidden"})
		return
	}

	var req changePasswordRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON"})
		return
	}
	if len(req.NewPassword) < 8 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "new_password must be at least 8 characters"})
		return
	}

	user, err := h.Proj.GetByUID(r.Context(), *uid)
	if err != nil || user == nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	// Real, honest verification -- never trust the caller's own JWT alone to change their own
	// password; require them to prove they still know the CURRENT one, same real bar
	// LocalAuthHandler's own login check already holds every sign-in to.
	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(req.CurrentPassword)); err != nil {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "current password is incorrect"})
		return
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(req.NewPassword), bcrypt.DefaultCost)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	payload, _ := json.Marshal(userlog.UserPasswordResetData{
		LocalUID:     *uid,
		PasswordHash: string(hash),
	})
	ev := userlog.Event{
		ID:          uuid.New().String(),
		Type:        userlog.EventUserPasswordReset,
		Source:      "idunapro/api",
		OccurredAt:  time.Now().UTC(),
		OperatorUID: *uid,
		Data:        json.RawMessage(payload),
	}
	recs, err := h.Log.Append(r.Context(), ev)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	_ = h.Proj.Apply(r.Context(), recs[0])
	_ = h.Proj.AdvanceCursor(r.Context(), recs[0].Sequence)

	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}
