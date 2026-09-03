package handlers

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	authjwt "idunapro/internal/auth/jwt"
	"idunapro/internal/userlog"

	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

// RegisterHandler handles POST /api/v1/auth/register.
// Open registration: email + password + optional display_name.
// Creates local user, sets free_trial GFD tier, returns same JWT shape as LocalAuthHandler.
type RegisterHandler struct {
	Keys   *authjwt.Keys
	Log    userlog.EventLog
	Proj   userlog.UserProjector
	Store  GFDRegistrationStore
	Issuer string
}

// GFDRegistrationStore is the subset of IAMStore needed by RegisterHandler.
type GFDRegistrationStore interface {
	SetGFDUserTier(ctx context.Context, userID, tierID string) error
}

type gfdRegisterRequest struct {
	Email       string `json:"email"`
	Password    string `json:"password"`
	DisplayName string `json:"display_name"`
}

type registerResponse struct {
	Token       string `json:"token"`
	ExpiresAt   int64  `json:"expires_at"`
	Sub         string `json:"sub"`
	UID         int    `json:"uid"`
	DisplayName string `json:"display_name"`
	Tier        string `json:"tier"`
}

func (h *RegisterHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req gfdRegisterRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON"})
		return
	}
	req.Email = strings.TrimSpace(strings.ToLower(req.Email))
	req.DisplayName = strings.TrimSpace(req.DisplayName)

	if req.Email == "" || req.Password == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "email and password required"})
		return
	}
	if len(req.Password) < 8 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "password must be at least 8 characters"})
		return
	}
	if req.DisplayName == "" {
		parts := strings.SplitN(req.Email, "@", 2)
		req.DisplayName = parts[0]
	}

	ctx := r.Context()

	// Reject duplicate emails.
	existing, err := h.Proj.GetByEmail(ctx, req.Email)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if existing != nil {
		writeJSON(w, http.StatusConflict, map[string]string{"error": "email already registered"})
		return
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	uid, err := h.Proj.NextUID(ctx)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	payload, _ := json.Marshal(userlog.UserCreatedData{
		LocalUID:     uid,
		Email:        req.Email,
		DisplayName:  req.DisplayName,
		PasswordHash: string(hash),
	})
	ev := userlog.Event{
		ID:          uuid.New().String(),
		Type:        userlog.EventUserCreated,
		Source:      "idunapro/register",
		OccurredAt:  time.Now().UTC(),
		OperatorUID: 0,
		Data:        json.RawMessage(payload),
	}
	records, err := h.Log.Append(ctx, ev)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if err := h.Proj.Apply(ctx, records[0]); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if err := h.Proj.AdvanceCursor(ctx, records[0].Sequence); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	// Set free_trial GFD tier (best-effort; non-fatal if not configured).
	_ = h.Store.SetGFDUserTier(ctx, itoa(uid), "free_trial")

	issuer := h.Issuer
	if issuer == "" {
		issuer = "https://iam.farthq.internal"
	}
	exp := time.Now().UTC().Add(8 * time.Hour)
	sub := "local:" + itoa(uid)
	claims := map[string]any{
		"sub":          sub,
		"local_uid":    uid,
		"email":        req.Email,
		"display_name": req.DisplayName,
		"permissions":  []string{"iduna.me.read", "users.read.self"},
		"iss":          issuer,
		"aud":          "farthq-ecosystem",
		"exp":          exp.Unix(),
	}
	token, err := authjwt.Sign(h.Keys, claims)
	if err != nil {
		http.Error(w, "failed to issue token", http.StatusInternalServerError)
		return
	}

	writeJSON(w, http.StatusCreated, registerResponse{
		Token:       token,
		ExpiresAt:   exp.Unix(),
		Sub:         sub,
		UID:         uid,
		DisplayName: req.DisplayName,
		Tier:        "free_trial",
	})
}
