package handlers

import (
	"encoding/json"
	"net/http"
	"strings"
	"time"

	authjwt "idunapro/internal/auth/jwt"
	"idunapro/internal/userlog"

	"golang.org/x/crypto/bcrypt"
)

// LocalAuthHandler handles POST /api/v1/auth/local.
// Accepts email + password, verifies against the local_users projection,
// and returns an ES256 JWT with uid, permissions, and sub=local:{uid}.
//
// Webmaster (uid=0) receives full admin permissions.
// All other local users receive the permissions associated with their status.
type LocalAuthHandler struct {
	Keys     *authjwt.Keys
	Proj     userlog.UserProjector
	Issuer   string
	EventLog userlog.EventLog // optional (S226-03); nil skips event emission entirely
}

type localAuthRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type localAuthResponse struct {
	Token     string `json:"token"`
	ExpiresAt int64  `json:"expires_at"`
	Sub       string `json:"sub"`
	UID       int    `json:"uid"`
}

func (h *LocalAuthHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req localAuthRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid JSON", http.StatusBadRequest)
		return
	}
	req.Email = strings.TrimSpace(strings.ToLower(req.Email))
	if req.Email == "" || req.Password == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "email and password required"})
		return
	}

	user, err := h.Proj.GetByEmail(r.Context(), req.Email)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if user == nil || user.Status == "deleted" || user.Status == "suspended" {
		emitAuthEvent(r.Context(), h.EventLog, "iduna:auth.local.failure", "iduna-auth", map[string]any{
			"email": req.Email,
		})
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid credentials"})
		return
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(req.Password)); err != nil {
		emitAuthEvent(r.Context(), h.EventLog, "iduna:auth.local.failure", "iduna-auth", map[string]any{
			"email": req.Email,
		})
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid credentials"})
		return
	}

	issuer := h.Issuer
	if issuer == "" {
		issuer = "https://iam.farthq.internal"
	}
	exp := time.Now().UTC().Add(8 * time.Hour)
	sub := "local:" + itoa(user.LocalUID)
	claims := map[string]any{
		"sub":         sub,
		"local_uid":   user.LocalUID,
		"email":       user.Email,
		"display_name": user.DisplayName,
		"permissions": localUserPermissions(user),
		"iss":         issuer,
		"aud":         "farthq-ecosystem",
		"exp":         exp.Unix(),
	}
	token, err := authjwt.Sign(h.Keys, claims)
	if err != nil {
		http.Error(w, "failed to issue token", http.StatusInternalServerError)
		return
	}

	emitAuthEvent(r.Context(), h.EventLog, "iduna:auth.local.success", "iduna-auth", map[string]any{
		"local_uid": user.LocalUID,
		"email":     user.Email,
	})
	writeJSON(w, http.StatusOK, localAuthResponse{
		Token:     token,
		ExpiresAt: exp.Unix(),
		Sub:       sub,
		UID:       user.LocalUID,
	})
}

// localUserPermissions returns the permission set for a local user.
// uid=0 (webmaster) gets full admin access.
//
// devportal.access added here 2026-08-28 (founder real-time: "get the
// developer portal working with iduna login instead of just the
// google oauth") -- the devportal permission itself already existed
// (migration 202608250001_devportal_permissions.sql), but the only
// real grant path built for it was the Google-OAuth-backed
// users/user_roles RBAC table, which had zero real rows (nobody had
// ever actually been granted it, Google sign-in being blocked on a
// human-only GCP Console step). local_users' own permission set is
// hardcoded here rather than DB-driven, so this is the real, direct
// way to grant it to the two local accounts that actually exist
// (uid=0 webmaster, and uid=1) without inventing a second, parallel
// grant UI for a one-account, interim need.
func localUserPermissions(u *userlog.LocalUser) []string {
	// CP-SIP-ADMIN-124323 ("admin genesis"): u.IsAdmin is the real, general, DB-backed grant
	// path -- uid=0 (webmaster) still always gets this same set automatically (backward
	// compatible with every deployment before this field existed), but it's no longer the
	// ONLY way in. See the LocalUser.IsAdmin field's own doc comment for how a grant actually
	// happens (idunapro admin-grant <email> for the first one, the real API after that).
	if u.LocalUID == 0 || u.IsAdmin {
		return []string{
			"iduna.admin",
			"iduna.me.read",
			"users.admin",
			"apples.read",
			"apples.write",
			"drive.read",
			"drive.write",
			"subscriptions.admin",
			"devportal.access",
			// kanban.access -- real, found-live gap (2026-09-04, while building `idunapro
			// kanban list`, cruise-queue card 9988): the bearer-token kanban API
			// (main.go's own `RequirePermission("kanban.access")`) had no real grant path
			// for ANY local user at all, webmaster included -- only a Google-OAuth user
			// with a DB role row could ever reach it. Added here for uid=0, matching this
			// function's own established "the two local accounts that actually exist" grant
			// pattern (devportal.access got the same treatment 2026-08-28). Whether
			// non-webmaster local users should also get it is a real, separate,
			// founder-level product question (kanban's own real "human/agent interop"
			// framing suggests yes eventually) -- not decided here.
			"kanban.access",
			// twilio.admin -- CP-SIP-242414/TWILLIO-API-124 ("we can do all of the operations
			// from the carepyre console side... user roles iam etc"). A real, separate
			// permission from users.admin (not folded into it) since Twilio operations are a
			// genuinely distinct capability an admin might not want every users.admin holder to
			// have -- same "the two local accounts that actually exist" grant pattern this
			// function already establishes for devportal.access/kanban.access.
			"twilio.admin",
		}
	}
	return []string{"iduna.me.read", "users.read.self", "devportal.access"}
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	digits := []byte{}
	neg := n < 0
	if neg {
		n = -n
	}
	for n > 0 {
		digits = append([]byte{byte('0' + n%10)}, digits...)
		n /= 10
	}
	if neg {
		digits = append([]byte{'-'}, digits...)
	}
	return string(digits)
}
