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
		"sub":          sub,
		"local_uid":    user.LocalUID,
		"email":        user.Email,
		"display_name": user.DisplayName,
		"permissions":  localUserPermissions(user),
		// org_id -- CP-HIPAA-3: baked into the JWT at login (same "cheap to read on every
		// request" convention local_uid/permissions already establish) so handlers never need a
		// DB round-trip just to know the caller's own organization for cluster-scoping checks.
		"org_id": user.OrgID,
		"iss":    issuer,
		"aud":    "farthq-ecosystem",
		"exp":    exp.Unix(),
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
// CP-HIPAA-2 (founder real-time, 2026-09-07: "the top admins at carepyre can disable admins but
// mid level operator admins cant disable other operator admins etc - but really the providers
// need the provider admin and the provider operators who can provision ... so its like a 3 or 4
// layer model"). The real 4-tier hierarchy:
//
//  1. Top Admin (uid=0 or IsAdmin) -- everything below, PLUS "admins.manage": the one permission
//     that lets a caller modify or disable another admin-tier account (Top or Operator). This is
//     the tier distinction the founder asked for -- Operator Admin gets every OTHER admin
//     capability but never this one.
//  2. Operator Admin (IsOperatorAdmin) -- the exact same practical permission set as Top Admin,
//     minus "admins.manage". Can manage every ordinary/provider-tier user, but users.go's own
//     updateUser/deleteUser refuse any mutation whose TARGET is itself Top or Operator Admin
//     unless the caller holds "admins.manage".
//  3. Provider Admin (IsProviderAdmin) -- provisions mailboxes/SIP accounts like a Provider
//     Operator (mail-accounts.provision, sip-accounts.provision), PLUS "providers.manage": can
//     grant/revoke the Provider Operator role on other users. Granting/revoking Provider Admin
//     itself stays Top-Admin-only (users.go gates is_provider_admin on "admins.manage"), the same
//     caution CP-SIP-ADMIN-124323 already applies to granting admin itself.
//  4. Provider Operator (IsProvider, CP-HIPAA-1) -- provision-only
//     (mail-accounts.provision, sip-accounts.provision), scoped server-side to participants they
//     themselves created.
func localUserPermissions(u *userlog.LocalUser) []string {
	// CP-SIP-ADMIN-124323 ("admin genesis"): u.IsAdmin is the real, general, DB-backed grant
	// path -- uid=0 (webmaster) still always gets this same set automatically (backward
	// compatible with every deployment before this field existed), but it's no longer the
	// ONLY way in. See the LocalUser.IsAdmin field's own doc comment for how a grant actually
	// happens (idunapro admin-grant <email> for the first one, the real API after that).
	if u.LocalUID == 0 || u.IsAdmin {
		return append(operatorAdminPermissions(),
			// admins.manage -- CP-HIPAA-2: the one permission Operator Admin never gets. Gates
			// every mutation (status/password/role-flag change, delete) whose TARGET is itself
			// Top or Operator Admin -- see users.go's own tierGuard.
			"admins.manage",
		)
	}
	if u.IsOperatorAdmin {
		return operatorAdminPermissions()
	}
	base := []string{"iduna.me.read", "users.read.self", "devportal.access"}
	// mail-accounts.provision / sip-accounts.provision -- CP-HIPAA-1/CP-HIPAA-2 ("we can allow
	// providers to create email accounts for participants" / "give the same treatment for
	// sip"). A real, least-privilege grant distinct from the admin tiers above: a provider can
	// provision/manage participant mailboxes and SIP extensions (MailAccountsHandler,
	// SipAccountsHandler) but gets none of users.admin's other console-wide capabilities
	// (kanban, mailing list, Twilio, user management itself).
	if u.IsProviderAdmin {
		base = append(base, "mail-accounts.provision", "sip-accounts.provision",
			// providers.manage -- CP-HIPAA-2: lets a Provider Admin grant/revoke IsProvider
			// (Provider Operator) on other users -- see users.go's own updateUser. Granting
			// Provider ADMIN itself stays admins.manage-gated (Top Admin only), same caution as
			// granting Top/Operator Admin.
			"providers.manage")
	} else if u.IsProvider {
		base = append(base, "mail-accounts.provision", "sip-accounts.provision")
	}
	return base
}

// operatorAdminPermissions is the full admin capability set MINUS admins.manage -- shared by
// both Top Admin (which adds admins.manage on top) and Operator Admin (which never gets it).
func operatorAdminPermissions() []string {
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
		// branding.admin -- CP-WHITELABEL-1 ("it needs to be both white labeled first then
		// made into carepyre"): configures the per-instance app name/tagline/colors/logo
		// (BrandingHandler.Put). Same platform-operator tier as twilio.admin/organizations.go.
		"branding.admin",
		// compliance.recording.manage -- CP-COMPLIANCE-REC-1: record/replace the "this call
		// may be recorded" consent-announcement audio (ComplianceRecordingHandler).
		"compliance.recording.manage",
	}
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
