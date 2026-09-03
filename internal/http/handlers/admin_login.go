package handlers

import (
	"fmt"
	"html/template"
	"net/http"
	"strings"
	"time"

	"idunapro/internal/auth/jwt"
	"idunapro/internal/store"
	"idunapro/internal/userlog"
)

// AdminSessionTTL is the admin session cookie/JWT lifetime. Shared with
// middleware.RequireCookieAuth's sliding-refresh window so the two stay in sync.
const AdminSessionTTL = 8 * time.Hour

// AdminLoginHandler serves /admin/login (GET + POST) and /admin/logout.
// These routes are public (no auth middleware) so the browser can reach them.
type AdminLoginHandler struct {
	Store    store.IAMStore
	Keys     *jwt.Keys
	Issuer   string
	EventLog userlog.EventLog // optional (S226-03); nil skips event emission entirely
}

func (h *AdminLoginHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Path {
	case "/admin/logout":
		h.logout(w, r)
	default:
		h.login(w, r)
	}
}

func (h *AdminLoginHandler) login(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		renderLoginPage(w, map[string]any{"Next": r.URL.Query().Get("next")})
		return
	}
	if r.Method != http.MethodPost {
		http.NotFound(w, r)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}

	agentName := strings.TrimSpace(r.FormValue("agent_name"))
	agentSecret := r.FormValue("agent_secret")
	next := r.FormValue("next")
	if next == "" || !strings.HasPrefix(next, "/admin") {
		next = "/admin"
	}

	agent, err := h.Store.AuthenticateAgent(r.Context(), agentName, agentSecret)
	if err != nil {
		emitAuthEvent(r.Context(), h.EventLog, "iduna:auth.admin_login.failure", "iduna-auth", map[string]any{
			"agent_name": agentName,
			"reason":     "invalid_credentials",
		})
		renderLoginPage(w, map[string]any{
			"Error": "Invalid agent name or secret.",
			"Next":  next,
		})
		return
	}

	hasAdmin := false
	for _, p := range agent.Permissions {
		if p == "iduna.admin" {
			hasAdmin = true
			break
		}
	}
	if !hasAdmin {
		emitAuthEvent(r.Context(), h.EventLog, "iduna:auth.admin_login.failure", "iduna-auth", map[string]any{
			"agent_name": agentName,
			"reason":     "missing_iduna_admin_permission",
		})
		renderLoginPage(w, map[string]any{
			"Error": fmt.Sprintf("Agent %q does not have the iduna.admin permission.", agentName),
			"Next":  next,
		})
		return
	}

	issuer := h.Issuer
	if issuer == "" {
		issuer = "https://iam.farthq.internal"
	}
	exp := time.Now().UTC().Add(AdminSessionTTL)
	claims := map[string]any{
		"sub":         agent.ID,
		"agent_name":  agent.Name,
		"agent_type":  agent.Type,
		"permissions": agent.Permissions,
		"iss":         issuer,
		"aud":         "farthq-ecosystem",
		"exp":         exp.Unix(),
	}
	token, err := jwt.Sign(h.Keys, claims)
	if err != nil {
		http.Error(w, "failed to issue session token", http.StatusInternalServerError)
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name:     "iduna_session",
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   int(AdminSessionTTL.Seconds()),
	})
	emitAuthEvent(r.Context(), h.EventLog, "iduna:auth.admin_login.success", "iduna-auth", map[string]any{
		"agent_id":   agent.ID,
		"agent_name": agent.Name,
	})
	http.Redirect(w, r, next, http.StatusSeeOther)
}

func (h *AdminLoginHandler) logout(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{
		Name:   "iduna_session",
		Value:  "",
		Path:   "/",
		MaxAge: -1,
	})
	http.Redirect(w, r, "/admin/login", http.StatusSeeOther)
}

func renderLoginPage(w http.ResponseWriter, data map[string]any) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := adminLoginPageTmpl.Execute(w, data); err != nil {
		http.Error(w, "template error: "+err.Error(), http.StatusInternalServerError)
	}
}

// adminLoginPageTmpl -- restyled 2026-08-25 to the real IDUNA style guide
// (IDUNA/index.html + IDUNA/styles.css: cream/gold ceremony aesthetic,
// Cormorant Garamond over Spectral), matching the notebook portal's own
// login page (portal.go's portalLoginTmpl) so the two agent/human login
// surfaces read as one system rather than two unrelated designs. Founder:
// "update iduna back office login page similar to your last login page
// redesign use promptoverse assets." Art is real Prompt-o-verse gallery
// output (eye-of-providence-robot -- an oversight/authority motif, fitting
// an admin surface), served as a real static file (main.go's
// /portal/images/ route). Designed via /design first (canvas "IDUNA Back
// Office Login"), then ported here so the live page matches.
var adminLoginPageTmpl = template.Must(template.New("admin-login").Parse(`<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Admin Login — IDUNA Back Office</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Cormorant+Garamond:wght@400;500;600&family=Spectral:wght@400;500&display=swap" rel="stylesheet">
<style>
  :root {
    --bg: #f4f1ea; --bg-soft: #ede7dc; --panel: #ebe4d8; --line-soft: #d2c7b8;
    --gold: #c6a75e; --gold-soft: #bfa062; --gold-highlight: #d6bc7a;
    --text-main: #3a352e; --text-muted: #7a7368; --text-faint: #a8a093; --rose: #b76e79;
  }
  * { box-sizing: border-box; }
  body {
    margin: 0; min-height: 100vh;
    background: radial-gradient(circle at top, color-mix(in srgb, var(--bg) 84%, #fff 16%), var(--bg-soft));
    color: var(--text-main); font-family: "Spectral", Georgia, serif; line-height: 1.45;
  }
  a { color: var(--gold-soft); }
  a:hover { color: var(--gold-highlight); }
  .shell { min-height: 100vh; display: grid; place-items: center; padding: 3.5rem 1.5rem; }
  .frame {
    width: min(460px, 100%);
    border: 1px solid color-mix(in srgb, var(--gold) 60%, var(--line-soft) 40%);
    border-radius: 8px; background: color-mix(in srgb, var(--panel) 92%, white 8%);
    overflow: hidden;
  }
  .art { position: relative; height: 210px; overflow: hidden; }
  .art img { width: 100%; height: 100%; object-fit: cover; display: block; }
  .art::after {
    content: ""; position: absolute; inset: 0;
    background: linear-gradient(to bottom, rgba(20,18,14,0.05) 0%, color-mix(in srgb, var(--panel) 92%, white 8%) 96%);
  }
  .body { padding: 0 2.1rem 2.3rem; text-align: center; }
  .label { letter-spacing: 0.35em; text-transform: uppercase; font-size: 0.66rem; color: var(--text-muted); margin-top: -1.4rem; position: relative; }
  h1 { margin: 0.7rem 0 0; font-family: "Cormorant Garamond", serif; font-weight: 500; font-size: 2.05rem; letter-spacing: 0.01em; }
  .sub { margin: 0.6rem 0 0; color: var(--text-muted); font-size: 0.9rem; }
  .sub code { font-style: italic; }
  .err {
    margin-top: 1.4rem; text-align: left; font-size: 0.85rem;
    padding: 0.75rem 1rem; border-radius: 5px; color: var(--rose);
    background: color-mix(in srgb, var(--panel) 90%, var(--rose) 10%);
    border: 1px solid color-mix(in srgb, var(--rose) 55%, var(--line-soft) 45%);
  }
  .field { margin-top: 1.2rem; text-align: left; }
  .field label {
    display: block; font-size: 0.68rem; letter-spacing: 0.1em; text-transform: uppercase;
    color: var(--text-muted); margin-bottom: 0.4rem;
  }
  .field input {
    width: 100%; padding: 0.72rem 0.9rem;
    border: 1px solid color-mix(in srgb, var(--gold) 68%, var(--line-soft) 32%);
    background: color-mix(in srgb, var(--panel) 97%, white 3%);
    color: var(--text-main); border-radius: 4px; font: inherit; font-size: 0.92rem;
  }
  .field input:focus { outline: none; border-color: var(--gold-highlight); }
  .field input::placeholder { color: var(--text-faint); }
  .submit {
    margin-top: 1.9rem; width: 100%; padding: 0.78rem 1rem;
    border: 1px solid color-mix(in srgb, var(--gold) 80%, #7b6640 20%);
    background: color-mix(in srgb, var(--panel) 88%, #e5dac7 12%);
    color: var(--text-main); border-radius: 5px; font: inherit; font-size: 0.95rem;
    letter-spacing: 0.02em; cursor: pointer;
  }
  .submit:hover { border-color: #c7ac72; }
  .footnote { margin-top: 1.9rem; font-size: 0.76rem; color: var(--text-faint); }
</style>
</head>
<body>
<div class="shell">
  <div class="frame">
    <div class="art"><img src="/portal/images/eye-of-providence-robot.jpg" alt=""></div>
    <div class="body">
      <p class="label">EINHORN_INDUSTRIAL &middot; IDUNA</p>
      <h1>Back Office</h1>
      <p class="sub">Sign in with an agent account that has the <code>iduna.admin</code> permission.</p>
      {{if .Error}}<div class="err">{{.Error}}</div>{{end}}
      <form method="POST" action="/admin/login">
        <input type="hidden" name="next" value="{{.Next}}">
        <div class="field">
          <label for="an">Agent Name</label>
          <input type="text" id="an" name="agent_name" placeholder="EMILY" autocomplete="off" required>
        </div>
        <div class="field">
          <label for="as">Agent Secret</label>
          <input type="password" id="as" name="agent_secret" required>
        </div>
        <button class="submit" type="submit">Sign In</button>
      </form>
      <p class="footnote">Agent credentials only &mdash; this is not the <a href="/portal/login">Developer Portal</a> sign-in.</p>
    </div>
  </div>
</div>
</body>
</html>`))
