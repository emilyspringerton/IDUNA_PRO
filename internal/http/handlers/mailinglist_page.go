package handlers

import (
	"net/http"
)

// MailingListPageHandler serves the S245-04 "consoleify" settings page: view
// subscriber count/sync status, configure the Mailchimp provider (S245-03),
// trigger an export (S245-02) -- the real visible front end for the three
// APIs that shipped ahead of it, mounted alongside the kanban board's own
// admin surface (S243-08). Same real "one handler, two entry points" split
// as kanban: this page + its own /admin/mailing-list/api/* routes are
// cookie-authenticated (browser session), while /api/v1/mailing-list/*
// stays the separate bearer-token path — both call the exact same
// MailingListHandler methods, no duplicated logic (see main.go's wiring).
//
// Same cream/gold ceremony style guide as /admin/kanban and /portal --
// tokens copied directly from kanban_page.go rather than reinvented.
type MailingListPageHandler struct{}

func (h *MailingListPageHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write([]byte(mailingListPageHTML))
}

const mailingListPageHTML = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Mailing List — Back Office</title>
<meta name="robots" content="noindex, nofollow">
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Cormorant+Garamond:wght@400;500;600&family=Spectral:wght@400;500&display=swap" rel="stylesheet">
<style>
  :root {
    --bg: #f4f1ea; --bg-soft: #ede7dc; --panel: #ebe4d8; --line-soft: #d2c7b8;
    --gold: #c6a75e; --gold-soft: #bfa062; --gold-highlight: #d6bc7a;
    --text-main: #3a352e; --text-muted: #7a7368; --text-faint: #a8a093;
  }
  * { box-sizing: border-box; }
  body {
    margin: 0; min-height: 100vh;
    background: radial-gradient(circle at top, color-mix(in srgb, var(--bg) 84%, #fff 16%), var(--bg-soft));
    color: var(--text-main); font-family: "Spectral", Georgia, serif; line-height: 1.45;
  }
  a { color: var(--gold-soft); }
  a:hover { color: var(--gold-highlight); }
  header {
    padding: 1.6rem 2rem 1.2rem;
    border-bottom: 1px solid color-mix(in srgb, var(--gold) 35%, var(--line-soft) 65%);
    display: flex; align-items: baseline; justify-content: space-between; flex-wrap: wrap; gap: 0.6rem;
  }
  h1 { margin: 0; font-family: "Cormorant Garamond", serif; font-weight: 500; font-size: 2rem; letter-spacing: 0.01em; }
  .sub { color: var(--text-muted); font-size: 0.85rem; }
  main { padding: 1.6rem 2rem 3rem; display: flex; flex-direction: column; gap: 1.4rem; max-width: 640px; }
  .panel {
    border: 1px solid color-mix(in srgb, var(--gold) 45%, var(--line-soft) 55%);
    border-radius: 8px; background: color-mix(in srgb, var(--panel) 92%, white 8%);
    padding: 1.2rem 1.4rem;
  }
  .panel h2 {
    margin: 0 0 0.8rem; font-family: "Cormorant Garamond", serif; font-weight: 600; font-size: 1.1rem;
    letter-spacing: 0.04em; text-transform: uppercase; color: var(--text-muted);
  }
  .stat-row { display: flex; gap: 1.8rem; flex-wrap: wrap; margin-bottom: 0.6rem; }
  .stat { display: flex; flex-direction: column; }
  .stat .n { font-family: "Cormorant Garamond", serif; font-size: 1.8rem; font-weight: 600; }
  .stat .l { font-size: 0.78rem; color: var(--text-muted); letter-spacing: 0.03em; text-transform: uppercase; }
  .badge { display: inline-block; padding: 0.15rem 0.5rem; border-radius: 999px; font-size: 0.75rem; }
  .badge.locked { background: color-mix(in srgb, #a24 20%, var(--panel) 80%); color: #a24; }
  .badge.unlocked { background: color-mix(in srgb, #4a7 20%, var(--panel) 80%); color: #2a6; }
  .source-list { font-size: 0.85rem; color: var(--text-muted); margin-top: 0.6rem; }
  .source-list div { display: flex; justify-content: space-between; padding: 0.15rem 0; }
  form.settings { display: flex; flex-direction: column; gap: 0.7rem; }
  label { font-size: 0.82rem; color: var(--text-muted); display: flex; flex-direction: column; gap: 0.3rem; }
  input {
    font-family: "Spectral", serif; font-size: 0.9rem; padding: 0.45rem 0.6rem;
    border: 1px solid color-mix(in srgb, var(--gold) 50%, var(--line-soft) 50%); border-radius: 5px;
    background: color-mix(in srgb, var(--panel) 97%, white 3%); color: var(--text-main);
  }
  button, .btn {
    font-family: "Spectral", serif; font-size: 0.88rem; padding: 0.48rem 1.1rem; cursor: pointer;
    border: 1px solid color-mix(in srgb, var(--gold) 60%, var(--line-soft) 40%); border-radius: 5px;
    background: color-mix(in srgb, var(--gold) 22%, var(--panel) 78%); color: var(--text-main);
    text-decoration: none; display: inline-block; width: fit-content;
  }
  button:hover, .btn:hover { background: color-mix(in srgb, var(--gold) 32%, var(--panel) 68%); }
  .export-row { display: flex; gap: 0.6rem; }
  #status { font-size: 0.82rem; color: var(--text-muted); min-height: 1.2em; margin-top: 0.4rem; }
  .hint { font-size: 0.78rem; color: var(--text-faint); }
</style>
</head>
<body>
<header>
  <div>
    <h1>Mailing List</h1>
    <div class="sub">Subscriber stats, provider settings, and export for this instance's mailing-list vault.</div>
  </div>
  <div class="sub"><a href="/admin/kanban">← Kanban</a></div>
</header>
<main>
  <div class="panel">
    <h2>Subscribers</h2>
    <div class="stat-row">
      <div class="stat"><span class="n" id="stat-total">—</span><span class="l">Total</span></div>
      <div class="stat"><span class="n" id="stat-synced">—</span><span class="l">Synced to provider</span></div>
      <div class="stat"><span class="n"><span class="badge" id="vault-badge">—</span></span><span class="l">Vault</span></div>
    </div>
    <div class="source-list" id="source-list"></div>
  </div>

  <div class="panel">
    <h2>Email provider (Mailchimp)</h2>
    <form class="settings" id="settings-form">
      <label>API key (write-only — never shown once saved)
        <input type="password" name="api_key" placeholder="key-us21" autocomplete="off">
      </label>
      <label>List / Audience ID
        <input type="text" name="list_id" placeholder="abc123def">
      </label>
      <button type="submit">Save settings</button>
    </form>
    <div class="hint" id="settings-hint"></div>
  </div>

  <div class="panel">
    <h2>Export</h2>
    <div class="export-row">
      <a class="btn" href="/admin/mailing-list/api/export?format=csv">Download CSV</a>
      <a class="btn" href="/admin/mailing-list/api/export?format=json">Download JSON</a>
    </div>
  </div>

  <div id="status"></div>
</main>
<script>
const SUMMARY_API = '/admin/mailing-list/api/summary';
const SETTINGS_API = '/admin/mailing-list/api/settings/mailchimp';
const statusEl = document.getElementById('status');

function setStatus(msg, isError) {
  statusEl.textContent = msg;
  statusEl.style.color = isError ? '#a24' : '';
}

async function loadSummary() {
  const res = await fetch(SUMMARY_API, { credentials: 'same-origin' });
  if (!res.ok) { setStatus('Failed to load subscriber summary (HTTP ' + res.status + ')', true); return; }
  const data = await res.json();
  document.getElementById('stat-total').textContent = data.total;
  document.getElementById('stat-synced').textContent = data.synced;
  const badge = document.getElementById('vault-badge');
  badge.textContent = data.vault_locked ? 'locked' : 'unlocked';
  badge.className = 'badge ' + (data.vault_locked ? 'locked' : 'unlocked');
  const list = document.getElementById('source-list');
  list.innerHTML = '';
  (data.by_source || []).forEach(function (sc) {
    const row = document.createElement('div');
    row.innerHTML = '<span>' + sc.Source + '</span><span>' + sc.Count + '</span>';
    list.appendChild(row);
  });
}

async function loadSettings() {
  const res = await fetch(SETTINGS_API, { credentials: 'same-origin' });
  if (!res.ok) { document.getElementById('settings-hint').textContent = 'Failed to load settings (HTTP ' + res.status + ')'; return; }
  const data = await res.json();
  const hint = document.getElementById('settings-hint');
  if (!data.configured) {
    hint.textContent = 'Not configured yet — falls back to this instance\'s env-var config, if any.';
  } else if (data.note) {
    hint.textContent = data.note;
  } else {
    hint.textContent = 'Configured — list ID: ' + data.list_id + '. Saving requires both fields again (no partial update — avoids ever leaving a half-set config).';
    document.querySelector('input[name="list_id"]').value = data.list_id || '';
  }
}

document.getElementById('settings-form').addEventListener('submit', async function (e) {
  e.preventDefault();
  const form = e.target;
  const apiKey = form.api_key.value.trim();
  const listId = form.list_id.value.trim();
  if (!apiKey || !listId) {
    setStatus('Both API key and List ID are required together.', true);
    return;
  }
  const res = await fetch(SETTINGS_API, {
    method: 'PUT',
    credentials: 'same-origin',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ api_key: apiKey, list_id: listId }),
  });
  if (!res.ok) {
    const body = await res.json().catch(function () { return {}; });
    setStatus('Save failed: ' + (body.error || res.status), true);
    return;
  }
  form.api_key.value = '';
  setStatus('Settings saved.', false);
  loadSettings();
});

loadSummary();
loadSettings();
</script>
</body>
</html>`
