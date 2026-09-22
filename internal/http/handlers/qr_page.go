package handlers

import (
	"net/http"
)

// QRPageHandler is the GUI half of the dynamic QR registry (see qr.go's own doc comment for the
// full design). Same cream/gold ceremony style as /admin/kanban, /portal -- copied token values
// directly rather than reinvented, same convention every other admin page here already follows.
type QRPageHandler struct{}

func (h *QRPageHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write([]byte(qrPageHTML))
}

const qrPageHTML = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>QR Codes — Back Office</title>
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
  h1 { font-family: "Cormorant Garamond", serif; font-weight: 600; letter-spacing: .02em; }
  main { max-width: 980px; margin: 0 auto; padding: 2.5rem 1.5rem 4rem; }
  .add-row { display: flex; flex-wrap: wrap; gap: .6rem; margin: 1.5rem 0 2rem; }
  input[type=text] {
    font-family: inherit; font-size: .95rem; padding: .55rem .7rem;
    border: 1px solid var(--line-soft); border-radius: 6px; background: #fffdf8; color: var(--text-main);
  }
  input[name=slug] { width: 10rem; }
  input[name=target_url] { flex: 1; min-width: 16rem; }
  input[name=label] { width: 14rem; }
  button {
    font-family: inherit; font-size: .9rem; padding: .55rem 1rem; border-radius: 6px;
    border: 1px solid var(--gold-soft); background: var(--gold); color: #2b2618; cursor: pointer;
  }
  button:hover { background: var(--gold-highlight); }
  button.danger { background: #e8e0d2; border-color: var(--line-soft); color: #7a3b2e; }
  table { width: 100%; border-collapse: collapse; background: var(--panel); border-radius: 8px; overflow: hidden; }
  th, td { text-align: left; padding: .6rem .7rem; border-bottom: 1px solid var(--line-soft); font-size: .9rem; vertical-align: top; }
  th { color: var(--text-muted); font-weight: 500; text-transform: uppercase; font-size: .72rem; letter-spacing: .06em; }
  td.slug { font-family: monospace; color: var(--gold-soft); white-space: nowrap; }
  td.url input { width: 100%; }
  td.actions { white-space: nowrap; }
  img.qr-thumb { width: 64px; height: 64px; border: 1px solid var(--line-soft); border-radius: 4px; background: #fff; }
  #status { margin-top: 1rem; font-size: .85rem; color: var(--text-muted); }
  #status.err { color: #7a3b2e; }
  .hint { color: var(--text-faint); font-size: .8rem; }
</style>
</head>
<body>
<main>
  <h1>QR Codes</h1>
  <p class="hint">Every code redirects through IDUNA's own URL — retargeting a code here repoints every already-printed copy of its QR image instantly, no reprint needed.</p>
  <form class="add-row" id="add-form">
    <input type="text" name="slug" placeholder="slug (blank = auto)" maxlength="64">
    <input type="text" name="target_url" placeholder="https://... (where it should go)" required>
    <input type="text" name="label" placeholder="Label (optional)" maxlength="200">
    <button type="submit">+ Create</button>
  </form>
  <table>
    <thead><tr><th>QR</th><th>Slug</th><th>Target URL</th><th>Label</th><th>Hits</th><th></th></tr></thead>
    <tbody id="rows"></tbody>
  </table>
  <div id="status"></div>
</main>
<script>
const API = '/admin/qr/api/codes';
function esc(s) { return String(s ?? '').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c])); }
function setStatus(msg, isErr) {
  const el = document.getElementById('status');
  el.textContent = msg; el.className = isErr ? 'err' : '';
}
async function loadCodes() {
  const res = await fetch(API, { credentials: 'same-origin' });
  if (!res.ok) { setStatus('Failed to load codes: HTTP ' + res.status, true); return; }
  const codes = await res.json();
  const rows = document.getElementById('rows');
  rows.innerHTML = '';
  for (const c of codes) {
    const tr = document.createElement('tr');
    tr.innerHTML =
      '<td><img class="qr-thumb" src="' + c.image_url + '" alt="QR for ' + esc(c.slug) + '"></td>' +
      '<td class="slug">' + esc(c.slug) + '</td>' +
      '<td class="url"><input type="text" value="' + esc(c.target_url) + '" data-slug="' + esc(c.slug) + '"></td>' +
      '<td>' + esc(c.label) + '</td>' +
      '<td>' + esc(c.hit_count) + '</td>' +
      '<td class="actions"><button data-save="' + esc(c.slug) + '">Save</button> ' +
      '<button class="danger" data-del="' + esc(c.slug) + '">Delete</button></td>';
    rows.appendChild(tr);
  }
}
document.getElementById('add-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  const form = e.currentTarget;
  const slug = form.slug.value.trim();
  const targetUrl = form.target_url.value.trim();
  const label = form.label.value.trim();
  if (!targetUrl) return;
  try {
    const res = await fetch(API, {
      method: 'POST', credentials: 'same-origin',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ slug, target_url: targetUrl, label })
    });
    if (!res.ok) throw new Error(await res.text());
    form.reset();
    setStatus('Created.', false);
    await loadCodes();
  } catch (err) {
    setStatus('Failed to create: ' + err.message, true);
  }
});
document.getElementById('rows').addEventListener('click', async (e) => {
  const saveSlug = e.target.getAttribute('data-save');
  const delSlug = e.target.getAttribute('data-del');
  if (saveSlug) {
    const input = e.target.closest('tr').querySelector('input[data-slug]');
    try {
      const res = await fetch(API + '/' + encodeURIComponent(saveSlug), {
        method: 'PATCH', credentials: 'same-origin',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ target_url: input.value.trim() })
      });
      if (!res.ok) throw new Error(await res.text());
      setStatus('Updated ' + saveSlug + '.', false);
      await loadCodes();
    } catch (err) {
      setStatus('Failed to update: ' + err.message, true);
    }
  } else if (delSlug) {
    if (!confirm('Delete QR code "' + delSlug + '"? Any printed copy will stop working.')) return;
    try {
      const res = await fetch(API + '/' + encodeURIComponent(delSlug), { method: 'DELETE', credentials: 'same-origin' });
      if (!res.ok && res.status !== 204) throw new Error(await res.text());
      setStatus('Deleted ' + delSlug + '.', false);
      await loadCodes();
    } catch (err) {
      setStatus('Failed to delete: ' + err.message, true);
    }
  }
});
loadCodes();
</script>
</body>
</html>`
