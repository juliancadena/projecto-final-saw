// Obtener sesión actual
async function getSession() {
  const res = await fetch('/api/session');
  if (!res.ok) { window.location = '/'; return null; }
  return res.json();
}

// Llamada genérica a la API
async function api(method, url, body) {
  const opts = { method, headers: { 'Content-Type': 'application/json' } };
  if (body) opts.body = JSON.stringify(body);
  const res = await fetch(url, opts);
  return res.json();
}

function showFlag(flag, containerId) {
  const el = document.getElementById(containerId);
  if (el && flag) {
    el.innerHTML = `<div class="flag-box">🚩 ${flag}</div>`;
  }
}
