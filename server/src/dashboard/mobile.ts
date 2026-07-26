/**
 * Sanctuary Mobile Companion (PWA) -- slice 1: phone-as-approval surface.
 *
 * A mobile-first, installable Progressive Web App that lets the operator
 * review and decide PENDING APPROVALS from their phone. It is a thin CLIENT
 * of the dashboard's EXISTING, already-secured API -- it introduces NO new
 * data surface and NO new auth path:
 *
 *   - reads pending approvals from `GET /api/pending` (read-auth), and
 *   - decides them via `POST /api/approvals/:id/(allow|deny)`, which is gated
 *     by the operator BEARER token (`isAuthorizedWithBearerToken`): loopback
 *     auto-auth is explicitly REJECTED for that mutation (a co-resident
 *     wrapped agent shares loopback with the operator, so loopback origin is
 *     NOT operator identity). The phone is off-loopback by definition, so the
 *     companion ALWAYS authenticates with the operator token.
 *
 * SECURITY POSTURE (why this is safe to serve):
 *   1. The served shell (this HTML + the manifest + the service worker) is a
 *      STATIC app shell. It carries no operator data -- every datum is fetched
 *      at runtime from the existing auth-gated `/api/*` routes. Serving the
 *      shell unauthenticated is exactly the posture of the desktop login
 *      shell.
 *   2. The operator token lives ONLY in `sessionStorage` + memory on the
 *      device and is sent ONLY as an `Authorization: Bearer` header. It is
 *      NEVER placed in a URL/query (no token in server logs) and NEVER cached.
 *   3. Live refresh is POLLING (bearer header on each fetch), not SSE:
 *      `EventSource` cannot set an `Authorization` header, and passing the
 *      token as a query param to authorize SSE would leak it into logs. SSE
 *      live-push is a follow-on once a header-safe SSE auth exists.
 *   4. The service worker is scope-limited to `/m/` and caches ONLY the app
 *      shell. It NEVER caches `/api/*` (a stale cached approval list or a
 *      cached auth response would be a correctness AND security defect) -- all
 *      `/api/*` requests are network-only and bypass the cache entirely.
 *   5. Rendered approval data is inserted via `textContent` only (never
 *      `innerHTML`), so hostile operation metadata cannot inject script.
 *   6. The page is fully self-contained (inline CSS + JS, no external
 *      origins), so it serves under a strict same-origin CSP.
 *
 * OUT OF SLICE 1 (deferred, tracked): the "emergency-brake" kill/pause
 * control (needs a dedicated fail-closed backend verb + is a Tier-1-class
 * control that wants an operator design review before it ships), push
 * notifications (needs VAPID key custody), and QR/short-code device pairing
 * (a new auth-transfer mechanism -- security-sensitive, draft-before-build).
 * Slice 1 reuses the operator's existing means of reaching the dashboard.
 */

import { PAPER_INK_ROOT_TOKENS_CSS } from "./design-tokens.js";

/** The route prefix the companion (shell, manifest, service worker) serves under. */
export const MOBILE_COMPANION_ROUTE_PREFIX = "/m";

/**
 * A strict, self-referential Content-Security-Policy for the companion shell.
 * Everything is inline and same-origin, so `default-src 'self'` with the
 * narrow inline allowances is sufficient; no external origin is ever needed.
 * `connect-src 'self'` keeps runtime fetches (the `/api/*` calls) same-origin.
 */
export const MOBILE_COMPANION_CSP =
  "default-src 'self'; " +
  "script-src 'self' 'unsafe-inline'; " +
  "style-src 'self' 'unsafe-inline'; " +
  "img-src 'self' data:; " +
  "connect-src 'self'; " +
  "manifest-src 'self'; " +
  "base-uri 'none'; " +
  "form-action 'none'; " +
  "frame-ancestors 'none'";

/**
 * The web app manifest (served at `/m/manifest.webmanifest`). Makes the
 * companion installable to the home screen as a standalone app. Icons are
 * inline SVG data-URIs so the shell stays self-contained (no external asset
 * fetch, no extra route to secure).
 */
const SHIELD_ICON_SVG =
  "data:image/svg+xml," +
  encodeURIComponent(
    '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 512 512">' +
      '<rect width="512" height="512" rx="96" fill="#1a1a17"/>' +
      '<path d="M256 96l128 48v104c0 88-56 150-128 172-72-22-128-84-128-172V144z" ' +
      'fill="none" stroke="#f7f5f0" stroke-width="24" stroke-linejoin="round"/>' +
      "</svg>",
  );

export const MOBILE_COMPANION_WEBMANIFEST: string = JSON.stringify(
  {
    name: "Sanctuary Companion",
    short_name: "Sanctuary",
    description: "Review and decide your agents' pending approvals from your phone.",
    start_url: "/m/",
    scope: "/m/",
    display: "standalone",
    orientation: "portrait",
    background_color: "#f7f5f0",
    theme_color: "#1a1a17",
    icons: [
      { src: SHIELD_ICON_SVG, sizes: "any", type: "image/svg+xml", purpose: "any" },
      { src: SHIELD_ICON_SVG, sizes: "any", type: "image/svg+xml", purpose: "maskable" },
    ],
  },
  null,
  2,
);

/**
 * The service worker (served at `/m/sw.js`). Deliberately minimal:
 *   - precaches the app shell (the three companion routes) on install;
 *   - serves the shell cache-first so the app opens offline;
 *   - BYPASSES the cache entirely for anything under `/api/` (network-only),
 *     so a live approval list is never served stale and an auth response is
 *     never cached;
 *   - claims clients immediately and drops old shell caches on activate.
 * The cache name (`CACHE`) is versioned; bump it whenever the shell changes so
 * old shells retire (a shell security fix must ride a fresh cache name).
 */
export const MOBILE_COMPANION_SERVICE_WORKER_JS = `/* Sanctuary Companion service worker (slice 1). */
'use strict';
var CACHE = 'sanctuary-companion-shell-v1';
var SHELL = ['/m/', '/m/manifest.webmanifest'];

self.addEventListener('install', function (event) {
  event.waitUntil(caches.open(CACHE).then(function (c) { return c.addAll(SHELL); }));
  self.skipWaiting();
});

self.addEventListener('activate', function (event) {
  event.waitUntil(
    caches.keys().then(function (keys) {
      return Promise.all(keys.map(function (k) { return k === CACHE ? null : caches.delete(k); }));
    }).then(function () { return self.clients.claim(); })
  );
});

self.addEventListener('fetch', function (event) {
  var req = event.request;
  var url = new URL(req.url);
  // NEVER cache API traffic: approvals must be live, auth responses must not
  // persist. Same-origin /api/* is network-only; cross-origin is left alone.
  if (url.origin === self.location.origin && url.pathname.indexOf('/api/') === 0) {
    return; // fall through to the network, no cache interaction
  }
  if (req.method !== 'GET') return;
  // App shell: cache-first, then network (and refresh the cached copy).
  event.respondWith(
    caches.match(req).then(function (hit) {
      var net = fetch(req).then(function (res) {
        if (res && res.ok && url.origin === self.location.origin) {
          var copy = res.clone();
          caches.open(CACHE).then(function (c) { c.put(req, copy); });
        }
        return res;
      }).catch(function () { return hit; });
      return hit || net;
    })
  );
});
`;

/**
 * Render the mobile companion shell (served at `/m`). Self-contained: inline
 * CSS (paper/ink tokens) + inline JS, no external origin. The JS holds the
 * operator token in `sessionStorage`, polls `/api/pending`, and posts
 * allow/deny with the bearer header.
 */
export function renderMobileCompanionHTML(): string {
  // Inline app script. Kept as a string (not a template with interpolation)
  // so no server-side value is ever spliced into executable JS.
  const appJs = String.raw`
'use strict';
(function () {
  var TOKEN_KEY = 'sanctuary.companion.token';
  var POLL_MS = 4000;
  var pollTimer = null;

  function token() { try { return sessionStorage.getItem(TOKEN_KEY) || ''; } catch (e) { return ''; } }
  function setToken(t) { try { t ? sessionStorage.setItem(TOKEN_KEY, t) : sessionStorage.removeItem(TOKEN_KEY); } catch (e) {} }
  function el(id) { return document.getElementById(id); }
  function authHeaders() { return { 'Authorization': 'Bearer ' + token() }; }

  function setStatus(text, kind) {
    var s = el('status');
    s.textContent = text;
    s.className = 'status' + (kind ? ' ' + kind : '');
  }

  function show(view) {
    el('unlock').hidden = view !== 'unlock';
    el('app').hidden = view !== 'app';
  }

  function connect() {
    var t = el('token-input').value.trim();
    if (!t) { setStatus('Enter your operator token to connect.', 'warn'); return; }
    setToken(t);
    el('token-input').value = '';
    show('app');
    refresh();
    start();
  }

  function lock() {
    setToken('');
    stop();
    show('unlock');
  }

  function start() { stop(); pollTimer = setInterval(refresh, POLL_MS); }
  function stop() { if (pollTimer) { clearInterval(pollTimer); pollTimer = null; } }

  function fmtDetail(a) {
    // Prefer a human summary the backend already provides; fall back to the
    // operation + a compact detail line. Everything is set via textContent.
    if (a && typeof a.summary === 'string' && a.summary) return a.summary;
    var op = (a && (a.operation || a.tool || a.action)) || 'operation';
    return String(op);
  }

  function decide(id, action, card) {
    var buttons = card.querySelectorAll('button');
    for (var i = 0; i < buttons.length; i++) buttons[i].disabled = true;
    setStatus('Sending ' + action + '…');
    fetch('/api/approvals/' + encodeURIComponent(id) + '/' + action, {
      method: 'POST', headers: authHeaders(), cache: 'no-store'
    }).then(function (r) {
      if (r.status === 401) { setStatus('Token rejected. Reconnect.', 'warn'); lock(); return; }
      if (!r.ok) { setStatus(action + ' failed (' + r.status + ').', 'warn'); refresh(); return; }
      card.parentNode && card.parentNode.removeChild(card);
      setStatus('Decision recorded.', 'ok');
      refresh();
    }).catch(function () { setStatus('Network error. Retrying.', 'warn'); refresh(); });
  }

  function render(items) {
    var list = el('list');
    list.textContent = '';
    if (!items || !items.length) {
      var empty = document.createElement('div');
      empty.className = 'empty';
      empty.textContent = 'No pending approvals.';
      list.appendChild(empty);
      return;
    }
    items.forEach(function (a) {
      var id = a && (a.id || a.approval_id || a.request_id);
      if (!id) return;
      var card = document.createElement('div');
      card.className = 'card';

      var title = document.createElement('div');
      title.className = 'card-title';
      title.textContent = fmtDetail(a);
      card.appendChild(title);

      if (a && a.agent_id) {
        var meta = document.createElement('div');
        meta.className = 'card-meta';
        meta.textContent = 'agent: ' + a.agent_id;
        card.appendChild(meta);
      }

      var row = document.createElement('div');
      row.className = 'actions';
      var allow = document.createElement('button');
      allow.className = 'btn allow';
      allow.textContent = 'Allow';
      allow.addEventListener('click', function () { decide(id, 'allow', card); });
      var deny = document.createElement('button');
      deny.className = 'btn deny';
      deny.textContent = 'Deny';
      deny.addEventListener('click', function () { decide(id, 'deny', card); });
      row.appendChild(deny);
      row.appendChild(allow);
      card.appendChild(row);
      list.appendChild(card);
    });
  }

  function refresh() {
    if (!token()) { lock(); return; }
    fetch('/api/pending', { headers: authHeaders(), cache: 'no-store' })
      .then(function (r) {
        if (r.status === 401) { setStatus('Token rejected. Reconnect.', 'warn'); lock(); return null; }
        if (!r.ok) { setStatus('Could not load (' + r.status + ').', 'warn'); return null; }
        return r.json();
      })
      .then(function (items) {
        if (items === null) return;
        render(items);
        setStatus(items.length ? (items.length + ' pending') : 'All clear', items.length ? 'warn' : 'ok');
      })
      .catch(function () { setStatus('Offline. Will retry.', 'warn'); });
  }

  document.addEventListener('DOMContentLoaded', function () {
    el('connect').addEventListener('click', connect);
    el('lock').addEventListener('click', lock);
    el('token-input').addEventListener('keydown', function (e) { if (e.key === 'Enter') connect(); });
    // Honest transport warning: on a non-secure context (plain HTTP on a LAN)
    // a pasted token can be intercepted and the service worker will not
    // register. localhost + HTTPS are secure contexts and pass silently.
    if (!window.isSecureContext) { var w = el('insecure-warn'); if (w) w.hidden = false; }
    if (token()) { show('app'); refresh(); start(); } else { show('unlock'); }
    if ('serviceWorker' in navigator) {
      navigator.serviceWorker.register('/m/sw.js').catch(function () {});
    }
    document.addEventListener('visibilitychange', function () {
      if (document.hidden) stop(); else if (token()) { refresh(); start(); }
    });
  });
})();
`;

  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">
<meta name="theme-color" content="#1a1a17">
<meta name="color-scheme" content="light dark">
<title>Sanctuary Companion</title>
<link rel="manifest" href="/m/manifest.webmanifest">
<link rel="apple-touch-icon" href="${SHIELD_ICON_SVG}">
<style>
${PAPER_INK_ROOT_TOKENS_CSS}
* { box-sizing: border-box; -webkit-tap-highlight-color: transparent; }
html, body { margin: 0; background: var(--paper); color: var(--ink); font-family: var(--sans); }
body { min-height: 100dvh; padding: env(safe-area-inset-top) 16px calc(env(safe-area-inset-bottom) + 16px); }
header { display: flex; align-items: center; justify-content: space-between; padding: 16px 0 8px; }
.brand { font-family: var(--serif); font-size: 20px; font-weight: 600; }
.status { font-family: var(--mono); font-size: 12px; color: var(--ink-3); min-height: 16px; padding: 4px 0; }
.status.ok { color: var(--sage); }
.status.warn { color: var(--rust); }
h1 { font-family: var(--serif); font-size: 22px; margin: 8px 0 4px; }
p.lead { color: var(--ink-3); font-size: 14px; margin: 0 0 20px; }
input {
  width: 100%; font-family: var(--mono); font-size: 16px; padding: 14px;
  border: 1px solid var(--rule-2); border-radius: var(--rad); background: var(--surface);
  color: var(--ink); margin-bottom: 12px;
}
.btn {
  appearance: none; border: 1px solid var(--rule-2); border-radius: var(--rad);
  padding: 16px; font-size: 16px; font-weight: 600; background: var(--surface);
  color: var(--ink); cursor: pointer; min-height: 52px;
}
.btn:active { transform: translateY(1px); }
.btn.primary { background: var(--ink); color: var(--paper); border-color: var(--ink); width: 100%; }
.btn.allow { background: var(--sage-bg); border-color: var(--sage); color: var(--ink); flex: 1; }
.btn.deny { background: var(--rust-bg); border-color: var(--rust); color: var(--ink); flex: 1; }
.btn[disabled] { opacity: .5; }
.card {
  border: 1px solid var(--rule); border-radius: var(--rad-lg); background: var(--surface);
  padding: 16px; margin-bottom: 12px; box-shadow: var(--shadow);
}
.card-title { font-size: 16px; font-weight: 600; word-break: break-word; }
.card-meta { font-family: var(--mono); font-size: 12px; color: var(--ink-3); margin-top: 4px; }
.actions { display: flex; gap: 10px; margin-top: 14px; }
.empty { text-align: center; color: var(--ink-3); padding: 48px 0; }
.warn { background: var(--rust-bg); border: 1px solid var(--rust); color: var(--ink); border-radius: var(--rad); padding: 12px; font-size: 13px; line-height: 1.4; margin-bottom: 14px; }
.linkbtn { background: none; border: none; color: var(--ink-3); font-family: var(--mono); font-size: 12px; cursor: pointer; padding: 4px; }
</style>
</head>
<body>
<header>
  <span class="brand">Sanctuary</span>
  <button id="lock" class="linkbtn" type="button">Lock</button>
</header>
<div id="status" class="status" role="status" aria-live="polite"></div>

<section id="unlock" hidden>
  <h1>Approvals on your phone</h1>
  <div id="insecure-warn" class="warn" hidden>This connection is not secure. Open Sanctuary over HTTPS or a trusted local tunnel before entering your token: on plain HTTP it can be intercepted, and offline mode is off.</div>
  <p class="lead">Paste your operator token to review and decide your agents' pending approvals. Your token stays on this device.</p>
  <input id="token-input" type="password" inputmode="text" autocomplete="off" autocapitalize="off" autocorrect="off" spellcheck="false" placeholder="Operator token">
  <button id="connect" class="btn primary" type="button">Connect</button>
</section>

<section id="app" hidden>
  <div id="list"></div>
</section>

<script>${appJs}</script>
</body>
</html>
`;
}
