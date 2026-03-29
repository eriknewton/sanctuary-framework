/**
 * Sanctuary MCP Server — Principal Dashboard HTML Template
 *
 * Embedded single-page HTML/CSS/JS for the Principal Dashboard.
 * No build step, no external dependencies, no CDN imports.
 * Served as a single HTML document by the DashboardApprovalChannel.
 */

/**
 * Generate the dashboard HTML with the given configuration.
 */
export function generateDashboardHTML(options: {
  timeoutSeconds: number;
  serverVersion: string;
  /** Auth token — used only in Authorization headers, never in URLs (SEC-012) */
  authToken?: string;
}): string {
  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Sanctuary — Principal Dashboard</title>
<style>
  :root {
    --bg: #0f1117;
    --bg-surface: #1a1d27;
    --bg-elevated: #242736;
    --border: #2e3244;
    --text: #e4e6f0;
    --text-muted: #8b8fa3;
    --accent: #6c8aff;
    --accent-hover: #839dff;
    --approve: #3ecf8e;
    --approve-hover: #5dd9a3;
    --deny: #f87171;
    --deny-hover: #fca5a5;
    --warning: #fbbf24;
    --tier1: #f87171;
    --tier2: #fbbf24;
    --tier3: #3ecf8e;
    --font: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
    --mono: "SF Mono", "Fira Code", "Cascadia Code", monospace;
    --radius: 8px;
  }

  * { box-sizing: border-box; margin: 0; padding: 0; }
  body {
    font-family: var(--font);
    background: var(--bg);
    color: var(--text);
    line-height: 1.5;
    min-height: 100vh;
  }

  /* Layout */
  .container { max-width: 960px; margin: 0 auto; padding: 24px 16px; }

  header {
    display: flex; align-items: center; justify-content: space-between;
    padding-bottom: 20px; border-bottom: 1px solid var(--border);
    margin-bottom: 24px;
  }
  header h1 { font-size: 20px; font-weight: 600; letter-spacing: -0.3px; }
  header h1 span { color: var(--accent); }
  .status-badge {
    display: inline-flex; align-items: center; gap: 6px;
    font-size: 12px; color: var(--text-muted);
    padding: 4px 10px; border-radius: 12px;
    background: var(--bg-surface); border: 1px solid var(--border);
  }
  .status-dot {
    width: 8px; height: 8px; border-radius: 50%;
    background: var(--approve); animation: pulse 2s infinite;
  }
  .status-dot.disconnected { background: var(--deny); animation: none; }
  @keyframes pulse { 0%, 100% { opacity: 1; } 50% { opacity: 0.5; } }

  /* Tabs */
  .tabs {
    display: flex; gap: 2px; margin-bottom: 20px;
    background: var(--bg-surface); border-radius: var(--radius);
    padding: 3px; border: 1px solid var(--border);
  }
  .tab {
    flex: 1; padding: 8px 12px; text-align: center;
    font-size: 13px; font-weight: 500; cursor: pointer;
    border-radius: 6px; border: none; color: var(--text-muted);
    background: transparent; transition: all 0.15s;
  }
  .tab:hover { color: var(--text); }
  .tab.active { background: var(--bg-elevated); color: var(--text); }
  .tab .count {
    display: inline-flex; align-items: center; justify-content: center;
    min-width: 18px; height: 18px; padding: 0 5px;
    font-size: 11px; font-weight: 600; border-radius: 9px;
    margin-left: 6px;
  }
  .tab .count.alert { background: var(--deny); color: white; }
  .tab .count.muted { background: var(--border); color: var(--text-muted); }

  /* Tab Content */
  .tab-content { display: none; }
  .tab-content.active { display: block; }

  /* Pending Requests */
  .pending-empty {
    text-align: center; padding: 60px 20px; color: var(--text-muted);
  }
  .pending-empty .icon { font-size: 32px; margin-bottom: 12px; }
  .pending-empty p { font-size: 14px; }

  .request-card {
    background: var(--bg-surface); border: 1px solid var(--border);
    border-radius: var(--radius); padding: 16px; margin-bottom: 12px;
    animation: slideIn 0.2s ease-out;
  }
  @keyframes slideIn { from { opacity: 0; transform: translateY(-8px); } to { opacity: 1; transform: translateY(0); } }
  .request-card.tier1 { border-left: 3px solid var(--tier1); }
  .request-card.tier2 { border-left: 3px solid var(--tier2); }
  .request-header {
    display: flex; align-items: center; justify-content: space-between;
    margin-bottom: 10px;
  }
  .request-op {
    font-family: var(--mono); font-size: 14px; font-weight: 600;
  }
  .tier-badge {
    font-size: 11px; font-weight: 600; padding: 2px 8px;
    border-radius: 4px; text-transform: uppercase;
  }
  .tier-badge.tier1 { background: rgba(248,113,113,0.15); color: var(--tier1); }
  .tier-badge.tier2 { background: rgba(251,191,36,0.15); color: var(--tier2); }
  .request-reason {
    font-size: 13px; color: var(--text-muted); margin-bottom: 12px;
  }
  .request-context {
    font-family: var(--mono); font-size: 12px; color: var(--text-muted);
    background: var(--bg); border-radius: 4px; padding: 8px 10px;
    margin-bottom: 14px; white-space: pre-wrap; word-break: break-all;
    max-height: 120px; overflow-y: auto;
  }
  .request-actions {
    display: flex; align-items: center; gap: 10px;
  }
  .btn {
    padding: 7px 16px; border-radius: 6px; font-size: 13px;
    font-weight: 600; border: none; cursor: pointer;
    transition: all 0.15s;
  }
  .btn-approve { background: var(--approve); color: #0f1117; }
  .btn-approve:hover { background: var(--approve-hover); }
  .btn-deny { background: var(--deny); color: white; }
  .btn-deny:hover { background: var(--deny-hover); }
  .countdown {
    margin-left: auto; font-size: 12px; color: var(--text-muted);
    font-family: var(--mono);
  }
  .countdown.urgent { color: var(--deny); font-weight: 600; }

  /* Audit Log */
  .audit-table { width: 100%; border-collapse: collapse; }
  .audit-table th {
    text-align: left; font-size: 11px; font-weight: 600;
    text-transform: uppercase; letter-spacing: 0.5px;
    color: var(--text-muted); padding: 8px 10px;
    border-bottom: 1px solid var(--border);
  }
  .audit-table td {
    font-size: 13px; padding: 8px 10px;
    border-bottom: 1px solid var(--border);
  }
  .audit-table tr { transition: background 0.1s; }
  .audit-table tr:hover { background: var(--bg-elevated); }
  .audit-table tr.new { animation: highlight 1s ease-out; }
  @keyframes highlight { from { background: rgba(108,138,255,0.15); } to { background: transparent; } }
  .audit-time { font-family: var(--mono); font-size: 12px; color: var(--text-muted); }
  .audit-op { font-family: var(--mono); font-size: 12px; }
  .audit-layer {
    font-size: 11px; font-weight: 600; padding: 1px 6px;
    border-radius: 3px; text-transform: uppercase;
  }
  .audit-layer.l1 { background: rgba(108,138,255,0.15); color: var(--accent); }
  .audit-layer.l2 { background: rgba(251,191,36,0.15); color: var(--tier2); }
  .audit-layer.l3 { background: rgba(62,207,142,0.15); color: var(--tier3); }
  .audit-layer.l4 { background: rgba(168,85,247,0.15); color: #a855f7; }

  /* Baseline & Policy */
  .info-section {
    background: var(--bg-surface); border: 1px solid var(--border);
    border-radius: var(--radius); padding: 16px; margin-bottom: 16px;
  }
  .info-section h3 {
    font-size: 13px; font-weight: 600; text-transform: uppercase;
    letter-spacing: 0.5px; color: var(--text-muted); margin-bottom: 12px;
  }
  .info-row {
    display: flex; justify-content: space-between; align-items: center;
    padding: 6px 0; font-size: 13px;
  }
  .info-label { color: var(--text-muted); }
  .info-value { font-family: var(--mono); font-size: 12px; }
  .tag-list { display: flex; flex-wrap: wrap; gap: 4px; }
  .tag {
    font-family: var(--mono); font-size: 11px; padding: 2px 8px;
    background: var(--bg-elevated); border-radius: 4px;
    color: var(--text-muted); border: 1px solid var(--border);
  }
  .policy-op {
    font-family: var(--mono); font-size: 12px; padding: 3px 0;
  }

  /* Footer */
  footer {
    margin-top: 32px; padding-top: 16px;
    border-top: 1px solid var(--border);
    font-size: 12px; color: var(--text-muted);
    text-align: center;
  }
</style>
</head>
<body>
<div class="container">
  <header>
    <h1><span>Sanctuary</span> Principal Dashboard</h1>
    <div class="status-badge">
      <div class="status-dot" id="statusDot"></div>
      <span id="statusText">Connected</span>
    </div>
  </header>

  <div class="tabs">
    <button class="tab active" data-tab="pending">
      Pending<span class="count muted" id="pendingCount">0</span>
    </button>
    <button class="tab" data-tab="audit">
      Audit Log<span class="count muted" id="auditCount">0</span>
    </button>
    <button class="tab" data-tab="baseline">Baseline</button>
    <button class="tab" data-tab="policy">Policy</button>
  </div>

  <!-- Pending Approvals -->
  <div class="tab-content active" id="tab-pending">
    <div class="pending-empty" id="pendingEmpty">
      <div class="icon">&#x2714;</div>
      <p>No pending approval requests.</p>
      <p style="font-size:12px; margin-top:4px;">Requests will appear here in real time.</p>
    </div>
    <div id="pendingList"></div>
  </div>

  <!-- Audit Log -->
  <div class="tab-content" id="tab-audit">
    <table class="audit-table">
      <thead>
        <tr><th>Time</th><th>Layer</th><th>Operation</th><th>Identity</th></tr>
      </thead>
      <tbody id="auditBody"></tbody>
    </table>
  </div>

  <!-- Baseline -->
  <div class="tab-content" id="tab-baseline">
    <div class="info-section">
      <h3>Session Info</h3>
      <div class="info-row"><span class="info-label">First session</span><span class="info-value" id="bFirstSession">—</span></div>
      <div class="info-row"><span class="info-label">Started</span><span class="info-value" id="bStarted">—</span></div>
    </div>
    <div class="info-section">
      <h3>Known Namespaces</h3>
      <div class="tag-list" id="bNamespaces"><span class="tag">—</span></div>
    </div>
    <div class="info-section">
      <h3>Known Counterparties</h3>
      <div class="tag-list" id="bCounterparties"><span class="tag">—</span></div>
    </div>
    <div class="info-section">
      <h3>Tool Call Counts</h3>
      <div id="bToolCalls"><span class="info-value">—</span></div>
    </div>
  </div>

  <!-- Policy -->
  <div class="tab-content" id="tab-policy">
    <div class="info-section">
      <h3>Tier 1 — Always Requires Approval</h3>
      <div id="pTier1"></div>
    </div>
    <div class="info-section">
      <h3>Tier 2 — Anomaly Detection</h3>
      <div id="pTier2"></div>
    </div>
    <div class="info-section">
      <h3>Tier 3 — Always Allowed</h3>
      <div class="info-row">
        <span class="info-label">Operations</span>
        <span class="info-value" id="pTier3Count">—</span>
      </div>
    </div>
    <div class="info-section">
      <h3>Approval Channel</h3>
      <div id="pChannel"></div>
    </div>
  </div>

  <footer>Sanctuary Framework v${options.serverVersion} — Principal Dashboard</footer>
</div>

<script>
(function() {
  const TIMEOUT = ${options.timeoutSeconds};
  // SEC-012: Auth token is passed via Authorization header only — never in URLs.
  // The token is provided by the server at generation time (embedded for initial auth).
  const AUTH_TOKEN = ${options.authToken ? JSON.stringify(options.authToken) : 'null'};
  let SESSION_ID = null; // Short-lived session for SSE and URL-based requests
  const pending = new Map();
  let auditCount = 0;

  // Auth helpers — SEC-012: token goes in header, session goes in URL
  function authHeaders() {
    const h = { 'Content-Type': 'application/json' };
    if (AUTH_TOKEN) h['Authorization'] = 'Bearer ' + AUTH_TOKEN;
    return h;
  }
  function sessionQuery(url) {
    if (!SESSION_ID) return url;
    const sep = url.includes('?') ? '&' : '?';
    return url + sep + 'session=' + SESSION_ID;
  }

  // SEC-012: Exchange the long-lived token for a short-lived session
  async function exchangeSession() {
    if (!AUTH_TOKEN) return;
    try {
      const resp = await fetch('/auth/session', { method: 'POST', headers: authHeaders() });
      if (resp.ok) {
        const data = await resp.json();
        SESSION_ID = data.session_id;
        // Refresh session before expiry (at 80% of TTL)
        const refreshMs = (data.expires_in_seconds || 300) * 800;
        setTimeout(async () => { await exchangeSession(); reconnectSSE(); }, refreshMs);
      }
    } catch(e) { /* will retry on next connect */ }
  }

  // Tab switching
  document.querySelectorAll('.tab').forEach(tab => {
    tab.addEventListener('click', () => {
      document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
      document.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));
      tab.classList.add('active');
      document.getElementById('tab-' + tab.dataset.tab).classList.add('active');
    });
  });

  // SSE Connection — SEC-012: uses short-lived session token in URL, not auth token
  let evtSource;
  function reconnectSSE() {
    if (evtSource) { evtSource.close(); }
    connect();
  }
  function connect() {
    evtSource = new EventSource(sessionQuery('/events'));
    evtSource.onopen = () => {
      document.getElementById('statusDot').classList.remove('disconnected');
      document.getElementById('statusText').textContent = 'Connected';
    };
    evtSource.onerror = () => {
      document.getElementById('statusDot').classList.add('disconnected');
      document.getElementById('statusText').textContent = 'Reconnecting...';
    };
    evtSource.addEventListener('pending-request', (e) => {
      const data = JSON.parse(e.data);
      addPendingRequest(data);
    });
    evtSource.addEventListener('request-resolved', (e) => {
      const data = JSON.parse(e.data);
      removePendingRequest(data.request_id);
    });
    evtSource.addEventListener('audit-entry', (e) => {
      const data = JSON.parse(e.data);
      addAuditEntry(data);
    });
    evtSource.addEventListener('baseline-update', (e) => {
      const data = JSON.parse(e.data);
      updateBaseline(data);
    });
    evtSource.addEventListener('policy-update', (e) => {
      const data = JSON.parse(e.data);
      updatePolicy(data);
    });
    evtSource.addEventListener('init', (e) => {
      const data = JSON.parse(e.data);
      if (data.baseline) updateBaseline(data.baseline);
      if (data.policy) updatePolicy(data.policy);
      if (data.pending) data.pending.forEach(addPendingRequest);
      if (data.audit) data.audit.forEach(addAuditEntry);
    });
  }

  // Pending requests
  function addPendingRequest(req) {
    pending.set(req.request_id, { ...req, remaining: TIMEOUT });
    renderPending();
    updatePendingCount();
    flashTab('pending');
  }

  function removePendingRequest(id) {
    pending.delete(id);
    renderPending();
    updatePendingCount();
  }

  function renderPending() {
    const list = document.getElementById('pendingList');
    const empty = document.getElementById('pendingEmpty');
    if (pending.size === 0) {
      list.innerHTML = '';
      empty.style.display = 'block';
      return;
    }
    empty.style.display = 'none';
    list.innerHTML = '';
    for (const [id, req] of pending) {
      const card = document.createElement('div');
      card.className = 'request-card tier' + req.tier;
      card.id = 'req-' + id;
      const ctx = typeof req.context === 'string' ? req.context : JSON.stringify(req.context, null, 2);
      card.innerHTML =
        '<div class="request-header">' +
          '<span class="request-op">' + esc(req.operation) + '</span>' +
          '<span class="tier-badge tier' + req.tier + '">Tier ' + req.tier + '</span>' +
        '</div>' +
        '<div class="request-reason">' + esc(req.reason) + '</div>' +
        '<div class="request-context">' + esc(ctx) + '</div>' +
        '<div class="request-actions">' +
          '<button class="btn btn-approve" onclick="handleApprove(\\'' + id + '\\')">Approve</button>' +
          '<button class="btn btn-deny" onclick="handleDeny(\\'' + id + '\\')">Deny</button>' +
          '<span class="countdown" id="cd-' + id + '">' + req.remaining + 's</span>' +
        '</div>';
      list.appendChild(card);
    }
  }

  function updatePendingCount() {
    const el = document.getElementById('pendingCount');
    el.textContent = pending.size;
    el.className = pending.size > 0 ? 'count alert' : 'count muted';
  }

  function flashTab(name) {
    const tab = document.querySelector('[data-tab="' + name + '"]');
    if (!tab.classList.contains('active')) {
      tab.style.background = 'rgba(248,113,113,0.15)';
      setTimeout(() => { tab.style.background = ''; }, 1500);
    }
  }

  // Countdown timer
  setInterval(() => {
    for (const [id, req] of pending) {
      req.remaining = Math.max(0, req.remaining - 1);
      const el = document.getElementById('cd-' + id);
      if (el) {
        el.textContent = req.remaining + 's';
        el.className = req.remaining <= 30 ? 'countdown urgent' : 'countdown';
      }
    }
  }, 1000);

  // Approve / Deny handlers (global scope)
  window.handleApprove = function(id) {
    fetch('/api/approve/' + id, { method: 'POST', headers: authHeaders() }).then(() => {
      removePendingRequest(id);
    });
  };
  window.handleDeny = function(id) {
    fetch('/api/deny/' + id, { method: 'POST', headers: authHeaders() }).then(() => {
      removePendingRequest(id);
    });
  };

  // Audit log
  function addAuditEntry(entry) {
    auditCount++;
    document.getElementById('auditCount').textContent = auditCount;
    const tbody = document.getElementById('auditBody');
    const tr = document.createElement('tr');
    tr.className = 'new';
    const time = entry.timestamp ? new Date(entry.timestamp).toLocaleTimeString() : '—';
    const layer = entry.layer || '—';
    tr.innerHTML =
      '<td class="audit-time">' + esc(time) + '</td>' +
      '<td><span class="audit-layer ' + layer + '">' + esc(layer) + '</span></td>' +
      '<td class="audit-op">' + esc(entry.operation || '—') + '</td>' +
      '<td style="font-size:12px;color:var(--text-muted)">' + esc(entry.identity_id || '—') + '</td>';
    tbody.insertBefore(tr, tbody.firstChild);
    // Keep last 100 entries
    while (tbody.children.length > 100) tbody.removeChild(tbody.lastChild);
  }

  // Baseline
  function updateBaseline(b) {
    if (!b) return;
    document.getElementById('bFirstSession').textContent = b.is_first_session ? 'Yes' : 'No';
    document.getElementById('bStarted').textContent = b.started_at ? new Date(b.started_at).toLocaleString() : '—';
    const ns = document.getElementById('bNamespaces');
    ns.innerHTML = (b.known_namespaces || []).length > 0
      ? (b.known_namespaces || []).map(n => '<span class="tag">' + esc(n) + '</span>').join('')
      : '<span class="tag">none</span>';
    const cp = document.getElementById('bCounterparties');
    cp.innerHTML = (b.known_counterparties || []).length > 0
      ? (b.known_counterparties || []).map(c => '<span class="tag">' + esc(c.slice(0,16)) + '...</span>').join('')
      : '<span class="tag">none</span>';
    const tc = document.getElementById('bToolCalls');
    const counts = b.tool_call_counts || {};
    const entries = Object.entries(counts).sort((a,b) => b[1] - a[1]);
    tc.innerHTML = entries.length > 0
      ? entries.map(([k,v]) => '<div class="info-row"><span class="info-label">' + esc(k) + '</span><span class="info-value">' + v + '</span></div>').join('')
      : '<span class="info-value">no calls yet</span>';
  }

  // Policy
  function updatePolicy(p) {
    if (!p) return;
    const t1 = document.getElementById('pTier1');
    t1.innerHTML = (p.tier1_always_approve || []).map(op =>
      '<div class="policy-op">' + esc(op) + '</div>'
    ).join('');
    const t2 = document.getElementById('pTier2');
    const cfg = p.tier2_anomaly || {};
    t2.innerHTML = Object.entries(cfg).map(([k,v]) =>
      '<div class="info-row"><span class="info-label">' + esc(k) + '</span><span class="info-value">' + esc(String(v)) + '</span></div>'
    ).join('');
    document.getElementById('pTier3Count').textContent = (p.tier3_always_allow || []).length + ' operations';
    const ch = document.getElementById('pChannel');
    const chan = p.approval_channel || {};
    ch.innerHTML = Object.entries(chan).filter(([k]) => k !== 'webhook_secret').map(([k,v]) =>
      '<div class="info-row"><span class="info-label">' + esc(k) + '</span><span class="info-value">' + esc(String(v)) + '</span></div>'
    ).join('');
  }

  function esc(s) {
    if (!s) return '';
    const d = document.createElement('div');
    d.textContent = String(s);
    return d.innerHTML;
  }

  // Init — SEC-012: exchange token for session before connecting SSE
  (async function init() {
    await exchangeSession();
    // Clean token from URL if present (legacy bookmarks)
    if (window.location.search.includes('token=')) {
      const clean = window.location.pathname;
      window.history.replaceState({}, '', clean);
    }
    connect();
    fetch('/api/status', { headers: authHeaders() }).then(r => r.json()).then(data => {
      if (data.baseline) updateBaseline(data.baseline);
      if (data.policy) updatePolicy(data.policy);
    }).catch(() => {});
  })();
})();
</script>
</body>
</html>`;
}
