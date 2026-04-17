/**
 * Sanctuary — Fortress View
 *
 * Human-facing dashboard that answers three questions:
 * 1. Is my agent safe? (green/yellow/red status)
 * 2. What is my agent doing? (live tool call feed)
 * 3. What needs my attention? (pending approvals, alerts)
 *
 * This is the default landing page when the dashboard is launched via
 * `sanctuary wrap`. The existing detailed panels become the "Advanced" tab.
 */

export interface FortressViewOptions {
  serverVersion: string;
  authToken?: string;
  upstreamServerCount: number;
}

/**
 * Generate the Fortress View HTML for the Cocoon dashboard.
 */
export function generateFortressViewHTML(options: FortressViewOptions): string {
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Sanctuary</title>
  <style>
    :root {
      --bg: #0d1117;
      --surface: #161b22;
      --surface-raised: #1c2128;
      --border: #30363d;
      --text-primary: #e6edf3;
      --text-secondary: #8b949e;
      --text-muted: #484f58;
      --green: #3fb950;
      --green-dim: #238636;
      --amber: #d29922;
      --amber-dim: #9e6a03;
      --red: #f85149;
      --red-dim: #da3633;
      --blue: #58a6ff;
      --blue-dim: #1f6feb;
    }

    * { margin: 0; padding: 0; box-sizing: border-box; }

    body {
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Helvetica, Arial, sans-serif;
      background-color: var(--bg);
      color: var(--text-primary);
      min-height: 100vh;
    }

    /* ── Header ─────────────────────────────────────────────── */
    .fortress-header {
      display: flex;
      align-items: center;
      justify-content: space-between;
      padding: 16px 24px;
      border-bottom: 1px solid var(--border);
      background: var(--surface);
    }

    .fortress-brand {
      display: flex;
      align-items: center;
      gap: 12px;
    }

    .fortress-brand .shield {
      font-size: 28px;
      color: var(--blue);
    }

    .fortress-brand h1 {
      font-size: 18px;
      font-weight: 600;
      letter-spacing: -0.5px;
    }

    .fortress-brand .version {
      font-size: 12px;
      color: var(--text-secondary);
    }

    .header-actions {
      display: flex;
      gap: 8px;
    }

    .header-actions button {
      padding: 6px 16px;
      border-radius: 6px;
      border: 1px solid var(--border);
      background: var(--surface);
      color: var(--text-primary);
      font-size: 13px;
      cursor: pointer;
      transition: background 0.15s;
    }

    .header-actions button:hover {
      background: var(--surface-raised);
    }

    .header-actions .pause-btn {
      border-color: var(--red-dim);
      color: var(--red);
    }

    .header-actions .pause-btn:hover {
      background: rgba(248, 81, 73, 0.1);
    }

    .header-actions .pause-btn.paused {
      background: var(--red-dim);
      color: white;
    }

    /* ── Tab bar ─────────────────────────────────────────────── */
    .tab-bar {
      display: flex;
      border-bottom: 1px solid var(--border);
      background: var(--surface);
      padding: 0 24px;
    }

    .tab-bar button {
      padding: 10px 16px;
      border: none;
      background: none;
      color: var(--text-secondary);
      font-size: 14px;
      cursor: pointer;
      border-bottom: 2px solid transparent;
      transition: all 0.15s;
    }

    .tab-bar button:hover {
      color: var(--text-primary);
    }

    .tab-bar button.active {
      color: var(--text-primary);
      border-bottom-color: var(--blue);
    }

    /* ── Content ─────────────────────────────────────────────── */
    .fortress-content { padding: 24px; }

    /* ── Status Banner ─────────────────────────────────────── */
    .status-banner {
      display: flex;
      align-items: center;
      gap: 16px;
      padding: 20px 24px;
      border-radius: 8px;
      border: 1px solid var(--border);
      background: var(--surface);
      margin-bottom: 24px;
    }

    .status-indicator {
      width: 48px;
      height: 48px;
      border-radius: 50%;
      display: flex;
      align-items: center;
      justify-content: center;
      font-size: 24px;
      flex-shrink: 0;
    }

    .status-indicator.green { background: rgba(63, 185, 80, 0.15); color: var(--green); }
    .status-indicator.amber { background: rgba(210, 153, 34, 0.15); color: var(--amber); }
    .status-indicator.red { background: rgba(248, 81, 73, 0.15); color: var(--red); }

    .status-info h2 {
      font-size: 18px;
      font-weight: 600;
      margin-bottom: 4px;
    }

    .status-info p {
      font-size: 14px;
      color: var(--text-secondary);
    }

    .status-stats {
      display: flex;
      gap: 24px;
      margin-left: auto;
    }

    .stat {
      text-align: center;
    }

    .stat .value {
      font-size: 24px;
      font-weight: 600;
      font-variant-numeric: tabular-nums;
    }

    .stat .label {
      font-size: 11px;
      color: var(--text-secondary);
      text-transform: uppercase;
      letter-spacing: 0.5px;
    }

    /* ── Two-column layout ─────────────────────────────────── */
    .fortress-grid {
      display: grid;
      grid-template-columns: 1fr 360px;
      gap: 24px;
    }

    @media (max-width: 900px) {
      .fortress-grid { grid-template-columns: 1fr; }
    }

    /* ── Feed ─────────────────────────────────────────────── */
    .feed-panel {
      background: var(--surface);
      border: 1px solid var(--border);
      border-radius: 8px;
      overflow: hidden;
    }

    .panel-header {
      display: flex;
      align-items: center;
      justify-content: space-between;
      padding: 12px 16px;
      border-bottom: 1px solid var(--border);
    }

    .panel-header h3 {
      font-size: 14px;
      font-weight: 600;
    }

    .feed-list {
      max-height: 600px;
      overflow-y: auto;
      scroll-behavior: smooth;
    }

    .feed-item {
      display: flex;
      align-items: flex-start;
      gap: 10px;
      padding: 10px 16px;
      border-bottom: 1px solid var(--border);
      font-size: 13px;
      transition: background 0.1s;
    }

    .feed-item:hover {
      background: var(--surface-raised);
    }

    .feed-dot {
      width: 8px;
      height: 8px;
      border-radius: 50%;
      margin-top: 5px;
      flex-shrink: 0;
    }

    .feed-dot.green { background: var(--green); }
    .feed-dot.amber { background: var(--amber); }
    .feed-dot.red { background: var(--red); }

    .feed-detail {
      flex: 1;
      min-width: 0;
    }

    .feed-tool {
      font-family: 'SF Mono', 'Fira Code', monospace;
      font-size: 12px;
      color: var(--blue);
      word-break: break-all;
    }

    .feed-decision {
      font-size: 12px;
      color: var(--text-secondary);
      margin-top: 2px;
    }

    .feed-time {
      font-size: 11px;
      color: var(--text-muted);
      flex-shrink: 0;
      white-space: nowrap;
    }

    .feed-empty {
      padding: 40px 16px;
      text-align: center;
      color: var(--text-muted);
      font-size: 14px;
    }

    /* ── Alerts Panel ─────────────────────────────────────── */
    .alerts-panel {
      background: var(--surface);
      border: 1px solid var(--border);
      border-radius: 8px;
      overflow: hidden;
    }

    .alert-item {
      padding: 12px 16px;
      border-bottom: 1px solid var(--border);
    }

    .alert-item .alert-title {
      font-size: 13px;
      font-weight: 500;
      margin-bottom: 4px;
    }

    .alert-item .alert-desc {
      font-size: 12px;
      color: var(--text-secondary);
      margin-bottom: 8px;
    }

    .alert-actions {
      display: flex;
      gap: 8px;
    }

    .alert-actions button {
      padding: 4px 12px;
      border-radius: 4px;
      border: 1px solid var(--border);
      font-size: 12px;
      cursor: pointer;
      transition: all 0.15s;
    }

    .approve-btn {
      background: var(--green-dim);
      color: white;
      border-color: var(--green-dim) !important;
    }

    .approve-btn:hover { opacity: 0.9; }

    .deny-btn {
      background: none;
      color: var(--red);
      border-color: var(--red-dim) !important;
    }

    .deny-btn:hover {
      background: rgba(248, 81, 73, 0.1);
    }

    .alerts-empty {
      padding: 40px 16px;
      text-align: center;
      color: var(--text-muted);
      font-size: 14px;
    }

    /* ── Servers panel ─────────────────────────────────────── */
    .servers-panel {
      margin-top: 16px;
    }

    .server-row {
      display: flex;
      align-items: center;
      gap: 8px;
      padding: 8px 16px;
      border-bottom: 1px solid var(--border);
      font-size: 13px;
    }

    .server-status-dot {
      width: 8px;
      height: 8px;
      border-radius: 50%;
    }

    .server-status-dot.connected { background: var(--green); }
    .server-status-dot.connecting { background: var(--amber); }
    .server-status-dot.disconnected, .server-status-dot.error { background: var(--red); }

    .server-name {
      font-family: 'SF Mono', 'Fira Code', monospace;
      font-size: 12px;
    }

    .server-tier {
      margin-left: auto;
      font-size: 11px;
      color: var(--text-secondary);
    }
  </style>
</head>
<body>
  <!-- Header -->
  <div class="fortress-header">
    <div class="fortress-brand">
      <div class="shield">&#x1F6E1;</div>
      <div>
        <h1>Sanctuary</h1>
        <div class="version">v${esc(options.serverVersion)}</div>
      </div>
    </div>
    <div class="header-actions">
      <button class="pause-btn" id="pause-btn" title="Pause agent — requires approval for all operations">Pause Agent</button>
      <button id="advanced-btn">Advanced</button>
    </div>
  </div>

  <!-- Tab bar -->
  <div class="tab-bar">
    <button class="active" data-tab="fortress">Fortress</button>
    <button data-tab="advanced">Advanced</button>
  </div>

  <!-- Fortress View -->
  <div class="fortress-content" id="fortress-tab">
    <!-- Status Banner -->
    <div class="status-banner" id="status-banner">
      <div class="status-indicator green" id="status-indicator">&#x2713;</div>
      <div class="status-info">
        <h2 id="status-title">Agent Protected</h2>
        <p id="status-subtitle">${options.upstreamServerCount} server${options.upstreamServerCount !== 1 ? "s" : ""} monitored. All systems nominal.</p>
      </div>
      <div class="status-stats">
        <div class="stat">
          <div class="value" id="stat-total">0</div>
          <div class="label">Calls</div>
        </div>
        <div class="stat">
          <div class="value" id="stat-blocked">0</div>
          <div class="label">Blocked</div>
        </div>
        <div class="stat">
          <div class="value" id="stat-pending">0</div>
          <div class="label">Pending</div>
        </div>
      </div>
    </div>

    <!-- Two-column layout -->
    <div class="fortress-grid">
      <!-- Live Feed -->
      <div class="feed-panel">
        <div class="panel-header">
          <h3>Live Activity</h3>
          <span style="font-size: 12px; color: var(--text-muted);" id="feed-count">0 events</span>
        </div>
        <div class="feed-list" id="feed-list">
          <div class="feed-empty">Waiting for tool calls...</div>
        </div>
      </div>

      <!-- Right column: Alerts + Servers -->
      <div>
        <!-- Alerts -->
        <div class="alerts-panel">
          <div class="panel-header">
            <h3>Needs Attention</h3>
            <span style="font-size: 12px; color: var(--text-muted);" id="alert-count">0</span>
          </div>
          <div id="alerts-list">
            <div class="alerts-empty">No pending actions</div>
          </div>
        </div>

        <!-- Servers -->
        <div class="alerts-panel servers-panel">
          <div class="panel-header">
            <h3>Upstream Servers</h3>
          </div>
          <div id="servers-list">
            <div class="alerts-empty">No servers configured</div>
          </div>
        </div>
      </div>
    </div>
  </div>

  <script>
    // ── State ───────────────────────────────────────────────────────
    const API_BASE = window.location.origin;
    const SESSION_TOKEN = sessionStorage.getItem('sanctuary_session') || '';
    const MAX_FEED_ITEMS = 50;

    let feedItems = [];
    let totalCalls = 0;
    let blockedCalls = 0;
    let pendingApprovals = [];
    let upstreamServers = [];
    let paused = false;

    // ── SSE Connection ──────────────────────────────────────────────
    function connectSSE() {
      const url = API_BASE + '/events' + (SESSION_TOKEN ? '?session=' + SESSION_TOKEN : '');
      const eventSource = new EventSource(url);

      eventSource.addEventListener('proxy-call', (e) => {
        try {
          const data = JSON.parse(e.data);
          addFeedItem(data);
        } catch {}
      });

      eventSource.addEventListener('proxy-server-status', (e) => {
        try {
          const data = JSON.parse(e.data);
          updateServerStatus(data.server, data.state, data.tool_count, data.error);
        } catch {}
      });

      eventSource.addEventListener('injection-alert', (e) => {
        try {
          const data = JSON.parse(e.data);
          addFeedItem({
            tool: data.tool_name || 'unknown',
            server: 'detection',
            decision: 'blocked',
            reason: 'Injection detected: ' + (data.signals || []).join(', '),
            timestamp: new Date().toISOString(),
          });
        } catch {}
      });

      eventSource.addEventListener('approval-request', (e) => {
        try {
          const data = JSON.parse(e.data);
          addPendingApproval(data);
        } catch {}
      });

      eventSource.addEventListener('approval-resolved', (e) => {
        try {
          const data = JSON.parse(e.data);
          removePendingApproval(data.id);
        } catch {}
      });

      eventSource.onerror = () => {
        eventSource.close();
        setTimeout(connectSSE, 3000);
      };
    }

    // ── Feed ────────────────────────────────────────────────────────
    function addFeedItem(data) {
      totalCalls++;
      if (data.decision === 'blocked' || data.decision === 'denied') {
        blockedCalls++;
      }

      feedItems.unshift({
        tool: data.tool || 'unknown',
        server: data.server || '',
        decision: data.decision || 'allowed',
        reason: data.reason || '',
        time: data.timestamp || new Date().toISOString(),
      });

      if (feedItems.length > MAX_FEED_ITEMS) {
        feedItems = feedItems.slice(0, MAX_FEED_ITEMS);
      }

      renderFeed();
      updateStats();
      updateStatus();
    }

    function renderFeed() {
      const container = document.getElementById('feed-list');
      if (feedItems.length === 0) {
        container.innerHTML = '<div class="feed-empty">Waiting for tool calls...</div>';
        return;
      }

      container.innerHTML = feedItems.map(item => {
        const dotColor = item.decision === 'allowed' ? 'green'
          : item.decision === 'pending' ? 'amber' : 'red';
        const decisionText = item.decision === 'allowed' ? 'Auto-allowed'
          : item.decision === 'pending' ? 'Awaiting approval'
          : item.decision === 'blocked' ? 'Blocked' : item.decision;
        const timeStr = new Date(item.time).toLocaleTimeString();

        return '<div class="feed-item">' +
          '<div class="feed-dot ' + dotColor + '"></div>' +
          '<div class="feed-detail">' +
            '<div class="feed-tool">' + esc(item.tool) + '</div>' +
            '<div class="feed-decision">' + esc(decisionText) +
              (item.reason ? ' — ' + esc(item.reason) : '') + '</div>' +
          '</div>' +
          '<div class="feed-time">' + esc(timeStr) + '</div>' +
        '</div>';
      }).join('');

      document.getElementById('feed-count').textContent = feedItems.length + ' events';
    }

    // ── Alerts (Pending Approvals) ──────────────────────────────────
    function addPendingApproval(data) {
      pendingApprovals.push(data);
      renderAlerts();
      updateStats();
      updateStatus();
    }

    function removePendingApproval(id) {
      pendingApprovals = pendingApprovals.filter(a => a.id !== id);
      renderAlerts();
      updateStats();
      updateStatus();
    }

    function renderAlerts() {
      const container = document.getElementById('alerts-list');
      if (pendingApprovals.length === 0) {
        container.innerHTML = '<div class="alerts-empty">No pending actions</div>';
        document.getElementById('alert-count').textContent = '0';
        return;
      }

      document.getElementById('alert-count').textContent = pendingApprovals.length.toString();

      container.innerHTML = pendingApprovals.map(approval => {
        return '<div class="alert-item">' +
          '<div class="alert-title">Approval required: ' + esc(approval.operation || approval.tool_name || 'unknown') + '</div>' +
          '<div class="alert-desc">' + esc(approval.reason || 'This operation requires your approval before it can proceed.') + '</div>' +
          '<div class="alert-actions">' +
            '<button class="approve-btn" onclick="handleApproval(\\'' + esc(approval.id) + '\\', true)">Approve</button>' +
            '<button class="deny-btn" onclick="handleApproval(\\'' + esc(approval.id) + '\\', false)">Deny</button>' +
          '</div>' +
        '</div>';
      }).join('');
    }

    async function handleApproval(id, approved) {
      const endpoint = approved ? '/api/approve/' : '/api/deny/';
      try {
        await fetch(API_BASE + endpoint + id, {
          method: 'POST',
          headers: SESSION_TOKEN ? { 'Authorization': 'Bearer ' + SESSION_TOKEN } : {},
        });
        removePendingApproval(id);
      } catch (err) {
        console.error('Approval action failed:', err);
      }
    }

    // ── Servers ─────────────────────────────────────────────────────
    function updateServerStatus(serverName, state, toolCount, error) {
      const existing = upstreamServers.find(s => s.name === serverName);
      if (existing) {
        existing.state = state;
        existing.tool_count = toolCount;
        existing.error = error;
      } else {
        upstreamServers.push({ name: serverName, state, tool_count: toolCount, error });
      }
      renderServers();
      updateStatus();
    }

    function renderServers() {
      const container = document.getElementById('servers-list');
      if (upstreamServers.length === 0) {
        container.innerHTML = '<div class="alerts-empty">No servers configured</div>';
        return;
      }

      container.innerHTML = upstreamServers.map(server => {
        const stateClass = server.state || 'disconnected';
        const stateLabel = server.state === 'connected' ? 'Connected'
          : server.state === 'connecting' ? 'Connecting...'
          : server.state === 'error' ? 'Error' : 'Disconnected';

        return '<div class="server-row">' +
          '<div class="server-status-dot ' + stateClass + '"></div>' +
          '<span class="server-name">' + esc(server.name) + '</span>' +
          '<span class="server-tier">' + esc(stateLabel) +
            (server.tool_count ? ' (' + server.tool_count + ' tools)' : '') + '</span>' +
        '</div>';
      }).join('');
    }

    // ── Status Banner ─────────────────────────────────────────────
    function updateStats() {
      document.getElementById('stat-total').textContent = totalCalls.toString();
      document.getElementById('stat-blocked').textContent = blockedCalls.toString();
      document.getElementById('stat-pending').textContent = pendingApprovals.length.toString();
    }

    function updateStatus() {
      const indicator = document.getElementById('status-indicator');
      const title = document.getElementById('status-title');
      const subtitle = document.getElementById('status-subtitle');

      const hasErrors = upstreamServers.some(s => s.state === 'error');
      const hasPending = pendingApprovals.length > 0;
      const hasBlocked = blockedCalls > 0;

      if (paused) {
        indicator.className = 'status-indicator red';
        indicator.innerHTML = '&#x23F8;';
        title.textContent = 'Agent Paused';
        subtitle.textContent = 'All operations require approval. Click Resume to restore normal mode.';
      } else if (hasErrors) {
        indicator.className = 'status-indicator red';
        indicator.innerHTML = '&#x26A0;';
        title.textContent = 'Connection Issues';
        subtitle.textContent = 'One or more upstream servers have errors.';
      } else if (hasPending) {
        indicator.className = 'status-indicator amber';
        indicator.innerHTML = '&#x23F3;';
        title.textContent = 'Action Required';
        subtitle.textContent = pendingApprovals.length + ' operation' + (pendingApprovals.length > 1 ? 's' : '') + ' awaiting your approval.';
      } else {
        indicator.className = 'status-indicator green';
        indicator.innerHTML = '&#x2713;';
        title.textContent = 'Agent Protected';
        const serverCount = upstreamServers.filter(s => s.state === 'connected').length || ${options.upstreamServerCount};
        subtitle.textContent = serverCount + ' server' + (serverCount !== 1 ? 's' : '') + ' monitored. All systems nominal.';
      }
    }

    // ── Pause/Resume ──────────────────────────────────────────────
    document.getElementById('pause-btn').addEventListener('click', () => {
      paused = !paused;
      const btn = document.getElementById('pause-btn');
      if (paused) {
        btn.textContent = 'Resume Agent';
        btn.classList.add('paused');
      } else {
        btn.textContent = 'Pause Agent';
        btn.classList.remove('paused');
      }
      updateStatus();
      // TODO: POST to /api/cocoon/pause to set all tiers to 1
    });

    // ── Tab switching ─────────────────────────────────────────────
    document.getElementById('advanced-btn').addEventListener('click', () => {
      window.location.href = '/dashboard?session=' + SESSION_TOKEN;
    });

    document.querySelectorAll('.tab-bar button').forEach(btn => {
      btn.addEventListener('click', () => {
        const tab = btn.dataset.tab;
        if (tab === 'advanced') {
          window.location.href = '/dashboard?session=' + SESSION_TOKEN;
        }
      });
    });

    // ── Escape helper ─────────────────────────────────────────────
    function esc(str) {
      if (!str) return '';
      const d = document.createElement('div');
      d.textContent = String(str);
      return d.innerHTML;
    }

    // ── Init ──────────────────────────────────────────────────────
    async function init() {
      // Load initial server state
      try {
        const resp = await fetch(API_BASE + '/api/proxy/servers', {
          headers: SESSION_TOKEN ? { 'Authorization': 'Bearer ' + SESSION_TOKEN } : {},
        });
        if (resp.ok) {
          const data = await resp.json();
          upstreamServers = data.servers || [];
          renderServers();
        }
      } catch {}

      // Load pending approvals
      try {
        const resp = await fetch(API_BASE + '/api/pending', {
          headers: SESSION_TOKEN ? { 'Authorization': 'Bearer ' + SESSION_TOKEN } : {},
        });
        if (resp.ok) {
          const data = await resp.json();
          pendingApprovals = data.pending || [];
          renderAlerts();
          updateStats();
        }
      } catch {}

      updateStatus();
      connectSSE();
    }

    init();
  </script>
</body>
</html>`;
}

function esc(str: string): string {
  return str
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}
