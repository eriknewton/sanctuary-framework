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
 * Generate the Fortress View HTML for the wrap dashboard.
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
    <!--
      Honest default (never-overclaim): the banner starts AMBER, not green. Green
      ("Agent Protected") is reserved for the case where the Castle Wall
      enforcement layer is PROVEN armed via the G4 posture signal
      (/api/posture/castle-wall, arm_state === "armed"). Until that evidence
      arrives (or if it reports unknown/degraded/unavailable), we render
      "Wrapped, enforcement not confirmed" so the page can never claim the
      enforcing layer is on while it is unproven. updateStatus() flips to green
      only on confirmed-armed posture.
    -->
    <div class="status-banner" id="status-banner">
      <div class="status-indicator amber" id="status-indicator">&#x26A0;</div>
      <div class="status-info">
        <h2 id="status-title">Wrapped, enforcement not confirmed</h2>
        <p id="status-subtitle">${options.upstreamServerCount} server${options.upstreamServerCount !== 1 ? "s" : ""} monitored. Confirming Castle Wall enforcement&hellip;</p>
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
    let AUTH_TOKEN = sessionStorage.getItem('authToken') || '';
    const MAX_FEED_ITEMS = 50;

    let feedItems = [];
    let totalCalls = 0;
    let blockedCalls = 0;
    let pendingApprovals = [];
    let upstreamServers = [];
    // Castle Wall enforcement posture (G4 / /api/posture/castle-wall arm_state).
    // Honest default is 'unknown': the page must not show green "protected"
    // until this resolves to 'armed' from real enforcement evidence. Values:
    // 'armed' (proven, green) | 'degraded' (present but not enforcing, red) |
    // 'unknown' (unproven, amber) | 'not_installed' (amber) | 'unavailable'
    // (posture endpoint unreachable/erroring, treated as unknown, amber).
    let wallArmState = 'unknown';

    function operatorAuthHeaders(extra) {
      const headers = Object.assign({}, extra || {});
      if (AUTH_TOKEN) {
        headers['Authorization'] = 'Bearer ' + AUTH_TOKEN;
      }
      return headers;
    }

    function promptForOperatorToken() {
      const entered = window.prompt('Operator token required for this action.');
      if (!entered || !entered.trim()) return false;
      AUTH_TOKEN = entered.trim();
      sessionStorage.setItem('authToken', AUTH_TOKEN);
      return true;
    }

    async function strictMutationFetch(path, init) {
      const request = init || {};
      const send = () => fetch(API_BASE + path, Object.assign({}, request, {
        headers: operatorAuthHeaders(request.headers),
      }));
      let response = await send();
      if (response.status === 401 && promptForOperatorToken()) {
        response = await send();
      }
      return response;
    }

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
        const response = await strictMutationFetch(endpoint + encodeURIComponent(id), {
          method: 'POST',
        });
        if (response.ok) {
          removePendingApproval(id);
        } else {
          console.error('Approval action failed:', response.status);
        }
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

    // ── Castle Wall enforcement posture (G4) ──────────────────────────
    // Fetch the enforcement-evidenced arm state from the same posture signal
    // the dashboard hero shield and /posture home consume. Green
    // ("Agent Protected") is earned ONLY by arm_state === 'armed'; anything
    // else (unknown / degraded / not_installed / unreachable) keeps the banner
    // off-green so the page never claims protection the enforcing layer cannot
    // prove (never-overclaim).
    async function refreshWallPosture() {
      try {
        const resp = await fetch(API_BASE + '/api/posture/castle-wall', {
          headers: SESSION_TOKEN ? { 'Authorization': 'Bearer ' + SESSION_TOKEN } : {},
        });
        if (resp.ok) {
          const data = await resp.json();
          wallArmState = (data && typeof data.arm_state === 'string') ? data.arm_state : 'unknown';
        } else {
          // Posture endpoint reachable but not serving an armed verdict
          // (e.g. 503 audit-locked, 404 on an older daemon): treat as
          // unproven, not protected.
          wallArmState = 'unavailable';
        }
      } catch {
        wallArmState = 'unavailable';
      }
      updateStatus();
    }

    function updateStatus() {
      const indicator = document.getElementById('status-indicator');
      const title = document.getElementById('status-title');
      const subtitle = document.getElementById('status-subtitle');

      const hasErrors = upstreamServers.some(s => s.state === 'error');
      const hasPending = pendingApprovals.length > 0;
      const wallArmed = wallArmState === 'armed';
      const wallDegraded = wallArmState === 'degraded';
      // S5-P distinct non-green: coarse wall enforcing, but a fine-grained
      // agent's exclusive-egress stack is not live. Never green.
      const wallCoarseOnly = wallArmState === 'coarse_only';

      if (hasErrors) {
        indicator.className = 'status-indicator red';
        indicator.innerHTML = '&#x26A0;';
        title.textContent = 'Connection Issues';
        subtitle.textContent = 'One or more upstream servers have errors.';
      } else if (wallDegraded) {
        // The enforcement layer reported it is present but NOT enforcing
        // (crashed / unbound / clobbered). This is a red state: traffic is not
        // being filtered even though the agent is wrapped.
        indicator.className = 'status-indicator red';
        indicator.innerHTML = '&#x26A0;';
        title.textContent = 'Enforcement not active';
        subtitle.textContent = 'Castle Wall is not filtering traffic. Your agent is wrapped but not protected.';
      } else if (wallCoarseOnly) {
        // S5-P: the DISTINCT coarse-only state. The coarse wall is enforcing
        // (the agent is confined to its declared destinations), but the
        // fine-grained exclusive-egress stack (gate + pf + generation) is not
        // live. Amber, named plainly - never green, never a vague unknown.
        indicator.className = 'status-indicator amber';
        indicator.innerHTML = '&#x26A0;';
        title.textContent = 'Coarse protection only';
        subtitle.textContent = 'Castle Wall is enforcing the coarse wall, but the fine-grained exclusive-egress gate is not live.';
      } else if (hasPending) {
        indicator.className = 'status-indicator amber';
        indicator.innerHTML = '&#x23F3;';
        title.textContent = 'Action Required';
        subtitle.textContent = pendingApprovals.length + ' operation' + (pendingApprovals.length > 1 ? 's' : '') + ' awaiting your approval.';
      } else if (wallArmed) {
        // Green is earned: Castle Wall posture proved 'armed' from fresh
        // enforcement evidence. This preserves the legitimate green path the
        // CW-POSTURE drill exercises.
        indicator.className = 'status-indicator green';
        indicator.innerHTML = '&#x2713;';
        title.textContent = 'Agent Protected';
        const serverCount = upstreamServers.filter(s => s.state === 'connected').length || ${options.upstreamServerCount};
        subtitle.textContent = serverCount + ' server' + (serverCount !== 1 ? 's' : '') + ' monitored. Castle Wall enforcing.';
      } else {
        // Enforcement is unproven (unknown / not_installed / posture
        // unavailable). The agent is wrapped, but we cannot confirm the
        // enforcing layer is on; render amber, never green.
        indicator.className = 'status-indicator amber';
        indicator.innerHTML = '&#x26A0;';
        title.textContent = 'Wrapped, enforcement not confirmed';
        const serverCount = upstreamServers.filter(s => s.state === 'connected').length || ${options.upstreamServerCount};
        subtitle.textContent = serverCount + ' server' + (serverCount !== 1 ? 's' : '') + ' monitored. Castle Wall enforcement not confirmed.';
      }
    }

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

      // Pull the Castle Wall enforcement posture before the first paint of the
      // banner, so the page does not flash green/amber incorrectly. Then poll
      // it on an interval so a wall that arms (or later degrades) is reflected.
      await refreshWallPosture();
      setInterval(refreshWallPosture, 15000);

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
