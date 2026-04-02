/**
 * Sanctuary MCP Server — Principal Dashboard HTML Template
 *
 * Embedded single-page HTML/CSS/JS for the Principal Dashboard.
 * No build step, no external dependencies, no CDN imports.
 * Served as a single HTML document by the DashboardApprovalChannel.
 *
 * Design: Dark, minimal, terminal-feel (Grafana dark mode aesthetic)
 * Architecture:
 * - Top status bar (fixed, always visible)
 * - Main content area: live activity feed (60%) + protection status sidebar (40%)
 * - Pending approvals: overlay panel that slides in from right when needed
 * - Threat panel: collapsible footer section
 * - SSE for real-time updates
 * - SEC-012: Auth via Authorization header + short-lived sessions
 */

/**
 * Generate the login page HTML for unauthenticated browser access.
 * Provides a clean token input form that exchanges the token for a session cookie.
 */
export function generateLoginHTML(options: {
  serverVersion: string;
}): string {
  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Sanctuary — Login</title>
<link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;600&display=swap" rel="stylesheet">
<style>
  :root {
    --bg: #0d1117;
    --surface: #161b22;
    --border: #30363d;
    --text-primary: #e6edf3;
    --text-secondary: #8b949e;
    --green: #3fb950;
    --red: #f85149;
    --blue: #58a6ff;
    --mono: 'JetBrains Mono', 'Fira Code', 'Consolas', monospace;
    --sans: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
    --radius: 6px;
  }
  * { box-sizing: border-box; margin: 0; padding: 0; }
  html, body { width: 100%; height: 100%; }
  body {
    font-family: var(--sans);
    background: var(--bg);
    color: var(--text-primary);
    display: flex;
    align-items: center;
    justify-content: center;
  }
  .login-container {
    width: 100%;
    max-width: 400px;
    padding: 40px 32px;
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 12px;
  }
  .login-logo {
    text-align: center;
    font-size: 20px;
    font-weight: 700;
    letter-spacing: -0.5px;
    margin-bottom: 8px;
  }
  .login-logo span { color: var(--blue); }
  .login-version {
    text-align: center;
    font-size: 11px;
    color: var(--text-secondary);
    font-family: var(--mono);
    margin-bottom: 32px;
  }
  .login-label {
    display: block;
    font-size: 13px;
    font-weight: 600;
    color: var(--text-secondary);
    margin-bottom: 8px;
  }
  .login-input {
    width: 100%;
    padding: 10px 14px;
    background: var(--bg);
    border: 1px solid var(--border);
    border-radius: var(--radius);
    color: var(--text-primary);
    font-family: var(--mono);
    font-size: 14px;
    outline: none;
    transition: border-color 0.15s;
  }
  .login-input:focus { border-color: var(--blue); }
  .login-input::placeholder { color: var(--text-secondary); opacity: 0.5; }
  .login-btn {
    width: 100%;
    margin-top: 20px;
    padding: 10px;
    background: var(--blue);
    color: var(--bg);
    border: none;
    border-radius: var(--radius);
    font-size: 14px;
    font-weight: 600;
    cursor: pointer;
    transition: opacity 0.15s;
    font-family: var(--sans);
  }
  .login-btn:hover { opacity: 0.9; }
  .login-btn:disabled { opacity: 0.5; cursor: not-allowed; }
  .login-error {
    margin-top: 16px;
    padding: 10px 14px;
    background: rgba(248, 81, 73, 0.1);
    border: 1px solid var(--red);
    border-radius: var(--radius);
    font-size: 12px;
    color: var(--red);
    display: none;
  }
  .login-hint {
    margin-top: 24px;
    padding-top: 16px;
    border-top: 1px solid var(--border);
    font-size: 11px;
    color: var(--text-secondary);
    line-height: 1.5;
  }
  .login-hint code {
    font-family: var(--mono);
    background: var(--bg);
    padding: 1px 4px;
    border-radius: 3px;
    font-size: 10px;
  }
</style>
</head>
<body>
<div class="login-container">
  <div class="login-logo"><span>&#9670;</span> SANCTUARY</div>
  <div class="login-version">Principal Dashboard v${options.serverVersion}</div>
  <form id="loginForm" onsubmit="return handleLogin(event)">
    <label class="login-label" for="tokenInput">Dashboard Auth Token</label>
    <input class="login-input" type="password" id="tokenInput"
           placeholder="Enter your auth token" autocomplete="off" autofocus required>
    <button class="login-btn" type="submit" id="loginBtn">Open Dashboard</button>
  </form>
  <div class="login-error" id="loginError"></div>
  <div class="login-hint">
    Your token is set via <code>SANCTUARY_DASHBOARD_AUTH_TOKEN</code> environment variable,
    or check your server's startup output.
  </div>
</div>
<script>
async function handleLogin(e) {
  e.preventDefault();
  var btn = document.getElementById('loginBtn');
  var errEl = document.getElementById('loginError');
  var token = document.getElementById('tokenInput').value.trim();
  if (!token) return false;
  btn.disabled = true;
  btn.textContent = 'Authenticating...';
  errEl.style.display = 'none';
  try {
    var resp = await fetch('/auth/session', {
      method: 'POST',
      headers: { 'Authorization': 'Bearer ' + token }
    });
    if (!resp.ok) {
      var data = await resp.json().catch(function() { return {}; });
      throw new Error(data.error || 'Authentication failed');
    }
    var result = await resp.json();
    // Store token in sessionStorage for auto-renewal inside the dashboard
    try { sessionStorage.setItem('sanctuary_token', token); } catch(_) {}
    // Set session cookie
    var maxAge = result.expires_in_seconds || 300;
    document.cookie = 'sanctuary_session=' + result.session_id +
      '; path=/; SameSite=Strict; max-age=' + maxAge;
    // Reload to enter the dashboard
    window.location.reload();
  } catch (err) {
    errEl.textContent = err.message || 'Authentication failed. Check your token.';
    errEl.style.display = 'block';
    btn.disabled = false;
    btn.textContent = 'Open Dashboard';
  }
  return false;
}
</script>
</body>
</html>`;
}

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
<link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;600&display=swap" rel="stylesheet">
<style>
  :root {
    --bg: #0d1117;
    --surface: #161b22;
    --border: #30363d;
    --text-primary: #e6edf3;
    --text-secondary: #8b949e;
    --green: #3fb950;
    --amber: #d29922;
    --red: #f85149;
    --blue: #58a6ff;
    --mono: 'JetBrains Mono', 'Fira Code', 'Consolas', monospace;
    --sans: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
    --radius: 6px;
  }

  * {
    box-sizing: border-box;
    margin: 0;
    padding: 0;
  }

  html, body {
    width: 100%;
    height: 100%;
    overflow: hidden;
  }

  body {
    font-family: var(--sans);
    background: var(--bg);
    color: var(--text-primary);
    display: flex;
    flex-direction: column;
  }

  /* ── Top Status Bar (fixed) ─────────────────────────────────────── */

  .status-bar {
    position: fixed;
    top: 0;
    left: 0;
    right: 0;
    height: 56px;
    background: var(--surface);
    border-bottom: 1px solid var(--border);
    display: flex;
    align-items: center;
    padding: 0 20px;
    gap: 24px;
    z-index: 1000;
  }

  .status-bar-left {
    display: flex;
    align-items: center;
    gap: 12px;
    flex: 0 0 auto;
  }

  .sanctuary-logo {
    font-weight: 700;
    font-size: 16px;
    letter-spacing: -0.5px;
    color: var(--text-primary);
  }

  .sanctuary-logo span {
    color: var(--blue);
  }

  .version {
    font-size: 11px;
    color: var(--text-secondary);
    font-family: var(--mono);
  }

  .status-bar-center {
    flex: 1;
    display: flex;
    align-items: center;
    justify-content: center;
  }

  .sovereignty-badge {
    display: flex;
    align-items: center;
    gap: 8px;
    padding: 6px 12px;
    background: rgba(88, 166, 255, 0.1);
    border: 1px solid var(--blue);
    border-radius: 20px;
    font-size: 13px;
    font-weight: 600;
  }

  .sovereignty-score {
    display: flex;
    align-items: center;
    justify-content: center;
    width: 28px;
    height: 28px;
    border-radius: 50%;
    font-family: var(--mono);
    font-weight: 700;
    font-size: 12px;
    background: var(--blue);
    color: var(--bg);
  }

  .sovereignty-score.high {
    background: var(--green);
  }

  .sovereignty-score.medium {
    background: var(--amber);
  }

  .sovereignty-score.low {
    background: var(--red);
  }

  .status-bar-right {
    display: flex;
    align-items: center;
    gap: 16px;
    flex: 0 0 auto;
  }

  .protections-indicator {
    display: flex;
    align-items: center;
    gap: 6px;
    font-size: 12px;
    color: var(--text-secondary);
    font-family: var(--mono);
  }

  .protections-indicator .count {
    color: var(--text-primary);
    font-weight: 600;
  }

  .uptime {
    display: flex;
    align-items: center;
    gap: 6px;
    font-size: 12px;
    color: var(--text-secondary);
    font-family: var(--mono);
  }

  .status-dot {
    width: 8px;
    height: 8px;
    border-radius: 50%;
    background: var(--green);
    animation: pulse 2s ease-in-out infinite;
  }

  .status-dot.disconnected {
    background: var(--red);
    animation: none;
  }

  @keyframes pulse {
    0%, 100% { opacity: 1; }
    50% { opacity: 0.5; }
  }

  .pending-badge {
    display: inline-flex;
    align-items: center;
    justify-content: center;
    min-width: 24px;
    height: 24px;
    padding: 0 6px;
    background: var(--red);
    color: white;
    border-radius: 12px;
    font-size: 11px;
    font-weight: 700;
    animation: pulse 1s ease-in-out infinite;
  }

  .pending-badge.hidden {
    display: none;
  }

  /* ── Main Layout ────────────────────────────────────────────────── */

  .main-container {
    flex: 1;
    display: flex;
    margin-top: 56px;
    overflow: hidden;
  }

  .activity-feed {
    flex: 3;
    display: flex;
    flex-direction: column;
    border-right: 1px solid var(--border);
    overflow: hidden;
  }

  .feed-header {
    padding: 16px 20px;
    border-bottom: 1px solid var(--border);
    display: flex;
    align-items: center;
    gap: 8px;
    font-size: 12px;
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 0.5px;
    color: var(--text-secondary);
  }

  .feed-header-dot {
    width: 6px;
    height: 6px;
    border-radius: 50%;
    background: var(--green);
  }

  .activity-list {
    flex: 1;
    overflow-y: auto;
    overflow-x: hidden;
  }

  .activity-item {
    padding: 12px 20px;
    border-bottom: 1px solid rgba(48, 54, 61, 0.5);
    font-size: 13px;
    font-family: var(--mono);
    cursor: pointer;
    transition: background 0.15s;
    display: flex;
    align-items: flex-start;
    gap: 10px;
  }

  .activity-item:hover {
    background: rgba(88, 166, 255, 0.05);
  }

  .activity-item-icon {
    flex: 0 0 auto;
    width: 16px;
    text-align: center;
    font-size: 12px;
    color: var(--text-secondary);
    margin-top: 1px;
  }

  .activity-item-content {
    flex: 1;
    min-width: 0;
  }

  .activity-time {
    color: var(--text-secondary);
    font-size: 11px;
    margin-bottom: 2px;
  }

  .activity-main {
    display: flex;
    gap: 8px;
    align-items: baseline;
    margin-bottom: 4px;
  }

  .activity-tier {
    display: inline-flex;
    align-items: center;
    justify-content: center;
    width: 24px;
    height: 16px;
    font-size: 10px;
    font-weight: 700;
    border-radius: 3px;
    text-transform: uppercase;
    flex: 0 0 auto;
  }

  .activity-tier.t1 {
    background: rgba(248, 81, 73, 0.2);
    color: var(--red);
  }

  .activity-tier.t2 {
    background: rgba(210, 153, 34, 0.2);
    color: var(--amber);
  }

  .activity-tier.t3 {
    background: rgba(63, 185, 80, 0.2);
    color: var(--green);
  }

  .activity-tool {
    color: var(--text-primary);
    font-weight: 600;
  }

  .activity-outcome {
    color: var(--green);
  }

  .activity-outcome.denied {
    color: var(--red);
  }

  .activity-detail {
    font-size: 12px;
    color: var(--text-secondary);
    margin-left: 0;
  }

  .activity-item.expanded .activity-detail {
    display: block;
    margin-top: 8px;
    padding: 10px;
    background: rgba(88, 166, 255, 0.08);
    border-left: 2px solid var(--blue);
    border-radius: 4px;
  }

  .activity-empty {
    display: flex;
    flex-direction: column;
    align-items: center;
    justify-content: center;
    height: 100%;
    color: var(--text-secondary);
  }

  .activity-empty-icon {
    font-size: 32px;
    margin-bottom: 12px;
  }

  .activity-empty-text {
    font-size: 14px;
  }

  /* ── Protection Status Sidebar (40%) ────────────────────────────── */

  .protection-sidebar {
    flex: 2;
    display: flex;
    flex-direction: column;
    background: rgba(22, 27, 34, 0.5);
    overflow: hidden;
  }

  .sidebar-header {
    padding: 16px 20px;
    border-bottom: 1px solid var(--border);
    font-size: 12px;
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 0.5px;
    color: var(--text-secondary);
    display: flex;
    align-items: center;
    gap: 8px;
  }

  .sidebar-content {
    flex: 1;
    overflow-y: auto;
    padding: 16px 16px;
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 12px;
  }

  .protection-card {
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: var(--radius);
    padding: 14px;
    display: flex;
    flex-direction: column;
    gap: 8px;
  }

  .protection-card-icon {
    font-size: 14px;
  }

  .protection-card-label {
    font-size: 11px;
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 0.5px;
    color: var(--text-secondary);
  }

  .protection-card-status {
    display: flex;
    align-items: center;
    gap: 6px;
    font-size: 12px;
    font-weight: 600;
  }

  .protection-card-status.active {
    color: var(--green);
  }

  .protection-card-status.inactive {
    color: var(--text-secondary);
  }

  .protection-card-stat {
    font-size: 11px;
    color: var(--text-secondary);
    font-family: var(--mono);
    margin-top: 4px;
  }

  /* ── Pending Approvals Overlay ──────────────────────────────────── */

  .pending-overlay {
    position: fixed;
    top: 56px;
    right: 0;
    bottom: 0;
    width: 0;
    background: var(--surface);
    border-left: 1px solid var(--border);
    z-index: 999;
    overflow-y: auto;
    transition: width 0.3s ease-out;
    display: flex;
    flex-direction: column;
  }

  .pending-overlay.active {
    width: 380px;
  }

  @media (max-width: 1400px) {
    .pending-overlay.active {
      width: 100%;
      right: auto;
      left: 0;
    }
  }

  .pending-overlay-header {
    padding: 16px 20px;
    border-bottom: 1px solid var(--border);
    display: flex;
    align-items: center;
    justify-content: space-between;
    flex: 0 0 auto;
  }

  .pending-overlay-title {
    font-size: 13px;
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 0.5px;
    color: var(--text-primary);
  }

  .pending-overlay-close {
    background: none;
    border: none;
    color: var(--text-secondary);
    cursor: pointer;
    font-size: 18px;
    padding: 0;
    display: flex;
    align-items: center;
    justify-content: center;
  }

  .pending-overlay-close:hover {
    color: var(--text-primary);
  }

  .pending-list {
    flex: 1;
    overflow-y: auto;
  }

  .pending-item {
    padding: 16px 20px;
    border-bottom: 1px solid rgba(48, 54, 61, 0.5);
    display: flex;
    flex-direction: column;
    gap: 10px;
  }

  .pending-item-header {
    display: flex;
    align-items: center;
    gap: 8px;
  }

  .pending-item-op {
    font-family: var(--mono);
    font-size: 12px;
    font-weight: 600;
    color: var(--text-primary);
    flex: 1;
  }

  .pending-item-tier {
    display: inline-flex;
    align-items: center;
    justify-content: center;
    width: 28px;
    height: 20px;
    font-size: 9px;
    font-weight: 700;
    border-radius: 3px;
    text-transform: uppercase;
    color: white;
  }

  .pending-item-tier.tier1 {
    background: var(--red);
  }

  .pending-item-tier.tier2 {
    background: var(--amber);
  }

  .pending-item-reason {
    font-size: 12px;
    color: var(--text-secondary);
  }

  .pending-item-timer {
    display: flex;
    align-items: center;
    gap: 6px;
    font-size: 11px;
    font-family: var(--mono);
    color: var(--text-secondary);
  }

  .pending-item-timer-bar {
    flex: 1;
    height: 4px;
    background: rgba(48, 54, 61, 0.8);
    border-radius: 2px;
    overflow: hidden;
  }

  .pending-item-timer-fill {
    height: 100%;
    background: var(--blue);
    transition: width 0.1s linear;
  }

  .pending-item-timer.urgent .pending-item-timer-fill {
    background: var(--red);
  }

  .pending-item-actions {
    display: flex;
    gap: 8px;
  }

  .btn {
    flex: 1;
    padding: 8px 12px;
    border: none;
    border-radius: var(--radius);
    font-size: 12px;
    font-weight: 600;
    cursor: pointer;
    transition: all 0.15s;
    font-family: var(--sans);
  }

  .btn-approve {
    background: var(--green);
    color: var(--bg);
  }

  .btn-approve:hover {
    background: #4ecf5e;
  }

  .btn-deny {
    background: var(--red);
    color: white;
  }

  .btn-deny:hover {
    background: #f9605e;
  }

  /* ── Threat Panel (collapsible footer) ──────────────────────────── */

  .threat-panel {
    position: fixed;
    bottom: 0;
    left: 0;
    right: 0;
    background: var(--surface);
    border-top: 1px solid var(--border);
    max-height: 240px;
    z-index: 500;
    display: flex;
    flex-direction: column;
    transition: max-height 0.3s ease-out;
  }

  .threat-panel.collapsed {
    max-height: 40px;
  }

  .threat-header {
    padding: 12px 20px;
    cursor: pointer;
    display: flex;
    align-items: center;
    gap: 8px;
    font-size: 12px;
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 0.5px;
    color: var(--text-secondary);
    flex: 0 0 auto;
  }

  .threat-header:hover {
    background: rgba(88, 166, 255, 0.05);
  }

  .threat-icon {
    font-size: 14px;
  }

  .threat-content {
    flex: 1;
    overflow-y: auto;
    padding: 0 20px 12px;
    display: flex;
    flex-direction: column;
    gap: 10px;
  }

  .threat-item {
    padding: 8px 10px;
    background: rgba(248, 81, 73, 0.1);
    border-left: 2px solid var(--red);
    border-radius: 4px;
    font-size: 11px;
    color: var(--text-secondary);
  }

  .threat-item-type {
    font-weight: 600;
    color: var(--red);
    font-family: var(--mono);
  }

  .threat-empty {
    text-align: center;
    padding: 20px 10px;
    color: var(--text-secondary);
    font-size: 12px;
  }

  /* ── Scrollbars ────────────────────────────────────────────────── */

  ::-webkit-scrollbar {
    width: 6px;
  }

  ::-webkit-scrollbar-track {
    background: transparent;
  }

  ::-webkit-scrollbar-thumb {
    background: var(--border);
    border-radius: 3px;
  }

  ::-webkit-scrollbar-thumb:hover {
    background: rgba(88, 166, 255, 0.3);
  }

  /* ── Responsive ────────────────────────────────────────────────── */

  @media (max-width: 1200px) {
    .protection-sidebar {
      display: none;
    }

    .activity-feed {
      border-right: none;
    }
  }

  @media (max-width: 768px) {
    .status-bar {
      padding: 0 12px;
      gap: 12px;
      height: 48px;
    }

    .sanctuary-logo {
      font-size: 14px;
    }

    .status-bar-center {
      display: none;
    }

    .main-container {
      margin-top: 48px;
    }

    .activity-item {
      padding: 10px 12px;
    }

    .pending-overlay.active {
      width: 100%;
    }

    .threat-panel {
      max-height: 200px;
    }
  }
</style>
</head>
<body>

<!-- Status Bar (fixed, top) -->
<div class="status-bar">
  <div class="status-bar-left">
    <div class="sanctuary-logo"><span>◆</span> SANCTUARY</div>
    <div class="version">v${options.serverVersion}</div>
  </div>
  <div class="status-bar-center">
    <div class="sovereignty-badge">
      <div class="sovereignty-score" id="sovereigntyScore">85</div>
      <span>Sovereignty Health</span>
    </div>
  </div>
  <div class="status-bar-right">
    <div class="protections-indicator">
      <span class="count" id="activeProtections">6</span>/6 protections
    </div>
    <div class="uptime">
      <span id="uptimeText">—</span>
    </div>
    <div class="status-dot" id="statusDot"></div>
    <div class="pending-badge hidden" id="pendingBadge">0</div>
  </div>
</div>

<!-- Main Layout -->
<div class="main-container">
  <!-- Activity Feed -->
  <div class="activity-feed">
    <div class="feed-header">
      <div class="feed-header-dot"></div>
      Live Activity
    </div>
    <div class="activity-list" id="activityList">
      <div class="activity-empty">
        <div class="activity-empty-icon">→</div>
        <div class="activity-empty-text">Waiting for activity...</div>
      </div>
    </div>
  </div>

  <!-- Protection Status Sidebar -->
  <div class="protection-sidebar" id="protectionSidebar">
    <div class="sidebar-header">
      <span>◆</span> Protection Status
    </div>
    <div class="sidebar-content">
      <div class="protection-card">
        <div class="protection-card-icon">🔐</div>
        <div class="protection-card-label">Encryption</div>
        <div class="protection-card-status active" id="encryptionStatus">✓ Active</div>
        <div class="protection-card-stat" id="encryptionStat">Ed25519</div>
      </div>

      <div class="protection-card">
        <div class="protection-card-icon">✓</div>
        <div class="protection-card-label">Approval Gate</div>
        <div class="protection-card-status active" id="approvalStatus">✓ Active</div>
        <div class="protection-card-stat" id="approvalStat">T1: 2 | T2: 3</div>
      </div>

      <div class="protection-card">
        <div class="protection-card-icon">🎯</div>
        <div class="protection-card-label">Context Gating</div>
        <div class="protection-card-status active" id="contextStatus">✓ Active</div>
        <div class="protection-card-stat" id="contextStat">12 filtered</div>
      </div>

      <div class="protection-card">
        <div class="protection-card-icon">⚠</div>
        <div class="protection-card-label">Injection Detection</div>
        <div class="protection-card-status active" id="injectionStatus">✓ Active</div>
        <div class="protection-card-stat" id="injectionStat">3 flags today</div>
      </div>

      <div class="protection-card">
        <div class="protection-card-icon">📊</div>
        <div class="protection-card-label">Behavioral Baseline</div>
        <div class="protection-card-status active" id="baselineStatus">✓ Active</div>
        <div class="protection-card-stat" id="baselineStat">0 anomalies</div>
      </div>

      <div class="protection-card">
        <div class="protection-card-icon">📋</div>
        <div class="protection-card-label">Audit Trail</div>
        <div class="protection-card-status active" id="auditStatus">✓ Active</div>
        <div class="protection-card-stat" id="auditStat">284 entries</div>
      </div>
    </div>
  </div>
</div>

<!-- Pending Approvals Overlay -->
<div class="pending-overlay" id="pendingOverlay">
  <div class="pending-overlay-header">
    <div class="pending-overlay-title">Pending Approvals</div>
    <button class="pending-overlay-close" onclick="closePendingOverlay()">×</button>
  </div>
  <div class="pending-list" id="pendingList"></div>
</div>

<!-- Threat Panel (collapsible footer) -->
<div class="threat-panel collapsed" id="threatPanel">
  <div class="threat-header" onclick="toggleThreatPanel()">
    <span class="threat-icon">⚠</span>
    Recent Threats
    <span id="threatCount" style="margin-left: auto; color: var(--red); font-weight: 700;">0</span>
  </div>
  <div class="threat-content" id="threatContent">
    <div class="threat-empty">No threats detected</div>
  </div>
</div>

<script>
(function() {
  'use strict';

  // ── Configuration ────────────────────────────────────────────────

  const TIMEOUT_SECONDS = ${options.timeoutSeconds};
  // AUTH_TOKEN: embedded token (for direct session access) or from sessionStorage (login page flow)
  const EMBEDDED_TOKEN = ${options.authToken ? JSON.stringify(options.authToken) : 'null'};
  const AUTH_TOKEN = EMBEDDED_TOKEN || (function() { try { return sessionStorage.getItem('sanctuary_token'); } catch(_) { return null; } })();
  const MAX_ACTIVITY_ITEMS = 100;
  const MAX_THREAT_ITEMS = 20;

  // ── State ────────────────────────────────────────────────────────

  let SESSION_ID = null;
  let evtSource = null;
  let startTime = Date.now();
  let activityCount = 0;
  let threatCount = 0;
  const pendingRequests = new Map();
  const activityItems = [];
  const threatItems = [];
  let sovereigntyScore = 85;
  let sessionRenewalTimer = null;

  // ── Auth Helpers (SEC-012) ───────────────────────────────────────

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

  function setCookie(sessionId, maxAge) {
    document.cookie = 'sanctuary_session=' + sessionId +
      '; path=/; SameSite=Strict; max-age=' + maxAge;
  }

  async function exchangeSession() {
    if (!AUTH_TOKEN) return;
    try {
      const resp = await fetch('/auth/session', { method: 'POST', headers: authHeaders() });
      if (resp.ok) {
        const data = await resp.json();
        SESSION_ID = data.session_id;
        var ttl = data.expires_in_seconds || 300;
        // Update cookie with new session
        setCookie(SESSION_ID, ttl);
        // Schedule renewal at 80% of TTL
        if (sessionRenewalTimer) clearTimeout(sessionRenewalTimer);
        sessionRenewalTimer = setTimeout(function() {
          exchangeSession().then(function() { reconnectSSE(); });
        }, ttl * 800);
      } else if (resp.status === 401) {
        // Token invalid or expired — show non-destructive re-login overlay
        showSessionExpired();
      }
    } catch (e) {
      // Network error — retry in 30s
      if (sessionRenewalTimer) clearTimeout(sessionRenewalTimer);
      sessionRenewalTimer = setTimeout(function() {
        exchangeSession().then(function() { reconnectSSE(); });
      }, 30000);
    }
  }

  function showSessionExpired() {
    // Clear stored token
    try { sessionStorage.removeItem('sanctuary_token'); } catch(_) {}
    // Redirect to login page
    document.cookie = 'sanctuary_session=; path=/; max-age=0';
    window.location.reload();
  }

  // ── UI Utilities ─────────────────────────────────────────────────

  function esc(s) {
    const d = document.createElement('div');
    d.textContent = String(s || '');
    return d.innerHTML;
  }

  function closePendingOverlay() {
    document.getElementById('pendingOverlay').classList.remove('active');
  }

  function toggleThreatPanel() {
    document.getElementById('threatPanel').classList.toggle('collapsed');
  }

  function updateUptime() {
    const elapsed = Math.floor((Date.now() - startTime) / 1000);
    const hours = Math.floor(elapsed / 3600);
    const mins = Math.floor((elapsed % 3600) / 60);
    const secs = elapsed % 60;
    let uptimeStr = '';
    if (hours > 0) uptimeStr += hours + 'h ';
    if (mins > 0) uptimeStr += mins + 'm ';
    uptimeStr += secs + 's';
    document.getElementById('uptimeText').textContent = uptimeStr;
  }

  // ── Sovereignty Score ────────────────────────────────────────────

  function updateSovereigntyScore(score) {
    sovereigntyScore = Math.min(100, Math.max(0, score || 85));
    const badge = document.getElementById('sovereigntyScore');
    badge.textContent = sovereigntyScore;
    badge.className = 'sovereignty-score';
    if (sovereigntyScore >= 80) {
      badge.classList.add('high');
    } else if (sovereigntyScore >= 50) {
      badge.classList.add('medium');
    } else {
      badge.classList.add('low');
    }
  }

  // ── Activity Feed ────────────────────────────────────────────────

  function addActivityItem(data) {
    const {
      timestamp,
      tier,
      tool,
      outcome,
      detail,
      hasInjection,
      isContextGated
    } = data;

    const item = {
      id: 'activity-' + activityCount++,
      timestamp: timestamp || new Date().toISOString(),
      tier: tier || 1,
      tool: tool || 'unknown_tool',
      outcome: outcome || 'executed',
      detail: detail || '',
      hasInjection: !!hasInjection,
      isContextGated: !!isContextGated
    };

    activityItems.unshift(item);
    if (activityItems.length > MAX_ACTIVITY_ITEMS) {
      activityItems.pop();
    }

    renderActivityFeed();
  }

  function renderActivityFeed() {
    const list = document.getElementById('activityList');

    if (activityItems.length === 0) {
      list.innerHTML = '<div class="activity-empty"><div class="activity-empty-icon">→</div><div class="activity-empty-text">Waiting for activity...</div></div>';
      return;
    }

    list.innerHTML = '';
    for (const item of activityItems) {
      const tr = document.createElement('div');
      tr.className = 'activity-item';
      tr.id = item.id;

      const time = new Date(item.timestamp);
      const timeStr = time.toLocaleTimeString();

      const tierClass = 't' + item.tier;
      const outcomeClass = item.outcome === 'denied' ? 'outcome denied' : 'outcome';

      let icon = '●';
      if (item.isContextGated) icon = '🎯';
      else if (item.hasInjection) icon = '⚠';
      else if (item.outcome === 'denied') icon = '✗';
      else icon = '✓';

      tr.innerHTML =
        '<div class="activity-item-icon">' + esc(icon) + '</div>' +
        '<div class="activity-item-content">' +
          '<div class="activity-time">' + esc(timeStr) + '</div>' +
          '<div class="activity-main">' +
            '<span class="activity-tier ' + tierClass + '">T' + item.tier + '</span>' +
            '<span class="activity-tool">' + esc(item.tool) + '</span>' +
            '<span class="activity-outcome ' + (outcomeClass === 'outcome denied' ? 'denied' : '') + '">' + (item.outcome === 'denied' ? '✗ denied' : '✓ allowed') + '</span>' +
          '</div>' +
          '<div class="activity-detail">' + esc(item.detail) + '</div>' +
        '</div>' +
      '';

      tr.addEventListener('click', () => {
        tr.classList.toggle('expanded');
      });

      list.appendChild(tr);
    }
  }

  // ── Pending Approvals ────────────────────────────────────────────

  function addPendingRequest(data) {
    const {
      request_id,
      operation,
      tier,
      reason,
      context,
      timestamp
    } = data;

    const pending = {
      id: request_id,
      operation: operation || 'unknown',
      tier: tier || 1,
      reason: reason || '',
      context: context || {},
      timestamp: timestamp || new Date().toISOString(),
      remaining: TIMEOUT_SECONDS
    };

    pendingRequests.set(request_id, pending);
    updatePendingUI();
  }

  function removePendingRequest(id) {
    pendingRequests.delete(id);
    updatePendingUI();
  }

  function updatePendingUI() {
    const count = pendingRequests.size;
    const badge = document.getElementById('pendingBadge');

    if (count > 0) {
      badge.classList.remove('hidden');
      badge.textContent = count;
      document.getElementById('pendingOverlay').classList.add('active');
    } else {
      badge.classList.add('hidden');
      document.getElementById('pendingOverlay').classList.remove('active');
    }

    renderPendingList();
  }

  function renderPendingList() {
    const list = document.getElementById('pendingList');
    list.innerHTML = '';

    for (const [id, req] of pendingRequests) {
      const item = document.createElement('div');
      item.className = 'pending-item';

      const tier = req.tier || 1;
      const tierClass = 'tier' + tier;
      const pct = Math.max(0, Math.min(100, (req.remaining / TIMEOUT_SECONDS) * 100));
      const isUrgent = req.remaining <= 30;

      item.innerHTML =
        '<div class="pending-item-header">' +
          '<div class="pending-item-op">' + esc(req.operation) + '</div>' +
          '<div class="pending-item-tier ' + tierClass + '">T' + tier + '</div>' +
        '</div>' +
        '<div class="pending-item-reason">' + esc(req.reason) + '</div>' +
        '<div class="pending-item-timer ' + (isUrgent ? 'urgent' : '') + '">' +
          '<div class="pending-item-timer-bar">' +
            '<div class="pending-item-timer-fill" style="width: ' + pct + '%"></div>' +
          '</div>' +
          '<span id="timer-' + id + '">' + req.remaining + 's</span>' +
        '</div>' +
        '<div class="pending-item-actions">' +
          '<button class="btn btn-approve" onclick="handleApprove(\'' + id + '\')">Approve</button>' +
          '<button class="btn btn-deny" onclick="handleDeny(\'' + id + '\')">Deny</button>' +
        '</div>' +
      '';

      list.appendChild(item);
    }
  }

  window.handleApprove = function(id) {
    fetch('/api/approve/' + id, { method: 'POST', headers: authHeaders() }).then(() => {
      removePendingRequest(id);
    }).catch(() => {});
  };

  window.handleDeny = function(id) {
    fetch('/api/deny/' + id, { method: 'POST', headers: authHeaders() }).then(() => {
      removePendingRequest(id);
    }).catch(() => {});
  };

  // ── Threats ──────────────────────────────────────────────────────

  function addThreat(data) {
    const {
      timestamp,
      severity,
      type,
      details
    } = data;

    const threat = {
      id: 'threat-' + threatCount++,
      timestamp: timestamp || new Date().toISOString(),
      severity: severity || 'medium',
      type: type || 'unknown',
      details: details || ''
    };

    threatItems.unshift(threat);
    if (threatItems.length > MAX_THREAT_ITEMS) {
      threatItems.pop();
    }

    if (threatCount > 0) {
      document.getElementById('threatPanel').classList.remove('collapsed');
    }

    renderThreats();
  }

  function renderThreats() {
    const content = document.getElementById('threatContent');
    const badge = document.getElementById('threatCount');

    if (threatItems.length === 0) {
      content.innerHTML = '<div class="threat-empty">No threats detected</div>';
      badge.textContent = '0';
      return;
    }

    badge.textContent = threatItems.length;
    content.innerHTML = '';

    for (const threat of threatItems) {
      const div = document.createElement('div');
      div.className = 'threat-item';
      const time = new Date(threat.timestamp).toLocaleTimeString();
      div.innerHTML =
        '<div style="margin-bottom: 3px;">' +
          '<span class="threat-item-type">' + esc(threat.type) + '</span>' +
          '<span style="font-size: 10px; color: var(--text-secondary); margin-left: 6px;">' + esc(time) + '</span>' +
        '</div>' +
        '<div>' + esc(threat.details) + '</div>' +
      '';
      content.appendChild(div);
    }
  }

  // ── SSE Connection ───────────────────────────────────────────────

  function reconnectSSE() {
    if (evtSource) evtSource.close();
    connect();
  }

  function connect() {
    evtSource = new EventSource(sessionQuery('/events'));

    evtSource.onopen = () => {
      document.getElementById('statusDot').classList.remove('disconnected');
    };

    evtSource.onerror = () => {
      document.getElementById('statusDot').classList.add('disconnected');
    };

    evtSource.addEventListener('init', (e) => {
      const data = JSON.parse(e.data);
      if (data.baseline) {
        updateBaseline(data.baseline);
      }
      if (data.policy) {
        updatePolicy(data.policy);
      }
      if (data.pending) {
        data.pending.forEach(addPendingRequest);
      }
    });

    evtSource.addEventListener('pending-request', (e) => {
      const data = JSON.parse(e.data);
      addPendingRequest(data);
    });

    evtSource.addEventListener('request-resolved', (e) => {
      const data = JSON.parse(e.data);
      removePendingRequest(data.request_id);
    });

    evtSource.addEventListener('tool-call', (e) => {
      const data = JSON.parse(e.data);
      addActivityItem({
        timestamp: data.timestamp,
        tier: data.tier || 1,
        tool: data.tool || 'unknown',
        outcome: data.outcome || 'executed',
        detail: data.detail || ''
      });
    });

    evtSource.addEventListener('context-gate-decision', (e) => {
      const data = JSON.parse(e.data);
      addActivityItem({
        timestamp: data.timestamp,
        tier: data.tier || 1,
        tool: data.tool || 'unknown',
        outcome: data.outcome || 'gated',
        detail: data.fields_filtered ? 'Filtered ' + data.fields_filtered + ' fields' : data.reason || '',
        isContextGated: true
      });
    });

    evtSource.addEventListener('injection-alert', (e) => {
      const data = JSON.parse(e.data);
      addActivityItem({
        timestamp: data.timestamp,
        tier: data.tier || 2,
        tool: data.tool || 'unknown',
        outcome: data.allowed ? 'allowed' : 'denied',
        detail: data.signal || 'Injection detected',
        hasInjection: true
      });
      addThreat({
        timestamp: data.timestamp,
        severity: data.severity || 'medium',
        type: 'Injection Alert',
        details: data.signal || 'Suspicious pattern detected'
      });
    });

    evtSource.addEventListener('protection-status', (e) => {
      const data = JSON.parse(e.data);
      updateProtectionStatus(data);
    });

    evtSource.addEventListener('audit-entry', (e) => {
      const data = JSON.parse(e.data);
      // Audit entries don't show in activity by default, but we could add them
    });

    evtSource.addEventListener('baseline-update', (e) => {
      const data = JSON.parse(e.data);
      updateBaseline(data);
    });
  }

  function updateBaseline(baseline) {
    if (!baseline) return;
    // Update baseline-derived stats if needed
  }

  function updatePolicy(policy) {
    if (!policy) return;
    // Update policy-derived stats
    if (policy.approval_channel) {
      // Policy info updated
    }
  }

  function updateProtectionStatus(status) {
    if (status.sovereignty_score !== undefined) {
      updateSovereigntyScore(status.sovereignty_score);
    }
    if (status.active_protections !== undefined) {
      document.getElementById('activeProtections').textContent = status.active_protections;
    }
    // Update individual protection cards
    if (status.encryption !== undefined) {
      const el = document.getElementById('encryptionStatus');
      el.className = 'protection-card-status ' + (status.encryption ? 'active' : 'inactive');
      el.textContent = status.encryption ? '✓ Active' : '✗ Inactive';
    }
    if (status.approval_gate !== undefined) {
      const el = document.getElementById('approvalStatus');
      el.className = 'protection-card-status ' + (status.approval_gate ? 'active' : 'inactive');
      el.textContent = status.approval_gate ? '✓ Active' : '✗ Inactive';
    }
    if (status.context_gating !== undefined) {
      const el = document.getElementById('contextStatus');
      el.className = 'protection-card-status ' + (status.context_gating ? 'active' : 'inactive');
      el.textContent = status.context_gating ? '✓ Active' : '✗ Inactive';
    }
    if (status.injection_detection !== undefined) {
      const el = document.getElementById('injectionStatus');
      el.className = 'protection-card-status ' + (status.injection_detection ? 'active' : 'inactive');
      el.textContent = status.injection_detection ? '✓ Active' : '✗ Inactive';
    }
    if (status.baseline !== undefined) {
      const el = document.getElementById('baselineStatus');
      el.className = 'protection-card-status ' + (status.baseline ? 'active' : 'inactive');
      el.textContent = status.baseline ? '✓ Active' : '✗ Inactive';
    }
    if (status.audit_trail !== undefined) {
      const el = document.getElementById('auditStatus');
      el.className = 'protection-card-status ' + (status.audit_trail ? 'active' : 'inactive');
      el.textContent = status.audit_trail ? '✓ Active' : '✗ Inactive';
    }
  }

  // ── Initialization ───────────────────────────────────────────────

  (async function init() {
    await exchangeSession();
    // Clean legacy ?token= from URL
    if (window.location.search.includes('token=')) {
      window.history.replaceState({}, '', window.location.pathname);
    }
    connect();

    // Start uptime ticker
    setInterval(updateUptime, 1000);
    updateUptime();

    // Pending request countdown timer
    setInterval(() => {
      for (const [id, req] of pendingRequests) {
        req.remaining = Math.max(0, req.remaining - 1);
        const el = document.getElementById('timer-' + id);
        if (el) {
          el.textContent = req.remaining + 's';
        }
      }
    }, 1000);

    // Load initial status
    try {
      const resp = await fetch('/api/status', { headers: authHeaders() });
      if (resp.ok) {
        const status = await resp.json();
        if (status.baseline) updateBaseline(status.baseline);
        if (status.policy) updatePolicy(status.policy);
      }
    } catch (e) {
      // Ignore
    }
  })();

})();
</script>

</body>
</html>`;
}

