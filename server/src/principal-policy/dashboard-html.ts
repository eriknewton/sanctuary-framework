export function generateLoginHTML(options: { serverVersion: string }): string {
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Sanctuary — Principal Dashboard</title>
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
    }

    * {
      margin: 0;
      padding: 0;
      box-sizing: border-box;
    }

    body {
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Helvetica, Arial, sans-serif;
      background-color: var(--bg);
      color: var(--text-primary);
      min-height: 100vh;
      display: flex;
      align-items: center;
      justify-content: center;
    }

    .login-container {
      width: 100%;
      max-width: 400px;
      padding: 20px;
    }

    .login-card {
      background-color: var(--surface);
      border: 1px solid var(--border);
      border-radius: 8px;
      padding: 40px 32px;
      box-shadow: 0 4px 12px rgba(0, 0, 0, 0.3);
    }

    .login-header {
      display: flex;
      align-items: center;
      gap: 12px;
      margin-bottom: 32px;
    }

    .logo {
      font-size: 24px;
      font-weight: 700;
      color: var(--blue);
    }

    .logo-text {
      display: flex;
      flex-direction: column;
    }

    .logo-text .title {
      font-size: 18px;
      font-weight: 600;
      letter-spacing: -0.5px;
    }

    .logo-text .version {
      font-size: 12px;
      color: var(--text-secondary);
      margin-top: 2px;
    }

    .form-group {
      margin-bottom: 24px;
    }

    label {
      display: block;
      font-size: 14px;
      font-weight: 500;
      margin-bottom: 8px;
      color: var(--text-primary);
    }

    input[type="text"],
    input[type="password"] {
      width: 100%;
      padding: 10px 12px;
      background-color: var(--bg);
      border: 1px solid var(--border);
      border-radius: 6px;
      color: var(--text-primary);
      font-size: 14px;
      font-family: 'JetBrains Mono', monospace;
      transition: border-color 0.2s;
    }

    input[type="text"]:focus,
    input[type="password"]:focus {
      outline: none;
      border-color: var(--blue);
      box-shadow: 0 0 0 2px rgba(88, 166, 255, 0.1);
    }

    .error-message {
      display: none;
      background-color: rgba(248, 81, 73, 0.1);
      border: 1px solid var(--red);
      color: #ff9999;
      padding: 12px;
      border-radius: 6px;
      font-size: 13px;
      margin-bottom: 20px;
    }

    .error-message.show {
      display: block;
    }

    button {
      width: 100%;
      padding: 10px 16px;
      background-color: var(--blue);
      color: var(--bg);
      border: none;
      border-radius: 6px;
      font-size: 14px;
      font-weight: 600;
      cursor: pointer;
      transition: background-color 0.2s;
    }

    button:hover {
      background-color: #79c0ff;
    }

    button:active {
      background-color: #4184e4;
    }

    button:disabled {
      background-color: var(--text-secondary);
      cursor: not-allowed;
      opacity: 0.5;
    }

    .info-text {
      font-size: 12px;
      color: var(--text-secondary);
      margin-top: 16px;
      text-align: center;
    }
  </style>
</head>
<body>
  <div class="login-container">
    <div class="login-card">
      <div class="login-header">
        <div class="logo">◆</div>
        <div class="logo-text">
          <div class="title">SANCTUARY</div>
          <div class="version">v${options.serverVersion}</div>
        </div>
      </div>

      <div id="error-message" class="error-message"></div>

      <form id="login-form">
        <div class="form-group">
          <label for="auth-token">Auth Token</label>
          <input
            type="text"
            id="auth-token"
            name="token"
            placeholder="Paste your session token..."
            autocomplete="off"
            spellcheck="false"
            required
          />
        </div>

        <button type="submit" id="login-button">Open Dashboard</button>
      </form>

      <div class="info-text">
        Session tokens expire after 1 hour of inactivity
      </div>
    </div>
  </div>

  <script>
    const loginForm = document.getElementById('login-form');
    const authTokenInput = document.getElementById('auth-token');
    const errorMessage = document.getElementById('error-message');
    const loginButton = document.getElementById('login-button');

    loginForm.addEventListener('submit', async (e) => {
      e.preventDefault();
      const token = authTokenInput.value.trim();

      if (!token) {
        showError('Token is required');
        return;
      }

      loginButton.disabled = true;
      loginButton.textContent = 'Verifying...';
      errorMessage.classList.remove('show');

      try {
        const response = await fetch('/auth/session', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'Authorization': 'Bearer ' + token,
          },
          body: JSON.stringify({ token }),
        });

        if (response.ok) {
          const data = await response.json();
          sessionStorage.setItem('authToken', token);
          window.location.href = '/'; // Dashboard is served at root path
        } else if (response.status === 401) {
          showError('Invalid token. Please check and try again.');
        } else {
          showError('Authentication failed. Please try again.');
        }
      } catch (err) {
        showError('Connection error. Please check your network.');
      } finally {
        loginButton.disabled = false;
        loginButton.textContent = 'Open Dashboard';
      }
    });

    function showError(message) {
      errorMessage.textContent = message;
      errorMessage.classList.add('show');
    }

    authTokenInput.addEventListener('input', () => {
      errorMessage.classList.remove('show');
    });
  </script>
</body>
</html>`;
}

export function generateDashboardHTML(options: {
  timeoutSeconds: number;
  serverVersion: string;
  // SEC-056: authToken parameter removed entirely from function signature.
  // The client uses sessionStorage (set during login flow) for API authentication.
  // v0.10.6: mirror the server's loopback auto-auth decision to the client so
  // the init-time auth gate doesn't redirect-loop when sessionStorage is empty
  // on a fresh tab. See dashboard.ts:isAuthenticated() — when _autoAuthLocalhost
  // is true and the caller is a loopback address, the server serves the
  // dashboard HTML without a bearer token. Without a client-side mirror of
  // that decision, the inline init() sees empty sessionStorage.authToken and
  // redirects to '/', which is the same URL, which loads the dashboard again,
  // which redirects again — the v0.10.5 reload-loop bug.
  loopbackAutoAuth: boolean;
}): string {
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Sanctuary — Principal Dashboard</title>
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
      --success: #3fb950;
      --warning: #d29922;
      --error: #f85149;
      --muted: #21262d;
    }

    * {
      margin: 0;
      padding: 0;
      box-sizing: border-box;
    }

    html, body {
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Helvetica, Arial, sans-serif;
      background-color: var(--bg);
      color: var(--text-primary);
      height: 100%;
      overflow: hidden;
    }

    body {
      display: flex;
      flex-direction: column;
    }

    /* Status Bar */
    .status-bar {
      position: fixed;
      top: 0;
      left: 0;
      right: 0;
      height: 56px;
      background-color: var(--surface);
      border-bottom: 1px solid var(--border);
      display: flex;
      align-items: center;
      padding: 0 24px;
      gap: 24px;
      z-index: 100;
      box-shadow: 0 2px 8px rgba(0, 0, 0, 0.3);
    }

    .status-bar-left {
      display: flex;
      align-items: center;
      gap: 12px;
      flex: 0 0 auto;
    }

    .logo-icon {
      font-size: 20px;
      color: var(--blue);
      font-weight: 700;
    }

    .logo-info {
      display: flex;
      flex-direction: column;
    }

    .logo-title {
      font-size: 13px;
      font-weight: 600;
      line-height: 1;
      color: var(--text-primary);
    }

    .logo-version {
      font-size: 11px;
      color: var(--text-secondary);
      margin-top: 2px;
    }

    .status-bar-center {
      flex: 1;
      display: flex;
      justify-content: center;
    }

    .sovereignty-badge {
      display: flex;
      align-items: center;
      gap: 8px;
      padding: 8px 16px;
      background-color: rgba(63, 185, 80, 0.1);
      border: 1px solid rgba(63, 185, 80, 0.3);
      border-radius: 6px;
      font-size: 13px;
      font-weight: 500;
    }

    .sovereignty-badge.degraded {
      background-color: rgba(210, 153, 34, 0.1);
      border-color: rgba(210, 153, 34, 0.3);
    }

    .sovereignty-badge.inactive {
      background-color: rgba(248, 81, 73, 0.1);
      border-color: rgba(248, 81, 73, 0.3);
    }

    .sovereignty-score {
      font-weight: 700;
      color: var(--green);
    }

    .sovereignty-badge.degraded .sovereignty-score {
      color: var(--amber);
    }

    .sovereignty-badge.inactive .sovereignty-score {
      color: var(--red);
    }

    .status-bar-right {
      display: flex;
      align-items: center;
      gap: 16px;
      flex: 0 0 auto;
    }

    .status-item {
      display: flex;
      align-items: center;
      gap: 6px;
      font-size: 12px;
      color: var(--text-secondary);
    }

    .status-item strong {
      color: var(--text-primary);
      font-weight: 500;
    }

    .status-dot {
      width: 8px;
      height: 8px;
      border-radius: 50%;
      background-color: var(--green);
    }

    .status-dot.disconnected {
      background-color: var(--red);
    }

    .pending-badge {
      display: flex;
      align-items: center;
      gap: 6px;
      padding: 4px 8px;
      background-color: var(--blue);
      color: var(--bg);
      border-radius: 4px;
      font-size: 11px;
      font-weight: 600;
      cursor: pointer;
    }

    /* Main Content */
    .main-content {
      flex: 1;
      margin-top: 56px;
      overflow-y: auto;
      padding: 24px;
    }

    .grid {
      display: grid;
      gap: 20px;
    }

    /* Row 1: Sovereignty Layers */
    .sovereignty-layers {
      display: grid;
      grid-template-columns: repeat(4, 1fr);
      gap: 16px;
    }

    .operator-cloud-disclosure {
      display: none;
      border: 1px solid var(--amber);
      background-color: rgba(210, 153, 34, 0.08);
      color: var(--text-primary);
      border-radius: 6px;
      padding: 12px 14px;
      font-size: 12px;
      line-height: 1.5;
    }

    .layer-card {
      background-color: var(--surface);
      border: 1px solid var(--border);
      border-radius: 8px;
      padding: 20px;
      display: flex;
      flex-direction: column;
      gap: 12px;
    }

    .layer-card.degraded {
      border-color: var(--amber);
      background-color: rgba(210, 153, 34, 0.05);
    }

    .layer-card.inactive {
      border-color: var(--red);
      background-color: rgba(248, 81, 73, 0.05);
    }

    .layer-name {
      font-size: 12px;
      font-weight: 600;
      color: var(--text-secondary);
      text-transform: uppercase;
      letter-spacing: 0.5px;
    }

    .layer-title {
      font-size: 14px;
      font-weight: 600;
      color: var(--text-primary);
    }

    .layer-status {
      display: inline-flex;
      align-items: center;
      gap: 6px;
      padding: 4px 8px;
      background-color: rgba(63, 185, 80, 0.15);
      color: var(--green);
      border-radius: 4px;
      font-size: 11px;
      font-weight: 600;
      width: fit-content;
    }

    .layer-card.degraded .layer-status {
      background-color: rgba(210, 153, 34, 0.15);
      color: var(--amber);
    }

    .layer-card.inactive .layer-status {
      background-color: rgba(248, 81, 73, 0.15);
      color: var(--red);
    }

    .layer-detail {
      font-size: 12px;
      color: var(--text-secondary);
      font-family: 'JetBrains Mono', monospace;
      padding: 8px;
      background-color: var(--bg);
      border-radius: 4px;
      border-left: 2px solid var(--blue);
    }

    /* Row 2: Info Cards */
    .info-cards {
      display: grid;
      grid-template-columns: repeat(3, 1fr);
      gap: 16px;
    }

    .info-card {
      background-color: var(--surface);
      border: 1px solid var(--border);
      border-radius: 8px;
      padding: 20px;
    }

    .card-header {
      font-size: 12px;
      font-weight: 600;
      color: var(--text-secondary);
      text-transform: uppercase;
      letter-spacing: 0.5px;
      margin-bottom: 16px;
    }

    .card-row {
      display: flex;
      justify-content: space-between;
      align-items: center;
      margin-bottom: 12px;
      font-size: 13px;
    }

    .card-row:last-child {
      margin-bottom: 0;
    }

    .card-label {
      color: var(--text-secondary);
    }

    .card-value {
      color: var(--text-primary);
      font-family: 'JetBrains Mono', monospace;
      font-weight: 500;
    }

    .identity-badge {
      display: inline-flex;
      align-items: center;
      gap: 4px;
      padding: 2px 6px;
      background-color: rgba(88, 166, 255, 0.15);
      color: var(--blue);
      border-radius: 3px;
      font-size: 10px;
      font-weight: 600;
      text-transform: uppercase;
    }

    .trust-tier-badge {
      display: inline-flex;
      align-items: center;
      gap: 4px;
      padding: 2px 6px;
      background-color: rgba(63, 185, 80, 0.15);
      color: var(--green);
      border-radius: 3px;
      font-size: 10px;
      font-weight: 600;
    }

    .truncated {
      max-width: 200px;
      overflow: hidden;
      text-overflow: ellipsis;
      white-space: nowrap;
    }

    /* Row 3: SHR & Activity */
    .main-panels {
      display: grid;
      grid-template-columns: 1fr 1fr;
      gap: 16px;
      min-height: 400px;
    }

    .panel {
      background-color: var(--surface);
      border: 1px solid var(--border);
      border-radius: 8px;
      display: flex;
      flex-direction: column;
      overflow: hidden;
    }

    .panel-header {
      padding: 16px 20px;
      border-bottom: 1px solid var(--border);
      display: flex;
      justify-content: space-between;
      align-items: center;
    }

    .panel-title {
      font-size: 14px;
      font-weight: 600;
      color: var(--text-primary);
    }

    .panel-action {
      background: none;
      border: none;
      color: var(--blue);
      cursor: pointer;
      font-size: 12px;
      padding: 0;
      font-weight: 500;
      transition: color 0.2s;
    }

    .panel-action:hover {
      color: #79c0ff;
    }

    .panel-content {
      flex: 1;
      overflow-y: auto;
      padding: 20px;
    }

    /* SHR Viewer */
    .shr-json {
      font-family: 'JetBrains Mono', monospace;
      font-size: 12px;
      line-height: 1.6;
      color: var(--text-secondary);
    }

    .shr-section {
      margin-bottom: 12px;
    }

    .shr-section-header {
      display: flex;
      align-items: center;
      gap: 8px;
      cursor: pointer;
      font-weight: 600;
      color: var(--text-primary);
      padding: 8px;
      background-color: var(--bg);
      border-radius: 4px;
      user-select: none;
    }

    .shr-section-header:hover {
      background-color: var(--muted);
    }

    .shr-toggle {
      width: 16px;
      height: 16px;
      display: flex;
      align-items: center;
      justify-content: center;
      font-size: 10px;
      transition: transform 0.2s;
    }

    .shr-section.collapsed .shr-toggle {
      transform: rotate(-90deg);
    }

    .shr-section-content {
      padding: 8px 16px;
      background-color: rgba(0, 0, 0, 0.2);
      border-radius: 4px;
      margin-top: 4px;
    }

    .shr-section.collapsed .shr-section-content {
      display: none;
    }

    .shr-item {
      display: flex;
      margin-bottom: 4px;
    }

    .shr-key {
      color: var(--blue);
      margin-right: 8px;
      min-width: 120px;
    }

    .shr-value {
      color: var(--green);
      word-break: break-all;
    }

    /* Activity Feed */
    .activity-feed {
      display: flex;
      flex-direction: column;
      gap: 12px;
    }

    .activity-item {
      padding: 12px;
      background-color: var(--bg);
      border-left: 2px solid var(--border);
      border-radius: 4px;
      font-size: 12px;
    }

    .activity-item.tool-call {
      border-left-color: var(--blue);
    }

    .activity-item.context-gate {
      border-left-color: var(--amber);
    }

    .activity-item.injection {
      border-left-color: var(--red);
    }

    .activity-item.protection {
      border-left-color: var(--green);
    }

    .activity-type {
      font-weight: 600;
      color: var(--text-primary);
      margin-bottom: 4px;
      text-transform: uppercase;
      font-size: 11px;
      letter-spacing: 0.5px;
    }

    .activity-content {
      color: var(--text-secondary);
      font-family: 'JetBrains Mono', monospace;
      margin-bottom: 4px;
      word-break: break-all;
    }

    .activity-time {
      font-size: 11px;
      color: var(--text-secondary);
    }

    .empty-state {
      display: flex;
      align-items: center;
      justify-content: center;
      height: 100%;
      color: var(--text-secondary);
      font-size: 13px;
    }

    /* Row 4: Handshake History */
    .handshake-table {
      background-color: var(--surface);
      border: 1px solid var(--border);
      border-radius: 8px;
      overflow: hidden;
    }

    .table-header {
      display: grid;
      grid-template-columns: 2fr 1fr 1fr 1fr 1.5fr 1.5fr;
      gap: 16px;
      padding: 16px 20px;
      border-bottom: 1px solid var(--border);
      background-color: var(--bg);
      font-size: 12px;
      font-weight: 600;
      color: var(--text-secondary);
      text-transform: uppercase;
      letter-spacing: 0.5px;
    }

    .table-rows {
      max-height: 300px;
      overflow-y: auto;
    }

    .table-row {
      display: grid;
      grid-template-columns: 2fr 1fr 1fr 1fr 1.5fr 1.5fr;
      gap: 16px;
      padding: 14px 20px;
      border-bottom: 1px solid var(--border);
      align-items: center;
      font-size: 12px;
      cursor: pointer;
      transition: background-color 0.2s;
    }

    .table-row:hover {
      background-color: var(--bg);
    }

    .table-row:last-child {
      border-bottom: none;
    }

    .table-cell {
      color: var(--text-secondary);
      font-family: 'JetBrains Mono', monospace;
    }

    .table-cell.strong {
      color: var(--text-primary);
      font-weight: 500;
    }

    .table-empty {
      padding: 40px 20px;
      text-align: center;
      color: var(--text-secondary);
      font-size: 13px;
    }

    /* Pending Overlay */
    .pending-overlay {
      position: fixed;
      top: 0;
      right: -400px;
      width: 400px;
      height: 100vh;
      background-color: var(--surface);
      border-left: 1px solid var(--border);
      box-shadow: -2px 0 8px rgba(0, 0, 0, 0.3);
      z-index: 200;
      transition: right 0.3s ease;
      display: flex;
      flex-direction: column;
      overflow-y: auto;
    }

    .pending-overlay.show {
      right: 0;
    }

    .pending-header {
      padding: 16px 20px;
      border-bottom: 1px solid var(--border);
      font-weight: 600;
      color: var(--text-primary);
    }

    .pending-items {
      flex: 1;
      overflow-y: auto;
      padding: 16px;
    }

    .pending-item {
      background-color: var(--bg);
      border: 1px solid var(--border);
      border-radius: 6px;
      padding: 16px;
      margin-bottom: 12px;
    }

    .pending-title {
      font-weight: 600;
      color: var(--text-primary);
      margin-bottom: 8px;
      word-break: break-word;
    }

    .pending-countdown {
      font-size: 12px;
      color: var(--amber);
      margin-bottom: 12px;
      font-weight: 500;
    }

    .pending-actions {
      display: flex;
      gap: 8px;
    }

    .pending-btn {
      flex: 1;
      padding: 8px 12px;
      border: none;
      border-radius: 4px;
      font-size: 12px;
      font-weight: 600;
      cursor: pointer;
      transition: background-color 0.2s;
    }

    .pending-approve {
      background-color: var(--green);
      color: var(--bg);
    }

    .pending-approve:hover {
      background-color: #3fa040;
    }

    .pending-deny {
      background-color: var(--red);
      color: var(--bg);
    }

    .pending-deny:hover {
      background-color: #e03c3c;
    }

    /* Sovereignty Profile Panel */
    .profile-panel {
      background-color: var(--surface);
      border: 1px solid var(--border);
      border-radius: 8px;
      padding: 20px;
    }

    .profile-panel .panel-header {
      display: flex;
      justify-content: space-between;
      align-items: center;
      margin-bottom: 16px;
    }

    .profile-panel .panel-title {
      font-size: 14px;
      font-weight: 600;
      color: var(--text-primary);
    }

    .profile-cards {
      display: grid;
      grid-template-columns: repeat(5, 1fr);
      gap: 12px;
      margin-bottom: 16px;
    }

    .profile-card {
      background-color: var(--bg);
      border: 1px solid var(--border);
      border-radius: 6px;
      padding: 14px;
      display: flex;
      flex-direction: column;
      gap: 8px;
      transition: border-color 0.2s;
    }

    .profile-card.active {
      border-color: var(--green);
    }

    .profile-card-header {
      display: flex;
      justify-content: space-between;
      align-items: center;
    }

    .profile-card-name {
      font-size: 12px;
      font-weight: 600;
      color: var(--text-primary);
    }

    .profile-card-desc {
      font-size: 11px;
      color: var(--text-secondary);
      line-height: 1.4;
    }

    /* Toggle switch */
    .toggle-switch {
      position: relative;
      width: 36px;
      height: 20px;
      flex-shrink: 0;
    }

    .toggle-switch input {
      opacity: 0;
      width: 0;
      height: 0;
    }

    .toggle-slider {
      position: absolute;
      cursor: pointer;
      top: 0;
      left: 0;
      right: 0;
      bottom: 0;
      background-color: var(--border);
      border-radius: 10px;
      transition: background-color 0.2s;
    }

    .toggle-slider::before {
      content: "";
      position: absolute;
      height: 14px;
      width: 14px;
      left: 3px;
      bottom: 3px;
      background-color: var(--text-secondary);
      border-radius: 50%;
      transition: transform 0.2s, background-color 0.2s;
    }

    .toggle-switch input:checked + .toggle-slider {
      background-color: rgba(63, 185, 80, 0.3);
    }

    .toggle-switch input:checked + .toggle-slider::before {
      transform: translateX(16px);
      background-color: var(--green);
    }

    .profile-badge {
      display: inline-flex;
      align-items: center;
      gap: 4px;
      padding: 2px 8px;
      border-radius: 4px;
      font-size: 10px;
      font-weight: 600;
      width: fit-content;
    }

    .profile-badge.enabled {
      background-color: rgba(63, 185, 80, 0.15);
      color: var(--green);
    }

    .profile-badge.disabled {
      background-color: rgba(139, 148, 158, 0.15);
      color: var(--text-secondary);
    }

    .profile-card-actions {
      display: flex;
      gap: 6px;
      margin-top: 4px;
    }

    .config-btn {
      padding: 3px 8px;
      border: 1px solid var(--border);
      border-radius: 4px;
      background-color: transparent;
      color: var(--text-secondary);
      font-size: 10px;
      cursor: pointer;
      transition: color 0.2s, border-color 0.2s;
    }

    .config-btn:hover {
      color: var(--blue);
      border-color: var(--blue);
    }

    /* Configuration panels */
    .config-panel {
      display: none;
      margin-top: 8px;
      padding: 10px;
      background-color: var(--surface);
      border: 1px solid var(--border);
      border-radius: 4px;
      font-size: 11px;
    }

    .config-panel.open {
      display: block;
    }

    .config-panel-title {
      font-size: 11px;
      font-weight: 600;
      color: var(--text-primary);
      margin-bottom: 8px;
    }

    .config-row {
      display: flex;
      align-items: center;
      gap: 8px;
      margin-bottom: 6px;
    }

    .config-label {
      font-size: 11px;
      color: var(--text-secondary);
      min-width: 80px;
    }

    .config-select, .config-input {
      background-color: var(--bg);
      border: 1px solid var(--border);
      border-radius: 4px;
      color: var(--text-primary);
      font-size: 11px;
      padding: 4px 8px;
    }

    .config-info {
      font-size: 11px;
      color: var(--text-secondary);
      line-height: 1.5;
    }

    .sensitivity-slider {
      display: flex;
      gap: 4px;
    }

    .sensitivity-option {
      padding: 3px 10px;
      border: 1px solid var(--border);
      border-radius: 4px;
      background-color: transparent;
      color: var(--text-secondary);
      font-size: 10px;
      cursor: pointer;
      transition: all 0.2s;
    }

    .sensitivity-option.selected {
      background-color: rgba(88, 166, 255, 0.15);
      color: var(--blue);
      border-color: var(--blue);
    }

    .sensitivity-option:hover:not(.selected) {
      border-color: var(--text-secondary);
    }

    /* Prompt section */
    .prompt-section {
      margin-top: 16px;
    }

    .prompt-display {
      position: relative;
      background-color: var(--bg);
      border: 1px solid var(--border);
      border-radius: 6px;
      margin-top: 8px;
      display: none;
    }

    .prompt-display.visible {
      display: block;
    }

    .prompt-display-header {
      display: flex;
      justify-content: space-between;
      align-items: center;
      padding: 8px 12px;
      border-bottom: 1px solid var(--border);
    }

    .prompt-token-count {
      font-size: 11px;
      color: var(--text-secondary);
    }

    .prompt-copy-btn {
      padding: 4px 10px;
      border: 1px solid var(--border);
      border-radius: 4px;
      background-color: var(--surface);
      color: var(--text-primary);
      font-size: 11px;
      cursor: pointer;
      transition: border-color 0.2s;
    }

    .prompt-copy-btn:hover {
      border-color: var(--blue);
    }

    .prompt-content {
      max-height: 300px;
      overflow-y: auto;
      padding: 12px;
      font-family: 'JetBrains Mono', monospace;
      font-size: 12px;
      line-height: 1.6;
      white-space: pre-wrap;
      color: var(--text-primary);
    }

    .prompt-actions {
      display: flex;
      gap: 8px;
      margin-top: 8px;
    }

    .prompt-btn {
      padding: 6px 12px;
      border: 1px solid var(--border);
      border-radius: 4px;
      background-color: var(--surface);
      color: var(--text-primary);
      font-size: 12px;
      cursor: pointer;
    }

    .prompt-btn:hover {
      background-color: var(--muted);
    }

    .prompt-btn.primary {
      background-color: var(--blue);
      color: var(--bg);
      border-color: var(--blue);
    }

    @media (max-width: 900px) {
      .profile-cards {
        grid-template-columns: repeat(2, 1fr);
      }
    }

    @media (max-width: 500px) {
      .profile-cards {
        grid-template-columns: 1fr;
      }
    }

    /* Threat Panel */
    .threat-panel {
      background-color: var(--surface);
      border: 1px solid var(--border);
      border-radius: 8px;
      margin-top: 20px;
      overflow: hidden;
    }

    .threat-header {
      padding: 16px 20px;
      border-bottom: 1px solid var(--border);
      display: flex;
      justify-content: space-between;
      align-items: center;
      cursor: pointer;
      user-select: none;
    }

    .threat-title {
      font-weight: 600;
      color: var(--text-primary);
    }

    .threat-toggle {
      font-size: 10px;
      color: var(--text-secondary);
      transition: transform 0.2s;
    }

    .threat-panel.collapsed .threat-toggle {
      transform: rotate(-90deg);
    }

    .threat-content {
      padding: 16px 20px;
      max-height: 300px;
      overflow-y: auto;
    }

    .threat-panel.collapsed .threat-content {
      display: none;
    }

    .threat-alert {
      background-color: rgba(248, 81, 73, 0.1);
      border: 1px solid var(--red);
      border-radius: 4px;
      padding: 12px;
      margin-bottom: 8px;
      font-size: 12px;
    }

    .threat-alert:last-child {
      margin-bottom: 0;
    }

    .threat-type {
      font-weight: 600;
      color: var(--red);
      margin-bottom: 4px;
      text-transform: uppercase;
      font-size: 10px;
      letter-spacing: 0.5px;
    }

    .threat-message {
      color: var(--text-secondary);
    }

    /* Scrollbar */
    ::-webkit-scrollbar {
      width: 8px;
    }

    ::-webkit-scrollbar-track {
      background-color: transparent;
    }

    ::-webkit-scrollbar-thumb {
      background-color: var(--border);
      border-radius: 4px;
    }

    ::-webkit-scrollbar-thumb:hover {
      background-color: var(--text-secondary);
    }

    /* Responsive */
    @media (max-width: 1400px) {
      .sovereignty-layers {
        grid-template-columns: repeat(2, 1fr);
      }

      .main-panels {
        grid-template-columns: 1fr;
      }

      .pending-overlay {
        width: 100%;
        right: -100%;
      }
    }

    @media (max-width: 768px) {
      .status-bar {
        flex-wrap: wrap;
        height: auto;
        padding: 12px;
        gap: 12px;
      }

      .status-bar-center {
        order: 3;
        flex-basis: 100%;
      }

      .main-content {
        margin-top: auto;
      }

      .info-cards {
        grid-template-columns: 1fr;
      }

      .table-header,
      .table-row {
        grid-template-columns: 1fr;
      }
    }

    .standalone-banner {
      background: #1c1f26;
      border: 1px solid var(--amber);
      border-radius: 6px;
      color: var(--amber);
      padding: 10px 16px;
      margin: 8px 16px 0 16px;
      font-size: 0.85rem;
      display: flex;
      align-items: center;
      gap: 8px;
    }
    .standalone-icon {
      font-size: 1rem;
      flex-shrink: 0;
    }
  </style>
</head>
<body>
  <!-- Status Bar -->
  <div class="status-bar">
    <div class="status-bar-left">
      <div class="logo-icon">◆</div>
      <div class="logo-info">
        <div class="logo-title">SANCTUARY</div>
        <div class="logo-version">v${options.serverVersion}</div>
      </div>
    </div>

    <div class="status-bar-center">
      <div id="sovereignty-badge" class="sovereignty-badge">
        <span>Sovereignty Health:</span>
        <span class="sovereignty-score" id="sovereignty-score">—</span>
        <span>/ 100</span>
      </div>
    </div>

    <div class="status-bar-right">
      <div class="status-item">
        <strong id="protections-count">—</strong>
        <span>Protections</span>
      </div>
      <div class="status-item">
        <strong id="uptime-value">—</strong>
        <span>Uptime</span>
      </div>
      <div class="status-dot" id="connection-status"></div>
      <div id="pending-item-badge" class="pending-badge" style="display: none;">
        <span>⏳</span>
        <span id="pending-count">0</span>
      </div>
    </div>
  </div>

  <!-- Standalone Mode Banner (hidden by default, shown via JS) -->
  <div id="standalone-banner" class="standalone-banner" style="display: none;">
    <span class="standalone-icon">◇</span>
    <span>Standalone mode — identity and sovereignty data loaded from storage. Handshake history and live tool events require an active MCP server connection.</span>
  </div>

  <!-- Main Content -->
  <div class="main-content">
    <div class="grid">
      <!-- Row 1: Sovereignty Layers -->
      <div class="sovereignty-layers" id="sovereignty-layers">
        <div class="layer-card" data-layer="l1">
          <div class="layer-name">Layer 1</div>
          <div class="layer-title">Cognitive Sovereignty</div>
          <div class="layer-status"><span>●</span> <span id="l1-status">—</span></div>
          <div class="layer-detail" id="l1-detail">Loading...</div>
        </div>
        <div class="layer-card" data-layer="l2">
          <div class="layer-name">Layer 2</div>
          <div class="layer-title">Operational Isolation</div>
          <div class="layer-status"><span>●</span> <span id="l2-status">—</span></div>
          <div class="layer-detail" id="l2-detail">Loading...</div>
        </div>
        <div class="layer-card" data-layer="l3">
          <div class="layer-name">Layer 3</div>
          <div class="layer-title">Selective Disclosure</div>
          <div class="layer-status"><span>●</span> <span id="l3-status">—</span></div>
          <div class="layer-detail" id="l3-detail">Loading...</div>
        </div>
        <div class="layer-card" data-layer="l4">
          <div class="layer-name">Layer 4</div>
          <div class="layer-title">Verifiable Reputation</div>
          <div class="layer-status"><span>●</span> <span id="l4-status">—</span></div>
          <div class="layer-detail" id="l4-detail">Loading...</div>
        </div>
      </div>

      <div id="operator-cloud-disclosure" class="operator-cloud-disclosure"></div>

      <!-- Row 2: Info Cards -->
      <div class="info-cards">
        <div class="info-card">
          <div class="card-header">Identity</div>
          <div class="card-row">
            <span class="card-label">Primary</span>
            <span class="card-value" id="identity-label">—</span>
          </div>
          <div class="card-row">
            <span class="card-label">DID</span>
            <span class="card-value truncated" id="identity-did" title="">—</span>
          </div>
          <div class="card-row">
            <span class="card-label">Public Key</span>
            <span class="card-value truncated" id="identity-pubkey" title="">—</span>
          </div>
          <div class="card-row">
            <span class="card-label">Type</span>
            <span class="identity-badge">Ed25519</span>
          </div>
          <div class="card-row">
            <span class="card-label">Created</span>
            <span class="card-value" id="identity-created">—</span>
          </div>
          <div class="card-row">
            <span class="card-label">Identities</span>
            <span class="card-value" id="identity-count">—</span>
          </div>
        </div>

        <div class="info-card">
          <div class="card-header">Handshakes</div>
          <div class="card-row">
            <span class="card-label">Total</span>
            <span class="card-value" id="handshake-count">—</span>
          </div>
          <div class="card-row">
            <span class="card-label">Latest Peer</span>
            <span class="card-value truncated" id="handshake-latest">—</span>
          </div>
          <div class="card-row">
            <span class="card-label">Trust Tier</span>
            <span class="trust-tier-badge" id="handshake-tier">Unverified</span>
          </div>
          <div class="card-row">
            <span class="card-label">Timestamp</span>
            <span class="card-value" id="handshake-time">—</span>
          </div>
        </div>

        <div class="info-card">
          <div class="card-header">Reputation</div>
          <div class="card-row">
            <span class="card-label">Weighted Score</span>
            <span class="card-value" id="reputation-score">—</span>
          </div>
          <div class="card-row">
            <span class="card-label">Attestations</span>
            <span class="card-value" id="reputation-attestations">—</span>
          </div>
          <div class="card-row">
            <span class="card-label">Verified Sovereign</span>
            <span class="card-value" id="reputation-verified">—</span>
          </div>
          <div class="card-row">
            <span class="card-label">Verified Degraded</span>
            <span class="card-value" id="reputation-degraded">—</span>
          </div>
          <div class="card-row">
            <span class="card-label">Unverified</span>
            <span class="card-value" id="reputation-unverified">—</span>
          </div>
        </div>
      </div>

      <!-- Row 3: SHR & Activity -->
      <div class="main-panels">
        <div class="panel">
          <div class="panel-header">
            <div class="panel-title">Sovereignty Health Report</div>
            <button class="panel-action" id="copy-shr-btn">Copy JSON</button>
          </div>
          <div class="panel-content">
            <div class="shr-json" id="shr-viewer">
              <div class="empty-state">Loading SHR...</div>
            </div>
          </div>
        </div>

        <div class="panel">
          <div class="panel-header">
            <div class="panel-title">Activity Feed</div>
          </div>
          <div class="panel-content">
            <div id="activity-feed" class="activity-feed">
              <div class="empty-state">Waiting for activity...</div>
            </div>
          </div>
        </div>
      </div>

      <!-- Row 4: Handshake History -->
      <div class="handshake-table">
        <div class="table-header">
          <div>Counterparty</div>
          <div>Trust Tier</div>
          <div>Sovereignty</div>
          <div>Verified</div>
          <div>Completed</div>
          <div>Expires</div>
        </div>
        <div class="table-rows" id="handshake-table">
          <div class="table-empty">No handshakes completed yet</div>
        </div>
      </div>

      <!--
        Mesh Health panel (WP-MVP-3 Follow-up #3).
        Subscribes to the existing /events SSE channel — no new transport.
        Render shape: per-node row with presence + flags + rollup.
        On open alert: list inline with operator-decision CTAs (rollback /
        split-brain / canonical-audit promotion).
        On post-recovery prompt: render rotation-prompt overlay with
        broker-credential list + "rotate now" buttons (rotation flow itself
        is the existing v0.10.x broker rotation surface).
      -->
      <div class="mesh-health-panel" id="mesh-health-panel">
        <div class="panel-header">
          <div class="panel-title">Mesh Health</div>
          <span class="card-value" id="mesh-health-updated-at" style="font-size: 11px; color: var(--text-secondary);">—</span>
        </div>
        <div id="mesh-health-rows" class="mesh-health-rows">
          <div class="empty-state">Waiting for mesh health data…</div>
        </div>
        <div id="mesh-health-alerts" class="mesh-health-alerts" style="margin-top: 12px;"></div>
        <div id="mesh-post-recovery-prompt" class="mesh-post-recovery-prompt" style="margin-top: 12px; display: none;"></div>
      </div>

      <!-- Sovereignty Profile Panel -->
      <div class="profile-panel" id="sovereignty-profile-panel">
        <div class="panel-header">
          <div class="panel-title">Sovereignty Profile</div>
          <span class="card-value" id="profile-updated-at" style="font-size: 11px; color: var(--text-secondary);">—</span>
        </div>
        <div class="profile-cards" id="profile-cards">
          <div class="profile-card" data-feature="audit_logging">
            <div class="profile-card-header">
              <div class="profile-card-name">Audit Logging</div>
              <label class="toggle-switch">
                <input type="checkbox" id="toggle-audit_logging" data-feature="audit_logging">
                <span class="toggle-slider"></span>
              </label>
            </div>
            <div class="profile-badge disabled" id="badge-audit_logging">OFF</div>
            <div class="profile-card-desc">Encrypted audit trail of all tool calls</div>
            <div class="profile-card-actions">
              <button class="config-btn" data-config="audit_logging">Configure</button>
            </div>
            <div class="config-panel" id="config-audit_logging">
              <div class="config-info">Audit logging is always-on when enabled. All tool calls, gate decisions, and profile changes are recorded to an encrypted audit trail. No additional configuration needed.</div>
            </div>
          </div>
          <div class="profile-card" data-feature="injection_detection">
            <div class="profile-card-header">
              <div class="profile-card-name">Injection Detection</div>
              <label class="toggle-switch">
                <input type="checkbox" id="toggle-injection_detection" data-feature="injection_detection">
                <span class="toggle-slider"></span>
              </label>
            </div>
            <div class="profile-badge disabled" id="badge-injection_detection">OFF</div>
            <div class="profile-card-desc">Scans tool arguments for prompt injection</div>
            <div class="profile-card-actions">
              <button class="config-btn" data-config="injection_detection">Configure</button>
            </div>
            <div class="config-panel" id="config-injection_detection">
              <div class="config-panel-title">Sensitivity</div>
              <div class="sensitivity-slider">
                <button class="sensitivity-option" data-sensitivity="low">Low</button>
                <button class="sensitivity-option selected" data-sensitivity="medium">Medium</button>
                <button class="sensitivity-option" data-sensitivity="high">High</button>
              </div>
            </div>
          </div>
          <div class="profile-card" data-feature="context_gating">
            <div class="profile-card-header">
              <div class="profile-card-name">Context Gating</div>
              <label class="toggle-switch">
                <input type="checkbox" id="toggle-context_gating" data-feature="context_gating">
                <span class="toggle-slider"></span>
              </label>
            </div>
            <div class="profile-badge disabled" id="badge-context_gating">OFF</div>
            <div class="profile-card-desc">Controls context flow to remote providers</div>
            <div class="profile-card-actions">
              <button class="config-btn" data-config="context_gating">Configure</button>
            </div>
            <div class="config-panel" id="config-context_gating">
              <div class="config-panel-title">Active Policy</div>
              <div class="config-row">
                <span class="config-label">Policy ID:</span>
                <select class="config-select" id="config-context-policy">
                  <option value="">None selected</option>
                </select>
              </div>
              <div class="config-info" style="margin-top: 6px;">Use MCP tool <code style="color: var(--blue);">sanctuary/context_gate_set_policy</code> or <code style="color: var(--blue);">sanctuary/context_gate_apply_template</code> to create policies.</div>
            </div>
          </div>
          <div class="profile-card" data-feature="approval_gate">
            <div class="profile-card-header">
              <div class="profile-card-name">Approval Gates</div>
              <label class="toggle-switch">
                <input type="checkbox" id="toggle-approval_gate" data-feature="approval_gate">
                <span class="toggle-slider"></span>
              </label>
            </div>
            <div class="profile-badge disabled" id="badge-approval_gate">OFF</div>
            <div class="profile-card-desc">Human approval for high-risk operations</div>
            <div class="profile-card-actions">
              <button class="config-btn" data-config="approval_gate">Configure</button>
            </div>
            <div class="config-panel" id="config-approval_gate">
              <div class="config-panel-title">Tier Assignments</div>
              <div class="config-info">
                <strong style="color: var(--red);">Tier 1 (always approve):</strong> export, import, key rotation, deletion<br>
                <strong style="color: var(--amber);">Tier 2 (approve on anomaly):</strong> new namespaces, unfamiliar counterparties, frequency spikes<br>
                <strong style="color: var(--green);">Tier 3 (auto-allow):</strong> standard operations, queries, reads
              </div>
            </div>
          </div>
          <div class="profile-card" data-feature="zk_proofs">
            <div class="profile-card-header">
              <div class="profile-card-name">ZK Proofs</div>
              <label class="toggle-switch">
                <input type="checkbox" id="toggle-zk_proofs" data-feature="zk_proofs">
                <span class="toggle-slider"></span>
              </label>
            </div>
            <div class="profile-badge disabled" id="badge-zk_proofs">OFF</div>
            <div class="profile-card-desc">Prove claims without revealing data</div>
            <div class="profile-card-actions">
              <button class="config-btn" data-config="zk_proofs">Configure</button>
            </div>
            <div class="config-panel" id="config-zk_proofs">
              <div class="config-info">Zero-knowledge proofs use Pedersen commitments on Ristretto255 and Schnorr proofs. No additional configuration needed. Available tools: <code style="color: var(--blue);">sanctuary/zk_commit</code>, <code style="color: var(--blue);">sanctuary/zk_prove</code>, <code style="color: var(--blue);">sanctuary/zk_range_prove</code>.</div>
            </div>
          </div>
        </div>
        <div class="prompt-section">
          <div class="prompt-actions">
            <button class="prompt-btn primary" id="generate-prompt-btn">Generate System Prompt</button>
          </div>
          <div class="prompt-display" id="prompt-display">
            <div class="prompt-display-header">
              <span class="prompt-token-count" id="prompt-token-count"></span>
              <button class="prompt-copy-btn" id="copy-prompt-btn">Copy to Clipboard</button>
            </div>
            <div class="prompt-content" id="system-prompt-output"></div>
          </div>
        </div>
      </div>

      <!-- Upstream Servers Panel -->
      <div class="profile-panel" id="proxy-servers-panel">
        <div class="panel-header">
          <div class="panel-title">Upstream Servers</div>
          <button class="panel-action" id="add-proxy-server-btn">+ Add Server</button>
        </div>
        <div id="proxy-servers-list">
          <div class="empty-state">No upstream servers configured</div>
        </div>

        <!-- Add Server Form (hidden by default) -->
        <div id="add-server-form" style="display: none; padding: 16px; border-top: 1px solid var(--border);">
          <div style="margin-bottom: 12px;">
            <label style="font-size: 12px; color: var(--text-secondary); display: block; margin-bottom: 4px;">Server Name</label>
            <input type="text" id="new-server-name" placeholder="e.g., filesystem" style="width: 100%; padding: 8px; background: var(--bg); border: 1px solid var(--border); border-radius: 4px; color: var(--text-primary); font-size: 13px;">
          </div>
          <div style="margin-bottom: 12px;">
            <label style="font-size: 12px; color: var(--text-secondary); display: block; margin-bottom: 4px;">Transport Type</label>
            <select id="new-server-transport" style="width: 100%; padding: 8px; background: var(--bg); border: 1px solid var(--border); border-radius: 4px; color: var(--text-primary); font-size: 13px;">
              <option value="stdio">stdio</option>
              <option value="sse">SSE</option>
            </select>
          </div>
          <div id="stdio-fields">
            <div style="margin-bottom: 12px;">
              <label style="font-size: 12px; color: var(--text-secondary); display: block; margin-bottom: 4px;">Command</label>
              <input type="text" id="new-server-command" placeholder="e.g., npx -y @modelcontextprotocol/server-filesystem" style="width: 100%; padding: 8px; background: var(--bg); border: 1px solid var(--border); border-radius: 4px; color: var(--text-primary); font-size: 13px;">
            </div>
            <div style="margin-bottom: 12px;">
              <label style="font-size: 12px; color: var(--text-secondary); display: block; margin-bottom: 4px;">Arguments (comma-separated)</label>
              <input type="text" id="new-server-args" placeholder="e.g., /Users/me/allowed-dir" style="width: 100%; padding: 8px; background: var(--bg); border: 1px solid var(--border); border-radius: 4px; color: var(--text-primary); font-size: 13px;">
            </div>
          </div>
          <div id="sse-fields" style="display: none;">
            <div style="margin-bottom: 12px;">
              <label style="font-size: 12px; color: var(--text-secondary); display: block; margin-bottom: 4px;">Server URL</label>
              <input type="text" id="new-server-url" placeholder="e.g., http://localhost:3001/sse" style="width: 100%; padding: 8px; background: var(--bg); border: 1px solid var(--border); border-radius: 4px; color: var(--text-primary); font-size: 13px;">
            </div>
          </div>
          <div style="margin-bottom: 12px;">
            <label style="font-size: 12px; color: var(--text-secondary); display: block; margin-bottom: 4px;">Default Tier</label>
            <select id="new-server-tier" style="width: 100%; padding: 8px; background: var(--bg); border: 1px solid var(--border); border-radius: 4px; color: var(--text-primary); font-size: 13px;">
              <option value="1">Tier 1 (Always approve)</option>
              <option value="2" selected>Tier 2 (Anomaly detection)</option>
              <option value="3">Tier 3 (Always allow)</option>
            </select>
          </div>
          <div style="display: flex; gap: 8px;">
            <button id="save-server-btn" style="flex: 1; padding: 8px; background: var(--green); color: #fff; border: none; border-radius: 4px; cursor: pointer; font-size: 13px;">Save</button>
            <button id="cancel-server-btn" style="flex: 1; padding: 8px; background: var(--surface); color: var(--text-secondary); border: 1px solid var(--border); border-radius: 4px; cursor: pointer; font-size: 13px;">Cancel</button>
          </div>
        </div>
      </div>

      <!-- Threat Panel -->
      <div class="threat-panel collapsed">
        <div class="threat-header">
          <div class="threat-title">Security Threats</div>
          <div class="threat-toggle">▶</div>
        </div>
        <div class="threat-content" id="threat-alerts">
          <div class="empty-state">No threats detected</div>
        </div>
      </div>
    </div>
  </div>

  <!-- Pending Overlay -->
  <div class="pending-overlay" id="pending-overlay">
    <div class="pending-header">Pending Approvals</div>
    <div class="pending-items" id="pending-items"></div>
  </div>

  <script>
    // Constants
    // SEC-038: Do NOT embed the long-lived auth token in page source.
    // Use only the session token stored in sessionStorage by the login flow.
    const AUTH_TOKEN = sessionStorage.getItem('authToken') || '';
    // v0.10.6: server-baked flag mirroring _autoAuthLocalhost. When true,
    // the init-time auth gate does NOT redirect to '/' on empty AUTH_TOKEN,
    // because the server already admitted this loopback caller without a
    // bearer token. See dashboard-html.ts generateDashboardHTML() doc.
    const LOOPBACK_AUTH = ${JSON.stringify(options.loopbackAutoAuth === true)};
    const TIMEOUT_SECONDS = ${options.timeoutSeconds};
    const API_BASE = '';

    // State
    let apiState = {
      sovereignty: null,
      identity: null,
      handshakes: [],
      shr: null,
      status: null,
      systemPrompt: null,
    };

    let pendingRequests = new Map();
    let activityLog = [];
    const maxActivityItems = 50;

    // Helpers
    function esc(text) {
      if (!text) return '';
      const div = document.createElement('div');
      div.textContent = text;
      return div.innerHTML;
    }

    function formatTime(isoString) {
      if (!isoString) return '—';
      const date = new Date(isoString);
      return date.toLocaleString('en-US', {
        month: 'short',
        day: 'numeric',
        hour: '2-digit',
        minute: '2-digit',
      });
    }

    function truncate(str, len = 16) {
      if (!str) return '—';
      if (str.length <= len) return str;
      return str.slice(0, len) + '...';
    }

    function calculateSovereigntyScore(shr) {
      if (!shr || !shr.layers) return 0;
      const layers = shr.layers;
      let score = 100;

      if (layers.l1?.status === 'degraded') score -= 20;
      if (layers.l1?.status === 'inactive') score -= 35;
      if (layers.l2?.status === 'degraded') score -= 15;
      if (layers.l2?.status === 'inactive') score -= 25;
      if (layers.l3?.status === 'degraded') score -= 15;
      if (layers.l3?.status === 'inactive') score -= 25;
      if (layers.l4?.status === 'degraded') score -= 10;
      if (layers.l4?.status === 'inactive') score -= 20;

      return Math.max(0, Math.min(100, score));
    }

    async function fetchAPI(endpoint) {
      try {
        const response = await fetch(API_BASE + endpoint, {
          headers: {
            'Authorization': 'Bearer ' + AUTH_TOKEN,
          },
        });

        if (response.status === 401) {
          redirectToLogin();
          return null;
        }

        if (!response.ok) {
          console.error('API Error:', response.status);
          return null;
        }

        return await response.json();
      } catch (err) {
        console.error('Fetch error:', err);
        return null;
      }
    }

    // Approval DECISION calls (approve/deny) release a Tier-1 op, so the
    // server dispatches them on POST and requires the operator bearer token
    // even on loopback auto-auth (see dashboard.ts isLegacyApprovalDecision /
    // checkAuth requireToken). fetchAPI above issues a GET, which 404s against
    // those POST-only routes — using it here left the legacy buttons dead.
    // This helper issues the matching token-bearing POST so the buttons go
    // through the same token-gated decision surface as the v1.1 fortress view.
    //
    // Token requirement is by design: under loopback auto-auth the page is
    // admitted for read-only data WITHOUT a token (LOOPBACK_AUTH), but a
    // co-resident agent must not be able to self-approve, so the decision
    // gate still demands the operator token. When AUTH_TOKEN is empty (a
    // fresh loopback session that never logged in) the POST returns 401.
    //
    // We cannot recover by redirecting to the login page: under loopback
    // auto-auth the server treats the loopback caller as authenticated, so
    // both '/' and '/v1.0' serve the dashboard, never the login form — the
    // operator would have no way to supply a token. Instead, on 401 we prompt
    // for the operator token inline, persist it to sessionStorage, and retry
    // the decision ONCE with that token. This keeps the action token-gated
    // (the server still enforces requireToken) while giving the operator a
    // real path to approve. If they dismiss the prompt, the decision is left
    // pending — a safe no-op, never an auto-approve.
    async function postAPI(endpoint) {
      const send = (token) =>
        fetch(API_BASE + endpoint, {
          method: 'POST',
          headers: {
            'Authorization': 'Bearer ' + token,
          },
        });
      try {
        let response = await send(AUTH_TOKEN);

        // On 401, prompt for the operator token and retry. We re-prompt on a
        // rejected token rather than redirecting: under loopback auto-auth a
        // redirect to '/' is a dead end (the server serves the dashboard, not
        // the login form), so the inline prompt is the only path that reaches
        // a valid token. Each retry still hits the server requireToken gate —
        // the client never self-authorizes. A dismissed prompt leaves the op
        // pending (safe no-op, never an auto-approve).
        let prompt = 'Operator token required to record this decision. Paste your operator token:';
        while (response.status === 401) {
          const entered = (window.prompt(prompt) || '').trim();
          if (!entered) {
            // Operator dismissed the prompt — leave the op pending.
            return null;
          }
          sessionStorage.setItem('authToken', entered);
          response = await send(entered);
          prompt = 'That token was rejected. Paste a valid operator token, or cancel to leave this decision pending:';
        }

        if (!response.ok) {
          console.error('API Error:', response.status);
          return null;
        }

        return await response.json();
      } catch (err) {
        console.error('Fetch error:', err);
        return null;
      }
    }

    function redirectToLogin() {
      sessionStorage.removeItem('authToken');
      window.location.href = '/';
    }

    // API Updates
    async function updateSovereignty() {
      const data = await fetchAPI('/api/sovereignty');
      if (!data || data.error) return;

      apiState.sovereignty = data;

      // API returns { score, overall_level, layers: { l1, l2, l3, l4 }, ... }
      const score = data.score ?? 0;
      const badge = document.getElementById('sovereignty-badge');
      const scoreEl = document.getElementById('sovereignty-score');

      scoreEl.textContent = score;

      badge.classList.remove('degraded', 'inactive');
      if (score < 70) badge.classList.add('degraded');
      if (score < 40) badge.classList.add('inactive');

      updateLayerCards(data);
      updateOperatorCloudDisclosure(data.federation);
    }

    function updateOperatorCloudDisclosure(federation) {
      const el = document.getElementById('operator-cloud-disclosure');
      if (!el) return;
      const boundary = federation?.trust_boundary;
      if (!boundary || !boundary.operator_cloud_nodes) {
        el.style.display = 'none';
        el.textContent = '';
        return;
      }
      const label = boundary.provider_in_trust_boundary
        ? 'provider in trust boundary, not TEE'
        : 'local operator host';
      el.textContent = label + ': ' + (boundary.disclosure || '');
      el.style.display = 'block';
    }

    function updateLayerCards(data) {
      if (!data || !data.layers) return;

      const layers = data.layers;

      updateLayerCard('l1', layers.l1, layers.l1?.detail || 'AES-256-GCM');
      updateLayerCard('l2', layers.l2, layers.l2?.detail || 'Process-level');
      updateLayerCard('l3', layers.l3, layers.l3?.detail || 'Schnorr-Pedersen');
      updateLayerCard('l4', layers.l4, layers.l4?.detail || 'Weighted');
    }

    function updateLayerCard(layer, layerData, detail) {
      if (!layerData) return;

      const card = document.querySelector(\`[data-layer="\${layer}"]\`);
      if (!card) return;

      const status = layerData.status || 'inactive';
      card.classList.remove('degraded', 'inactive');

      if (status === 'degraded') {
        card.classList.add('degraded');
      } else if (status === 'inactive') {
        card.classList.add('inactive');
      }

      document.getElementById(\`\${layer}-status\`).textContent = status.toUpperCase();
      document.getElementById(\`\${layer}-detail\`).textContent = detail;
    }

    async function updateIdentity() {
      const data = await fetchAPI('/api/identity');
      if (!data) return;

      apiState.identity = data;

      // API returns { identities: [...], count, primary_id }
      // Find the primary identity from the array
      const primary = (data.identities || []).find(id => id.identity_id === data.primary_id) || {};
      document.getElementById('identity-label').textContent = primary.label || '—';
      document.getElementById('identity-did').textContent = truncate(primary.did, 24);
      document.getElementById('identity-did').title = primary.did || '';
      document.getElementById('identity-pubkey').textContent = truncate(primary.public_key, 24);
      document.getElementById('identity-pubkey').title = primary.public_key || '';
      document.getElementById('identity-created').textContent = formatTime(primary.created_at);
      document.getElementById('identity-count').textContent = data.count || '—';
    }

    async function updateHandshakes() {
      const data = await fetchAPI('/api/handshakes');
      if (!data) return;

      apiState.handshakes = data.handshakes || [];

      document.getElementById('handshake-count').textContent = data.count || '0';

      if (data.handshakes && data.handshakes.length > 0) {
        const latest = data.handshakes[0];
        document.getElementById('handshake-latest').textContent = truncate(latest.counterparty_id, 20);
        document.getElementById('handshake-latest').title = latest.counterparty_id || '';
        document.getElementById('handshake-tier').textContent = (latest.trust_tier || 'Unverified').toUpperCase();
        document.getElementById('handshake-time').textContent = formatTime(latest.completed_at);
      } else {
        document.getElementById('handshake-latest').textContent = '—';
        document.getElementById('handshake-tier').textContent = 'Unverified';
        document.getElementById('handshake-time').textContent = '—';
      }

      updateHandshakeTable(data.handshakes || []);
    }

    function updateHandshakeTable(handshakes) {
      const table = document.getElementById('handshake-table');

      if (!handshakes || handshakes.length === 0) {
        table.innerHTML = '<div class="table-empty">No handshakes completed yet</div>';
        return;
      }

      table.innerHTML = handshakes
        .map(
          (hs) => \`
        <div class="table-row">
          <div class="table-cell strong">\${esc(truncate(hs.counterparty_id, 24))}</div>
          <div class="table-cell">\${esc(hs.trust_tier || 'Unverified')}</div>
          <div class="table-cell">\${esc(hs.sovereignty_level || '—')}</div>
          <div class="table-cell">\${hs.verified ? 'Yes' : 'No'}</div>
          <div class="table-cell">\${formatTime(hs.completed_at)}</div>
          <div class="table-cell">\${formatTime(hs.expires_at)}</div>
        </div>
      \`
        )
        .join('');
    }

    async function updateSHR() {
      const data = await fetchAPI('/api/shr');
      if (!data) return;

      apiState.shr = data;
      renderSHRViewer(data);
    }

    function renderSHRViewer(shr) {
      const viewer = document.getElementById('shr-viewer');

      if (!shr || shr.error) {
        viewer.innerHTML = '<div class="empty-state">No SHR available</div>';
        return;
      }

      // SignedSHR shape: { body: { implementation, instance_id, layers, ... }, signed_by, signature }
      const body = shr.body || shr;

      let html = '';

      // Implementation
      html += \`
        <div class="shr-section">
          <div class="shr-section-header">
            <div class="shr-toggle">▼</div>
            <div>Implementation</div>
          </div>
          <div class="shr-section-content">
            <div class="shr-item">
              <div class="shr-key">sanctuary_version:</div>
              <div class="shr-value">\${esc(body.implementation?.sanctuary_version || '—')}</div>
            </div>
            <div class="shr-item">
              <div class="shr-key">node_version:</div>
              <div class="shr-value">\${esc(body.implementation?.node_version || '—')}</div>
            </div>
            <div class="shr-item">
              <div class="shr-key">generated_by:</div>
              <div class="shr-value">\${esc(body.implementation?.generated_by || '—')}</div>
            </div>
          </div>
        </div>
      \`;

      // Metadata
      html += \`
        <div class="shr-section">
          <div class="shr-section-header">
            <div class="shr-toggle">▼</div>
            <div>Metadata</div>
          </div>
          <div class="shr-section-content">
            <div class="shr-item">
              <div class="shr-key">instance_id:</div>
              <div class="shr-value">\${esc(truncate(body.instance_id, 20))}</div>
            </div>
            <div class="shr-item">
              <div class="shr-key">generated_at:</div>
              <div class="shr-value">\${formatTime(body.generated_at)}</div>
            </div>
            <div class="shr-item">
              <div class="shr-key">expires_at:</div>
              <div class="shr-value">\${formatTime(body.expires_at)}</div>
            </div>
          </div>
        </div>
      \`;

      // Layers
      if (body.layers) {
        html += \`<div class="shr-section">
          <div class="shr-section-header">
            <div class="shr-toggle">▼</div>
            <div>Layers</div>
          </div>
          <div class="shr-section-content">
        \`;

        for (const [key, layer] of Object.entries(body.layers)) {
          html += \`
            <div style="margin-bottom: 12px;">
              <div style="color: var(--blue); font-weight: 600; margin-bottom: 4px;">\${esc(key)}</div>
              <div style="padding-left: 12px;">
          \`;

          for (const [lkey, lvalue] of Object.entries(layer || {})) {
            const displayValue =
              typeof lvalue === 'boolean'
                ? lvalue
                  ? 'true'
                  : 'false'
                : esc(String(lvalue));
            html += \`
              <div class="shr-item">
                <div class="shr-key">\${esc(lkey)}:</div>
                <div class="shr-value">\${displayValue}</div>
              </div>
            \`;
          }

          html += \`
              </div>
            </div>
          \`;
        }

        html += \`
          </div>
        </div>
        \`;
      }

      // Capabilities
      if (shr.capabilities) {
        html += \`
          <div class="shr-section">
            <div class="shr-section-header">
              <div class="shr-toggle">▼</div>
              <div>Capabilities</div>
            </div>
            <div class="shr-section-content">
        \`;

        for (const [key, value] of Object.entries(shr.capabilities)) {
          const displayValue = value ? 'true' : 'false';
          html += \`
            <div class="shr-item">
              <div class="shr-key">\${esc(key)}:</div>
              <div class="shr-value">\${displayValue}</div>
            </div>
          \`;
        }

        html += \`
            </div>
          </div>
        \`;
      }

      // Signature
      html += \`
        <div class="shr-section">
          <div class="shr-section-header">
            <div class="shr-toggle">▼</div>
            <div>Signature</div>
          </div>
          <div class="shr-section-content">
            <div class="shr-item">
              <div class="shr-key">signed_by:</div>
              <div class="shr-value">\${esc(truncate(shr.signed_by, 20))}</div>
            </div>
            <div class="shr-item">
              <div class="shr-key">signature:</div>
              <div class="shr-value">\${esc(truncate(shr.signature, 32))}</div>
            </div>
          </div>
        </div>
      \`;

      viewer.innerHTML = html;

      // Add collapse functionality
      document.querySelectorAll('.shr-section-header').forEach((header) => {
        header.addEventListener('click', () => {
          header.closest('.shr-section').classList.toggle('collapsed');
        });
      });
    }

    async function updateStatus() {
      const data = await fetchAPI('/api/status');
      if (!data) return;

      apiState.status = data;

      document.getElementById('protections-count').textContent = data.protectionsCount || '0';
      document.getElementById('uptime-value').textContent = formatUptime(data.uptime);

      const connectionStatus = document.getElementById('connection-status');
      connectionStatus.classList.toggle('disconnected', !data.connected);

      // Show standalone mode banner if applicable
      const banner = document.getElementById('standalone-banner');
      if (banner && data.standalone_mode) {
        banner.style.display = 'flex';
      }
    }

    function formatUptime(seconds) {
      if (!seconds) return '—';
      const hours = Math.floor(seconds / 3600);
      const minutes = Math.floor((seconds % 3600) / 60);
      if (hours > 0) return \`\${hours}h \${minutes}m\`;
      return \`\${minutes}m\`;
    }

    // SSE Setup
    function setupSSE() {
      // v0.10.5: the standard browser EventSource API does not support a
      // headers option — it is silently dropped. Auth must travel as a
      // cookie (set by /auth/session and sent automatically by the
      // browser) or as a ?session= query parameter, both of which Stack
      // A's checkAuth honours. Loopback callers also bypass auth via the
      // v0.10.2 _autoAuthLocalhost path, which is the path Mini1
      // hits when the dashboard is auto-opened on 127.0.0.1.
      //
      // The endpoint itself is /events — Stack A's route table mounts it
      // there, and the previous /api/events URL was a 404 in every real
      // boot from v0.10.0 through v0.10.4. The retry loop that result
      // produced is exactly the "status bar flashing blue continuously"
      // Mini1 reported on v0.10.4.
      const eventSource = new EventSource(API_BASE + '/events');

      eventSource.addEventListener('init', (e) => {
        console.log('Connected to SSE');
      });

      eventSource.addEventListener('sovereignty-update', () => {
        updateSovereignty();
      });

      eventSource.addEventListener('handshake-update', () => {
        updateHandshakes();
      });

      eventSource.addEventListener('tool-call', (e) => {
        const data = JSON.parse(e.data);
        addActivityItem({
          type: 'tool-call',
          title: 'Tool Call',
          content: data.toolName,
          timestamp: new Date().toISOString(),
        });
      });

      eventSource.addEventListener('context-gate-decision', (e) => {
        const data = JSON.parse(e.data);
        addActivityItem({
          type: 'context-gate',
          title: 'Context Gate',
          content: data.decision,
          timestamp: new Date().toISOString(),
        });
      });

      eventSource.addEventListener('injection-alert', (e) => {
        const data = JSON.parse(e.data);
        addActivityItem({
          type: 'injection',
          title: 'Injection Alert',
          content: data.pattern,
          timestamp: new Date().toISOString(),
        });
        addThreatAlert(data);
      });

      eventSource.addEventListener('pending-request', (e) => {
        const data = JSON.parse(e.data);
        addPendingRequest(data);
      });

      eventSource.addEventListener('request-resolved', (e) => {
        const data = JSON.parse(e.data);
        removePendingRequest(data.requestId);
      });

      eventSource.addEventListener('sovereignty-profile-update', (e) => {
        try {
          const data = JSON.parse(e.data);
          if (data.profile) {
            applyProfileToUI(data.profile);
          }
          if (data.system_prompt) {
            apiState.systemPrompt = data.system_prompt;
            updatePromptDisplay(data.system_prompt);
          }
        } catch (err) {
          // Fallback to full refresh
          updateSovereigntyProfile();
        }
      });

      eventSource.addEventListener('proxy-server-status', (e) => {
        try {
          const data = JSON.parse(e.data);
          updateProxyServerStatus(data.server, data.state, data.tool_count, data.error);
        } catch (err) {
          // Fallback to full refresh
          loadProxyServers();
        }
      });

      eventSource.addEventListener('proxy-servers-update', () => {
        loadProxyServers();
      });

      // ── Mesh Health (WP-MVP-3 Follow-up #3) ─────────────────────────
      // The federation FailureModeDetector pushes per-tick snapshots and
      // per-detection alerts via the existing /events channel. Renders are
      // best-effort — if the panel DOM is absent (older HTML cache), we
      // silently skip rather than crashing.
      eventSource.addEventListener('mesh-health', (e) => {
        try {
          const snap = JSON.parse(e.data);
          renderMeshHealth(snap);
        } catch (err) { console.error('mesh-health render failed', err); }
      });
      eventSource.addEventListener('mesh-failure-mode-alert', (e) => {
        try {
          const alert = JSON.parse(e.data);
          appendMeshAlert(alert);
        } catch (err) { console.error('mesh alert render failed', err); }
      });
      eventSource.addEventListener('mesh-post-recovery-prompt', (e) => {
        try {
          const prompt = JSON.parse(e.data);
          renderMeshPostRecoveryPrompt(prompt);
        } catch (err) { console.error('mesh post-recovery render failed', err); }
      });

      eventSource.onerror = () => {
        console.error('SSE error');
        setTimeout(setupSSE, 5000);
      };
    }

    // ── Mesh Health rendering (WP-MVP-3 Follow-up #3) ────────────────
    function renderMeshHealth(snap) {
      const updatedAt = document.getElementById('mesh-health-updated-at');
      const rows = document.getElementById('mesh-health-rows');
      if (!rows || !snap) return;
      if (updatedAt) updatedAt.textContent = formatTime(snap.generated_at);
      const nodes = Array.isArray(snap.nodes) ? snap.nodes : [];
      if (nodes.length === 0) {
        rows.innerHTML = '<div class="empty-state">No mesh nodes seen yet.</div>';
        return;
      }
      rows.innerHTML = nodes.map((n) => {
        const flags = (n.flags || []).map((f) => '<span class="mesh-flag">' + esc(f) + '</span>').join(' ');
        return '<div class="mesh-row" data-rollup="' + esc(n.rollup) + '">' +
          '<span class="mesh-node-id">' + esc(n.node_id) + '</span>' +
          '<span class="mesh-presence">' + esc(n.presence) + '</span>' +
          '<span class="mesh-rollup">' + esc(n.rollup) + '</span>' +
          '<span class="mesh-flags">' + flags + '</span>' +
        '</div>';
      }).join('');
      const alertsBox = document.getElementById('mesh-health-alerts');
      if (alertsBox && Array.isArray(snap.open_alerts)) {
        alertsBox.innerHTML = snap.open_alerts.map((a) =>
          '<div class="mesh-alert" data-mode="' + esc(a.mode) + '">' +
          '<div class="mesh-alert-mode">' + esc(a.mode) + ' — ' + esc(a.target_node) + '</div>' +
          '<div class="mesh-alert-message">' + esc(a.message) + '</div>' +
          '</div>'
        ).join('');
      }
    }

    function appendMeshAlert(alert) {
      const alertsBox = document.getElementById('mesh-health-alerts');
      if (!alertsBox || !alert) return;
      const html = '<div class="mesh-alert" data-mode="' + esc(alert.mode) + '">' +
        '<div class="mesh-alert-mode">' + esc(alert.mode) + ' — ' + esc(alert.target_node) + '</div>' +
        '<div class="mesh-alert-message">' + esc(alert.message) + '</div>' +
        '</div>';
      alertsBox.insertAdjacentHTML('afterbegin', html);
    }

    function renderMeshPostRecoveryPrompt(prompt) {
      const box = document.getElementById('mesh-post-recovery-prompt');
      if (!box || !prompt) return;
      box.style.display = 'block';
      const creds = Array.isArray(prompt.credentials) ? prompt.credentials : [];
      box.innerHTML = '<div class="mesh-rotation-banner">' +
        '<strong>Post-rotation hygiene:</strong> we just rotated your fortress root key. ' +
        'Rotate externally-scoped broker credentials that third parties may still associate with ' +
        'the pre-rotation key material.' +
        '</div>' +
        '<ul class="mesh-rotation-list">' +
        creds.map((c) => '<li>' +
          '<span class="mesh-cred-name">' + esc(c.secret_name) + '</span>' +
          '<button class="mesh-cred-rotate" data-secret="' + esc(c.secret_name) + '">' +
          'rotate now</button>' +
          '</li>').join('') +
        '</ul>';
    }

    // Activity Feed
    function addActivityItem(item) {
      activityLog.unshift(item);
      if (activityLog.length > maxActivityItems) {
        activityLog.pop();
      }

      const feed = document.getElementById('activity-feed');
      const html = \`
        <div class="activity-item \${esc(item.type)}">
          <div class="activity-type">\${esc(item.title)}</div>
          <div class="activity-content">\${esc(item.content)}</div>
          <div class="activity-time">\${formatTime(item.timestamp)}</div>
        </div>
      \`;

      if (feed.querySelector('.empty-state')) {
        feed.innerHTML = '';
      }

      feed.insertAdjacentHTML('afterbegin', html);

      if (feed.children.length > maxActivityItems) {
        feed.lastChild.remove();
      }
    }

    // Pending Requests
    function addPendingRequest(request) {
      pendingRequests.set(request.requestId, {
        id: request.requestId,
        title: request.title,
        details: request.details,
        expiresAt: new Date(Date.now() + TIMEOUT_SECONDS * 1000),
      });

      updatePendingDisplay();
    }

    function removePendingRequest(requestId) {
      pendingRequests.delete(requestId);
      updatePendingDisplay();
    }

    function updatePendingDisplay() {
      const badge = document.getElementById('pending-item-badge');
      const count = pendingRequests.size;

      if (count > 0) {
        document.getElementById('pending-count').textContent = count;
        badge.style.display = 'flex';
      } else {
        badge.style.display = 'none';
      }

      const overlay = document.getElementById('pending-overlay');
      const items = document.getElementById('pending-items');

      if (count === 0) {
        items.innerHTML = '';
        overlay.classList.remove('show');
        return;
      }

      let html = '';
      for (const req of pendingRequests.values()) {
        const remaining = Math.max(0, Math.floor((req.expiresAt - Date.now()) / 1000));
        html += \`
          <div class="pending-item">
            <div class="pending-title">\${esc(req.title)}</div>
            <div class="pending-countdown">Expires in \${remaining}s</div>
            <div class="pending-actions">
              <button class="pending-btn pending-approve" data-id="\${req.id}">Approve</button>
              <button class="pending-btn pending-deny" data-id="\${req.id}">Deny</button>
            </div>
          </div>
        \`;
      }

      items.innerHTML = html;

      document.querySelectorAll('.pending-approve').forEach((btn) => {
        btn.addEventListener('click', async () => {
          const id = btn.getAttribute('data-id');
          await postAPI(\`/api/approve/\${id}\`);
        });
      });

      document.querySelectorAll('.pending-deny').forEach((btn) => {
        btn.addEventListener('click', async () => {
          const id = btn.getAttribute('data-id');
          await postAPI(\`/api/deny/\${id}\`);
        });
      });
    }

    // Threat Panel
    function addThreatAlert(alert) {
      const panel = document.querySelector('.threat-panel');
      const content = document.getElementById('threat-alerts');

      if (content.querySelector('.empty-state')) {
        content.innerHTML = '';
      }

      panel.classList.remove('collapsed');

      const html = \`
        <div class="threat-alert">
          <div class="threat-type">\${esc(alert.type || 'Injection Alert')}</div>
          <div class="threat-message">\${esc(alert.message || alert.pattern || '—')}</div>
        </div>
      \`;

      content.insertAdjacentHTML('afterbegin', html);

      const alerts = content.querySelectorAll('.threat-alert');
      if (alerts.length > 10) {
        alerts[alerts.length - 1].remove();
      }
    }

    // Threat Panel Toggle
    document.querySelector('.threat-header').addEventListener('click', () => {
      document.querySelector('.threat-panel').classList.toggle('collapsed');
    });

    // SHR Copy Button
    document.getElementById('copy-shr-btn').addEventListener('click', async () => {
      if (!apiState.shr) return;

      const json = JSON.stringify(apiState.shr, null, 2);
      try {
        await navigator.clipboard.writeText(json);
        const btn = document.getElementById('copy-shr-btn');
        const original = btn.textContent;
        btn.textContent = 'Copied!';
        setTimeout(() => {
          btn.textContent = original;
        }, 2000);
      } catch (err) {
        console.error('Copy failed:', err);
      }
    });

    // Pending Overlay Toggle
    document.getElementById('pending-item-badge').addEventListener('click', () => {
      document.getElementById('pending-overlay').classList.toggle('show');
    });

    // Sovereignty Profile
    let profileToggleLock = false;

    async function updateSovereigntyProfile() {
      try {
        const data = await fetchAPI('/api/sovereignty-profile');
        if (data && data.profile) {
          applyProfileToUI(data.profile);
          if (data.system_prompt) {
            apiState.systemPrompt = data.system_prompt;
            updatePromptDisplay(data.system_prompt);
          }
        }
      } catch (e) {
        // Profile not available
      }
    }

    function applyProfileToUI(profile) {
      const features = profile.features;
      for (const [key, value] of Object.entries(features)) {
        const enabled = value && value.enabled;

        // Update badge
        const badge = document.getElementById('badge-' + key);
        if (badge) {
          badge.textContent = enabled ? 'ON' : 'OFF';
          badge.className = 'profile-badge ' + (enabled ? 'enabled' : 'disabled');
        }

        // Update toggle (without triggering change event)
        const toggle = document.getElementById('toggle-' + key);
        if (toggle && toggle.checked !== enabled) {
          profileToggleLock = true;
          toggle.checked = enabled;
          profileToggleLock = false;
        }

        // Update card active state
        const card = document.querySelector('[data-feature="' + key + '"]');
        if (card) {
          card.classList.toggle('active', enabled);
        }

        // Feature-specific config UI updates
        if (key === 'injection_detection' && value.sensitivity) {
          document.querySelectorAll('#config-injection_detection .sensitivity-option').forEach(function(btn) {
            btn.classList.toggle('selected', btn.getAttribute('data-sensitivity') === value.sensitivity);
          });
        }

        if (key === 'context_gating' && value.policy_id) {
          const sel = document.getElementById('config-context-policy');
          if (sel) {
            // Add the policy as an option if not present
            let found = false;
            for (let i = 0; i < sel.options.length; i++) {
              if (sel.options[i].value === value.policy_id) { found = true; break; }
            }
            if (!found) {
              const opt = document.createElement('option');
              opt.value = value.policy_id;
              opt.textContent = value.policy_id;
              sel.appendChild(opt);
            }
            sel.value = value.policy_id;
          }
        }
      }

      const updatedEl = document.getElementById('profile-updated-at');
      if (updatedEl && profile.updated_at) {
        updatedEl.textContent = 'Updated: ' + new Date(profile.updated_at).toLocaleString();
      }
    }

    function updatePromptDisplay(promptText) {
      const display = document.getElementById('prompt-display');
      const content = document.getElementById('system-prompt-output');
      const tokenCount = document.getElementById('prompt-token-count');
      if (!display || !content) return;

      if (promptText) {
        content.textContent = promptText;
        // Rough token estimate: word count * 1.3
        const words = promptText.split(/\\s+/).filter(function(w) { return w.length > 0; }).length;
        const tokens = Math.round(words * 1.3);
        tokenCount.textContent = '~' + tokens + ' tokens';
        display.classList.add('visible');
      }
    }

    // Toggle handlers
    async function handleToggle(feature, enabled) {
      if (profileToggleLock) return;
      const payload = {};
      payload[feature] = { enabled: enabled };

      try {
        const response = await fetch(API_BASE + '/api/sovereignty-profile', {
          method: 'POST',
          headers: {
            'Authorization': 'Bearer ' + AUTH_TOKEN,
            'Content-Type': 'application/json',
          },
          body: JSON.stringify(payload),
        });

        if (response.status === 401) {
          redirectToLogin();
          return;
        }

        if (response.ok) {
          const data = await response.json();
          if (data.profile) {
            applyProfileToUI(data.profile);
          }
          if (data.system_prompt) {
            apiState.systemPrompt = data.system_prompt;
            updatePromptDisplay(data.system_prompt);
          }
        } else {
          // Revert toggle on failure
          const toggle = document.getElementById('toggle-' + feature);
          if (toggle) {
            profileToggleLock = true;
            toggle.checked = !enabled;
            profileToggleLock = false;
          }
        }
      } catch (err) {
        console.error('Toggle update failed:', err);
        // Revert toggle
        const toggle = document.getElementById('toggle-' + feature);
        if (toggle) {
          profileToggleLock = true;
          toggle.checked = !enabled;
          profileToggleLock = false;
        }
      }
    }

    // Wire up toggle switches
    document.querySelectorAll('.toggle-switch input').forEach(function(toggle) {
      toggle.addEventListener('change', function() {
        const feature = this.getAttribute('data-feature');
        handleToggle(feature, this.checked);
      });
    });

    // Wire up configure buttons
    document.querySelectorAll('.config-btn').forEach(function(btn) {
      btn.addEventListener('click', function() {
        const feature = this.getAttribute('data-config');
        const panel = document.getElementById('config-' + feature);
        if (panel) {
          panel.classList.toggle('open');
          this.textContent = panel.classList.contains('open') ? 'Close' : 'Configure';
        }
      });
    });

    // Injection sensitivity handler
    document.querySelectorAll('#config-injection_detection .sensitivity-option').forEach(function(btn) {
      btn.addEventListener('click', async function() {
        const sensitivity = this.getAttribute('data-sensitivity');
        const response = await fetch(API_BASE + '/api/sovereignty-profile', {
          method: 'POST',
          headers: {
            'Authorization': 'Bearer ' + AUTH_TOKEN,
            'Content-Type': 'application/json',
          },
          body: JSON.stringify({ injection_detection: { sensitivity: sensitivity } }),
        });
        if (response.ok) {
          document.querySelectorAll('#config-injection_detection .sensitivity-option').forEach(function(b) {
            b.classList.toggle('selected', b.getAttribute('data-sensitivity') === sensitivity);
          });
          const data = await response.json();
          if (data.profile) applyProfileToUI(data.profile);
          if (data.system_prompt) {
            apiState.systemPrompt = data.system_prompt;
            updatePromptDisplay(data.system_prompt);
          }
        }
      });
    });

    // Context gating policy selector handler
    document.getElementById('config-context-policy').addEventListener('change', async function() {
      const policyId = this.value;
      const response = await fetch(API_BASE + '/api/sovereignty-profile', {
        method: 'POST',
        headers: {
          'Authorization': 'Bearer ' + AUTH_TOKEN,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ context_gating: { policy_id: policyId } }),
      });
      if (response.ok) {
        const data = await response.json();
        if (data.profile) applyProfileToUI(data.profile);
        if (data.system_prompt) {
          apiState.systemPrompt = data.system_prompt;
          updatePromptDisplay(data.system_prompt);
        }
      }
    });

    // Generate prompt button
    document.getElementById('generate-prompt-btn').addEventListener('click', async () => {
      const data = await fetchAPI('/api/sovereignty-profile');
      if (data && data.system_prompt) {
        apiState.systemPrompt = data.system_prompt;
        updatePromptDisplay(data.system_prompt);
      }
    });

    // Copy prompt button
    document.getElementById('copy-prompt-btn').addEventListener('click', async () => {
      const content = document.getElementById('system-prompt-output');
      if (!content || !content.textContent) return;
      try {
        await navigator.clipboard.writeText(content.textContent);
        const btn = document.getElementById('copy-prompt-btn');
        const original = btn.textContent;
        btn.textContent = 'Copied!';
        setTimeout(() => { btn.textContent = original; }, 2000);
      } catch (err) {
        console.error('Copy failed:', err);
      }
    });

    // ── Proxy Server Management ─────────────────────────────────────

    let proxyServers = [];

    async function loadProxyServers() {
      try {
        const resp = await fetch(API_BASE + '/api/proxy/servers', {
          headers: { 'Authorization': 'Bearer ' + AUTH_TOKEN },
        });
        if (!resp.ok) return;
        const data = await resp.json();
        proxyServers = data.servers || [];
        renderProxyServers();
      } catch (err) {
        // Proxy endpoint may not be available
      }
    }

    function renderProxyServers() {
      const container = document.getElementById('proxy-servers-list');
      if (!container) return;

      if (proxyServers.length === 0) {
        container.innerHTML = '<div class="empty-state">No upstream servers configured</div>';
        return;
      }

      container.innerHTML = proxyServers.map(server => {
        const stateColor = server.state === 'connected' ? 'var(--green)' :
                          server.state === 'connecting' ? 'var(--amber)' : 'var(--red)';
        const stateLabel = server.state || 'disconnected';
        const tierLabel = 'Tier ' + server.default_tier;

        return \`
          <div class="proxy-server-card" data-server="\${esc(server.name)}" style="padding: 12px 16px; border-bottom: 1px solid var(--border);">
            <div style="display: flex; align-items: center; justify-content: space-between; margin-bottom: 6px;">
              <div style="display: flex; align-items: center; gap: 8px;">
                <span style="color: \${stateColor}; font-size: 10px;">\\u25CF</span>
                <span style="font-weight: 600; font-size: 14px;">\${esc(server.name)}</span>
                <span style="font-size: 11px; color: var(--text-secondary); background: var(--bg); padding: 2px 6px; border-radius: 3px;">\${esc(server.transport_type)}</span>
              </div>
              <div style="display: flex; align-items: center; gap: 8px;">
                <span style="font-size: 11px; color: var(--text-secondary);">\${server.tool_count} tools</span>
                <span style="font-size: 11px; color: var(--blue); background: rgba(88,166,255,0.1); padding: 2px 6px; border-radius: 3px;">\${tierLabel}</span>
                <button class="proxy-remove-btn" data-server="\${esc(server.name)}" style="background: none; border: none; color: var(--red); cursor: pointer; font-size: 14px; padding: 2px 6px;" title="Remove server">\\u00D7</button>
              </div>
            </div>
            <div style="font-size: 11px; color: var(--text-secondary);">
              Status: <span style="color: \${stateColor}">\${esc(stateLabel)}</span>
              \${server.error ? '<span style="color: var(--red);"> — ' + esc(server.error) + '</span>' : ''}
            </div>
            <div class="proxy-tools-expand" style="margin-top: 8px; display: none;">
              <div style="font-size: 11px; color: var(--text-secondary); margin-bottom: 4px;">Discovered Tools:</div>
              <div class="proxy-tools-list" style="font-size: 11px; font-family: monospace; color: var(--text-primary); max-height: 150px; overflow-y: auto;"></div>
            </div>
          </div>
        \`;
      }).join('');

      // Attach remove handlers
      container.querySelectorAll('.proxy-remove-btn').forEach(btn => {
        btn.addEventListener('click', (e) => {
          const serverName = e.target.dataset.server;
          removeProxyServer(serverName);
        });
      });

      // Attach expand/collapse on card click
      container.querySelectorAll('.proxy-server-card').forEach(card => {
        card.style.cursor = 'pointer';
        card.addEventListener('click', (e) => {
          if (e.target.classList.contains('proxy-remove-btn')) return;
          const expand = card.querySelector('.proxy-tools-expand');
          if (expand) {
            expand.style.display = expand.style.display === 'none' ? 'block' : 'none';
          }
        });
      });
    }

    function updateProxyServerStatus(serverName, state, toolCount, error) {
      const server = proxyServers.find(s => s.name === serverName);
      if (server) {
        server.state = state;
        server.tool_count = toolCount;
        server.error = error;
        renderProxyServers();
      }
    }

    async function addProxyServer(serverConfig) {
      const current = [...proxyServers];
      // Check for duplicate
      if (current.find(s => s.name === serverConfig.name)) {
        alert('A server with that name already exists');
        return;
      }
      current.push(serverConfig);

      try {
        const resp = await fetch(API_BASE + '/api/proxy/servers', {
          method: 'POST',
          headers: {
            'Authorization': 'Bearer ' + AUTH_TOKEN,
            'Content-Type': 'application/json',
          },
          body: JSON.stringify({ upstream_servers: current }),
        });
        if (!resp.ok) {
          const err = await resp.json();
          alert('Failed to add server: ' + (err.error || 'Unknown error'));
          return;
        }
        await loadProxyServers();
      } catch (err) {
        alert('Failed to add server: ' + err.message);
      }
    }

    async function removeProxyServer(serverName) {
      if (!confirm('Remove upstream server "' + serverName + '"?')) return;

      const updated = proxyServers.filter(s => s.name !== serverName);

      try {
        const resp = await fetch(API_BASE + '/api/proxy/servers', {
          method: 'POST',
          headers: {
            'Authorization': 'Bearer ' + AUTH_TOKEN,
            'Content-Type': 'application/json',
          },
          body: JSON.stringify({ upstream_servers: updated }),
        });
        if (!resp.ok) {
          const err = await resp.json();
          alert('Failed to remove server: ' + (err.error || 'Unknown error'));
          return;
        }
        await loadProxyServers();
      } catch (err) {
        alert('Failed to remove server: ' + err.message);
      }
    }

    // Add Server form handlers
    (function setupProxyForm() {
      const addBtn = document.getElementById('add-proxy-server-btn');
      const form = document.getElementById('add-server-form');
      const saveBtn = document.getElementById('save-server-btn');
      const cancelBtn = document.getElementById('cancel-server-btn');
      const transportSelect = document.getElementById('new-server-transport');
      const stdioFields = document.getElementById('stdio-fields');
      const sseFields = document.getElementById('sse-fields');

      if (!addBtn || !form) return;

      addBtn.addEventListener('click', () => {
        form.style.display = form.style.display === 'none' ? 'block' : 'none';
      });

      cancelBtn.addEventListener('click', () => {
        form.style.display = 'none';
      });

      transportSelect.addEventListener('change', () => {
        if (transportSelect.value === 'stdio') {
          stdioFields.style.display = 'block';
          sseFields.style.display = 'none';
        } else {
          stdioFields.style.display = 'none';
          sseFields.style.display = 'block';
        }
      });

      saveBtn.addEventListener('click', () => {
        const name = document.getElementById('new-server-name').value.trim();
        const type = transportSelect.value;
        const tier = parseInt(document.getElementById('new-server-tier').value, 10);

        if (!name) { alert('Server name is required'); return; }
        if (!/^[a-zA-Z0-9_-]+$/.test(name)) { alert('Name must contain only letters, numbers, hyphens, and underscores'); return; }

        const transport = { type };
        if (type === 'stdio') {
          const command = document.getElementById('new-server-command').value.trim();
          if (!command) { alert('Command is required for stdio transport'); return; }
          transport.command = command;
          const argsStr = document.getElementById('new-server-args').value.trim();
          if (argsStr) {
            transport.args = argsStr.split(',').map(s => s.trim()).filter(Boolean);
          }
        } else {
          const url = document.getElementById('new-server-url').value.trim();
          if (!url) { alert('URL is required for SSE transport'); return; }
          transport.url = url;
        }

        addProxyServer({
          name,
          transport,
          enabled: true,
          default_tier: tier,
        });

        // Reset form
        form.style.display = 'none';
        document.getElementById('new-server-name').value = '';
        document.getElementById('new-server-command').value = '';
        document.getElementById('new-server-args').value = '';
        document.getElementById('new-server-url').value = '';
      });
    })();

    // Initialize
    async function initialize() {
      // v0.10.6: gate on BOTH sessionStorage and the server-baked loopback
      // auto-auth mirror. Pre-fix, a fresh loopback tab had empty
      // sessionStorage.authToken AND was admitted by the server via
      // _autoAuthLocalhost — this single-operand gate redirected to '/'
      // which reloaded the same page, which redirected again, infinitely.
      // See generateDashboardHTML() header comment for full threat model.
      if (!AUTH_TOKEN && !LOOPBACK_AUTH) {
        redirectToLogin();
        return;
      }

      // Initial data fetch
      await Promise.all([
        updateSovereignty(),
        updateIdentity(),
        updateHandshakes(),
        updateSHR(),
        updateStatus(),
        updateSovereigntyProfile(),
        loadProxyServers(),
      ]);

      // Setup SSE for real-time updates
      setupSSE();

      // Refresh status periodically
      setInterval(updateStatus, 30000);
    }

    // Start
    initialize();
  </script>
</body>
</html>`;
}
