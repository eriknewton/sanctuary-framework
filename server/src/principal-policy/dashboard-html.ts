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
          window.location.href = '/dashboard';
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
  authToken?: string;
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
    const AUTH_TOKEN = '${options.authToken || ''}' || sessionStorage.getItem('authToken') || '';
    const TIMEOUT_SECONDS = ${options.timeoutSeconds};
    const API_BASE = '';

    // State
    let apiState = {
      sovereignty: null,
      identity: null,
      handshakes: [],
      shr: null,
      status: null,
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

    function redirectToLogin() {
      sessionStorage.removeItem('authToken');
      window.location.href = '/';
    }

    // API Updates
    async function updateSovereignty() {
      const data = await fetchAPI('/api/sovereignty');
      if (!data) return;

      apiState.sovereignty = data;

      const score = calculateSovereigntyScore(data.shr);
      const badge = document.getElementById('sovereignty-badge');
      const scoreEl = document.getElementById('sovereignty-score');

      scoreEl.textContent = score;

      badge.classList.remove('degraded', 'inactive');
      if (score < 70) badge.classList.add('degraded');
      if (score < 40) badge.classList.add('inactive');

      updateLayerCards(data.shr);
    }

    function updateLayerCards(shr) {
      if (!shr || !shr.layers) return;

      const layers = shr.layers;

      updateLayerCard('l1', layers.l1, layers.l1?.encryption || 'AES-256-GCM');
      updateLayerCard('l2', layers.l2, layers.l2?.isolation_type || 'Process-level');
      updateLayerCard('l3', layers.l3, layers.l3?.proof_system || 'Schnorr-Pedersen');
      updateLayerCard('l4', layers.l4, layers.l4?.reputation_mode || 'Weighted');
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

      const primary = data.primary || {};
      document.getElementById('identity-label').textContent = primary.label || '—';
      document.getElementById('identity-did').textContent = truncate(primary.did, 24);
      document.getElementById('identity-did').title = primary.did || '';
      document.getElementById('identity-pubkey').textContent = truncate(primary.publicKey, 24);
      document.getElementById('identity-pubkey').title = primary.publicKey || '';
      document.getElementById('identity-created').textContent = formatTime(primary.createdAt);
      document.getElementById('identity-count').textContent = data.identities?.length || '—';
    }

    async function updateHandshakes() {
      const data = await fetchAPI('/api/handshakes');
      if (!data) return;

      apiState.handshakes = data.handshakes || [];

      document.getElementById('handshake-count').textContent = data.handshakes?.length || '0';

      if (data.handshakes && data.handshakes.length > 0) {
        const latest = data.handshakes[0];
        document.getElementById('handshake-latest').textContent = truncate(latest.counterpartyId, 20);
        document.getElementById('handshake-latest').title = latest.counterpartyId || '';
        document.getElementById('handshake-tier').textContent = (latest.trustTier || 'Unverified').toUpperCase();
        document.getElementById('handshake-time').textContent = formatTime(latest.completedAt);
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
          <div class="table-cell strong">\${esc(truncate(hs.counterpartyId, 24))}</div>
          <div class="table-cell">\${esc(hs.trustTier || 'Unverified')}</div>
          <div class="table-cell">\${esc(hs.sovereigntyLevel || '—')}</div>
          <div class="table-cell">\${hs.verified ? 'Yes' : 'No'}</div>
          <div class="table-cell">\${formatTime(hs.completedAt)}</div>
          <div class="table-cell">\${formatTime(hs.expiresAt)}</div>
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

      if (!shr) {
        viewer.innerHTML = '<div class="empty-state">No SHR available</div>';
        return;
      }

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
              <div class="shr-value">\${esc(shr.implementation?.sanctuary_version || '—')}</div>
            </div>
            <div class="shr-item">
              <div class="shr-key">node_version:</div>
              <div class="shr-value">\${esc(shr.implementation?.node_version || '—')}</div>
            </div>
            <div class="shr-item">
              <div class="shr-key">generated_by:</div>
              <div class="shr-value">\${esc(shr.implementation?.generated_by || '—')}</div>
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
              <div class="shr-value">\${esc(truncate(shr.instance_id, 20))}</div>
            </div>
            <div class="shr-item">
              <div class="shr-key">generated_at:</div>
              <div class="shr-value">\${formatTime(shr.generated_at)}</div>
            </div>
            <div class="shr-item">
              <div class="shr-key">expires_at:</div>
              <div class="shr-value">\${formatTime(shr.expires_at)}</div>
            </div>
          </div>
        </div>
      \`;

      // Layers
      if (shr.layers) {
        html += \`<div class="shr-section">
          <div class="shr-section-header">
            <div class="shr-toggle">▼</div>
            <div>Layers</div>
          </div>
          <div class="shr-section-content">
        \`;

        for (const [key, layer] of Object.entries(shr.layers)) {
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
      const eventSource = new EventSource(API_BASE + '/api/events', {
        headers: {
          'Authorization': 'Bearer ' + AUTH_TOKEN,
        },
      });

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

      eventSource.onerror = () => {
        console.error('SSE error');
        setTimeout(setupSSE, 5000);
      };
    }

    // Activity Feed
    function addActivityItem(item) {
      activityLog.unshift(item);
      if (activityLog.length > maxActivityItems) {
        activityLog.pop();
      }

      const feed = document.getElementById('activity-feed');
      const html = \`
        <div class="activity-item \${item.type}">
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
          await fetchAPI(\`/api/approve/\${id}\`);
        });
      });

      document.querySelectorAll('.pending-deny').forEach((btn) => {
        btn.addEventListener('click', async () => {
          const id = btn.getAttribute('data-id');
          await fetchAPI(\`/api/deny/\${id}\`);
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

    // Initialize
    async function initialize() {
      if (!AUTH_TOKEN) {
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
