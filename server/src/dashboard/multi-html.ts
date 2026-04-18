/**
 * Sanctuary Dashboard — Multi-tenant overview HTML
 *
 * Renders the `/agents` page: a per-tenant table with status pill, passphrase
 * status, last activity, and deep-link into each tenant's own dashboard.
 * Pure-string template consistent with `html.ts` — no client framework, no
 * build step, CSP-friendly.
 */

import type { MultiTenantSnapshot } from "./multi-aggregator.js";

function escHtml(value: unknown): string {
  if (value == null) return "";
  return String(value)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}

function formatRelative(iso: string | null, now: Date = new Date()): string {
  if (!iso) return "never";
  const then = new Date(iso).getTime();
  if (Number.isNaN(then)) return "unknown";
  const diffMs = Math.max(0, now.getTime() - then);
  const sec = Math.floor(diffMs / 1000);
  if (sec < 60) return `${sec}s ago`;
  const min = Math.floor(sec / 60);
  if (min < 60) return `${min}m ago`;
  const hr = Math.floor(min / 60);
  if (hr < 24) return `${hr}h ago`;
  const day = Math.floor(hr / 24);
  return `${day}d ago`;
}

function statusPill(
  running: boolean,
  initialized: boolean
): { label: string; cls: string } {
  if (running) return { label: "running", cls: "pill-running" };
  if (initialized) return { label: "stopped", cls: "pill-stopped" };
  return { label: "empty", cls: "pill-empty" };
}

export interface MultiAgentHTMLOptions {
  snapshot: MultiTenantSnapshot;
  /** Current host + port (for display). */
  host?: string;
  port?: number;
}

export function renderMultiAgentHTML(options: MultiAgentHTMLOptions): string {
  const { snapshot } = options;
  const rows =
    snapshot.tenants.length === 0
      ? `<tr class="empty"><td colspan="6">No tenants found — run <code>sanctuary wrap</code> with <code>SANCTUARY_STORAGE_PATH</code> to create one.</td></tr>`
      : snapshot.tenants
          .map((t) => {
            const pill = statusPill(t.running, t.initialized);
            const link = t.dashboard_url
              ? `<a href="${escHtml(t.dashboard_url)}" target="_blank" rel="noopener">${escHtml(t.dashboard_url)}</a>`
              : `<span class="muted">—</span>`;
            const pp =
              t.passphrase_status === "keychain"
                ? "Keychain"
                : t.passphrase_status === "fallback-file"
                ? "Fallback file"
                : "Not initialized";
            return `<tr data-tenant="${escHtml(t.name)}">
              <td class="cell-name"><strong>${escHtml(t.name)}</strong></td>
              <td><span class="pill ${pill.cls}">${escHtml(pill.label)}</span></td>
              <td class="mono">${link}</td>
              <td>${escHtml(pp)}</td>
              <td>${escHtml(formatRelative(t.last_activity))}</td>
              <td class="mono path">${escHtml(t.storage_path)}</td>
            </tr>`;
          })
          .join("");

  const initialSnapshot = JSON.stringify(snapshot)
    .replace(/</g, "\\u003c")
    .replace(/\u2028/g, "\\u2028")
    .replace(/\u2029/g, "\\u2029");

  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Sanctuary — Multi-Agent Overview</title>
<style>
:root {
  --bg: #07080c;
  --bg-2: #0f1220;
  --surface: #131729;
  --surface-2: #1a1f36;
  --border: #26304d;
  --ink: #eef1fb;
  --ink-dim: #b9c0dc;
  --ink-mute: #7e86a8;
  --accent: #7db4ff;
  --ok: #5ee4b6;
  --warn: #f5c371;
  --muted: #555e80;
}
* { box-sizing: border-box; }
body {
  margin: 0;
  font-family: -apple-system, BlinkMacSystemFont, "Inter", "Segoe UI", sans-serif;
  background: var(--bg);
  color: var(--ink);
  padding: 32px;
}
header {
  max-width: 1080px;
  margin: 0 auto 24px;
}
h1 {
  font-size: 22px;
  margin: 0 0 6px;
  letter-spacing: -0.01em;
}
header p {
  margin: 0;
  color: var(--ink-dim);
  font-size: 14px;
}
.summary {
  display: flex;
  gap: 16px;
  margin: 16px 0 24px;
  flex-wrap: wrap;
}
.summary .chip {
  background: var(--surface);
  border: 1px solid var(--border);
  border-radius: 999px;
  padding: 6px 14px;
  font-size: 13px;
  color: var(--ink-dim);
}
.summary .chip strong {
  color: var(--ink);
  font-weight: 600;
  margin-right: 6px;
}
main {
  max-width: 1080px;
  margin: 0 auto;
}
table {
  width: 100%;
  border-collapse: collapse;
  background: var(--surface);
  border: 1px solid var(--border);
  border-radius: 12px;
  overflow: hidden;
  font-size: 13px;
}
th, td {
  padding: 12px 14px;
  text-align: left;
  border-bottom: 1px solid var(--border);
}
th {
  background: var(--surface-2);
  color: var(--ink-dim);
  font-weight: 500;
  font-size: 11px;
  text-transform: uppercase;
  letter-spacing: 0.06em;
}
tr:last-child td { border-bottom: 0; }
tr.empty td {
  text-align: center;
  color: var(--ink-mute);
  padding: 36px 14px;
}
td a {
  color: var(--accent);
  text-decoration: none;
}
td a:hover { text-decoration: underline; }
.mono { font-family: "JetBrains Mono", ui-monospace, monospace; }
.path { color: var(--ink-mute); font-size: 12px; }
.muted { color: var(--ink-mute); }
.pill {
  display: inline-block;
  padding: 2px 10px;
  border-radius: 999px;
  font-size: 12px;
  font-weight: 500;
}
.pill-running { background: rgba(94, 228, 182, 0.12); color: var(--ok); }
.pill-stopped { background: rgba(245, 195, 113, 0.12); color: var(--warn); }
.pill-empty { background: rgba(85, 94, 128, 0.2); color: var(--muted); }
footer {
  max-width: 1080px;
  margin: 32px auto 0;
  color: var(--ink-mute);
  font-size: 12px;
}
code { background: var(--surface-2); padding: 1px 6px; border-radius: 4px; }
</style>
</head>
<body>
<header>
  <h1>Sanctuary — Multi-Agent Overview</h1>
  <p>${escHtml(snapshot.tenant_count)} tenant${snapshot.tenant_count === 1 ? "" : "s"} discovered on this host · ${escHtml(snapshot.running_count)} running.</p>
  <div class="summary">
    <span class="chip"><strong>Tenants</strong>${escHtml(snapshot.tenant_count)}</span>
    <span class="chip"><strong>Running</strong>${escHtml(snapshot.running_count)}</span>
    <span class="chip"><strong>Updated</strong>${escHtml(new Date(snapshot.generated_at).toLocaleTimeString())}</span>
  </div>
</header>
<main>
<table>
  <thead>
    <tr>
      <th>Tenant</th>
      <th>Status</th>
      <th>Dashboard</th>
      <th>Passphrase</th>
      <th>Last activity</th>
      <th>Storage</th>
    </tr>
  </thead>
  <tbody>
    ${rows}
  </tbody>
</table>
</main>
<footer>
  <p>Tenant creation: <code>SANCTUARY_STORAGE_PATH=~/.sanctuary/&lt;name&gt; sanctuary wrap …</code></p>
  <p>Single-tenant mode still works as before — launch a multi-agent overview only with <code>sanctuary dashboard --multi</code>.</p>
</footer>
<script id="snapshot-data" type="application/json">${initialSnapshot}</script>
</body>
</html>`;
}
