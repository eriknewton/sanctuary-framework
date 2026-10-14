/**
 * Sanctuary Dashboard: Multi-tenant overview HTML
 *
 * Renders the `/agents` page: a per-tenant table with status pill, passphrase
 * status, last activity, and deep-link into each tenant's own dashboard.
 * Pure-string template consistent with `html.ts`: no client framework, no
 * build step, CSP-friendly. Slice 2b: it reads the server's design tokens and
 * bundled faces and follows the console's light or dark choice; it declares
 * no palette or font stack of its own.
 */

import { CONSOLE_FONT_FACE_CSS } from "./design-fonts.js";
import { PAPER_INK_ROOT_TOKENS_CSS, THEME_BOOTSTRAP_SCRIPT } from "./design-tokens.js";
import type {
  MultiTenantSnapshot,
  MultiTenantTenantRow,
} from "./multi-aggregator.js";

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
  probeState: MultiTenantTenantRow["probe_state"],
  initialized: boolean
): { label: string; cls: string } {
  if (probeState === "confirmed") {
    return { label: "running", cls: "pill-running" };
  }
  // A port answered HTTP but did not prove it is a Sanctuary tenant. Never claim
  // "running" here: it may be a foreign process on a reused port or an older
  // build. Surface the honest "port answered, not confirmed" state.
  if (probeState === "answered_unconfirmed") {
    return { label: "port answered, not confirmed", cls: "pill-unconfirmed" };
  }
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
      ? `<tr class="empty"><td colspan="6">No tenants found. Run <code>sanctuary protect</code> with <code>SANCTUARY_STORAGE_PATH</code> to create one.</td></tr>`
      : snapshot.tenants
          .map((t) => {
            const pill = statusPill(t.probe_state, t.initialized);
            const link = t.dashboard_url
              ? `<a href="${escHtml(t.dashboard_url)}" target="_blank" rel="noopener">${escHtml(t.dashboard_url)}</a>`
              : `<span class="muted">None</span>`;
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
<title>Sanctuary: Multi-Agent Overview</title>
<script>${THEME_BOOTSTRAP_SCRIPT}</script>
<style>
${CONSOLE_FONT_FACE_CSS}
${PAPER_INK_ROOT_TOKENS_CSS}
* { box-sizing: border-box; }
body {
  margin: 0;
  font-family: var(--sans);
  background: var(--paper);
  color: var(--ink);
  padding: 32px;
}
header {
  max-width: 1080px;
  margin: 0 auto 24px;
}
h1 {
  font-family: var(--display);
  font-size: 22px;
  font-weight: 600;
  margin: 0 0 6px;
  letter-spacing: -0.01em;
}
header p {
  margin: 0;
  color: var(--ink-2);
  font-size: var(--text-base);
}
.summary {
  display: flex;
  gap: 16px;
  margin: 16px 0 24px;
  flex-wrap: wrap;
}
.summary .chip {
  background: var(--surface);
  border: 1px solid var(--rule);
  border-radius: 999px;
  padding: 6px 14px;
  font-size: var(--text-sm);
  color: var(--ink-2);
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
  border: 1px solid var(--rule);
  border-radius: var(--rad-lg);
  overflow: hidden;
  font-size: var(--text-sm);
}
th, td {
  padding: 12px 14px;
  text-align: left;
  border-bottom: 1px solid var(--rule);
}
th {
  background: var(--paper-2);
  color: var(--ink-3);
  font-family: var(--mono);
  font-weight: 500;
  font-size: var(--text-xs);
  text-transform: uppercase;
  letter-spacing: 0.06em;
}
tr:last-child td { border-bottom: 0; }
tr.empty td {
  text-align: center;
  color: var(--ink-3);
  padding: 36px 14px;
}
td a {
  color: var(--accent);
  text-decoration: none;
}
td a:hover { text-decoration: underline; }
a:focus-visible { outline: 2px solid var(--focus); outline-offset: 2px; }
.mono { font-family: var(--mono); }
.path { color: var(--ink-3); font-size: var(--text-xs); }
.muted { color: var(--ink-3); }
/* Status pills carry a shape as well as a hue and a word: running is the
   pass circle, stopped is a square, port-answered-not-confirmed is the warn
   triangle, and empty is the neutral dash. */
.pill {
  display: inline-flex;
  align-items: center;
  gap: 6px;
  padding: 2px 10px;
  border-radius: 999px;
  font-family: var(--mono);
  font-size: var(--text-xs);
  font-weight: 600;
}
.pill::before { content: ""; width: 8px; height: 8px; flex: none; background: currentColor; }
.pill-running { background: var(--sage-bg); color: var(--sage); }
.pill-running::before { border-radius: 50%; }
.pill-stopped, .pill-unconfirmed { background: var(--ochre-bg); color: var(--ochre); }
.pill-stopped::before { border-radius: 0; }
.pill-unconfirmed::before { clip-path: polygon(50% 0, 100% 100%, 0 100%); }
.pill-empty { background: var(--surface-2); color: var(--ink-3); }
.pill-empty::before { height: 2px; border-radius: 1px; }
footer {
  max-width: 1080px;
  margin: 32px auto 0;
  color: var(--ink-3);
  font-size: var(--text-sm);
}
/* calc: the design's 4px small radius, --rad less one 2px step. */
code { font-family: var(--mono); background: var(--surface-2); padding: 1px 6px; border-radius: calc(var(--rad) - 2px); }
</style>
</head>
<body>
<header>
  <h1>Sanctuary: Multi-Agent Overview</h1>
  <p>${escHtml(snapshot.tenant_count)} tenant${snapshot.tenant_count === 1 ? "" : "s"} discovered on this host · ${escHtml(snapshot.running_count)} running.</p>
  <div class="summary">
    <span class="chip"><strong>Tenants</strong>${escHtml(snapshot.tenant_count)}</span>
    <span class="chip"><strong>Running</strong>${escHtml(snapshot.running_count)}</span>
    ${snapshot.answered_unconfirmed_count > 0
      ? `<span class="chip"><strong>Port answered, not confirmed</strong>${escHtml(snapshot.answered_unconfirmed_count)}</span>`
      : ""}
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
  <p>Tenant creation: <code>SANCTUARY_STORAGE_PATH=~/.sanctuary/&lt;name&gt; sanctuary protect …</code></p>
  <p>Single-tenant mode still works as before. Launch a multi-agent overview only with <code>sanctuary dashboard --multi</code>.</p>
</footer>
<script id="snapshot-data" type="application/json">${initialSnapshot}</script>
</body>
</html>`;
}
