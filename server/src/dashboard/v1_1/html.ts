/**
 * Sanctuary v1.1 Dashboard — HTML Shell
 *
 * Server-rendered single-page HTML. Embeds the client module as inline
 * ESM. Pattern matches the v1.0 dashboard at `dashboard/html.ts` and the
 * principal-policy console.
 *
 * The shell renders the static skeleton: sidebar nav, top bar, three-pane
 * grid layout, FortressColumn slots, and the SSE wire-up bootstrap. The
 * client.ts module fills the dynamic regions from the hub API.
 *
 * Naming-discipline rule: no competitor names anywhere here.
 * No-em-dash rule: every operator-visible string uses periods, commas,
 * colons, or parentheses.
 * UBAI-retirement rule: no Universal-Basic-AI-style framing.
 * Composition partners (Coinbase x402, Anthropic, Google AP2, Hermes A2A)
 * are NOT named here at v1.1 ship.
 */

import { getClientScript } from "./client.js";

export interface DashboardV11HtmlOptions {
  /** Bearer token for hub API auth, when not running loopback auto-auth. */
  authToken?: string;
  /** Hub API base. Defaults to `/api/hub`. */
  hubApiBase?: string;
  /** Stream endpoint. Defaults to `/api/stream`. */
  streamUrl?: string;
  /** Operator identity id surfaced in the top bar. */
  identityId?: string;
  /** Stable fortress id surfaced in the top bar. */
  fortressId?: string;
  /** Override for tests: render the inline client script body. Defaults to true. */
  embedClient?: boolean;
}

const STYLES = String.raw`:root {
  --paper: #f7f5f0;
  --paper-2: #efece5;
  --paper-3: #e6e3da;
  --ink: #1a1a17;
  --ink-2: #39362f;
  --ink-3: #6a6659;
  --ink-4: #9a9585;
  --rule: #d8d4c8;
  --rule-2: #c4bfb0;
  --surface: #fdfcf8;
  --surface-2: #f1eee6;
  --sage: oklch(62% 0.07 145);
  --sage-bg: oklch(94% 0.02 145);
  --ochre: oklch(68% 0.09 75);
  --ochre-bg: oklch(94% 0.03 75);
  --rust: oklch(55% 0.11 35);
  --rust-bg: oklch(94% 0.03 35);
  --indigo: oklch(50% 0.10 260);
  --indigo-bg: oklch(94% 0.03 260);
  --mono: ui-monospace, "SF Mono", Menlo, Consolas, "Liberation Mono", monospace;
  --sans: -apple-system, BlinkMacSystemFont, "Segoe UI", Helvetica, Arial, sans-serif;
  --serif: "Iowan Old Style", "Charter", "Georgia", serif;
  --rad: 6px;
  --rad-lg: 10px;
  --shadow: 0 1px 2px rgba(0,0,0,0.04), 0 0 0 1px rgba(0,0,0,0.02);
}
[data-theme="dark"] {
  --paper: #121210;
  --paper-2: #171714;
  --paper-3: #1e1e1b;
  --ink: #ecebe5;
  --ink-2: #c7c5bd;
  --ink-3: #8d8a80;
  --ink-4: #5e5c55;
  --rule: #2a2a26;
  --rule-2: #36352f;
  --surface: #1a1a17;
  --surface-2: #1f1e1a;
  --sage: oklch(72% 0.08 145);
  --sage-bg: oklch(22% 0.03 145);
  --ochre: oklch(78% 0.09 75);
  --ochre-bg: oklch(22% 0.04 75);
  --rust: oklch(70% 0.11 35);
  --rust-bg: oklch(22% 0.04 35);
  --indigo: oklch(72% 0.09 260);
  --indigo-bg: oklch(22% 0.03 260);
}
* { box-sizing: border-box; }
html, body { margin: 0; padding: 0; }
body {
  font-family: var(--sans);
  font-size: 14px;
  background: var(--paper);
  color: var(--ink);
  line-height: 1.45;
}
.app {
  min-height: 100vh;
  display: grid;
  grid-template-columns: 220px 1fr 360px;
  grid-template-rows: 48px 1fr;
  grid-template-areas:
    "sidebar topbar topbar"
    "sidebar main fortress";
}
.app.route-full {
  grid-template-columns: 220px 1fr;
  grid-template-areas:
    "sidebar topbar"
    "sidebar main";
}
.sidebar { grid-area: sidebar; background: var(--paper-2); border-right: 1px solid var(--rule); padding: 12px 8px; }
.sidebar h1 { font-family: var(--serif); font-size: 16px; margin: 4px 8px 16px; }
.sidebar nav { display: flex; flex-direction: column; gap: 2px; }
.sidebar nav a {
  display: block; padding: 6px 10px; border-radius: var(--rad);
  color: var(--ink-2); text-decoration: none; font-size: 13px;
}
.sidebar nav a:hover { background: var(--paper-3); }
.sidebar nav a.active { background: var(--surface); color: var(--ink); border: 1px solid var(--rule); }
.topbar { grid-area: topbar; display: flex; align-items: center; gap: 12px; padding: 0 16px; border-bottom: 1px solid var(--rule); background: var(--surface); }
.topbar .brand { font-family: var(--serif); font-size: 14px; }
.topbar .pills { display: flex; gap: 6px; flex: 1; }
.pill {
  display: inline-flex; align-items: center; gap: 4px;
  padding: 2px 8px; border-radius: 12px; font-size: 11px;
  font-family: var(--mono); border: 1px solid var(--rule);
  background: var(--surface-2); color: var(--ink-2);
}
.pill.tone-verified { background: var(--sage-bg); color: var(--sage); border-color: var(--sage); }
.pill.tone-degraded { background: var(--ochre-bg); color: var(--ochre); border-color: var(--ochre); }
.pill.tone-unverified, .pill.tone-locked { background: var(--rust-bg); color: var(--rust); border-color: var(--rust); }
.pill.tone-info { background: var(--indigo-bg); color: var(--indigo); border-color: var(--indigo); }
.btn {
  display: inline-flex; align-items: center; gap: 4px;
  padding: 4px 10px; border-radius: var(--rad);
  background: var(--surface); border: 1px solid var(--rule);
  font-family: var(--sans); font-size: 12px; color: var(--ink);
  cursor: pointer;
}
.btn:hover:not(:disabled) { background: var(--surface-2); }
.btn:disabled { color: var(--ink-4); cursor: not-allowed; opacity: 0.7; }
.btn.btn-primary { background: var(--ink); color: var(--paper); border-color: var(--ink); }
.btn.btn-primary:hover:not(:disabled) { background: var(--ink-2); }
.btn.btn-danger { background: var(--rust-bg); color: var(--rust); border-color: var(--rust); }
.btn.tier1-pending { background: var(--ochre-bg); color: var(--ochre); border-color: var(--ochre); }
.btn.tier1-engaged { background: var(--rust-bg); color: var(--rust); border-color: var(--rust); }
.main { grid-area: main; overflow-y: auto; padding: 16px 24px; }
.fortress { grid-area: fortress; overflow-y: auto; border-left: 1px solid var(--rule); background: var(--paper-2); padding: 12px; display: flex; flex-direction: column; gap: 10px; }
.app.route-full .fortress { display: none; }
.card {
  background: var(--surface); border: 1px solid var(--rule);
  border-radius: var(--rad); padding: 12px;
}
.card h3 { margin: 0 0 8px; font-size: 13px; font-weight: 600; color: var(--ink); }
.muted { color: var(--ink-3); }
.mono { font-family: var(--mono); font-size: 12px; }
.row { display: flex; align-items: center; gap: 8px; padding: 6px 0; border-bottom: 1px dashed var(--rule); }
.row:last-child { border-bottom: 0; }
.row .grow { flex: 1; min-width: 0; }
.agent-row { flex-direction: column; align-items: stretch; gap: 6px; }
.agent-row-head { display: flex; align-items: center; gap: 8px; min-width: 0; }
.agent-row-head .grow { flex: 1; min-width: 0; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.agent-row-actions { display: flex; flex-wrap: wrap; gap: 4px; }
.kv { display: grid; grid-template-columns: max-content 1fr; gap: 4px 12px; font-size: 12px; }
.kv dt { color: var(--ink-3); }
.kv dd { margin: 0; color: var(--ink); }
.glyph { display: inline-block; width: 8px; height: 8px; border-radius: 50%; background: var(--ink-4); }
.glyph.online { background: var(--sage); }
.glyph.idle { background: var(--ochre); }
.glyph.away { background: var(--ochre); opacity: 0.5; }
.glyph.offline { background: var(--rust); }
.toast {
  position: fixed; bottom: 16px; right: 16px;
  background: var(--ink); color: var(--paper); padding: 8px 12px;
  border-radius: var(--rad); font-size: 12px; z-index: 1000;
  max-width: 360px;
}
.toast.error { background: var(--rust); color: var(--paper); }
.layer-card { background: var(--surface-2); border: 1px solid var(--rule); border-radius: var(--rad); padding: 8px; }
.layer-card h4 { margin: 0 0 4px; font-size: 12px; font-weight: 600; }
.layer-card p { margin: 0; font-size: 11px; color: var(--ink-3); }
.chat-thread { display: flex; flex-direction: column; gap: 8px; padding-bottom: 12px; }
.chat-msg { padding: 8px 10px; border-radius: var(--rad); border: 1px solid var(--rule); background: var(--surface); max-width: 78%; }
.chat-msg.system { background: var(--paper-3); color: var(--ink-3); font-size: 12px; max-width: 100%; }
.chat-msg.agent { align-self: flex-start; }
.chat-msg.operator { align-self: flex-end; background: var(--ink); color: var(--paper); }
.chat-msg .meta { font-size: 10px; color: var(--ink-4); margin-top: 4px; }
.composer { display: flex; gap: 8px; padding: 8px; border-top: 1px solid var(--rule); }
.composer input { flex: 1; padding: 6px 8px; border: 1px solid var(--rule); border-radius: var(--rad); font-family: var(--sans); }
.wizard-step { padding: 10px; border: 1px solid var(--rule); border-radius: var(--rad); margin-bottom: 8px; background: var(--surface); }
.wizard-step.active { border-color: var(--ink); }
.wizard-step.done { background: var(--sage-bg); border-color: var(--sage); }
.code-block { font-family: var(--mono); background: var(--paper-3); padding: 8px; border-radius: var(--rad); font-size: 12px; overflow-x: auto; }
@media (max-width: 1100px) {
  .app, .app.route-full { grid-template-columns: 56px 1fr; grid-template-areas: "sidebar topbar" "sidebar main"; }
  .fortress { display: none; }
  .sidebar h1, .sidebar nav a span { display: none; }
}
`;

/**
 * Sidebar nav definition. Out-of-scope screens at v1.1 ship are NOT
 * present in this list. Federation (v1.3), Composition (v1.4+), and full
 * Recovery management are excluded by construction.
 */
const NAV_ITEMS: Array<{ id: string; label: string }> = [
  { id: "dashboard", label: "Dashboard" },
  { id: "agents", label: "Agents" },
  { id: "policy", label: "Policy" },
  { id: "privacy", label: "Privacy" },
  { id: "coordination", label: "Coordination" },
  { id: "health", label: "Health" },
  { id: "exit-drill", label: "Exit drill" },
];

function escHtml(value: unknown): string {
  if (value == null) return "";
  return String(value)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}

export function renderDashboardV11Html(
  options: DashboardV11HtmlOptions = {},
): string {
  const authToken = options.authToken ?? "";
  const hubApiBase = options.hubApiBase ?? "/api/hub";
  const streamUrl = options.streamUrl ?? "/api/stream";
  const identityId = options.identityId ?? "operator";
  const fortressId = options.fortressId ?? "fortress";
  const embedClient = options.embedClient !== false;

  const nav = NAV_ITEMS.map(
    (n) =>
      `<a href="#${n.id}" data-route="${n.id}"><span>${escHtml(n.label)}</span></a>`,
  ).join("\n        ");

  // Emit raw JSON inside `<script type="application/json">`. HTML parsers
  // treat script content as RAWTEXT so character references are NOT
  // decoded; HTML-escaping the JSON would produce `&quot;` and break the
  // client's `JSON.parse(cfgEl.textContent)`. JSON.stringify already
  // escapes `"` and `\`; the only remaining concern is a config value
  // containing `</script>`, prevented by unicode-escaping `<`.
  const config = JSON.stringify({
    authToken,
    hubApiBase,
    streamUrl,
    identityId,
    fortressId,
  }).replace(/</g, "\\u003c");

  const clientBlock = embedClient
    ? `<script type="module">${getClientScript()}</script>`
    : `<!-- client script omitted by render option -->`;

  return `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>Sanctuary Dashboard v1.1</title>
  <style>${STYLES}</style>
</head>
<body>
  <div class="app" id="app" data-route="dashboard">
    <aside class="sidebar">
      <h1>Sanctuary</h1>
      <nav id="sidebar-nav">
        ${nav}
      </nav>
    </aside>
    <header class="topbar">
      <span class="brand mono">${escHtml(fortressId)}</span>
      <div class="pills" id="topbar-pills">
        <span class="pill" data-pill="deployment">deployment: local</span>
        <span class="pill" data-pill="mode">mode: solo</span>
        <span class="pill" data-pill="attestation">attestation: pending</span>
      </div>
      <button class="btn btn-danger" id="btn-lockdown" data-action="lockdown">Lockdown</button>
    </header>
    <main class="main" id="main"><p class="muted">Loading dashboard.</p></main>
    <aside class="fortress" id="fortress"><p class="muted">Loading fortress column.</p></aside>
  </div>
  <div id="toast-host" aria-live="polite"></div>
  <script id="dashboard-config" type="application/json">${config}</script>
  ${clientBlock}
</body>
</html>`;
}
