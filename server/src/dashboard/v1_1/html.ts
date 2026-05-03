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
import { SANCTUARY_VERSION } from "../../config.js";

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
  /**
   * Server build-time binary version (read from package.json at module
   * load). Surfaced as a topbar pill so operators can verify the running
   * binary matches what they expect (Finding CCC, v1.2.0-rc.3). Defaults
   * to the package's own version constant; tests override.
   */
  sanctuaryVersion?: string;
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
/* Click-to-inspect affordance: the head sub-row of a fortress-column
   agent row is a click target. cursor + hover signal clickability;
   focus ring keeps keyboard navigation legible for screen-reader users
   who tab to the role="button" head. */
.agent-row-head[data-action="agent-row-inspect-open"] { cursor: pointer; border-radius: var(--rad); padding: 4px 6px; margin: -4px -6px; }
.agent-row-head[data-action="agent-row-inspect-open"]:hover { background: var(--paper-3); }
.agent-row-head[data-action="agent-row-inspect-open"]:focus-visible { outline: 2px solid var(--ink-3); outline-offset: 1px; }
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
.policy-center { max-width: 980px; margin: 0 auto; }
.policy-center .eyebrow { margin: 0 0 6px; color: var(--ink-3); font-family: var(--mono); font-size: 12px; letter-spacing: 0; }
.policy-center h1 { font-family: var(--serif); font-size: 36px; line-height: 1.08; font-weight: 400; margin: 0 0 10px; }
.policy-subtitle { max-width: 860px; color: var(--ink-2); font-size: 15px; margin: 0 0 24px; }
.policy-panel { background: var(--surface); border: 1px solid var(--rule); border-radius: var(--rad-lg); padding: 20px; margin: 18px 0; }
.policy-panel h2 { font-family: var(--serif); font-size: 22px; font-weight: 400; margin: 0 0 14px; }
.template-grid { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 12px; }
.template-card { background: var(--surface-2); border: 1px solid var(--rule); border-radius: var(--rad); padding: 14px; min-height: 132px; }
.template-card-head { display: flex; justify-content: space-between; align-items: center; gap: 8px; margin-bottom: 12px; }
.severity { border-radius: 999px; padding: 2px 9px; font-family: var(--mono); font-size: 11px; font-weight: 700; }
.severity.low { color: var(--sage); background: var(--sage-bg); }
.severity.medium { color: var(--ochre); background: var(--ochre-bg); }
.template-id { background: var(--paper-3); border-radius: var(--rad); padding: 2px 7px; color: var(--ink-3); }
.template-card h3 { font-size: 16px; margin: 0 0 6px; }
.template-card p { color: var(--ink-3); margin: 0; font-size: 14px; }
.rules-scroll { overflow-x: auto; }
.rules-table { width: 100%; border-collapse: collapse; min-width: 760px; }
.rules-table th { text-align: left; color: var(--ink-3); font-family: var(--mono); font-size: 12px; letter-spacing: 0; padding: 8px 10px; border-bottom: 1px solid var(--rule); }
.rules-table td { padding: 12px 10px; border-bottom: 1px solid var(--rule); vertical-align: top; }
.link-btn, .template-cell { border: 0; background: transparent; color: var(--ink); padding: 0; cursor: pointer; font: inherit; text-align: left; }
.template-cell { font-family: var(--mono); max-width: 180px; overflow-wrap: anywhere; }
.template-picker { position: absolute; z-index: 20; margin-top: 8px; width: min(420px, calc(100vw - 80px)); background: var(--surface); border: 1px solid var(--rule-2); border-radius: var(--rad); box-shadow: var(--shadow); padding: 10px; }
.template-picker-options { display: grid; gap: 6px; max-height: 320px; overflow-y: auto; }
.template-option { display: grid; grid-template-columns: 18px 1fr; gap: 8px; padding: 8px; border: 1px solid var(--rule); border-radius: var(--rad); background: var(--surface-2); }
.template-option small { display: block; color: var(--ink-3); margin-top: 2px; }
.template-picker-actions { display: flex; justify-content: flex-end; gap: 8px; margin-top: 10px; }
.allow-count { color: var(--sage); font-weight: 700; }
.block-count { color: var(--rust); }
.toggle-on { display: inline-block; width: 28px; height: 16px; border-radius: 999px; background: var(--sage); position: relative; }
.toggle-on::after { content: ""; position: absolute; right: 2px; top: 2px; width: 12px; height: 12px; border-radius: 50%; background: var(--surface); }
.error-text { color: var(--rust); margin: 8px 0 0; }
.intel-center { max-width: 980px; margin: 0 auto; }
.intel-center .eyebrow { margin: 0 0 6px; color: var(--ink-3); font-family: var(--mono); font-size: 12px; letter-spacing: 0; }
.intel-center h1 { font-family: var(--serif); font-size: 36px; line-height: 1.08; font-weight: 400; margin: 0 0 10px; }
.intel-subtitle { max-width: 860px; color: var(--ink-2); font-size: 15px; margin: 0 0 24px; }
.intel-panel { background: var(--surface); border: 1px solid var(--rule); border-radius: var(--rad-lg); padding: 20px; margin: 18px 0; }
.intel-panel h2 { font-family: var(--serif); font-size: 22px; font-weight: 400; margin: 0 0 14px; }
.intel-row { display: grid; grid-template-columns: 200px 1fr auto; gap: 16px; padding: 14px 0; border-bottom: 1px solid var(--rule); align-items: start; }
.intel-row:last-child { border-bottom: 0; }
.intel-row-name { font-weight: 600; }
.intel-row-name small { display: block; color: var(--ink-3); font-weight: 400; font-size: 12px; margin-top: 2px; font-family: var(--mono); }
.intel-row-body { display: flex; flex-direction: column; gap: 6px; min-width: 0; }
.intel-row-current { display: flex; gap: 8px; align-items: center; flex-wrap: wrap; }
.intel-row-tradeoff { color: var(--ink-2); font-size: 13px; line-height: 1.5; }
.intel-status-dot { display: inline-block; width: 10px; height: 10px; border-radius: 50%; }
.intel-status-dot.green { background: var(--sage); }
.intel-status-dot.yellow { background: var(--ochre); }
.intel-status-dot.red { background: var(--rust); }
.intel-hardware { display: grid; grid-template-columns: max-content 1fr; gap: 4px 16px; font-size: 13px; }
.intel-hardware dt { color: var(--ink-3); font-family: var(--mono); }
.intel-hardware dd { margin: 0; }
.intel-modal-backdrop {
  position: fixed; inset: 0; background: rgba(0,0,0,0.4); z-index: 1100;
  display: flex; align-items: flex-start; justify-content: center;
  padding: 40px 16px; overflow-y: auto;
}
.intel-modal {
  background: var(--surface); border: 1px solid var(--rule-2); border-radius: var(--rad-lg);
  box-shadow: 0 8px 32px rgba(0,0,0,0.18); padding: 24px;
  width: 100%; max-width: 640px;
}
.intel-modal h2 { font-family: var(--serif); font-size: 22px; font-weight: 400; margin: 0 0 8px; }
.intel-modal-subtitle { color: var(--ink-3); margin: 0 0 18px; font-size: 13px; }
.intel-option {
  border: 1px solid var(--rule); border-radius: var(--rad); padding: 12px;
  margin-bottom: 10px; background: var(--surface-2); cursor: pointer;
  display: grid; grid-template-columns: 18px 1fr; gap: 10px; align-items: start;
}
.intel-option.selected { border-color: var(--ink); background: var(--surface); }
.intel-option-body strong { display: block; font-size: 14px; margin-bottom: 4px; }
.intel-option-body small { display: block; color: var(--ink-3); font-size: 12px; line-height: 1.5; }
.intel-suboptions { margin-top: 10px; padding: 10px; background: var(--paper-3); border-radius: var(--rad); }
.intel-suboptions label { display: block; margin: 6px 0; font-size: 13px; }
.intel-suboptions input[type="text"], .intel-suboptions input[type="password"] {
  width: 100%; padding: 6px 8px; border: 1px solid var(--rule); border-radius: var(--rad);
  font-family: var(--mono); font-size: 12px; box-sizing: border-box;
}
.intel-modal-actions { display: flex; justify-content: flex-end; gap: 8px; margin-top: 18px; }
.banner-warn {
  background: var(--ochre-bg); color: var(--ochre); border: 1px solid var(--ochre);
  border-radius: var(--rad); padding: 8px 12px; margin: 8px 0; font-size: 13px;
}
.banner-info {
  background: var(--indigo-bg); color: var(--indigo); border: 1px solid var(--indigo);
  border-radius: var(--rad); padding: 8px 12px; margin: 8px 0; font-size: 13px;
}
.btn.chip {
  border-radius: 999px; padding: 4px 12px; font-size: 12px;
  background: var(--surface-2); border-color: var(--rule);
}
.btn.chip:hover:not(:disabled) { background: var(--paper-3); }
/* Finding DDD (v1.2.0-rc.5): the concierge card uses a bounded
 * max-height + the history is the inner scroll container with
 * min-height: 0 (so flex shrink works in WebKit) + the composer is
 * flex-shrink: 0 (so it stays pinned at the bottom of the card
 * regardless of how much history is above). The pre-rc.5 layout used
 * min-height: calc(100vh - 180px) on the card and min-height: 360px
 * on the history; with no height bound, the card grew to fit content,
 * the history never scrolled internally (scrollHeight === clientHeight),
 * and on long threads the composer was pushed below the page fold.
 * Operator quote from Pass 5 drill: "It does move the response up
 * dynamically, but the input box is below the fold, so I still have
 * to scroll." rc.5 closes that with a structural layout fix.
 */
.concierge-card {
  display: flex; flex-direction: column;
  height: calc(100vh - 180px);
  max-height: calc(100vh - 180px);
  min-height: 360px;
  padding: 16px 18px;
  gap: 0;
}
.concierge-header {
  display: flex; align-items: center; justify-content: space-between;
  gap: 12px; padding-bottom: 12px; border-bottom: 1px solid var(--rule);
  flex-wrap: wrap;
  flex-shrink: 0;
}
.concierge-persona {
  display: flex; align-items: baseline; gap: 8px;
  font-size: 14px;
}
.concierge-persona strong { font-size: 14px; }
.concierge-badge { white-space: nowrap; }
.concierge-history {
  flex: 1 1 auto;
  min-height: 0;
  overflow-y: auto;
  padding: 14px 4px;
  display: flex; flex-direction: column; gap: 14px;
}
.concierge-msg {
  display: flex; flex-direction: column; gap: 4px;
  max-width: 80%;
}
.concierge-msg-author {
  font-size: 11px;
}
.concierge-msg-body {
  padding: 10px 14px; border-radius: 12px;
  border: 1px solid var(--rule); background: var(--surface);
  white-space: pre-wrap; word-wrap: break-word;
  font-size: 14px; line-height: 1.5;
}
.concierge-msg-concierge { align-self: flex-start; }
.concierge-msg-operator { align-self: flex-end; align-items: flex-end; }
.concierge-msg-operator .concierge-msg-body {
  background: var(--ink); color: var(--paper); border-color: var(--ink);
}
.concierge-empty {
  padding: 24px 8px; text-align: left;
  font-size: 13px; line-height: 1.6;
}
.concierge-composer {
  display: flex; gap: 10px; align-items: center;
  padding: 12px 0 8px;
  border-top: 1px solid var(--rule);
  flex-shrink: 0;
}
.concierge-composer input {
  flex: 1; min-width: 0;
  padding: 10px 14px;
  border: 1px solid var(--rule); border-radius: var(--rad);
  font-family: var(--sans); font-size: 14px;
  background: var(--surface); color: var(--ink);
}
.concierge-composer input:focus {
  outline: none; border-color: var(--ink-3);
}
.concierge-composer .btn-primary {
  padding: 8px 18px; font-size: 13px; flex-shrink: 0;
}
.concierge-chips {
  display: flex; flex-wrap: wrap; gap: 6px;
  padding: 10px 0 0;
}
.concierge-chips::before {
  content: "Try:"; color: var(--ink-3); font-size: 12px;
  align-self: center; margin-right: 4px;
}
.concierge-foot {
  margin: 12px 0 0; padding-top: 10px; border-top: 1px dashed var(--rule);
  font-size: 12px;
}
.concierge-foot a { color: var(--ink-2); }
.tier1-approval-card {
  background: var(--ochre-bg); border: 1px solid var(--ochre);
  border-radius: var(--rad); padding: 14px 16px; margin: 12px 0;
}
.tier1-approval-card h3 {
  margin: 0 0 8px; color: var(--ochre); font-size: 14px;
}
.tier1-approval-card p { margin: 0 0 12px; font-size: 13px; }
.tier1-approval-card .actions {
  display: flex; gap: 8px; flex-wrap: wrap;
}
@media (max-width: 1100px) {
  .app, .app.route-full { grid-template-columns: 56px 1fr; grid-template-areas: "sidebar topbar" "sidebar main"; }
  .fortress { display: none; }
  .sidebar h1, .sidebar nav a span { display: none; }
  .template-grid { grid-template-columns: 1fr; }
  .policy-center h1 { font-size: 30px; }
  .intel-center h1 { font-size: 30px; }
  .intel-row { grid-template-columns: 1fr; }
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
  { id: "intelligence", label: "Intelligence" },
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
  const sanctuaryVersion = options.sanctuaryVersion ?? SANCTUARY_VERSION;
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
    sanctuaryVersion,
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
        <span class="pill" data-pill="version">v${escHtml(sanctuaryVersion)}</span>
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
