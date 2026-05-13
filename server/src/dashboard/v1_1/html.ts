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
  /* Type scale. Names are size-relative, not semantic, so refactors do
     not need to invent new names. Existing rules used these literal px
     values; tokens make future polish a one-line change. */
  --text-xs: 11px;
  --text-sm: 12px;
  --text-base: 13px;
  --text-md: 14px;
  --text-lg: 16px;
  --text-xl: 22px;
  --text-display: 36px;
  /* Spacing scale (4px multiples). Layout-specific magic numbers
     (220px sidebar, 360px fortress rail, concierge-card heights) stay
     as literals because the token system is for component padding /
     margin / gap, not grid track sizing. */
  --space-1: 4px;
  --space-2: 8px;
  --space-3: 12px;
  --space-4: 16px;
  --space-5: 24px;
  --space-6: 32px;
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
  font-size: var(--text-md);
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
.sidebar h1 { font-family: var(--serif); font-size: var(--text-lg); margin: 4px 8px 16px; }
.sidebar nav { display: flex; flex-direction: column; gap: 2px; }
.sidebar nav a {
  display: flex; align-items: center; gap: var(--space-2);
  padding: 6px 10px; border-radius: var(--rad);
  color: var(--ink-2); text-decoration: none; font-size: var(--text-base);
}
.sidebar nav a svg {
  flex-shrink: 0; width: 16px; height: 16px;
  color: var(--ink-3);
}
.sidebar nav a:hover { background: var(--paper-3); }
.sidebar nav a:hover svg { color: var(--ink-2); }
.sidebar nav a.active { background: var(--surface); color: var(--ink); border: 1px solid var(--rule); }
.sidebar nav a.active svg { color: var(--ink); }
.topbar { grid-area: topbar; display: flex; align-items: center; gap: var(--space-3); padding: 0 16px; border-bottom: 1px solid var(--rule); background: var(--surface); }
.topbar .brand { font-family: var(--serif); font-size: var(--text-md); }
.topbar .pills { display: flex; gap: 6px; flex: 1; }
.pill {
  display: inline-flex; align-items: center; gap: 4px;
  padding: 2px 8px; border-radius: 12px; font-size: var(--text-xs);
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
  font-family: var(--sans); font-size: var(--text-sm); color: var(--ink);
  cursor: pointer;
}
.btn:hover:not(:disabled) { background: var(--surface-2); }
.btn:disabled { color: var(--ink-4); cursor: not-allowed; opacity: 0.7; }
.btn.btn-primary { background: var(--ink); color: var(--paper); border-color: var(--ink); }
.btn.btn-primary:hover:not(:disabled) { background: var(--ink-2); }
.btn.btn-danger { background: var(--rust-bg); color: var(--rust); border-color: var(--rust); }
.btn.tier1-pending { background: var(--ochre-bg); color: var(--ochre); border-color: var(--ochre); }
.btn.tier1-engaged { background: var(--rust-bg); color: var(--rust); border-color: var(--rust); }
.btn.btn-icon {
  padding: 4px 6px;
  display: inline-flex; align-items: center; justify-content: center;
  color: var(--ink-2);
}
.btn.btn-icon svg { width: 16px; height: 16px; }
.btn.btn-icon .icon-sun { display: none; }
[data-theme="dark"] .btn.btn-icon .icon-moon { display: none; }
[data-theme="dark"] .btn.btn-icon .icon-sun { display: inline; }
.main { grid-area: main; overflow-y: auto; padding: 16px 24px; }
.fortress { grid-area: fortress; overflow-y: auto; border-left: 1px solid var(--rule); background: var(--paper-2); padding: var(--space-3); display: flex; flex-direction: column; gap: 10px; }
.app.route-full .fortress { display: none; }
.card {
  background: var(--surface); border: 1px solid var(--rule);
  border-radius: var(--rad); padding: var(--space-3);
}
.card h3 { margin: 0 0 8px; font-size: var(--text-base); font-weight: 600; color: var(--ink); }
.muted { color: var(--ink-3); }
.mono { font-family: var(--mono); font-size: var(--text-sm); }
.row { display: flex; align-items: center; gap: var(--space-2); padding: 6px 0; border-bottom: 1px dashed var(--rule); }
.row:last-child { border-bottom: 0; }
.row .grow { flex: 1; min-width: 0; }
.agent-row { flex-direction: column; align-items: stretch; gap: 6px; }
.agent-row-head { display: flex; align-items: center; gap: var(--space-2); min-width: 0; }
.agent-row-head .grow { flex: 1; min-width: 0; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.agent-row-actions { display: flex; flex-wrap: wrap; gap: 4px; }
/* Click-to-inspect affordance: the head sub-row of a fortress-column
   agent row is a click target. cursor + hover signal clickability;
   focus ring keeps keyboard navigation legible for screen-reader users
   who tab to the role="button" head. */
.agent-row-head[data-action="agent-row-inspect-open"] { cursor: pointer; border-radius: var(--rad); padding: 4px 6px; margin: -4px -6px; }
.agent-row-head[data-action="agent-row-inspect-open"]:hover { background: var(--paper-3); }
.agent-row-head[data-action="agent-row-inspect-open"]:focus-visible { outline: 2px solid var(--ink-3); outline-offset: 1px; }
.kv { display: grid; grid-template-columns: max-content 1fr; gap: 4px 12px; font-size: var(--text-sm); }
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
  border-radius: var(--rad); font-size: var(--text-sm); z-index: 1000;
  max-width: 360px;
}
.toast.error { background: var(--rust); color: var(--paper); }
.layer-card { background: var(--surface-2); border: 1px solid var(--rule); border-radius: var(--rad); padding: var(--space-2); }
.layer-card h4 { margin: 0 0 4px; font-size: var(--text-sm); font-weight: 600; }
.layer-card p { margin: 0; font-size: var(--text-xs); color: var(--ink-3); }
.chat-thread { display: flex; flex-direction: column; gap: var(--space-2); padding-bottom: 12px; }
.chat-msg { padding: 8px 10px; border-radius: var(--rad); border: 1px solid var(--rule); background: var(--surface); max-width: 78%; }
.chat-msg.system { background: var(--paper-3); color: var(--ink-3); font-size: var(--text-sm); max-width: 100%; }
.chat-msg.agent { align-self: flex-start; }
.chat-msg.operator { align-self: flex-end; background: var(--ink); color: var(--paper); }
.chat-msg .meta { font-size: 10px; color: var(--ink-4); margin-top: 4px; }
.composer { display: flex; gap: var(--space-2); padding: var(--space-2); border-top: 1px solid var(--rule); }
.composer input { flex: 1; padding: 6px 8px; border: 1px solid var(--rule); border-radius: var(--rad); font-family: var(--sans); }
.wizard-step { padding: 10px; border: 1px solid var(--rule); border-radius: var(--rad); margin-bottom: 8px; background: var(--surface); }
.wizard-step.active { border-color: var(--ink); }
.wizard-step.done { background: var(--sage-bg); border-color: var(--sage); }
.code-block { font-family: var(--mono); background: var(--paper-3); padding: var(--space-2); border-radius: var(--rad); font-size: var(--text-sm); overflow-x: auto; }
.policy-center { max-width: 980px; margin: 0 auto; }
.policy-center .eyebrow { margin: 0 0 6px; color: var(--ink-3); font-family: var(--mono); font-size: var(--text-sm); letter-spacing: 0; }
.policy-center h1 { font-family: var(--serif); font-size: var(--text-display); line-height: 1.08; font-weight: 400; margin: 0 0 10px; }
.policy-subtitle { max-width: 860px; color: var(--ink-2); font-size: 15px; margin: 0 0 24px; }
.policy-panel { background: var(--surface); border: 1px solid var(--rule); border-radius: var(--rad-lg); padding: 20px; margin: 18px 0; }
.policy-panel h2 { font-family: var(--serif); font-size: var(--text-xl); font-weight: 400; margin: 0 0 14px; }
.recommendation-list { display: grid; gap: var(--space-2); }
.recommendation-row { display: grid; grid-template-columns: minmax(0, 1fr) auto; gap: var(--space-3); align-items: center; border: 1px solid var(--rule); border-radius: var(--rad); padding: var(--space-3); background: var(--surface); }
.recommendation-row h3 { margin: 0 0 4px; font-size: var(--text-base); }
.recommendation-row p { margin: 0; color: var(--ink-3); font-size: var(--text-sm); }
.recommendation-actions { display: flex; flex-wrap: wrap; gap: var(--space-2); justify-content: flex-end; }
.recommendation-stats { display: flex; flex-wrap: wrap; gap: 6px; margin-top: 8px; }
.auto-trigger-rule-list { display: grid; gap: var(--space-3); }
.auto-trigger-rule-row { border: 1px solid var(--rule); border-radius: var(--rad); padding: var(--space-3); background: var(--surface); }
.auto-trigger-rule-head { display: flex; justify-content: space-between; gap: var(--space-3); align-items: start; }
.auto-trigger-rule-head h3 { margin: 0 0 4px; font-size: var(--text-base); overflow-wrap: anywhere; }
.auto-trigger-rule-head p { margin: 0; color: var(--ink-3); font-size: var(--text-sm); }
.rung-badge { border: 1px solid var(--rule-2); border-radius: 999px; padding: 3px 9px; font-family: var(--mono); font-size: var(--text-xs); white-space: nowrap; }
.auto-trigger-rule-grid { display: grid; grid-template-columns: minmax(140px, 220px) minmax(0, 1fr); gap: var(--space-3); margin-top: var(--space-3); align-items: center; }
.auto-trigger-trend { min-height: 28px; display: flex; align-items: end; gap: 3px; }
.trend-bar { width: 7px; height: 24px; border-radius: 2px; background: var(--ink-4); display: inline-block; }
.trend-bar.good { background: var(--sage); }
.trend-bar.warn { background: var(--ochre); }
.trend-bar.pending { background: var(--ink-4); }
.history-strip { display: flex; flex-wrap: wrap; gap: 5px; min-height: 28px; align-items: center; }
.history-chip { border: 1px solid var(--rule); border-radius: 999px; padding: 2px 7px; font-family: var(--mono); font-size: var(--text-xs); background: var(--paper-3); }
.history-chip.auto_proceeded, .history-chip.operator_approved { color: var(--sage); background: var(--sage-bg); }
.history-chip.operator_canceled, .history-chip.operator_revoked { color: var(--ochre); background: var(--ochre-bg); }
.auto-trigger-form { display: grid; grid-template-columns: repeat(5, minmax(100px, 1fr)) auto; gap: var(--space-2); margin-top: var(--space-3); align-items: end; }
.auto-trigger-form label { display: grid; gap: 4px; color: var(--ink-3); font-size: var(--text-xs); font-family: var(--mono); }
.auto-trigger-form input { width: 100%; box-sizing: border-box; border: 1px solid var(--rule); border-radius: var(--rad); padding: 6px 8px; font: inherit; color: var(--ink); background: var(--surface-2); }
@media (max-width: 760px) {
  .recommendation-row, .auto-trigger-rule-grid, .auto-trigger-form { grid-template-columns: 1fr; }
  .recommendation-actions { justify-content: flex-start; }
}
.template-grid { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: var(--space-3); }
.template-card { background: var(--surface-2); border: 1px solid var(--rule); border-radius: var(--rad); padding: 14px; min-height: 132px; }
.template-card-head { display: flex; justify-content: space-between; align-items: center; gap: var(--space-2); margin-bottom: 12px; }
.severity { border-radius: 999px; padding: 2px 9px; font-family: var(--mono); font-size: var(--text-xs); font-weight: 700; }
.severity.low { color: var(--sage); background: var(--sage-bg); }
.severity.medium { color: var(--ochre); background: var(--ochre-bg); }
.template-id { background: var(--paper-3); border-radius: var(--rad); padding: 2px 7px; color: var(--ink-3); }
.template-card h3 { font-size: var(--text-lg); margin: 0 0 6px; }
.template-card p { color: var(--ink-3); margin: 0; font-size: var(--text-md); }
.rules-scroll { overflow-x: auto; }
.rules-table { width: 100%; border-collapse: collapse; min-width: 760px; }
.rules-table th { text-align: left; color: var(--ink-3); font-family: var(--mono); font-size: var(--text-sm); letter-spacing: 0; padding: 8px 10px; border-bottom: 1px solid var(--rule); }
.rules-table td { padding: 12px 10px; border-bottom: 1px solid var(--rule); vertical-align: top; }
.link-btn, .template-cell { border: 0; background: transparent; color: var(--ink); padding: 0; cursor: pointer; font: inherit; text-align: left; }
.template-cell { font-family: var(--mono); max-width: 180px; overflow-wrap: anywhere; }
.template-picker { position: absolute; z-index: 20; margin-top: 8px; width: min(420px, calc(100vw - 80px)); background: var(--surface); border: 1px solid var(--rule-2); border-radius: var(--rad); box-shadow: var(--shadow); padding: 10px; }
.template-picker-options { display: grid; gap: 6px; max-height: 320px; overflow-y: auto; }
.template-option { display: grid; grid-template-columns: 18px 1fr; gap: var(--space-2); padding: var(--space-2); border: 1px solid var(--rule); border-radius: var(--rad); background: var(--surface-2); }
.template-option small { display: block; color: var(--ink-3); margin-top: 2px; }
.template-picker-actions { display: flex; justify-content: flex-end; gap: var(--space-2); margin-top: 10px; }
.allow-count { color: var(--sage); font-weight: 700; }
.block-count { color: var(--rust); }
.toggle-on { display: inline-block; width: 28px; height: 16px; border-radius: 999px; background: var(--sage); position: relative; }
.toggle-on::after { content: ""; position: absolute; right: 2px; top: 2px; width: 12px; height: 12px; border-radius: 50%; background: var(--surface); }
.error-text { color: var(--rust); margin: 8px 0 0; }
.intel-center { max-width: 980px; margin: 0 auto; }
.intel-center .eyebrow { margin: 0 0 6px; color: var(--ink-3); font-family: var(--mono); font-size: var(--text-sm); letter-spacing: 0; }
.intel-center h1 { font-family: var(--serif); font-size: var(--text-display); line-height: 1.08; font-weight: 400; margin: 0 0 10px; }
.intel-subtitle { max-width: 860px; color: var(--ink-2); font-size: 15px; margin: 0 0 24px; }
.intel-panel { background: var(--surface); border: 1px solid var(--rule); border-radius: var(--rad-lg); padding: 20px; margin: 18px 0; }
.intel-panel h2 { font-family: var(--serif); font-size: var(--text-xl); font-weight: 400; margin: 0 0 14px; }
.intel-row { display: grid; grid-template-columns: 200px 1fr auto; gap: var(--space-4); padding: 14px 0; border-bottom: 1px solid var(--rule); align-items: start; }
.intel-row:last-child { border-bottom: 0; }
.intel-row-name { font-weight: 600; }
.intel-row-name small { display: block; color: var(--ink-3); font-weight: 400; font-size: var(--text-sm); margin-top: 2px; font-family: var(--mono); }
.intel-row-body { display: flex; flex-direction: column; gap: 6px; min-width: 0; }
.intel-row-current { display: flex; gap: var(--space-2); align-items: center; flex-wrap: wrap; }
.intel-row-tradeoff { color: var(--ink-2); font-size: var(--text-base); line-height: 1.5; }
.intel-status-dot { display: inline-block; width: 10px; height: 10px; border-radius: 50%; }
.intel-status-dot.green { background: var(--sage); }
.intel-status-dot.yellow { background: var(--ochre); }
.intel-status-dot.red { background: var(--rust); }
.intel-hardware { display: grid; grid-template-columns: max-content 1fr; gap: 4px 16px; font-size: var(--text-base); }
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
.intel-modal h2 { font-family: var(--serif); font-size: var(--text-xl); font-weight: 400; margin: 0 0 8px; }
.intel-modal-subtitle { color: var(--ink-3); margin: 0 0 18px; font-size: var(--text-base); }
.intel-option {
  border: 1px solid var(--rule); border-radius: var(--rad); padding: var(--space-3);
  margin-bottom: 10px; background: var(--surface-2); cursor: pointer;
  display: grid; grid-template-columns: 18px 1fr; gap: 10px; align-items: start;
}
.intel-option.selected { border-color: var(--ink); background: var(--surface); }
.intel-option-body strong { display: block; font-size: var(--text-md); margin-bottom: 4px; }
.intel-option-body small { display: block; color: var(--ink-3); font-size: var(--text-sm); line-height: 1.5; }
.intel-suboptions { margin-top: 10px; padding: 10px; background: var(--paper-3); border-radius: var(--rad); }
.intel-suboptions label { display: block; margin: 6px 0; font-size: var(--text-base); }
.intel-suboptions input[type="text"], .intel-suboptions input[type="password"] {
  width: 100%; padding: 6px 8px; border: 1px solid var(--rule); border-radius: var(--rad);
  font-family: var(--mono); font-size: var(--text-sm); box-sizing: border-box;
}
.intel-modal-actions { display: flex; justify-content: flex-end; gap: var(--space-2); margin-top: 18px; }
/*
 * Intelligence panel polish (Sprint Piece 2 PR 3). Card grid layout
 * replaces the legacy 3-col row visual. The legacy .intel-row and
 * .intel-status-dot rules above are retained for the e2e selector
 * contract (.intel-row[data-intel-surface="..."]) and as the responsive
 * fallback. Cards render as a flex column with a substrate inset,
 * status badge with shaped glyph, and a recent-failures toggle in the
 * card foot.
 */
.intel-wrap { max-width: 1000px; margin: 0 auto; }
.intel-grid {
  display: grid;
  grid-template-columns: repeat(2, minmax(0, 1fr));
  gap: 12px;
}
.intel-card {
  background: var(--surface);
  border: 1px solid var(--rule);
  border-radius: var(--rad-lg);
  padding: 16px;
  display: flex; flex-direction: column;
  gap: 12px;
}
.intel-card-head {
  display: flex; align-items: flex-start; justify-content: space-between;
  gap: 10px;
}
.intel-card-name {
  display: flex; flex-direction: column; gap: 2px;
  min-width: 0;
}
.intel-card-name strong {
  font-family: var(--serif); font-weight: 500;
  font-size: 15px; letter-spacing: 0.005em;
}
.intel-card-name small {
  color: var(--ink-3); font-size: 11px; font-family: var(--mono);
}
.intel-card-status {
  display: inline-flex; align-items: center; gap: 6px;
  font-family: var(--mono); font-size: 11px;
  padding: 3px 9px; border-radius: 999px;
  border: 1px solid var(--rule); background: var(--surface-2);
  flex-shrink: 0;
}
.intel-card-status.ok { color: var(--sage); border-color: var(--sage); background: var(--sage-bg); }
.intel-card-status.warn { color: var(--ochre); border-color: var(--ochre); background: var(--ochre-bg); }
.intel-card-status.fail { color: var(--rust); border-color: var(--rust); background: var(--rust-bg); }
.status-glyph {
  width: 10px; height: 10px;
  position: relative; flex-shrink: 0;
}
.status-glyph.ok::before {
  content: ""; position: absolute; inset: 0;
  border-radius: 50%; background: currentColor;
}
.status-glyph.warn::before {
  content: ""; position: absolute; inset: 0;
  background: currentColor;
  clip-path: polygon(50% 0%, 100% 100%, 0% 100%);
}
.status-glyph.fail::before {
  content: ""; position: absolute; inset: 1px;
  background: currentColor;
  clip-path: polygon(50% 0, 100% 50%, 50% 100%, 0 50%);
}
.intel-substrate {
  display: flex; flex-direction: column; gap: 4px;
  padding: 10px 12px;
  background: var(--paper-2);
  border: 1px solid var(--rule);
  border-radius: var(--rad);
}
.intel-substrate .sub-line {
  display: flex; justify-content: space-between; align-items: center;
  gap: 10px; font-size: 12px;
}
.intel-substrate .sub-line.primary {
  font-family: var(--mono); font-size: 13px; color: var(--ink);
}
.intel-substrate .sub-line.secondary { color: var(--ink-3); font-size: 11px; }
.intel-card-foot {
  display: flex; align-items: center; justify-content: space-between;
  gap: 8px; padding-top: 4px;
}
.intel-failures-toggle {
  display: inline-flex; align-items: center; gap: 6px;
  font-size: 12px; font-family: var(--mono);
  color: var(--ink-3);
  background: transparent; border: 0; padding: 0;
  cursor: pointer;
}
.intel-failures-toggle:hover { color: var(--ink); }
.intel-failures-toggle .caret {
  display: inline-block; width: 0; height: 0;
  border-left: 4px solid transparent;
  border-right: 4px solid transparent;
  border-top: 5px solid currentColor;
  transition: transform 160ms ease;
}
.intel-failures-toggle.open .caret { transform: rotate(180deg); }
.intel-failures {
  border-top: 1px solid var(--rule);
  padding-top: 12px;
  display: flex; flex-direction: column;
  gap: 8px;
}
.intel-failure-row {
  display: grid; grid-template-columns: 88px 1fr; gap: 12px;
  font-size: 12px; padding: 8px 10px;
  border-radius: var(--rad);
  background: var(--paper-2);
  border: 1px solid var(--rule);
}
.intel-failure-row .ts {
  font-family: var(--mono); font-size: 11px; color: var(--ink-3);
}
.intel-failure-row .err-class {
  font-family: var(--mono); font-size: 10px;
  letter-spacing: 0.04em; text-transform: uppercase;
  color: var(--rust); margin-bottom: 2px;
}
.btn-quiet {
  background: transparent; border: 1px solid var(--rule);
  padding: 2px 6px; font-size: 11px;
  border-radius: var(--rad); cursor: pointer;
  color: var(--ink-2); font-family: var(--sans);
}
.btn-quiet:hover { background: var(--surface-2); color: var(--ink); }
.banner-warn {
  background: var(--ochre-bg); color: var(--ochre); border: 1px solid var(--ochre);
  border-radius: var(--rad); padding: 8px 12px; margin: 8px 0; font-size: var(--text-base);
}
.banner-info {
  background: var(--indigo-bg); color: var(--indigo); border: 1px solid var(--indigo);
  border-radius: var(--rad); padding: 8px 12px; margin: 8px 0; font-size: var(--text-base);
}
.btn.chip {
  border-radius: 999px; padding: 4px 12px; font-size: var(--text-sm);
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
/* Sprint Piece 2 PR 2 (2026-05-03): concierge surface polish.
 * Translates Claude Design references at
 * server/docs/design-refs/sprint-piece-2/surface-concierge.jsx and the
 * Surface 1 block of surfaces.css. The bounded-card layout above is
 * preserved verbatim because rc.5 and the DDD e2e suite depend on it;
 * the Claude Design reference uses height: 720px for the card, but
 * production keeps the calc-based bounded height so the card adapts
 * to the operator viewport. The polish lands the persona glyph-ring,
 * mono uppercase author labels, paper-2 background for concierge
 * replies, suggest-grid empty-state cards, and the composer input-wrap
 * with the keyboard-shortcut pill.
 */
.concierge-wrap { max-width: 880px; margin: 0 auto; }
.page-head {
  display: flex; align-items: flex-end; justify-content: space-between;
  gap: var(--space-4);
  margin-bottom: 18px; padding-bottom: 14px;
  border-bottom: 1px solid var(--rule);
}
.page-head .eyebrow {
  font-family: var(--mono); font-size: var(--text-xs);
  letter-spacing: 0.08em; text-transform: uppercase;
  color: var(--ink-3);
  margin: 0 0 6px;
}
.page-head h1 {
  font-family: var(--serif); font-weight: 400;
  font-size: 28px; letter-spacing: -0.01em;
  margin: 0 0 4px;
}
.page-head .sub {
  color: var(--ink-3); margin: 0;
  font-size: var(--text-base); max-width: 60ch;
}
.concierge-card {
  display: flex; flex-direction: column;
  height: calc(100vh - 180px);
  max-height: calc(100vh - 180px);
  min-height: 360px;
  padding: 18px 22px 14px;
  gap: 0;
}
.concierge-header {
  display: flex; align-items: center; justify-content: space-between;
  gap: var(--space-3); padding-bottom: 14px;
  border-bottom: 1px solid var(--rule);
  flex-wrap: wrap;
  flex-shrink: 0;
}
.concierge-persona { display: flex; align-items: center; gap: 10px; }
.concierge-persona .glyph-ring {
  width: 26px; height: 26px;
  border: 1.5px solid var(--ink-2);
  border-radius: 50%;
  position: relative;
  flex-shrink: 0;
}
.concierge-persona .glyph-ring::after {
  content: ""; position: absolute; inset: 5px;
  border-radius: 50%; background: var(--ink-2);
}
.concierge-persona-text { display: flex; flex-direction: column; }
.concierge-persona-text strong {
  font-family: var(--serif); font-weight: 500;
  font-size: 15px; letter-spacing: 0.005em;
}
.concierge-persona-text small {
  color: var(--ink-3); font-size: var(--text-xs);
  font-family: var(--mono);
}
.concierge-meta {
  display: flex; gap: 6px; align-items: center; flex-wrap: wrap;
}
.concierge-badge { white-space: nowrap; }
.concierge-history {
  flex: 1 1 auto;
  min-height: 0;
  overflow-y: auto;
  padding: 18px 4px 6px;
  display: flex; flex-direction: column; gap: 18px;
}
.concierge-msg {
  display: flex; flex-direction: column; gap: 5px;
  max-width: 78%;
}
.concierge-msg-author {
  font-size: 10px;
  font-family: var(--mono);
  letter-spacing: 0.04em;
  text-transform: uppercase;
  color: var(--ink-4);
}
.concierge-msg-body {
  padding: 11px 14px;
  border-radius: 12px;
  border: 1px solid var(--rule);
  background: var(--surface);
  font-size: var(--text-md);
  line-height: 1.55;
  white-space: pre-wrap;
  word-wrap: break-word;
}
.concierge-msg-concierge { align-self: flex-start; }
.concierge-msg-concierge .concierge-msg-body {
  background: var(--paper-2);
}
.concierge-msg-operator { align-self: flex-end; align-items: flex-end; }
.concierge-msg-operator .concierge-msg-body {
  background: var(--ink); color: var(--paper); border-color: var(--ink);
}
.concierge-msg-meta {
  display: flex; gap: 6px;
  font-size: 10px;
  color: var(--ink-4);
  font-family: var(--mono);
}
.concierge-empty {
  flex: 1 1 auto;
  display: flex; flex-direction: column; gap: 22px;
  justify-content: center;
  padding: 24px 12px;
}
.concierge-empty-headline { max-width: 52ch; }
.concierge-empty-headline h2 {
  font-family: var(--serif); font-weight: 400;
  font-size: var(--text-xl); margin: 0 0 6px;
  letter-spacing: -0.005em;
}
.concierge-empty-headline p {
  color: var(--ink-3); margin: 0;
  font-size: var(--text-md); line-height: 1.55;
}
.concierge-suggest-grid {
  display: grid;
  grid-template-columns: repeat(3, minmax(0, 1fr));
  gap: 10px;
}
.concierge-suggest {
  background: var(--surface);
  border: 1px solid var(--rule);
  border-radius: var(--rad);
  padding: 12px 14px;
  font-size: var(--text-base);
  cursor: pointer;
  display: flex; flex-direction: column;
  gap: 6px;
  text-align: left;
  font-family: var(--sans);
  color: var(--ink);
}
.concierge-suggest:hover:not(:disabled) {
  background: var(--surface-2);
  border-color: var(--rule-2);
}
.concierge-suggest:disabled {
  cursor: not-allowed; color: var(--ink-4); opacity: 0.7;
}
.concierge-suggest .label {
  font-family: var(--mono);
  font-size: 10px;
  letter-spacing: 0.06em;
  text-transform: uppercase;
  color: var(--ink-3);
}
.concierge-composer {
  display: flex; gap: 10px; align-items: center;
  padding: 12px 0 4px;
  border-top: 1px solid var(--rule);
  flex-shrink: 0;
}
.concierge-composer .input-wrap {
  flex: 1;
  display: flex; align-items: center; gap: var(--space-2);
  padding: 8px 12px;
  border: 1px solid var(--rule);
  border-radius: var(--rad);
  background: var(--surface);
}
.concierge-composer .input-wrap:focus-within {
  border-color: var(--ink-3);
}
.concierge-composer input {
  flex: 1; min-width: 0;
  padding: 4px 0;
  border: 0;
  background: transparent;
  color: var(--ink);
  font-family: var(--sans);
  font-size: var(--text-md);
  outline: none;
}
.concierge-composer input::placeholder { color: var(--ink-4); }
.concierge-composer .composer-meta {
  font-family: var(--mono);
  font-size: 10px;
  color: var(--ink-4);
  letter-spacing: 0.04em;
}
.concierge-composer .btn-primary {
  padding: 8px 18px; font-size: var(--text-base); flex-shrink: 0;
}
.concierge-foot {
  margin: 12px 0 0; padding-top: 10px; border-top: 1px dashed var(--rule);
  font-size: var(--text-sm);
}
.concierge-foot a { color: var(--ink-2); }
.tier1-approval-card {
  background: var(--ochre-bg); border: 1px solid var(--ochre);
  border-radius: var(--rad); padding: 14px 16px; margin: 12px 0;
}
.tier1-approval-card h3 {
  margin: 0 0 8px; color: var(--ochre); font-size: var(--text-md);
}
.tier1-approval-card p { margin: 0 0 12px; font-size: var(--text-base); }
.tier1-approval-card .actions {
  display: flex; gap: var(--space-2); flex-wrap: wrap;
}
/* Sprint Piece 2 PR 4 (2026-05-04): Agents view + Inspect pane polish.
 * Translates Claude Design references at
 * server/docs/design-refs/sprint-piece-2/surface-agents.jsx and the
 * Surface 3 block of surfaces.css. The fortress-column .agent-row,
 * .agent-row-head, and .agent-row-actions rules above are kept verbatim
 * because Finding DD tests pin them; the new Agents-view list scopes
 * its grid layout under .agents-list (descendant selector) so the
 * fortress-column rules are unaffected. The inspect pane combines the
 * existing .card surface with .inspect-pane structure (sticky right
 * rail, internal scroll, sectioned body) for the agent-detail view.
 */
.agents-wrap { max-width: 1080px; margin: 0 auto; }
.agents-layout {
  display: grid;
  grid-template-columns: 1fr 420px;
  gap: 20px;
  align-items: start;
}
.agents-list {
  background: var(--surface);
  border: 1px solid var(--rule);
  border-radius: var(--rad-lg);
  overflow: hidden;
}
.agents-list-head {
  display: grid;
  grid-template-columns: minmax(0, 1fr) 110px 120px 88px;
  gap: 12px;
  padding: 10px 16px;
  border-bottom: 1px solid var(--rule);
  background: var(--paper-2);
  font-family: var(--mono);
  font-size: 10px;
  letter-spacing: 0.06em;
  text-transform: uppercase;
  color: var(--ink-3);
}
.agents-list .agent-row {
  display: grid;
  grid-template-columns: minmax(0, 1fr) 110px 120px 88px;
  gap: 12px;
  padding: 14px 16px;
  border-bottom: 1px solid var(--rule);
  align-items: center;
  cursor: pointer;
  transition: background 120ms ease;
}
.agents-list .agent-row:last-child { border-bottom: 0; }
.agents-list .agent-row:hover { background: var(--paper-2); }
.agents-list .agent-row.selected {
  background: var(--paper-2);
  box-shadow: inset 3px 0 0 var(--ink);
}
.agent-identity { display: flex; align-items: center; gap: 10px; min-width: 0; }
.agent-glyph {
  width: 28px; height: 28px;
  border-radius: var(--rad);
  background: var(--paper-3);
  border: 1px solid var(--rule);
  display: grid; place-items: center;
  flex-shrink: 0;
  font-family: var(--mono);
  font-size: 11px;
  color: var(--ink-2);
  font-weight: 600;
}
.agent-name {
  display: flex; flex-direction: column; min-width: 0;
}
.agent-name strong {
  font-size: var(--text-base); font-weight: 500;
  white-space: nowrap; overflow: hidden; text-overflow: ellipsis;
}
.agent-name small {
  font-family: var(--mono); font-size: var(--text-xs); color: var(--ink-3);
  white-space: nowrap; overflow: hidden; text-overflow: ellipsis;
  display: block;
}
.agent-state {
  display: inline-flex; align-items: center; gap: 6px;
  font-size: var(--text-xs);
  font-family: var(--mono);
}
.state-dot {
  width: 7px; height: 7px; border-radius: 50%;
  background: var(--ink-4);
}
.state-dot.live { background: var(--sage); animation: pulse-soft 2.4s ease-in-out infinite; }
.state-dot.idle { background: var(--ochre); }
.state-dot.off { background: var(--ink-4); }
@keyframes pulse-soft {
  0%, 100% { box-shadow: 0 0 0 0 currentColor; opacity: 1; }
  50% { box-shadow: 0 0 0 4px transparent; opacity: 0.7; }
}
.agent-last {
  font-family: var(--mono); font-size: var(--text-xs); color: var(--ink-3);
}
/* Inspect pane (combined with .card outer wrapper for the
 * renderAgentInspectPanel return-shape regex anchored in
 * dashboard-welcome.test.ts:152). The .inspect-pane modifier overrides
 * .card padding so internal sections control their own spacing.
 */
.inspect-pane {
  padding: 0;
  display: flex; flex-direction: column;
  position: sticky;
  top: 20px;
  max-height: calc(100vh - 100px);
  overflow: hidden;
}
.inspect-head {
  padding: 16px 18px;
  border-bottom: 1px solid var(--rule);
  display: flex; flex-direction: column; gap: 10px;
}
.inspect-head .row1 {
  display: flex; align-items: center; gap: 10px;
}
.inspect-head h3 {
  font-family: var(--serif); font-weight: 500;
  font-size: 17px; margin: 0;
}
.inspect-head .meta {
  display: flex; gap: 6px; flex-wrap: wrap;
}
.inspect-body {
  overflow-y: auto;
  padding: 4px 18px 18px;
}
.inspect-section {
  padding: 14px 0;
  border-bottom: 1px solid var(--rule);
}
.inspect-section:last-child { border-bottom: 0; }
.inspect-section h4 {
  font-family: var(--mono);
  font-size: 10px;
  letter-spacing: 0.08em;
  text-transform: uppercase;
  color: var(--ink-3);
  margin: 0 0 10px;
  display: flex; align-items: center; justify-content: space-between;
}
.inspect-section h4 .count {
  font-family: var(--mono);
  background: var(--paper-3);
  border-radius: 999px;
  padding: 1px 7px;
  color: var(--ink-2);
  font-size: 10px;
}
.approval-row {
  background: var(--ochre-bg);
  border: 1px solid var(--ochre);
  border-radius: var(--rad);
  padding: 10px 12px;
  margin-bottom: 8px;
  display: flex; flex-direction: column; gap: 8px;
}
.approval-row .what { font-size: var(--text-base); color: var(--ink); }
.approval-row .what .pill { margin-right: 6px; }
.approval-row .why {
  font-size: var(--text-sm); color: var(--ink-2);
  padding-left: 10px;
  border-left: 2px solid var(--ochre);
}
.approval-row .actions { display: flex; gap: 6px; justify-content: flex-end; }
.timeline {
  display: flex; flex-direction: column; gap: 0;
  position: relative;
  padding-left: 14px;
}
.timeline::before {
  content: "";
  position: absolute;
  left: 4px; top: 6px; bottom: 6px;
  width: 1px;
  background: var(--rule);
}
.timeline-item {
  position: relative;
  padding: 6px 0 10px;
  font-size: var(--text-sm);
}
.timeline-item::before {
  content: "";
  position: absolute;
  left: -14px; top: 11px;
  width: 8px; height: 8px;
  border-radius: 50%;
  background: var(--surface);
  border: 1.5px solid var(--ink-4);
}
.timeline-item.ok::before { border-color: var(--sage); }
.timeline-item.warn::before { border-color: var(--ochre); }
.timeline-item.fail::before { border-color: var(--rust); }
.timeline-item .ts {
  font-family: var(--mono); font-size: 10px;
  color: var(--ink-3);
  letter-spacing: 0.02em;
}
.timeline-item .what {
  margin-top: 2px; color: var(--ink); font-size: var(--text-base);
}
.timeline-item .att {
  margin-top: 4px;
  display: inline-flex;
}
.policy-line {
  display: flex; justify-content: space-between; align-items: center;
  padding: 5px 0; font-size: var(--text-base);
  border-bottom: 1px dashed var(--rule);
}
.policy-line:last-child { border-bottom: 0; }
.policy-line .k { color: var(--ink-3); }
.policy-line .v { font-family: var(--mono); font-size: var(--text-sm); color: var(--ink); }
/* Empty-state block for when no agents are wrapped. The
 * renderAgentsList empty-state branch begins with the literal
 * '<h1>Agents</h1>' (regex-pinned in agents-empty-state-canary.test.ts)
 * and the "No wrapped agents yet." copy is preserved verbatim.
 */
.agents-empty {
  background: var(--surface);
  border: 1px dashed var(--rule-2);
  border-radius: var(--rad-lg);
  padding: 56px 40px;
  text-align: center;
  max-width: 720px;
  margin: 32px auto;
}
.agents-empty .icon-frame {
  width: 64px; height: 64px;
  margin: 0 auto 18px;
  border: 1px solid var(--rule);
  border-radius: 50%;
  display: grid; place-items: center;
  position: relative;
}
.agents-empty .icon-frame::before,
.agents-empty .icon-frame::after {
  content: "";
  position: absolute;
  border: 1px solid var(--rule);
  border-radius: 50%;
}
.agents-empty .icon-frame::before { inset: -8px; opacity: 0.6; }
.agents-empty .icon-frame::after { inset: -16px; opacity: 0.3; }
.agents-empty .icon-frame .core {
  width: 22px; height: 22px;
  background: var(--ink);
  border-radius: 50%;
}
.agents-empty h2 {
  font-family: var(--serif);
  font-weight: 400;
  font-size: var(--text-xl);
  margin: 0 0 8px;
}
.agents-empty p {
  color: var(--ink-3);
  margin: 0 0 20px;
  font-size: var(--text-md);
  line-height: 1.55;
  max-width: 50ch;
  margin-left: auto; margin-right: auto;
}
.terminal-block {
  text-align: left;
  background: var(--paper-3);
  border: 1px solid var(--rule);
  border-radius: var(--rad);
  padding: 14px 16px;
  font-family: var(--mono);
  font-size: var(--text-base);
  margin: 0 auto 16px;
  max-width: 480px;
  display: flex; align-items: center; justify-content: space-between;
}
.terminal-block .cmd { color: var(--ink); }
.terminal-block .cmd .prompt { color: var(--ink-3); margin-right: 8px; user-select: none; }
.copy-btn {
  background: transparent; border: 0;
  color: var(--ink-3); cursor: pointer;
  font-family: var(--mono); font-size: var(--text-xs);
  padding: 2px 6px;
  border-radius: var(--rad);
}
.copy-btn:hover { color: var(--ink); background: var(--paper-2); }

/* Surface 5. Attestation badge gallery. */
.att-gallery {
  display: flex; flex-direction: column; gap: 24px;
  max-width: 1000px;
  margin: 0 auto;
}
.att-section {
  background: var(--surface);
  border: 1px solid var(--rule);
  border-radius: var(--rad-lg);
  padding: 22px 24px;
}
.att-section-head {
  display: flex; justify-content: space-between; align-items: baseline;
  gap: 12px;
  margin-bottom: 16px;
  padding-bottom: 12px;
  border-bottom: 1px solid var(--rule);
}
.att-section-head h2 {
  font-family: var(--serif);
  font-weight: 400;
  font-size: 19px;
  margin: 0 0 4px;
}
.att-section-head p {
  color: var(--ink-3);
  margin: 0;
  font-size: 13px;
  line-height: 1.5;
  max-width: 64ch;
}
.att-section-head .label {
  font-family: var(--mono);
  font-size: 10px;
  letter-spacing: 0.08em;
  text-transform: uppercase;
  color: var(--ink-3);
}
.att-row {
  display: grid;
  grid-template-columns: 240px 1fr;
  gap: 24px;
  padding: 14px 0;
  border-bottom: 1px dashed var(--rule);
  align-items: center;
}
.att-row:last-child { border-bottom: 0; }
.att-row .demo {
  display: flex; align-items: center; justify-content: flex-start;
  padding: 12px 16px;
  background: var(--paper-2);
  border: 1px solid var(--rule);
  border-radius: var(--rad);
  min-height: 56px;
}
.att-row .desc strong {
  font-size: 13px; display: block; margin-bottom: 3px;
}
.att-row .desc small {
  color: var(--ink-3); font-size: 12px;
  line-height: 1.5;
}

/* Global persistent badge. Lives in the topbar across every surface. */
.att-global {
  display: inline-flex; align-items: center;
  gap: 8px;
  padding: 4px 10px 4px 6px;
  border: 1px solid var(--rule);
  border-radius: 999px;
  background: var(--surface-2);
  font-family: var(--mono);
  font-size: 11px;
  color: var(--ink-2);
}
.att-global.verified { border-color: var(--sage); background: var(--sage-bg); color: var(--sage); }
.att-global.degraded { border-color: var(--ochre); background: var(--ochre-bg); color: var(--ochre); }
.att-global.unverified { border-color: var(--rust); background: var(--rust-bg); color: var(--rust); }
.att-global .seal {
  width: 18px; height: 18px;
  position: relative;
  flex-shrink: 0;
}
.att-global .seal-ring {
  position: absolute; inset: 0;
  border: 1.5px solid currentColor;
  border-radius: 50%;
}
.att-global .seal-ring.dashed { border-style: dashed; }
.att-global .seal-core {
  position: absolute; inset: 4px;
  background: currentColor;
  border-radius: 50%;
  opacity: 0.85;
}
.att-global.degraded .seal-core { background: transparent; border: 1px solid currentColor; }
.att-global.unverified .seal-core {
  background: transparent;
  border: 1px solid currentColor;
}
.att-global.unverified .seal-core::after {
  content: ""; position: absolute; inset: 0;
  background: currentColor; opacity: 0.4;
  clip-path: polygon(0 0, 100% 100%, 100% 90%, 10% 0);
}
.att-global .label {
  font-family: var(--mono);
  font-size: 11px;
  letter-spacing: 0.02em;
  text-transform: uppercase;
}
.att-global .hash {
  font-family: var(--mono);
  font-size: 10px;
  opacity: 0.7;
  border-left: 1px solid currentColor;
  padding-left: 8px;
  margin-left: 2px;
}

/* Per-agent badge. Square chip beside each agent. */
.att-agent {
  display: inline-flex; align-items: center;
  gap: 6px;
  padding: 3px 7px;
  border-radius: var(--rad);
  border: 1px solid var(--rule);
  background: var(--surface);
  font-family: var(--mono);
  font-size: 10px;
  color: var(--ink-2);
}
.att-agent .mark {
  width: 10px; height: 10px;
  border: 1.5px solid currentColor;
  border-radius: 2px;
  position: relative;
}
.att-agent.verified { color: var(--sage); border-color: var(--sage); background: var(--sage-bg); }
.att-agent.verified .mark { background: currentColor; }
.att-agent.degraded { color: var(--ochre); border-color: var(--ochre); background: var(--ochre-bg); }
.att-agent.unverified { color: var(--rust); border-color: var(--rust); background: var(--rust-bg); }
.att-agent.unverified .mark {
  background: repeating-linear-gradient(
    45deg, currentColor, currentColor 1px,
    transparent 1px, transparent 3px
  );
}

/* Per-action badge. Tiny inline tick on timeline rows. */
.att-action {
  display: inline-flex; align-items: center; gap: 4px;
  font-family: var(--mono);
  font-size: 10px;
  color: var(--ink-3);
  padding: 1px 6px;
  border-radius: 4px;
  background: var(--paper-3);
  border: 1px solid transparent;
}
.att-action .tick {
  width: 6px; height: 6px;
  border-radius: 1px;
  background: currentColor;
}
.att-action.verified { color: var(--sage); }
.att-action.degraded { color: var(--ochre); }
.att-action.unverified { color: var(--rust); }
.att-action.neutral .tick { background: var(--ink-4); border-radius: 50%; }

/* Custody-provenance badge stub (v1.x). Visibly stubbed with dashed border. */
.att-custody {
  display: inline-flex; align-items: center; gap: 8px;
  padding: 4px 10px 4px 6px;
  border-radius: var(--rad);
  border: 1px dashed var(--rule-2);
  background: var(--paper-3);
  color: var(--ink-3);
  font-family: var(--mono);
  font-size: 10px;
}
.att-custody .seal-stub {
  width: 16px; height: 16px;
  border: 1px dashed var(--ink-4);
  border-radius: 50%;
  position: relative;
  flex-shrink: 0;
}
.att-custody .seal-stub::after {
  content: ""; position: absolute; inset: 4px;
  border: 1px dashed var(--ink-4);
  border-radius: 50%;
}
.att-custody .stub-tag {
  letter-spacing: 0.06em;
  text-transform: uppercase;
}

/* Tooltip surface for badges. */
.att-tooltip {
  background: var(--ink);
  color: var(--paper);
  font-family: var(--mono);
  font-size: 11px;
  padding: 8px 10px;
  border-radius: var(--rad);
  max-width: 280px;
  line-height: 1.5;
  display: inline-block;
}
[data-theme="dark"] .att-tooltip {
  background: var(--paper-3);
  color: var(--ink);
}

@media (max-width: 1100px) {
  .app, .app.route-full { grid-template-columns: 56px 1fr; grid-template-areas: "sidebar topbar" "sidebar main"; }
  .fortress { display: none; }
  .sidebar h1, .sidebar nav a span { display: none; }
  .sidebar nav a { justify-content: center; padding: 8px 6px; }
  .template-grid { grid-template-columns: 1fr; }
  .policy-center h1 { font-size: 30px; }
  .intel-center h1 { font-size: 30px; }
  .intel-row { grid-template-columns: 1fr; }
  .intel-grid { grid-template-columns: 1fr; }
  .intel-failure-row { grid-template-columns: 1fr; }
  .agents-layout { grid-template-columns: 1fr; }
  .agents-list-head, .agents-list .agent-row { grid-template-columns: minmax(0, 1fr) 90px 90px; }
  .agents-list-head span:nth-child(4), .agents-list .agent-row > .agent-last { display: none; }
  .inspect-pane { position: static; max-height: none; }
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
  { id: "auto-trigger", label: "Auto-trigger" },
  { id: "intelligence", label: "Intelligence" },
  { id: "attestation", label: "Attestation" },
  { id: "honeypot", label: "Honeypots" },
  { id: "privacy", label: "Privacy" },
  { id: "coordination", label: "Coordination" },
  { id: "health", label: "Health" },
  { id: "exit-drill", label: "Exit drill" },
];

/**
 * Inline-SVG icon set for the sidebar nav. Each icon is 16x16, fill:none,
 * stroke:currentColor (so themed via the `.sidebar nav a svg` rule).
 * Lucide-style geometry kept deliberately simple to fit the paper/ink
 * aesthetic without introducing an icon library dependency. The svg
 * attributes are emitted by the rendering loop to keep these strings
 * compact.
 */
const NAV_ICON_PATHS: Record<string, string> = {
  dashboard:
    '<rect x="2" y="2" width="5" height="5" rx="1"/><rect x="9" y="2" width="5" height="5" rx="1"/><rect x="2" y="9" width="5" height="5" rx="1"/><rect x="9" y="9" width="5" height="5" rx="1"/>',
  agents:
    '<circle cx="6" cy="5.5" r="2.3"/><path d="M2 13.5c0-2.2 1.8-4 4-4s4 1.8 4 4"/><circle cx="11.5" cy="6" r="1.8"/><path d="M14 12.5c0-1.7-1.1-2.7-2.5-3"/>',
  policy:
    '<path d="M4 2h5l3 3v9H4z"/><path d="M9 2v3h3"/><path d="M6 9h4M6 11.5h4"/>',
  "auto-trigger":
    '<path d="M3 12V4l5-2 5 2v8l-5 2z"/><path d="M8 5v3l2 1"/>',
  intelligence:
    '<rect x="3.5" y="3.5" width="9" height="9" rx="0.5"/><rect x="6" y="6" width="4" height="4"/><path d="M6 1.5v2M10 1.5v2M6 12.5v2M10 12.5v2M1.5 6h2M1.5 10h2M12.5 6h2M12.5 10h2"/>',
  attestation:
    '<circle cx="8" cy="8" r="5.5"/><circle cx="8" cy="8" r="2.2"/><path d="M8 1.5v1.5M8 13v1.5M1.5 8h1.5M13 8h1.5"/>',
  honeypot:
    '<path d="M8 1.5l5 2v4.5c0 3.1-2.1 5.2-5 6.5-2.9-1.3-5-3.4-5-6.5V3.5z"/><path d="M6 7.5h4M6.5 10h3"/>',
  privacy:
    '<path d="M8 1.5L3 3v4.5c0 3 2.2 5.4 5 7 2.8-1.6 5-4 5-7V3z"/><path d="M6 8l1.5 1.5L10.5 6"/>',
  coordination:
    '<circle cx="4" cy="3.5" r="1.4"/><circle cx="4" cy="12.5" r="1.4"/><circle cx="12" cy="8" r="1.4"/><path d="M4 4.9V11.1M4 5c0 3 3 3 6.7 3"/>',
  health:
    '<path d="M2 8h2.5l1.5-4 3 8 1.5-4H14"/>',
  "exit-drill":
    '<path d="M9.5 2H3v12h6.5"/><path d="M11 5l3 3-3 3"/><path d="M14 8H6.5"/>',
};

const SVG_OPEN = '<svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">';

/**
 * Theme-toggle icons. Sun for "switch to light" (visible when dark theme
 * is active), moon for "switch to dark" (visible when light theme is
 * active). CSS in STYLES toggles visibility off the [data-theme="dark"]
 * selector so the rendered button stays a single span.
 */
const THEME_ICON_MOON = SVG_OPEN +
  '<path d="M13 9.5A5.5 5.5 0 0 1 6.5 3 5.5 5.5 0 1 0 13 9.5z"/></svg>';
const THEME_ICON_SUN = SVG_OPEN +
  '<circle cx="8" cy="8" r="2.5"/><path d="M8 1.5v2M8 12.5v2M1.5 8h2M12.5 8h2M3.2 3.2l1.4 1.4M11.4 11.4l1.4 1.4M3.2 12.8l1.4-1.4M11.4 4.6l1.4-1.4"/></svg>';

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

  const nav = NAV_ITEMS.map((n) => {
    const iconPath = NAV_ICON_PATHS[n.id] ?? "";
    const icon = iconPath ? SVG_OPEN + iconPath + "</svg>" : "";
    return `<a href="#${n.id}" data-route="${n.id}">${icon}<span>${escHtml(n.label)}</span></a>`;
  }).join("\n        ");

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
        <span class="att-global pending" data-pill="attestation" title="Fortress attestation"><span class="seal"><span class="seal-ring dashed"></span><span class="seal-core"></span></span><span class="label">pending</span></span>
      </div>
      <button class="btn btn-icon" id="btn-theme-toggle" data-action="theme-toggle" aria-label="Toggle theme" title="Toggle theme">
        <span class="icon-moon">${THEME_ICON_MOON}</span>
        <span class="icon-sun">${THEME_ICON_SUN}</span>
      </button>
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
