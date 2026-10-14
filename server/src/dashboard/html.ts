/**
 * Sanctuary Dashboard: Single-Page HTML
 *
 * Hero shield + four layer cards + live activity feed + approval queue +
 * audit trail. Vanilla HTML/CSS/JS in one string, matching the convention
 * established by server/src/wrap/fortress-view.ts.
 *
 * The initial snapshot is embedded server-side so the page renders
 * correctly without JavaScript. Live updates layer on via SSE + REST.
 */

import type { ProtectionSnapshot } from "./aggregator.js";
import { CONSOLE_FONT_FACE_CSS } from "./design-fonts.js";
import { PAPER_INK_ROOT_TOKENS_CSS, THEME_BOOTSTRAP_SCRIPT } from "./design-tokens.js";
import {
  PROTECTION_HERO_COPY,
  protectionHeroCopyForLight,
} from "../egress-gate/protection-claim.js";

// Re-export the multi-tenant renderer so dashboard consumers can import a
// single module for both modes.
export {
  renderMultiAgentHTML,
  type MultiAgentHTMLOptions,
} from "./multi-html.js";

/** Hero copy. Change here if we ever A/B test. */
export const HERO_COPY = PROTECTION_HERO_COPY.green;
const NON_GREEN_HERO_COPY = PROTECTION_HERO_COPY.nonGreen;

export interface DashboardHTMLOptions {
  snapshot: ProtectionSnapshot;
  authToken?: string;
}

function escHtml(value: unknown): string {
  if (value == null) return "";
  return String(value)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}

function shieldStatusMark(light: string): string {
  if (light === "green") return "M85 102 L96 113 L118 90";
  if (light === "yellow") return "M100 78 L122 120 L78 120 Z";
  return "M84 84 L116 116 M116 84 L84 116";
}

function layerCard(
  layer:
    | ProtectionSnapshot["layers"]["l1"]
    | ProtectionSnapshot["layers"]["l2"]
    | ProtectionSnapshot["layers"]["l3"]
    | ProtectionSnapshot["layers"]["l4"],
  extra: string
): string {
  return `<section class="layer-card layer-${escHtml(layer.state)}" data-layer-label="${escHtml(layer.label)}">
    <div class="layer-head">
      <div class="layer-dot"></div>
      <div>
        <h3>${escHtml(layer.label)}</h3>
        <p class="layer-headline">${escHtml(layer.headline)}</p>
      </div>
    </div>
    <dl class="layer-detail">${extra}</dl>
  </section>`;
}

function l1Card(l1: ProtectionSnapshot["layers"]["l1"]): string {
  return layerCard(
    l1,
    `<div><dt>Encryption</dt><dd>${escHtml(l1.encryption)}</dd></div>
     <div><dt>Injections blocked today</dt><dd>${escHtml(l1.injection_blocked_today)}</dd></div>
     <div><dt>memory_attest</dt><dd>${l1.memory_attest_ready ? "Ready" : "Not ready"}</dd></div>`
  );
}

function l2Card(l2: ProtectionSnapshot["layers"]["l2"]): string {
  return layerCard(
    l2,
    `<div><dt>Isolation</dt><dd>${escHtml(l2.isolation_type)}</dd></div>
     <div><dt>TEE</dt><dd>${escHtml(l2.tee_status)}</dd></div>
     <div><dt>Sandbox</dt><dd>${escHtml(l2.sandbox_status)}</dd></div>`
  );
}

function l3Card(l3: ProtectionSnapshot["layers"]["l3"]): string {
  return layerCard(
    l3,
    `<div><dt>DID</dt><dd>${l3.did_active ? "Active" : "None"}</dd></div>
     <div><dt>Credentials</dt><dd>${escHtml(l3.vc_count)}</dd></div>
     <div><dt>Proofs today</dt><dd>${escHtml(l3.proofs_today)}</dd></div>`
  );
}

// The apex verascore.ai 307-redirects to www.verascore.ai; linking the
// www host directly avoids the redirect round trip on every click.
const VERASCORE_CLAIM_URL = "https://www.verascore.ai";

function l4Card(l4: ProtectionSnapshot["layers"]["l4"]): string {
  let score: string;
  if (l4.score != null) {
    score = `<div class="score-block"><span class="score-value">${escHtml(l4.score)}</span><span class="score-label">Verascore</span></div>`;
  } else {
    const claimText = l4.claim_cta ?? "Claim your profile at verascore.ai";
    score = `<div class="claim-block"><a class="claim-link" href="${VERASCORE_CLAIM_URL}" target="_blank" rel="noopener noreferrer">${escHtml(claimText)}</a></div>`;
  }
  return layerCard(
    l4,
    `<div class="layer-cta">${score}</div>${l4EvidenceBlock(l4)}`
  );
}

function formatRelativeDays(iso: string | null): string {
  if (!iso) return "none on record";
  const ts = new Date(iso).getTime();
  if (isNaN(ts)) return "unknown";
  const days = Math.round((Date.now() - ts) / (24 * 60 * 60 * 1000));
  if (days <= 0) return "today";
  if (days === 1) return "1 day ago";
  return `${days} days ago`;
}

function l4EvidenceBlock(l4: ProtectionSnapshot["layers"]["l4"]): string {
  if (!l4.evidence) return "";
  const ev = l4.evidence;
  const tierSovereign = ev.tier_distribution["verified-sovereign"];
  const tierDegraded = ev.tier_distribution["verified-degraded"];
  const tierSelf = ev.tier_distribution["self-attested"];
  const tierUnverified = ev.tier_distribution["unverified"];
  const contextCount = Object.keys(ev.context_breakdown).length;
  const mostRecent = formatRelativeDays(ev.most_recent_attestation_at);
  const score = l4.layer_score ?? 100;

  const summaryLine = `
    <div><dt>L4 score</dt><dd>${escHtml(score)} / 100</dd></div>
    <div><dt>Attestations</dt><dd>${escHtml(ev.attestation_count)}</dd></div>
    <div><dt>Verified tiers</dt><dd>${escHtml(tierSovereign)} sovereign · ${escHtml(tierDegraded)} degraded</dd></div>
    <div><dt>Lower tiers</dt><dd>${escHtml(tierSelf)} self · ${escHtml(tierUnverified)} unverified</dd></div>
    <div><dt>Contexts</dt><dd>${escHtml(contextCount)}</dd></div>
    <div><dt>Disputes</dt><dd>${escHtml(ev.dispute_count)}</dd></div>
    <div><dt>Last activity</dt><dd>${escHtml(mostRecent)}</dd></div>
    <div><dt>Verascore link</dt><dd>${ev.verascore_linked ? "Yes" : "Not linked"}</dd></div>
  `;

  const degs = l4.active_degradations ?? [];
  const degList = degs.length === 0
    ? ""
    : `<ul class="l4-deg-list">${degs
        .map(
          (d) => `
          <li class="l4-deg l4-deg-${escHtml(d.severity)}">
            <div class="l4-deg-head">
              <span class="l4-deg-code">${escHtml(d.code)}</span>
              <span class="l4-deg-sev">${escHtml(d.severity)}</span>
            </div>
            <p class="l4-deg-desc">${escHtml(d.description)}</p>
            ${d.mitigation ? `<p class="l4-deg-mit">${escHtml(d.mitigation)}</p>` : ""}
          </li>`
        )
        .join("")}</ul>`;

  return `
    <div class="l4-evidence">
      <dl class="layer-detail l4-evidence-summary">${summaryLine}</dl>
      ${degList}
    </div>
  `;
}

export function renderDashboardHTML(options: DashboardHTMLOptions): string {
  const { snapshot } = options;
  const { overall, agent, layers, activity, pending_approvals, audit, privacy, upstream_servers } = snapshot;
  const heroCopy = protectionHeroCopyForLight(overall.light);
  const approvalsRedacted = snapshot.pending_approvals_redacted === true;
  const approvalCount = approvalsRedacted
    ? snapshot.pending_approvals_count ?? pending_approvals.length
    : pending_approvals.length;

  const activityRows = activity.length === 0
    ? `<tr class="empty"><td colspan="5">Waiting for tool calls…</td></tr>`
    : activity
        .map((entry) => {
          const time = new Date(entry.timestamp).toLocaleTimeString();
          return `<tr class="result-${escHtml(entry.result)}">
            <td class="mono time">${escHtml(time)}</td>
            <td class="mono">${escHtml(entry.tool)}</td>
            <td class="mono">${escHtml(entry.server)}</td>
            <td class="tier tier-${escHtml(entry.tier)}">T${escHtml(entry.tier)}</td>
            <td class="result">${escHtml(entry.result)}</td>
          </tr>`;
        })
        .join("");

  const approvalItems = approvalsRedacted
    ? `<div class="empty-block approval-redacted" data-pending-approvals-redacted="1">Approvals are hidden, not empty. Pending count: ${escHtml(approvalCount)}</div>`
    : pending_approvals.length === 0
    ? `<div class="empty-block">No pending approvals</div>`
    : pending_approvals
        .map((p) => `<article class="approval" data-id="${escHtml(p.id)}">
          <div class="approval-head">
            <span class="tier-chip tier-${escHtml(p.tier)}">Tier ${escHtml(p.tier)}</span>
            <span class="mono">${escHtml(p.operation)}</span>
          </div>
          <p class="approval-reason">${escHtml(p.reason)}</p>
          <div class="approval-actions">
            <button class="btn btn-allow" data-action="allow" data-id="${escHtml(p.id)}">Allow</button>
            <button class="btn btn-deny" data-action="deny" data-id="${escHtml(p.id)}">Deny</button>
          </div>
        </article>`)
        .join("");

  const auditRows = audit.length === 0
    ? `<tr class="empty"><td colspan="4">Audit log empty</td></tr>`
    : audit
        .map((entry) => `<tr data-kind="${escHtml(entry.layer)}" data-op="${escHtml(entry.operation)}">
          <td class="mono time">${escHtml(new Date(entry.timestamp).toLocaleTimeString())}</td>
          <td class="layer-pill">${escHtml(entry.layer.toUpperCase())}</td>
          <td class="mono">${escHtml(entry.operation)}</td>
          <td class="result-${escHtml(entry.result)}">${escHtml(entry.result)}</td>
        </tr>`)
        .join("");

  const serverRows = upstream_servers.length === 0
    ? `<li class="empty-block">No upstream servers connected</li>`
    : upstream_servers
        .map((s) => `<li class="server-row state-${escHtml(s.state)}">
          <span class="server-dot"></span>
          <span class="mono">${escHtml(s.name)}</span>
          <span class="server-meta">${escHtml(s.state)} · ${escHtml(s.tool_count)} tool${s.tool_count === 1 ? "" : "s"}</span>
        </li>`)
        .join("");

  const privacyClasses = Object.entries(privacy.classes)
    .sort((a, b) => b[1] - a[1])
    .map(([name, count]) => `<span class="privacy-chip">${escHtml(name)} ${escHtml(count)}</span>`)
    .join("");
  const privacyLast = privacy.last_filtered_at
    ? new Date(privacy.last_filtered_at).toLocaleString()
    : "No filtering events yet";

  const initialSnapshot = JSON.stringify(snapshot)
    .replace(/</g, "\\u003c")
    .replace(/\u2028/g, "\\u2028")
    .replace(/\u2029/g, "\\u2029");

  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Sanctuary: Sovereignty Dashboard</title>
<script>${THEME_BOOTSTRAP_SCRIPT}</script>
<style>
/* Slice 2b: this page reads the server's design tokens and bundled faces
   (design-tokens.ts, design-fonts.ts), the same block the console shell
   interpolates, and follows the console's light or dark choice through the
   head bootstrap above. It declares no palette, font stack or radius of its
   own. State marks carry a shape per state as well as a hue (circle pass,
   triangle warn, square fault, hollow dotted ring unknown), and a control's
   edge is --ink-3, which clears 3:1 on every fill in both themes. */
${CONSOLE_FONT_FACE_CSS}
${PAPER_INK_ROOT_TOKENS_CSS}
* { margin: 0; padding: 0; box-sizing: border-box; }
html, body { background: var(--paper); color: var(--ink); font-family: var(--sans); min-height: 100vh; -webkit-font-smoothing: antialiased; }
a { color: var(--accent); text-decoration: none; }
a:hover { text-decoration: underline; }
button { font: inherit; cursor: pointer; }
:is(a, button, summary):focus-visible { outline: 2px solid var(--focus); outline-offset: 2px; }

.wrap { max-width: 1180px; margin: 0 auto; padding: 40px 32px 120px; }

/* ── Top meta row ─────────────────────────────────────────────── */
.meta-row {
  display: flex;
  justify-content: space-between;
  align-items: center;
  color: var(--ink-3);
  font-family: var(--mono);
  font-size: var(--text-xs);
  letter-spacing: 0.08em;
  text-transform: uppercase;
  margin-bottom: 8px;
}
.meta-row .mode-pill {
  padding: 4px 10px;
  border-radius: 999px;
  border: 1px solid var(--rule);
  background: var(--surface);
  text-transform: none;
  letter-spacing: 0;
  color: var(--ink-2);
}

/* ── Hero ─────────────────────────────────────────────────────── */
.hero {
  display: flex;
  flex-direction: column;
  align-items: center;
  text-align: center;
  padding: 48px 24px 56px;
  border-radius: var(--rad-lg);
  background: var(--surface);
  border: 1px solid var(--rule);
  margin-bottom: 32px;
}
.shield { width: 200px; height: 200px; position: relative; }
.shield svg { width: 100%; height: 100%; display: block; }
.shield .shield-core { fill: transparent; }
.shield.green .shield-ring, .shield.green .shield-mark { stroke: var(--sage); }
.shield.green .shield-core { fill: var(--sage-bg); }
.shield.yellow .shield-ring, .shield.yellow .shield-mark { stroke: var(--ochre); }
.shield.yellow .shield-core { fill: var(--ochre-bg); }
.shield.red .shield-ring, .shield.red .shield-mark { stroke: var(--rust); }
.shield.red .shield-core { fill: var(--rust-bg); }
.shield .shield-ring { fill: none; stroke-width: 3; }
.shield .shield-ring-bg { fill: none; stroke: var(--rule); stroke-width: 3; }
.shield .shield-mark { fill: none; stroke-width: 4; stroke-linecap: round; stroke-linejoin: round; }

.hero h1 {
  font-family: var(--display);
  font-size: 40px;
  font-weight: 600;
  letter-spacing: -0.02em;
  margin-top: 28px;
}
.hero .hero-sub {
  margin-top: 10px;
  color: var(--ink-2);
  font-size: var(--text-md);
}
.identity-line {
  margin-top: 22px;
  display: inline-flex;
  align-items: center;
  gap: 10px;
  padding: 10px 18px;
  border-radius: 999px;
  border: 1px solid var(--rule);
  background: var(--surface-2);
  font-family: var(--mono);
  font-size: var(--text-sm);
  color: var(--ink-2);
}
.identity-line .name { color: var(--ink); font-weight: 600; font-family: var(--sans); letter-spacing: 0; }
.identity-line .sep { color: var(--ink-3); }
.identity-line .did { color: var(--ink-2); }
.identity-line .primary-flag {
  padding: 2px 8px;
  border-radius: 999px;
  background: var(--indigo-bg);
  color: var(--indigo);
  font-size: var(--text-xs);
  text-transform: uppercase;
  letter-spacing: 0.1em;
}

/* ── Layer grid ───────────────────────────────────────────────── */
.layer-grid {
  display: grid;
  grid-template-columns: repeat(4, 1fr);
  gap: 16px;
  margin-bottom: 32px;
}
@media (max-width: 960px) { .layer-grid { grid-template-columns: repeat(2, 1fr); } }
@media (max-width: 520px) { .layer-grid { grid-template-columns: 1fr; } }

.layer-card {
  padding: 20px;
  border-radius: var(--rad-lg);
  background: var(--surface);
  border: 1px solid var(--rule);
}
.layer-card:hover { border-color: var(--rule-2); }
.layer-head { display: flex; align-items: flex-start; gap: 12px; margin-bottom: 14px; }
/* One shape per layer state: the pass circle (full), the warn triangle
   (degraded), the fault square (compromised), and the hollow dotted unknown
   ring for any state this page does not know. The headline names it too. */
.layer-dot { width: 12px; height: 12px; flex: none; margin-top: 6px; box-sizing: border-box; border-radius: 50%; background: transparent; border: 2px dotted var(--slate); }
.layer-full .layer-dot { background: var(--sage); border: 0; }
.layer-degraded .layer-dot { background: var(--ochre); border: 0; border-radius: 0; clip-path: polygon(50% 0, 100% 100%, 0 100%); }
.layer-compromised .layer-dot { background: var(--rust); border: 0; border-radius: 0; }
.layer-head h3 { font-family: var(--mono); font-size: var(--text-xs); text-transform: uppercase; letter-spacing: 0.08em; color: var(--ink-2); margin-bottom: 4px; }
.layer-headline { font-size: var(--text-md); color: var(--ink); line-height: 1.35; }

.layer-detail { display: flex; flex-direction: column; gap: 8px; }
.layer-detail > div { display: flex; justify-content: space-between; gap: 12px; font-size: var(--text-sm); }
.layer-detail dt { color: var(--ink-3); text-transform: uppercase; letter-spacing: 0.06em; font-size: var(--text-xs); }
.layer-detail dd { color: var(--ink-2); text-align: right; font-family: var(--mono); font-size: var(--text-sm); }

.layer-cta { margin-top: 6px; text-align: center; padding: 16px; border-radius: var(--rad); background: var(--paper-2); border: 1px solid var(--rule); }
.score-block { display: flex; flex-direction: column; gap: 2px; }
/* The score is a number, not a verdict: it wears the ink, never the pass hue. */
.score-value { font-family: var(--display); font-size: 28px; font-weight: 600; color: var(--ink); letter-spacing: -0.02em; }
.score-label { font-family: var(--mono); font-size: var(--text-xs); text-transform: uppercase; color: var(--ink-3); letter-spacing: 0.08em; }
.claim-block { font-size: var(--text-sm); }

/* ── L4 evidence widget (v0.9.1) ──────────────────────────────── */
.l4-evidence { margin-top: 12px; padding-top: 12px; border-top: 1px dashed var(--rule); }
.l4-evidence-summary { gap: 6px; margin-bottom: 10px; }
.l4-evidence-summary dt { font-size: 10px; }
.l4-evidence-summary dd { font-size: var(--text-xs); }
.l4-deg-list { list-style: none; display: flex; flex-direction: column; gap: 6px; margin-top: 8px; }
.l4-deg { padding: 8px 10px; border-radius: var(--rad); background: var(--paper-2); border: 1px solid var(--rule); font-size: var(--text-sm); }
.l4-deg-head { display: flex; justify-content: space-between; align-items: baseline; gap: 8px; margin-bottom: 3px; }
.l4-deg-code { font-family: var(--mono); font-size: var(--text-xs); color: var(--ink); letter-spacing: 0.02em; }
.l4-deg-sev { font-family: var(--mono); font-size: 10px; text-transform: uppercase; letter-spacing: 0.08em; color: var(--ink-3); }
.l4-deg-warning { border-color: var(--ochre-line); }
.l4-deg-warning .l4-deg-sev { color: var(--ochre); }
.l4-deg-critical { border-color: var(--rust-line); }
.l4-deg-critical .l4-deg-sev { color: var(--rust); }
.l4-deg-info .l4-deg-sev { color: var(--indigo); }
.l4-deg-desc { color: var(--ink-2); line-height: 1.35; font-size: var(--text-xs); }
.l4-deg-mit { color: var(--ink-3); line-height: 1.35; font-size: 10px; margin-top: 3px; font-style: italic; }

/* ── Section headers ─────────────────────────────────────────── */
.section { margin-bottom: 28px; }
.section h2 {
  font-family: var(--mono);
  font-size: var(--text-xs);
  text-transform: uppercase;
  letter-spacing: 0.1em;
  color: var(--ink-2);
  margin-bottom: 12px;
  display: flex;
  align-items: center;
  gap: 12px;
}
.section h2 .count, details.audit-details summary .count {
  font-family: var(--mono);
  font-size: var(--text-xs);
  padding: 2px 8px;
  border-radius: 999px;
  background: var(--surface);
  border: 1px solid var(--rule);
  color: var(--ink-3);
  text-transform: none;
  letter-spacing: 0;
}

/* ── Approval queue ──────────────────────────────────────────── */
.approval-list { display: flex; flex-direction: column; gap: 10px; }
.approval {
  padding: 16px;
  background: var(--surface);
  border: 1px solid var(--ochre);
  border-radius: var(--rad-lg);
}
.approval-head { display: flex; align-items: center; gap: 10px; margin-bottom: 6px; font-size: var(--text-base); }
.tier-chip { padding: 2px 8px; border-radius: 999px; font-family: var(--mono); font-size: 10px; text-transform: uppercase; letter-spacing: 0.08em; }
.tier-chip.tier-1 { background: var(--rust-bg); color: var(--rust); }
.tier-chip.tier-2 { background: var(--ochre-bg); color: var(--ochre); }
.approval-reason { font-size: var(--text-sm); color: var(--ink-2); margin-bottom: 12px; }
.approval-actions { display: flex; gap: 8px; }
.btn {
  padding: 7px 14px;
  border-radius: var(--rad);
  border: 1px solid var(--ink-3);
  background: var(--surface);
  color: var(--ink);
  font-size: var(--text-sm);
}
.btn:hover { border-color: var(--ink-2); background: var(--surface-2); }
.btn-allow { background: var(--ink); border-color: var(--ink); color: var(--paper); }
.btn-allow:hover { background: var(--ink-2); border-color: var(--ink-2); }
/* Deny is the danger style: bad text and a bad-hue edge, never a red fill. */
.btn-deny { background: transparent; border-color: var(--rust); color: var(--rust); }
.btn-deny:hover { background: var(--rust-bg); border-color: var(--rust); }

/* ── Tables ──────────────────────────────────────────────────── */
.panel { background: var(--surface); border: 1px solid var(--rule); border-radius: var(--rad-lg); overflow: hidden; }
.panel-head { display: flex; justify-content: space-between; align-items: center; padding: 12px 18px; border-bottom: 1px solid var(--rule); }
.panel-head h3 { font-family: var(--mono); font-size: var(--text-xs); text-transform: uppercase; letter-spacing: 0.1em; color: var(--ink-2); }
.privacy-grid { display: grid; grid-template-columns: repeat(3, minmax(0, 1fr)); gap: 12px; }
.privacy-metric { background: var(--surface); border: 1px solid var(--rule); border-radius: var(--rad); padding: 14px 16px; }
.privacy-metric dt { color: var(--ink-3); font-family: var(--mono); font-size: var(--text-xs); text-transform: uppercase; letter-spacing: 0.08em; margin-bottom: 6px; }
.privacy-metric dd { color: var(--ink); font-family: var(--display); font-size: 22px; font-weight: 600; }
.privacy-metric dd.small { font-family: var(--sans); font-size: var(--text-sm); font-weight: 500; color: var(--ink-2); line-height: 1.35; overflow-wrap: anywhere; }
.privacy-classes { display: flex; flex-wrap: wrap; gap: 6px; margin-top: 10px; }
.privacy-chip { border: 1px solid var(--rule); color: var(--ink-2); border-radius: 999px; padding: 4px 8px; font-size: var(--text-sm); background: var(--surface-2); }
.filter-row { display: flex; gap: 6px; }
.filter-row button {
  padding: 4px 10px;
  font-family: var(--mono);
  font-size: var(--text-xs);
  border-radius: 999px;
  background: transparent;
  border: 1px solid var(--ink-3);
  color: var(--ink-2);
  text-transform: uppercase;
  letter-spacing: 0.06em;
}
.filter-row button:hover { color: var(--ink); border-color: var(--ink-2); background: var(--surface-2); }
/* The chosen filter is the ink fill, not a shade of the same edge, so it
   reads without color. */
.filter-row button.active { color: var(--paper); border-color: var(--ink); background: var(--ink); }

table { width: 100%; border-collapse: collapse; }
th, td { padding: 10px 18px; text-align: left; font-size: var(--text-sm); border-bottom: 1px solid var(--rule); }
th { font-family: var(--mono); font-size: var(--text-xs); text-transform: uppercase; letter-spacing: 0.08em; color: var(--ink-3); font-weight: 500; background: var(--paper-2); }
tr:last-child td { border-bottom: none; }
tr.empty td { text-align: center; color: var(--ink-3); padding: 32px 18px; }
.mono { font-family: var(--mono); font-size: var(--text-sm); }
.time { color: var(--ink-3); white-space: nowrap; }
.tier { text-align: center; font-family: var(--mono); font-size: var(--text-xs); font-weight: 600; }
.tier-1 { color: var(--rust); }
.tier-2 { color: var(--ochre); }
.tier-3 { color: var(--sage); }
.result { font-family: var(--mono); font-size: var(--text-sm); text-transform: uppercase; letter-spacing: 0.06em; }
.result-allowed, .result-success { color: var(--sage); }
.result-denied, .result-failure { color: var(--rust); }
.result-approved { color: var(--indigo); }
.result-pending { color: var(--ochre); }
.layer-pill { font-family: var(--mono); font-size: var(--text-xs); padding: 2px 8px; border-radius: 999px; background: var(--surface-2); color: var(--ink-2); display: inline-block; }

/* ── Upstream servers ────────────────────────────────────────── */
.server-list { list-style: none; display: flex; flex-direction: column; gap: 8px; }
.server-row { display: flex; align-items: center; gap: 10px; padding: 10px 14px; background: var(--surface); border: 1px solid var(--rule); border-radius: var(--rad); font-size: var(--text-sm); }
/* One shape per connection state: the pass circle (connected), the warn
   triangle (connecting), the fault square (disconnected or error), the
   hollow dotted unknown ring for anything else. The state word follows. */
.server-dot { width: 8px; height: 8px; flex: none; box-sizing: border-box; border-radius: 50%; background: transparent; border: 1.5px dotted var(--slate); }
.server-row.state-connected .server-dot { background: var(--sage); border: 0; }
.server-row.state-connecting .server-dot { background: var(--ochre); border: 0; border-radius: 0; clip-path: polygon(50% 0, 100% 100%, 0 100%); }
.server-row.state-disconnected .server-dot, .server-row.state-error .server-dot { background: var(--rust); border: 0; border-radius: 0; }
.server-meta { margin-left: auto; font-size: var(--text-sm); color: var(--ink-3); font-family: var(--mono); }

.empty-block { padding: 18px; color: var(--ink-3); text-align: center; font-size: var(--text-sm); background: var(--surface); border: 1px dashed var(--rule-2); border-radius: var(--rad); }

/* ── Audit collapsible ───────────────────────────────────────── */
details.audit-details { background: var(--surface); border: 1px solid var(--rule); border-radius: var(--rad-lg); overflow: hidden; }
details.audit-details summary { cursor: pointer; list-style: none; padding: 14px 18px; display: flex; align-items: center; justify-content: space-between; }
details.audit-details summary::-webkit-details-marker { display: none; }
details.audit-details summary h3 { font-family: var(--mono); font-size: var(--text-xs); text-transform: uppercase; letter-spacing: 0.1em; color: var(--ink-2); }
details.audit-details summary .caret { color: var(--ink-3); font-family: var(--mono); }
details.audit-details[open] .caret { transform: rotate(90deg); display: inline-block; }
details.audit-details .audit-filters { display: flex; gap: 6px; padding: 0 18px 12px; border-bottom: 1px solid var(--rule); }
</style>
</head>
<body>
<div class="wrap">
  <div class="meta-row">
    <span>Sanctuary Framework</span>
    <span class="mode-pill" id="mode-pill">${escHtml(snapshot.mode)} · v${escHtml(snapshot.server_version)}</span>
  </div>

  <section class="hero">
    <div class="shield ${escHtml(overall.light)}" id="shield">
      <svg viewBox="0 0 200 200" aria-hidden="true">
        <circle class="shield-ring-bg" cx="100" cy="100" r="92"></circle>
        <circle class="shield-ring" cx="100" cy="100" r="92"></circle>
        <circle class="shield-core" cx="100" cy="100" r="80" fill="none"></circle>
        <path class="shield-mark" d="M100 52 L132 68 L132 108 C132 130 118 144 100 150 C82 144 68 130 68 108 L68 68 Z"></path>
        <path class="shield-mark" id="shield-status-mark" d="${escHtml(shieldStatusMark(overall.light))}"></path>
      </svg>
    </div>
    <h1 id="hero-copy">${escHtml(heroCopy)}</h1>
    <p class="hero-sub" id="hero-sub">${escHtml(overall.headline)}</p>
    <div class="identity-line" id="identity-line">
      <span class="name" id="agent-name">${escHtml(agent.display_name)}</span>
      <span class="sep">·</span>
      <span class="did" id="agent-did">${escHtml(agent.did_fingerprint ?? "unclaimed")}</span>
      ${agent.primary_identity_id ? `<span class="primary-flag">Primary</span>` : ""}
    </div>
  </section>

  <div class="layer-grid" id="layer-grid">
    ${l1Card(layers.l1)}
    ${l2Card(layers.l2)}
    ${l3Card(layers.l3)}
    ${l4Card(layers.l4)}
  </div>

  <section class="section" id="approval-section">
    <h2>Needs approval <span class="count" id="approval-count">${escHtml(approvalCount)}</span></h2>
    <div class="approval-list" id="approval-list">${approvalItems}</div>
  </section>

  <section class="section">
    <h2>Upstream servers <span class="count">${upstream_servers.length}</span></h2>
    <ul class="server-list" id="server-list">${serverRows}</ul>
  </section>

  <section class="section">
    <h2>Privacy boundary <span class="count" id="privacy-count">${privacy.filtered_spans}</span></h2>
    <dl class="privacy-grid">
      <div class="privacy-metric">
        <dt>Filtered spans</dt>
        <dd id="privacy-spans">${escHtml(privacy.filtered_spans)}</dd>
      </div>
      <div class="privacy-metric">
        <dt>Filtered events</dt>
        <dd id="privacy-events">${escHtml(privacy.filtered_events)}</dd>
      </div>
      <div class="privacy-metric">
        <dt>Last filter</dt>
        <dd class="small" id="privacy-last">${escHtml(privacyLast)}</dd>
      </div>
    </dl>
    <div class="privacy-classes" id="privacy-classes">
      ${privacyClasses || `<span class="privacy-chip">No classes recorded</span>`}
    </div>
  </section>

  <section class="section">
    <h2>Live activity <span class="count" id="activity-count">${activity.length}</span></h2>
    <div class="panel">
      <div class="panel-head"><h3>Recent tool calls</h3></div>
      <table>
        <thead><tr><th>Time</th><th>Tool</th><th>Server</th><th>Tier</th><th>Result</th></tr></thead>
        <tbody id="activity-body">${activityRows}</tbody>
      </table>
    </div>
  </section>

  <section class="section">
    <details class="audit-details">
      <summary>
        <h3>Audit trail <span class="count" id="audit-count">${audit.length}</span></h3>
        <span class="caret">▸</span>
      </summary>
      <div class="audit-filters">
        <div class="filter-row" id="audit-filter">
          <button class="active" data-filter="all">All</button>
          <button data-filter="l1">Cognitive</button>
          <button data-filter="l2">Operational</button>
          <button data-filter="l3">Disclosure</button>
          <button data-filter="l4">Reputation</button>
        </div>
      </div>
      <table>
        <thead><tr><th>Time</th><th>Layer</th><th>Operation</th><th>Result</th></tr></thead>
        <tbody id="audit-body">${auditRows}</tbody>
      </table>
    </details>
  </section>
</div>

<script>
(() => {
  const INITIAL_SNAPSHOT = ${initialSnapshot};
  let AUTH_TOKEN = sessionStorage.getItem("authToken") || "";
  function authHeader() {
    return AUTH_TOKEN ? { "Authorization": "Bearer " + AUTH_TOKEN } : {};
  }
  function promptForOperatorToken() {
    const entered = window.prompt("Operator token required for this action.");
    if (!entered || !entered.trim()) return false;
    AUTH_TOKEN = entered.trim();
    sessionStorage.setItem("authToken", AUTH_TOKEN);
    return true;
  }

  let snapshot = INITIAL_SNAPSHOT;

  function esc(value) {
    if (value == null) return "";
    return String(value)
      .replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;").replace(/'/g, "&#039;");
  }
  function fmtTime(iso) {
    try { return new Date(iso).toLocaleTimeString(); } catch { return iso; }
  }
  const HERO_COPY_TEXT = ${JSON.stringify(HERO_COPY)};
  const NON_GREEN_HERO_COPY_TEXT = ${JSON.stringify(NON_GREEN_HERO_COPY)};
  function heroCopyForLight(light) {
    return light === "green" ? HERO_COPY_TEXT : NON_GREEN_HERO_COPY_TEXT;
  }
  function shieldStatusMarkForLight(light) {
    if (light === "green") return "M85 102 L96 113 L118 90";
    if (light === "yellow") return "M100 78 L122 120 L78 120 Z";
    return "M84 84 L116 116 M116 84 L84 116";
  }

  function renderShield(light, headline) {
    const shield = document.getElementById("shield");
    if (!shield) return;
    shield.classList.remove("green", "yellow", "red");
    shield.classList.add(light);
    const mark = document.getElementById("shield-status-mark");
    if (mark) mark.setAttribute("d", shieldStatusMarkForLight(light));
    document.getElementById("hero-copy").textContent = heroCopyForLight(light);
    document.getElementById("hero-sub").textContent = headline;
  }

  function renderActivity(entries) {
    const body = document.getElementById("activity-body");
    const count = document.getElementById("activity-count");
    if (!body) return;
    count.textContent = String(entries.length);
    if (!entries.length) {
      body.innerHTML = '<tr class="empty"><td colspan="5">Waiting for tool calls\u2026</td></tr>';
      return;
    }
    body.innerHTML = entries.map(e => (
      '<tr class="result-' + esc(e.result) + '">' +
        '<td class="mono time">' + esc(fmtTime(e.timestamp)) + '</td>' +
        '<td class="mono">' + esc(e.tool) + '</td>' +
        '<td class="mono">' + esc(e.server) + '</td>' +
        '<td class="tier tier-' + esc(e.tier) + '">T' + esc(e.tier) + '</td>' +
        '<td class="result">' + esc(e.result) + '</td>' +
      '</tr>'
    )).join("");
  }

  function renderApprovals(list, redacted, redactedCount) {
    const container = document.getElementById("approval-list");
    const count = document.getElementById("approval-count");
    if (!container) return;
    if (redacted) {
      count.textContent = String(redactedCount || 0);
      container.innerHTML = '<div class="empty-block approval-redacted" data-pending-approvals-redacted="1">Approvals are hidden, not empty. Pending count: ' + esc(redactedCount || 0) + '</div>';
      return;
    }
    count.textContent = String(list.length);
    if (!list.length) {
      container.innerHTML = '<div class="empty-block">No pending approvals</div>';
      return;
    }
    container.innerHTML = list.map(p => (
      '<article class="approval" data-id="' + esc(p.id) + '">' +
        '<div class="approval-head">' +
          '<span class="tier-chip tier-' + esc(p.tier) + '">Tier ' + esc(p.tier) + '</span>' +
          '<span class="mono">' + esc(p.operation) + '</span>' +
        '</div>' +
        '<p class="approval-reason">' + esc(p.reason) + '</p>' +
        '<div class="approval-actions">' +
          '<button class="btn btn-allow" data-action="allow" data-id="' + esc(p.id) + '">Allow</button>' +
          '<button class="btn btn-deny" data-action="deny" data-id="' + esc(p.id) + '">Deny</button>' +
        '</div>' +
      '</article>'
    )).join("");
    wireApprovalButtons();
  }

  function renderAudit(entries, filter) {
    filter = filter || "all";
    const body = document.getElementById("audit-body");
    const count = document.getElementById("audit-count");
    if (!body) return;
    const visible = filter === "all" ? entries : entries.filter(e => e.layer === filter);
    count.textContent = String(visible.length);
    if (!visible.length) {
      body.innerHTML = '<tr class="empty"><td colspan="4">Audit log empty</td></tr>';
      return;
    }
    body.innerHTML = visible.map(e => (
      '<tr data-kind="' + esc(e.layer) + '" data-op="' + esc(e.operation) + '">' +
        '<td class="mono time">' + esc(fmtTime(e.timestamp)) + '</td>' +
        '<td><span class="layer-pill">' + esc(String(e.layer).toUpperCase()) + '</span></td>' +
        '<td class="mono">' + esc(e.operation) + '</td>' +
        '<td class="result-' + esc(e.result) + '">' + esc(e.result) + '</td>' +
      '</tr>'
    )).join("");
  }

  function renderPrivacy(summary) {
    const count = document.getElementById("privacy-count");
    const spans = document.getElementById("privacy-spans");
    const events = document.getElementById("privacy-events");
    const last = document.getElementById("privacy-last");
    const classes = document.getElementById("privacy-classes");
    if (!summary || !spans || !events || !last || !classes) return;
    if (count) count.textContent = String(summary.filtered_spans || 0);
    spans.textContent = String(summary.filtered_spans || 0);
    events.textContent = String(summary.filtered_events || 0);
    last.textContent = summary.last_filtered_at ? new Date(summary.last_filtered_at).toLocaleString() : "No filtering events yet";
    const rows = Object.entries(summary.classes || {}).sort((a, b) => b[1] - a[1]);
    classes.innerHTML = rows.length
      ? rows.map(([name, n]) => '<span class="privacy-chip">' + esc(name) + ' ' + esc(n) + '</span>').join("")
      : '<span class="privacy-chip">No classes recorded</span>';
  }

  function renderAll(snap) {
    snapshot = snap;
    renderShield(snap.overall.light, snap.overall.headline);
    const mp = document.getElementById("mode-pill");
    if (mp) mp.textContent = snap.mode + " · v" + snap.server_version;
    document.getElementById("agent-name").textContent = snap.agent.display_name;
    document.getElementById("agent-did").textContent = snap.agent.did_fingerprint || "unclaimed";
    renderActivity(snap.activity);
    renderApprovals(
      snap.pending_approvals,
      snap.pending_approvals_redacted === true,
      snap.pending_approvals_count || 0,
    );
    renderPrivacy(snap.privacy);
    renderAudit(snap.audit, currentAuditFilter());
  }

  function currentAuditFilter() {
    const active = document.querySelector("#audit-filter button.active");
    return active ? active.dataset.filter : "all";
  }

  function wireApprovalButtons() {
    document.querySelectorAll("#approval-list button[data-action]").forEach(btn => {
      btn.addEventListener("click", async () => {
        const id = btn.dataset.id;
        const action = btn.dataset.action;
        btn.disabled = true;
        try {
          let response = await fetch("/api/approvals/" + encodeURIComponent(id) + "/" + action, {
            method: "POST", headers: authHeader()
          });
          if (response.status === 401 && promptForOperatorToken()) {
            response = await fetch("/api/approvals/" + encodeURIComponent(id) + "/" + action, {
              method: "POST", headers: authHeader()
            });
          }
        } catch {}
        await refreshSnapshot();
      });
    });
  }

  function wireAuditFilter() {
    document.querySelectorAll("#audit-filter button").forEach(btn => {
      btn.addEventListener("click", () => {
        document.querySelectorAll("#audit-filter button").forEach(b => b.classList.remove("active"));
        btn.classList.add("active");
        renderAudit(snapshot.audit, btn.dataset.filter);
      });
    });
  }

  async function refreshSnapshot() {
    try {
      const res = await fetch("/api/snapshot", { headers: authHeader() });
      if (!res.ok) return;
      const snap = await res.json();
      renderAll(snap);
    } catch {}
  }

  async function createSessionQuery() {
    if (!AUTH_TOKEN) return "";
    const res = await fetch("/auth/session", { method: "POST", headers: authHeader() });
    if (!res.ok) throw new Error("session_exchange_failed");
    const body = await res.json();
    if (!body || !body.session_id || body.session_id === "no-auth") return "";
    return "?session=" + encodeURIComponent(body.session_id);
  }

  async function connectSSE() {
    try {
      const sessionQuery = await createSessionQuery();
      const es = new EventSource("/api/stream" + sessionQuery);
      es.addEventListener("snapshot", (ev) => {
        try { renderAll(JSON.parse(ev.data)); } catch {}
      });
      es.addEventListener("activity", () => refreshSnapshot());
      es.addEventListener("approval", () => refreshSnapshot());
      es.onerror = () => { es.close(); setTimeout(connectSSE, 3000); };
    } catch {}
  }

  wireApprovalButtons();
  wireAuditFilter();
  connectSSE();
})();
</script>
</body>
</html>`;
}
