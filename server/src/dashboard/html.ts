/**
 * Sanctuary Dashboard — Single-Page HTML
 *
 * Hero shield + four layer cards + live activity feed + approval queue +
 * audit trail. Vanilla HTML/CSS/JS in one string, matching the convention
 * established by server/src/cocoon/fortress-view.ts.
 *
 * The initial snapshot is embedded server-side so the page renders
 * correctly without JavaScript. Live updates layer on via SSE + REST.
 */

import type { ProtectionSnapshot } from "./aggregator.js";

// Re-export the multi-tenant renderer so dashboard consumers can import a
// single module for both modes.
export {
  renderMultiAgentHTML,
  type MultiAgentHTMLOptions,
} from "./multi-html.js";

/** Hero copy. Change here if we ever A/B test. */
export const HERO_COPY = "Your agent is protected.";

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
  const { overall, agent, layers, activity, pending_approvals, audit, upstream_servers } = snapshot;

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

  const approvalItems = pending_approvals.length === 0
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

  const initialSnapshot = JSON.stringify(snapshot)
    .replace(/</g, "\\u003c")
    .replace(/\u2028/g, "\\u2028")
    .replace(/\u2029/g, "\\u2029");

  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Sanctuary — Sovereignty Dashboard</title>
<style>
:root {
  --bg: #07080c;
  --bg-2: #0f1220;
  --surface: #131729;
  --surface-2: #1a1f36;
  --border: #26304d;
  --border-strong: #39436a;
  --ink: #eef1fb;
  --ink-dim: #b9c0dc;
  --ink-mute: #7e86a8;
  --indigo: #6e7bff;
  --indigo-deep: #3b4ad8;
  --green: #3ee08f;
  --green-deep: #168a4d;
  --amber: #f1c05a;
  --red: #ff6b7a;
  --violet: #a77bff;
  --radius: 14px;
  --radius-sm: 8px;
  --shadow: 0 14px 42px rgba(3, 6, 19, 0.45);
  --mono: ui-monospace, SFMono-Regular, "SF Mono", Menlo, Consolas, monospace;
}
* { margin: 0; padding: 0; box-sizing: border-box; }
html, body { background: var(--bg); color: var(--ink); font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Inter, sans-serif; min-height: 100vh; -webkit-font-smoothing: antialiased; }
body { background: radial-gradient(circle at 50% -200px, rgba(110, 123, 255, 0.18), transparent 60%), var(--bg); }
a { color: var(--indigo); text-decoration: none; }
button { font: inherit; cursor: pointer; }

.wrap { max-width: 1180px; margin: 0 auto; padding: 40px 32px 120px; }

/* ── Top meta row ─────────────────────────────────────────────── */
.meta-row {
  display: flex;
  justify-content: space-between;
  align-items: center;
  color: var(--ink-mute);
  font-size: 12px;
  letter-spacing: 0.08em;
  text-transform: uppercase;
  margin-bottom: 8px;
}
.meta-row .mode-pill {
  padding: 4px 10px;
  border-radius: 999px;
  border: 1px solid var(--border);
  background: var(--surface);
  font-family: var(--mono);
  text-transform: none;
  letter-spacing: 0;
  font-size: 11px;
  color: var(--ink-dim);
}

/* ── Hero ─────────────────────────────────────────────────────── */
.hero {
  display: flex;
  flex-direction: column;
  align-items: center;
  text-align: center;
  padding: 48px 24px 56px;
  border-radius: 22px;
  background:
    radial-gradient(circle at 50% 0%, rgba(62, 224, 143, 0.08), transparent 70%),
    linear-gradient(180deg, var(--bg-2) 0%, var(--surface) 100%);
  border: 1px solid var(--border);
  box-shadow: var(--shadow);
  margin-bottom: 32px;
  position: relative;
  overflow: hidden;
}
.hero::after {
  content: "";
  position: absolute;
  inset: 0;
  background: radial-gradient(circle at 50% 100%, rgba(110, 123, 255, 0.10), transparent 60%);
  pointer-events: none;
}
.shield {
  width: 200px;
  height: 200px;
  position: relative;
  filter: drop-shadow(0 16px 32px rgba(62, 224, 143, 0.18));
  animation: hero-in 600ms cubic-bezier(0.2, 0.8, 0.2, 1) both;
}
@keyframes hero-in {
  from { opacity: 0; transform: translateY(12px) scale(0.96); }
  to { opacity: 1; transform: translateY(0) scale(1); }
}
.shield svg { width: 100%; height: 100%; display: block; }
.shield.green .shield-ring { stroke: var(--green); }
.shield.green .shield-core { fill: rgba(62, 224, 143, 0.14); }
.shield.green .shield-mark { stroke: var(--green); }
.shield.yellow .shield-ring { stroke: var(--amber); }
.shield.yellow .shield-core { fill: rgba(241, 192, 90, 0.14); }
.shield.yellow .shield-mark { stroke: var(--amber); }
.shield.red .shield-ring { stroke: var(--red); }
.shield.red .shield-core { fill: rgba(255, 107, 122, 0.16); }
.shield.red .shield-mark { stroke: var(--red); }
.shield .shield-ring {
  fill: none;
  stroke-width: 3;
  stroke-dasharray: 600;
  stroke-dashoffset: 0;
  transform-origin: center;
  transition: stroke 320ms ease;
}
.shield .shield-ring-bg { fill: none; stroke: rgba(255, 255, 255, 0.06); stroke-width: 3; }
.shield .shield-mark { fill: none; stroke-width: 4; stroke-linecap: round; stroke-linejoin: round; transition: stroke 320ms ease; }

.hero h1 {
  font-size: 40px;
  font-weight: 650;
  letter-spacing: -0.02em;
  margin-top: 28px;
  position: relative;
  z-index: 1;
}
.hero .hero-sub {
  margin-top: 10px;
  color: var(--ink-dim);
  font-size: 15px;
  position: relative;
  z-index: 1;
}
.identity-line {
  margin-top: 22px;
  display: inline-flex;
  align-items: center;
  gap: 10px;
  padding: 10px 18px;
  border-radius: 999px;
  border: 1px solid var(--border);
  background: rgba(19, 23, 41, 0.7);
  font-family: var(--mono);
  font-size: 13px;
  color: var(--ink-dim);
  position: relative;
  z-index: 1;
}
.identity-line .name { color: var(--ink); font-weight: 500; font-family: -apple-system, BlinkMacSystemFont, Inter, sans-serif; letter-spacing: 0; }
.identity-line .sep { color: var(--ink-mute); }
.identity-line .did { color: var(--violet); }
.identity-line .primary-flag {
  padding: 2px 8px;
  border-radius: 999px;
  background: rgba(110, 123, 255, 0.16);
  color: var(--indigo);
  font-size: 11px;
  text-transform: uppercase;
  letter-spacing: 0.1em;
  font-family: -apple-system, BlinkMacSystemFont, Inter, sans-serif;
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
  border-radius: var(--radius);
  background: var(--surface);
  border: 1px solid var(--border);
  transition: border 220ms ease, transform 220ms ease;
}
.layer-card:hover { border-color: var(--border-strong); transform: translateY(-1px); }

.layer-head { display: flex; align-items: flex-start; gap: 12px; margin-bottom: 14px; }
.layer-dot { width: 12px; height: 12px; border-radius: 50%; margin-top: 6px; background: var(--ink-mute); box-shadow: 0 0 0 3px rgba(255, 255, 255, 0.04); }
.layer-full .layer-dot { background: var(--green); box-shadow: 0 0 0 3px rgba(62, 224, 143, 0.18); }
.layer-degraded .layer-dot { background: var(--amber); box-shadow: 0 0 0 3px rgba(241, 192, 90, 0.18); }
.layer-compromised .layer-dot { background: var(--red); box-shadow: 0 0 0 3px rgba(255, 107, 122, 0.18); }
.layer-head h3 { font-size: 13px; text-transform: uppercase; letter-spacing: 0.08em; color: var(--ink-dim); margin-bottom: 4px; }
.layer-headline { font-size: 15px; color: var(--ink); line-height: 1.35; }

.layer-detail { display: flex; flex-direction: column; gap: 8px; }
.layer-detail > div { display: flex; justify-content: space-between; gap: 12px; font-size: 12px; }
.layer-detail dt { color: var(--ink-mute); text-transform: uppercase; letter-spacing: 0.06em; font-size: 11px; }
.layer-detail dd { color: var(--ink-dim); text-align: right; font-family: var(--mono); font-size: 12px; }

.layer-cta { margin-top: 6px; text-align: center; padding: 16px; border-radius: var(--radius-sm); background: var(--bg-2); border: 1px solid var(--border); }
.score-block { display: flex; flex-direction: column; gap: 2px; }
.score-value { font-size: 28px; font-weight: 650; color: var(--green); letter-spacing: -0.02em; }
.score-label { font-size: 11px; text-transform: uppercase; color: var(--ink-mute); letter-spacing: 0.08em; }
.claim-block { font-size: 13px; color: var(--violet); }

/* ── L4 evidence widget (v0.9.1) ──────────────────────────────── */
.l4-evidence { margin-top: 12px; padding-top: 12px; border-top: 1px dashed var(--border); }
.l4-evidence-summary { gap: 6px; margin-bottom: 10px; }
.l4-evidence-summary dt { font-size: 10px; }
.l4-evidence-summary dd { font-size: 11px; }
.l4-deg-list { list-style: none; display: flex; flex-direction: column; gap: 6px; margin-top: 8px; }
.l4-deg { padding: 8px 10px; border-radius: var(--radius-sm); background: var(--bg-2); border: 1px solid var(--border); font-size: 12px; }
.l4-deg-head { display: flex; justify-content: space-between; align-items: baseline; gap: 8px; margin-bottom: 3px; }
.l4-deg-code { font-family: var(--mono); font-size: 11px; color: var(--ink); letter-spacing: 0.02em; }
.l4-deg-sev { font-size: 10px; text-transform: uppercase; letter-spacing: 0.08em; color: var(--ink-mute); }
.l4-deg-warning { border-color: rgba(241, 192, 90, 0.4); }
.l4-deg-warning .l4-deg-sev { color: var(--amber); }
.l4-deg-critical { border-color: rgba(255, 107, 122, 0.5); }
.l4-deg-critical .l4-deg-sev { color: var(--red); }
.l4-deg-info .l4-deg-sev { color: var(--indigo); }
.l4-deg-desc { color: var(--ink-dim); line-height: 1.35; font-size: 11px; }
.l4-deg-mit { color: var(--ink-mute); line-height: 1.35; font-size: 10px; margin-top: 3px; font-style: italic; }

/* ── Section headers ─────────────────────────────────────────── */
.section { margin-bottom: 28px; }
.section h2 {
  font-size: 13px;
  text-transform: uppercase;
  letter-spacing: 0.1em;
  color: var(--ink-dim);
  margin-bottom: 12px;
  display: flex;
  align-items: center;
  gap: 12px;
}
.section h2 .count {
  font-family: var(--mono);
  font-size: 11px;
  padding: 2px 8px;
  border-radius: 999px;
  background: var(--surface);
  border: 1px solid var(--border);
  color: var(--ink-mute);
  text-transform: none;
  letter-spacing: 0;
}

/* ── Approval queue ──────────────────────────────────────────── */
.approval-list { display: flex; flex-direction: column; gap: 10px; }
.approval {
  padding: 16px;
  background: var(--surface);
  border: 1px solid var(--amber);
  border-radius: var(--radius);
  box-shadow: 0 0 0 1px rgba(241, 192, 90, 0.18);
  animation: fade-up 260ms ease both;
}
@keyframes fade-up { from { opacity: 0; transform: translateY(6px); } to { opacity: 1; transform: translateY(0); } }
.approval-head { display: flex; align-items: center; gap: 10px; margin-bottom: 6px; font-size: 14px; }
.tier-chip { padding: 2px 8px; border-radius: 999px; font-size: 10px; text-transform: uppercase; letter-spacing: 0.08em; font-family: -apple-system, Inter, sans-serif; }
.tier-chip.tier-1 { background: rgba(255, 107, 122, 0.16); color: var(--red); }
.tier-chip.tier-2 { background: rgba(241, 192, 90, 0.16); color: var(--amber); }
.approval-reason { font-size: 13px; color: var(--ink-dim); margin-bottom: 12px; }
.approval-actions { display: flex; gap: 8px; }
.btn {
  padding: 7px 14px;
  border-radius: var(--radius-sm);
  border: 1px solid var(--border);
  background: var(--surface-2);
  color: var(--ink);
  font-size: 13px;
  transition: all 160ms ease;
}
.btn:hover { border-color: var(--border-strong); background: #202641; }
.btn-allow { background: var(--green-deep); border-color: var(--green-deep); color: white; }
.btn-allow:hover { background: #1ba25b; border-color: #1ba25b; }
.btn-deny { background: transparent; border-color: var(--red); color: var(--red); }
.btn-deny:hover { background: rgba(255, 107, 122, 0.1); border-color: var(--red); }

/* ── Tables ──────────────────────────────────────────────────── */
.panel { background: var(--surface); border: 1px solid var(--border); border-radius: var(--radius); overflow: hidden; }
.panel-head { display: flex; justify-content: space-between; align-items: center; padding: 12px 18px; border-bottom: 1px solid var(--border); }
.panel-head h3 { font-size: 12px; text-transform: uppercase; letter-spacing: 0.1em; color: var(--ink-dim); }
.filter-row { display: flex; gap: 6px; }
.filter-row button {
  padding: 4px 10px;
  font-size: 11px;
  border-radius: 999px;
  background: transparent;
  border: 1px solid var(--border);
  color: var(--ink-mute);
  text-transform: uppercase;
  letter-spacing: 0.06em;
  transition: all 140ms ease;
}
.filter-row button.active, .filter-row button:hover { color: var(--ink); border-color: var(--border-strong); background: var(--surface-2); }

table { width: 100%; border-collapse: collapse; }
th, td { padding: 10px 18px; text-align: left; font-size: 13px; border-bottom: 1px solid var(--border); }
th { font-size: 11px; text-transform: uppercase; letter-spacing: 0.08em; color: var(--ink-mute); font-weight: 500; background: var(--bg-2); }
tr:last-child td { border-bottom: none; }
tr.empty td { text-align: center; color: var(--ink-mute); padding: 32px 18px; }
.mono { font-family: var(--mono); font-size: 12px; }
.time { color: var(--ink-mute); white-space: nowrap; }
.tier { text-align: center; font-family: var(--mono); font-size: 11px; font-weight: 600; }
.tier-1 { color: var(--red); }
.tier-2 { color: var(--amber); }
.tier-3 { color: var(--green); }
.result { font-family: var(--mono); font-size: 12px; text-transform: uppercase; letter-spacing: 0.06em; }
.result-allowed, .result-success { color: var(--green); }
.result-denied, .result-failure { color: var(--red); }
.result-approved { color: var(--indigo); }
.result-pending { color: var(--amber); }
.layer-pill { font-family: var(--mono); font-size: 11px; padding: 2px 8px; border-radius: 999px; background: var(--surface-2); color: var(--ink-dim); display: inline-block; }

/* ── Upstream servers ────────────────────────────────────────── */
.server-list { list-style: none; display: flex; flex-direction: column; gap: 8px; }
.server-row { display: flex; align-items: center; gap: 10px; padding: 10px 14px; background: var(--surface); border: 1px solid var(--border); border-radius: var(--radius-sm); font-size: 13px; }
.server-dot { width: 8px; height: 8px; border-radius: 50%; background: var(--ink-mute); }
.server-row.state-connected .server-dot { background: var(--green); }
.server-row.state-connecting .server-dot { background: var(--amber); }
.server-row.state-disconnected .server-dot, .server-row.state-error .server-dot { background: var(--red); }
.server-meta { margin-left: auto; font-size: 12px; color: var(--ink-mute); font-family: var(--mono); }

.empty-block { padding: 18px; color: var(--ink-mute); text-align: center; font-size: 13px; background: var(--surface); border: 1px dashed var(--border); border-radius: var(--radius-sm); }

/* ── Audit collapsible ───────────────────────────────────────── */
details.audit-details { background: var(--surface); border: 1px solid var(--border); border-radius: var(--radius); overflow: hidden; }
details.audit-details summary { cursor: pointer; list-style: none; padding: 14px 18px; display: flex; align-items: center; justify-content: space-between; }
details.audit-details summary::-webkit-details-marker { display: none; }
details.audit-details summary h3 { font-size: 12px; text-transform: uppercase; letter-spacing: 0.1em; color: var(--ink-dim); }
details.audit-details summary .caret { color: var(--ink-mute); font-family: var(--mono); }
details.audit-details[open] .caret { transform: rotate(90deg); display: inline-block; }
details.audit-details .audit-filters { display: flex; gap: 6px; padding: 0 18px 12px; border-bottom: 1px solid var(--border); }
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
        <circle class="shield-core" cx="100" cy="100" r="80" fill="rgba(255,255,255,0.02)"></circle>
        <path class="shield-mark" d="M100 52 L132 68 L132 108 C132 130 118 144 100 150 C82 144 68 130 68 108 L68 68 Z"></path>
        <path class="shield-mark" d="M85 102 L96 113 L118 90"></path>
      </svg>
    </div>
    <h1 id="hero-copy">${escHtml(HERO_COPY)}</h1>
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
    <h2>Needs approval <span class="count" id="approval-count">${pending_approvals.length}</span></h2>
    <div class="approval-list" id="approval-list">${approvalItems}</div>
  </section>

  <section class="section">
    <h2>Upstream servers <span class="count">${upstream_servers.length}</span></h2>
    <ul class="server-list" id="server-list">${serverRows}</ul>
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
  const AUTH_TOKEN = ${options.authToken ? JSON.stringify(options.authToken) : "null"};
  const AUTH_HEADER = AUTH_TOKEN ? { "Authorization": "Bearer " + AUTH_TOKEN } : {};
  const AUTH_QS = AUTH_TOKEN ? "?token=" + encodeURIComponent(AUTH_TOKEN) : "";

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

  function renderShield(light, headline) {
    const shield = document.getElementById("shield");
    if (!shield) return;
    shield.classList.remove("green", "yellow", "red");
    shield.classList.add(light);
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

  function renderApprovals(list) {
    const container = document.getElementById("approval-list");
    const count = document.getElementById("approval-count");
    if (!container) return;
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

  function renderAll(snap) {
    snapshot = snap;
    renderShield(snap.overall.light, snap.overall.headline);
    const mp = document.getElementById("mode-pill");
    if (mp) mp.textContent = snap.mode + " · v" + snap.server_version;
    document.getElementById("agent-name").textContent = snap.agent.display_name;
    document.getElementById("agent-did").textContent = snap.agent.did_fingerprint || "unclaimed";
    renderActivity(snap.activity);
    renderApprovals(snap.pending_approvals);
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
          await fetch("/api/approvals/" + encodeURIComponent(id) + "/" + action + AUTH_QS, {
            method: "POST", headers: AUTH_HEADER
          });
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
      const res = await fetch("/api/snapshot" + AUTH_QS, { headers: AUTH_HEADER });
      if (!res.ok) return;
      const snap = await res.json();
      renderAll(snap);
    } catch {}
  }

  function connectSSE() {
    try {
      const es = new EventSource("/api/stream" + AUTH_QS);
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
