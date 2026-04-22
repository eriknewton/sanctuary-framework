/**
 * Sanctuary Operator Console v1.0 — HTML renderer.
 *
 * Server-rendered HTML for the six primary surfaces. The same document is
 * served to the browser and to the thin Electron shell — satisfying the
 * "single render tree, two shells" acceptance criterion via one HTML surface
 * consumed by both.
 *
 * Scope notes:
 *   - No competitor product names in copy (naming-discipline rule).
 *   - No em-dashes in operator-facing strings (no-em-dash rule).
 *   - Attestation badges render with deterministic class names so tests can
 *     assert on them without mocking.
 *   - Reserved v1.x surfaces render as disabled affordances.
 */

import type { MeshConsoleClient } from "./client.js";
import {
  CONSOLE_VERSION,
  RESERVED_V1X_SURFACES,
  RESERVED_V1X_SURFACE_LABELS,
  SURFACE_LABELS,
  CONSOLE_SURFACES,
} from "./constants.js";
import type {
  AttestationBadgeView,
  FortressOverviewView,
  AgentsPanelView,
  AlertInboxView,
  PendingJoinView,
  RecoveryEntryView,
} from "./types.js";

function htmlEscape(s: string): string {
  return s
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

function renderBadge(b: AttestationBadgeView): string {
  return `<span class="${htmlEscape(b.class_name)}" data-layer="${htmlEscape(
    b.layer
  )}" data-state="${htmlEscape(b.state)}" title="${htmlEscape(b.tooltip)}">${htmlEscape(
    b.label
  )}</span>`;
}

function renderNavigation(active: string): string {
  const items: string[] = [];
  for (const id of CONSOLE_SURFACES) {
    const cls = id === active ? "nav-item active" : "nav-item";
    items.push(
      `<a class="${cls}" href="#${id}" data-surface="${htmlEscape(id)}">${htmlEscape(
        SURFACE_LABELS[id]
      )}</a>`
    );
  }
  for (const id of RESERVED_V1X_SURFACES) {
    items.push(
      `<span class="nav-item reserved-v1x" data-reserved="true" data-surface="${htmlEscape(
        id
      )}" title="Reserved for v1.x. Not rendered at v1.0.">${htmlEscape(
        RESERVED_V1X_SURFACE_LABELS[id]
      )}</span>`
    );
  }
  return `<nav class="console-nav">${items.join("")}</nav>`;
}

function renderFortressOverview(view: FortressOverviewView): string {
  const nodeRows = view.nodes
    .map(
      (n) => `
        <tr data-node-id="${htmlEscape(n.node_id)}">
          <td class="node-id">${htmlEscape(n.node_id.slice(0, 12))}...</td>
          <td class="node-mode node-mode-${htmlEscape(n.mode)}">${htmlEscape(n.mode)}</td>
          <td class="node-presence">${htmlEscape(n.presence)}</td>
          <td>${n.last_heartbeat_at ?? "(none yet)"}</td>
          <td>${renderBadge(n.badge)}</td>
        </tr>`
    )
    .join("");

  return `
    <section id="fortress" class="surface">
      <h2>Fortress overview</h2>
      <div class="fortress-meta">
        <div>Fortress: <code>${htmlEscape(view.fortress_id)}</code></div>
        <div>Master created: ${htmlEscape(view.master_created_at)}</div>
        <div>Canonical audit node: <code>${htmlEscape(view.canonical_audit_node)}</code></div>
        <div>Last rotation: ${view.last_rotation_at ? htmlEscape(view.last_rotation_at) : "(never rotated)"}</div>
        <div>Global attestation: ${renderBadge(view.global_badge)}</div>
        <div>Custody provenance: ${renderBadge(
          {
            layer: "custody-provenance-stub",
            state: "unknown",
            label: "Custody (v1.x)",
            class_name: "att-badge att-custody-provenance-stub att-v1x-reserved",
            tooltip:
              "Custody-provenance attestation (Agentic.Market / x402 signing flow) lands in v1.x. Not rendered at v1.0.",
          }
        )}</div>
      </div>
      ${
        view.canonical_audit_loss
          ? `<div class="alert-banner warn">Canonical audit node unreachable past grace window. Reassignment suggested.</div>`
          : ""
      }
      <table class="node-table">
        <thead>
          <tr><th>Node</th><th>Mode</th><th>Presence</th><th>Last heartbeat</th><th>Attestation</th></tr>
        </thead>
        <tbody>${nodeRows || '<tr><td colspan="5">No peers admitted yet.</td></tr>'}</tbody>
      </table>
    </section>`;
}

function renderAgentsPanel(view: AgentsPanelView): string {
  if (view.agents.length === 0) {
    return `<section id="agents" class="surface">
      <h2>Agents</h2>
      <p class="empty-state">${htmlEscape(view.empty_state)}</p>
    </section>`;
  }
  const rows = view.agents
    .map(
      (a) => `
        <tr data-agent-id="${htmlEscape(a.agent_id)}">
          <td class="agent-id">${htmlEscape(a.agent_id)}</td>
          <td>v${a.last_policy_version}</td>
          <td>${a.last_usage_event_id ? htmlEscape(a.last_usage_event_id.slice(0, 10)) + "..." : "(none)"}</td>
          <td>${a.last_usage_event_at ? htmlEscape(a.last_usage_event_at) : "(none)"}</td>
          <td>${renderBadge(a.per_agent_badge)}</td>
          <td>${renderBadge(a.last_action_badge)}</td>
        </tr>`
    )
    .join("");
  return `
    <section id="agents" class="surface">
      <h2>Agents</h2>
      <table class="agent-table">
        <thead>
          <tr><th>Agent</th><th>Policy</th><th>Last action</th><th>Last action time</th><th>Agent badge</th><th>Action badge</th></tr>
        </thead>
        <tbody>${rows}</tbody>
      </table>
    </section>`;
}

function renderPolicyEditor(client: MeshConsoleClient): string {
  const templates = client.listChannelTemplates();
  const options = templates
    .map(
      (t) =>
        `<option value="${htmlEscape(t.id)}">${htmlEscape(t.label)}</option>`
    )
    .join("");
  const templateDocs = templates
    .map(
      (t) => `
        <li>
          <strong>${htmlEscape(t.label)}</strong> (<code>${htmlEscape(t.id)}</code>):
          ${htmlEscape(t.description)}
        </li>`
    )
    .join("");
  return `
    <section id="policy" class="surface">
      <h2>Policy editor</h2>
      <p>Compose a policy in plain English via one of the five channel templates, then pin it. Pinning emits a signed <code>policy_update</code> event over the mesh.</p>
      <form id="policy-compose" class="policy-form">
        <label>Agent ID
          <input name="agent_id" required pattern="[a-zA-Z0-9_\\-]+" />
        </label>
        <label>Counterparty
          <input name="counterparty" required pattern="[a-zA-Z0-9_\\-]+" />
        </label>
        <label>Channel template
          <select name="channel_template_id" required>${options}</select>
        </label>
        <label>Scope (optional JSON object)
          <input name="scope_json" placeholder='{"credential_id":"example"}' />
        </label>
        <button type="submit">Pin policy</button>
      </form>
      <div id="policy-pinned-list" class="policy-pinned"></div>
      <details>
        <summary>Channel templates reference</summary>
        <ul>${templateDocs}</ul>
      </details>
    </section>`;
}

function renderPendingJoin(join: PendingJoinView): string {
  return `
    <li class="join-pending-row" data-request-id="${htmlEscape(join.request_id)}">
      <div>Candidate <code>${htmlEscape(join.candidate_node_id.slice(0, 12))}...</code></div>
      <div>Mode: <span class="node-mode-${htmlEscape(join.candidate_node_mode)}">${htmlEscape(join.candidate_node_mode)}</span></div>
      <div>Issuer: <code>${htmlEscape(join.issuer_principal)}</code></div>
      <div>Attestation: ${join.attestation_ok ? "present" : "absent"}</div>
      <div class="join-actions">
        <button class="join-approve" data-request-id="${htmlEscape(join.request_id)}">Approve</button>
        <button class="join-deny" data-request-id="${htmlEscape(join.request_id)}">Deny</button>
      </div>
      <p class="tier-note">Tier 1 gate: explicit confirmation required. No auto-approve path.</p>
    </li>`;
}

function renderJoinRevoke(pending: PendingJoinView[]): string {
  const rows = pending.map(renderPendingJoin).join("");
  return `
    <section id="join-revoke" class="surface">
      <h2>Join and revoke</h2>
      <h3>Pending join requests</h3>
      <ul class="join-pending-list">${rows || '<li class="empty-state">No pending join requests.</li>'}</ul>
      <h3>Revoke a node</h3>
      <form id="revoke-form" class="revoke-form">
        <label>Node ID to revoke <input name="node_id" required /></label>
        <label>Reason <input name="reason" required placeholder="e.g. compromised key" /></label>
        <label>Effective at (ISO8601) <input name="effective_at" required type="text" placeholder="YYYY-MM-DDTHH:MM:SSZ" /></label>
        <label>Guardian quorum signatures (JSON array)
          <textarea name="quorum_signatures" required rows="3" placeholder='[{"guardian_pubkey":"...","signature":"..."}]'></textarea>
        </label>
        <button type="submit">Emit signed node_revoke</button>
        <p class="tier-note">Revocation is irreversible. Guardian quorum signatures required.</p>
      </form>
    </section>`;
}

function renderMeshHealth(view: AlertInboxView): string {
  const alertRows = view.rows
    .map(
      (r) => `
        <li class="alert-row alert-row-${htmlEscape(r.state)}" data-alert-id="${htmlEscape(r.alert_id)}">
          <div>
            <strong>${htmlEscape(r.mode)}</strong> on <code>${htmlEscape(r.target_node.slice(0, 12))}...</code>
            <span class="alert-state">${htmlEscape(r.state)}</span>
          </div>
          <p>${htmlEscape(r.message)}</p>
          <div class="alert-decisions">
            ${r.decision_options
              .map(
                (o) =>
                  `<button class="alert-decision" data-alert-id="${htmlEscape(r.alert_id)}" data-decision="${htmlEscape(o.id)}">${htmlEscape(o.label)}</button>`
              )
              .join("")}
          </div>
        </li>`
    )
    .join("");
  return `
    <section id="mesh-health" class="surface">
      <h2>Mesh Health</h2>
      <p>Live failure-mode alerts stream in via Server-Sent Events. Operator decisions are recorded; resolution emits an ack to the mesh.</p>
      <ul class="alert-inbox">${alertRows || '<li class="empty-state">No open alerts.</li>'}</ul>
    </section>`;
}

function renderRecovery(view: RecoveryEntryView): string {
  return `
    <section id="recovery" class="surface">
      <h2>Recovery</h2>
      <div class="recovery-stub" data-eta="${htmlEscape(view.eta)}">
        <p><strong>Status:</strong> ${htmlEscape(view.status)}</p>
        <p>${htmlEscape(view.message)}</p>
      </div>
    </section>`;
}

const STYLES = `
  body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; margin: 0; background: #f6f7f9; color: #1a1a1a; }
  header.console-header { background: #0b1021; color: #fff; padding: 16px 24px; display: flex; align-items: center; justify-content: space-between; }
  header.console-header h1 { font-size: 18px; margin: 0; font-weight: 600; }
  header.console-header .version { font-size: 12px; opacity: 0.7; }
  .console-nav { background: #101632; color: #dfe6f3; padding: 8px 24px; display: flex; gap: 12px; flex-wrap: wrap; }
  .console-nav .nav-item { color: #dfe6f3; text-decoration: none; padding: 6px 10px; border-radius: 4px; font-size: 13px; }
  .console-nav .nav-item.active { background: #27346f; font-weight: 600; }
  .console-nav .nav-item.reserved-v1x { color: #7b87a7; cursor: not-allowed; font-style: italic; }
  main { padding: 24px; display: flex; flex-direction: column; gap: 32px; max-width: 1200px; margin: 0 auto; }
  .surface { background: #fff; border-radius: 8px; padding: 20px 24px; box-shadow: 0 1px 2px rgba(0,0,0,0.06); }
  .surface h2 { margin: 0 0 12px; font-size: 20px; }
  .fortress-meta { display: grid; grid-template-columns: repeat(auto-fit, minmax(260px, 1fr)); gap: 8px 24px; margin-bottom: 16px; }
  table { width: 100%; border-collapse: collapse; font-size: 13px; }
  th, td { text-align: left; padding: 8px 10px; border-bottom: 1px solid #ececec; }
  th { background: #f0f2f5; font-weight: 600; }
  code { font-family: "SF Mono", Menlo, monospace; font-size: 12px; background: #f0f2f5; padding: 2px 4px; border-radius: 3px; }
  .alert-banner { background: #fff3cd; border-left: 4px solid #f39c12; padding: 10px 14px; margin-bottom: 12px; border-radius: 4px; }
  .alert-banner.warn { background: #fff0e0; border-left-color: #e67e22; }
  .empty-state { font-style: italic; color: #555; }

  /* AttestationBadge three-layer classes */
  .att-badge { display: inline-block; padding: 2px 8px; border-radius: 12px; font-size: 11px; font-weight: 600; border: 1px solid transparent; }
  .att-badge.att-global-verified,
  .att-badge.att-per-agent-verified,
  .att-badge.att-per-action-verified { background: #e6f7e6; color: #176c2f; border-color: #95d9a5; }
  .att-badge.att-global-pending,
  .att-badge.att-per-agent-pending,
  .att-badge.att-per-action-pending { background: #eef3ff; color: #234892; border-color: #a7bef0; }
  .att-badge.att-global-degraded,
  .att-badge.att-per-agent-degraded,
  .att-badge.att-per-action-degraded { background: #fff6e3; color: #8a5a00; border-color: #e9c672; }
  .att-badge.att-global-failed,
  .att-badge.att-per-agent-failed,
  .att-badge.att-per-action-failed { background: #fde7e7; color: #962222; border-color: #ea8f8f; }
  .att-badge.att-global-unknown,
  .att-badge.att-per-agent-unknown,
  .att-badge.att-per-action-unknown { background: #eef0f5; color: #505b74; border-color: #c2c9d8; }
  .att-badge.att-custody-provenance-stub.att-v1x-reserved { background: #f4f0ff; color: #5a3fa0; border-color: #c8b6f5; font-style: italic; }

  /* Policy editor form */
  .policy-form, .revoke-form { display: grid; gap: 10px; max-width: 560px; }
  .policy-form label, .revoke-form label { display: flex; flex-direction: column; gap: 4px; font-size: 13px; }
  .policy-form input, .revoke-form input, .revoke-form textarea, .policy-form select { padding: 8px; border: 1px solid #cdd2db; border-radius: 4px; font-size: 14px; }
  .policy-form button, .revoke-form button, .alert-decision, .join-actions button { background: #27346f; color: #fff; border: none; padding: 8px 14px; border-radius: 4px; font-size: 13px; cursor: pointer; }
  .policy-form button:hover, .revoke-form button:hover, .alert-decision:hover, .join-actions button:hover { background: #1c2759; }
  .join-deny { background: #8a2a2a !important; }
  .join-deny:hover { background: #6d1f1f !important; }
  .tier-note { font-size: 12px; color: #7a4f00; background: #fdf6e3; padding: 6px 10px; border-radius: 4px; margin-top: 6px; }

  /* Alert inbox */
  .alert-inbox { list-style: none; padding: 0; margin: 0; display: flex; flex-direction: column; gap: 10px; }
  .alert-row { background: #fff7e6; border-left: 4px solid #e67e22; padding: 10px 14px; border-radius: 4px; }
  .alert-row-resolved { background: #f0f2f5; border-left-color: #7a8396; opacity: 0.75; }
  .alert-state { font-size: 11px; padding: 2px 6px; background: #fff; border-radius: 10px; margin-left: 6px; }

  /* Pending joins */
  .join-pending-list { list-style: none; padding: 0; display: flex; flex-direction: column; gap: 10px; }
  .join-pending-row { background: #eef3ff; padding: 10px 14px; border-radius: 4px; border-left: 4px solid #3f5aa8; }
  .join-actions { display: flex; gap: 8px; margin-top: 8px; }

  /* Node mode badges */
  .node-mode-local { color: #176c2f; font-weight: 600; }
  .node-mode-operator_cloud { color: #234892; font-weight: 600; }
  .node-mode-sovereign_tee { color: #5a3fa0; font-weight: 600; }

  /* Recovery stub */
  .recovery-stub { background: #fdf6e3; padding: 14px; border-radius: 4px; border-left: 4px solid #c7a200; }
`;

const CLIENT_JS = `
  const SSE_URL = "/api/console/stream";
  const POLICY_URL = "/api/console/policy/compose";
  const JOIN_URL = "/api/console/join/decide";
  const ALERT_URL = "/api/console/alerts/ack";
  const REVOKE_URL = "/api/console/nodes/revoke";

  function qs(sel, root) { return (root || document).querySelector(sel); }
  function qsa(sel, root) { return Array.from((root || document).querySelectorAll(sel)); }

  function refreshSurface(surface, data) {
    // Server-side re-render by reloading; an SSE poke is sufficient to know
    // fresh state is available. Full-page reload keeps the render tree as the
    // single source of truth.
    if (document.body.dataset.autoRefresh === "true") {
      window.location.reload();
    }
  }

  // Hash-routing: highlight the active nav item
  function updateNavActive() {
    const hash = (window.location.hash || "#fortress").slice(1);
    qsa(".nav-item").forEach(el => {
      if (el.dataset.surface === hash) el.classList.add("active");
      else el.classList.remove("active");
    });
    qsa(".surface").forEach(s => {
      s.style.display = s.id === hash ? "" : "none";
    });
  }
  window.addEventListener("hashchange", updateNavActive);
  document.addEventListener("DOMContentLoaded", updateNavActive);

  // SSE: live updates
  try {
    const es = new EventSource(SSE_URL);
    es.addEventListener("message", e => {
      try {
        const evt = JSON.parse(e.data);
        if (evt.kind === "join-pending" || evt.kind === "join-resolved" || evt.kind === "alert" || evt.kind === "policy-pinned" || evt.kind === "fortress" || evt.kind === "agents" || evt.kind === "health") {
          refreshSurface(evt.kind, evt.payload);
        }
      } catch (_) {}
    });
    es.addEventListener("error", () => { /* browser auto-retries */ });
  } catch (_) { /* older runtime */ }

  // Policy compose
  const policyForm = qs("#policy-compose");
  if (policyForm) {
    policyForm.addEventListener("submit", async (e) => {
      e.preventDefault();
      const fd = new FormData(policyForm);
      const scope_json = fd.get("scope_json");
      let scope = undefined;
      if (scope_json) {
        try { scope = JSON.parse(scope_json); } catch (_) {
          alert("Scope must be valid JSON (or left blank).");
          return;
        }
      }
      const body = {
        agent_id: fd.get("agent_id"),
        counterparty: fd.get("counterparty"),
        channel_template_id: fd.get("channel_template_id"),
        scope: scope,
      };
      const resp = await fetch(POLICY_URL, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body),
        credentials: "include",
      });
      const data = await resp.json();
      if (!resp.ok) {
        alert("Policy pin failed: " + (data.error || "unknown"));
        return;
      }
      alert("Policy v" + data.policy_version + " pinned for " + body.agent_id + ".\\n" + data.source_english);
      window.location.reload();
    });
  }

  // Join decisions
  qsa(".join-approve").forEach(btn => {
    btn.addEventListener("click", async () => {
      const id = btn.dataset.requestId;
      await fetch(JOIN_URL, {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ request_id: id, approved: true }),
        credentials: "include",
      });
      window.location.reload();
    });
  });
  qsa(".join-deny").forEach(btn => {
    btn.addEventListener("click", async () => {
      const id = btn.dataset.requestId;
      const reason = prompt("Denial reason (operator-facing):", "denied") || "denied";
      await fetch(JOIN_URL, {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ request_id: id, approved: false, denial_reason: reason }),
        credentials: "include",
      });
      window.location.reload();
    });
  });

  // Alert decisions
  qsa(".alert-decision").forEach(btn => {
    btn.addEventListener("click", async () => {
      const id = btn.dataset.alertId;
      const dec = btn.dataset.decision;
      const note = prompt("Optional operator note (audit log):", "") || undefined;
      await fetch(ALERT_URL, {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ alert_id: id, decision: dec, note: note }),
        credentials: "include",
      });
      window.location.reload();
    });
  });

  // Revoke form
  const revokeForm = qs("#revoke-form");
  if (revokeForm) {
    revokeForm.addEventListener("submit", async (e) => {
      e.preventDefault();
      const fd = new FormData(revokeForm);
      let sigs;
      try { sigs = JSON.parse(String(fd.get("quorum_signatures"))); }
      catch (_) { alert("Quorum signatures must be a JSON array."); return; }
      const body = {
        node_id: fd.get("node_id"),
        reason: fd.get("reason"),
        effective_at: fd.get("effective_at"),
        quorum_signatures: sigs,
      };
      const resp = await fetch(REVOKE_URL, {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body),
        credentials: "include",
      });
      const data = await resp.json();
      if (!resp.ok) { alert("Revoke failed: " + (data.error || "unknown")); return; }
      alert("Revoke signed, event_id " + data.signed_event_id);
      window.location.reload();
    });
  }
`;

export function renderConsoleHTML(client: MeshConsoleClient): string {
  const fortress = client.fortressOverview();
  const agents = client.agentsPanel();
  const pending = client.pendingJoinsSnapshot();
  const alerts = client.alertInbox();
  const recovery = client.recoveryEntry();
  const activeSurface = "fortress";

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>Sanctuary Operator Console ${htmlEscape(CONSOLE_VERSION)}</title>
  <style>${STYLES}</style>
</head>
<body data-auto-refresh="true">
  <header class="console-header">
    <h1>Sanctuary Operator Console</h1>
    <span class="version">v${htmlEscape(CONSOLE_VERSION)} • Fortress <code>${htmlEscape(fortress.fortress_id.slice(0, 8))}</code></span>
  </header>
  ${renderNavigation(activeSurface)}
  <main>
    ${renderFortressOverview(fortress)}
    ${renderAgentsPanel(agents)}
    ${renderPolicyEditor(client)}
    ${renderJoinRevoke(pending)}
    ${renderMeshHealth(alerts)}
    ${renderRecovery(recovery)}
  </main>
  <script>${CLIENT_JS}</script>
</body>
</html>`;
}

/** The current rendered HTML length — used by tests to assert non-triviality. */
export function renderConsoleHTMLBytes(client: MeshConsoleClient): number {
  return Buffer.byteLength(renderConsoleHTML(client), "utf-8");
}
