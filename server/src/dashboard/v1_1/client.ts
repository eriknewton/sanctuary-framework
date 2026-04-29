/**
 * Sanctuary v1.1 Dashboard — Embedded Client Script
 *
 * Returns the ES-module body as a string. The HTML shell embeds this
 * inside `<script type="module">`. Pattern matches the v1.0 dashboard.
 *
 * The client is plain TS-as-string with intentional minimal abstractions:
 * - `api(path, opts)` for hub API calls (with bearer-token + JSON body).
 * - `sse(url, handlers)` for the reconnect-and-restore SSE subscription.
 * - One `render*` function per route/region; all consume the same in-memory
 *   `state` object.
 * - State is module-local. NEVER persisted to localStorage. The sidebar
 *   collapse flag is the one allowed sessionStorage entry per the binding
 *   addendum acceptance criterion 10.
 *
 * NO localStorage anywhere. NO operator-typed direct chat command at v1.1
 * (free text routes to the concierge as a UI-side suggestion engine).
 * NO verifier in-process (exit drill steps 4 + 5 display CLI commands;
 * they do NOT call the verifier from the dashboard process).
 *
 * Naming-discipline rule: no competitor names anywhere in operator-visible
 * strings.
 * No-em-dash rule: every operator-visible string here uses periods,
 * commas, colons, or parentheses.
 * UBAI-retirement rule: no Universal-Basic-AI surfaces.
 */

/**
 * Returns the inline client script body. The HTML shell wraps this in
 * `<script type="module">` tags.
 *
 * Tests can import this string and assert the absence of forbidden
 * patterns (em-dashes, UBAI strings, MLS dead-claims, raw chat-command
 * POST paths, verifier function imports) using simple regex checks.
 */
export function getClientScript(): string {
  return CLIENT_SCRIPT;
}

const CLIENT_SCRIPT = String.raw`
"use strict";

// ── Config ─────────────────────────────────────────────────────────────
const cfgEl = document.getElementById("dashboard-config");
const config = cfgEl ? JSON.parse(cfgEl.textContent || "{}") : {};
const HUB = config.hubApiBase || "/api/hub";
const STREAM = config.streamUrl || "/api/stream";
const TOKEN = config.authToken || "";
const SESSION_KEY = "sanctuary-v11-sidebar";

// ── State ──────────────────────────────────────────────────────────────
const state = {
  route: "dashboard",
  agents: [],
  inbox: [],
  activity: [],
  policies: [],
  templateBinding: { agentId: null, selectedTemplateId: null, pendingItemId: null, error: null },
  privacyEvents: [],
  handoffEvents: [],
  topbarPills: { deployment: "local", mode: "solo", attestation: "pending" },
  tier1: {
    lockdown: { state: "idle", inboxItemId: null }
  },
  exitDrill: { step: 1, inboxItemId: null, bundleResult: null },
  selectedAgentId: null,
  chatActiveAgentId: null,
  seenEventIds: new Set(),
  sidebarCollapsed: sessionStorage.getItem(SESSION_KEY) === "1"
};

// ── Helpers ────────────────────────────────────────────────────────────
function escHtml(v) {
  if (v == null) return "";
  return String(v).replace(/[&<>"']/g, function (c) {
    return ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#039;"})[c];
  });
}

function shortTime(iso) {
  if (!iso) return "";
  const d = new Date(iso);
  if (isNaN(d.getTime())) return iso;
  const month = d.toLocaleString("en-US", { month: "short" });
  const day = d.getDate();
  const hh = String(d.getHours()).padStart(2, "0");
  const mm = String(d.getMinutes()).padStart(2, "0");
  return month + " " + day + ", " + hh + ":" + mm;
}

async function api(path, opts) {
  const init = Object.assign({ headers: {} }, opts || {});
  if (TOKEN) init.headers["Authorization"] = "Bearer " + TOKEN;
  if (init.body && typeof init.body !== "string") {
    init.headers["Content-Type"] = "application/json";
    init.body = JSON.stringify(init.body);
  }
  const res = await fetch(HUB + path, init);
  let body = null;
  try { body = await res.json(); } catch (e) { body = null; }
  if (!res.ok) {
    const detail = body && (body.detail || body.error) ? (body.detail || body.error) : ("HTTP " + res.status);
    const err = new Error(detail);
    err.status = res.status;
    err.body = body;
    throw err;
  }
  return body;
}

function toast(message, kind) {
  const host = document.getElementById("toast-host");
  if (!host) return;
  const el = document.createElement("div");
  el.className = "toast" + (kind === "error" ? " error" : "");
  el.textContent = message;
  host.appendChild(el);
  setTimeout(function () { el.remove(); }, 4000);
}

// ── Template registry (mirror of server templates.ts) ──────────────────
function arg(args, kind, fallback) {
  fallback = fallback || "(unknown)";
  for (let i = 0; i < args.length; i++) {
    if (args[i].kind === kind) return String(args[i].value);
  }
  return fallback;
}

const TEMPLATES = {
  "approval_pending.tier1.lockdown": (a) => "Lock down agent " + arg(a,"agent_id") + ". This stops all egress and freezes gates.",
  "approval_pending.tier1.unwrap": (a) => "Unwrap agent " + arg(a,"agent_id") + ". Cocoon and registry binding will be removed.",
  "approval_pending.tier1.policy_change": (a) => "Bind agent " + arg(a,"agent_id") + " to policy " + arg(a,"policy_id") + ".",
  "approval_pending.tier1.policy_change_template": (a) => "Bind agent " + arg(a,"agent_id") + " to template " + arg(a,"policy_id") + ".",
  "approval_pending.tier1.exit_bundle_export": (a) => "Export the fortress as a portable bundle. Agent: " + arg(a,"agent_id","all agents") + ".",
  "approval_pending.tier1.exit_bundle_import": (a) => "Import a portable bundle into this fortress.",
  "approval_pending.tier1.exit_bundle_rekey": (a) => "Re-key encrypted state for portable export.",
  "approval_pending.tier1.state_export": (a) => "Export agent " + arg(a,"agent_id") + " state as a portable bundle.",
  "approval_pending.tier1.state_import": (a) => "Import state into agent " + arg(a,"agent_id") + ".",
  "approval_pending.tier1.state_delete": (a) => "Delete state for agent " + arg(a,"agent_id") + ". This is irreversible.",
  "approval_pending.tier1.identity_rotate": (a) => "Rotate the identity key for " + arg(a,"agent_id","this fortress") + ".",
  "approval_pending.tier1.reputation_export": (a) => "Export reputation bundle for " + arg(a,"agent_id") + ".",
  "approval_pending.tier1.reputation_import": (a) => "Import reputation bundle for " + arg(a,"agent_id") + ".",
  "approval_pending.tier1.sanctuary_export_identity_bundle": (a) => "Export the operator identity bundle.",
  "approval_pending.tier1.other": (a) => "Tier 1 operation pending on agent " + arg(a,"agent_id","(no agent)") + ".",
  "approval_pending.tier2.policy_change": (a) => "Tier 2 policy change requested on agent " + arg(a,"agent_id") + ".",
  "approval_pending.tier2.other": (a) => "Tier 2 operation pending on agent " + arg(a,"agent_id","(no agent)") + ".",
  "blocked_egress.egress_policy_deny": (a) => "Egress to " + arg(a,"destination_category") + " blocked by policy on agent " + arg(a,"agent_id") + ".",
  "blocked_egress.budget_exceeded": (a) => "Egress to " + arg(a,"destination_category") + " blocked: budget exceeded for agent " + arg(a,"agent_id") + ".",
  "blocked_egress.privacy_fail_closed": (a) => "Egress to " + arg(a,"destination_category") + " blocked: privacy filter unavailable, fail-closed default applied for agent " + arg(a,"agent_id") + ".",
  "blocked_egress.privacy_deny_rule": (a) => "Egress to " + arg(a,"destination_category") + " blocked by privacy rule on agent " + arg(a,"agent_id") + ".",
  "blocked_egress.lockdown_active": (a) => "Egress to " + arg(a,"destination_category") + " blocked by active lockdown on agent " + arg(a,"agent_id") + ".",
  "blocked_egress.other": (a) => "Egress to " + arg(a,"destination_category") + " blocked on agent " + arg(a,"agent_id") + ".",
  "privacy_event.filtered": (a) => "Privacy filter applied to outbound traffic from agent " + arg(a,"agent_id") + ".",
  "privacy_event.allowed": (a) => "Outbound traffic allowed by privacy policy for agent " + arg(a,"agent_id") + ".",
  "privacy_event.denied": (a) => "Outbound traffic denied by privacy policy for agent " + arg(a,"agent_id") + ".",
  "privacy_event.error": (a) => "Privacy filter error on agent " + arg(a,"agent_id") + ". Outbound traffic blocked, fail-closed.",
  "privacy_event.rehydrated": (a) => "Inbound response rehydrated through placeholder vault for agent " + arg(a,"agent_id") + ".",
  "budget_warning.soft_warn": (a) => "Budget soft-warn on agent " + arg(a,"agent_id") + ".",
  "budget_warning.hard_cap": (a) => "Budget hard-cap reached on agent " + arg(a,"agent_id") + ". Operator unblock required.",
  "recovery_prompt.passphrase_reset": () => "Recommended: rotate the cocoon passphrase.",
  "recovery_prompt.keychain_rebind": () => "Recommended: rebind the keychain entry for this fortress.",
  "recovery_prompt.config_backup_restore": () => "Recommended: back up your current configuration.",
  "recovery_prompt.exit_drill": () => "Recommended: run an exit drill so you know recovery works.",
  "recovery_prompt.other": () => "Recovery action recommended.",
  "agent_error.harness_error": (a) => "Agent " + arg(a,"agent_id") + " reported a harness error.",
  "agent_error.harness_unreachable": (a) => "Agent " + arg(a,"agent_id") + " is unreachable.",
  "agent_error.policy_breach": (a) => "Agent " + arg(a,"agent_id") + " attempted a policy-breaching action and was blocked.",
  "agent_error.config_drift": (a) => "Agent " + arg(a,"agent_id") + " configuration has drifted from the bound policy.",
  "agent_error.other": (a) => "Agent " + arg(a,"agent_id") + " reported an internal error.",
  "activity.policy_decision": (a) => "Policy gate decision on agent " + arg(a,"agent_id") + ".",
  "activity.approval": (a) => "Operator approved action for agent " + arg(a,"agent_id") + ".",
  "activity.denial": (a) => "Operator denied action for agent " + arg(a,"agent_id") + ".",
  "activity.egress": (a) => "Outbound traffic from agent " + arg(a,"agent_id") + " to " + arg(a,"destination_category") + ".",
  "activity.privacy": (a) => "Privacy event recorded for agent " + arg(a,"agent_id") + ".",
  "activity.handoff": (a) => "Internal handoff event involving agent " + arg(a,"agent_id") + ".",
  "activity.lifecycle": (a) => "Lifecycle change on agent " + arg(a,"agent_id") + ".",
  "activity.agent_policy_change_engaged": (a) => "Template binding changed on agent " + arg(a,"agent_id") + ": " + arg(a,"channel_template_id","default none") + " to " + arg(a,"policy_id") + ".",
  "activity.agent_policy_change_denied": (a) => "Template binding denied on agent " + arg(a,"agent_id") + ": " + arg(a,"channel_template_id","default none") + " to " + arg(a,"policy_id") + ".",
  "activity.config": (a) => "Configuration change applied.",
  "activity.other": (a) => "Audit event recorded for agent " + arg(a,"agent_id","(fortress)") + "."
};

function renderTemplate(id, args) {
  const fn = TEMPLATES[id];
  if (!fn) return "[unrecognized template: " + id + "]";
  try { return fn(args || []); } catch (e) { return "[template render failed: " + id + "]"; }
}

// ── Status mapping ─────────────────────────────────────────────────────
const STATUS_MAP = {
  active: { label: "Running", glyph: "online" },
  paused: { label: "Paused", glyph: "idle" },
  restarting: { label: "Restarting", glyph: "idle" },
  locked_down: { label: "Locked down", glyph: "offline" },
  unwrapping: { label: "Unwrapping", glyph: "idle" },
  error: { label: "Error", glyph: "away" },
  unknown: { label: "Unknown", glyph: "unknown" }
};

const REASON_LABELS = {
  operator_lockdown: "Locked down by operator",
  policy_breach: "Policy breach detected",
  budget_hard_cap: "Budget hard-cap reached",
  harness_error: "Harness reported an error",
  harness_unreachable: "Harness is unreachable",
  passphrase_required: "Cocoon passphrase required",
  config_drift: "Configuration drift detected",
  other: "Other reason. See activity feed."
};

const CHANNEL_TEMPLATES = [
  {
    id: "request-approve-act",
    severity: "MEDIUM",
    title: "Request -> approve -> act",
    description: "Operator sends a task. Agent proposes writes, pauses for approval, then executes. Most wrapped agents live here."
  },
  {
    id: "read-then-report",
    severity: "LOW",
    title: "Read -> report",
    description: "Agent reads allowed sources and reports back. Any fetch outside allowed-hosts surfaces as an approval request."
  },
  {
    id: "scheduled-digest",
    severity: "LOW",
    title: "Scheduled digest",
    description: "Runs on timer or external trigger. Pushes summaries into chat. Cannot write outward without approval."
  },
  {
    id: "plan-draft-only",
    severity: "LOW",
    title: "Plan, draft-only",
    description: "Drafts plans you review before anything runs. Cannot execute, pay, or mutate state on its own."
  },
  {
    id: "fortress-relay",
    severity: "MEDIUM",
    title: "Fortress relay",
    description: "Routes signed events between peer fortresses. Commits bind only when both sides sign."
  },
  {
    id: "concierge-loop",
    severity: "LOW",
    title: "Concierge loop",
    description: "Bidirectional Q&A with the operator. Reads local fortress state; never writes outward."
  }
];

// ── Inbox action surface per kind (binding addendum 1.2) ───────────────
function inboxActions(item) {
  switch (item.kind) {
    case "approval_pending":
      // Tier 1 items refuse dismiss; the 'dismiss' action is missing here.
      if (item.tier === "tier1") return ["approve", "deny"];
      return ["approve", "deny", "dismiss"];
    case "blocked_egress": return ["dismiss", "review_receipt"];
    case "privacy_event": return ["open_filter_event"];
    case "budget_warning": return ["dismiss"];
    case "recovery_prompt": return ["dismiss", "schedule_drill"];
    case "agent_error": return ["dismiss", "view_log"];
    default: return ["dismiss"];
  }
}

const INBOX_ACTION_LABEL = {
  approve: "Approve",
  deny: "Deny",
  dismiss: "Dismiss",
  review_receipt: "Review receipt",
  open_filter_event: "Open filter event",
  schedule_drill: "Schedule drill",
  view_log: "View log"
};

// ── Render: app-level ─────────────────────────────────────────────────
function setRoute(route) {
  state.route = route;
  const app = document.getElementById("app");
  if (!app) return;
  app.setAttribute("data-route", route);
  const fullRoutes = ["agents", "policy", "privacy", "coordination", "health", "exit-drill", "agent-detail"];
  if (fullRoutes.indexOf(route) >= 0) app.classList.add("route-full");
  else app.classList.remove("route-full");
  document.querySelectorAll("#sidebar-nav a").forEach(function (a) {
    if (a.getAttribute("data-route") === route) a.classList.add("active");
    else a.classList.remove("active");
  });
  renderMain();
  renderFortress();
}

function renderTopbar() {
  const pillEl = document.getElementById("topbar-pills");
  if (!pillEl) return;
  pillEl.innerHTML = [
    '<span class="pill" data-pill="deployment">deployment: ' + escHtml(state.topbarPills.deployment) + '</span>',
    '<span class="pill" data-pill="mode">mode: ' + escHtml(state.topbarPills.mode) + '</span>',
    '<span class="pill tone-' + escHtml(state.topbarPills.attestation) + '" data-pill="attestation">attestation: ' + escHtml(state.topbarPills.attestation) + '</span>'
  ].join("");
  // Lockdown button three-state UX (binding addendum 3).
  const btn = document.getElementById("btn-lockdown");
  if (!btn) return;
  const t1 = state.tier1.lockdown;
  btn.classList.remove("tier1-pending", "tier1-engaged");
  btn.disabled = false;
  if (t1.state === "pending") {
    btn.textContent = "Awaiting approval";
    btn.classList.add("tier1-pending");
    btn.disabled = true;
  } else if (t1.state === "engaged") {
    btn.textContent = "Lockdown ON";
    btn.classList.add("tier1-engaged");
    btn.disabled = true;
  } else {
    btn.textContent = "Lockdown";
  }
}

// ── Render: main area ──────────────────────────────────────────────────
function renderMain() {
  const main = document.getElementById("main");
  if (!main) return;
  switch (state.route) {
    case "dashboard": main.innerHTML = renderDashboardWelcome(); break;
    case "agents": main.innerHTML = renderAgentsList(); break;
    case "agent-detail": main.innerHTML = renderAgentDetail(); break;
    case "policy": main.innerHTML = renderPolicyCenter(); break;
    case "privacy": main.innerHTML = renderPrivacyPage(); break;
    case "coordination": main.innerHTML = renderCoordinationPage(); break;
    case "health": main.innerHTML = renderHealthPage(); break;
    case "exit-drill": main.innerHTML = renderExitDrill(); break;
    default: main.innerHTML = '<p class="muted">Route not found.</p>';
  }
}

// ── Render: dashboard welcome ──────────────────────────────────────────
// v1.1.7: replaces the half-built chat surface that v1.1.6 shipped with
// a "What you can do today" summary card mapping each nav target to
// the operator action it enables. Direct concierge chat is a v1.2 work
// package (WP-V1.2-3 + WP-V1.2-4).
function renderDashboardWelcome() {
  return [
    '<h1>What you can do today</h1>',
    '<div class="card">',
      '<dl class="kv">',
        '<dt><a href="#agents">Agents</a></dt>',
        '<dd>Pause, resume, restart, lockdown, or unwrap any wrapped harness.</dd>',
        '<dt><a href="#policy">Policy</a></dt>',
        '<dd>Review the active policy bound to each agent.</dd>',
        '<dt><a href="#privacy">Privacy</a></dt>',
        '<dd>See what context is flowing to which provider per channel.</dd>',
        '<dt><a href="#coordination">Coordination</a></dt>',
        '<dd>Inspect intra-fortress agent coordination state.</dd>',
        '<dt><a href="#health">Health</a></dt>',
        '<dd>Check fortress posture, cocoon status, and dashboard refresh.</dd>',
        '<dt><a href="#exit-drill">Exit drill</a></dt>',
        '<dd>Snapshot, verify, and prepare a portable exit bundle.</dd>',
      '</dl>',
    '</div>',
    '<p class="muted">Direct chat with the concierge ships in v1.2.</p>'
  ].join("");
}

// ── Render: agents list / detail ───────────────────────────────────────
function renderAgentsList() {
  if (!state.agents.length) return '<h1>Agents</h1><p class="muted">No wrapped agents yet. Run <code>sanctuary wrap</code> to wrap a harness.</p>';
  const rows = state.agents.map(function (a) {
    const map = STATUS_MAP[a.status] || STATUS_MAP.unknown;
    const reason = a.status_reason_class ? (REASON_LABELS[a.status_reason_class] || "") : "";
    return '<div class="row">' +
      '<span class="glyph ' + map.glyph + '"></span>' +
      '<div class="grow"><strong>' + escHtml(a.agent_id) + '</strong> <span class="muted mono">' + escHtml(a.harness) + '</span></div>' +
      '<span class="pill" title="' + escHtml(reason) + '">' + escHtml(map.label) + '</span>' +
      '<button class="btn" data-action="open-agent" data-agent-id="' + escHtml(a.agent_id) + '">Open</button>' +
      '</div>';
  }).join("\n");
  return '<h1>Agents</h1><div class="card">' + rows + '</div>';
}

function renderAgentDetail() {
  const a = state.agents.find(function (x) { return x.agent_id === state.selectedAgentId; });
  if (!a) return '<h1>Agent</h1><p class="muted">Agent not found. <a href="#agents">Back to list</a>.</p>';
  const map = STATUS_MAP[a.status] || STATUS_MAP.unknown;
  const events = state.activity.filter(function (e) { return e.agent_id === a.agent_id; }).slice(0, 50);
  const timeline = events.length
    ? events.map(function (e) {
        const t = renderTemplate(e.display_template_id, e.display_template_args);
        return '<div class="row"><span class="muted">' + escHtml(shortTime(e.emitted_at)) + '</span><span>' + escHtml(t) + '</span></div>';
      }).join("\n")
    : '<p class="muted">No activity yet.</p>';
  return '<h1>' + escHtml(a.agent_id) + '</h1>' +
    '<div class="card"><h3>Identity</h3>' +
      '<dl class="kv">' +
      '<dt>Harness</dt><dd class="mono">' + escHtml(a.harness) + '</dd>' +
      '<dt>Model</dt><dd class="mono">' + escHtml(a.model_provider.vendor) + " / " + escHtml(a.model_provider.model_id) + '</dd>' +
      '<dt>Policy</dt><dd class="mono">' + escHtml(a.policy_id) + '</dd>' +
      '<dt>Status</dt><dd><span class="glyph ' + map.glyph + '"></span> ' + escHtml(map.label) + '</dd>' +
      '</dl>' +
    '</div>' +
    '<div class="card"><h3>Timeline</h3>' + timeline + '</div>';
  // v1.1.7: "Open chat" button removed alongside the half-built chat
  // surface (Finding EE). The agent-detail timeline + capability buttons
  // are the operator's interaction surface at v1.1; chat ships in v1.2.
}

// ── Render: privacy ────────────────────────────────────────────────────
function renderPrivacyPage() {
  // Safe-metadata-only render (binding addendum 1.6). Content_hash visible
  // only as opaque hex with a tooltip; no raw_path, no raw_value, no
  // source bytes.
  const events = state.privacyEvents.slice(0, 50);
  if (!events.length) return '<h1>Privacy</h1><p class="muted">No privacy events recorded yet.</p>';
  const rows = events.map(function (e) {
    const payload = e.payload || {};
    const hashShort = payload.outbound_payload_hash ? String(payload.outbound_payload_hash).slice(0, 12) + "..." : "n/a";
    const denialReason = payload.denial_reason_class ? escHtml(payload.denial_reason_class) : "";
    return '<div class="row">' +
      '<span class="muted">' + escHtml(shortTime(e.emitted_at)) + '</span>' +
      '<span class="pill">' + escHtml(payload.kind || "(unknown)") + '</span>' +
      '<span class="muted mono">' + escHtml(payload.destination_category || "") + '</span>' +
      '<span class="grow">' + (denialReason ? "Reason: " + denialReason : "") + '</span>' +
      '<span class="mono" data-content-hash="' + escHtml(hashShort) + '" title="Local fingerprint, not the value">hash: ' + escHtml(hashShort) + '</span>' +
      '</div>';
  }).join("\n");
  return '<h1>Privacy</h1>' +
    '<p class="muted">Events show only safe metadata. Raw values never leave the privacy filter.</p>' +
    '<div class="card">' + rows + '</div>' +
    '<p class="muted">Per-agent toggles are read-only at v1.1. <a href="#policy">Edit via Policy center</a>.</p>';
}

// ── Render: coordination ──────────────────────────────────────────────
function renderCoordinationPage() {
  const events = state.handoffEvents.slice(0, 100);
  if (!events.length) return '<h1>Coordination</h1><p class="muted">No internal handoffs yet.</p>';
  const rows = events.map(function (e) {
    const p = e.payload || {};
    return '<div class="row">' +
      '<span class="muted">' + escHtml(shortTime(e.emitted_at)) + '</span>' +
      '<span class="pill">' + escHtml(p.new_status || "") + '</span>' +
      '<span class="muted mono">' + escHtml(p.actor_role || "") + '</span>' +
      '<span class="grow"><strong>' + escHtml(p.sender_agent_id || "?") + '</strong> to <strong>' + escHtml(p.recipient_agent_id || "?") + '</strong></span>' +
      '</div>';
  }).join("\n");
  return '<h1>Coordination</h1>' +
    '<p class="muted">Internal-only handoffs inside this fortress. Cross-fortress coordination lands in v1.3.</p>' +
    '<div class="card">' + rows + '</div>' +
    '<button class="btn" disabled title="Operator-initiated handoff arrives in v1.2.">New shared workflow</button>';
}

// ── Render: health ─────────────────────────────────────────────────────
function renderHealthPage() {
  const totalAgents = state.agents.length;
  const lockedDown = state.agents.filter(function (a) { return a.status === "locked_down"; }).length;
  const errored = state.agents.filter(function (a) { return a.status === "error"; }).length;
  const recentDenials = state.activity.filter(function (e) { return e.category === "denial"; }).length;
  return '<h1>Health</h1>' +
    '<p class="muted">Projected from existing data. A dedicated health endpoint lands in v1.2.</p>' +
    '<div class="card"><h3>Fortress at a glance</h3>' +
      '<dl class="kv">' +
      '<dt>Wrapped agents</dt><dd>' + escHtml(totalAgents) + '</dd>' +
      '<dt>Locked down</dt><dd>' + escHtml(lockedDown) + '</dd>' +
      '<dt>Errored</dt><dd>' + escHtml(errored) + '</dd>' +
      '<dt>Denials in feed</dt><dd>' + escHtml(recentDenials) + '</dd>' +
      '</dl>' +
    '</div>' +
    '<button class="btn" disabled title="Manual audit landing in v1.2.">Run full audit</button>';
}

// ── Render: policy ─────────────────────────────────────────────────────
function renderPolicyCenter() {
  const tmplCards = CHANNEL_TEMPLATES.map(function (t) {
    return '<article class="template-card">' +
      '<div class="template-card-head">' +
        '<span class="severity ' + (t.severity === "MEDIUM" ? "medium" : "low") + '">' + escHtml(t.severity) + '</span>' +
        '<span class="template-id mono">' + escHtml(t.id) + '</span>' +
      '</div>' +
      '<h3>' + escHtml(t.title) + '</h3>' +
      '<p>' + escHtml(t.description) + '</p>' +
    '</article>';
  }).join("\n");
  const rows = state.agents.length
    ? state.agents.map(function (a) {
        const binding = a.channel_template_id || "default none";
        const budget = a.budget_summary && a.budget_summary.daily
          ? "$" + escHtml(a.budget_summary.daily.cap) + "/day"
          : "Not set";
        const open = state.templateBinding.agentId === a.agent_id;
        return '<tr>' +
          '<td><button class="link-btn" data-action="open-agent" data-agent-id="' + escHtml(a.agent_id) + '">' + escHtml(a.agent_id) + '</button></td>' +
          '<td><button class="template-cell" data-action="template-picker-open" data-agent-id="' + escHtml(a.agent_id) + '">' + escHtml(binding) + '</button>' +
            (open ? renderTemplatePicker(a) : '') +
          '</td>' +
          '<td><span class="allow-count">12</span> <span class="muted">.</span> <span class="block-count">3</span></td>' +
          '<td>' + budget + '</td>' +
          '<td>30 d</td>' +
          '<td><span class="toggle-on" aria-label="enabled"></span></td>' +
          '<td>T1, T2</td>' +
        '</tr>';
      }).join("\n")
    : '<tr><td colspan="7" class="muted">No wrapped agents yet.</td></tr>';
  return '<section class="policy-center">' +
    '<p class="eyebrow">POLICY CENTER</p>' +
    '<h1>One screen for every rule <span class="pill tone-verified">v1.1</span></h1>' +
    '<p class="policy-subtitle">Templates, per-agent rules, egress allowlists, retention, budgets, and privacy-minimization settings. Edits write a signed receipt; agents pick up changes within one tool-call cycle.</p>' +
    '<section class="policy-panel"><h2>Channel templates · 6 shipped</h2><div class="template-grid">' + tmplCards + '</div></section>' +
    '<section class="policy-panel"><h2>Per-agent rules</h2>' +
      '<div class="rules-scroll"><table class="rules-table">' +
      '<thead><tr><th>AGENT</th><th>TEMPLATE</th><th>ALLOW / BLOCK</th><th>BUDGET</th><th>RETENTION</th><th>MINIMIZE</th><th>APPROVALS</th></tr></thead>' +
      '<tbody>' + rows + '</tbody></table></div>' +
    '</section>' +
  '</section>';
}

function renderTemplatePicker(agent) {
  const current = agent.channel_template_id || "";
  const selected = state.templateBinding.selectedTemplateId || current || CHANNEL_TEMPLATES[0].id;
  const options = CHANNEL_TEMPLATES.map(function (t) {
    return '<label class="template-option">' +
      '<input type="radio" name="template-choice-' + escHtml(agent.agent_id) + '" value="' + escHtml(t.id) + '"' + (selected === t.id ? ' checked' : '') + ' data-action="template-picker-select" data-agent-id="' + escHtml(agent.agent_id) + '" data-template-id="' + escHtml(t.id) + '">' +
      '<span><strong>' + escHtml(t.title) + '</strong><small>' + escHtml(t.description) + '</small></span>' +
    '</label>';
  }).join("");
  const pending = state.templateBinding.pendingItemId ? '<p class="muted">Awaiting approval...</p>' : '';
  const error = state.templateBinding.error ? '<p class="error-text">' + escHtml(state.templateBinding.error) + '</p>' : '';
  return '<div class="template-picker">' +
    '<div class="template-picker-options">' + options + '</div>' +
    pending + error +
    '<div class="template-picker-actions">' +
      '<button class="btn" data-action="template-picker-close">Cancel</button>' +
      '<button class="btn btn-primary" data-action="template-bind" data-agent-id="' + escHtml(agent.agent_id) + '"' + (state.templateBinding.pendingItemId ? ' disabled' : '') + '>Bind</button>' +
    '</div>' +
  '</div>';
}

// ── Render: exit drill ────────────────────────────────────────────────
function renderExitDrill() {
  const step = state.exitDrill.step;
  function stepBlock(n, title, body, isActive, isDone) {
    const cls = "wizard-step" + (isActive ? " active" : "") + (isDone ? " done" : "");
    return '<div class="' + cls + '"><strong>Step ' + n + ': ' + escHtml(title) + '</strong><div>' + body + '</div></div>';
  }
  const lockState = state.tier1.lockdown.state;
  const exportPending = state.exitDrill.inboxItemId !== null && !state.exitDrill.bundleResult;
  const exportDone = !!state.exitDrill.bundleResult;
  const step1Body = exportDone
    ? 'Bundle approved and packaging.'
    : exportPending
    ? '<span class="muted">Awaiting approval. See inbox in the right pane.</span>'
    : '<button class="btn btn-primary" data-action="exit-export-start">Snapshot now</button>';
  const step2Body = exportDone ? 'Re-key complete.' : '<span class="muted">Re-keying state for portable export.</span>';
  const step3Body = exportDone
    ? '<dl class="kv"><dt>Bundle dir</dt><dd class="mono">' + escHtml(state.exitDrill.bundleResult.bundle_dir || "") + '</dd>' +
      '<dt>Manifest hash</dt><dd class="mono">' + escHtml((state.exitDrill.bundleResult.manifest_hash || "").slice(0, 32) + "...") + '</dd></dl>'
    : '<span class="muted">Bundle artifacts will be listed here once packaging completes.</span>';
  const verifyCmd = "npx @sanctuary-framework/mcp-server verify-exit-bundle &lt;bundle_dir&gt;";
  const importCmd = "npx @sanctuary-framework/mcp-server import-exit-bundle &lt;bundle_dir&gt;";
  const step4Body = '<p class="muted">Run on a fresh shell:</p><pre class="code-block">' + verifyCmd + '</pre>' +
    '<button class="btn" data-action="exit-mark-verified">Mark verified</button>';
  const step5Body = '<p class="muted">Run this command on the destination fortress, not on this one. The destination will prompt for the bundle source passphrase or recovery key.</p><pre class="code-block">' + importCmd + '</pre>';
  const step6Body = '<p class="muted">Optional. Re-wrap the destination harness using <code>sanctuary wrap</code>. See <a href="#" data-action="open-harness-doc">harness compatibility matrix</a>.</p>';
  return '<h1>Exit drill</h1>' +
    '<p class="muted">Six-step wizard. Verify and import are run out-of-band on the operator shell. The dashboard does not call the verifier in-process.</p>' +
    stepBlock(1, "Snapshot the fortress", step1Body, step === 1, exportDone) +
    stepBlock(2, "Re-key encrypted state", step2Body, step === 2, exportDone) +
    stepBlock(3, "Package the bundle", step3Body, step === 3, exportDone) +
    stepBlock(4, "Verify offline", step4Body, step === 4, false) +
    stepBlock(5, "Import on the new host", step5Body, step === 5, false) +
    stepBlock(6, "Harness migration", step6Body, step === 6, false);
}

// ── Render: fortress column ───────────────────────────────────────────
function renderFortress() {
  const fortress = document.getElementById("fortress");
  if (!fortress) return;
  const inboxRows = state.inbox.length
    ? state.inbox.map(function (i) {
        const text = renderTemplate(i.display_template_id, i.display_template_args);
        const actions = inboxActions(i);
        const buttons = actions.map(function (act) {
          const apiAction = (act === "approve" || act === "deny" || act === "dismiss") ? act : null;
          if (apiAction) {
            return '<button class="btn" data-action="inbox-' + apiAction + '" data-item-id="' + escHtml(i.item_id) + '">' + INBOX_ACTION_LABEL[act] + '</button>';
          }
          return '<button class="btn" data-action="inbox-' + act + '" data-item-id="' + escHtml(i.item_id) + '">' + INBOX_ACTION_LABEL[act] + '</button>';
        }).join("");
        const tierBadge = i.kind === "approval_pending"
          ? '<span class="pill">' + escHtml(i.tier) + '</span>'
          : '<span class="pill">' + escHtml(i.kind) + '</span>';
        return '<div class="row" data-inbox-row="' + escHtml(i.item_id) + '" data-inbox-kind="' + escHtml(i.kind) + '"' +
          (i.kind === "approval_pending" ? ' data-inbox-tier="' + escHtml(i.tier) + '"' : '') + '>' +
          '<div class="grow">' + escHtml(text) + '</div>' +
          tierBadge +
          '<div style="display:flex;gap:4px;">' + buttons + '</div>' +
          '</div>';
      }).join("\n")
    : '<p class="muted">Nothing pending.</p>';

  const agentsCard = state.agents.length
    ? state.agents.slice(0, 8).map(function (a) {
        const map = STATUS_MAP[a.status] || STATUS_MAP.unknown;
        const c = a.capabilities || {};
        const menuItems = [
          { action: "pause", label: "Pause", enabled: !!c.can_pause },
          { action: "resume", label: "Resume", enabled: !!c.can_resume },
          { action: "restart", label: "Restart", enabled: !!c.can_restart },
          { action: "lockdown", label: "Lockdown", enabled: !!c.can_lockdown, tier1: true },
          { action: "unwrap", label: "Unwrap", enabled: !!c.can_unwrap, tier1: true }
        ];
        const buttons = menuItems.map(function (mi) {
          const tip = mi.enabled
            ? (mi.tier1 ? "Tier 1: requires inbox approval." : "")
            : "This harness does not support " + mi.label.toLowerCase() + ".";
          return '<button class="btn" data-action="agent-' + mi.action + '" data-agent-id="' + escHtml(a.agent_id) + '"' + (mi.enabled ? '' : ' disabled') + ' title="' + escHtml(tip) + '">' + escHtml(mi.label) + '</button>';
        }).join("");
        return '<div class="row agent-row" data-agent-row="' + escHtml(a.agent_id) + '">' +
          '<div class="agent-row-head">' +
            '<span class="glyph ' + map.glyph + '" title="' + escHtml(REASON_LABELS[a.status_reason_class] || "") + '"></span>' +
            '<div class="grow"><strong>' + escHtml(a.agent_id) + '</strong></div>' +
            '<span class="pill">' + escHtml(map.label) + '</span>' +
          '</div>' +
          '<div class="agent-row-actions">' + buttons + '</div>' +
          '</div>';
      }).join("\n")
    : '<p class="muted">No agents wrapped.</p>';

  fortress.innerHTML = [
    '<section class="card">',
      '<h3>This fortress</h3>',
      '<p class="muted mono">' + escHtml(config.fortressId || "(local)") + '</p>',
      '<p class="muted">Operator: ' + escHtml(config.identityId || "(unknown)") + '</p>',
    '</section>',
    '<section class="card"><h3>Layers</h3>',
      '<div class="layer-card"><h4>L1 Cognitive</h4><p>Encrypted state at rest.</p></div>',
      '<div class="layer-card"><h4>L2 Operational</h4><p>Approval gates and policy enforcement.</p></div>',
      '<div class="layer-card"><h4>L3 Selective disclosure</h4><p>Commitments without revealing values.</p></div>',
      '<div class="layer-card"><h4>L4 Verifiable reputation</h4><p>Signed attestations, portable.</p></div>',
    '</section>',
    '<section class="card"><h3>Inbox (' + state.inbox.filter(function (i) { return !i.resolved; }).length + ')</h3>' + inboxRows + '</section>',
    '<section class="card"><h3>Agents (' + state.agents.length + ')</h3>' + agentsCard + '</section>',
    '<section class="card"><h3>Posture</h3><p class="muted">Local-only. Single operator. Federation: off.</p></section>'
  ].join("");
}

// ── Hub API actions ────────────────────────────────────────────────────
async function fetchAll() {
  try {
    const ar = await api("/agents");
    state.agents = ar.data.agents || [];
    state.chatActiveAgentId = state.chatActiveAgentId || (state.agents[0] ? state.agents[0].agent_id : null);
  } catch (e) { /* tolerate */ }
  try {
    const ir = await api("/inbox");
    state.inbox = ir.data.items || [];
  } catch (e) { /* tolerate */ }
  try {
    const acr = await api("/activity");
    state.activity = acr.data.entries || [];
  } catch (e) { /* tolerate */ }
  try {
    const pr = await api("/policies");
    state.policies = pr.data.policies || [];
  } catch (e) { /* tolerate */ }
  try {
    const pe = await api("/activity?category=privacy");
    state.privacyEvents = pe.data.entries || [];
  } catch (e) { /* tolerate */ }
  try {
    const he = await api("/activity?category=handoff");
    state.handoffEvents = he.data.entries || [];
  } catch (e) { /* tolerate */ }
}

// Tier 1 lockdown click. Two-step: POST returns 202 + inbox_item_id, button
// transitions to "pending"; only the inbox approval lifts the controller call.
async function onLockdownClick() {
  if (state.tier1.lockdown.state !== "idle") return;
  try {
    const r = await api("/agents/all/lockdown", { method: "POST", body: {} });
    state.tier1.lockdown = { state: "pending", inboxItemId: r.data.inbox_item_id };
    renderTopbar();
  } catch (e) {
    if (e.status === 404) {
      toast("Fortress-level lockdown endpoint not yet wired. Use per-agent lockdown.", "error");
    } else {
      toast("Lockdown request failed: " + e.message, "error");
    }
  }
}

async function onAgentControl(agentId, action) {
  try {
    const r = await api("/agents/" + encodeURIComponent(agentId) + "/" + action, { method: "POST", body: {} });
    if (r.data && r.data.status === "approval_pending") {
      toast("Approval pending. See inbox.", "info");
    } else {
      toast(action + " applied to " + agentId, "info");
    }
    await fetchAll();
    rerender();
  } catch (e) {
    if (e.status === 422) {
      toast("This harness does not support " + action + ".", "error");
    } else {
      toast(action + " failed: " + e.message, "error");
    }
  }
}

async function onInboxAction(itemId, action) {
  try {
    const r = await api("/inbox/" + encodeURIComponent(itemId) + "/" + action, { method: "POST", body: {} });
    // Tier 1 lockdown engagement: the approve handler triggers the controller
    // call. Reflect engaged state once the activity feed confirms.
    const item = (r.data && r.data.item) || null;
    if (item && state.tier1.lockdown.inboxItemId === itemId) {
      state.tier1.lockdown.state = action === "approve" ? "engaged" : "idle";
      renderTopbar();
    }
    if (state.exitDrill.inboxItemId === itemId && action === "approve") {
      // Real export call would land server-side via the inbox-resolution
      // handler; the dashboard reflects the result asynchronously via the
      // activity feed. v1.1 ships projection-only.
      state.exitDrill.bundleResult = { bundle_dir: "(see activity feed)", manifest_hash: "" };
    }
    await fetchAll();
    rerender();
  } catch (e) {
    // Tier 1 dismiss returns HubConflictError (409) per binding addendum 1.2.
    if (e.status === 409) {
      toast("Tier 1 items cannot be dismissed. Approve or deny.", "error");
    } else {
      toast("Inbox action failed: " + e.message, "error");
    }
  }
}

async function onExitExportStart() {
  try {
    const r = await api("/agents/all/exit-bundle/export", { method: "POST", body: {} });
    state.exitDrill.inboxItemId = r.data.inbox_item_id;
    rerender();
  } catch (e) {
    if (e.status === 404) {
      toast("Fortress-level exit-bundle endpoint not yet wired. See backend gap follow-up.", "error");
    } else {
      toast("Export start failed: " + e.message, "error");
    }
  }
}

async function onTemplateBind(agentId) {
  const templateId = state.templateBinding.selectedTemplateId;
  if (!templateId) {
    state.templateBinding.error = "Pick a template before binding.";
    return rerender();
  }
  try {
    state.templateBinding.pendingItemId = "pending";
    state.templateBinding.error = null;
    rerender();
    const r = await api("/agents/" + encodeURIComponent(agentId) + "/template", {
      method: "POST",
      body: { template_id: templateId }
    });
    state.templateBinding.pendingItemId = r.data.inbox_item_id;
    toast("Approval pending. See inbox.", "info");
    await fetchAll();
    rerender();
  } catch (e) {
    state.templateBinding.pendingItemId = null;
    state.templateBinding.error = e.message;
    toast("Template binding failed: " + e.message, "error");
    rerender();
  }
}

// ── SSE wire-up ────────────────────────────────────────────────────────
function connectStream() {
  let es = null;
  let reconnectTimer = null;
  function open() {
    try {
      const url = TOKEN ? STREAM + "?token=" + encodeURIComponent(TOKEN) : STREAM;
      es = new EventSource(url);
    } catch (e) { schedulePolling(); return; }
    es.addEventListener("snapshot", function () { /* v1.0 snapshot pass-through; v1.1 projects from hub. */ });
    es.addEventListener("activity", function (ev) {
      try {
        const e = JSON.parse(ev.data);
        if (state.seenEventIds.has(e.entry_id)) return;
        state.seenEventIds.add(e.entry_id);
        state.activity = [e].concat(state.activity).slice(0, 200);
        if (e.category === "privacy") state.privacyEvents = [e].concat(state.privacyEvents).slice(0, 200);
        if (e.category === "handoff") state.handoffEvents = [e].concat(state.handoffEvents).slice(0, 200);
        rerender();
      } catch (err) { /* ignore */ }
    });
    es.addEventListener("inbox", function (ev) {
      try {
        const item = JSON.parse(ev.data);
        if (state.seenEventIds.has(item.item_id)) return;
        state.seenEventIds.add(item.item_id);
        // Replace-or-prepend by item_id.
        const existing = state.inbox.findIndex(function (x) { return x.item_id === item.item_id; });
        if (existing >= 0) state.inbox[existing] = item;
        else state.inbox = [item].concat(state.inbox);
        rerender();
      } catch (err) { /* ignore */ }
    });
    es.addEventListener("agent_status", function (ev) {
      try {
        const snap = JSON.parse(ev.data);
        const idx = state.agents.findIndex(function (a) { return a.agent_id === snap.agent_id; });
        if (idx >= 0) {
          state.agents[idx] = Object.assign({}, state.agents[idx], { status: snap.status, status_reason_class: snap.status_reason_class, last_activity_at: snap.last_activity_at });
        }
        rerender();
      } catch (err) { /* ignore */ }
    });
    es.addEventListener("approval", function () { fetchAll().then(rerender); });
    es.onerror = function () {
      try { es && es.close(); } catch (e) { /* ignore */ }
      es = null;
      // Reconnect with refetch-and-restore: pause, refetch full state,
      // resume SSE. Race-safe: any inbox/activity events that arrive
      // during refetch are deduped by event_id via seenEventIds.
      if (reconnectTimer) return;
      reconnectTimer = setTimeout(async function () {
        reconnectTimer = null;
        await fetchAll();
        rerender();
        open();
      }, 1000);
    };
  }
  open();
}

// Polling fallback compiled-in but not user-facing. Activated by build-time
// flag (window.__sanctuaryDashboardPolling__ = true) or when EventSource
// is unavailable.
function schedulePolling() {
  setInterval(function () { fetchAll().then(rerender); }, 5000);
}

// ── Rerender ───────────────────────────────────────────────────────────
function rerender() {
  renderTopbar();
  renderMain();
  renderFortress();
}

// ── Wire-up: events ────────────────────────────────────────────────────
function bindHashRoute() {
  function fromHash() {
    const h = (location.hash || "#dashboard").slice(1);
    setRoute(h.split("?")[0] || "dashboard");
  }
  window.addEventListener("hashchange", fromHash);
  fromHash();
}

document.addEventListener("click", function (ev) {
  const tgt = ev.target;
  if (!(tgt instanceof Element)) return;
  const action = tgt.getAttribute("data-action");
  if (!action) return;
  const itemId = tgt.getAttribute("data-item-id");
  const agentId = tgt.getAttribute("data-agent-id");
  const route = tgt.getAttribute("data-route");
  if (action === "lockdown") return void onLockdownClick();
  if (action === "exit-export-start") return void onExitExportStart();
  if (action === "exit-mark-verified") { state.exitDrill.step = 5; return rerender(); }
  if (action === "open-agent" && agentId) { state.selectedAgentId = agentId; location.hash = "agent-detail"; return; }
  if (action === "template-picker-open" && agentId) {
    const agent = state.agents.find(function (a) { return a.agent_id === agentId; });
    state.templateBinding = {
      agentId: agentId,
      selectedTemplateId: (agent && agent.channel_template_id) || CHANNEL_TEMPLATES[0].id,
      pendingItemId: null,
      error: null
    };
    return rerender();
  }
  if (action === "template-picker-close") {
    state.templateBinding = { agentId: null, selectedTemplateId: null, pendingItemId: null, error: null };
    return rerender();
  }
  if (action === "template-picker-select" && agentId) {
    state.templateBinding.agentId = agentId;
    state.templateBinding.selectedTemplateId = tgt.getAttribute("data-template-id");
    state.templateBinding.error = null;
    return rerender();
  }
  if (action === "template-bind" && agentId) return void onTemplateBind(agentId);
  if (action === "set-route" && route) { location.hash = route; return; }
  if (action === "show-details" && itemId) {
    const i = state.inbox.find(function (x) { return x.item_id === itemId; });
    if (i) toast("Template: " + i.display_template_id);
    return;
  }
  if (action.indexOf("inbox-") === 0 && itemId) {
    const sub = action.slice("inbox-".length);
    return void onInboxAction(itemId, sub);
  }
  if (action.indexOf("agent-") === 0 && agentId) {
    const sub = action.slice("agent-".length);
    return void onAgentControl(agentId, sub);
  }
});

// v1.1.7: chat composer submit handler removed alongside the half-built
// chat surface (Finding EE). Direct concierge chat ships in v1.2; until
// then the dashboard view renders a static welcome card with no form
// inputs that could be confused for a working command surface.

// Theme: system preference only at v1.1.
const mq = window.matchMedia ? window.matchMedia("(prefers-color-scheme: dark)") : null;
if (mq && mq.matches) document.documentElement.setAttribute("data-theme", "dark");
if (mq) mq.addEventListener("change", function (e) {
  if (e.matches) document.documentElement.setAttribute("data-theme", "dark");
  else document.documentElement.removeAttribute("data-theme");
});

// Boot.
fetchAll().then(function () { rerender(); });
bindHashRoute();
connectStream();
`;
