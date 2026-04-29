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
  sidebarCollapsed: sessionStorage.getItem(SESSION_KEY) === "1",
  intelligence: {
    status: null,
    config: null,
    notConfigured: false,
    loadError: null,
    picker: {
      open: false,
      surface: null,
      candidate: null,
      localModelPick: null,
      veniceApiKey: "",
      frontierProvider: "anthropic",
      frontierApiKey: "",
      saving: false,
      error: null
    }
  },
  // WP-V1.2-4: operator chat surfaces. Concierge is fortress-wide; direct-
  // agent is per-agent and Tier 1 gated. Composer text is held module-local
  // so input keystrokes do NOT trigger re-render (the input listener mirrors
  // value into state without rerender; send handler reads from state).
  chat: {
    concierge: {
      messages: [],
      composer: "",
      sending: false,
      error: null,
      badge: null
    },
    directAgent: {
      threadByAgentId: {},
      sessionByAgentId: {},
      pendingApprovalByAgentId: {},
      composer: "",
      sending: false,
      error: null
    }
  }
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
  const fullRoutes = ["agents", "policy", "intelligence", "privacy", "coordination", "health", "exit-drill", "agent-detail"];
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
    case "dashboard": main.innerHTML = renderDashboardConcierge(); break;
    case "agents": main.innerHTML = renderAgentsList(); break;
    case "agent-detail": main.innerHTML = renderAgentDetail(); break;
    case "policy": main.innerHTML = renderPolicyCenter(); break;
    case "intelligence": main.innerHTML = renderIntelligenceCenter(); break;
    case "privacy": main.innerHTML = renderPrivacyPage(); break;
    case "coordination": main.innerHTML = renderCoordinationPage(); break;
    case "health": main.innerHTML = renderHealthPage(); break;
    case "exit-drill": main.innerHTML = renderExitDrill(); break;
    default: main.innerHTML = '<p class="muted">Route not found.</p>';
  }
}

// ── Render: dashboard concierge ────────────────────────────────────────
// WP-V1.2-4 concierge surface (replaces v1.1.7's "What you can do today"
// landing card per Finding EE follow-up). The concierge is a fortress-
// wide chat panel: operator types in plain English, the substrate
// selector summarizes audit log + activity feed + agent registry, the
// response renders inline. No session model. PII filter (Tier 1 regex)
// runs pre-substrate; Tier 2 NER is substrate-routed.
//
// Visual contract per the spawn-prompt screenshots 00 + 01:
// - Header: "Chat / This fortress" with sub-header
//   "Sanctuary Fortress concierge" persona.
// - Chat history (operator + concierge messages, oldest first).
// - Input field at the bottom, send button.
// - Suggested-action chips below the input (hardcoded in v1.2 per
//   spawn-prompt §4.1; LLM-suggested chips defer to v1.3+).
// - Substrate badge in the header (e.g. "Local Gemma 2 2B" or
//   "Concierge unavailable; substrate not configured") sourced from the
//   last response's served_by + display_label.
const CONCIERGE_SUGGESTIONS = [
  { id: "summarize-hour", label: "summarize the last hour", query: "Summarize what happened in this fortress in the last hour." },
  { id: "agent-touched", label: "what has each agent touched today", query: "What has each wrapped agent done today? Group by agent." },
  { id: "open-approvals", label: "any open approvals?", query: "Are there any open Tier 1 approvals or pending inbox items I should look at?" }
];

function renderDashboardConcierge() {
  const c = state.chat.concierge;
  const badge = c.badge && c.badge.displayLabel
    ? '<span class="pill mono concierge-badge" title="Substrate that served the most recent response">' + escHtml(c.badge.displayLabel) + '</span>'
    : '<span class="pill muted concierge-badge">Concierge: substrate not yet contacted</span>';
  const messages = c.messages.length
    ? c.messages.map(function (m) {
        const cls = m.role === "operator" ? "concierge-msg-operator" : "concierge-msg-concierge";
        const author = m.role === "operator" ? "you" : "Sanctuary Fortress concierge";
        return '<div class="concierge-msg ' + cls + '">' +
          '<div class="concierge-msg-author muted">' + escHtml(author) + ' · ' + escHtml(shortTime(m.created_at)) + '</div>' +
          '<div class="concierge-msg-body">' + escHtml(m.body) + '</div>' +
          '</div>';
      }).join("\n")
    : '<p class="muted concierge-empty">No messages yet. Ask the concierge anything about your fortress: it can summarize agent activity, surface open approvals, or describe the current policy.</p>';
  const errorBanner = c.error
    ? '<div class="banner banner-warn">' + escHtml(c.error) + '</div>'
    : "";
  const sendDisabled = c.sending ? ' disabled' : '';
  const sendLabel = c.sending ? 'Sending...' : 'Send';
  const chips = CONCIERGE_SUGGESTIONS.map(function (s) {
    return '<button class="btn chip" data-action="concierge-suggestion" data-suggestion-id="' + escHtml(s.id) + '"' + sendDisabled + '>' + escHtml(s.label) + '</button>';
  }).join("\n");
  return [
    '<h1>Chat <span class="muted">/ This fortress</span></h1>',
    '<div class="card concierge-card">',
      '<div class="concierge-header">',
        '<div class="concierge-persona"><strong>Sanctuary Fortress concierge</strong> <span class="muted">read-only over fortress state</span></div>',
        badge,
      '</div>',
      errorBanner,
      '<div class="concierge-history" id="concierge-history">' + messages + '</div>',
      '<form class="concierge-composer" data-action="concierge-submit">',
        '<input type="text" name="concierge-input" placeholder="Ask the concierge about this fortress..." value="' + escHtml(c.composer) + '" data-action="concierge-input"' + sendDisabled + ' autocomplete="off">',
        '<button type="submit" class="btn btn-primary" data-action="concierge-send"' + sendDisabled + '>' + escHtml(sendLabel) + '</button>',
      '</form>',
      '<div class="concierge-chips">' + chips + '</div>',
      '<p class="muted concierge-foot">First time? <a href="#intelligence">Pick a substrate</a> to enable concierge replies.</p>',
    '</div>'
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
  // WP-V1.2-4 direct-agent chat surface. Per spawn-prompt §4.2 + the
  // Agent Chat screenshot: clicking "Open direct chat" fires the Tier 1
  // ApprovalGate (one approval per session-open, NOT per message). On
  // approval the chat surface opens with the agent's identity + current
  // template binding inline. Per-message handoff is convenience inside
  // the conversation; session entry is the privileged action.
  const chatPanel = renderDirectAgentChat(a);
  return '<h1>' + escHtml(a.agent_id) + '</h1>' +
    '<div class="card"><h3>Identity</h3>' +
      '<dl class="kv">' +
      '<dt>Harness</dt><dd class="mono">' + escHtml(a.harness) + '</dd>' +
      '<dt>Model</dt><dd class="mono">' + escHtml(a.model_provider.vendor) + " / " + escHtml(a.model_provider.model_id) + '</dd>' +
      '<dt>Policy</dt><dd class="mono">' + escHtml(a.policy_id) + '</dd>' +
      '<dt>Template</dt><dd class="mono">' + escHtml(a.channel_template_id || "no_template") + '</dd>' +
      '<dt>Status</dt><dd><span class="glyph ' + map.glyph + '"></span> ' + escHtml(map.label) + '</dd>' +
      '</dl>' +
    '</div>' +
    chatPanel +
    '<div class="card"><h3>Timeline</h3>' + timeline + '</div>';
}

// Direct-agent chat panel for the Agents view per the spawn-prompt
// screenshot "Agent Chat.png". Three states:
//   1. No session and no pending approval: show "Open direct chat" CTA
//      that fires the Tier 1 inbox enqueue. The CTA copy is the spawn
//      prompt's exact framing of the privileged action.
//   2. Tier 1 inbox item pending: show a "Approve in inbox" hint + the
//      pending inbox item id so the operator can resolve it from the
//      inbox panel (the existing Tier 1 inbox flow handles approve/deny).
//   3. Active session: chat surface (header with agent identity +
//      template binding + session expiry + End-session button + chat
//      history + composer). Per-message Tier 1 gate is NOT fired (one
//      approval per session-open).
function renderDirectAgentChat(agent) {
  const da = state.chat.directAgent;
  const session = da.sessionByAgentId[agent.agent_id] || null;
  const pendingInboxId = da.pendingApprovalByAgentId[agent.agent_id] || null;
  const errorBanner = da.error
    ? '<div class="banner banner-warn">' + escHtml(da.error) + '</div>'
    : "";

  // State 3: active session: render chat surface.
  if (session && !session.closed_at) {
    const thread = da.threadByAgentId[agent.agent_id] || [];
    const messages = thread.length
      ? thread.map(function (m) {
          const cls = m.role === "operator" ? "concierge-msg-operator" : "concierge-msg-concierge";
          const author = m.role === "operator" ? "you" : escHtml(agent.agent_id);
          return '<div class="concierge-msg ' + cls + '">' +
            '<div class="concierge-msg-author muted">' + escHtml(author) + ' · ' + escHtml(shortTime(m.created_at)) + '</div>' +
            '<div class="concierge-msg-body">' + escHtml(m.body) + '</div>' +
            '</div>';
        }).join("\n")
      : '<p class="muted concierge-empty">Session open. Type a message; the wrapped agent will reply when its harness wires up the v1.2.x reply hook. Operator-side messages persist + audit-emit immediately.</p>';
    const sendDisabled = da.sending ? ' disabled' : '';
    const sendLabel = da.sending ? 'Sending...' : 'Send';
    const expiry = session.expires_at
      ? '<span class="muted mono">Session expires ' + escHtml(shortTime(session.expires_at)) + '</span>'
      : '';
    return '<div class="card concierge-card">' +
      '<div class="concierge-header">' +
        '<div class="concierge-persona"><strong>Direct chat with ' + escHtml(agent.agent_id) + '</strong> ' +
          '<span class="muted">' + escHtml(agent.channel_template_id || "no_template") + '</span></div>' +
        expiry +
      '</div>' +
      errorBanner +
      '<div class="concierge-history" id="direct-agent-history">' + messages + '</div>' +
      '<form class="concierge-composer" data-action="direct-agent-submit" data-agent-id="' + escHtml(agent.agent_id) + '">' +
        '<input type="text" name="direct-agent-input" placeholder="Type a message to ' + escHtml(agent.agent_id) + '..." value="' + escHtml(da.composer) + '" data-action="direct-agent-input"' + sendDisabled + ' autocomplete="off">' +
        '<button type="submit" class="btn btn-primary" data-action="direct-agent-send" data-agent-id="' + escHtml(agent.agent_id) + '"' + sendDisabled + '>' + escHtml(sendLabel) + '</button>' +
      '</form>' +
      '<div class="concierge-chips">' +
        '<button class="btn" data-action="direct-agent-end" data-agent-id="' + escHtml(agent.agent_id) + '"' + sendDisabled + '>End session</button>' +
      '</div>' +
    '</div>';
  }

  // State 2: Tier 1 inbox item pending operator approval.
  if (pendingInboxId) {
    return '<div class="card">' +
      '<h3>Direct chat</h3>' +
      errorBanner +
      '<p>Tier 1 approval pending for direct chat with <span class="mono">' + escHtml(agent.agent_id) + '</span>. ' +
        'Approve or deny it in the <a href="#dashboard">inbox</a>; ' +
        'the chat surface opens here on approve.</p>' +
      '<p class="muted mono">' + escHtml(pendingInboxId) + '</p>' +
    '</div>';
  }

  // State 1: no session and no pending approval: CTA.
  return '<div class="card">' +
    '<h3>Direct chat</h3>' +
    errorBanner +
    '<p>Open a Tier 1 approved chat session with this wrapped agent. ' +
      'One approval per session-open; per-message handoff is convenience inside the conversation.</p>' +
    '<button class="btn btn-primary" data-action="direct-agent-start" data-agent-id="' + escHtml(agent.agent_id) + '">Open direct chat (Tier 1)</button>' +
  '</div>';
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

// ── Render: intelligence ───────────────────────────────────────────────
// Stable label + tradeoff registry mirrored from server templates.ts. Keep
// these strings in sync with server/src/intelligence/templates.ts; the
// dashboard owns the canonical render so the operator-visible copy is
// reviewable here without grep-walking the selector module.
const SUBSTRATE_LABELS = {
  "local": "Local model",
  "venice": "Venice.ai",
  "frontier-with-filter": "Frontier with PII filter",
  "hybrid": "Hybrid (per surface)",
  "disabled": "Disabled"
};
const SUBSTRATE_TRADEOFFS = {
  "local": "Your queries never leave your machine. Capability is moderate; complex reasoning may underperform a frontier model. Hardware required: 8GB RAM Apple Silicon M1+ or equivalent.",
  "venice": "Queries reach Venice's relay during inference. Venice's contract states no retention or training on user data. Trust is contractual, not cryptographic. Capability higher than local.",
  "frontier-with-filter": "Queries reach the frontier provider after PII redaction. Highest capability. The frontier provider may log queries per their ToS. Redaction can fail on subtle PII (paraphrased addresses, contextual identifiers); expect imperfect privacy. The Privacy Filter event log shows what was redacted.",
  "hybrid": "Each surface routes to its own substrate per your configuration. Tradeoffs apply per surface; see each row.",
  "disabled": "This surface does not invoke an LLM. Privacy filter falls back to Tier 1 regex; concierge, sentinel scoring, and gate explanation surfaces become unavailable until you pick a substrate."
};
const LOCAL_MODEL_LABELS = {
  "gemma-2-2b": "Gemma 2 2B (via Ollama)",
  "phi-4-mini": "Phi-4 Mini (via Ollama)",
  "llama-3.1-8b": "Llama 3.1 8B (via Ollama)"
};
const SURFACE_LABELS = {
  "concierge": "Concierge",
  "direct-agent-gate-advisor": "Direct-agent gate advisor",
  "sentinel-scoring": "Sentinel scoring",
  "gate-explanation": "Gate explanation",
  "privacy-filter-tier-2": "Privacy filter (Tier 2)",
  "template-suggestion": "Template suggestion"
};
const SURFACES_ORDER = [
  "concierge",
  "direct-agent-gate-advisor",
  "sentinel-scoring",
  "gate-explanation",
  "privacy-filter-tier-2",
  "template-suggestion"
];
const SUBSTRATE_OPTIONS = ["local", "venice", "frontier-with-filter", "hybrid", "disabled"];
const FRONTIER_PROVIDERS = ["anthropic", "openai", "google"];
const FRONTIER_PROVIDER_LABELS = {
  "anthropic": "Anthropic",
  "openai": "OpenAI",
  "google": "Google"
};

function substrateLabel(substrate) {
  return SUBSTRATE_LABELS[substrate] || substrate;
}

function substrateTradeoff(substrate) {
  return SUBSTRATE_TRADEOFFS[substrate] || "Tradeoffs documented in source.";
}

function statusDotClass(status) {
  if (status === "green") return "green";
  if (status === "yellow") return "yellow";
  return "red";
}

function statusLabel(health) {
  if (health === "ok") return "Working";
  if (health === "degraded") return "Degraded";
  return "Unavailable";
}

function tierLabel(tier) {
  if (tier === "below-baseline") return "Below baseline (under 8 GB RAM)";
  if (tier === "baseline") return "Baseline (8 to 16 GB RAM)";
  if (tier === "mid") return "Mid (16 to 32 GB RAM)";
  if (tier === "pro") return "Pro (32 GB+ RAM)";
  return "Unknown";
}

function renderIntelligenceCenter() {
  if (state.intelligence.notConfigured) {
    return '<section class="intel-center">' +
      '<p class="eyebrow">INTELLIGENCE</p>' +
      '<h1>Substrate selector not configured</h1>' +
      '<p class="intel-subtitle">This dashboard binding does not include an Intelligence Substrate Selector. Run <code>sanctuary dashboard</code> against an unlocked fortress to bind one. See the WP-V1.2-5 release notes for setup details.</p>' +
    '</section>';
  }
  if (state.intelligence.loadError) {
    return '<section class="intel-center">' +
      '<p class="eyebrow">INTELLIGENCE</p>' +
      '<h1>Could not load substrate status</h1>' +
      '<p class="intel-subtitle error-text">' + escHtml(state.intelligence.loadError) + '</p>' +
      '<button class="btn" data-action="intel-reload">Retry</button>' +
    '</section>';
  }
  if (!state.intelligence.status) {
    return '<section class="intel-center">' +
      '<p class="eyebrow">INTELLIGENCE</p>' +
      '<h1>Intelligence Substrate</h1>' +
      '<p class="intel-subtitle muted">Loading substrate status.</p>' +
    '</section>';
  }
  const status = state.intelligence.status;
  const config = state.intelligence.config || {};
  const surfaceRows = SURFACES_ORDER.map(function (surfaceId) {
    const surfaceStatus = (status.surfaces || []).find(function (s) { return s.surface === surfaceId; });
    if (!surfaceStatus) {
      return '<div class="intel-row"><div class="intel-row-name">' + escHtml(SURFACE_LABELS[surfaceId] || surfaceId) +
        '<small>' + escHtml(surfaceId) + '</small></div>' +
        '<div class="intel-row-body muted">No status reported.</div>' +
        '<div></div></div>';
    }
    const substrate = surfaceStatus.chosen;
    const localPick = (config.local_model_picks || {})[surfaceId];
    let currentBadge = substrateLabel(substrate);
    if (substrate === "local" && localPick) {
      currentBadge = currentBadge + " . " + (LOCAL_MODEL_LABELS[localPick] || localPick);
    }
    if (substrate === "frontier-with-filter") {
      // Surface which provider is wired (first non-empty per pickFrontierProvider rule).
      const fp = config.frontier_keys_present || {};
      let provider = null;
      if (fp.anthropic) provider = "anthropic";
      else if (fp.openai) provider = "openai";
      else if (fp.google) provider = "google";
      if (provider) currentBadge = currentBadge + " (" + (FRONTIER_PROVIDER_LABELS[provider] || provider) + ")";
    }
    const dotClass = statusDotClass((surfaceStatus.badge || {}).status || "red");
    return '<div class="intel-row" data-intel-surface="' + escHtml(surfaceId) + '">' +
      '<div class="intel-row-name">' + escHtml(SURFACE_LABELS[surfaceId] || surfaceId) +
        '<small>' + escHtml(surfaceId) + '</small></div>' +
      '<div class="intel-row-body">' +
        '<div class="intel-row-current">' +
          '<span class="intel-status-dot ' + dotClass + '" title="' + escHtml(statusLabel(surfaceStatus.health)) + '"></span>' +
          '<span class="pill">' + escHtml(currentBadge) + '</span>' +
          '<span class="muted mono">' + escHtml(statusLabel(surfaceStatus.health)) + '</span>' +
        '</div>' +
        '<div class="intel-row-tradeoff">' + escHtml(substrateTradeoff(substrate)) + '</div>' +
      '</div>' +
      '<div><button class="btn" data-action="intel-picker-open" data-intel-surface="' + escHtml(surfaceId) + '">Change</button></div>' +
    '</div>';
  }).join("\n");

  const hardware = status.hardware || {};
  const recommended = hardware.recommendedLocalModel ? (LOCAL_MODEL_LABELS[hardware.recommendedLocalModel] || hardware.recommendedLocalModel) : "(below baseline)";
  const ollamaLabel = hardware.ollamaReachable
    ? 'Reachable. Models present: ' + ((hardware.ollamaModels || []).length || 0)
    : 'Not reachable at ' + escHtml(config.ollama_endpoint || "http://localhost:11434");

  const modal = state.intelligence.picker.open ? renderIntelligencePicker() : "";

  return '<section class="intel-center">' +
    '<p class="eyebrow">INTELLIGENCE</p>' +
    '<h1>Intelligence Substrate</h1>' +
    '<p class="intel-subtitle">Choose how Sanctuary thinks. Tradeoffs visible per surface. Multi-option framing is preserved: no single substrate is the right answer.</p>' +
    '<section class="intel-panel"><h2>Surfaces</h2>' + surfaceRows + '</section>' +
    '<section class="intel-panel"><h2>Host capability</h2>' +
      '<dl class="intel-hardware">' +
        '<dt>Total RAM</dt><dd>' + escHtml(hardware.totalRamGb || "?") + ' GB</dd>' +
        '<dt>CPU arch</dt><dd>' + escHtml(hardware.cpuArch || "?") + '</dd>' +
        '<dt>Tier</dt><dd>' + escHtml(tierLabel(hardware.tier)) + '</dd>' +
        '<dt>Recommended local model</dt><dd>' + escHtml(recommended) + '</dd>' +
        '<dt>Ollama endpoint</dt><dd class="mono">' + escHtml(config.ollama_endpoint || "http://localhost:11434") + '</dd>' +
        '<dt>Ollama status</dt><dd>' + ollamaLabel + '</dd>' +
      '</dl>' +
    '</section>' +
    modal +
  '</section>';
}

function renderIntelligencePicker() {
  const p = state.intelligence.picker;
  const status = state.intelligence.status || {};
  const hardware = status.hardware || {};
  const config = state.intelligence.config || {};
  const surfaceLabel = SURFACE_LABELS[p.surface] || p.surface;
  const candidate = p.candidate || "local";
  const optionRows = SUBSTRATE_OPTIONS.map(function (sub) {
    const cls = "intel-option" + (candidate === sub ? " selected" : "");
    return '<button type="button" class="' + cls + '" data-action="intel-picker-select-substrate" data-intel-substrate="' + escHtml(sub) + '">' +
      '<input type="radio" name="intel-substrate" tabindex="-1"' + (candidate === sub ? ' checked' : '') + '>' +
      '<span class="intel-option-body">' +
        '<strong>' + escHtml(substrateLabel(sub)) + '</strong>' +
        '<small>' + escHtml(substrateTradeoff(sub)) + '</small>' +
      '</span>' +
    '</button>';
  }).join("");

  let sub = "";
  if (candidate === "local") {
    const recommended = hardware.recommendedLocalModel || "gemma-2-2b";
    const localPick = p.localModelPick || (config.local_model_picks || {})[p.surface] || recommended;
    const presentModels = hardware.ollamaModels || [];
    const ollamaLine = hardware.ollamaReachable
      ? 'Ollama reachable. Models present: ' + (presentModels.length ? presentModels.join(", ") : "(none)")
      : 'Ollama not reachable at ' + (config.ollama_endpoint || "http://localhost:11434") + '. Install Ollama and run "ollama pull gemma2:2b".';
    sub = '<div class="intel-suboptions">' +
      '<label>Pick a local model:</label>' +
      ['gemma-2-2b','phi-4-mini','llama-3.1-8b'].map(function (m) {
        return '<label><input type="radio" name="intel-local-model" value="' + escHtml(m) + '"' +
          (localPick === m ? ' checked' : '') +
          ' data-action="intel-picker-select-local-model" data-intel-local-model="' + escHtml(m) + '"> ' +
          escHtml(LOCAL_MODEL_LABELS[m]) + (recommended === m ? ' (recommended)' : '') + '</label>';
      }).join("") +
      '<p class="muted" style="margin-top:8px;">' + escHtml(ollamaLine) + '</p>' +
    '</div>';
  } else if (candidate === "venice") {
    const haveKey = (config.venice_api_key_present === true);
    sub = '<div class="intel-suboptions">' +
      '<label>Venice API key:</label>' +
      '<input type="password" name="intel-venice-key" placeholder="' + (haveKey ? "(saved; enter to replace)" : "Paste your Venice API key") + '" value="' + escHtml(p.veniceApiKey) + '" data-action="intel-picker-input-venice-key">' +
      '<p class="muted" style="margin-top:6px;">Anonymous payment recommended. See Venice setup docs for crypto-payment flow.</p>' +
    '</div>';
  } else if (candidate === "frontier-with-filter") {
    const fp = config.frontier_keys_present || {};
    const provider = p.frontierProvider || "anthropic";
    const haveKey = !!fp[provider];
    const providerOptions = FRONTIER_PROVIDERS.map(function (f) {
      return '<label><input type="radio" name="intel-frontier-provider" value="' + escHtml(f) + '"' +
        (provider === f ? ' checked' : '') +
        ' data-action="intel-picker-select-frontier-provider" data-intel-frontier-provider="' + escHtml(f) + '"> ' +
        escHtml(FRONTIER_PROVIDER_LABELS[f]) +
        (fp[f] ? ' (key saved)' : '') + '</label>';
    }).join("");
    sub = '<div class="intel-suboptions">' +
      '<label>Frontier provider:</label>' +
      providerOptions +
      '<label style="margin-top:8px;">API key:</label>' +
      '<input type="password" name="intel-frontier-key" placeholder="' + (haveKey ? "(saved; enter to replace)" : "Paste your provider API key") + '" value="' + escHtml(p.frontierApiKey) + '" data-action="intel-picker-input-frontier-key">' +
      '<p class="muted" style="margin-top:6px;">Queries route through Privacy Filter Tier 2 before egress. Redaction can fail on subtle PII; expect imperfect privacy.</p>' +
    '</div>';
  } else if (candidate === "hybrid") {
    sub = '<div class="intel-suboptions"><p class="muted">Hybrid routes per-surface using rules set elsewhere. Each surface should be assigned an explicit substrate before picking hybrid here.</p></div>';
  } else if (candidate === "disabled") {
    sub = '<div class="intel-suboptions"><p class="muted">This surface will not invoke an LLM. Privacy filter (Tier 2) falls back to Tier 1 regex when disabled here.</p></div>';
  }

  const errorBlock = p.error ? '<p class="error-text">' + escHtml(p.error) + '</p>' : "";
  const saveLabel = p.saving ? "Saving..." : "Save";
  return '<div class="intel-modal-backdrop" data-action="intel-picker-close-backdrop">' +
    '<div class="intel-modal" role="dialog" aria-label="Pick substrate" data-action="intel-picker-modal-stop">' +
      '<h2>Pick a substrate for ' + escHtml(surfaceLabel) + '</h2>' +
      '<p class="intel-modal-subtitle">' + escHtml(SUBSTRATE_TRADEOFFS[candidate] || "") + '</p>' +
      optionRows +
      sub +
      errorBlock +
      '<div class="intel-modal-actions">' +
        '<button class="btn" data-action="intel-picker-close">Cancel</button>' +
        '<button class="btn btn-primary" data-action="intel-picker-save"' + (p.saving ? ' disabled' : '') + '>' + escHtml(saveLabel) + '</button>' +
      '</div>' +
    '</div>' +
  '</div>';
}

async function fetchIntelligenceState() {
  state.intelligence.loadError = null;
  try {
    const sr = await api("/intelligence/status");
    state.intelligence.status = sr.data || null;
    state.intelligence.notConfigured = false;
  } catch (e) {
    if (e.status === 503) {
      state.intelligence.notConfigured = true;
      state.intelligence.status = null;
      state.intelligence.config = null;
      return;
    }
    state.intelligence.loadError = e.message;
    return;
  }
  try {
    const cr = await api("/intelligence/config");
    state.intelligence.config = cr.data || null;
  } catch (e) {
    if (e.status === 503) {
      state.intelligence.notConfigured = true;
      return;
    }
    state.intelligence.loadError = e.message;
  }
}

async function onIntelPickerOpen(surfaceId) {
  if (!state.intelligence.status || state.intelligence.notConfigured) {
    toast("Intelligence panel not configured.", "error");
    return;
  }
  const surfaceStatus = (state.intelligence.status.surfaces || []).find(function (s) { return s.surface === surfaceId; });
  const config = state.intelligence.config || {};
  state.intelligence.picker = {
    open: true,
    surface: surfaceId,
    candidate: surfaceStatus ? surfaceStatus.chosen : "local",
    localModelPick: (config.local_model_picks || {})[surfaceId] || null,
    veniceApiKey: "",
    frontierProvider: "anthropic",
    frontierApiKey: "",
    saving: false,
    error: null
  };
  rerender();
}

function onIntelPickerClose() {
  state.intelligence.picker = {
    open: false, surface: null, candidate: null, localModelPick: null,
    veniceApiKey: "", frontierProvider: "anthropic", frontierApiKey: "",
    saving: false, error: null
  };
  rerender();
}

async function onIntelPickerSave() {
  const p = state.intelligence.picker;
  if (!p.open || !p.surface || !p.candidate) return;
  p.saving = true;
  p.error = null;
  rerender();
  try {
    if (p.candidate === "venice" && p.veniceApiKey && p.veniceApiKey.length > 0) {
      await api("/intelligence/credentials/venice", {
        method: "POST",
        body: { api_key: p.veniceApiKey }
      });
    }
    if (p.candidate === "frontier-with-filter" && p.frontierApiKey && p.frontierApiKey.length > 0) {
      await api("/intelligence/credentials/frontier", {
        method: "POST",
        body: { provider: p.frontierProvider, api_key: p.frontierApiKey }
      });
    }
    const choiceBody = { substrate: p.candidate };
    if (p.candidate === "local" && p.localModelPick) {
      choiceBody.local_model_pick = p.localModelPick;
    }
    await api("/intelligence/surfaces/" + encodeURIComponent(p.surface) + "/choice", {
      method: "POST",
      body: choiceBody
    });
    await fetchIntelligenceState();
    onIntelPickerClose();
    toast("Substrate updated for " + (SURFACE_LABELS[p.surface] || p.surface) + ".", "info");
  } catch (e) {
    state.intelligence.picker.saving = false;
    state.intelligence.picker.error = e.message;
    rerender();
  }
}

// ── WP-V1.2-4 chat handlers ─────────────────────────────────────────────

async function fetchConciergeHistory() {
  try {
    const res = await api("/chat/concierge/history");
    state.chat.concierge.messages = (res.data && res.data.messages) || [];
    // Surface the most recent concierge response's served_by as the
    // header badge so the operator sees which substrate served the
    // last visible reply.
    const reversed = state.chat.concierge.messages.slice().reverse();
    const lastConcierge = reversed.find(function (m) { return m.role === "concierge"; });
    if (lastConcierge && lastConcierge.served_by) {
      state.chat.concierge.badge = {
        substrate: lastConcierge.served_by,
        displayLabel: substrateBadgeLabel(lastConcierge.served_by)
      };
    }
  } catch (e) {
    // On 422 (chat not wired) or 404 etc., leave history empty; the
    // concierge surface itself surfaces "substrate not configured" once
    // the operator submits.
    state.chat.concierge.messages = [];
  }
}

function substrateBadgeLabel(sub) {
  if (sub === "local") return "Concierge: Local model";
  if (sub === "venice") return "Concierge: Venice.ai";
  if (sub === "frontier-with-filter") return "Concierge: Frontier with PII filter";
  if (sub === "hybrid") return "Concierge: Hybrid (per-surface)";
  if (sub === "disabled") return "Concierge: substrate not configured";
  return "Concierge: " + sub;
}

async function onConciergeSend() {
  const c = state.chat.concierge;
  if (c.sending) return;
  const message = (c.composer || "").trim();
  if (message.length === 0) return;
  c.sending = true;
  c.error = null;
  rerender();
  try {
    const res = await api("/chat/concierge", {
      method: "POST",
      body: { message: message }
    });
    const data = res.data || {};
    // Refetch history so both operator submit + concierge response
    // render in chronological order. The service persisted both
    // messages before the response returned; the history endpoint is
    // the single source of truth for the visible thread.
    await fetchConciergeHistory();
    // Update the badge directly from the response so it reflects what
    // served THIS query even before the next render.
    if (data.served_by) {
      state.chat.concierge.badge = {
        substrate: data.served_by,
        displayLabel: data.display_label || substrateBadgeLabel(data.served_by)
      };
    }
    c.composer = "";
  } catch (e) {
    c.error = e.message || "Concierge call failed.";
  } finally {
    c.sending = false;
    rerender();
  }
}

async function fetchDirectAgentHistory(agentId) {
  try {
    const res = await api("/chat/agents/" + encodeURIComponent(agentId) + "/history");
    state.chat.directAgent.threadByAgentId[agentId] = (res.data && res.data.messages) || [];
  } catch (e) {
    // Tolerate 422/404; operator will see the empty thread + can still
    // open a session.
    state.chat.directAgent.threadByAgentId[agentId] = [];
  }
}

async function fetchActiveSessions() {
  try {
    const res = await api("/chat/sessions");
    const sessions = (res.data && res.data.sessions) || [];
    const map = {};
    for (let i = 0; i < sessions.length; i++) {
      const s = sessions[i];
      if (s && s.agent_id && !s.closed_at) map[s.agent_id] = s;
    }
    state.chat.directAgent.sessionByAgentId = map;
    // For any active session, hydrate the per-agent thread so the chat
    // surface renders with full history on first paint instead of an
    // empty pane that fills in after a separate round trip.
    const agentIds = Object.keys(map);
    for (let j = 0; j < agentIds.length; j++) {
      await fetchDirectAgentHistory(agentIds[j]);
    }
  } catch (e) {
    // 422 (chat not wired) leaves sessionByAgentId untouched.
  }
}

async function onDirectAgentStart(agentId) {
  const da = state.chat.directAgent;
  da.error = null;
  rerender();
  try {
    const res = await api("/chat/agents/" + encodeURIComponent(agentId) + "/session/start", {
      method: "POST",
      body: {}
    });
    const data = res.data || {};
    if (data.status === "approval_pending" && data.inbox_item_id) {
      // Tier 1 inbox flow: track the pending item id; the operator
      // approves it from the inbox panel; on approve the session opens
      // and shows up in the next /chat/sessions fetch.
      da.pendingApprovalByAgentId[agentId] = data.inbox_item_id;
      toast("Tier 1 approval queued. Approve in the dashboard inbox to open the session.", "info");
      await fetchAll();
    } else {
      // The hub returned a session record directly (test rig path or
      // future auto-approve mode). Pick up the session.
      await fetchActiveSessions();
    }
  } catch (e) {
    da.error = e.message || "Could not open direct chat.";
  } finally {
    rerender();
  }
}

async function onDirectAgentSend(agentId) {
  const da = state.chat.directAgent;
  if (da.sending) return;
  const message = (da.composer || "").trim();
  if (message.length === 0) return;
  const session = da.sessionByAgentId[agentId];
  if (!session || session.closed_at) {
    da.error = "Session is not active. Open a new direct chat session.";
    rerender();
    return;
  }
  da.sending = true;
  da.error = null;
  rerender();
  try {
    await api("/chat/agents/" + encodeURIComponent(agentId) + "/message", {
      method: "POST",
      body: { session_id: session.session_id, message: message }
    });
    await fetchDirectAgentHistory(agentId);
    da.composer = "";
  } catch (e) {
    da.error = e.message || "Could not send message.";
  } finally {
    da.sending = false;
    rerender();
  }
}

async function onDirectAgentEnd(agentId) {
  const da = state.chat.directAgent;
  const session = da.sessionByAgentId[agentId];
  if (!session) return;
  da.error = null;
  rerender();
  try {
    await api("/chat/agents/" + encodeURIComponent(agentId) + "/session/end", {
      method: "POST",
      body: { session_id: session.session_id }
    });
    delete da.sessionByAgentId[agentId];
    delete da.pendingApprovalByAgentId[agentId];
    da.composer = "";
    await fetchActiveSessions();
  } catch (e) {
    da.error = e.message || "Could not end session.";
  } finally {
    rerender();
  }
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
  await fetchIntelligenceState();
  // WP-V1.2-4: hydrate operator chat state on every fetch cycle so the
  // concierge thread, active sessions, and per-agent direct-chat history
  // all reflect what the server holds. Each call tolerates 422
  // (chat not wired); the surfaces degrade to honest empty states.
  await fetchConciergeHistory();
  await fetchActiveSessions();
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
  const rawTgt = ev.target;
  if (!(rawTgt instanceof Element)) return;
  // Walk up to the first ancestor that carries a data-action so clicks on
  // child elements inside option buttons land on the option, not on the
  // inner text node. Fall back to the original target for non-action
  // clicks (the early-return below catches them).
  let tgt = rawTgt;
  while (tgt && !tgt.getAttribute("data-action")) {
    tgt = tgt.parentElement;
  }
  if (!tgt) return;
  const action = tgt.getAttribute("data-action");
  if (!action) return;
  const itemId = tgt.getAttribute("data-item-id");
  const agentId = tgt.getAttribute("data-agent-id");
  const route = tgt.getAttribute("data-route");
  const intelSurface = tgt.getAttribute("data-intel-surface");
  const intelSubstrate = tgt.getAttribute("data-intel-substrate");
  const intelLocalModel = tgt.getAttribute("data-intel-local-model");
  const intelFrontierProvider = tgt.getAttribute("data-intel-frontier-provider");
  if (action === "lockdown") return void onLockdownClick();
  if (action === "intel-reload") { return void fetchIntelligenceState().then(rerender); }
  if (action === "intel-picker-open" && intelSurface) return void onIntelPickerOpen(intelSurface);
  if (action === "intel-picker-close") return onIntelPickerClose();
  if (action === "intel-picker-close-backdrop") return onIntelPickerClose();
  if (action === "intel-picker-modal-stop") { ev.stopPropagation(); return; }
  if (action === "intel-picker-select-substrate" && intelSubstrate) {
    state.intelligence.picker.candidate = intelSubstrate;
    state.intelligence.picker.error = null;
    return rerender();
  }
  if (action === "intel-picker-select-local-model" && intelLocalModel) {
    state.intelligence.picker.localModelPick = intelLocalModel;
    return rerender();
  }
  if (action === "intel-picker-select-frontier-provider" && intelFrontierProvider) {
    state.intelligence.picker.frontierProvider = intelFrontierProvider;
    return rerender();
  }
  if (action === "intel-picker-save") return void onIntelPickerSave();
  // WP-V1.2-4 concierge handlers ──────────────────────────────────
  if (action === "concierge-submit") { ev.preventDefault(); return void onConciergeSend(); }
  if (action === "concierge-send") { ev.preventDefault(); return void onConciergeSend(); }
  if (action === "concierge-suggestion") {
    const sid = tgt.getAttribute("data-suggestion-id");
    const found = CONCIERGE_SUGGESTIONS.find(function (s) { return s.id === sid; });
    if (found) {
      state.chat.concierge.composer = found.query;
      return void onConciergeSend();
    }
    return;
  }
  // WP-V1.2-4 direct-agent handlers ───────────────────────────────
  if (action === "direct-agent-start" && agentId) return void onDirectAgentStart(agentId);
  if (action === "direct-agent-submit" && agentId) { ev.preventDefault(); return void onDirectAgentSend(agentId); }
  if (action === "direct-agent-send" && agentId) { ev.preventDefault(); return void onDirectAgentSend(agentId); }
  if (action === "direct-agent-end" && agentId) return void onDirectAgentEnd(agentId);
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

// Intelligence picker: capture password / text input updates without
// re-rendering on every keystroke (re-rendering would clobber the input
// state). The state mirrors back into the picker on save.
document.addEventListener("input", function (ev) {
  const tgt = ev.target;
  if (!(tgt instanceof HTMLInputElement)) return;
  const action = tgt.getAttribute("data-action");
  if (action === "intel-picker-input-venice-key") {
    state.intelligence.picker.veniceApiKey = tgt.value;
  } else if (action === "intel-picker-input-frontier-key") {
    state.intelligence.picker.frontierApiKey = tgt.value;
  } else if (action === "concierge-input") {
    // Mirror composer text into state without rerender so keystrokes
    // do not clobber the input element's value or caret position.
    state.chat.concierge.composer = tgt.value;
  } else if (action === "direct-agent-input") {
    state.chat.directAgent.composer = tgt.value;
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
