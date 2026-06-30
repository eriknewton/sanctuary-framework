/**
 * Sanctuary v1.1 Dashboard Embedded Client Script
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
 *   collapse flag and operator-entered bearer token use sessionStorage only.
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
const AUTO_TRIGGER = "/api/auto-trigger";
const INBOX_PREFS = "/api/inbox/unified/prefs";
const STREAM = config.streamUrl || "/api/stream";
let TOKEN = config.authToken || sessionStorage.getItem("authToken") || "";
const SANCTUARY_VERSION = config.sanctuaryVersion || "";
const SESSION_KEY = "sanctuary-v11-sidebar";

// ── State ──────────────────────────────────────────────────────────────
const state = {
  route: "dashboard",
  agents: [],
  inbox: [],
  inboxOps: {
    selected: {},
    filters: { search: "", source: "", severity: "", agent: "", from: "", to: "" },
    snoozeDialog: null
  },
  activity: [],
  policies: [],
  autoTrigger: { rules: [], recommendations: [], loadError: null, savingRuleId: null },
  templateBinding: { agentId: null, selectedTemplateId: null, pendingItemId: null, error: null },
  privacyEvents: [],
  handoffEvents: [],
  honeypot: { toolTraps: [], credentialTraps: [], loadError: null },
  topbarPills: { deployment: "local", mode: "solo", attestation: "pending" },
  // Wave 1 (2026-06-30): which protected agent the operator is steering.
  // null means "All agents" (fortress-wide). Scopes the approvals queue +
  // ambient posture readout. The conversation spine is fortress-wide today
  // (the concierge reads fortress state), so the scope label is shown but
  // the concierge thread is not re-queried per agent in wave 1.
  agentScope: { selectedAgentId: null, switcherOpen: false },
  // Wave 1: HONEST posture from the evidence-gated /api/sovereignty verdict
  // (#828). castleWallArmState drives the seal color; NEVER green-on-presence.
  // null until first load; load failure leaves it null and the seal reads
  // "Unknown / Attention", never a fabricated "Protected".
  //
  // home / homeError (2026-06-30 one-surface fold): the full posture-home
  // payload from GET /api/posture/home (metric cards, today's story, anomaly
  // findings, per-agent rows). Reuses the EXISTING posture data endpoint - the
  // Posture screen folded into this single surface renders from this, and links
  // out to the per-agent drill-down (/posture/agent/:id) and the evidence view
  // (/posture/evidence). storyPlain toggles the plain-language story summary.
  posture: { data: null, error: null, sealOpen: false, home: null, homeError: null, storyPlain: false },
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
    // Per-surface expanded-recent-failures toggle. Click "Recent failures (N)"
    // on a surface row to expand its inline list of recent failure entries.
    // Map<surfaceId, true>; absence means collapsed.
    expandedFailures: {},
    picker: {
      open: false,
      surface: null,
      candidate: null,
      localModelPick: null,
      veniceApiKey: "",
      frontierProvider: "anthropic",
      frontierApiKey: "",
      saving: false,
      error: null,
      // "Apply to all surfaces" toggle (Finding SS, v1.2.0-rc.1).
      // Hydrated from config.apply_to_all_surfaces on picker open;
      // persists back via /api/hub/intelligence/preferences/apply-to-all
      // so the operator's pick survives a dashboard reload.
      applyToAll: true
    }
  },
  recognition: {
    health: null,
    error: null,
    rotating: false
  },
  // WP-V1.2-4: operator chat surfaces. Concierge is fortress-wide; direct-
  // agent is per-agent. v1.2.x click-to-chat opens the session
  // synchronously on click (the click IS the affirmative action; no
  // separate approval ask). Composer text is held module-local
  // so input keystrokes do NOT trigger re-render (the input listener mirrors
  // value into state without rerender; send handler reads from state).
  chat: {
    concierge: {
      messages: [],
      composer: "",
      sending: false,
      error: null,
      badge: null,
      // Finding DDD (v1.2.0-rc.4): when the operator sends a message,
      // unconditionally bring the latest reply into the viewport on the
      // next render so the operator sees their submitted message and
      // the concierge reply land in view. For passive renders (poll-
      // driven history refresh, badge refresh, unrelated state changes)
      // the scroll is conditional on the operator already following the
      // conversation (the latest message was visible before the render).
      // If the operator scrolled up to read history, do not auto-scroll
      // on background ticks; that would be hostile.
      pendingScroll: false
    },
    inspect: {
      // panelByAgentId: keyed by agent_id, the most recently fetched
      // inspect-panel response (recent_activity + pending_approvals +
      // policy_summary + opened_at). The panel is read-only; no
      // streaming updates. The dashboard re-fetches on click.
      panelByAgentId: {},
      // openingAgentId: agent id whose inspect-open round-trip is in
      // flight. Set during onAgentInspectOpen so the CTA hides on click;
      // cleared in the finally branch.
      openingAgentId: null,
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

function escCssAttr(v) {
  return String(v || "").replace(/\\/g, "\\\\").replace(/"/g, '\\"');
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

function promptForOperatorToken() {
  const entered = window.prompt("Operator token required for this action.");
  if (!entered || !entered.trim()) return false;
  TOKEN = entered.trim();
  sessionStorage.setItem("authToken", TOKEN);
  return true;
}

async function api(path, opts) {
  const init = Object.assign({ headers: {} }, opts || {});
  if (TOKEN) init.headers["Authorization"] = "Bearer " + TOKEN;
  if (init.body && typeof init.body !== "string") {
    init.headers["Content-Type"] = "application/json";
    init.body = JSON.stringify(init.body);
  }
  // Finding ZZ (v1.2.0-rc.5): the dashboard SPA wants fresh state on
  // every fetch. WebKit/Safari's HTTP cache serves prior /status,
  // /policies, /activity responses on subsequent GETs even when the
  // server-side state has changed (e.g. recent-failures buffer cleared
  // on substrate flip). The pre-rc.5 client used bare fetch with no
  // cache control, which on Mini1 Safari produced a stale view of
  // server state and made the operator-visible badge color stick to
  // its prior value across substrate changes. Belt + suspenders:
  // cache: "no-store" turns off the response cache; the _t query
  // string defeats heuristic caches that ignore Cache-Control. Both
  // are required: Safari has a known history of ignoring no-store on
  // ETag'd responses with no Last-Modified, and a heuristic cache may
  // stick on a URL with no query string variation. A POST/PUT/DELETE
  // is never cached, so the cache-bust path is GET-only; the query
  // string is appended for GETs that don't already carry one.
  init.cache = "no-store";
  init.headers["Cache-Control"] = "no-cache";
  init.headers["Pragma"] = "no-cache";
  let url = HUB + path;
  const method = (init.method || "GET").toUpperCase();
  if (method === "GET") {
    url += (path.indexOf("?") >= 0 ? "&" : "?") + "_t=" + Date.now();
  }
  let res = await fetch(url, init);
  if (res.status === 401 && method !== "GET" && promptForOperatorToken()) {
    init.headers["Authorization"] = "Bearer " + TOKEN;
    res = await fetch(url, init);
  }
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

async function honeypotApi(path) {
  const headers = { "Cache-Control": "no-cache", "Pragma": "no-cache" };
  if (TOKEN) headers["Authorization"] = "Bearer " + TOKEN;
  const sep = path.indexOf("?") >= 0 ? "&" : "?";
  const res = await fetch("/api/honeypot" + path + sep + "_t=" + Date.now(), {
    headers,
    cache: "no-store"
  });
  let body = null;
  try { body = await res.json(); } catch (e) { body = null; }
  if (!res.ok) throw new Error(body && body.error ? body.error : ("HTTP " + res.status));
  return body;
}

async function autoTriggerApi(path, opts) {
  const init = Object.assign({ headers: {} }, opts || {});
  if (TOKEN) init.headers["Authorization"] = "Bearer " + TOKEN;
  if (init.body && typeof init.body !== "string") {
    init.headers["Content-Type"] = "application/json";
    init.body = JSON.stringify(init.body);
  }
  init.cache = "no-store";
  init.headers["Cache-Control"] = "no-cache";
  init.headers["Pragma"] = "no-cache";
  let url = AUTO_TRIGGER + path;
  const method = (init.method || "GET").toUpperCase();
  if (method === "GET") url += (path.indexOf("?") >= 0 ? "&" : "?") + "_t=" + Date.now();
  const res = await fetch(url, init);
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

async function createStreamSessionQuery() {
  if (!TOKEN) return "";
  const res = await fetch("/auth/session", {
    method: "POST",
    headers: { "Authorization": "Bearer " + TOKEN },
    cache: "no-store"
  });
  let body = null;
  try { body = await res.json(); } catch (e) { body = null; }
  if (!res.ok) throw new Error(body && body.error ? body.error : ("HTTP " + res.status));
  if (!body || !body.session_id || body.session_id === "no-auth") return "";
  return "?session=" + encodeURIComponent(body.session_id);
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
  "approval_pending.tier1.fortress_lockdown": () => "Lockdown approval pending. Approving locks the entire fortress: writes are blocked, reads continue with LOCKED posture signals, active operations may fail, and agent workflows stop until the operator recovers or restarts them.",
  "approval_pending.tier1.unwrap": (a) => "Unwrap agent " + arg(a,"agent_id") + ". Protection and registry binding will be removed.",
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
  "recovery_prompt.passphrase_reset": () => "Recommended: rotate the fortress passphrase.",
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
  active: { label: "Protected", glyph: "online" },
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
  passphrase_required: "Fortress passphrase required",
  config_drift: "Configuration drift detected",
  other: "Other reason. See activity feed."
};

const CHANNEL_TEMPLATES = [
  {
    id: "request-approve-act",
    severity: "MEDIUM",
    title: "Request -> approve -> act",
    description: "Operator sends a task. Agent proposes writes, pauses for approval, then executes. Most protected agents live here."
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
  const fullRoutes = ["activity", "agents", "policy", "auto-trigger", "intelligence", "honeypot", "privacy", "coordination", "health", "exit-drill", "agent-detail"];
  if (fullRoutes.indexOf(route) >= 0) app.classList.add("route-full");
  else app.classList.remove("route-full");
  document.querySelectorAll("#sidebar-nav a").forEach(function (a) {
    if (a.getAttribute("data-route") === route) a.classList.add("active");
    else a.classList.remove("active");
  });
  renderMain();
  renderFortress();
}

// Renders the global attestation badge (Q1 layer 1, persistent across
// surfaces). Tone is driven by state.topbarPills.attestation. Pending
// state shows a dashed seal ring; verified shows solid; degraded shows
// outlined core; unverified shows the broken-seal mark. Observation
// language only; Castle Layer 1 enforcement ships in WP-V1.x-CASTLE-WALL.
function renderTopbarAttestationBadge(stateName) {
  const valid = stateName === "verified" || stateName === "degraded" || stateName === "unverified" || stateName === "pending";
  const cls = valid ? stateName : "pending";
  const ringDashed = cls === "pending" ? " dashed" : "";
  return '<span class="att-global ' + cls + '" data-pill="attestation" title="Fortress attestation">' +
    '<span class="seal">' +
      '<span class="seal-ring' + ringDashed + '"></span>' +
      '<span class="seal-core"></span>' +
    '</span>' +
    '<span class="label">' + escHtml(cls) + '</span>' +
  '</span>';
}

function renderTopbar() {
  const pillEl = document.getElementById("topbar-pills");
  if (!pillEl) return;
  // Version pill (Finding CCC, v1.2.0-rc.3): operator-visible binary
  // version so a stale build is impossible to mistake for a fresh one.
  // Server-rendered initially in html.ts; refreshed here on every
  // renderTopbar so the pill survives any future state-driven topbar
  // rewrite. Reads from the immutable SANCTUARY_VERSION constant
  // hydrated at boot from the dashboard-config script block.
  const versionPill = SANCTUARY_VERSION
    ? '<span class="pill" data-pill="version">v' + escHtml(SANCTUARY_VERSION) + '</span>'
    : '';
  pillEl.innerHTML = [
    versionPill,
    '<span class="pill" data-pill="deployment">deployment: ' + escHtml(state.topbarPills.deployment) + '</span>',
    '<span class="pill" data-pill="mode">mode: ' + escHtml(state.topbarPills.mode) + '</span>',
    renderTopbarAttestationBadge(state.topbarPills.attestation)
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
  renderAgentSwitcher();
  renderPostureSeal();
}

// Wave 1 (2026-06-30): the top-bar agent switcher. Wired to the EXISTING
// GET /api/hub/agents (state.agents, populated by the wrap command).
// Selecting an agent sets state.agentScope.selectedAgentId, which scopes the
// approvals queue (pendingApprovalItems) and the ambient posture readout.
// "All agents" (null) is the fortress-wide default. The fortress (machine)
// switcher is DEFERRED to wave 2; the existing "Fleet Switcher" deep-link
// remains the cross-machine affordance for now.
function agentScopeGlyph(agentId) {
  if (!agentId) return "··";
  const tail = String(agentId).split(":").pop() || "";
  const cleaned = tail.replace(/[^a-zA-Z0-9]/g, "");
  return (cleaned.slice(0, 2) || "··").toUpperCase();
}
function renderAgentSwitcher() {
  const labelEl = document.getElementById("agent-switcher-label");
  const glyphEl = document.getElementById("agent-switcher-glyph");
  const menuEl = document.getElementById("agent-switcher-menu");
  const trigger = document.getElementById("agent-switcher-trigger");
  if (!labelEl || !glyphEl || !menuEl) return;
  const selected = state.agentScope.selectedAgentId;
  const selectedAgent = selected
    ? state.agents.find(function (a) { return a.agent_id === selected; })
    : null;
  // If the selected agent disappeared from the registry, fall back to "All".
  if (selected && !selectedAgent) state.agentScope.selectedAgentId = null;
  const curLabel = state.agentScope.selectedAgentId || "All agents";
  labelEl.textContent = curLabel;
  glyphEl.textContent = agentScopeGlyph(state.agentScope.selectedAgentId);
  const open = !!state.agentScope.switcherOpen;
  menuEl.hidden = !open;
  if (trigger) trigger.setAttribute("aria-expanded", open ? "true" : "false");
  if (!open) return;
  const allSelected = !state.agentScope.selectedAgentId;
  const rows = ['<button type="button" class="agent-switcher-opt' + (allSelected ? ' selected' : '') +
    '" data-action="agent-scope-select" data-agent-id="">' +
    '<span class="opt-glyph">··</span>' +
    '<span class="opt-name">All agents</span>' +
    '<span class="opt-state">' + state.agents.length + ' wrapped</span>' +
    '</button>'];
  state.agents.forEach(function (a) {
    const map = STATUS_MAP[a.status] || STATUS_MAP.unknown;
    const isSel = a.agent_id === state.agentScope.selectedAgentId;
    rows.push('<button type="button" class="agent-switcher-opt' + (isSel ? ' selected' : '') +
      '" data-action="agent-scope-select" data-agent-id="' + escHtml(a.agent_id) + '">' +
      '<span class="opt-glyph">' + escHtml(agentScopeGlyph(a.agent_id)) + '</span>' +
      '<span class="opt-name">' + escHtml(a.agent_id) + '</span>' +
      '<span class="opt-state">' + escHtml(map.label || "") + '</span>' +
      '</button>');
  });
  menuEl.innerHTML = rows.join("");
}

// Wave 1 (2026-06-30): the posture seal. Honest verdict drives its color and
// word (deriveSeal); the popover spells out the named layers (no L-numbers).
function renderPostureSeal() {
  const seal = deriveSeal();
  const sealEl = document.getElementById("posture-seal");
  const wordEl = document.getElementById("posture-seal-word");
  const popEl = document.getElementById("posture-seal-pop");
  if (!sealEl || !wordEl || !popEl) return;
  sealEl.classList.remove("tone-protected", "tone-attention", "tone-locked");
  if (seal.tone === "protected") sealEl.classList.add("tone-protected");
  else if (seal.tone === "locked") sealEl.classList.add("tone-locked");
  else if (seal.tone === "attention") sealEl.classList.add("tone-attention");
  // "unknown" tone keeps the neutral default styling.
  wordEl.textContent = seal.word;
  const open = !!state.posture.sealOpen;
  popEl.hidden = !open;
  sealEl.setAttribute("aria-expanded", open ? "true" : "false");
  if (!open) return;
  var head, sub;
  if (seal.tone === "protected") {
    head = "You are protected.";
    sub = "Everything below is checked right now. Nothing leaves this machine without your hand on it.";
  } else if (seal.tone === "locked") {
    head = "This fortress is locked down.";
    sub = "Wrapped agents are held until you lift the lockdown. The Charter still gates every risky action.";
  } else if (seal.tone === "attention") {
    head = "Needs your attention.";
    sub = "Live enforcement is degraded or unconfirmed right now. The Charter still holds risky actions for your approval. Check the Health screen.";
  } else {
    head = "Posture is being checked.";
    sub = "Live enforcement evidence is not loaded yet. Until it is confirmed, this is not shown as protected.";
  }
  const lines = postureLayerLines().map(function (l) {
    const dotCls = l.off ? "pp-dot off" : (l.warn ? "pp-dot warn" : "pp-dot");
    return '<div class="pp-line"><span class="' + dotCls + '"></span>' +
      '<span class="pp-k">' + escHtml(l.k) + '</span>' +
      '<span class="pp-v">' + escHtml(l.v) + '</span></div>';
  }).join("");
  // One-surface fold: the seal expands to a "See full posture detail" link that
  // routes into the Posture screen (the folded-in metric cards, today's story,
  // anomaly findings, and per-agent drill-down). data-seal keeps the click
  // inside the seal so the outside-click dismiss does not fire first.
  const more = '<a class="pp-more" href="#posture" data-action="posture-detail-open">See full posture detail</a>';
  popEl.innerHTML = '<h4>' + escHtml(head) + '</h4><p class="pp-sub">' + escHtml(sub) + '</p>' + lines + more;
}

// Per-route cache of the last HTML written to #main. Used by renderMain
// to skip innerHTML assignment when a poll-driven rerender produces
// identical output, preserving the existing DOM tree and (crucially) any
// active text selection in the chat-history container. Finding UU
// (v1.2.0-rc.1): unconditional innerHTML replacement on every poll cycle
// destroyed click-and-drag and double-click selections in the concierge
// chat surface, making it impossible for operators to copy a Sanctuary-
// generated reply via the standard macOS selection mechanism.
const __renderCache = { route: null, html: null };

// ── Render: main area ──────────────────────────────────────────────────
function renderMain() {
  const main = document.getElementById("main");
  if (!main) return;
  // F8 fix: capture focused-input identity + caret position so an SSE-
  // triggered rerender during typing does not clobber the operator's
  // typing experience. innerHTML replacement creates new DOM nodes; we
  // re-find the equivalent input by data-action + optional data-agent-id
  // and restore focus + selection range.
  const active = document.activeElement;
  let focus = null;
  if (
    active &&
    active.tagName === "INPUT" &&
    typeof active.getAttribute === "function" &&
    active.getAttribute("data-action")
  ) {
    focus = {
      action: active.getAttribute("data-action"),
      agentId: active.getAttribute("data-agent-id"),
      selectionStart: active.selectionStart,
      selectionEnd: active.selectionEnd
    };
  }
  // Finding DDD (v1.2.0-rc.5): capture whether the operator is
  // following the conversation BEFORE the DOM is replaced. With the
  // rc.5 bounded-card layout, .concierge-history is the inner scroll
  // container (max-height on the card + min-height: 0 + overflow-y:
  // auto on history). The composer sits OUTSIDE the history's scroll
  // region, so it stays visible regardless of where the operator has
  // scrolled. "Following" now means the latest message is visible
  // inside the history container's viewport. The check compares the
  // last message's bounding rect to the history element's bounding
  // rect (both are border-box rects in viewport space, so the
  // intersection test is direct). The rc.5 restore continues to use
  // scrollIntoView, which scrolls whichever ancestor is the actual
  // scroll container, now .concierge-history.
  let conciergeWasFollowing = false;
  if (state.route === "dashboard") {
    const histEl = document.getElementById("concierge-history");
    if (histEl) {
      const lastMsg = histEl.querySelector(".concierge-msg:last-child");
      if (lastMsg) {
        const histRect = histEl.getBoundingClientRect();
        const lastRect = lastMsg.getBoundingClientRect();
        // Following = the last message overlaps the history container's
        // visible region. If the operator scrolled up past the latest
        // message, the message is below histRect.bottom (clipped); if
        // far above the visible region, it's above histRect.top.
        conciergeWasFollowing =
          lastRect.top < histRect.bottom && lastRect.bottom > histRect.top;
      } else {
        // Empty thread. Treat as following so a fresh exchange lands
        // in view.
        conciergeWasFollowing = true;
      }
    }
  }
  let nextHtml;
  switch (state.route) {
    case "dashboard": nextHtml = renderDashboardConcierge(); break;
    case "activity": nextHtml = renderActivityScreen(); break;
    case "posture": nextHtml = renderPostureScreen(); break;
    case "agents": nextHtml = renderAgentsList(); break;
    case "agent-detail": nextHtml = renderAgentDetail(); break;
    case "policy": nextHtml = renderPolicyCenter(); break;
    case "auto-trigger": nextHtml = renderAutoTriggerPage(); break;
    case "intelligence": nextHtml = renderIntelligenceCenter(); break;
    case "attestation": nextHtml = renderAttestation(); break;
    case "honeypot": nextHtml = renderHoneypotPage(); break;
    case "privacy": nextHtml = renderPrivacyPage(); break;
    case "coordination": nextHtml = renderCoordinationPage(); break;
    case "health": nextHtml = renderHealthPage(); break;
    case "exit-drill": nextHtml = renderExitDrill(); break;
    default: nextHtml = '<p class="muted">Route not found.</p>';
  }
  // Skip the innerHTML write when the rendered output is byte-identical
  // to the last write on the same route. Preserves the existing DOM
  // tree, focus, and any active text selection during no-op poll
  // cycles. The route-change branch always writes (cache miss).
  let didWrite = false;
  if (__renderCache.route === state.route && __renderCache.html === nextHtml) {
    // No-op: DOM already reflects current state.
  } else {
    main.innerHTML = nextHtml;
    __renderCache.route = state.route;
    __renderCache.html = nextHtml;
    didWrite = true;
  }
  // Finding DDD (v1.2.0-rc.4): bring the latest concierge message into
  // the viewport when (a) the operator just sent a message
  // (pendingScroll flag set in onConciergeSend), or (b) the operator
  // was following the conversation before this render. If the operator
  // scrolled up to read history, leave their position alone.
  // scrollIntoView is layout-agnostic; it scrolls whichever ancestor is
  // the actual scroll container (window in the current layout, or the
  // history element if a future layout puts a fixed height on it).
  if (state.route === "dashboard" && didWrite) {
    const histEl = document.getElementById("concierge-history");
    if (histEl) {
      const pending = state.chat.concierge.pendingScroll;
      if (pending || conciergeWasFollowing) {
        const lastMsg = histEl.querySelector(".concierge-msg:last-child");
        if (lastMsg && typeof lastMsg.scrollIntoView === "function") {
          lastMsg.scrollIntoView({ block: "end", behavior: "auto" });
        }
      }
      state.chat.concierge.pendingScroll = false;
    }
  }
  if (focus) {
    let sel = 'input[data-action="' + focus.action + '"]';
    if (focus.agentId) sel += '[data-agent-id="' + focus.agentId + '"]';
    const el = main.querySelector(sel);
    if (el && typeof el.focus === "function") {
      try {
        el.focus();
        if (
          typeof el.setSelectionRange === "function" &&
          focus.selectionStart != null &&
          focus.selectionEnd != null
        ) {
          el.setSelectionRange(focus.selectionStart, focus.selectionEnd);
        }
      } catch (e) { /* ignore browsers that disallow programmatic focus */ }
    }
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
  { id: "summarize-hour", category: "Summarize", label: "summarize the last hour", query: "Summarize what happened in this fortress in the last hour." },
  { id: "agent-touched", category: "Inspect", label: "what has each agent touched today", query: "What has each protected agent done today? Group by agent." },
  { id: "open-approvals", category: "Approvals", label: "any open approvals?", query: "Are there any open Tier 1 approvals or pending inbox items I should look at?" }
];

// Direct-agent chat surface was removed in the v1.2 reshape; the
// click-to-chat affordance now opens the inspect/approve panel
// (recent activity + pending approvals + policy summary). The
// "Active chats" panel is gone with the surface; its replacement
// surfaces live on each agent row + the inspect panel itself.
function renderActiveChatsPanel() {
  return "";
}

function renderDashboardConcierge() {
  const c = state.chat.concierge;
  const badge = c.badge && c.badge.displayLabel
    ? '<span class="pill mono concierge-badge" title="Substrate that served the most recent response">' + escHtml(c.badge.displayLabel) + '</span>'
    : '<span class="pill muted concierge-badge">Concierge: substrate not yet contacted</span>';
  const sendDisabled = c.sending ? ' disabled' : '';
  const sendLabel = c.sending ? 'Sending...' : 'Send';
  // Sprint Piece 2 PR 2: empty state lives INSIDE the concierge-history
  // container so the DDD e2e selector .concierge-history matches both
  // empty and active state. The container's flex layout hosts a single
  // .concierge-empty child that fills the available height with a serif
  // headline and a 3-up suggest grid; the grid replaces the v1.2 bottom
  // chip row, which is retired with this polish.
  const emptyState =
    '<div class="concierge-empty">' +
      '<div class="concierge-empty-headline">' +
        '<h2>Where would you like to begin.</h2>' +
        '<p>Ask anything about your fortress. Sanctuary holds your context, your agents, your policy. It will answer plainly, or hand you to the right surface.</p>' +
      '</div>' +
      '<div class="concierge-suggest-grid">' +
        CONCIERGE_SUGGESTIONS.map(function (s) {
          return '<button class="concierge-suggest" data-action="concierge-suggestion" data-suggestion-id="' + escHtml(s.id) + '"' + sendDisabled + '>' +
            '<span class="label">' + escHtml(s.category || '') + '</span>' +
            escHtml(s.label) +
            '</button>';
        }).join("") +
      '</div>' +
    '</div>';
  const messagesHtml = c.messages.length
    ? c.messages.map(function (m) {
        const cls = m.role === "operator" ? "concierge-msg-operator" : "concierge-msg-concierge";
        const authorLabel = m.role === "operator" ? "you" : "sanctuary";
        const metaParts = [];
        if (m.created_at) metaParts.push(escHtml(shortTime(m.created_at)));
        if (m.role === "concierge" && m.served_by) metaParts.push('substrate: ' + escHtml(m.served_by));
        const meta = metaParts.length
          ? '<div class="concierge-msg-meta"><span>' + metaParts.join(' · ') + '</span></div>'
          : '';
        return '<div class="concierge-msg ' + cls + '">' +
          '<span class="concierge-msg-author">' + escHtml(authorLabel) + '</span>' +
          '<div class="concierge-msg-body">' + escHtml(m.body) + '</div>' +
          meta +
          '</div>';
      }).join("\n")
    : emptyState;
  const errorBanner = c.error
    ? '<div class="banner banner-warn">' + escHtml(c.error) + '</div>'
    : "";
  const activeChatsPanel = renderActiveChatsPanel();
  return [
    '<div class="concierge-wrap spine-hero">',
      '<div class="page-head"><div>',
        '<p class="eyebrow">Concierge</p>',
        '<h1>Talk to your fortress.</h1>',
        '<p class="sub">A direct line to Sanctuary, routed through the substrate you chose. Nothing leaves without your hand on it.</p>',
      '</div></div>',
      activeChatsPanel,
      '<div class="card concierge-card">',
        '<div class="concierge-header">',
          '<div class="concierge-persona">',
            '<div class="glyph-ring"></div>',
            '<div class="concierge-persona-text"><strong>Sanctuary Fortress concierge</strong><small>read-only over fortress state</small></div>',
          '</div>',
          '<div class="concierge-meta">' + badge + '</div>',
        '</div>',
        errorBanner,
        '<div class="concierge-history" id="concierge-history">' + messagesHtml + '</div>',
        '<form class="concierge-composer" data-action="concierge-submit">',
          '<div class="input-wrap">',
            '<input type="text" name="concierge-input" placeholder="Type to Sanctuary. Enter to send." value="' + escHtml(c.composer) + '" data-action="concierge-input"' + sendDisabled + ' autocomplete="off">',
            '<span class="composer-meta">Enter</span>',
          '</div>',
          '<button type="submit" class="btn btn-primary" data-action="concierge-send"' + sendDisabled + '>' + escHtml(sendLabel) + '</button>',
        '</form>',
        '<p class="muted concierge-foot">First time? <a href="#intelligence">Pick a substrate</a> to enable concierge replies.</p>',
      '</div>',
    '</div>'
  ].join("");
}

// ── Render: agents list / detail ───────────────────────────────────────
//
// Sprint Piece 2 PR 4 polish: empty state uses .agents-empty with the
// concentric icon-frame + a terminal-block CTA. Populated state uses the
// .agents-layout grid with the .agents-list 4-column table (Agent /
// State / Attestation / Last seen). The empty-state branch keeps the
// literal '<h1>Agents</h1>' start and the "No wrapped agents yet." copy
// because agents-empty-state-canary.test.ts pins both.
function agentInitials(agentId) {
  const tail = String(agentId || "").split(":").pop() || "";
  const cleaned = tail.replace(/[^a-zA-Z0-9]/g, "");
  return (cleaned.slice(0, 2) || "??").toUpperCase();
}
function agentStateClass(status) {
  if (status === "active") return "live";
  if (status === "locked_down" || status === "error") return "off";
  return "idle";
}
// Per-agent attestation badge (Q1 layer 2). Square chip beside each
// agent: a bounded glyph beside a bounded entity. Color and fill pattern
// carry meaning together so the badge reads even monochrome. The "locked"
// status maps to the unverified visual (rust + hatched mark) since a
// locked-down agent has no current attestation; the inspect-pane copy
// explains the distinction. Pure visual surface; no state derivation.
function renderAgentAttestationBadge(status) {
  let cls;
  let label;
  if (status === "active") { cls = "verified"; label = "protected"; }
  else if (status === "locked_down") { cls = "unverified"; label = "locked"; }
  else if (status === "error") { cls = "unverified"; label = "unverified"; }
  else { cls = "degraded"; label = "degraded"; }
  return '<span class="att-agent ' + cls + '" title="Agent attestation"><span class="mark"></span>' + escHtml(label) + '</span>';
}
// Per-action attestation tick (Q1 layer 3). Tiny inline shape on every
// timeline row. Two-byte signature fragment is enough at low resolution;
// the full signature is one click away. Neutral state shows a circle
// instead of a tick when the signer was unreachable; the action is still
// recorded. Visual surface only.
function renderActionAttestationBadge(stateName, sig) {
  const valid = stateName === "verified" || stateName === "degraded" || stateName === "unverified" || stateName === "neutral";
  const cls = valid ? stateName : "neutral";
  const sigText = sig ? String(sig) : "--";
  return '<span class="att-action ' + cls + '" title="Action attestation">' +
    '<span class="tick"></span>' +
    '<span>' + escHtml(sigText) + '</span>' +
  '</span>';
}
// Attestation gallery surface (Q1 four classes: global / per-agent /
// per-action / per-transaction custody-provenance stub). Reference for
// operators: shows what each badge looks like across verified, degraded,
// unverified, and (where applicable) pending or neutral states. Pure
// visual; no derivation, no live data. Castle Layer 3 cooperative-MCP UX
// surface; Castle Layer 1 enforcement ships in WP-V1.x-CASTLE-WALL.
function renderAttestation() {
  return '<div class="att-gallery">' +
    '<div class="page-head"><div>' +
      '<p class="eyebrow">Attestation</p>' +
      '<h1>Four classes of badge.</h1>' +
      '<p class="sub">A signature you can see. From the whole fortress, down to a single action. Degrade, never destroy: a failed signature becomes neutral with a tooltip; the surface keeps working.</p>' +
    '</div></div>' +
    // Global
    '<div class="att-section">' +
      '<div class="att-section-head"><div>' +
        '<h2>Global. The fortress itself.</h2>' +
        '<p>Lives in the topbar. Visible on every surface. Tells you the fortress identity is currently signed and matches the binary you installed.</p>' +
      '</div><span class="label">topbar</span></div>' +
      attRow(renderTopbarAttestationBadge("verified"), "Verified", "Identity matches. Binary matches. Default state for a healthy fortress.") +
      attRow(renderTopbarAttestationBadge("degraded"), "Degraded", "The signature is older than the staleness window, or one of two co-signers is unreachable. The fortress keeps running.") +
      attRow(renderTopbarAttestationBadge("unverified"), "Unverified", "The signature did not validate. The surface still works; lockdown is still available; the badge tells you to investigate.") +
      attRow(renderTopbarAttestationBadge("pending"), "Pending", "First-run state. Fortress is signing for the first time. Settles in seconds.") +
    '</div>' +
    // Per-agent
    '<div class="att-section">' +
      '<div class="att-section-head"><div>' +
        '<h2>Per-agent. In the agents list and inspect pane.</h2>' +
        '<p>A square chip beside each agent. Square because an agent is bounded; the fortress (a circle) contains it.</p>' +
      '</div><span class="label">agents view</span></div>' +
      '<div class="att-row">' +
        '<div class="demo" style="display:flex; gap:8px; flex-wrap:wrap;">' +
          renderAgentAttestationBadge("active") +
          renderAgentAttestationBadgeForState("degraded", "degraded") +
          renderAgentAttestationBadgeForState("unverified", "unverified") +
        '</div>' +
        '<div class="desc"><strong>Verified, degraded, unverified</strong>' +
          '<small>Color and the fill pattern carry meaning together. A solid square reads "attested" at a glance; a hatched square reads "trouble" at a glance, even monochrome.</small>' +
        '</div>' +
      '</div>' +
    '</div>' +
    // Per-action
    '<div class="att-section">' +
      '<div class="att-section-head"><div>' +
        '<h2>Per-action. Inline in the activity timeline.</h2>' +
        '<p>Each entry in any timeline carries a small signature fragment. Hover to expand. A tick instead of a fill keeps the row visually quiet at low resolution.</p>' +
      '</div><span class="label">timeline</span></div>' +
      '<div class="att-row">' +
        '<div class="demo" style="display:flex; gap:10px; flex-wrap:wrap; align-items:center;">' +
          '<span style="font-size:13px; color:var(--ink-2);">14:22:08 doc-reviewer summarized intake.pdf</span>' +
          renderActionAttestationBadge("verified", "9c7d..2a") +
        '</div>' +
        '<div class="desc"><strong>Verified action</strong>' +
          '<small>The most common shape. Two-byte signature fragment is enough; the full signature is one click away.</small>' +
        '</div>' +
      '</div>' +
      '<div class="att-row">' +
        '<div class="demo" style="display:flex; gap:10px; align-items:center;">' +
          '<span style="font-size:13px; color:var(--ink-2);">14:11:47 privacy filter redacted payload</span>' +
          renderActionAttestationBadge("degraded", "b440..71") +
        '</div>' +
        '<div class="desc"><strong>Degraded action</strong>' +
          '<small>The action signed, but the signature class was less than the policy preferred. Useful when a substrate is still warming up.</small>' +
        '</div>' +
      '</div>' +
      '<div class="att-row">' +
        '<div class="demo" style="display:flex; gap:10px; align-items:center;">' +
          '<span style="font-size:13px; color:var(--ink-2);">14:09:02 agent attempted external link</span>' +
          renderActionAttestationBadge("neutral", "--") +
        '</div>' +
        '<div class="desc"><strong>Neutral. Degrade, not destroy.</strong>' +
          '<small>The signer was unreachable. Rather than hide the action, the badge becomes neutral and a tooltip explains. The action is still recorded.</small>' +
        '</div>' +
      '</div>' +
    '</div>' +
    // Custody stub
    '<div class="att-section">' +
      '<div class="att-section-head"><div>' +
        '<h2>Custody. Stub for v1.x.</h2>' +
        '<p>A fourth class, surfaced conservatively. Reserved for forthcoming custody-provenance signatures (x402 payment receipts, ERC-8004 identity assertions). Visible, dashed, clearly stubbed.</p>' +
      '</div><span class="label">stub</span></div>' +
      '<div class="att-row">' +
        '<div class="demo">' +
          '<span class="att-custody" title="Custody-provenance, v1.x">' +
            '<span class="seal-stub"></span>' +
            '<span class="stub-tag">custody. stub</span>' +
          '</span>' +
        '</div>' +
        '<div class="desc"><strong>Custody. Stub.</strong>' +
          '<small>Dashed border signals "shape reserved, content pending." Will populate when custody signatures land in a future release. Cannot be confused with a verified badge at any zoom level.</small>' +
        '</div>' +
      '</div>' +
    '</div>' +
    // Tooltip
    '<div class="att-section">' +
      '<div class="att-section-head"><div>' +
        '<h2>Tooltip on failure.</h2>' +
        '<p>A failed badge is never silent. The tooltip explains in plain language, suggests one action, and confirms the surface is still working.</p>' +
      '</div><span class="label">degrade not destroy</span></div>' +
      '<div class="att-row">' +
        '<div class="demo">' +
          '<span class="att-tooltip">The signer at sig.fortress.local did not respond in 4s. Your fortress kept working. Try: open Health to see the signer status.</span>' +
        '</div>' +
        '<div class="desc"><strong>Plain-language tooltip</strong>' +
          '<small>Three lines, in order: what happened, what did not break, what to do. No jargon, no stack trace.</small>' +
        '</div>' +
      '</div>' +
    '</div>' +
  '</div>';
}
function attRow(demoHtml, strong, smallText) {
  return '<div class="att-row">' +
    '<div class="demo">' + demoHtml + '</div>' +
    '<div class="desc"><strong>' + escHtml(strong) + '</strong>' +
      '<small>' + escHtml(smallText) + '</small>' +
    '</div>' +
  '</div>';
}
// Gallery-only variant: render a per-agent badge for a given visual state
// (verified / degraded / unverified) without going through the agent
// status mapping. Used by renderAttestation to show all three states
// side by side as design reference.
function renderAgentAttestationBadgeForState(cls, label) {
  return '<span class="att-agent ' + escHtml(cls) + '" title="Agent attestation"><span class="mark"></span>' + escHtml(label) + '</span>';
}

function renderHoneypotPage() {
  const toolTraps = state.honeypot.toolTraps || [];
  const credentialTraps = state.honeypot.credentialTraps || [];
  const toolRows = toolTraps.length ? toolTraps.map(function (trap) {
    const activations = trap.activations || [];
    const latest = activations.length ? activations[activations.length - 1] : null;
    const followups = latest && latest.follow_up_tool_calls ? latest.follow_up_tool_calls : [];
    const followupText = followups.length
      ? followups.map(function (f) { return escHtml(f.tool_name) + " at " + escHtml(shortTime(f.called_at)); }).join(", ")
      : "No follow-up calls in the 5 minute window.";
    const latestText = latest
      ? escHtml(latest.caller_identity) + " invoked " + escHtml(trap.fake_tool_name) + " at " + escHtml(shortTime(latest.invoked_at)) + "; received the operator-configured fake response; followed up with " + followups.length + " calls."
      : "No invocations recorded.";
    return '<section class="card">' +
      '<div class="page-head" style="margin-bottom:8px;"><div>' +
        '<p class="eyebrow">Tool-call trap</p>' +
        '<h2>' + escHtml(trap.fake_tool_name) + '</h2>' +
      '</div><span class="label">' + escHtml(trap.catalog_visibility) + '</span></div>' +
      '<div class="layer-grid">' +
        '<div class="layer-card"><h4>Invocations</h4><p>' + escHtml(trap.invocation_count) + '</p></div>' +
        '<div class="layer-card"><h4>Last invocation</h4><p>' + escHtml(trap.last_invocation_at ? shortTime(trap.last_invocation_at) : "never") + '</p></div>' +
        '<div class="layer-card"><h4>Caller diversity</h4><p>' + escHtml(trap.caller_diversity) + '</p></div>' +
      '</div>' +
      '<p class="muted">' + latestText + '</p>' +
      '<p class="muted">Follow-up correlation: ' + followupText + '</p>' +
      (latest ? '<pre class="terminal-block">' + escHtml(JSON.stringify(latest.invocation_args || {}, null, 2)) + '</pre>' : '') +
    '</section>';
  }).join("") : '<section class="card"><h3>No tool-call traps deployed.</h3><p class="muted">Compile and deploy a tool_call honeypot to see catalog injections and invocations here.</p></section>';
  const credentialRows = credentialTraps.length ? credentialTraps.map(function (trap) {
    const accesses = trap.accesses || [];
    const attempts = trap.use_attempts || [];
    const latestAccess = accesses.length ? accesses[accesses.length - 1] : null;
    const latestAttempt = attempts.length ? attempts[attempts.length - 1] : null;
    const latestText = latestAccess
      ? escHtml(latestAccess.caller_identity) + " read " + escHtml(trap.fake_credential_name) + " from " + escHtml(latestAccess.emission_path) + " at " + escHtml(shortTime(latestAccess.accessed_at)) + "."
      : "No reads recorded.";
    const attemptText = latestAttempt
      ? escHtml(latestAttempt.caller_identity) + " attempted use against " + escHtml(latestAttempt.target_host) + " at " + escHtml(shortTime(latestAttempt.attempted_at)) + ". Castle Wall blocked the egress."
      : "No use attempts recorded.";
    return '<section class="card">' +
      '<div class="page-head" style="margin-bottom:8px;"><div>' +
        '<p class="eyebrow">Credential trap</p>' +
        '<h2>' + escHtml(trap.fake_credential_name) + '</h2>' +
      '</div><span class="label">' + escHtml(trap.visibility) + '</span></div>' +
      '<div class="layer-grid">' +
        '<div class="layer-card"><h4>Reads</h4><p>' + escHtml(trap.read_count) + '</p></div>' +
        '<div class="layer-card"><h4>Use attempts</h4><p>' + escHtml(trap.use_attempt_count) + '</p></div>' +
        '<div class="layer-card"><h4>Caller diversity</h4><p>' + escHtml(trap.caller_diversity) + '</p></div>' +
      '</div>' +
      '<p class="muted">Emission paths: ' + escHtml((trap.emission_paths || []).join(", ")) + '</p>' +
      '<p class="muted">' + latestText + '</p>' +
      '<p class="muted">' + attemptText + '</p>' +
    '</section>';
  }).join("") : '<section class="card"><h3>No credential traps deployed.</h3><p class="muted">Compile and deploy a credential honeypot to see broker, env, config, and use-attempt detections here.</p></section>';
  const error = state.honeypot.loadError
    ? '<p class="muted">Honeypot stats unavailable: ' + escHtml(state.honeypot.loadError) + '</p>'
    : '';
  const hasTraps = toolTraps.length > 0 || credentialTraps.length > 0;
  const createCta = !hasTraps
    ? '<section class="card"><h3>No honeypot traps deployed yet.</h3>' +
      '<p class="muted">Coming in v1.4: full create UI from this tab. For now, deploy honeypots via the auto-trigger ladder (<code>sanctuary auto-trigger promote --rule-type honeypot</code>) or by adding trap definitions to your fortress config.</p>' +
      '</section>'
    : '';
  return '<div class="page-head"><div>' +
    '<p class="eyebrow">Honeypots</p>' +
    '<h1>Honeypot traps.</h1>' +
    '<p class="sub">Fake tools and fake credentials. Reads, invocations, and attempted credential use create sentinel findings without revealing the trap.</p>' +
  '</div></div>' + error + createCta + credentialRows + toolRows;
}

function relTimeFromIso(iso) {
  if (!iso) return "";
  const d = new Date(iso);
  if (isNaN(d.getTime())) return iso;
  const diffMs = Date.now() - d.getTime();
  const diffSec = Math.max(0, Math.floor(diffMs / 1000));
  if (diffSec < 60) return diffSec + "s ago";
  const diffMin = Math.floor(diffSec / 60);
  if (diffMin < 60) return diffMin + "m ago";
  const diffHr = Math.floor(diffMin / 60);
  if (diffHr < 24) return diffHr + "h ago";
  const diffDay = Math.floor(diffHr / 24);
  return diffDay + "d ago";
}
function renderAgentsList() {
  if (!state.agents.length) return '<h1>Agents</h1>' +
    '<div class="agents-empty">' +
      '<div class="icon-frame"><div class="core"></div></div>' +
      '<h2>No protected agents yet.</h2>' +
      '<p>Protect an agent to give it a portable identity, a charter, and approval gates. Run <code>sanctuary protect</code> in any project where your agent lives.</p>' +
      '<div class="terminal-block"><span class="cmd"><span class="prompt">$</span>sanctuary protect</span></div>' +
    '</div>';
  const count = state.agents.length;
  const subCopy = count + ' protected. Click one to inspect its activity, policy, and pending approvals.';
  const rows = state.agents.map(function (a) {
    const map = STATUS_MAP[a.status] || STATUS_MAP.unknown;
    const dotCls = agentStateClass(a.status);
    const initials = agentInitials(a.agent_id);
    const role = escHtml(a.harness) + (a.model_provider && a.model_provider.model_id ? ' · ' + escHtml(a.model_provider.model_id) : '');
    const isSelected = state.selectedAgentId === a.agent_id;
    return '<div class="agent-row' + (isSelected ? ' selected' : '') + '" data-action="open-agent" data-agent-id="' + escHtml(a.agent_id) + '" role="button" tabindex="0" title="Open inspect panel for ' + escHtml(a.agent_id) + '">' +
      '<div class="agent-identity">' +
        '<div class="agent-glyph">' + escHtml(initials) + '</div>' +
        '<div class="agent-name">' +
          '<strong>' + escHtml(a.agent_id) + '</strong>' +
          '<small>' + role + '</small>' +
        '</div>' +
      '</div>' +
      '<span class="agent-state">' +
        '<span class="state-dot ' + dotCls + '"></span>' +
        escHtml(map.label) +
      '</span>' +
      renderAgentAttestationBadge(a.status) +
      '<span class="agent-last">' + escHtml(relTimeFromIso(a.last_activity_at)) + '</span>' +
      '</div>';
  }).join("\n");
  return '<div class="agents-wrap">' +
    '<div class="page-head">' +
      '<div>' +
        '<p class="eyebrow">Agents</p>' +
        '<h1>Agents.</h1>' +
        '<p class="sub">' + escHtml(subCopy) + '</p>' +
      '</div>' +
    '</div>' +
    '<div class="agents-layout">' +
      '<div class="agents-list">' +
        '<div class="agents-list-head">' +
          '<span>Agent</span><span>State</span><span>Attestation</span><span>Last seen</span>' +
        '</div>' +
        rows +
      '</div>' +
    '</div>' +
  '</div>';
}

function renderAgentDetail() {
  const a = state.agents.find(function (x) { return x.agent_id === state.selectedAgentId; });
  if (!a) return '<h1>Agent</h1><p class="muted">Agent not found. <a href="#agents">Back to list</a>.</p>';
  const map = STATUS_MAP[a.status] || STATUS_MAP.unknown;
  const events = state.activity.filter(function (e) { return e.agent_id === a.agent_id; }).slice(0, 50);
  const timeline = events.length
    ? events.map(function (e) {
        const t = renderTemplate(e.display_template_id, e.display_template_args);
        const badgeHtml = e.attestation
          ? ' ' + renderActionAttestationBadge(e.attestation.state, e.attestation.fragment)
          : '';
        return '<div class="row"><span class="muted">' + escHtml(shortTime(e.emitted_at)) + '</span><span>' + escHtml(t) + badgeHtml + '</span></div>';
      }).join("\n")
    : '<p class="muted">No activity yet.</p>';
  // WP-V1.2 reshape click-to-inspect surface. Clicking "Open inspect
  // panel" hits POST /api/hub/agents/:id/inspect/open synchronously and
  // renders recent activity + pending approvals + policy summary. The
  // chat surface was removed in the reshape; the panel is read-only and
  // re-fetches on each click (no streaming updates).
  const inspectPanel = renderAgentInspectPanel(a);
  // Inspect panel is the primary action surface; render it immediately
  // under the H1 above the Identity card so recent activity + pending
  // approvals are visible above the fold. Identity + Timeline drop to
  // reference position.
  return '<h1>' + escHtml(a.agent_id) + '</h1>' +
    inspectPanel +
    '<div class="card"><h3>Identity</h3>' +
      '<dl class="kv">' +
      '<dt>Harness</dt><dd class="mono">' + escHtml(a.harness) + '</dd>' +
      '<dt>Model</dt><dd class="mono">' + escHtml(a.model_provider.vendor) + " / " + escHtml(a.model_provider.model_id) + '</dd>' +
      '<dt>Policy</dt><dd class="mono">' + escHtml(a.policy_id) + '</dd>' +
      '<dt>Template</dt><dd class="mono">' + escHtml(a.channel_template_id || "no_template") + '</dd>' +
      '<dt>Status</dt><dd><span class="glyph ' + map.glyph + '"></span> ' + escHtml(map.label) + '</dd>' +
      '</dl>' +
    '</div>' +
    '<div class="card"><h3>Timeline</h3>' + timeline + '</div>';
}

// Inspect panel for the Agents view (WP-V1.2 reshape). Clicking the
// inspect affordance opens the panel synchronously via POST
// /api/hub/agents/:id/inspect/open. The panel is read-only:
// recent activity, pending Tier 1 approvals, policy summary. States:
//   1. No panel data yet: show "Open inspect panel" CTA.
//   1b. Optimistic-open in flight: render an interim "Opening..." pane.
//   2. Panel loaded: render activity feed + pending approvals + policy
//      summary. Operator can re-open to refresh.
function renderAgentInspectPanel(agent) {
  const ip = state.chat.inspect;
  const panel = ip.panelByAgentId[agent.agent_id] || null;
  const opening = ip.openingAgentId === agent.agent_id;
  const errorBanner = ip.error
    ? '<div class="banner banner-warn">' + escHtml(ip.error) + '</div>'
    : "";

  // State 2: panel loaded.
  // Sprint Piece 2 PR 4 polish: outer wrapper combines .card with
  // .inspect-pane (sticky right rail, internal scroll, sectioned body).
  // The .card class is preserved so the rendered surface keeps its
  // shared card chrome; .inspect-pane overrides .card padding so the
  // inspect-head and inspect-body control their own spacing per design.
  if (panel) {
    const dotCls = agentStateClass(agent.status);
    const stateMap = STATUS_MAP[agent.status] || STATUS_MAP.unknown;
    const activity = (panel.recent_activity || []).slice(0, 20);
    const activityHtml = activity.length
      ? '<div class="timeline">' +
        activity.map(function (e) {
          const t = renderTemplate(e.display_template_id, e.display_template_args);
          const badgeHtml = e.attestation
            ? renderActionAttestationBadge(e.attestation.state, e.attestation.fragment)
            : '';
          return '<div class="timeline-item ok">' +
            '<div class="ts">' + escHtml(shortTime(e.emitted_at)) + '</div>' +
            '<div class="what">' + escHtml(t) + '</div>' +
            (badgeHtml ? '<div class="att">' + badgeHtml + '</div>' : '') +
            '</div>';
        }).join("") +
        '</div>'
      : '<p class="muted">No recent activity for this agent.</p>';

    const approvals = panel.pending_approvals || [];
    const approvalsHtml = approvals.length
      ? approvals.map(function (item) {
          const promptText = renderTemplate(item.display_template_id, item.display_template_args);
          return '<div class="approval-row">' +
            '<div class="what">' +
              '<span class="pill tone-degraded">' + escHtml(item.tier || "tier1") + '</span>' +
              escHtml(promptText) +
            '</div>' +
            '<div class="actions">' +
              '<button class="btn" data-action="inbox-deny" data-item-id="' + escHtml(item.item_id) + '">Deny</button>' +
              '<button class="btn btn-primary" data-action="inbox-approve" data-item-id="' + escHtml(item.item_id) + '">Approve once</button>' +
            '</div>' +
            '</div>';
        }).join("")
      : '<p class="muted">No pending approvals routed through this agent.</p>';

    const policySection = panel.policy_summary
      ? '<div class="policy-line"><span class="k">Policy</span><span class="v">' + escHtml(panel.policy_summary.display_label || panel.policy_summary.policy_id) + '</span></div>' +
        (panel.policy_summary.channel_template_id
          ? '<div class="policy-line"><span class="k">Template</span><span class="v">' + escHtml(panel.policy_summary.channel_template_id) + '</span></div>'
          : '') +
        '<div class="policy-line"><span class="k">Bound</span><span class="v">' + escHtml(shortTime(panel.policy_summary.bound_at)) + '</span></div>'
      : '<div class="policy-line"><span class="k">Policy</span><span class="v">No bound policy yet.</span></div>';

    const modelLine = agent.model_provider
      ? '<div class="policy-line"><span class="k">Model</span><span class="v">' + escHtml(agent.model_provider.vendor) + ' / ' + escHtml(agent.model_provider.model_id) + '</span></div>'
      : '';

    return '<div class="card inspect-pane">' +
      '<div class="inspect-head">' +
        '<div class="row1">' +
          '<div class="agent-glyph">' + escHtml(agentInitials(agent.agent_id)) + '</div>' +
          '<h3>' + escHtml(agent.agent_id) + '</h3>' +
          '<span style="margin-left:auto;">' + renderAgentAttestationBadge(agent.status) + '</span>' +
        '</div>' +
        '<div class="meta">' +
          '<span class="pill ' + (dotCls === "live" ? "tone-verified" : "tone-degraded") + '"><span class="state-dot ' + dotCls + '" style="margin-right:4px;"></span>' + escHtml(stateMap.label) + '</span>' +
          '<span class="pill">opened ' + escHtml(shortTime(panel.opened_at)) + '</span>' +
          '<button class="btn btn-quiet" data-action="agent-inspect-open" data-agent-id="' + escHtml(agent.agent_id) + '" title="Refresh inspect panel">Refresh</button>' +
        '</div>' +
      '</div>' +
      '<div class="inspect-body">' +
        errorBanner +
        '<div class="inspect-section">' +
          '<h4>Pending approvals' + (approvals.length ? ' <span class="count">' + approvals.length + '</span>' : '') + '</h4>' +
          approvalsHtml +
        '</div>' +
        '<div class="inspect-section">' +
          '<h4>Recent activity</h4>' +
          activityHtml +
        '</div>' +
        '<div class="inspect-section">' +
          '<h4>Policy summary</h4>' +
          policySection +
        '</div>' +
        '<div class="inspect-section">' +
          '<h4>Identity</h4>' +
          '<div class="policy-line"><span class="k">Agent id</span><span class="v">' + escHtml(agent.agent_id) + '</span></div>' +
          '<div class="policy-line"><span class="k">Harness</span><span class="v">' + escHtml(agent.harness) + '</span></div>' +
          modelLine +
          '<div class="policy-line"><span class="k">Protected since</span><span class="v">' + escHtml(shortTime(agent.wrapped_at)) + '</span></div>' +
        '</div>' +
        '<p class="muted" style="margin-top:10px;font-size:12px;">' +
          '<a href="#activity?agent=' + escHtml(agent.agent_id) + '">View full activity</a> · ' +
          '<a href="#policy">Edit policy</a>' +
        '</p>' +
      '</div>' +
    '</div>';
  }

  // State 1b: optimistic-open in flight.
  if (opening) {
    return '<div class="card">' +
      '<h3>Inspect</h3>' +
      errorBanner +
      '<p class="muted">Opening inspect panel for ' + escHtml(agent.agent_id) + '...</p>' +
    '</div>';
  }

  // State 1: no panel data: CTA.
  return '<div class="card">' +
    '<h3>Inspect</h3>' +
    errorBanner +
    '<p>Open the inspect panel to see this agent\'s recent activity, ' +
      'pending Tier 1 approvals, and policy summary at a glance. ' +
      'Read-only; the panel re-fetches on each open.</p>' +
    '<button class="btn btn-primary" data-action="agent-inspect-open" data-agent-id="' + escHtml(agent.agent_id) + '">Open inspect panel</button>' +
  '</div>';
}

// ── Render: privacy ────────────────────────────────────────────────────
function renderPrivacyPage() {
  // Safe-metadata-only render (binding addendum 1.6). Content_hash visible
  // only as opaque hex with a tooltip; no raw_path, no raw_value, no
  // source bytes.
  const events = state.privacyEvents.slice(0, 50);
  if (!events.length) return '<h1>Privacy</h1>' +
    '<section class="card"><h3>No privacy events recorded yet.</h3>' +
    '<p class="muted">Privacy events appear when the privacy filter redacts, denies, or logs an outbound payload. Protect an agent with a privacy-minimization policy to start seeing events here.</p>' +
    '</section>';
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
    '<p class="muted">Per-agent toggles are read-only. <a href="#policy">Edit via Policy center</a>.</p>';
}

// ── Render: coordination ──────────────────────────────────────────────
function renderCoordinationPage() {
  const events = state.handoffEvents.slice(0, 100);
  if (!events.length) return '<h1>Coordination</h1>' +
    '<section class="card"><h3>No coordination flows recorded yet.</h3>' +
    '<p class="muted">Coordination flows appear when protected agents hand off tasks to each other inside this fortress. Protect two or more agents and initiate a handoff to see events here.</p>' +
    '</section>';
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
    '<p class="muted">Internal-only handoffs inside this fortress.</p>' +
    '<div class="card">' + rows + '</div>';
}

// ── Render: health ─────────────────────────────────────────────────────
function renderHealthPage() {
  const totalAgents = state.agents.length;
  const lockedDown = state.agents.filter(function (a) { return a.status === "locked_down"; }).length;
  const errored = state.agents.filter(function (a) { return a.status === "error"; }).length;
  const recentDenials = state.activity.filter(function (e) { return e.category === "denial"; }).length;
  return '<h1>Health</h1>' +
    '<p class="muted">Projected from existing data.</p>' +
    '<div class="card"><h3>Fortress at a glance</h3>' +
      '<dl class="kv">' +
      '<dt>Protected agents</dt><dd>' + escHtml(totalAgents) + '</dd>' +
      '<dt>Locked down</dt><dd>' + escHtml(lockedDown) + '</dd>' +
      '<dt>Errored</dt><dd>' + escHtml(errored) + '</dd>' +
      '<dt>Denials in feed</dt><dd>' + escHtml(recentDenials) + '</dd>' +
      '</dl>' +
    '</div>' +
    '<button class="btn" data-action="run-full-audit">Run full audit</button>';
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

// Card-grid polish (Sprint Piece 2 PR 3) maps the badge dot class onto
// the shaped glyph token. Sage circle for ok, ochre triangle for warn,
// rust diamond for fail. Keep aligned with .status-glyph rules in
// html.ts and the .intel-card-status modifier classes.
function statusGlyphClass(dotClass) {
  if (dotClass === "green") return "ok";
  if (dotClass === "yellow") return "warn";
  return "fail";
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
  // Wave 1 (2026-06-30) copy fix: the prior empty-state pointed at a dead
  // dead "sanctuary intelligence configure" command (no such CLI verb; a
  // substrate is picked in THIS dashboard's Intelligence picker, persisted via
  // /api/hub/intelligence/preferences). The corrected copy points operators at
  // the in-dashboard picker, and spells out the substrate privacy tradeoff
  // using the canonical strings from server/src/intelligence/templates.ts
  // (BACKEND_FALLBACK_STRINGS): local = queries never leave your machine;
  // Venice = contractual, not cryptographic; cloud/frontier = may log, expect
  // imperfect privacy. So the operator understands the privacy stakes BEFORE
  // they choose, on the first screen they see.
  if (state.intelligence.notConfigured) {
    return '<section class="intel-center">' +
      '<p class="eyebrow">INTELLIGENCE</p>' +
      '<h1>Pick a model for your fortress</h1>' +
      '<p class="intel-subtitle">No model is connected yet, so the concierge and other intelligence surfaces are quiet. Choose one to turn them on. Your choice decides where your questions go.</p>' +
      '<p class="intel-subtitle muted"><strong>Local model:</strong> Your queries never leave your machine. Capability is moderate; complex reasoning may underperform a frontier model. Needs 8GB RAM Apple Silicon M1+ or equivalent.</p>' +
      '<p class="intel-subtitle muted"><strong>Venice.ai:</strong> Queries reach Venice\'s relay during inference. Venice\'s contract states no retention or training on your data. Trust is contractual, not cryptographic. Capability higher than local.</p>' +
      '<p class="intel-subtitle muted"><strong>Frontier with PII filter:</strong> Queries reach the frontier provider after redaction. Highest capability. The provider may log queries per their terms. Redaction can fail on subtle PII; expect imperfect privacy.</p>' +
      '<p class="intel-subtitle muted">Choose and connect a model in the picker on this Intelligence screen (the cards appear once a substrate is bound). It also reads the substrate environment variables set when the dashboard launched.</p>' +
    '</section>';
  }
  if (state.intelligence.loadError) {
    return '<section class="intel-center">' +
      '<p class="eyebrow">INTELLIGENCE</p>' +
      '<h1>Could not load substrate status</h1>' +
      '<p class="intel-subtitle error-text">' + escHtml(state.intelligence.loadError) + '</p>' +
      '<p class="intel-subtitle muted">If this is a new fortress, pick a model in the Intelligence picker on this screen first (local keeps your queries on your machine; Venice.ai is contractual, not cryptographic; a frontier model is highest capability but may log queries, so expect imperfect privacy). The picker reads the substrate environment variables set when the dashboard launched.</p>' +
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
  const surfaceCards = SURFACES_ORDER.map(function (surfaceId) {
    const surfaceStatus = (status.surfaces || []).find(function (s) { return s.surface === surfaceId; });
    if (!surfaceStatus) {
      return '<div class="intel-row intel-card" data-intel-surface="' + escHtml(surfaceId) + '">' +
        '<div class="intel-card-head">' +
          '<div class="intel-card-name">' +
            '<strong>' + escHtml(SURFACE_LABELS[surfaceId] || surfaceId) + '</strong>' +
            '<small>' + escHtml(surfaceId) + '</small>' +
          '</div>' +
        '</div>' +
        '<div class="muted">No status reported.</div>' +
      '</div>';
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
    const glyphClass = statusGlyphClass(dotClass);
    const failures = surfaceStatus.recentFailures || [];
    const expanded = !!state.intelligence.expandedFailures[surfaceId];

    // Card foot. The failures toggle is the load-bearing affordance for
    // the rc.6 ZZ test (button[data-action="intel-failures-toggle"] with
    // text "recent failures (N)"). Pluralization is "failures" regardless
    // of N for backward compatibility with the seeded test contract.
    // Surface zero-failure state as a quiet mono note so the card still
    // has visual rhythm in its foot row.
    let footHtml;
    if (failures.length > 0) {
      const toggleLabel = (expanded ? "Hide" : "View") + " recent failures (" + failures.length + ")";
      footHtml =
        '<button class="intel-failures-toggle' + (expanded ? ' open' : '') + '" data-action="intel-failures-toggle" data-intel-surface="' + escHtml(surfaceId) + '">' +
          '<span class="caret"></span>' +
          escHtml(toggleLabel) +
        '</button>';
    } else {
      footHtml = '<span class="muted mono" style="font-size: 11px;">no recent failures</span>';
    }

    let failuresBlock = "";
    if (failures.length > 0 && expanded) {
      const rows = failures.slice().reverse().map(function (f) {
        return '<div class="intel-failure-row">' +
          '<span class="ts">' + escHtml(shortTime(f.ts)) + '</span>' +
          '<div>' +
            '<div class="err-class">' + escHtml(f.failureClass) + '</div>' +
            '<div>' + escHtml(f.snippet) + '</div>' +
          '</div>' +
        '</div>';
      }).join("");
      failuresBlock = '<div class="intel-failures">' + rows + '</div>';
    }

    return '<div class="intel-row intel-card" data-intel-surface="' + escHtml(surfaceId) + '">' +
      '<div class="intel-card-head">' +
        '<div class="intel-card-name">' +
          '<strong>' + escHtml(SURFACE_LABELS[surfaceId] || surfaceId) + '</strong>' +
          '<small>' + escHtml(surfaceId) + '</small>' +
        '</div>' +
        '<span class="intel-card-status ' + glyphClass + '" title="' + escHtml(statusLabel(surfaceStatus.health)) + '">' +
          '<span class="status-glyph ' + glyphClass + '"></span>' +
          escHtml(statusLabel(surfaceStatus.health)) +
        '</span>' +
      '</div>' +
      '<div class="intel-substrate">' +
        '<div class="sub-line primary">' +
          '<span>' + escHtml(currentBadge) + '</span>' +
          '<button class="btn-quiet" data-action="intel-picker-open" data-intel-surface="' + escHtml(surfaceId) + '">Change</button>' +
        '</div>' +
      '</div>' +
      '<div class="intel-row-tradeoff">' + escHtml(substrateTradeoff(substrate)) + '</div>' +
      '<div class="intel-card-foot">' + footHtml + '</div>' +
      failuresBlock +
    '</div>';
  }).join("\n");

  const hardware = status.hardware || {};
  const recommended = hardware.recommendedLocalModel ? (LOCAL_MODEL_LABELS[hardware.recommendedLocalModel] || hardware.recommendedLocalModel) : "(below baseline)";
  const ollamaLabel = hardware.ollamaReachable
    ? 'Reachable. Models present: ' + ((hardware.ollamaModels || []).length || 0)
    : 'Not reachable at ' + escHtml(config.ollama_endpoint || "http://localhost:11434");

  const modal = state.intelligence.picker.open ? renderIntelligencePicker() : "";

  return '<section class="intel-wrap">' +
    '<div class="page-head">' +
      '<div>' +
        '<p class="eyebrow">Intelligence</p>' +
        '<h1>Substrate routing.</h1>' +
        '<p class="sub">Six surfaces, six choices. Each surface picks where its thinking happens. Local for privacy. Hosted for capability. Hybrid for both.</p>' +
      '</div>' +
    '</div>' +
    '<div class="intel-grid">' + surfaceCards + '</div>' +
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
  // Bulk-apply toggle (Finding SS, v1.2.0-rc.1). Default ON. When ON the
  // save flow POSTs to /surfaces/all/choice; when OFF it POSTs to
  // /surfaces/:surface/choice. The H2 label tracks the toggle so the
  // operator sees what will happen before clicking Save.
  const heading = p.applyToAll
    ? "Pick a substrate for all surfaces"
    : "Pick a substrate for " + surfaceLabel;
  const applyToAllToggle =
    '<label class="intel-apply-to-all">' +
      '<input type="checkbox" data-action="intel-picker-toggle-apply-to-all"' +
        (p.applyToAll ? ' checked' : '') + '> ' +
      '<span>Apply to all surfaces (' + SURFACES_ORDER.length + ')</span>' +
      '<small class="muted">When on, this substrate + key applies to every surface in one save.</small>' +
    '</label>';
  const saveLabel = p.saving ? "Saving..." : "Save";
  return '<div class="intel-modal-backdrop" data-action="intel-picker-close-backdrop">' +
    '<div class="intel-modal" role="dialog" aria-label="Pick substrate" data-action="intel-picker-modal-stop">' +
      '<h2>' + escHtml(heading) + '</h2>' +
      '<p class="intel-modal-subtitle">' + escHtml(SUBSTRATE_TRADEOFFS[candidate] || "") + '</p>' +
      applyToAllToggle +
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
    if (e.status === 401) {
      state.intelligence.loadError = "Dashboard authentication required. Reload the page or re-launch the dashboard with: sanctuary dashboard --fortress <path>";
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
    if (e.status === 401) {
      state.intelligence.loadError = "Dashboard authentication required. Reload the page or re-launch the dashboard with: sanctuary dashboard --fortress <path>";
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
  // Default toggle ON for the operator-friendly bulk path. config flag
  // explicitly false flips it OFF so per-surface operators do not get
  // surprised by a bulk apply on subsequent picks.
  const applyToAll = config.apply_to_all_surfaces !== false;
  state.intelligence.picker = {
    open: true,
    surface: surfaceId,
    candidate: surfaceStatus ? surfaceStatus.chosen : "local",
    localModelPick: (config.local_model_picks || {})[surfaceId] || null,
    veniceApiKey: "",
    frontierProvider: "anthropic",
    frontierApiKey: "",
    saving: false,
    error: null,
    applyToAll: applyToAll
  };
  rerender();
}

function onIntelPickerClose() {
  state.intelligence.picker = {
    open: false, surface: null, candidate: null, localModelPick: null,
    veniceApiKey: "", frontierProvider: "anthropic", frontierApiKey: "",
    saving: false, error: null, applyToAll: true
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
    // Persist the toggle state so the picker reopens with the
    // operator's preference next time. Best-effort: a failure here does
    // not block the substrate save.
    try {
      await api("/intelligence/preferences/apply-to-all", {
        method: "POST",
        body: { value: !!p.applyToAll }
      });
    } catch (_e) { /* tolerate */ }
    if (p.applyToAll) {
      await api("/intelligence/surfaces/all/choice", {
        method: "POST",
        body: choiceBody
      });
    } else {
      await api("/intelligence/surfaces/" + encodeURIComponent(p.surface) + "/choice", {
        method: "POST",
        body: choiceBody
      });
    }
    await fetchIntelligenceState();
    onIntelPickerClose();
    const target = p.applyToAll
      ? "all surfaces"
      : (SURFACE_LABELS[p.surface] || p.surface);
    toast("Substrate updated for " + target + ".", "info");
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
    // Finding DDD (v1.2.0-rc.3): the operator just submitted a message
    // and a concierge reply just landed. Force scroll to bottom on the
    // next render so the new exchange is in view, even if the operator
    // had drifted up by a poll-cycle's worth of layout shift.
    c.pendingScroll = true;
  } catch (e) {
    c.error = e.message || "Concierge call failed.";
  } finally {
    c.sending = false;
    rerender();
  }
}

async function onAgentInspectOpen(agentId) {
  // WP-V1.2 reshape click-to-inspect: the operator's click on the
  // inspect affordance hits POST /api/hub/agents/:id/inspect/open
  // synchronously. Returns the panel data (recent activity + pending
  // approvals + policy summary). The panel is read-only; no streaming
  // updates. The operator can re-open to refresh.
  const ip = state.chat.inspect;
  ip.error = null;
  // Optimistic render: drop the CTA immediately so the operator sees
  // the click registered. The panel swaps in as soon as the route
  // returns. On error, the optimistic state is rolled back by the
  // catch branch (no panel data to render).
  ip.openingAgentId = agentId;
  rerender();
  try {
    const res = await api("/agents/" + encodeURIComponent(agentId) + "/inspect/open", {
      method: "POST",
      body: {}
    });
    const panel = (res.data && res.data.panel) || null;
    if (panel && panel.agent_id) {
      ip.panelByAgentId[panel.agent_id] = panel;
    } else {
      ip.error = "Inspect panel returned an unexpected shape.";
    }
  } catch (e) {
    ip.error = e.message || "Could not open inspect panel.";
  } finally {
    ip.openingAgentId = null;
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
    : '<tr><td colspan="7" class="muted">No protected agents yet.</td></tr>';
  return '<section class="policy-center">' +
    '<p class="eyebrow">POLICY CENTER</p>' +
    '<h1>One screen for every rule</h1>' +
    '<p class="policy-subtitle">Templates, per-agent rules, egress allowlists, retention, budgets, and privacy-minimization settings. Edits write a signed receipt; agents pick up changes within one tool-call cycle.</p>' +
    '<section class="policy-panel"><h2>Channel templates · ' + CHANNEL_TEMPLATES.length + ' shipped</h2><div class="template-grid">' + tmplCards + '</div></section>' +
    '<section class="policy-panel"><h2>Per-agent rules</h2>' +
      '<div class="rules-scroll"><table class="rules-table">' +
      '<thead><tr><th>AGENT</th><th>TEMPLATE</th><th>ALLOW / BLOCK</th><th>BUDGET</th><th>RETENTION</th><th>MINIMIZE</th><th>APPROVALS</th></tr></thead>' +
      '<tbody>' + rows + '</tbody></table></div>' +
    '</section>' +
  '</section>';
}

function renderAutoTriggerPage() {
  const rules = state.autoTrigger.rules || [];
  const recs = state.autoTrigger.recommendations || [];
  const summary = rules.length
    ? '<div class="auto-trigger-rule-list">' + rules.map(renderAutoTriggerRuleRow).join("") + '</div>'
    : '<p class="muted">No auto-trigger ladders configured. Ladders appear here after a sentinel, anomaly detector, or honeypot records its first finding. Use <code>sanctuary auto-trigger promote</code> to create one.</p>';
  const body = recs.length
    ? '<div class="recommendation-list">' + recs.map(function (r) {
        const hs = r.history_summary || {};
        const approval = Math.round(((hs.operator_approval_rate || 0) * 100));
        const cancel = hs.operator_cancel_rate == null ? null : Math.round(hs.operator_cancel_rate * 100);
        const revoke = hs.operator_revocation_rate == null ? null : Math.round(hs.operator_revocation_rate * 100);
        const suppressed = r.suppressed_until ? '<span class="pill tone-degraded">cool-down until ' + escHtml(shortTime(r.suppressed_until)) + '</span>' : '';
        return '<article class="recommendation-row">' +
          '<div>' +
            '<h3>' + escHtml(r.rule_id) + '</h3>' +
            '<p>' + escHtml(r.recommendation_reason) + '</p>' +
            '<div class="recommendation-stats">' +
              '<span class="pill">rung ' + escHtml(r.current_rung) + ' to ' + escHtml(r.recommended_rung) + '</span>' +
              '<span class="pill">fires ' + escHtml(hs.fires_in_window || 0) + '</span>' +
              '<span class="pill">approved ' + escHtml(approval) + '%</span>' +
              (cancel === null ? '' : '<span class="pill">canceled ' + escHtml(cancel) + '%</span>') +
              (revoke === null ? '' : '<span class="pill">revoked ' + escHtml(revoke) + '%</span>') +
              '<span class="pill tone-info">' + escHtml(r.confidence) + '</span>' +
              suppressed +
            '</div>' +
          '</div>' +
          '<div class="recommendation-actions">' +
            '<button class="btn" data-action="auto-trigger-reject" data-rule-id="' + escHtml(r.rule_id) + '">Reject</button>' +
            '<button class="btn btn-primary" data-action="auto-trigger-accept" data-rule-id="' + escHtml(r.rule_id) + '">Accept</button>' +
          '</div>' +
        '</article>';
      }).join("") + '</div>'
    : '<p class="muted">No active recommendations.</p>';
  const error = state.autoTrigger.loadError
    ? '<p class="muted">Auto-trigger recommendations unavailable: ' + escHtml(state.autoTrigger.loadError) + '</p>'
    : '';
  return '<section class="policy-center">' +
    '<p class="eyebrow">AUTO-TRIGGER LADDER</p>' +
    '<h1>Calibration <span class="pill tone-info">operator controlled</span></h1>' +
    '<p class="policy-subtitle">Each rule starts operator-approved. Thresholds, cancel windows, and rung changes stay local to this fortress and write an audit receipt.</p>' +
    '<section class="policy-panel"><h2>Rules</h2>' + error + summary + '</section>' +
    '<section class="policy-panel"><h2>Recommendations</h2>' + error + body + '</section>' +
  '</section>';
}

function renderAutoTriggerRuleRow(rule) {
  const o = rule.threshold_overrides || {};
  const history = (rule.history || []).slice(-30);
  const recent = history.slice(-6).reverse();
  const trend = renderAutoTriggerTrend(history);
  const saving = state.autoTrigger.savingRuleId === rule.rule_id;
  const recentHtml = recent.length
    ? recent.map(function (h) {
        return '<span class="history-chip ' + escHtml(h.outcome) + '" title="' + escHtml(shortTime(h.observed_at)) + '">' + escHtml(h.outcome) + '</span>';
      }).join("")
    : '<span class="muted">No recent action attempts.</span>';
  return '<article class="auto-trigger-rule-row">' +
    '<div class="auto-trigger-rule-head">' +
      '<div><h3>' + escHtml(rule.rule_id) + '</h3><p>' + escHtml(rule.rule_type) + ' rule. Updated ' + escHtml(shortTime(rule.updated_at)) + '.</p></div>' +
      '<span class="rung-badge">rung ' + escHtml(rule.current_rung) + '</span>' +
    '</div>' +
    '<div class="auto-trigger-rule-grid">' +
      '<div class="auto-trigger-trend" aria-label="last 30 action attempts">' + trend + '</div>' +
      '<div class="history-strip">' + recentHtml + '</div>' +
    '</div>' +
    '<div class="auto-trigger-form">' +
      '<label>Warn sigma<input data-action="auto-trigger-input" data-rule-id="' + escHtml(rule.rule_id) + '" data-field="warn_sigma" type="number" step="0.1" min="0" value="' + escHtml(o.warn_sigma == null ? "" : o.warn_sigma) + '"></label>' +
      '<label>Alert sigma<input data-action="auto-trigger-input" data-rule-id="' + escHtml(rule.rule_id) + '" data-field="alert_sigma" type="number" step="0.1" min="0" value="' + escHtml(o.alert_sigma == null ? "" : o.alert_sigma) + '"></label>' +
      '<label>Promotion fires<input data-action="auto-trigger-input" data-rule-id="' + escHtml(rule.rule_id) + '" data-field="promotion_fire_count" type="number" step="1" min="1" value="' + escHtml(o.promotion_fire_count == null ? "" : o.promotion_fire_count) + '"></label>' +
      '<label>Window days<input data-action="auto-trigger-input" data-rule-id="' + escHtml(rule.rule_id) + '" data-field="promotion_window_days" type="number" step="1" min="1" value="' + escHtml(o.promotion_window_days == null ? "" : o.promotion_window_days) + '"></label>' +
      '<label>Cancel seconds<input data-action="auto-trigger-input" data-rule-id="' + escHtml(rule.rule_id) + '" data-field="cancel_window_seconds" type="number" step="1" min="1" max="3600" value="' + escHtml(rule.cancel_window_seconds || 60) + '"></label>' +
      '<button class="btn btn-primary" data-action="auto-trigger-threshold-save" data-rule-id="' + escHtml(rule.rule_id) + '"' + (saving ? ' disabled' : '') + '>Save</button>' +
    '</div>' +
  '</article>';
}

function renderAutoTriggerTrend(history) {
  if (!history.length) return '<span class="muted">No 30-day trend yet.</span>';
  return history.slice(-30).map(function (h) {
    const cls = h.outcome === "auto_proceeded" || h.outcome === "operator_approved" ? "good" :
      h.outcome === "operator_canceled" || h.outcome === "operator_revoked" ? "warn" : "pending";
    return '<span class="trend-bar ' + cls + '" title="' + escHtml(h.outcome + " at " + shortTime(h.observed_at)) + '"></span>';
  }).join("");
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
  const verifyCmd = "sanctuary verify-exit-bundle &lt;bundle_dir&gt;";
  const importCmd = "sanctuary import-exit-bundle &lt;bundle_dir&gt;";
  const step4Body = '<p class="muted">Run on a fresh shell:</p><pre class="code-block">' + verifyCmd + '</pre>' +
    '<button class="btn" data-action="exit-mark-verified">Mark verified</button>';
  const step5Body = '<p class="muted">Run this command on the destination fortress, not on this one. The destination will prompt for the bundle source passphrase or recovery key.</p><pre class="code-block">' + importCmd + '</pre>';
  const step6Body = '<p class="muted">Optional. Re-protect the destination harness using <code>sanctuary protect</code>. See <a href="#" data-action="open-harness-doc">harness compatibility matrix</a>.</p>';
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
function normalizeInboxPrefs(raw) {
  const source = raw && typeof raw === "object" ? raw : {};
  return {
    search: typeof source.search === "string" ? source.search : "",
    source: typeof source.source === "string" ? source.source : "",
    severity: typeof source.severity === "string" ? source.severity : "",
    agent: typeof source.agent === "string" ? source.agent : "",
    from: typeof source.from === "string" ? source.from : "",
    to: typeof source.to === "string" ? source.to : ""
  };
}

async function loadInboxPrefs() {
  try {
    const res = await fetch(INBOX_PREFS, {
      headers: TOKEN ? { "Authorization": "Bearer " + TOKEN } : {},
      cache: "no-store"
    });
    if (!res.ok) return;
    const body = await res.json();
    state.inboxOps.filters = normalizeInboxPrefs(body && body.data && body.data.filters);
  } catch (_) {}
}

async function saveInboxPrefs() {
  try {
    await fetch(INBOX_PREFS, {
      method: "PUT",
      headers: Object.assign({ "Content-Type": "application/json" }, TOKEN ? { "Authorization": "Bearer " + TOKEN } : {}),
      cache: "no-store",
      body: JSON.stringify({ filters: normalizeInboxPrefs(state.inboxOps.filters) })
    });
  } catch (_) {}
}

function inboxOption(value, bucket) {
  const selected = (bucket === "severity" ? state.inboxOps.filters.severity : state.inboxOps.filters.source) === value;
  return '<option value="' + escHtml(value) + '"' + (selected ? ' selected' : '') + '>' + escHtml(value) + '</option>';
}

function inboxAgentOptions() {
  const seen = {};
  state.inbox.forEach(function (i) {
    if (i.agent_id) seen[i.agent_id] = true;
    if (i.display_template_args && i.display_template_args.agent_id) seen[i.display_template_args.agent_id] = true;
  });
  return Object.keys(seen).sort().map(function (agent) {
    return '<option value="' + escHtml(agent) + '"' + (state.inboxOps.filters.agent === agent ? ' selected' : '') + '>' + escHtml(agent) + '</option>';
  }).join("");
}

function filterInbox(items) {
  const f = state.inboxOps.filters;
  const q = f.search.trim().toLowerCase();
  const fromMs = f.from ? Date.parse(f.from + "T00:00:00.000Z") : null;
  const toMs = f.to ? Date.parse(f.to + "T23:59:59.999Z") : null;
  return items.filter(function (i) {
    const args = i.display_template_args || {};
    const agent = i.agent_id || args.agent_id || "";
    const severity = i.severity || args.severity || "";
    const source = i.source_class || i.kind || "";
    const when = Date.parse(i.created_at || i.observed_at || i.timestamp || "");
    const text = (renderTemplate(i.display_template_id, args) + " " + JSON.stringify(args)).toLowerCase();
    if (f.source && source !== f.source) return false;
    if (f.severity && severity !== f.severity) return false;
    if (f.agent && agent !== f.agent) return false;
    if (fromMs !== null && Number.isFinite(when) && when < fromMs) return false;
    if (toMs !== null && Number.isFinite(when) && when > toMs) return false;
    if (q && text.indexOf(q) < 0) return false;
    return true;
  });
}

// Wave 1 (2026-06-30): the right rail is now a calm two-element column:
// the click-to-clear approvals queue + ambient posture. The heavy six-field
// inbox filter panel and the full multi-kind inbox moved OFF the rail to the
// Activity screen (renderActivityScreen); the rail holds only what is
// "waiting on you" plus an at-a-glance "how protected am I right now".
//
// SECURITY (HIGH, non-negotiable): each Approve/Deny tile issues the
// IDENTICAL operator-bearer-token-gated request the inbox path uses, by
// calling onInboxAction(itemId, action) -> api("/inbox/:id/approve|deny",
// {method:"POST"}). There is NO new approve path, NO loopback shortcut, NO
// token in served HTML (api() reads TOKEN from sessionStorage at runtime).
// A tokenless POST is rejected by the requireToken chokepoint in
// hub/api-router.ts (#823). See test/dashboard/v1_1/queue-approve-token-gate.test.ts.
function pendingApprovalItems() {
  // Pending Tier-1 approvals, scoped to the selected agent when one is
  // chosen. These are the only items the rail queue shows; everything else
  // (privacy events, budget warnings, blocked egress) lives on Activity.
  const scope = state.agentScope.selectedAgentId;
  return state.inbox.filter(function (i) {
    if (i.resolved) return false;
    if (i.kind !== "approval_pending") return false;
    if (i.tier !== "tier1" && i.tier !== "tier2") return false;
    if (scope && (i.agent_id || "") !== scope) return false;
    return true;
  });
}

// Wave 1: the fortress-column agents card and Recognition Layer health card
// previously lived on the right rail. They are real surfaces (agent
// lifecycle controls + did:web rotation), so they were relocated to the
// Activity screen rather than removed; the markup, data-action hooks, and
// capability-gating logic are preserved verbatim. The rail keeps only the
// approvals queue + ambient posture.
function renderFortressAgentsCard() {
  return state.agents.length
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
        // Click-to-inspect: the head sub-row is the click target. A click
        // navigates to agent-detail and opens the read-only inspect panel
        // synchronously via the WP-V1.2 reshape route. Lifecycle buttons in
        // agent-row-actions still take precedence (the dispatcher walks up to
        // the closest data-action ancestor; buttons are siblings, not
        // children, of the head).
        return '<div class="row agent-row" data-agent-row="' + escHtml(a.agent_id) + '">' +
          '<div class="agent-row-head" data-action="agent-row-inspect-open" data-agent-id="' + escHtml(a.agent_id) + '" role="button" tabindex="0" title="Open inspect panel for ' + escHtml(a.agent_id) + '">' +
            '<span class="glyph ' + map.glyph + '" title="' + escHtml(REASON_LABELS[a.status_reason_class] || "") + '"></span>' +
            '<div class="grow"><strong>' + escHtml(a.agent_id) + '</strong></div>' +
            '<span class="pill">' + escHtml(map.label) + '</span>' +
          '</div>' +
          '<div class="agent-row-actions">' + buttons + '</div>' +
          '</div>';
      }).join("\n")
    : '<p class="muted">No agents protected.</p>';
}

function renderRecognitionHealthCard() {
  const recognition = state.recognition.health;
  if (state.recognition.error) {
    return '<p class="muted">Recognition Layer health unavailable: ' + escHtml(state.recognition.error) + '</p>';
  }
  if (!recognition) {
    return '<p class="muted">Loading Recognition Layer health.</p>';
  }
  if (!recognition.configured) {
    return '<p class="muted">No did:web identifier registered. Run <code>sanctuary did-web issue --authority-host &lt;host&gt;</code>.</p>';
  }
  const last = recognition.last_rotation
    ? shortTime(recognition.last_rotation.rotated_at) + ' (' + recognition.last_rotation.reason + ')'
    : 'never';
  const history = recognition.key_history && recognition.key_history.length
    ? recognition.key_history.slice().reverse().slice(0, 4).map(function (h) {
        return '<div class="row"><div class="grow"><span class="mono">' + escHtml(shortTime(h.rotated_at)) + '</span><br><span class="muted">' + escHtml(h.reason) + '</span></div><span class="pill">' + escHtml(h.new_verification_method_id.split("#").pop() || "key") + '</span></div>';
      }).join("")
    : '<p class="muted">No rotations yet.</p>';
  return '<dl class="kv">' +
    '<dt>Identifier</dt><dd class="mono">' + escHtml(recognition.identifier) + '</dd>' +
    '<dt>Last rotation</dt><dd>' + escHtml(last) + '</dd>' +
    '<dt>Next periodic</dt><dd>' + escHtml(recognition.days_until_recommended_rotation) + ' days</dd>' +
    '</dl>' +
    '<button class="btn btn-danger" data-action="did-web-rotate-compromised"' + (state.recognition.rotating ? ' disabled' : '') + '>' + (state.recognition.rotating ? 'Rotating...' : 'Compromised rotation') + '</button>' +
    '<div style="margin-top:8px;">' + history + '</div>';
}

function renderApprovalTile(i) {
  const text = renderTemplate(i.display_template_id, i.display_template_args);
  const agentId = i.agent_id || (i.display_template_args && i.display_template_args.agent_id) || "this fortress";
  return '<div class="approval-tile" data-approval-tile="' + escHtml(i.item_id) + '">' +
    '<div class="at-what">' + escHtml(text) + '</div>' +
    '<div class="at-agent"><span class="ad"></span>' + escHtml(agentId) + '</div>' +
    '<div class="at-actions">' +
      '<button class="btn btn-sm at-approve" data-action="inbox-approve" data-item-id="' + escHtml(i.item_id) + '">Approve</button>' +
      '<button class="btn btn-sm at-deny" data-action="inbox-deny" data-item-id="' + escHtml(i.item_id) + '">Deny</button>' +
    '</div>' +
  '</div>';
}

function renderFortress() {
  const fortress = document.getElementById("fortress");
  if (!fortress) return;
  const pending = pendingApprovalItems();
  const countCls = pending.length ? "count" : "count zero";
  const queueBody = pending.length
    ? '<div class="approval-queue" id="approval-queue">' + pending.map(renderApprovalTile).join("") + '</div>'
    : '<div class="queue-empty"><span class="qe-check"></span>Nothing waiting on you.</div>';

  // Ambient posture: honest, glanceable. The seal mirrors the top bar; the
  // one-line "what's protecting you" uses NAMED layers only (no L-numbers).
  const seal = deriveSeal();
  const scopeLabel = state.agentScope.selectedAgentId
    ? escHtml(state.agentScope.selectedAgentId)
    : "All agents";
  const fortressLabel = escHtml(config.tenantName || config.fortressId || "this fortress");
  var protectingLine;
  if (seal.arm === "armed") {
    protectingLine = "Castle Wall is enforcing on this machine. Sentinels watch every wrapped agent, and the Charter holds anything risky for your approval.";
  } else if (seal.arm === "locked_down") {
    protectingLine = "This fortress is locked down. Wrapped agents are held until you lift it. The Charter still gates every risky action.";
  } else if (seal.arm === "degraded") {
    protectingLine = "Castle Wall protection is degraded right now. Sentinels still watch your wrapped agents and the Charter still holds risky actions for your approval. Check the Health screen.";
  } else {
    protectingLine = "Castle Wall enforcement is not confirmed on this machine right now. Sentinels still watch your wrapped agents and the Charter still holds risky actions for your approval.";
  }
  const wrapped = state.agents.length;
  const federationState = (state.posture.data && state.posture.data.federation && state.posture.data.federation.operator_cloud_nodes)
    ? "On" : "Off";

  fortress.innerHTML = [
    '<div class="rail-section">',
      '<div class="rail-section-label">Waiting on you <span class="' + countCls + '" id="queue-count">' + pending.length + '</span></div>',
      queueBody,
    '</div>',
    '<div class="rail-section">',
      '<div class="rail-section-label" style="color:var(--ink-4)">Right now</div>',
      '<div class="ambient-posture">',
        '<div class="ambient-seal tone-' + seal.tone + '">',
          '<span class="as-glyph"></span>',
          '<span class="as-text"><strong>' + escHtml(seal.word) + '</strong><small>' + scopeLabel + ' &middot; ' + fortressLabel + '</small></span>',
        '</div>',
        '<div class="ambient-line"><span class="lead">What is protecting you</span>' + escHtml(protectingLine) + '</div>',
        '<div class="ambient-stats">',
          '<div class="ambient-stat"><span class="n">' + wrapped + '</span><span class="l">Wrapped</span></div>',
          '<div class="ambient-stat"><span class="n">' + pending.length + '</span><span class="l">Waiting</span></div>',
          '<div class="ambient-stat"><span class="n">' + federationState + '</span><span class="l">Federation</span></div>',
        '</div>',
      '</div>',
    '</div>'
  ].join("");
}

// Wave 1 (2026-06-30): the Activity screen. The heavy six-field inbox
// filter panel + the full multi-kind inbox (privacy events, blocked egress,
// budget warnings, recovery prompts, agent errors, AND the tiered approvals)
// moved here OFF the right rail, where power-querying belongs. The rail now
// shows only the click-to-clear approvals queue. This renderer reuses the
// EXACT filter panel + inbox-row markup that previously lived inline in the
// rail, including the same data-action hooks, so the batch toolbar, snooze
// dialog, and per-item approve/deny continue to route through the same
// token-gated paths (onInboxAction -> api()). No behavior change; only the
// home of the panel moved.
function renderActivityScreen() {
  const visibleInbox = filterInbox(state.inbox.filter(function (i) { return !i.resolved; }));
  const selectedIds = Object.keys(state.inboxOps.selected).filter(function (id) { return state.inboxOps.selected[id]; });
  const batchToolbar = selectedIds.length
    ? '<div class="toolbar" style="margin-bottom:8px;">' +
        '<span class="pill">' + selectedIds.length + ' selected</span>' +
        '<button class="btn" data-action="inbox-batch-archive">Archive</button>' +
        '<button class="btn" data-action="inbox-batch-dismiss">Dismiss</button>' +
        '<button class="btn" data-action="inbox-batch-snooze-open">Snooze</button>' +
        '<button class="btn btn-danger" data-action="inbox-batch-delete">Delete</button>' +
      '</div>'
    : "";
  const snoozeDialog = state.inboxOps.snoozeDialog
    ? '<div class="modal-backdrop"><div class="modal"><h3>Snooze</h3><div class="toolbar">' +
        '<button class="btn" data-action="inbox-batch-snooze" data-snooze-ms="3600000">1h</button>' +
        '<button class="btn" data-action="inbox-batch-snooze" data-snooze-ms="14400000">4h</button>' +
        '<button class="btn" data-action="inbox-batch-snooze" data-snooze-ms="86400000">1d</button>' +
        '<button class="btn" data-action="inbox-batch-snooze" data-snooze-ms="604800000">1w</button>' +
        '<input class="input" data-action="inbox-snooze-custom" type="datetime-local">' +
        '<button class="btn" data-action="inbox-batch-snooze-custom">Custom</button>' +
        '<button class="btn" data-action="inbox-batch-snooze-close">Cancel</button>' +
      '</div></div></div>'
    : "";
  const filterPanel =
    '<div class="toolbar" style="align-items:flex-end;flex-wrap:wrap;margin-bottom:8px;">' +
      '<label>Search<br><input class="input" data-action="inbox-filter-search" value="' + escHtml(state.inboxOps.filters.search) + '"></label>' +
      '<label>Source<br><select class="input" data-action="inbox-filter-source"><option value="">Any</option>' + inboxOption("blocked_egress") + inboxOption("privacy_event") + inboxOption("budget_warning") + inboxOption("recovery_prompt") + inboxOption("agent_error") + inboxOption("approval") + inboxOption("sentinel_finding") + '</select></label>' +
      '<label>Severity<br><select class="input" data-action="inbox-filter-severity"><option value="">Any</option>' + inboxOption("info", "severity") + inboxOption("warn", "severity") + inboxOption("alert", "severity") + inboxOption("critical", "severity") + '</select></label>' +
      '<label>Agent<br><select class="input" data-action="inbox-filter-agent"><option value="">Any</option>' + inboxAgentOptions() + '</select></label>' +
      '<label>From<br><input class="input" data-action="inbox-filter-from" type="date" value="' + escHtml(state.inboxOps.filters.from) + '"></label>' +
      '<label>To<br><input class="input" data-action="inbox-filter-to" type="date" value="' + escHtml(state.inboxOps.filters.to) + '"></label>' +
    '</div>';
  var inboxRows;
  if (!visibleInbox.length) {
    inboxRows = '<p class="muted">Nothing pending.</p>';
  } else {
    var tier1Items = visibleInbox.filter(function (i) { return i.kind === "approval_pending" && i.tier === "tier1"; });
    var tier2Items = visibleInbox.filter(function (i) { return i.kind === "approval_pending" && i.tier === "tier2"; });
    var otherItems = visibleInbox.filter(function (i) { return i.kind !== "approval_pending" || (i.tier !== "tier1" && i.tier !== "tier2"); });
    function renderInboxRow(i) {
      var text = renderTemplate(i.display_template_id, i.display_template_args);
      var actions = inboxActions(i);
      var buttons = actions.map(function (act) {
        return '<button class="btn" data-action="inbox-' + act + '" data-item-id="' + escHtml(i.item_id) + '">' + INBOX_ACTION_LABEL[act] + '</button>';
      }).join("");
      var tierBadge = i.kind === "approval_pending"
        ? '<span class="pill">' + escHtml(i.tier) + '</span>'
        : '<span class="pill">' + escHtml(i.kind) + '</span>';
      return '<div class="row" data-inbox-row="' + escHtml(i.item_id) + '" data-inbox-kind="' + escHtml(i.kind) + '"' +
        (i.kind === "approval_pending" ? ' data-inbox-tier="' + escHtml(i.tier) + '"' : '') + '>' +
        '<input type="checkbox" data-action="inbox-select" data-item-id="' + escHtml(i.item_id) + '"' + (state.inboxOps.selected[i.item_id] ? ' checked' : '') + '>' +
        '<div class="grow">' + escHtml(text) + '</div>' +
        tierBadge +
        '<button class="btn" data-action="inbox-snooze-menu" data-item-id="' + escHtml(i.item_id) + '" title="Snooze">...</button>' +
        '<div style="display:flex;gap:4px;">' + buttons + '</div>' +
        '</div>';
    }
    var sections = [];
    if (tier1Items.length) sections.push('<h4 class="inbox-group-head">Tier 1 approvals</h4>' + tier1Items.map(renderInboxRow).join("\n"));
    if (tier2Items.length) sections.push('<h4 class="inbox-group-head">Tier 2 approvals</h4>' + tier2Items.map(renderInboxRow).join("\n"));
    if (otherItems.length) sections.push((tier1Items.length || tier2Items.length ? '<h4 class="inbox-group-head">Other</h4>' : '') + otherItems.map(renderInboxRow).join("\n"));
    inboxRows = sections.join("\n");
  }
  const total = state.inbox.filter(function (i) { return !i.resolved; }).length;
  return [
    '<section class="concierge-wrap">',
      '<div class="page-head"><div>',
        '<p class="eyebrow">Activity</p>',
        '<h1>Everything across your fortress.</h1>',
        '<p class="sub">Approvals, blocked actions, privacy events, and budget warnings, with filters to find one. Approve or deny right here. Anything waiting on you also shows in the rail.</p>',
      '</div></div>',
      '<section class="card">',
        '<h3>This fortress</h3>',
        (config.tenantName ? '<p><strong>' + escHtml(config.tenantName) + '</strong></p>' : ''),
        '<p class="muted mono">' + escHtml(config.fortressId || "(local)") + '</p>',
        '<p class="muted">Operator: ' + escHtml(config.identityId || "(unknown)") + '</p>',
      '</section>',
      '<section class="card"><h3>Inbox (' + total + ')</h3>' + filterPanel + batchToolbar + inboxRows + snoozeDialog + '</section>',
      '<section class="card"><h3>Agents (' + state.agents.length + ')</h3>' + renderFortressAgentsCard() + '</section>',
      '<section class="card"><h3>Recognition Layer health</h3>' + renderRecognitionHealthCard() + '</section>',
    '</section>'
  ].join("");
}

// ── Posture screen (one-surface fold, 2026-06-30) ───────────────────────
// The full posture detail folded into the single default surface. Reuses the
// EXISTING /api/posture/* data (state.posture.home, fetched by fetchPostureHome)
// and renders the same evidence the standalone posture board showed: the six
// metric cards (Protection Requested, Enforcement Confirmed, Castle Wall,
// Approvals Waiting, Open Anomalies, Audit Chain), Today's Story with the
// plain-summary toggle, the Anomaly Findings list, and the per-agent rows that
// link out to the per-agent drill-down (/posture/agent/:id) and the Evidence
// view (/posture/evidence). HONESTY: Castle Wall reads green only on an "armed"
// arm-state; each agent reads green only on confirmed live enforcement; the
// audit chain reads VERIFIED only when chain_verified is true. Named layers
// only (no L-numbers); no em-dashes in user-visible copy.
function postureWallLabel(armState) {
  if (armState === "armed") return { cls: "pill tone-verified", text: "Enforcing" };
  if (armState === "degraded") return { cls: "pill tone-degraded", text: "Degraded" };
  if (armState === "not_installed") return { cls: "pill", text: "Not installed" };
  if (armState === "locked_down") return { cls: "pill tone-locked", text: "Locked down" };
  return { cls: "pill", text: "Unknown" };
}
function postureMetricCard(value, label) {
  return '<div class="posture-metric"><span class="pm-v">' + value + '</span><span class="pm-l">' + escHtml(label) + '</span></div>';
}
function renderPostureStory(d) {
  if (state.posture.storyPlain) {
    const chainText = d.chain_verified
      ? "The audit log verified clean: no tampering."
      : "The audit log is unverified: " + escHtml(d.integrity_finding_count) + " integrity finding(s).";
    return '<p>Today your agents ran <strong>' + escHtml(d.total_operations) +
      '</strong> operations in the last 24h. Sanctuary blocked <strong>' + escHtml(d.kernel_blocks) +
      '</strong> outbound connections and allowed <strong>' + escHtml(d.kernel_allows) +
      '</strong>. You denied <strong>' + escHtml(d.approvals_denied) +
      '</strong> approvals and granted <strong>' + escHtml(d.approvals_granted) +
      '</strong>. ' + chainText + '</p>';
  }
  const lines = [
    '<strong>' + escHtml(d.total_operations) + '</strong> operations in the last 24h.',
    '<strong>' + escHtml(d.kernel_blocks) + '</strong> outbound connections blocked at the kernel; ' + escHtml(d.kernel_allows) + ' allowed.',
    '<strong>' + escHtml(d.approvals_denied) + '</strong> approvals denied, ' + escHtml(d.approvals_granted) + ' granted by you.',
    d.chain_verified
      ? '<span class="pill tone-verified">Audit chain verified</span> no tampering.'
      : '<span class="pill tone-locked">Audit chain UNVERIFIED (' + escHtml(d.integrity_finding_count) + ' findings).</span>'
  ];
  return lines.map(function (l) { return '<div class="story-line">' + l + '</div>'; }).join("");
}
function renderPostureAnomalies(findings) {
  if (!findings || !findings.length) {
    return '<p class="muted">No open anomaly findings.</p>';
  }
  return findings.map(function (f) {
    return '<div class="story-line"><span class="pill tone-degraded">' + escHtml(f.severity || "finding") + '</span> ' +
      escHtml(f.summary || f.detector_id || f.finding_id || "anomaly") + '</div>';
  }).join("");
}
function renderPostureAgentRows(home) {
  const rows = (home.agents || []);
  if (!rows.length) return '<p class="muted">No protected agents yet.</p>';
  return rows.map(function (a) {
    // HONEST per-agent pill (#634): green ONLY on confirmed live enforcement;
    // amber on policy-only protection; never machine-arm bleed-through.
    var pill;
    if (a.enforcement_active === "active") pill = '<span class="pill tone-verified">Enforcing</span>';
    else if (a.policy_protected) pill = '<span class="pill tone-degraded">Protection requested</span>';
    else pill = '<span class="pill">Not protected</span>';
    const drill = "/posture/agent/" + encodeURIComponent(a.agent_id);
    return '<div class="row">' +
      '<div class="grow"><strong>' + escHtml(a.agent_id) + '</strong> ' + pill +
      '<div class="muted mono">' + escHtml(a.harness) + ' &middot; status ' + escHtml(a.status) + '</div></div>' +
      '<a class="btn" href="' + drill + '">View posture</a>' +
      '</div>';
  }).join("");
}
function renderPostureScreen() {
  const home = state.posture.home;
  const head =
    '<div class="page-head"><div>' +
      '<p class="eyebrow">Posture</p>' +
      '<h1>How safe you are right now.</h1>' +
      '<p class="sub">The full posture detail, on this one surface. Castle Wall reads protected only on a fresh enforcement check. Every number traces to your signed audit trail.</p>' +
    '</div></div>';
  if (!home) {
    const why = state.posture.homeError
      ? 'Could not load posture detail (' + escHtml(state.posture.homeError) + '). The data routes stay behind your operator token.'
      : 'Loading posture detail.';
    return '<section class="concierge-wrap">' + head +
      '<section class="card"><p class="muted">' + why + '</p></section>' +
      '</section>';
  }
  const wall = postureWallLabel(home.castle_wall && home.castle_wall.arm_state);
  const pending = state.inbox.filter(function (i) { return !i.resolved && i.kind === "approval_pending"; }).length;
  const findings = home.anomaly_findings || [];
  const chainPill = home.digest && home.digest.chain_verified
    ? '<span class="pill tone-verified">Verified</span>'
    : '<span class="pill tone-locked">Unverified</span>';
  const metricCards =
    '<div class="posture-metrics">' +
      postureMetricCard(escHtml(home.protection_requested_count), "Protection requested") +
      postureMetricCard(escHtml(home.enforcement_confirmed_count), "Enforcement confirmed") +
      postureMetricCard('<span class="' + wall.cls + '">' + escHtml(wall.text) + '</span>', "Castle Wall") +
      postureMetricCard(escHtml(pending), "Approvals waiting") +
      postureMetricCard(escHtml(findings.length), "Open anomalies") +
      postureMetricCard(chainPill, "Audit chain") +
    '</div>';
  const storyToggle =
    '<label class="story-toggle"><input type="checkbox" data-action="posture-story-plain"' +
    (state.posture.storyPlain ? ' checked' : '') + '> Plain summary</label>';
  return [
    '<section class="concierge-wrap">',
      head,
      '<section class="card">',
        '<h3>At a glance</h3>',
        metricCards,
        '<p class="muted">Machine: ' + escHtml(home.origin_machine || "(local)") + '</p>',
      '</section>',
      '<section class="card">',
        '<div class="card-head-row"><h3>Today&#39;s story</h3>' + storyToggle + '</div>',
        renderPostureStory(home.digest || {}),
        '<div class="evidence"><a href="/posture/evidence">Open the Evidence view</a></div>',
      '</section>',
      '<section class="card">',
        '<h3>Anomaly findings</h3>',
        renderPostureAnomalies(findings),
      '</section>',
      '<section class="card">',
        '<h3>Per-agent posture (' + (home.agents || []).length + ')</h3>',
        renderPostureAgentRows(home),
      '</section>',
    '</section>'
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
  try {
    await fetchAutoTriggerState();
  } catch (e) {
    state.autoTrigger.loadError = e && e.message && e.message !== "Not Found" ? e.message : null;
  }
  try {
    const rh = await api("/recognition/did-web");
    state.recognition.health = rh.data || null;
    state.recognition.error = null;
  } catch (e) {
    state.recognition.error = e.message || "load failed";
  }
  await fetchIntelligenceState();
  await fetchHoneypotState();
  await fetchSovereignty();
  await fetchPostureHome();
  // WP-V1.2 reshape: hydrate the concierge thread on every fetch cycle.
  // The direct-agent surface was removed; the inspect panel is fetched
  // lazily on click rather than maintained in state.
  await fetchConciergeHistory();
}

async function fetchHoneypotState() {
  try {
    const tool = await honeypotApi("/tool-traps");
    const credential = await honeypotApi("/credential-traps");
    state.honeypot.toolTraps = (tool.data && tool.data.traps) || [];
    state.honeypot.credentialTraps = (credential.data && credential.data.traps) || [];
    state.honeypot.loadError = null;
  } catch (e) {
    state.honeypot.loadError = e && e.message ? e.message : String(e);
  }
}

// Wave 1 (2026-06-30): the HONEST posture read. /api/sovereignty returns
// the evidence-gated Castle Wall arm-state (#828): green ONLY on a fresh
// enforcement verdict (arm_state "armed"), never on config presence. The
// seal + ambient posture render from this, so the operator never sees a
// fabricated "Protected". This endpoint lives at the server root (NOT under
// /api/hub), so it is fetched directly with the same bearer token. A read
// failure leaves state.posture.data null; the seal then reads "Unknown"
// (an honest non-green state), never "Protected".
async function fetchSovereignty() {
  try {
    const headers = { "Cache-Control": "no-cache", "Pragma": "no-cache" };
    if (TOKEN) headers["Authorization"] = "Bearer " + TOKEN;
    const res = await fetch("/api/sovereignty?_t=" + Date.now(), { headers: headers, cache: "no-store" });
    let body = null;
    try { body = await res.json(); } catch (e) { body = null; }
    if (!res.ok || !body || body.error) {
      state.posture.data = null;
      state.posture.error = (body && body.error) || ("HTTP " + res.status);
      return;
    }
    state.posture.data = body;
    state.posture.error = null;
  } catch (e) {
    state.posture.data = null;
    state.posture.error = e && e.message ? e.message : String(e);
  }
}

// One-surface fold (2026-06-30): hydrate the full posture detail folded into
// this surface. Reuses the EXISTING posture data endpoints, never a duplicate:
// GET /api/posture/home (the same buildHome payload the /posture board renders -
// metric cards, today's story digest, per-agent rows) and GET
// /api/anomaly/findings (the open anomaly list). Both are GET reads behind the
// SAME read-auth contract as the rest of the surface (the operator bearer from
// sessionStorage when set; on a local bind the server may grant a loopback read
// without a token, exactly as the other GET reads do). These are READS only; no
// approve/deny or mutation is issued here. A read failure leaves
// state.posture.home null and the Posture screen shows an honest "could not
// load" state, never fabricated data.
async function fetchPostureHome() {
  const headers = { "Cache-Control": "no-cache", "Pragma": "no-cache" };
  if (TOKEN) headers["Authorization"] = "Bearer " + TOKEN;
  try {
    const res = await fetch("/api/posture/home?_t=" + Date.now(), { headers: headers, cache: "no-store" });
    let body = null;
    try { body = await res.json(); } catch (e) { body = null; }
    if (!res.ok || !body || body.error) {
      state.posture.home = null;
      state.posture.homeError = (body && body.error) || ("HTTP " + res.status);
    } else {
      // Anomaly findings come from the dedicated endpoint; tolerate its absence
      // (a fortress with no anomaly detector wired) without failing the screen.
      let findings = [];
      try {
        const ar = await fetch("/api/anomaly/findings?_t=" + Date.now(), { headers: headers, cache: "no-store" });
        if (ar.ok) {
          const ab = await ar.json();
          findings = (ab && ab.data && ab.data.findings) || [];
        }
      } catch (e) { findings = []; }
      body.anomaly_findings = findings;
      state.posture.home = body;
      state.posture.homeError = null;
    }
  } catch (e) {
    state.posture.home = null;
    state.posture.homeError = e && e.message ? e.message : String(e);
  }
}

// Wave 1: map the honest Castle Wall arm-state to the operator-facing seal.
// "armed" (fresh enforcement evidence) is the ONLY green/Protected state;
// "degraded" reads Attention; everything else (unknown, not_installed,
// missing data) reads Attention too, NEVER Protected (never-overclaim).
// A locked-down fortress (the lockdown control engaged) reads Locked.
function deriveSeal() {
  const t1 = state.tier1.lockdown.state;
  if (t1 === "engaged") {
    return { tone: "locked", word: "Locked", arm: "locked_down" };
  }
  const d = state.posture.data;
  const arm = d && d.live_enforcement ? d.live_enforcement.castle_wall_arm_state : null;
  if (arm === "armed") return { tone: "protected", word: "Protected", arm: arm };
  if (arm === "degraded") return { tone: "attention", word: "Attention", arm: arm };
  if (arm) return { tone: "attention", word: "Attention", arm: arm };
  return { tone: "unknown", word: "Unknown", arm: null };
}

// Plain-English line for the named layer in the posture popover. Uses the
// retired-L-number rule: named layers only, never "L1".."L4". Values are
// honest: the wall line reflects the real arm-state, not config presence.
function postureLayerLines() {
  const d = state.posture.data;
  const seal = deriveSeal();
  var wallV;
  if (seal.arm === "armed") wallV = "enforcing";
  else if (seal.arm === "degraded") wallV = "degraded";
  else if (seal.arm === "locked_down") wallV = "locked down";
  else if (seal.arm) wallV = "not enforcing";
  else wallV = "unknown";
  const wallWarn = seal.arm !== "armed";
  const pending = state.inbox.filter(function (i) { return !i.resolved && i.kind === "approval_pending"; }).length;
  const wrapped = state.agents.length;
  return [
    { k: "Castle Wall (boundary)", v: wallV, warn: wallWarn },
    { k: "Sentinels watching agents", v: wrapped + " wrapped", warn: false, off: wrapped === 0 },
    { k: "Charter approvals", v: pending ? pending + " waiting" : "clear", warn: pending > 0 },
    { k: "Heralds (reputation)", v: d && d.layers && d.layers.l4 && d.layers.l4.status === "active" ? "signed" : "configured", warn: false }
  ];
}

async function onAutoTriggerRecommendation(ruleId, action) {
  try {
    await autoTriggerApi(
      "/rules/" + encodeURIComponent(ruleId) + "/" + action + "-recommendation",
      { method: "POST", body: {} }
    );
    await fetchAutoTriggerState();
    toast(action === "accept" ? "Recommendation accepted." : "Recommendation rejected.", "info");
    rerender();
  } catch (e) {
    toast("Recommendation action failed: " + (e && e.message ? e.message : "unknown"), "error");
  }
}

async function onAutoTriggerThresholdSave(ruleId) {
  const rule = (state.autoTrigger.rules || []).find(function (r) { return r.rule_id === ruleId; });
  if (!rule) return toast("Rule not loaded.", "error");
  const inputs = Array.prototype.slice.call(document.querySelectorAll('input[data-action="auto-trigger-input"][data-rule-id="' + escCssAttr(ruleId) + '"]'));
  const overrides = {};
  let cancelWindow = null;
  for (let i = 0; i < inputs.length; i++) {
    const el = inputs[i];
    const field = el.getAttribute("data-field");
    const raw = String(el.value || "").trim();
    if (!raw) continue;
    const num = Number(raw);
    if (!Number.isFinite(num) || num < 0) return toast("Threshold values must be positive numbers.", "error");
    if (field === "cancel_window_seconds") {
      if (num < 1 || num > 3600) return toast("Cancel window must be 1 to 3600 seconds.", "error");
      cancelWindow = Math.floor(num);
    } else {
      overrides[field] = field === "warn_sigma" || field === "alert_sigma" ? num : Math.floor(num);
    }
  }
  try {
    state.autoTrigger.savingRuleId = ruleId;
    rerender();
    const body = { rule_type: rule.rule_type, threshold_overrides: overrides };
    if (cancelWindow !== null) body.cancel_window_seconds = cancelWindow;
    await autoTriggerApi("/rules/" + encodeURIComponent(ruleId), { method: "PATCH", body: body });
    await fetchAutoTriggerState();
    toast("Thresholds saved.", "info");
  } catch (e) {
    toast("Threshold save failed: " + (e && e.message ? e.message : "unknown"), "error");
  } finally {
    state.autoTrigger.savingRuleId = null;
    rerender();
  }
}

async function fetchAutoTriggerState() {
  const rules = await autoTriggerApi("/rules");
  const list = (rules.data && rules.data.rules) || [];
  const hydrated = [];
  for (let i = 0; i < list.length; i++) {
    try {
      const detail = await autoTriggerApi("/rules/" + encodeURIComponent(list[i].rule_id));
      hydrated.push((detail.data && detail.data.rule) || list[i]);
    } catch (e) {
      hydrated.push(list[i]);
    }
  }
  state.autoTrigger.rules = hydrated;
  const at = await autoTriggerApi("/recommendations");
  state.autoTrigger.recommendations = (at.data && at.data.recommendations) || [];
  state.autoTrigger.loadError = null;
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
  // WP-V1.2 reshape: direct-agent chat surface removed; the
  // pending-approval bookkeeping that previously synced with chat
  // session state is gone. Inbox approve/deny now is a clean inbox-only
  // resolve with the lockdown / exit-drill side effects preserved.
  // After approve, the inspect panel for the bound agent (if any) is
  // re-fetched via the route, not through state mutation.
  const item0 = state.inbox.find(function (x) { return x.item_id === itemId; });
  const boundAgentId = (item0 && item0.agent_id) || null;
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
    // After approve on an agent-bound inbox item, refresh the inspect
    // panel for that agent if the operator is currently viewing it, so
    // the panel reflects the resolved approval.
    if (
      action === "approve" &&
      boundAgentId &&
      state.selectedAgentId === boundAgentId &&
      state.chat.inspect.panelByAgentId[boundAgentId]
    ) {
      void onAgentInspectOpen(boundAgentId);
    }
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

async function onInboxBatchAction(action, until) {
  const ids = Object.keys(state.inboxOps.selected).filter(function (id) { return state.inboxOps.selected[id]; });
  if (ids.length === 0) return;
  try {
    if (action === "archive" || action === "delete" || action === "snooze") {
      await fetch("/api/inbox/unified/batch", {
        method: "POST",
        headers: Object.assign({ "Content-Type": "application/json" }, TOKEN ? { "Authorization": "Bearer " + TOKEN } : {}),
        body: JSON.stringify({ action: action, entry_ids: ids, until: until })
      });
    }
    if (action === "dismiss") {
      for (const id of ids) await onInboxAction(id, "dismiss");
    }
    state.inboxOps.selected = {};
    state.inboxOps.snoozeDialog = null;
    await fetchAll();
    rerender();
  } catch (e) {
    toast("Inbox batch action failed.", "error");
  }
}

async function onRunFullAudit() {
  try {
    toast("Running audit-chain export + verify...");
    const r = await api("/audit-chain/verify", { method: "POST", body: {} });
    const verdict = r.data && r.data.verdict ? r.data.verdict : "unknown";
    const entries = r.data && r.data.entries_checked ? r.data.entries_checked : "?";
    if (verdict === "PASS") {
      toast("Audit chain verified: " + entries + " entries, verdict PASS", "success");
    } else {
      toast("Audit chain verdict: " + verdict + " (" + entries + " entries checked)", "error");
    }
  } catch (e) {
    if (e.status === 404) {
      toast("Audit-chain verify endpoint not available. Run manually: sanctuary audit-chain export | sanctuary audit-chain verify --input -", "error");
    } else {
      toast("Audit failed: " + (e.message || "unknown error"), "error");
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

async function onDidWebCompromisedRotation() {
  if (state.recognition.rotating) return;
  state.recognition.rotating = true;
  rerender();
  try {
    const r = await api("/recognition/did-web/rotate-compromised", { method: "POST", body: {} });
    state.recognition.health = r.data.health;
    state.recognition.error = null;
    toast("did:web key rotated. Publish the updated DID Document.", "info");
  } catch (e) {
    state.recognition.error = e.message || "rotation failed";
    toast("did:web rotation failed: " + state.recognition.error, "error");
  } finally {
    state.recognition.rotating = false;
    rerender();
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
  async function open() {
    try {
      const sessionQuery = await createStreamSessionQuery();
      const url = STREAM + sessionQuery;
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
        if (String(e.display_template_id || "").indexOf("auto_trigger") >= 0 || String(e.display_template_id || "").indexOf("auto_action") >= 0) {
          void fetchAutoTriggerState().then(rerender);
          return;
        }
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
        void open();
      }, 1000);
    };
  }
  void open();
}

// Polling fallback compiled-in but not user-facing. Activated by build-time
// flag (window.__sanctuaryDashboardPolling__ = true) or when EventSource
// is unavailable.
function schedulePolling() {
  setInterval(function () { fetchAll().then(rerender); }, 5000);
}

// WP-V1.2 reshape: the F9 polling loop for direct-agent chat history
// was removed with the chat surface. The inspect panel is fetched
// lazily on click and is read-only; no streaming updates required.

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
  // Wave 1: close the top-bar popovers on any click that lands outside both
  // of them (and is not their own toggle, which is handled below). Runs
  // before the no-action early-return so a click on empty page chrome
  // dismisses an open switcher / seal.
  if (state.agentScope.switcherOpen || state.posture.sealOpen) {
    const insideSwitcher = !!rawTgt.closest("[data-switcher]");
    const insideSeal = !!rawTgt.closest("[data-seal]");
    if (!insideSwitcher && !insideSeal) {
      state.agentScope.switcherOpen = false;
      state.posture.sealOpen = false;
      renderTopbar();
    }
  }
  if (!tgt) return;
  const action = tgt.getAttribute("data-action");
  if (!action) return;
  const itemId = tgt.getAttribute("data-item-id");
  const agentId = tgt.getAttribute("data-agent-id");
  const ruleId = tgt.getAttribute("data-rule-id");
  const route = tgt.getAttribute("data-route");
  const intelSurface = tgt.getAttribute("data-intel-surface");
  const intelSubstrate = tgt.getAttribute("data-intel-substrate");
  const intelLocalModel = tgt.getAttribute("data-intel-local-model");
  const intelFrontierProvider = tgt.getAttribute("data-intel-frontier-provider");
  if (action === "lockdown") return void onLockdownClick();
  if (action === "theme-toggle") {
    const isDark = document.documentElement.getAttribute("data-theme") === "dark";
    const next = isDark ? "light" : "dark";
    sessionStorage.setItem(THEME_KEY, next);
    applyTheme(next);
    return;
  }
  // Wave 1: agent switcher + posture seal (top-bar popovers).
  if (action === "agent-switcher-toggle") {
    ev.stopPropagation();
    state.agentScope.switcherOpen = !state.agentScope.switcherOpen;
    state.posture.sealOpen = false;
    return renderTopbar();
  }
  if (action === "agent-scope-select") {
    const id = tgt.getAttribute("data-agent-id") || "";
    state.agentScope.selectedAgentId = id || null;
    state.agentScope.switcherOpen = false;
    // Scope the queue + ambient posture to the chosen agent; re-render the
    // rail and the topbar. The conversation spine stays fortress-wide in
    // wave 1 (the concierge reads fortress state); per-agent conversation
    // scoping is a wave-2 follow-up.
    renderTopbar();
    renderFortress();
    return;
  }
  if (action === "posture-seal-toggle") {
    ev.stopPropagation();
    state.posture.sealOpen = !state.posture.sealOpen;
    state.agentScope.switcherOpen = false;
    return renderTopbar();
  }
  // One-surface fold: the seal click-to-expand routes into the full Posture
  // screen (the folded-in posture detail). Closes the popover and navigates.
  if (action === "posture-detail-open") {
    ev.preventDefault();
    state.posture.sealOpen = false;
    setRoute("posture");
    location.hash = "#posture";
    renderTopbar();
    return;
  }
  // Today's Story plain-summary toggle on the Posture screen.
  if (action === "posture-story-plain") {
    state.posture.storyPlain = !state.posture.storyPlain;
    return rerender();
  }
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
  if (action === "intel-picker-toggle-apply-to-all") {
    state.intelligence.picker.applyToAll = !state.intelligence.picker.applyToAll;
    state.intelligence.picker.error = null;
    return rerender();
  }
  if (action === "intel-failures-toggle" && intelSurface) {
    if (state.intelligence.expandedFailures[intelSurface]) {
      delete state.intelligence.expandedFailures[intelSurface];
    } else {
      state.intelligence.expandedFailures[intelSurface] = true;
    }
    return rerender();
  }
  if (action === "auto-trigger-accept" && ruleId) {
    return void onAutoTriggerRecommendation(ruleId, "accept");
  }
  if (action === "auto-trigger-reject" && ruleId) {
    return void onAutoTriggerRecommendation(ruleId, "reject");
  }
  if (action === "auto-trigger-threshold-save" && ruleId) {
    return void onAutoTriggerThresholdSave(ruleId);
  }
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
  // WP-V1.2 reshape click-to-inspect handler ────────────────────────
  if (action === "agent-inspect-open" && agentId) return void onAgentInspectOpen(agentId);
  if (action === "run-full-audit") return void onRunFullAudit();
  if (action === "exit-export-start") return void onExitExportStart();
  if (action === "did-web-rotate-compromised") return void onDidWebCompromisedRotation();
  if (action === "exit-mark-verified") { state.exitDrill.step = 5; return rerender(); }
  if (action === "open-agent" && agentId) { state.selectedAgentId = agentId; location.hash = "agent-detail"; return; }
  // Click-to-inspect from the fortress-column agent rows (PR #100
  // sidebar wire-up): navigate to the agent-detail view AND fire the
  // synchronous /inspect/open route so the panel renders already-loaded.
  // Same component as the Agents-view CTA; the optimistic "Opening..."
  // pane (openingAgentId) renders during the round-trip.
  if (action === "agent-row-inspect-open" && agentId) {
    state.selectedAgentId = agentId;
    if (location.hash !== "#agent-detail") {
      location.hash = "agent-detail";
    } else {
      setRoute("agent-detail");
    }
    void onAgentInspectOpen(agentId);
    return;
  }
  // Keyboard activation for the role="button" agent-row-head: Enter and
  // Space invoke the same handler as a click. Mirrors native button
  // semantics for accessibility without restructuring the head into a
  // real <button> (the head contains a glyph span + grow div + pill,
  // which would be awkward children of a button element).
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
  if (action === "inbox-select" && itemId) {
    state.inboxOps.selected[itemId] = tgt.checked;
    return rerender();
  }
  if (action === "inbox-batch-archive") return void onInboxBatchAction("archive");
  if (action === "inbox-batch-dismiss") return void onInboxBatchAction("dismiss");
  if (action === "inbox-batch-delete") return void onInboxBatchAction("delete");
  if (action === "inbox-batch-snooze-open") {
    state.inboxOps.snoozeDialog = true;
    return rerender();
  }
  if (action === "inbox-snooze-menu" && itemId) {
    state.inboxOps.selected = {};
    state.inboxOps.selected[itemId] = true;
    state.inboxOps.snoozeDialog = true;
    return rerender();
  }
  if (action === "inbox-batch-snooze-close") {
    state.inboxOps.snoozeDialog = null;
    return rerender();
  }
  if (action === "inbox-batch-snooze") {
    const ms = Number(tgt.getAttribute("data-snooze-ms") || "0");
    return void onInboxBatchAction("snooze", new Date(Date.now() + ms).toISOString());
  }
  if (action === "inbox-batch-snooze-custom") {
    const input = document.querySelector('[data-action="inbox-snooze-custom"]');
    const raw = input && input.value ? input.value : "";
    return void onInboxBatchAction("snooze", raw ? new Date(raw).toISOString() : new Date(Date.now() + 3600000).toISOString());
  }
  if (action.indexOf("inbox-") === 0 && itemId) {
    const sub = action.slice("inbox-".length);
    // Wave 1: when the click is on a rail approval-queue tile, animate the
    // tile out for a click-to-clear feel. The resolve itself is the SAME
    // token-gated onInboxAction path the inbox rows use; the animation is
    // cosmetic and never bypasses the request. A subsequent fetchAll +
    // rerender re-renders the rail authoritatively from server state.
    if (sub === "approve" || sub === "deny") {
      const tile = rawTgt.closest(".approval-tile");
      if (tile) {
        tile.classList.add("leaving");
        const countEl = document.getElementById("queue-count");
        if (countEl) {
          const remaining = document.querySelectorAll(".approval-tile:not(.leaving)").length;
          countEl.textContent = String(remaining);
          if (remaining === 0) countEl.classList.add("zero");
        }
      }
    }
    return void onInboxAction(itemId, sub);
  }
  if (action.indexOf("agent-") === 0 && agentId) {
    const sub = action.slice("agent-".length);
    return void onAgentControl(agentId, sub);
  }
});

// Keyboard activation for the fortress-column agent-row click target.
// The agent-row-head is a div with role="button" + tabindex="0", so it
// is focusable but does not activate on Enter/Space the way a real
// button does. This handler restores native button keyboard semantics
// for the click-to-inspect surface only; other data-action elements
// are real buttons and inherit Enter/Space natively.
document.addEventListener("keydown", function (ev) {
  if (ev.key !== "Enter" && ev.key !== " ") return;
  const rawTgt = ev.target;
  if (!(rawTgt instanceof Element)) return;
  const action = rawTgt.getAttribute("data-action");
  if (action !== "agent-row-inspect-open") return;
  const agentId = rawTgt.getAttribute("data-agent-id");
  if (!agentId) return;
  ev.preventDefault();
  state.selectedAgentId = agentId;
  if (location.hash !== "#agent-detail") {
    location.hash = "agent-detail";
  } else {
    setRoute("agent-detail");
  }
  void onAgentInspectOpen(agentId);
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
  } else if (action === "inbox-filter-search") {
    state.inboxOps.filters.search = tgt.value;
    saveInboxPrefs();
    rerender();
  } else if (action === "inbox-filter-from") {
    state.inboxOps.filters.from = tgt.value;
    saveInboxPrefs();
    rerender();
  } else if (action === "inbox-filter-to") {
    state.inboxOps.filters.to = tgt.value;
    saveInboxPrefs();
    rerender();
  }
});

document.addEventListener("change", function (ev) {
  const tgt = ev.target;
  if (!(tgt instanceof Element) || tgt.tagName !== "SELECT") return;
  const action = tgt.getAttribute("data-action");
  if (action === "inbox-filter-source") state.inboxOps.filters.source = tgt.value;
  else if (action === "inbox-filter-severity") state.inboxOps.filters.severity = tgt.value;
  else if (action === "inbox-filter-agent") state.inboxOps.filters.agent = tgt.value;
  else return;
  saveInboxPrefs();
  rerender();
});

// v1.1.7: chat composer submit handler removed alongside the half-built
// chat surface (Finding EE). Direct concierge chat ships in v1.2; until
// then the dashboard view renders a static welcome card with no form
// inputs that could be confused for a working command surface.

// Theme: explicit operator preference (sessionStorage) overrides system
// pref. The toggle button in the topbar dispatches data-action
// "theme-toggle" which writes the chosen theme and updates the
// [data-theme] attribute. When no explicit choice exists, fall back to
// system preference and track changes so dark-mode-at-sunset behavior
// keeps working on macOS / Windows.
const THEME_KEY = "sanctuary-v11-theme";
function applyTheme(theme) {
  if (theme === "dark") document.documentElement.setAttribute("data-theme", "dark");
  else document.documentElement.removeAttribute("data-theme");
}
const explicitTheme = sessionStorage.getItem(THEME_KEY);
const mq = window.matchMedia ? window.matchMedia("(prefers-color-scheme: dark)") : null;
if (explicitTheme === "dark" || explicitTheme === "light") {
  applyTheme(explicitTheme);
} else if (mq && mq.matches) {
  applyTheme("dark");
}
if (mq) mq.addEventListener("change", function (e) {
  // Only honor system pref changes when the operator has not made an
  // explicit choice. Once they toggle, the choice sticks for the
  // session.
  if (sessionStorage.getItem(THEME_KEY)) return;
  applyTheme(e.matches ? "dark" : "light");
});

// Boot.
loadInboxPrefs().then(function () {
  return fetchAll();
}).then(function () { rerender(); });
bindHashRoute();
connectStream();
`;
