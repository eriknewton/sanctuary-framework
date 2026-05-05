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
const SANCTUARY_VERSION = config.sanctuaryVersion || "";
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
    case "agents": nextHtml = renderAgentsList(); break;
    case "agent-detail": nextHtml = renderAgentDetail(); break;
    case "policy": nextHtml = renderPolicyCenter(); break;
    case "intelligence": nextHtml = renderIntelligenceCenter(); break;
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
  { id: "agent-touched", category: "Inspect", label: "what has each agent touched today", query: "What has each wrapped agent done today? Group by agent." },
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
    '<div class="concierge-wrap">',
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
function agentAttestationTone(status) {
  if (status === "active") return { cls: "tone-verified", label: "verified" };
  if (status === "locked_down") return { cls: "tone-locked", label: "locked" };
  if (status === "error") return { cls: "tone-unverified", label: "unverified" };
  return { cls: "tone-degraded", label: "degraded" };
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
      '<h2>No wrapped agents yet.</h2>' +
      '<p>Wrap an agent to give it a portable identity, a charter, and approval gates. Run <code>sanctuary wrap</code> in any project where your agent lives.</p>' +
      '<div class="terminal-block"><span class="cmd"><span class="prompt">$</span>sanctuary wrap</span></div>' +
    '</div>';
  const count = state.agents.length;
  const subCopy = count + ' wrapped. Click one to inspect its activity, policy, and pending approvals.';
  const rows = state.agents.map(function (a) {
    const map = STATUS_MAP[a.status] || STATUS_MAP.unknown;
    const dotCls = agentStateClass(a.status);
    const att = agentAttestationTone(a.status);
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
      '<span class="pill ' + att.cls + '">' + escHtml(att.label) + '</span>' +
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
        return '<div class="row"><span class="muted">' + escHtml(shortTime(e.emitted_at)) + '</span><span>' + escHtml(t) + '</span></div>';
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
    const att = agentAttestationTone(agent.status);
    const dotCls = agentStateClass(agent.status);
    const stateMap = STATUS_MAP[agent.status] || STATUS_MAP.unknown;
    const activity = (panel.recent_activity || []).slice(0, 20);
    const activityHtml = activity.length
      ? '<div class="timeline">' +
        activity.map(function (e) {
          const t = renderTemplate(e.display_template_id, e.display_template_args);
          return '<div class="timeline-item ok">' +
            '<div class="ts">' + escHtml(shortTime(e.emitted_at)) + '</div>' +
            '<div class="what">' + escHtml(t) + '</div>' +
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
          '<span style="margin-left:auto;"><span class="pill ' + att.cls + '">' + escHtml(att.label) + '</span></span>' +
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
          '<div class="policy-line"><span class="k">Wrapped at</span><span class="v">' + escHtml(shortTime(agent.wrapped_at)) + '</span></div>' +
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
  const visibleInbox = state.inbox.filter(function (i) { return !i.resolved; });
  const inboxRows = visibleInbox.length
    ? visibleInbox.map(function (i) {
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
        // Click-to-inspect: the head sub-row is the click target. A click
        // navigates to agent-detail and opens the read-only inspect panel
        // synchronously via the WP-V1.2 reshape route (the original PR #98
        // chat wire-up was repurposed when direct-agent chat was removed
        // from v1.2). Lifecycle buttons in agent-row-actions still take
        // precedence (the dispatcher walks up to the closest data-action
        // ancestor; buttons are siblings, not children, of the head).
        return '<div class="row agent-row" data-agent-row="' + escHtml(a.agent_id) + '">' +
          '<div class="agent-row-head" data-action="agent-row-inspect-open" data-agent-id="' + escHtml(a.agent_id) + '" role="button" tabindex="0" title="Open inspect panel for ' + escHtml(a.agent_id) + '">' +
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
  // WP-V1.2 reshape: hydrate the concierge thread on every fetch cycle.
  // The direct-agent surface was removed; the inspect panel is fetched
  // lazily on click rather than maintained in state.
  await fetchConciergeHistory();
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
  if (action === "theme-toggle") {
    const isDark = document.documentElement.getAttribute("data-theme") === "dark";
    const next = isDark ? "light" : "dark";
    sessionStorage.setItem(THEME_KEY, next);
    applyTheme(next);
    return;
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
  if (action === "exit-export-start") return void onExitExportStart();
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
  if (action.indexOf("inbox-") === 0 && itemId) {
    const sub = action.slice("inbox-".length);
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
  }
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
fetchAll().then(function () { rerender(); });
bindHashRoute();
connectStream();
`;
