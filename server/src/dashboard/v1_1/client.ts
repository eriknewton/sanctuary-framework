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
 * NO localStorage writes. The one localStorage access is a read of the
 * Fleet Switcher's saved machine list (FLEET_STORAGE_KEY) for the Machines
 * screen; the Fleet Switcher page owns and writes that list. NO
 * operator-typed direct chat command at v1.1
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

import type { AuditChainVerdictStatus } from "../../operational/audit-log.js";
import { castleWallLocalPlatformSubject } from "../../castle-wall/provision-state.js";
import { HUB_ACTIVITY_TEMPLATE_NAMESPACES } from "../../hub/constants.js";
import { ACTIVITY_FALLBACK_TEMPLATE_BY_NAMESPACE } from "./templates.js";

/**
 * Returns the inline client script body. The HTML shell wraps this in
 * `<script type="module">` tags.
 *
 * Tests can import this string and assert the absence of forbidden
 * patterns (em-dashes, UBAI strings, MLS dead-claims, raw chat-command
 * POST paths, verifier function imports) using simple regex checks.
 */
const LOCAL_CASTLE_WALL_SUBJECT_PLACEHOLDER =
  "__SANCTUARY_LOCAL_CASTLE_WALL_SUBJECT__";

export function getClientScript(
  platform: NodeJS.Platform = process.platform,
): string {
  return CLIENT_SCRIPT.replaceAll(
    LOCAL_CASTLE_WALL_SUBJECT_PLACEHOLDER,
    castleWallLocalPlatformSubject(platform),
  );
}

// Must match DASHBOARD_MODE_NOT_SERVED_* in
// server/src/dashboard/standalone-mode-signal.ts. The embedded browser client
// cannot import server modules at runtime, so tests assert this pinned protocol
// tuple stays in full parity.
export const DASHBOARD_CLIENT_MODE_NOT_SERVED_STATUS = 503;
export const DASHBOARD_CLIENT_MODE_NOT_SERVED_ERROR =
  "dashboard_mode_not_served";
export const DASHBOARD_CLIENT_MODE_NOT_SERVED_MODE = "standalone";
export const DASHBOARD_CLIENT_MODE_NOT_SERVED_MESSAGE =
  "Not available in this dashboard mode.";

// Must cover AuditChainVerdictStatus in operational/audit-log.ts; the browser
// receives this typed map verbatim, and the wired test compares the whole union.
const EVIDENCE_CHAIN_VERDICTS = {
  verified: { kind: "good", word: "CHAIN VERIFIED", summary: "Routine entries and any readable sealed region verified clean." },
  verified_suffix_only: { kind: "warn", word: "RECENT ENTRIES VERIFIED", summary: "Recent entries are verified. The sealed older region could not be verified at this privilege." },
  findings: { kind: "bad", word: "INTEGRITY FINDINGS", summary: "The server reported integrity findings." },
  key_unavailable: { kind: "unknown", word: "NOT VERIFIED", summary: "The audit key is not available, so the chain was not verified." },
} satisfies Record<AuditChainVerdictStatus, { kind: string; word: string; summary: string }>;

const CLIENT_SCRIPT = String.raw`
"use strict";

// Must match parseIsoInstantWithOffset in server/src/core/time.ts: dashboard
// freshness is a protection claim, so offset-less or normalised timestamps
// fail toward stale/unknown instead of borrowing the browser's local zone.
function parseEvidenceTimestamp(value) {
  if (typeof value !== "string") return undefined;
  const match = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.(\d{1,9}))?(?:Z|([+-])(\d{2}):(\d{2}))$/.exec(value);
  if (match === null) return undefined;
  const year = Number(match[1]);
  const month = Number(match[2]);
  const day = Number(match[3]);
  const hour = Number(match[4]);
  const minute = Number(match[5]);
  const second = Number(match[6]);
  const writtenMs = Number((match[7] || "").padEnd(3, "0").slice(0, 3));
  const offsetSign = match[8];
  const offsetHours = offsetSign ? Number(match[9]) : 0;
  const offsetMinutes = offsetSign ? Number(match[10]) : 0;
  // Mirrors the server predicate's finite Date.parse refusal for in-shape but out-of-range offsets.
  if (offsetHours > 23 || offsetMinutes > 59) return undefined;
  const offsetMs = (offsetSign === "-" ? -1 : 1) * (offsetHours * 60 + offsetMinutes) * 60 * 1000;
  const wall = new Date(0);
  // Set year/month/day together so years 0000..0099 stay proleptic instead of remapping through 1900..1999.
  wall.setUTCFullYear(year, month - 1, day);
  wall.setUTCHours(hour, minute, second, writtenMs);
  const timestamp = wall.getTime() - offsetMs;
  if (!Number.isFinite(timestamp)) return undefined;
  const rendered = new Date(timestamp + offsetMs);
  const calendarFieldsMatch =
    rendered.getUTCFullYear() === year &&
    rendered.getUTCMonth() + 1 === month &&
    rendered.getUTCDate() === day &&
    rendered.getUTCHours() === hour &&
    rendered.getUTCMinutes() === minute &&
    rendered.getUTCSeconds() === second &&
    rendered.getUTCMilliseconds() === writtenMs;
  return calendarFieldsMatch ? timestamp : undefined;
}

// ── Config ─────────────────────────────────────────────────────────────
const cfgEl = document.getElementById("dashboard-config");
const config = cfgEl ? JSON.parse(cfgEl.textContent || "{}") : {};
const HUB = config.hubApiBase || "/api/hub";
const AUTO_TRIGGER = "/api/auto-trigger";
const POLICY = "/api/policy";
const INBOX_PREFS = "/api/inbox/unified/prefs";
const STREAM = config.streamUrl || "/api/stream";
let TOKEN = config.authToken || sessionStorage.getItem("authToken") || "";
const SANCTUARY_VERSION = config.sanctuaryVersion || "";
const SESSION_KEY = "sanctuary-v11-sidebar";
const URL_SESSION = (function () {
  try { return new URLSearchParams(location.search || "").get("session") || ""; }
  catch (_e) { return ""; }
})();
// The top-bar seal is the strongest visible protection claim on the page.
// It must be backed by evidence, not just the backend arm-state label. Ten
// minutes is only an upper bound here; if the payload supplies a smaller
// window, the smaller window wins. Missing, malformed, or non-positive
// freshness windows are unknown, never silently widened to this maximum.
const SEAL_FRESHNESS_MAX_MS = 10 * 60 * 1000;
// Must match windowEnd in buildAuditDigest (principal-policy/posture.ts): the verdict and window end share a build.
const AUDIT_CHAIN_VERIFIED_MAX_AGE_MS = SEAL_FRESHNESS_MAX_MS;
const sealFreshnessTimers = new Map();
let homeFreshnessTimer = null;
// One five-second interaction budget bounds a read, including its JSON body.
// Preferences are optional and get the same budget; neither gates startup.
// Must match DASHBOARD_CLIENT_READ_DEADLINE_MS in server/src/dashboard/read-response.ts.
const DASHBOARD_MILLISECONDS_PER_SECOND = 1000;
const DASHBOARD_READ_DEADLINE_SECONDS = 5;
const DASHBOARD_READ_DEADLINE_MS = DASHBOARD_READ_DEADLINE_SECONDS * DASHBOARD_MILLISECONDS_PER_SECOND;
const SEAL_REREAD_MIN_INTERVAL_DIVISOR = 20;
// 20 = at most one automatic seal re-read per source per 30 s of the 10-minute
// SEAL_FRESHNESS_MAX_MS window (10m / 20 = 30 s); the 5 s read deadline is added so a
// re-read is never issued while the previous one may still be in flight. Bound: one read
// per 35 s per source even when evidence arrives at its window edge. Trade-off: a payload
// with under 35 s of window left shows Attention until the floored re-read lands.
const DASHBOARD_SEAL_REREAD_MIN_INTERVAL_MS = (SEAL_FRESHNESS_MAX_MS / SEAL_REREAD_MIN_INTERVAL_DIVISOR) + DASHBOARD_READ_DEADLINE_MS;
const SEAL_FRESHNESS_BOUNDARY_OFFSET_MS = 1; // One millisecond moves past the inclusive freshness boundary.
const INBOX_PREFS_DEADLINE_MS = DASHBOARD_READ_DEADLINE_MS;
const pendingReads = new Map();
// Must match DASHBOARD_CLIENT_MODE_NOT_SERVED_* exports in
// server/src/dashboard/v1_1/client.ts, which tests pin to
// server/src/dashboard/standalone-mode-signal.ts. This is a positive server
// signal, distinct from a bare 404, so optional standalone panels render as
// unavailable without a Retry button.
const DASHBOARD_MODE_NOT_SERVED_STATUS = ${DASHBOARD_CLIENT_MODE_NOT_SERVED_STATUS};
const DASHBOARD_MODE_NOT_SERVED_ERROR = ${JSON.stringify(DASHBOARD_CLIENT_MODE_NOT_SERVED_ERROR)};
const DASHBOARD_MODE_NOT_SERVED_MODE = ${JSON.stringify(DASHBOARD_CLIENT_MODE_NOT_SERVED_MODE)};
const DASHBOARD_MODE_NOT_SERVED_MESSAGE = ${JSON.stringify(DASHBOARD_CLIENT_MODE_NOT_SERVED_MESSAGE)};
// Invariant: every panel tracks one explicit read state per source; only
// state_LOADED may render a count, checked empty list, clear, configured or
// protective status. UNREAD/LOADING/FAILED render Unknown with a labeled Retry;
// state_NOT_SERVED renders the positive standalone-mode signal with no Retry.
// Protection additionally requires fresh evidence. Fixed sources never evict.
const sourceReads = new Map([
  INBOX_PREFS, HUB + "/agents", HUB + "/inbox", HUB + "/activity",
  "/api/posture/evidence",
  HUB + "/policies", HUB + "/activity?category=privacy", HUB + "/activity?category=handoff",
  HUB + "/recognition/did-web", HUB + "/intelligence/status", HUB + "/intelligence/config",
  HUB + "/chat/concierge/history", POLICY + "/current", AUTO_TRIGGER + "/rules",
  AUTO_TRIGGER + "/recommendations", AUTO_TRIGGER + "/details",
  "/api/honeypot/tool-traps", "/api/honeypot/credential-traps",
  "/api/sovereignty", "/api/posture/home", "/api/anomaly/findings", "/api/fleet/roster", "/api/sentinels/findings"
].map(function (path) { return [readKey(path), { state: "state_UNREAD", error: null, failures: 0, nextReadAt: 0, revision: 0, lastReadAt: 0 }]; }));
const READ_BACKOFF_MAX_MS = 60 * 1000; // At most one automatic retry per minute after repeated failures.
function readKey(url) {
  const parsed = new URL(url, location.origin);
  parsed.searchParams.delete("_t"); parsed.searchParams.delete("session");
  // Filter changes share one bounded read slot; queuePanel invalidates the old revision.
  if (parsed.pathname === "/api/posture/evidence") {
    ["agent", "since", "operation_type", "layer", "result", "limit"].forEach(function (key) {
      parsed.searchParams.delete(key);
    });
  }
  return parsed.origin + parsed.pathname + parsed.search;
}
function sourceRead(path) { return sourceReads.get(readKey(path)); }
let liveUpdatesStopped = false;
function sourceLoaded(path) { const read = sourceRead(path); return !liveUpdatesStopped && !!read && read.state === "state_LOADED"; }
function sourceNotServed(path) { const read = sourceRead(path); return !liveUpdatesStopped && !!read && read.state === "state_NOT_SERVED"; }
function failSource(path, error) {
  const read = sourceRead(path);
  if (!read) return;
  read.state = "state_FAILED";
  read.error = error.message || "The latest result is unavailable.";
  read.failures = Math.min(read.failures + 1, 5); // Five doublings already reach the one-minute ceiling.
  read.nextReadAt = Date.now() + Math.min(READ_BACKOFF_MAX_MS, DASHBOARD_READ_DEADLINE_MS * Math.pow(2, read.failures - 1));
  clearSealFreshnessTimer(path);
}
function markSourceNotServed(path) {
  const read = sourceRead(path);
  if (!read) return;
  read.state = "state_NOT_SERVED";
  read.error = DASHBOARD_MODE_NOT_SERVED_MESSAGE;
  read.failures = 0;
  read.nextReadAt = 0;
  read.status = null;
  clearSealFreshnessTimer(path);
}
function isDashboardModeNotServedResponse(status, body) {
  return status === DASHBOARD_MODE_NOT_SERVED_STATUS &&
    !!body &&
    body.ok === false &&
    body.error === DASHBOARD_MODE_NOT_SERVED_ERROR &&
    body.mode === DASHBOARD_MODE_NOT_SERVED_MODE &&
    body.unavailable === true &&
    body.message === DASHBOARD_MODE_NOT_SERVED_MESSAGE;
}
function mfpOptionalText(value) { return value == null || typeof value === "string"; }
function validateReadBody(key, body) {
  const data = body && body.data;
  const arrayFields = [
    [HUB + "/agents", "agents"], [HUB + "/inbox", "items"],
    [HUB + "/activity", "entries"], [HUB + "/activity?category=privacy", "entries"],
    [HUB + "/activity?category=handoff", "entries"], [HUB + "/policies", "policies"],
    [HUB + "/chat/concierge/history", "messages"], [AUTO_TRIGGER + "/rules", "rules"],
    [AUTO_TRIGGER + "/recommendations", "recommendations"], ["/api/anomaly/findings", "findings"],
    ["/api/honeypot/tool-traps", "traps"], ["/api/honeypot/credential-traps", "traps"], ["/api/sentinels/findings", "findings"]
  ];
  if (key === readKey("/api/fleet/roster") && (!body || typeof body.available !== "boolean" || !Array.isArray(body.nodes) || !body.nodes.every(function (node) {
    return node && typeof node.node_id === "string" && mfpOptionalText(node.label) && mfpOptionalText(node.trust_state) &&
      // The roster's evaluator reports this node's trust; a mistyped flag cannot establish evaluability.
      (node.trust_evaluable === undefined || typeof node.trust_evaluable === "boolean") &&
      mfpOptionalText(node.reach) && mfpOptionalText(node.last_sync_received_at) &&
      (node.policy == null || (typeof node.policy === "object" && mfpOptionalText(node.policy.drift_state)));
  }))) return false;
  if (key === readKey("/api/sentinels/findings") && (!data || !Array.isArray(data.findings) || !data.findings.every(function (finding) {
    return finding && typeof finding.finding_id === "string" && mfpOptionalText(finding.summary) && mfpOptionalText(finding.severity) &&
      mfpOptionalText(finding.sentinel_id) && mfpOptionalText(finding.agent_id) && mfpOptionalText(finding.observed_at) &&
      (finding.evidence_audit_ids == null || (Array.isArray(finding.evidence_audit_ids) && finding.evidence_audit_ids.every(function (id) { return typeof id === "string"; })));
  }))) return false;
  const array = arrayFields.find(function (entry) { return readKey(entry[0]) === key; });
  if (array && !(array[1] === "items" && isPendingApprovalsRedactedMarker(data)) && (!data || !Array.isArray(data[array[1]]))) return false;
  if ([HUB + "/recognition/did-web", HUB + "/intelligence/status", HUB + "/intelligence/config", POLICY + "/current"].some(function (path) { return readKey(path) === key; }) && (!data || typeof data !== "object" || Array.isArray(data))) return false;
  if (key === readKey(HUB + "/recognition/did-web") && typeof data.configured !== "boolean") return false;
  if (key === readKey(HUB + "/intelligence/status") && !Array.isArray(data.surfaces)) return false;
  if (key === readKey("/api/posture/home") && (!body.castle_wall || !Array.isArray(body.agents) || !body.digest)) return false;
  if (key === readKey("/api/posture/evidence") && (!Array.isArray(body.entries) || !Array.isArray(body.integrity_findings))) return false;
  if (key === readKey("/api/sovereignty") && (!body.live_enforcement || typeof body.live_enforcement !== "object")) return false;
  return true;
}

// ── State ──────────────────────────────────────────────────────────────
const state = {
  // Posture-first landing (S2, 2026-07-18): the SPA opens on the posture
  // Overview board ("How safe you are right now"), not the concierge. Talk
  // stays fully reachable at the frozen "dashboard" route via the Assist nav.
  route: "posture",
  mfp: { roster: null, findings: [], totals: { roster: 0, findings: 0, policy: 0 }, findingId: null, folds: { "auto-trigger": false, honeypot: false }, pages: { roster: 0, findings: 0, policy: 0, bindings: 0, rules: 0, recommendations: 0, toolTraps: 0, credentialTraps: 0 } },
  agents: [],
  agentInventory: { status: "", harness: "", sort: "name", page: 0 },
  agentTab: "overview",
  agentReach: { state: "state_UNREAD", agentId: null, data: null, readAt: 0 },
  inbox: [],
  inboxRedacted: false,
  inboxRedactedCount: 0,
  inboxOps: {
    selected: {},
    filters: { search: "", source: "", severity: "", agent: "", from: "", to: "" },
    snoozeDialog: null
  },
  approvals: {
    selectedId: null,
    alwaysAllow: false,
    confirmingTier1Id: null,
    cancelledTier1Id: null,
    inFlightItemId: null,
    // One retained decision result for every inbox decision, and the lock that is its in-flight form.
    // Both are owned by the decision-result section below (state_ADMITTEDDecision through state_RELEASEDDecision).
    lock: null,
    result: null,
    filters: { state: "all", agent: "", tier: "both", category: "" }
  },
  activity: [],
  evidence: {
    view: null,
    filters: { query: "", layer: "", agent: "", event: "", result: "", from: "" },
    selectedIndex: 0
  },
  policies: [],
  autoTrigger: { rules: [], recommendations: [], loadError: null, savingRuleId: null },
  // Tunability UX: plain-English view of the LIVE Principal Policy, fetched
  // from the operator-bearer-gated GET /api/policy/current. null until first
  // load; loadError carries a truthful failure message. Read-only surface.
  policyView: { view: null, loadError: null, loading: false },
  templateBinding: { agentId: null, selectedTemplateId: null, pendingItemId: null, error: null },
  privacyEvents: [],
  handoffEvents: [],
  honeypot: { toolTraps: [], credentialTraps: [], loadError: null },
  topbarPills: { deployment: "unavailable", mode: "unavailable", attestation: "unavailable" },
  // Wave 1 (2026-06-30): which protected agent the operator is steering.
  // null means "All agents" (fortress-wide). Scopes the approvals queue +
  // ambient posture readout. The conversation spine is fortress-wide today
  // (the concierge reads fortress state), so the scope label is shown but
  // the concierge thread is not re-queried per agent in wave 1.
  agentScope: { selectedAgentId: null, switcherOpen: false },
  // Slice 2 shell (2026-10-13): Talk opens the concierge as a panel beside
  // the current screen; the top-bar search filters only what this page has
  // already loaded (no endpoint); the time range is a client-side window
  // over the Evidence list, "all" until the operator narrows it.
  talk: { open: false },
  search: { query: "", open: false },
  timeRange: "all",
  // Wave 1: HONEST posture from the evidence-gated /api/sovereignty verdict
  // (#828). castleWallArmState drives the seal color; NEVER green-on-presence.
  // null until first load; load failure leaves it null and the seal reads
  // "Unknown / Attention", never a fabricated "Protected".
  //
  // home / homeError (2026-06-30 one-surface fold): the full posture-home
  // payload from GET /api/posture/home (today's story, anomaly
  // findings, per-agent rows). Reuses the EXISTING posture data endpoint - the
  // Posture screen folded into this single surface renders from this, and links
  // out to the per-agent drill-down (/posture/agent/:id) and the evidence view
  // (/posture/evidence).
  posture: { data: null, error: null, sealOpen: false, home: null, homeError: null },
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
  if (!window.prompt) return false;
  const entered = window.prompt("Operator token required for this action.");
  if (!entered || !entered.trim()) return false;
  TOKEN = entered.trim();
  sessionStorage.setItem("authToken", TOKEN);
  return true;
}

function credentialedReadUrl(url, method) {
  // The launch URL's short-lived session may authenticate same-origin reads and
  // SSE only. Decisions continue to require the explicit operator bearer.
  if (String(method || "GET").toUpperCase() !== "GET" || !URL_SESSION) return url;
  try {
    const parsed = new URL(url, location.origin);
    if (parsed.origin !== location.origin) return url;
    // A freshly minted stream session from an explicit bearer is newer and
    // more specific than the launch URL's read session; never replace it.
    if (!parsed.searchParams.has("session")) parsed.searchParams.set("session", URL_SESSION);
    return parsed.pathname + parsed.search + parsed.hash;
  } catch (_e) { return url; }
}

// These three snapshot readers carry a per-source generation through transport and projection.
function beginMfpRead(path) {
  const source = sourceRead(path);
  source.generation = (source.generation || 0) + 1;
  return source.generation;
}
function currentMfpRead(path, generation) { return sourceRead(path).generation === generation; }
// For the three snapshot readers (fetchMfpRead and readPolicyView), every site that bumps the read's revision also sets
// its state (queuePanel to LOADING and queues the trailing read; a restart to UNREAD; a stop to FAILED), so this refusal
// means "not mine to publish", never a failed read. Other panels reach loadPanel's catch and still fail on it.
function supersededByRefresh() {
  const error = new Error("A newer refresh is pending.");
  error.supersededByRefresh = true;
  return error;
}
// A rejected race cannot publish late bytes, even if a transport ignores abort.
// Only GETs use this helper; a mutation timeout must not imply it was undone.
function readResponse(url, init, deadlineMs, generation) {
  const key = readKey(url);
  if (generation === undefined && pendingReads.has(key)) return pendingReads.get(key);
  const source = sourceReads.get(key);
  const revision = source && source.revision;
  if (source && source.state === "state_FAILED" && Date.now() < source.nextReadAt) {
    const error = new Error(source.error); error.status = source.status; return Promise.reject(error);
  }
  if (source) { clearSealFreshnessTimer(url); source.lastReadAt = Date.now(); source.state = "state_LOADING"; source.error = null; rerender(); }
  const controller = new AbortController();
  let timer;
  const expired = new Promise(function (_, reject) {
    timer = setTimeout(function () {
      reject(new Error("Read timed out. The latest result is unavailable."));
      controller.abort();
    }, deadlineMs === undefined ? DASHBOARD_READ_DEADLINE_MS : deadlineMs);
  });
  const read = (async function () {
    if (deadlineMs !== undefined && deadlineMs <= 0) throw new Error("Read timed out. The latest result is unavailable.");
    const res = await fetch(url, Object.assign({}, init, { signal: controller.signal }));
    let body = null;
    try {
      body = key === readKey("/api/fleet/roster") || key === readKey("/api/sentinels/findings") || key === readKey(POLICY + "/current") ? await readMfpBody(res) : await res.json();
    } catch (_) { /* Preserve HTTP status even for proxy HTML or empty error bodies. */ }
    if (!res.ok) {
      if (isDashboardModeNotServedResponse(res.status, body)) {
        const error = new Error(DASHBOARD_MODE_NOT_SERVED_MESSAGE);
        error.status = res.status;
        error.body = body;
        error.dashboardModeNotServed = true;
        throw error;
      }
      const error = new Error(res.status === 401 || res.status === 403
        ? "Operator access required (HTTP " + res.status + ")."
        : "Read failed (HTTP " + res.status + ").");
      error.status = res.status;
      error.body = body;
      throw error;
    }
    if (!body || typeof body !== "object" || body.error || !validateReadBody(key, body)) throw new Error("The latest result is unavailable.");
    return { ok: res.ok, status: res.status, json: async function () { return body; } };
  })();
  const result = Promise.race([read, expired]).then(function (res) {
    // Only the newest read may publish loaded state; an older success carries no current evidence.
    if (generation !== undefined && !currentMfpRead(url, generation)) throw new Error("A newer read replaced this response.");
    // A response admitted before an event or decision cannot publish over its trailing read.
    if (source && source.revision !== revision) throw supersededByRefresh();
    if (source) { source.state = "state_LOADED"; source.failures = 0; source.nextReadAt = 0; source.status = null; }
    return res;
  }, function (error) {
    // An older failure cannot revoke evidence already supplied by a newer generation.
    if (generation !== undefined && !currentMfpRead(url, generation)) throw error;
    // A snapshot read whose revision moved failed after a trailing read or a stop took over its state, so the failure
    // is not this source's result: the reader keeps its snapshot, as it does when a superseded read succeeds.
    if (generation !== undefined && source && source.revision !== revision) throw supersededByRefresh();
    if (error && error.dashboardModeNotServed) markSourceNotServed(url);
    else failSource(url, error);
    if (source && source.state !== "state_NOT_SERVED") source.status = error.status;
    rerender();
    throw error;
  }).finally(function () {
    clearTimeout(timer);
    if (pendingReads.get(key) === result) pendingReads.delete(key);
  });
  pendingReads.set(key, result);
  return result;
}

function dashboardResponse(url, init, deadlineAt) {
  return !init || !init.method || init.method.toUpperCase() === "GET"
    ? readResponse(url, init, deadlineAt === undefined ? undefined : Math.max(0, deadlineAt - Date.now()))
    : fetch(url, init);
}

function readLabel(path) {
  const labels = [
    ["/api/fleet/roster", "Fleet roster"], ["/api/sentinels/findings", "Sentinel findings"],
    [INBOX_PREFS, "Saved inbox filters"], ["/api/posture/home", "Protection status"],
    ["/api/sovereignty", "Protection evidence"], ["/api/anomaly", "Anomaly findings"],
    [HUB + "/agents", "Agents"], [HUB + "/inbox", "Decisions"],
    ["/api/posture/evidence", "Chain verification"],
    [HUB + "/activity?category=privacy", "Privacy"], [HUB + "/activity?category=handoff", "Coordination"],
    [HUB + "/activity", "Activity"], [HUB + "/policies", "Agent policies"],
    [HUB + "/intelligence/status", "Intelligence status"], [HUB + "/intelligence/config", "Intelligence configuration"], [HUB + "/intelligence", "Intelligence"], [HUB + "/recognition", "Recognition"],
    [HUB + "/chat", "Conversation history"], [POLICY, "Operator policy"],
    [AUTO_TRIGGER + "/recommendations", "Recommendations"], [AUTO_TRIGGER + "/details", "Rule details"], [AUTO_TRIGGER, "Auto-trigger"], ["/api/honeypot/tool-traps", "Tool honeypots"], ["/api/honeypot/credential-traps", "Credential honeypots"], ["/api/honeypot", "Honeypots"]
  ];
  const match = labels.find(function (entry) { return path.indexOf(entry[0]) === 0; });
  return match ? match[1] : "Panel";
}
function renderSourceRead(path) {
  const read = sourceRead(path);
  if (!read || (!liveUpdatesStopped && read.state === "state_LOADED")) return "";
  const label = readLabel(path);
  if (sourceNotServed(path)) {
    return '<section class="card" data-source="' + escHtml(path) + '">' +
      '<p role="status" aria-live="polite">' + escHtml(label) + ': ' +
      escHtml(read.error || DASHBOARD_MODE_NOT_SERVED_MESSAGE) + '</p></section>';
  }
  const loading = read.state === "state_LOADING";
  return '<section class="card" data-source="' + escHtml(path) + '">' +
    '<p role="status" aria-live="polite">' + escHtml(label) + ': Unknown. ' +
    escHtml(liveUpdatesStopped ? "Live updates stopped. Retry to resume." : loading ? "Read in progress." : (read.error || "Current data is unavailable.")) + '</p>' +
    '<button class="btn" data-action="retry-panel" data-read="' + escHtml(path) +
    '" aria-label="Retry ' + escHtml(label) + '" aria-busy="' + loading + '">Retry</button></section>';
}
function unavailablePanel(title, paths) {
  return '<h1>' + escHtml(title) + '</h1>' + paths.map(renderSourceRead).join("");
}
function restoreRetryFocus(active, container) {
  if (!active || !active.getAttribute || active.getAttribute("data-action") !== "retry-panel") return;
  const path = active.getAttribute("data-read");
  const next = container.querySelector && container.querySelector('[data-action="retry-panel"][data-read="' + escCssAttr(path) + '"]');
  if (next) next.focus();
  else if (container.setAttribute && container.focus) { container.setAttribute("tabindex", "-1"); container.focus(); }
}

async function api(path, opts, deadlineAt) {
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
  // The audit download uses the same bearer and read handling as hub calls.
  let url = path === "/api/audit-log" ? path : HUB + path;
  const method = (init.method || "GET").toUpperCase();
  if (method === "GET") {
    url += (url.indexOf("?") >= 0 ? "&" : "?") + "_t=" + Date.now();
  }
  url = credentialedReadUrl(url, method);
  let res = await dashboardResponse(url, init, deadlineAt);
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
  const res = await readResponse(credentialedReadUrl("/api/honeypot" + path + sep + "_t=" + Date.now(), "GET"), {
    headers,
    cache: "no-store"
  });
  let body = null;
  try { body = await res.json(); } catch (e) { body = null; }
  if (!res.ok) throw new Error(body && body.error ? body.error : ("HTTP " + res.status));
  return body;
}

async function autoTriggerApi(path, opts, deadlineAt) {
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
  url = credentialedReadUrl(url, method);
  const res = await dashboardResponse(url, init, deadlineAt);
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

// Tunability UX: all /api/policy/* calls (plain-English view + promote)
// go through here. Same operator-bearer gate as api(): the token is read
// from sessionStorage at runtime and sent as the Authorization header;
// it is NEVER embedded in served HTML. A 401 on a mutation re-prompts for
// the operator token once, exactly like api(). There is no loopback
// shortcut and no second, weaker path: the server runs authMiddleware
// then requireOperatorCredential on every sensitive policy route.
async function policyApi(path, opts, generation) {
  const init = Object.assign({ headers: {} }, opts || {});
  if (TOKEN) init.headers["Authorization"] = "Bearer " + TOKEN;
  if (init.body && typeof init.body !== "string") {
    init.headers["Content-Type"] = "application/json";
    init.body = JSON.stringify(init.body);
  }
  init.cache = "no-store";
  init.headers["Cache-Control"] = "no-cache";
  init.headers["Pragma"] = "no-cache";
  let url = POLICY + path;
  const method = (init.method || "GET").toUpperCase();
  if (method === "GET") url += (path.indexOf("?") >= 0 ? "&" : "?") + "_t=" + Date.now();
  url = credentialedReadUrl(url, method);
  let res = await (generation === undefined ? dashboardResponse(url, init) : readResponse(url, init, undefined, generation));
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

async function createStreamSessionQuery() {
  if (!TOKEN) return "";
  const res = await readResponse("/auth/session", {
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
  // Newest first keeps F at its origin so expiry cannot hide the retained headline.
  host.insertBefore(el, host.firstChild);
  const feedback = document.getElementById("feedback");
  if (feedback) feedback.scrollTop = 0;
  const toastLifetimeMs = 4 * 1000; // Four seconds, preserving the existing toast lifetime.
  setTimeout(function () { el.remove(); }, toastLifetimeMs);
}

// ── Template registry (mirror of server templates.ts) ──────────────────
function arg(args, kind, fallback) {
  fallback = fallback || "(unknown)";
  for (let i = 0; i < args.length; i++) {
    if (args[i].kind === kind) return String(args[i].value);
  }
  return fallback;
}

// True when the first arg of the kind, the one arg() renders, carries a nonempty string. Must match hasArgValue in
// templates.ts.
function hasArgValue(args, kind) {
  if (!Array.isArray(args)) return false;
  for (let i = 0; i < args.length; i++) {
    if (args[i] && args[i].kind === kind) return typeof args[i].value === "string" && args[i].value.length > 0;
  }
  return false;
}

// Cross-file contract: every key here must have a matching key in the
// server TEMPLATES registry in templates.ts (this map is a mirror of that
// registry). Enforced by the full-set parity test in
// test/dashboard/v1_1/templates.test.ts; a key present only here is a
// client orphan, a key present only in templates.ts falls through to
// "[unrecognized template: ...]" on a live operator-facing card.
const TEMPLATES = {
  "approval_pending.tier1.lockdown": (a) => "Cut agent " + arg(a,"agent_id") + "'s network access. The agent keeps running and keeps local access; it stops reaching anything off this machine.",
  "approval_pending.tier1.fortress_lockdown": () => "Lockdown approval pending. Approving revokes network access for confined agents. Agents keep running and keep local access; off-machine reachability is cut when Castle Wall reloads.",
  // Must match "approval_pending.tier1.fortress_exit_bundle_export" in templates.ts.
  "approval_pending.tier1.fortress_exit_bundle_export": () => "Export the entire fortress as a portable exit bundle.",
  // Must match "approval_pending.tier1.unwrap" in templates.ts.
  "approval_pending.tier1.unwrap": (a) => "Request to remove protection from agent " + arg(a,"agent_id") + ". This build refuses unsupported removals before approval is queued.",
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
  "activity.lifecycle.agent_lockdown_engaged": (a) => "Network access revoked for agent " + arg(a,"agent_id") + ".",
  "activity.lifecycle.agent_lockdown_partial": (a) => "Network access was revoked on disk for agent " + arg(a,"agent_id") + ", but the live Castle Wall reload was not confirmed.",
  "activity.lifecycle.agent_lockdown_refused": (a) => "Network stop refused for agent " + arg(a,"agent_id") + ".",
  "activity.lifecycle.fortress_lockdown_engaged": () => "Fortress lockdown engaged for all confined agents.",
  "activity.lifecycle.fortress_lockdown_partial": () => "Fortress lockdown partially engaged; at least one confined agent could not be locked.",
  "activity.lifecycle.fortress_lockdown_failed": () => "Fortress lockdown failed; no confined agent was locked.",
  "activity.lifecycle.fortress_lockdown_no_agents": () => "Fortress lockdown found no confined agents to lock.",
  "activity.agent_policy_change_engaged": (a) => "Template binding changed on agent " + arg(a,"agent_id") + ": " + arg(a,"channel_template_id","default none") + " to " + arg(a,"policy_id") + ".",
  "activity.agent_policy_change_denied": (a) => "Template binding denied on agent " + arg(a,"agent_id") + ": " + arg(a,"channel_template_id","default none") + " to " + arg(a,"policy_id") + ".",
  "activity.config": (a) => "Configuration change applied.",
  "activity.other": (a) => "Audit event recorded for agent " + arg(a,"agent_id","(fortress)") + "."
};

// Must match ACTIVITY_TEMPLATE_NAMESPACES in templates.ts, sourced from hub/constants.ts.
const ACTIVITY_TEMPLATE_NAMESPACES = ${JSON.stringify(Object.values(HUB_ACTIVITY_TEMPLATE_NAMESPACES))};
// Must match ACTIVITY_FALLBACK_TEMPLATE_BY_NAMESPACE in templates.ts, injected from it when the script is built.
const ACTIVITY_FALLBACK_TEMPLATES = ${JSON.stringify(ACTIVITY_FALLBACK_TEMPLATE_BY_NAMESPACE)};

function renderTemplate(id, args) {
  let fn = TEMPLATES[id];
  if (!fn && typeof id === "string") {
    // The hub serves operation-suffixed ids; the dashboard registers sentences per category. An operation renders its
    // category's sentence only where that sentence is true of every operation the hub files there.
    const namespace = ACTIVITY_TEMPLATE_NAMESPACES.find((prefix) => id.startsWith(prefix + "."));
    const fallback = namespace ? ACTIVITY_FALLBACK_TEMPLATES[namespace] : undefined;
    // A row without a verified agent never renders a sentence that would name the fortress as its subject: the hub
    // serves agent_id only for a re-verified producer signature, so the row keeps the diagnostic fallback instead.
    if (fallback && (fallback.requiredArg === null || hasArgValue(args, fallback.requiredArg))) fn = TEMPLATES[fallback.template];
  }
  if (!fn) return "[unrecognized template: " + id + "]";
  try { return fn(args || []); } catch (e) { return "[template render failed: " + id + "]"; }
}

// ── Status mapping ─────────────────────────────────────────────────────
// Table-level pin: must match STATUS_MAPPING in status-mapping.ts. Enforced
// by the status parity guard in test/dashboard/v1_1/templates.test.ts.
const STATUS_MAP = {
  active: { label: "Protected", glyph: "online" },
  paused: { label: "Paused", glyph: "idle" },
  restarting: { label: "Restarting", glyph: "idle" },
  locked_down: { label: "Locked down", glyph: "offline" },
  // Must match STATUS_MAPPING.unwrapping in status-mapping.ts.
  unwrapping: { label: "Removing protection", glyph: "idle" },
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
  approve: "Allow once",
  deny: "Deny",
  dismiss: "Dismiss",
  review_receipt: "Review receipt",
  open_filter_event: "Open filter event",
  schedule_drill: "Schedule drill",
  view_log: "View log"
};

// ── Render: app-level ─────────────────────────────────────────────────
// Slice 2 rail (2026-10-13): which rail item a hash route lights. The rail
// carries ten destinations; the older routes fold into them as tabs,
// sections or actions, and every older hash still renders its own screen
// when navigated directly. Talk ("dashboard") lights no rail item: it is a
// top-bar button. Must match RAIL_PRIMARY and RAIL_CONFIGURE in
// server/src/dashboard/v1_1/html.ts: every value here is a rail id there.
const ROUTE_RAIL_PARENT = {
  "posture": "posture",
  "approvals": "approvals",
  "agents": "agents",
  "agent-detail": "agents",
  "machines": "machines",
  "enforcement": "enforcement",
  "findings": "findings",
  "honeypot": "findings",
  "activity": "activity",
  "exit-drill": "activity",
  "policy": "policy",
  "auto-trigger": "policy",
  "integrations": "integrations",
  "coordination": "integrations",
  "settings": "settings",
  "health": "settings",
  "privacy": "settings",
  "intelligence": "settings",
  "attestation": "settings",
  "dashboard": null
};
// Settings tabs: each is a plain hash link to the older route id, so the tab
// IS the route and a deep link to #privacy still lands on Privacy.
const SETTINGS_TABS = [
  { id: "health", label: "Health" },
  { id: "privacy", label: "Privacy" },
  { id: "intelligence", label: "Local models" },
  { id: "attestation", label: "Attestation" }
];
// Time-range windows, in milliseconds, for the Evidence list. Only the
// Evidence screen has a client-side window today; every other screen shows
// current state, so the control is disabled there with a title saying so.
const MS_PER_HOUR = 60 * 60 * 1000;
const TIME_RANGE_MS = { "24h": 24 * MS_PER_HOUR, "7d": 7 * 24 * MS_PER_HOUR, "30d": 30 * 24 * MS_PER_HOUR };
const TIME_RANGE_LABEL = { "all": "all time", "24h": "the last 24 hours", "7d": "the last 7 days", "30d": "the last 30 days" };
const TIME_RANGE_ROUTES = ["activity"];
// Every route but Talk's full page is route-full: the fortress column (the
// queue and ambient posture beside the concierge) shows only there. The
// route-walk test asserts this for every hash id but "dashboard".
const ROUTE_FULL = ["activity", "posture", "agents", "policy", "auto-trigger", "intelligence", "honeypot", "privacy", "coordination", "health", "exit-drill", "agent-detail", "approvals", "machines", "enforcement", "findings", "integrations", "settings", "attestation"];
function setRoute(route) {
  // A queued reach read belongs to the open detail route, never to a remembered selection; a cleared subject was
  // never read, so its loading placeholder returns to unread rather than claiming a read in progress.
  if (route !== "agent-detail") {
    if (agentReachPendingId && state.agentReach.agentId === agentReachPendingId && state.agentReach.state === "state_LOADING") state.agentReach = { state: "state_UNREAD", agentId: null, data: null, readAt: 0 };
    agentReachPendingId = null;
  }
  state.route = route;
  const app = document.getElementById("app");
  if (!app) return;
  app.setAttribute("data-route", route);
  if (ROUTE_FULL.indexOf(route) >= 0) app.classList.add("route-full");
  else app.classList.remove("route-full");
  const railRoute = Object.prototype.hasOwnProperty.call(ROUTE_RAIL_PARENT, route) ? ROUTE_RAIL_PARENT[route] : null;
  document.querySelectorAll("#sidebar-nav a").forEach(function (a) {
    if (railRoute && a.getAttribute("data-route") === railRoute) { a.classList.add("active"); a.setAttribute("aria-current", "page"); }
    else { a.classList.remove("active"); a.removeAttribute("aria-current"); }
  });
  state.search.open = false;
  if (route === "machines") { void probeFleetMachines(); scheduleFleetAgeTick(); }
  else renderMain();
  renderFortress();
  renderShellChrome();
  // Tunability UX: entering the Policy surface loads the LIVE plain-English
  // policy from the operator-bearer-gated GET /api/policy/current. Fired
  // fire-and-forget; loadPolicyView rerenders when the view arrives.
  if (route === "policy" || route === "approvals") void loadPolicyView();
  // Machines probes on every entry, as the Fleet Switcher does on load, and
  // keeps its check age current while it shows.
}

// Tunability UX: fetch the plain-English rendering of the LIVE Principal
// Policy from the operator-bearer-gated GET /api/policy/current. Read-only.
// On failure it records a truthful loadError rather than showing a
// fabricated policy. Never exposes an agent-readable path: policyApi()
// sends the operator bearer and the server gates the route.
async function loadPolicyView(afterMutation) {
  if (afterMutation) return refreshPanel(POLICY + "/current");
  return loadPanel(policyPanelJob);
}
async function readPolicyView() {
  const path = POLICY + "/current";
  const generation = beginMfpRead(path);
  state.policyView.loading = true;
  state.policyView.loadError = null;
  try {
    const r = await policyApi("/current", { method: "GET" }, generation);
    // Only the newest generation may commit a policy projection or its total.
    if (!currentMfpRead(path, generation)) return;
    const view = r && r.data && r.data.view;
    if (!view || !Array.isArray(view.lines) || !view.lines.every(function (line) { return line && typeof line.section === "string" && typeof line.text === "string" && line.text.length <= MFP_EVIDENCE_CHAR_LIMIT; })) throw new Error("Policy rule list unavailable.");
    state.mfp.totals.policy = view.lines.length;
    // Only a bounded projection is retained; every refresh replaces the previous policy snapshot.
    state.policyView.view = { policy_version: view.policy_version, lines: view.lines.slice(0, MFP_RECORD_LIMIT).map(function (line) {
      return { section: line.section, text: line.text };
    }) };
  } catch (e) {
    // A superseded failure must leave the newer policy and its loaded state intact.
    if (!currentMfpRead(path, generation)) return;
    // The refresh that superseded this read owns the next policy and already set the read state.
    if (e && e.supersededByRefresh === true) return;
    if (sourceRead(path).state !== "state_FAILED" && !sourceNotServed(path)) failSource(path, e);
    state.mfp.totals.policy = 0;
    state.policyView.view = null;
    state.policyView.loadError =
      e.status === 401 || e.status === 403
        ? "Operator token required to view your policy."
        : e.status === 503
          ? "Policy engine is not configured on this fortress."
          : (e.message || "Could not load policy.");
  } finally {
    if (currentMfpRead(path, generation)) {
      state.policyView.loading = false;
      if (state.route === "policy" || state.route === "approvals") rerender();
    }
  }
}

// Renders the global attestation badge (Q1 layer 1, persistent across
// surfaces). Tone is driven by state.topbarPills.attestation. Pending
// state shows a dashed seal ring; verified shows solid; degraded shows
// outlined core; unverified shows the broken-seal mark. Observation
// language only; Castle Layer 1 enforcement ships in WP-V1.x-CASTLE-WALL.
function renderTopbarAttestationBadge(stateName) {
  if (stateName === "unavailable") {
    return '<span class="pill" data-pill="attestation">attestation: unavailable</span>';
  }
  const valid = stateName === "verified" || stateName === "degraded" || stateName === "unverified" || stateName === "pending";
  if (!valid) return renderTopbarAttestationBadge("unavailable");
  const cls = stateName;
  const ringDashed = cls === "pending" ? " dashed" : "";
  return '<span class="att-global ' + cls + '" data-pill="attestation" title="Fortress attestation">' +
    '<span class="seal">' +
      '<span class="seal-ring' + ringDashed + '"></span>' +
      '<span class="seal-core"></span>' +
    '</span>' +
    '<span class="label">' + escHtml(cls) + '</span>' +
  '</span>';
}

// Legacy clipboard path for non-secure contexts, where navigator.clipboard is
// undefined. Returns true only when the copy actually succeeded, so the caller
// can fall through to an honest "copy it manually" message. The scratch textarea
// is positioned offscreen and removed synchronously; it never enters layout.
function copyViaExecCommand(text) {
  try {
    const ta = document.createElement("textarea");
    ta.value = text;
    ta.setAttribute("readonly", "");
    ta.style.position = "fixed";
    ta.style.top = "-1000px";
    ta.style.opacity = "0";
    document.body.appendChild(ta);
    ta.select();
    const ok = document.execCommand && document.execCommand("copy");
    document.body.removeChild(ta);
    if (ok) toast("Machine id copied.", "info");
    return ok === true;
  } catch (e) {
    return false;
  }
}

function renderTopbar() {
  // S3 nit: id renamed topbar-pills -> sidebar-pills. S2 relocated these chips
  // from the top bar into the sidebar footer, leaving the old id describing a
  // place they no longer live. The element is still found by id here.
  const pillEl = document.getElementById("sidebar-pills");
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
  // Lock down button reflects the approved handler's reported outcome.
  const btn = document.getElementById("btn-lockdown");
  if (!btn) return;
  const t1 = state.tier1.lockdown;
  btn.classList.remove("tier1-pending", "tier1-partial", "tier1-engaged");
  btn.disabled = false;
  if (t1.state === "pending") {
    // Must match TIER1_BUTTON_COPY.lockdown.pending in status-mapping.ts.
    btn.textContent = "Awaiting approval";
    btn.classList.add("tier1-pending");
    btn.disabled = true;
  } else if (t1.state === "partial") {
    // Must match TIER1_BUTTON_COPY.lockdown.partial in status-mapping.ts.
    btn.textContent = "Partly locked down";
    btn.classList.add("tier1-partial");
  } else if (t1.state === "engaged") {
    // Must match TIER1_BUTTON_COPY.lockdown.engaged in status-mapping.ts.
    btn.textContent = "Locked down";
    btn.classList.add("tier1-engaged");
    btn.disabled = true;
  } else {
    // Must match TIER1_BUTTON_COPY.lockdown.idle in status-mapping.ts.
    btn.textContent = "Lock down";
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
  // Slice 2: the agent switcher folded into the top bar's scope control. The
  // trigger shows the machine and its id (server-rendered) plus the agent
  // scope; the menu's static head carries the full id and its copy control,
  // and the agent options are written into #agent-switcher-options.
  const labelEl = document.getElementById("agent-switcher-label");
  const menuEl = document.getElementById("agent-switcher-menu");
  const optionsEl = document.getElementById("agent-switcher-options") || menuEl;
  const trigger = document.getElementById("agent-switcher-trigger");
  if (!labelEl || !menuEl) return;
  const selected = state.agentScope.selectedAgentId;
  const selectedAgent = selected
    ? state.agents.find(function (a) { return a.agent_id === selected; })
    : null;
  // If the selected agent disappeared from the registry, fall back to "All".
  if (selected && !selectedAgent) state.agentScope.selectedAgentId = null;
  const curLabel = state.agentScope.selectedAgentId || "All agents";
  labelEl.textContent = curLabel;
  const open = !!state.agentScope.switcherOpen;
  menuEl.hidden = !open;
  if (trigger) trigger.setAttribute("aria-expanded", open ? "true" : "false");
  if (!open) return;
  if (!sourceLoaded(HUB + "/agents")) { optionsEl.innerHTML = renderSourceRead(HUB + "/agents"); return; }
  const allSelected = !state.agentScope.selectedAgentId;
  const rows = ['<button type="button" class="agent-switcher-opt' + (allSelected ? ' selected' : '') +
    '" data-action="agent-scope-select" data-agent-id="">' +
    '<span class="opt-glyph">··</span>' +
    '<span class="opt-name">All agents</span>' +
    // A roster count, never "protected": enforcement evidence is per agent.
    '<span class="opt-state">' + (state.agents.length === 1 ? "1 agent" : state.agents.length + " agents") + '</span>' +
    '</button>'];
  state.agents.forEach(function (a) {
    const map = agentDisplayStatus(a);
    const isSel = a.agent_id === state.agentScope.selectedAgentId;
    rows.push('<button type="button" class="agent-switcher-opt' + (isSel ? ' selected' : '') +
      '" data-action="agent-scope-select" data-agent-id="' + escHtml(a.agent_id) + '">' +
      '<span class="opt-glyph">' + escHtml(agentScopeGlyph(a.agent_id)) + '</span>' +
      '<span class="opt-name">' + escHtml(a.agent_id) + '</span>' +
      '<span class="opt-state">' + escHtml(map.label || "") + '</span>' +
      '</button>');
  });
  optionsEl.innerHTML = rows.join("");
}

// Wave 1 (2026-06-30): the posture seal. Honest verdict drives its color and
// word (deriveSeal); the popover spells out the named layers (no L-numbers).
function renderPostureSeal() {
  const seal = deriveSeal();
  const sealEl = document.getElementById("posture-seal");
  const wordEl = document.getElementById("posture-seal-word");
  const freshnessEl = document.getElementById("posture-seal-freshness");
  const popEl = document.getElementById("posture-seal-pop");
  if (!sealEl || !wordEl || !popEl) return;
  sealEl.classList.remove("tone-protected", "tone-attention", "tone-locked", "tone-unknown");
  if (seal.tone === "protected") sealEl.classList.add("tone-protected");
  else if (seal.tone === "locked") sealEl.classList.add("tone-locked");
  else if (seal.tone === "attention") sealEl.classList.add("tone-attention");
  // Unknown wears its own full-weight slate and an empty dotted ring, never
  // the neutral "Checking" chrome and never the pass hue.
  else sealEl.classList.add("tone-unknown");
  wordEl.textContent = seal.word;
  if (freshnessEl) {
    freshnessEl.textContent = seal.freshness.inline;
    // The freshness may ellipsize on a narrow bar; the full text stays here.
    freshnessEl.setAttribute("title", seal.freshness.inline);
    freshnessEl.classList.remove("fresh", "not-fresh");
    freshnessEl.classList.add(seal.freshness.current ? "fresh" : "not-fresh");
  }
  const open = !!state.posture.sealOpen;
  popEl.hidden = !open;
  sealEl.setAttribute("aria-expanded", open ? "true" : "false");
  sealEl.setAttribute("title", seal.title);
  if (!open) return;
  var head, sub;
  if (seal.tone === "protected") {
    head = "Protected. " + seal.freshness.inline + ".";
    sub = "Protected means Castle Wall enforcement was observed within the freshness window and the Charter still gates risky actions. It does not mean every past action is fully verified here.";
  } else if (seal.tone === "locked") {
    head = "This fortress is locked down.";
    // Must match the Lock down button title in html.ts and the
    // approval_pending.tier1.fortress_lockdown template: network access is
    // revoked for confined agents, and agents keep running and local access.
    sub = "Lockdown revokes network access for every confined agent; agents keep running and keep local access. Protected is only shown when Castle Wall enforcement has current evidence.";
  } else if (seal.tone === "attention") {
    head = "Protected is not confirmed.";
    sub = "The current enforcement observation is missing, stale, invalid, degraded, or missing a freshness window. Retry the protection evidence read.";
  } else {
    head = "Protection evidence is unavailable.";
    sub = "Current enforcement is Unknown. Retry the protection evidence read.";
  }
  const lines = postureLayerLines().map(function (l) {
    const dotCls = layerDotClass(l);
    return '<div class="pp-line"><span class="' + dotCls + '"></span>' +
      '<span class="pp-k">' + escHtml(l.k) + '</span>' +
      '<span class="pp-v">' + escHtml(l.v) + '</span></div>';
  }).join("");
  // One-surface fold: the seal expands to a "See full posture detail" link that
  // routes into the Posture screen (the folded-in metric cards, today's story,
  // anomaly findings, and per-agent drill-down). data-seal keeps the click
  // inside the seal so the outside-click dismiss does not fire first.
  const more = '<a class="pp-more" href="#posture" data-action="posture-detail-open">See full posture detail</a>';
  popEl.innerHTML = '<h4>' + escHtml(head) + '</h4><p class="pp-sub">' + escHtml(sub) + '</p>' + lines + renderSourceRead("/api/sovereignty") + more;
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
// Counts every #main replacement; the decision release waits for a quiet hold measured against it.
let mainWriteCount = 0;

// Talk owns one live composer for the lifetime of its current host. Background
// reads hydrate only named presentation parts; they never replace the form.
// Minimal VM DOMs and old engines retain the former whole-string path; the
// mounted owner runs only where every primitive it calls exists. The owner
// path reads Node.isConnected (hydrateTalkHost's disconnect check), calls
// Element.replaceChildren (non-append history rewrite) and parses through
// template.content; an engine missing any one of them would throw mid-hydrate,
// so the check names all three and such an engine takes the legacy path.
const talkDomOwnerSupported = typeof document.createElement === "function" &&
  !!document.createElement("template").content &&
  typeof Node !== "undefined" && !!Node.prototype && "isConnected" in Node.prototype &&
  typeof Element !== "undefined" && !!Element.prototype &&
  typeof Element.prototype.replaceChildren === "function";
let talkOwner = null;
let talkFollowIntent = null;
let talkComposing = false;
let talkViewportState = null;
let talkUserScrollEpoch = 0;
// "At the bottom" tolerance: 4 CSS px absorbs the sub-pixel remainder of
// scrollTop + clientHeight against scrollHeight under zoom and fractional
// device pixel ratios, where an exact equality never holds at the true bottom.
// Must match BOTTOM_SLACK_PX in server/test/e2e/talk-follow-ownership.e2e.ts.
const TALK_BOTTOM_SLACK_PX = 4;
// Motion threshold for the scroll-epoch watcher: half a CSS px, below which a
// scroll event is layout jitter from fractional scrollTop, not a reader moving.
const TALK_SCROLL_MOTION_PX = 0.5;
function captureTalkViewport(history) {
  if (!history) return null;
  // A history with no layout box (hidden panel, detached node, unlaid VM fake)
  // reports 0 for scrollTop, clientHeight and scrollHeight, and 0 + 0 >= 0 - 4
  // reads as "following". That reading says nothing about where the reader was,
  // so capture refuses: callers keep the last real snapshot instead of saving a
  // meaningless one, whatever order a teardown hides and captures in.
  if (history.isConnected === false || !(history.clientHeight > 0)) return null;
  return {
    top: history.scrollTop,
    following: history.scrollTop + history.clientHeight >= history.scrollHeight - TALK_BOTTOM_SLACK_PX
  };
}
// The only writer of talkViewportState from a live history: a refused capture
// leaves the saved snapshot untouched rather than clearing it.
function saveTalkViewport(history) {
  const snapshot = captureTalkViewport(history);
  if (snapshot) talkViewportState = snapshot;
  return snapshot;
}
function restoreTalkViewport(history, snapshot, forceFollow) {
  if (!history) return;
  if (forceFollow || !snapshot || snapshot.following) history.scrollTop = history.scrollHeight;
  else history.scrollTop = snapshot.top;
}
// A send's follow request survives until the reader actually scrolls. Both the
// mounted owner and the legacy whole-string path read this one predicate, so
// there is a single follow policy rather than one per render path.
function talkFollowRequested() {
  return !!talkFollowIntent && talkFollowIntent.scrollEpoch === talkUserScrollEpoch;
}
// Watches one history element for reader scrolls. Only a trusted scroll whose
// scrollTop actually moved bumps the epoch: a programmatic restore is followed
// by watch.lastTop = scrollTop, and a no-motion wheel at either end fires no
// movement, so neither revokes a send's follow request.
function watchTalkScroll(history) {
  const watch = { lastTop: history.scrollTop };
  watch.onScroll = function (event) {
    const moved = Math.abs(history.scrollTop - watch.lastTop) > TALK_SCROLL_MOTION_PX;
    watch.lastTop = history.scrollTop;
    if (event.isTrusted && moved) talkUserScrollEpoch++;
  };
  history.addEventListener("scroll", watch.onScroll);
  return watch;
}
function disposeTalkOwner() {
  if (!talkOwner) return;
  saveTalkViewport(talkOwner.history);
  talkOwner.history.removeEventListener("scroll", talkOwner.watch.onScroll);
  talkOwner.host.innerHTML = "";
  talkOwner = null;
  talkComposing = false;
}
function attachTalkOwner(host) {
  if (talkOwner && talkOwner.host !== host) disposeTalkOwner();
  const history = host.querySelector("#concierge-history");
  const input = host.querySelector('input[data-action="concierge-input"]');
  if (!history || !input || !host.querySelector("[data-talk-read-status]") ||
      !host.querySelector("[data-talk-error]")) throw new Error("Talk mount anchors missing");
  const owner = { host: host, history: history, input: input, watch: watchTalkScroll(history) };
  talkOwner = owner;
  restoreTalkViewport(history, talkViewportState, talkFollowRequested());
  owner.watch.lastTop = history.scrollTop;
}
// Legacy whole-string path, after a write: restore the viewport and watch the
// new history element. A landed reply (pendingScroll) follows only while the
// send's follow request is unrevoked, the same epoch rule the mounted owner
// applies, so a reader who scrolled during the in-flight send stays put.
// The replaced history element took its old watcher with it; no removal needed.
function restoreLegacyTalkHistory(history, viewport) {
  if (history) {
    restoreTalkViewport(history, viewport || talkViewportState,
      state.chat.concierge.pendingScroll && talkFollowRequested());
    saveTalkViewport(history);
    if (typeof history.addEventListener === "function") watchTalkScroll(history);
  }
  state.chat.concierge.pendingScroll = false;
}
function hydrateTalkHost(host) {
  const owner = talkOwner;
  // Fail loud, recover by navigation only: a disconnected owner means some
  // other writer replaced the mounted composer, so the draft and viewport this
  // owner holds no longer match the screen. Silently remounting would hide
  // that second writer and could drop an operator's typed draft; throwing
  // stops this render, and the next route or panel change disposes the stale
  // owner and mounts a fresh one from state.
  if (!owner || owner.host !== host || !owner.input.isConnected || !owner.history.isConnected) {
    throw new Error("Talk mount disconnected during background refresh");
  }
  const template = document.createElement("template");
  template.innerHTML = renderDashboardConcierge();
  const fresh = template.content.querySelector(".concierge-wrap");
  if (!fresh) throw new Error("Talk render shell missing");
  // Read-status and badge changes resize history even when its messages are unchanged.
  // Capture before any presentation write so shrinking the viewport cannot erase follow intent.
  const history = owner.history;
  const viewport = captureTalkViewport(history);
  const requestedFollow = talkFollowRequested();
  ["[data-talk-read-status]", ".concierge-meta", "[data-talk-error]"].forEach(function (selector) {
    const livePart = host.querySelector(selector);
    const freshPart = fresh.querySelector(selector);
    if (!livePart || !freshPart) throw new Error("Talk presentation anchor missing: " + selector);
    if (livePart.innerHTML === freshPart.innerHTML) return;
    // Rewriting a part replaces its controls (the read status carries Retry),
    // so a keyboard user focused inside it would drop to the page body. Focus
    // is captured from the part being rewritten and restored into it, on
    // whichever host (full-page Talk or the panel) this owner is mounted in.
    const focus = livePart.contains(document.activeElement) ? captureInputFocus(livePart) : null;
    livePart.innerHTML = freshPart.innerHTML;
    restoreInputFocus(livePart, focus);
  });
  const freshHistory = fresh.querySelector("#concierge-history");
  if (!freshHistory) throw new Error("Talk history anchor missing");
  const changed = history.innerHTML !== freshHistory.innerHTML;
  // Only real message admission starts a thread; an empty-to-empty refresh must preserve the suggestion reader's offset.
  const firstMessages = changed && !history.querySelector(".concierge-msg") && !!freshHistory.querySelector(".concierge-msg");
  if (changed) {
    // Compare and copy text separators as well as message elements. Cloning
    // only .children drops the renderer's newline nodes, making a later
    // unchanged refresh look different and replace selected reply text.
    const oldNodes = Array.from(history.childNodes);
    const newNodes = Array.from(freshHistory.childNodes);
    const appendOnly = oldNodes.length > 0 && newNodes.length > oldNodes.length &&
      oldNodes.every(function (node, index) { return node.isEqualNode(newNodes[index]); });
    if (appendOnly) {
      newNodes.slice(oldNodes.length).forEach(function (node) { history.appendChild(node.cloneNode(true)); });
    } else {
      history.replaceChildren(...newNodes.map(function (node) { return node.cloneNode(true); }));
    }
  }
  const sending = state.chat.concierge.sending;
  owner.input.disabled = sending;
  host.querySelectorAll(".concierge-suggest").forEach(function (button) { button.disabled = sending; });
  const send = host.querySelector('[data-action="concierge-send"]');
  if (!send) throw new Error("Talk send control missing");
  send.disabled = sending;
  const label = sending ? "Sending..." : "Send";
  if (send.textContent !== label) send.textContent = label;
  // Preserve the reader across the complete hydration, including chrome-only refreshes.
  restoreTalkViewport(history, viewport || talkViewportState, firstMessages || (changed && requestedFollow));
  // Rebase only our own motion so a reader scroll awaiting its event still revokes the send's follow request.
  if (!viewport || history.scrollTop !== viewport.top) owner.watch.lastTop = history.scrollTop;
  state.chat.concierge.pendingScroll = false;
}


// F8 fix: capture focused-input identity + caret position so an SSE-
// triggered rerender during typing does not clobber the operator's typing
// experience. innerHTML replacement creates new DOM nodes; we re-find the
// equivalent input or route control by data-action, href and optional
// data-agent-id and restore focus. Shared by #main and the Talk panel, the
// two containers whose inputs a rerender rewrites.
function captureInputFocus(container) {
  const active = document.activeElement;
  if (!active || (container.contains && !container.contains(active)) || typeof active.getAttribute !== "function") return null;
  if (active.tagName === "INPUT" && ["text", "search", "email", "url", "tel", "password"].indexOf(active.type || "text") >= 0 && active.getAttribute("data-action")) {
    return {
      kind: "input",
      action: active.getAttribute("data-action"),
      agentId: active.getAttribute("data-agent-id"),
      itemId: active.getAttribute("data-item-id"),
      selectionStart: active.selectionStart,
      selectionEnd: active.selectionEnd
    };
  }
  if ((active.tagName === "BUTTON" || active.tagName === "A") && (active.getAttribute("data-action") || active.getAttribute("href"))) {
    return {
      kind: "control",
      action: active.getAttribute("data-action"),
      href: active.getAttribute("href"),
      agentId: active.getAttribute("data-agent-id"),
      itemId: active.getAttribute("data-item-id")
    };
  }
  return null;
}
function restoreInputFocus(container, focus) {
  if (!focus || !container.querySelector) return;
  // Decision controls disappear and reappear on different queue rows as the
  // inbox changes. Restoring them by selector can move focus to the wrong
  // decision, so only stable route controls and text inputs are restored.
  if (focus.kind === "control" && focus.itemId) return;
  let sel;
  if (focus.kind === "input") sel = 'input[data-action="' + escCssAttr(focus.action) + '"]';
  else if (focus.action) sel = '[data-action="' + escCssAttr(focus.action) + '"]';
  else if (focus.href) sel = 'a[href="' + escCssAttr(focus.href) + '"]';
  else return;
  if (focus.agentId) sel += '[data-agent-id="' + escCssAttr(focus.agentId) + '"]';
  if (focus.itemId) sel += '[data-item-id="' + escCssAttr(focus.itemId) + '"]';
  let matches;
  try {
    matches = container.querySelectorAll ? container.querySelectorAll(sel) : [];
  } catch (e) { return; }
  // A stable control is restored only when the selector names one element.
  // Ambiguous matches can move focus to a sibling control with the same action.
  if (!matches || matches.length !== 1) return;
  const el = matches[0];
  if (el && typeof el.focus === "function") {
    try {
      el.focus();
      if (
        focus.kind === "input" &&
        typeof el.setSelectionRange === "function" &&
        focus.selectionStart != null &&
        focus.selectionEnd != null
      ) {
        el.setSelectionRange(focus.selectionStart, focus.selectionEnd);
      }
    } catch (e) { /* ignore browsers that disallow programmatic focus */ }
  }
}

// ── Render: main area ──────────────────────────────────────────────────
function renderMain() {
  const main = document.getElementById("main");
  if (!main) return;
  const talkMain = talkDomOwnerSupported && state.route === "dashboard" && !liveUpdatesStopped;
  const focus = talkMain ? null : captureInputFocus(main);
  // Legacy capture reads the one live history wherever it is mounted (Talk's
  // element ids exist once in the document). A panel-to-full-page move runs
  // renderMain before renderTalkPanel closes the panel, so this is the only
  // point that sees the panel reader's current position rather than the
  // panel's previous write.
  const legacyViewport = !talkDomOwnerSupported ? saveTalkViewport(document.getElementById("concierge-history")) : null;
  let nextHtml;
  switch (state.route) {
    case "dashboard": nextHtml = renderDashboardConcierge(); break;
    case "activity": nextHtml = renderActivityScreen(); break;
    case "posture": nextHtml = renderPostureScreen(); break;
    case "approvals": nextHtml = renderApprovalsScreen(); break;
    case "agents": nextHtml = renderAgentsList(); break;
    case "agent-detail": nextHtml = renderAgentDetail(); break;
    case "machines": nextHtml = renderMachinesScreen(); break;
    case "enforcement": nextHtml = renderEnforcementScreen(); break;
    case "findings": nextHtml = renderFindingsScreen(); break;
    // Policies hosts the auto-trigger ladder as a section; #auto-trigger
    // still renders the ladder on its own.
    case "policy": nextHtml = renderPolicyCenter() + renderMfpFoldedSections(); break;
    case "auto-trigger": nextHtml = renderAutoTriggerPage(); break;
    case "integrations": nextHtml = renderIntegrationsScreen(); break;
    case "settings": nextHtml = settingsTabStrip("health") + renderHealthPage(); break;
    case "intelligence": nextHtml = settingsTabStrip("intelligence") + renderIntelligenceCenter() + renderSourceRead(HUB + "/intelligence/status") + renderSourceRead(HUB + "/intelligence/config"); break;
    case "attestation": nextHtml = settingsTabStrip("attestation") + renderAttestation(); break;
    case "honeypot": nextHtml = renderHoneypotPage(); break;
    case "privacy": nextHtml = settingsTabStrip("privacy") + renderPrivacyPage(); break;
    case "coordination": nextHtml = renderCoordinationPage(); break;
    case "health": nextHtml = settingsTabStrip("health") + renderHealthPage(); break;
    case "exit-drill": nextHtml = renderExitDrill(); break;
    default: nextHtml = '<p class="muted">Route not found.</p>';
  }
  if (liveUpdatesStopped) nextHtml = unavailablePanel("Live updates stopped", ["/api/posture/home"]);
  // F is outside the route body, including stopped-updates and Talk screens.
  renderFeedback();
  // Fail loud, recover by navigation only (same contract as hydrateTalkHost):
  // a composer that left the document while still owned was replaced by some
  // other writer, and a silent remount would discard the draft it held.
  if (talkMain && talkOwner && talkOwner.host === main && !talkOwner.input.isConnected) {
    throw new Error("Talk composer disconnected during background refresh");
  }
  const mountedTalk = talkMain && talkOwner && talkOwner.host === main && talkOwner.input.isConnected;
  let didWrite = false;
  if (mountedTalk) {
    hydrateTalkHost(main);
  } else if (__renderCache.route !== state.route || __renderCache.html !== nextHtml || talkMain) {
    if (talkOwner && (talkOwner.host === main || talkMain)) disposeTalkOwner();
    main.innerHTML = nextHtml;
    didWrite = true;
    mainWriteCount++;
    __renderCache.route = state.route;
    __renderCache.html = talkMain ? null : nextHtml;
    if (talkMain) attachTalkOwner(main);
  }
  if (state.route === "machines") hydrateMachinesScreen();
  if (state.route === "dashboard" && !talkDomOwnerSupported && didWrite) {
    restoreLegacyTalkHistory(main.querySelector("#concierge-history"), legacyViewport);
  }
  restoreInputFocus(main, focus);
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
        '<div data-talk-read-status>' + renderSourceRead(HUB + "/chat/concierge/history") + '</div>',
        '<div class="concierge-header">',
          '<div class="concierge-persona">',
            '<div class="glyph-ring"></div>',
            '<div class="concierge-persona-text"><strong>Sanctuary Fortress concierge</strong><small>read-only over fortress state</small></div>',
          '</div>',
          '<div class="concierge-meta">' + badge + '</div>',
        '</div>',
        '<div data-talk-error>' + errorBanner + '</div>',
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
// The state dot beside an agent's state word, one shape per state so it
// reads in monochrome: active is the pass circle, locked down the hollow
// locked square, an error the fault square, Unknown the hollow unknown ring,
// and known transitional states (paused, restarting, unwrapping) the warn triangle.
// An agent with no current evidence is Unknown, never painted as working.
function agentStateClass(status) {
  if (status === "active") return "live";
  if (status === "locked_down") return "locked";
  if (status === "error") return "off";
  if (!status || status === "unknown") return "unknown";
  if (status === "paused" || status === "restarting" || status === "unwrapping") return "idle";
  return "unknown";
}
// The inspect pane's state pill wears the same state as the dot inside it.
const AGENT_STATE_PILL_TONE = { live: "tone-verified", locked: "tone-locked", off: "tone-unverified", unknown: "tone-unknown", idle: "tone-degraded" };
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
  else if (status === "unknown") { cls = "neutral"; label = "Unknown"; }
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
  if (!sourceLoaded("/api/honeypot/tool-traps") || !sourceLoaded("/api/honeypot/credential-traps")) return unavailablePanel("Honeypots", ["/api/honeypot/tool-traps", "/api/honeypot/credential-traps"]);
  const toolTraps = state.honeypot.toolTraps || [];
  const credentialTraps = state.honeypot.credentialTraps || [];
  const toolPage = mfpPage(toolTraps, "toolTraps", MFP_ALL_SERVED);
  const credentialPage = mfpPage(credentialTraps, "credentialTraps", MFP_ALL_SERVED);
  const toolRows = toolTraps.length ? toolPage.rows.map(function (trap) {
    const activations = trap.activations || [];
    const latest = activations.length ? activations[activations.length - 1] : null;
    const followups = latest && latest.follow_up_tool_calls ? latest.follow_up_tool_calls : [];
    const followupText = followups.length
      ? followups.slice(0, MFP_PAGE_SIZE).map(function (f) { return escHtml(f.tool_name) + " at " + escHtml(shortTime(f.called_at)); }).join(", ")
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
  const credentialRows = credentialTraps.length ? credentialPage.rows.map(function (trap) {
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
  // Successful empty reads already have an empty state, so only populated lists need a record pager.
  '</div></div>' + error + createCta + (credentialTraps.length ? mfpPager(credentialPage, "credentialTraps", "/api/honeypot/credential-traps") : "") + credentialRows + (toolTraps.length ? mfpPager(toolPage, "toolTraps", "/api/honeypot/tool-traps") : "") + toolRows;
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

function durationLabelFromMs(ms) {
  const safeMs = Math.max(0, Number(ms) || 0);
  const sec = Math.floor(safeMs / 1000);
  if (sec < 60) return sec + "s";
  const min = Math.floor(sec / 60);
  if (min < 60) return min + "m";
  const hr = Math.floor(min / 60);
  if (hr < 24) return hr + "h";
  const day = Math.floor(hr / 24);
  return day + "d";
}

// Inventory pages hold one screenful; detail lists hold twenty rows to keep review bounded.
const AGENTS_PAGE_SIZE = 25;
const AGENT_DETAIL_LIST_LIMIT = 20;
const AGENT_STATE_FILTERS = [["", "All states"], ["active", "Protected"], ["unknown", "Unknown"], ["paused", "Paused"], ["locked_down", "Locked down"], ["error", "Error"], ["ownerless", "Ownerless"]];
const AGENT_TABS = ["overview", "approvals", "activity", "policy", "identity", "memory", "evidence"];
function agentEmpty(title, reason, href, action) {
  return '<div class="overview-empty"><h3>' + escHtml(title) + '</h3><p>' + escHtml(reason) + '</p><a class="btn" href="' + escHtml(href) + '">' + escHtml(action) + '</a></div>';
}
function renderAgentsList() {
  const loaded = sourceLoaded(HUB + "/agents");
  if (loaded && !state.agents.length) return '<h1>Agents</h1><section data-agents-first-run>' + agentEmpty("No protected agents yet", "Run sanctuary protect in your agent's project. The roster returned no registered agents.", "#posture", "Open Overview") + '</section>';
  const total = loaded ? state.agents.length : null;
  const age = loadedSourceReadAge(HUB + "/agents");
  const home = sourceLoaded("/api/posture/home") && state.posture.home;
  const detected = loaded && home && unprotectedHarnesses(home);
  const protectedCount = loaded && home ? state.agents.filter(function (a) { return agentEvidenceStatus(a) === "active"; }).length : null;
  const denominator = detected ? total + detected.length : null;
  const count = function (n, d) { return n === null || d === null ? overviewChip("unknown", "UNKNOWN") : escHtml(n + " of " + d); };
  const rosterAge = "roster read " + (age || "Unknown");
  const tiles = overviewTile("Total", count(total, denominator), escHtml("Loaded registered of detected in this read · " + rosterAge + "; detection read " + (loadedSourceReadAge("/api/posture/home") || "Unknown")), "#agents") +
    overviewTile("Protected of detected", count(protectedCount, denominator), escHtml("Current per-agent enforcement evidence required · posture read " + (loadedSourceReadAge("/api/posture/home") || "Unknown")), "#agents?state=active") +
    overviewTile("Ownerless", count(loaded ? state.agents.filter(function (a) { return !a.identity_id; }).length : null, total), escHtml("Of loaded registered agents; detected-only ownership Unknown · " + rosterAge), "#agents?state=ownerless") +
    overviewTile("At risk", overviewChip("unknown", "Not evaluated"), escHtml("Risk evaluation not served for " + (total === null ? "Unknown" : total) + " registered agents · " + rosterAge), "#agents");
  if (!loaded) return '<h1>Agents</h1><div class="agents-tiles">' + tiles + '</div>' + renderOverviewAgentsTable();
  const filters = state.agentInventory;
  const rows = state.agents.filter(function (a) {
    return (!filters.harness || a.harness === filters.harness) && (!filters.status || (filters.status === "ownerless" ? !a.identity_id : agentEvidenceStatus(a) === filters.status));
  }).sort(function (a, b) {
    if (filters.sort === "activity") return String(b.last_activity_at || "").localeCompare(String(a.last_activity_at || ""));
    const order = String(a.agent_id).localeCompare(String(b.agent_id));
    return filters.sort === "name-desc" ? -order : order;
  });
  filters.page = Math.min(filters.page, Math.max(0, Math.ceil(rows.length / AGENTS_PAGE_SIZE) - 1));
  const select = function (label, action, values, selected) {
    return '<label>' + label + '<select data-action="' + action + '">' + values.map(function (v) { return '<option value="' + escHtml(v[0]) + '"' + (v[0] === selected ? ' selected' : '') + '>' + escHtml(v[1]) + '</option>'; }).join("") + '</select></label>';
  };
  const harnesses = Array.from(new Set(state.agents.map(function (a) { return a.harness; }))).sort();
  const controls = select("State", "agents-state", AGENT_STATE_FILTERS, filters.status) +
    select("Harness", "agents-harness", [["", "All harnesses"]].concat(harnesses.map(function (h) { return [h, h]; })), filters.harness) +
    select("Sort", "agents-sort", [["name", "Agent A to Z"], ["name-desc", "Agent Z to A"], ["activity", "Last activity"]], filters.sort);
  const page = '<div class="agent-pagination"><span>Page ' + (filters.page + 1) + ' of ' + Math.max(1, Math.ceil(rows.length / AGENTS_PAGE_SIZE)) + ' · ' + escHtml(rosterAge) + '</span>' +
    '<button class="btn" data-action="agents-page" data-page="' + (filters.page - 1) + '"' + (filters.page === 0 ? ' disabled' : '') + '>Previous</button>' +
    '<button class="btn" data-action="agents-page" data-page="' + (filters.page + 1) + '"' + ((filters.page + 1) * AGENTS_PAGE_SIZE >= rows.length ? ' disabled' : '') + '>Next</button></div>';
  return '<h1>Agents</h1><div class="agents-tiles">' + tiles + '</div><div class="agent-filters">' + controls + '</div>' +
    renderOverviewAgentsTable(rows, AGENTS_PAGE_SIZE, filters.page * AGENTS_PAGE_SIZE) + page +
    '<p class="muted">Inventory covers the served roster. Detection uses harness configuration presence; counts are not a process census.</p>';
}

function agentPolicySummary(agent) {
  return sourceLoaded(HUB + "/policies") && state.policies.find(function (p) { return p.policy_id === agent.policy_id; });
}
function renderAgentStanding(agent) {
  // A served negative policy flag is evidence of intent, not an unanswered policy read.
  const evidence = sourceLoaded("/api/posture/home") && postureEvidenceByAgent(state.posture.home || {})[agent.agent_id];
  const row = function (k, v) { return '<dt>' + k + '</dt><dd>' + v + '</dd>'; };
  return '<section class="card" aria-label="Standing"><h3>Standing</h3><dl class="kv">' +
    row("Status", '<span class="glyph ' + agentDisplayStatus(agent).glyph + '"></span> ' + escHtml(agentDisplayStatus(agent).label)) +
    row("Protection requested", escHtml(evidence && typeof evidence.policy_protected === "boolean" ? (evidence.policy_protected ? "Yes" : "No") + " · roster intent; posture read " + loadedSourceReadAge("/api/posture/home") : "Unknown · no agent policy evidence served")) +
    row("Enforcement confirmed", agentEnforcementChip(agent) + '<span class="muted"> Per-agent posture · ' + escHtml(evidence && evidence.last_enforcement_evidence_at ? relTimeFromIso(evidence.last_enforcement_evidence_at) : "evidence age Unknown") + '</span>') +
    row("Account isolation", "Unknown · account-isolation evidence not served") +
    row("Memory", "Unknown · agent memory inventory not served") +
    row("Budget today", escHtml(agentBudgetText(agent) + " · budget evidence " + (agent.budget_summary && agent.budget_summary.last_refreshed_at ? relTimeFromIso(agent.budget_summary.last_refreshed_at) : "Unknown"))) +
    row("Reputation", "Unknown · agent reputation evidence not served") +
    row("Last anomaly", "Unknown · agent-scoped anomaly evidence not served") + '</dl></section>';
}
function renderAgentIdentity(agent) {
  // Only these public metadata fields are rendered; extra response fields never enumerate key material.
  return '<section class="card" aria-label="Identity"><h3>Identity</h3><dl class="kv"><dt>Owner</dt><dd>' + escHtml(agent.identity_id || "Unknown") + '</dd>' +
    '<dt>DID</dt><dd>Unknown · agent DID not served</dd><dt>Fingerprint</dt><dd>Unknown · agent fingerprint not served</dd>' +
    '<dt>Rotation</dt><dd>Unknown · agent key history not served</dd><dt>Custody</dt><dd>Unknown · custody evidence not served</dd>' +
    '<dt>Evidence age</dt><dd>Roster read ' + escHtml(loadedSourceReadAge(HUB + "/agents") || "Unknown") + '</dd></dl></section>';
}
// One unresolved transport slot survives a UI timeout; a transport ignoring abort cannot accumulate reads.
const AGENT_REACH_MAX_IN_FLIGHT = 1;
const AGENT_REACH_DESTINATION_LIMIT = 256; // A detail snapshot, with the full policy available at its existing link.
const AGENT_REACH_FIELD_LIMIT = 2048; // Accommodates URL-sized destinations without retaining arbitrary strings.
const AGENT_REACH_BODY_LIMIT = 2 * 1024 * 1024; // Two MiB covers 256 pairs of URL-sized fields plus JSON framing.
const AGENT_REACH_MAX_AGE_MS = 60 * 1000; // Configured reach must be reread after one minute; it is not live enforcement evidence.
let agentReachController = null;
let agentReachRevision = 0;
let agentReachInFlight = 0;
let agentReachExpiry = null;
// One pending slot: the newest subject asked for while a read holds admission, never a queue.
let agentReachPendingId = null;
async function readAgentReachBody(response) {
  if (!response.ok || !response.body) throw new Error("Reach unavailable");
  const reader = response.body.getReader();
  const decoder = new TextDecoder();
  let bytes = 0;
  let text = "";
  try {
    while (true) {
      const chunk = await reader.read();
      if (chunk.done) break;
      bytes += chunk.value.byteLength;
      // Refuse the whole read before decoding or retaining a body beyond the per-request budget.
      if (bytes > AGENT_REACH_BODY_LIMIT) throw new Error("Reach unavailable");
      text += decoder.decode(chunk.value, { stream: true });
    }
    return JSON.parse(text + decoder.decode());
  } finally { void reader.cancel().catch(function () {}); reader.releaseLock(); }
}
async function loadAgentReach(agentId) {
  if (agentReachInFlight >= AGENT_REACH_MAX_IN_FLIGHT) {
    if (state.agentReach.agentId !== agentId) {
      ++agentReachRevision;
      agentReachController.abort();
      // This subject has not been read yet, so it waits as loading and never reads as a failed read.
      agentReachPendingId = agentId;
      state.agentReach = { state: "state_LOADING", agentId: agentId, data: null, readAt: 0 };
      rerender();
    }
    return;
  }
  const revision = ++agentReachRevision;
  const controller = new AbortController();
  agentReachController = controller;
  agentReachInFlight++;
  clearTimeout(agentReachExpiry);
  state.agentReach = { state: "state_LOADING", agentId: agentId, data: null, readAt: 0 };
  rerender();
  const headers = {};
  if (TOKEN) headers.Authorization = "Bearer " + TOKEN;
  let deadline;
  const expired = new Promise(function (_, reject) {
    deadline = setTimeout(function () { controller.abort(); reject(new Error("Reach unavailable")); }, DASHBOARD_READ_DEADLINE_MS);
  });
  // Release admission only when transport AND body reading settle, never when the UI deadline wins.
  const transport = (async function () {
    try {
      const response = await fetch(credentialedReadUrl("/api/posture/reach/" + encodeURIComponent(agentId), "GET"), { headers: headers, cache: "no-store", signal: controller.signal });
      if (controller.signal.aborted) { if (response.body) void response.body.cancel().catch(function () {}); throw new Error("Reach unavailable"); }
      return await readAgentReachBody(response);
    } finally {
      agentReachInFlight--;
      const next = agentReachPendingId;
      agentReachPendingId = null;
      // setRoute clears this slot whenever the detail route closes, so a subject still pending here belongs to an open
      // or opening detail page: an open from another route queues the read before its hashchange lands.
      if (next && next === state.selectedAgentId) void loadAgentReach(next);
    }
  })();
  try {
    const data = await Promise.race([transport, expired]);
    // Only this requested subject's current read may populate reach; late or cancelled reads never publish.
    if (revision !== agentReachRevision || controller.signal.aborted) return;
    if (!data || data.agent_id !== agentId || !Array.isArray(data.destinations) || data.destinations.length > AGENT_REACH_DESTINATION_LIMIT || !data.destinations.every(function (d) { return d && typeof d.destination === "string" && d.destination.length <= AGENT_REACH_FIELD_LIMIT && typeof d.rule_id === "string" && d.rule_id.length <= AGENT_REACH_FIELD_LIMIT && ["allow", "prompt", "deny"].includes(d.disposition) && ["castle_wall", "policy"].includes(d.enforcing_layer); })) throw new Error("Reach unavailable");
    // Retain only the bounded public projection; unknown response fields are not a cache or a secret inventory.
    const projection = { enforcement_confirmed: data.enforcement_confirmed === true, has_wall_policy: data.has_wall_policy === true,
      destinations: data.destinations.map(function (d) { return { destination: d.destination, rule_id: d.rule_id, disposition: d.disposition, enforcing_layer: d.enforcing_layer }; }) };
    state.agentReach = { state: "state_LOADED", agentId: agentId, data: projection, readAt: Date.now() };
    agentReachExpiry = setTimeout(function () {
      if (revision !== agentReachRevision) return;
      state.agentReach = { state: "state_EXPIRED", agentId: agentId, data: null, readAt: state.agentReach.readAt };
      rerender();
    }, AGENT_REACH_MAX_AGE_MS);
  } catch (e) {
    if (revision !== agentReachRevision) return;
    state.agentReach = { state: "state_FAILED", agentId: agentId, data: null, readAt: Date.now() };
  } finally {
    clearTimeout(deadline);
    if (revision === agentReachRevision) rerender();
  }
}
// Every way of opening an agent row must reset the tab and start its read before navigation and inspection.
function openAgentRowInspect(agentId) {
  state.selectedAgentId = agentId;
  state.agentTab = "overview";
  void loadAgentReach(agentId);
  if (location.hash !== "#agent-detail") location.hash = "agent-detail";
  else setRoute("agent-detail");
  void onAgentInspectOpen(agentId);
}

function renderAgentReach(agent) {
  const policy = agentPolicySummary(agent);
  const read = state.agentReach;
  const now = Date.now();
  // Only a numeric read time can be aged; any other value counts as no time, so no comparison or Date below can throw.
  const readMs = typeof read.readAt === "number" ? read.readAt : NaN;
  // A different subject has no read here, regardless of the stored read's state.
  let reachState = read.agentId !== agent.agent_id ? "state_UNREAD" : read.state;
  if (reachState === "state_LOADED" && read.data) {
    // A stopped stream cannot establish current reach even when its last read is recent.
    if (liveUpdatesStopped) reachState = "state_STOPPED";
    // A read time that is not a finite number cannot be aged, so it cannot establish freshness either.
    else if (!Number.isFinite(readMs)) reachState = "state_UNDATED";
    // A future read cannot establish freshness against this device's clock.
    else if (now < readMs) reachState = "state_FUTURE";
    // Configured reach expires at the same one-minute boundary used by the loader.
    else if (now - readMs >= AGENT_REACH_MAX_AGE_MS) reachState = "state_EXPIRED";
  }
  // A read time outside the Date range has no ISO form, so its age reads Unknown instead of throwing while the card renders.
  const readTime = new Date(readMs);
  const readAge = Number.isFinite(readTime.getTime()) ? relTimeFromIso(readTime.toISOString()) : "time Unknown";
  // Only a current, matching loaded read may expose destinations; malformed clocks remain withheld.
  const reach = reachState === "state_LOADED" && !liveUpdatesStopped && now >= readMs && now - readMs < AGENT_REACH_MAX_AGE_MS ? read.data : null;
  const intro = '<p>' + escHtml(policy ? policy.display_label : "Policy summary Unknown") + ' · ' + escHtml(agent.policy_id || "policy Unknown") + ' · version Unknown · policy read ' + escHtml(loadedSourceReadAge(HUB + "/policies") || "Unknown") + '</p>';
  const lanes = [["allow", "May reach"], ["prompt", "Asks you first"], ["deny", "Never"]].map(function (lane) {
    const entries = reach ? reach.destinations.filter(function (d) { return d.disposition === lane[0]; }) : [];
    return '<div class="agent-reach-lane"><h4>' + lane[1] + '</h4><div>' + (reach ? entries.slice(0, AGENT_DETAIL_LIST_LIMIT).map(function (d) {
      return '<div class="mono">' + escHtml(d.destination) + ' <span class="muted">' + (d.enforcing_layer === "castle_wall" ? "Castle Wall" : "Charter") + ' · ' + escHtml(d.rule_id) + '</span></div>';
    }).join("") + '<p class="muted">showing ' + Math.min(entries.length, AGENT_DETAIL_LIST_LIMIT) + ' of ' + entries.length + ' configured destinations</p>' : '<span class="state-chip unknown"><i aria-hidden="true"></i>UNKNOWN</span>') + '</div></div>';
  }).join("");
  // A configured rule and a fresh read do not prove enforcement; both the scoped reach and posture must confirm it.
  const confirmed = reach && reach.enforcement_confirmed === true && agentEvidenceStatus(agent) === "active";
  // Each read state describes its own evidence; absence never borrows a failure or loading claim.
  const descriptions = {
    state_UNREAD: "Reach not read yet.",
    state_LOADING: "Reading this agent's reach.",
    state_EXPIRED: "Reach read expired after one minute without interaction.",
    state_STOPPED: "Live updates stopped. Retry to resume.",
    state_FUTURE: "Reach read time is ahead of this device's clock, so it is not current.",
    state_UNDATED: "Reach read time is unknown, so it is not current.",
    state_FAILED: "Reach read failed · " + readAge,
    state_LOADED: "The reach source answered without a record for this agent."
  };
  // Withheld loaded evidence must not leave lanes visible as though they describe current reach.
  const visibleLanes = ["state_STOPPED", "state_UNDATED", "state_FUTURE", "state_EXPIRED"].includes(reachState) ? "" : lanes;
  const description = reach ? (confirmed ? "Enforcement confirmed" : "Configured; enforcement not confirmed") + (reach.has_wall_policy ? "" : ". No Castle Wall ruleset applies") : descriptions[reachState];
  return '<section class="card" aria-label="Effective reach"><h3>Effective reach</h3>' + intro + '<p>' + escHtml(description) + '</p>' + visibleLanes +
    '<p class="muted">' + (reach ? reach.destinations.filter(function (d) { return d.disposition === "allow"; }).length + ' allowed destinations; ' : '') + 'requested hosts Unknown · MCP servers Unknown · tools Unknown · reach read ' + escHtml(reach ? readAge : "Unknown") + '</p>' +
    '<a class="btn" href="/posture/agent/' + escHtml(encodeURIComponent(agent.agent_id)) + '">All configured reach</a> ' +
    '<button class="btn" data-action="agent-reach-refresh" data-agent-id="' + escHtml(agent.agent_id) + '">Refresh reach</button></section>';
}
function agentApprovalRows(items) {
  return items.slice(0, AGENT_DETAIL_LIST_LIMIT).map(function (item) {
    // Only an explicit Tier 2 hold is safe inline; unknown tiers must take the Approvals review path.
    const controls = item.tier === "tier2"
      ? '<button class="btn" data-action="inbox-deny" data-item-id="' + escHtml(item.item_id) + '"' + approvalDecisionDisabled() + '>Deny</button><button class="btn btn-primary" data-action="inbox-approve" data-item-id="' + escHtml(item.item_id) + '"' + approvalDecisionDisabled() + '>Allow once</button>' + renderDecisionInline(item)
      : '<a class="btn" href="#approvals">Review in Approvals</a>';
    return '<div class="approval-row"><div class="what">' + overviewChip("warn", "WAITING") + ' <span>' + (item.tier === "tier1" ? "Tier 1" : item.tier === "tier2" ? "Tier 2" : "Tier Unknown") + '</span> ' +
      escHtml(renderTemplate(item.display_template_id, item.display_template_args)) + '<span class="muted"> · ' + escHtml(item.created_at ? relTimeFromIso(item.created_at) : "age Unknown") + '</span></div><div class="actions">' + controls + '</div></div>';
  }).join("");
}
function renderAgentApprovals(agent) {
  const items = sourceLoaded(HUB + "/inbox") && !state.inboxRedacted ? state.inbox.filter(function (i) { return i.agent_id === agent.agent_id && i.kind === "approval_pending" && !i.resolved; }) : null;
  return '<section class="card"><h3>This agent\'s approvals</h3>' + (items ? (items.length ? agentApprovalRows(items) : agentEmpty("No waiting approvals", "The loaded queue has no waiting items for this agent.", "#approvals", "Open Approvals")) +
    '<p class="muted">showing ' + Math.min(items.length, AGENT_DETAIL_LIST_LIMIT) + ' of ' + items.length + ' · queue read ' + escHtml(loadedSourceReadAge(HUB + "/inbox")) + ' · <a href="#approvals">All approvals</a></p>' : agentEmpty("Approvals Unknown", "Agent-scoped approval details are unavailable.", "#approvals", "Review in Approvals")) + '</section>';
}
function renderAgentTimeline(agent, evidenceTab) {
  const entries = sourceLoaded(HUB + "/activity") ? state.activity.filter(function (e) { return e.agent_id === agent.agent_id; }).sort(function (a, b) { return String(b.emitted_at).localeCompare(String(a.emitted_at)); }) : null;
  const href = '#activity?agent=' + encodeURIComponent(agent.agent_id);
  const rows = entries && entries.slice(0, AGENT_DETAIL_LIST_LIMIT).map(function (e) {
    // The approval category also holds requests and denied or resolved decisions, so only a denial names an outcome.
    const verdict = e.category === "denial" ? ["bad", "DENIED"] : ["neutral", "RECORDED"];
    // Must match categorizeOperation in hub/activity-feed.ts: categories classify operation names, not their audit layer.
    // Even egress admits dynamic operation names from multiple producers, so no category alone proves a layer.
    const layer = "Layer not served";
    return '<div class="agent-event"><time>' + escHtml(relTimeFromIso(e.emitted_at)) + '</time>' + overviewChip(verdict[0], verdict[1]) +
      '<a href="' + escHtml(href) + '" title="Evidence entry ' + escHtml(e.entry_id) + '">' + escHtml(renderTemplate(e.display_template_id, e.display_template_args)) + '<small>Entry ' + escHtml(e.entry_id) + '</small></a><span class="muted">' + layer + '</span>' +
      (e.attestation ? '<div class="att">' + renderActionAttestationBadge(e.attestation.state, e.attestation.fragment) + '</div>' : '') + '</div>';
  }).join("");
  return '<section class="card"><h3>' + (evidenceTab ? 'Agent evidence' : 'Recent activity') + '</h3>' + (entries ? (entries.length ? rows : agentEmpty("No agent activity in this read", "The loaded feed has no entries for this agent.", href, "Open Evidence")) +
    '<p class="muted">showing ' + Math.min(entries.length, AGENT_DETAIL_LIST_LIMIT) + ' of ' + entries.length + ' loaded entries · feed read ' + escHtml(loadedSourceReadAge(HUB + "/activity")) + ' · <a href="' + escHtml(href) + '">All activity</a></p>' : agentEmpty("Activity Unknown", "The activity source has not answered.", href, "Open Evidence")) + '</section>';
}
function renderAgentDetail() {
  if (!sourceLoaded(HUB + "/agents")) return unavailablePanel("Agent", [HUB + "/agents"]);
  const a = state.agents.find(function (x) { return x.agent_id === state.selectedAgentId; });
  if (!a) return agentEmpty("Agent not found", "This agent is not in the loaded roster.", "#agents", "Back to Agents");
  const tab = AGENT_TABS.includes(state.agentTab) ? state.agentTab : "overview";
  const tabs = '<nav class="agent-tabs" aria-label="Agent sections">' + AGENT_TABS.map(function (id) { return '<button class="btn" data-action="agent-tab" data-tab="' + id + '" aria-pressed="' + (id === tab) + '">' + sentenceCase(id) + '</button>'; }).join("") + '</nav>';
  let body;
  switch (tab) {
    case "approvals": body = renderAgentApprovals(a); break;
    case "activity": body = renderAgentTimeline(a, false); break;
    case "policy": body = renderAgentReach(a); break;
    case "identity": body = renderAgentIdentity(a); break;
    case "memory": body = agentEmpty("Memory inventory unavailable", "The server does not serve a per-agent memory inventory. This is not a confirmation of empty memory.", "#activity", "Open Evidence"); break;
    case "evidence": body = renderAgentTimeline(a, true); break;
    default: body = '<div class="agent-entity-grid"><div>' + renderAgentStanding(a) + renderAgentReach(a) + renderAgentIdentity(a) + '</div><div>' + renderAgentTimeline(a, false) + renderAgentApprovals(a) + renderAgentInspectPanel(a) + '</div></div>';
  }
  return '<div class="agent-entity"><nav aria-label="Breadcrumb"><a href="#agents">Agents</a> / ' + escHtml(a.agent_id) + '</nav><header class="agent-entity-header"><h1>' + escHtml(a.agent_id) + ' ' + agentStateChip(a) + ' ' + agentEnforcementChip(a) + '</h1>' +
    '<p class="muted">' + escHtml(a.harness || "Harness Unknown") + ' · ' + escHtml(a.model_provider ? a.model_provider.vendor + " / " + a.model_provider.model_id : "Model Unknown") + ' · Policy template: ' + escHtml(a.channel_template_id || "Unknown") + ' · protection requested ' + escHtml(a.wrapped_at ? relTimeFromIso(a.wrapped_at) : "Unknown") + '</p>' +
    '<div class="agent-entity-actions">' + renderAgentControlButtons(a, true) + '<a class="btn" href="#policy">' + escHtml(agentControlLabel("edit_policy")) + '</a><button class="btn" disabled title="Per-agent identity rotation is not served by this dashboard.">' + escHtml(agentControlLabel("identity_rotate")) + ' <span>Tier 1</span></button></div></header>' + tabs + '<div data-agent-tab="' + tab + '">' + body + '</div></div>';
}

// Inspect panel for the Agents view (WP-V1.2 reshape). Clicking the
// inspect affordance opens the panel synchronously via POST
// /api/hub/agents/:id/inspect/open. The panel is read-only:
// recent activity, pending approvals, policy summary. States:
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

  // state_LOADED: the inspect response is available.
  // Sprint Piece 2 PR 4 polish: outer wrapper combines .card with
  // .inspect-pane (sticky right rail, internal scroll, sectioned body).
  // The .card class is preserved so the rendered surface keeps its
  // shared card chrome; .inspect-pane overrides .card padding so the
  // inspect-head and inspect-body control their own spacing per design.
  if (panel) {
    const dotCls = agentStateClass(agentEvidenceStatus(agent));
    const stateMap = agentDisplayStatus(agent);
    const activity = (panel.recent_activity || []).slice(0, AGENT_DETAIL_LIST_LIMIT);
    const activityHtml = activity.length
      ? '<div class="timeline">' +
        activity.map(function (e) {
          const t = renderTemplate(e.display_template_id, e.display_template_args);
          const badgeHtml = e.attestation
            ? renderActionAttestationBadge(e.attestation.state, e.attestation.fragment)
            : '';
          // An activity row carries no verdict, so its mark is the neutral
          // dash; the pass circle is kept for an observed success.
          return '<div class="timeline-item">' +
            '<div class="ts">' + escHtml(shortTime(e.emitted_at)) + '</div>' +
            '<div class="what">' + escHtml(t) + '</div>' +
            (badgeHtml ? '<div class="att">' + badgeHtml + '</div>' : '') +
            '</div>';
        }).join("") +
        '</div>'
      : '<p class="muted">No recent activity for this agent.</p>';

    const approvals = (panel.pending_approvals || []).filter(function (item) { return !item.resolved; });
    const approvalsHtml = (approvals.length ? agentApprovalRows(approvals) : '<p class="muted">No pending approvals routed through this agent.</p>') +
      '<p class="muted">showing ' + Math.min(approvals.length, AGENT_DETAIL_LIST_LIMIT) + ' of ' + approvals.length + ' · panel read ' + escHtml(relTimeFromIso(panel.opened_at)) + ' · <a href="#approvals">All approvals</a></p>';

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
          '<span style="margin-left:auto;">' + renderAgentAttestationBadge(agentEvidenceStatus(agent)) + '</span>' +
        '</div>' +
        '<div class="meta">' +
          '<span class="pill ' + (AGENT_STATE_PILL_TONE[dotCls] || "tone-unknown") + '"><span class="state-dot ' + dotCls + '" style="margin-right:4px;"></span>' + escHtml(stateMap.label) + '</span>' +
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
          activityHtml + '<p class="muted">showing ' + activity.length + ' of ' + (panel.recent_activity || []).length + ' · <a href="#activity">All activity</a></p>' +
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
          '<div class="policy-line"><span class="k">Protection requested</span><span class="v">' + escHtml(shortTime(agent.wrapped_at)) + '</span></div>' +
        '</div>' +
        '<p class="muted" style="margin-top:10px;font-size:12px;">' +
          '<a href="#activity?agent=' + escHtml(agent.agent_id) + '">View full activity</a> · ' +
          '<a href="#policy">Edit policy</a>' +
        '</p>' +
      '</div>' +
    '</div>';
  }

  // state_LOADING: the inspect response is pending.
  if (opening) {
    return '<div class="card">' +
      '<h3>Inspect</h3>' +
      errorBanner +
      '<p class="muted">Opening inspect panel for ' + escHtml(agent.agent_id) + '...</p>' +
    '</div>';
  }

  // state_UNREAD: request an inspect response.
  return '<div class="card">' +
    '<h3>Inspect</h3>' +
    errorBanner +
    '<p>Open the inspect panel to see this agent\'s recent activity, ' +
      'pending approvals, and policy summary at a glance. ' +
      'Read-only; the panel re-fetches on each open.</p>' +
    '<button class="btn btn-primary" data-action="agent-inspect-open" data-agent-id="' + escHtml(agent.agent_id) + '">Open inspect panel</button>' +
  '</div>';
}

// ── Render: privacy ────────────────────────────────────────────────────
function renderPrivacyPage() {
  if (!sourceLoaded(HUB + "/activity?category=privacy")) return unavailablePanel("Privacy", [HUB + "/activity?category=privacy"]);
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
  if (!sourceLoaded(HUB + "/activity?category=handoff")) return unavailablePanel("Coordination", [HUB + "/activity?category=handoff"]);
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
  const totalAgents = sourceLoaded(HUB + "/agents") ? state.agents.length : "Unknown";
  const lockedDown = state.agents.filter(function (a) { return a.status === "locked_down"; }).length;
  const errored = state.agents.filter(function (a) { return a.status === "error"; }).length;
  const recentDenials = state.activity.filter(function (e) { return e.category === "denial"; }).length;
  // No hub verifier route exists; this renders an honest unavailable state,
  // never a button that posts to a missing endpoint.
  const auditVerifyState = '<p class="muted">Audit-chain verification is not available from this dashboard in this build.</p>';
  return '<h1>Health</h1>' +
    '<p class="muted">Projected from existing data.</p>' +
    '<div class="card"><h3>Fortress at a glance</h3>' +
      '<dl class="kv">' +
      '<dt>Protection requested</dt><dd>' + escHtml(totalAgents) + '</dd>' +
      '<dt>Locked down</dt><dd>' + escHtml(sourceLoaded(HUB + "/agents") ? lockedDown : "Unknown") + '</dd>' +
      '<dt>Errored</dt><dd>' + escHtml(sourceLoaded(HUB + "/agents") ? errored : "Unknown") + '</dd>' +
      '<dt>Denials in feed</dt><dd>' + escHtml(sourceLoaded(HUB + "/activity") ? recentDenials : "Unknown") + '</dd>' +
      '</dl>' +
    '</div>' +
    renderSourceRead(HUB + "/agents") + renderSourceRead(HUB + "/activity") + auditVerifyState;
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
      '<button class="btn" data-action="intel-reload" aria-label="Retry Intelligence">Retry</button>' +
    '</section>';
  }
  if (!sourceLoaded(HUB + "/intelligence/status") || !sourceLoaded(HUB + "/intelligence/config") || !state.intelligence.status) {
    return '<section class="intel-center">' +
      '<p class="eyebrow">INTELLIGENCE</p>' +
      '<h1>Intelligence Substrate</h1>' +
      '<p class="intel-subtitle muted">Substrate status unavailable. Current status is Unknown.</p>' +
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
      : 'Ollama not reachable at ' + (config.ollama_endpoint || "http://localhost:11434") + '. Re-run sanctuary protect or sanctuary init interactively to review the signed local-intelligence setup plan. Until a signed model manifest is available and every pulled digest verifies, local surfaces remain DEGRADED.';
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

async function fetchIntelligenceState(deadlineAt) {
  if (deadlineAt === undefined) deadlineAt = Date.now() + DASHBOARD_READ_DEADLINE_MS;
  state.intelligence.loadError = null;
  try {
    const sr = await api("/intelligence/status", undefined, deadlineAt);
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
      state.intelligence.loadError = "Dashboard authentication required. Reload the page or re-launch the dashboard with: sanctuary --fortress <path> dashboard";
      return;
    }
    state.intelligence.loadError = e.message;
    return;
  }
  try {
    const cr = await api("/intelligence/config", undefined, deadlineAt);
    state.intelligence.config = cr.data || null;
  } catch (e) {
    if (e.status === 503) {
      state.intelligence.notConfigured = true;
      return;
    }
    if (e.status === 401) {
      state.intelligence.loadError = "Dashboard authentication required. Reload the page or re-launch the dashboard with: sanctuary --fortress <path> dashboard";
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
    await refreshPanel(HUB + "/intelligence");
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
    // Keep the last conversation for inspection; the read status marks it unavailable.
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
  talkFollowIntent = { scrollEpoch: talkUserScrollEpoch };
  c.sending = true;
  c.error = null;
  // True once the POST has settled successfully. The catch below reads it to
  // tell a failed send (nothing reached the service; the draft stays for a
  // retry) from a failed redraw over a sent message (the draft must not come
  // back, because another Send would post the same message twice).
  let posted = false;
  try {
    // Inside the try: c.sending is now true, and only the finally below resets
    // it. A render that throws here (a fail-loud Talk mount check) must still
    // reach that finally, or every later send returns early forever. A throw
    // here happens before the POST, so the request is never sent twice.
    rerender();
    const res = await api("/chat/concierge", {
      method: "POST",
      body: { message: message }
    });
    // INVARIANT: the sent state commits here, at POST settlement and before
    // any redraw. The service has persisted the message, so the draft clears
    // now; a redraw that throws after this line is a display problem over a
    // sent message, never a failed send, and must not leave the draft in the
    // composer where a retry would post it a second time.
    posted = true;
    c.composer = "";
    // The operator's successful send is an explicit draft clear, unlike a
    // background hydration. A route or panel change can remount Talk while
    // this request is in flight. The shared composer is still disabled until
    // settlement, so clear the currently mounted input regardless of
    // scroll-follow intent.
    if (talkOwner) talkOwner.input.value = "";
    const data = res.data || {};
    // Refetch history so both operator submit + concierge response
    // render in chronological order. The service persisted both
    // messages before the response returned; the history endpoint is
    // the single source of truth for the visible thread.
    await refreshPanel(HUB + "/chat/concierge/history");
    // Update the badge from the response AFTER the history refresh: the
    // history loader (fetchConciergeHistory) writes a generic per-substrate
    // label from the last reply, and the response carries the more specific
    // display_label for THIS reply, which must be the one left standing.
    if (data.served_by) {
      state.chat.concierge.badge = {
        substrate: data.served_by,
        displayLabel: data.display_label || substrateBadgeLabel(data.served_by)
      };
    }
    if (!talkDomOwnerSupported) c.pendingScroll = true;
  } catch (e) {
    // After the POST settled, the only thing that can throw is the redraw of
    // a message the service already holds: report it as a display problem in
    // plain words, with no stack, and never as a failed send.
    c.error = posted
      ? "Your message was sent, but the screen could not refresh. Reload the page to see the reply."
      : (e.message || "Concierge call failed.");
  } finally {
    c.sending = false;
    // The settling render still reads the follow request (it lands the reply);
    // the request ends with this send even if that render throws.
    try { rerender(); } finally { talkFollowIntent = null; }
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

// Tunability UX: the LIVE Principal Policy rendered in plain English, so the
// operator can SEE what their fine-grained policy actually does without
// reading manifest YAML. Read-only view (editing is guided elsewhere). The
// data comes from the operator-bearer-gated GET /api/policy/current; a
// co-resident agent cannot reach it, upholding AGENTS.md hard rule 7.
const POLICY_SECTION_TITLES = {
  approval: "Always asks you first",
  auto_allow: "Agents may do freely",
  anomaly: "Unusual-behavior rules",
  channel: "How approvals reach you"
};
const POLICY_SECTION_ORDER = ["approval", "auto_allow", "anomaly", "channel"];
function renderPolicyPlainEnglishPanel() {
  const path = POLICY + "/current";
  const view = sourceLoaded(path) && state.policyView.view;
  if (!view || !Array.isArray(view.lines)) return '<section class="policy-panel"><h2>Policy Unknown</h2>' + overviewChip("unknown", "UNKNOWN") +
    '<p>' + escHtml(state.policyView.loadError || "The current policy did not answer with a rule list.") + '</p>' + (sourceLoaded(path) ? '<button class="btn" data-action="retry-panel" data-read="/api/policy/current">Retry</button>' : renderSourceRead(path)) + '</section>';
  const page = mfpPage(view.lines, "policy");
  page.total = state.mfp.totals.policy;
  const sections = POLICY_SECTION_ORDER.map(function (section) {
    const lines = page.rows.filter(function (line) { return line.section === section; });
    if (!lines.length) return "";
    return '<section><h3>' + escHtml(POLICY_SECTION_TITLES[section]) + '</h3><ul>' +
      lines.map(function (line) { return '<li>' + escHtml(line.text) + '</li>'; }).join("") + '</ul></section>';
  }).join("");
  const unknownGroup = function (title, reason) { return '<section><h3>' + title + '</h3>' + overviewChip("unknown", "UNKNOWN") + '<p>' + reason + '</p></section>'; };
  const rows = page.rows.map(function (line, index) {
    return '<tr><td class="mono">' + (page.start + index + 1) + '</td><td>' + escHtml(POLICY_SECTION_TITLES[line.section] || "Unknown") + '</td><td>' + escHtml(line.text) + '</td></tr>';
  }).join("");
  return '<section class="policy-panel" data-mfp-policy><div class="card-head-row"><h2>Principal policy</h2>' +
    overviewChip(typeof view.policy_version === "number" ? "neutral" : "unknown", typeof view.policy_version === "number" ? "Version " + view.policy_version : "Version Unknown") + '</div>' +
    '<p>Signature: ' + overviewChip("unknown", "UNKNOWN") + ' Signature state is not served by this policy view.</p>' +
    '<p class="muted">Read-only policy lines. Groups and table show the same page of the current policy; row numbers are display positions.</p>' +
    (view.lines.length ? mfpPager(page, "policy", path) : "") +
    (view.lines.length ? '<div class="mfp-policy-grid"><div class="mfp-policy-groups">' +
      unknownGroup("What agents may reach", "Destination and tool reach rules are not served by this policy view.") + sections +
      unknownGroup("What is never allowed", "A deny list is not served by this policy view.") +
      '</div><section><h3>Rule table</h3><div class="overview-table-scroll"><table class="overview-table mfp-table"><thead><tr><th>Row</th><th>Group</th><th>Rule</th></tr></thead><tbody>' + rows + '</tbody></table></div></section></div>' :
      mfpEmpty("No policy lines returned", "The current policy returned 0 of 0 lines; this is not a claim that every action is allowed.", path)) + '</section>';
}

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
  const bindingPage = mfpPage(state.agents, "bindings");
  const rows = state.agents.length
    ? bindingPage.rows.map(function (a) {
        const binding = a.channel_template_id || "default none";
        const budget = a.budget_summary && a.budget_summary.daily
          ? "$" + escHtml(a.budget_summary.daily.cap) + "/day"
          : "Not set";
        const open = state.templateBinding.agentId === a.agent_id;
        // LocalAgentRecord carries real template and budget fields only; these
        // cells use an honest empty state, never invented policy detail.
        const policyDetailUnavailable = '<span class="muted">Not available yet</span>';
        return '<tr>' +
          '<td><button class="link-btn" data-action="open-agent" data-agent-id="' + escHtml(a.agent_id) + '">' + escHtml(a.agent_id) + '</button></td>' +
          '<td><button class="template-cell" data-action="template-picker-open" data-agent-id="' + escHtml(a.agent_id) + '">' + escHtml(binding) + '</button>' +
            (open ? renderTemplatePicker(a) : '') +
          '</td>' +
          '<td>' + policyDetailUnavailable + '</td>' +
          '<td>' + budget + '</td>' +
          '<td>' + policyDetailUnavailable + '</td>' +
          '<td>' + policyDetailUnavailable + '</td>' +
          '<td>' + policyDetailUnavailable + '</td>' +
        '</tr>';
      }).join("\n")
    : '<tr><td colspan="7" class="muted">No protected agents yet.</td></tr>';
  return '<section class="policy-center">' +
    '<p class="eyebrow">Configure</p>' +
    '<h1>Policies</h1>' +
    // Traced to the edit path: a template change is queued as a Tier 1
    // approval; approving it records the new template and policy binding
    // on the agent's record, and approving or denying it appends an audit
    // log entry. The copy claims nothing past that.
    '<p class="policy-subtitle">Principal policy lines and agent template bindings. A template change waits for your approval; approving it records the new template on the agent, and your decision either way is written to your audit log.</p>' +
    renderPolicyPlainEnglishPanel() +
    '<section class="policy-panel"><h2>Channel templates · ' + CHANNEL_TEMPLATES.length + ' shipped</h2><div class="template-grid">' + tmplCards + '</div></section>' +
    // A pager describes served rows; unread sources keep their status and loaded empty agents keep their empty state.
    '<section class="policy-panel"><h2>Per-agent rules</h2><p class="muted">Agent template bindings and daily budgets. Other rule fields are not served here.</p>' + (sourceLoaded(HUB + "/agents") && state.agents.length ? mfpPager(bindingPage, "bindings", HUB + "/agents") : "") +
      '<div class="rules-scroll"><table class="rules-table">' +
      '<thead><tr><th>AGENT</th><th>TEMPLATE</th><th>ALLOW / BLOCK</th><th>BUDGET</th><th>RETENTION</th><th>MINIMIZE</th><th>APPROVALS</th></tr></thead>' +
      '<tbody>' + (sourceLoaded(HUB + "/agents") ? rows : '<tr><td colspan="7">' + renderSourceRead(HUB + "/agents") + '</td></tr>') + '</tbody></table></div>' +
    '</section>' +
  '</section>';
}

function renderAutoTriggerPage() {
  const rules = state.autoTrigger.rules || [];
  const recs = state.autoTrigger.recommendations || [];
  const rulePage = mfpPage(rules, "rules", MFP_ALL_SERVED);
  const recommendationPage = mfpPage(recs, "recommendations", MFP_ALL_SERVED);
  const summary = !sourceLoaded(AUTO_TRIGGER + "/rules") ? renderSourceRead(AUTO_TRIGGER + "/rules") : rules.length
    ? mfpPager(rulePage, "rules", AUTO_TRIGGER + "/rules") + '<div class="auto-trigger-rule-list">' + rulePage.rows.map(renderAutoTriggerRuleRow).join("") + '</div>'
    : '<p class="muted">No auto-trigger ladders configured. Ladders appear here after a sentinel, anomaly detector, or honeypot records its first finding. Use <code>sanctuary auto-trigger promote</code> to create one.</p>';
  const body = !sourceLoaded(AUTO_TRIGGER + "/recommendations") ? renderSourceRead(AUTO_TRIGGER + "/recommendations") : recs.length
    ? mfpPager(recommendationPage, "recommendations", AUTO_TRIGGER + "/recommendations") + '<div class="recommendation-list">' + recommendationPage.rows.map(function (r) {
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
  const detailsUnavailable = !sourceLoaded(AUTO_TRIGGER + "/details") || rule.detailUnavailable;
  const trend = detailsUnavailable ? '<span class="muted">Trend unavailable.</span>' : renderAutoTriggerTrend(history);
  const saving = state.autoTrigger.savingRuleId === rule.rule_id;
  const recentHtml = detailsUnavailable ? renderSourceRead(AUTO_TRIGGER + "/details") : recent.length
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
  const counts = { good: 0, warn: 0, pending: 0 };
  const bars = history.slice(-30).map(function (h) {
    const cls = trendOutcomeClass(h.outcome);
    counts[cls]++;
    return '<span class="trend-bar ' + cls + '" title="' + escHtml(h.outcome + " at " + shortTime(h.observed_at)) + '"></span>';
  }).join("");
  // Each outcome has its own bar shape (a tall filled bar went ahead, a
  // short filled bar was stopped, an outline is anything else), and the
  // legend names each shape with its count, so the strip reads without color.
  return '<span class="trend-bars">' + bars + '</span>' +
    '<span class="trend-legend">' +
      '<span><i class="trend-bar good" aria-hidden="true"></i>' + counts.good + ' went ahead</span>' +
      '<span><i class="trend-bar warn" aria-hidden="true"></i>' + counts.warn + ' stopped</span>' +
      '<span><i class="trend-bar pending" aria-hidden="true"></i>' + counts.pending + ' other</span>' +
    '</span>';
}
function trendOutcomeClass(outcome) {
  if (outcome === "auto_proceeded" || outcome === "operator_approved") return "good";
  if (outcome === "operator_canceled" || outcome === "operator_revoked") return "warn";
  return "pending";
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
    ? '<span class="muted">Awaiting approval. It waits in <a href="#approvals">Approvals</a>.</span>'
    : '<button class="btn btn-primary" data-action="exit-export-start">Snapshot now</button>';
  const step2Body = exportDone ? 'Re-key complete.' : '<span class="muted">Re-keying state for portable export.</span>';
  // A7: always render state_entry_count (including 0) so "Bundle ready" cannot
  // imply state was included when none was. When count is null/undefined despite
  // exportDone, render explicit "Unavailable" so absence is not silent.
  // Warnings are text-escaped to prevent HTML injection; they must not be rendered as raw HTML.
  var step3StateCount = exportDone
    ? (state.exitDrill.bundleResult.state_entry_count !== null && state.exitDrill.bundleResult.state_entry_count !== undefined
        ? '<dt>State entries</dt><dd class="mono">' + escHtml(String(state.exitDrill.bundleResult.state_entry_count)) + '</dd>'
        : '<dt>State entries</dt><dd class="mono">Unavailable</dd>')
    : '';
  var step3Warnings = (exportDone && Array.isArray(state.exitDrill.bundleResult.warnings) && state.exitDrill.bundleResult.warnings.length > 0)
    ? '<ul class="warnings">' + state.exitDrill.bundleResult.warnings.map(function(w) { return '<li>' + escHtml(String(w)) + '</li>'; }).join('') + '</ul>'
    : '';
  const step3Body = exportDone
    ? '<dl class="kv"><dt>Bundle dir</dt><dd class="mono">' + escHtml(state.exitDrill.bundleResult.bundle_dir || "") + '</dd>' +
      '<dt>Manifest hash</dt><dd class="mono">' + escHtml((state.exitDrill.bundleResult.manifest_hash || "").slice(0, 32) + "...") + '</dd>' +
      step3StateCount + '</dl>' + step3Warnings
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
  const initialFilters = JSON.stringify(state.inboxOps.filters);
  try {
    const res = await readResponse(credentialedReadUrl(INBOX_PREFS, "GET"), {
      headers: TOKEN ? { "Authorization": "Bearer " + TOKEN } : {},
      cache: "no-store"
    }, INBOX_PREFS_DEADLINE_MS);
    if (!res.ok) return;
    const body = await res.json();
    // A delayed preference read must not overwrite filters the operator edited.
    if (JSON.stringify(state.inboxOps.filters) === initialFilters) {
      state.inboxOps.filters = normalizeInboxPrefs(body && body.data && body.data.filters);
    }
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

function isPendingApprovalsRedactedMarker(value) {
  return !!(
    value &&
    value.pending_approvals_redacted === true &&
    typeof value.pending_approvals_count === "number"
  );
}

function setInboxRedacted(marker) {
  state.inboxRedacted = true;
  state.inboxRedactedCount = Math.max(0, marker.pending_approvals_count || 0);
  state.inbox = state.inbox.filter(function (i) {
    return i.kind !== "approval_pending";
  });
}

function applyInboxPayload(data) {
  if (isPendingApprovalsRedactedMarker(data)) {
    setInboxRedacted(data);
  } else {
    state.inboxRedacted = false;
    state.inboxRedactedCount = 0;
  }
  state.inbox = (data && data.items) || [];
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

function filterInbox(items, ignoreTimeRange) {
  const f = state.inboxOps.filters;
  const q = f.search.trim().toLowerCase();
  const fromMs = f.from ? Date.parse(f.from + "T00:00:00.000Z") : null;
  const toMs = f.to ? Date.parse(f.to + "T23:59:59.999Z") : null;
  // The top-bar time range narrows the same list; like the date filters, an
  // item whose time does not parse is kept rather than silently dropped.
  const windowMs = ignoreTimeRange ? undefined : TIME_RANGE_MS[state.timeRange];
  const sinceMs = typeof windowMs === "number" ? Date.now() - windowMs : null;
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
    if (sinceMs !== null && Number.isFinite(when) && when < sinceMs) return false;
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
  // chosen. These are the only items the queue shows; everything else
  // (privacy events, budget warnings, blocked egress) lives on Evidence.
  return heldApprovalItems(state.agentScope.selectedAgentId);
}
// Every held operation, optionally narrowed to one agent. Called with null
// it is the fortress-wide denominator the waiting count is stated against.
function heldApprovalItems(scope) {
  return state.inbox.filter(function (i) {
    if (i.resolved) return false;
    if (i.kind !== "approval_pending") return false;
    if (i.tier !== "tier1" && i.tier !== "tier2") return false;
    if (scope && (i.agent_id || "") !== scope) return false;
    return true;
  });
}

const AGENT_CONTROL_LABELS = {
  pause: "Pause",
  resume: "Resume",
  restart: "Restart",
  // Must match TIER1_BUTTON_COPY.lockdown.idle in status-mapping.ts; both renderers use this map.
  lockdown: "Lock down",
  // Must match TIER1_BUTTON_COPY.unwrap.idle in status-mapping.ts; both renderers use this map.
  unwrap: "Remove protection",
  edit_policy: "Edit policy",
  identity_rotate: "Rotate identity"
};

function agentControlLabel(action) {
  return AGENT_CONTROL_LABELS[action] || "This control";
}

function renderAgentControlButtons(a, scoped) {
  // Must match projectAgentCapabilities in hub/hub-service.ts: a flag includes stored permission AND controller support.
  const c = a.capabilities || {};
  const menuItems = [
    { action: "pause", enabled: !!c.can_pause },
    { action: "resume", enabled: !!c.can_resume },
    { action: "restart", enabled: !!c.can_restart },
    // "Lock down" is the top bar's verb; "Remove protection" is the
    // operator's word for the frozen "unwrap" action id, which stays
    // the wire name in data-action only.
    { action: "lockdown", enabled: !!c.can_lockdown, tier1: true },
    { action: "unwrap", enabled: !!c.can_unwrap, tier1: true }
  ];
  const disabledTipByAction = {
    pause: "Sanctuary does not control this agent's process, so pause is not available.",
    resume: "Sanctuary does not control this agent's process, so resume is not available.",
    restart: "Sanctuary does not control this agent's process, so restart is not available.",
    lockdown: "This agent is not confined to a dedicated uid, so network lockdown is not available.",
    unwrap: "Removing protection from the dashboard is not available yet; an unsupported request is refused before any approval is queued."
  };
  return menuItems.map(function (mi) {
    const tip = mi.enabled
      ? (mi.tier1 ? "Tier 1: requires inbox approval." : "")
      : disabledTipByAction[mi.action];
    return '<button class="btn" data-action="agent-' + mi.action + '" data-agent-id="' + escHtml(a.agent_id) + '"' + (mi.enabled ? '' : ' disabled') + ' title="' + escHtml(tip) + '">' + escHtml(agentControlLabel(mi.action) + (scoped && mi.action === "lockdown" ? " this agent" : "")) + '</button>';
  }).join("");
}

// Wave 1: the fortress-column agents card and Recognition Layer health card
// previously lived on the right rail. They are real surfaces (agent
// lifecycle controls + did:web rotation), so they were relocated to the
// Activity screen rather than removed; the markup, data-action hooks, and
// capability-gating logic are preserved verbatim. The rail keeps only the
// approvals queue + ambient posture.
function renderFortressAgentsCard() {
  if (!sourceLoaded(HUB + "/agents")) return renderSourceRead(HUB + "/agents");
  return state.agents.length
    ? state.agents.slice(0, 8).map(function (a) {
        const map = agentDisplayStatus(a);
        const buttons = renderAgentControlButtons(a, false);
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
  if (!sourceLoaded(HUB + "/recognition/did-web")) return renderSourceRead(HUB + "/recognition/did-web");
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

// The operation an approval names, when it maps to a promotable standing
// rule. Returns null for approvals with no concrete operation to promote
// (e.g. policy_change, lockdown, unwrap). Kept in sync with the server
// deterministic compiler, which recognizes "auto-allow <snake_case_op>".
const NON_PROMOTABLE_OPERATIONS = {
  policy_change: true,
  lockdown: true,
  unwrap: true,
  // "other" is the category enum's catch-all, never an operation name, so
  // promoting it would compile the standing rule "auto-allow other" against
  // an operation that does not exist. The card carries no operation name to
  // promote instead: HubDisplayTemplateArg has no free-text member, on
  // purpose, so a Charter hold's raw tool arguments cannot reach a card.
  other: true
};
function promotableOperation(i) {
  const op = i && i.operation_category;
  if (typeof op !== "string" || op.length === 0) return null;
  if (NON_PROMOTABLE_OPERATIONS[op]) return null;
  // Server compiler pattern is /^auto-allow [a-z][a-z0-9_]*$/. Guard the
  // client side to the same shape so we never send a payload the compiler
  // would low-confidence-reject.
  if (!/^[a-z][a-z0-9_]*$/.test(op)) return null;
  return op;
}

const EVIDENCE_LAYER_NAMES = {
  // Must match validLayers in server/src/principal-policy/posture-routes.ts.
  l1: "Castle Wall",
  l2: "Sentinels",
  l3: "Charter",
  l4: "Heralds"
};
const EVIDENCE_LAYER_ORDER = ["l1", "l2", "l3", "l4"];
const EVIDENCE_ROUTE_DEFAULT_LIMIT = 50; // Must match buildEvidence default in principal-policy/posture-routes.ts.
const EVIDENCE_CHAIN_VERDICTS = ${JSON.stringify(EVIDENCE_CHAIN_VERDICTS)};
// 50 is the route default limit in buildEvidence, so the first page and the
// server window have the same bound unless the route changes.
const EVIDENCE_PAGE_SIZE = EVIDENCE_ROUTE_DEFAULT_LIMIT;
const EVIDENCE_DETAIL_VALUE_MAX_CHARS = 240; // 240 = four 60-char lines in the drawer key-value column.
const EVIDENCE_RAW_RECORD_MAX_CHARS = 6000; // 6000 = about 100 60-char lines, enough for inspection without unbounded DOM growth.
// The decided approvals list shows at most one audit page of rows, so the screen's two lists share one row budget.
const EVIDENCE_DECIDED_APPROVAL_LIMIT = EVIDENCE_PAGE_SIZE;
const EVIDENCE_DETAIL_KEY_LIMIT = EVIDENCE_PAGE_SIZE; // One record gets at most the same row budget as one audit page.
const EVIDENCE_SINCE_ROUND_MS = 60 * 1000; // One minute: the time range start sent with the read is rounded to it.
const EVIDENCE_FINDING_DISPLAY_LIMIT = 5; // Five findings fit in the strip before the table leaves the first viewport.
// Must match the limit default in handleAuditLog in server/src/principal-policy/dashboard.ts: the audit
// log read serves the most recent entries up to this limit, so the export says it is that bound.
const EVIDENCE_JSON_EXPORT_LIMIT = 50;

function evidenceLayerName(layer) {
  return EVIDENCE_LAYER_NAMES[layer] || "Unknown";
}

function evidenceTimestamp(entry) {
  return entry && entry.timestamp || "";
}

// Invariant: the Evidence read serves AuditEntry only, so every cell reads a
// served AuditEntry field or says the value is missing.
function evidenceAgent(entry) {
  return entry && entry.identity_id || "agent not named";
}

function evidenceEvent(entry) {
  return entry && entry.operation || "operation not named";
}

function evidenceResult(entry) {
  const raw = String(entry && entry.result || "").toLowerCase();
  if (raw === "success" || raw === "failure") return raw;
  return "";
}

function cappedText(value, maxChars) {
  var raw;
  if (value === null) raw = "null";
  else if (value === undefined) raw = "missing";
  else if (typeof value === "string") raw = value;
  else {
    try { raw = JSON.stringify(value); } catch (_e) { raw = String(value); }
  }
  if (raw.length <= maxChars) return raw;
  return raw.slice(0, maxChars) + "... truncated at " + maxChars + " chars";
}

function evidenceDetailsList(entry) {
  const details = entry && entry.details && typeof entry.details === "object" && !Array.isArray(entry.details) ? entry.details : null;
  if (!details) return "";
  const keys = Object.keys(details).sort();
  if (!keys.length) return "";
  return '<dt>Details</dt><dd>showing ' + Math.min(keys.length, EVIDENCE_DETAIL_KEY_LIMIT) + ' of ' + keys.length + ' fields</dd>' + keys.slice(0, EVIDENCE_DETAIL_KEY_LIMIT).map(function (key) {
    return '<dt>' + escHtml(cappedText(key, EVIDENCE_DETAIL_VALUE_MAX_CHARS)) + '</dt><dd>' + escHtml(cappedText(details[key], EVIDENCE_DETAIL_VALUE_MAX_CHARS)) + '</dd>';
  }).join("");
}

function evidenceContributorsList(entry) {
  const contributors = entry && Array.isArray(entry.contributors) ? entry.contributors : [];
  if (!contributors.length) return "";
  return '<dt>contributors</dt><dd>' + escHtml(cappedText(contributors, EVIDENCE_DETAIL_VALUE_MAX_CHARS)) + '</dd>';
}

function evidenceEntryText(entry) {
  const details = entry && entry.details && typeof entry.details === "object" ? entry.details : {};
  return [
    evidenceEvent(entry),
    evidenceAgent(entry),
    evidenceResult(entry),
    evidenceLayerName(entry && entry.layer),
    JSON.stringify(details)
  ].filter(Boolean).join(" ");
}

function evidenceMatchesQuery(entry, query) {
  const trimmed = String(query || "").trim().toLowerCase();
  if (!trimmed) return true;
  const words = trimmed.split(/\s+/).filter(Boolean);
  const haystack = evidenceEntryText(entry).toLowerCase();
  return words.every(function (word) {
    const split = word.indexOf(":");
    if (split > 0) {
      const field = word.slice(0, split);
      const value = word.slice(split + 1);
      if (field === "agent") return String(evidenceAgent(entry)).toLowerCase().indexOf(value) >= 0;
      if (field === "layer") return evidenceLayerName(entry.layer).toLowerCase().indexOf(value) >= 0 || String(entry.layer || "").toLowerCase() === value;
      if (field === "result") return evidenceResult(entry).toLowerCase().indexOf(value) >= 0;
      if (field === "event" || field === "operation" || field === "text") return haystack.indexOf(value) >= 0;
    }
    return haystack.indexOf(word) >= 0;
  });
}

function applyEvidenceHashFilters(hash) {
  const route = String(hash || "").split("?")[0];
  if (route !== "activity") return;
  const qs = String(hash || "").split("?")[1] || "";
  const params = new URLSearchParams(qs);
  const filters = state.evidence.filters;
  filters.query = params.get("q") || "";
  const layer = params.get("layer") || "";
  filters.layer = EVIDENCE_LAYER_NAMES[layer] ? layer : "";
  filters.agent = params.get("agent") || "";
  filters.event = params.get("event") || "";
  const result = params.get("result") || "";
  filters.result = result === "success" || result === "failure" ? result : "";
  filters.from = evidenceFromDate(params.get("from") || "");
}

// The From filter is a calendar date in the operator's own time zone (what a date input holds), so
// anything that is not a real YYYY-MM-DD date is dropped instead of sent as a window that matches nothing.
function evidenceFromDate(value) {
  const m = /^(\d{4})-(\d{2})-(\d{2})$/.exec(String(value || ""));
  if (!m) return "";
  const local = new Date(Number(m[1]), Number(m[2]) - 1, Number(m[3]));
  return local.getFullYear() === Number(m[1]) && local.getMonth() === Number(m[2]) - 1 && local.getDate() === Number(m[3]) ? value : "";
}

// The start of the Evidence read's window: the later of the From date's local midnight and the start of
// the top-bar time range. The time range start is rounded down to the minute, so reads within one minute
// ask for the same window and a repeated read compares equal.
function evidenceSinceIso() {
  const from = evidenceFromDate(state.evidence.filters.from);
  const fromMs = from ? new Date(Number(from.slice(0, 4)), Number(from.slice(5, 7)) - 1, Number(from.slice(8, 10))).getTime() : null;
  const windowMs = TIME_RANGE_MS[state.timeRange];
  const rangeMs = typeof windowMs === "number" ? Math.floor((Date.now() - windowMs) / EVIDENCE_SINCE_ROUND_MS) * EVIDENCE_SINCE_ROUND_MS : null;
  const since = fromMs === null ? rangeMs : rangeMs === null ? fromMs : Math.max(fromMs, rangeMs);
  return since === null ? "" : new Date(since).toISOString();
}

function evidenceHashFromFilters() {
  const params = new URLSearchParams();
  const filters = state.evidence.filters;
  if (filters.query) params.set("q", filters.query);
  if (filters.layer) params.set("layer", filters.layer);
  if (filters.agent) params.set("agent", filters.agent);
  if (filters.event) params.set("event", filters.event);
  if (filters.result) params.set("result", filters.result);
  if (filters.from) params.set("from", filters.from);
  const qs = params.toString();
  return "#activity" + (qs ? "?" + qs : "");
}

function setEvidenceFilter(name, value) {
  if (!Object.prototype.hasOwnProperty.call(state.evidence.filters, name)) return;
  const previousUrl = evidenceReadUrl();
  state.evidence.filters[name] = value;
  state.evidence.selectedIndex = 0;
  const nextHash = evidenceHashFromFilters();
  if (location.hash !== nextHash) location.hash = nextHash;
  else rerender();
  if (evidenceReadUrl() !== previousUrl) queueEvidenceRead();
}

function evidenceReadUrl() {
  const params = new URLSearchParams();
  const filters = state.evidence.filters;
  if (filters.agent) params.set("agent", filters.agent);
  const since = evidenceSinceIso();
  if (since) params.set("since", since);
  if (filters.event) params.set("operation_type", filters.event);
  if (filters.layer) params.set("layer", filters.layer);
  if (filters.result) params.set("result", filters.result);
  params.set("limit", String(EVIDENCE_PAGE_SIZE));
  const qs = params.toString();
  return "/api/posture/evidence" + (qs ? "?" + qs : "");
}

function queueEvidenceRead() {
  const job = panelJobs.find(function (candidate) {
    return candidate.paths.indexOf("/api/posture/evidence") >= 0;
  });
  if (job) { void queuePanel(job); rerender(); }
}

function filteredEvidenceEntries(entries) {
  const filters = state.evidence.filters;
  return (entries || []).filter(function (entry) {
    return evidenceMatchesQuery(entry, filters.query);
  });
}

function renderEvidenceStatusChip(kind, word) {
  return '<span class="state-chip ' + escHtml(kind) + '"><i aria-hidden="true"></i>' + escHtml(word) + '</span>';
}

function renderFortress() {
  const fortress = document.getElementById("fortress");
  if (!fortress) return;
  const evidence = approvalQueueEvidence();
  const queueCount = !sourceLoaded(HUB + "/inbox") ? "Unknown" : state.inboxRedacted ? state.inboxRedactedCount : evidence.count;
  // The muted zero badge is the same claim as the green check, so it needs the same earned evidence.
  const countCls = evidence.earned ? "count zero" : "count";
  const approvalSummary = evidence.summary;

  // Ambient posture: honest, glanceable. The seal mirrors the top bar; the
  // one-line "what's protecting you" uses NAMED layers only (no L-numbers).
  const seal = deriveSeal();
  const scopeLabel = state.agentScope.selectedAgentId
    ? escHtml(state.agentScope.selectedAgentId)
    : "All agents";
  const fortressLabel = escHtml(config.tenantName || config.fortressId || "this fortress");
  var protectingLine;
  if (seal.tone === "protected") {
    protectingLine = "Castle Wall enforcement has current evidence on this machine.";
  } else if (seal.arm === "locked_down") {
    protectingLine = "This fortress reports lockdown. See the current agent status for its scope.";
  } else if (seal.arm === "armed") {
    protectingLine = "Castle Wall enforcement evidence is not current enough for a protected claim. Current protection is unavailable. Retry the protection evidence read.";
  } else if (seal.arm === "degraded") {
    protectingLine = "Castle Wall protection is degraded right now. Current protection is unavailable. Retry the protection evidence read. Check the Health screen.";
  } else {
    protectingLine = "Castle Wall enforcement is not confirmed on this machine right now. Current protection is unavailable. Retry the protection evidence read.";
  }
  const wrapped = sourceLoaded(HUB + "/agents") ? state.agents.length : "Unknown";
  const federationState = !sourceLoaded("/api/sovereignty") ? "Unknown" : (state.posture.data && state.posture.data.federation && state.posture.data.federation.operator_cloud_nodes)
    ? "On" : "Off";

  const active = !fortress.contains || fortress.contains(document.activeElement) ? document.activeElement : null;
  fortress.innerHTML = [
      '<div class="rail-section">',
      '<div class="rail-section-label">Waiting on you <span class="' + countCls + '" id="queue-count">' + queueCount + '</span></div>',
      approvalSummary,
    '</div>',
    '<div class="rail-section">',
      '<div class="rail-section-label">Right now</div>',
      '<div class="ambient-posture">',
        '<div class="ambient-seal tone-' + seal.tone + '">',
          '<span class="as-glyph"></span>',
          '<span class="as-text"><strong>' + escHtml(seal.word) + '</strong><small>' + escHtml(seal.freshness.inline) + ' &middot; ' + scopeLabel + ' &middot; ' + fortressLabel + '</small></span>',
        '</div>',
        '<div class="ambient-line"><span class="lead">What is protecting you</span>' + escHtml(protectingLine) + '</div>',
        '<div class="ambient-stats">',
          '<div class="ambient-stat" title="Agents placed under Sanctuary protection; enforcement evidence is stated per agent"><span class="n">' + wrapped + '</span><span class="l">Protection requested</span></div>',
          '<div class="ambient-stat"><span class="n">' + queueCount + '</span><span class="l">Waiting</span></div>',
          '<div class="ambient-stat"><span class="n">' + federationState + '</span><span class="l">Federation</span></div>',
        '</div>',
      '</div>',
    renderSourceRead(HUB + "/agents"), renderSourceRead("/api/sovereignty"),
    '</div>'
  ].join("");
  restoreRetryFocus(active, fortress);
}

function renderEvidenceIntegrity(view) {
  const read = sourceRead("/api/posture/evidence");
  if (!sourceLoaded("/api/posture/evidence") || !view) {
    const reason = read && read.error ? read.error : "server verification has not answered";
    return '<section class="evidence-integrity unknown"><div class="ei-badge">' + renderEvidenceStatusChip("unknown", "UNKNOWN") +
      '</div><div class="ei-facts"><strong>Chain verification Unknown</strong><span>' + escHtml(reason) + '</span></div></section>';
  }
  const findings = Array.isArray(view.integrity_findings) ? view.integrity_findings : [];
  const total = typeof view.total === "number" ? view.total : "Unknown";
  const sealed = renderSealedRegion(view.sealed_region);
  const status = view.chain_verdict;
  const known = Object.prototype.hasOwnProperty.call(EVIDENCE_CHAIN_VERDICTS, status);
  // Only the served whole-chain verdict with no findings earns CHAIN VERIFIED.
  // Continuing paths: verified -> clean; suffix -> qualified; any served finding -> bad, whatever the
  // served verdict, so no reassuring word sits above a finding; key unavailable or an unrecognized
  // verdict -> no verification claim.
  const verdict = known ? EVIDENCE_CHAIN_VERDICTS[findings.length ? "findings" : status] : {
    kind: "unknown", word: "UNKNOWN", summary: "The audit chain status was not recognized or was not served."
  };
  const chipKind = verdict.kind;
  const chipWord = verdict.word;
  const summary = verdict.summary;
  const shownFindings = findings.slice(0, EVIDENCE_FINDING_DISPLAY_LIMIT).map(function (finding) {
    return '<span>' + escHtml(cappedText(finding.kind || "finding", EVIDENCE_DETAIL_VALUE_MAX_CHARS)) + ': ' +
      escHtml(cappedText(finding.message || "message not served", EVIDENCE_DETAIL_VALUE_MAX_CHARS)) + '</span>';
  }).join("");
  const findingCount = findings.length
    ? '<span>showing ' + escHtml(Math.min(findings.length, EVIDENCE_FINDING_DISPLAY_LIMIT)) + ' of ' + escHtml(findings.length) + ' findings</span>'
    : '<span><b>0</b> integrity findings reported for the whole chain</span>';
  return '<section class="evidence-integrity ' + escHtml(chipKind) + '"><div class="ei-badge">' + renderEvidenceStatusChip(chipKind, chipWord) + '</div>' +
    '<div class="ei-facts"><strong>' + escHtml(summary) + '</strong><span><b>' + escHtml(total) + '</b> entries in the served window before page limit and result filter</span>' +
    findingCount + '<span>sealed region: ' + escHtml(sealed) + '</span><span>age of this read: ' + escHtml(sourceReadAge("/api/posture/evidence") || "now") + '</span>' +
    shownFindings + '</div></section>';
}

// Must match SealedRegionVerdict in server/src/operational/audit-log.ts: every served status has its own
// words here, and a status this list does not name reads Unknown, never a verification.
function renderSealedRegion(sealed) {
  if (!sealed || typeof sealed !== "object") return "Unknown";
  if (sealed.status === "not_present") return "no sealed legacy region present";
  if (sealed.status === "empty") return "sealed legacy region is empty";
  if (sealed.status === "verified") return "sealed region verified, entries verified " + String(sealed.entries_verified || 0);
  if (sealed.status === "unreadable") return "sealed older region unreadable at this privilege: " + cappedText(sealed.note || "reason not served", EVIDENCE_DETAIL_VALUE_MAX_CHARS);
  if (sealed.status === "incomplete") return "sealed region incomplete, highest present " + String(sealed.highest_present || 0) + " of expected tip " + String(sealed.expected_tip || 0);
  if (sealed.status === "hash_mismatch") return "sealed region hash mismatch at sequence " + String(sealed.sequence || "unknown");
  return "Unknown";
}

function renderEvidenceQueryBar() {
  const f = state.evidence.filters;
  const layerOptions = ['<option value="">Any</option>'].concat(EVIDENCE_LAYER_ORDER.map(function (token) {
    return '<option value="' + token + '"' + (f.layer === token ? ' selected' : '') + '>' + escHtml(evidenceLayerName(token)) + '</option>';
  })).join("");
  const resultOptions = ["", "success", "failure"].map(function (value) {
    const label = value ? sentenceCase(value) : "Any";
    return '<option value="' + escHtml(value) + '"' + (f.result === value ? ' selected' : '') + '>' + escHtml(label) + '</option>';
  }).join("");
  const chips = [
    "Layer: " + (f.layer ? evidenceLayerName(f.layer) : "Any"),
    "Agent: " + (f.agent || "Any"),
    "Event: " + (f.event || "Any"),
    "Result: " + (f.result ? sentenceCase(f.result) : "Any"),
    "From: " + (f.from || "Any"),
    "Time range: " + TIME_RANGE_LABEL[state.timeRange]
  ].map(function (chip) { return '<span class="evidence-chip">' + escHtml(chip) + '</span>'; }).join("");
  return '<section class="card evidence-query"><div class="filter-bar" role="group" aria-label="Filter evidence entries">' +
    '<label class="field evidence-query-field"><span class="field-label">Query</span><input class="input" data-action="evidence-filter-query" placeholder="agent: layer: result: event: or text" value="' + escHtml(f.query) + '"></label>' +
    '<label class="field"><span class="field-label">Layer</span><select class="input" data-action="evidence-filter-layer">' + layerOptions + '</select></label>' +
    '<label class="field"><span class="field-label">Agent</span><input class="input" data-action="evidence-filter-agent" value="' + escHtml(f.agent) + '"></label>' +
    '<label class="field"><span class="field-label">Event</span><input class="input" data-action="evidence-filter-event" value="' + escHtml(f.event) + '"></label>' +
    '<label class="field"><span class="field-label">Result</span><select class="input" data-action="evidence-filter-result">' + resultOptions + '</select></label>' +
    '<label class="field"><span class="field-label">From</span><input class="input" data-action="evidence-filter-from" type="date" value="' + escHtml(f.from) + '"></label>' +
    '</div><div class="evidence-chips">' + chips + '<span class="evidence-chip">Query searches only the entries loaded on this page</span></div></section>';
}

function renderEvidenceRow(entry, index) {
  const selected = state.evidence.selectedIndex === index;
  const result = evidenceResult(entry);
  const resultKind = result === "success" ? "neutral" : result === "failure" ? "bad" : "unknown";
  return '<tr' + (selected ? ' class="sel"' : '') + ' data-evidence-row="' + escHtml(index) + '">' +
    '<td class="mono">' + escHtml(shortTime(evidenceTimestamp(entry)) || "timestamp missing") + '</td>' +
    '<td><span class="lay">' + escHtml(evidenceLayerName(entry.layer)) + '</span></td>' +
    '<td><span class="row">' + escHtml(evidenceAgent(entry)) + '</span></td>' +
    '<td><button class="btn" data-action="evidence-select" data-evidence-index="' + index + '" aria-pressed="' + selected + '">' + escHtml(evidenceEvent(entry)) + '</button></td>' +
    '<td>' + renderEvidenceStatusChip(resultKind, result ? sentenceCase(result) : "Missing") + '</td>' +
  '</tr>';
}

function renderEvidenceDrawer(entry) {
  if (!entry) {
    return '<aside class="panel evidence-detail"><div class="overview-empty"><h3>No record selected</h3><p>Select an entry to inspect the served audit record.</p></div></aside>';
  }
  const result = evidenceResult(entry);
  const details = evidenceDetailsList(entry);
  const contributors = evidenceContributorsList(entry);
  const raw = cappedText(entry, EVIDENCE_RAW_RECORD_MAX_CHARS);
  return '<aside class="panel evidence-detail" aria-label="Selected entry">' +
    '<div class="hd"><div class="t">' + escHtml(evidenceEvent(entry)) + '</div><div class="m">' + escHtml(evidenceTimestamp(entry)) + ' · ' + escHtml(evidenceLayerName(entry.layer)) + '</div></div>' +
    '<div class="sec"><h3>What happened</h3><dl class="kv">' +
      '<dt>Operation</dt><dd>' + escHtml(evidenceEvent(entry)) + '</dd>' +
      '<dt>Agent</dt><dd>' + escHtml(evidenceAgent(entry)) + '</dd>' +
      '<dt>Layer</dt><dd>' + escHtml(evidenceLayerName(entry.layer)) + '</dd>' +
      '<dt>Result</dt><dd>' + renderEvidenceStatusChip(result === "success" ? "neutral" : result === "failure" ? "bad" : "unknown", result ? sentenceCase(result) : "Missing") + '</dd>' +
      '<dt>Time</dt><dd>' + escHtml(evidenceTimestamp(entry) || "timestamp missing") + '</dd>' +
      details + contributors +
    '</dl></div>' +
    '<div class="sec"><h3>Seal</h3><div class="chain">' +
      '<p class="muted">Per-entry seal data is not served by this read. Chain integrity is the strip above.</p>' +
    '</div></div>' +
    '<div class="sec"><h3>Raw record</h3><pre class="json">' + escHtml(raw) + '</pre></div>' +
  '</aside>';
}

function renderEvidenceExports() {
  return '<section class="card evidence-export"><h3>Export</h3><div class="toolbar">' +
    '<button class="btn" data-action="evidence-export-json">JSON: latest ' + EVIDENCE_JSON_EXPORT_LIMIT + ' audit entries</button>' +
    '<button class="btn" disabled title="CEF export is available from the audit_export_siem tool, not from this dashboard yet.">CEF unavailable from this dashboard</button>' +
    '<button class="btn" disabled title="Compliance bundle export is Tier 1 through compliance_generate_eu_ai_act_bundle, not from this dashboard yet.">Compliance bundle unavailable from this dashboard</button>' +
    '<a class="btn" href="/posture/evidence">Open the signed Evidence view</a>' +
    '<a class="btn" href="#exit-drill">Exit drill</a>' +
  '</div></section>';
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
  const view = state.evidence.view;
  // Must match AuditLog.query in server/src/operational/audit-log.ts, which serves the most recent
  // entries oldest first (filtered.slice(-limit)); the table lists that page newest first.
  const entries = sourceLoaded("/api/posture/evidence") && view && Array.isArray(view.entries) ? view.entries.slice().reverse() : [];
  const filtered = filteredEvidenceEntries(entries);
  const shown = filtered.slice(0, EVIDENCE_PAGE_SIZE);
  if (!shown[state.evidence.selectedIndex]) state.evidence.selectedIndex = 0;
  const selected = shown[state.evidence.selectedIndex] || null;
  const total = view && typeof view.total === "number" ? view.total : "Unknown";
  // buildEvidence applies the page limit before the result filter and serves total before both, so a
  // result filter narrows only the most recent page, and the count says so.
  const resultScopeLine = state.evidence.filters.result
    ? '<p class="muted" data-evidence-result-scope="1">The result filter checks the ' + EVIDENCE_PAGE_SIZE + ' most recent entries in the window; ' + escHtml(total) + ' counts entries of every result.</p>'
    : "";
  const searchedLine = state.evidence.filters.query
    ? "searching the " + entries.length + " entries loaded"
    : "search is local to the " + entries.length + " entries loaded";
  const timeRangeActive = state.timeRange !== "all";
  const serverFiltersActive = Object.keys(state.evidence.filters).some(function (key) { return key !== "query" && !!state.evidence.filters[key]; });
  const searchActive = !!state.evidence.filters.query;
  // Name only filters actually applied; a range-only view cannot be cleared by navigating to its existing hash.
  const activeFilterNames = (timeRangeActive ? ["time range"] : []).concat(serverFiltersActive ? ["server filters"] : [], searchActive ? ["page-local search"] : []);
  const noMatchNote = entries.length + " entries were loaded" + (timeRangeActive ? " for " + TIME_RANGE_LABEL[state.timeRange] : "") + ". " +
    (activeFilterNames.length ? "Active filters: " + activeFilterNames.join(", ") + ". " : "") + "No matches on this page." +
    (timeRangeActive ? (serverFiltersActive || searchActive ? " Clear filters keeps the time range; change it in the top bar." : " Change the time range in the top bar.") : "");
  const clearFiltersLink = serverFiltersActive || searchActive ? '<a class="btn" href="#activity">Clear filters</a>' : "";
  const empty = sourceLoaded("/api/posture/evidence") && !filtered.length
    // AuditLog.query applies range/agent/layer/operation before total and paging; only buildEvidence's result
    // post-filter can explain an empty served page with a positive total. Page-local search runs after that read.
    ? !entries.length && total > 0 && !state.evidence.filters.result
      ? '<div class="overview-empty"><h3>No entries on this page</h3><p>' + escHtml("The server counts " + total + (total === 1 ? " entry" : " entries") + " in this view, but this read shows none.") + '</p><button class="btn" data-action="retry-panel" data-read="/api/posture/evidence">Retry</button></div>'
      : entries.length || total > 0 || timeRangeActive || Object.values(state.evidence.filters).some(Boolean)
      ? '<div class="overview-empty"><h3>No entries match this view</h3><p>' + escHtml(noMatchNote) + '</p>' + clearFiltersLink + '</div>'
      : '<div class="overview-empty"><h3>No audit entries in this view</h3><p>The server returned an empty Evidence window for these filters.</p></div>'
    : "";
  const table = sourceLoaded("/api/posture/evidence")
    ? '<section class="panel evidence-entries" aria-label="Entries"><div class="ph"><h2>Entries <span class="n">showing ' + escHtml(shown.length) + ' of ' + escHtml(total) + '</span></h2><span class="hint">page size ' + EVIDENCE_PAGE_SIZE + ' · ' + escHtml(searchedLine) + '</span></div>' + resultScopeLine +
      (shown.length ? '<div class="overview-table-scroll"><table class="overview-table evidence-table"><thead><tr><th>Time</th><th>Layer</th><th>Agent</th><th>Event</th><th>Result</th></tr></thead><tbody>' + shown.map(renderEvidenceRow).join("") + '</tbody></table></div>' : empty) + '</section>'
    : '<section class="panel evidence-entries" aria-label="Entries"><div class="overview-empty"><h3>Entries Unknown</h3><p>The server verification read has not loaded entries.</p></div></section>';
  const operations = renderEvidenceOperationsSection();
  return [
    '<section class="evidence-page">',
      '<div class="page-head"><div>',
        '<p class="eyebrow">Evidence</p>',
        '<h1>Evidence</h1>',
        // The subtitle names the source and makes no completeness or tamper claim: not every decision is
        // recorded here (inbox decisions stay in the inbox), and integrity is the strip's to state.
        '<p class="sub">The audit log this fortress keeps. Integrity is shown only from the server verification read.</p>',
      '</div></div>',
      renderEvidenceIntegrity(view),
      renderEvidenceQueryBar(),
      renderSourceRead("/api/posture/evidence"),
      '<div class="evidence-layout">' + table + renderEvidenceDrawer(selected) + '</div>',
      renderEvidenceExports(),
      operations,
    '</section>'
  ].join("");
}

function renderEvidenceDecidedApprovals() {
  if (!sourceLoaded(HUB + "/inbox")) return "";
  if (state.inboxRedacted) return '<section class="card"><h3>Decided approvals</h3><p>Approvals are hidden, not empty. Paste the operator token to review them.</p></section>';
  const decided = state.inbox.filter(function (item) { return item.kind === "approval_pending" && item.resolved; });
  const shown = filterInbox(decided).slice(0, EVIDENCE_DECIDED_APPROVAL_LIMIT);
  // Resolution is a served historical fact, never permission to decide the item again.
  return '<section class="card"><h3>Decided approvals</h3><p class="muted">showing ' + shown.length + ' of ' + decided.length +
    ' loaded decisions · inbox read ' + escHtml(sourceReadAge(HUB + "/inbox") || "now") + '</p>' +
    (shown.length ? shown.map(function (item) {
      return '<div class="row" data-decided-approval="' + escHtml(item.item_id) + '"><div class="grow">' +
        escHtml(renderTemplate(item.display_template_id, item.display_template_args)) + '</div>' +
        renderEvidenceStatusChip("neutral", "Resolved") + '<span class="mono">' + escHtml(item.resolved_at || "resolution time not served") + '</span></div>';
    }).join("") : '<p class="muted">No decided approvals in this loaded view.</p>') + '</section>';
}

function renderEvidenceOperationsSection() {
  const visibleInbox = filterInbox(state.inbox.filter(function (i) { return !i.resolved; }));
  const selectedIds = Object.keys(state.inboxOps.selected).filter(function (id) { return state.inboxOps.selected[id]; });
  const batchToolbar = selectedIds.length
    ? '<div class="toolbar" style="margin-bottom:8px;">' +
        '<span class="pill">' + selectedIds.length + ' selected</span>' +
        '<button class="btn" data-action="inbox-batch-archive"' + approvalDecisionDisabled() + '>Archive</button>' +
        '<button class="btn" data-action="inbox-batch-dismiss"' + approvalDecisionDisabled() + '>Dismiss</button>' +
        '<button class="btn" data-action="inbox-batch-snooze-open"' + approvalDecisionDisabled() + '>Snooze</button>' +
        '<button class="btn btn-danger" data-action="inbox-batch-delete"' + approvalDecisionDisabled() + '>Delete</button>' +
      '</div>'
    : "";
  const snoozeDialog = state.inboxOps.snoozeDialog
    ? '<div class="modal-backdrop"><div class="modal"><h3>Snooze</h3><div class="toolbar">' +
        '<button class="btn" data-action="inbox-batch-snooze" data-snooze-ms="' + (MS_PER_HOUR) + '"' + approvalDecisionDisabled() + '>1h</button>' +
        '<button class="btn" data-action="inbox-batch-snooze" data-snooze-ms="' + (4 * MS_PER_HOUR) + '"' + approvalDecisionDisabled() + '>4h</button>' +
        '<button class="btn" data-action="inbox-batch-snooze" data-snooze-ms="' + (24 * MS_PER_HOUR) + '"' + approvalDecisionDisabled() + '>1d</button>' +
        '<button class="btn" data-action="inbox-batch-snooze" data-snooze-ms="' + (7 * 24 * MS_PER_HOUR) + '"' + approvalDecisionDisabled() + '>1w</button>' +
        '<input class="input" data-action="inbox-snooze-custom" type="datetime-local">' +
        '<button class="btn" data-action="inbox-batch-snooze-custom"' + approvalDecisionDisabled() + '>Custom</button>' +
        '<button class="btn" data-action="inbox-batch-snooze-close">Cancel</button>' +
      '</div></div></div>'
    : "";
  // Each filter is a labelled field in a wrapping grid: the label sits above
  // its control in the label style, so no label runs into its neighbour.
  const filterField = function (label, control) {
    return '<label class="field"><span class="field-label">' + label + '</span>' + control + '</label>';
  };
  const filterPanel =
    '<div class="filter-bar" role="group" aria-label="Filter the inbox">' +
      filterField("Search", '<input class="input" data-action="inbox-filter-search" value="' + escHtml(state.inboxOps.filters.search) + '">') +
      filterField("Source", '<select class="input" data-action="inbox-filter-source"><option value="">Any</option>' + inboxOption("blocked_egress") + inboxOption("privacy_event") + inboxOption("budget_warning") + inboxOption("recovery_prompt") + inboxOption("agent_error") + inboxOption("approval") + inboxOption("sentinel_finding") + '</select>') +
      filterField("Severity", '<select class="input" data-action="inbox-filter-severity"><option value="">Any</option>' + inboxOption("info", "severity") + inboxOption("warn", "severity") + inboxOption("alert", "severity") + inboxOption("critical", "severity") + '</select>') +
      filterField("Agent", '<select class="input" data-action="inbox-filter-agent"><option value="">Any</option>' + inboxAgentOptions() + '</select>') +
      filterField("From", '<input class="input" data-action="inbox-filter-from" type="date" value="' + escHtml(state.inboxOps.filters.from) + '">') +
      filterField("To", '<input class="input" data-action="inbox-filter-to" type="date" value="' + escHtml(state.inboxOps.filters.to) + '">') +
    '</div>';
  const redactedNotice = state.inboxRedacted
    ? '<div class="banner-warn" data-pending-approvals-redacted="1">Approvals are hidden, not empty. Pending count: ' + escHtml(state.inboxRedactedCount) + '. Paste the operator token to review and decide them.</div>'
    : '';
  var inboxRows;
  const openItems = state.inbox.filter(function (i) { return !i.resolved; });
  if (!visibleInbox.length && !openItems.length) {
    inboxRows = redactedNotice || '<p class="muted">Nothing pending.</p>';
  } else if (!visibleInbox.length) {
    // Open items exist but the view shows none: say where they went, so an
    // empty window never reads as an empty inbox.
    const anyTime = filterInbox(openItems, true).length;
    const hiddenByFilters = openItems.length - anyTime;
    const parts = [];
    if (anyTime) parts.push(anyTime + (anyTime === 1 ? " older item is" : " older items are") + " outside " + TIME_RANGE_LABEL[state.timeRange]);
    if (hiddenByFilters) parts.push(hiddenByFilters + (hiddenByFilters === 1 ? " item is" : " items are") + " hidden by your filters");
    inboxRows = redactedNotice + '<p class="muted">No open items in this view: ' + escHtml(parts.join("; ")) + '.</p>';
  } else {
    var tier1Items = visibleInbox.filter(function (i) { return i.kind === "approval_pending" && i.tier === "tier1"; });
    var tier2Items = visibleInbox.filter(function (i) { return i.kind === "approval_pending" && i.tier === "tier2"; });
    var otherItems = visibleInbox.filter(function (i) { return i.kind !== "approval_pending" || (i.tier !== "tier1" && i.tier !== "tier2"); });
    function renderInboxRow(i) {
      var text = renderTemplate(i.display_template_id, i.display_template_args);
      var actions = inboxActions(i);
      // Invariant: as on the Overview, a held approval is decided inline only at Tier 2; every other
      // served tier links to Approvals, where a Tier 1 decision takes the drawer's two steps.
      var reviewInApprovals = i.kind === "approval_pending" && i.tier !== "tier2";
      var buttons = reviewInApprovals
        ? '<a class="btn" href="#approvals" data-evidence-review="' + escHtml(i.item_id) + '">Review in Approvals</a>'
        : actions.map(function (act) {
          // A decision control shares the one decision lock; a receipt link is not a decision.
          const decides = act === "approve" || act === "deny" || act === "dismiss";
          return '<button class="btn" data-action="inbox-' + act + '" data-item-id="' + escHtml(i.item_id) + '"' + (decides ? approvalDecisionDisabled() : "") + '>' + INBOX_ACTION_LABEL[act] + '</button>';
        }).join("");
      var tierBadge = i.kind === "approval_pending"
        ? '<span class="pill">' + escHtml(i.tier) + '</span>'
        : '<span class="pill">' + escHtml(i.kind) + '</span>';
      return '<div class="row" data-inbox-row="' + escHtml(i.item_id) + '" data-inbox-kind="' + escHtml(i.kind) + '"' +
        (i.kind === "approval_pending" ? ' data-inbox-tier="' + escHtml(i.tier) + '"' : '') + '>' +
        '<input type="checkbox" data-action="inbox-select" data-item-id="' + escHtml(i.item_id) + '"' + (state.inboxOps.selected[i.item_id] ? ' checked' : '') + batchSelectionDisabled() + '>' +
        '<div class="grow">' + escHtml(text) + '</div>' +
        tierBadge +
        '<button class="btn" data-action="inbox-snooze-menu" data-item-id="' + escHtml(i.item_id) + '"' + (decisionInFlight() ? approvalDecisionDisabled() : ' title="Snooze"') + '>...</button>' +
        '<div style="display:flex;gap:4px;">' + buttons + '</div>' + renderDecisionInline(i) +
        '</div>';
    }
    var sections = [];
    if (tier1Items.length) sections.push('<h4 class="inbox-group-head">Tier 1 approvals</h4>' + tier1Items.map(renderInboxRow).join("\n"));
    if (tier2Items.length) sections.push('<h4 class="inbox-group-head">Tier 2 approvals</h4>' + tier2Items.map(renderInboxRow).join("\n"));
    if (otherItems.length) sections.push((tier1Items.length || tier2Items.length ? '<h4 class="inbox-group-head">Other</h4>' : '') + otherItems.map(renderInboxRow).join("\n"));
    inboxRows = redactedNotice + sections.join("\n");
  }
  const total = sourceLoaded(HUB + "/inbox") ? state.inbox.filter(function (i) { return !i.resolved; }).length : "Unknown";
  // The count states what the filters and the time range left showing, out of
  // every open item, so a narrowed list never reads as the whole inbox.
  const inboxCount = sourceLoaded(HUB + "/inbox") ? visibleInbox.length + " of " + total : "Unknown";
  if (!sourceLoaded(HUB + "/inbox")) inboxRows = renderSourceRead(HUB + "/inbox");
  return [
    '<section class="evidence-ops">',
      '<section class="card">',
        '<h3>This fortress</h3>',
        (config.tenantName ? '<p><strong>' + escHtml(config.tenantName) + '</strong></p>' : ''),
        '<p class="muted mono">' + escHtml(config.fortressId || "(local)") + '</p>',
        '<p class="muted">Operator: ' + escHtml(config.identityId || "(unknown)") + '</p>',
      '</section>',
      '<section class="card"><h3>Inbox (' + inboxCount + ')' + (state.timeRange !== "all" ? ' <span class="count-age">' + escHtml(TIME_RANGE_LABEL[state.timeRange]) + '</span>' : '') + '</h3>' + renderSourceRead(INBOX_PREFS) + filterPanel + (sourceLoaded(HUB + "/inbox") ? batchToolbar : '') + renderDecisionBatchInline() + inboxRows + snoozeDialog + '</section>',
      renderEvidenceDecidedApprovals(),
      '<section class="card"><h3>Agents (' + (sourceLoaded(HUB + "/agents") ? state.agents.length : "Unknown") + ')</h3>' + renderFortressAgentsCard() + '</section>',
      '<section class="card"><h3>Recognition Layer health</h3>' + renderRecognitionHealthCard() + '</section>',
    '</section>'
  ].join("");
}

// ── Posture screen (Overview, 2026-10-14) ────────────────────────────────
// The default surface is the security-console Overview. It reuses served
// posture, roster, inbox and Sentinel data, then renders honest tiles, the
// decision queue, findings, and the agents table. Named layers only (no
// L-numbers); no em-dashes in user-visible copy.
function evidenceCurrent(evidence) {
  // Protection requires one unambiguous, valid instant; invalid or offset-less evidence fails closed.
  const timestamp = evidence && parseEvidenceTimestamp(evidence.last_enforcement_evidence_at);
  const windowMs = evidence && Number(evidence.freshness_window_ms);
  return Number.isFinite(timestamp) && Number.isFinite(windowMs) && windowMs > 0 && Date.now() >= timestamp && Date.now() - timestamp <= Math.min(windowMs, SEAL_FRESHNESS_MAX_MS);
}
function agentEvidenceStatus(agent) {
  if (!sourceLoaded(HUB + "/agents")) return "unknown";
  if (agent.status !== "active") return agent.status;
  // Only this agent's loaded posture evidence can vouch for protection; roster or machine timestamps cannot.
  const home = sourceLoaded("/api/posture/home") && state.posture.home;
  return home && agentEnforcementConfirmedNow(agent, home) ? "active" : "unknown";
}
function agentDisplayStatus(agent) {
  return STATUS_MAP[agentEvidenceStatus(agent)] || STATUS_MAP.unknown;
}
function postureWallLabel(armState) {
  if (!sourceLoaded("/api/posture/home") || (armState === "armed" && !evidenceCurrent(state.posture.home && state.posture.home.castle_wall))) return { cls: "pill tone-unknown", text: "Unknown" };
  if (armState === "armed") return { cls: "pill tone-verified", text: "Enforcing" };
  // S5-P distinct non-green: coarse wall enforcing, fine-grained exclusive-egress
  // stack not live. Never the verified/green tone.
  if (armState === "coarse_only") return { cls: "pill tone-degraded", text: "Coarse-only" };
  if (armState === "degraded") return { cls: "pill tone-degraded", text: "Degraded" };
  if (armState === "not_installed") return { cls: "pill", text: "Not installed" };
  if (armState === "locked_down") return { cls: "pill tone-locked", text: "Locked down" };
  return { cls: "pill tone-unknown", text: "Unknown" };
}
// Slice 3 Overview caps. Each rendered list prints "showing M of N" beside
// the panel title so the cap bounds client work without hiding the backlog.
const OVERVIEW_DECISION_LIMIT = 4;
const OVERVIEW_FINDING_LIMIT = 3;
const OVERVIEW_AGENT_LIMIT = 8;
const OVERVIEW_DESTINATION_LIMIT = 3; // Compact Overview preview, with the full served list on Enforcement.
// Must match BLOCKED_DESTINATION_SERVED_LIMIT in principal-policy/posture.ts.
const OUTBOUND_DESTINATION_LIMIT = 10;

function overviewSourceReason(path, noun) {
  const read = sourceRead(path);
  if (sourceNotServed(path)) return noun + " is not served on this host";
  if (!read || read.state === "state_UNREAD" || read.state === "state_LOADING") return noun + " has not answered yet";
  if (read.state === "state_FAILED") return noun + " did not answer" + (read.error ? ": " + stripTrailingPeriod(read.error) : "");
  return noun + " is not evaluated";
}
function sentenceCase(text) {
  const value = String(text || "");
  return value ? value.charAt(0).toUpperCase() + value.slice(1) : value;
}
function stripTrailingPeriod(text) {
  return String(text || "").replace(/[.]+$/, "");
}
function loadedSourceReadAge(path) {
  return sourceLoaded(path) ? sourceReadAge(path) : null;
}

function overviewChip(kind, word, detail) {
  return '<span class="state-chip ' + escHtml(kind) + ' overview-chip"><span class="overview-chip-head"><i aria-hidden="true"></i>' +
    escHtml(word) + '</span>' + (detail ? '<span class="overview-chip-detail">' + escHtml(detail) + '</span>' : '') + '</span>';
}

function overviewTile(label, valueHtml, evidenceHtml, href) {
  return '<div class="overview-tile">' +
    '<a class="ot-label" href="' + escHtml(href || "#activity") + '">' + escHtml(label) + '</a>' +
    '<span class="ot-value">' + valueHtml + '</span>' +
    '<span class="ot-evidence">' + (typeof evidenceHtml === "string" ? evidenceHtml : (evidenceHtml && evidenceHtml.text) || "") + '</span>' +
  '</div>';
}

function servedCount(value) {
  return Number.isSafeInteger(value) && value >= 0;
}

function renderOverviewProtection(home) {
  const loaded = sourceLoaded("/api/posture/home") && home;
  const requested = loaded ? home.protection_requested_count : null;
  const detected = loaded ? home.protection_detected_count : null;
  const known = servedCount(requested) && servedCount(detected) && requested <= detected;
  const reason = !loaded ? overviewSourceReason("/api/posture/home", "posture")
    : !servedCount(requested) || !servedCount(detected) ? "protection counts not served"
    : "requested count exceeds detected count";
  // Policy intent is never an enforcement claim, including a fully requested roster.
  return overviewTile("Protection requested", known ? escHtml(requested + " of " + detected) : overviewChip("unknown", "UNKNOWN"),
    known ? "registered agents plus unprotected harnesses · posture read " + escHtml(loadedSourceReadAge("/api/posture/home") || "Unknown") : escHtml(reason), "#agents");
}

function auditChainEvidence(digest) {
  return { last_enforcement_evidence_at: digest && digest.window_end, freshness_window_ms: AUDIT_CHAIN_VERIFIED_MAX_AGE_MS };
}

function auditChainCheckCurrent(digest) {
  // The chip and counts share both the accepted verdict and its evidence clock.
  return !!digest && ((digest.chain_verdict === "verified" && digest.chain_verified === true) ||
    digest.chain_verdict === "verified_suffix_only") && evidenceCurrent(auditChainEvidence(digest));
}

function windowCoverageReason(d) {
  // Must match AuditDigest.window_incomplete_reason in principal-policy/posture.ts.
  if (typeof d.window_complete !== "boolean") return "window completeness not served";
  if (d.window_complete) return null;
  switch (d.window_incomplete_reason) {
    case "read_limit": return "window larger than one read";
    case "sealed_region": return "sealed audit region coverage not established";
    // This reason establishes missing coverage, not whether pruning, a legacy prefix, or an append caused it.
    case "retention": return "the check could not reach the oldest audit entry, so this window is not fully covered";
    default: return "window coverage not established";
  }
}

function renderOutboundConnections(d, overview) {
  d = d || {};
  // Counts require both a covered window and the same current verified/suffix check as the chip.
  // Continuing paths also require dated reads and safe served counts; all refusals name their missing evidence.
  // Must match the fail-honest returns in buildAuditDigest (principal-policy/posture.ts).
  // Counts and the chip must name the same missing evidence; a mismatched verdict is not a stale verification.
  const reason = (d.chain_verdict !== "verified" && d.chain_verdict !== "verified_suffix_only") || (d.chain_verdict === "verified" && d.chain_verified !== true) ? "chain not verified"
    : windowCoverageReason(d) ? windowCoverageReason(d)
    : !Number.isFinite(parseEvidenceTimestamp(d.window_start)) || !Number.isFinite(parseEvidenceTimestamp(d.window_end)) ? "window not stated"
    : !auditChainCheckCurrent(d) ? "audit check not current"
    : !servedCount(d.kernel_blocks) || !servedCount(d.kernel_allows) ? "count not served" : null;
  const notEvaluated = function (why) {
    const age = why === "audit check not current" ? '<span class="outbound-reason muted">last verified ' + escHtml(relTimeFromIso(d.window_end)) + '</span>' : '';
    return overviewChip("unknown", "Not evaluated") + '<span class="outbound-reason muted">' + escHtml(why) + '</span>' + age;
  };
  // Continuing paths: Blocked needs the common gate; Allowed additionally needs exactly zero overrides.
  const allowedReason = reason || (!servedCount(d.kernel_allow_overrides) ? "override count not served"
    : d.kernel_allow_overrides === 1 ? "1 allowed verdict was overridden after it was recorded"
    : d.kernel_allow_overrides > 0 ? d.kernel_allow_overrides + " allowed verdicts were overridden after they were recorded" : null);
  const counts = '<div class="outbound-counts"><div>Blocked ' + (reason ? notEvaluated(reason) : '<strong>' + escHtml(d.kernel_blocks) + '</strong>') + '</div><div>Allowed ' +
    (allowedReason ? notEvaluated(allowedReason) : '<strong>' + escHtml(d.kernel_allows) + '</strong>') + '</div></div>';
  const windowLabel = Number.isFinite(parseEvidenceTimestamp(d.window_start)) && Number.isFinite(parseEvidenceTimestamp(d.window_end))
    ? '<p class="muted">window ' + escHtml(shortTime(d.window_start)) + ' to ' + escHtml(shortTime(d.window_end)) + '</p>' : '';
  let destinations;
  if (reason) destinations = '<p>' + notEvaluated(reason) + '</p>';
  else if (!Array.isArray(d.blocked_destinations)) destinations = '<p>' + notEvaluated("Blocked destinations are not served") + '</p>';
  else {
    const rows = d.blocked_destinations;
    // Validation compares served values only; displayed counts are never reconstructed from rows.
    const validRows = rows.length <= OUTBOUND_DESTINATION_LIMIT && rows.every(function (row) {
      return row && (row.destination === null || typeof row.destination === "string") && servedCount(row.blocks) && row.blocks > 0 &&
        (row.last_blocked_at === null || Number.isFinite(parseEvidenceTimestamp(row.last_blocked_at)));
    });
    const sum = validRows ? rows.reduce(function (n, row) { return n + row.blocks; }, 0) : NaN;
    const disagree = !validRows || !servedCount(sum) || sum > d.kernel_blocks ||
      !servedCount(d.blocked_destination_count) || d.blocked_destination_count < rows.length ||
      d.blocked_destination_count > d.kernel_blocks ||
      (d.kernel_blocks > 0 && (rows.length === 0 || d.blocked_destination_count === 0)) ||
      (d.blocked_destination_count === rows.length && sum < d.kernel_blocks);
    // Destinations continue only through the count gate plus row-shape and consistency checks.
    if (disagree) destinations = '<p>' + notEvaluated("served destination values disagree") + '</p>';
    else if (d.kernel_blocks === 0) destinations = '<p>No blocked connections in this window</p>';
    else {
      const shown = rows.slice(0, overview ? OVERVIEW_DESTINATION_LIMIT : OUTBOUND_DESTINATION_LIMIT);
      destinations = '<div class="card-head-row"><h4>Blocked destinations <span class="count-age">showing ' + escHtml(shown.length) + ' of ' + escHtml(d.blocked_destination_count) + '</span></h4>' +
        (overview ? '<a href="#enforcement">all outbound connections</a>' : '') + '</div>' +
        '<div class="overview-table-scroll"><table class="overview-table outbound-table"><thead><tr><th>Destination</th><th>Blocks</th><th>Last blocked</th></tr></thead><tbody>' +
        shown.map(function (row) { return '<tr><td>' + escHtml(row.destination === null ? "destination not recorded" : row.destination) + '</td><td>' + escHtml(row.blocks) + '</td><td>' + escHtml(row.last_blocked_at === null ? "Unknown" : shortTime(row.last_blocked_at)) + '</td></tr>'; }).join("") + '</tbody></table></div>';
    }
  }
  // Enforcement always keeps the window's age and evidence destination, including withheld and empty reads.
  const foot = overview ? '' : '<div class="evidence pm-foot"><span class="pm-fresh">' +
    (Number.isFinite(parseEvidenceTimestamp(d.window_end)) ? 'window closed ' + escHtml(relTimeFromIso(d.window_end)) : 'window not stated') +
    '</span><a class="pm-ev" href="/posture/evidence">Open the Evidence view &rarr;</a></div>';
  return '<section class="card outbound-card"><h3>Outbound connections</h3>' + counts + windowLabel + destinations + foot + '</section>';
}

function postureEvidenceByAgent(home) {
  const map = Object.create(null);
  (home && home.agents || []).forEach(function (row) { if (row && row.agent_id) map[row.agent_id] = row; });
  return map;
}

function unprotectedHarnesses(home) {
  return home && home.unwrapped && Array.isArray(home.unwrapped.unwrapped) ? home.unwrapped.unwrapped : null;
}

function isRosterStateProtectable(agent) {
  return agent && agent.status !== "locked_down" && agent.status !== "error" && agent.status !== "paused";
}

function agentEnforcementConfirmedNow(agent, home) {
  const evidence = postureEvidenceByAgent(home)[agent && agent.agent_id];
  // Invariant: confirmed means this protected agent has current active enforcement evidence and is not in a continuing roster state that suspends or invalidates it.
  return !!(isRosterStateProtectable(agent) && evidence && evidence.enforcement_active === "active" && evidenceCurrent(evidence));
}

function oldestAge(items) {
  const times = items.map(function (i) { return parseEvidenceTimestamp(i.created_at || ""); }).filter(Number.isFinite);
  if (!times.length) return "oldest age Unknown";
  return "oldest " + durationLabelFromMs(Date.now() - Math.min.apply(null, times)) + " ago";
}

function overviewFirstRun(home) {
  const unwrapped = unprotectedHarnesses(home);
  const detectedHarnesses = Array.isArray(unwrapped) ? unwrapped : [];
  const reason = !Array.isArray(unwrapped)
    ? "Unprotected-harness list was not served"
    : detectedHarnesses.length
    ? String(detectedHarnesses.length) + " agent harness" + (detectedHarnesses.length === 1 ? "" : "es") + " detected, none protected"
    : "No harness was detected";
  return '<section class="overview-empty" data-overview-first-run="1">' +
    '<h2>No agents protected yet</h2>' +
    '<p>' + escHtml(sentenceCase(reason) + ". Evidence read " + (loadedSourceReadAge("/api/posture/home") || "is current only after the first check") + ".") + '</p>' +
    (detectedHarnesses.length ? '<p class="muted">' + escHtml(detectedHarnesses.map(function (u) { return u.harness || "unknown harness"; }).join(", ")) + '</p>' : '') +
    '<a class="btn btn-primary" href="#agents">Protect an agent</a>' +
  '</section>';
}

function overviewDecisionRow(item) {
  const text = renderTemplate(item.display_template_id, item.display_template_args);
  const agentId = item.agent_id || "";
  const createdAt = parseEvidenceTimestamp(item.created_at || "");
  const wait = Number.isFinite(createdAt) ? durationLabelFromMs(Date.now() - createdAt) + " ago" : "Unknown";
  const tier = item.tier === "tier1" ? "Tier 1" : item.tier === "tier2" ? "Tier 2" : (item.tier ? "Tier " + String(item.tier) : "Tier unknown");
  // Invariant: inline decisions are a positive Tier 2 affordance only; every other served tier stays on the full Approvals path.
  const actions = item.tier === "tier2"
    ? '<div class="actions"><button class="btn btn-sm at-approve" data-action="inbox-approve" data-item-id="' + escHtml(item.item_id) + '"' + approvalDecisionDisabled() + '>Allow once</button>' +
      '<button class="btn btn-sm" data-action="inbox-deny" data-item-id="' + escHtml(item.item_id) + '"' + approvalDecisionDisabled() + '>Deny</button></div>' + renderDecisionInline(item)
    : '<a class="btn btn-sm" href="#approvals" data-overview-review="' + escHtml(item.item_id) + '">Review in Approvals</a>';
  const agentCell = agentId
    ? '<a href="#agent-detail" data-action="open-agent" data-agent-id="' + escHtml(agentId) + '">' + escHtml(agentId) + '</a>'
    : '<span>agent not named</span>';
  return '<tr><td class="overview-tier"><span class="mono">' + escHtml(tier) + '</span></td><td>' + agentCell + '</td>' +
    '<td class="mono">' + escHtml(item.operation_category || "approval") + '</td><td>' + escHtml(text) + '</td><td class="mono">' + escHtml(wait) + '</td><td>' + actions + '</td></tr>';
}

function renderOverviewDecisionQueue() {
  if (!sourceLoaded(HUB + "/inbox")) {
    return '<section class="card"><div class="card-head-row"><h3>Needs your decision <span class="count-age">Not evaluated</span></h3></div>' +
      '<div class="overview-empty"><h3>Approvals Unknown</h3><p>' + escHtml(sentenceCase(overviewSourceReason(HUB + "/inbox", "approval queue"))) + '.</p><button class="btn" data-action="retry-panel" data-read="' + HUB + "/inbox" + '">Retry</button></div></section>';
  }
  if (state.inboxRedacted) {
    return '<section class="card"><div class="card-head-row"><h3>Needs your decision <span class="count-age">Unknown</span></h3></div>' +
      '<div class="overview-empty"><h3>Approvals hidden</h3><p>Approval queue is hidden until you paste the operator token. Pending count: ' + escHtml(state.inboxRedactedCount) + '.</p><a class="btn" href="#approvals">Open Approvals</a></div></section>';
  }
  const all = heldApprovalItems(null).slice().sort(function (a, b) {
    return (parseEvidenceTimestamp(a.created_at || "") || 0) - (parseEvidenceTimestamp(b.created_at || "") || 0);
  });
  const shown = all.slice(0, OVERVIEW_DECISION_LIMIT);
  const evidence = approvalQueueEvidence();
  if (!all.length) {
    // The same evidence bound as Approvals prevents a full or unrecognized page from claiming an empty queue.
    if (!evidence.earned) return '<section class="card"><div class="card-head-row"><h3>Needs your decision <span class="count-age">queue read ' + escHtml(sourceReadAge(HUB + "/inbox") || "now") + '</span></h3></div>' + evidence.emptyHtml + evidence.warning + '<a class="btn" href="#approvals">Open Approvals</a></section>';
    return '<section class="card"><div class="card-head-row"><h3>Needs your decision <span class="count-age">0 of 0 · queue read ' + escHtml(sourceReadAge(HUB + "/inbox") || "now") + '</span></h3></div>' +
      '<div class="overview-empty"><h3>No approvals waiting</h3><p>0 of 0 held operations are open. Queue read ' + escHtml(sourceReadAge(HUB + "/inbox") || "now") + '.</p><a class="btn" href="#activity">Open Evidence</a></div></section>';
  }
  // The card's recognized total covers only the served page, so a full page cannot present it as exact.
  return '<section class="card"><div class="card-head-row"><h3>Needs your decision <span class="count-age">showing ' + escHtml(shown.length) + ' of ' + escHtml(all.length) + (evidence.full ? '+' : '') + ' · ' + escHtml(oldestAge(all)) + '</span></h3>' +
    '<a href="#approvals">all approvals</a></div><div class="overview-table-scroll"><table class="overview-table overview-table-decisions"><thead><tr><th>Tier</th><th>Agent</th><th>Operation</th><th>Why it asked</th><th>Waiting</th><th></th></tr></thead><tbody>' +
    // Recognized rows do not account for unknown tiers, so the card must retain their separate warning.
    shown.map(overviewDecisionRow).join("") + '</tbody></table></div>' + evidence.warning + '</section>';
}

function severityClass(level) {
  const v = String(level || "info").toLowerCase();
  if (v === "critical" || v === "high" || v === "medium" || v === "low") return v;
  return "info";
}
function severityRank(level) {
  const sev = severityClass(level);
  return sev === "critical" ? 0 : sev === "high" ? 1 : sev === "medium" ? 2 : sev === "low" ? 3 : 4;
}

function renderOverviewFindingsPanel() {
  const unknown = !sourceLoaded("/api/anomaly/findings") || state.posture.anomaliesUnknown !== false;
  const findings = unknown ? [] : (state.posture.anomalies || []).slice().sort(function (a, b) {
    return severityRank(a.severity) - severityRank(b.severity);
  });
  const shown = findings.slice(0, OVERVIEW_FINDING_LIMIT);
  const list = unknown
    ? '<div class="overview-empty"><h3>Sentinel findings Unknown</h3><p>' + escHtml(sentenceCase(overviewSourceReason("/api/anomaly/findings", "Sentinels"))) + '. This is not a confirmation of zero findings.</p><button class="btn" data-action="retry-panel" data-read="/api/anomaly/findings">Retry Anomaly findings</button></div>'
    : shown.length
      ? '<div class="overview-list">' + shown.map(function (f) {
          const sev = severityClass(f.severity);
          return '<div class="item"><span class="severity ' + sev + '"><b></b>' + escHtml(sev) + '</span><div class="body"><div class="title">' + escHtml(f.summary || f.detector_id || f.finding_id || "Sentinel finding") + '</div><div class="detail">Sentinel: ' + escHtml(f.detector_id || "Unknown") + '</div></div><span class="mono muted">' + escHtml(relTimeFromIso(f.created_at || f.observed_at)) + '</span></div>';
        }).join("") + '</div>'
      : '<div class="overview-empty"><h3>No open Sentinel findings</h3><p>0 of 0 open findings. Sentinels answered ' + escHtml(sourceReadAge("/api/anomaly/findings") || "now") + '.</p><a class="btn" href="#findings">Open Findings</a></div>';
  return '<section class="card"><div class="card-head-row"><h3>Findings <span class="count-age">' +
    (unknown ? "Not evaluated" : "showing " + shown.length + " of " + findings.length) + '</span></h3><a href="#findings">all findings</a></div>' + list +
    '<div class="card-head-row" style="border-top:1px solid var(--rule);padding-top:10px;margin-top:10px;"><h3>Fleet <span class="count-age">this machine plus saved machines</span></h3><a href="#machines">machines</a></div>' +
    '<p class="muted">Fleet enforcement status comes from the Machines screen health probes; this Overview does not infer remote protection from local evidence.</p></section>';
}

function agentBudgetText(agent) {
  const daily = agent && agent.budget_summary && agent.budget_summary.daily;
  if (!daily) return "Unknown";
  return String(daily.used) + " of " + String(daily.cap) + " " + String(daily.unit || "");
}

function agentStateChip(agent) {
  const status = agentEvidenceStatus(agent);
  const evidence = postureEvidenceByAgent(state.posture.home || {})[agent && agent.agent_id];
  const evidenceAge = evidence && evidence.last_enforcement_evidence_at ? relTimeFromIso(evidence.last_enforcement_evidence_at) : "";
  if (status === "active") return overviewChip("good", "RUNNING", evidenceAge);
  const tone = { paused: "neutral", restarting: "neutral", unwrapping: "neutral", locked_down: "locked", error: "bad" }[status] || "unknown";
  return overviewChip(tone, agentDisplayStatus(agent).label.toUpperCase());
}

function agentEnforcementChip(agent) {
  const evidence = postureEvidenceByAgent(state.posture.home || {})[agent && agent.agent_id];
  const evidenceAge = evidence && evidence.last_enforcement_evidence_at ? relTimeFromIso(evidence.last_enforcement_evidence_at) : "";
  return agentEvidenceStatus(agent) === "active"
    ? overviewChip("good", "CONFIRMED", evidenceAge)
    : overviewChip("unknown", "UNKNOWN");
}

function renderOverviewAgentsTable(agents, limit, offset) {
  const roster = agents || state.agents;
  const pageLimit = limit || OVERVIEW_AGENT_LIMIT;
  if (!sourceLoaded(HUB + "/agents")) {
    return '<section class="card"><div class="card-head-row"><h3>Agents <span class="count-age">Not evaluated</span></h3></div><div class="overview-empty"><h3>Agent roster Unknown</h3><p>' + escHtml(overviewSourceReason(HUB + "/agents", "agent roster")) + '.</p><button class="btn" data-action="retry-panel" data-read="' + HUB + "/agents" + '">Retry</button></div></section>';
  }
  const shown = roster.slice(offset || 0, (offset || 0) + pageLimit);
  const rows = shown.map(function (a) {
    const owner = a.identity_id || "Unknown";
    const template = a.channel_template_id || "Unknown";
    const policyAge = loadedSourceReadAge(HUB + "/policies");
    return '<tr><td><a href="#agent-detail" data-action="open-agent" data-agent-id="' + escHtml(a.agent_id) + '">' + escHtml(a.agent_id) + '</a></td>' +
      '<td>' + escHtml(owner) + '</td><td>' + escHtml(a.harness || "Unknown") + '</td><td>' + escHtml(template) + '</td>' +
      '<td class="mono">Unknown hosts · Unknown MCP · Unknown tools<br><span class="muted">' + escHtml((a.policy_id || "policy Unknown") + (policyAge ? " · policy read " + policyAge : "")) + '</span></td>' +
      '<td>' + agentEnforcementChip(a) + '</td><td>' + agentStateChip(a) + '</td><td>' + escHtml(agentBudgetText(a)) + '</td><td class="mono muted">' + escHtml(a.last_activity_at ? relTimeFromIso(a.last_activity_at) : "no activity reported") + '</td></tr>';
  }).join("");
  return '<section class="card"><div class="card-head-row"><h3>Agents <span class="n">showing ' + escHtml(shown.length) + ' of ' + escHtml(roster.length) + ' · <a href="#agents">all agents</a></span></h3><span class="count-age">Reach (allowed of requested)' + (loadedSourceReadAge(HUB + "/policies") ? ' · policy read ' + escHtml(loadedSourceReadAge(HUB + "/policies")) : '') + '</span></div>' +
    '<div class="overview-table-scroll"><table class="overview-table overview-table-agents"><thead><tr><th>Agent</th><th>Owner</th><th>Harness</th><th>Policy template</th><th>Reach (allowed of requested)</th><th>Enforcement</th><th>State</th><th>Budget today</th><th>Last activity</th></tr></thead><tbody>' + rows + '</tbody></table></div></section>';
}
function renderPostureAnomalies(findings, unknown) {
  if (unknown) {
    return '<p class="muted">Open anomaly findings unavailable (the detector is not available). This is not a confirmation of zero findings.</p>';
  }
  if (!findings || !findings.length) {
    // S3 quiet empty state: earned calm, and explicit about WHY it is empty.
    // This is the detector-ANSWERED case only; the unknown branch above must
    // never borrow it, because a silent detector is not a clean bill of health.
    return '<div class="posture-quiet"><span class="quiet-mark">&#9679;</span>' +
      '<span>No open anomaly findings.' +
      '<span class="quiet-why"> The detector answered and reported nothing open.</span>' +
      '</span></div>';
  }
  return findings.map(function (f) {
    return '<div class="story-line"><span class="pill tone-degraded">' + escHtml(f.severity || "finding") + '</span> ' +
      escHtml(f.summary || f.detector_id || f.finding_id || "anomaly") + '</div>';
  }).join("");
}
function renderPostureAgentRows(home) {
  const rows = (home.agents || []);
  // S3 first-run empty state: emptiness becomes a guided path rather than a
  // void. Step 1 is the only step actionable before an agent exists; the wall
  // and chain steps are described, never claimed. Nothing here asserts a
  // protection that is not in place, and the tiles above stay grey until
  // there is evidence for them.
  if (!rows.length) return '<div class="posture-firstrun">' +
    '<h4>No agents protected yet.</h4>' +
    '<p>Sanctuary protects an agent by giving it an identity, a policy, and approval ' +
    'gates, then enforcing them at the operating system. Three steps get this board to green.</p>' +
    '<ol class="firstrun-steps">' +
      '<li><strong>Protect your first agent.</strong> Run this where your agent lives.' +
      '<code class="firstrun-cmd">sanctuary protect</code></li>' +
      '<li><strong>Arm the wall.</strong> Turns policy into blocking the agent cannot talk its way past.' +
      '<code class="firstrun-cmd">sanctuary castle-wall arm</code></li>' +
      '<li><strong>Verify your audit chain.</strong> Confirms the record of what happened has not been altered.' +
      '<code class="firstrun-cmd">sanctuary audit-chain verify</code></li>' +
    '</ol>' +
    '<p class="firstrun-foot">Each step lights its own tile above.</p>' +
    '</div>';
  return rows.map(function (a) {
    // HONEST per-agent pill (#634): green ONLY on confirmed live enforcement;
    // amber on policy-only protection; never machine-arm bleed-through.
    var pill;
    var unprotected = false;
    if (a.enforcement_active === "active" && evidenceCurrent(a)) pill = '<span class="pill tone-verified">Enforcing</span>';
    else if (a.policy_protected) pill = '<span class="pill tone-degraded">Protection requested</span>';
    else { pill = '<span class="pill">Not protected</span>'; unprotected = true; }
    const drill = "/posture/agent/" + encodeURIComponent(a.agent_id);
    const statusText = unprotected ? "" : ' &middot; status ' + escHtml(a.status);
    return '<div class="row">' +
      '<div class="grow"><strong>' + escHtml(a.agent_id) + '</strong> ' + pill +
      '<div class="muted mono">' + escHtml(a.harness) + statusText + '</div></div>' +
      '<a class="btn" href="' + drill + '">View posture</a>' +
      '</div>';
  }).join("");
}
function renderPostureScreen() {
  const home = state.posture.home;
  const head =
    '<div class="page-head"><div>' +
      '<p class="eyebrow">Overview</p>' +
      '<h1>Overview</h1>' +
      '<p class="sub">What needs attention now. Unknown means a source has not answered or has not proven the value.</p>' +
    '</div></div>';
  if (!sourceLoaded("/api/posture/home") || !home) {
    const why = state.posture.homeError
      ? 'Protection status unavailable. Overview unavailable. This dashboard could not read the latest posture check. ' + escHtml(state.posture.homeError)
      : 'Protection status unavailable. Overview unavailable. Current posture is Unknown.';
    return '<section class="overview-page">' + head + '<div class="overview-tiles" aria-label="At a glance">' + renderOverviewProtection(home) + '</div>' +
      '<section class="card"><p class="muted">' + why + '</p></section>' + renderSourceRead("/api/posture/home") +
      '</section>';
  }
  const machineLine = home.origin_machine
    ? '<p class="muted overview-machine">Machine <span class="mono">' + escHtml(home.origin_machine) + '</span></p>'
    : '';
  if (sourceLoaded(HUB + "/agents") && state.agents.length === 0 && (home.agents || []).length === 0) {
    const below = [];
    // An empty agent roster cannot establish that a full or unrecognized inbox page has no holds.
    if (sourceLoaded(HUB + "/inbox") && ((!state.inboxRedacted && !approvalQueueEvidence().earned) || (state.inboxRedacted && Number(state.inboxRedactedCount) > 0))) below.push(renderOverviewDecisionQueue());
    if (sourceLoaded("/api/anomaly/findings") && state.posture.anomaliesUnknown === false && (state.posture.anomalies || []).length) below.push(renderOverviewFindingsPanel());
    return '<section class="overview-page">' + head + machineLine + overviewFirstRun(home) + '<div class="overview-tiles" aria-label="At a glance">' + renderOverviewProtection(home) + '</div>' + below.join("") + '</section>';
  }
  const wall = postureWallLabel(home.castle_wall && home.castle_wall.arm_state);
  const vaultProvision = home.castle_wall && home.castle_wall.castle_wall_provision;
  const vaultNotice = vaultProvision === "not_yet_walled"
    ? '<p class="muted">This vault is not on ${LOCAL_CASTLE_WALL_SUBJECT_PLACEHOLDER}\'s Castle Wall yet, so the wall state above is the machine\'s, not this vault\'s.</p>'
    : "";
  const findings = home.anomaly_findings || [];
  const anomalyUnknown = !sourceLoaded("/api/anomaly/findings") || home.anomaly_findings_unknown === true;
  const wallEvidenceAt = home.castle_wall && home.castle_wall.last_enforcement_evidence_at;
  const digest = home.digest || {};
  const wallAge = wallEvidenceAt ? relTimeFromIso(wallEvidenceAt) : "";
  const wallChip = wall.text === "Enforcing"
    ? overviewChip("good", "ENFORCING", wallAge)
    : wall.text === "Coarse-only" || wall.text === "Degraded"
      ? overviewChip("warn", wall.text.toUpperCase(), wallAge || "evidence not current")
      : wall.text === "Locked down"
        ? overviewChip("locked", "LOCKED DOWN", wallAge)
        : wall.text === "Not installed"
          ? overviewChip("warn", "NOT INSTALLED", wallAge || "not installed")
          : overviewChip("unknown", "UNKNOWN", wallAge || "no evidence");
  const pendingKnown = sourceLoaded(HUB + "/inbox") && !state.inboxRedacted;
  const pending = pendingKnown ? heldApprovalItems(null) : [];
  const pendingEvidence = approvalQueueEvidence();
  // Only earned evidence permits an unqualified zero; full pages and unknown tiers retain their bounds below.
  const pendingValue = pendingEvidence.earned ? "0" : pending.length + (pendingEvidence.full ? "+" : "");
  const pendingNote = (pendingEvidence.full ? "from the first " + APPROVAL_QUEUE_ITEM_CAP + " inbox items · " : "") +
    (pendingEvidence.unknown ? pendingEvidence.unknownLine + " · " : "");
  const chainWindowEnd = parseEvidenceTimestamp(digest.window_end || "");
  // VERIFIED requires current evidence from this digest build; stale and future checks never remain green.
  const checkCurrent = auditChainCheckCurrent(digest);
  const chainVerified = digest.chain_verified === true && digest.chain_verdict === "verified" && checkCurrent;
  // The verdict covers the whole chain, so only a positive safe window count can supply a findings detail.
  const findingDetail = Number.isSafeInteger(digest.integrity_finding_count) && digest.integrity_finding_count > 0
    ? digest.integrity_finding_count + (digest.integrity_finding_count === 1 ? " finding" : " findings") : "chain not verified";
  const chainChip = chainVerified
    ? overviewChip("good", "VERIFIED", relTimeFromIso(digest.window_end))
    : (digest.chain_verified === true || digest.chain_verdict === "verified_suffix_only") && !checkCurrent
      ? overviewChip("unknown", "UNKNOWN", "last verified " + (Number.isFinite(chainWindowEnd) ? relTimeFromIso(digest.window_end) : "Unknown"))
    : digest.chain_verdict === "findings"
      ? overviewChip("bad", "FAILED", findingDetail)
      : digest.chain_verdict === "verified_suffix_only" && checkCurrent
      ? overviewChip("warn", "SUFFIX ONLY", digest.window_end ? relTimeFromIso(digest.window_end) : "")
      : overviewChip("unknown", "NOT YET VERIFIED", digest.window_end ? relTimeFromIso(digest.window_end) : "no check age");
  const metricCards =
    '<div class="overview-tiles" aria-label="At a glance">' +
      renderOverviewProtection(home) +
      overviewTile("Castle Wall", wallChip, escHtml((home.castle_wall && home.castle_wall.platform) || "platform not served") + " · " + (wallEvidenceAt ? "evidence " + escHtml(wallAge) : "no enforcement evidence yet"), "#enforcement") +
      overviewTile("Approvals waiting", pendingKnown ? escHtml(pendingValue) : overviewChip("unknown", state.inboxRedacted ? "UNKNOWN" : "Not evaluated"), pendingKnown ? escHtml(pendingNote) + escHtml(oldestAge(pending)) + " · queue read " + escHtml(loadedSourceReadAge(HUB + "/inbox") || "Unknown") + ' · <a href="#approvals">decide</a>' : (state.inboxRedacted ? escHtml("approval queue hidden; pending count " + state.inboxRedactedCount) : escHtml(overviewSourceReason(HUB + "/inbox", "approval queue"))), "#approvals") +
      // Must match renderAnomalyFindingsCard on the Findings screen: both count /api/anomaly/findings.
      overviewTile("Open Sentinel findings", anomalyUnknown ? overviewChip("unknown", "Not evaluated") : escHtml(findings.length), anomalyUnknown ? escHtml(overviewSourceReason("/api/anomaly/findings", "Sentinels")) : "Sentinels answered " + escHtml(loadedSourceReadAge("/api/anomaly/findings") || "now") + ' · <a href="#findings">findings</a>', "#findings") +
      overviewTile("Audit chain", chainChip, Number.isFinite(chainWindowEnd) ? (chainVerified ? "checked " : "digest from ") + escHtml(relTimeFromIso(digest.window_end)) + (chainVerified ? "" : (digest.chain_verified === true || digest.chain_verdict === "verified_suffix_only") && !checkCurrent ? ", not current" : ", not verified") : "last check Not evaluated", "#activity") +
    '</div>';
  return [
    '<section class="overview-page">',
      head,
      machineLine,
      metricCards,
      vaultNotice,
      renderOverviewDecisionQueue(),
      renderOverviewFindingsPanel(),
      renderOutboundConnections(digest, true),
      renderOverviewAgentsTable(),
      '<p class="muted">Overview values come directly from served posture, approval, Sentinel and roster reads. Unknown remains explicit when a source has not answered.</p>',
    '</section>'
  ].join("");
}

// ── Slice 2 shell: folded destinations (2026-10-13) ─────────────────────
// The rail's new screens are compositions of renderers this client already
// had; none reads a new endpoint, and every number keeps its denominator and
// the age of the read behind it. The older routes they host keep rendering
// on their own hashes.

// A folded section: an older screen hosted inside a rail destination, with a
// link to the same content on its own route (the frozen hash id). The fold's
// head carries the hosted page's eyebrow and title, and the stylesheet hides
// the hosted page's own eyebrow and h1 inside a fold, so no heading repeats.
// titleSuffixHtml is trusted markup from the caller (a status pill the hosted
// h1 carried), never data.
function renderFoldedSection(eyebrow, title, routeId, html, titleSuffixHtml) {
  return '<section class="folded-section" data-folded-route="' + escHtml(routeId) + '">' +
    '<div class="folded-head"><div><p class="eyebrow">' + escHtml(eyebrow) + '</p>' +
    '<h2>' + escHtml(title) + (titleSuffixHtml ? ' ' + titleSuffixHtml : '') + '</h2></div>' +
    '<a href="#' + escHtml(routeId) + '">Open on its own page</a></div>' +
    html + '</section>';
}

// Settings tab strip. Each tab is a hash link to the older route id, so the
// active tab is simply the current route.
function settingsTabStrip(activeId) {
  return '<div class="screen-tabs"><p class="eyebrow">Settings</p><nav aria-label="Settings">' +
    SETTINGS_TABS.map(function (t) {
      const active = t.id === activeId;
      return '<a href="#' + t.id + '"' + (active ? ' class="active" aria-current="page"' : '') + '>' + escHtml(t.label) + '</a>';
    }).join("") + '</nav></div>';
}

// The age of a source's last read, as "Ns ago", or null before any read.
// Read start is the bound: the data on screen is at least this old.
function sourceReadAge(path) {
  const read = sourceRead(path);
  if (!read || !read.lastReadAt) return null;
  return durationLabelFromMs(Date.now() - read.lastReadAt) + " ago";
}

// The waiting count, its denominator, and the age of the queue read behind
// it, as one sentence for titles and accessible names. Unknown until the
// queue read is LOADED (never a zero the client has not observed). The
// numerator honors the agent scope; the denominator is every held operation
// on this fortress. A redacted queue reports the server's pending count,
// which no agent scope can narrow.
function approvalWaitingSummary() {
  if (!sourceLoaded(HUB + "/inbox")) {
    return { known: false, n: null, of: null, sentence: "Held operations waiting on you: Unknown until the approval queue loads." };
  }
  const age = sourceReadAge(HUB + "/inbox") || "at an unknown time";
  if (state.inboxRedacted) {
    const hidden = state.inboxRedactedCount;
    // A served redacted count cannot establish emptiness because hidden rows and tiers cannot be checked.
    return { known: true, n: hidden, of: hidden, earned: false, unrecognized: 0, sentence: hidden + " of " + heldOperationsPhrase(hidden, "waits", "wait") + " on you, hidden until you paste the operator token · queue read " + age + "." };
  }
  const evidence = approvalQueueEvidence();
  const n = evidence.waiting;
  const of = evidence.total;
  const scope = state.agentScope.selectedAgentId;
  // A full page establishes observed counts only, so the sentence binds them to the served inbox page.
  const countLine = n + " of " + (evidence.full
    ? heldOperationsPhrase(of) + " in the first " + APPROVAL_QUEUE_ITEM_CAP + " inbox items " + (of === 1 ? "waits" : "wait")
    : heldOperationsPhrase(of, "waits", "wait")) + " on you";
  // Unknown tiers cannot disappear into a recognized zero, even when the current agent scope hides them.
  // The wording comes from approvalQueueEvidence so the queue warning, tile, seal row and this sentence say it the same way.
  const unknownClause = evidence.unknown ? "; " + evidence.unknownLine : "";
  return { known: true, n: n, of: of, full: evidence.full, earned: evidence.earned, unrecognized: evidence.unknown, sentence: countLine + (scope ? " (scoped to " + scope + ")" : "") + unknownClause + " · queue read " + age + "." + (evidence.full ? evidence.pageEdge : "") };
}

function renderApprovalCounts() {
  const w = approvalWaitingSummary();
  const suffix = w.full ? "+" : "";
  const text = w.known ? w.n + suffix + " of " + w.of + suffix : "Unknown";
  // The pill's digits count recognized holds only, so a hold they count, inside or outside the agent scope, looks hot.
  const counted = w.known && w.of > 0;
  // An unearned zero cannot look calm because unseen or unrecognized holds may still need a decision.
  const unknown = !w.known || (!w.earned && !counted);
  const railCount = document.getElementById("rail-approvals-count");
  if (railCount) {
    railCount.className = "count" + (unknown ? " unknown" : counted ? " hot" : "");
    railCount.textContent = text;
    const link = railCount.parentElement;
    if (link && typeof link.setAttribute === "function") {
      link.setAttribute("title", w.sentence);
      link.setAttribute("aria-label", "Approvals: " + w.sentence);
    }
  }
  const notify = document.getElementById("btn-notifications");
  if (notify) {
    notify.setAttribute("title", w.sentence);
    notify.setAttribute("aria-label", "Approvals: " + w.sentence);
    // The badge goes only when nothing waits fortress-wide: a zero scoped to
    // one agent while other agents' holds wait is not an all-clear, so the
    // badge stays and reads "0 of N". Full pages and unknown tiers also cannot
    // earn an empty claim; the title states the count bounds and age.
    if (w.known && w.earned) notify.classList.remove("waiting");
    else notify.classList.add("waiting");
  }
  const badge = document.getElementById("notify-count");
  if (badge) {
    // Hiding the badge is an empty-queue claim and requires the same evidence as the calm summary.
    badge.hidden = w.known && w.earned;
    // The badge signals any observed hold, including a tier this console cannot decide, so only a zero with
    // nothing observed takes the unknown look.
    badge.className = "wait" + (unknown && !(w.known && w.unrecognized > 0) ? " unknown" : "");
    badge.innerHTML = '<i aria-hidden="true"></i>' + escHtml(text);
  }
}

// Route-dependent top-bar state: the waiting count, the time range (live
// only where a screen has a client-side window), the Talk button and panel,
// and the search results. Called on every route change and rerender.
function renderShellChrome() {
  renderApprovalCounts();
  const range = document.getElementById("time-range");
  if (range) {
    const applies = TIME_RANGE_ROUTES.indexOf(state.route) >= 0;
    range.disabled = !applies;
    range.value = state.timeRange;
    range.setAttribute("title", applies
      ? "Time range for the Evidence list: " + TIME_RANGE_LABEL[state.timeRange] + "."
      : "This screen shows current state and has no time window. The time range applies to the Evidence list.");
  }
  const talkBtn = document.getElementById("btn-talk");
  if (talkBtn) {
    const talkShown = state.route === "dashboard" || !!state.talk.open;
    if (talkShown) talkBtn.classList.add("active"); else talkBtn.classList.remove("active");
    talkBtn.setAttribute("aria-expanded", state.talk.open && state.route !== "dashboard" ? "true" : "false");
  }
  renderTalkPanel();
  renderSearchResults();
}

// Talk as a panel: the full-page concierge renderer, mounted in the right-hand
// panel. On Talk's own full-page route the panel stays shut, so the
// concierge's element ids exist once in the document.
let talkPanelLegacyCache = null;
function renderTalkPanel() {
  const panel = document.getElementById("talk-panel");
  const body = document.getElementById("talk-panel-body");
  if (!panel || !body) return;
  const open = !!state.talk.open && state.route !== "dashboard";
  if (!open) {
    // Capture before hide: a hidden panel's history has no layout box, so any
    // viewport read after panel.hidden = true is zero geometry. The reader's
    // position is saved first, and only then is the panel shut.
    if (!talkDomOwnerSupported) {
      if (talkPanelLegacyCache !== null) {
        saveTalkViewport(body.querySelector("#concierge-history"));
        body.innerHTML = "";
        talkPanelLegacyCache = null;
      }
    } else if (talkOwner && talkOwner.host === body) disposeTalkOwner();
    else if (body.firstChild) body.innerHTML = "";
    panel.hidden = true;
    return;
  }
  // Shown before any mount or restore: a scrollTop written into a hidden
  // panel's history is discarded, so the panel must have layout first.
  panel.hidden = false;
  if (!talkDomOwnerSupported) {
    const html = renderDashboardConcierge();
    if (html !== talkPanelLegacyCache) {
      const viewport = saveTalkViewport(body.querySelector("#concierge-history"));
      const focus = captureInputFocus(body);
      body.innerHTML = html;
      talkPanelLegacyCache = html;
      restoreInputFocus(body, focus);
      restoreLegacyTalkHistory(body.querySelector("#concierge-history"), viewport);
    }
    return;
  }
  if (talkOwner && talkOwner.host === body) {
    hydrateTalkHost(body);
    return;
  }
  if (talkOwner) disposeTalkOwner();
  body.innerHTML = renderDashboardConcierge();
  attachTalkOwner(body);
}

// Top-bar search over what this page already holds: agents, waiting
// approvals and recent evidence rows. No endpoint; a group whose read has not
// loaded says so instead of reporting no match.
const SEARCH_HITS_PER_GROUP = 6;
function searchGroups(needle) {
  const match = function (text) { return String(text || "").toLowerCase().indexOf(needle) >= 0; };
  return [
    {
      label: "Agents",
      loaded: sourceLoaded(HUB + "/agents"),
      total: state.agents.length,
      hits: state.agents.filter(function (a) { return match(a.agent_id) || match(a.harness); }).map(function (a) {
        return '<a href="#agent-detail" data-action="open-agent" data-agent-id="' + escHtml(a.agent_id) + '">' + escHtml(a.agent_id) +
          '<span class="sr-meta">' + escHtml(agentDisplayStatus(a).label || "") + '</span></a>';
      })
    },
    {
      label: "Waiting approvals",
      loaded: sourceLoaded(HUB + "/inbox") && !state.inboxRedacted,
      // Loaded but redacted: the server withheld the items, so a match can be
      // neither shown nor ruled out until the operator token is pasted.
      hidden: sourceLoaded(HUB + "/inbox") && !!state.inboxRedacted,
      total: heldApprovalItems(null).length,
      hits: heldApprovalItems(null).filter(function (i) {
        return match(renderTemplate(i.display_template_id, i.display_template_args)) || match(i.agent_id);
      }).map(function (i) {
        return '<a href="#approvals">' + escHtml(renderTemplate(i.display_template_id, i.display_template_args)) +
          '<span class="sr-meta">' + escHtml(i.tier || "") + '</span></a>';
      })
    },
    {
      label: "Recent evidence",
      loaded: sourceLoaded(HUB + "/activity"),
      total: state.activity.length,
      hits: state.activity.filter(function (e) {
        return match(renderTemplate(e.display_template_id, e.display_template_args)) || match(e.agent_id) || match(e.category);
      }).map(function (e) {
        return '<a href="#activity">' + escHtml(renderTemplate(e.display_template_id, e.display_template_args)) +
          '<span class="sr-meta">' + escHtml(shortTime(e.emitted_at)) + '</span></a>';
      })
    }
  ];
}
function renderSearchResults() {
  const panel = document.getElementById("search-results");
  const input = document.getElementById("global-search");
  if (!panel) return;
  const needle = String(state.search.query || "").trim().toLowerCase();
  const open = !!state.search.open && needle.length > 0;
  panel.hidden = !open;
  if (input && typeof input.setAttribute === "function") input.setAttribute("aria-expanded", open ? "true" : "false");
  if (!open) return;
  const groups = searchGroups(needle);
  const scope = groups.map(function (g) {
    return g.loaded ? g.total + " " + g.label.toLowerCase() : g.label.toLowerCase() + (g.hidden ? " hidden" : " not loaded");
  }).join(", ");
  let any = false;
  // A "no match" line is a negative result, so it is earned only when at
  // least one group actually loaded and none matched; with nothing loaded
  // the honest answer is that nothing searchable has loaded yet.
  const anyLoaded = groups.some(function (g) { return g.loaded; });
  const body = groups.map(function (g) {
    if (g.hidden) return '<div class="sr-group">' + escHtml(g.label) + '</div><div class="sr-empty">Unknown: hidden until you paste the operator token, so a match cannot be ruled out.</div>';
    if (!g.loaded) return '<div class="sr-group">' + escHtml(g.label) + '</div><div class="sr-empty">Unknown: not loaded yet, so a match cannot be ruled out.</div>';
    if (!g.hits.length) return "";
    any = true;
    const shown = g.hits.slice(0, SEARCH_HITS_PER_GROUP);
    return '<div class="sr-group">' + escHtml(g.label) + ' (' + shown.length + ' of ' + g.hits.length + ' matches)</div>' + shown.join("");
  }).join("");
  panel.innerHTML = '<div class="sr-scope">Searching what this page has loaded: ' + escHtml(scope) + '.</div>' +
    body + (any ? "" : anyLoaded
      ? '<div class="sr-empty" data-search-no-match="1">No match in what this page has loaded.</div>'
      : '<div class="sr-empty" data-search-nothing-loaded="1">Nothing searchable has loaded yet, so no result is known.</div>');
}

// One page bounds the Approvals queue and its evidence claims.
const APPROVAL_QUEUE_ITEM_CAP = 100; // 100 matches HUB_INBOX_DEFAULT_LIMIT in hub/constants.ts, the one page this client reads.
// Must match CHARTER_APPROVAL_ITEM_ID_PREFIX in server/src/hub/charter-approval-bridge.ts.
const CHARTER_APPROVAL_ITEM_ID_PREFIX = "charter.approval.";

// All three approval surfaces share the same evidence bounds so none can earn a false calm zero.
function approvalQueueEvidence() {
  const ready = sourceLoaded(HUB + "/inbox") && !state.inboxRedacted;
  const full = state.inbox.length >= APPROVAL_QUEUE_ITEM_CAP;
  // A decided item is no longer held, so only waiting items with an unrecognized tier are counted.
  const unknown = state.inbox.filter(function (i) {
    return i.kind === "approval_pending" && !i.resolved && i.tier !== "tier1" && i.tier !== "tier2";
  }).length;
  const unknownLine = unknown === 1 ? "1 held item carries a tier this console does not recognize" : unknown + " held items carry a tier this console does not recognize";
  const warning = ready && unknown
    ? '<p class="muted">' + unknownLine + (unknown === 1
      ? '. It is not shown here and cannot be decided from this screen.'
      : '. They are not shown here and cannot be decided from this screen.') + '</p>' : "";
  const waiting = pendingApprovalItems().length;
  const outside = heldApprovalItems(null).length - waiting;
  let title = "Nothing selected";
  let line = "";
  // A partial or redacted read cannot establish an empty queue.
  const earned = ready && !full && !unknown && !waiting && !outside;
  const pageEdge = " The inbox has at least " + APPROVAL_QUEUE_ITEM_CAP + " items and this read shows only the first " + APPROVAL_QUEUE_ITEM_CAP + ", so a held operation may be waiting past them.";
  if (!ready) line = state.inboxRedacted ? "Approvals are hidden, not empty. Pending count: " + state.inboxRedactedCount + "." : "Approval data is Unknown until the queue read loads.";
  // Observed recognized holds cannot exclude unknown tiers or holds beyond this page in the selected scope.
  else if (outside && !waiting) line = "No recognized held operation for " + (state.agentScope.selectedAgentId || "this agent") + " is waiting in this read. " + (full ? "At least " : "") + heldOperationsPhrase(outside, "waits", "wait") + " outside this agent scope; choose All agents in the scope menu to see them." + (full ? pageEdge : "");
  else if (full && !waiting) {
    // The inbox serves no total, so a full page cannot rule out a held operation beyond its edge.
    line = state.inbox.some(function (i) { return i.kind === "approval_pending"; }) ? "No recognized held operation is waiting in this page." : "None of the first " + APPROVAL_QUEUE_ITEM_CAP + " inbox items is a held operation.";
    line += pageEdge;
  } else if (unknown && !waiting) {
    // Unrecognized holds are not shown, so the empty state says what is known instead of rendering blank.
    line = "No recognized held operation is waiting.";
  } else if (earned) {
    title = "No approvals waiting";
    line = "0 of 0 held operations are waiting on you.";
  }
  const emptyHtml = '<div class="queue-empty"' + (outside && !waiting ? ' data-scoped-empty="1"' : '') + '>' +
    (earned ? '<span class="qe-check"></span>Nothing waiting on you.' : escHtml(line)) + '</div>';
  let summary = emptyHtml;
  if (ready && waiting) {
    // Full-page counts describe only a lower bound, never the fortress total.
    const count = full ? "At least " + heldOperationsPhrase(waiting) + " waiting (from the first " + APPROVAL_QUEUE_ITEM_CAP + " inbox items)." : heldOperationsPhrase(waiting) + " waiting.";
    summary = '<div class="queue-empty"><span class="qe-warn"></span>' + escHtml(count) + ' <a href="#approvals">Open Approvals</a>.</div>';
  }
  if (!sourceLoaded(HUB + "/inbox")) summary = renderSourceRead(HUB + "/inbox");
  else if (state.inboxRedacted) summary = '<div class="queue-empty" data-pending-approvals-redacted="1">' + escHtml(line) + '</div>';
  // Only recognized holds belong in scoped counts; unknown tiers retain their separate warning and cannot earn calm.
  const total = waiting + outside;
  const suffix = full ? "+" : "";
  // A full page bounds both counts even when every observed hold belongs to the selected scope.
  const count = waiting + suffix + (outside || full ? " of " + total + suffix : "");
  return { title: title, line: line, emptyHtml: emptyHtml, summary: summary + warning, warning: warning, count: count, earned: earned, waiting: waiting, outside: outside, total: total, full: full, pageEdge: pageEdge, unknown: unknown, unknownLine: unknownLine };
}

// "1 held operation" or "N held operations", with the verb that agrees when one is given.
function heldOperationsPhrase(n, singularVerb, pluralVerb) {
  const phrase = n === 1 ? "1 held operation" : n + " held operations";
  return singularVerb ? phrase + " " + (n === 1 ? singularVerb : pluralVerb) : phrase;
}

function resetApprovalConsent() {
  // Consent belongs to the selected request and never transfers to a replacement or a changed view.
  state.approvals.alwaysAllow = false;
  state.approvals.confirmingTier1Id = null;
  state.approvals.cancelledTier1Id = null;
}

function approvalItemsForScreen() {
  const scope = state.agentScope.selectedAgentId;
  return state.inbox.filter(function (i) {
    if (i.kind !== "approval_pending") return false;
    if (i.tier !== "tier1" && i.tier !== "tier2") return false;
    if (scope && (i.agent_id || "") !== scope) return false;
    return true;
  });
}

function approvalArg(item, names, fallback) {
  const args = item && item.display_template_args;
  if (!Array.isArray(args)) return fallback || "";
  for (let i = 0; i < args.length; i++) {
    if (names.indexOf(args[i].kind) >= 0) return String(args[i].value);
  }
  return fallback || "";
}

function approvalAgentId(item) {
  return item.agent_id || approvalArg(item, ["agent_id"], "this fortress");
}

function approvalOperation(item) {
  return item.operation_category || String(item.display_template_id || "").split(".").pop() || "approval";
}

function approvalText(item) {
  return renderTemplate(item.display_template_id, item.display_template_args);
}

function approvalHoldReason(item) {
  const tier = item.tier === "tier1" ? "Tier 1" : "Tier 2";
  // Hub controls and the catch-all category carry no policy-gate reason in the served item.
  if (item.operation_category === "other" || !isCharterApprovalItem(item)) return "Held for your decision (" + approvalOperation(item) + ", " + tier + ").";
  return approvalOperation(item) + " is a " + tier + " operation under the operator policy.";
}

function isCharterApprovalItem(item) {
  return !!(item && typeof item.item_id === "string" && item.item_id.indexOf(CHARTER_APPROVAL_ITEM_ID_PREFIX) === 0);
}

function approvalRecordLine(item) {
  return isCharterApprovalItem(item) ? "recorded in your audit log" : "marked decided in this inbox";
}

function approvalOutcomeLine(item) {
  return isCharterApprovalItem(item) ? "outcome in your audit log" : "outcome not reported by the inbox";
}

function approvalPolicyUnavailableReason() {
  if (state.policyView.loadError) return state.policyView.loadError;
  const read = sourceRead(POLICY + "/current");
  if (read && read.state === "state_FAILED") return read.error || "Policy engine is not configured on this fortress.";
  if (read && read.state === "state_NOT_SERVED") return read.error || DASHBOARD_MODE_NOT_SERVED_MESSAGE;
  if (state.policyView.loading || (read && read.state === "state_LOADING")) return "Checking the policy-change path.";
  if (!sourceLoaded(POLICY + "/current")) return "Checking the policy-change path.";
  return "";
}

function approvalStandingState(item) {
  const op = promotableOperation(item);
  if (!op) return { enabled: false, reason: "Always allow is unavailable for this operation." };
  if (item.tier === "tier1") return { enabled: false, reason: "Tier 1 approvals cannot become standing rules from this drawer." };
  const unavailable = approvalPolicyUnavailableReason();
  if (unavailable) return { enabled: false, reason: unavailable };
  // The standing rule is activated into the fortress policy through the policy engine; this console has no
  // control that removes one, so the note states that bound instead of promising a revocation path.
  return { enabled: true, reason: "Adds a standing rule to this fortress's policy. The console has no control to remove a standing rule yet. Allow always first allows this request, then asks the policy engine to compile a standing rule for " + op + " and activate it with your operator token. Either step can be refused; your policy changes only if both succeed." };
}

function batchSelectionLocked() { return decisionInFlight() && state.approvals.lock.kind === "batch"; }
function batchSelectionDisabled() {
  // The selection checkboxes pause only while a batch holds the lock; an item decision leaves them live.
  return batchSelectionLocked() ? ' disabled title="' + DECISION_BUSY_REASON + '"' : "";
}
function approvalDecisionDisabled() {
  // Invariant: every decision control on every screen reads the one decision lock, so while a decision is in
  // flight no second request can be clicked anywhere, and each paused control says why.
  if (!decisionInFlight()) return "";
  return ' disabled title="' + (state.approvals.lock.status === "pending" ? DECISION_BUSY_REASON : DECISION_REREAD_BUSY_REASON) + '"';
}

function renderApprovalRow(item, selectedId) {
  const selected = item.item_id === selectedId;
  const agent = approvalAgentId(item);
  const op = approvalOperation(item);
  const created = item.created_at || "";
  const age = created ? relTimeFromIso(created) : "age unknown";
  const tier = item.tier === "tier1" ? "Tier 1" : "Tier 2";
  if (item.resolved) {
    // The inbox serves no operator decision outcome, so the screen never
    // infers allow or deny from agent-control result fields.
    const outcomeLine = approvalOutcomeLine(item);
    return '<tr class="' + (selected ? "sel" : "") + '" data-approval-row="' + escHtml(item.item_id) + '">' +
      '<td><button class="link-btn" data-action="approval-select" data-item-id="' + escHtml(item.item_id) + '">' + escHtml(tier) + '</button></td>' +
      '<td><strong>' + escHtml(agent) + '</strong></td>' +
      '<td class="mono">' + escHtml(op) + '</td>' +
      '<td>' + escHtml(approvalHoldReason(item)) + '</td>' +
      '<td class="mono muted">Decided at ' + escHtml(shortTime(item.resolved_at || created)) + '</td>' +
      '<td><span class="state-chip neutral"><i aria-hidden="true"></i>DECIDED</span><div class="muted">' + escHtml(outcomeLine) + ' · <a href="#activity">Evidence</a></div></td>' +
    '</tr>';
  }
  const disabled = approvalDecisionDisabled();
  const decisionCell = item.tier === "tier1"
    ? '<button class="btn btn-sm" data-action="approval-select" data-item-id="' + escHtml(item.item_id) + '">Review in drawer</button><div class="muted">' + escHtml(approvalRecordLine(item)) + '</div>'
    : '<button class="btn btn-sm btn-primary" data-action="inbox-approve" data-item-id="' + escHtml(item.item_id) + '"' + disabled + '>Allow once</button> <button class="btn btn-sm" data-action="inbox-deny" data-item-id="' + escHtml(item.item_id) + '"' + disabled + '>Deny</button><div class="muted">' + escHtml(approvalRecordLine(item)) + '</div>';
  // The queue row echoes its own decision as the drawer does, since the drawer may be showing another request.
  const echo = item.tier === "tier1" ? "" : renderDecisionInline(item);
  return '<tr class="' + (selected ? "sel" : "") + '" data-approval-row="' + escHtml(item.item_id) + '">' +
    '<td><button class="link-btn" data-action="approval-select" data-item-id="' + escHtml(item.item_id) + '">' + escHtml(tier) + '</button></td>' +
    '<td><strong>' + escHtml(agent) + '</strong></td>' +
    '<td class="mono">' + escHtml(op) + '</td>' +
    '<td>' + escHtml(approvalHoldReason(item)) + '</td>' +
    '<td class="mono">' + escHtml(age) + '</td>' +
    '<td>' + decisionCell + echo + '</td>' +
  '</tr>';
}

function renderApprovalDrawer(item, empty) {
  if (!item) {
    const e = empty || {};
    const evidence = approvalQueueEvidence();
    // Filters can hide loaded holds but cannot establish that no holds exist.
    const title = e.filteredOut ? "Nothing selected" : evidence.title;
    const line = e.filteredOut
      ? "No held operation matches these filters. " + heldOperationsPhrase(e.waiting, "in this scope is", "in this scope are") + " waiting on you."
      : evidence.line;
    return '<aside class="card approval-drawer"><div class="approval-empty"><div class="empty-glyph neutral" aria-hidden="true"></div><h3>' + escHtml(title) + '</h3><p>' + escHtml(line) + ' Queue checked ' + escHtml(sourceReadAge(HUB + "/inbox") || "at an unknown time") + '.</p>' + evidence.warning + '<a class="btn" href="#activity">Open Evidence</a></div></aside>';
  }
  const agent = approvalAgentId(item);
  const op = approvalOperation(item);
  const tier = item.tier === "tier1" ? "Tier 1" : "Tier 2";
  const standing = approvalStandingState(item);
  const checked = state.approvals.alwaysAllow && standing.enabled && !item.resolved;
  const disabled = approvalDecisionDisabled();
  const primaryAction = checked ? "inbox-promote" : "inbox-approve";
  const primaryLabel = checked ? "Allow always" : "Allow once";
  const checkbox = item.resolved ? "" : '<label class="approval-standing"><input type="checkbox" data-action="approval-always-allow"' +
    (checked ? " checked" : "") + (standing.enabled && !disabled ? "" : " disabled") + '><span>' +
    (standing.enabled ? "Always allow this operation for every agent on this fortress. " : "Always allow is unavailable. ") +
    '<strong class="warn">' + escHtml(standing.reason) + '</strong></span></label>';
  const tier1Confirming = state.approvals.confirmingTier1Id === item.item_id;
  const tier1Cancelled = state.approvals.cancelledTier1Id === item.item_id;
  const startButton = '<button class="btn btn-primary approval-tier1-step" data-action="approval-start-tier1-allow" data-item-id="' + escHtml(item.item_id) + '"' + disabled + '>Allow once</button>';
  const cancelButton = '<button class="btn approval-tier1-step" data-action="approval-cancel-tier1-allow" data-item-id="' + escHtml(item.item_id) + '"' + disabled + '>Cancel</button>';
  const primaryButton = item.resolved ? "" : item.tier === "tier1"
    ? (tier1Confirming || tier1Cancelled ? cancelButton : startButton)
    : '<button class="btn btn-primary" data-approval-primary="' + escHtml(item.item_id) + '" data-action="' + primaryAction + '" data-item-id="' + escHtml(item.item_id) + '"' + disabled + '>' + primaryLabel + '</button>';
  const denyButton = item.resolved ? "" : '<button class="btn" data-action="inbox-deny" data-item-id="' + escHtml(item.item_id) + '"' + disabled + '>Deny</button>';
  // Confirm occupies a separate row so the second click in the first-step slot can only cancel.
  const confirmRow = !item.resolved && tier1Confirming
    ? '<div class="approval-confirm-row"><button class="btn btn-primary" data-action="approval-confirm-tier1-allow" data-item-id="' + escHtml(item.item_id) + '"' + disabled + '>Confirm ' + escHtml(op) + '</button></div>' : "";
  // Keep Cancel in its original slot and focused after disarming; a new Allow step uses a separate slot.
  const restartButton = !item.resolved && tier1Cancelled ? startButton : "";
  const standingEffect = checked
    ? "Later matching operations stop asking only if the policy engine accepts both steps."
    : "The next matching operation asks again.";
  // A Tier 1 Allow once only arms the request; the card says so, matching the note below it.
  const allowCopy = checked
    ? "Allows this request once, then requests a standing rule for every agent on this fortress. " + standingEffect
    : item.tier === "tier1" && !item.resolved
      ? "Allow once arms this request, and Confirm " + op + " sends the approval; the decision is " + approvalRecordLine(item) + "."
      : "Allow once sends this approval and the decision is " + approvalRecordLine(item) + ".";
  const tier1Note = item.tier === "tier1" && !item.resolved
    ? '<div class="approval-tier-note">Tier 1 takes two steps here: Allow once, then Confirm ' + escHtml(op) + '. Only Confirm sends the approval.</div>'
    : "";
  return '<aside class="card approval-drawer" aria-label="Selected approval">' +
    '<div class="approval-drawer-head"><div><span class="pill">' + escHtml(tier) + '</span> <span class="state-chip ' + (item.resolved ? "neutral" : "warn") + '"><i aria-hidden="true"></i>' + (item.resolved ? "DECIDED" : "WAITING") + '</span></div><h3 tabindex="-1" data-approval-drawer-focus="1">Selected approval</h3><div class="mono">' + escHtml(op) + '</div><p class="muted">Requested by ' + escHtml(agent) + ' · request id ' + escHtml(item.item_id) + '</p></div>' +
    '<div class="approval-drawer-sec"><h4>What it wants to do</h4><p>' + escHtml(approvalText(item)) + '</p></div>' +
    // The inbox contract carries typed template args only, no free agent prose. The drawer must not invent a context channel.
    '<div class="approval-drawer-sec"><h4>Why it is held</h4><p>' + escHtml(approvalHoldReason(item)) + '</p></div>' +
    '<div class="approval-drawer-sec"><h4>If you decide</h4><div class="approval-effects"><div><strong>' + primaryLabel + '</strong><p>' + escHtml(allowCopy) + '</p></div><div><strong>Deny</strong><p>Deny sends this refusal and the decision is ' + escHtml(approvalRecordLine(item)) + '.</p></div></div></div>' +
    tier1Note +
    '<div class="approval-decide">' + checkbox + '<div class="toolbar">' + primaryButton + denyButton + restartButton + '</div>' + confirmRow + renderDecisionInline(item) + '<p class="muted mono">Decision ' + escHtml(approvalRecordLine(item)) + ' · <a href="#activity">Evidence</a></p></div>' +
  '</aside>';
}

function approvalFilterOptions(items, field, current) {
  const seen = Object.create(null);
  items.forEach(function (item) {
    const value = field === "agent" ? approvalAgentId(item) : approvalOperation(item);
    if (value) seen[value] = true;
  });
  // A stale filter remains visible and selected, so choosing All can actually clear it.
  const stale = current && !seen[current]
    ? '<option value="' + escHtml(current) + '" selected>' + escHtml(current) + ' (none loaded)</option>' : "";
  return stale + Object.keys(seen).sort().map(function (value) {
    return '<option value="' + escHtml(value) + '"' + (current === value ? " selected" : "") + '>' + escHtml(value) + '</option>';
  }).join("");
}

function filterApprovalItems(items) {
  const f = state.approvals.filters || {};
  return items.filter(function (item) {
    if (f.state === "waiting" && item.resolved) return false;
    if (f.state === "decided" && !item.resolved) return false;
    if (f.agent && approvalAgentId(item) !== f.agent) return false;
    if (f.tier === "tier1" && item.tier !== "tier1") return false;
    if (f.tier === "tier2" && item.tier !== "tier2") return false;
    if (f.category && approvalOperation(item) !== f.category) return false;
    return true;
  });
}

function renderApprovalsScreen() {
  if (!sourceLoaded(HUB + "/inbox")) {
    return '<section class="concierge-wrap"><div class="page-head"><div><p class="eyebrow">Approvals</p><h1>Held operations waiting on you.</h1><p class="sub">Approval data is Unknown until the queue read loads.</p></div></div>' + renderSourceRead(HUB + "/inbox") + '</section>';
  }
  if (state.inboxRedacted) {
    return '<section class="concierge-wrap"><div class="page-head"><div><p class="eyebrow">Approvals</p><h1>Held operations waiting on you.</h1><p class="sub">Approvals are hidden, not empty. Pending count: ' + escHtml(state.inboxRedactedCount) + '.</p></div></div>' + renderSourceRead(HUB + "/inbox") + '</section>';
  }
  const all = approvalItemsForScreen();
  const filtered = filterApprovalItems(all);
  // Waiting operations get the bounded decision slots before decided history can consume them.
  const capped = filtered.filter(function (i) { return !i.resolved; }).concat(filtered.filter(function (i) { return !!i.resolved; })).slice(0, APPROVAL_QUEUE_ITEM_CAP);
  const allWaitingCount = all.filter(function (i) { return !i.resolved; }).length;
  const waiting = capped.filter(function (i) { return !i.resolved; }).sort(function (a, b) {
    return (parseEvidenceTimestamp(a.created_at || "") || 0) - (parseEvidenceTimestamp(b.created_at || "") || 0);
  });
  const decided = capped.filter(function (i) { return !!i.resolved; });
  const selectedId = capped.some(function (i) { return i.item_id === state.approvals.selectedId; })
    ? state.approvals.selectedId
    : (waiting[0] || capped[0] || {}).item_id || null;
  if (state.approvals.selectedId !== selectedId) resetApprovalConsent();
  state.approvals.selectedId = selectedId;
  const selected = capped.find(function (i) { return i.item_id === selectedId; }) || null;
  const oldest = waiting.length && waiting[0].created_at ? relTimeFromIso(waiting[0].created_at) : "none waiting";
  const rows = [
    waiting.length ? '<tr class="sect"><td colspan="6">Waiting on you · ' + waiting.length + ' of ' + allWaitingCount + ' · oldest wait ' + escHtml(oldest) + '</td></tr>' : "",
    waiting.map(function (i) { return renderApprovalRow(i, selectedId); }).join(""),
    decided.length ? '<tr class="sect"><td colspan="6">Decided · showing ' + decided.length + ' of ' + filtered.filter(function (i) { return !!i.resolved; }).length + '</td></tr>' : "",
    decided.map(function (i) { return renderApprovalRow(i, selectedId); }).join("")
  ].join("");
  const evidence = approvalQueueEvidence();
  const noFilterMatch = all.length > 0 && filtered.length === 0;
  // One inbox read returns at most APPROVAL_QUEUE_ITEM_CAP items of every kind and serves no total,
  // so a full page means held operations past it may exist; the counts above cover the loaded page only.
  const pageFullNotice = state.inbox.length >= APPROVAL_QUEUE_ITEM_CAP
    ? '<p class="muted" data-inbox-page-full="1">The inbox read returned a full page of ' + APPROVAL_QUEUE_ITEM_CAP + ' items; held operations beyond it are not shown here.</p>'
    : "";
  // Decided history cannot hide holds waiting elsewhere when the selected scope has no waiting operations.
  const outsideNotice = evidence.outside && !evidence.waiting ? evidence.emptyHtml : "";
  const body = capped.length ? outsideNotice + '<div class="approval-table-wrap" id="approval-queue"><table class="approval-table"><thead><tr><th>Tier</th><th>Agent</th><th>Operation</th><th>Why it asked</th><th>Waiting / decided</th><th>Decision</th></tr></thead><tbody>' + rows + '</tbody></table></div>' :
    noFilterMatch ? '<div class="queue-empty">No held operation matches these filters.</div>' :
    evidence.emptyHtml;
  const f = state.approvals.filters;
  const filterBar = '<div class="approval-filters" role="group" aria-label="Filter approvals">' +
      '<label class="filter-field">State<select class="input" data-action="approval-filter-state"><option value="all"' + (f.state === "all" ? " selected" : "") + '>All</option><option value="waiting"' + (f.state === "waiting" ? " selected" : "") + '>Waiting</option><option value="decided"' + (f.state === "decided" ? " selected" : "") + '>Decided</option></select></label>' +
      '<label class="filter-field">Agent<select class="input" data-action="approval-filter-agent"><option value="">All</option>' + approvalFilterOptions(all, "agent", f.agent) + '</select></label>' +
      '<label class="filter-field">Tier<select class="input" data-action="approval-filter-tier"><option value="both"' + (f.tier === "both" ? " selected" : "") + '>Tier 1 and Tier 2</option><option value="tier1"' + (f.tier === "tier1" ? " selected" : "") + '>Tier 1</option><option value="tier2"' + (f.tier === "tier2" ? " selected" : "") + '>Tier 2</option></select></label>' +
      '<label class="filter-field">Category<select class="input" data-action="approval-filter-category"><option value="">All</option>' + approvalFilterOptions(all, "category", f.category) + '</select></label>' +
      '<span class="count-age">showing ' + capped.length + ' of ' + all.length + ' · cap ' + APPROVAL_QUEUE_ITEM_CAP + '</span>' +
    '</div>';
  return [
    '<section class="concierge-wrap approvals-wide">',
      '<div class="page-head"><div>',
        '<p class="eyebrow">Approvals</p>',
        '<h1>Held operations waiting on you.</h1>',
        '<p class="sub">A decision on a Charter hold is recorded in your audit log; a decision on any other held item is marked decided in this inbox.</p>',
      '</div></div>',
      filterBar,
      '<p class="muted">Left rail agent scope applies first; these controls then narrow that scoped queue.</p>',
      pageFullNotice,
      evidence.warning,
      '<div class="approval-layout"><section class="card"><h3>Queue <span class="count-age">showing ' + capped.length + ' of ' + all.length + '</span></h3>' + body + '</section>' + renderApprovalDrawer(selected, { filteredOut: noFilterMatch, waiting: allWaitingCount, total: all.length }) + '</div>',
    '</section>'
  ].join("");
}

function renderEnforcementScreen() {
  const home = state.posture.home;
  const head =
    '<div class="page-head"><div>' +
      '<p class="eyebrow">Enforcement</p>' +
      '<h1>What is enforced on this machine.</h1>' +
      '<p class="sub">Castle Wall reads enforcing only on a fresh enforcement check. Outbound counts come from the kernel for the stated window.</p>' +
    '</div></div>';
  if (!sourceLoaded("/api/posture/home") || !home) {
    const why = state.posture.homeError
      ? 'Enforcement status unavailable. This dashboard could not read the latest check. ' + escHtml(state.posture.homeError)
      : 'Enforcement status unavailable. Current data is Unknown.';
    return '<section class="concierge-wrap">' + head +
      '<section class="card"><p class="muted">' + why + '</p></section>' + renderSourceRead("/api/posture/home") +
      '</section>';
  }
  const wall = postureWallLabel(home.castle_wall && home.castle_wall.arm_state);
  const wallEvidenceAt = home.castle_wall && home.castle_wall.last_enforcement_evidence_at;
  const wallAge = wallEvidenceAt ? relTimeFromIso(wallEvidenceAt) : "";
  const wallAgeHtml = wallAge
    ? '<span class="pm-fresh" title="' + escHtml(wallEvidenceAt) + '">last enforcement evidence ' + escHtml(wallAge) + '</span>'
    : '<span class="pm-fresh none">no enforcement evidence yet</span>';
  const vaultProvision = home.castle_wall && home.castle_wall.castle_wall_provision;
  const vaultNotice = vaultProvision === "not_yet_walled"
    ? '<p class="muted">This vault is not on ${LOCAL_CASTLE_WALL_SUBJECT_PLACEHOLDER}\'s Castle Wall yet, so the wall state above is the machine\'s, not this vault\'s.</p>'
    : "";
  const layers = postureLayerLines().map(function (l) {
    const dotCls = layerDotClass(l);
    return '<div class="pp-line"><span class="' + dotCls + '"></span>' +
      '<span class="pp-k">' + escHtml(l.k) + '</span>' +
      '<span class="pp-v">' + escHtml(l.v) + '</span></div>';
  }).join("");
  return [
    '<section class="concierge-wrap">',
      head,
      '<section class="card">',
        '<div class="card-head-row"><h3>Castle Wall</h3><span class="' + wall.cls + '">' + escHtml(wall.text) + '</span></div>',
        '<div class="evidence pm-foot">' + wallAgeHtml + '<a class="pm-ev" href="/posture/evidence">Open the Evidence view &rarr;</a></div>',
        vaultNotice,
        '<div class="enforcement-layers">' + layers + '</div>',
        renderSourceRead("/api/sovereignty"),
      '</section>',
      renderOutboundConnections(home.digest, false),
      '<section class="card">',
        '<h3>Per-agent enforcement (' + (home.agents || []).length + ')</h3>',
        renderPostureAgentRows(home),
      '</section>',
    '</section>'
  ].join("");
}

// 25 rows per page keeps the console scannable; 20 pages bound sorting and retained snapshots.
const MFP_PAGE_SIZE = 25;
const MFP_RECORD_LIMIT = MFP_PAGE_SIZE * 20;
// Evidence text is a preview capped at 16 KiB, with the original read available separately.
const MFP_EVIDENCE_CHAR_LIMIT = 16 * 1024;
// Control lists page over all served items so the preview cap cannot hide an operator action.
const MFP_ALL_SERVED = "all-served";
function mfpPage(items, key, scope) {
  const count = scope === MFP_ALL_SERVED ? items.length : Math.min(items.length, MFP_RECORD_LIMIT);
  const last = Math.max(0, Math.ceil(count / MFP_PAGE_SIZE) - 1);
  const page = Math.min(last, Math.max(0, state.mfp.pages[key] || 0));
  state.mfp.pages[key] = page;
  const start = page * MFP_PAGE_SIZE;
  return { rows: items.slice(start, start + MFP_PAGE_SIZE), total: items.length, allServed: scope === MFP_ALL_SERVED, start: start, page: page, last: last };
}
// Read URLs carry the launch session only inside fetch calls; a rendered link would place it in the page and in the
// browser history, so these lists name their count and read age without linking to the raw read.
function mfpPager(page, key, path) {
  return '<div class="mfp-pager"><span>Showing ' + page.rows.length + ' of ' + page.total + ' returned records · read ' + escHtml(sourceReadAge(path) || "Unknown") + '</span>' +
    (!page.allServed && page.total > MFP_RECORD_LIMIT ? '<span>Only the first ' + MFP_RECORD_LIMIT + ' returned records are browsable here.</span>' : '') +
    (page.last ? '<button class="btn" data-action="mfp-page" data-list="' + key + '" data-step="-1"' + (page.page === 0 ? ' disabled' : '') + '>Previous</button>' +
      '<span>Page ' + (page.page + 1) + ' of ' + (page.last + 1) + '</span><button class="btn" data-action="mfp-page" data-list="' + key + '" data-step="1"' + (page.page === page.last ? ' disabled' : '') + '>Next</button>' : '') + '</div>';
}
function mfpEmpty(title, reason, path) {
  return '<div class="overview-empty">' + overviewChip("neutral", "EMPTY") + '<h3>' + title + '</h3><p>' + reason + ' Read ' + escHtml(sourceReadAge(path) || "Unknown") + '.</p>' +
    '<button class="btn" data-action="retry-panel" data-read="' + escHtml(path) + '">Refresh</button></div>';
}
function renderMfpFoldedSections() {
  return '<details class="mfp-fold" data-mfp-fold="auto-trigger"' + (state.mfp.folds["auto-trigger"] ? ' open' : '') + '><summary>Auto-trigger</summary>' + renderFoldedSection("Auto-trigger ladder", "Calibration", "auto-trigger", renderAutoTriggerPage()) + '</details>' +
    '<details class="mfp-fold" data-mfp-fold="honeypot"' + (state.mfp.folds.honeypot ? ' open' : '') + '><summary>Honeypots</summary>' + renderFoldedSection("Honeypots", "Honeypot traps.", "honeypot", renderHoneypotPage()) + '</details>';
}
// Only Sentinel wire values carry severity: alert maps to High, warn to Medium and info to Info; any other value reads
// Unknown.
function mfpSeverity(value) {
  // Sentinel wire values alone carry severity evidence; display-scale words are not server verdicts.
  return value === "alert" ? "high" : value === "warn" ? "medium" : value === "info" ? "info" : null;
}
function mfpSeverityMark(value) {
  return mfpDisplaySeverityMark(mfpSeverity(value));
}
// The legend names the display scale independently of the server's narrower severity vocabulary.
function mfpDisplaySeverityMark(level) {
  return level ? '<span class="mfp-severity ' + level + '"><b aria-hidden="true"></b>' + escHtml(sentenceCase(level)) + '</span>' : overviewChip("unknown", "UNKNOWN");
}
// Keep expanded configuration sections open across polling renders; only these two fixed keys persist.
document.addEventListener("toggle", function (event) {
  const target = event.target;
  if (!target || !target.getAttribute) return;
  const key = target.getAttribute("data-mfp-fold");
  if (Object.prototype.hasOwnProperty.call(state.mfp.folds, key)) state.mfp.folds[key] = target.open === true;
}, true);
function mfpFindingAgent(finding) {
  // Missing agent evidence cannot establish fortress-wide scope in either the queue or the drawer.
  return finding.agent_id || "Unknown · agent not served";
}
function renderFindingDrawer(finding) {
  const details = JSON.stringify(finding.details || {}, null, 2);
  const evidence = Array.isArray(finding.evidence_audit_ids) ? finding.evidence_audit_ids : [];
  return '<aside class="mfp-drawer" aria-label="Finding evidence"><div class="card-head-row"><h2>Finding evidence</h2><button class="btn" data-action="mfp-finding-close">Close</button></div>' +
    mfpSeverityMark(finding.severity) + ' ' + overviewChip("unknown", "LIFECYCLE UNKNOWN") +
    '<h3>' + escHtml(finding.summary || "Finding") + '</h3><p class="mono">' + escHtml(finding.finding_id) + '</p>' +
    '<dl><dt>Sentinel</dt><dd>' + escHtml(finding.sentinel_id || "Unknown") + '</dd><dt>Agent</dt><dd>' + escHtml(mfpFindingAgent(finding)) +
    '</dd><dt>Observed</dt><dd>' + escHtml(finding.observed_at || "Unknown") + ' · ' + escHtml(finding.observed_at ? relTimeFromIso(finding.observed_at) : "Unknown") + '</dd></dl>' +
    '<h3>Evidence and baseline</h3><p class="muted">Detector-supplied data. Shown as recorded, not as instructions.</p><pre>' + escHtml(details.slice(0, MFP_EVIDENCE_CHAR_LIMIT)) + '</pre>' +
    (details.length > MFP_EVIDENCE_CHAR_LIMIT ? '<p>Evidence preview truncated at ' + MFP_EVIDENCE_CHAR_LIMIT + ' characters of ' + details.length + '.</p>' : '') +
    '<h3>Audit references</h3><p>Showing ' + Math.min(evidence.length, MFP_PAGE_SIZE) + ' of ' + evidence.length + ' recorded references.</p><ul>' +
    evidence.slice(0, MFP_PAGE_SIZE).map(function (id) { return '<li class="mono">' + escHtml(id) + '</li>'; }).join("") + '</ul><a href="#activity">Open Evidence</a></aside>';
}
function renderFindingsScreen() {
  const path = "/api/sentinels/findings";
  const loaded = sourceLoaded(path);
  // No lifecycle field exists in the shipped finding schema: absence never becomes an invented Open state.
  const findings = loaded ? state.mfp.findings.slice(0, MFP_RECORD_LIMIT).sort(function (a, b) {
    // Unknown follows all five display levels, rather than inheriting severityClass's Info default.
    const unknownRank = 5; // Five display levels precede Unknown.
    const rank = function (value) { const level = mfpSeverity(value); return level ? severityRank(level) : unknownRank; };
    return rank(a.severity) - rank(b.severity);
  }) : [];
  const page = mfpPage(findings, "findings");
  page.total = loaded ? state.mfp.totals.findings : 0;
  const selected = loaded && findings.find(function (f) { return f.finding_id === state.mfp.findingId; });
  const rows = page.rows.map(function (finding) {
    return '<tr' + (finding.finding_id === state.mfp.findingId ? ' class="selected"' : '') + '><td>' + mfpSeverityMark(finding.severity) + '</td><td><button class="link-btn" data-action="mfp-finding" data-finding-id="' + escHtml(finding.finding_id) + '">' +
      escHtml(finding.summary || "Finding") + '</button><div class="muted">' + escHtml(mfpFindingAgent(finding)) + '</div></td><td>' + overviewChip("unknown", "UNKNOWN") + '</td><td class="mono">' + escHtml(finding.sentinel_id || "Unknown") + '</td><td class="mono">' + escHtml(finding.observed_at ? relTimeFromIso(finding.observed_at) : "Unknown") + '</td></tr>';
  }).join("");
  return '<section class="mfp-screen" data-mfp-findings><div class="page-head"><div><p class="eyebrow">This fortress</p><h1>Findings</h1><p class="sub">Sentinel observations, ranked by severity. Read-only. Lifecycle is not served; this view cannot resolve or dismiss findings.</p></div></div>' +
    '<div class="mfp-legend" aria-label="Severity scale">' + ["critical", "high", "medium", "low", "info"].map(mfpDisplaySeverityMark).join("") + '</div>' +
    '<p class="muted">Server alert maps to High, warn to Medium, and info to Info. Critical and Low are display levels not emitted by this source. The source returns a limited history, not an open-finding count.</p>' +
    '<div class="mfp-queue-grid' + (selected ? ' has-selection' : '') + '"><section class="card"><h2>Sentinel queue</h2>' +
    (!loaded ? '<h3>Sentinel findings Unknown</h3>' + overviewChip("unknown", "UNKNOWN") + renderSourceRead(path) :
      !findings.length ? mfpEmpty("No findings returned", "The source returned 0 of 0 findings. This does not establish detector coverage.", path) :
      mfpPager(page, "findings", path) + '<div class="overview-table-scroll"><table class="overview-table mfp-table"><thead><tr><th>Severity</th><th>Finding</th><th>Lifecycle</th><th>Sentinel</th><th>Age</th></tr></thead><tbody>' + rows + '</tbody></table></div>') +
    '</section>' + (selected ? renderFindingDrawer(selected) : '') + '</div>' + renderAnomalyFindingsCard() + renderMfpFoldedSections() + '</section>';
}
// Must match the Overview's "Open Sentinel findings" tile (renderPostureScreen), which counts this source and links here.
function renderAnomalyFindingsCard() {
  const findings = state.posture.anomalies || [];
  const unknown = !sourceLoaded("/api/anomaly/findings") || state.posture.anomaliesUnknown !== false;
  const age = sourceReadAge("/api/anomaly/findings");
  const countLine = unknown
    ? '<span class="count-age">Unknown: the detector has not answered</span>'
    : '<span class="count-age">' + escHtml(findings.length) + ' open' + (age ? ' · detector read ' + escHtml(age) : '') + '</span>';
  return '<section class="card" data-anomaly-findings><h3>Anomaly findings ' + countLine + '</h3>' +
    renderPostureAnomalies(findings, unknown) + renderSourceRead("/api/anomaly/findings") + '</section>';
}

function renderServerFleetRoster() {
  const path = "/api/fleet/roster";
  const roster = sourceLoaded(path) && state.mfp.roster;
  if (!roster) return '<section class="card" data-mfp-roster><h2>Fleet roster Unknown</h2>' + overviewChip("unknown", "UNKNOWN") + renderSourceRead(path) + '</section>';
  if (!roster.available) return '<section class="card" data-mfp-roster><h2>Fleet not configured</h2><p>The server reports no provisioned federation roster. Read ' + escHtml(sourceReadAge(path)) + '.</p><a class="btn" href="/fleet">Open Fleet Switcher</a></section>';
  const page = mfpPage(roster.nodes, "roster");
  page.total = state.mfp.totals.roster;
  const status = function (value, labels, warnings) {
    if (!Object.prototype.hasOwnProperty.call(labels, value)) return overviewChip("unknown", "UNKNOWN");
    // These are recorded federation verdicts, not fresh enforcement claims; never infer trust from reach.
    return overviewChip(value === "revoked" || value === "untrusted" ? "bad" : warnings.indexOf(value) >= 0 ? "warn" : "neutral", labels[value]);
  };
  const rows = page.rows.map(function (node) {
    // The server evaluator's false flag means this node's trust is unprovable, never proven safe.
    const trust = node.trust_evaluable === false
      ? overviewChip("warn", "NOT EVALUATED") + '<div>Trust could not be evaluated; treated as untrusted</div>'
      : status(node.trust_state, { admitted: "ADMITTED", revoked: "REVOKED", untrusted: "UNTRUSTED" }, ["revoked", "untrusted"]);
    return '<tr><td><strong>' + escHtml(node.label || node.node_id || "Unknown") + '</strong><div class="mono">' + escHtml(node.node_id || "Unknown") + '</div></td>' +
      '<td>' + trust + '</td>' +
      '<td>' + status(node.reach, { recent: "RECENT SYNC", stale: "STALE SYNC", never: "NEVER SYNCED" }, ["stale"]) + '</td>' +
      '<td>' + status(node.policy && node.policy.drift_state, { in_sync: "IN SYNC", drifted: "DRIFTED" }, ["drifted"]) + '</td>' +
      '<td>' + overviewChip("unknown", "UNKNOWN") + '</td><td class="mono">Roster read ' + escHtml(sourceReadAge(path) || "Unknown") +
      '<div>Last sync: ' + escHtml(node.last_sync_received_at ? relTimeFromIso(node.last_sync_received_at) : "Unknown") + '</div></td></tr>';
  }).join("");
  return '<section class="card" data-mfp-roster><h2>Fleet roster</h2><p>Trust, reach and policy drift are server verdicts at the roster read. Enrollment status is not served. Enrollment actions are not available in this read-only roster.</p>' +
    (!roster.nodes.length ? mfpEmpty("No machines in the roster", "The server returned 0 of 0 machines in the federation roster.", path) :
      mfpPager(page, "roster", path) + '<div class="overview-table-scroll"><table class="overview-table mfp-table"><thead><tr><th>Machine</th><th>Trust</th><th>Reach</th><th>Drift</th><th>Enrollment</th><th>Last check</th></tr></thead><tbody>' + rows + '</tbody></table></div>') + '</section>';
}

function renderIntegrationsScreen() {
  return '<div class="screen-tabs"><p class="eyebrow">Integrations</p><nav aria-label="Integrations">' +
    '<a href="#coordination" class="active" aria-current="page">Coordination</a></nav></div>' +
    renderCoordinationPage();
}

// ── Machines (slice 2b) ────────────────────────────────────────────────
// The fleet the Fleet Switcher page (/fleet) shows, inside the shell, from
// the same two reads: the machine list the operator saved in this browser,
// and each machine's unauthenticated GET /api/health liveness probe. This
// screen only reads: adding and removing machines stays on /fleet, which
// owns and writes the list. fleetMachines below is this client's one read
// of persistent browser storage, and nothing here ever writes it.
// Must match STORAGE_KEY in generateFleetSwitcherHTML
// (server/src/principal-policy/dashboard-html.ts).
const FLEET_STORAGE_KEY = "sanctuary_fleet_machines";
// Must match the Fleet Switcher's health-probe abort (3000 ms in
// generateFleetSwitcherHTML), so both views give a machine the same time to
// answer before they stop waiting.
const FLEET_PROBE_DEADLINE_SECONDS = 3;
const FLEET_PROBE_DEADLINE_MS = FLEET_PROBE_DEADLINE_SECONDS * DASHBOARD_MILLISECONDS_PER_SECOND;
// 25 probes = the visible current machine plus two dozen saved peers, which
// bounds one Check-again wave while leaving enough rows for a real small fleet.
const FLEET_PROBED_MACHINE_LIMIT = 25;
// The check age is rewritten once a second while the screen shows, so the
// age on screen is never more than one second younger than the probe round.
const FLEET_AGE_TICK_MS = DASHBOARD_MILLISECONDS_PER_SECOND;
// Named probe states. Only state_ONLINE counts toward the online numerator.
// state_UNKNOWN is no answer at all (a timeout, a refused or blocked
// connection, an answer that is not the health JSON): it is never counted
// as online and never as down, because no answer is evidence of neither.
const FLEET_PROBE = {
  CHECKING: "state_CHECKING",
  ONLINE: "state_ONLINE",
  NOT_HEALTHY: "state_NOT_HEALTHY",
  UNKNOWN: "state_UNKNOWN",
  UNPROBED: "state_UNPROBED"
};
// The Fleet Switcher's probe words in generateFleetSwitcherHTML in
// server/src/principal-policy/dashboard-html.ts must match this table's words
// for the same outcomes, so switching views does not change what the evidence means.
const FLEET_PROBE_VIEW = {
  state_CHECKING: { word: "Checking", cls: "checking" },
  state_ONLINE: { word: "Online", cls: "good" },
  state_NOT_HEALTHY: { word: "Not healthy", cls: "bad" },
  state_UNKNOWN: { word: "Unknown", cls: "unknown" },
  state_UNPROBED: { word: "Unchecked", cls: "unknown" }
};
const FLEET_ROW_UPDATE_REASON = "Unknown: this row could not be updated; use Check again.";
const FLEET_ROW_DRAW_FAILED = "One machine could not be shown; use Check again.";
const fleet = { round: 0, roundStartedAt: null, roundDone: false, probes: {}, ageTimer: null, controller: null, paintScheduled: false, machines: null, paintRows: {}, rowUpdateFailed: {} };

// Only an http or https address becomes a link or a probe target: the list
// is operator-typed text in browser storage, and a javascript: or data:
// address must never reach an href or a fetch.
function fleetHttpUrl(raw) {
  try {
    const u = new URL(String(raw));
    return u.protocol === "http:" || u.protocol === "https:" ? u : null;
  } catch (e) { return null; }
}

// The saved list, plus this machine when the list does not carry it (the
// Fleet Switcher adds it on load; this read-only screen shows it without
// writing). An unreadable or malformed list reads as empty, never as a
// failure that hides this machine.
function fleetMachines() {
  let saved = [];
  try {
    const parsed = JSON.parse(localStorage.getItem(FLEET_STORAGE_KEY) || "[]");
    if (Array.isArray(parsed)) saved = parsed;
  } catch (e) { saved = []; }
  const here = location.origin;
  const seen = {};
  const list = [];
  saved.forEach(function (m) {
    if (!m || typeof m.url !== "string" || !m.url) return;
    const web = fleetHttpUrl(m.url);
    const key = web ? web.origin : "raw:" + m.url;
    if (seen[key]) return;
    seen[key] = true;
    list.push({
      name: typeof m.name === "string" && m.name ? m.name : m.url,
      url: m.url,
      origin: web ? web.origin : null,
      probeUrl: web ? web.origin + "/api/health" : null,
      current: web ? web.origin === here : m.url === here,
      capped: false
    });
  });
  const currentIndex = list.findIndex(function (m) { return m.current; });
  if (currentIndex > 0) {
    // The local console is probed before the cap is applied; otherwise a
    // saved list could make this page skip the machine serving it.
    list.unshift(list.splice(currentIndex, 1)[0]);
  }
  // The machine serving this console is always in the list, under the name
  // the scope trigger shows for it, so the denominator never omits it.
  if (currentIndex < 0) {
    const selfUrl = fleetHttpUrl(here);
    list.unshift({ name: config.tenantName || "This machine", url: here, origin: selfUrl ? selfUrl.origin : null, probeUrl: selfUrl ? selfUrl.origin + "/api/health" : null, current: true, capped: false });
  }
  let probeSlots = 0;
  list.forEach(function (m) {
    if (!m.origin) return;
    probeSlots++;
    // The cap is enforced on web addresses only: non-web entries are never
    // probe candidates, so they cannot consume probe slots.
    m.capped = probeSlots > FLEET_PROBED_MACHINE_LIMIT;
  });
  return list;
}

// One liveness probe. It never carries the operator bearer or a cookie: a
// machine in a browser-stored list must never receive this machine's
// credential, and /api/health needs none.
async function probeFleetMachine(machine, signal) {
  if (!machine.origin || machine.capped) return machine.capped ? FLEET_PROBE.UNPROBED : FLEET_PROBE.UNKNOWN;
  try {
    const resp = await fetch(machine.probeUrl, { signal: signal, credentials: "omit", cache: "no-store", redirect: "manual" });
    // A health result is trusted only when the named web origin answered a
    // non-redirecting 2xx response. Error pages and redirects are not a
    // machine-health answer, even if their body happens to contain ok.
    if (!resp || !resp.ok || resp.redirected || resp.type === "opaqueredirect") return FLEET_PROBE.UNKNOWN;
    const body = await resp.json();
    return body && body.ok === true ? FLEET_PROBE.ONLINE : body && body.ok === false ? FLEET_PROBE.NOT_HEALTHY : FLEET_PROBE.UNKNOWN;
  } catch (e) {
    return FLEET_PROBE.UNKNOWN;
  }
}

function scheduleFleetPaint(url) {
  if (state.route !== "machines") return;
  if (url) fleet.paintRows[url] = true;
  if (fleet.paintScheduled) return;
  fleet.paintScheduled = true;
  Promise.resolve().then(function () {
    fleet.paintScheduled = false;
    if (state.route === "machines") paintMachinesScreen();
  });
}

// A probe round. A result from an older round never overwrites a newer
// one, so a slow answer cannot repaint a machine after "Check again".
async function probeFleetMachines() {
  const round = ++fleet.round;
  const machines = fleetMachines();
  if (fleet.controller) fleet.controller.abort();
  const controller = new AbortController();
  fleet.controller = controller;
  const timer = setTimeout(function () { controller.abort(); }, FLEET_PROBE_DEADLINE_MS);
  fleet.roundStartedAt = Date.now();
  fleet.roundDone = false;
  fleet.machines = machines;
  fleet.probes = {};
  fleet.paintRows = {};
  fleet.rowUpdateFailed = {};
  machines.forEach(function (m) {
    fleet.probes[m.url] = !m.origin ? FLEET_PROBE.UNKNOWN : m.capped ? FLEET_PROBE.UNPROBED : FLEET_PROBE.CHECKING;
  });
  if (state.route === "machines") renderMain();
  await Promise.all(machines.filter(function (m) { return m.origin && !m.capped; }).map(async function (m) {
    const result = await probeFleetMachine(m, controller.signal);
    if (round !== fleet.round) return;
    fleet.probes[m.url] = result;
    scheduleFleetPaint(m.url);
  }));
  clearTimeout(timer);
  if (round !== fleet.round) return;
  fleet.roundDone = true;
  if (fleet.controller === controller) fleet.controller = null;
  scheduleFleetPaint(null);
}

// The fleet count with its denominator and its check age. The age is the
// round's start, so the answers on screen are at least this old. Unknown
// and not-healthy machines are named beside the count, never folded into it.
function fleetSummary(machines) {
  const total = machines.length;
  const noun = total === 1 ? " machine" : " machines";
  if (!fleet.roundStartedAt) return { text: "Not checked yet: 0 of " + total + noun + " checked", age: "" };
  let online = 0, unknown = 0, notHealthy = 0, checking = 0, unprobed = 0, probeable = 0;
  machines.forEach(function (m) {
    if (m.origin && !m.capped) probeable++;
    const s = fleet.probes[m.url] || FLEET_PROBE.UNKNOWN;
    if (s === FLEET_PROBE.ONLINE) online++;
    else if (s === FLEET_PROBE.NOT_HEALTHY) notHealthy++;
    else if (s === FLEET_PROBE.CHECKING) checking++;
    else if (s === FLEET_PROBE.UNPROBED) unprobed++;
    else unknown++;
  });
  const parts = [online + " of " + total + noun + " online"];
  if (unprobed) {
    const cappedWebTotal = probeable + unprobed;
    const cappedNoun = cappedWebTotal === 1 ? " machine" : " machines";
    // The cap denominator counts web addresses only; non-web rows keep their
    // own Unknown reason and must not be folded into the unchecked remainder.
    parts.push((checking ? "checking " : "checked ") + probeable + " of " + cappedWebTotal + cappedNoun + " with a web address; the rest are listed unchecked");
  }
  if (checking && !unprobed) parts.push(checking + " checking");
  if (notHealthy) parts.push(notHealthy + " not healthy");
  if (unknown) parts.push(unknown + " Unknown");
  return { text: parts.join(" · "), age: "checked " + durationLabelFromMs(Date.now() - fleet.roundStartedAt) + " ago" };
}

function scheduleFleetAgeTick() {
  if (fleet.ageTimer) return;
  fleet.ageTimer = setTimeout(function () {
    fleet.ageTimer = null;
    if (state.route !== "machines") return;
    const el = document.getElementById("machines-age");
    if (el && fleet.roundStartedAt) el.textContent = "checked " + durationLabelFromMs(Date.now() - fleet.roundStartedAt) + " ago";
    scheduleFleetAgeTick();
  }, FLEET_AGE_TICK_MS);
}

function renderMachinesScreen() {
  return [
    '<section class="concierge-wrap">',
      '<div class="page-head"><div>',
        '<p class="eyebrow">Machines</p>',
        '<h1>Machines</h1>',
        '<p class="sub">The authenticated federation roster is separate from machines saved in this browser. Saved machines are checked at their host health check. Online means the host answered; it is not a statement about that machine\'s protection. Add or remove machines on the <a href="/fleet">Fleet Switcher</a>.</p>',
      '</div></div>',
      renderServerFleetRoster(),
      '<section class="card browser-machines" aria-label="Saved in this browser">',
        '<div class="card-head-row"><div><h1>Machines saved in this browser.</h1><span class="count-age" id="machines-summary"></span></div>',
        '<button type="button" class="btn" data-action="machines-recheck">Check again</button></div>',
        '<div class="machine-list" id="machines-list"></div>',
      '</section>',
    '</section>'
  ].join("");
}

function appendText(parent, text) {
  parent.appendChild(document.createTextNode(String(text)));
}

function makeTextElement(tag, className, text) {
  const el = document.createElement(tag);
  if (className) el.className = className;
  appendText(el, text);
  return el;
}

function machineStatus(machine) {
  return fleet.roundStartedAt ? (fleet.probes[machine.url] || FLEET_PROBE.UNKNOWN) : FLEET_PROBE.UNKNOWN;
}

function machineStatusReason(machine, status) {
  return !machine.origin
    ? "Unknown: this saved address is not a web address, so it was not linked or checked."
    : status === FLEET_PROBE.UNPROBED
      ? "Unchecked: this row is past the " + FLEET_PROBED_MACHINE_LIMIT + "-machine probe cap, so it was listed but not checked."
      : status === FLEET_PROBE.UNKNOWN
        ? "Unknown: no answer to the health check within " + FLEET_PROBE_DEADLINE_SECONDS + " seconds, or an answer that was not the health check. This is not proof the machine is down."
        : status === FLEET_PROBE.NOT_HEALTHY ? "The machine answered its health check with ok false."
        : status === FLEET_PROBE.ONLINE ? "The machine answered its health check with ok true. This says only that the host answered." : "The health check is in flight.";
}

function updateMachinesSummary(summaryEl, machines) {
  const summary = fleetSummary(machines);
  summaryEl.replaceChildren(document.createTextNode(summary.text));
  if (summary.age) {
    appendText(summaryEl, " · ");
    const age = makeTextElement("span", "", summary.age);
    age.setAttribute("id", "machines-age");
    summaryEl.appendChild(age);
  }
}

function makeMachineRow(machine, index) {
  const status = machineStatus(machine);
  const view = FLEET_PROBE_VIEW[status] || FLEET_PROBE_VIEW.state_UNKNOWN;
  const row = document.createElement("div");
  row.className = "machine-row";
  row.setAttribute("data-machine-index", String(index));
  row.setAttribute("data-machine-url", machine.url);
  const chip = document.createElement("span");
  chip.className = "state-chip " + view.cls;
  chip.setAttribute("title", machineStatusReason(machine, status));
  const mark = document.createElement("i");
  mark.setAttribute("aria-hidden", "true");
  chip.appendChild(mark);
  appendText(chip, view.word);
  row.appendChild(chip);
  const id = document.createElement("div");
  id.className = "machine-id";
  const name = makeTextElement("strong", "", machine.name);
  const address = makeTextElement("small", "mono", machine.url);
  id.appendChild(name);
  id.appendChild(address);
  if (machine.origin) id.appendChild(makeTextElement("small", "mono", "host health check"));
  row.appendChild(id);
  if (machine.current) {
    row.appendChild(makeTextElement("span", "machine-here", "This machine"));
  } else if (machine.origin) {
    const open = makeTextElement("a", "btn", "Open console");
    const parsed = fleetHttpUrl(machine.url);
    // The link uses the same parsed web address as the probe, so a loosely
    // written address cannot resolve as a path on this console.
    if (parsed) open.setAttribute("href", parsed.href);
    open.setAttribute("rel", "noopener");
    row.appendChild(open);
  } else {
    row.appendChild(makeTextElement("span", "muted", "Not a web address"));
  }
  return row;
}

function makeMachineUpdateFallbackRow(machine, index) {
  const row = document.createElement("div");
  row.className = "machine-row";
  row.setAttribute("data-machine-index", String(index));
  row.setAttribute("data-machine-url", machine.url);
  const chip = document.createElement("span");
  chip.className = "state-chip unknown";
  chip.setAttribute("title", FLEET_ROW_UPDATE_REASON);
  const mark = document.createElement("i");
  mark.setAttribute("aria-hidden", "true");
  chip.appendChild(mark);
  appendText(chip, "Unknown");
  row.appendChild(chip);
  const id = document.createElement("div");
  id.className = "machine-id";
  id.appendChild(makeTextElement("strong", "", machine.name || machine.url));
  row.appendChild(id);
  return row;
}

function guardedMachineRow(machine, index) {
  try { return makeMachineRow(machine, index); }
  catch (e) {
    fleet.rowUpdateFailed[machine.url] = true;
    try { return makeMachineUpdateFallbackRow(machine, index); }
    catch (fallbackError) {
      // A row whose fallback also fails still takes its place in the list as
      // fixed text that reads no machine field, so the list never silently
      // shows fewer machines than the summary counts; if even that fails, an
      // empty node keeps the other rows and the focus restore running.
      try {
        const placeholder = document.createElement("div");
        placeholder.className = "machine-row";
        placeholder.appendChild(makeTextElement("span", "muted", FLEET_ROW_DRAW_FAILED));
        return placeholder;
      } catch (placeholderError) {
        return document.createTextNode("");
      }
    }
  }
}

function replaceMachineWithFallback(oldRow) {
  try {
    const chip = oldRow && oldRow.querySelector(".state-chip");
    if (!chip) return;
    // Reuse the chip and its mark so a repeated row-construction failure cannot
    // leave Checking behind or discard the operator's focused link.
    chip.className = "state-chip unknown";
    chip.title = FLEET_ROW_UPDATE_REASON;
    if (chip.lastChild) chip.lastChild.textContent = "Unknown";
  } catch (e) { /* A failed in-place mark leaves the existing row; other rows and focus restore still run. */ }
}

function rebuildMachinesList(listEl, machines) {
  const frag = document.createDocumentFragment();
  machines.forEach(function (m, index) {
    frag.appendChild(guardedMachineRow(m, index));
  });
  listEl.replaceChildren(frag);
}

function paintMachinesScreen() {
  const summaryEl = document.getElementById("machines-summary");
  const listEl = document.getElementById("machines-list");
  if (!summaryEl || !listEl) return;
  const machines = fleet.roundStartedAt && fleet.machines ? fleet.machines : fleetMachines();
  updateMachinesSummary(summaryEl, machines);
  const pending = fleet.paintRows || {};
  fleet.paintRows = {};
  const focus = captureInputFocus(listEl);
  try {
    let rebuilt = false;
    Object.keys(pending).forEach(function (url) {
      let oldRow = null;
      let index = -1;
      try {
        index = machines.findIndex(function (m) { return m.url === url; });
        if (index < 0 || !listEl.querySelector) return;
        // Row lookup is by the generated numeric index; saved machine addresses
        // can contain control characters that are not safe selector text.
        oldRow = listEl.querySelector('[data-machine-index="' + index + '"]');
        if (!oldRow) {
          try { oldRow = listEl.querySelector('[data-machine-url="' + escCssAttr(machines[index].url) + '"]'); }
          catch (e) { oldRow = null; }
          if (oldRow) {
            fleet.rowUpdateFailed[url] = true;
            replaceMachineWithFallback(oldRow);
            return;
          }
        }
        if (!oldRow) {
          if (!rebuilt) {
            rebuilt = true;
            rebuildMachinesList(listEl, machines);
          }
          return;
        }
        if (fleet.rowUpdateFailed[url]) {
          replaceMachineWithFallback(oldRow);
          return;
        }
        if (oldRow && typeof oldRow.replaceWith === "function") oldRow.replaceWith(makeMachineRow(machines[index], index));
      } catch (e) {
        // A finished probe must never leave an old Checking chip behind; that
        // would claim work is still in flight after the answer arrived.
        if (index >= 0) fleet.rowUpdateFailed[url] = true;
        if (oldRow && index >= 0) replaceMachineWithFallback(oldRow);
        else if (!rebuilt) {
          rebuilt = true;
          rebuildMachinesList(listEl, machines);
        }
      }
    });
  } finally {
    // restoreInputFocus enforces the exactly-one-match rule, so a replaced
    // row can regain focus without moving the operator to a sibling control.
    restoreInputFocus(listEl, focus);
  }
}

function hydrateMachinesScreen() {
  const summaryEl = document.getElementById("machines-summary");
  const listEl = document.getElementById("machines-list");
  if (!summaryEl || !listEl) return;
  const machines = fleet.roundStartedAt && fleet.machines ? fleet.machines : fleetMachines();
  updateMachinesSummary(summaryEl, machines);
  const frag = document.createDocumentFragment();
  machines.forEach(function (m, index) {
    frag.appendChild(guardedMachineRow(m, index));
  });
  listEl.replaceChildren(frag);
}

// ── Hub API actions ────────────────────────────────────────────────────
// Each independent panel publishes as soon as it settles. One slow route must
// never hold Posture, or another panel, behind it. Retries select one panel.
// Two MiB covers 500 public records at roughly 4 KiB each; larger reads fail Unknown.
const MFP_BODY_BYTE_LIMIT = 2 * 1024 * 1024;
async function readMfpBody(response) {
  if (!response.body || !response.body.getReader) throw new Error("Dashboard read body unavailable");
  const reader = response.body.getReader();
  const decoder = new TextDecoder();
  let bytes = 0;
  let text = "";
  try {
    while (true) {
      const part = await reader.read();
      if (part.done) break;
      bytes += part.value.byteLength;
      // Untrusted roster, finding and policy text cannot grow the retained response beyond the fixed budget.
      if (bytes > MFP_BODY_BYTE_LIMIT) throw new Error("Dashboard read body too large");
      text += decoder.decode(part.value, { stream: true });
    }
    return JSON.parse(text + decoder.decode());
  } finally { void reader.cancel().catch(function () {}); reader.releaseLock(); }
}
async function fetchMfpRead(path, key) {
  const generation = beginMfpRead(path);
  const headers = TOKEN ? { Authorization: "Bearer " + TOKEN } : {};
  try {
    const res = await readResponse(credentialedReadUrl(path + "?_t=" + Date.now(), "GET"), { headers: headers, cache: "no-store" }, undefined, generation);
    const body = await res.json();
    // Only the newest generation may commit rows and totals; older completions have no current authority.
    if (!currentMfpRead(path, generation)) return;
    // Snapshots replace prior state; the byte cap bounds text and the record cap bounds sorting and DOM work.
    const rows = key === "roster" ? body.nodes : body.data.findings;
    state.mfp.totals[key] = rows.length;
    state.mfp[key] = key === "roster" ? { available: body.available, nodes: rows.slice(0, MFP_RECORD_LIMIT) } : rows.slice(0, MFP_RECORD_LIMIT);
  } catch (error) {
    // A superseded failure cannot clear the current snapshot or change its loaded state.
    if (!currentMfpRead(path, generation)) return;
    // The refresh that superseded this read owns the next snapshot and its selection, and already set the read state.
    if (error && error.supersededByRefresh === true) return;
    if (sourceRead(path).state !== "state_FAILED" && !sourceNotServed(path)) failSource(path, error);
    state.mfp.totals[key] = 0;
    state.mfp[key] = key === "roster" ? null : [];
    // Selection belongs to the failed snapshot; a later success must not reopen its drawer.
    if (key === "findings") state.mfp.findingId = null;
  }
}

const panelJobs = [
  { paths: [INBOX_PREFS], load: loadInboxPrefs },
  { paths: ["/api/fleet/roster"], load: function () { return fetchMfpRead("/api/fleet/roster", "roster"); } },
  { paths: ["/api/sentinels/findings"], load: function () { return fetchMfpRead("/api/sentinels/findings", "findings"); } },
  { paths: [HUB + "/agents"], load: async function () {
    const ar = await api("/agents");
    state.agents = ar.data.agents || [];
    state.chatActiveAgentId = state.chatActiveAgentId || (state.agents[0] ? state.agents[0].agent_id : null);
  } },
  { paths: [HUB + "/inbox"], load: async function () { const r = await api("/inbox"); applyInboxPayload(r.data || {}); } },
  { paths: [HUB + "/activity"], load: async function () { const r = await api("/activity"); state.activity = r.data.entries || []; } },
  { paths: ["/api/posture/evidence"], load: async function (deadlineAt) {
    const url = evidenceReadUrl();
    const sep = url.indexOf("?") >= 0 ? "&" : "?";
    const res = await readResponse(credentialedReadUrl(url + sep + "_t=" + Date.now(), "GET"), {
      headers: Object.assign({ "Cache-Control": "no-cache", "Pragma": "no-cache" }, TOKEN ? { "Authorization": "Bearer " + TOKEN } : {}),
      cache: "no-store"
    }, deadlineAt === undefined ? undefined : Math.max(0, deadlineAt - Date.now()));
    state.evidence.view = await res.json();
  } },
  { paths: [HUB + "/policies"], load: async function () { const r = await api("/policies"); state.policies = r.data.policies || []; } },
  { paths: [HUB + "/activity?category=privacy"], load: async function () { const r = await api("/activity?category=privacy"); state.privacyEvents = r.data.entries || []; } },
  { paths: [HUB + "/activity?category=handoff"], load: async function () { const r = await api("/activity?category=handoff"); state.handoffEvents = r.data.entries || []; } },
  { paths: [AUTO_TRIGGER], load: fetchAutoTriggerState },
  { paths: [AUTO_TRIGGER + "/recommendations"], load: async function () { const r = await autoTriggerApi("/recommendations"); state.autoTrigger.recommendations = r.data.recommendations; } },
  { paths: [HUB + "/recognition/did-web"], load: async function () {
    try { const r = await api("/recognition/did-web"); state.recognition.health = r.data || null; state.recognition.error = null; }
    catch (e) { state.recognition.error = e.message; }
  } },
  { paths: [HUB + "/intelligence"], load: fetchIntelligenceState },
  { paths: ["/api/honeypot"], load: fetchHoneypotState },
  { paths: ["/api/sovereignty"], load: fetchSovereignty },
  { paths: ["/api/posture/home"], load: fetchPostureHome },
  { paths: ["/api/anomaly/findings"], load: fetchPostureAnomalies },
  { paths: [HUB + "/chat/concierge/history"], load: fetchConciergeHistory }
];
const policyPanelJob = { paths: [POLICY + "/current"], load: readPolicyView };
const pendingPanels = new Map();
function loadPanel(job) {
  if (pendingPanels.has(job)) return pendingPanels.get(job);
  // Dependent reads share the panel's budget instead of resetting it per step.
  const deadlineAt = Date.now() + DASHBOARD_READ_DEADLINE_MS;
  const pending = Promise.resolve().then(function () { return job.load(deadlineAt); }).then(function () {
    return job.paths.some(function (path) { const read = sourceRead(path); return read && read.state === "state_LOADED"; });
  }).catch(function (error) {
    job.paths.forEach(function (path) { if (sourceRead(path) && sourceRead(path).state !== "state_FAILED" && sourceRead(path).state !== "state_NOT_SERVED") failSource(path, error); });
    return false;
  }).finally(function () { pendingPanels.delete(job); rerender(); });
  pendingPanels.set(job, pending);
  return pending;
}
const trailingPanels = new Map();
function queuePanel(job) {
  // One queued read per fixed panel coalesces bursts; every event invalidates older admitted bytes.
  job.paths.forEach(function (path) {
    sourceReads.forEach(function (read, key) {
      if (key === readKey(path) || key.indexOf(readKey(path) + "/") === 0) {
        read.revision++; read.state = "state_LOADING"; read.nextReadAt = 0;
      }
    });
  });
  if (trailingPanels.has(job)) return trailingPanels.get(job);
  const queued = Promise.resolve(pendingPanels.get(job)).then(function () {
    trailingPanels.delete(job); // An event during the new read must queue a subsequent read.
    job.paths.forEach(function (path) {
      sourceReads.forEach(function (read, key) { if (key === readKey(path) || key.indexOf(readKey(path) + "/") === 0) read.nextReadAt = 0; });
    });
    return loadPanel(job);
  });
  trailingPanels.set(job, queued);
  return queued;
}
function orderedPanelJobs(jobs) {
  const critical = jobs.filter(function (job) { return job.load === fetchSovereignty || job.load === fetchPostureHome; });
  return critical.concat(jobs.filter(function (job) { return critical.indexOf(job) < 0; }));
}
async function fetchAll(afterMutation, selectedJobs) {
  const jobs = selectedJobs || panelJobs.filter(function (job) { return job.load !== loadInboxPrefs; });
  const pending = orderedPanelJobs(jobs).map(afterMutation ? queuePanel : loadPanel);
  if (afterMutation) rerender();
  const results = await Promise.all(pending);
  return results.some(Boolean);
}
function fetchEverySource(afterMutation) {
  return fetchAll(afterMutation, panelJobs.concat([policyPanelJob]));
}
function jobsForPaths(paths) {
  return panelJobs.filter(function (job) {
    return job.paths.some(function (path) { return paths.some(function (target) { return readKey(path) === readKey(target); }); });
  });
}
function queueStreamRefresh(paths) {
  return fetchAll(true, jobsForPaths(paths));
}
function retryPanel(path) {
  if (liveUpdatesStopped) {
    // A manual restart must reread every source before old snapshots may look current again.
    sourceReads.forEach(function (read) { read.revision++; read.state = "state_UNREAD"; read.error = null; read.failures = 0; read.nextReadAt = 0; });
    liveUpdatesStopped = false;
    pollingStarted = false;
    const pending = fetchEverySource(true);
    connectStream();
    return pending;
  }
  const source = sourceRead(path);
  if (source) source.nextReadAt = 0;
  if (readKey(path) === readKey(POLICY + "/current")) return loadPolicyView();
  const job = panelJobs.slice().reverse().find(function (candidate) {
    return candidate.paths.some(function (prefix) { return readKey(path) === readKey(prefix) || readKey(path).indexOf(readKey(prefix) + "/") === 0; });
  });
  if (job) {
    job.paths.forEach(function (prefix) { sourceReads.forEach(function (read, key) { if (key === readKey(prefix) || key.indexOf(readKey(prefix) + "/") === 0) read.nextReadAt = 0; }); });
    const result = loadPanel(job); rerender(); return result;
  }
}
async function refreshPanel(path) {
  await Promise.all(Array.from(pendingPanels.values()));
  if (path === AUTO_TRIGGER) return Promise.all([retryPanel(AUTO_TRIGGER + "/rules"), retryPanel(AUTO_TRIGGER + "/recommendations")]);
  return retryPanel(path);
}
function refreshAutoTriggerPanels() {
  return Promise.all(panelJobs.filter(function (job) { return job.paths[0].indexOf(AUTO_TRIGGER) === 0; }).map(queuePanel));
}

async function fetchHoneypotState() {
  try {
    const [tool, credential] = await Promise.all([honeypotApi("/tool-traps"), honeypotApi("/credential-traps")]);
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
    const res = await readResponse(credentialedReadUrl("/api/sovereignty?_t=" + Date.now(), "GET"), { headers: headers, cache: "no-store" });
    let body = null;
    try { body = await res.json(); } catch (e) { body = null; }
    if (!res.ok || !body || body.error) {
      state.posture.data = null;
      state.posture.error = (body && body.error) || ("HTTP " + res.status);
      clearSealFreshnessTimer("/api/sovereignty");
      return;
    }
    state.posture.data = body;
    state.posture.error = null;
    scheduleSealFreshnessRefresh("/api/sovereignty", deriveSealFreshness(body.live_enforcement));
  } catch (e) {
    state.posture.data = null;
    state.posture.error = e && e.message ? e.message : String(e);
    clearSealFreshnessTimer("/api/sovereignty");
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
function postureHomeExpiryAt(home) {
  if (!home) return null;
  // Each agent expires on its own evidence; a machine timestamp cannot extend an agent badge.
  const expiries = [home.castle_wall, home.digest && (home.digest.chain_verified === true || home.digest.chain_verdict === "verified_suffix_only") ? auditChainEvidence(home.digest) : null].concat(home.agents || []).filter(evidenceCurrent).map(function (evidence) {
    return parseEvidenceTimestamp(evidence.last_enforcement_evidence_at) + Math.min(Number(evidence.freshness_window_ms), SEAL_FRESHNESS_MAX_MS) + SEAL_FRESHNESS_BOUNDARY_OFFSET_MS;
  });
  return expiries.length ? Math.min.apply(null, expiries) : null;
}
function scheduleHomeFreshness() {
  clearTimeout(homeFreshnessTimer);
  const refreshAt = postureHomeExpiryAt(state.posture.home);
  // Invariant: expired evidence removes protection claims immediately; only the following LOADED read may restore them.
  if (refreshAt !== null) homeFreshnessTimer = setTimeout(function () { rerender(); scheduleHomeFreshness(); }, refreshAt - Date.now());
}
async function fetchPostureHome() {
  const headers = { "Cache-Control": "no-cache", "Pragma": "no-cache" };
  if (TOKEN) headers["Authorization"] = "Bearer " + TOKEN;
  try {
    const res = await readResponse(credentialedReadUrl("/api/posture/home?_t=" + Date.now(), "GET"), { headers: headers, cache: "no-store" });
    let body = null;
    try { body = await res.json(); } catch (e) { body = null; }
    if (!res.ok || !body || body.error) {
      state.posture.home = null;
      state.posture.homeError = (body && body.error) || ("HTTP " + res.status);
      clearSealFreshnessTimer("/api/posture/home");
    } else {
      // Optional detector evidence is independent of the primary home read.
      body.anomaly_findings = state.posture.anomalies || [];
      body.anomaly_findings_unknown = state.posture.anomaliesUnknown !== false;
      state.posture.home = body;
      scheduleHomeFreshness();
      scheduleSealFreshnessRefresh("/api/posture/home", { current: true, refreshAt: postureHomeExpiryAt(body) });
      state.posture.homeError = null;
    }
  } catch (e) {
    state.posture.home = null;
    state.posture.homeError = e && e.message ? e.message : String(e);
    clearSealFreshnessTimer("/api/posture/home");
  }
}

async function fetchPostureAnomalies() {
  try {
    const headers = TOKEN ? { "Authorization": "Bearer " + TOKEN } : {};
    const res = await readResponse(credentialedReadUrl("/api/anomaly/findings?_t=" + Date.now(), "GET"), { headers: headers, cache: "no-store" });
    const body = await res.json();
    if (!body.data || !Array.isArray(body.data.findings)) throw new Error("Anomaly findings unavailable.");
    state.posture.anomalies = body.data.findings;
    state.posture.anomaliesUnknown = false;
  } catch (_) {
    // An absent detector is unavailable evidence, never proof of zero findings.
    state.posture.anomalies = [];
    state.posture.anomaliesUnknown = true;
  }
  if (state.posture.home) {
    state.posture.home.anomaly_findings = state.posture.anomalies;
    state.posture.home.anomaly_findings_unknown = state.posture.anomaliesUnknown;
  }
}

function liveEnforcementSnapshot() {
  if (!sourceLoaded("/api/sovereignty")) return null;
  const d = state.posture.data;
  return d && d.live_enforcement ? d.live_enforcement : null;
}

function sealFreshnessWindowMs(live) {
  const payloadWindow = live ? Number(live.freshness_window_ms) : NaN;
  if (Number.isFinite(payloadWindow) && payloadWindow > 0) {
    return Math.min(payloadWindow, SEAL_FRESHNESS_MAX_MS);
  }
  return null;
}

function sealEvidenceWhat(live) {
  if (!live) return "not loaded";
  switch (live.evidence_basis) {
    case "fresh_enforcement_evidence":
    case "stale_evidence":
      return "Castle Wall enforcement";
    case "not_enforcing_evidence":
      return "not enforcing";
    case "intentionally_stopped":
      return "intentional stand-down";
    case "daemon_liveness_unconfirmed":
      return "daemon liveness unconfirmed";
    case "not_installed":
      return "wall not installed";
    case "subject_unbound_evidence":
      return "subject unbound";
    case "legacy_macos_audit_token":
      return "legacy macOS audit token";
    case "pre_canonical_linux_agent_name":
      return "pre-canonical Linux agent name";
    case "subject_unresolvable":
      return "subject unresolved";
    case "producer_key_unavailable":
      return "producer key unavailable";
    case "no_evidence":
      return "no enforcement evidence";
    default:
      return live.castle_wall_arm_state
        ? String(live.castle_wall_arm_state).replace(/_/g, " ")
        : "unknown";
  }
}

function deriveSealFreshness(live, now) {
  const checkedAt = typeof now === "number" ? now : Date.now();
  const windowMs = sealFreshnessWindowMs(live);
  const windowKnown = typeof windowMs === "number" && Number.isFinite(windowMs);
  const windowLabel = windowKnown ? durationLabelFromMs(windowMs) : "unknown";
  const what = sealEvidenceWhat(live);
  if (!windowKnown) {
    return {
      state: "unknown",
      current: false,
      inline: "freshness window unknown",
      detail: "freshness window unknown",
      windowLabel: windowLabel,
      windowKnown: false,
      refreshAt: null,
      what: what
    };
  }
  const raw = live && live.last_enforcement_evidence_at;
  if (typeof raw !== "string" || raw.trim() === "") {
    return {
      state: "absent",
      current: false,
      inline: "no evidence",
      detail: "not provided",
      windowLabel: windowLabel,
      windowKnown: true,
      refreshAt: null,
      what: what
    };
  }
  const iso = raw.trim();
  const observedAt = parseEvidenceTimestamp(iso);
  if (!Number.isFinite(observedAt)) {
    return {
      state: "unparseable",
      current: false,
      inline: "invalid evidence time",
      detail: "unparseable timestamp",
      windowLabel: windowLabel,
      windowKnown: true,
      refreshAt: null,
      what: what
    };
  }
  const ageMs = checkedAt - observedAt;
  if (ageMs < 0) {
    return {
      state: "unparseable",
      current: false,
      inline: "invalid evidence time",
      detail: "timestamp is in the future",
      windowLabel: windowLabel,
      windowKnown: true,
      refreshAt: null,
      what: what
    };
  }
  const ageLabel = durationLabelFromMs(ageMs);
  const inline = "last evidenced " + ageLabel + " ago";
  const current = ageMs <= windowMs;
  return {
    state: current ? "fresh" : "stale",
    current: current,
    inline: inline,
    detail: shortTime(iso) + " (" + ageLabel + " ago)",
    windowLabel: windowLabel,
    windowKnown: true,
    refreshAt: current ? observedAt + windowMs + SEAL_FRESHNESS_BOUNDARY_OFFSET_MS : null,
    what: what
  };
}

function clearSealFreshnessTimerValue(value) {
  if (Array.isArray(value)) value.forEach(function (timer) { clearTimeout(timer); });
  else clearTimeout(value);
}
function clearSealFreshnessTimer(path) {
  if (path === undefined) {
    sealFreshnessTimers.forEach(clearSealFreshnessTimerValue);
    sealFreshnessTimers.clear();
    return;
  }
  const key = readKey(path);
  const timers = sealFreshnessTimers.get(key);
  if (timers !== undefined) clearSealFreshnessTimerValue(timers);
  sealFreshnessTimers.delete(key);
}

function scheduleSealFreshnessRefresh(path, freshness) {
  clearSealFreshnessTimer(path);
  // Stopped means stopped: a user-action refetch while live updates are stopped must not
  // re-arm automatic seal re-reads; Retry clears the flag before it rereads and re-arms.
  if (liveUpdatesStopped) return;
  if (
    !freshness ||
    !freshness.current ||
    typeof freshness.refreshAt !== "number" ||
    !Number.isFinite(freshness.refreshAt)
  ) return;
  const source = sourceRead(path);
  const lastReadAt = source && Number.isFinite(source.lastReadAt) ? source.lastReadAt : 0;
  const rereadAt = Math.max(freshness.refreshAt, lastReadAt + DASHBOARD_SEAL_REREAD_MIN_INTERVAL_MS);
  const expiryDelayMs = Math.max(0, freshness.refreshAt - Date.now());
  const rereadDelayMs = Math.max(0, rereadAt - Date.now());
  const key = readKey(path);
  const expiryTimer = setTimeout(function () {
    // Invariant: the visual protection claim expires on the evidence boundary even when the network re-read is rate-limited.
    rerender();
  }, expiryDelayMs);
  const rereadTimer = setTimeout(function () {
    sealFreshnessTimers.delete(key);
    // Invariant: the source is set loading before the network read, so expired evidence cannot keep rendering Protected while the re-read is pending.
    queueStreamRefresh([path]);
  }, rereadDelayMs);
  sealFreshnessTimers.set(key, [expiryTimer, rereadTimer]);
}

// Wave 1: map the honest Castle Wall arm-state to the operator-facing seal.
// "armed" plus current, parseable enforcement evidence is the ONLY
// green/Protected state; "degraded" reads Attention; everything else
// (unknown, not_installed, missing data, absent evidence timestamp,
// unparseable evidence timestamp, stale evidence timestamp) reads non-green.
// A locked-down fortress (the lockdown control engaged) reads Locked.
function deriveSeal() {
  const t1 = state.tier1.lockdown.state;
  const live = liveEnforcementSnapshot();
  const freshness = deriveSealFreshness(live);
  const arm = live ? live.castle_wall_arm_state : null;
  const title = function (word) {
    const qualifier = freshness.inline.charAt(0).toUpperCase() + freshness.inline.slice(1);
    return word + ". " + qualifier + ".";
  };
  if (t1 === "engaged" && sourceLoaded(HUB + "/agents") && sourceLoaded(HUB + "/inbox")) {
    return { tone: "locked", word: "Locked", arm: "locked_down", freshness: freshness, title: title("Locked") };
  }
  if (arm === "armed" && freshness.current) {
    return { tone: "protected", word: "Protected", arm: arm, freshness: freshness, title: title("Protected") };
  }
  if (arm === "degraded") {
    return { tone: "attention", word: "Attention", arm: arm, freshness: freshness, title: title("Attention") };
  }
  if (arm) {
    return { tone: "attention", word: "Attention", arm: arm, freshness: freshness, title: title("Attention") };
  }
  return { tone: "unknown", word: "Unknown", arm: null, freshness: freshness, title: title("Unknown") };
}

// Plain-English line for the named layer in the posture popover. Uses the
// retired-L-number rule: named layers only, never "L1".."L4". Values are
// honest: the wall line reflects the real arm-state, not config presence.
// The dot beside a layer line. A line whose word is Unknown wears the unknown
// dot (slate, hollow) whatever its other flags say: the pass dot is earned by
// observed evidence, never by the absence of a warning. Shared by the seal
// popover and the Enforcement screen so the two cannot disagree.
function layerDotClass(l) {
  if (l.unknown || /^unknown$/i.test(String(l.v).trim())) return "pp-dot unknown";
  if (l.off) return "pp-dot off";
  return l.warn ? "pp-dot warn" : "pp-dot";
}
function postureLayerLines() {
  const d = state.posture.data;
  const seal = deriveSeal();
  var wallV;
  if (seal.arm === "armed" && seal.freshness.current) wallV = "enforcing";
  else if (seal.arm === "armed") wallV = "evidence not current";
  // S5-P: honest coarse-only line - the coarse wall IS enforcing, the
  // fine-grained exclusive-egress stack is not live. Non-green (warn) below.
  else if (seal.arm === "coarse_only") wallV = "coarse-only (exclusive egress not live)";
  else if (seal.arm === "degraded") wallV = "degraded";
  else if (seal.arm === "locked_down") wallV = "locked down";
  else if (seal.arm) wallV = "not enforcing";
  else wallV = "unknown";
  const wallWarn = !(seal.arm === "armed" && seal.freshness.current);
  const pending = heldApprovalItems(null).length;
  const approvalsEvidence = approvalQueueEvidence();
  // Only a complete, readable queue without recognized or unknown holds can earn a clear Charter row.
  const approvalsValue = !sourceLoaded(HUB + "/inbox") || state.inboxRedacted ? "Unknown" : approvalsEvidence.earned ? "clear" :
    pending + (approvalsEvidence.full ? "+" : "") + " waiting" + (approvalsEvidence.unknown ? "; " + approvalsEvidence.unknownLine : "");
  return [
    { k: "What was evidenced", v: seal.freshness.what, warn: !seal.freshness.current, off: seal.freshness.state === "absent" },
    { k: "Evidence time", v: seal.freshness.detail, warn: !seal.freshness.current, off: seal.freshness.state === "absent" },
    { k: "Freshness window", v: seal.freshness.windowKnown ? "within " + seal.freshness.windowLabel : "unknown", warn: !seal.freshness.windowKnown },
    { k: "Castle Wall (boundary)", v: wallV, warn: wallWarn },
    // No read this page makes carries a Sentinel report, and a roster of
    // protected agents is not evidence that a Sentinel is watching them, so
    // this line is Unknown until a Sentinel report is part of a read.
    { k: "Sentinels watching agents", v: "Unknown", unknown: true },
    // Every value short of earned clear keeps the warning; unknown values retain the shared Unknown dot.
    { k: "Charter approvals", v: approvalsValue, warn: approvalsValue !== "clear" },
    // A Heralds layer that is configured but not active is not signing: it
    // reads "configured" with the warn dot, never the pass dot.
    { k: "Heralds (reputation)", v: !sourceLoaded("/api/sovereignty") || !d || !d.layers || !d.layers.l4 ? "Unknown" : d.layers.l4.status === "active" ? "signed" : "configured", warn: !sourceLoaded("/api/sovereignty") || !d || !d.layers || !d.layers.l4 || d.layers.l4.status !== "active" }
  ];
}

async function onAutoTriggerRecommendation(ruleId, action) {
  try {
    await autoTriggerApi(
      "/rules/" + encodeURIComponent(ruleId) + "/" + action + "-recommendation",
      { method: "POST", body: {} }
    );
    await refreshPanel(AUTO_TRIGGER);
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
    await refreshPanel(AUTO_TRIGGER);
    toast("Thresholds saved.", "info");
  } catch (e) {
    toast("Threshold save failed: " + (e && e.message ? e.message : "unknown"), "error");
  } finally {
    state.autoTrigger.savingRuleId = null;
    rerender();
  }
}

async function fetchAutoTriggerState(deadlineAt) {
  if (deadlineAt === undefined) deadlineAt = Date.now() + DASHBOARD_READ_DEADLINE_MS;
  const rules = await autoTriggerApi("/rules", undefined, deadlineAt);
  const list = rules.data.rules;
  state.autoTrigger.rules = list;
  const details = sourceRead(AUTO_TRIGGER + "/details");
  const detailsBackedOff = details.state === "state_FAILED" && Date.now() < details.nextReadAt;
  if (!detailsBackedOff) details.state = "state_LOADING";
  let detailFailed = false;
  const hydrated = [];
  for (let i = 0; i < list.length; i++) {
    try {
      if (detailsBackedOff || Date.now() >= deadlineAt) throw new Error("Rule details unavailable.");
      const detail = await autoTriggerApi("/rules/" + encodeURIComponent(list[i].rule_id), undefined, deadlineAt);
      if (!detail.data || !detail.data.rule || !Array.isArray(detail.data.rule.history)) throw new Error("Rule details unavailable.");
      hydrated.push(detail.data.rule);
    } catch (_) {
      detailFailed = true;
      hydrated.push(Object.assign({}, list[i], { detailUnavailable: true }));
    }
  }
  state.autoTrigger.rules = hydrated;
  if (detailFailed) { if (!detailsBackedOff) failSource(AUTO_TRIGGER + "/details", new Error("Rule details unavailable.")); }
  else { details.state = "state_LOADED"; details.failures = 0; details.nextReadAt = 0; }
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
  const label = agentControlLabel(action);
  try {
    const r = await api("/agents/" + encodeURIComponent(agentId) + "/" + action, { method: "POST", body: {} });
    if (r.data && r.data.status === "approval_pending") {
      toast("Approval pending. See inbox.", "info");
    } else {
      toast('"' + label + '" applied to ' + agentId, "info");
    }
    await fetchAll(true);
    rerender();
  } catch (e) {
    if (e.status === 422) {
      toast('Sanctuary cannot apply "' + label + '" for this agent.', "error");
    } else {
      toast('"' + label + '" failed. Try again.', "error");
    }
  }
}

function decisionNotAdmissible(ids) {
  // Invariant: a decision is sent only against a loaded inbox read in which every admitted id is still held; a
  // stale selection, a resolved row or a queue that could not be re-read sends nothing and says why.
  if (!sourceLoaded(HUB + "/inbox")) return "the queue has not been read since it last changed, so nothing was sent. Re-read the queue first.";
  const gone = ids.filter(function (id) { const item = state.inbox.find(function (i) { return i.item_id === id; }); return !item || item.resolved; });
  if (gone.length === 0) return "";
  return (ids.length === 1 ? "the request is no longer waiting in the loaded queue"
    : gone.length + " of the " + ids.length + " selected items " + (gone.length === 1 ? "is" : "are") + " no longer waiting in the loaded queue") + ", so nothing was sent.";
}
function state_NOTADMITTEDDecision(fields, reason) {
  // Nothing was sent, so no lock is taken; the retained result still tells the operator what did not happen.
  if (decisionInFlight()) return;
  const notSent = decisionVerb(fields.action) + " was not sent for " + fields.subject + ": " + reason;
  const current = state.approvals.result;
  if (current && current.status === "uncertain") {
    // Invariant: an unconfirmed result is replaced only by a decision that was sent; a later click that sends
    // nothing is noted on it (one slot, so repeated clicks cannot grow it) and the warning stays unclearable.
    current.notSent = "Your next " + notSent;
    announceDecision(current);
    renderFeedback();
    return;
  }
  state.approvals.result = Object.assign({ status: "not_sent", rule: null, refresh: "loaded", records: [] }, fields, { message: notSent });
  announceDecision(state.approvals.result);
  rerender();
}
async function onInboxAction(itemId, action) {
  // Invariant: a second decision is never admitted while one holds the lock, so a stale or repeated click
  // sends nothing and the retained result keeps naming the first request only.
  if (decisionInFlight()) return false;
  const fields = { kind: "item", action: action, itemId: itemId, ids: [itemId], subject: decisionSubject(itemId) };
  const blocked = decisionNotAdmissible([itemId]);
  if (blocked) { state_NOTADMITTEDDecision(fields, blocked); return false; }
  const result = state_ADMITTEDDecision(fields);
  let acknowledged = false;
  await runDecision(result, async function () {
    const outcome = await performInboxAction(itemId, action, result.subject);
    settleDecision(result, outcome.status, outcome.message);
    acknowledged = outcome.status === "acknowledged";
  });
  return acknowledged;
}

// ── Decision result: one retained outcome for every inbox decision ─────
// Every per-item and batch decision is admitted into state.approvals.result and settles there; the screens
// with decision controls render from it, and nothing else reports a decision. Named states, in order:
// state_ADMITTEDDecision, then settleDecision (acknowledged, refused or uncertain), then
// refreshAfterDecision, then state_SETTLINGDecision (the held layout), then state_RELEASEDDecision. The lock
// (state.approvals.lock) is the admitted result and is held through the refresh and the hold, so no new
// decision is taken against a list the last one has not re-read.
// Must match the reason and note text asserted in test/dashboard/v1_1/approval-decision-result.test.ts.
const DECISION_BUSY_REASON = "Another decision is being sent.";
const DECISION_REREAD_NOTE = "The queue could not be re-read after this decision, so this list may be out of date.";
const DECISION_UNCERTAIN_ADVICE = "The decision may or may not have been applied. Check the queue before deciding again.";
const DECISION_VERB = { approve: "Allow once", deny: "Deny", dismiss: "Dismiss", archive: "Archive", delete: "Delete", snooze: "Snooze" };
const DECISION_DONE = { approve: "Allowed once", deny: "Denied", dismiss: "Dismissed", archive: "Archived", delete: "Deleted", snooze: "Snoozed" };
const DECISION_REREAD_BUSY_REASON = "The queue is being re-read after a decision.";
// not_sent is client-side only: nothing reached the server, so it is neither a refusal (a 4xx) nor unconfirmed.
const DECISION_HEADLINE = { pending: "Sending your decision", acknowledged: "Decision taken", refused: "Decision refused", uncertain: "Decision unconfirmed", not_sent: "Decision not sent" };
const DECISION_UNCERTAIN_STAYS = "This result stays on screen until your next decision replaces it.";

function decisionInFlight() { return !!state.approvals.lock; }
function decisionVerb(action) { return DECISION_VERB[action] || action; }
function decisionDone(action) { return DECISION_DONE[action] || "Done"; }
function decisionSubject(itemId) {
  // Captured at admission: after the refresh the item may have left the served projection.
  const item = state.inbox.find(function (i) { return i.item_id === itemId; });
  // The category is an internal token (state_export); the operator reads it as words (state export).
  return (item ? approvalOperation(item).replace(/_/g, " ") + " by " + approvalAgentId(item) + " " : "") + "(request " + itemId + ")";
}
function decisionHeadline(result) {
  // A batch that was taken for some items and refused for others says so in its headline, never "taken" alone.
  if (result.status === "acknowledged" && result.records.some(function (rec) { return rec.status !== "acknowledged"; })) return "Decision partly taken";
  return DECISION_HEADLINE[result.status];
}
function endSentence(text) {
  const t = String(text || "").trim();
  return t ? (/[.!?]$/.test(t) ? t : t + ".") : "";
}
function announceDecision(result) {
  // The shell live region outlives every #main repaint, so an announcement is never lost to innerHTML replacement.
  const region = document.getElementById("decision-announcement");
  // The re-read note is part of the announcement, so a screen reader hears that the list may be stale.
  if (region) region.textContent = decisionHeadline(result) + ". " + result.message + (result.refresh === "unavailable" ? " " + DECISION_REREAD_NOTE : "") + (result.notSent ? " " + result.notSent : "");
}
function state_ADMITTEDDecision(fields) {
  // Invariant: the lock and the retained result are set together, so the paused controls and the status text
  // can never disagree about whether a decision is in flight.
  const result = Object.assign({ status: "pending", rule: null, refresh: "pending", records: [] }, fields);
  result.message = "Sending " + decisionVerb(result.action) + " for " + result.subject + ". Other decision controls are paused until the server answers.";
  state.approvals.lock = result;
  state.approvals.result = result;
  state.approvals.inFlightItemId = result.kind === "item" ? result.itemId : null;
  announceDecision(result);
  rerender();
  return result;
}
function settleDecision(result, status, message) {
  // Invariant: only the result holding the lock settles, and only once; a late or foreign settlement is
  // dropped, so the retained outcome always belongs to the admitted request.
  if (state.approvals.lock !== result || result.status !== "pending") return;
  result.status = status;
  result.message = message;
  announceDecision(result);
  rerender();
}
function extendDecision(result, text, rule) {
  if (state.approvals.lock !== result) return;
  result.message += " " + text;
  if (rule) result.rule = rule;
  announceDecision(result);
  rerender();
}
async function refreshAfterDecision(result) {
  // Invariant: the refresh never changes the status. A false return, an inbox read that did not load, or a
  // thrown repaint all become the plain-English re-read note, so an acknowledged decision cannot read as
  // refused and a stale list cannot read as current.
  let loaded = false;
  try { loaded = !!(await fetchAll(true)) && sourceLoaded(HUB + "/inbox"); }
  catch (e) { loaded = false; }
  if (state.approvals.lock !== result) return;
  result.refresh = loaded ? "loaded" : "unavailable";
  if (!loaded) announceDecision(result);
}
// Every layout change a decision causes is painted and held on screen with every decision control still
// disabled for DECISION_RELEASE_HOLD_MS before the lock is released. 300 ms = the upper end of a human
// visual reaction (200 to 300 ms), about 18 frames at 60 Hz, so the browser displays the held layout and a
// pointer already moving toward an old position lands on a disabled control, never on a moved live one.
const DECISION_RELEASE_HOLD_MS = 300;
// A background read can rewrite #main during a hold and restart it; after this many restarts the lock is
// released anyway, so a constantly changing screen cannot hold decisions paused for more than about 3 s.
const DECISION_RELEASE_MAX_HOLDS = 10;
async function state_SETTLINGDecision(result) {
  if (state.approvals.lock !== result) return;
  // Consent belongs to the selected request; a decision on another row leaves it in place.
  if (result.ids.indexOf(state.approvals.selectedId) >= 0) resetApprovalConsent();
  rerender();
  for (let hold = 0; hold < DECISION_RELEASE_MAX_HOLDS; hold++) {
    const writes = mainWriteCount;
    await new Promise(function (resolve) { setTimeout(resolve, DECISION_RELEASE_HOLD_MS); });
    if (state.approvals.lock !== result) return;
    // Invariant: the lock is released only after a full hold in which #main was not rewritten and a
    // repaint under the lock rewrites nothing, so the release repaint that follows changes only the
    // disabled and title attributes the lock adds. A repaint that throws ends the hold early; the release
    // repaints again, so a failure that persists still surfaces there.
    try { rerender(); } catch (e) { return; }
    if (mainWriteCount === writes) return;
  }
}
function state_RELEASEDDecision(result) {
  if (state.approvals.lock !== result) return;
  state.approvals.lock = null;
  state.approvals.inFlightItemId = null;
  rerender();
}
async function runDecision(result, send) {
  try {
    try { await send(); }
    catch (e) { settleDecision(result, "uncertain", "The server's answer could not be read (" + ((e && e.message) || "no detail") + "). " + DECISION_UNCERTAIN_ADVICE); }
    await refreshAfterDecision(result);
  } finally {
    // A repaint that throws before the hold still releases the lock, so decisions are never stranded paused.
    try { await state_SETTLINGDecision(result); }
    finally { state_RELEASEDDecision(result); }
  }
}
function decisionRefusedByServer(error) {
  // Invariant: only a 4xx answer proves the server refused; no answer, a 5xx or an unreadable body leaves the
  // decision uncertain, never refused and never acknowledged.
  const status = error && error.status;
  return typeof status === "number" && status >= 400 && status < 500;
}
function decisionOutcomeFromError(action, subject, error, item) {
  const http = error && typeof error.status === "number" ? " (HTTP " + error.status + ")" : "";
  const reason = (error && error.message) || "no answer from the server";
  if (decisionRefusedByServer(error)) {
    // A Tier 1 dismiss returns 409 (binding addendum 1.2) and the operator needs the next step, not the code; any
    // other 409 (for example a request another surface already resolved) keeps the server's own reason.
    const tier1Dismiss = error.status === 409 && action === "dismiss" && !!item && item.tier === "tier1";
    const detail = tier1Dismiss ? "Tier 1 items cannot be dismissed. Approve or deny instead." : endSentence(reason + http);
    // A refusal proves only that this decision was not applied; the queue below shows the request's current state.
    return { status: "refused", message: decisionVerb(action) + " was refused for " + subject + ": " + detail + " The decision was not applied." };
  }
  return { status: "uncertain", message: "The server did not confirm " + decisionVerb(action) + " for " + subject + " (" + reason + http + "). " + DECISION_UNCERTAIN_ADVICE };
}
function decisionAcknowledges(body, itemId) {
  // Invariant: an acknowledgement is only a 2xx body that names the admitted item as resolved; a 2xx that says
  // anything else is uncertain, so the screen never shows a decision the server did not confirm.
  const item = body && body.data && body.data.item;
  return !!(item && item.item_id === itemId && item.resolved === true);
}
function decisionRecordLine(item, action) {
  if (!item || (action !== "approve" && action !== "deny")) return "";
  return isCharterApprovalItem(item) ? " Recorded in your audit log." : " Marked decided in this inbox.";
}
// The host id must match decision-feedback-result in html.ts. Clear uses this
// patch directly so it does not replace route nodes or restore input focus.
let lastFeedbackHtml = null;
function renderFeedback() {
  const host = document.getElementById("decision-feedback-result");
  if (!host) return;
  const html = renderDecisionResult();
  // Compare emitted strings: DOM serialization changes quote entities and would replace focused Clear.
  if (lastFeedbackHtml !== html) {
    host.innerHTML = html;
    lastFeedbackHtml = html;
    // A changed result starts at F's origin so stale scrolling cannot hide its headline.
    const feedback = document.getElementById("feedback");
    if (feedback) feedback.scrollTop = 0;
  }
}
function renderDecisionResult() {
  const r = state.approvals.result;
  if (!r || r.cleared) return "";
  const note = r.refresh === "unavailable" ? " " + DECISION_REREAD_NOTE : r.status !== "pending" && r.refresh === "pending" ? " Re-reading the queue." : "";
  const records = r.records.length
    ? '<ul>' + r.records.map(function (rec) { return '<li>' + escHtml(rec.message) + '</li>'; }).join("") + '</ul>' : "";
  // Clear waits for the release: a result cannot leave the screen while its decision still holds the lock. An
  // unconfirmed result has no Clear at all: the operator owes the queue a check, and only the next decision
  // replaces the warning, so it cannot be dismissed unread.
  const stays = r.status === "uncertain" ? " " + DECISION_UNCERTAIN_STAYS + (r.notSent ? " " + r.notSent : "") : "";
  const clear = r.status === "pending" || r.status === "uncertain" ? "" : '<button class="btn btn-sm" data-action="decision-result-clear"' + approvalDecisionDisabled() + '>Clear</button>';
  return '<section class="decision-result" data-decision-status="' + r.status + '" aria-label="Decision result"><div><strong>' + decisionHeadline(r) + '</strong><p>' + escHtml(r.message + note + stays) + '</p>' + records + '</div>' + clear + '</section>';
}
function decisionFirstSentence(message) {
  const first = message.split(". ")[0];
  return first.slice(-1) === "." ? first : first + ".";
}
function renderDecisionBatchInline() {
  // The Evidence inbox repeats the last batch status beside its toolbar; full text stays in F.
  const r = state.approvals.result;
  if (!r || r.kind !== "batch") return "";
  // A partly taken batch keeps its whole short message here, so the refusal is not dropped with the second sentence.
  const line = r.status === "pending" ? "Sending " + decisionVerb(r.action) + " for " + r.ids.length + " selected item" + (r.ids.length === 1 ? "" : "s") + "."
    : r.status === "acknowledged" ? (decisionHeadline(r) === DECISION_HEADLINE.acknowledged ? decisionFirstSentence(r.message) : r.message)
    : r.status === "refused" ? "Refused."
    : r.status === "not_sent" ? "Not sent."
    : "Unconfirmed.";
  return '<p class="decision-inline" data-decision-status="' + r.status + '">' + escHtml(line) + '</p>';
}
function renderDecisionInline(item) {
  // The drawer and rows repeat the status for the decided request; full text stays in F.
  const r = state.approvals.result;
  if (!r || r.kind !== "item" || r.itemId !== item.item_id || item.resolved) return "";
  const line = r.status === "pending" ? "Sending " + decisionVerb(r.action) + "."
    : r.status === "acknowledged" ? decisionDone(r.action) + "."
    : r.status === "refused" ? "Refused."
    : r.status === "not_sent" ? "Not sent."
    : "Unconfirmed.";
  return '<p class="decision-inline" data-decision-status="' + r.status + '">' + escHtml(line) + '</p>';
}

// Below the stacking breakpoint the drawer sits under the whole queue, so selecting a row moves focus to
// the drawer's heading, which brings it into view. The target is a heading, not a decision control, so a
// stray key press after the click cannot decide.
function focusApprovalDrawer() {
  const main = document.getElementById("main");
  const head = main && main.querySelector('[data-approval-drawer-focus="1"]');
  if (head && typeof head.focus === "function") head.focus();
}
function focusTier1Cancel() {
  const main = document.getElementById("main");
  const cancel = main && main.querySelector('[data-action="approval-cancel-tier1-allow"]');
  if (cancel) cancel.focus();
}
function state_ARMEDTier1(itemId) {
  const item = state.inbox.find(function (i) { return i.item_id === itemId; });
  // Arming binds consent to the current unresolved Tier 1 request, never a stale or in-flight row.
  if (!item || item.resolved || item.tier !== "tier1" || state.approvals.selectedId !== itemId || decisionInFlight()) return;
  state.approvals.confirmingTier1Id = itemId;
  state.approvals.cancelledTier1Id = null;
  rerender();
  focusTier1Cancel();
}
function state_CANCELLEDTier1(itemId) {
  // An in-flight approval cannot be cancelled by a local control after submission.
  if (decisionInFlight()) return;
  // Cancellation disarms the request before repainting, so no subsequent Confirm can submit it.
  state.approvals.confirmingTier1Id = null;
  state.approvals.cancelledTier1Id = itemId;
  rerender();
  focusTier1Cancel();
}
async function state_APPROVINGAlwaysAllow(itemId) {
  const item = state.inbox.find(function (i) { return i.item_id === itemId; });
  // Only an explicitly checked, available standing option on this waiting item can begin promotion.
  if (!item || item.resolved || state.approvals.selectedId !== itemId || !state.approvals.alwaysAllow || !approvalStandingState(item).enabled || decisionInFlight()) return;
  const op = promotableOperation(item);
  const fields = { kind: "item", action: "approve", itemId: itemId, ids: [itemId], subject: decisionSubject(itemId), rule: "pending" };
  const blocked = decisionNotAdmissible([itemId]);
  if (blocked) { state_NOTADMITTEDDecision(fields, blocked); return; }
  const result = state_ADMITTEDDecision(fields);
  await runDecision(result, async function () {
    const outcome = await performInboxAction(itemId, "approve", result.subject);
    settleDecision(result, outcome.status, outcome.message);
    // Invariant: a refused or unconfirmed approval never grants a standing rule; only an acknowledged approval reaches compile.
    if (outcome.status !== "acknowledged") { extendDecision(result, "No standing rule was requested.", "refused"); return; }
    await state_PROMOTINGAlwaysAllow(result, itemId, op);
  });
}
async function state_PROMOTINGAlwaysAllow(result, itemId, op) {
  try {
    await onInboxPromote(itemId, op);
    extendDecision(result, "Standing rule added: agents may " + op.replace(/_/g, " ") + " without asking.", "added");
  } catch (e) {
    // The approval already succeeded, so a policy failure reports that partial outcome in words, never as a refused decision.
    extendDecision(result, e && e.ruleUncertain
      ? "The standing rule may not have been added: " + endSentence(e.message) + " Check the policy before relying on it."
      : "The standing rule was not added: " + endSentence((e && e.message) || "no detail"), e && e.ruleUncertain ? "uncertain" : "refused");
  }
}

async function performInboxAction(itemId, action, subject) {
  // WP-V1.2 reshape: direct-agent chat surface removed; the
  // pending-approval bookkeeping that previously synced with chat
  // session state is gone. Inbox approve/deny now is a clean inbox-only
  // resolve with the lockdown / exit-drill side effects preserved.
  // After approve, the inspect panel for the bound agent (if any) is
  // re-fetched via the route, not through state mutation.
  // Returns the settled outcome { status, message } for the caller's retained result; it never reports on its own.
  const item0 = state.inbox.find(function (x) { return x.item_id === itemId; });
  const boundAgentId = (item0 && item0.agent_id) || null;
  // The subject was captured at admission, so a row that moves during the request cannot rewrite the sentence.
  subject = subject || decisionSubject(itemId);
  let r;
  try {
    r = await api("/inbox/" + encodeURIComponent(itemId) + "/" + action, { method: "POST", body: {} });
  } catch (e) {
    return decisionOutcomeFromError(action, subject, e, item0);
  }
  if (!decisionAcknowledges(r, itemId)) {
    return { status: "uncertain", message: "The server answered but did not confirm " + decisionVerb(action) + " for " + subject + ". " + DECISION_UNCERTAIN_ADVICE };
  }
  const item = r.data.item;
  // payload is resolved here, before the lockdown and exit-drill branches, so both can
  // read it. Declaring it inside the lockdown if-block puts it out of scope for the
  // exit-drill branch and causes ReferenceError when the lockdown branch did not execute.
  const payload = item.resolution_payload || {};
  let effect = "";
  if (item && state.tier1.lockdown.inboxItemId === itemId) {
    if (action === "approve" && payload.outcome === "engaged") {
      state.tier1.lockdown.state = "engaged";
      effect = " Lockdown engaged.";
    } else if (action === "approve" && payload.outcome === "partial") {
      state.tier1.lockdown.state = "partial";
      effect = " Lockdown partially applied. At least one confined agent did not confirm a live stop.";
    } else {
      state.tier1.lockdown.state = "idle";
      if (action === "approve" && payload.outcome) {
        effect = " Lockdown outcome: " + payload.outcome + ".";
      }
    }
    renderTopbar();
  }
  if (state.exitDrill.inboxItemId === itemId && action === "approve") {
    // A7: read the real export values from resolution_payload rather than
    // a placeholder, so the dashboard renders the honest state_entry_count
    // and warnings. payload is in scope from the outer block above.
    // state_entry_count accepts only nonneg integers; fractional or negative
    // values are stored as null so the renderer omits the field rather than
    // displaying a nonsensical count.
    // warnings accepts only string entries; non-string entries are filtered
    // out before they reach escHtml so a future coercion change cannot widen
    // the injection surface.
    const rawCount = payload.state_entry_count;
    const secCount = (typeof rawCount === "number" && Number.isInteger(rawCount) && rawCount >= 0) ? rawCount : null;
    const rawWarnings = payload.warnings;
    const secWarnings = Array.isArray(rawWarnings)
      ? rawWarnings.filter(function(w) { return typeof w === "string"; })
      : undefined;
    state.exitDrill.bundleResult = {
      bundle_dir: payload.bundle_dir || "(see activity feed)",
      manifest_hash: payload.manifest_hash || "",
      artifact_count: typeof payload.artifact_count === "number" ? payload.artifact_count : 0,
      state_entry_count: secCount,
      warnings: (secWarnings && secWarnings.length > 0) ? secWarnings : undefined,
    };
  }
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
  return { status: "acknowledged", message: decisionDone(action) + ": " + subject + "." + decisionRecordLine(item0, action) + effect };
}

// Tunability UX: promote a pending approval into a durable standing rule.
// ONE guided action, backed by the REAL english-policy activator (no stub,
// no parallel path):
//   1. POST /api/policy/compile      -> deterministic "auto-allow <op>"
//                                        yields a tier3_add_operation draft.
//   2. POST /api/policy/drafts/:id/activate
//                                     -> the SAME EnglishPolicyActivator the
//                                        Xi-2 lifecycle uses. Server-side it
//                                        runs the conflict-detector AND the
//                                        #805 config-downgrade gate, so a
//                                        promotion that would WEAKEN posture
//                                        is refused (or requires the explicit
//                                        audited override) and every promote
//                                        emits an audit event.
// Both requests carry the operator bearer via policyApi(); a co-resident
// agent on loopback cannot promote by network position alone. This never
// creates an agent-readable policy path (AGENTS.md hard rule 7): the agent
// sees only the generic gate denial, never the promoted rule.
async function onInboxPromote(itemId, approvedOperation) {
  // The approved operation is captured before refetch because resolved Charter holds leave the projection.
  const op = approvedOperation;
  const compiled = await policyApi("/compile", {
    method: "POST",
    body: { english_text: "auto-allow " + op }
  });
  const draft = compiled && compiled.data && compiled.data.draft;
  // Missing draft evidence cannot authorize an activation.
  if (!draft || !draft.draft_id) throw new Error("Could not prepare a rule for " + op.replace(/_/g, " ") + ".");
  await activateStandingRule(draft.draft_id, op, false);
}

// Activate a compiled standing-rule draft. On a #805 posture-downgrade
// refusal (409), the operator is asked to explicitly confirm; ONLY then do
// we retry with the audited override. The gate is never bypassed silently:
// a refused promote either stops or goes through the operator-confirmed,
// server-audited (policy_force_downgrade_used) path.
// Resolves when the rule is activated and throws otherwise; the caller's retained result carries the outcome.
async function activateStandingRule(draftId, op, force) {
  const path = "/drafts/" + encodeURIComponent(draftId) + "/activate" +
    (force ? "?override_downgrade=true" : "");
  try {
    const activated = await policyApi(path, { method: "POST", body: {} });
    const status = activated && activated.data && typeof activated.data.status === "string" ? activated.data.status : null;
    if (status === "activated") {
      if (state.route === "policy") await loadPolicyView(true);
    } else if (status === null) {
      // Invariant: a 2xx whose body carries no readable status may already have changed the policy, so it is
      // unconfirmed, never a refusal; only an explicit non-activated status is a refusal.
      const unreadable = new Error("the activation answer could not be read.");
      unreadable.ruleUncertain = true;
      throw unreadable;
    } else {
      // Only an explicit activated result establishes that the standing rule was added.
      const notActivated = new Error("Rule not activated (" + status + ").");
      notActivated.ruleRefused = true;
      throw notActivated;
    }
  } catch (e) {
    if (e.status === 409 && !force) {
      // The downgrade gate refused because the rule would WEAKEN protection.
      // Confirm explicitly, then retry through the audited override path.
      const ok = window.confirm(
        "This rule would relax your protection so agents can " + op +
        " without asking you. This is recorded in your audit log. Add it anyway?");
      if (ok) return activateStandingRule(draftId, op, true);
      throw new Error("you chose to keep your protection.");
    }
    let error = e;
    if (e.status === 401 || e.status === 403) {
      error = new Error("Operator token required to change policy.");
    } else if (e.status === 503) {
      error = new Error("Policy engine is not configured on this fortress.");
    }
    // Invariant: a 4xx, a non-activated status, an unconfigured engine or the operator's own cancel is a definite
    // refusal; only an activate call with no readable answer may have taken effect, so only that is uncertain.
    error.ruleUncertain = e.ruleUncertain === true || !(e.ruleRefused || decisionRefusedByServer(e) || e.status === 503);
    throw error;
  }
}

async function onInboxBatchAction(action, until) {
  // The batch shares the one decision lock, so it never overlaps an individual decision or another batch.
  if (decisionInFlight()) return;
  const ids = Object.keys(state.inboxOps.selected).filter(function (id) { return state.inboxOps.selected[id]; });
  if (ids.length === 0) return;
  const fields = { kind: "batch", action: action, ids: ids, subject: ids.length + (ids.length === 1 ? " selected item" : " selected items") };
  const blocked = decisionNotAdmissible(ids);
  if (blocked) { state_NOTADMITTEDDecision(fields, blocked); return; }
  const result = state_ADMITTEDDecision(fields);
  await runDecision(result, async function () {
    if (action === "dismiss") {
      // Each id takes the same path as an individual decision under the batch's lock, and each outcome is kept.
      for (const id of ids) {
        const outcome = await performInboxAction(id, "dismiss", decisionSubject(id));
        result.records.push({ itemId: id, status: outcome.status, message: outcome.message });
      }
      settleBatchFromRecords(result);
    } else if (action === "archive" || action === "delete" || action === "snooze") {
      settleUnifiedBatch(result, ids, await submitUnifiedBatch(action, ids, until));
    } else {
      settleDecision(result, "refused", "Unsupported batch action " + action + "; nothing was sent.");
    }
    // Invariant: the selection clears only on an acknowledgement, so a refused or unconfirmed batch leaves the
    // operator's choice in place for a retry instead of looking done.
    if (result.status === "acknowledged") {
      state.inboxOps.selected = {};
      state.inboxOps.snoozeDialog = null;
    }
  });
}
function settleBatchFromRecords(result) {
  const counts = { acknowledged: 0, refused: 0, uncertain: 0 };
  result.records.forEach(function (rec) { counts[rec.status]++; });
  const total = result.records.length;
  // One unconfirmed item makes the batch unconfirmed; a batch with no acknowledgement is refused.
  const status = counts.uncertain ? "uncertain" : counts.acknowledged ? "acknowledged" : "refused";
  const message = decisionDone(result.action) + " " + counts.acknowledged + " of " + total + (total === 1 ? " item." : " items.") +
    (counts.refused ? " " + counts.refused + (counts.refused === 1 ? " was refused." : " were refused.") : "") +
    (counts.uncertain ? " " + counts.uncertain + (counts.uncertain === 1 ? " is unconfirmed. " : " are unconfirmed. ") + DECISION_UNCERTAIN_ADVICE : "");
  settleDecision(result, status, message);
}
async function submitUnifiedBatch(action, ids, until) {
  // The unified inbox keeps its own route and bearer handling; only the answer is now read before anything is reported.
  const res = await fetch("/api/inbox/unified/batch", {
    method: "POST",
    headers: Object.assign({ "Content-Type": "application/json" }, TOKEN ? { "Authorization": "Bearer " + TOKEN } : {}),
    body: JSON.stringify({ action: action, entry_ids: ids, until: until })
  });
  let body = null;
  try { body = await res.json(); } catch (e) { body = null; }
  return { ok: res.ok, status: res.status, body: body };
}
function settleUnifiedBatch(result, ids, answer) {
  const body = answer.body;
  if (!answer.ok) {
    const error = new Error(body && (body.error || body.detail) ? (body.error || body.detail) : "HTTP " + answer.status);
    error.status = answer.status;
    const outcome = decisionOutcomeFromError(result.action, result.subject, error);
    settleDecision(result, outcome.status, outcome.message);
    return;
  }
  const summary = body && body.ok === true && body.data && body.data.result;
  // Invariant: a batch is acknowledged only by a summary whose counts account for every id sent (must match
  // BatchActionResult in principal-policy/unified-inbox-bridge.ts); anything else is uncertain.
  const consistent = !!summary && summary.requested === ids.length && Number.isInteger(summary.affected) && summary.affected >= 0 &&
    Array.isArray(summary.missing) && summary.affected + summary.missing.length === summary.requested &&
    // Every missing entry must be one of the ids this batch sent, once; a foreign, duplicated or non-string entry
    // means the summary describes some other batch, so it confirms nothing about this one.
    summary.missing.every(function (id, index) { return typeof id === "string" && ids.indexOf(id) >= 0 && summary.missing.indexOf(id) === index; });
  if (!consistent) {
    settleDecision(result, "uncertain", "The server answered but did not confirm " + decisionVerb(result.action) + " for " + result.subject + ". " + DECISION_UNCERTAIN_ADVICE);
    return;
  }
  const missing = summary.missing.length;
  settleDecision(result, "acknowledged", decisionDone(result.action) + " " + summary.affected + " of " + ids.length + (ids.length === 1 ? " item." : " items.") +
    (missing ? " " + missing + (missing === 1 ? " was not found: " : " were not found: ") + summary.missing.map(String).join(", ") + "." : ""));
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

async function onEvidenceJsonExport() {
  try {
    // api() sends the exact /api/audit-log path unprefixed, so the read relies on the route's default limit.
    const body = await api("/api/audit-log", { method: "GET" });
    // Must match handleAuditLog in server/src/principal-policy/dashboard.ts: with an audit log it serves the
    // query result object ({ entries, total, integrity_findings }), and without one, or when the query fails,
    // an empty array. An empty answer of either shape is reported as no entries, never as a downloaded log.
    const entries = Array.isArray(body) ? body : body && typeof body === "object" && Array.isArray(body.entries) ? body.entries : null;
    if (!entries) throw new Error("the audit log read did not return entries");
    if (!entries.length) {
      toast("No audit entries were returned, so nothing was exported. The audit log read returns none both for an empty log and for a log it could not read.", "info");
      return;
    }
    // The file is the served answer unchanged, so the export carries the read's own total and findings with its entries.
    downloadJsonFile(body, "sanctuary-audit-log.json");
    toast("Downloaded the latest " + entries.length + (entries.length === 1 ? " audit entry" : " audit entries") + " as JSON (at most " + EVIDENCE_JSON_EXPORT_LIMIT + ").", "info");
  } catch (e) {
    toast("Audit log JSON export failed: " + (e && e.message ? e.message : "unknown"), "error");
  }
}

function downloadJsonFile(body, filename) {
  if (typeof Blob === "undefined" || typeof URL === "undefined" || !URL.createObjectURL) throw new Error("File downloads are not available in this browser.");
  const blob = new Blob([JSON.stringify(body, null, 2)], { type: "application/json" });
  const href = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = href;
  a.download = filename;
  a.style.display = "none";
  if (document.body && document.body.appendChild) document.body.appendChild(a);
  if (typeof a.click === "function") a.click();
  if (a.parentElement && a.parentElement.removeChild) a.parentElement.removeChild(a);
  if (URL.revokeObjectURL) URL.revokeObjectURL(href);
}

async function onDidWebCompromisedRotation() {
  if (state.recognition.rotating) return;
  state.recognition.rotating = true;
  rerender();
  try {
    await api("/recognition/did-web/rotate-compromised", { method: "POST", body: {} });
    await refreshPanel(HUB + "/recognition/did-web");
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
    await fetchAll(true);
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
  let reconnectAttempts = 0;
  const MAX_RECONNECT_ATTEMPTS = 5; // Five repair waves, then operator Retry only.
  function markStreamFrameReceived() {
    reconnectAttempts = 0;
  }
  async function open() {
    try {
      const sessionQuery = await createStreamSessionQuery();
      const url = credentialedReadUrl(STREAM + sessionQuery, "GET");
      es = new EventSource(url);
    } catch (e) { schedulePolling(); return; }
    es.addEventListener("snapshot", function () { markStreamFrameReceived(); /* v1.0 snapshot pass-through; v1.1 projects from hub. */ });
    es.addEventListener("activity", function (ev) {
      try {
        markStreamFrameReceived();
        const e = JSON.parse(ev.data);
        if (state.seenEventIds.has(e.entry_id)) return;
        state.seenEventIds.add(e.entry_id);
        if (String(e.display_template_id || "").indexOf("auto_trigger") >= 0 || String(e.display_template_id || "").indexOf("auto_action") >= 0) {
          void refreshAutoTriggerPanels();
        }
        const paths = [HUB + "/activity", HUB + "/activity?category=privacy", HUB + "/activity?category=handoff", "/api/honeypot", "/api/anomaly/findings", "/api/sentinels/findings"];
        void queueStreamRefresh(paths);
      } catch (err) { /* ignore */ }
    });
    es.addEventListener("inbox", function (ev) {
      try {
        markStreamFrameReceived();
        const item = JSON.parse(ev.data);
        if (isPendingApprovalsRedactedMarker(item)) {
          setInboxRedacted(item);
          void queueStreamRefresh([HUB + "/inbox", HUB + "/activity"]);
          return;
        }
        if (state.seenEventIds.has(item.item_id)) return;
        state.seenEventIds.add(item.item_id);
        void queueStreamRefresh([HUB + "/inbox", HUB + "/activity"]);
      } catch (err) { /* ignore */ }
    });
    es.addEventListener("agent_status", function (ev) {
      try {
        markStreamFrameReceived();
        JSON.parse(ev.data);
        void queueStreamRefresh([HUB + "/agents", HUB + "/activity"]);
      } catch (err) { /* ignore */ }
    });
    es.addEventListener("approval", function () { markStreamFrameReceived(); void queueStreamRefresh([HUB + "/inbox", HUB + "/activity", HUB + "/agents"]); });
    es.onerror = function () {
      try { es && es.close(); } catch (e) { /* ignore */ }
      es = null;
      // The bounded recovery budget ends visibly; no loaded clear stays current after give-up.
      if (reconnectTimer) return;
      if (reconnectAttempts >= MAX_RECONNECT_ATTEMPTS) { stopLiveUpdates(); return; }
      const delay = 1000 * Math.pow(2, reconnectAttempts++);
      reconnectTimer = setTimeout(async function () {
        reconnectTimer = null;
        await fetchAll(true);
        rerender();
        void open();
      }, delay);
    };
  }
  void open();
}

function stopLiveUpdates() {
  liveUpdatesStopped = true;
  clearSealFreshnessTimer();
  sourceReads.forEach(function (read) { read.revision++; read.state = "state_FAILED"; read.error = "Live updates stopped. Retry to resume."; });
  // Every read is now failed, so no findings snapshot is current: the selection closes, as a failed findings read
  // closes it, and a restart cannot reopen it.
  state.mfp.findingId = null;
  rerender();
}

// Polling fallback compiled-in but not user-facing. Activated by build-time
// flag (window.__sanctuaryDashboardPolling__ = true) or when EventSource
// is unavailable.
let pollingStarted = false;
function schedulePolling() {
  if (pollingStarted) return;
  pollingStarted = true;
  let failedWaves = 0;
  const MAX_POLL_ATTEMPTS = 5; // Bound automatic recovery work; panel Retry remains available.
  function poll() {
    if (failedWaves >= MAX_POLL_ATTEMPTS) { stopLiveUpdates(); return; }
    setTimeout(async function () {
      const refreshed = await fetchAll(true);
      failedWaves = refreshed ? 0 : failedWaves + 1;
      rerender();
      poll();
    }, Math.min(READ_BACKOFF_MAX_MS, DASHBOARD_READ_DEADLINE_MS * Math.pow(2, failedWaves)));
  }
  poll();
}

// WP-V1.2 reshape: the F9 polling loop for direct-agent chat history
// was removed with the chat surface. The inspect panel is fetched
// lazily on click and is read-only; no streaming updates required.

// ── Rerender ───────────────────────────────────────────────────────────
function rerender() {
  renderTopbar();
  renderMain();
  renderFortress();
  renderShellChrome();
}

// ── Wire-up: events ────────────────────────────────────────────────────
function bindHashRoute() {
  function fromHash() {
    const h = (location.hash || "#posture").slice(1);
    const previousUrl = evidenceReadUrl();
    applyEvidenceHashFilters(h);
    if (evidenceReadUrl() !== previousUrl) { state.evidence.selectedIndex = 0; queueEvidenceRead(); }
    if (h.split("?")[0] === "agents") {
      const requestedState = new URLSearchParams(h.split("?")[1] || "").get("state") || "";
      // The select and filter share one allowed set so an unknown hash cannot silently hide rows.
      state.agentInventory.status = AGENT_STATE_FILTERS.some(function (option) { return option[0] === requestedState; }) ? requestedState : "";
      state.agentInventory.page = 0;
    }
    setRoute(h.split("?")[0] || "posture");
  }
  window.addEventListener("hashchange", fromHash);
  fromHash();
}

// Slice 2 keyboard: Ctrl-K (Cmd-K on a Mac) focuses the top-bar search;
// Escape closes, in order, the search results, an open top-bar popover, and
// the Talk panel.
document.addEventListener("keydown", function (ev) {
  // With no focused control, native page keys must target the workspace scroller.
  if (document.activeElement === document.body && !ev.ctrlKey && !ev.metaKey && !ev.altKey &&
      ["PageDown", "PageUp", "Home", "End", "ArrowDown", "ArrowUp", " "].includes(ev.key)) {
    const main = document.getElementById("main");
    if (main && typeof main.focus === "function") main.focus({ preventScroll: true });
  }
  if ((ev.ctrlKey || ev.metaKey) && !ev.altKey && String(ev.key || "").toLowerCase() === "k") {
    const input = document.getElementById("global-search");
    if (input && typeof input.focus === "function") {
      ev.preventDefault();
      input.focus();
      if (typeof input.select === "function") input.select();
      if (state.search.query) { state.search.open = true; renderSearchResults(); }
    }
    return;
  }
  if (ev.key !== "Escape") return;
  if (state.search.open) { state.search.open = false; renderSearchResults(); return; }
  if (state.agentScope.switcherOpen || state.posture.sealOpen) {
    state.agentScope.switcherOpen = false;
    state.posture.sealOpen = false;
    renderTopbar();
    return;
  }
  if (state.talk.open) {
    state.talk.open = false;
    renderShellChrome();
    const talkBtn = document.getElementById("btn-talk");
    if (talkBtn && typeof talkBtn.focus === "function") talkBtn.focus();
  }
});

document.addEventListener("visibilitychange", function () {
  if (document.visibilityState === "visible") rerender();
});

document.addEventListener("compositionstart", function (ev) {
  if (ev.target instanceof HTMLInputElement && ev.target.getAttribute("data-action") === "concierge-input") talkComposing = true;
});
document.addEventListener("compositionend", function (ev) {
  if (ev.target instanceof HTMLInputElement && ev.target.getAttribute("data-action") === "concierge-input") talkComposing = false;
});
document.addEventListener("keydown", function (ev) {
  if (ev.key !== "Enter") return;
  if (!(ev.target instanceof HTMLInputElement) || ev.target.getAttribute("data-action") !== "concierge-input") return;
  if (ev.isComposing || talkComposing || ev.keyCode === 229) ev.preventDefault();
});
document.addEventListener("submit", function (ev) {
  const form = ev.target;
  if (!(form instanceof HTMLFormElement) || form.getAttribute("data-action") !== "concierge-submit") return;
  ev.preventDefault();
  if (!talkComposing) void onConciergeSend();
});

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
  // Slice 2: the search results close on any click outside the search box,
  // and on any click on a result. A result that links to the route already
  // showing (an approval hit from #approvals, an evidence hit from
  // #activity) assigns an unchanged hash, so no hashchange fires; the close
  // here is explicit for that reason, not left to the route change.
  if (state.search.open && (!rawTgt.closest("[data-search]") || rawTgt.closest("#search-results a"))) {
    state.search.open = false;
    renderSearchResults();
  }
  if (!tgt) return;
  const action = tgt.getAttribute("data-action");
  if (action === "retry-panel") return void retryPanel(tgt.getAttribute("data-read"));
  if (!action) return;
  if (action === "mfp-page") {
    const key = tgt.getAttribute("data-list");
    if (Object.prototype.hasOwnProperty.call(state.mfp.pages, key)) {
      const step = tgt.getAttribute("data-step") === "-1" ? -1 : 1;
      // mfpPage clamps against this list's served length when it renders, including control lists beyond 500.
      state.mfp.pages[key] = Math.max(0, state.mfp.pages[key] + step);
      rerender();
    }
    return;
  }
  if (action === "mfp-finding" || action === "mfp-finding-close") {
    state.mfp.findingId = action === "mfp-finding" ? tgt.getAttribute("data-finding-id") : null;
    rerender(); return;
  }
  const itemId = tgt.getAttribute("data-item-id");
  const agentId = tgt.getAttribute("data-agent-id");
  const ruleId = tgt.getAttribute("data-rule-id");
  const route = tgt.getAttribute("data-route");
  const intelSurface = tgt.getAttribute("data-intel-surface");
  const intelSubstrate = tgt.getAttribute("data-intel-substrate");
  const intelLocalModel = tgt.getAttribute("data-intel-local-model");
  const intelFrontierProvider = tgt.getAttribute("data-intel-frontier-provider");
  if (action === "lockdown") return void onLockdownClick();
  // Slice 2: Talk opens the concierge as a panel beside the current screen.
  if (action === "talk-toggle") {
    if (state.route === "dashboard") return;
    state.talk.open = !state.talk.open;
    return renderShellChrome();
  }
  if (action === "talk-close") {
    state.talk.open = false;
    renderShellChrome();
    const talkBtn = document.getElementById("btn-talk");
    if (talkBtn && typeof talkBtn.focus === "function") talkBtn.focus();
    return;
  }
  // The full-page link keeps its href navigation; the panel closes with it.
  if (action === "talk-open-full") { state.talk.open = false; return; }
  if (action === "theme-toggle") {
    const isDark = document.documentElement.getAttribute("data-theme") === "dark";
    const next = isDark ? "light" : "dark";
    sessionStorage.setItem(THEME_KEY, next);
    applyTheme(next);
    return;
  }
  // S2 (2026-07-18): copy the full machine id to the clipboard. The top bar
  // shows a human machine name with the id demoted to a short mono chip; the
  // chip copies the untruncated id so operators can paste it verbatim.
  // S3 nit: the handler previously did nothing at all when navigator.clipboard
  // was unavailable, which is the common case rather than the rare one -- the
  // async Clipboard API needs a secure context, so reaching this dashboard over
  // plain http on a LAN address (http://192.168.x.x:3501) silently disabled the
  // chip while it still looked clickable. It now falls back to the legacy
  // execCommand path and, failing that, tells the operator to copy manually.
  // A copy affordance that quietly does nothing is worse than one that admits
  // it cannot: never a silent no-op.
  if (action === "copy-fortress-id") {
    const id = tgt.getAttribute("data-fortress-id") || "";
    if (!id) return;
    if (navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(id).then(
        function () { toast("Machine id copied.", "info"); },
        function () { if (!copyViaExecCommand(id)) toast("Could not copy. Select the id and copy it manually.", "error"); }
      );
      return;
    }
    if (!copyViaExecCommand(id)) {
      toast("Copying needs a secure connection. Select the id and copy it manually.", "error");
    }
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
    state.approvals.filters.agent = "";
    resetApprovalConsent();
    state.agentScope.switcherOpen = false;
    // Scope the queue + ambient posture to the chosen agent and repaint
    // everything that shows them: since slice 2 the queue renders on the
    // Approvals screen (main) and its scoped count on the rail pill and the
    // bell (shell chrome), so repainting only the top bar and the fortress
    // column left a stale, unscoped count. The conversation spine stays
    // fortress-wide in wave 1 (the concierge reads fortress state);
    // per-agent conversation scoping is a wave-2 follow-up.
    rerender();
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
  if (action === "intel-reload") { return void refreshPanel(HUB + "/intelligence"); }
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
      if (talkOwner && talkOwner.input.isConnected) talkOwner.input.value = found.query;
      return void onConciergeSend();
    }
    return;
  }
  if (action === "agent-tab") {
    const tab = tgt.getAttribute("data-tab");
    if (AGENT_TABS.includes(tab)) state.agentTab = tab;
    return rerender();
  }
  if (action === "agents-page") {
    const page = Number(tgt.getAttribute("data-page"));
    if (Number.isSafeInteger(page) && page >= 0) state.agentInventory.page = page;
    return rerender();
  }
  if (action === "agent-reach-refresh" && agentId) return void loadAgentReach(agentId);
  // WP-V1.2 reshape click-to-inspect handler ────────────────────────
  if (action === "agent-inspect-open" && agentId) return void onAgentInspectOpen(agentId);
  if (action === "exit-export-start") return void onExitExportStart();
  if (action === "evidence-select") {
    const index = Number(tgt.getAttribute("data-evidence-index"));
    if (Number.isInteger(index) && index >= 0 && index < EVIDENCE_PAGE_SIZE) state.evidence.selectedIndex = index;
    return rerender();
  }
  if (action === "evidence-export-json") return void onEvidenceJsonExport();
  if (action === "did-web-rotate-compromised") return void onDidWebCompromisedRotation();
  if (action === "exit-mark-verified") { state.exitDrill.step = 5; return rerender(); }
  if (action === "open-agent" && agentId) {
    if (ev && typeof ev.preventDefault === "function") ev.preventDefault();
    state.selectedAgentId = agentId;
    state.agentTab = "overview";
    void loadAgentReach(agentId);
    // Close the search results here: a hit opened from #agent-detail assigns
    // the hash it already has, so no hashchange fires to close them or to
    // render the newly selected agent; setRoute does both explicitly.
    state.search.open = false;
    renderSearchResults();
    if (location.hash !== "#agent-detail") location.hash = "agent-detail";
    else setRoute("agent-detail");
    return;
  }
  // Click-to-inspect from the fortress-column agent rows (PR #100
  // sidebar wire-up): navigate to the agent-detail view AND fire the
  // synchronous /inspect/open route so the panel renders already-loaded.
  // Same component as the Agents-view CTA; the optimistic "Opening..."
  // pane (openingAgentId) renders during the round-trip.
  if (action === "agent-row-inspect-open" && agentId) {
    openAgentRowInspect(agentId);
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
  if (action === "set-route" && route) {
    state.agentScope.switcherOpen = false;
    const nextHash = "#" + route;
    // Hashchange is the route owner; direct setRoute runs only when the hash
    // is already there, so a click starts one probe wave.
    if (location.hash !== nextHash) location.hash = nextHash;
    else setRoute(route);
    renderTopbar();
    return;
  }
  if (action === "machines-recheck") { void probeFleetMachines(); return; }
  if (action === "show-details" && itemId) {
    const i = state.inbox.find(function (x) { return x.item_id === itemId; });
    if (i) toast("Template: " + i.display_template_id);
    return;
  }
  if (action === "approval-select" && itemId) {
    state.approvals.selectedId = itemId;
    resetApprovalConsent();
    rerender();
    return focusApprovalDrawer();
  }
  if (action === "decision-result-clear") {
    // F hides a result only through its own control, never while its decision holds the lock, and an
    // unconfirmed result has no such control: a stray click on a stale button must not clear it either.
    if (decisionInFlight() || (state.approvals.result && state.approvals.result.status === "uncertain")) return;
    const clearHadFocus = document.activeElement === tgt;
    // Clear hides only F; keep status echoes stable on background redraws until the next decision.
    if (state.approvals.result) state.approvals.result.cleared = true;
    renderFeedback();
    // Removing focused Clear must retain the keyboard user's place without moving decision controls.
    if (clearHadFocus) document.getElementById("feedback").focus({ preventScroll: true });
    return;
  }
  if (action === "approval-always-allow") {
    // An in-flight decision retains its consent state until settlement.
    if (decisionInFlight()) return;
    state.approvals.alwaysAllow = !!tgt.checked;
    state.approvals.confirmingTier1Id = null;
    return rerender();
  }
  if (action === "approval-start-tier1-allow" && itemId) return state_ARMEDTier1(itemId);
  if (action === "approval-cancel-tier1-allow" && itemId) return state_CANCELLEDTier1(itemId);
  if (action === "approval-confirm-tier1-allow" && itemId) {
    // Only an armed confirmation for the selected request may submit a Tier 1 approval.
    if (state.approvals.confirmingTier1Id !== itemId || state.approvals.selectedId !== itemId) return;
    return void onInboxAction(itemId, "approve");
  }
  if (action === "inbox-select" && itemId) {
    // A batch in flight owns its selection until it settles; a tick under that lock would rewrite what a refusal keeps.
    if (batchSelectionLocked()) return;
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
    // Invariant: the row menu replaces the selection, so under the lock it is refused like every other decision
    // control; otherwise a refused batch would report against a selection the operator no longer sees.
    if (decisionInFlight()) return;
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
    return void onInboxBatchAction("snooze", raw ? new Date(raw).toISOString() : new Date(Date.now() + MS_PER_HOUR).toISOString());
  }
  // Tunability UX: promote-to-standing-rule. Intercepted BEFORE the generic
  // inbox-* dispatcher: approve the request first, then compile and activate
  // the standing rule through the existing operator-gated policyApi path.
  if (action === "inbox-promote" && itemId) {
    return void state_APPROVINGAlwaysAllow(itemId);
  }
  if (action.indexOf("inbox-") === 0 && itemId) {
    const sub = action.slice("inbox-".length);
    // Only a loaded read after the decision may remove a tile or change its queue count.
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
  openAgentRowInspect(agentId);
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
  } else if (action === "global-search") {
    // Search results re-render alone, so typing never rewrites the input.
    state.search.query = tgt.value;
    state.search.open = true;
    renderSearchResults();
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
  } else if (action === "evidence-filter-query") {
    setEvidenceFilter("query", tgt.value);
  } else if (action === "evidence-filter-agent") {
    setEvidenceFilter("agent", tgt.value);
  } else if (action === "evidence-filter-event") {
    setEvidenceFilter("event", tgt.value);
  } else if (action === "evidence-filter-from") {
    setEvidenceFilter("from", evidenceFromDate(tgt.value));
  }
});

document.addEventListener("change", function (ev) {
  const tgt = ev.target;
  if (!(tgt instanceof Element) || tgt.tagName !== "SELECT") return;
  const action = tgt.getAttribute("data-action");
  if (["agents-state", "agents-harness", "agents-sort"].includes(action)) {
    const field = { "agents-state": "status", "agents-harness": "harness", "agents-sort": "sort" }[action];
    state.agentInventory[field] = tgt.value;
    state.agentInventory.page = 0;
    return rerender();
  }
  if (action === "time-range") {
    // Not saved with the inbox preferences. It narrows the loaded inbox list on the client, and it is
    // sent with the Evidence entries read as that read's window start, so the table, its counts and the
    // integrity strip's entry total cover the range the control shows.
    const previousUrl = evidenceReadUrl();
    state.timeRange = Object.prototype.hasOwnProperty.call(TIME_RANGE_LABEL, tgt.value) ? tgt.value : "all";
    rerender();
    if (evidenceReadUrl() !== previousUrl) { state.evidence.selectedIndex = 0; queueEvidenceRead(); }
    return;
  }
  if (action === "inbox-filter-source") state.inboxOps.filters.source = tgt.value;
  else if (action === "inbox-filter-severity") state.inboxOps.filters.severity = tgt.value;
  else if (action === "inbox-filter-agent") state.inboxOps.filters.agent = tgt.value;
  else if (action === "evidence-filter-layer") return setEvidenceFilter("layer", tgt.value);
  else if (action === "evidence-filter-result") return setEvidenceFilter("result", tgt.value);
  else if (action === "approval-filter-state") state.approvals.filters.state = tgt.value === "waiting" || tgt.value === "decided" ? tgt.value : "all";
  else if (action === "approval-filter-agent") state.approvals.filters.agent = tgt.value;
  else if (action === "approval-filter-tier") state.approvals.filters.tier = tgt.value === "tier1" || tgt.value === "tier2" ? tgt.value : "both";
  else if (action === "approval-filter-category") state.approvals.filters.category = tgt.value;
  else return;
  if (action.indexOf("inbox-filter-") === 0) saveInboxPrefs();
  if (action.indexOf("approval-filter-") === 0) {
    state.approvals.selectedId = null;
    resetApprovalConsent();
  }
  rerender();
});

// v1.1.7: chat composer submit handler removed alongside the half-built
// chat surface (Finding EE). Direct concierge chat ships in v1.2; until
// then the dashboard view renders a static welcome card with no form
// inputs that could be confused for a working command surface.

// Theme: the ratified console is DARK BY DEFAULT (2026-10-13). An explicit
// operator choice (sessionStorage, written by the top-bar toggle) wins; with
// no explicit choice the page is dark whatever the OS reports. Must match
// THEME_BOOTSTRAP_SCRIPT in server/src/dashboard/design-tokens.ts, which
// applies the same rule in the head before first paint: same key, and "no
// explicit choice" resolves to dark in both.
const THEME_KEY = "sanctuary-v11-theme";
function applyTheme(theme) {
  if (theme === "dark") document.documentElement.setAttribute("data-theme", "dark");
  else document.documentElement.removeAttribute("data-theme");
}
const explicitTheme = sessionStorage.getItem(THEME_KEY);
const mq = window.matchMedia ? window.matchMedia("(prefers-color-scheme: dark)") : null;
applyTheme(explicitTheme === "light" ? "light" : "dark");
if (mq) mq.addEventListener("change", function () {
  // An OS appearance change applies only when the operator has made no
  // explicit choice, and the no-choice state is dark: it no longer follows
  // the OS to light.
  if (sessionStorage.getItem(THEME_KEY)) return;
  applyTheme("dark");
});

// Boot.
void loadPanel(panelJobs[0]);
void fetchAll();
bindHashRoute();
connectStream();
`;
