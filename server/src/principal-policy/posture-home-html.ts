/**
 * Sovereignty Posture Dashboard - Phase 1 home HTML.
 *
 * A single self-contained page that renders the posture board: the banner, the
 * agent grid (wrapped + detected-unwrapped amber cards), the approvals inbox,
 * "today's story," anomaly findings, and the Castle Wall panel - with a
 * persistent data-custody footer. CISO-first ordering: security and
 * data-sovereignty affordances lead; agent-welfare content is deliberately
 * absent from Home (it lives in the agent drill-down's secondary section).
 *
 * Live refresh (Phase 2, additive): the page subscribes to the SSE stream at
 * `/api/posture/stream`, which pushes the SAME `buildHome` payload on a cadence
 * plus a heartbeat. On a drop, error, or staleness the page reconnects (capped
 * backoff) AND falls back to polling, so it keeps working exactly as before if
 * SSE never connects (progressive enhancement). The connection indicator is the
 * honesty surface (#617): "Live" (green dot) is shown ONLY when a fresh frame
 * arrived inside the staleness window; any drop or silence flips it to
 * "Reconnecting…" (amber) while keeping a "last updated <time>" so a stale view
 * can never be mistaken for a live green-all-well.
 *
 * The page authenticates via the same loopback/bearer model as the rest of the
 * dashboard. Every tile drills to evidence: counts link into the audit feed,
 * the wall panel exposes its evidence basis, reach links to the per-agent
 * reach endpoint. "Never fake green" is enforced in the renderer - the banner
 * shows ARMED green only when `arm_state === "armed"`; `unknown` is amber and
 * `degraded` is red.
 *
 * Returns a string so the dashboard can serve it directly (mirrors
 * `generateDashboardHTML`).
 */

import type { FeatureHealthStatus } from "./feature-health.js";
import type { CustodyState } from "./posture.js";
import {
  AGENT_PILL_FN_SOURCE,
  EVIDENCE_SPINE_CSS,
  POSTURE_ROOT_TOKENS_CSS,
  REL_TIME_FN_SOURCE,
  STATUS_PILL_CSS,
  THEME_BOOTSTRAP_SCRIPT,
} from "./posture-html-shared.js";

/**
 * "Never fake green" + "never imply anonymity" for the Query-privacy section
 * (Phase 2), as a PURE mapper so the honesty contract is unit-testable without a
 * browser. The status color model is the same one the feature-health endpoint
 * emits: GREEN is earned ONLY by `active` (real strip/rewrite evidence in the
 * window). `unconfirmed` and `unknown` are amber and MUST NEVER render green -
 * that includes the Tier B PII-rewrite row, which is `unconfirmed` until the
 * deferred rewrite emitter wiring lands. `fault` is red.
 *
 * The client-side `queryPrivacyPill` below embeds the exact same mapping (the
 * page is a self-contained string); this exported function is the canonical
 * definition the renderer mirrors and the tests pin.
 */
export function queryPrivacyPill(status: FeatureHealthStatus): {
  cls: "green" | "amber" | "red";
  label: string;
} {
  switch (status) {
    case "active":
      return { cls: "green", label: "active" };
    case "fault":
      return { cls: "red", label: "fault" };
    case "unconfirmed":
      return { cls: "amber", label: "unconfirmed" };
    case "unknown":
    default:
      // Fail closed: any unrecognized status is non-green by construction.
      return { cls: "amber", label: "unconfirmed" };
  }
}

/**
 * "Never fake green" for the feature-health panel, as a PURE mapper so the
 * honesty contract is unit-testable without a browser. The color model is the
 * one the feature-health endpoint already emits (`feature-health.ts`): GREEN is
 * earned ONLY by `active` (fresh evidence for self-reporting features, or real
 * activity for event-driven ones). `fault` is red. `unconfirmed` and `unknown`
 * are amber and MUST NEVER render green - that is the #617/#634 invariant the
 * endpoint enforces and the surface must not weaken.
 *
 * The client-side `renderFeatureHealth` function below embeds the exact same
 * mapping (the page is a self-contained string); this exported function is the
 * canonical definition the renderer mirrors and the tests pin, so a future edit
 * that introduced a green path for a non-`active` status would fail a test.
 */
export function featureHealthPill(status: FeatureHealthStatus): {
  cls: "green" | "amber" | "red";
  label: string;
} {
  switch (status) {
    case "active":
      return { cls: "green", label: "active" };
    case "fault":
      return { cls: "red", label: "fault" };
    case "unconfirmed":
      return { cls: "amber", label: "unconfirmed" };
    // S5-P (design §6): the DISTINCT non-green coarse-only chip. The coarse
    // wall is enforcing but a fine-grained-provisioned agent's exclusive-egress
    // stack is not live. Amber (not red: the coarse wall IS protecting), with
    // its own label so it is never mistaken for a vague "unconfirmed".
    case "coarse_only":
      return { cls: "amber", label: "coarse-only" };
    case "unknown":
    default:
      // Fail closed: any unrecognized status is non-green by construction.
      return { cls: "amber", label: "unknown" };
  }
}

/**
 * "Never fake green" for the Custody tile (Slice 3), as a PURE mapper so the
 * honesty contract is unit-testable without a browser. The custody tile is
 * GREEN never: the facts that would prove custody HEALTH (two-factor floor,
 * envelope MAC, anti-rollback epoch, pinned-key non-extraction) live under the
 * transient master at boot and are not re-derivable from the dashboard's
 * request-time view. So `unconfirmed` is amber (the honest default), `damaged`
 * is red (earned by fresh negative evidence), and there is no green branch - a
 * future edit that introduced one would fail a test.
 *
 * The client-side `custodyPill` below embeds the exact same mapping (the page is
 * a self-contained string); this exported function is the canonical definition
 * the renderer mirrors and the tests pin.
 */
export function custodyPill(state: CustodyState): {
  cls: "amber" | "red";
  label: string;
} {
  switch (state) {
    case "damaged":
      return { cls: "red", label: "damaged" };
    case "unconfirmed":
    default:
      // Fail closed: never green. Custody health is unprovable from this view.
      return { cls: "amber", label: "unconfirmed" };
  }
}

export function renderPostureHomeHTML(): string {
  // Inline everything (no external assets) so the page works on a locked-down
  // loopback dashboard with a strict CSP and no network egress.
  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width, initial-scale=1" />
<title>Sanctuary - Security Posture</title>
<script>${THEME_BOOTSTRAP_SCRIPT}</script>
<style>
  ${POSTURE_ROOT_TOKENS_CSS}
  * { box-sizing: border-box; }
  body {
    margin: 0; background: var(--paper); color: var(--ink);
    font: 14px/1.5 -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
  }
  header { padding: 16px 24px; border-bottom: 1px solid var(--rule); }
  .header-row { display: flex; align-items: flex-start; gap: 16px; }
  .header-row .header-titles { flex: 1; min-width: 0; }
  h1 { font-size: 16px; margin: 0; font-weight: 600; letter-spacing: .2px; }
  .sub { color: var(--ink-3); font-size: 12px; margin-top: 2px; }
  .fleet-link {
    flex: none; align-self: center; color: var(--indigo); font-size: 13px;
    padding: 6px 12px; border: 1px solid var(--rule); border-radius: 6px;
    background: var(--surface); white-space: nowrap;
  }
  .fleet-link:hover { border-color: var(--indigo); text-decoration: none; }
  main { padding: 20px 24px; max-width: 1100px; margin: 0 auto; }
  /*
    S3: the at-a-glance row is a grid, not a wrapping flex row. With the
    evidence spine each tile is taller and carries a footer, and flex-wrap left
    the last tile orphaned on its own row at common widths. auto-fit keeps the
    six tiles on an even baseline and lets them reflow to 3+3 or 2+2+2 rather
    than 5+1.
  */
  .banner {
    display: grid; grid-template-columns: repeat(2, 1fr);
    gap: 14px 18px; padding: 16px;
    background: var(--surface); border: 1px solid var(--rule); border-radius: 10px;
    margin-bottom: 20px;
  }
  @media (min-width: 780px) { .banner { grid-template-columns: repeat(3, 1fr); } }
  .stat { display: flex; flex-direction: column; min-width: 0; }
  .stat .v { font-size: 22px; font-weight: 700; font-variant-numeric: tabular-nums; }
  .stat .l { color: var(--ink-3); font-size: 12px; text-transform: uppercase; letter-spacing: .4px; }
  ${STATUS_PILL_CSS}
  ${EVIDENCE_SPINE_CSS}
  section { margin-bottom: 24px; }
  section > h2 { font-size: 13px; text-transform: uppercase; letter-spacing: .5px; color: var(--ink-3); margin: 0 0 10px; }
  .grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(260px, 1fr)); gap: 12px; }
  .card {
    background: var(--surface); border: 1px solid var(--rule); border-radius: 10px;
    padding: 14px;
  }
  .card.amber { border-color: var(--ochre); }
  .card h3 { margin: 0 0 4px; font-size: 14px; }
  .card .meta { color: var(--ink-3); font-size: 12px; }
  .reach { margin-top: 8px; font-size: 12px; color: var(--ink-3); }
  a { color: var(--indigo); text-decoration: none; }
  a:hover { text-decoration: underline; }
  .panel { background: var(--surface); border: 1px solid var(--rule); border-radius: 10px; padding: 16px; }
  .story-line { margin: 4px 0; }
  .fh-row { display: flex; align-items: baseline; gap: 8px; padding: 6px 0; border-bottom: 1px solid var(--rule); }
  .fh-row:last-child { border-bottom: 0; }
  .fh-row .name { flex: 1; }
  .fh-row .why { color: var(--ink-3); font-size: 12px; }
  .fh-note { color: var(--ink-3); font-size: 11px; margin-top: 10px; }
  .approval-row {
    display: flex; align-items: flex-start; justify-content: space-between; gap: 12px;
    padding: 10px 0; border-bottom: 1px solid var(--rule);
  }
  .approval-row:last-child { border-bottom: 0; }
  .approval-main { min-width: 0; }
  .approval-title { font-weight: 600; }
  .approval-detail { color: var(--ink-3); font-size: 12px; margin-top: 2px; }
  .approval-actions { display: flex; gap: 8px; flex: none; }
  .approval-actions button {
    border: 1px solid var(--rule); border-radius: 6px; padding: 5px 10px;
    color: var(--ink); background: var(--surface-2); cursor: pointer; font-size: 12px;
  }
  .approval-actions button.approve { border-color: var(--sage); }
  .approval-actions button.deny { border-color: var(--rust); }
  .approval-actions button:disabled { opacity: .55; cursor: not-allowed; }
  .approval-error { color: var(--rust); font-size: 12px; margin-top: 8px; }
  .footer {
    margin: 24px 0 8px; padding: 14px 16px; background: var(--surface-2);
    border: 1px solid var(--rule); border-radius: 10px; color: var(--ink-3); font-size: 12px;
  }
  .footer strong { color: var(--ink); }
  .empty { color: var(--ink-3); font-style: italic; }
  .err { color: var(--rust); }
  code { background: var(--surface-2); padding: 1px 5px; border-radius: 4px; font-size: 12px; }
  .evidence { font-size: 11px; color: var(--ink-3); margin-top: 6px; }
  button.guided {
    margin-top: 8px; background: var(--surface-2); color: var(--ink);
    border: 1px solid var(--rule); border-radius: 6px; padding: 5px 10px; cursor: pointer; font-size: 12px;
  }
  button.guided:hover { border-color: var(--indigo); }
  /* Live-refresh connection indicator. The dot color is the at-a-glance honesty
     signal: green = a fresh frame arrived inside the staleness window; amber =
     reconnecting / no recent frame (the data on screen may be stale). It is
     NEVER green merely because a stream socket is open. */
  .conn { display: flex; align-items: center; gap: 6px; font-size: 12px; color: var(--ink-3); margin-top: 4px; }
  .conn .dot { width: 8px; height: 8px; border-radius: 50%; background: var(--ink-3); flex: none; }
  .conn.live .dot { background: var(--sage); }
  .conn.reconnecting .dot { background: var(--ochre); }
  .conn .updated { color: var(--ink-3); }
  .section-head { display: flex; align-items: center; justify-content: space-between; gap: 12px; margin: 0 0 10px; }
  .section-head h2 { font-size: 13px; text-transform: uppercase; letter-spacing: .5px; color: var(--ink-3); margin: 0; }
  .story-toggle { display: inline-flex; align-items: center; gap: 6px; color: var(--ink-3); font-size: 12px; user-select: none; }
  .story-toggle input { margin: 0; }
  .story-summary { margin: 0; }
  /*
    S3 first-run empty state. An empty fortress is the most common first
    impression, so emptiness renders as a guided path rather than a void. It
    spans the agent grid's columns so the checklist reads as one block.
  */
  .firstrun {
    grid-column: 1 / -1; background: var(--surface); border: 1px solid var(--rule);
    border-radius: 10px; padding: 18px 20px;
  }
  .firstrun h3 { margin: 0 0 6px; font-size: 15px; }
  .firstrun p { margin: 0 0 12px; color: var(--ink-3); font-size: 12.5px; max-width: 68ch; }
  .firstrun-steps { margin: 0; padding-left: 20px; display: grid; gap: 10px; }
  .firstrun-steps li { font-size: 12.5px; color: var(--ink-2); }
  .firstrun-cmd {
    display: block; margin-top: 5px; font-family: var(--mono, monospace); font-size: 11.5px;
    background: var(--surface-2); border: 1px solid var(--rule); border-radius: 6px;
    padding: 5px 9px; color: var(--ink-2); width: fit-content;
  }
  .firstrun-foot { margin: 14px 0 0; font-size: 11.5px; color: var(--ink-4, var(--ink-3)); }
  /*
    S3 quiet empty state: "nothing here" should read as earned calm, not as a
    failure or a blank. Used for the panels that are legitimately empty on a
    healthy box (no approvals waiting, no anomaly findings).
  */
  .quiet { display: flex; align-items: baseline; gap: 8px; font-size: 12.5px; color: var(--ink-2); }
  .quiet .quiet-mark { color: var(--sage); font-size: 11px; }
  .quiet .quiet-why { color: var(--ink-3); font-size: 11.5px; }
</style>
</head>
<body>
<header>
  <div class="header-row">
    <div class="header-titles">
      <h1>Sanctuary - Security Posture</h1>
      <div class="sub" id="origin">Loading…</div>
      <div class="conn" id="conn">
        <span class="dot"></span>
        <span id="conn-label">Connecting…</span>
        <span class="updated" id="conn-updated"></span>
      </div>
    </div>
    <a href="/fleet" class="fleet-link" title="Switch between Sanctuary machines">Fleet Switcher</a>
  </div>
</header>
<main>
  <div class="banner" id="banner"><span class="empty">Loading posture…</span></div>

  <section>
    <h2>Agents</h2>
    <div class="grid" id="agents"><span class="empty">Loading…</span></div>
  </section>

  <!--
    Fleet (Fleet Console Slice 1). Hidden by default and only revealed when this
    fortress has federation provisioned (the /api/posture/fleet endpoint returns
    200 with available:true). A 404 (federation not wired) or available:false
    (not provisioned) keeps this section display:none so the panel is ABSENT,
    never a greyed shell or a fabricated "all admitted" roster over a fortress
    with no fleet. SEE / MONITOR only, no trust actions here (a later slice adds
    in-console admit/revoke).
  -->
  <section id="fleet-section" style="display:none">
    <div class="section-head">
      <h2>Fleet</h2>
      <span class="sub" id="fleet-summary"></span>
    </div>
    <div class="panel" id="fleet"><span class="empty">Loading…</span></div>
  </section>

  <section>
    <h2>Approvals waiting</h2>
    <div class="panel" id="approvals"><span class="empty">Loading…</span></div>
  </section>

  <section>
    <div class="section-head">
      <h2>Today's story</h2>
      <label class="story-toggle">
        <input type="checkbox" id="story-plain-summary" />
        Plain summary
      </label>
    </div>
    <div class="panel" id="story"><span class="empty">Loading…</span></div>
  </section>

  <section>
    <h2>Anomaly findings</h2>
    <div class="panel" id="anomalies"><span class="empty">Loading…</span></div>
  </section>

  <section>
    <h2>Castle Wall</h2>
    <div class="panel" id="wall"><span class="empty">Loading…</span></div>
  </section>

  <section>
    <h2>Security features</h2>
    <div class="panel" id="features"><span class="empty">Loading…</span></div>
  </section>

  <section>
    <h2>Custody and Exit</h2>
    <div class="panel" id="custody"><span class="empty">Loading…</span></div>
  </section>

  <section>
    <h2>Query privacy</h2>
    <div class="panel" id="queryprivacy"><span class="empty">Loading…</span></div>
  </section>

  <!--
    Recognition + portability (P5). Hidden by default and only revealed when the
    composition gate is ON (the /api/posture/recognition endpoint returns 200).
    When composition is OFF the endpoint 404s and this section stays display:none
    so the panel is ABSENT, never a greyed shell that would imply a Concordia /
    Verascore dependency.
  -->
  <section id="recognition-section" style="display:none">
    <h2>Recognition and portability</h2>
    <div class="panel" id="recognition"><span class="empty">Loading…</span></div>
  </section>

  <div class="footer">
    <strong>Your data, your machine.</strong>
    State: encrypted at rest (AES-256-GCM) under <code>~/.sanctuary</code> on this machine.
    Keys: yours, passphrase-derived. Audit log: hash-chained, signed.
    Nothing on this screen leaves your hardware.
  </div>
</main>

<script>
(function () {
  "use strict";
  // Same auth model as the rest of the dashboard: loopback auto-auth or a
  // bearer token the operator pasted. We send credentials: same-origin so the
  // login session cookie rides along; if a token is in the URL hash we use it.
  var tokenMatch = /[#&]token=([^&]+)/.exec(location.hash);
  var token = tokenMatch ? decodeURIComponent(tokenMatch[1]) : null;
  if (!token && typeof sessionStorage !== "undefined") {
    token = sessionStorage.getItem("authToken") || null;
  }

  function readUrlSession() {
    try {
      var value = new URLSearchParams(location.search || "").get("session");
      // Dashboard sessions are server-minted opaque URL-safe ids. Reject odd
      // characters rather than reflecting them into any follow-up request URL.
      if (value && /^[A-Za-z0-9_-]{1,256}$/.test(value)) return value;
    } catch (e) {}
    return null;
  }

  var urlSession = readUrlSession();

  function credentialedPath(path) {
    if (!urlSession) return path;
    try {
      var u = new URL(path, location.origin);
      if (u.origin !== location.origin) return path;
      u.searchParams.set("session", urlSession);
      return u.pathname + u.search + u.hash;
    } catch (e) {
      return path;
    }
  }

  function api(path) {
    var opts = { credentials: "same-origin", headers: {} };
    if (token) opts.headers["Authorization"] = "Bearer " + token;
    var url = credentialedPath(path);
    return fetch(url, opts).then(function (r) {
      if (!r.ok) throw new Error(path + " -> " + r.status);
      return r.json();
    });
  }

  function rememberToken(value) {
    token = value;
    if (typeof sessionStorage !== "undefined") {
      sessionStorage.setItem("authToken", value);
    }
  }

  function promptForToken() {
    if (typeof window === "undefined" || typeof window.prompt !== "function") return null;
    var entered = window.prompt("Sanctuary operator token required for approval decisions.");
    if (!entered) return null;
    entered = entered.trim();
    if (!entered) return null;
    rememberToken(entered);
    return entered;
  }

  function decisionHeaders() {
    var headers = {};
    if (token) headers["Authorization"] = "Bearer " + token;
    return headers;
  }

  function postDecision(path, retried) {
    return fetch(credentialedPath(path), {
      method: "POST",
      credentials: "same-origin",
      headers: decisionHeaders(),
      cache: "no-store",
    }).then(function (r) {
      if (r.status === 401 && !retried) {
        if (!promptForToken()) return null;
        return postDecision(path, true);
      }
      if (!r.ok) throw new Error(path + " -> " + r.status);
      return r.json().catch(function () { return {}; });
    });
  }

  // SEC-012 stream handshake: EventSource cannot set an Authorization header,
  // and checkAuth rejects the long-lived ?token= in the URL (to keep tokens out
  // of access logs, proxy logs, and browser history). The dashboard already
  // mints a SHORT-LIVED session from the bearer at POST /auth/session (the same
  // endpoint and TTL the v1.1 client uses) and accepts it via ?session=. We only
  // perform the handshake when (a) a bearer token is present in the URL hash and
  // (b) there is no existing session cookie - i.e. a remote token-hash session
  // with no cookie, where the stream would otherwise stay unauthenticated and
  // the page degrade to polling. On loopback / cookie auth no token is in the
  // hash (or a cookie already authorizes), so NO mint is attempted and the prior
  // behavior is unchanged. The long-lived bearer goes in the Authorization
  // header of the POST, NEVER in any URL.
  function hasSessionCookie() {
    if (typeof document === "undefined" || !document.cookie) return false;
    return /(?:^|;\\s*)sanctuary_session=/.test(document.cookie);
  }

  // Returns a "?session=<id>" query string to append to the stream URL, or "" if
  // no handshake is needed or it could not complete. Never throws: any mint
  // failure, 401, or malformed body resolves to "" so the caller falls back to
  // polling honestly. Reuses the dashboard's existing session TTL (we do not
  // lengthen it) and never puts the long-lived token in a URL.
  function mintStreamSession() {
    if (urlSession) return Promise.resolve("?session=" + encodeURIComponent(urlSession));
    if (!token || hasSessionCookie()) return Promise.resolve("");
    return fetch("/auth/session", {
      method: "POST",
      // Bearer goes in the header, NOT the URL.
      headers: { "Authorization": "Bearer " + token },
      cache: "no-store",
    }).then(function (r) {
      if (!r.ok) return "";
      return r.json().then(function (body) {
        if (!body || !body.session_id || body.session_id === "no-auth") return "";
        return "?session=" + encodeURIComponent(body.session_id);
      }, function () { return ""; });
    }, function () { return ""; });
  }

  function esc(s) {
    return String(s == null ? "" : s).replace(/[&<>"']/g, function (c) {
      return { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c];
    });
  }

  // "Never fake green": ARMED is the ONLY green arm-state. COARSE-ONLY (S5-P)
  // is the DISTINCT non-green state: the coarse wall is enforcing but a
  // fine-grained-provisioned agent's exclusive-egress stack is not live.
  function wallPill(state) {
    if (state === "armed") return '<span class="pill green">ARMED</span>';
    if (state === "coarse_only") return '<span class="pill amber">COARSE-ONLY</span>';
    if (state === "degraded") return '<span class="pill red">DEGRADED</span>';
    if (state === "not_installed") return '<span class="pill amber">NOT INSTALLED</span>';
    return '<span class="pill amber">UNKNOWN</span>';
  }

  // "Never fake green" for the agent grid (#634 honesty split). GREEN is earned
  // only by CONFIRMED live enforcement for the agent; a policy-protected agent
  // whose enforcement we cannot observe is amber "protection requested", never
  // green. A no-longer-protected agent (mid-unwrap, or observed not enforcing)
  // is red. This mirrors the wall pill's evidence-gated color model so the most-
  // screenshotted tile can no longer overclaim enforcement from policy intent.
  // The function body is the SHARED source of truth (posture-html-shared.ts) so
  // the drill-down cannot weaken this color model independently (#641).
  ${AGENT_PILL_FN_SOURCE}

  // S3 evidence spine: the shared freshness formatter (posture-html-shared.ts).
  // Returns "" for an absent or unparseable timestamp so a missing check can
  // never render as a recent one; call sites render an explicit "no evidence
  // yet" on "". Shared so "checked 14s ago" means the same on every surface.
  ${REL_TIME_FN_SOURCE}

  // "Never fake green" for the feature-health panel. Mirrors the canonical
  // pure mapper exported from this module (featureHealthPill). GREEN is earned
  // ONLY by "active"; "fault" is red; "unconfirmed" and "unknown" are amber and
  // are NEVER green. This is the same color model the /api/posture/feature-health
  // endpoint enforces (feature-health.ts) - the surface must not weaken it.
  function featurePill(status) {
    if (status === "active") return '<span class="pill green">active</span>';
    if (status === "fault") return '<span class="pill red">fault</span>';
    if (status === "unconfirmed") return '<span class="pill amber">unconfirmed</span>';
    if (status === "coarse_only") return '<span class="pill amber">coarse-only</span>';
    return '<span class="pill amber">unknown</span>';
  }

  // Plain-English reason copy, derived from the endpoint's stable basis enum.
  // Never leaks rule internals; phrases the honest non-green cases plainly.
  //
  // HONESTY: the liveness bases (alive_no_recent_enforcement / dead_no_heartbeat
  // / intentionally_stopped / daemon_liveness_unconfirmed /
  // no_evidence_self_reporting) are SHARED between the
  // Castle Wall row and the broker DAEMON row, but they mean different things.
  // For Castle Wall, a fresh heartbeat means "armed but idle" (no flow filtered).
  // For the broker daemon it means ONLY "the process is up" - NOT that it would
  // mint/deny a token correctly, NOT that the keychain is reachable. So the
  // broker daemon row gets PROCESS-LIVENESS copy ("broker daemon alive"), never
  // "healthy"/green. Branch on the stable feature_id to keep both honest.
  function featureWhy(row) {
    var isBrokerDaemon = row.feature_id === "secret_broker_daemon";
    switch (row.basis) {
      case "fresh_enforcement_evidence":
        return "Confirmed by fresh enforcement evidence.";
      case "activity_in_window":
        return "Activity observed in the last 24h.";
      case "fault_evidence":
        return "A fault event was observed; not enforcing.";
      case "exclusive_egress_not_live":
        return "Coarse-only: the coarse wall is enforcing, but a fine-grained agent's exclusive-egress stack (gate, pf, generation) is not live.";
      case "stale_evidence":
        return "Evidence is stale; recent state cannot be confirmed.";
      case "no_evidence_self_reporting":
        return isBrokerDaemon
          ? "No recent heartbeat ever seen; cannot tell a never-started daemon from one that stopped long ago."
          : "No recent evidence; working state cannot be confirmed.";
      case "alive_no_recent_enforcement":
        return isBrokerDaemon
          ? "Broker daemon alive (recent heartbeat). Process liveness only - this does NOT confirm it would correctly mint or deny a token, nor that the keychain is reachable."
          : "The wall is alive (recent heartbeat) but has not filtered a flow in the window.";
      case "dead_no_heartbeat":
        return isBrokerDaemon
          ? "The broker daemon was running but its heartbeat stopped; the process appears to have silently died."
          : "The wall was running but its heartbeat stopped; it appears to have silently died.";
      case "intentionally_stopped":
        return isBrokerDaemon
          ? "The broker daemon was intentionally stopped (clean shutdown); it is off on purpose, not dead."
          : "The wall was intentionally stopped (operator stop, disable, or arm-lease revoke); it is off on purpose, not dead.";
      case "daemon_liveness_unconfirmed":
        return isBrokerDaemon
          ? "Broker daemon liveness is not confirmed after recent activity; not rendered green."
          : "The wall has prior enforcement evidence, but daemon liveness is not currently confirmed; not rendered green.";
      case "subject_unbound_evidence":
        return "Castle Wall has recent enforcement evidence, but it is not attributed to this confined agent.";
      case "legacy_macos_audit_token":
        return "Evidence predates the subject-binding format; re-arm Castle Wall to produce subject-bound evidence.";
      case "pre_canonical_linux_agent_name":
        return "Linux evidence predates canonical subject binding; upgrade the daemon path before claiming this agent is protected.";
      case "subject_unresolvable":
        return "This agent's confinement identity could not be read, so no enforcement evidence can be bound to it.";
      case "no_activity_event_driven":
        return row.broken_zero_detectable === false
          ? "No activity in window. A silently-disabled feature is undetectable here, so this is shown as unconfirmed, not green."
          : "No activity in the window.";
      case "floor_met":
        return "Activity met the minimum volume you declared for this feature.";
      case "below_expected_floor":
        return "Below the minimum volume you declared for this feature. This is your stated expectation being quiet, not a detected fault.";
      case "integrity_tainted":
        return "Audit integrity finding present; status cannot be trusted.";
      case "freshness_scan_incomplete":
        return "Recent-evidence scan could not be proven complete; not shown green by design.";
      default:
        return "";
    }
  }

  function renderFeatures(panel) {
    var el = document.getElementById("features");
    if (!panel || !panel.rows || !panel.rows.length) {
      el.innerHTML = '<span class="empty">No feature-health data.</span>';
      return;
    }
    var rows = panel.rows.map(function (r) {
      return '<div class="fh-row">' + featurePill(r.status) +
        '<span class="name">' + esc(r.label) + "</span>" +
        '<span class="why">' + esc(featureWhy(r)) + "</span></div>";
    }).join("");
    var note = (panel.disclosure && panel.disclosure.broken_zero_undetectable_for_event_driven)
      ? '<div class="fh-note">For activity-only features, a feature that was silently turned off cannot be ' +
        'distinguished from one that is simply quiet, so quiet reads as unconfirmed (never green). ' +
        'A feature only reads active on real evidence in the window.</div>'
      : "";
    el.innerHTML = rows + note;
  }

  // "Never fake green" for the Custody tile. Mirrors the canonical pure mapper
  // exported from this module (custodyPill). There is NO green branch: custody
  // HEALTH is a boot-time fact under the transient master and is not re-derivable
  // from the dashboard's request-time view, so "unconfirmed" is amber and
  // "damaged" is red. The panel never claims custody is healthy from absence of
  // damage evidence (the #617 honesty contract).
  function custodyPill(state) {
    if (state === "damaged") return '<span class="pill red">DAMAGED</span>';
    return '<span class="pill amber">UNCONFIRMED</span>';
  }

  // Plain-English copy from the panel's stable basis enum. Never leaks internals.
  function custodyWhy(basis) {
    switch (basis) {
      case "rollback_freeze_active":
        return "A suspected custody rollback has FROZEN trust-bearing writes. Acknowledge with 'sanctuary restore-attest'.";
      case "fresh_custody_damage_evidence":
        return "The Castle Wall pinned key does not decrypt under the current master (dual-path custody damage). Re-pin when ready.";
      case "integrity_tainted":
        return "Audit integrity finding present; custody state cannot be trusted from this read.";
      case "no_negative_evidence_unconfirmed":
      default:
        return "No custody damage observed. Custody health (two-factor floor, key non-extraction, anti-rollback epoch) is established at boot under your key and cannot be re-proven from this screen, so it is shown as unconfirmed, never green.";
    }
  }

  function renderCustodyExit(panel) {
    var el = document.getElementById("custody");
    if (!panel) {
      el.innerHTML = '<span class="empty">No custody and exit data.</span>';
      return;
    }
    var html =
      "<div>" + custodyPill(panel.custody_state) + " &nbsp;" + esc(custodyWhy(panel.custody_basis)) + "</div>";
    // Establishment provenance, when a fresh-enough event is on the chain. Shown
    // as provenance only (install mode + verified-factor count), never as a
    // health claim.
    if (panel.establishment) {
      var e = panel.establishment;
      html +=
        '<div class="evidence">Custody event: <code>' + esc(e.operation) + "</code>" +
        (e.install_mode ? " · install mode " + esc(e.install_mode) : "") +
        (e.verified_wraps !== null && e.verified_wraps !== undefined
          ? " · " + esc(e.verified_wraps) + " verified recovery factor(s)"
          : "") +
        // S3 freshness: an age reads faster than a raw ISO stamp. The absolute
        // timestamp stays in the title attribute so the exact value an operator
        // would cite in an incident write-up is never lost, only demoted.
        ' · observed <span title="' + esc(e.observed_at) + '">' +
        esc(relTime(e.observed_at) || e.observed_at) + "</span></div>";
    }
    if (panel.last_damage_evidence_at) {
      html += '<div class="evidence">Last custody-damage evidence: ' +
        '<span title="' + esc(panel.last_damage_evidence_at) + '">' +
        esc(relTime(panel.last_damage_evidence_at) || panel.last_damage_evidence_at) +
        "</span></div>";
    }
    if (!panel.audit_integrity_ok) {
      html += '<div class="err">Audit integrity finding present - custody read may be incomplete.</div>';
    }
    // Exit / portability: the honest capability statement. The Tier-1-gated CLI
    // export exists; the FULL clean-exit guarantee is NOT yet earned, so we say
    // "evidence bundle" and never assert the full clean-exit claim on Home.
    html +=
      '<div class="evidence" style="margin-top:10px">Exit and portability: ' +
      (panel.exit_state === "export_available"
        ? '<span class="pill amber">evidence bundle</span> ' +
          "Create a portable evidence bundle with <code>" +
          esc(panel.exit_command || "sanctuary exit") +
          "</code> (a Tier-1 operation: it requires your approval before it runs)."
        : "unknown") +
      "</div>";
    html +=
      '<div class="fh-note">An evidence bundle does not yet mean a guaranteed clean exit: ' +
      "the portable evidence-bundle command ships, but the full clean-exit guarantee (complete, " +
      "verifiable handover with nothing left behind) is not yet earned, so it is not claimed here.</div>";
    el.innerHTML = html;
  }

  // ── Recognition + portability (P5) ──────────────────────────────────────
  // The single most impartiality-loaded panel. Hard rules, all visible here:
  //   - NO SCORE: this renderer never reads or shows a Verascore (or any vendor)
  //     reputation score. It shows LOCAL attestation COUNTS only, plus the local
  //     "published?" boolean. There is no score field on the payload to render.
  //   - LOCAL VERIFICATION: counterparty verification is labeled as LOCAL bridge
  //     cryptography, keyed off panel.receipts.verification_basis. It is NEVER
  //     labeled "verified by Concordia" or "verified by Verascore".
  //   - NEVER FAKE GREEN: the reputation row is green ONLY when real attestation
  //     evidence is present (reputation_state === "present"); otherwise amber.
  //     The portable-identity export is an amber capability, never green.
  function recognitionRepPill(state) {
    if (state === "present") return '<span class="pill green">on record</span>';
    return '<span class="pill amber">no evidence yet</span>';
  }
  function renderRecognition(panel) {
    var section = document.getElementById("recognition-section");
    var el = document.getElementById("recognition");
    if (!el || !section) return;
    if (!panel) {
      el.innerHTML = '<span class="empty">No recognition data.</span>';
      return;
    }
    var r = panel.receipts || {};
    // Counterparty receipts. The verification label is keyed strictly off the
    // payload's frozen basis constant so it can never drift to a vendor claim.
    var verifyLabel =
      r.verification_basis === "local_bridge_crypto"
        ? "verified locally by Sanctuary's bridge cryptography (signature + commitment recomputation + terms-hash match)"
        : "verification basis unknown";
    var html =
      '<div class="evidence">Counterparty receipts (Concordia bridge): ' +
      '<code>' + esc(r.committed) + '</code> committed · ' +
      '<code>' + esc(r.verified_true) + '</code> ' + esc(verifyLabel) +
      (r.verified_false ? ' · <code>' + esc(r.verified_false) + '</code> failed verification' : '') +
      ' · <code>' + esc(r.attested) + '</code> attested to reputation.</div>';
    html +=
      '<div class="fh-note">These counts come from your local bridge audit and storage with no Concordia process running. ' +
      'A receipt proves the revealed terms match what was committed and is bound to the named parties; it is not a full counterparty track record.</div>';
    // Honest cap disclosure (#651 LOW): the verify/attest counts read the most
    // recent audit_query_cap entries, so on a very busy fortress they are a lower
    // bound, not a complete tally. Disclose it rather than silently undercounting.
    if (r.receipts_capped) {
      html +=
        '<div class="fh-note">Note: verify/attest counts cover the most recent ' +
        '<code>' + esc(r.audit_query_cap) + '</code> audit entries, so on a very busy fortress they are a lower bound (not a complete all-time tally).</div>';
    }
    // Local reputation EVIDENCE (counts only; NEVER a score).
    var ev = panel.reputation_evidence;
    html +=
      '<div style="margin-top:10px">' + recognitionRepPill(panel.reputation_state) +
      ' &nbsp;Local reputation evidence (counts from your own attestation store, not a score)</div>';
    if (ev) {
      html +=
        '<div class="evidence"><code>' + esc(ev.attestation_count) + '</code> attestation(s) · ' +
        '<code>' + esc(ev.dispute_count) + '</code> dispute(s)' +
        (ev.most_recent_attestation_at ? ' · most recent ' + esc(ev.most_recent_attestation_at) : '') +
        ' · external publish: ' +
        (ev.verascore_linked
          ? '<span class="pill amber">published</span> (you ran reputation_publish; this is a local flag, not a fetched score)'
          : '<span class="pill amber">not published</span>') +
        '.</div>';
    } else {
      html +=
        '<div class="fh-note">No local reputation evidence yet, so this row is amber, not green. ' +
        'Sanctuary never fetches or displays an external reputation score.</div>';
    }
    // Portable identity: the Slice-3 amber capability treatment, reused.
    html +=
      '<div class="evidence" style="margin-top:10px">Portable identity: ' +
      (panel.export_state === "export_available"
        ? '<span class="pill amber">export available</span> ' +
          'Export your portable identity bundle with <code>' +
          esc(panel.export_tool || "sanctuary_export_identity_bundle") +
          '</code> (a Tier-1 operation: it requires your approval before it runs).'
        : 'unknown') +
      '</div>';
    if (!panel.audit_integrity_ok) {
      html += '<div class="err">Audit integrity finding present - receipt counts may be incomplete.</div>';
    }
    el.innerHTML = html;
  }

  // Fetch the Recognition panel behind the composition render gate. A 200 reveals
  // the section; a 404 (composition OFF) leaves it hidden so the panel is ABSENT,
  // never a greyed shell that implies a dependency.
  //
  // RETRY ON LOCKED (#651 MEDIUM): the panel sits behind the audit-unlock 503
  // guard, so the very first fetch can land while the fortress is still locked
  // (a 503). A one-shot fetch would then keep the panel hidden FOREVER even after
  // the operator unlocks. So we retry with capped backoff on ANY status that is
  // not a definitive 404. A 404 means composition is off (a config fact that does
  // not change within a session): that stays an honest, permanent absence and we
  // stop. We never render a greyed shell while retrying: the section stays
  // display:none until a 200 supplies real evidence, so a locked/booting fortress
  // shows nothing (honest absence), not a composition-off implication.
  var RECOGNITION_RETRY_MS = [1000, 2000, 4000, 8000, 15000, 30000];
  function loadRecognition(attempt) {
    var section = document.getElementById("recognition-section");
    if (!section) return;
    api("/api/posture/recognition").then(function (panel) {
      // composition_enabled is always true on a served panel; reveal + render.
      section.style.display = "";
      renderRecognition(panel);
    }).catch(function (err) {
      // Keep the panel absent while we decide. Never a greyed/empty card.
      section.style.display = "none";
      // api() throws Error("<path> -> <status>"); a 404 is a definitive
      // composition-off absence, so stop. Anything else (503 locked, transient
      // network) is retryable so the panel appears once the fortress unlocks.
      var msg = err && err.message ? String(err.message) : "";
      if (/-> 404$/.test(msg)) return;
      var i = attempt || 0;
      if (i >= RECOGNITION_RETRY_MS.length) {
        // Settle at the slowest cadence so a long-locked fortress still recovers
        // the panel after unlock without hammering the endpoint.
        setTimeout(function () { loadRecognition(i); }, RECOGNITION_RETRY_MS[RECOGNITION_RETRY_MS.length - 1]);
        return;
      }
      setTimeout(function () { loadRecognition(i + 1); }, RECOGNITION_RETRY_MS[i]);
    });
  }
  function loadRecognitionOnce() { loadRecognition(0); }

  // ── Fleet roster (Fleet Console Slice 1) ────────────────────────────────
  // A separate, federation-gated fetch for the full roster (the home payload
  // carries only the tiny banner summary). A 200 with available:true reveals the
  // panel; a 404 (federation not wired) or available:false (not provisioned)
  // keeps it hidden (honest absence), never a fabricated roster. Unlike
  // Recognition, the fleet is RE-POLLED on a cadence so a revocation (a machine
  // going from admitted -> revoked, or an unevaluable machine flipping to
  // untrusted) shows up live on the board without a reload.
  var FLEET_RETRY_MS = [1000, 2000, 4000, 8000, 15000, 30000];
  var FLEET_REFRESH_MS = 15000;
  var fleetRefreshTimer = null;
  function scheduleFleetRefresh() {
    if (fleetRefreshTimer !== null) return;
    fleetRefreshTimer = setInterval(function () { loadFleet(0); }, FLEET_REFRESH_MS);
  }
  function loadFleet(attempt) {
    var section = document.getElementById("fleet-section");
    if (!section) return;
    api("/api/posture/fleet").then(function (roster) {
      renderFleet(roster);
      // Once we have ANY successful read, keep the panel current on a cadence so
      // trust changes (revoke / unevaluable) flip the board live. renderFleet
      // hides the section honestly when available:false, so a provisioned-then-
      // disabled fortress is handled by the renderer, not a stop here.
      scheduleFleetRefresh();
    }).catch(function (err) {
      // A 404 is a definitive "federation not wired on this dashboard" absence:
      // stop and leave the panel hidden. Anything else (503 locked, transient
      // network) is retryable so the panel appears once the fortress unlocks.
      var msg = err && err.message ? String(err.message) : "";
      if (/-> 404$/.test(msg)) { section.style.display = "none"; return; }
      var i = attempt || 0;
      if (i >= FLEET_RETRY_MS.length) {
        setTimeout(function () { loadFleet(i); }, FLEET_RETRY_MS[FLEET_RETRY_MS.length - 1]);
        return;
      }
      setTimeout(function () { loadFleet(i + 1); }, FLEET_RETRY_MS[i]);
    });
  }
  function loadFleetOnce() { loadFleet(0); }

  // "Never fake green" for the Query-privacy section. Mirrors the canonical pure
  // mapper exported from this module (queryPrivacyPill). GREEN is earned ONLY by
  // "active" (real strip/rewrite evidence); "unconfirmed"/"unknown" are amber and
  // NEVER green; "fault" is red. The Tier B PII-rewrite row stays amber
  // unconfirmed (its emitter is unwired), so it can never show green from config.
  function queryPrivacyPill(status) {
    if (status === "active") return '<span class="pill green">active</span>';
    if (status === "fault") return '<span class="pill red">fault</span>';
    return '<span class="pill amber">unconfirmed</span>';
  }

  // Plain-English row copy keyed on the tier. Tier A is the always-on header
  // strip (metadata hygiene, never anonymity); Tier B is the opt-in PII rewrite
  // that is unconfirmed until its emitter is wired into the live call path.
  function queryPrivacyWhy(row) {
    if (row.tier === "A") {
      // Key the copy on the honesty discriminator, NOT just the status, so the
      // three Tier-A cases each read distinctly (#617). Green active means
      // headers were actually stripped; calls-but-nothing-to-strip and no-calls
      // are both amber but say plainly that NO stripping happened, so a viewer
      // can never read a 0-stripped window as stripping-happened.
      if (row.tier_a_evidence === "stripped") {
        return "Fingerprintable headers were stripped on outbound calls in the last 24h.";
      }
      if (row.tier_a_evidence === "none_to_strip") {
        return "Outbound calls were observed, but none carried a fingerprintable header to strip, so nothing was stripped in the last 24h. Shown amber, never green.";
      }
      return "No outbound calls observed in the last 24h, so the strip cannot be confirmed from evidence. Shown amber, never green.";
    }
    return "Off by default. PII rewrite is not yet wired into the live call path, so it reads unconfirmed until a real rewrite fires. It is never shown green from configuration alone.";
  }

  function renderQueryPrivacy(qp) {
    var el = document.getElementById("queryprivacy");
    if (!qp || !qp.rows) {
      el.innerHTML = '<span class="empty">No query-privacy data.</span>';
      return;
    }
    // HONEST HEADLINE (#617 overclaim flag): header stripping is metadata
    // hygiene, NOT anonymity. Say the boundary plainly: the substrate provider
    // still sees the query content and the authenticated API key.
    var headline =
      '<div>Fingerprintable headers stripped on every call; PII rewrite available opt-in. ' +
      "<strong>" + esc(qp.headers_stripped_24h) + "</strong> headers stripped across " +
      "<strong>" + esc(qp.header_strip_calls_24h) + "</strong> outbound calls in the last 24h.</div>";
    var rows = qp.rows.map(function (r) {
      return '<div class="fh-row">' + queryPrivacyPill(r.status) +
        '<span class="name">' + esc(r.label) + "</span>" +
        '<span class="why">' + esc(queryPrivacyWhy(r)) + "</span></div>";
    }).join("");
    var note =
      '<div class="fh-note">Header stripping is metadata hygiene, not anonymity: ' +
      "the substrate provider still sees the query content and your authenticated " +
      "API key. This reduces what can be correlated across calls; it does not make " +
      "your queries anonymous.</div>";
    el.innerHTML = headline + rows + note;
  }

  function renderBanner(home, approvalState, anomalies) {
    var openAnomalies = (anomalies && anomalies.length) || 0;
    var pendingCount = (approvalState && approvalState.rows && approvalState.rows.length) || 0;
    var federation = home && home.federation;
    var originText = "Machine: " + home.origin_machine;
    if (federation && federation.available) {
      var fleetCount = Number(federation.fleet_node_count || 0);
      if (federation.enabled) {
        originText += " · federation: " + fleetCount + " machines";
      } else {
        originText += " · federation provisioned, disabled · " + fleetCount + " machines";
      }
    } else {
      originText += " · single-machine view (federation off)";
    }
    document.getElementById("origin").textContent =
      originText;
    // S3 evidence spine. Every tile below carries, where the payload already
    // supports it: a denominator (so a bare count cannot be read as a whole), a
    // freshness stamp (so a claim states how recently it was checked), and a
    // link to the evidence behind the number. Nothing here fetches new data --
    // every value comes from the /api/posture/home payload the page already
    // holds. Where the payload has no honest denominator or timestamp for a
    // tile, that tile renders WITHOUT one rather than inventing a plausible
    // value. See the null-handling in statOf/fresh below.
    var detectedTotal =
      ((home.agents && home.agents.length) || 0) +
      ((home.unwrapped && home.unwrapped.unwrapped && home.unwrapped.unwrapped.length) || 0);
    var wallEvidenceAt = home.castle_wall && home.castle_wall.last_enforcement_evidence_at;
    var digest = home.digest || {};
    document.getElementById("banner").innerHTML =
      // Honest split (#634): "protection requested" is policy intent; "enforcement
      // confirmed" is the observed-live count. Reporting only a flat "protected"
      // number overstated enforcement the server cannot prove. S3 keeps that
      // split and adds the denominator that makes it legible: requested is "of
      // N detected", and confirmed is "of N requested" -- so a "0 of 3" reads as
      // the honest gap it is rather than an unexplained zero.
      stat(home.protection_requested_count, "Protection requested", {
        of: detectedTotal,
        ev: { href: "#agents", text: "agents" },
      }) +
      stat(home.enforcement_confirmed_count, "Enforcement confirmed", {
        of: home.protection_requested_count,
        ev: { href: "/posture/evidence", text: "evidence" },
      }) +
      stat(wallPill(home.castle_wall.arm_state), "Castle Wall", {
        // The wall's freshness is the age of its last ENFORCEMENT evidence, not
        // the age of this page render. No evidence means an explicit "no
        // enforcement evidence yet", never a blank that could read as fresh.
        fresh: wallEvidenceAt,
        freshNoneText: "no enforcement evidence yet",
        ev: { href: "#wall", text: "what is protecting you" },
      }) +
      stat(pendingCount, "Approvals waiting", {
        ev: { href: "#approvals", text: "queue" },
      }) +
      stat(openAnomalies, "Open anomalies", {
        ev: { href: "#anomalies", text: "findings" },
      }) +
      stat(auditChainPill(home.digest), "Audit chain", {
        // The digest window is the period the chain verdict covers. Rendering
        // its end as a freshness stamp says how current the verdict is.
        fresh: digest.window_end,
        freshNoneText: "no verify on record",
        ev: { href: "/api/audit-log", text: "audit log" },
      });
  }
  // F2 BLOCKER-1: three-state pill from the shared verdict — green VERIFIED only
  // for a fully-verified chain; a neutral SUFFIX-ONLY when the sealed history is
  // unreadable at this privilege (an armed box's operator uid); red UNVERIFIED on
  // tamper/failure. Never green over an in-place-corrupted sealed entry.
  function auditChainPill(d) {
    if (d.chain_verdict === "verified_suffix_only")
      return '<span class="pill amber">SUFFIX-ONLY</span>';
    return d.chain_verified
      ? '<span class="pill green">VERIFIED</span>'
      : '<span class="pill red">UNVERIFIED</span>';
  }
  // S3 evidence spine tile. The opts argument is optional and every field in it
  // is optional, because the honest render of a missing denominator or a missing
  // timestamp is to OMIT it, not to substitute a placeholder that looks like
  // data. Specifically:
  //   opts.of            a denominator. Rendered only when it is a finite
  //                      number; a null/undefined/NaN total renders a bare
  //                      count, never "of 0" and never "of -".
  //   opts.fresh         an ISO timestamp. Rendered through the shared relTime,
  //                      which returns "" for absent/unparseable input; on ""
  //                      we render opts.freshNoneText in the slate unknown tone
  //                      so "not checked" can never be mistaken for "checked".
  //   opts.ev            { href, text } link to the evidence behind the number.
  function stat(value, label, opts) {
    var o = opts || {};
    var ofText = "";
    if (typeof o.of === "number" && isFinite(o.of)) {
      ofText = '<span class="stat-of">of ' + esc(o.of) + "</span>";
    }
    var foot = "";
    var freshText = o.fresh ? relTime(o.fresh) : "";
    var freshHtml = "";
    if (freshText) {
      freshHtml = '<span class="stat-fresh">checked ' + esc(freshText) + "</span>";
    } else if (o.freshNoneText) {
      freshHtml = '<span class="stat-fresh none">' + esc(o.freshNoneText) + "</span>";
    }
    var evHtml = o.ev
      ? '<a class="stat-ev" href="' + esc(o.ev.href) + '">' + esc(o.ev.text) + " &rarr;</a>"
      : "";
    if (freshHtml || evHtml) {
      foot = '<span class="stat-foot">' + freshHtml + evHtml + "</span>";
    }
    return (
      '<div class="stat"><span class="v">' + value + ofText + "</span>" +
      '<span class="l">' + esc(label) + "</span>" + foot + "</div>"
    );
  }

  function renderAgents(home) {
    var html = "";
    (home.agents || []).forEach(function (a) {
      // Each card title links to the per-agent drill-down page (Slice 4):
      // reach + the honest Standing section. The raw reach JSON stays available
      // as a secondary link for operators who want the payload directly.
      var drill = "/posture/agent/" + encodeURIComponent(a.agent_id);
      html +=
        '<div class="card"><h3><a href="' + drill + '">' + esc(a.agent_id) + "</a> " + agentPill(a) + "</h3>" +
        '<div class="meta">' + esc(a.harness) + " · status " + esc(a.status) + "</div>" +
        '<div class="reach"><a href="' + drill + '">View posture &rarr;</a>' +
        ' · <a href="/api/posture/reach/' + encodeURIComponent(a.agent_id) + '">raw reach</a></div></div>';
    });
    (home.unwrapped.unwrapped || []).forEach(function (u) {
      html +=
        '<div class="card amber"><h3>' + esc(u.harness) + ' <span class="pill amber">NOT protected</span></h3>' +
        '<div class="meta">detected by ' + esc(u.detection_method) + '</div>' +
        '<div class="reach"><code>' + esc(u.config_path) + "</code></div>" +
        '<button class="guided" data-harness="' + esc(u.harness) + '">Protect (guided)</button></div>';
    });
    // S3 empty states: first-run reads as a guided path, not as a void. An
    // empty agent grid is the most common first impression a new operator gets,
    // and "No agents detected." gave them nothing to do next. The checklist
    // below is honest about state -- step 1 is the only step that is actionable
    // before an agent exists, and the wall/chain steps are described, not
    // claimed. Nothing here asserts a protection that is not in place.
    if (!html) {
      html =
        '<div class="firstrun">' +
        "<h3>No agents protected yet.</h3>" +
        "<p>Sanctuary protects an agent by giving it an identity, a policy, and " +
        "approval gates, then enforcing them at the operating system. Three steps " +
        "get this board to green.</p>" +
        '<ol class="firstrun-steps">' +
        "<li><strong>Protect your first agent.</strong> Run this where your agent lives." +
        '<code class="firstrun-cmd">sanctuary protect</code></li>' +
        "<li><strong>Arm the wall.</strong> Turns policy into blocking that the " +
        "agent cannot talk its way past." +
        '<code class="firstrun-cmd">sanctuary castle-wall arm</code></li>' +
        "<li><strong>Verify your audit chain.</strong> Confirms the record of what " +
        "happened has not been altered." +
        '<code class="firstrun-cmd">sanctuary audit-chain verify</code></li>' +
        "</ol>" +
        '<p class="firstrun-foot">Each step lights its own tile above. The tiles ' +
        "stay grey until there is evidence for them.</p>" +
        "</div>";
    }
    var el = document.getElementById("agents");
    el.innerHTML = html;
    // Guided wrap: show the command, never execute in-place (one-click
    // execution is blocked on the supervised-daemon decision).
    Array.prototype.forEach.call(el.querySelectorAll("button.guided"), function (b) {
      b.addEventListener("click", function () {
        var h = b.getAttribute("data-harness");
        alert("Guided wrap\\n\\nRun this in your terminal to protect " + h + ":\\n\\n    sanctuary wrap --" +
          h.replace(/_/g, "-") + "\\n\\nOne-click protection ships once the supervised-daemon model lands.");
      });
    });
  }

  function normalizeLegacyApproval(p) {
    var id = p && (p.id || p.request_id);
    if (!id) return null;
    return {
      id: String(id),
      source: "legacy",
      title: p.operation || "pending operation",
      detail: (p.reason || "") + (p.tier ? " · Tier " + p.tier : ""),
      review_href: "/api/pending",
      approve_path: "/api/approve/" + encodeURIComponent(id),
      deny_path: "/api/deny/" + encodeURIComponent(id),
    };
  }

  function normalizeInboxApproval(p) {
    var id = p && p.aggregator_id;
    if (!id) return null;
    return {
      id: String(id),
      source: "approval-inbox",
      title: p.action_summary || p.policy_rule_id || "pending operation",
      detail: (p.source_harness || "approval inbox") +
        (p.source_agent_id ? " · " + p.source_agent_id : ""),
      review_href: "/api/approval-inbox/" + encodeURIComponent(id),
      approve_path: "/api/approval-inbox/" + encodeURIComponent(id) + "/approve",
      deny_path: "/api/approval-inbox/" + encodeURIComponent(id) + "/deny",
    };
  }

  function mapRows(items, mapper) {
    var rows = [];
    (items || []).forEach(function (item) {
      var row = mapper(item);
      if (row) rows.push(row);
    });
    return rows;
  }

  function approvalRedirect(status) {
    return status && status.policy && status.policy.approval_redirect
      ? status.policy.approval_redirect
      : { enabled: false, mode: "replace" };
  }

  function chooseApprovalRows(legacyRows, inboxRows, status) {
    var redirect = approvalRedirect(status);
    if (redirect.enabled === true && redirect.mode === "replace") {
      return { rows: inboxRows, source: "approval-inbox" };
    }
    if (legacyRows.length) return { rows: legacyRows, source: "legacy" };
    if (inboxRows.length) return { rows: inboxRows, source: "approval-inbox" };
    return { rows: [], source: "none" };
  }

  function buildApprovalState(legacyBody, inboxBody, status) {
    var legacyList = legacyBody && legacyBody.pending ? legacyBody.pending : legacyBody;
    var inboxList = inboxBody && inboxBody.data && inboxBody.data.entries
      ? inboxBody.data.entries
      : [];
    var selected = chooseApprovalRows(
      mapRows(legacyList || [], normalizeLegacyApproval),
      mapRows(inboxList || [], normalizeInboxApproval),
      status || null
    );
    return {
      rows: selected.rows,
      source: selected.source,
      can_decide: !!status && status.decision_capable === true,
      mode: status
        ? (status.standalone_mode === true ? "standalone" : "co-located")
        : "unknown",
    };
  }

  function renderApprovals(approvalState) {
    var pending = (approvalState && approvalState.rows) || [];
    if (!pending.length) {
      // S3 quiet empty state: earned calm. An empty approvals queue is a good
      // state, so it reads as one -- but the second clause keeps it honest
      // about WHY it is empty (nothing was held), not that nothing happened.
      document.getElementById("approvals").innerHTML =
        '<div class="quiet"><span class="quiet-mark">&#9679;</span>' +
        "<span>Nothing needs you." +
        '<span class="quiet-why"> No operation is waiting on your decision.</span>' +
        "</span></div>";
      return;
    }
    var html = "";
    pending.forEach(function (p) {
      html += '<div class="approval-row" data-approval-row="' + esc(p.id) + '">' +
        '<div class="approval-main"><div class="approval-title">' + esc(p.title) + "</div>" +
        (p.detail ? '<div class="approval-detail">' + esc(p.detail) + "</div>" : "") +
        '<div class="approval-detail"><a href="' + esc(p.review_href) + '">review &rarr;</a></div>' +
        '<div class="approval-error" data-approval-error="' + esc(p.id) + '"></div></div>';
      if (approvalState && approvalState.can_decide) {
        html += '<div class="approval-actions">' +
          '<button class="approve" data-decision-path="' + esc(p.approve_path) + '" data-approval-id="' + esc(p.id) + '">Approve</button>' +
          '<button class="deny" data-decision-path="' + esc(p.deny_path) + '" data-approval-id="' + esc(p.id) + '">Deny</button>' +
          "</div>";
      }
      html += "</div>";
    });
    var el = document.getElementById("approvals");
    el.innerHTML = html;
    if (approvalState && approvalState.can_decide) wireApprovalButtons(el);
  }

  function wireApprovalButtons(el) {
    Array.prototype.forEach.call(el.querySelectorAll("button[data-decision-path]"), function (button) {
      button.addEventListener("click", function () {
        var path = button.getAttribute("data-decision-path");
        var id = button.getAttribute("data-approval-id");
        if (!path) return;
        var row = id ? el.querySelector('[data-approval-row="' + id + '"]') : null;
        var rowButtons = row ? row.querySelectorAll("button[data-decision-path]") : [button];
        Array.prototype.forEach.call(rowButtons, function (b) { b.disabled = true; });
        var error = id ? el.querySelector('[data-approval-error="' + id + '"]') : null;
        if (error) error.textContent = "";
        postDecision(path, false).then(function (result) {
          if (result === null) {
            Array.prototype.forEach.call(rowButtons, function (b) { b.disabled = false; });
            return;
          }
          pollOnce();
        }).catch(function (err) {
          Array.prototype.forEach.call(rowButtons, function (b) { b.disabled = false; });
          if (error) error.textContent = "Decision failed: " + (err && err.message ? err.message : "unknown error");
        });
      });
    });
  }

  var STORY_PLAIN_SUMMARY_KEY = "postureStoryPlainSummary";
  var lastStoryDigest = null;

  function readStoryPlainSummaryPreference() {
    try {
      return typeof sessionStorage !== "undefined" &&
        sessionStorage.getItem(STORY_PLAIN_SUMMARY_KEY) === "1";
    } catch (e) {
      return false;
    }
  }

  function setStoryPlainSummaryPreference(enabled) {
    try {
      if (typeof sessionStorage !== "undefined") {
        sessionStorage.setItem(STORY_PLAIN_SUMMARY_KEY, enabled ? "1" : "0");
      }
    } catch (e) {}
  }

  function syncStoryToggle() {
    var toggle = document.getElementById("story-plain-summary");
    if (!toggle) return;
    toggle.checked = readStoryPlainSummaryPreference();
  }

  // S3 evidence spine for Today's story: the window the counts cover, how
  // recently that window closed, and the two links to the evidence behind them.
  // The digest carries window_start/window_end already; stating the window's
  // age stops a stale digest from reading as live. When the payload has no
  // window_end we say so rather than implying the counts are current.
  function storyEvidenceFoot(d) {
    var freshText = d && d.window_end ? relTime(d.window_end) : "";
    var fresh = freshText
      ? '<span class="stat-fresh" title="' + esc(d.window_end) + '">window closed ' + esc(freshText) + "</span>"
      : '<span class="stat-fresh none">window not stated</span>';
    return (
      '<div class="evidence stat-foot">' + fresh +
      '<span><a class="stat-ev" href="/posture/evidence">Evidence view &rarr;</a>' +
      ' &nbsp;<a class="stat-ev" href="/api/audit-log">signed audit feed &rarr;</a></span></div>'
    );
  }

  function renderStoryPlainSummary(d) {
    var chainText = d.chain_verified
      ? "The audit log verified clean: no tampering."
      : d.chain_verdict === "verified_suffix_only"
        ? "The recent audit log verified clean; the sealed legacy history is not re-verifiable at this privilege (run as root for a full verify)."
        : "The audit log is unverified: " + d.integrity_finding_count + " integrity finding(s).";
    return '<p class="story-summary">Today your agents ran <strong>' + esc(d.total_operations) +
      "</strong> operations in the last 24h. Sanctuary blocked <strong>" + esc(d.kernel_blocks) +
      "</strong> outbound connections and allowed <strong>" + esc(d.kernel_allows) +
      "</strong>. You denied <strong>" + esc(d.approvals_denied) +
      "</strong> approvals and granted <strong>" + esc(d.approvals_granted) +
      "</strong>. " + esc(chainText) + "</p>" +
      storyEvidenceFoot(d);
  }

  function renderStory(d) {
    var el = document.getElementById("story");
    lastStoryDigest = d;
    syncStoryToggle();
    if (readStoryPlainSummaryPreference()) {
      el.innerHTML = renderStoryPlainSummary(d);
      return;
    }
    // S3 denominators: each count states the whole it came out of, so a "4" is
    // legible as 4-of-2,113 rather than an unanchored number. The totals are
    // computed from fields already on the digest; nothing new is fetched.
    var connTotal = (d.kernel_blocks || 0) + (d.kernel_allows || 0);
    var decidedTotal = (d.approvals_denied || 0) + (d.approvals_granted || 0);
    var lines = [];
    lines.push("<strong>" + d.total_operations + "</strong> operations in the last 24h" +
      (d.failures ? ", " + d.failures + " of them failed." : "."));
    lines.push("<strong>" + d.kernel_blocks + "</strong> of " + connTotal +
      " observed outbound connections blocked at the kernel; " + d.kernel_allows + " allowed.");
    lines.push("<strong>" + d.approvals_denied + "</strong> of " + decidedTotal +
      " decided approvals denied by you, " + d.approvals_granted + " granted.");
    lines.push(d.chain_verified
      ? '<span class="pill green">Audit chain verified</span> no tampering.'
      : d.chain_verdict === "verified_suffix_only"
        ? '<span class="pill amber">Audit chain: recent verified, sealed history not re-verifiable at this privilege</span> (run as root for a full verify).'
        : '<span class="err">Audit chain UNVERIFIED (' + d.integrity_finding_count + " findings).</span>");
    el.innerHTML = lines.map(function (l) { return '<div class="story-line">' + l + "</div>"; }).join("") +
      storyEvidenceFoot(d);
  }

  function wireStoryToggle() {
    var toggle = document.getElementById("story-plain-summary");
    if (!toggle) return;
    syncStoryToggle();
    toggle.addEventListener("change", function () {
      setStoryPlainSummaryPreference(toggle.checked === true);
      if (lastStoryDigest) renderStory(lastStoryDigest);
    });
  }

  function renderAnomalies(findings) {
    var el = document.getElementById("anomalies");
    if (!findings || !findings.length) {
      // S3 quiet empty state: earned calm. This is the DETECTOR-ANSWERED empty
      // case only. The separate "detector did not respond" path elsewhere on
      // this page must never borrow this treatment: a silent detector is an
      // unknown, not a clean bill of health.
      el.innerHTML =
        '<div class="quiet"><span class="quiet-mark">&#9679;</span>' +
        "<span>No open anomaly findings." +
        '<span class="quiet-why"> The detector answered and reported nothing open.</span>' +
        "</span></div>";
      return;
    }
    el.innerHTML = findings.map(function (f) {
      return '<div class="story-line"><span class="pill amber">' + esc(f.severity || "finding") + "</span> " +
        esc(f.summary || f.detector_id || f.finding_id || "anomaly") + "</div>";
    }).join("");
  }

  // "Never fake green" for the fleet roster. GREEN (admitted) is earned ONLY by
  // the federation layer's own revocation verdict returning "not revoked" for a
  // node it could EVALUATE. A revoked node is red; an UNEVALUABLE node (the
  // fail-closed case) is also red ("untrusted"), NEVER amber and never green:
  // the same fail-closed model the sync chokepoint applies. The server already
  // computed this verdict via isNodeRevoked; the page only colors it.
  function fleetTrustPill(state) {
    if (state === "admitted") return '<span class="pill green">ADMITTED</span>';
    if (state === "revoked") return '<span class="pill red">REVOKED</span>';
    // untrusted == unevaluable revocation state, fail-closed. Red, not amber.
    return '<span class="pill red">UNTRUSTED</span>';
  }

  // Reach is liveness telemetry, NOT a trust signal, so it uses a SEPARATE,
  // muted vocabulary and never a green/red trust pill: a node's reach can never
  // launder it into looking trusted. "recent" is informational, not "all well."
  function fleetReachLabel(reach) {
    if (reach === "recent") return '<span class="pill" style="background:var(--surface-2)">reachable</span>';
    if (reach === "stale") return '<span class="pill amber">no recent sync</span>';
    return '<span class="pill amber">never synced</span>';
  }

  function fleetTrustWhy(node) {
    if (node.trust_state === "admitted") {
      return "Admitted to the fleet. The federation layer confirms this machine is not revoked.";
    }
    if (node.trust_state === "revoked") {
      return "Revoked by you. This machine is locked out across the fleet.";
    }
    // untrusted: distinguish the fail-closed unevaluable case in plain English.
    return node.trust_evaluable === false
      ? "Trust could not be evaluated for this machine right now, so it is shown UNTRUSTED by design (fail-closed), not assumed safe."
      : "This machine is not in good standing and is shown untrusted.";
  }

  // Fleet-wide sync-health rollup (A1). LIVENESS only: it reports how many
  // machines are currently in touch, NEVER a trust claim. It uses the muted reach
  // vocabulary (not a green/red trust pill) so a reachable-but-revoked node can
  // never read as "all well." Honest when nothing has ever synced.
  function fleetSyncHealthLine(h) {
    if (!h) return "";
    var parts = [];
    if (h.reachable) parts.push(esc(h.reachable) + " in touch");
    if (h.stale) parts.push(esc(h.stale) + " no recent sync");
    if (h.never) parts.push(esc(h.never) + " never synced");
    var summary = parts.length ? parts.join(" · ") : "no sync activity yet";
    var frontier = h.oldest_last_sync
      ? " · oldest sync " + esc(h.oldest_last_sync)
      : "";
    return '<div class="evidence">Fleet reach (liveness, not trust): ' +
      summary + frontier + "</div>";
  }

  // Signed-policy-distribution status (A2). Custody-state distribution only:
  // hash/version markers from verified signed bundles, never raw policy
  // contents. Unknown is never green.
  function fleetPolicySummaryText(pd) {
    if (!pd || pd.available !== true) return "policy unknown";
    var summary = pd.summary || { in_sync: 0, drifted: 0, unknown: 0 };
    var policy = pd.operator_policy;
    if (!policy || policy.version == null || !policy.hash || !policy.hash_algorithm) {
      return "no operator policy";
    }
    var total = summary.in_sync + summary.drifted + summary.unknown;
    return "operator policy v" + policy.version +
      " · " + summary.in_sync + " of " + total + " nodes in sync" +
      " / " + summary.drifted + " drifted" +
      " / " + summary.unknown + " unknown";
  }

  function fleetPolicyDistributionLine(pd) {
    if (!pd || pd.available !== true) {
      return '<div class="evidence">' +
        '<span class="pill amber">policy unknown</span> &nbsp;' +
        "Policy distribution status cannot be evaluated for this fleet.</div>";
    }
    var summary = pd.summary || { in_sync: 0, drifted: 0, unknown: 0 };
    var policy = pd.operator_policy;
    if (!policy || policy.version == null || !policy.hash || !policy.hash_algorithm) {
      return '<div class="evidence">' +
        '<span class="pill amber">policy unknown</span> &nbsp;' +
        "No signed operator policy bundle is known yet. " +
        "Nodes render policy drift as unknown until an operator policy hash is distributed.</div>";
    }
    var total = summary.in_sync + summary.drifted + summary.unknown;
    return '<div class="evidence">' +
      '<span class="pill">operator policy v' + esc(policy.version) + "</span> &nbsp;" +
      esc(summary.in_sync) + " of " + esc(total) + " nodes in sync" +
      " / " + esc(summary.drifted) + " drifted" +
      " / " + esc(summary.unknown) + " unknown" +
      " · hash " + esc(policy.hash_algorithm) + ":" + esc(policy.hash) + "</div>";
  }

  function fleetPolicyPill(state) {
    if (state === "in_sync") return '<span class="pill green">policy in sync</span>';
    if (state === "drifted") return '<span class="pill red">policy drifted</span>';
    return '<span class="pill amber">policy unknown</span>';
  }

  function fleetPolicyEvidence(policy) {
    if (!policy || policy.version == null) {
      return "applied policy unknown";
    }
    var base = "applied policy v" + policy.version;
    if (policy.hash && policy.hash_algorithm) {
      base += " hash " + policy.hash_algorithm + ":" + policy.hash;
    } else {
      base += " hash unknown";
    }
    if (policy.applied_at) base += " applied " + policy.applied_at;
    return base;
  }

  function renderFleet(roster) {
    var section = document.getElementById("fleet-section");
    var el = document.getElementById("fleet");
    var summaryEl = document.getElementById("fleet-summary");
    if (!section || !el) return;
    // Honest absence: a fortress with no federation provisioned has no fleet to
    // present. Keep the section hidden rather than render an empty green shell.
    if (!roster || roster.available !== true) {
      section.style.display = "none";
      return;
    }
    section.style.display = "";
    var s = roster.summary || { total: 0, admitted: 0, revoked: 0, untrusted: 0 };
    if (summaryEl) {
      var parts = [esc(s.total) + " machine" + (s.total === 1 ? "" : "s")];
      if (s.admitted) parts.push(esc(s.admitted) + " admitted");
      if (s.revoked) parts.push(esc(s.revoked) + " revoked");
      if (s.untrusted) parts.push(esc(s.untrusted) + " untrusted");
      parts.push(fleetPolicySummaryText(roster.policy_distribution));
      summaryEl.textContent = parts.join(" · ");
    }
    var head =
      '<div class="evidence">Fleet ' + (roster.enabled ? "on" : "off") +
      " · this machine <code>" + esc(roster.node_id) + "</code>" +
      " · fortress <code>" + esc(roster.fortress_id) + "</code>" +
      " · eviction serial " + esc(roster.eviction_serial) + "</div>" +
      fleetSyncHealthLine(roster.sync_health) +
      fleetPolicyDistributionLine(roster.policy_distribution);
    var nodes = roster.nodes || [];
    if (!nodes.length) {
      el.innerHTML = head +
        '<div class="empty">No other machines admitted to this fleet yet.</div>';
      return;
    }
    var rows = nodes.map(function (n) {
      var modeNote = n.provider_in_trust_boundary
        ? ' · <span class="why">provider in trust boundary</span>'
        : "";
      return '<div class="story-line">' +
        fleetTrustPill(n.trust_state) + " &nbsp;" +
        fleetPolicyPill(n.policy && n.policy.drift_state) + " &nbsp;" +
        "<code>" + esc(n.node_id) + "</code>" +
        (n.label ? " (" + esc(n.label) + ")" : "") +
        " &nbsp;" + fleetReachLabel(n.reach) +
        '<div class="evidence">' + esc(fleetTrustWhy(n)) +
        " · mode " + esc(n.node_mode) + modeNote +
        " · " + esc(fleetPolicyEvidence(n.policy)) +
        // S3 freshness: a machine's staleness is the point of this line, and an
        // age states it directly. "no sync received" stays explicit -- a silent
        // machine must never render as a recently-synced one.
        (n.last_sync_received_at
          ? ' · last sync <span title="' + esc(n.last_sync_received_at) + '">' +
            esc(relTime(n.last_sync_received_at) || n.last_sync_received_at) + "</span>"
          : " · no sync received") +
        "</div></div>";
    }).join("");
    el.innerHTML = head + rows;
  }

  function renderWall(w) {
    var el = document.getElementById("wall");
    // S5-P: when the arm-state is capped to coarse_only, the precise meaning
    // depends on the WORST per-agent mode carried on the exclusive_egress
    // block: coarse-only (coarse wall enforcing, fine stack down) vs
    // unprotected (a fine-grained agent has NO coarse wall either). Never
    // assert coarse protection when the worst mode is unprotected.
    var coarseMeaning =
      w.exclusive_egress && w.exclusive_egress.mode === "unprotected"
        ? "A fine-grained agent is UNPROTECTED: its exclusive-egress stack is not live AND coarse Castle Wall enforcement is not confirmed for this fortress. Not green by design."
        : "The coarse wall is enforcing, but a fine-grained agent's exclusive-egress stack (gate, pf, generation) is NOT live. Not green by design.";
    var meaning = w.arm_state === "armed"
      ? "The operating system is blocking unauthorized outbound connections from wrapped agents."
      : w.arm_state === "coarse_only"
        ? coarseMeaning
        : w.arm_state === "degraded"
          ? "The wall is present but recent evidence shows it is NOT enforcing."
          : w.arm_state === "not_installed"
            ? "Castle Wall is not installed on this machine."
            : "Enforcement could not be proven from recent audit evidence. Not rendered green by design.";
    // S5-P: the exclusive-egress posture block (design section 6), rendered
    // whenever the wall posture carries it. Non-live reasons are listed so the
    // coarse-only state is a first-class story, never a footnote.
    var exclusiveDetail = "";
    var x = w.exclusive_egress;
    if (x && x.fine_grained_declared) {
      var xLabel = x.exclusive_egress_live
        ? "live (all fine-grained agents exclusive)"
        : "NOT live" + (x.mode ? " (" + esc(x.mode) + ")" : "");
      exclusiveDetail =
        '<div class="evidence">Exclusive egress: <code>' + xLabel + "</code>" +
        (x.reasons && x.reasons.length
          ? " · " + esc(x.reasons.join(" · "))
          : "") +
        "</div>";
    }
    el.innerHTML =
      "<div>" + wallPill(w.arm_state) + " &nbsp;" + esc(meaning) + "</div>" +
      exclusiveDetail +
      // S3 denominator: the three verdict counts are parts of one total, so the
      // total is stated rather than left for the reader to add up. A zero total
      // says "no traffic observed", which is NOT the same claim as "nothing was
      // blocked" -- an unarmed wall also reports zeros.
      '<div class="evidence">Platform: ' + esc(w.platform) +
      " · verdicts (24h): " +
      (w.verdict_counts.allowed + w.verdict_counts.blocked + w.verdict_counts.operator_decisions) +
      " observed, of which " + w.verdict_counts.allowed + " allowed / " +
      w.verdict_counts.blocked + " blocked / " +
      w.verdict_counts.operator_decisions + " operator decisions</div>" +
      '<div class="evidence">Evidence basis: <code>' + esc(w.evidence_basis) + "</code>" +
      // S3 freshness: the age of the evidence the wall's color rests on. When
      // there is none, say so outright -- absence of evidence must read as
      // absence, never as a fresh check.
      (w.last_enforcement_evidence_at
        ? ' · last enforcement <span title="' + esc(w.last_enforcement_evidence_at) + '">' +
          esc(relTime(w.last_enforcement_evidence_at) || w.last_enforcement_evidence_at) + "</span>"
        : " · no enforcement evidence on record") + "</div>" +
      // Slice R: honestly surface the cryptographic basis the green light rests
      // on. producer_signed = the daemon producer signature was re-verified at
      // read time. channel_authenticated = the green rests on the mutually-
      // pinned IPC channel + tamper-evident chain only (the honest macOS / pre-
      // provision floor; NOT per-producer authenticated). Only shown when armed.
      (w.arm_state === "armed" && w.producer_authenticity
        ? '<div class="evidence">Authenticity: <code>' + esc(w.producer_authenticity) + "</code>" +
          (w.producer_authenticity === "producer_signed"
            ? " (enforcement evidence cryptographically re-verified against the pinned producer key)"
            : " (channel-authenticated + tamper-evident chain; per-producer signing not available on this reader)") +
          "</div>"
        : "") +
      (w.audit_integrity_ok ? "" : '<div class="err">Audit integrity finding present - arm-state read may be incomplete.</div>');
  }

  // ── Render the whole board from one honest home payload ─────────────────
  // Both the SSE live path and the poll fallback call this with the SAME shape,
  // so there is ONE rendering path and no second, weaker green model. The
  // pending-approvals + anomaly findings come from the existing endpoints (not
  // carried on the home payload), so the caller passes the most recent values it
  // has; both default to empty arrays when never fetched.
  function renderHome(home, approvals, findings) {
    approvals = approvals || { rows: [], can_decide: false, mode: "unknown", source: "none" };
    findings = findings || [];
    renderBanner(home, approvals, findings);
    renderAgents(home);
    renderApprovals(approvals);
    renderStory(home.digest);
    renderAnomalies(findings);
    renderWall(home.castle_wall);
    renderFeatures(home.feature_health);
    renderCustodyExit(home.custody_exit);
    renderQueryPrivacy(home.query_privacy);
  }

  // ── Honest connection indicator (#617) ──────────────────────────────────
  // The single most important honesty rule on this surface: a stale view must
  // NEVER be mistaken for a live green-all-well. The indicator has exactly two
  // colors: "live" (green dot) is shown ONLY when a fresh frame arrived inside
  // the staleness window; any drop, error, or simply going quiet past the window
  // flips it to "reconnecting" (amber dot) and keeps the "last updated <time>"
  // so the operator can see the data on screen may be stale. The tile colors
  // (wall pill, agent pills, etc.) are NEVER touched here - they keep whatever
  // honest value the last real frame produced - but the connection banner makes
  // the freshness of that frame unmistakable.
  var lastFrameAt = null; // ms epoch of the last successful render, or null.
  var streamAvailable = false;
  // If no fresh frame arrives within this window, the view is treated as stale
  // even if a socket is nominally open. Comfortably larger than the server push
  // cadence (5s) + heartbeat (15s) so a single missed tick is not flapped.
  var STALENESS_WINDOW_MS = 20000;
  function pad2(n) { return (n < 10 ? "0" : "") + n; }
  function fmtTime(ms) {
    var d = new Date(ms);
    return pad2(d.getHours()) + ":" + pad2(d.getMinutes()) + ":" + pad2(d.getSeconds());
  }
  function setConn(stateName) {
    var el = document.getElementById("conn");
    var label = document.getElementById("conn-label");
    var updated = document.getElementById("conn-updated");
    if (!el || !label || !updated) return;
    el.classList.remove("live", "reconnecting");
    if (stateName === "live") {
      el.classList.add("live");
      label.textContent = "Live";
    } else {
      // reconnecting / connecting / stale all read as "reconnecting" amber so a
      // stale screen can never look like a healthy live one.
      el.classList.add("reconnecting");
      label.textContent = "Reconnecting…";
    }
    updated.textContent = lastFrameAt
      ? " · last updated " + fmtTime(lastFrameAt)
      : " · no data received yet";
  }
  // Watchdog: if the last fresh frame is older than the staleness window, force
  // the indicator to "reconnecting" regardless of socket state. This is what
  // makes silence honest - an open-but-quiet socket cannot keep a green "Live".
  function tickStaleness() {
    if (lastFrameAt === null) return;
    if (Date.now() - lastFrameAt > STALENESS_WINDOW_MS) setConn("reconnecting");
  }
  setInterval(tickStaleness, 3000);

  // ── Auxiliary fetches (pending approvals + anomaly findings) ────────────
  // Not carried on the home payload, so refreshed alongside each home frame.
  // Failures degrade to empty (never block the home render); these are honest
  // empties, not green claims.
  var lastApprovals = { rows: [], can_decide: false, mode: "unknown", source: "none" };
  var lastFindings = [];
  function refreshAuxiliary() {
    return Promise.all([
      api("/api/pending").catch(function () { return []; }),
      api("/api/approval-inbox?status=pending").catch(function () { return { data: { entries: [] } }; }),
      api("/api/status").catch(function () { return null; }),
      api("/api/anomaly/findings").catch(function () { return { findings: [] }; }),
    ]).then(function (rest) {
      lastApprovals = buildApprovalState(rest[0], rest[1], rest[2]);
      lastFindings = rest[3].findings || rest[3] || [];
    });
  }

  // Apply a fresh home payload: refresh auxiliaries, render, stamp the frame
  // time, and mark the connection Live. This is the ONLY place lastFrameAt is
  // advanced, so the "Live" indicator is earned by a real, fully-rendered frame.
  function applyHome(home) {
    return refreshAuxiliary().then(function () {
      streamAvailable = home && home.stream_available === true;
      renderHome(home, lastApprovals, lastFindings);
      lastFrameAt = Date.now();
      setConn("live");
    });
  }

  // ── Poll fallback (progressive enhancement) ─────────────────────────────
  // Used when EventSource is unavailable in the browser, OR while the SSE
  // stream is down (so the board keeps updating even with no live stream). The
  // page therefore works exactly as before if SSE never connects. A failed poll
  // surfaces an honest error in the banner and leaves the indicator amber.
  function pollOnce() {
    return api("/api/posture/home")
      .then(function (home) {
        return applyHome(home).then(function () {
          if (supportsSSE && streamAvailable && !es && reconnectTimer === null) connectStream();
        });
      })
      .catch(function (e) {
        setConn("reconnecting");
        document.getElementById("banner").innerHTML =
          '<span class="err">Could not load posture: ' + esc(e.message) + "</span>";
      });
  }

  var pollTimer = null;
  function startPolling() {
    if (pollTimer !== null) return;
    pollOnce();
    pollTimer = setInterval(pollOnce, 15000);
  }
  function stopPolling() {
    if (pollTimer !== null) { clearInterval(pollTimer); pollTimer = null; }
  }

  // ── SSE live stream with reconnect-and-restore ──────────────────────────
  // Mirrors the v1.1 dashboard reconnect pattern: on error, close the source,
  // schedule a reconnect via reconnectTimer (capped backoff, never a tight
  // loop), and fall back to polling in the meantime so the board still updates.
  // An "error" event from the server (a failed buildHome read) is treated like
  // a drop - the indicator goes amber, the stale data is never relabeled fresh.
  var es = null;
  var reconnectTimer = null;
  var reconnectDelayMs = 1000;
  var RECONNECT_MAX_MS = 30000;
  var supportsSSE = typeof window !== "undefined" && "EventSource" in window;

  function scheduleReconnect() {
    setConn("reconnecting");
    // Keep polling while disconnected so the board stays current (and honest:
    // each poll advances lastFrameAt only on success).
    startPolling();
    if (reconnectTimer !== null) return;
    reconnectTimer = setTimeout(function () {
      reconnectTimer = null;
      reconnectDelayMs = Math.min(reconnectDelayMs * 2, RECONNECT_MAX_MS);
      connectStream();
    }, reconnectDelayMs);
  }

  function connectStream() {
    if (!streamAvailable) { startPolling(); return; }
    if (!supportsSSE) { startPolling(); return; }
    if (es) { try { es.close(); } catch (e) {} es = null; }
    // EventSource cannot set an Authorization header. On loopback / cookie auth
    // the bare stream URL authenticates via same-origin loopback auto-auth or the
    // session cookie (withCredentials sends it), and mintStreamSession() returns
    // "" so nothing changes. In a remote token-hash session with no cookie,
    // mintStreamSession() exchanges the bearer (in the POST header, never a URL)
    // for a SHORT-LIVED session id and we connect via ?session=<id> - the SEC-012
    // handshake. Any mint failure / 401 resolves to "" (no throw); we still open
    // the bare stream, and if that cannot authenticate the existing onerror path
    // schedules a reconnect and keeps polling, so the board stays honest and the
    // page never blocks. The long-lived token is NEVER placed in a URL.
    mintStreamSession().then(function (sessionQuery) {
      // Guard against a connectStream() that was superseded while the async mint
      // was in flight (e.g. a reconnect fired): only open if we still have no es.
      if (es) return;
      var url = "/api/posture/stream" + (sessionQuery || "");
      try {
        es = new EventSource(url, { withCredentials: true });
      } catch (e) {
        scheduleReconnect();
        return;
      }
      wireStream();
    });
  }

  // Attach the SSE listeners to the live EventSource. Split out of connectStream
  // so the async mint handshake can open the source first.
  function wireStream() {
    es.addEventListener("home", function (ev) {
      var home;
      try { home = JSON.parse(ev.data); } catch (e) { return; }
      // A good frame: stop the poll fallback (the stream is healthy), reset the
      // backoff, render, and mark Live.
      reconnectDelayMs = 1000;
      stopPolling();
      applyHome(home);
    });
    // Server-emitted honest failure frame (buildHome read failed). Do NOT render
    // anything - keep the last data but flip the indicator to reconnecting so the
    // operator knows it is not fresh. The watchdog will keep it amber.
    es.addEventListener("error", function () {
      // EventSource fires 'error' both for server "error" events and for socket
      // drops; in both cases the honest action is the same: go amber + reconnect.
      setConn("reconnecting");
    });
    es.onerror = function () {
      // Transport-level drop. Close and reconnect with backoff + poll fallback.
      if (es) { try { es.close(); } catch (e) {} es = null; }
      scheduleReconnect();
    };
  }

  // ── Boot ────────────────────────────────────────────────────────────────
  // Progressive enhancement: render once immediately (so the page is correct on
  // first paint even before the stream connects), then attach the live stream.
  // If SSE is unavailable, this degrades to the prior poll-only behavior.
  setConn("reconnecting");
  wireStoryToggle();
  pollOnce().then(function () {
    if (!supportsSSE || !streamAvailable) startPolling();
  });
  // Recognition + portability (P5) is a separate, composition-gated fetch (it is
  // NOT on the home payload, so an off-fortress never receives any of its data).
  // Loaded once at boot: the gate flag is config and stable within a session.
  loadRecognitionOnce();
  // Fleet roster (Fleet Console Slice 1) is a separate, federation-gated fetch
  // (also NOT on the home payload). Loaded at boot; it self-schedules a refresh
  // cadence on first success so revocations flip the board live.
  loadFleetOnce();
})();
</script>
</body>
</html>`;
}
