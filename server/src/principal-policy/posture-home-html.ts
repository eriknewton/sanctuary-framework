/**
 * Sovereignty Posture Dashboard — Phase 1 home HTML.
 *
 * A single self-contained page that renders the posture board: the banner, the
 * agent grid (wrapped + detected-unwrapped amber cards), the approvals inbox,
 * "today's story," anomaly findings, and the Castle Wall panel — with a
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
 * reach endpoint. "Never fake green" is enforced in the renderer — the banner
 * shows ARMED green only when `arm_state === "armed"`; `unknown` is amber and
 * `degraded` is red.
 *
 * Returns a string so the dashboard can serve it directly (mirrors
 * `generateDashboardHTML`).
 */

import type { FeatureHealthStatus } from "./feature-health.js";
import type { CustodyState } from "./posture.js";
import { AGENT_PILL_FN_SOURCE } from "./posture-html-shared.js";

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
 * is red (earned by fresh negative evidence), and there is no green branch — a
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
<title>Sanctuary — Sovereignty Posture</title>
<style>
  :root {
    --bg: #0e1116; --panel: #161b22; --panel-2: #1c2330; --border: #2a313c;
    --text: #e6edf3; --muted: #9aa6b2; --green: #2ea043; --amber: #d29922;
    --red: #f85149; --accent: #58a6ff;
  }
  * { box-sizing: border-box; }
  body {
    margin: 0; background: var(--bg); color: var(--text);
    font: 14px/1.5 -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
  }
  header { padding: 16px 24px; border-bottom: 1px solid var(--border); }
  h1 { font-size: 16px; margin: 0; font-weight: 600; letter-spacing: .2px; }
  .sub { color: var(--muted); font-size: 12px; margin-top: 2px; }
  main { padding: 20px 24px; max-width: 1100px; margin: 0 auto; }
  .banner {
    display: flex; flex-wrap: wrap; gap: 14px; padding: 16px;
    background: var(--panel); border: 1px solid var(--border); border-radius: 10px;
    margin-bottom: 20px;
  }
  .stat { display: flex; flex-direction: column; min-width: 130px; }
  .stat .v { font-size: 22px; font-weight: 700; }
  .stat .l { color: var(--muted); font-size: 12px; text-transform: uppercase; letter-spacing: .4px; }
  .pill { display: inline-block; padding: 2px 8px; border-radius: 999px; font-size: 11px; font-weight: 600; }
  .pill.green { background: rgba(46,160,67,.18); color: var(--green); }
  .pill.amber { background: rgba(210,153,34,.18); color: var(--amber); }
  .pill.red { background: rgba(248,81,73,.18); color: var(--red); }
  section { margin-bottom: 24px; }
  section > h2 { font-size: 13px; text-transform: uppercase; letter-spacing: .5px; color: var(--muted); margin: 0 0 10px; }
  .grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(260px, 1fr)); gap: 12px; }
  .card {
    background: var(--panel); border: 1px solid var(--border); border-radius: 10px;
    padding: 14px;
  }
  .card.amber { border-color: var(--amber); }
  .card h3 { margin: 0 0 4px; font-size: 14px; }
  .card .meta { color: var(--muted); font-size: 12px; }
  .reach { margin-top: 8px; font-size: 12px; color: var(--muted); }
  a { color: var(--accent); text-decoration: none; }
  a:hover { text-decoration: underline; }
  .panel { background: var(--panel); border: 1px solid var(--border); border-radius: 10px; padding: 16px; }
  .story-line { margin: 4px 0; }
  .fh-row { display: flex; align-items: baseline; gap: 8px; padding: 6px 0; border-bottom: 1px solid var(--border); }
  .fh-row:last-child { border-bottom: 0; }
  .fh-row .name { flex: 1; }
  .fh-row .why { color: var(--muted); font-size: 12px; }
  .fh-note { color: var(--muted); font-size: 11px; margin-top: 10px; }
  .footer {
    margin: 24px 0 8px; padding: 14px 16px; background: var(--panel-2);
    border: 1px solid var(--border); border-radius: 10px; color: var(--muted); font-size: 12px;
  }
  .footer strong { color: var(--text); }
  .empty { color: var(--muted); font-style: italic; }
  .err { color: var(--red); }
  code { background: var(--panel-2); padding: 1px 5px; border-radius: 4px; font-size: 12px; }
  .evidence { font-size: 11px; color: var(--muted); margin-top: 6px; }
  button.guided {
    margin-top: 8px; background: var(--panel-2); color: var(--text);
    border: 1px solid var(--border); border-radius: 6px; padding: 5px 10px; cursor: pointer; font-size: 12px;
  }
  button.guided:hover { border-color: var(--accent); }
  /* Live-refresh connection indicator. The dot color is the at-a-glance honesty
     signal: green = a fresh frame arrived inside the staleness window; amber =
     reconnecting / no recent frame (the data on screen may be stale). It is
     NEVER green merely because a stream socket is open. */
  .conn { display: flex; align-items: center; gap: 6px; font-size: 12px; color: var(--muted); margin-top: 4px; }
  .conn .dot { width: 8px; height: 8px; border-radius: 50%; background: var(--muted); flex: none; }
  .conn.live .dot { background: var(--green); }
  .conn.reconnecting .dot { background: var(--amber); }
  .conn .updated { color: var(--muted); }
</style>
</head>
<body>
<header>
  <h1>Sanctuary — Sovereignty Posture</h1>
  <div class="sub" id="origin">Loading…</div>
  <div class="conn" id="conn">
    <span class="dot"></span>
    <span id="conn-label">Connecting…</span>
    <span class="updated" id="conn-updated"></span>
  </div>
</header>
<main>
  <div class="banner" id="banner"><span class="empty">Loading posture…</span></div>

  <section>
    <h2>Agents</h2>
    <div class="grid" id="agents"><span class="empty">Loading…</span></div>
  </section>

  <section>
    <h2>Approvals waiting</h2>
    <div class="panel" id="approvals"><span class="empty">Loading…</span></div>
  </section>

  <section>
    <h2>Today's story</h2>
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

  function api(path) {
    var opts = { credentials: "same-origin", headers: {} };
    if (token) opts.headers["Authorization"] = "Bearer " + token;
    return fetch(path, opts).then(function (r) {
      if (!r.ok) throw new Error(path + " -> " + r.status);
      return r.json();
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

  // "Never fake green": ARMED is the ONLY green arm-state.
  function wallPill(state) {
    if (state === "armed") return '<span class="pill green">ARMED</span>';
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

  // "Never fake green" for the feature-health panel. Mirrors the canonical
  // pure mapper exported from this module (featureHealthPill). GREEN is earned
  // ONLY by "active"; "fault" is red; "unconfirmed" and "unknown" are amber and
  // are NEVER green. This is the same color model the /api/posture/feature-health
  // endpoint enforces (feature-health.ts) - the surface must not weaken it.
  function featurePill(status) {
    if (status === "active") return '<span class="pill green">active</span>';
    if (status === "fault") return '<span class="pill red">fault</span>';
    if (status === "unconfirmed") return '<span class="pill amber">unconfirmed</span>';
    return '<span class="pill amber">unknown</span>';
  }

  // Plain-English reason copy, derived from the endpoint's stable basis enum.
  // Never leaks rule internals; phrases the honest non-green cases plainly.
  function featureWhy(row) {
    switch (row.basis) {
      case "fresh_enforcement_evidence":
        return "Confirmed by fresh enforcement evidence.";
      case "activity_in_window":
        return "Activity observed in the last 24h.";
      case "fault_evidence":
        return "A fault event was observed; not enforcing.";
      case "stale_evidence":
        return "Evidence is stale; recent state cannot be confirmed.";
      case "no_evidence_self_reporting":
        return "No recent evidence; working state cannot be confirmed.";
      case "no_activity_event_driven":
        return row.broken_zero_detectable === false
          ? "No activity in window. A silently-disabled feature is undetectable here, so this is shown as unconfirmed, not green."
          : "No activity in the window.";
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
        " · observed " + esc(e.observed_at) + "</div>";
    }
    if (panel.last_damage_evidence_at) {
      html += '<div class="evidence">Last custody-damage evidence: ' +
        esc(panel.last_damage_evidence_at) + "</div>";
    }
    if (!panel.audit_integrity_ok) {
      html += '<div class="err">Audit integrity finding present - custody read may be incomplete.</div>';
    }
    // Exit / portability: the honest capability statement. The Tier-1-gated CLI
    // export exists; the FULL clean-exit guarantee is NOT yet earned, so we say
    // "export available" and never assert the full clean-exit claim on Home.
    html +=
      '<div class="evidence" style="margin-top:10px">Exit and portability: ' +
      (panel.exit_state === "export_available"
        ? '<span class="pill amber">export available</span> ' +
          "Export your fortress as a portable bundle with <code>" +
          esc(panel.exit_command || "sanctuary exit") +
          "</code> (a Tier-1 operation: it requires your approval before it runs)."
        : "unknown") +
      "</div>";
    html +=
      '<div class="fh-note">Export available does not yet mean a guaranteed clean exit: ' +
      "the portable-bundle export ships, but the full clean-exit guarantee (complete, " +
      "verifiable handover with nothing left behind) is not yet earned, so it is not claimed here.</div>";
    el.innerHTML = html;
  }

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

  function renderBanner(home, pending, anomalies) {
    var openAnomalies = (anomalies && anomalies.length) || 0;
    var pendingCount = (pending && pending.length) || 0;
    document.getElementById("origin").textContent =
      "Machine: " + home.origin_machine + " · single-machine view (federation off)";
    document.getElementById("banner").innerHTML =
      // Honest split (#634): "protection requested" is policy intent; "enforcement
      // confirmed" is the observed-live count. Reporting only a flat "protected"
      // number overstated enforcement the server cannot prove.
      stat(home.protection_requested_count, "Protection requested") +
      stat(home.enforcement_confirmed_count, "Enforcement confirmed") +
      stat(wallPill(home.castle_wall.arm_state), "Castle Wall") +
      stat(pendingCount, "Approvals waiting") +
      stat(openAnomalies, "Open anomalies") +
      stat(home.digest.chain_verified ? '<span class="pill green">VERIFIED</span>' : '<span class="pill red">UNVERIFIED</span>', "Audit chain");
  }
  function stat(value, label) {
    return '<div class="stat"><span class="v">' + value + '</span><span class="l">' + esc(label) + "</span></div>";
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
    if (!html) html = '<span class="empty">No agents detected.</span>';
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

  function renderApprovals(pending) {
    if (!pending || !pending.length) {
      document.getElementById("approvals").innerHTML = '<span class="empty">Nothing needs you.</span>';
      return;
    }
    var html = "";
    pending.forEach(function (p) {
      html += '<div class="story-line">' + esc(p.operation || p.id || "pending operation") +
        ' — <a href="/api/pending">review &rarr;</a></div>';
    });
    document.getElementById("approvals").innerHTML = html;
  }

  function renderStory(d) {
    var el = document.getElementById("story");
    var lines = [];
    lines.push("<strong>" + d.total_operations + "</strong> operations in the last 24h.");
    lines.push("<strong>" + d.kernel_blocks + "</strong> outbound connections blocked at the kernel; " +
      d.kernel_allows + " allowed.");
    lines.push("<strong>" + d.approvals_denied + "</strong> approvals denied, " +
      d.approvals_granted + " granted by you.");
    lines.push(d.chain_verified
      ? '<span class="pill green">Audit chain verified</span> no tampering.'
      : '<span class="err">Audit chain UNVERIFIED (' + d.integrity_finding_count + " findings).</span>");
    el.innerHTML = lines.map(function (l) { return '<div class="story-line">' + l + "</div>"; }).join("") +
      '<div class="evidence"><a href="/api/audit-log">Open the signed audit feed &rarr;</a></div>';
  }

  function renderAnomalies(findings) {
    var el = document.getElementById("anomalies");
    if (!findings || !findings.length) {
      el.innerHTML = '<span class="empty">No open anomaly findings.</span>';
      return;
    }
    el.innerHTML = findings.map(function (f) {
      return '<div class="story-line"><span class="pill amber">' + esc(f.severity || "finding") + "</span> " +
        esc(f.summary || f.detector_id || f.finding_id || "anomaly") + "</div>";
    }).join("");
  }

  function renderWall(w) {
    var el = document.getElementById("wall");
    var meaning = w.arm_state === "armed"
      ? "The operating system is blocking unauthorized outbound connections from wrapped agents."
      : w.arm_state === "degraded"
        ? "The wall is present but recent evidence shows it is NOT enforcing."
        : w.arm_state === "not_installed"
          ? "Castle Wall is not installed on this machine."
          : "Enforcement could not be proven from recent audit evidence. Not rendered green by design.";
    el.innerHTML =
      "<div>" + wallPill(w.arm_state) + " &nbsp;" + esc(meaning) + "</div>" +
      '<div class="evidence">Platform: ' + esc(w.platform) +
      " · verdicts (24h): " + w.verdict_counts.allowed + " allowed / " + w.verdict_counts.blocked + " blocked / " +
      w.verdict_counts.operator_decisions + " operator decisions</div>" +
      '<div class="evidence">Evidence basis: <code>' + esc(w.evidence_basis) + "</code>" +
      (w.last_enforcement_evidence_at ? " · last enforcement " + esc(w.last_enforcement_evidence_at) : "") + "</div>" +
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
      (w.audit_integrity_ok ? "" : '<div class="err">Audit integrity finding present — arm-state read may be incomplete.</div>');
  }

  // ── Render the whole board from one honest home payload ─────────────────
  // Both the SSE live path and the poll fallback call this with the SAME shape,
  // so there is ONE rendering path and no second, weaker green model. The
  // pending-approvals + anomaly findings come from the existing endpoints (not
  // carried on the home payload), so the caller passes the most recent values it
  // has; both default to empty arrays when never fetched.
  function renderHome(home, pending, findings) {
    pending = pending || [];
    findings = findings || [];
    renderBanner(home, pending, findings);
    renderAgents(home);
    renderApprovals(pending);
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
  var lastPending = [];
  var lastFindings = [];
  function refreshAuxiliary() {
    return Promise.all([
      api("/api/pending").catch(function () { return { pending: [] }; }),
      api("/api/anomaly/findings").catch(function () { return { findings: [] }; }),
    ]).then(function (rest) {
      lastPending = rest[0].pending || rest[0] || [];
      lastFindings = rest[1].findings || rest[1] || [];
    });
  }

  // Apply a fresh home payload: refresh auxiliaries, render, stamp the frame
  // time, and mark the connection Live. This is the ONLY place lastFrameAt is
  // advanced, so the "Live" indicator is earned by a real, fully-rendered frame.
  function applyHome(home) {
    return refreshAuxiliary().then(function () {
      renderHome(home, lastPending, lastFindings);
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
      .then(function (home) { return applyHome(home); })
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
  pollOnce().then(function () {
    if (supportsSSE) connectStream();
    else startPolling();
  });
})();
</script>
</body>
</html>`;
}
