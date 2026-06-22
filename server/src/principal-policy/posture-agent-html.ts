/**
 * Sovereignty Posture Dashboard - per-agent drill-down HTML (Slice 4).
 *
 * A single self-contained page for ONE agent, served at `/posture/agent/:id`.
 * It composes data that already ships - it adds NO new server endpoint:
 *
 *   1. Effective reach: the existing `/api/posture/reach/:id` (G5) shaper,
 *      rendered as a per-destination table annotated by the layer that enforces
 *      each line (castle_wall = OS-blocked; policy = cooperative).
 *   2. Standing: the agent's honest posture row from `/api/posture/home`
 *      (the Slice 1 PostureAgentRow), rendered with the SAME never-fake-green
 *      pill model as the Home grid - green only on confirmed live enforcement,
 *      amber for policy-only "protection requested", red for not-enforcing.
 *
 * HONESTY CONTRACT (#617/#634): every status here is evidence-based. Green is
 * reserved for `enforcement_active === "active"`. Unknown / unconfirmed reads
 * amber, never green. The page reuses the canonical shapers; it never invents a
 * green path of its own.
 *
 * Auth: served behind the SAME `checkAuth` gate as `/posture` and `/api/posture/*`
 * (the dashboard runs the gate before dispatch); the client-side fetches ride the
 * same loopback/bearer model as the Home page.
 *
 * Unknown agent id: the reach endpoint 404s for an id absent from the wrapped
 * roster. The page renders an honest "agent not found" state rather than a crash
 * or a fabricated card.
 *
 * Returns a string so the dashboard can serve it directly (mirrors
 * `renderPostureHomeHTML`).
 */

import { AGENT_PILL_FN_SOURCE } from "./posture-html-shared.js";

export function renderPostureAgentHTML(): string {
  // Inline everything (no external assets) so the page works on a locked-down
  // loopback dashboard with a strict CSP and no network egress.
  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width, initial-scale=1" />
<title>Sanctuary - Agent posture</title>
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
  .back { display: inline-block; margin-top: 6px; font-size: 12px; }
  main { padding: 20px 24px; max-width: 1100px; margin: 0 auto; }
  .pill { display: inline-block; padding: 2px 8px; border-radius: 999px; font-size: 11px; font-weight: 600; }
  .pill.green { background: rgba(46,160,67,.18); color: var(--green); }
  .pill.amber { background: rgba(210,153,34,.18); color: var(--amber); }
  .pill.red { background: rgba(248,81,73,.18); color: var(--red); }
  .pill.neutral { background: rgba(154,166,178,.18); color: var(--muted); }
  section { margin-bottom: 24px; }
  section > h2 { font-size: 13px; text-transform: uppercase; letter-spacing: .5px; color: var(--muted); margin: 0 0 10px; }
  .panel { background: var(--panel); border: 1px solid var(--border); border-radius: 10px; padding: 16px; }
  a { color: var(--accent); text-decoration: none; }
  a:hover { text-decoration: underline; }
  .empty { color: var(--muted); font-style: italic; }
  .err { color: var(--red); }
  code { background: var(--panel-2); padding: 1px 5px; border-radius: 4px; font-size: 12px; }
  .evidence { font-size: 11px; color: var(--muted); margin-top: 6px; }
  .meta { color: var(--muted); font-size: 12px; }
  table.reach { width: 100%; border-collapse: collapse; font-size: 13px; }
  table.reach th { text-align: left; color: var(--muted); font-weight: 600; font-size: 11px;
    text-transform: uppercase; letter-spacing: .4px; padding: 4px 8px; border-bottom: 1px solid var(--border); }
  table.reach td { padding: 6px 8px; border-bottom: 1px solid var(--border); vertical-align: top; }
  table.reach tr:last-child td { border-bottom: 0; }
  .standing-row { display: flex; align-items: baseline; gap: 8px; padding: 6px 0; border-bottom: 1px solid var(--border); }
  .standing-row:last-child { border-bottom: 0; }
  .standing-row .name { flex: 1; }
  .standing-row .why { color: var(--muted); font-size: 12px; }
  .footer {
    margin: 24px 0 8px; padding: 14px 16px; background: var(--panel-2);
    border: 1px solid var(--border); border-radius: 10px; color: var(--muted); font-size: 12px;
  }
  .footer strong { color: var(--text); }
</style>
</head>
<body>
<header>
  <h1>Sanctuary - Agent posture</h1>
  <div class="sub" id="origin">Loading...</div>
  <a class="back" href="/posture">&larr; Back to posture home</a>
</header>
<main>
  <section>
    <h2>Standing</h2>
    <div class="panel" id="standing"><span class="empty">Loading...</span></div>
  </section>

  <section>
    <h2>Distress channel</h2>
    <div class="panel" id="distress"><span class="empty">Loading...</span></div>
  </section>

  <section>
    <h2>Effective reach</h2>
    <div class="panel" id="reach"><span class="empty">Loading...</span></div>
  </section>

  <div class="footer">
    <strong>Evidence-based, never fake green.</strong>
    Green here means confirmed live enforcement, not policy intent. Where the
    server cannot prove enforcement for this agent it shows amber "protection
    requested" or "unknown", never green. Reach lines are annotated by the layer
    that enforces them: Castle Wall lines are blocked by the operating system;
    policy lines are cooperative (enforced at the MCP boundary).
  </div>
</main>

<script>
(function () {
  "use strict";
  // Same auth model as the rest of the dashboard: loopback auto-auth or a
  // bearer token the operator pasted. We send credentials: same-origin so the
  // session cookie rides along; if a token is in the URL hash we use it.
  var tokenMatch = /[#&]token=([^&]+)/.exec(location.hash);
  var token = tokenMatch ? decodeURIComponent(tokenMatch[1]) : null;

  // The agent id is the last path segment of /posture/agent/:id.
  var parts = location.pathname.split("/");
  var agentId = decodeURIComponent(parts[parts.length - 1] || "");

  function api(path) {
    var opts = { credentials: "same-origin", headers: {} };
    if (token) opts.headers["Authorization"] = "Bearer " + token;
    return fetch(path, opts).then(function (r) {
      if (r.status === 404) {
        var notFound = new Error("not_found");
        notFound.status = 404;
        throw notFound;
      }
      if (!r.ok) throw new Error(path + " -> " + r.status);
      return r.json();
    });
  }

  function esc(s) {
    return String(s == null ? "" : s).replace(/[&<>"']/g, function (c) {
      return { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c];
    });
  }

  // "Never fake green" for the agent Standing pill (#634 honesty split, mirrors
  // the Home grid's agentPill). GREEN is earned only by CONFIRMED live
  // enforcement; a policy-protected agent whose enforcement we cannot observe is
  // amber "protection requested", never green; a no-longer-protected agent is
  // red. This is the SAME color model the Home agent grid uses - the drill-down
  // must not weaken it. The body is the SHARED source of truth
  // (posture-html-shared.ts), byte-identical to Home's copy and test-pinned (#641).
  ${AGENT_PILL_FN_SOURCE}

  // Plain-English honesty line for the enforcement column. "unknown" is the only
  // value the read path emits today (no per-agent live enforcement signal
  // exists), so it is stated plainly rather than dressed up.
  function enforcementWhy(row) {
    if (row.enforcement_active === "active")
      return "Protection observed live and enforcing for this agent.";
    if (row.enforcement_active === "inactive")
      return "Protection observed NOT enforcing for this agent.";
    return "No per-agent live enforcement signal is available, so this is " +
      "shown as unknown (amber), never green. Machine-level Castle Wall state " +
      "is not inherited per agent by design.";
  }

  // Disposition pill (#641 honesty gate). A green "deny" claims the OS actively
  // STOPS this destination - so it is reserved for CONFIRMED enforcement
  // (enforcementConfirmed). When enforcement is not confirmed (today: always,
  // since no per-agent live enforcement signal exists), a configured deny rule
  // is shown amber "deny (configured)": the rule is on disk, but the OS is not
  // confirmed to be enforcing it, so it must not read as an in-effect block.
  // allow is neutral; prompt is amber regardless (it is a gate, never a green
  // protective state). This describes a rule line, not a live agent claim.
  function dispositionPill(d, enforcementConfirmed) {
    if (d === "deny")
      return enforcementConfirmed
        ? '<span class="pill green">deny</span>'
        : '<span class="pill amber">deny (configured)</span>';
    if (d === "prompt") return '<span class="pill amber">prompt</span>';
    return '<span class="pill neutral">allow</span>';
  }

  // Enforced-by pill (#641 honesty gate). A green "Castle Wall" pill claims the
  // operating system is enforcing this line at the kernel. That claim is earned
  // ONLY by confirmed enforcement; when enforcement is not confirmed the same
  // line is shown amber "Castle Wall (configured)" - the rule is configured for
  // the wall, but the OS is not confirmed to be enforcing it for this agent.
  // policy lines are cooperative (neutral) either way.
  function layerLabel(layer, enforcementConfirmed) {
    if (layer === "castle_wall")
      return enforcementConfirmed
        ? '<span class="pill green">Castle Wall</span>'
        : '<span class="pill amber">Castle Wall (configured)</span>';
    return '<span class="pill neutral">policy</span>';
  }

  function renderStanding(row) {
    var el = document.getElementById("standing");
    document.getElementById("origin").textContent =
      "Agent: " + agentId + " - machine " + row.origin_machine +
      " - single-machine view (federation off)";
    var lines = [
      '<div class="standing-row">' + agentPill(row) +
        '<span class="name">Protection</span>' +
        '<span class="why">' + esc(enforcementWhy(row)) + "</span></div>",
      '<div class="standing-row">' +
        '<span class="pill neutral">' + esc(row.harness) + "</span>" +
        '<span class="name">Harness</span>' +
        '<span class="why">The agent runtime this protection wraps.</span></div>',
      '<div class="standing-row">' +
        '<span class="pill neutral">' + esc(row.status) + "</span>" +
        '<span class="name">Status</span>' +
        '<span class="why">Current lifecycle status from the hub registry.</span></div>",
      '<div class="standing-row">' +
        (row.policy_protected
          ? '<span class="pill amber">requested</span>'
          : '<span class="pill red">not requested</span>') +
        '<span class="name">Policy intent</span>' +
        '<span class="why">Whether the operator has requested protection ' +
        "(policy), distinct from confirmed enforcement above.</span></div>"
    ];
    el.innerHTML = lines.join("");
  }

  // "Never fake green" for the distress tile (Phase 2 design 2.4 C). FACTS ONLY:
  // a count + most-recent time + the static habeas guaranteed-egress policy fact.
  // There is NO green "channel healthy/active" state - no listener-bound evidence
  // exists on this read - so the tile uses neutral pills only. Absence of signals
  // is "no distress signals recorded", never a fabricated green "all well". The
  // inbox is operator-global today (per-agent filtering is deferred); it is
  // framed here as the operator distress channel, surfaced in the agent's
  // secondary Standing section per the CISO-first ordering (never on Home).
  function renderDistress(inbox) {
    var el = document.getElementById("distress");
    var entries = (inbox && inbox.data && inbox.data.entries) || [];
    var count = (inbox && inbox.data && typeof inbox.data.count === "number")
      ? inbox.data.count
      : entries.length;
    var lines = [];
    if (count > 0) {
      var newest = entries[0];
      var when = newest && newest.received_at ? newest.received_at : "unknown time";
      var reason = newest && newest.envelope ? newest.envelope.reason : "";
      var severity = newest && newest.envelope ? newest.envelope.severity : "";
      lines.push(
        '<div class="standing-row">' +
          '<span class="pill amber">' + esc(count) + " received</span>" +
          '<span class="name">Distress signals</span>' +
          '<span class="why">Most recent ' + esc(when) +
          (severity ? " (severity " + esc(severity) + ", " + esc(reason) + ")" : "") +
          ". A received signal is a fact, not a health state.</span></div>"
      );
    } else {
      lines.push(
        '<div class="standing-row">' +
          '<span class="pill neutral">none recorded</span>' +
          '<span class="name">Distress signals</span>' +
          '<span class="why">No distress signals recorded. Absence is not a ' +
          'green "all well": a quiet channel and a listener that never bound ' +
          "look the same here, so this is shown neutrally, never green.</span></div>"
      );
    }
    // Static, structural guaranteed-egress fact (always true, verifiable from the
    // curated allowlist / composer): the reserved loopback habeas rule is injected
    // into every manifest and policy cannot remove or shadow it. This is a policy
    // fact, NOT a listener-liveness or welfare guarantee.
    lines.push(
      '<div class="standing-row">' +
        '<span class="pill neutral">guaranteed egress</span>' +
        '<span class="name">Habeas lane</span>' +
        '<span class="why">The wall policy always permits a wrapped agent to ' +
        "reach the operator at the loopback habeas port (8741): a reserved rule " +
        "that policy cannot remove or shadow. This is a structural policy fact, " +
        "not a claim that the listener is currently bound.</span></div>"
    );
    el.innerHTML = lines.join("");
  }

  function renderReach(reach) {
    var el = document.getElementById("reach");
    // #641 honesty gate: enforcement_confirmed is the SAME evidence the Standing
    // pill keys on (a confirmed-active per-agent enforcement signal). Today it is
    // always false (no per-agent live signal exists), so the reach table must NOT
    // claim the OS is enforcing these rules - it shows them as configured.
    var enforcementConfirmed = reach.enforcement_confirmed === true;
    var head =
      '<div class="meta">Allowed, prompt, and deny destinations for this agent, ' +
      "annotated by the layer that enforces each line.</div>";
    if (!reach.has_wall_policy) {
      // Honest gap: no Castle Wall ruleset applies to this agent, so the wall is
      // not restricting its egress. Surface the gap rather than imply protection.
      head +=
        '<div class="evidence err">No Castle Wall ruleset applies to this agent. ' +
        "The operating system is not restricting its outbound reach - this is a " +
        'gap, shown in red by design.</div>';
    } else if (!enforcementConfirmed) {
      // A wall ruleset is configured, but enforcement is NOT confirmed for this
      // agent - so we must NOT claim default-deny is in effect (that is an
      // OS-enforcement claim). State plainly that the rules are configured and
      // the OS is not confirmed to be enforcing them.
      head +=
        '<div class="evidence">These rules are configured for the Castle Wall, ' +
        "but the wall is not confirmed armed and enforcing for this agent, so the " +
        "operating system is not confirmed to be enforcing them. The rules below " +
        "describe the configured policy, not a confirmed in-effect block.</div>";
    } else {
      head +=
        '<div class="evidence">' +
        (reach.default_deny
          ? "Default-deny: only the destinations listed below are reachable."
          : "Default-deny is NOT in effect (an allow-everything rule defeats it).") +
        "</div>";
    }
    if (!reach.destinations || !reach.destinations.length) {
      el.innerHTML = head + '<div class="empty">No reach lines for this agent.</div>';
      return;
    }
    var rows = reach.destinations.map(function (d) {
      return "<tr><td>" + dispositionPill(d.disposition, enforcementConfirmed) + "</td>" +
        "<td><code>" + esc(d.destination) + "</code></td>" +
        "<td>" + layerLabel(d.enforcing_layer, enforcementConfirmed) + "</td>" +
        '<td class="meta">' + esc(d.rule_id) + "</td></tr>";
    }).join("");
    el.innerHTML = head +
      '<table class="reach"><thead><tr>' +
      "<th>Disposition</th><th>Destination</th><th>Enforced by</th><th>Rule</th>" +
      "</tr></thead><tbody>" + rows + "</tbody></table>" +
      '<div class="evidence"><a href="/api/posture/reach/' + encodeURIComponent(agentId) +
      '">Open the raw reach payload &rarr;</a></div>';
  }

  function renderNotFound() {
    document.getElementById("origin").textContent = "Agent: " + agentId;
    document.getElementById("standing").innerHTML =
      '<span class="err">Agent not found.</span> ' +
      "<span class=\\"meta\\">No wrapped agent with this id is in the registry on " +
      "this machine. It may have been unwrapped, or the link is stale.</span>";
    document.getElementById("reach").innerHTML =
      '<span class="empty">No reach to show for an unknown agent.</span>';
  }

  function load() {
    // Reach is the source of truth for "does this agent exist" (it 404s for an
    // id absent from the wrapped roster). Load it first so an unknown id renders
    // the honest not-found state instead of a half-populated page.
    api("/api/posture/reach/" + encodeURIComponent(agentId))
      .then(function (reach) {
        renderReach(reach);
        // Standing comes from the composed home payload (the Slice 1 honest
        // PostureAgentRow). Find this agent's row; if absent (raced unwrap), show
        // a minimal honest row rather than fabricate enforcement.
        return api("/api/posture/home").then(function (home) {
          var row = (home.agents || []).filter(function (a) {
            return a.agent_id === agentId;
          })[0];
          if (!row) {
            row = {
              origin_machine: home.origin_machine,
              agent_id: agentId,
              harness: reach.harness,
              status: "unknown",
              policy_protected: false,
              enforcement_active: "unknown"
            };
          }
          renderStanding(row);
          // Distress channel (Phase 2): best-effort over the already-mounted,
          // durable /api/distress/inbox. A failure or absent inbox renders the
          // honest "none recorded" state, never a fabricated green.
          api("/api/distress/inbox?limit=1")
            .then(function (inbox) { renderDistress(inbox); })
            .catch(function () { renderDistress({ data: { entries: [], count: 0 } }); });
        });
      })
      .catch(function (e) {
        if (e && e.status === 404) {
          renderNotFound();
          return;
        }
        document.getElementById("standing").innerHTML =
          '<span class="err">Could not load agent posture: ' + esc(e.message) + "</span>";
        document.getElementById("reach").innerHTML = "";
      });
  }

  load();
})();
</script>
</body>
</html>`;
}
