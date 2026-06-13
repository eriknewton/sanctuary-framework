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
 * The page polls the Phase-1 endpoints (no SSE in standalone mode yet) and
 * authenticates via the same loopback/bearer model as the rest of the
 * dashboard. Every tile drills to evidence: counts link into the audit feed,
 * the wall panel exposes its evidence basis, reach links to the per-agent
 * reach endpoint. "Never fake green" is enforced in the renderer — the banner
 * shows ARMED green only when `arm_state === "armed"`; `unknown` is amber and
 * `degraded` is red.
 *
 * Returns a string so the dashboard can serve it directly (mirrors
 * `generateDashboardHTML`).
 */

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
</style>
</head>
<body>
<header>
  <h1>Sanctuary — Sovereignty Posture</h1>
  <div class="sub" id="origin">Loading…</div>
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

  function renderBanner(home, pending, anomalies) {
    var openAnomalies = (anomalies && anomalies.length) || 0;
    var pendingCount = (pending && pending.length) || 0;
    document.getElementById("origin").textContent =
      "Machine: " + home.origin_machine + " · single-machine view (federation off)";
    document.getElementById("banner").innerHTML =
      stat(home.protected_agent_count, "Agents protected") +
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
      html +=
        '<div class="card"><h3>' + esc(a.agent_id) + ' <span class="pill green">protected</span></h3>' +
        '<div class="meta">' + esc(a.harness) + " · status " + esc(a.status) + "</div>" +
        '<div class="reach"><a href="/api/posture/reach/' + encodeURIComponent(a.agent_id) + '">Effective reach &rarr;</a></div></div>';
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
      (w.audit_integrity_ok ? "" : '<div class="err">Audit integrity finding present — arm-state read may be incomplete.</div>');
  }

  function load() {
    api("/api/posture/home")
      .then(function (home) {
        // Pending approvals + anomaly findings come from existing endpoints.
        Promise.all([
          api("/api/pending").catch(function () { return { pending: [] }; }),
          api("/api/anomaly/findings").catch(function () { return { findings: [] }; }),
        ]).then(function (rest) {
          var pending = rest[0].pending || rest[0] || [];
          var findings = rest[1].findings || rest[1] || [];
          renderBanner(home, pending, findings);
          renderAgents(home);
          renderApprovals(pending);
          renderStory(home.digest);
          renderAnomalies(findings);
          renderWall(home.castle_wall);
        });
      })
      .catch(function (e) {
        document.getElementById("banner").innerHTML =
          '<span class="err">Could not load posture: ' + esc(e.message) + "</span>";
      });
  }

  load();
  setInterval(load, 15000); // poll; SSE parity is Phase 2
})();
</script>
</body>
</html>`;
}
