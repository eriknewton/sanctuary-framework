/**
 * Sovereignty Posture Dashboard - Evidence View HTML (Phase 2, design section 2.5).
 *
 * Renders a filterable audit-entry table at `/posture/evidence`, composing the
 * existing `AuditLog.query()` output (entries + integrity_findings) into a
 * human-readable, operator-gated view.  This is the "third IA level" the Phase 1
 * design promised: two clicks from the posture home to the individual signed
 * entries that back every claim on the board.
 *
 * HONESTY CONTRACT (#617/#634, mandatory across all posture surfaces):
 *   - `integrity_findings` are surfaced ON-VIEW, prominently.  A fortress with
 *     chain findings never renders a clean/green evidence banner.
 *   - A log with zero entries is "no audit entries found" (neutral), never a
 *     fabricated "all clear".
 *   - Timestamps, operation names, layers, and detail values are HTML-escaped
 *     before insertion; no field value from audit content can inject markup.
 *   - Filter parameters (agent, since, operation class, result) pass through to
 *     `AuditLog.query()` verbatim; no new backend query logic is added.
 *
 * Auth: served behind the SAME `checkAuth` gate as `/posture/agent/:id` and
 * `/api/posture/*` - the dashboard runs the gate before dispatch.  The audit log
 * is the operator's own data, but it MUST be operator-gated (never exposed
 * unauthenticated, never to a non-operator, never cross-tenant).
 *
 * Returns a string so the dashboard can serve it directly, mirroring
 * `renderPostureAgentHTML`.
 */

export function renderPostureEvidenceHTML(): string {
  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width, initial-scale=1" />
<title>Sanctuary - Audit evidence</title>
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
  main { padding: 20px 24px; max-width: 1200px; margin: 0 auto; }
  .pill {
    display: inline-block; padding: 2px 8px; border-radius: 999px;
    font-size: 11px; font-weight: 600;
  }
  .pill.green { background: rgba(46,160,67,.18); color: var(--green); }
  .pill.amber { background: rgba(210,153,34,.18); color: var(--amber); }
  .pill.red { background: rgba(248,81,73,.18); color: var(--red); }
  .pill.neutral { background: rgba(154,166,178,.18); color: var(--muted); }
  section { margin-bottom: 24px; }
  section > h2 {
    font-size: 13px; text-transform: uppercase; letter-spacing: .5px;
    color: var(--muted); margin: 0 0 10px;
  }
  .panel {
    background: var(--panel); border: 1px solid var(--border);
    border-radius: 10px; padding: 16px;
  }
  a { color: var(--accent); text-decoration: none; }
  a:hover { text-decoration: underline; }
  .empty { color: var(--muted); font-style: italic; }
  .err { color: var(--red); }
  code {
    background: var(--panel-2); padding: 1px 5px; border-radius: 4px;
    font-size: 12px;
  }
  .findings-banner {
    background: rgba(248,81,73,.1); border: 1px solid rgba(248,81,73,.4);
    border-radius: 8px; padding: 12px 16px; margin-bottom: 16px;
    color: var(--red);
  }
  .findings-banner h3 { margin: 0 0 8px; font-size: 13px; }
  .finding-item { font-size: 12px; margin: 4px 0; font-family: monospace; }
  .filters {
    display: flex; flex-wrap: wrap; gap: 8px; margin-bottom: 16px;
    align-items: flex-end;
  }
  .filter-group { display: flex; flex-direction: column; gap: 4px; }
  .filter-group label { font-size: 11px; color: var(--muted); text-transform: uppercase; letter-spacing: .3px; }
  .filter-group input, .filter-group select {
    background: var(--panel-2); border: 1px solid var(--border); color: var(--text);
    padding: 5px 8px; border-radius: 6px; font-size: 13px; min-width: 140px;
  }
  .filter-group input:focus, .filter-group select:focus {
    outline: 2px solid var(--accent); outline-offset: 1px;
  }
  button.apply {
    padding: 6px 14px; background: var(--accent); color: #0e1116;
    border: none; border-radius: 6px; font-size: 13px; font-weight: 600;
    cursor: pointer; align-self: flex-end;
  }
  button.apply:hover { opacity: .9; }
  .result-meta { font-size: 12px; color: var(--muted); margin-bottom: 10px; }
  .result-meta .total { color: var(--text); font-weight: 600; }
  table.entries { width: 100%; border-collapse: collapse; font-size: 12px; }
  table.entries th {
    text-align: left; color: var(--muted); font-weight: 600;
    font-size: 11px; text-transform: uppercase; letter-spacing: .4px;
    padding: 4px 8px; border-bottom: 1px solid var(--border);
    white-space: nowrap;
  }
  table.entries td {
    padding: 5px 8px; border-bottom: 1px solid var(--border); vertical-align: top;
    word-break: break-all;
  }
  table.entries tr:last-child td { border-bottom: 0; }
  table.entries tr:hover td { background: var(--panel-2); }
  .ts { white-space: nowrap; font-family: monospace; font-size: 11px; color: var(--muted); }
  .op { font-family: monospace; }
  .details-toggle { cursor: pointer; color: var(--accent); font-size: 11px; user-select: none; }
  .details-block {
    display: none; margin-top: 4px; background: var(--bg); border: 1px solid var(--border);
    border-radius: 4px; padding: 6px 8px; font-family: monospace; font-size: 11px;
    white-space: pre-wrap; word-break: break-all; color: var(--muted); max-width: 480px;
  }
  .footer {
    margin: 24px 0 8px; padding: 14px 16px; background: var(--panel-2);
    border: 1px solid var(--border); border-radius: 10px;
    color: var(--muted); font-size: 12px;
  }
  .footer strong { color: var(--text); }
</style>
</head>
<body>
<header>
  <h1>Sanctuary - Audit evidence</h1>
  <div class="sub" id="origin">Loading...</div>
  <a class="back" href="/posture">&larr; Back to posture home</a>
</header>
<main>
  <section>
    <h2>Filters</h2>
    <div class="panel">
      <div class="filters">
        <div class="filter-group">
          <label>Agent / identity</label>
          <input id="f-agent" type="text" placeholder="any" />
        </div>
        <div class="filter-group">
          <label>Since (ISO / date)</label>
          <input id="f-since" type="text" placeholder="e.g. 2026-06-01" />
        </div>
        <div class="filter-group">
          <label>Operation</label>
          <input id="f-op" type="text" placeholder="any" />
        </div>
        <div class="filter-group">
          <label>Layer</label>
          <select id="f-layer">
            <option value="">any</option>
            <option value="l1">l1 - Castle Wall (Boundary)</option>
            <option value="l2">l2 - Sentinels (Operational)</option>
            <option value="l3">l3 - Charter (Selective Disclosure)</option>
            <option value="l4">l4 - Heralds (Verifiable Reputation)</option>
          </select>
        </div>
        <div class="filter-group">
          <label>Result</label>
          <select id="f-result">
            <option value="">any</option>
            <option value="success">success</option>
            <option value="failure">failure</option>
          </select>
        </div>
        <div class="filter-group">
          <label>Limit</label>
          <select id="f-limit">
            <option value="50">50</option>
            <option value="100">100</option>
            <option value="200">200</option>
          </select>
        </div>
        <button class="apply" id="btn-apply">Apply</button>
      </div>
    </div>
  </section>

  <section>
    <h2>Chain integrity</h2>
    <div class="panel" id="integrity"><span class="empty">Loading...</span></div>
  </section>

  <section>
    <h2>Entries</h2>
    <div class="panel" id="entries-panel"><span class="empty">Loading...</span></div>
  </section>

  <div class="footer">
    <strong>Evidence-based, never fake green.</strong>
    This view reads the encrypted, tamper-evident audit chain directly. Chain
    integrity findings are surfaced prominently - a fortress with findings never
    shows a green banner. All field values are HTML-escaped; no audit content can
    inject markup. Filters pass through to the same
    <code>AuditLog.query()</code> the rest of the posture surface uses; no
    additional query logic is added here.
  </div>
</main>

<script>
(function () {
  "use strict";

  // Same auth model as the rest of the dashboard: loopback auto-auth or a
  // bearer token the operator pasted.  We send credentials: same-origin so
  // the session cookie rides along; if a token is in the URL hash we use it.
  var tokenMatch = /[#&]token=([^&]+)/.exec(location.hash);
  var token = tokenMatch ? decodeURIComponent(tokenMatch[1]) : null;

  function api(path) {
    var opts = { credentials: "same-origin", headers: {} };
    if (token) opts.headers["Authorization"] = "Bearer " + token;
    return fetch(path, opts).then(function (r) {
      if (!r.ok) {
        return r.json().then(function (body) {
          var err = new Error(body.reason || body.error || (path + " -> " + r.status));
          err.status = r.status;
          throw err;
        }).catch(function (e) {
          if (e.status) throw e;
          throw new Error(path + " -> " + r.status);
        });
      }
      return r.json();
    });
  }

  // HTML-escape: ALL audit field values pass through this before being inserted
  // into the DOM.  Audit content is operator-controlled but can contain arbitrary
  // strings; we must never trust it as markup.
  function esc(s) {
    return String(s == null ? "" : s).replace(/[&<>"']/g, function (c) {
      return { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c];
    });
  }

  // Safely JSON-stringify an arbitrary value so it can be dropped into a
  // <pre> / code block (the result is STILL HTML-escaped before insertion).
  function safeJson(v) {
    try { return JSON.stringify(v, null, 2); } catch { return String(v); }
  }

  function layerPill(layer) {
    var label = esc(layer);
    return '<span class="pill neutral">' + label + "</span>";
  }

  function resultPill(result) {
    if (result === "success")
      return '<span class="pill green">success</span>';
    if (result === "failure")
      return '<span class="pill red">failure</span>';
    return '<span class="pill neutral">' + esc(result) + "</span>";
  }

  // HONESTY: integrity findings must be surfaced prominently.  A chain with
  // findings never renders a green banner.  A clean chain renders a neutral
  // "no findings" pill - not green, because chain integrity is only as strong
  // as the last verification pass, and absence of findings is not a proof of
  // tamper-free operation (only the full verify-chain path proves that).
  function renderIntegrity(findings) {
    var el = document.getElementById("integrity");
    if (!findings || findings.length === 0) {
      el.innerHTML =
        '<span class="pill neutral">no findings</span>' +
        '<span style="margin-left:8px;color:var(--muted);font-size:12px">' +
        "No chain integrity findings on this read. Absence of findings is not a " +
        "positive proof of tamper-free operation - it means the reader found no " +
        "anomalies in the entries it loaded. A full chain re-verification is " +
        "separate from this per-read check.</span>";
      return;
    }
    // Chain has findings: show them all, prominently, in red.
    var rows = findings.map(function (f) {
      var parts = [
        '<span class="pill red">' + esc(f.kind) + "</span>",
        esc(f.message)
      ];
      if (f.key) parts.push("key: <code>" + esc(f.key) + "</code>");
      if (f.sequence != null) parts.push("seq: <code>" + esc(f.sequence) + "</code>");
      if (f.expected != null) parts.push("expected: <code>" + esc(f.expected) + "</code>");
      if (f.actual != null) parts.push("actual: <code>" + esc(f.actual) + "</code>");
      return '<div class="finding-item">' + parts.join(" &nbsp; ") + "</div>";
    }).join("");
    el.innerHTML =
      '<div class="findings-banner">' +
      '<h3>Chain integrity findings (' + esc(findings.length) + ')</h3>' +
      rows +
      '<p style="margin:8px 0 0;font-size:12px">These findings indicate anomalies ' +
      "in the audit chain. The entries below may be incomplete or altered. " +
      "Do not treat the evidence view as authoritative until the chain is repaired.</p>" +
      "</div>";
  }

  // Toggle the JSON details block for one entry row.
  function toggleDetails(id) {
    var el = document.getElementById("d-" + id);
    if (!el) return;
    el.style.display = el.style.display === "block" ? "none" : "block";
  }
  // Expose globally so the onclick attribute can reach it.
  window._evToggle = toggleDetails;

  function renderEntries(data) {
    var el = document.getElementById("entries-panel");
    var entries = data.entries || [];
    var total = typeof data.total === "number" ? data.total : entries.length;
    var meta = '<div class="result-meta"><span class="total">' + esc(total) +
      "</span> entr" + (total === 1 ? "y" : "ies") +
      (entries.length < total
        ? " (showing most recent " + esc(entries.length) + ")"
        : "") + "</div>";
    if (entries.length === 0) {
      el.innerHTML = meta + '<div class="empty">No audit entries match the current filters.</div>';
      return;
    }
    var rows = entries.map(function (e, i) {
      var detailsId = "entry-" + i;
      var hasDetails = e.details && Object.keys(e.details).length > 0;
      var detailsHtml = "";
      if (hasDetails) {
        // safeJson output is itself escaped before insertion.
        detailsHtml =
          '<span class="details-toggle" onclick="window._evToggle(' + JSON.stringify(detailsId) + ')">details &darr;</span>' +
          '<div class="details-block" id="d-' + esc(detailsId) + '">' +
          esc(safeJson(e.details)) + "</div>";
      }
      return "<tr>" +
        '<td class="ts">' + esc(e.timestamp) + "</td>" +
        "<td>" + layerPill(e.layer) + "</td>" +
        '<td class="op"><code>' + esc(e.operation) + "</code></td>" +
        "<td>" + resultPill(e.result) + "</td>" +
        '<td style="max-width:220px;word-break:break-all;font-size:11px">' +
        esc(e.identity_id) + "</td>" +
        "<td>" + detailsHtml + "</td>" +
        "</tr>";
    }).join("");
    el.innerHTML = meta +
      '<table class="entries"><thead><tr>' +
      "<th>Timestamp</th><th>Layer</th><th>Operation</th><th>Result</th>" +
      "<th>Identity</th><th>Details</th>" +
      "</tr></thead><tbody>" + rows + "</tbody></table>";
  }

  function buildQueryParams() {
    var params = new URLSearchParams();
    var agent = document.getElementById("f-agent").value.trim();
    var since = document.getElementById("f-since").value.trim();
    var op = document.getElementById("f-op").value.trim();
    var layer = document.getElementById("f-layer").value;
    var result = document.getElementById("f-result").value;
    var limit = document.getElementById("f-limit").value;
    if (agent) params.set("agent", agent);
    if (since) params.set("since", since);
    if (op) params.set("operation_type", op);
    if (layer) params.set("layer", layer);
    if (result) params.set("result", result);
    if (limit) params.set("limit", limit);
    return params.toString();
  }

  function load() {
    var qs = buildQueryParams();
    var url = "/api/posture/evidence" + (qs ? "?" + qs : "");
    document.getElementById("entries-panel").innerHTML = '<span class="empty">Loading...</span>';
    document.getElementById("integrity").innerHTML = '<span class="empty">Loading...</span>';
    api(url).then(function (data) {
      document.getElementById("origin").textContent =
        "Machine: " + esc(data.origin_machine || "") +
        " - single-machine view (federation off)";
      renderIntegrity(data.integrity_findings);
      renderEntries(data);
    }).catch(function (e) {
      var msg = e && e.message ? e.message : String(e);
      document.getElementById("integrity").innerHTML =
        '<span class="err">Could not load evidence: ' + esc(msg) + "</span>";
      document.getElementById("entries-panel").innerHTML = "";
    });
  }

  document.getElementById("btn-apply").addEventListener("click", load);

  // Pre-populate filter params from URL query string so a direct link can
  // carry filters (e.g. the posture-home story link can include an agent id).
  (function initFromURL() {
    var urlParams = new URLSearchParams(location.search);
    var agent = urlParams.get("agent");
    var since = urlParams.get("since");
    var op = urlParams.get("operation_type");
    var layer = urlParams.get("layer");
    var result = urlParams.get("result");
    var limit = urlParams.get("limit");
    if (agent) document.getElementById("f-agent").value = agent;
    if (since) document.getElementById("f-since").value = since;
    if (op) document.getElementById("f-op").value = op;
    if (layer) {
      var sel = document.getElementById("f-layer");
      for (var i = 0; i < sel.options.length; i++) {
        if (sel.options[i].value === layer) { sel.selectedIndex = i; break; }
      }
    }
    if (result) {
      var sel2 = document.getElementById("f-result");
      for (var j = 0; j < sel2.options.length; j++) {
        if (sel2.options[j].value === result) { sel2.selectedIndex = j; break; }
      }
    }
    if (limit) {
      var sel3 = document.getElementById("f-limit");
      for (var k = 0; k < sel3.options.length; k++) {
        if (sel3.options[k].value === limit) { sel3.selectedIndex = k; break; }
      }
    }
  })();

  load();
})();
</script>
</body>
</html>`;
}
