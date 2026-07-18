/**
 * S3 acceptance harness (NOT shipped product code, NOT part of the build).
 *
 * Renders each web surface to a standalone HTML file so the S3 evidence-spine
 * work can be screenshotted in light and dark without provisioning a fortress.
 *
 * The pages fetch their data client-side, so this harness injects a stub
 * `fetch` that answers the posture endpoints with representative payloads. Two
 * fixture sets are emitted per surface:
 *
 *   - "populated": a box with agents, enforcement evidence, and a verified
 *     chain, so the denominators / freshness stamps / evidence links are all
 *     exercised;
 *   - "degraded": the natural dev-box state (wall unknown, no enforcement
 *     evidence, empty roster), so the honest no-evidence and first-run empty
 *     states are captured as an operator would actually first see them.
 *
 * The stub only supplies TRANSPORT. It never bypasses a mapper: the pages'
 * own honesty logic decides every pill and every rendered claim from these
 * payloads exactly as it would from the live daemon.
 */
import { mkdirSync, writeFileSync } from "node:fs";
import { renderPostureHomeHTML } from "../src/principal-policy/posture-home-html.js";
import { renderPostureAgentHTML } from "../src/principal-policy/posture-agent-html.js";
import { renderPostureEvidenceHTML } from "../src/principal-policy/posture-evidence-html.js";
import { generateFleetSwitcherHTML } from "../src/principal-policy/dashboard-html.js";
import { renderDashboardV11Html } from "../src/dashboard/v1_1/html.js";

const OUT = process.argv[2] || "/tmp/s3-shots";
mkdirSync(OUT, { recursive: true });

const iso = (msAgo: number) => new Date(Date.now() - msAgo).toISOString();

const populatedHome = {
  origin_machine: "Mini1",
  federation: { available: true, enabled: true, fleet_node_count: 3 },
  stream_available: false,
  protection_requested_count: 3,
  enforcement_confirmed_count: 2,
  castle_wall: {
    origin_machine: "Mini1",
    arm_state: "armed",
    platform: "macos",
    evidence_basis: "fresh_enforcement_evidence",
    last_enforcement_evidence_at: iso(14_000),
    freshness_window_ms: 300_000,
    verdict_counts: { allowed: 208, blocked: 4, operator_decisions: 3 },
    audit_integrity_ok: true,
    sealed_region_unverified_at_privilege: false,
    producer_authenticity: "producer_signed",
  },
  digest: {
    origin_machine: "Mini1",
    window_start: iso(86_400_000),
    window_end: iso(120_000),
    total_operations: 2113,
    failures: 2,
    kernel_blocks: 4,
    kernel_allows: 208,
    approvals_granted: 2,
    approvals_denied: 1,
    by_agent: [],
    chain_verified: true,
    chain_verdict: "verified",
    integrity_finding_count: 0,
  },
  unwrapped: {
    origin_machine: "Mini1",
    unwrapped: [
      { harness: "cursor", platform: "macos", config_path: "~/.cursor/config.json", protected: false, detection_method: "config_file_presence" },
    ],
    detection_method: "config_file_presence",
  },
  feature_health: {
    origin_machine: "Mini1",
    window_start: iso(86_400_000),
    window_end: iso(120_000),
    rows: [],
    plugin_rows: [],
    audit_integrity_ok: true,
    sealed_region_unverified_at_privilege: false,
  },
  custody_exit: {
    custody_state: "unconfirmed",
    custody_basis: "no_negative_evidence",
    rollback_freeze_suspected: false,
    pin_custody_mismatch: false,
    establishment: { operation: "fortress_init", install_mode: "supervised", verified_wraps: 2, observed_at: iso(7_200_000) },
    last_damage_evidence_at: null,
    freshness_window_ms: 300_000,
    audit_integrity_ok: true,
    exit_state: "clean",
    exit_command: "sanctuary exit",
    clean_exit_guaranteed: true,
  },
  query_privacy: {
    origin_machine: "Mini1",
    header_strip_calls_24h: 41,
    headers_stripped_24h: 41,
    header_strip_is_anonymity: false,
    tier_a_strip_observed: true,
    rows: [],
  },
  agents: [
    { origin_machine: "Mini1", agent_id: "hermes", harness: "claude-code", status: "active", policy_protected: true, enforcement_active: "active" },
    { origin_machine: "Mini1", agent_id: "scribe", harness: "claude-code", status: "active", policy_protected: true, enforcement_active: "active" },
    { origin_machine: "Mini1", agent_id: "atlas", harness: "cursor", status: "idle", policy_protected: true, enforcement_active: "unknown" },
  ],
};

// The natural dev-box state: nothing provisioned, wall never armed, no
// enforcement evidence on record, chain never verified. This is the honest
// first impression and the state the acceptance criteria call for.
const degradedHome = {
  ...populatedHome,
  origin_machine: "(local)",
  federation: { available: false, enabled: false, fleet_node_count: 0 },
  protection_requested_count: 0,
  enforcement_confirmed_count: 0,
  castle_wall: {
    ...populatedHome.castle_wall,
    origin_machine: "(local)",
    arm_state: "unknown",
    evidence_basis: "no_evidence",
    last_enforcement_evidence_at: null,
    verdict_counts: { allowed: 0, blocked: 0, operator_decisions: 0 },
  },
  digest: {
    ...populatedHome.digest,
    window_end: null,
    total_operations: 0,
    failures: 0,
    kernel_blocks: 0,
    kernel_allows: 0,
    approvals_granted: 0,
    approvals_denied: 0,
    chain_verified: false,
    chain_verdict: "findings",
    integrity_finding_count: 1,
  },
  unwrapped: { ...populatedHome.unwrapped, origin_machine: "(local)", unwrapped: [] },
  custody_exit: { ...populatedHome.custody_exit, establishment: null },
  agents: [],
};

function stubScript(home: unknown, opts: { emptyAux: boolean }) {
  const aux = opts.emptyAux
    ? { pending: [], findings: [], inbox: [] }
    : {
        pending: [{ id: "p1", title: "hermes wants to export its encrypted state", detail: "Held because exports are irreversible.", review_href: "/api/pending" }],
        findings: [],
        inbox: [],
      };
  return `<script>
(function () {
  var HOME = ${JSON.stringify(home)};
  var AUX = ${JSON.stringify(aux)};
  function json(body) {
    return Promise.resolve({
      ok: true, status: 200,
      json: function () { return Promise.resolve(body); },
      text: function () { return Promise.resolve(JSON.stringify(body)); },
      headers: { get: function () { return "application/json"; } }
    });
  }
  window.fetch = function (url) {
    var u = String(url);
    if (u.indexOf("/api/posture/home") !== -1) return json(HOME);
    if (u.indexOf("/api/posture/feature-health") !== -1) return json(HOME.feature_health);
    if (u.indexOf("/api/posture/custody-exit") !== -1) return json(HOME.custody_exit);
    if (u.indexOf("/api/posture/fleet") !== -1) return Promise.resolve({ ok: false, status: 404, json: function () { return Promise.resolve({}); } });
    if (u.indexOf("/api/anomaly/findings") !== -1) return json({ findings: AUX.findings });
    if (u.indexOf("/api/approval-inbox") !== -1) return json({ items: AUX.pending });
    if (u.indexOf("/api/pending") !== -1) return json({ pending: AUX.pending });
    if (u.indexOf("/inbox") !== -1) return json({ items: AUX.inbox });
    if (u.indexOf("/agents") !== -1) return json({ agents: HOME.agents });
    if (u.indexOf("/activity") !== -1) return json({ entries: [] });
    if (u.indexOf("/api/sovereignty") !== -1) return json({
      score: 0, overall_level: "degraded", layers: {},
      live_enforcement: {
        castle_wall_arm_state: HOME.castle_wall.arm_state,
        evidence_basis: HOME.castle_wall.evidence_basis,
        last_enforcement_evidence_at: HOME.castle_wall.last_enforcement_evidence_at,
        audit_integrity_ok: true
      },
      degradations: [], capabilities: {}, config_loaded: true
    });
    return json({});
  };
  window.EventSource = function () { this.close = function () {}; this.addEventListener = function () {}; };
})();
</script>`;
}

function forceTheme(theme: "light" | "dark") {
  return `<script>
(function () {
  try { sessionStorage.setItem("sanctuaryTheme", ${JSON.stringify(theme)}); } catch (e) {}
  document.documentElement.setAttribute("data-theme", ${JSON.stringify(theme)});
  document.addEventListener("DOMContentLoaded", function () {
    document.documentElement.setAttribute("data-theme", ${JSON.stringify(theme)});
  });
  setTimeout(function () { document.documentElement.setAttribute("data-theme", ${JSON.stringify(theme)}); }, 400);
})();
</script>`;
}

/** Inject the stub + theme immediately after <head> so they run before the page script. */
function inject(html: string, ...blocks: string[]) {
  const i = html.indexOf("<head>");
  if (i === -1) return blocks.join("\n") + html;
  const at = i + "<head>".length;
  return html.slice(0, at) + "\n" + blocks.join("\n") + html.slice(at);
}

type Surface = { name: string; html: string; home?: unknown; emptyAux?: boolean };

const surfaces: Surface[] = [
  { name: "posture-home-populated", html: renderPostureHomeHTML(), home: populatedHome, emptyAux: false },
  { name: "posture-home-degraded", html: renderPostureHomeHTML(), home: degradedHome, emptyAux: true },
  { name: "posture-agent", html: renderPostureAgentHTML(), home: populatedHome, emptyAux: false },
  { name: "posture-evidence", html: renderPostureEvidenceHTML(), home: populatedHome, emptyAux: false },
  { name: "v11-posture-populated", html: renderDashboardV11Html({}), home: populatedHome, emptyAux: false },
  { name: "v11-posture-degraded", html: renderDashboardV11Html({}), home: degradedHome, emptyAux: true },
  {
    name: "fleet-switcher",
    html: generateFleetSwitcherHTML({ serverVersion: "1.6.1", protocol: "http", currentHost: "127.0.0.1", currentPort: 3501 }),
  },
];

for (const s of surfaces) {
  for (const theme of ["light", "dark"] as const) {
    const blocks = [forceTheme(theme)];
    if (s.home) blocks.push(stubScript(s.home, { emptyAux: s.emptyAux === true }));
    const file = `${OUT}/${s.name}-${theme}.html`;
    writeFileSync(file, inject(s.html, ...blocks), "utf8");
    console.log(file);
  }
}
