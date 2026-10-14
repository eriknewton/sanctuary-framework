/** Shared real-shape scenarios for the wired client and the lane's capture script. */
import type { PostureHome } from "../../../../src/principal-policy/posture-home-types.js";
import type { SovereigntyRoutePayload } from "../../../../src/principal-policy/dashboard.js";
import type { LocalAgentRecord } from "../../../../src/contracts/v1.1/local-agent-records.js";
import { buildHome } from "../../../../src/principal-policy/posture-routes.js";
import { AuditLog } from "../../../../src/operational/audit-log.js";
import { MemoryStorage } from "../../../../src/storage/memory.js";
import { generateRandomKey } from "../../../../src/core/random.js";
import { createDashboardReadFlightMap } from "../../../../src/dashboard/read-response.js";
import { CASTLE_WALL_AUDIT_PROVENANCE_KEY, CASTLE_WALL_AUDIT_PROVENANCE_VALUE } from "../../../../src/castle-wall/constants.js";

export const OVERVIEW_MINUTE_MS = 60 * 1000;
export const OVERVIEW_FRESHNESS_MS = 10 * OVERVIEW_MINUTE_MS;
const ORIGIN = "fixture-linux";
const SUBJECT = ORIGIN + "/uid-601";
export async function overviewScenarios(now: number) {
  const timestamp = new Date(now - 1000).toISOString();
  const records = ["research-agent", "billing-agent", "ops-agent"].map(agent_id => ({
    version: "1.1", agent_id, identity_id: SUBJECT, harness: "claude_code",
    model_provider: { vendor: "anthropic", model_id: "fixture", runs_locally: false },
    policy_id: "fixture-policy", status: "active", budget_summary: { last_refreshed_at: timestamp },
    last_activity_at: timestamp, wrapped_at: timestamp,
    capabilities: { can_pause: true, can_resume: true, can_restart: true, can_unwrap: true, can_lockdown: true, can_chat: false, can_change_template: false },
  } satisfies LocalAgentRecord));
  const auditLog = new AuditLog(new MemoryStorage(), generateRandomKey());
  // Twelve destinations exceed the ten-row server cap. The null bucket is first.
  for (let i = 0; i < 12; i++) for (let j = 0; j < (i === 0 ? 5 : 1); j++) {
    await auditLog.appendCritical({ layer: "l1", operation: "egress_blocked", identity_id: SUBJECT,
      result: "failure", timestamp, details: {
        [CASTLE_WALL_AUDIT_PROVENANCE_KEY]: CASTLE_WALL_AUDIT_PROVENANCE_VALUE,
        dest_host: i === 0 ? null : `destination-${String(i).padStart(2, "0")}.example`, dest_port: 443,
      } });
  }
  const deps = { auditLog, originMachine: ORIGIN, listAgents: () => records,
    detectInstalledHarnesses: async () => [{ harness: "cursor" as const, platform: "cursor" as const, config_path: "/fixture/cursor.json" }],
    resolveProtectionClaimSubject: () => SUBJECT, platform: "linux" as const, now: () => now,
    readFlightMap: createDashboardReadFlightMap(),
  };
  const base = await buildHome(deps);
  const healthy = { ...base } satisfies PostureHome;
  const failHonest = { ...await buildHome({ ...deps, producerKeyExpectedButUnavailable: true }) } satisfies PostureHome;
  await auditLog.appendCritical({ layer: "l1", operation: "egress_verdict_superseded", identity_id: SUBJECT,
    result: "failure", timestamp, details: { [CASTLE_WALL_AUDIT_PROVENANCE_KEY]: CASTLE_WALL_AUDIT_PROVENANCE_VALUE } });
  const overrides = { ...await buildHome(deps) } satisfies PostureHome;
  // An unchanged cached home ages as a whole, including its wall evidence and destination times.
  const age = 11 * OVERVIEW_MINUTE_MS;
  const shift = (iso: string) => new Date(Date.parse(iso) - age).toISOString();
  const stale = { ...base,
    castle_wall: { ...base.castle_wall, last_enforcement_evidence_at: shift(timestamp) },
    digest: { ...base.digest, window_start: shift(base.digest.window_start), window_end: shift(base.digest.window_end),
      blocked_destinations: base.digest.blocked_destinations.map(row => ({ ...row, last_blocked_at: row.last_blocked_at === null ? null : shift(row.last_blocked_at) })) },
  } satisfies PostureHome;
  const emptyLog = new AuditLog(new MemoryStorage(), generateRandomKey());
  const noEvidence = { ...await buildHome({ ...deps, auditLog: emptyLog }) } satisfies PostureHome;
  const firstRun = { ...await buildHome({ ...deps, auditLog: emptyLog, listAgents: () => [] }) } satisfies PostureHome;
  const scenarios = [
    { name: "healthy", home: healthy }, { name: "fail-honest", home: failHonest },
    { name: "overrides", home: overrides }, { name: "stale-verified", home: stale },
    { name: "first-run-unprotected", home: firstRun }, { name: "no-evidence", home: noEvidence },
  ];
  return scenarios.map(sc => {
    const wall = sc.home.castle_wall;
    // Must match buildSovereigntyRoutePayload's live_enforcement projection in dashboard.ts.
    const live_enforcement = {
      castle_wall_arm_state: wall.arm_state, evidence_basis: wall.evidence_basis,
      last_enforcement_evidence_at: wall.last_enforcement_evidence_at,
      freshness_window_ms: wall.freshness_window_ms, audit_integrity_ok: wall.audit_integrity_ok,
    } satisfies SovereigntyRoutePayload["live_enforcement"];
    return { ...sc, agents: sc.home.agents.length ? records : [], sovereignty: { live_enforcement }, inbox: [], activity: [], findings: [] };
  });
}
