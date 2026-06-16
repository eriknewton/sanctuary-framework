import { describe, expect, it } from "vitest";
import { AuditLog } from "../../src/operational/audit-log.js";
import { MemoryStorage } from "../../src/storage/memory.js";
import { generateRandomKey } from "../../src/core/random.js";
import type { LocalAgentRecord } from "../../src/contracts/v1.1/local-agent-records.js";
import {
  buildCastleWallPosture,
  buildAuditDigest,
  buildUnwrappedRoster,
  buildAgentReach,
  type DetectedHarness,
  type ReachRule,
} from "../../src/principal-policy/posture.js";

const FORTRESS = "fortress:test";

function newAuditLog(): { log: AuditLog; storage: MemoryStorage } {
  const storage = new MemoryStorage();
  const log = new AuditLog(storage, generateRandomKey());
  return { log, storage };
}

// Append a Castle-Wall-originated audit entry: carries the provenance marker
// the audit consumer stamps, so the posture logic treats it as real
// enforcement evidence.
async function appendCW(
  log: AuditLog,
  operation: string,
  timestamp: string,
  result: "success" | "failure" = "success",
): Promise<void> {
  await log.appendCritical({
    layer: "l1",
    operation,
    identity_id: FORTRESS,
    result,
    details: { cw_source: "castle_wall_audit_consumer" },
    timestamp,
  });
}

// Append an L1 entry with the SAME operation name but NO Castle Wall
// provenance — must never arm the wall.
async function appendForgedL1(
  log: AuditLog,
  operation: string,
  timestamp: string,
): Promise<void> {
  await log.appendCritical({
    layer: "l1",
    operation,
    identity_id: FORTRESS,
    result: "success",
    details: { cw_source: "not-castle-wall" },
    timestamp,
  });
}

function agent(id: string, harness: string): LocalAgentRecord {
  return {
    version: "1.1",
    agent_id: id,
    identity_id: FORTRESS,
    harness: harness as LocalAgentRecord["harness"],
    model_provider: { vendor: "anthropic", model_id: "claude", runs_locally: false },
    policy_id: "p1",
    status: "active",
    budget_summary: { last_refreshed_at: new Date().toISOString() },
    last_activity_at: new Date().toISOString(),
    wrapped_at: new Date().toISOString(),
    capabilities: {
      can_pause: true,
      can_resume: true,
      can_restart: true,
      can_unwrap: true,
      can_lockdown: true,
      can_chat: false,
      can_change_template: false,
    },
  };
}

describe("G4 — Castle Wall posture (enforcement-evidenced)", () => {
  it("renders UNKNOWN, never armed, when there is no enforcement evidence", async () => {
    const { log } = newAuditLog();
    const posture = await buildCastleWallPosture({
      auditLog: log,
      originMachine: FORTRESS,
      platform: "darwin",
      now: Date.now(),
    });
    expect(posture.arm_state).toBe("unknown");
    expect(posture.evidence_basis).toBe("no_evidence");
    expect(posture.last_enforcement_evidence_at).toBeNull();
  });

  it("renders ARMED only with FRESH extension verdict evidence", async () => {
    const { log } = newAuditLog();
    const now = Date.now();
    // A real allow verdict 1 minute ago.
    await appendCW(log, "egress_allowed", new Date(now - 60_000).toISOString());
    const posture = await buildCastleWallPosture({
      auditLog: log,
      originMachine: FORTRESS,
      platform: "darwin",
      now,
    });
    expect(posture.arm_state).toBe("armed");
    expect(posture.evidence_basis).toBe("fresh_enforcement_evidence");
    expect(posture.verdict_counts.allowed).toBe(1);
  });

  it("does NOT render armed when the only evidence is stale (older than the freshness window)", async () => {
    const { log } = newAuditLog();
    const now = Date.now();
    // A verdict from 30 minutes ago, outside the 10-minute window.
    await appendCW(log, "egress_blocked", new Date(now - 30 * 60_000).toISOString());
    const posture = await buildCastleWallPosture({
      auditLog: log,
      originMachine: FORTRESS,
      platform: "darwin",
      now,
    });
    expect(posture.arm_state).toBe("unknown");
    expect(posture.evidence_basis).toBe("stale_evidence");
    // The verdict still counts in the 24h digest window.
    expect(posture.verdict_counts.blocked).toBe(1);
  });

  it("does NOT arm on future-dated evidence (a far-future timestamp is not 'fresh')", async () => {
    const { log } = newAuditLog();
    const now = Date.now();
    // Evidence stamped 2 hours into the future.
    await appendCW(log, "egress_allowed", new Date(now + 2 * 60 * 60_000).toISOString());
    const posture = await buildCastleWallPosture({
      auditLog: log,
      originMachine: FORTRESS,
      platform: "darwin",
      now,
    });
    expect(posture.arm_state).toBe("unknown");
  });

  it("does NOT arm on a non-Castle-Wall L1 entry that reuses an enforcement operation name", async () => {
    const { log } = newAuditLog();
    const now = Date.now();
    // A forged/foreign L1 `egress_blocked` with no Castle Wall provenance.
    await appendForgedL1(log, "egress_blocked", new Date(now - 30_000).toISOString());
    const posture = await buildCastleWallPosture({
      auditLog: log,
      originMachine: FORTRESS,
      platform: "darwin",
      now,
    });
    expect(posture.arm_state).toBe("unknown");
    expect(posture.evidence_basis).toBe("no_evidence");
    // It also does not inflate the verdict counts.
    expect(posture.verdict_counts.blocked).toBe(0);
  });

  it("does NOT treat lifecycle events (filter_started) as enforcement — daemon belief is not enforcement", async () => {
    const { log } = newAuditLog();
    const now = Date.now();
    await appendCW(log, "filter_started", new Date(now - 30_000).toISOString());
    const posture = await buildCastleWallPosture({
      auditLog: log,
      originMachine: FORTRESS,
      platform: "darwin",
      now,
    });
    expect(posture.arm_state).toBe("unknown");
  });

  it("renders DEGRADED on fresh not-enforcing evidence (e.g. provider_unbound)", async () => {
    const { log } = newAuditLog();
    const now = Date.now();
    await appendCW(log, "provider_unbound", new Date(now - 30_000).toISOString());
    const posture = await buildCastleWallPosture({
      auditLog: log,
      originMachine: FORTRESS,
      platform: "darwin",
      now,
    });
    expect(posture.arm_state).toBe("degraded");
    expect(posture.evidence_basis).toBe("not_enforcing_evidence");
  });

  it("prefers fresh enforcement over fresh not-enforcing when both present", async () => {
    const { log } = newAuditLog();
    const now = Date.now();
    await appendCW(log, "provider_unbound", new Date(now - 120_000).toISOString());
    await appendCW(log, "egress_blocked", new Date(now - 30_000).toISOString());
    const posture = await buildCastleWallPosture({
      auditLog: log,
      originMachine: FORTRESS,
      platform: "darwin",
      now,
    });
    expect(posture.arm_state).toBe("armed");
  });

  it("never renders armed when the audit read is tainted, even with fresh enforcement evidence", async () => {
    const now = Date.now();
    // Stub audit log that returns a FRESH enforcement event but ALSO surfaces
    // an integrity finding (a tainted/tampered chain). Green must be refused.
    const taintedLog = {
      query: async () => ({
        entries: [
          {
            timestamp: new Date(now - 30_000).toISOString(),
            layer: "l1" as const,
            operation: "egress_allowed",
            identity_id: FORTRESS,
            result: "success" as const,
          },
        ],
        total: 1,
        integrity_findings: [
          { kind: "entry_hash_mismatch" as const, message: "tampered" },
        ],
      }),
    };
    const posture = await buildCastleWallPosture({
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      auditLog: taintedLog as any,
      originMachine: FORTRESS,
      platform: "darwin",
      now,
    });
    expect(posture.arm_state).toBe("unknown");
    expect(posture.audit_integrity_ok).toBe(false);
  });

  it("carries origin_machine for /v1-compatible shapes", async () => {
    const { log } = newAuditLog();
    const posture = await buildCastleWallPosture({
      auditLog: log,
      originMachine: "fortress:abc",
      platform: "linux",
      now: Date.now(),
    });
    expect(posture.origin_machine).toBe("fortress:abc");
    expect(posture.platform).toBe("linux");
  });
});

describe("G2 — today's audit story digest", () => {
  it("counts operations, kernel blocks/allows, and verifies the chain", async () => {
    const { log } = newAuditLog();
    const now = Date.now();
    await appendCW(log, "egress_allowed", new Date(now - 1000).toISOString());
    await appendCW(log, "egress_allowed", new Date(now - 2000).toISOString());
    await appendCW(log, "egress_blocked", new Date(now - 3000).toISOString(), "failure");
    const digest = await buildAuditDigest({
      auditLog: log,
      originMachine: FORTRESS,
      now,
    });
    expect(digest.total_operations).toBe(3);
    expect(digest.kernel_allows).toBe(2);
    expect(digest.kernel_blocks).toBe(1);
    expect(digest.failures).toBe(1);
    expect(digest.chain_verified).toBe(true);
    expect(digest.by_agent[0]?.identity_id).toBe(FORTRESS);
    expect(digest.by_agent[0]?.operations).toBe(3);
  });

  it("splits approvals granted/denied from cross_harness_approval_resolved", async () => {
    const { log } = newAuditLog();
    const now = Date.now();
    await log.appendCritical({
      layer: "l2",
      operation: "cross_harness_approval_resolved",
      identity_id: FORTRESS,
      result: "success",
      details: { decision: "approved" },
      timestamp: new Date(now - 1000).toISOString(),
    });
    await log.appendCritical({
      layer: "l2",
      operation: "cross_harness_approval_resolved",
      identity_id: FORTRESS,
      result: "failure",
      details: { decision: "denied" },
      timestamp: new Date(now - 2000).toISOString(),
    });
    const digest = await buildAuditDigest({
      auditLog: log,
      originMachine: FORTRESS,
      now,
    });
    expect(digest.approvals_granted).toBe(1);
    expect(digest.approvals_denied).toBe(1);
  });

  it("excludes entries older than the 24h window", async () => {
    const { log } = newAuditLog();
    const now = Date.now();
    await appendCW(log, "egress_allowed", new Date(now - 25 * 60 * 60_000).toISOString());
    const digest = await buildAuditDigest({
      auditLog: log,
      originMachine: FORTRESS,
      now,
    });
    expect(digest.total_operations).toBe(0);
  });

  it("excludes future-dated entries (window upper edge is now)", async () => {
    const { log } = newAuditLog();
    const now = Date.now();
    await appendCW(log, "egress_allowed", new Date(now + 60 * 60_000).toISOString());
    const digest = await buildAuditDigest({
      auditLog: log,
      originMachine: FORTRESS,
      now,
    });
    expect(digest.total_operations).toBe(0);
    expect(digest.kernel_allows).toBe(0);
  });

  it("does NOT count kernel blocks/allows from non-Castle-Wall producers", async () => {
    const { log } = newAuditLog();
    const now = Date.now();
    // Forged L1 egress events with no provenance marker.
    await appendForgedL1(log, "egress_blocked", new Date(now - 1000).toISOString());
    await appendForgedL1(log, "egress_allowed", new Date(now - 2000).toISOString());
    const digest = await buildAuditDigest({
      auditLog: log,
      originMachine: FORTRESS,
      now,
    });
    // They still count as operations, but NOT as kernel verdicts.
    expect(digest.total_operations).toBe(2);
    expect(digest.kernel_blocks).toBe(0);
    expect(digest.kernel_allows).toBe(0);
  });
});

describe("G1 — detected-but-unwrapped roster", () => {
  const detected: DetectedHarness[] = [
    { platform: "cursor", harness: "cursor", config_path: "/home/u/.cursor/mcp.json" },
    { platform: "claude-code", harness: "claude_code", config_path: "/home/u/.claude.json" },
  ];

  it("flags installed harnesses with no wrapped record", () => {
    const roster = buildUnwrappedRoster({
      originMachine: FORTRESS,
      wrappedAgents: [agent("a1", "claude_code")],
      detectedHarnesses: detected,
    });
    // claude_code is wrapped; only cursor surfaces as unwrapped.
    expect(roster.unwrapped).toHaveLength(1);
    expect(roster.unwrapped[0]?.harness).toBe("cursor");
    expect(roster.unwrapped[0]?.protected).toBe(false);
    expect(roster.detection_method).toBe("config_file_presence");
  });

  it("dedupes multiple config paths for the same harness kind", () => {
    const roster = buildUnwrappedRoster({
      originMachine: FORTRESS,
      wrappedAgents: [],
      detectedHarnesses: [
        { platform: "cursor", harness: "cursor", config_path: "/a" },
        { platform: "cursor", harness: "cursor", config_path: "/b" },
      ],
    });
    expect(roster.unwrapped).toHaveLength(1);
  });

  it("returns an empty roster when all detected harnesses are wrapped", () => {
    const roster = buildUnwrappedRoster({
      originMachine: FORTRESS,
      wrappedAgents: [agent("a1", "cursor"), agent("a2", "claude_code")],
      detectedHarnesses: detected,
    });
    expect(roster.unwrapped).toHaveLength(0);
  });
});

describe("G5 — per-agent effective reach", () => {
  const rules: ReachRule[] = [
    {
      rule_id: "curated-anthropic-api",
      host: ["api.anthropic.com"],
      disposition: "allow",
      enforcing_layer: "castle_wall",
    },
    {
      rule_id: "scoped-github",
      host: "github.com",
      disposition: "allow",
      enforcing_layer: "castle_wall",
      agent_ids: ["agent-x"],
    },
  ];

  it("merges reach rules and annotates the enforcing layer", () => {
    const reach = buildAgentReach({
      originMachine: FORTRESS,
      agentId: "agent-x",
      harness: "claude_code",
      rules,
    });
    const dests = reach.destinations.map((d) => d.destination).sort();
    expect(dests).toContain("api.anthropic.com");
    expect(dests).toContain("github.com");
    expect(reach.destinations.every((d) => d.enforcing_layer === "castle_wall")).toBe(true);
    expect(reach.has_wall_policy).toBe(true);
    expect(reach.default_deny).toBe(true);
  });

  it("excludes rules scoped to a different agent", () => {
    const reach = buildAgentReach({
      originMachine: FORTRESS,
      agentId: "agent-y",
      harness: "cursor",
      rules,
    });
    const dests = reach.destinations.map((d) => d.destination);
    // The unscoped anthropic rule applies; the github rule (scoped to agent-x)
    // does not.
    expect(dests).toContain("api.anthropic.com");
    expect(dests).not.toContain("github.com");
  });

  it("surfaces no-wall-policy as a gap (default_deny false, has_wall_policy false)", () => {
    const reach = buildAgentReach({
      originMachine: FORTRESS,
      agentId: "agent-z",
      harness: "cursor",
      rules: [],
    });
    expect(reach.has_wall_policy).toBe(false);
    expect(reach.default_deny).toBe(false);
    expect(reach.destinations).toHaveLength(0);
  });

  it("does NOT report a wall policy when the only wall rule is scoped to a different agent", () => {
    const reach = buildAgentReach({
      originMachine: FORTRESS,
      agentId: "agent-y",
      harness: "cursor",
      rules: [
        {
          rule_id: "scoped-to-x",
          host: "github.com",
          disposition: "allow",
          enforcing_layer: "castle_wall",
          agent_ids: ["agent-x"],
        },
      ],
    });
    // The rule applies only to agent-x; agent-y has no applicable wall policy.
    expect(reach.has_wall_policy).toBe(false);
    expect(reach.default_deny).toBe(false);
    expect(reach.destinations).toHaveLength(0);
  });

  it("a wildcard allow defeats default-deny", () => {
    const reach = buildAgentReach({
      originMachine: FORTRESS,
      agentId: "agent-z",
      harness: "cursor",
      rules: [
        {
          rule_id: "open",
          host: "*",
          disposition: "allow",
          enforcing_layer: "castle_wall",
        },
      ],
    });
    expect(reach.has_wall_policy).toBe(true);
    expect(reach.default_deny).toBe(false);
  });
});
