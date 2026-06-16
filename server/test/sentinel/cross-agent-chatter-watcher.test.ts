/**
 * WP-V1.3-1 Phi-3 Cross-Agent Chatter Watcher regression suite.
 *
 * Coverage:
 *  - Union query: extracts pairs from both v1.1_local_handoff (Tau-3)
 *    and cross_harness_approval_* (Upsilon-1).
 *  - Pre-baseline silence (< 7 days history).
 *  - Baseline-info one-shot then silent for in-baseline volume.
 *  - Per-pair warn at +3 sigma; alert at +6 sigma.
 *  - New-partner detection (single new partner -> warn).
 *  - Multi-new-partner escalation (>= 3 new partners -> alert).
 *  - Self-loops dropped (sender == recipient).
 *  - No new-partner finding when no prior graph at all.
 *  - Multi-fortress isolation: each watcher only sees its own audit log.
 *  - Catalog: cross-agent-chatter is registered and instantiable.
 *  - Findings carry evidence_audit_ids + agent_id.
 */

import { describe, it, expect } from "vitest";

import {
  AuditLog,
  type AuditEntry,
} from "../../src/operational/audit-log.js";
import { MemoryStorage } from "../../src/storage/memory.js";
import { generateRandomKey } from "../../src/core/random.js";
import {
  CrossAgentChatterWatcher,
  CROSS_AGENT_CHATTER_SENTINEL_ID,
} from "../../src/sentinel/sentinels/cross-agent-chatter-watcher.js";
import {
  PHI1_BASELINE_CATALOG,
} from "../../src/sentinel/sentinels/index.js";
import type { SentinelFinding } from "../../src/sentinel/types.js";

const FORTRESS_A = "fortress_a";
const FORTRESS_B = "fortress_b";

/**
 * Tiny audit-log stub that returns pre-seeded entries. The watcher
 * only calls `query()`; a stub preserves precise timestamps that
 * `AuditLog.append()` would otherwise overwrite with `new Date()`.
 */
function makeStubAuditLog(entries: AuditEntry[]): AuditLog {
  return {
    async query(opts: {
      since?: string;
      layer?: AuditEntry["layer"];
      operation_type?: string;
      limit?: number;
    }): Promise<{ entries: AuditEntry[]; total: number }> {
      let filtered = entries;
      if (opts.since) {
        const sinceMs = Date.parse(opts.since);
        filtered = filtered.filter(
          (e) => Date.parse(e.timestamp) >= sinceMs,
        );
      }
      if (opts.layer) {
        filtered = filtered.filter((e) => e.layer === opts.layer);
      }
      if (opts.operation_type) {
        filtered = filtered.filter((e) => e.operation === opts.operation_type);
      }
      const limit = opts.limit ?? 50;
      return { entries: filtered.slice(-limit), total: filtered.length };
    },
  } as unknown as AuditLog;
}

const dayMs = 24 * 60 * 60 * 1000;

function handoffEntries(opts: {
  now: Date;
  sender: string;
  recipient: string;
  perDay: number[];
  currentDayCount: number;
}): AuditEntry[] {
  const out: AuditEntry[] = [];
  for (let i = 0; i < opts.currentDayCount; i += 1) {
    out.push({
      timestamp: new Date(opts.now.getTime() - 60_000 - i * 1000).toISOString(),
      layer: "l2",
      operation: "v1.1_local_handoff",
      identity_id: opts.sender,
      result: "success",
      details: {
        sender_agent_id: opts.sender,
        recipient_agent_id: opts.recipient,
      },
    });
  }
  for (let day = 1; day <= opts.perDay.length; day += 1) {
    const count = opts.perDay[day - 1]!;
    for (let i = 0; i < count; i += 1) {
      out.push({
        timestamp: new Date(
          opts.now.getTime() - day * dayMs - 60_000 - i * 1000,
        ).toISOString(),
        layer: "l2",
        operation: "v1.1_local_handoff",
        identity_id: opts.sender,
        result: "success",
        details: {
          sender_agent_id: opts.sender,
          recipient_agent_id: opts.recipient,
        },
      });
    }
  }
  return out;
}

function crossHarnessEntries(opts: {
  now: Date;
  sourceHarness: string;
  perDay: number[];
  currentDayCount: number;
}): AuditEntry[] {
  const out: AuditEntry[] = [];
  for (let i = 0; i < opts.currentDayCount; i += 1) {
    out.push({
      timestamp: new Date(opts.now.getTime() - 60_000 - i * 1000).toISOString(),
      layer: "l2",
      operation: "cross_harness_approval_aggregated",
      identity_id: "system",
      result: "success",
      details: {
        source_harness: opts.sourceHarness,
        source_agent_id: `${opts.sourceHarness}-agent`,
      },
    });
  }
  for (let day = 1; day <= opts.perDay.length; day += 1) {
    const count = opts.perDay[day - 1]!;
    for (let i = 0; i < count; i += 1) {
      out.push({
        timestamp: new Date(
          opts.now.getTime() - day * dayMs - 60_000 - i * 1000,
        ).toISOString(),
        layer: "l2",
        operation: "cross_harness_approval_aggregated",
        identity_id: "system",
        result: "success",
        details: {
          source_harness: opts.sourceHarness,
          source_agent_id: `${opts.sourceHarness}-agent`,
        },
      });
    }
  }
  return out;
}

async function makeWatcher(
  audit: AuditLog,
  now: Date,
  fortressId: string = FORTRESS_A,
): Promise<CrossAgentChatterWatcher> {
  const watcher = new CrossAgentChatterWatcher();
  await watcher.subscribe({
    fortressId,
    auditLog: audit,
    now: () => now,
  });
  return watcher;
}

function findFinding(
  findings: SentinelFinding[],
  predicate: (f: SentinelFinding) => boolean,
): SentinelFinding | undefined {
  return findings.find(predicate);
}

describe("WP-V1.3-1 Phi-3 CrossAgentChatterWatcher", () => {
  it("returns no findings when audit log is empty", async () => {
    const now = new Date("2026-05-09T12:00:00.000Z");
    const watcher = await makeWatcher(makeStubAuditLog([]), now);
    const findings = await watcher.evaluate();
    expect(findings).toEqual([]);
  });

  it("is silent before the 7-day baseline is established", async () => {
    const now = new Date("2026-05-09T12:00:00.000Z");
    const audit = makeStubAuditLog(
      handoffEntries({
        now,
        sender: "agent-a",
        recipient: "agent-b",
        perDay: [10, 10, 10],
        currentDayCount: 100,
      }),
    );
    const watcher = await makeWatcher(audit, now);
    const findings = await watcher.evaluate();
    expect(findings).toEqual([]);
  });

  it("emits a baseline-info finding once per pair, then is silent on further normal volume", async () => {
    const now = new Date("2026-05-09T12:00:00.000Z");
    const audit = makeStubAuditLog(
      handoffEntries({
        now,
        sender: "agent-a",
        recipient: "agent-b",
        perDay: [10, 10, 10, 10, 10, 10, 10],
        currentDayCount: 10,
      }),
    );
    const watcher = await makeWatcher(audit, now);
    const first = await watcher.evaluate();
    expect(first.length).toBe(1);
    expect(first[0]?.severity).toBe("info");
    expect(first[0]?.details["sender_agent_id"]).toBe("agent-a");
    expect(first[0]?.details["recipient_agent_id"]).toBe("agent-b");
    const second = await watcher.evaluate();
    expect(second).toEqual([]);
  });

  it("fires alert when a pair's 24h count exceeds baseline by more than 6 sigma", async () => {
    const now = new Date("2026-05-09T12:00:00.000Z");
    const audit = makeStubAuditLog(
      handoffEntries({
        now,
        sender: "agent-a",
        recipient: "agent-b",
        perDay: [10, 11, 9, 12, 10, 11, 10],
        currentDayCount: 200,
      }),
    );
    const watcher = await makeWatcher(audit, now);
    await watcher.evaluate();
    const findings = await watcher.evaluate();
    expect(findings.length).toBe(1);
    expect(findings[0]?.severity).toBe("alert");
    expect(findings[0]?.details["sigma_threshold"]).toBe(6);
    expect(findings[0]?.details["sender_agent_id"]).toBe("agent-a");
    expect(findings[0]?.evidence_audit_ids.length).toBeGreaterThan(0);
    expect(findings[0]?.agent_id).toBe("agent-a");
  });

  it("fires warn between +3 and +6 sigma", async () => {
    const now = new Date("2026-05-09T12:00:00.000Z");
    // baseline mean=10.43, stddev=1.05; warn>13.58, alert>16.73
    const audit = makeStubAuditLog(
      handoffEntries({
        now,
        sender: "agent-a",
        recipient: "agent-b",
        perDay: [10, 11, 9, 12, 10, 11, 10],
        currentDayCount: 15,
      }),
    );
    const watcher = await makeWatcher(audit, now);
    await watcher.evaluate();
    const findings = await watcher.evaluate();
    expect(findings.length).toBe(1);
    expect(findings[0]?.severity).toBe("warn");
    expect(findings[0]?.details["sigma_threshold"]).toBe(3);
  });

  it("does not fire rate spike when current count is within baseline", async () => {
    const now = new Date("2026-05-09T12:00:00.000Z");
    const audit = makeStubAuditLog(
      handoffEntries({
        now,
        sender: "agent-a",
        recipient: "agent-b",
        perDay: [10, 11, 9, 12, 10, 11, 10],
        currentDayCount: 11,
      }),
    );
    const watcher = await makeWatcher(audit, now);
    await watcher.evaluate();
    const findings = await watcher.evaluate();
    expect(findings).toEqual([]);
  });

  it("emits a warn new-partner finding when a single fresh recipient appears in the current window", async () => {
    const now = new Date("2026-05-09T12:00:00.000Z");
    const established = handoffEntries({
      now,
      sender: "cursor",
      recipient: "openclaw",
      perDay: [5, 5, 5, 5, 5, 5, 5],
      currentDayCount: 5,
    });
    const newPartner = handoffEntries({
      now,
      sender: "cursor",
      recipient: "hermes",
      perDay: [0, 0, 0, 0, 0, 0, 0],
      currentDayCount: 3,
    });
    const audit = makeStubAuditLog([...established, ...newPartner]);
    const watcher = await makeWatcher(audit, now);
    const findings = await watcher.evaluate();
    const newPartnerFinding = findFinding(
      findings,
      (f) => Array.isArray(f.details["new_partners"]),
    );
    expect(newPartnerFinding).toBeDefined();
    expect(newPartnerFinding?.severity).toBe("warn");
    expect(newPartnerFinding?.details["new_partners"]).toEqual(["hermes"]);
    expect(newPartnerFinding?.details["new_partner_count"]).toBe(1);
    expect(newPartnerFinding?.agent_id).toBe("cursor");
  });

  it("escalates to alert when one source agent acquires 3+ new partners in one window", async () => {
    const now = new Date("2026-05-09T12:00:00.000Z");
    const established = handoffEntries({
      now,
      sender: "cursor",
      recipient: "openclaw",
      perDay: [5, 5, 5, 5, 5, 5, 5],
      currentDayCount: 5,
    });
    const newPartners: AuditEntry[] = [];
    for (const recipient of ["hermes", "mastra-research", "claude-code-helper"]) {
      newPartners.push(
        ...handoffEntries({
          now,
          sender: "cursor",
          recipient,
          perDay: [0, 0, 0, 0, 0, 0, 0],
          currentDayCount: 2,
        }),
      );
    }
    const audit = makeStubAuditLog([...established, ...newPartners]);
    const watcher = await makeWatcher(audit, now);
    const findings = await watcher.evaluate();
    const newPartnerFinding = findFinding(
      findings,
      (f) => Array.isArray(f.details["new_partners"]),
    );
    expect(newPartnerFinding?.severity).toBe("alert");
    expect((newPartnerFinding?.details["new_partners"] as string[]).sort()).toEqual([
      "claude-code-helper",
      "hermes",
      "mastra-research",
    ]);
    expect(newPartnerFinding?.details["new_partner_count"]).toBe(3);
  });

  it("does NOT emit a new-partner finding when there is no prior graph at all", async () => {
    const now = new Date("2026-05-09T12:00:00.000Z");
    const audit = makeStubAuditLog(
      handoffEntries({
        now,
        sender: "agent-a",
        recipient: "agent-b",
        perDay: [0, 0, 0, 0, 0, 0, 0],
        currentDayCount: 5,
      }),
    );
    const watcher = await makeWatcher(audit, now);
    const findings = await watcher.evaluate();
    const newPartnerFinding = findFinding(
      findings,
      (f) => Array.isArray(f.details["new_partners"]),
    );
    expect(newPartnerFinding).toBeUndefined();
  });

  it("ignores self-loop entries (sender == recipient)", async () => {
    const now = new Date("2026-05-09T12:00:00.000Z");
    const selfLoop: AuditEntry = {
      timestamp: new Date(now.getTime() - 60_000).toISOString(),
      layer: "l2",
      operation: "v1.1_local_handoff",
      identity_id: "agent-a",
      result: "success",
      details: { sender_agent_id: "agent-a", recipient_agent_id: "agent-a" },
    };
    const audit = makeStubAuditLog([selfLoop]);
    const watcher = await makeWatcher(audit, now);
    const findings = await watcher.evaluate();
    expect(findings).toEqual([]);
  });

  it("extracts cross_harness_approval events as wrapped-agent -> operator pairs", async () => {
    const now = new Date("2026-05-09T12:00:00.000Z");
    const audit = makeStubAuditLog(
      crossHarnessEntries({
        now,
        sourceHarness: "claude-code",
        perDay: [4, 4, 4, 4, 4, 4, 4],
        currentDayCount: 80,
      }),
    );
    const watcher = await makeWatcher(audit, now);
    await watcher.evaluate();
    const findings = await watcher.evaluate();
    expect(findings.length).toBe(1);
    expect(findings[0]?.severity).toBe("alert");
    expect(findings[0]?.details["sender_agent_id"]).toBe("claude-code");
    expect(findings[0]?.details["recipient_agent_id"]).toBe("operator");
  });

  it("multi-fortress isolation: each watcher sees only its own audit log", async () => {
    const now = new Date("2026-05-09T12:00:00.000Z");
    const auditA = makeStubAuditLog(
      handoffEntries({
        now,
        sender: "agent-a",
        recipient: "agent-b",
        perDay: [10, 11, 9, 12, 10, 11, 10],
        currentDayCount: 10,
      }),
    );
    const auditB = makeStubAuditLog([]);
    const watcherA = await makeWatcher(auditA, now, FORTRESS_A);
    const watcherB = await makeWatcher(auditB, now, FORTRESS_B);
    const findingsA = await watcherA.evaluate();
    const findingsB = await watcherB.evaluate();
    expect(findingsA.length).toBe(1);
    expect(findingsA[0]?.severity).toBe("info");
    expect(findingsB.length).toBe(0);
  });

  it("registry catalog includes cross-agent-chatter and instantiates a CrossAgentChatterWatcher", () => {
    const entry = PHI1_BASELINE_CATALOG.find(
      (e) => e.sentinelId === CROSS_AGENT_CHATTER_SENTINEL_ID,
    );
    expect(entry).toBeDefined();
    const instance = entry!.factory();
    expect(instance.sentinelId).toBe(CROSS_AGENT_CHATTER_SENTINEL_ID);
    expect(instance.description.length).toBeGreaterThan(0);
  });

  it("evidence_audit_ids on rate-spike findings link back to current-window entries", async () => {
    const now = new Date("2026-05-09T12:00:00.000Z");
    const audit = makeStubAuditLog(
      handoffEntries({
        now,
        sender: "agent-a",
        recipient: "agent-b",
        perDay: [10, 11, 9, 12, 10, 11, 10],
        currentDayCount: 200,
      }),
    );
    const watcher = await makeWatcher(audit, now);
    await watcher.evaluate();
    const findings = await watcher.evaluate();
    const spike = findFinding(
      findings,
      (f) => f.details["sigma_threshold"] === 6,
    );
    expect(spike).toBeDefined();
    expect(spike!.evidence_audit_ids.length).toBeGreaterThan(0);
    for (const auditId of spike!.evidence_audit_ids) {
      expect(auditId).toMatch(/^.*:v1\.1_local_handoff$/);
    }
  });

  it("ignores entries whose details lack the pair fields", async () => {
    const now = new Date("2026-05-09T12:00:00.000Z");
    const malformed: AuditEntry = {
      timestamp: new Date(now.getTime() - 60_000).toISOString(),
      layer: "l2",
      operation: "v1.1_local_handoff",
      identity_id: "agent-a",
      result: "success",
      details: { unrelated: "value" },
    };
    const audit = makeStubAuditLog([malformed]);
    const watcher = await makeWatcher(audit, now);
    const findings = await watcher.evaluate();
    expect(findings).toEqual([]);
  });
});
