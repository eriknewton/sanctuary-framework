/**
 * Sanctuary v1.3 WP-V1.3-1 Phi-5 Anomaly Trigger meta-sentinel regression suite.
 *
 * Covers:
 *  - Trigger A (compound): >=2 distinct sentinel-IDs on one agent
 *    within 24h fires alert; single-sentinel repeats do not; info
 *    severity does not contribute; multiple agents tracked
 *    independently.
 *  - Trigger B (fortress-count spike): warmup silence, +3 sigma warn,
 *    +6 sigma alert, normal silence.
 *  - Trigger C (novel sentinel-ID combo): novel combo fires info,
 *    familiar combo silent, single-sentinel windows silent, warmup
 *    silent.
 *  - Phi-5 ignores its own findings (no self-bootstrapping).
 *  - Multi-fortress isolation (per-fortress finding store).
 *  - Subscribe rejects context with missing findingStore.
 *  - Catalog + registry integration.
 *  - Failure-mode: store read throws -> [] not crash.
 */

import { describe, it, expect } from "vitest";
import {
  AnomalyTriggerWatcher,
  ANOMALY_TRIGGER_SENTINEL_ID,
} from "../../src/sentinel/sentinels/anomaly-trigger.js";
import {
  PHI1_BASELINE_CATALOG,
  EGRESS_VOLUME_SENTINEL_ID,
  CREDENTIAL_USAGE_SENTINEL_ID,
  CROSS_AGENT_CHATTER_SENTINEL_ID,
  SUSPICIOUS_TOOL_CALL_SENTINEL_ID,
} from "../../src/sentinel/sentinels/index.js";
import { SentinelRegistry } from "../../src/sentinel/sentinel-registry.js";
import type {
  SentinelContext,
  SentinelFinding,
  SentinelSeverity,
} from "../../src/sentinel/types.js";
import type { AuditLog } from "../../src/l2-operational/audit-log.js";
import type { SentinelFindingStore } from "../../src/sentinel/sentinel-finding-store.js";

const NOW = new Date("2026-05-10T15:00:00.000Z");

function fixedClock(now: Date): () => Date {
  return () => now;
}

/**
 * Minimal `SentinelFindingStore` stub: filters in-memory findings by
 * the same fields the real store supports. The real store is per-
 * fortress and AAD-bound to finding_ids; Phi-5 only reads it, so the
 * stub's filter shape is what matters for the regression suite.
 */
function makeStubFindingStore(findings: SentinelFinding[]): SentinelFindingStore {
  return {
    async listFindings(opts?: {
      since?: string;
      severity?: SentinelSeverity;
      sentinelId?: string;
      agentId?: string;
      limit?: number;
    }): Promise<SentinelFinding[]> {
      let out = findings.slice();
      if (opts?.since) out = out.filter((f) => f.observed_at >= opts.since!);
      if (opts?.severity) out = out.filter((f) => f.severity === opts.severity);
      if (opts?.sentinelId) out = out.filter((f) => f.sentinel_id === opts.sentinelId);
      if (opts?.agentId) out = out.filter((f) => f.agent_id === opts.agentId);
      out.sort((a, b) => (a.observed_at < b.observed_at ? 1 : -1));
      const limit = opts?.limit ?? 100;
      return out.slice(0, limit);
    },
  } as unknown as SentinelFindingStore;
}

function makeFailingFindingStore(): SentinelFindingStore {
  return {
    async listFindings(): Promise<SentinelFinding[]> {
      throw new Error("finding-store io_failed");
    },
  } as unknown as SentinelFindingStore;
}

function makeStubAuditLog(): AuditLog {
  return {
    async query() {
      return { entries: [], total: 0 };
    },
  } as unknown as AuditLog;
}

function makeContext(opts: {
  findingStore?: SentinelFindingStore;
  fortressId?: string;
}): SentinelContext {
  return {
    fortressId: opts.fortressId ?? "fortress-A",
    auditLog: makeStubAuditLog(),
    now: fixedClock(NOW),
    ...(opts.findingStore !== undefined
      ? { findingStore: opts.findingStore }
      : {}),
  };
}

/**
 * Build a synthetic finding. The fields Phi-5 reads are
 * `observed_at`, `sentinel_id`, `severity`, `agent_id`, `finding_id`.
 */
function mkFinding(opts: {
  ageMs: number;
  sentinelId: string;
  severity?: SentinelSeverity;
  agentId?: string;
  findingId?: string;
  fortressId?: string;
}): SentinelFinding {
  return {
    finding_id:
      opts.findingId ??
      `f-${opts.sentinelId}-${opts.agentId ?? "_"}-${opts.ageMs}`,
    sentinel_id: opts.sentinelId,
    severity: opts.severity ?? "warn",
    summary: `test fixture ${opts.sentinelId}`,
    details: {},
    observed_at: new Date(NOW.getTime() - opts.ageMs).toISOString(),
    evidence_audit_ids: [],
    fortress_id: opts.fortressId ?? "fortress-A",
    ...(opts.agentId !== undefined ? { agent_id: opts.agentId } : {}),
  };
}

// ── Trigger A: compound finding on one agent ─────────────────────────────

describe("WP-V1.3-1 Phi-5 AnomalyTriggerWatcher: Trigger A (compound finding)", () => {
  it("fires alert when 2+ distinct sentinel-IDs warn/alert on same agent within 24h", async () => {
    const findings = [
      mkFinding({
        ageMs: 60 * 60 * 1000,
        sentinelId: CREDENTIAL_USAGE_SENTINEL_ID,
        severity: "warn",
        agentId: "Cline",
      }),
      mkFinding({
        ageMs: 30 * 60 * 1000,
        sentinelId: CROSS_AGENT_CHATTER_SENTINEL_ID,
        severity: "alert",
        agentId: "Cline",
      }),
    ];
    const watcher = new AnomalyTriggerWatcher();
    await watcher.subscribe(
      makeContext({ findingStore: makeStubFindingStore(findings) }),
    );
    const out = await watcher.evaluate();
    const compound = out.find((f) => f.details.trigger === "compound");
    expect(compound).toBeDefined();
    expect(compound!.severity).toBe("alert");
    expect(compound!.agent_id).toBe("Cline");
    expect(
      (compound!.details.contributing_sentinels as string[]).sort(),
    ).toEqual(
      [
        CREDENTIAL_USAGE_SENTINEL_ID,
        CROSS_AGENT_CHATTER_SENTINEL_ID,
      ].sort(),
    );
    expect(compound!.evidence_audit_ids.length).toBe(2);
  });

  it("does NOT fire when the same single sentinel-ID repeats on one agent", async () => {
    const findings = [
      mkFinding({
        ageMs: 60 * 60 * 1000,
        sentinelId: CREDENTIAL_USAGE_SENTINEL_ID,
        severity: "warn",
        agentId: "Cline",
      }),
      mkFinding({
        ageMs: 30 * 60 * 1000,
        sentinelId: CREDENTIAL_USAGE_SENTINEL_ID,
        severity: "alert",
        agentId: "Cline",
      }),
    ];
    const watcher = new AnomalyTriggerWatcher();
    await watcher.subscribe(
      makeContext({ findingStore: makeStubFindingStore(findings) }),
    );
    const out = await watcher.evaluate();
    expect(out.find((f) => f.details.trigger === "compound")).toBeUndefined();
  });

  it("does NOT count info-severity findings toward the compound trigger", async () => {
    const findings = [
      mkFinding({
        ageMs: 60 * 60 * 1000,
        sentinelId: CREDENTIAL_USAGE_SENTINEL_ID,
        severity: "info",
        agentId: "Cline",
      }),
      mkFinding({
        ageMs: 30 * 60 * 1000,
        sentinelId: CROSS_AGENT_CHATTER_SENTINEL_ID,
        severity: "warn",
        agentId: "Cline",
      }),
    ];
    const watcher = new AnomalyTriggerWatcher();
    await watcher.subscribe(
      makeContext({ findingStore: makeStubFindingStore(findings) }),
    );
    const out = await watcher.evaluate();
    expect(out.find((f) => f.details.trigger === "compound")).toBeUndefined();
  });

  it("tracks each agent independently (one agent's compound does not affect another)", async () => {
    const findings = [
      // Agent Cline triggers compound.
      mkFinding({
        ageMs: 60 * 60 * 1000,
        sentinelId: CREDENTIAL_USAGE_SENTINEL_ID,
        severity: "alert",
        agentId: "Cline",
      }),
      mkFinding({
        ageMs: 30 * 60 * 1000,
        sentinelId: CROSS_AGENT_CHATTER_SENTINEL_ID,
        severity: "warn",
        agentId: "Cline",
      }),
      // Agent OpenClaw has only one sentinel firing.
      mkFinding({
        ageMs: 45 * 60 * 1000,
        sentinelId: EGRESS_VOLUME_SENTINEL_ID,
        severity: "warn",
        agentId: "OpenClaw",
      }),
    ];
    const watcher = new AnomalyTriggerWatcher();
    await watcher.subscribe(
      makeContext({ findingStore: makeStubFindingStore(findings) }),
    );
    const compounds = (await watcher.evaluate()).filter(
      (f) => f.details.trigger === "compound",
    );
    expect(compounds.length).toBe(1);
    expect(compounds[0]!.agent_id).toBe("Cline");
  });
});

// ── Trigger B: fortress-level count spike ────────────────────────────────

describe("WP-V1.3-1 Phi-5 AnomalyTriggerWatcher: Trigger B (fortress count spike)", () => {
  it("returns no count-spike finding during warmup (fewer than 7 populated baseline windows)", async () => {
    // 50 findings in current window, 0 in baseline windows. Warmup
    // gating must suppress the count-spike path.
    const findings: SentinelFinding[] = [];
    for (let i = 0; i < 50; i += 1) {
      findings.push(
        mkFinding({
          ageMs: 60 * 60 * 1000 + i * 1000,
          sentinelId: EGRESS_VOLUME_SENTINEL_ID,
        }),
      );
    }
    const watcher = new AnomalyTriggerWatcher();
    await watcher.subscribe(
      makeContext({ findingStore: makeStubFindingStore(findings) }),
    );
    const out = await watcher.evaluate();
    expect(out.find((f) => f.details.trigger === "count_spike")).toBeUndefined();
  });

  it("fires alert when current 24h finding count exceeds mean + 6 sigma", async () => {
    const findings = buildCountHistory({
      perDayBaseline: [10, 10, 10, 10, 8, 12, 10], // mean 10, stddev ~1.13
      currentDayCount: 50,
    });
    const watcher = new AnomalyTriggerWatcher();
    await watcher.subscribe(
      makeContext({ findingStore: makeStubFindingStore(findings) }),
    );
    const out = await watcher.evaluate();
    const spike = out.find((f) => f.details.trigger === "count_spike");
    expect(spike).toBeDefined();
    expect(spike!.severity).toBe("alert");
    expect(spike!.details.current_count).toBe(50);
  });

  it("fires warn when current count between +3 sigma and +6 sigma", async () => {
    // mean=10, stddev ~1.07, warn ~13.2, alert ~16.4. current=15.
    const findings = buildCountHistory({
      perDayBaseline: [8, 10, 10, 10, 10, 10, 12],
      currentDayCount: 15,
    });
    const watcher = new AnomalyTriggerWatcher();
    await watcher.subscribe(
      makeContext({ findingStore: makeStubFindingStore(findings) }),
    );
    const out = await watcher.evaluate();
    const spike = out.find((f) => f.details.trigger === "count_spike");
    expect(spike).toBeDefined();
    expect(spike!.severity).toBe("warn");
    expect(spike!.details.sigma_threshold).toBe(3);
  });

  it("stays silent at normal levels (within +3 sigma)", async () => {
    const findings = buildCountHistory({
      perDayBaseline: [10, 11, 9, 10, 12, 8, 10],
      currentDayCount: 11,
    });
    const watcher = new AnomalyTriggerWatcher();
    await watcher.subscribe(
      makeContext({ findingStore: makeStubFindingStore(findings) }),
    );
    const out = await watcher.evaluate();
    expect(out.find((f) => f.details.trigger === "count_spike")).toBeUndefined();
  });
});

// ── Trigger C: novel sentinel-ID combination ─────────────────────────────

describe("WP-V1.3-1 Phi-5 AnomalyTriggerWatcher: Trigger C (novel combination)", () => {
  it("fires info when the current-window sentinel-ID combination has not appeared in baseline", async () => {
    // Baseline windows each fire just (egress-volume + credential-usage).
    // Current window fires (credential-usage + cross-agent-chatter), never
    // seen historically.
    const findings = buildComboHistory({
      baselineCombo: [EGRESS_VOLUME_SENTINEL_ID, CREDENTIAL_USAGE_SENTINEL_ID],
      currentCombo: [
        CREDENTIAL_USAGE_SENTINEL_ID,
        CROSS_AGENT_CHATTER_SENTINEL_ID,
      ],
    });
    const watcher = new AnomalyTriggerWatcher();
    await watcher.subscribe(
      makeContext({ findingStore: makeStubFindingStore(findings) }),
    );
    const out = await watcher.evaluate();
    const novel = out.find((f) => f.details.trigger === "novel_combo");
    expect(novel).toBeDefined();
    expect(novel!.severity).toBe("info");
    const ids = (novel!.details.sentinel_ids as string[]).sort();
    expect(ids).toEqual(
      [
        CREDENTIAL_USAGE_SENTINEL_ID,
        CROSS_AGENT_CHATTER_SENTINEL_ID,
      ].sort(),
    );
  });

  it("stays silent when current combo matches at least one historical baseline window", async () => {
    const findings = buildComboHistory({
      baselineCombo: [
        CREDENTIAL_USAGE_SENTINEL_ID,
        CROSS_AGENT_CHATTER_SENTINEL_ID,
      ],
      currentCombo: [
        CREDENTIAL_USAGE_SENTINEL_ID,
        CROSS_AGENT_CHATTER_SENTINEL_ID,
      ],
    });
    const watcher = new AnomalyTriggerWatcher();
    await watcher.subscribe(
      makeContext({ findingStore: makeStubFindingStore(findings) }),
    );
    const out = await watcher.evaluate();
    expect(out.find((f) => f.details.trigger === "novel_combo")).toBeUndefined();
  });

  it("stays silent when current window has fewer than 2 distinct sentinel-IDs", async () => {
    const findings = buildComboHistory({
      baselineCombo: [
        EGRESS_VOLUME_SENTINEL_ID,
        CREDENTIAL_USAGE_SENTINEL_ID,
      ],
      currentCombo: [EGRESS_VOLUME_SENTINEL_ID],
    });
    const watcher = new AnomalyTriggerWatcher();
    await watcher.subscribe(
      makeContext({ findingStore: makeStubFindingStore(findings) }),
    );
    const out = await watcher.evaluate();
    expect(out.find((f) => f.details.trigger === "novel_combo")).toBeUndefined();
  });

  it("stays silent during warmup (fewer than 7 populated baseline windows)", async () => {
    // 2 days of baseline plus today.
    const findings = buildComboHistory({
      baselineCombo: [EGRESS_VOLUME_SENTINEL_ID, CREDENTIAL_USAGE_SENTINEL_ID],
      currentCombo: [
        CREDENTIAL_USAGE_SENTINEL_ID,
        CROSS_AGENT_CHATTER_SENTINEL_ID,
      ],
      baselineDays: 3,
    });
    const watcher = new AnomalyTriggerWatcher();
    await watcher.subscribe(
      makeContext({ findingStore: makeStubFindingStore(findings) }),
    );
    const out = await watcher.evaluate();
    expect(out.find((f) => f.details.trigger === "novel_combo")).toBeUndefined();
  });
});

// ── Self-bootstrapping protection ────────────────────────────────────────

describe("WP-V1.3-1 Phi-5 AnomalyTriggerWatcher: self-bootstrapping protection", () => {
  it("excludes its own findings from the input set (avoids feedback loop)", async () => {
    // Two of the inputs are PRIOR anomaly-trigger findings on the same
    // agent. Phi-5 must NOT count those toward Trigger A; only the one
    // first-order sentinel firing remains, so no compound fires.
    const findings = [
      mkFinding({
        ageMs: 60 * 60 * 1000,
        sentinelId: ANOMALY_TRIGGER_SENTINEL_ID,
        severity: "alert",
        agentId: "Cline",
      }),
      mkFinding({
        ageMs: 45 * 60 * 1000,
        sentinelId: ANOMALY_TRIGGER_SENTINEL_ID,
        severity: "alert",
        agentId: "Cline",
      }),
      mkFinding({
        ageMs: 30 * 60 * 1000,
        sentinelId: CREDENTIAL_USAGE_SENTINEL_ID,
        severity: "warn",
        agentId: "Cline",
      }),
    ];
    const watcher = new AnomalyTriggerWatcher();
    await watcher.subscribe(
      makeContext({ findingStore: makeStubFindingStore(findings) }),
    );
    const out = await watcher.evaluate();
    expect(out.find((f) => f.details.trigger === "compound")).toBeUndefined();
  });
});

// ── Multi-fortress isolation ─────────────────────────────────────────────

describe("WP-V1.3-1 Phi-5 AnomalyTriggerWatcher: multi-fortress isolation", () => {
  it("each watcher reads only its own per-fortress finding store", async () => {
    const fortressAFindings = [
      mkFinding({
        ageMs: 60 * 60 * 1000,
        sentinelId: CREDENTIAL_USAGE_SENTINEL_ID,
        severity: "alert",
        agentId: "Cline",
      }),
      mkFinding({
        ageMs: 30 * 60 * 1000,
        sentinelId: CROSS_AGENT_CHATTER_SENTINEL_ID,
        severity: "warn",
        agentId: "Cline",
      }),
    ];
    const watcherA = new AnomalyTriggerWatcher();
    const watcherB = new AnomalyTriggerWatcher();
    await watcherA.subscribe(
      makeContext({
        findingStore: makeStubFindingStore(fortressAFindings),
        fortressId: "fortress-A",
      }),
    );
    await watcherB.subscribe(
      makeContext({
        findingStore: makeStubFindingStore([]),
        fortressId: "fortress-B",
      }),
    );
    const outA = await watcherA.evaluate();
    const outB = await watcherB.evaluate();
    expect(outA.some((f) => f.details.trigger === "compound")).toBe(true);
    expect(outB).toEqual([]);
  });
});

// ── Subscribe contract ───────────────────────────────────────────────────

describe("WP-V1.3-1 Phi-5 AnomalyTriggerWatcher: subscribe contract", () => {
  it("rejects a SentinelContext that does not carry a findingStore", async () => {
    const watcher = new AnomalyTriggerWatcher();
    await expect(
      watcher.subscribe(makeContext({})),
    ).rejects.toThrow(/findingStore missing/);
  });
});

// ── Failure-mode handling ────────────────────────────────────────────────

describe("WP-V1.3-1 Phi-5 AnomalyTriggerWatcher: failure-mode handling", () => {
  it("returns [] when the finding store throws (fail-soft, no cascading failure)", async () => {
    const watcher = new AnomalyTriggerWatcher();
    await watcher.subscribe(
      makeContext({ findingStore: makeFailingFindingStore() }),
    );
    const out = await watcher.evaluate();
    expect(out).toEqual([]);
  });
});

// ── Catalog + registry integration ───────────────────────────────────────

describe("WP-V1.3-1 Phi-5 catalog + registry integration", () => {
  it("anomaly-trigger is registered in PHI1_BASELINE_CATALOG alongside the other four sentinels", () => {
    const ids = PHI1_BASELINE_CATALOG.map((e) => e.sentinelId);
    expect(ids).toContain(EGRESS_VOLUME_SENTINEL_ID);
    expect(ids).toContain(CREDENTIAL_USAGE_SENTINEL_ID);
    expect(ids).toContain(CROSS_AGENT_CHATTER_SENTINEL_ID);
    expect(ids).toContain(SUSPICIOUS_TOOL_CALL_SENTINEL_ID);
    expect(ids).toContain(ANOMALY_TRIGGER_SENTINEL_ID);
    // Baseline pack (5) + 2 observation sentinels added post-baseline.
    expect(ids.length).toBe(7);
  });

  it("subscribes + unsubscribes via the Phi-1 registry surface", async () => {
    const registry = new SentinelRegistry();
    for (const entry of PHI1_BASELINE_CATALOG) registry.register(entry);
    const subscribed = await registry.subscribe(
      ANOMALY_TRIGGER_SENTINEL_ID,
      makeContext({ findingStore: makeStubFindingStore([]) }),
    );
    expect(subscribed.sentinelId).toBe(ANOMALY_TRIGGER_SENTINEL_ID);
    expect(registry.isSubscribed(ANOMALY_TRIGGER_SENTINEL_ID)).toBe(true);
    const torn = await registry.unsubscribe(ANOMALY_TRIGGER_SENTINEL_ID);
    expect(torn).toBe(true);
    expect(registry.isSubscribed(ANOMALY_TRIGGER_SENTINEL_ID)).toBe(false);
  });
});

// ── Helpers ──────────────────────────────────────────────────────────────

interface CountHistoryOpts {
  /** Count of findings in each prior day (index 0 = 1 day ago). */
  perDayBaseline: number[];
  /** Count of findings in the current 24h window. */
  currentDayCount: number;
}

function buildCountHistory(opts: CountHistoryOpts): SentinelFinding[] {
  const dayMs = 24 * 60 * 60 * 1000;
  const findings: SentinelFinding[] = [];
  // Current window. Spread across distinct sentinel-IDs so neither
  // Trigger A nor Trigger C fires from this fixture; Trigger B is the
  // only signal under test.
  const carriers = [
    EGRESS_VOLUME_SENTINEL_ID,
    CREDENTIAL_USAGE_SENTINEL_ID,
    CROSS_AGENT_CHATTER_SENTINEL_ID,
    SUSPICIOUS_TOOL_CALL_SENTINEL_ID,
  ];
  for (let i = 0; i < opts.currentDayCount; i += 1) {
    findings.push(
      mkFinding({
        ageMs: 60 * 60 * 1000 + i * 100,
        sentinelId: carriers[i % carriers.length]!,
        severity: "info",
        findingId: `cur-${i}`,
      }),
    );
  }
  // Baseline windows. Same shape so the trigger C "novel combo" test
  // does not spuriously fire alongside Trigger B.
  for (let day = 0; day < opts.perDayBaseline.length; day += 1) {
    const count = opts.perDayBaseline[day]!;
    for (let i = 0; i < count; i += 1) {
      findings.push(
        mkFinding({
          ageMs: (day + 1) * dayMs + 60 * 1000 + i * 100,
          sentinelId: carriers[i % carriers.length]!,
          severity: "info",
          findingId: `b${day}-${i}`,
        }),
      );
    }
  }
  return findings;
}

interface ComboHistoryOpts {
  baselineCombo: string[];
  currentCombo: string[];
  /** Defaults to 7 (full baseline window). */
  baselineDays?: number;
}

function buildComboHistory(opts: ComboHistoryOpts): SentinelFinding[] {
  const dayMs = 24 * 60 * 60 * 1000;
  const days = opts.baselineDays ?? 7;
  const findings: SentinelFinding[] = [];
  // Current window.
  for (let i = 0; i < opts.currentCombo.length; i += 1) {
    findings.push(
      mkFinding({
        ageMs: 60 * 60 * 1000 + i * 1000,
        sentinelId: opts.currentCombo[i]!,
        severity: "info",
        findingId: `cur-${i}`,
      }),
    );
  }
  // Each baseline window fires the baselineCombo set.
  for (let day = 1; day <= days; day += 1) {
    for (let i = 0; i < opts.baselineCombo.length; i += 1) {
      findings.push(
        mkFinding({
          ageMs: day * dayMs + 60 * 1000 + i * 1000,
          sentinelId: opts.baselineCombo[i]!,
          severity: "info",
          findingId: `b${day}-${i}`,
        }),
      );
    }
  }
  return findings;
}
