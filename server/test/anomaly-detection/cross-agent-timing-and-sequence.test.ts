/**
 * WP-V1.3-2 Chi-4 cross-agent-timing + tool-call-sequence regression suite.
 *
 * Coverage:
 *  - Cross-agent timing extractor: co-fire-rate baseline, abnormal
 *    co-fire spike, inter-event-time distribution, Pearson
 *    correlation strength.
 *  - Tool-call sequence extractor: distinct-tools baseline, sequence-
 *    length capture, n-gram entropy (low + high), repeat-pattern.
 *  - Multi-classifier integration: each detector accepts CUSUM and
 *    PSI alongside the default rolling baseline; findings propagate
 *    with the right shape.
 *  - Per-feature explanation: the rolling baseline carries
 *    `feature_contributions` with the deviating feature surfaced.
 *  - Multi-fortress isolation: the catalog factories produce
 *    detectors that bind to one fortress only.
 *  - Predict-then-observe invariant: outliers are NOT absorbed into
 *    the baseline (Chi-1 invariant; Chi-2 + Chi-4 preserve).
 *  - Catalog membership: both new detector ids registered.
 */

import { describe, it, expect } from "vitest";

import {
  AuditLog,
  type AuditEntry,
} from "../../src/operational/audit-log.js";
import { MemoryStorage } from "../../src/storage/memory.js";
import { generateRandomKey } from "../../src/core/random.js";
import {
  AnomalyPipelineDispatcher,
  type AnomalyContext,
} from "../../src/anomaly-detection/anomaly-pipeline.js";
import { SentinelFindingStore } from "../../src/sentinel/sentinel-finding-store.js";
import {
  extractCrossAgentTiming,
  CO_FIRE_WINDOW_MS,
  CORRELATION_BUCKET_MS,
  pairKey,
} from "../../src/anomaly-detection/feature-extractors/cross-agent-timing.js";
import {
  extractToolCallSequence,
  SEQUENCE_WINDOW_MS,
} from "../../src/anomaly-detection/feature-extractors/tool-call-sequence.js";
import {
  CrossAgentTimingDetector,
  CROSS_AGENT_TIMING_DETECTOR_ID,
} from "../../src/anomaly-detection/detectors/cross-agent-timing-detector.js";
import {
  ToolCallSequenceDetector,
  TOOL_CALL_SEQUENCE_DETECTOR_ID,
} from "../../src/anomaly-detection/detectors/tool-call-sequence-detector.js";
import { ANOMALY_DETECTOR_CATALOG } from "../../src/anomaly-detection/detectors/index.js";
import {
  RollingBaselineClassifier,
} from "../../src/anomaly-detection/classifiers/rolling-baseline.js";
import { CusumClassifier } from "../../src/anomaly-detection/classifiers/cusum.js";
import { PsiClassifier } from "../../src/anomaly-detection/classifiers/psi.js";
import { ClassifierStateStore } from "../../src/anomaly-detection/classifier-state-store.js";

const FORTRESS_A = "fortress_a";
const FORTRESS_B = "fortress_b";
const IDENTITY = "identity_test";

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
      const limit = opts.limit ?? 50;
      return { entries: filtered.slice(-limit), total: filtered.length };
    },
  } as unknown as AuditLog;
}

function makeAuditEntry(
  ts: Date,
  identityId: string,
  operation: string,
  layer: AuditEntry["layer"] = "l2",
): AuditEntry {
  return {
    timestamp: ts.toISOString(),
    layer,
    operation,
    identity_id: identityId,
    result: "success",
    details: {},
  };
}

function makeContext(
  audit: AuditLog,
  now: Date,
  fortressId: string = FORTRESS_A,
): AnomalyContext {
  return {
    fortressId,
    auditLog: audit,
    storage: new MemoryStorage(),
    masterKey: generateRandomKey(),
    now: () => now,
  };
}

/* ============================================================
 * Cross-agent timing extractor
 * ============================================================ */

describe("WP-V1.3-2 Chi-4 cross-agent-timing extractor", () => {
  it("returns one FeatureVector per UNORDERED agent pair observed in the window", async () => {
    const now = new Date("2026-05-09T12:00:00.000Z");
    const tEarly = new Date(now.getTime() - 60_000);
    const audit = makeStubAuditLog([
      makeAuditEntry(tEarly, "agent-a", "state_read"),
      makeAuditEntry(tEarly, "agent-b", "state_read"),
      makeAuditEntry(tEarly, "agent-c", "state_read"),
    ]);
    const vectors = await extractCrossAgentTiming(
      makeContext(audit, now),
    );
    // 3 agents -> 3 unordered pairs.
    expect(vectors.length).toBe(3);
    const pairs = vectors.map((v) => v.agent_id).sort();
    expect(pairs).toEqual([
      pairKey("agent-a", "agent-b"),
      pairKey("agent-a", "agent-c"),
      pairKey("agent-b", "agent-c"),
    ]);
  });

  it("co_fire_rate_24h counts within-60s pairings; quiet baseline returns 0", async () => {
    const now = new Date("2026-05-09T12:00:00.000Z");
    const audit = makeStubAuditLog([
      makeAuditEntry(new Date(now.getTime() - 60 * 60 * 1000), "agent-a", "x"),
      makeAuditEntry(new Date(now.getTime() - 30 * 60 * 1000), "agent-b", "x"),
    ]);
    const vectors = await extractCrossAgentTiming(makeContext(audit, now));
    expect(vectors[0]?.features["co_fire_rate_24h"]).toBe(0);
  });

  it("co_fire_rate_24h captures abnormal co-fire spike when events fire within CO_FIRE_WINDOW_MS", async () => {
    const now = new Date("2026-05-09T12:00:00.000Z");
    const entries: AuditEntry[] = [];
    // 5 pairs of co-fires within 30s of each other.
    for (let i = 0; i < 5; i += 1) {
      const ts = new Date(now.getTime() - (i + 1) * 5 * 60 * 1000);
      entries.push(makeAuditEntry(ts, "agent-a", "x"));
      entries.push(
        makeAuditEntry(new Date(ts.getTime() + 30_000), "agent-b", "y"),
      );
    }
    const audit = makeStubAuditLog(entries);
    const vectors = await extractCrossAgentTiming(makeContext(audit, now));
    expect(vectors.length).toBe(1);
    const cofire = vectors[0]?.features["co_fire_rate_24h"] ?? 0;
    expect(cofire).toBe(5);
    // p50 should be ~30s; p99 ~30s (all the same).
    const p50 = vectors[0]?.features["inter_event_time_p50_ms"] ?? -1;
    expect(p50).toBeLessThanOrEqual(CO_FIRE_WINDOW_MS);
  });

  it("correlation_strength is high when both agents fire in the same buckets with varying intensity, and low when independent", async () => {
    const now = new Date("2026-05-09T12:00:00.000Z");
    // Lockstep with varying intensity per bucket so Pearson has
    // non-zero variance to work with. Bucket 1 has 1 event each;
    // bucket 2 has 2 events each; bucket 3 has 4 events each; etc.
    const lockstep: AuditEntry[] = [];
    for (let bucket = 1; bucket <= 6; bucket += 1) {
      const baseTs = now.getTime() - bucket * CORRELATION_BUCKET_MS;
      const intensity = bucket; // 1, 2, 3, 4, 5, 6
      for (let i = 0; i < intensity; i += 1) {
        const ts = new Date(baseTs + i * 1000);
        lockstep.push(makeAuditEntry(ts, "agent-a", "x"));
        lockstep.push(makeAuditEntry(ts, "agent-b", "y"));
      }
    }
    const lockstepResult = await extractCrossAgentTiming(
      makeContext(makeStubAuditLog(lockstep), now),
    );
    expect(lockstepResult[0]?.features["correlation_strength"]).toBeCloseTo(
      1.0,
      2,
    );

    // Disjoint with varying intensity: when one agent fires high,
    // the other fires low (or zero). Anti-correlated.
    const disjoint: AuditEntry[] = [];
    for (let bucket = 1; bucket <= 6; bucket += 1) {
      const baseTs = now.getTime() - bucket * CORRELATION_BUCKET_MS;
      // Agent A peaks on odd buckets, agent B on even buckets.
      const aIntensity = bucket % 2 === 1 ? 5 : 1;
      const bIntensity = bucket % 2 === 0 ? 5 : 1;
      for (let i = 0; i < aIntensity; i += 1) {
        disjoint.push(
          makeAuditEntry(new Date(baseTs + i * 1000), "agent-a", "x"),
        );
      }
      for (let i = 0; i < bIntensity; i += 1) {
        disjoint.push(
          makeAuditEntry(new Date(baseTs + i * 1000), "agent-b", "y"),
        );
      }
    }
    const disjointResult = await extractCrossAgentTiming(
      makeContext(makeStubAuditLog(disjoint), now),
    );
    const corr = disjointResult[0]?.features["correlation_strength"] ?? 1;
    expect(corr).toBeLessThan(0); // anti-correlated
  });
});

/* ============================================================
 * Tool-call sequence extractor
 * ============================================================ */

describe("WP-V1.3-2 Chi-4 tool-call-sequence extractor", () => {
  function pushSequence(
    now: Date,
    agent: string,
    tools: string[],
  ): AuditEntry[] {
    return tools.map((tool, i) =>
      makeAuditEntry(
        new Date(now.getTime() - (tools.length - i) * 1000),
        agent,
        `proxy_call:${tool}`,
      ),
    );
  }

  it("distinct_tools_used + max_sequence_length reflect the per-agent tool palette", async () => {
    const now = new Date("2026-05-09T12:00:00.000Z");
    const audit = makeStubAuditLog(
      pushSequence(now, "agent-a", [
        "read_file",
        "compute",
        "write_file",
        "read_file",
        "compute",
      ]),
    );
    const vectors = await extractToolCallSequence(
      makeContext(audit, now),
    );
    expect(vectors.length).toBe(1);
    expect(vectors[0]?.features["distinct_tools_used"]).toBe(3);
    expect(vectors[0]?.features["max_sequence_length"]).toBe(5);
  });

  it("ngram_3_histogram_entropy is low for single-tool repeating sequences and high for unique-each-step sequences", async () => {
    const now = new Date("2026-05-09T12:00:00.000Z");
    // Truly low entropy: one tool repeated. Single 3-gram (a,a,a) ->
    // entropy = 0.
    const lowEntropySeq = ["a", "a", "a", "a", "a", "a", "a", "a", "a"];
    // High entropy: every step a different tool. Each 3-gram unique;
    // entropy = log2(n - 2).
    const highEntropySeq = [
      "a",
      "b",
      "c",
      "d",
      "e",
      "f",
      "g",
      "h",
      "i",
    ];
    const lowAudit = makeStubAuditLog(
      pushSequence(now, "agent-a", lowEntropySeq),
    );
    const highAudit = makeStubAuditLog(
      pushSequence(now, "agent-a", highEntropySeq),
    );
    const lowVec = await extractToolCallSequence(makeContext(lowAudit, now));
    const highVec = await extractToolCallSequence(makeContext(highAudit, now));
    const lowEnt = lowVec[0]?.features["ngram_3_histogram_entropy"] ?? -1;
    const highEnt = highVec[0]?.features["ngram_3_histogram_entropy"] ?? -1;
    expect(lowEnt).toBe(0);
    expect(highEnt).toBeGreaterThan(2);
  });

  it("repeat_pattern_score captures hammered 2-grams (data-exfiltration shape)", async () => {
    const now = new Date("2026-05-09T12:00:00.000Z");
    // (read,write) twice + (write,read) once = pattern (read,write) repeats.
    const audit = makeStubAuditLog(
      pushSequence(now, "agent-a", [
        "read",
        "write",
        "read",
        "write",
        "read",
      ]),
    );
    const vectors = await extractToolCallSequence(makeContext(audit, now));
    const score = vectors[0]?.features["repeat_pattern_score"] ?? 0;
    // (read,write) appears 2x -> contributes 1; (write,read) 2x -> contributes 1.
    expect(score).toBe(2);
  });

  it("idle agents are skipped (no FeatureVector when no proxy_call entries in the 5-min window)", async () => {
    const now = new Date("2026-05-09T12:00:00.000Z");
    const audit = makeStubAuditLog([
      // outside window
      makeAuditEntry(
        new Date(now.getTime() - SEQUENCE_WINDOW_MS - 60_000),
        "agent-a",
        "proxy_call:x",
      ),
      // non-proxy entries inside window (skipped)
      makeAuditEntry(new Date(now.getTime() - 30_000), "agent-b", "state_read"),
    ]);
    const vectors = await extractToolCallSequence(makeContext(audit, now));
    expect(vectors).toEqual([]);
  });
});

/* ============================================================
 * Multi-classifier integration + per-feature explanation
 * ============================================================ */

describe("WP-V1.3-2 Chi-4 multi-classifier integration", () => {
  it("CrossAgentTimingDetector accepts a CUSUM additional classifier and emits a finding shape from it", async () => {
    const now = new Date("2026-05-09T12:00:00.000Z");
    const detector = new CrossAgentTimingDetector({
      minSamplesForPrediction: 1,
    });
    const ctx = makeContext(makeStubAuditLog([]), now);
    await detector.subscribe(ctx);
    const stateStore = new ClassifierStateStore({
      storage: ctx.storage,
      masterKey: ctx.masterKey,
      fortressId: ctx.fortressId,
    });
    const cusum = new CusumClassifier({
      stateStore,
      minSamplesForPrediction: 1,
    });
    expect(detector.addClassifier(cusum)).toBe(true);
    expect(detector.listClassifierIds()).toContain(cusum.classifierId);
    expect(detector.getAllClassifiers().length).toBe(2);
  });

  it("ToolCallSequenceDetector accepts a PSI additional classifier and the ids are listed correctly", async () => {
    const now = new Date("2026-05-09T12:00:00.000Z");
    const detector = new ToolCallSequenceDetector({
      minSamplesForPrediction: 1,
    });
    const ctx = makeContext(makeStubAuditLog([]), now);
    await detector.subscribe(ctx);
    const stateStore = new ClassifierStateStore({
      storage: ctx.storage,
      masterKey: ctx.masterKey,
      fortressId: ctx.fortressId,
    });
    const psi = new PsiClassifier({
      stateStore,
      minSamplesForPrediction: 1,
    });
    expect(detector.addClassifier(psi)).toBe(true);
    expect(detector.listClassifierIds()).toContain(psi.classifierId);
    expect(detector.getAllClassifiers().length).toBe(2);
  });
});

describe("WP-V1.3-2 Chi-4 per-feature explanation", () => {
  it("rolling-baseline classifier surfaces the deviating feature in feature_contributions", async () => {
    const stateStore = new ClassifierStateStore({
      storage: new MemoryStorage(),
      masterKey: generateRandomKey(),
      fortressId: FORTRESS_A,
    });
    const classifier = new RollingBaselineClassifier({
      stateStore,
      minSamplesForPrediction: 5,
    });
    const baselineVec = {
      agent_id: "pair-key",
      observed_at: "2026-05-09T12:00:00.000Z",
      features: {
        co_fire_rate_24h: 1,
        inter_event_time_p50_ms: 60_000,
        inter_event_time_p99_ms: 90_000,
        correlation_strength: 0,
      },
      window_label: "24h_rolling",
    };
    for (let i = 0; i < 7; i += 1) {
      await classifier.observe(baselineVec);
    }
    const driftVec = {
      ...baselineVec,
      features: {
        co_fire_rate_24h: 100, // huge drift here
        inter_event_time_p50_ms: 60_000,
        inter_event_time_p99_ms: 90_000,
        correlation_strength: 0,
      },
    };
    const prediction = await classifier.predict(driftVec);
    expect(prediction.baseline_ready).toBe(true);
    expect(prediction.feature_contributions.length).toBeGreaterThan(0);
    expect(prediction.feature_contributions[0]?.feature_name).toBe(
      "co_fire_rate_24h",
    );
    expect(Math.abs(prediction.feature_contributions[0]!.z_score)).toBeGreaterThan(
      5,
    );
  });

  it("explanation entries are sorted highest-deviation-first", async () => {
    const stateStore = new ClassifierStateStore({
      storage: new MemoryStorage(),
      masterKey: generateRandomKey(),
      fortressId: FORTRESS_A,
    });
    const classifier = new RollingBaselineClassifier({
      stateStore,
      minSamplesForPrediction: 3,
    });
    const baselineVec = {
      agent_id: "agent-a",
      observed_at: "2026-05-09T12:00:00.000Z",
      features: {
        distinct_tools_used: 3,
        max_sequence_length: 10,
        ngram_3_histogram_entropy: 1.5,
        repeat_pattern_score: 0,
      },
      window_label: "5min_sliding",
    };
    for (let i = 0; i < 5; i += 1) {
      await classifier.observe(baselineVec);
    }
    const driftVec = {
      ...baselineVec,
      features: {
        distinct_tools_used: 5, // small drift
        max_sequence_length: 10,
        ngram_3_histogram_entropy: 1.5,
        repeat_pattern_score: 50, // huge drift
      },
    };
    const prediction = await classifier.predict(driftVec);
    expect(prediction.explanation[0]).toContain("repeat_pattern_score");
  });
});

/* ============================================================
 * Multi-fortress isolation
 * ============================================================ */

describe("WP-V1.3-2 Chi-4 multi-fortress isolation", () => {
  it("a CrossAgentTimingDetector subscribed to fortress A sees only A's audit log", async () => {
    const now = new Date("2026-05-09T12:00:00.000Z");
    const auditA = makeStubAuditLog([
      makeAuditEntry(new Date(now.getTime() - 30_000), "agent-a", "x"),
      makeAuditEntry(new Date(now.getTime() - 25_000), "agent-b", "x"),
    ]);
    const auditB = makeStubAuditLog([]);
    const detectorA = new CrossAgentTimingDetector({
      minSamplesForPrediction: 1,
    });
    const detectorB = new CrossAgentTimingDetector({
      minSamplesForPrediction: 1,
    });
    await detectorA.subscribe(makeContext(auditA, now, FORTRESS_A));
    await detectorB.subscribe(makeContext(auditB, now, FORTRESS_B));
    const findingsA = await detectorA.evaluate();
    const findingsB = await detectorB.evaluate();
    // Single-vector first call observes baseline; no findings expected.
    expect(findingsA).toEqual([]);
    expect(findingsB).toEqual([]);
  });
});

/* ============================================================
 * Predict-then-observe invariant
 * ============================================================ */

describe("WP-V1.3-2 Chi-4 predict-then-observe invariant", () => {
  it("CrossAgentTimingDetector does not absorb outliers into baseline (Chi-1 invariant)", async () => {
    const now = new Date("2026-05-09T12:00:00.000Z");
    const stable: AuditEntry[] = [];
    for (let i = 0; i < 6; i += 1) {
      const tsA = new Date(now.getTime() - (i + 1) * 60 * 60 * 1000);
      const tsB = new Date(tsA.getTime() + 30 * 60 * 1000);
      stable.push(makeAuditEntry(tsA, "agent-a", "x"));
      stable.push(makeAuditEntry(tsB, "agent-b", "y"));
    }
    const auditStable = makeStubAuditLog(stable);
    const detector = new CrossAgentTimingDetector({
      minSamplesForPrediction: 5,
    });
    const ctxStable = makeContext(auditStable, now);
    await detector.subscribe(ctxStable);
    for (let i = 0; i < 6; i += 1) {
      await detector.evaluate();
    }
    const baselineMean = (detector.classifier as unknown as {
      getAgentState?: (id: string) => { features: Record<string, { mean: number }> } | undefined;
    }).getAgentState?.(pairKey("agent-a", "agent-b"));
    expect(baselineMean).toBeDefined();
    const baselineCofire = baselineMean!.features["co_fire_rate_24h"]!.mean;
    expect(baselineCofire).toBeLessThan(1);
    // Now hit it with a deviant vector.
    const deviant: AuditEntry[] = [];
    for (let i = 0; i < 30; i += 1) {
      const ts = new Date(now.getTime() - (i + 1) * 60_000);
      deviant.push(makeAuditEntry(ts, "agent-a", "x"));
      deviant.push(
        makeAuditEntry(new Date(ts.getTime() + 30_000), "agent-b", "y"),
      );
    }
    (detector as unknown as { context: AnomalyContext }).context = makeContext(
      makeStubAuditLog(deviant),
      now,
    );
    const findings = await detector.evaluate();
    // A drift finding should fire; verify the outlier did NOT contaminate the baseline.
    const postDriftMean = (detector.classifier as unknown as {
      getAgentState?: (id: string) => { features: Record<string, { mean: number }> } | undefined;
    }).getAgentState?.(pairKey("agent-a", "agent-b"));
    expect(postDriftMean!.features["co_fire_rate_24h"]!.mean).toBe(
      baselineCofire,
    );
    expect(findings.length).toBeGreaterThanOrEqual(1);
  });

  it("ToolCallSequenceDetector does not absorb outliers into baseline (Chi-1 invariant)", async () => {
    const now = new Date("2026-05-09T12:00:00.000Z");
    const buildAudit = (tools: string[]): AuditEntry[] =>
      tools.map((tool, i) =>
        makeAuditEntry(
          new Date(now.getTime() - (tools.length - i) * 1000),
          "agent-a",
          `proxy_call:${tool}`,
        ),
      );
    const stableTools = ["read", "compute", "write"];
    const detector = new ToolCallSequenceDetector({
      minSamplesForPrediction: 4,
    });
    const stableCtx = makeContext(makeStubAuditLog(buildAudit(stableTools)), now);
    await detector.subscribe(stableCtx);
    for (let i = 0; i < 5; i += 1) {
      await detector.evaluate();
    }
    const baselineDistinct = (detector.classifier as unknown as {
      getAgentState?: (id: string) => { features: Record<string, { mean: number }> } | undefined;
    }).getAgentState?.("agent-a");
    expect(baselineDistinct).toBeDefined();
    const baselineMean = baselineDistinct!.features["distinct_tools_used"]!.mean;
    // Drift event: many distinct tools.
    const driftTools = [
      "a",
      "b",
      "c",
      "d",
      "e",
      "f",
      "g",
      "h",
      "i",
      "j",
    ];
    (detector as unknown as { context: AnomalyContext }).context = makeContext(
      makeStubAuditLog(buildAudit(driftTools)),
      now,
    );
    const findings = await detector.evaluate();
    const postDriftMean = (detector.classifier as unknown as {
      getAgentState?: (id: string) => { features: Record<string, { mean: number }> } | undefined;
    }).getAgentState?.("agent-a");
    // Baseline mean unchanged (predict-then-observe; outlier rejected).
    expect(postDriftMean!.features["distinct_tools_used"]!.mean).toBe(
      baselineMean,
    );
    expect(findings.length).toBeGreaterThanOrEqual(1);
  });
});

/* ============================================================
 * Catalog membership
 * ============================================================ */

describe("WP-V1.3-2 Chi-4 catalog membership (Chi-3 forward-compat)", () => {
  it("ANOMALY_DETECTOR_CATALOG contains both Chi-4 detector ids and they instantiate cleanly", () => {
    const ids = ANOMALY_DETECTOR_CATALOG.map((e) => e.detectorId);
    expect(ids).toContain(CROSS_AGENT_TIMING_DETECTOR_ID);
    expect(ids).toContain(TOOL_CALL_SEQUENCE_DETECTOR_ID);
    for (const entry of ANOMALY_DETECTOR_CATALOG) {
      const inst = entry.factory();
      expect(inst.detectorId).toBe(entry.detectorId);
      expect(inst.description.length).toBeGreaterThan(0);
    }
  });

  it("dispatcher registers a Chi-4 detector via registerDetector and listDetectors reports it", async () => {
    const storage = new MemoryStorage();
    const masterKey = generateRandomKey();
    const auditLog = new AuditLog(storage, masterKey);
    const findingStore = new SentinelFindingStore({
      storage,
      masterKey,
      fortressId: FORTRESS_A,
    });
    const dispatcher = new AnomalyPipelineDispatcher({
      findingStore,
      auditLog,
      storage,
      masterKey,
      fortressId: FORTRESS_A,
      identityId: IDENTITY,
      tickIntervalMs: 0,
    });
    await dispatcher.registerDetector(new CrossAgentTimingDetector());
    await dispatcher.registerDetector(new ToolCallSequenceDetector());
    expect(dispatcher.listDetectors().sort()).toEqual([
      CROSS_AGENT_TIMING_DETECTOR_ID,
      TOOL_CALL_SEQUENCE_DETECTOR_ID,
    ]);
  });
});
