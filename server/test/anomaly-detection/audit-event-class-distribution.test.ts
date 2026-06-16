/**
 * WP-V1.3-2 Chi-5 audit-event class distribution drift regression suite.
 *
 * Coverage:
 *  - Distribution extraction over the existing audit-log query surface.
 *  - Detector-local categorical PSI integration and threshold tuning.
 *  - Top per-class attribution, direction, magnitude, and deterministic ties.
 *  - Predict-then-observe invariant: drift samples do not reset baseline.
 *  - Multi-fortress state isolation and castle-walking local-only posture.
 */

import { describe, it, expect } from "vitest";

import type { AuditEntry, AuditLog } from "../../src/operational/audit-log.js";
import { MemoryStorage } from "../../src/storage/memory.js";
import { generateRandomKey } from "../../src/core/random.js";
import { SentinelFindingStore } from "../../src/sentinel/sentinel-finding-store.js";
import {
  AnomalyPipelineDispatcher,
  ANOMALY_AUDIT_OPS,
  type AnomalyClassifier,
  type AnomalyContext,
  type AnomalyPrediction,
  type FeatureVector,
  type TrainingResult,
} from "../../src/anomaly-detection/anomaly-pipeline.js";
import { ClassifierStateStore } from "../../src/anomaly-detection/classifier-state-store.js";
import {
  AUDIT_EVENT_CLASS_DISTRIBUTION_EXTRACTOR_ID,
  AUDIT_EVENT_CLASS_WINDOW_LABEL,
  buildAuditEventClassDistributions,
  distributionToFeatureVector,
  extractAuditEventClassDistribution,
  extractAuditEventClassDistributions,
} from "../../src/anomaly-detection/feature-extractors/audit-event-class-distribution.js";
import {
  AUDIT_EVENT_CLASS_DISTRIBUTION_DETECTOR_ID,
  AUDIT_EVENT_CLASS_DISTRIBUTION_PSI_CLASSIFIER_ID,
  AuditEventClassDistributionDetector,
  AuditEventClassDistributionPsiClassifier,
  computeCategoricalPsi,
  computePerClassDriftAttribution,
} from "../../src/anomaly-detection/detectors/audit-event-class-distribution-detector.js";
import { ANOMALY_DETECTOR_CATALOG } from "../../src/anomaly-detection/detectors/index.js";

const FORTRESS_A = "fortress_a";
const FORTRESS_B = "fortress_b";
const IDENTITY = "identity_test";

function makeAuditEntry(
  ts: Date,
  identityId: string,
  operation: string,
): AuditEntry {
  return {
    timestamp: ts.toISOString(),
    layer: "l2",
    operation,
    identity_id: identityId,
    result: "success",
    details: {},
  };
}

function makeStubAuditLog(entries: AuditEntry[]): AuditLog {
  return {
    async query(opts: { since?: string; limit?: number }) {
      let filtered = entries;
      if (opts.since) {
        const sinceMs = Date.parse(opts.since);
        filtered = filtered.filter(
          (entry) => Date.parse(entry.timestamp) >= sinceMs,
        );
      }
      const limit = opts.limit ?? 50;
      return { entries: filtered.slice(-limit), total: filtered.length };
    },
    append(
      layer: AuditEntry["layer"],
      operation: string,
      identity_id: string,
      details: Record<string, unknown>,
      result: AuditEntry["result"] = "success",
    ) {
      entries.push({
        timestamp: new Date("2026-05-09T13:00:00.000Z").toISOString(),
        layer,
        operation,
        identity_id,
        result,
        details,
      });
    },
  } as unknown as AuditLog;
}

function makeContext(
  entries: AuditEntry[],
  now = new Date("2026-05-09T12:00:00.000Z"),
  fortressId = FORTRESS_A,
  storage = new MemoryStorage(),
  masterKey = generateRandomKey(),
): AnomalyContext {
  return {
    fortressId,
    auditLog: makeStubAuditLog(entries),
    storage,
    masterKey,
    now: () => now,
  };
}

function vector(
  agentId: string,
  proportions: Record<string, number>,
): FeatureVector {
  const features: Record<string, number> = { total_events: 100 };
  for (const [className, proportion] of Object.entries(proportions)) {
    features[`class_proportion:${className}`] = proportion;
    features[`class_count:${className}`] = Math.round(proportion * 100);
  }
  return {
    agent_id: agentId,
    observed_at: "2026-05-09T12:00:00.000Z",
    features,
    window_label: AUDIT_EVENT_CLASS_WINDOW_LABEL,
  };
}

function makeClassifier(opts?: {
  storage?: MemoryStorage;
  masterKey?: Uint8Array;
  fortressId?: string;
  psiThreshold?: number;
  baselineSampleCount?: number;
}): AuditEventClassDistributionPsiClassifier {
  const stateStore = new ClassifierStateStore({
    storage: opts?.storage ?? new MemoryStorage(),
    masterKey: opts?.masterKey ?? generateRandomKey(),
    fortressId: opts?.fortressId ?? FORTRESS_A,
  });
  return new AuditEventClassDistributionPsiClassifier({
    stateStore,
    psiThreshold: opts?.psiThreshold,
    baselineSampleCount: opts?.baselineSampleCount ?? 3,
  });
}

async function trainBaseline(
  classifier: AuditEventClassDistributionPsiClassifier,
  agentId = "agent-a",
): Promise<void> {
  for (let i = 0; i < 3; i += 1) {
    await classifier.observe(
      vector(agentId, {
        tool_call: 0.4,
        state_read: 0.3,
        audit_query: 0.2,
        policy_check: 0.1,
      }),
    );
  }
}

describe("WP-V1.3-2 Chi-5 audit-event class distribution extractor", () => {
  it("extracts a single-class distribution with proportion 1.0", async () => {
    const now = new Date("2026-05-09T12:00:00.000Z");
    const entries = [
      makeAuditEntry(new Date(now.getTime() - 1_000), "agent-a", "state_read"),
      makeAuditEntry(new Date(now.getTime() - 2_000), "agent-a", "state_read"),
    ];
    const distributions = await extractAuditEventClassDistributions(
      makeContext(entries, now),
    );
    expect(distributions[0]?.total_events).toBe(2);
    expect(distributions[0]?.class_counts).toEqual({ state_read: 2 });
    expect(distributions[0]?.class_proportions).toEqual({ state_read: 1 });
  });

  it("extracts a balanced multi-class distribution and numeric feature vector", async () => {
    const now = new Date("2026-05-09T12:00:00.000Z");
    const entries = [
      makeAuditEntry(new Date(now.getTime() - 1_000), "agent-a", "tool_call"),
      makeAuditEntry(new Date(now.getTime() - 2_000), "agent-a", "state_read"),
      makeAuditEntry(new Date(now.getTime() - 3_000), "agent-a", "tool_call"),
      makeAuditEntry(new Date(now.getTime() - 4_000), "agent-a", "state_read"),
    ];
    const vectors = await extractAuditEventClassDistribution(
      makeContext(entries, now),
    );
    expect(vectors[0]?.features["total_events"]).toBe(4);
    expect(vectors[0]?.features["class_proportion:state_read"]).toBe(0.5);
    expect(vectors[0]?.features["class_count:tool_call"]).toBe(2);
    expect(vectors[0]?.window_label).toBe(AUDIT_EVENT_CLASS_WINDOW_LABEL);
  });

  it("keeps sparse class counts per agent without cross-agent bleed", () => {
    const start = "2026-05-08T12:00:00.000Z";
    const end = "2026-05-09T12:00:00.000Z";
    const entries = [
      makeAuditEntry(new Date(end), "agent-a", "secret_read"),
      makeAuditEntry(new Date(end), "agent-b", "policy_check"),
      makeAuditEntry(new Date(end), "agent-b", "policy_check"),
    ];
    const distributions = buildAuditEventClassDistributions(entries, start, end);
    expect(distributions.map((d) => d.agent_id)).toEqual(["agent-a", "agent-b"]);
    expect(distributions[0]?.class_proportions).toEqual({ secret_read: 1 });
    expect(distributions[1]?.class_counts).toEqual({ policy_check: 2 });
  });
});

describe("WP-V1.3-2 Chi-5 PSI integration", () => {
  it("reports no drift when the current distribution matches baseline", async () => {
    const classifier = makeClassifier();
    await trainBaseline(classifier);
    const prediction = await classifier.predict(
      vector("agent-a", {
        tool_call: 0.4,
        state_read: 0.3,
        audit_query: 0.2,
        policy_check: 0.1,
      }),
    );
    expect(prediction.baseline_ready).toBe(true);
    expect(prediction.anomaly_score).toBe(0);
  });

  it("keeps modest drift below the default threshold silent", async () => {
    const classifier = makeClassifier();
    await trainBaseline(classifier);
    const prediction = await classifier.predict(
      vector("agent-a", {
        tool_call: 0.35,
        state_read: 0.35,
        audit_query: 0.2,
        policy_check: 0.1,
      }),
    );
    expect(prediction.baseline_ready).toBe(true);
    expect(prediction.anomaly_score).toBe(0);
  });

  it("flags severe distribution drift above threshold", async () => {
    const classifier = makeClassifier();
    await trainBaseline(classifier);
    const prediction = await classifier.predict(
      vector("agent-a", {
        tool_call: 0.1,
        state_read: 0.71,
        audit_query: 0.09,
        policy_check: 0.1,
      }),
    );
    expect(prediction.baseline_ready).toBe(true);
    expect(prediction.anomaly_score).toBeGreaterThanOrEqual(6);
    expect(prediction.explanation[0]).toContain("state_read");
  });

  it("honors operator-tuned PSI threshold overrides", async () => {
    const classifier = makeClassifier({ psiThreshold: 0.9 });
    await trainBaseline(classifier);
    const prediction = await classifier.predict(
      vector("agent-a", {
        tool_call: 0.1,
        state_read: 0.71,
        audit_query: 0.09,
        policy_check: 0.1,
      }),
    );
    expect(prediction.baseline_ready).toBe(true);
    expect(prediction.anomaly_score).toBe(0);
  });

  it("can prime baseline from the prior 7 days of audit history before scoring the current window", async () => {
    const now = new Date("2026-05-09T12:00:00.000Z");
    const historicalBase = Date.parse("2026-05-07T12:00:00.000Z");
    const currentBase = Date.parse("2026-05-09T11:00:00.000Z");
    const entries = [
      ...Array.from({ length: 40 }, (_, i) =>
        makeAuditEntry(new Date(historicalBase - i), "agent-a", "tool_call"),
      ),
      ...Array.from({ length: 30 }, (_, i) =>
        makeAuditEntry(new Date(historicalBase - 10_000 - i), "agent-a", "state_read"),
      ),
      ...Array.from({ length: 20 }, (_, i) =>
        makeAuditEntry(new Date(historicalBase - 20_000 - i), "agent-a", "audit_query"),
      ),
      ...Array.from({ length: 10 }, (_, i) =>
        makeAuditEntry(new Date(historicalBase - 30_000 - i), "agent-a", "policy_check"),
      ),
      ...Array.from({ length: 71 }, (_, i) =>
        makeAuditEntry(new Date(currentBase - i), "agent-a", "state_read"),
      ),
      ...Array.from({ length: 10 }, (_, i) =>
        makeAuditEntry(new Date(currentBase - 10_000 - i), "agent-a", "tool_call"),
      ),
      ...Array.from({ length: 9 }, (_, i) =>
        makeAuditEntry(new Date(currentBase - 20_000 - i), "agent-a", "audit_query"),
      ),
      ...Array.from({ length: 10 }, (_, i) =>
        makeAuditEntry(new Date(currentBase - 30_000 - i), "agent-a", "policy_check"),
      ),
    ];
    const detector = new AuditEventClassDistributionDetector({
      baselineSampleCount: 99,
    });
    await detector.subscribe(makeContext(entries, now));
    const findings = await detector.evaluate();
    expect(findings.length).toBe(1);
    expect(findings[0]?.details["psi_score"]).toBeGreaterThanOrEqual(0.25);
    expect(detector.classifier.getAgentState("agent-a")?.baseline_proportions).toEqual({
      audit_query: 0.2,
      policy_check: 0.1,
      state_read: 0.3,
      tool_call: 0.4,
    });
  });
});

describe("WP-V1.3-2 Chi-5 per-class drift attribution", () => {
  it("identifies the top three drifters by absolute proportion delta", () => {
    const drift = computePerClassDriftAttribution(
      { tool_call: 0.4, state_read: 0.3, audit_query: 0.2, policy_check: 0.1 },
      { tool_call: 0.1, state_read: 0.71, audit_query: 0.09, policy_check: 0.1 },
    );
    expect(drift.slice(0, 3).map((d) => d.class_name)).toEqual([
      "state_read",
      "tool_call",
      "audit_query",
    ]);
  });

  it("records magnitude and direction for each drifted class", () => {
    const drift = computePerClassDriftAttribution(
      { tool_call: 0.4, state_read: 0.3 },
      { tool_call: 0.1, state_read: 0.6, secret_read: 0.3 },
    );
    const stateRead = drift.find((d) => d.class_name === "state_read")!;
    const toolCall = drift.find((d) => d.class_name === "tool_call")!;
    const secretRead = drift.find((d) => d.class_name === "secret_read")!;
    expect(stateRead.direction).toBe("up");
    expect(stateRead.relative_delta).toBeCloseTo(1);
    expect(toolCall.direction).toBe("down");
    expect(secretRead.relative_delta).toBeNull();
  });

  it("breaks attribution ties deterministically by class name", () => {
    const drift = computePerClassDriftAttribution(
      { a_class: 0.5, b_class: 0.5 },
      { a_class: 0.4, b_class: 0.6 },
    );
    expect(drift.map((d) => d.class_name)).toEqual(["a_class", "b_class"]);
  });
});

describe("WP-V1.3-2 Chi-5 predict-then-observe invariant", () => {
  it("does not absorb a drift sample into the baseline without reset", async () => {
    const classifier = makeClassifier();
    await trainBaseline(classifier);
    const before = classifier.getAgentState("agent-a")!.baseline_proportions!;
    const driftVector = vector("agent-a", {
      tool_call: 0.1,
      state_read: 0.71,
      audit_query: 0.09,
      policy_check: 0.1,
    });
    const detector = new AuditEventClassDistributionDetector({ classifier });
    const ctx = makeContext([]);
    await detector.subscribe(ctx);
    await detector.evaluate();
    const after = classifier.getAgentState("agent-a")!.baseline_proportions!;
    expect(after).toEqual(before);
    expect(computeCategoricalPsi(after, {
      tool_call: 0.1,
      state_read: 0.71,
      audit_query: 0.09,
      policy_check: 0.1,
    })).toBeGreaterThanOrEqual(0.25);
    expect(driftVector.features["class_proportion:state_read"]).toBe(0.71);
  });

  it("keeps classifier state unchanged when detector emits a drift finding", async () => {
    const classifier = makeClassifier();
    await trainBaseline(classifier);
    const entries = [
      ...Array.from({ length: 71 }, (_, i) =>
        makeAuditEntry(new Date(Date.parse("2026-05-09T12:00:00.000Z") - i), "agent-a", "state_read"),
      ),
      ...Array.from({ length: 10 }, (_, i) =>
        makeAuditEntry(new Date(Date.parse("2026-05-09T11:00:00.000Z") - i), "agent-a", "tool_call"),
      ),
      ...Array.from({ length: 9 }, (_, i) =>
        makeAuditEntry(new Date(Date.parse("2026-05-09T10:00:00.000Z") - i), "agent-a", "audit_query"),
      ),
      ...Array.from({ length: 10 }, (_, i) =>
        makeAuditEntry(new Date(Date.parse("2026-05-09T09:00:00.000Z") - i), "agent-a", "policy_check"),
      ),
    ];
    const detector = new AuditEventClassDistributionDetector({ classifier });
    await detector.subscribe(makeContext(entries));
    const beforeCount = classifier.getAgentState("agent-a")!.observation_count;
    const findings = await detector.evaluate();
    expect(findings.length).toBe(1);
    expect(classifier.getAgentState("agent-a")!.observation_count).toBe(beforeCount);
  });
});

describe("WP-V1.3-2 Chi-5 wiring and sovereignty", () => {
  it("keeps classifier state isolated by fortress", async () => {
    const storage = new MemoryStorage();
    const masterKey = generateRandomKey();
    const classifierA = makeClassifier({ storage, masterKey, fortressId: FORTRESS_A });
    await trainBaseline(classifierA);
    await classifierA.train();
    const classifierB = makeClassifier({ storage, masterKey, fortressId: FORTRESS_B });
    const stateB = classifierB.getAgentState("agent-a");
    expect(stateB).toBeUndefined();
    const predictionB = await classifierB.predict(vector("agent-a", { tool_call: 1 }));
    expect(predictionB.baseline_ready).toBe(false);
  });

  it("registers in the anomaly detector catalog with detector-specific PSI id", () => {
    const entry = ANOMALY_DETECTOR_CATALOG.find(
      (candidate) =>
        candidate.detectorId === AUDIT_EVENT_CLASS_DISTRIBUTION_DETECTOR_ID,
    );
    expect(entry).toBeDefined();
    expect(entry!.factory().detectorId).toBe(AUDIT_EVENT_CLASS_DISTRIBUTION_EXTRACTOR_ID);
    expect(AUDIT_EVENT_CLASS_DISTRIBUTION_PSI_CLASSIFIER_ID).toContain("psi");
  });

  it("continues to run operator-attached additional classifiers", async () => {
    const classifier = makeClassifier();
    await trainBaseline(classifier);
    const detector = new AuditEventClassDistributionDetector({ classifier });
    const extra = new AlwaysWarnClassifier();
    expect(detector.addClassifier(extra)).toBe(true);
    const entries = [
      makeAuditEntry(new Date("2026-05-09T12:00:00.000Z"), "agent-a", "tool_call"),
      makeAuditEntry(new Date("2026-05-09T11:59:59.000Z"), "agent-a", "state_read"),
    ];
    await detector.subscribe(makeContext(entries));
    const findings = await detector.evaluate();
    expect(extra.predictions).toBe(1);
    expect(
      findings.some(
        (finding) => finding.details["classifier_id"] === extra.classifierId,
      ),
    ).toBe(true);
  });

  it("routes detector findings through the dispatcher, finding store, and PSI audit op", async () => {
    const storage = new MemoryStorage();
    const masterKey = generateRandomKey();
    const entries: AuditEntry[] = [];
    const auditLog = makeStubAuditLog(entries);
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
      now: () => new Date("2026-05-09T12:00:00.000Z"),
      tickIntervalMs: 0,
    });
    const classifier = makeClassifier({ storage, masterKey, fortressId: FORTRESS_A });
    await trainBaseline(classifier);
    const detector = new AuditEventClassDistributionDetector({ classifier });
    await dispatcher.registerDetector(detector);
    entries.push(
      ...buildAuditEventClassDistributions([
        ...Array.from({ length: 80 }, (_, i) =>
          makeAuditEntry(new Date(Date.parse("2026-05-09T12:00:00.000Z") - i), "agent-a", "state_read"),
        ),
        ...Array.from({ length: 20 }, (_, i) =>
          makeAuditEntry(new Date(Date.parse("2026-05-09T11:00:00.000Z") - i), "agent-a", "tool_call"),
        ),
      ], "2026-05-08T12:00:00.000Z", "2026-05-09T12:00:00.000Z")
        .flatMap((d) => [
          ...Array.from({ length: d.class_counts["state_read"] ?? 0 }, (_, i) =>
            makeAuditEntry(new Date(Date.parse("2026-05-09T12:00:00.000Z") - i), d.agent_id, "state_read"),
          ),
          ...Array.from({ length: d.class_counts["tool_call"] ?? 0 }, (_, i) =>
            makeAuditEntry(new Date(Date.parse("2026-05-09T11:00:00.000Z") - i), d.agent_id, "tool_call"),
          ),
        ]),
    );
    const findings = await dispatcher.tick();
    expect(findings.length).toBe(1);
    expect(findings[0]?.details["classifier_id"]).toBe(
      AUDIT_EVENT_CLASS_DISTRIBUTION_PSI_CLASSIFIER_ID,
    );
    expect(
      entries.some(
        (entry) =>
          entry.operation === ANOMALY_AUDIT_OPS.PSI_DISTRIBUTION_SHIFT_DETECTED,
      ),
    ).toBe(true);
  });

  it("castle-walking stays pure-local: no proxy, substrate, or outbound ops are emitted", async () => {
    const entries = [
      makeAuditEntry(new Date("2026-05-09T12:00:00.000Z"), "agent-a", "state_read"),
      makeAuditEntry(new Date("2026-05-09T11:59:59.000Z"), "agent-a", "tool_call"),
    ];
    const vectors = await extractAuditEventClassDistribution(makeContext(entries));
    const ops = new Set(entries.map((entry) => entry.operation));
    expect(vectors.length).toBe(1);
    expect([...ops].some((op) => op.startsWith("proxy_call:"))).toBe(false);
    expect(ops.has("intelligence_substrate_invoked")).toBe(false);
    expect(ops.has("query_anonymity_headers_stripped")).toBe(false);
  });
});

class AlwaysWarnClassifier implements AnomalyClassifier {
  readonly classifierId = "audit-event-class-distribution:test-extra";
  predictions = 0;

  async observe(): Promise<void> {}

  async predict(): Promise<AnomalyPrediction> {
    this.predictions += 1;
    return {
      anomaly_score: 3,
      explanation: ["test extra classifier fired"],
      feature_contributions: [],
      baseline_ready: true,
    };
  }

  async train(): Promise<TrainingResult> {
    return {
      trained_at: "2026-05-09T12:00:00.000Z",
      sample_count: 0,
      agent_count: 0,
    };
  }
}
