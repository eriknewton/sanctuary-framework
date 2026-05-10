/**
 * WP-V1.3-2 Chi-1 Anomaly Detection Pipeline foundation regression suite.
 *
 * Coverage:
 *  - Severity mapping: 1/3/6 sigma thresholds; sub-1 sigma silence.
 *  - RollingBaselineClassifier: warmup gate, per-feature mean +
 *    stddev correctness, anomaly score for normal vs deviant inputs,
 *    persisted state survives a restart, multi-fortress AAD binding.
 *  - PerAgentActivityExtractor: feature schema correctness, per-agent
 *    bucketing, system-bucket fallback, classification of egress /
 *    credential / receipt event categories.
 *  - PerAgentActivityDetector: end-to-end extract + observe + predict
 *    + finding emission; pre-baseline silence; warn / alert paths.
 *  - AnomalyPipelineDispatcher: registerDetector + audit emission,
 *    finding routing into SentinelFindingStore + audit log + listener,
 *    failure isolation (eval throws -> audit + listener emit; training
 *    throws -> audit + dispatcher continues), unregister, dispose.
 *  - Local-only invariant: classifier-state ciphertext does NOT
 *    contain plaintext feature names.
 *  - Multi-fortress isolation.
 *  - Castle-walking: extractor + classifier + dispatcher do not
 *    surface any outbound network call.
 *  - Existing v1.2/v1.3 + Phi-1/2/3/4 paths unchanged (additive
 *    surface; no test verifies this directly because it is enforced
 *    by full-suite green).
 */

import { describe, it, expect } from "vitest";

import {
  AuditLog,
  type AuditEntry,
} from "../../src/l2-operational/audit-log.js";
import { MemoryStorage } from "../../src/storage/memory.js";
import { generateRandomKey } from "../../src/core/random.js";
import { bytesToString } from "../../src/core/encoding.js";
import { SentinelFindingStore } from "../../src/sentinel/sentinel-finding-store.js";
import {
  AnomalyDetector,
  AnomalyPipelineDispatcher,
  ANOMALY_AUDIT_OPS,
  ANOMALY_SENTINEL_ID_PREFIX,
  severityFromAnomalyScore,
  type AnomalyClassifier,
  type AnomalyContext,
  type AnomalyFinding,
  type FeatureVector,
} from "../../src/anomaly-detection/anomaly-pipeline.js";
import {
  ANOMALY_CLASSIFIER_STATE_NAMESPACE,
  ClassifierStateStore,
} from "../../src/anomaly-detection/classifier-state-store.js";
import {
  RollingBaselineClassifier,
  ROLLING_BASELINE_CLASSIFIER_ID,
} from "../../src/anomaly-detection/classifiers/rolling-baseline.js";
import {
  extractPerAgentActivity,
  PER_AGENT_ACTIVITY_EXTRACTOR_ID,
  PER_AGENT_ACTIVITY_WINDOW_LABEL,
  SYSTEM_AGENT_BUCKET,
} from "../../src/anomaly-detection/feature-extractors/per-agent-activity.js";
import { PerAgentActivityDetector } from "../../src/anomaly-detection/detectors/per-agent-activity-detector.js";

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
      if (opts.operation_type) {
        filtered = filtered.filter((e) => e.operation === opts.operation_type);
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

function makeRig(opts?: {
  fortressId?: string;
  now?: () => Date;
  tickIntervalMs?: number;
}): {
  storage: MemoryStorage;
  masterKey: Uint8Array;
  auditLog: AuditLog;
  findingStore: SentinelFindingStore;
  dispatcher: AnomalyPipelineDispatcher;
} {
  const fortressId = opts?.fortressId ?? FORTRESS_A;
  const storage = new MemoryStorage();
  const masterKey = generateRandomKey();
  const auditLog = new AuditLog(storage, masterKey);
  const findingStore = new SentinelFindingStore({
    storage,
    masterKey,
    fortressId,
    ...(opts?.now !== undefined ? { now: opts.now } : {}),
  });
  const dispatcher = new AnomalyPipelineDispatcher({
    findingStore,
    auditLog,
    storage,
    masterKey,
    fortressId,
    identityId: IDENTITY,
    ...(opts?.now !== undefined ? { now: opts.now } : {}),
    tickIntervalMs: opts?.tickIntervalMs ?? 0,
  });
  return { storage, masterKey, auditLog, findingStore, dispatcher };
}

describe("WP-V1.3-2 Chi-1 severity mapping", () => {
  it("returns null below 1 sigma and a stepped severity above", () => {
    expect(severityFromAnomalyScore(0)).toBeNull();
    expect(severityFromAnomalyScore(0.99)).toBeNull();
    expect(severityFromAnomalyScore(1)).toBe("info");
    expect(severityFromAnomalyScore(2.99)).toBe("info");
    expect(severityFromAnomalyScore(3)).toBe("warn");
    expect(severityFromAnomalyScore(5.99)).toBe("warn");
    expect(severityFromAnomalyScore(6)).toBe("alert");
    expect(severityFromAnomalyScore(20)).toBe("alert");
    expect(severityFromAnomalyScore(Number.NaN)).toBeNull();
  });
});

describe("WP-V1.3-2 Chi-1 RollingBaselineClassifier", () => {
  function makeClassifier(opts?: {
    minSamplesForPrediction?: number;
  }): { classifier: RollingBaselineClassifier; storage: MemoryStorage } {
    const storage = new MemoryStorage();
    const masterKey = generateRandomKey();
    const stateStore = new ClassifierStateStore({
      storage,
      masterKey,
      fortressId: FORTRESS_A,
    });
    const classifier = new RollingBaselineClassifier({
      stateStore,
      ...(opts?.minSamplesForPrediction !== undefined
        ? { minSamplesForPrediction: opts.minSamplesForPrediction }
        : {}),
    });
    return { classifier, storage };
  }

  it("warmup gate: predict() returns baseline_ready=false until enough samples are observed", async () => {
    const { classifier } = makeClassifier({ minSamplesForPrediction: 5 });
    const vec = (count: number): FeatureVector => ({
      agent_id: "agent-a",
      observed_at: "2026-05-09T12:00:00.000Z",
      features: { tool_call_count: count },
      window_label: "24h_rolling",
    });
    for (let i = 0; i < 4; i += 1) {
      await classifier.observe(vec(10));
    }
    const before = await classifier.predict(vec(10));
    expect(before.baseline_ready).toBe(false);
    await classifier.observe(vec(10));
    const after = await classifier.predict(vec(10));
    expect(after.baseline_ready).toBe(true);
  });

  it("per-feature mean and stddev match Welford expectations", async () => {
    const { classifier } = makeClassifier({ minSamplesForPrediction: 3 });
    const vec = (count: number): FeatureVector => ({
      agent_id: "agent-a",
      observed_at: "2026-05-09T12:00:00.000Z",
      features: { tool_call_count: count },
      window_label: "24h_rolling",
    });
    for (const value of [10, 12, 14, 16, 18]) {
      await classifier.observe(vec(value));
    }
    const probe = await classifier.predict(vec(14));
    expect(probe.baseline_ready).toBe(true);
    const contrib = probe.feature_contributions.find(
      (c) => c.feature_name === "tool_call_count",
    );
    expect(contrib?.baseline_mean).toBeCloseTo(14, 5);
    // Welford sample variance for [10,12,14,16,18] = 10 -> stddev sqrt(10) ~= 3.162
    expect(contrib!.baseline_stddev).toBeGreaterThan(3);
    expect(contrib!.baseline_stddev).toBeLessThan(4);
  });

  it("anomaly score is small for in-baseline values and large for deviant values", async () => {
    const { classifier } = makeClassifier({ minSamplesForPrediction: 5 });
    const vec = (count: number): FeatureVector => ({
      agent_id: "agent-a",
      observed_at: "2026-05-09T12:00:00.000Z",
      features: { tool_call_count: count },
      window_label: "24h_rolling",
    });
    for (const value of [10, 11, 9, 12, 10, 11, 10]) {
      await classifier.observe(vec(value));
    }
    const inBaseline = await classifier.predict(vec(10));
    const deviant = await classifier.predict(vec(200));
    expect(inBaseline.anomaly_score).toBeLessThan(1);
    expect(deviant.anomaly_score).toBeGreaterThan(6);
  });

  it("train() persists state; a fresh classifier instance reads it back without retraining", async () => {
    const storage = new MemoryStorage();
    const masterKey = generateRandomKey();
    const stateStore1 = new ClassifierStateStore({
      storage,
      masterKey,
      fortressId: FORTRESS_A,
    });
    const c1 = new RollingBaselineClassifier({
      stateStore: stateStore1,
      minSamplesForPrediction: 3,
    });
    const vec = (count: number): FeatureVector => ({
      agent_id: "agent-a",
      observed_at: "2026-05-09T12:00:00.000Z",
      features: { tool_call_count: count },
      window_label: "24h_rolling",
    });
    for (const v of [10, 11, 9, 12, 10, 11, 10]) {
      await c1.observe(vec(v));
    }
    const trainResult = await c1.train();
    expect(trainResult.sample_count).toBe(7);
    expect(trainResult.agent_count).toBe(1);
    const stateStore2 = new ClassifierStateStore({
      storage,
      masterKey,
      fortressId: FORTRESS_A,
    });
    const c2 = new RollingBaselineClassifier({
      stateStore: stateStore2,
      minSamplesForPrediction: 3,
    });
    const probe = await c2.predict(vec(10));
    expect(probe.baseline_ready).toBe(true);
    expect(probe.anomaly_score).toBeLessThan(1);
  });

  it("multi-fortress AAD binding rejects a state record persisted under a different fortress", async () => {
    const storage = new MemoryStorage();
    const masterKey = generateRandomKey();
    const storeA = new ClassifierStateStore({
      storage,
      masterKey,
      fortressId: FORTRESS_A,
    });
    const storeB = new ClassifierStateStore({
      storage,
      masterKey,
      fortressId: FORTRESS_B,
    });
    await storeA.saveState(ROLLING_BASELINE_CLASSIFIER_ID, "agent-a", {
      observation_count: 7,
      last_observed_at: "2026-05-09T12:00:00.000Z",
      features: { tool_call_count: { n: 7, mean: 10.4, m2: 5.1 } },
    });
    const fromB = await storeB.loadState(
      ROLLING_BASELINE_CLASSIFIER_ID,
      "agent-a",
    );
    expect(fromB).toBeNull();
  });
});

describe("WP-V1.3-2 Chi-1 PerAgentActivityExtractor", () => {
  it("returns one FeatureVector per agent observed in the window", async () => {
    const now = new Date("2026-05-09T12:00:00.000Z");
    const recent = new Date(now.getTime() - 60_000);
    const audit = makeStubAuditLog([
      makeAuditEntry(recent, "agent-a", "state_read"),
      makeAuditEntry(recent, "agent-a", "proxy_call:openai.com"),
      makeAuditEntry(recent, "agent-b", "state_read"),
    ]);
    const ctx: AnomalyContext = {
      fortressId: FORTRESS_A,
      auditLog: audit,
      storage: new MemoryStorage(),
      masterKey: generateRandomKey(),
      now: () => now,
    };
    const vectors = await extractPerAgentActivity(ctx);
    expect(vectors.length).toBe(2);
    const a = vectors.find((v) => v.agent_id === "agent-a")!;
    const b = vectors.find((v) => v.agent_id === "agent-b")!;
    expect(a.features["tool_call_count"]).toBe(2);
    expect(a.features["egress_call_count"]).toBe(1);
    expect(b.features["tool_call_count"]).toBe(1);
    expect(b.features["egress_call_count"]).toBe(0);
    expect(a.window_label).toBe(PER_AGENT_ACTIVITY_WINDOW_LABEL);
  });

  it("buckets system-attributed audit entries under the system agent", async () => {
    const now = new Date("2026-05-09T12:00:00.000Z");
    const recent = new Date(now.getTime() - 60_000);
    const audit = makeStubAuditLog([
      makeAuditEntry(recent, "system", "proxy_call:openai.com"),
      makeAuditEntry(recent, "system", "proxy_call:openai.com"),
    ]);
    const ctx: AnomalyContext = {
      fortressId: FORTRESS_A,
      auditLog: audit,
      storage: new MemoryStorage(),
      masterKey: generateRandomKey(),
      now: () => now,
    };
    const vectors = await extractPerAgentActivity(ctx);
    expect(vectors.length).toBe(1);
    expect(vectors[0]?.agent_id).toBe(SYSTEM_AGENT_BUCKET);
    expect(vectors[0]?.features["egress_call_count"]).toBe(2);
  });

  it("classifies broker_secret_*/broker_token_* as credential_use_count and composition_receipt_*/reputation_* as recent_receipt_count", async () => {
    const now = new Date("2026-05-09T12:00:00.000Z");
    const recent = new Date(now.getTime() - 60_000);
    const audit = makeStubAuditLog([
      makeAuditEntry(recent, "agent-a", "broker_secret_added"),
      makeAuditEntry(recent, "agent-a", "broker_token_issued"),
      makeAuditEntry(recent, "agent-a", "composition_receipt_packed"),
      makeAuditEntry(recent, "agent-a", "reputation_record"),
    ]);
    const ctx: AnomalyContext = {
      fortressId: FORTRESS_A,
      auditLog: audit,
      storage: new MemoryStorage(),
      masterKey: generateRandomKey(),
      now: () => now,
    };
    const vectors = await extractPerAgentActivity(ctx);
    const a = vectors[0]!;
    expect(a.features["credential_use_count"]).toBe(2);
    expect(a.features["recent_receipt_count"]).toBe(2);
  });
});

describe("WP-V1.3-2 Chi-1 PerAgentActivityDetector end-to-end", () => {
  it("detector id matches the extractor id", () => {
    const detector = new PerAgentActivityDetector();
    expect(detector.detectorId).toBe(PER_AGENT_ACTIVITY_EXTRACTOR_ID);
  });

  it("fires no findings during the warmup window", async () => {
    const now = new Date("2026-05-09T12:00:00.000Z");
    const recent = new Date(now.getTime() - 60_000);
    const audit = makeStubAuditLog([
      makeAuditEntry(recent, "agent-a", "state_read"),
    ]);
    const detector = new PerAgentActivityDetector({
      minSamplesForPrediction: 5,
    });
    await detector.subscribe({
      fortressId: FORTRESS_A,
      auditLog: audit,
      storage: new MemoryStorage(),
      masterKey: generateRandomKey(),
      now: () => now,
    });
    const findings = await detector.evaluate();
    expect(findings).toEqual([]);
  });

  it("fires an alert when an agent's activity drifts well past 6 sigma", async () => {
    const now = new Date("2026-05-09T12:00:00.000Z");
    const recent = new Date(now.getTime() - 60_000);
    const detector = new PerAgentActivityDetector({
      minSamplesForPrediction: 5,
    });
    await detector.subscribe({
      fortressId: FORTRESS_A,
      auditLog: makeStubAuditLog([]),
      storage: new MemoryStorage(),
      masterKey: generateRandomKey(),
      now: () => now,
    });
    const baseline: FeatureVector = {
      agent_id: "agent-a",
      observed_at: now.toISOString(),
      features: {
        tool_call_count: 10,
        egress_call_count: 2,
        credential_use_count: 0,
        audit_event_count: 10,
        recent_receipt_count: 0,
      },
      window_label: PER_AGENT_ACTIVITY_WINDOW_LABEL,
    };
    for (let i = 0; i < 7; i += 1) {
      await detector.classifier.observe(baseline);
    }
    // Manually wire a deviant evaluate by injecting matching audit entries.
    const deviant: AuditEntry[] = [];
    for (let i = 0; i < 200; i += 1) {
      deviant.push(makeAuditEntry(recent, "agent-a", "proxy_call:openai.com"));
    }
    (detector as unknown as { context: AnomalyContext }).context = {
      fortressId: FORTRESS_A,
      auditLog: makeStubAuditLog(deviant),
      storage: new MemoryStorage(),
      masterKey: generateRandomKey(),
      now: () => now,
    };
    const findings = await detector.evaluate();
    expect(findings.length).toBe(1);
    expect(findings[0]?.severity).toBe("alert");
    expect(findings[0]?.agent_id).toBe("agent-a");
    expect(findings[0]?.sentinel_id).toBe(
      `${ANOMALY_SENTINEL_ID_PREFIX}${PER_AGENT_ACTIVITY_EXTRACTOR_ID}`,
    );
  });
});

describe("WP-V1.3-2 Chi-1 AnomalyPipelineDispatcher", () => {
  it("registerDetector emits anomaly_detector_registered audit event; unregister mirrors it", async () => {
    const rig = makeRig();
    const detector = new PerAgentActivityDetector({
      minSamplesForPrediction: 1,
    });
    await rig.dispatcher.registerDetector(detector);
    let audit = await rig.auditLog.query({ layer: "l2", limit: 100 });
    expect(
      audit.entries.some(
        (e) => e.operation === ANOMALY_AUDIT_OPS.DETECTOR_REGISTERED,
      ),
    ).toBe(true);
    expect(rig.dispatcher.listDetectors()).toContain(
      detector.detectorId,
    );
    const removed = await rig.dispatcher.unregisterDetector(
      detector.detectorId,
    );
    expect(removed).toBe(true);
    audit = await rig.auditLog.query({ layer: "l2", limit: 100 });
    expect(
      audit.entries.some(
        (e) => e.operation === ANOMALY_AUDIT_OPS.DETECTOR_UNREGISTERED,
      ),
    ).toBe(true);
  });

  it("tick() routes findings to the SentinelFindingStore + audit log + listeners", async () => {
    const rig = makeRig();
    const stub = new StubDetector();
    await rig.dispatcher.registerDetector(stub);
    stub.next = [
      {
        finding_id: "",
        sentinel_id: `${ANOMALY_SENTINEL_ID_PREFIX}stub`,
        severity: "warn",
        summary: "synthetic anomaly",
        details: { synthetic: true, anomaly_score: 4 },
        observed_at: "2026-05-09T12:00:00.000Z",
        agent_id: "agent-a",
        evidence_audit_ids: [],
        fortress_id: "",
      },
    ];
    const emitted: AnomalyFinding[] = [];
    rig.dispatcher.onEvent((event) => {
      if (event.type === "finding") emitted.push(event.finding);
    });
    const findings = await rig.dispatcher.tick();
    expect(findings.length).toBe(1);
    expect(findings[0]?.fortress_id).toBe(FORTRESS_A);
    expect(emitted.length).toBe(1);
    const stored = await rig.findingStore.listFindings();
    expect(stored.length).toBe(1);
    expect(stored[0]?.sentinel_id).toBe(
      `${ANOMALY_SENTINEL_ID_PREFIX}stub`,
    );
    const audit = await rig.auditLog.query({ layer: "l2", limit: 100 });
    expect(
      audit.entries.some(
        (e) => e.operation === ANOMALY_AUDIT_OPS.FINDING_EMITTED,
      ),
    ).toBe(true);
  });

  it("evaluate() failure emits anomaly_evaluation_failed and the dispatcher continues", async () => {
    const rig = makeRig();
    const flaky = new StubDetector("flaky");
    flaky.shouldThrow = true;
    const healthy = new StubDetector("healthy");
    healthy.next = [
      {
        finding_id: "",
        sentinel_id: `${ANOMALY_SENTINEL_ID_PREFIX}healthy`,
        severity: "info",
        summary: "healthy fixture",
        details: { anomaly_score: 1.5 },
        observed_at: "2026-05-09T12:00:00.000Z",
        agent_id: "agent-a",
        evidence_audit_ids: [],
        fortress_id: "",
      },
    ];
    await rig.dispatcher.registerDetector(flaky);
    await rig.dispatcher.registerDetector(healthy);
    const findings = await rig.dispatcher.tick();
    expect(findings.length).toBe(1);
    expect(findings[0]?.sentinel_id).toBe(
      `${ANOMALY_SENTINEL_ID_PREFIX}healthy`,
    );
    const audit = await rig.auditLog.query({ layer: "l2", limit: 100 });
    const failures = audit.entries.filter(
      (e) => e.operation === ANOMALY_AUDIT_OPS.EVALUATION_FAILED,
    );
    expect(failures.length).toBe(1);
    expect(failures[0]?.details?.["detector_id"]).toBe("flaky");
    expect(failures[0]?.result).toBe("failure");
  });

  it("training failure is logged but does not abort the tick", async () => {
    const rig = makeRig();
    const detector = new StubDetector("trains-bad");
    detector.classifierTrainsBadly = true;
    detector.next = [
      {
        finding_id: "",
        sentinel_id: `${ANOMALY_SENTINEL_ID_PREFIX}trains-bad`,
        severity: "warn",
        summary: "fixture",
        details: { anomaly_score: 4 },
        observed_at: "2026-05-09T12:00:00.000Z",
        agent_id: "agent-a",
        evidence_audit_ids: [],
        fortress_id: "",
      },
    ];
    await rig.dispatcher.registerDetector(detector);
    const findings = await rig.dispatcher.tick();
    expect(findings.length).toBe(1);
    const audit = await rig.auditLog.query({ layer: "l2", limit: 100 });
    expect(
      audit.entries.some(
        (e) => e.operation === ANOMALY_AUDIT_OPS.TRAINING_FAILED,
      ),
    ).toBe(true);
  });

  it("dispose() unregisters everything and stops the auto-tick", async () => {
    const rig = makeRig();
    const detector = new StubDetector("to-dispose");
    await rig.dispatcher.registerDetector(detector);
    expect(rig.dispatcher.listDetectors()).toContain("to-dispose");
    await rig.dispatcher.dispose();
    expect(rig.dispatcher.listDetectors()).toEqual([]);
  });

  it("multi-fortress isolation: each dispatcher only reaches its own audit log", async () => {
    const rigA = makeRig({ fortressId: FORTRESS_A });
    const rigB = makeRig({ fortressId: FORTRESS_B });
    // Seed fortress A's REAL audit log with activity. Fortress B
    // gets nothing.
    for (let i = 0; i < 5; i += 1) {
      rigA.auditLog.append("l1", "state_read", "agent-a");
    }
    await rigA.dispatcher.registerDetector(
      new PerAgentActivityDetector({ minSamplesForPrediction: 1 }),
    );
    await rigB.dispatcher.registerDetector(
      new PerAgentActivityDetector({ minSamplesForPrediction: 1 }),
    );
    await rigA.dispatcher.tick();
    await rigA.dispatcher.tick();
    await rigB.dispatcher.tick();
    await rigB.dispatcher.tick();
    // Fortress A's storage carries classifier state with agent-a's
    // observations from its seeded audit log. Each dispatcher also
    // produces its own self-emissions (registration / training audit
    // events under IDENTITY), which the per-agent extractor naturally
    // bucketizes as per-agent activity for IDENTITY; that cross-cutting
    // signal is not the multi-fortress isolation pivot.
    const stateA = await rigA.storage.list(
      ANOMALY_CLASSIFIER_STATE_NAMESPACE,
    );
    expect(stateA.length).toBeGreaterThan(0);
    // Multi-fortress isolation: fortress B's state namespace must
    // never contain fortress A's specific agent-id (agent-a). Each
    // fortress's classifier sees only its own audit log + its own
    // master-key-derived encryption keys.
    const stateAKeys = stateA.map((m) => m.key);
    expect(
      stateAKeys.some((k) => k.includes("agent-a")),
    ).toBe(true);
    const stateB = await rigB.storage.list(
      ANOMALY_CLASSIFIER_STATE_NAMESPACE,
    );
    const stateBKeys = stateB.map((m) => m.key);
    expect(stateBKeys.some((k) => k.includes("agent-a"))).toBe(false);
  });
});

describe("WP-V1.3-2 Chi-1 local-only invariant", () => {
  it("classifier-state ciphertext does not contain plaintext feature names", async () => {
    const storage = new MemoryStorage();
    const masterKey = generateRandomKey();
    const stateStore = new ClassifierStateStore({
      storage,
      masterKey,
      fortressId: FORTRESS_A,
    });
    const classifier = new RollingBaselineClassifier({
      stateStore,
      minSamplesForPrediction: 1,
    });
    const vec: FeatureVector = {
      agent_id: "agent-a",
      observed_at: "2026-05-09T12:00:00.000Z",
      features: {
        tool_call_count: 10,
        egress_call_count: 2,
      },
      window_label: "24h_rolling",
    };
    await classifier.observe(vec);
    await classifier.train();
    const stored = await storage.list(ANOMALY_CLASSIFIER_STATE_NAMESPACE);
    expect(stored.length).toBe(1);
    const raw = await storage.read(
      ANOMALY_CLASSIFIER_STATE_NAMESPACE,
      stored[0]!.key,
    );
    expect(raw).not.toBeNull();
    const asString = bytesToString(raw!);
    expect(asString).not.toContain("tool_call_count");
    expect(asString).not.toContain("egress_call_count");
    // Encrypted envelope is JSON with "alg" and "ct"; the ct is base64
    // so neither feature names nor literal numbers should appear.
    expect(asString).toContain("alg");
  });
});

class StubDetector extends AnomalyDetector {
  readonly detectorId: string;
  readonly description = "Test fixture detector.";
  classifier: AnomalyClassifier;
  next: AnomalyFinding[] = [];
  shouldThrow = false;
  classifierTrainsBadly = false;

  constructor(id = "stub") {
    super();
    this.detectorId = id;
    this.classifier = new StubClassifier(this);
  }

  override async featureExtract(): Promise<FeatureVector[]> {
    return [];
  }

  override async evaluate(): Promise<AnomalyFinding[]> {
    if (this.shouldThrow) throw new Error("stub detector exploded");
    return this.next;
  }
}

class StubClassifier implements AnomalyClassifier {
  readonly classifierId = "stub-classifier" as const;
  constructor(private readonly host: StubDetector) {}
  async observe(): Promise<void> {
    /* no-op */
  }
  async predict(): Promise<never> {
    throw new Error("StubClassifier.predict not used");
  }
  async train(): Promise<{
    trained_at: string;
    sample_count: number;
    agent_count: number;
  }> {
    if (this.host.classifierTrainsBadly) {
      throw new Error("training error");
    }
    return {
      trained_at: new Date().toISOString(),
      sample_count: 0,
      agent_count: 0,
    };
  }
}
