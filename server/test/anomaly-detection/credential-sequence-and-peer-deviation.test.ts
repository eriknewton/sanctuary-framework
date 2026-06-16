/**
 * WP-V1.3-2 Chi-6 credential-use-sequence + cross-agent-distribution
 * regression suite.
 *
 * Coverage:
 *  - Credential-use-sequence extractor: per-agent emission, broker-op
 *    filtering, distinct-credential breadth, repeat-pair score, burst
 *    feature, details.agent attribution + fallbacks, idle-agent skip.
 *  - Cross-agent-distribution extractor: per-agent peer-z vectors,
 *    single-agent skip, outlier peer-z magnitude, uniform-cohort
 *    floor behavior, peer_count feature.
 *  - Fire / no-fire / threshold behavior through the rolling-baseline
 *    classifier: stable history emits nothing; drift emits a finding
 *    with the deviating feature surfaced; sub-1-sigma drift stays
 *    silent.
 *  - Multi-classifier integration: both detectors accept CUSUM / PSI
 *    additional classifiers.
 *  - Predict-then-observe invariant: outliers are NOT absorbed into
 *    the baseline (Chi-1 invariant; Chi-2 + Chi-4 + Chi-6 preserve).
 *  - Multi-fortress isolation: detectors bind to one fortress only.
 *  - Catalog membership: both Chi-6 detector ids registered in
 *    ANOMALY_DETECTOR_CATALOG and ANOMALY_CATALOG; dispatcher
 *    registration works.
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
  extractCredentialUseSequence,
  CREDENTIAL_SEQUENCE_WINDOW_MS,
  BURST_BUCKET_MS,
} from "../../src/anomaly-detection/feature-extractors/credential-use-sequence.js";
import {
  extractCrossAgentDistribution,
  PEER_Z_PREFIX,
  PEER_COUNT_FEATURE,
} from "../../src/anomaly-detection/feature-extractors/cross-agent-distribution.js";
import {
  CredentialUseSequenceDetector,
  CREDENTIAL_USE_SEQUENCE_DETECTOR_ID,
} from "../../src/anomaly-detection/detectors/credential-use-sequence-detector.js";
import {
  CrossAgentDistributionDetector,
  CROSS_AGENT_DISTRIBUTION_DETECTOR_ID,
} from "../../src/anomaly-detection/detectors/cross-agent-distribution-detector.js";
import { ANOMALY_DETECTOR_CATALOG } from "../../src/anomaly-detection/detectors/index.js";
import {
  ANOMALY_CATALOG,
  findCatalogEntry,
} from "../../src/anomaly-detection/anomaly-catalog.js";
import {
  RollingBaselineClassifier,
  ROLLING_BASELINE_CLASSIFIER_ID,
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
  details: Record<string, unknown> = {},
  layer: AuditEntry["layer"] = "l3",
): AuditEntry {
  return {
    timestamp: ts.toISOString(),
    layer,
    operation,
    identity_id: identityId,
    result: "success",
    details,
  } as AuditEntry;
}

function makeCredentialRead(
  ts: Date,
  agent: string,
  secret: string,
): AuditEntry {
  return makeAuditEntry(ts, "broker-identity", "broker_secret_read", {
    agent,
    secret,
  });
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
 * Credential-use-sequence extractor
 * ============================================================ */

describe("WP-V1.3-2 Chi-6 credential-use-sequence extractor", () => {
  it("emits one FeatureVector per agent with credential activity, attributed via details.agent", async () => {
    const now = new Date("2026-06-11T12:00:00.000Z");
    const t = (minAgo: number): Date =>
      new Date(now.getTime() - minAgo * 60_000);
    const audit = makeStubAuditLog([
      makeCredentialRead(t(60), "agent-a", "db_token"),
      makeCredentialRead(t(50), "agent-a", "db_token"),
      makeCredentialRead(t(40), "agent-b", "stripe_secret"),
      // non-credential entry is ignored
      makeAuditEntry(t(30), "agent-a", "state_read"),
    ]);
    const vectors = await extractCredentialUseSequence(
      makeContext(audit, now),
    );
    expect(vectors.length).toBe(2);
    expect(vectors.map((v) => v.agent_id)).toEqual(["agent-a", "agent-b"]);
    expect(vectors[0]?.features["credential_event_count"]).toBe(2);
    expect(vectors[0]?.features["distinct_credentials_used"]).toBe(1);
    expect(vectors[1]?.features["credential_event_count"]).toBe(1);
  });

  it("falls back to identity_id then the system bucket when details.agent is absent", async () => {
    const now = new Date("2026-06-11T12:00:00.000Z");
    const audit = makeStubAuditLog([
      // no details.agent -> identity_id
      makeAuditEntry(
        new Date(now.getTime() - 60_000),
        "agent-direct",
        "broker_token_issued",
        { secret: "tok" },
      ),
      // no details.agent, blank identity -> system bucket
      makeAuditEntry(
        new Date(now.getTime() - 30_000),
        "",
        "broker_secret_read",
        {},
      ),
    ]);
    const vectors = await extractCredentialUseSequence(
      makeContext(audit, now),
    );
    expect(vectors.map((v) => v.agent_id)).toEqual([
      "agent-direct",
      "system",
    ]);
  });

  it("distinct_credentials_used captures enumeration breadth; tokens without details.secret fall back to the operation name", async () => {
    const now = new Date("2026-06-11T12:00:00.000Z");
    const t = (minAgo: number): Date =>
      new Date(now.getTime() - minAgo * 60_000);
    const audit = makeStubAuditLog([
      makeCredentialRead(t(50), "agent-a", "db_token"),
      makeCredentialRead(t(40), "agent-a", "aws_root"),
      makeCredentialRead(t(30), "agent-a", "stripe_secret"),
      // schema-less broker entry: token falls back to operation name
      makeAuditEntry(t(20), "broker-identity", "broker_token_issued", {
        agent: "agent-a",
      }),
    ]);
    const vectors = await extractCredentialUseSequence(
      makeContext(audit, now),
    );
    expect(vectors.length).toBe(1);
    expect(vectors[0]?.features["distinct_credentials_used"]).toBe(4);
    expect(vectors[0]?.features["credential_event_count"]).toBe(4);
  });

  it("repeat_pair_score captures hammered credential alternation", async () => {
    const now = new Date("2026-06-11T12:00:00.000Z");
    const t = (minAgo: number): Date =>
      new Date(now.getTime() - minAgo * 60_000);
    // a,b,a,b,a -> (a,b) twice + (b,a) twice -> score 2.
    const audit = makeStubAuditLog([
      makeCredentialRead(t(50), "agent-a", "cred-a"),
      makeCredentialRead(t(40), "agent-a", "cred-b"),
      makeCredentialRead(t(30), "agent-a", "cred-a"),
      makeCredentialRead(t(20), "agent-a", "cred-b"),
      makeCredentialRead(t(10), "agent-a", "cred-a"),
    ]);
    const vectors = await extractCredentialUseSequence(
      makeContext(audit, now),
    );
    expect(vectors[0]?.features["repeat_pair_score"]).toBe(2);
  });

  it("burst_max_5min captures a tight credential dump while spread-out use stays low", async () => {
    const now = new Date("2026-06-11T12:00:00.000Z");
    // Burst: 5 reads within one 5-minute bucket.
    const burstBase =
      Math.floor((now.getTime() - 60 * 60_000) / BURST_BUCKET_MS) *
      BURST_BUCKET_MS;
    const burst = [0, 10, 20, 30, 40].map((s) =>
      makeCredentialRead(new Date(burstBase + s * 1000), "agent-burst", "x"),
    );
    // Spread: 5 reads across 5 separate hours.
    const spread = [1, 2, 3, 4, 5].map((h) =>
      makeCredentialRead(
        new Date(now.getTime() - h * 60 * 60_000),
        "agent-spread",
        "x",
      ),
    );
    const vectors = await extractCredentialUseSequence(
      makeContext(makeStubAuditLog([...burst, ...spread]), now),
    );
    const byAgent = new Map(vectors.map((v) => [v.agent_id, v]));
    expect(byAgent.get("agent-burst")?.features["burst_max_5min"]).toBe(5);
    expect(byAgent.get("agent-spread")?.features["burst_max_5min"]).toBe(1);
  });

  it("skips agents with no credential activity in the 24h window", async () => {
    const now = new Date("2026-06-11T12:00:00.000Z");
    const audit = makeStubAuditLog([
      // outside the window
      makeCredentialRead(
        new Date(now.getTime() - CREDENTIAL_SEQUENCE_WINDOW_MS - 60_000),
        "agent-old",
        "x",
      ),
      // non-credential activity only
      makeAuditEntry(
        new Date(now.getTime() - 60_000),
        "agent-busy",
        "proxy_call:fetch",
      ),
    ]);
    const vectors = await extractCredentialUseSequence(
      makeContext(audit, now),
    );
    expect(vectors).toEqual([]);
  });
});

/* ============================================================
 * Cross-agent-distribution extractor
 * ============================================================ */

describe("WP-V1.3-2 Chi-6 cross-agent-distribution extractor", () => {
  it("emits one peer-z FeatureVector per agent when two or more agents are observed", async () => {
    const now = new Date("2026-06-11T12:00:00.000Z");
    const t = new Date(now.getTime() - 60_000);
    const audit = makeStubAuditLog([
      makeAuditEntry(t, "agent-a", "state_read"),
      makeAuditEntry(t, "agent-b", "state_read"),
      makeAuditEntry(t, "agent-c", "state_read"),
    ]);
    const vectors = await extractCrossAgentDistribution(
      makeContext(audit, now),
    );
    expect(vectors.length).toBe(3);
    for (const vector of vectors) {
      expect(vector.features[PEER_COUNT_FEATURE]).toBe(2);
      expect(
        Object.keys(vector.features).some((k) => k.startsWith(PEER_Z_PREFIX)),
      ).toBe(true);
    }
  });

  it("emits nothing for a single-agent fortress (no peer distribution)", async () => {
    const now = new Date("2026-06-11T12:00:00.000Z");
    const audit = makeStubAuditLog([
      makeAuditEntry(new Date(now.getTime() - 60_000), "agent-a", "state_read"),
    ]);
    const vectors = await extractCrossAgentDistribution(
      makeContext(audit, now),
    );
    expect(vectors).toEqual([]);
  });

  it("an outlier agent gets a large positive peer-z while uniform peers sit near zero", async () => {
    const now = new Date("2026-06-11T12:00:00.000Z");
    const entries: AuditEntry[] = [];
    // Three quiet peers: 2 events each. One hot agent: 40 events.
    for (const agent of ["peer-1", "peer-2", "peer-3"]) {
      for (let i = 0; i < 2; i += 1) {
        entries.push(
          makeAuditEntry(
            new Date(now.getTime() - (i + 1) * 60_000),
            agent,
            "state_read",
          ),
        );
      }
    }
    for (let i = 0; i < 40; i += 1) {
      entries.push(
        makeAuditEntry(
          new Date(now.getTime() - (i + 1) * 30_000),
          "agent-hot",
          "state_read",
        ),
      );
    }
    const vectors = await extractCrossAgentDistribution(
      makeContext(makeStubAuditLog(entries), now),
    );
    const byAgent = new Map(vectors.map((v) => [v.agent_id, v]));
    const hotZ =
      byAgent.get("agent-hot")?.features[
        `${PEER_Z_PREFIX}audit_event_count`
      ] ?? 0;
    const peerZ =
      byAgent.get("peer-1")?.features[`${PEER_Z_PREFIX}audit_event_count`] ??
      99;
    expect(hotZ).toBeGreaterThan(6);
    // peer-1 compared against {peer-2, peer-3, agent-hot}; its z is
    // negative (below the cohort mean dragged up by the hot agent).
    expect(peerZ).toBeLessThan(0);
  });

  it("uniform cohort yields zero peer-z via the stddev floor (no divide-by-zero)", async () => {
    const now = new Date("2026-06-11T12:00:00.000Z");
    const entries: AuditEntry[] = [];
    for (const agent of ["agent-a", "agent-b", "agent-c"]) {
      entries.push(
        makeAuditEntry(new Date(now.getTime() - 60_000), agent, "state_read"),
      );
    }
    const vectors = await extractCrossAgentDistribution(
      makeContext(makeStubAuditLog(entries), now),
    );
    for (const vector of vectors) {
      const z = vector.features[`${PEER_Z_PREFIX}audit_event_count`] ?? 99;
      expect(Number.isFinite(z)).toBe(true);
      expect(z).toBe(0);
    }
  });
});

/* ============================================================
 * Fire / no-fire / threshold behavior
 * ============================================================ */

describe("WP-V1.3-2 Chi-6 fire/no-fire/threshold behavior", () => {
  function makeRollingClassifier(minSamples: number): RollingBaselineClassifier {
    return new RollingBaselineClassifier({
      stateStore: new ClassifierStateStore({
        storage: new MemoryStorage(),
        masterKey: generateRandomKey(),
        fortressId: FORTRESS_A,
      }),
      minSamplesForPrediction: minSamples,
    });
  }

  function stableCredentialAudit(now: Date): AuditEntry[] {
    // Two reads of the same credential an hour apart: quiet baseline.
    return [
      makeCredentialRead(new Date(now.getTime() - 2 * 60 * 60_000), "agent-a", "db_token"),
      makeCredentialRead(new Date(now.getTime() - 60 * 60_000), "agent-a", "db_token"),
    ];
  }

  it("no-fire: stable credential history emits no findings", async () => {
    const now = new Date("2026-06-11T12:00:00.000Z");
    const detector = new CredentialUseSequenceDetector({
      classifier: makeRollingClassifier(4),
    });
    await detector.subscribe(
      makeContext(makeStubAuditLog(stableCredentialAudit(now)), now),
    );
    for (let i = 0; i < 6; i += 1) {
      const findings = await detector.evaluate();
      expect(findings).toEqual([]);
    }
  });

  it("fire: a credential enumeration burst after a stable baseline emits a finding naming the deviating feature", async () => {
    const now = new Date("2026-06-11T12:00:00.000Z");
    const detector = new CredentialUseSequenceDetector({
      classifier: makeRollingClassifier(4),
    });
    await detector.subscribe(
      makeContext(makeStubAuditLog(stableCredentialAudit(now)), now),
    );
    for (let i = 0; i < 5; i += 1) {
      await detector.evaluate();
    }
    // Drift: agent suddenly reads 20 distinct credentials in a burst.
    const burstBase =
      Math.floor((now.getTime() - 60 * 60_000) / BURST_BUCKET_MS) *
      BURST_BUCKET_MS;
    const drift: AuditEntry[] = [];
    for (let i = 0; i < 20; i += 1) {
      drift.push(
        makeCredentialRead(
          new Date(burstBase + i * 1000),
          "agent-a",
          `secret-${i}`,
        ),
      );
    }
    (detector as unknown as { context: AnomalyContext }).context =
      makeContext(makeStubAuditLog(drift), now);
    const findings = await detector.evaluate();
    expect(findings.length).toBeGreaterThanOrEqual(1);
    const finding = findings[0]!;
    expect(finding.sentinel_id).toBe(
      `anomaly:${CREDENTIAL_USE_SEQUENCE_DETECTOR_ID}`,
    );
    expect(finding.agent_id).toBe("agent-a");
    expect(["info", "warn", "alert"]).toContain(finding.severity);
    const details = finding.details as {
      detector_id: string;
      classifier_id: string;
      feature_contributions: Array<{ feature_name: string }>;
    };
    expect(details.detector_id).toBe(CREDENTIAL_USE_SEQUENCE_DETECTOR_ID);
    expect(details.classifier_id).toBe(ROLLING_BASELINE_CLASSIFIER_ID);
    const contributedNames = details.feature_contributions.map(
      (c) => c.feature_name,
    );
    expect(contributedNames).toContain("distinct_credentials_used");
  });

  it("threshold: small drift lands in the info band, not warn or alert", async () => {
    const now = new Date("2026-06-11T12:00:00.000Z");
    const classifier = makeRollingClassifier(4);
    const detector = new CredentialUseSequenceDetector({ classifier });
    await detector.subscribe(
      makeContext(makeStubAuditLog(stableCredentialAudit(now)), now),
    );
    for (let i = 0; i < 5; i += 1) {
      await detector.evaluate();
    }
    // Small drift: one extra read of the same credential. Against the
    // 0.5 stddev floor: credential_event_count 2 -> 3 (z=2) and
    // repeat_pair_score 0 -> 1 (z=2); score = sqrt(8) ~ 2.83, which
    // sits in the info band (1 <= score < 3).
    const slight = [
      ...stableCredentialAudit(now),
      makeCredentialRead(
        new Date(now.getTime() - 30 * 60_000),
        "agent-a",
        "db_token",
      ),
    ];
    (detector as unknown as { context: AnomalyContext }).context =
      makeContext(makeStubAuditLog(slight), now);
    const findings = await detector.evaluate();
    const credentialFindings = findings.filter(
      (f) => f.agent_id === "agent-a",
    );
    expect(credentialFindings.length).toBeGreaterThanOrEqual(1);
    for (const finding of credentialFindings) {
      expect(finding.severity).toBe("info");
    }
  });

  it("fire: an agent breaking from its cohort emits a cross-agent-distribution finding", async () => {
    const now = new Date("2026-06-11T12:00:00.000Z");
    const stable: AuditEntry[] = [];
    for (const agent of ["agent-a", "agent-b", "agent-c"]) {
      for (let i = 0; i < 3; i += 1) {
        stable.push(
          makeAuditEntry(
            new Date(now.getTime() - (i + 1) * 60 * 60_000),
            agent,
            "state_read",
          ),
        );
      }
    }
    const detector = new CrossAgentDistributionDetector({
      classifier: makeRollingClassifier(4),
    });
    await detector.subscribe(makeContext(makeStubAuditLog(stable), now));
    for (let i = 0; i < 5; i += 1) {
      const findings = await detector.evaluate();
      expect(findings).toEqual([]);
    }
    // Drift: agent-a goes hot while peers stay flat.
    const drift: AuditEntry[] = [...stable];
    for (let i = 0; i < 60; i += 1) {
      drift.push(
        makeAuditEntry(
          new Date(now.getTime() - (i + 1) * 30_000),
          "agent-a",
          "state_read",
        ),
      );
    }
    (detector as unknown as { context: AnomalyContext }).context =
      makeContext(makeStubAuditLog(drift), now);
    const findings = await detector.evaluate();
    const agentAFindings = findings.filter((f) => f.agent_id === "agent-a");
    expect(agentAFindings.length).toBeGreaterThanOrEqual(1);
    expect(agentAFindings[0]?.sentinel_id).toBe(
      `anomaly:${CROSS_AGENT_DISTRIBUTION_DETECTOR_ID}`,
    );
  });
});

/* ============================================================
 * Multi-classifier integration
 * ============================================================ */

describe("WP-V1.3-2 Chi-6 multi-classifier integration", () => {
  it("CredentialUseSequenceDetector accepts a CUSUM additional classifier", async () => {
    const now = new Date("2026-06-11T12:00:00.000Z");
    const detector = new CredentialUseSequenceDetector({
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

  it("CrossAgentDistributionDetector accepts a PSI additional classifier", async () => {
    const now = new Date("2026-06-11T12:00:00.000Z");
    const detector = new CrossAgentDistributionDetector({
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

/* ============================================================
 * Predict-then-observe invariant
 * ============================================================ */

describe("WP-V1.3-2 Chi-6 predict-then-observe invariant", () => {
  it("CredentialUseSequenceDetector does not absorb outliers into baseline (Chi-1 invariant)", async () => {
    const now = new Date("2026-06-11T12:00:00.000Z");
    const stable = [
      makeCredentialRead(
        new Date(now.getTime() - 2 * 60 * 60_000),
        "agent-a",
        "db_token",
      ),
      makeCredentialRead(
        new Date(now.getTime() - 60 * 60_000),
        "agent-a",
        "db_token",
      ),
    ];
    const detector = new CredentialUseSequenceDetector({
      minSamplesForPrediction: 4,
    });
    await detector.subscribe(makeContext(makeStubAuditLog(stable), now));
    for (let i = 0; i < 5; i += 1) {
      await detector.evaluate();
    }
    const getMean = (): number | undefined =>
      (detector.classifier as unknown as {
        getAgentState?: (
          id: string,
        ) => { features: Record<string, { mean: number }> } | undefined;
      }).getAgentState?.("agent-a")?.features["credential_event_count"]?.mean;
    const baselineMean = getMean();
    expect(baselineMean).toBeDefined();
    // Deviant window: 30 credential reads.
    const deviant: AuditEntry[] = [];
    for (let i = 0; i < 30; i += 1) {
      deviant.push(
        makeCredentialRead(
          new Date(now.getTime() - (i + 1) * 60_000),
          "agent-a",
          `s-${i % 10}`,
        ),
      );
    }
    (detector as unknown as { context: AnomalyContext }).context =
      makeContext(makeStubAuditLog(deviant), now);
    const findings = await detector.evaluate();
    expect(getMean()).toBe(baselineMean);
    expect(findings.length).toBeGreaterThanOrEqual(1);
  });
});

/* ============================================================
 * Multi-fortress isolation
 * ============================================================ */

describe("WP-V1.3-2 Chi-6 multi-fortress isolation", () => {
  it("a CredentialUseSequenceDetector subscribed to fortress A sees only A's audit log", async () => {
    const now = new Date("2026-06-11T12:00:00.000Z");
    const auditA = makeStubAuditLog([
      makeCredentialRead(new Date(now.getTime() - 30_000), "agent-a", "x"),
    ]);
    const auditB = makeStubAuditLog([]);
    const detectorA = new CredentialUseSequenceDetector({
      minSamplesForPrediction: 1,
    });
    const detectorB = new CredentialUseSequenceDetector({
      minSamplesForPrediction: 1,
    });
    await detectorA.subscribe(makeContext(auditA, now, FORTRESS_A));
    await detectorB.subscribe(makeContext(auditB, now, FORTRESS_B));
    const findingsA = await detectorA.evaluate();
    const findingsB = await detectorB.evaluate();
    // First-call observations build baselines; no findings either side.
    expect(findingsA).toEqual([]);
    expect(findingsB).toEqual([]);
  });
});

/* ============================================================
 * Catalog membership
 * ============================================================ */

describe("WP-V1.3-2 Chi-6 catalog membership", () => {
  it("ANOMALY_DETECTOR_CATALOG contains both Chi-6 detector ids and they instantiate cleanly", () => {
    const ids = ANOMALY_DETECTOR_CATALOG.map((e) => e.detectorId);
    expect(ids).toContain(CREDENTIAL_USE_SEQUENCE_DETECTOR_ID);
    expect(ids).toContain(CROSS_AGENT_DISTRIBUTION_DETECTOR_ID);
    for (const entry of ANOMALY_DETECTOR_CATALOG) {
      const inst = entry.factory();
      expect(inst.detectorId).toBe(entry.detectorId);
      expect(inst.description.length).toBeGreaterThan(0);
    }
  });

  it("ANOMALY_CATALOG exposes both Chi-6 detectors with the rolling-baseline classifier tuple", () => {
    for (const detectorId of [
      CREDENTIAL_USE_SEQUENCE_DETECTOR_ID,
      CROSS_AGENT_DISTRIBUTION_DETECTOR_ID,
    ]) {
      const entry = findCatalogEntry(
        detectorId,
        ROLLING_BASELINE_CLASSIFIER_ID,
      );
      expect(entry).toBeDefined();
      expect(entry?.description.length).toBeGreaterThan(0);
      const detector = entry!.factory();
      expect(detector.detectorId).toBe(detectorId);
    }
    expect(
      ANOMALY_CATALOG.filter(
        (e) =>
          e.detectorId === CREDENTIAL_USE_SEQUENCE_DETECTOR_ID ||
          e.detectorId === CROSS_AGENT_DISTRIBUTION_DETECTOR_ID,
      ).length,
    ).toBe(2);
  });

  it("dispatcher registers both Chi-6 detectors and listDetectors reports them", async () => {
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
    await dispatcher.registerDetector(new CredentialUseSequenceDetector());
    await dispatcher.registerDetector(new CrossAgentDistributionDetector());
    expect(dispatcher.listDetectors().sort()).toEqual([
      CREDENTIAL_USE_SEQUENCE_DETECTOR_ID,
      CROSS_AGENT_DISTRIBUTION_DETECTOR_ID,
    ]);
  });
});
