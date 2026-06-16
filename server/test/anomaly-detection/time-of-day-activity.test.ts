/**
 * WP-V1.3-2 Chi-7 time-of-day-activity regression suite.
 *
 * Coverage:
 *  - Time-of-day-activity extractor: per-agent emission, band
 *    assignment, band-boundary hours, cross-midnight window coverage,
 *    proportion math, active-band count, identity fallback to the
 *    system bucket, window exclusion, idle-log empty result.
 *  - Chi-1 blindness contrast: two windows with identical volume and
 *    operation mix but different hours produce identical
 *    per-agent-activity features while the time-of-day features
 *    differ (the gap this detector exists to close).
 *  - Fire / no-fire / threshold behavior through the rolling-baseline
 *    classifier: stable diurnal history emits nothing; an off-hours
 *    burst fires with `band_count:night` as the top contributor; a
 *    constant-volume shift into the night band fires; small drift
 *    lands in the info band.
 *  - Multi-classifier integration: CUSUM / PSI additional classifiers.
 *  - Predict-then-observe invariant: outliers are NOT absorbed into
 *    the baseline (Chi-1 invariant; Chi-2 + Chi-4 + Chi-6 + Chi-7
 *    preserve).
 *  - Multi-fortress isolation: detectors bind to one fortress only.
 *  - Catalog membership: detector id registered in
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
  extractTimeOfDayActivity,
  bandForUtcHour,
  TIME_OF_DAY_WINDOW_MS,
  TIME_OF_DAY_BANDS,
  BAND_COUNT_PREFIX,
  BAND_PROPORTION_PREFIX,
  ACTIVE_BAND_COUNT_FEATURE,
} from "../../src/anomaly-detection/feature-extractors/time-of-day-activity.js";
import { extractPerAgentActivity } from "../../src/anomaly-detection/feature-extractors/per-agent-activity.js";
import {
  TimeOfDayActivityDetector,
  TIME_OF_DAY_ACTIVITY_DETECTOR_ID,
} from "../../src/anomaly-detection/detectors/time-of-day-activity-detector.js";
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

/** now = 12:00:00 UTC: the trailing 24h window covers every clock hour once. */
const NOW = new Date("2026-06-12T12:00:00.000Z");

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
  operation: string = "state_read",
  layer: AuditEntry["layer"] = "l2",
): AuditEntry {
  return {
    timestamp: ts.toISOString(),
    layer,
    operation,
    identity_id: identityId,
    result: "success",
    details: {},
  } as AuditEntry;
}

/** Audit entry at an exact UTC wall-clock time today (or yesterday via dayOffset). */
function entryAtUtc(
  agent: string,
  hour: number,
  minute = 0,
  second = 0,
  dayOffset = 0,
  operation = "state_read",
): AuditEntry {
  const ts = new Date(
    Date.UTC(2026, 5, 12 + dayOffset, hour, minute, second),
  );
  return makeAuditEntry(ts, agent, operation);
}

function makeContext(
  audit: AuditLog,
  now: Date = NOW,
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
 * Time-of-day-activity extractor
 * ============================================================ */

describe("WP-V1.3-2 Chi-7 time-of-day-activity extractor", () => {
  it("emits one FeatureVector per agent with per-band counts, proportions, and active-band count", async () => {
    const audit = makeStubAuditLog([
      entryAtUtc("agent-a", 2), // night
      entryAtUtc("agent-a", 8), // morning
      entryAtUtc("agent-a", 8, 30), // morning
      entryAtUtc("agent-b", 20, 0, 0, -1), // evening, yesterday (16h ago, in window)
    ]);
    const vectors = await extractTimeOfDayActivity(makeContext(audit));
    expect(vectors.length).toBe(2);
    expect(vectors.map((v) => v.agent_id)).toEqual(["agent-a", "agent-b"]);

    const a = vectors[0]!.features;
    expect(a[`${BAND_COUNT_PREFIX}night`]).toBe(1);
    expect(a[`${BAND_COUNT_PREFIX}morning`]).toBe(2);
    expect(a[`${BAND_COUNT_PREFIX}afternoon`]).toBe(0);
    expect(a[`${BAND_COUNT_PREFIX}evening`]).toBe(0);
    expect(a[`${BAND_PROPORTION_PREFIX}night`]).toBeCloseTo(1 / 3, 10);
    expect(a[`${BAND_PROPORTION_PREFIX}morning`]).toBeCloseTo(2 / 3, 10);
    expect(a[ACTIVE_BAND_COUNT_FEATURE]).toBe(2);

    const b = vectors[1]!.features;
    expect(b[`${BAND_COUNT_PREFIX}evening`]).toBe(1);
    expect(b[`${BAND_PROPORTION_PREFIX}evening`]).toBe(1);
    expect(b[ACTIVE_BAND_COUNT_FEATURE]).toBe(1);
    expect(vectors[0]!.window_label).toBe("24h_rolling");
  });

  it("assigns band-boundary hours to the later band (05:59:59 night, 06:00:00 morning)", async () => {
    expect(bandForUtcHour(0)).toBe("night");
    expect(bandForUtcHour(5)).toBe("night");
    expect(bandForUtcHour(6)).toBe("morning");
    expect(bandForUtcHour(11)).toBe("morning");
    expect(bandForUtcHour(12)).toBe("afternoon");
    expect(bandForUtcHour(17)).toBe("afternoon");
    expect(bandForUtcHour(18)).toBe("evening");
    expect(bandForUtcHour(23)).toBe("evening");

    const audit = makeStubAuditLog([
      entryAtUtc("agent-a", 5, 59, 59), // night
      entryAtUtc("agent-a", 6, 0, 0), // morning
    ]);
    const vectors = await extractTimeOfDayActivity(makeContext(audit));
    const features = vectors[0]!.features;
    expect(features[`${BAND_COUNT_PREFIX}night`]).toBe(1);
    expect(features[`${BAND_COUNT_PREFIX}morning`]).toBe(1);
  });

  it("proportions over the four bands sum to 1 for any active agent", async () => {
    const audit = makeStubAuditLog([
      entryAtUtc("agent-a", 1),
      entryAtUtc("agent-a", 7),
      entryAtUtc("agent-a", 13, 0, 0, -1), // yesterday afternoon (23h ago, in window)
      entryAtUtc("agent-a", 19, 0, 0, -1), // yesterday evening
      entryAtUtc("agent-a", 19, 30, 0, -1),
    ]);
    const vectors = await extractTimeOfDayActivity(makeContext(audit));
    const features = vectors[0]!.features;
    let sum = 0;
    for (const band of TIME_OF_DAY_BANDS) {
      sum += features[`${BAND_PROPORTION_PREFIX}${band}`] ?? 0;
    }
    expect(sum).toBeCloseTo(1, 10);
    expect(features[ACTIVE_BAND_COUNT_FEATURE]).toBe(4);
  });

  it("buckets blank identities under the system agent", async () => {
    const audit = makeStubAuditLog([
      makeAuditEntry(new Date(NOW.getTime() - 60_000), ""),
    ]);
    const vectors = await extractTimeOfDayActivity(makeContext(audit));
    expect(vectors.map((v) => v.agent_id)).toEqual(["system"]);
  });

  it("excludes events older than the 24h window and emits nothing for an empty log", async () => {
    const audit = makeStubAuditLog([
      makeAuditEntry(
        new Date(NOW.getTime() - TIME_OF_DAY_WINDOW_MS - 60_000),
        "agent-old",
      ),
    ]);
    expect(await extractTimeOfDayActivity(makeContext(audit))).toEqual([]);
    expect(
      await extractTimeOfDayActivity(makeContext(makeStubAuditLog([]))),
    ).toEqual([]);
  });

  it("sees the diurnal shift that per-agent-activity is blind to (same volume, different hours)", async () => {
    // Same agent, same 4 events of the same operations -- but the day
    // window has them in business hours, the drift window at 3am.
    const dayWindow = makeStubAuditLog([
      entryAtUtc("agent-a", 9),
      entryAtUtc("agent-a", 10),
      entryAtUtc("agent-a", 10, 30),
      entryAtUtc("agent-a", 11),
    ]);
    const nightWindow = makeStubAuditLog([
      entryAtUtc("agent-a", 3),
      entryAtUtc("agent-a", 3, 10),
      entryAtUtc("agent-a", 3, 20),
      entryAtUtc("agent-a", 3, 30),
    ]);
    const chi1Day = await extractPerAgentActivity(makeContext(dayWindow));
    const chi1Night = await extractPerAgentActivity(makeContext(nightWindow));
    // Chi-1 features identical: it cannot distinguish the two windows.
    expect(chi1Day[0]!.features).toEqual(chi1Night[0]!.features);

    const todDay = await extractTimeOfDayActivity(makeContext(dayWindow));
    const todNight = await extractTimeOfDayActivity(makeContext(nightWindow));
    expect(todDay[0]!.features[`${BAND_COUNT_PREFIX}morning`]).toBe(4);
    expect(todDay[0]!.features[`${BAND_COUNT_PREFIX}night`]).toBe(0);
    expect(todNight[0]!.features[`${BAND_COUNT_PREFIX}night`]).toBe(4);
    expect(todNight[0]!.features[`${BAND_COUNT_PREFIX}morning`]).toBe(0);
  });
});

/* ============================================================
 * Fire / no-fire / threshold behavior
 * ============================================================ */

describe("WP-V1.3-2 Chi-7 fire/no-fire/threshold behavior", () => {
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

  function stableMorningAudit(): AuditEntry[] {
    // Two business-hours events: quiet morning-only baseline.
    return [entryAtUtc("agent-a", 8), entryAtUtc("agent-a", 9)];
  }

  it("no-fire: a stable diurnal shape emits no findings", async () => {
    const detector = new TimeOfDayActivityDetector({
      classifier: makeRollingClassifier(4),
    });
    await detector.subscribe(
      makeContext(makeStubAuditLog(stableMorningAudit())),
    );
    for (let i = 0; i < 6; i += 1) {
      const findings = await detector.evaluate();
      expect(findings).toEqual([]);
    }
  });

  it("fire: an off-hours burst after a business-hours baseline alerts with band_count:night as top contributor", async () => {
    const detector = new TimeOfDayActivityDetector({
      classifier: makeRollingClassifier(4),
    });
    await detector.subscribe(
      makeContext(makeStubAuditLog(stableMorningAudit())),
    );
    for (let i = 0; i < 5; i += 1) {
      await detector.evaluate();
    }
    // Drift: usual morning events PLUS a 12-event burst at 02:00-03:00.
    const drift: AuditEntry[] = [...stableMorningAudit()];
    for (let i = 0; i < 12; i += 1) {
      drift.push(entryAtUtc("agent-a", 2, i * 5));
    }
    (detector as unknown as { context: AnomalyContext }).context =
      makeContext(makeStubAuditLog(drift));
    const findings = await detector.evaluate();
    expect(findings.length).toBeGreaterThanOrEqual(1);
    const finding = findings[0]!;
    expect(finding.sentinel_id).toBe(
      `anomaly:${TIME_OF_DAY_ACTIVITY_DETECTOR_ID}`,
    );
    expect(finding.agent_id).toBe("agent-a");
    expect(finding.severity).toBe("alert");
    const details = finding.details as {
      detector_id: string;
      classifier_id: string;
      feature_contributions: Array<{ feature_name: string; z_score: number }>;
    };
    expect(details.detector_id).toBe(TIME_OF_DAY_ACTIVITY_DETECTOR_ID);
    expect(details.classifier_id).toBe(ROLLING_BASELINE_CLASSIFIER_ID);
    // Contributions are sorted highest-|z| first; the night-band count
    // (0 -> 12 against the 0.5 stddev floor, z=24) must lead.
    expect(details.feature_contributions[0]?.feature_name).toBe(
      `${BAND_COUNT_PREFIX}night`,
    );
  });

  it("fire: a constant-volume shift into the night band alerts (the Chi-1-blind case)", async () => {
    const detector = new TimeOfDayActivityDetector({
      classifier: makeRollingClassifier(4),
    });
    await detector.subscribe(
      makeContext(makeStubAuditLog(stableMorningAudit())),
    );
    for (let i = 0; i < 5; i += 1) {
      await detector.evaluate();
    }
    // Drift: SAME total volume (2 events), moved to 03:00.
    // band_count:night 0->2 (z=4), band_count:morning 2->0 (z=-4),
    // proportions flip (z=+/-2 each): score = sqrt(16+16+4+4) ~ 6.32.
    const drift = [
      entryAtUtc("agent-a", 3),
      entryAtUtc("agent-a", 3, 30),
    ];
    (detector as unknown as { context: AnomalyContext }).context =
      makeContext(makeStubAuditLog(drift));
    const findings = await detector.evaluate();
    expect(findings.length).toBeGreaterThanOrEqual(1);
    expect(findings[0]!.severity).toBe("alert");
    const details = findings[0]!.details as {
      feature_contributions: Array<{ feature_name: string }>;
    };
    const contributedNames = details.feature_contributions.map(
      (c) => c.feature_name,
    );
    expect(contributedNames).toContain(`${BAND_COUNT_PREFIX}night`);
    expect(contributedNames).toContain(`${BAND_COUNT_PREFIX}morning`);
  });

  it("threshold: small drift lands in the info band, not warn or alert", async () => {
    const detector = new TimeOfDayActivityDetector({
      classifier: makeRollingClassifier(4),
    });
    await detector.subscribe(
      makeContext(makeStubAuditLog(stableMorningAudit())),
    );
    for (let i = 0; i < 5; i += 1) {
      await detector.evaluate();
    }
    // Small drift: one extra morning event. Against the 0.5 stddev
    // floor: band_count:morning 2 -> 3 (z=2); proportions and
    // active-band count are unchanged; score = sqrt(4) = 2, which sits
    // in the info band (1 <= score < 3).
    const slight = [...stableMorningAudit(), entryAtUtc("agent-a", 10)];
    (detector as unknown as { context: AnomalyContext }).context =
      makeContext(makeStubAuditLog(slight));
    const findings = await detector.evaluate();
    const agentFindings = findings.filter((f) => f.agent_id === "agent-a");
    expect(agentFindings.length).toBeGreaterThanOrEqual(1);
    for (const finding of agentFindings) {
      expect(finding.severity).toBe("info");
    }
  });
});

/* ============================================================
 * Multi-classifier integration
 * ============================================================ */

describe("WP-V1.3-2 Chi-7 multi-classifier integration", () => {
  it("TimeOfDayActivityDetector accepts CUSUM and PSI additional classifiers", async () => {
    const detector = new TimeOfDayActivityDetector({
      minSamplesForPrediction: 1,
    });
    const ctx = makeContext(makeStubAuditLog([]));
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
    const psi = new PsiClassifier({
      stateStore,
      minSamplesForPrediction: 1,
    });
    expect(detector.addClassifier(cusum)).toBe(true);
    expect(detector.addClassifier(psi)).toBe(true);
    expect(detector.listClassifierIds()).toContain(cusum.classifierId);
    expect(detector.listClassifierIds()).toContain(psi.classifierId);
    expect(detector.getAllClassifiers().length).toBe(3);
    // Re-attach is idempotent.
    expect(detector.addClassifier(cusum)).toBe(false);
  });
});

/* ============================================================
 * Predict-then-observe invariant
 * ============================================================ */

describe("WP-V1.3-2 Chi-7 predict-then-observe invariant", () => {
  it("TimeOfDayActivityDetector does not absorb outliers into baseline (Chi-1 invariant)", async () => {
    const stable = [entryAtUtc("agent-a", 8), entryAtUtc("agent-a", 9)];
    const detector = new TimeOfDayActivityDetector({
      minSamplesForPrediction: 4,
    });
    await detector.subscribe(makeContext(makeStubAuditLog(stable)));
    for (let i = 0; i < 5; i += 1) {
      await detector.evaluate();
    }
    const getMean = (): number | undefined =>
      (detector.classifier as unknown as {
        getAgentState?: (
          id: string,
        ) => { features: Record<string, { mean: number }> } | undefined;
      }).getAgentState?.("agent-a")?.features[`${BAND_COUNT_PREFIX}night`]
        ?.mean;
    const baselineMean = getMean();
    expect(baselineMean).toBeDefined();
    // Deviant window: 30 events in the night band.
    const deviant: AuditEntry[] = [];
    for (let i = 0; i < 30; i += 1) {
      deviant.push(entryAtUtc("agent-a", 1 + Math.floor(i / 10), i % 10));
    }
    (detector as unknown as { context: AnomalyContext }).context =
      makeContext(makeStubAuditLog(deviant));
    const findings = await detector.evaluate();
    expect(getMean()).toBe(baselineMean);
    expect(findings.length).toBeGreaterThanOrEqual(1);
  });
});

/* ============================================================
 * Multi-fortress isolation
 * ============================================================ */

describe("WP-V1.3-2 Chi-7 multi-fortress isolation", () => {
  it("a TimeOfDayActivityDetector subscribed to fortress A sees only A's audit log", async () => {
    const auditA = makeStubAuditLog([entryAtUtc("agent-a", 8)]);
    const auditB = makeStubAuditLog([]);
    const detectorA = new TimeOfDayActivityDetector({
      minSamplesForPrediction: 1,
    });
    const detectorB = new TimeOfDayActivityDetector({
      minSamplesForPrediction: 1,
    });
    await detectorA.subscribe(makeContext(auditA, NOW, FORTRESS_A));
    await detectorB.subscribe(makeContext(auditB, NOW, FORTRESS_B));
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

describe("WP-V1.3-2 Chi-7 catalog membership", () => {
  it("ANOMALY_DETECTOR_CATALOG contains the Chi-7 detector id and every entry instantiates cleanly", () => {
    const ids = ANOMALY_DETECTOR_CATALOG.map((e) => e.detectorId);
    expect(ids).toContain(TIME_OF_DAY_ACTIVITY_DETECTOR_ID);
    for (const entry of ANOMALY_DETECTOR_CATALOG) {
      const inst = entry.factory();
      expect(inst.detectorId).toBe(entry.detectorId);
      expect(inst.description.length).toBeGreaterThan(0);
    }
  });

  it("ANOMALY_CATALOG exposes the Chi-7 detector with the rolling-baseline classifier tuple", () => {
    const entry = findCatalogEntry(
      TIME_OF_DAY_ACTIVITY_DETECTOR_ID,
      ROLLING_BASELINE_CLASSIFIER_ID,
    );
    expect(entry).toBeDefined();
    expect(entry?.description.length).toBeGreaterThan(0);
    const detector = entry!.factory();
    expect(detector.detectorId).toBe(TIME_OF_DAY_ACTIVITY_DETECTOR_ID);
    expect(
      ANOMALY_CATALOG.filter(
        (e) => e.detectorId === TIME_OF_DAY_ACTIVITY_DETECTOR_ID,
      ).length,
    ).toBe(1);
  });

  it("dispatcher registers the Chi-7 detector and listDetectors reports it", async () => {
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
    await dispatcher.registerDetector(new TimeOfDayActivityDetector());
    expect(dispatcher.listDetectors()).toEqual([
      TIME_OF_DAY_ACTIVITY_DETECTOR_ID,
    ]);
  });
});
