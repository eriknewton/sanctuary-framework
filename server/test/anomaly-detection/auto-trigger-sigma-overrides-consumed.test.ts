/**
 * Operator-tuned anomaly thresholds are honored by the classifier they
 * configure, verified through the production catalog construction path
 * rather than isolated unit construction (wired-consumer test, AGENTS.md
 * rule 4). Absent or invalid tuning keeps the classifier's own defaults,
 * so detection never widens.
 *
 * Private register: ic-sweep-auto-trigger-thresholds-consumed.
 */
import { describe, it, expect } from "vitest";

import { AuditLog } from "../../src/operational/audit-log.js";
import { MemoryStorage } from "../../src/storage/memory.js";
import { generateRandomKey } from "../../src/core/random.js";
import {
  ANOMALY_CATALOG,
  findCatalogEntry,
} from "../../src/anomaly-detection/anomaly-catalog.js";
import { PER_AGENT_ACTIVITY_DETECTOR_ID } from "../../src/anomaly-detection/detectors/per-agent-activity-detector.js";
import {
  CUSUM_CLASSIFIER_ID,
  CusumClassifier,
  DEFAULT_CUSUM_K,
  DEFAULT_CUSUM_H,
} from "../../src/anomaly-detection/classifiers/cusum.js";
import { ClassifierStateStore } from "../../src/anomaly-detection/classifier-state-store.js";
import type { AnomalyContext, FeatureVector } from "../../src/anomaly-detection/types.js";
import { ThresholdConfigStore } from "../../src/auto-trigger/threshold-config-store.js";
import { anomalyRuleId } from "../../src/auto-trigger/types.js";

const FORTRESS_ID = "fortress_ic29";
const WINDOW = "24h_rolling";
const NOW = () => new Date("2026-08-28T00:00:00.000Z");

// Baseline holds mean=10, stddev~0.816 (Welford over these 10 samples).
// A single observed=13 sample scores ~0.635 under DEFAULT_CUSUM_H=5
// (below the anomaly-score-1 finding floor) but ~15.9 under an
// alert_sigma=0.2 override -- a deliberate, decisive crossing in one
// direction only, so the test can tell "override consumed" from
// "override ignored" unambiguously. See sim in PR description.
const BASELINE = [9, 10, 11, 10, 9, 11, 10, 9, 10, 11];
const DRIFT_SAMPLE = 13;
const OVERRIDE_ALERT_SIGMA = 0.2;

function vec(
  agentId: string,
  features: Record<string, number>,
): FeatureVector {
  return {
    agent_id: agentId,
    observed_at: NOW().toISOString(),
    features,
    window_label: WINDOW,
  };
}

async function driftScoreAfterBaseline(
  classifier: CusumClassifier,
  agentId: string,
): Promise<number> {
  for (const v of BASELINE) {
    await classifier.observe(vec(agentId, { x: v }));
  }
  const prediction = await classifier.predict(vec(agentId, { x: DRIFT_SAMPLE }));
  return prediction.anomaly_score;
}

function makeContext(storage: MemoryStorage, masterKey: Uint8Array): AnomalyContext {
  return {
    fortressId: FORTRESS_ID,
    auditLog: new AuditLog(storage, masterKey),
    storage,
    masterKey,
    now: NOW,
  };
}

describe("IC-29 -- auto-trigger sigma overrides reach the CUSUM classifier", () => {
  it("classifierFactory built via the catalog consumes a persisted alert_sigma override", async () => {
    const entry = findCatalogEntry(
      PER_AGENT_ACTIVITY_DETECTOR_ID,
      CUSUM_CLASSIFIER_ID,
    );
    expect(entry?.classifierFactory).toBeTruthy();

    const storage = new MemoryStorage();
    const masterKey = generateRandomKey();
    const context = makeContext(storage, masterKey);

    // Control: confirm DRIFT_SAMPLE is deliberately sub-alert under the
    // classifier's own defaults (independent of the catalog/override
    // plumbing under test).
    const defaultOnlyClassifier = new CusumClassifier({
      stateStore: new ClassifierStateStore({
        storage: new MemoryStorage(),
        masterKey,
        fortressId: FORTRESS_ID,
      }),
    });
    const defaultScore = await driftScoreAfterBaseline(
      defaultOnlyClassifier,
      "agent-control",
    );
    expect(defaultScore).toBeLessThan(1);

    // Plant the divergence: persist an alert_sigma override, via the
    // SAME store + rule_id shape `sanctuary auto-trigger rules
    // set-threshold` writes (ThresholdConfigStore + anomalyRuleId).
    const configStore = new ThresholdConfigStore({
      storage,
      masterKey,
      fortressId: FORTRESS_ID,
      now: NOW,
    });
    const ruleId = anomalyRuleId(
      PER_AGENT_ACTIVITY_DETECTOR_ID,
      CUSUM_CLASSIFIER_ID,
    );
    const config = await configStore.getOrInit(ruleId, "anomaly");
    await configStore.set({
      ...config,
      threshold_overrides: {
        ...config.threshold_overrides,
        alert_sigma: OVERRIDE_ALERT_SIGMA,
      },
    });

    // Production path: build the classifier exactly how the /subscribe
    // route and the CLI do, through the catalog's classifierFactory.
    const overriddenClassifier = (await entry!.classifierFactory!(
      context,
    )) as CusumClassifier;
    expect(overriddenClassifier.h).toBeCloseTo(OVERRIDE_ALERT_SIGMA);

    const overriddenScore = await driftScoreAfterBaseline(
      overriddenClassifier,
      "agent-overridden",
    );
    expect(overriddenScore).toBeGreaterThanOrEqual(1);
    // The whole point: identical baseline + identical drift sample,
    // decisively different outcome once the persisted override reaches
    // construction.
    expect(overriddenScore).toBeGreaterThan(defaultScore * 10);
  });

  it("classifierFactory falls back to CusumClassifier's own defaults when no override is persisted", async () => {
    const entry = findCatalogEntry(
      PER_AGENT_ACTIVITY_DETECTOR_ID,
      CUSUM_CLASSIFIER_ID,
    );
    const storage = new MemoryStorage();
    const masterKey = generateRandomKey();
    const context = makeContext(storage, masterKey);

    const classifier = (await entry!.classifierFactory!(
      context,
    )) as CusumClassifier;
    expect(classifier.k).toBeCloseTo(DEFAULT_CUSUM_K);
    expect(classifier.h).toBeCloseTo(DEFAULT_CUSUM_H);
  });

  it("an out-of-range persisted alert_sigma (<=0) is ignored, never widening detection past defaults", async () => {
    const entry = findCatalogEntry(
      PER_AGENT_ACTIVITY_DETECTOR_ID,
      CUSUM_CLASSIFIER_ID,
    );
    const storage = new MemoryStorage();
    const masterKey = generateRandomKey();
    const context = makeContext(storage, masterKey);

    const configStore = new ThresholdConfigStore({
      storage,
      masterKey,
      fortressId: FORTRESS_ID,
      now: NOW,
    });
    const ruleId = anomalyRuleId(
      PER_AGENT_ACTIVITY_DETECTOR_ID,
      CUSUM_CLASSIFIER_ID,
    );
    const config = await configStore.getOrInit(ruleId, "anomaly");
    await configStore.set({
      ...config,
      threshold_overrides: {
        ...config.threshold_overrides,
        alert_sigma: -1,
        warn_sigma: 0,
      },
    });

    const classifier = (await entry!.classifierFactory!(
      context,
    )) as CusumClassifier;
    expect(classifier.k).toBeCloseTo(DEFAULT_CUSUM_K);
    expect(classifier.h).toBeCloseTo(DEFAULT_CUSUM_H);
  });

  it("ANOMALY_CATALOG's cusum entry still exposes a classifierFactory (sanity)", () => {
    const entry = ANOMALY_CATALOG.find(
      (e) =>
        e.detectorId === PER_AGENT_ACTIVITY_DETECTOR_ID &&
        e.classifierId === CUSUM_CLASSIFIER_ID,
    );
    expect(entry).toBeTruthy();
    expect(typeof entry?.classifierFactory).toBe("function");
  });
});
