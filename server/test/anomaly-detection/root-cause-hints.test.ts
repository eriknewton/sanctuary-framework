/**
 * WP-V1.3-2 Chi-8 root-cause hints regression suite.
 *
 * Coverage:
 *  - Per-detector hint mapping: every one of the seven shipped
 *    detectors maps its real emitted feature names to detector-
 *    specific likely-cause text (positive cases), including the
 *    prefixed namespaces (`band_count:*`, `band_proportion:*`,
 *    `peer_z:*`, `class_count:*`, `class_proportion:*`).
 *  - Direction thresholds: |z| < 1 earns no hint; z >= +1 maps to
 *    above_baseline; z <= -1 maps to below_baseline.
 *  - Ordering, cap, and determinism: highest |z| first, then feature
 *    name; max 5 hints; identical input yields identical output.
 *  - Fallbacks: unknown detector id and unknown feature names degrade
 *    to generic stat-only hints; empty / missing / malformed
 *    contributions degrade to an empty array; never throw.
 *  - per_class_drift mapping for audit-event-class-distribution:
 *    up/down direction, flat skipped, top-3 cap, mirrored
 *    class_proportion contributions deduplicated, z_score null.
 *  - Fail-closed wrapper: a hint builder forced to throw degrades to
 *    an empty hints array; hostile details (throwing getter) degrade
 *    to unchanged details; in both cases the finding survives.
 *  - Dispatcher integration: routed findings carry root_cause_hints
 *    in the store, the tick return value, and the listener emit; a
 *    finding with hostile details still persists.
 *  - No-leakage invariant: hints contain no values copied from raw
 *    audit event details (observed_features payloads, secret-looking
 *    strings) beyond numeric contribution stats and feature names.
 */

import { describe, it, expect } from "vitest";

import { AuditLog } from "../../src/l2-operational/audit-log.js";
import { MemoryStorage } from "../../src/storage/memory.js";
import { generateRandomKey } from "../../src/core/random.js";
import { SentinelFindingStore } from "../../src/sentinel/sentinel-finding-store.js";
import {
  AnomalyDetector,
  AnomalyPipelineDispatcher,
  ANOMALY_SENTINEL_ID_PREFIX,
  type AnomalyClassifier,
  type AnomalyFinding,
  type FeatureVector,
} from "../../src/anomaly-detection/anomaly-pipeline.js";
import {
  buildRootCauseHints,
  enrichDetailsWithRootCauseHints,
  ROOT_CAUSE_HINTS_DETAILS_KEY,
  ROOT_CAUSE_HINT_MAX_CLASS_HINTS,
  ROOT_CAUSE_HINT_MAX_HINTS,
  ROOT_CAUSE_HINT_NAME_MAX_LENGTH,
  ROOT_CAUSE_HINT_Z_THRESHOLD,
  type RootCauseHint,
} from "../../src/anomaly-detection/root-cause-hints.js";
import { PER_AGENT_ACTIVITY_DETECTOR_ID } from "../../src/anomaly-detection/detectors/per-agent-activity-detector.js";
import { CROSS_AGENT_TIMING_DETECTOR_ID } from "../../src/anomaly-detection/detectors/cross-agent-timing-detector.js";
import { TOOL_CALL_SEQUENCE_DETECTOR_ID } from "../../src/anomaly-detection/detectors/tool-call-sequence-detector.js";
import { AUDIT_EVENT_CLASS_DISTRIBUTION_DETECTOR_ID } from "../../src/anomaly-detection/detectors/audit-event-class-distribution-detector.js";
import { CREDENTIAL_USE_SEQUENCE_DETECTOR_ID } from "../../src/anomaly-detection/detectors/credential-use-sequence-detector.js";
import { CROSS_AGENT_DISTRIBUTION_DETECTOR_ID } from "../../src/anomaly-detection/detectors/cross-agent-distribution-detector.js";
import { TIME_OF_DAY_ACTIVITY_DETECTOR_ID } from "../../src/anomaly-detection/detectors/time-of-day-activity-detector.js";

const FORTRESS_A = "fortress_a";
const IDENTITY = "identity_test";

/** Build a FeatureContribution-shaped entry. */
function contribution(
  featureName: string,
  zScore: number,
  observed = 10,
  baselineMean = 2,
  baselineStddev = 1,
): Record<string, unknown> {
  return {
    feature_name: featureName,
    observed,
    baseline_mean: baselineMean,
    baseline_stddev: baselineStddev,
    z_score: zScore,
  };
}

/** Build finding details with the standard attribution shape. */
function detailsFor(
  detectorId: string,
  contributions: Record<string, unknown>[],
  extra?: Record<string, unknown>,
): Record<string, unknown> {
  return {
    detector_id: detectorId,
    classifier_id: "rolling-baseline",
    anomaly_score: 4,
    window_label: "24h_rolling",
    feature_contributions: contributions,
    explanation: [],
    ...extra,
  };
}

function hintFor(
  hints: RootCauseHint[],
  featureName: string,
): RootCauseHint | undefined {
  return hints.find((h) => h.feature_names.includes(featureName));
}

describe("WP-V1.3-2 Chi-8 per-detector hint mapping", () => {
  it("per-agent-activity: every emitted feature name has detector-specific text", () => {
    const features = [
      "tool_call_count",
      "egress_call_count",
      "credential_use_count",
      "audit_event_count",
      "recent_receipt_count",
    ];
    const hints = buildRootCauseHints(
      detailsFor(
        PER_AGENT_ACTIVITY_DETECTOR_ID,
        features.map((f) => contribution(f, 4)),
      ),
    );
    expect(hints.length).toBe(features.length);
    for (const feature of features) {
      const hint = hintFor(hints, feature);
      expect(hint).toBeDefined();
      expect(hint?.source).toBe("detector");
      expect(hint?.direction).toBe("above_baseline");
      expect(hint?.likely_cause).toContain("Likely cause");
    }
  });

  it("per-agent-activity: credential_use_count spike names credential harvesting", () => {
    const hints = buildRootCauseHints(
      detailsFor(PER_AGENT_ACTIVITY_DETECTOR_ID, [
        contribution("credential_use_count", 5),
      ]),
    );
    expect(hints[0]?.likely_cause).toContain("credential harvesting");
  });

  it("cross-agent-timing: co_fire_rate_24h spike names lockstep coordination", () => {
    const hints = buildRootCauseHints(
      detailsFor(CROSS_AGENT_TIMING_DETECTOR_ID, [
        contribution("co_fire_rate_24h", 6),
        contribution("correlation_strength", 3),
        contribution("inter_event_time_p50_ms", -2),
        contribution("inter_event_time_p99_ms", 1.5),
      ]),
    );
    expect(hints.length).toBe(4);
    expect(hintFor(hints, "co_fire_rate_24h")?.likely_cause).toContain(
      "lockstep",
    );
    expect(hintFor(hints, "co_fire_rate_24h")?.likely_cause).toContain(
      "60 seconds",
    );
    expect(
      hintFor(hints, "inter_event_time_p50_ms")?.direction,
    ).toBe("below_baseline");
    for (const hint of hints) expect(hint.source).toBe("detector");
  });

  it("tool-call-sequence: repeat_pattern_score spike names the exfiltration-shaped loop", () => {
    const hints = buildRootCauseHints(
      detailsFor(TOOL_CALL_SEQUENCE_DETECTOR_ID, [
        contribution("repeat_pattern_score", 7),
        contribution("ngram_3_histogram_entropy", -3),
        contribution("distinct_tools_used", 2),
        contribution("max_sequence_length", 2.5),
      ]),
    );
    expect(hints.length).toBe(4);
    expect(hintFor(hints, "repeat_pattern_score")?.likely_cause).toContain(
      "exfiltration",
    );
    const entropy = hintFor(hints, "ngram_3_histogram_entropy");
    expect(entropy?.direction).toBe("below_baseline");
    expect(entropy?.likely_cause).toContain("repeating pattern");
    for (const hint of hints) expect(hint.source).toBe("detector");
  });

  it("credential-use-sequence: distinct_credentials_used spike names the enumeration shape", () => {
    const hints = buildRootCauseHints(
      detailsFor(CREDENTIAL_USE_SEQUENCE_DETECTOR_ID, [
        contribution("distinct_credentials_used", 8),
        contribution("burst_max_5min", 6),
        contribution("credential_event_count", 4),
        contribution("repeat_pair_score", 2),
      ]),
    );
    expect(hints.length).toBe(4);
    expect(
      hintFor(hints, "distinct_credentials_used")?.likely_cause,
    ).toContain("credential-enumeration");
    expect(hintFor(hints, "burst_max_5min")?.likely_cause).toContain(
      "burst",
    );
    for (const hint of hints) expect(hint.source).toBe("detector");
  });

  it("cross-agent-distribution: peer_z:* and peer_count map to cohort-divergence text", () => {
    const hints = buildRootCauseHints(
      detailsFor(CROSS_AGENT_DISTRIBUTION_DETECTOR_ID, [
        contribution("peer_z:credential_use_count", 5),
        contribution("peer_z:tool_call_count", -3),
        contribution("peer_count", -2),
      ]),
    );
    expect(hints.length).toBe(3);
    const hot = hintFor(hints, "peer_z:credential_use_count");
    expect(hot?.source).toBe("detector");
    expect(hot?.likely_cause).toContain("peer cohort");
    expect(hot?.likely_cause).toContain("credential_use_count");
    expect(hot?.likely_cause).toContain("hotter");
    const quiet = hintFor(hints, "peer_z:tool_call_count");
    expect(quiet?.direction).toBe("below_baseline");
    expect(quiet?.likely_cause).toContain("quieter");
    expect(hintFor(hints, "peer_count")?.likely_cause).toContain("cohort");
  });

  it("time-of-day-activity: night-band spike reads as off-hours activity", () => {
    const hints = buildRootCauseHints(
      detailsFor(TIME_OF_DAY_ACTIVITY_DETECTOR_ID, [
        contribution("band_proportion:night", 6),
        contribution("band_count:night", 5),
        contribution("band_proportion:morning", -2),
        contribution("active_band_count", 1.5),
      ]),
    );
    expect(hints.length).toBe(4);
    const night = hintFor(hints, "band_proportion:night");
    expect(night?.source).toBe("detector");
    expect(night?.likely_cause).toContain("off-hours");
    expect(night?.likely_cause).toContain("00:00-06:00 UTC");
    const morning = hintFor(hints, "band_proportion:morning");
    expect(morning?.direction).toBe("below_baseline");
    expect(morning?.likely_cause).toContain("morning band");
    expect(hintFor(hints, "active_band_count")?.source).toBe("detector");
  });

  it("audit-event-class-distribution: total_events and class_count:* have detector text", () => {
    const hints = buildRootCauseHints(
      detailsFor(AUDIT_EVENT_CLASS_DISTRIBUTION_DETECTOR_ID, [
        contribution("total_events", 3),
        contribution("class_count:proxy_call:fetch", 2),
      ]),
    );
    expect(hints.length).toBe(2);
    expect(hintFor(hints, "total_events")?.source).toBe("detector");
    const classHint = hintFor(hints, "class_count:proxy_call:fetch");
    expect(classHint?.source).toBe("detector");
    expect(classHint?.likely_cause).toContain("proxy_call:fetch");
  });
});

describe("WP-V1.3-2 Chi-8 per_class_drift hints", () => {
  function classDrift(
    className: string,
    baselineProportion: number,
    currentProportion: number,
    direction: "up" | "down" | "flat",
  ): Record<string, unknown> {
    return {
      class_name: className,
      baseline_proportion: baselineProportion,
      current_proportion: currentProportion,
      absolute_delta: currentProportion - baselineProportion,
      relative_delta: null,
      direction,
      psi_contribution: 0.1,
    };
  }

  it("maps up/down drift to directioned class hints with null z_score", () => {
    const hints = buildRootCauseHints(
      detailsFor(AUDIT_EVENT_CLASS_DISTRIBUTION_DETECTOR_ID, [], {
        per_class_drift: [
          classDrift("broker_secret_read", 0.1, 0.6, "up"),
          classDrift("state_read", 0.5, 0.2, "down"),
        ],
      }),
    );
    expect(hints.length).toBe(2);
    const up = hintFor(hints, "class_proportion:broker_secret_read");
    expect(up?.direction).toBe("above_baseline");
    expect(up?.z_score).toBeNull();
    expect(up?.source).toBe("detector");
    expect(up?.likely_cause).toContain("broker_secret_read");
    expect(up?.likely_cause).toContain("0.1");
    expect(up?.likely_cause).toContain("0.6");
    const down = hintFor(hints, "class_proportion:state_read");
    expect(down?.direction).toBe("below_baseline");
  });

  it("skips flat entries and caps class hints at the top entries by |delta|", () => {
    const drift = [
      classDrift("op_flat", 0.2, 0.2, "flat"),
      classDrift("op_a", 0.1, 0.5, "up"),
      classDrift("op_b", 0.4, 0.1, "down"),
      classDrift("op_c", 0.3, 0.1, "down"),
      classDrift("op_d", 0.2, 0.3, "up"),
    ];
    const hints = buildRootCauseHints(
      detailsFor(AUDIT_EVENT_CLASS_DISTRIBUTION_DETECTOR_ID, [], {
        per_class_drift: drift,
      }),
    );
    expect(hints.length).toBe(ROOT_CAUSE_HINT_MAX_CLASS_HINTS);
    const named = hints.map((h) => h.feature_names[0]);
    expect(named).toEqual([
      "class_proportion:op_a",
      "class_proportion:op_b",
      "class_proportion:op_c",
    ]);
    expect(named).not.toContain("class_proportion:op_flat");
  });

  it("deduplicates the mirrored class_proportion contributions when per_class_drift is present", () => {
    const hints = buildRootCauseHints(
      detailsFor(
        AUDIT_EVENT_CLASS_DISTRIBUTION_DETECTOR_ID,
        [contribution("class_proportion:broker_secret_read", 9)],
        {
          per_class_drift: [
            classDrift("broker_secret_read", 0.1, 0.6, "up"),
          ],
        },
      ),
    );
    const matching = hints.filter((h) =>
      h.feature_names.includes("class_proportion:broker_secret_read"),
    );
    expect(matching.length).toBe(1);
    expect(matching[0]?.z_score).toBeNull();
  });
});

describe("WP-V1.3-2 Chi-8 direction thresholds, ordering, and determinism", () => {
  it("contributions below the 1-sigma threshold earn no hint", () => {
    const hints = buildRootCauseHints(
      detailsFor(PER_AGENT_ACTIVITY_DETECTOR_ID, [
        contribution("tool_call_count", 0.99),
        contribution("egress_call_count", -0.5),
        contribution("credential_use_count", 0),
      ]),
    );
    expect(hints).toEqual([]);
  });

  it("z exactly at the threshold earns a hint; sign picks the direction", () => {
    expect(ROOT_CAUSE_HINT_Z_THRESHOLD).toBe(1);
    const hints = buildRootCauseHints(
      detailsFor(PER_AGENT_ACTIVITY_DETECTOR_ID, [
        contribution("tool_call_count", 1),
        contribution("egress_call_count", -1),
      ]),
    );
    expect(hints.length).toBe(2);
    expect(hintFor(hints, "tool_call_count")?.direction).toBe(
      "above_baseline",
    );
    expect(hintFor(hints, "egress_call_count")?.direction).toBe(
      "below_baseline",
    );
  });

  it("hints sort by |z| descending then feature name, and cap at the max", () => {
    const details = detailsFor(PER_AGENT_ACTIVITY_DETECTOR_ID, [
      contribution("feature_b", 2),
      contribution("feature_a", 2),
      contribution("tool_call_count", 9),
      contribution("egress_call_count", -6),
      contribution("credential_use_count", 4),
      contribution("audit_event_count", 3),
      contribution("recent_receipt_count", 2.5),
    ]);
    const hints = buildRootCauseHints(details);
    expect(hints.length).toBe(ROOT_CAUSE_HINT_MAX_HINTS);
    expect(hints.map((h) => h.feature_names[0])).toEqual([
      "tool_call_count",
      "egress_call_count",
      "credential_use_count",
      "audit_event_count",
      "recent_receipt_count",
    ]);
    // Tie-break check: equal |z| orders by feature name.
    const tied = buildRootCauseHints(
      detailsFor(PER_AGENT_ACTIVITY_DETECTOR_ID, [
        contribution("feature_b", 2),
        contribution("feature_a", 2),
      ]),
    );
    expect(tied.map((h) => h.feature_names[0])).toEqual([
      "feature_a",
      "feature_b",
    ]);
  });

  it("identical input produces identical output (deterministic, no clock)", () => {
    const details = detailsFor(TIME_OF_DAY_ACTIVITY_DETECTOR_ID, [
      contribution("band_count:night", 5),
      contribution("band_proportion:evening", -1.2),
    ]);
    const first = buildRootCauseHints(details);
    const second = buildRootCauseHints(details);
    expect(second).toEqual(first);
  });
});

describe("WP-V1.3-2 Chi-8 fallback and degradation", () => {
  it("unknown detector id degrades to generic stat-only hints", () => {
    const hints = buildRootCauseHints(
      detailsFor("future-detector", [
        contribution("mystery_feature", 4, 42, 7),
      ]),
    );
    expect(hints.length).toBe(1);
    expect(hints[0]?.source).toBe("generic");
    expect(hints[0]?.direction).toBe("above_baseline");
    expect(hints[0]?.likely_cause).toContain("mystery_feature");
    expect(hints[0]?.likely_cause).toContain("42");
    expect(hints[0]?.likely_cause).toContain("7");
    expect(hints[0]?.likely_cause).toContain("4 sigma");
  });

  it("known detector with an unknown feature degrades to a generic hint", () => {
    const hints = buildRootCauseHints(
      detailsFor(PER_AGENT_ACTIVITY_DETECTOR_ID, [
        contribution("tool_call_count", 5),
        contribution("brand_new_feature", 3),
      ]),
    );
    expect(hintFor(hints, "tool_call_count")?.source).toBe("detector");
    const unknown = hintFor(hints, "brand_new_feature");
    expect(unknown?.source).toBe("generic");
    expect(unknown?.likely_cause).toContain(
      "No detector-specific interpretation",
    );
  });

  it("empty contributions produce an empty hint array", () => {
    expect(
      buildRootCauseHints(detailsFor(PER_AGENT_ACTIVITY_DETECTOR_ID, [])),
    ).toEqual([]);
  });

  it("missing detector_id and missing contributions degrade to empty, never throw", () => {
    expect(buildRootCauseHints({})).toEqual([]);
    expect(buildRootCauseHints({ detector_id: 42 })).toEqual([]);
    expect(
      buildRootCauseHints({ feature_contributions: "not-an-array" }),
    ).toEqual([]);
    expect(
      buildRootCauseHints({ per_class_drift: { not: "an array" } }),
    ).toEqual([]);
  });

  it("malformed contribution entries are skipped without aborting valid ones", () => {
    const hints = buildRootCauseHints(
      detailsFor(PER_AGENT_ACTIVITY_DETECTOR_ID, [
        "garbage" as unknown as Record<string, unknown>,
        { feature_name: "", z_score: 9, observed: 1, baseline_mean: 1 },
        { feature_name: "no_z", observed: 1, baseline_mean: 1 },
        {
          feature_name: "nan_z",
          observed: 1,
          baseline_mean: 1,
          z_score: Number.NaN,
        },
        {
          feature_name: "inf_observed",
          observed: Number.POSITIVE_INFINITY,
          baseline_mean: 1,
          z_score: 5,
        },
        contribution("tool_call_count", 4),
      ]),
    );
    expect(hints.length).toBe(1);
    expect(hints[0]?.feature_names).toEqual(["tool_call_count"]);
  });
});

describe("WP-V1.3-2 Chi-8 fail-closed enrichment wrapper", () => {
  it("a hint builder forced to throw degrades to an empty hints array", () => {
    const details = detailsFor(PER_AGENT_ACTIVITY_DETECTOR_ID, [
      contribution("tool_call_count", 4),
    ]);
    const enriched = enrichDetailsWithRootCauseHints(details, () => {
      throw new Error("hint table exploded");
    });
    expect(enriched[ROOT_CAUSE_HINTS_DETAILS_KEY]).toEqual([]);
    // The rest of the details survive untouched.
    expect(enriched["detector_id"]).toBe(PER_AGENT_ACTIVITY_DETECTOR_ID);
    expect(enriched["anomaly_score"]).toBe(4);
  });

  it("hostile details (throwing getter) degrade to the original details unchanged", () => {
    const hostile: Record<string, unknown> = { detector_id: "stub" };
    Object.defineProperty(hostile, "feature_contributions", {
      enumerable: true,
      get() {
        throw new Error("hostile getter");
      },
    });
    const enriched = enrichDetailsWithRootCauseHints(hostile);
    expect(enriched).toBe(hostile);
  });

  it("does not mutate the input details object", () => {
    const details = detailsFor(PER_AGENT_ACTIVITY_DETECTOR_ID, [
      contribution("tool_call_count", 4),
    ]);
    const enriched = enrichDetailsWithRootCauseHints(details);
    expect(enriched).not.toBe(details);
    expect(ROOT_CAUSE_HINTS_DETAILS_KEY in details).toBe(false);
    expect(
      (enriched[ROOT_CAUSE_HINTS_DETAILS_KEY] as RootCauseHint[]).length,
    ).toBe(1);
  });
});

class StubDetector extends AnomalyDetector {
  readonly detectorId: string;
  readonly description = "Chi-8 test fixture detector.";
  classifier: AnomalyClassifier;
  next: AnomalyFinding[] = [];

  constructor(id = "stub") {
    super();
    this.detectorId = id;
    this.classifier = new StubClassifier();
  }

  override async featureExtract(): Promise<FeatureVector[]> {
    return [];
  }

  override async evaluate(): Promise<AnomalyFinding[]> {
    return this.next;
  }
}

class StubClassifier implements AnomalyClassifier {
  readonly classifierId = "stub-classifier" as const;
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
    return {
      trained_at: new Date().toISOString(),
      sample_count: 0,
      agent_count: 0,
    };
  }
}

function makeRig(): {
  findingStore: SentinelFindingStore;
  auditLog: AuditLog;
  dispatcher: AnomalyPipelineDispatcher;
} {
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
  return { findingStore, auditLog, dispatcher };
}

function stubFinding(details: Record<string, unknown>): AnomalyFinding {
  return {
    finding_id: "",
    sentinel_id: `${ANOMALY_SENTINEL_ID_PREFIX}stub`,
    severity: "warn",
    summary: "synthetic anomaly",
    details,
    observed_at: "2026-06-12T12:00:00.000Z",
    agent_id: "agent-a",
    evidence_audit_ids: [],
    fortress_id: "",
  };
}

describe("WP-V1.3-2 Chi-8 dispatcher integration", () => {
  it("routed findings carry root_cause_hints in the store, return value, and listener emit", async () => {
    const rig = makeRig();
    const stub = new StubDetector(CREDENTIAL_USE_SEQUENCE_DETECTOR_ID);
    await rig.dispatcher.registerDetector(stub);
    stub.next = [
      stubFinding(
        detailsFor(CREDENTIAL_USE_SEQUENCE_DETECTOR_ID, [
          contribution("distinct_credentials_used", 8),
        ]),
      ),
    ];
    const emitted: AnomalyFinding[] = [];
    rig.dispatcher.onEvent((event) => {
      if (event.type === "finding") emitted.push(event.finding);
    });
    const findings = await rig.dispatcher.tick();
    expect(findings.length).toBe(1);
    const returnedHints = findings[0]?.details[
      ROOT_CAUSE_HINTS_DETAILS_KEY
    ] as RootCauseHint[];
    expect(returnedHints.length).toBe(1);
    expect(returnedHints[0]?.likely_cause).toContain(
      "credential-enumeration",
    );
    const stored = await rig.findingStore.listFindings();
    expect(stored.length).toBe(1);
    const storedHints = stored[0]?.details[
      ROOT_CAUSE_HINTS_DETAILS_KEY
    ] as RootCauseHint[];
    expect(storedHints).toEqual(returnedHints);
    expect(emitted.length).toBe(1);
    expect(
      emitted[0]?.details[ROOT_CAUSE_HINTS_DETAILS_KEY],
    ).toEqual(returnedHints);
  });

  it("a finding whose details defeat hint generation still persists (fail-closed)", async () => {
    const rig = makeRig();
    const stub = new StubDetector();
    await rig.dispatcher.registerDetector(stub);
    // Non-enumerable throwing getter: invisible to spread and JSON
    // serialization (so the pre-existing persistence path is
    // unaffected) but hit by the hint builder's direct property
    // access, forcing the degradation path inside the enrichment
    // wrapper.
    const hostile: Record<string, unknown> = {
      detector_id: "stub",
      anomaly_score: 4,
    };
    Object.defineProperty(hostile, "feature_contributions", {
      enumerable: false,
      get() {
        throw new Error("hostile getter");
      },
    });
    stub.next = [stubFinding(hostile)];
    const findings = await rig.dispatcher.tick();
    expect(findings.length).toBe(1);
    expect(findings[0]?.details[ROOT_CAUSE_HINTS_DETAILS_KEY]).toEqual([]);
    const stored = await rig.findingStore.listFindings();
    expect(stored.length).toBe(1);
    expect(stored[0]?.severity).toBe("warn");
  });

  it("findings without attribution still route, with empty hints attached", async () => {
    const rig = makeRig();
    const stub = new StubDetector();
    await rig.dispatcher.registerDetector(stub);
    stub.next = [stubFinding({ detector_id: "stub", anomaly_score: 4 })];
    const findings = await rig.dispatcher.tick();
    expect(findings.length).toBe(1);
    expect(findings[0]?.details[ROOT_CAUSE_HINTS_DETAILS_KEY]).toEqual([]);
  });
});

describe("WP-V1.3-2 Chi-8 no-leakage invariant", () => {
  it("hints never copy raw audit payload values from finding details", () => {
    const secret = "hunter2-raw-secret-value";
    const details = detailsFor(
      CREDENTIAL_USE_SEQUENCE_DETECTOR_ID,
      [
        contribution("distinct_credentials_used", 8),
        contribution("unknown_feature", 3),
      ],
      {
        observed_features: {
          distinct_credentials_used: 12,
        },
        raw_payload: secret,
        secret_token: secret,
      },
    );
    const hints = buildRootCauseHints(details);
    expect(hints.length).toBe(2);
    const serialized = JSON.stringify(hints);
    expect(serialized).not.toContain(secret);
    expect(serialized).not.toContain("raw_payload");
    expect(serialized).not.toContain("secret_token");
  });

  it("hint objects expose only the allowed fields", () => {
    const hints = buildRootCauseHints(
      detailsFor(TIME_OF_DAY_ACTIVITY_DETECTOR_ID, [
        contribution("band_count:night", 5),
      ]),
    );
    expect(hints.length).toBe(1);
    expect(Object.keys(hints[0]!).sort()).toEqual([
      "direction",
      "feature_names",
      "likely_cause",
      "source",
      "z_score",
    ]);
  });

  it("generic hints carry only numeric stats and the feature name", () => {
    const hints = buildRootCauseHints(
      detailsFor("unknown-detector", [
        contribution("some_feature", 2.5, 99, 11),
      ]),
    );
    expect(hints.length).toBe(1);
    // The text references only the feature name and the contribution
    // stats; nothing else from the details object appears.
    expect(hints[0]?.likely_cause).toContain("some_feature");
    expect(hints[0]?.likely_cause).not.toContain("rolling-baseline");
    expect(hints[0]?.likely_cause).not.toContain("24h_rolling");
  });
});

describe("WP-V1.3-2 Chi-8 data-dependent name sanitization", () => {
  it("hostile feature names cannot inject control characters into hint text", () => {
    // Audit operation names can be composed from runtime strings
    // (e.g. tool names), so a feature suffix may carry hostile text.
    const hostile = "peer_z:evil\u001b[31m\nFAKE ALERT: disarm the wall";
    const hints = buildRootCauseHints(
      detailsFor(CROSS_AGENT_DISTRIBUTION_DETECTOR_ID, [
        contribution(hostile, 4),
      ]),
    );
    expect(hints.length).toBe(1);
    const serialized = JSON.stringify(hints);
    expect(serialized).not.toContain("\u001b");
    expect(hints[0]?.likely_cause).not.toContain("\n");
    expect(hints[0]?.feature_names[0]).not.toContain("\n");
    // The safe-charset replacement keeps the structural prefix so the
    // operator can still identify the feature namespace.
    expect(hints[0]?.feature_names[0]?.startsWith("peer_z:evil_")).toBe(true);
  });

  it("hostile class names in per_class_drift are sanitized in text and feature_names", () => {
    const hostileClass = "state read; rm -rf /\u001b[2J";
    const hints = buildRootCauseHints(
      detailsFor(AUDIT_EVENT_CLASS_DISTRIBUTION_DETECTOR_ID, [], {
        per_class_drift: [
          {
            class_name: hostileClass,
            baseline_proportion: 0.1,
            current_proportion: 0.6,
            absolute_delta: 0.5,
            direction: "up",
          },
        ],
      }),
    );
    expect(hints.length).toBe(1);
    const serialized = JSON.stringify(hints);
    expect(serialized).not.toContain("");
    expect(serialized).not.toContain("\u001b");
    expect(serialized).not.toContain(" rm -rf /");
    expect(hints[0]?.feature_names[0]?.startsWith("class_proportion:")).toBe(
      true,
    );
  });

  it("overlong names are capped with a truncation marker", () => {
    const overlong = `band_count:${"x".repeat(400)}`;
    const hints = buildRootCauseHints(
      detailsFor(TIME_OF_DAY_ACTIVITY_DETECTOR_ID, [
        contribution(overlong, 3),
      ]),
    );
    expect(hints.length).toBe(1);
    const name = hints[0]?.feature_names[0];
    expect(name?.length).toBe(ROOT_CAUSE_HINT_NAME_MAX_LENGTH + 3);
    expect(name?.endsWith("...")).toBe(true);
  });

  it("legitimate feature keys and dotted operation class names pass through unchanged", () => {
    const hints = buildRootCauseHints(
      detailsFor(AUDIT_EVENT_CLASS_DISTRIBUTION_DETECTOR_ID, [], {
        per_class_drift: [
          {
            class_name: "state.read",
            baseline_proportion: 0.2,
            current_proportion: 0.5,
            absolute_delta: 0.3,
            direction: "up",
          },
        ],
      }),
    );
    expect(hints.length).toBe(1);
    expect(hints[0]?.feature_names[0]).toBe("class_proportion:state.read");
    expect(hints[0]?.likely_cause).toContain("state.read");
    // And a prefixed detector feature still resolves its specific text.
    const bandHints = buildRootCauseHints(
      detailsFor(TIME_OF_DAY_ACTIVITY_DETECTOR_ID, [
        contribution("band_proportion:night", 4),
      ]),
    );
    expect(bandHints[0]?.feature_names[0]).toBe("band_proportion:night");
    expect(bandHints[0]?.source).toBe("detector");
  });
});
