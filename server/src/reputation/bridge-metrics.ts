/**
 * Concordia-bridge reputation metric validation.
 *
 * Invariant #8: Concordia attestations may include behavioral signals only,
 * never raw deal-term fields.
 */

import type { ConcordiaOutcome } from "../bridge/types.js";

export const CONCORDIA_BRIDGE_REPUTATION_CONTEXT = "concordia-bridge" as const;

export const BRIDGE_METRIC_POLICY =
  "concordia-bridge-behavioral-v1" as const;

export const BRIDGE_POLICY_METRIC_ALLOWLIST = [
  "negotiation_round_bucket",
  "declared_offers_made_bucket",
  "declared_concession_bucket",
  "declared_reasoning_provided",
  "declared_response_time_bucket",
] as const;

export type BridgePolicyMetricName =
  typeof BRIDGE_POLICY_METRIC_ALLOWLIST[number];

export type BridgePolicyMetrics =
  Partial<Record<BridgePolicyMetricName, number>> & {
    negotiation_round_bucket: number;
  };

export const BRIDGE_ATTESTATION_BEHAVIORAL_METRIC_ALLOWLIST = [
  "declared_offers_made",
  "declared_concession",
  "declared_reasoning_provided",
  "declared_response_time_ms",
] as const;

export type BridgeAttestationBehavioralMetric =
  typeof BRIDGE_ATTESTATION_BEHAVIORAL_METRIC_ALLOWLIST[number];

export const LEGACY_BRIDGE_ATTESTATION_BEHAVIORAL_METRIC_ALLOWLIST = [
  "rounds",
  "negotiation_rounds",
  "response_time_ms",
  "concession_magnitude",
  "offers_made",
  "reasoning_provided",
] as const;

const BRIDGE_POLICY_METRICS = new Set<string>(
  BRIDGE_POLICY_METRIC_ALLOWLIST
);

const LEGACY_BRIDGE_ATTESTATION_BEHAVIORAL_METRICS = new Set<string>(
  LEGACY_BRIDGE_ATTESTATION_BEHAVIORAL_METRIC_ALLOWLIST
);

const COUNT_LIKE_BRIDGE_METRICS = new Set<string>([
  "rounds",
  "negotiation_rounds",
  "offers_made",
]);

const BRIDGE_DECLARED_METRIC_INPUTS = new Set<string>(
  BRIDGE_ATTESTATION_BEHAVIORAL_METRIC_ALLOWLIST
);

const LEGACY_PRECISE_BRIDGE_METRIC_NAMES = new Set<string>([
  "rounds",
  "negotiation_rounds",
  "offers_made",
  "concession_magnitude",
  "response_time_ms",
  "terms_complexity",
]);

const RAW_TERM_LIKE_BRIDGE_METRIC_KEYS = new Set<string>([
  "amount",
  "price",
  "quantity",
  "term",
  "terms",
  "total",
  "unit_price",
]);

const ROUND_COUNT_MIN = 1;
const ROUND_COUNT_MAX = 64;
const RESPONSE_TIME_MAX_MS = 3_600_000;

function metricKeyList(keys: string[]): string {
  return keys.sort().join(", ");
}

export class BridgeAttestationMetricValidationError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "BridgeAttestationMetricValidationError";
  }
}

export function isConcordiaBridgeReputationContext(
  context: string
): context is typeof CONCORDIA_BRIDGE_REPUTATION_CONTEXT {
  return context === CONCORDIA_BRIDGE_REPUTATION_CONTEXT;
}

export function isBridgePolicyMetricName(
  metric: string
): metric is BridgePolicyMetricName {
  return BRIDGE_POLICY_METRICS.has(metric);
}

function reject(error: string): { ok: false; error: string } {
  return { ok: false, error };
}

function validateFiniteNumber(
  value: unknown,
  key: string
): { ok: true; value: number } | { ok: false; error: string } {
  if (typeof value !== "number" || !Number.isFinite(value)) {
    return reject(
      "Bridge attestation metrics rejected: metric values must be finite numbers; " +
        `offending metric key(s): ${key}.`
    );
  }
  if (Object.is(value, -0)) {
    return reject(
      "Bridge attestation metrics rejected: negative zero is not a valid " +
        `metric value; offending metric key(s): ${key}.`
    );
  }
  if (Number.isInteger(value) && !Number.isSafeInteger(value)) {
    return reject(
      "Bridge attestation metrics rejected: integer metric values must be " +
        `safe integers; offending metric key(s): ${key}.`
    );
  }
  return { ok: true, value };
}

function validateIntegerInRange(
  value: unknown,
  key: string,
  min: number,
  max: number
): { ok: true; value: number } | { ok: false; error: string } {
  const numeric = validateFiniteNumber(value, key);
  if (!numeric.ok) return numeric;
  if (
    !Number.isInteger(numeric.value) ||
    numeric.value < min ||
    numeric.value > max
  ) {
    return reject(
      "Bridge attestation metrics rejected: " +
        `${key} must be an integer from ${min} to ${max}; ` +
        `offending metric key(s): ${key}.`
    );
  }
  return numeric;
}

export function bridgeCountBucket(value: number): number {
  if (value === 1) return 0;
  if (value <= 3) return 1;
  if (value <= 7) return 2;
  if (value <= 15) return 3;
  if (value <= 31) return 4;
  return 5;
}

function responseTimeBucket(ms: number): number {
  if (ms <= 1_000) return 0;
  if (ms <= 5_000) return 1;
  if (ms <= 30_000) return 2;
  if (ms <= 120_000) return 3;
  if (ms <= 600_000) return 4;
  return 5;
}

function validateMetricObject(value: unknown):
  | { ok: true; input: Record<string, unknown>; keys: string[] }
  | { ok: false; error: string } {
  if (value === undefined || value === null) {
    return { ok: true, input: {}, keys: [] };
  }
  if (typeof value !== "object" || Array.isArray(value)) {
    return reject(
      "Bridge attestation metrics rejected: metrics must be an object; " +
        "arrays, strings, and nested scalar payloads are not accepted."
    );
  }

  const input = value as Record<string, unknown>;
  return { ok: true, input, keys: Object.keys(input) };
}

export function buildBridgeAttestationMetrics(
  outcome: ConcordiaOutcome,
  supplied: unknown
): {
  metrics: BridgePolicyMetrics;
  policy: typeof BRIDGE_METRIC_POLICY;
} {
  const rounds = validateIntegerInRange(
    outcome.rounds,
    "outcome.rounds",
    ROUND_COUNT_MIN,
    ROUND_COUNT_MAX
  );
  if (!rounds.ok) {
    throw new BridgeAttestationMetricValidationError(rounds.error);
  }

  const parsed = validateMetricObject(supplied);
  if (!parsed.ok) {
    throw new BridgeAttestationMetricValidationError(parsed.error);
  }
  const { input, keys } = parsed;

  const legacyKeys = keys.filter((key) =>
    LEGACY_PRECISE_BRIDGE_METRIC_NAMES.has(key)
  );
  if (legacyKeys.length > 0) {
    throw new BridgeAttestationMetricValidationError(
      "Bridge attestation metrics rejected: legacy exact metric names are " +
        "not accepted on bridge_attest; use declared_* inputs that are " +
        "bucketed before storage; " +
        `offending metric key(s): ${metricKeyList(legacyKeys)}.`
    );
  }

  const rawTermKeys = keys.filter((key) =>
    RAW_TERM_LIKE_BRIDGE_METRIC_KEYS.has(key)
  );
  if (rawTermKeys.length > 0) {
    throw new BridgeAttestationMetricValidationError(
      "Bridge attestation metrics rejected: raw deal-term-like metric keys " +
        "are not accepted; " +
        `offending metric key(s): ${metricKeyList(rawTermKeys)}.`
    );
  }

  const disallowed = keys.filter(
    (key) => !BRIDGE_DECLARED_METRIC_INPUTS.has(key)
  );
  if (disallowed.length > 0) {
    throw new BridgeAttestationMetricValidationError(
      "Bridge attestation metrics rejected: only declared bridge metric " +
        "inputs are accepted; allowed inputs are declared_offers_made, " +
        "declared_concession, declared_reasoning_provided, and " +
        "declared_response_time_ms; " +
        `offending metric key(s): ${metricKeyList(disallowed)}.`
    );
  }

  const metrics: BridgePolicyMetrics = {
    negotiation_round_bucket: bridgeCountBucket(rounds.value),
  };

  if (Object.hasOwn(input, "declared_offers_made")) {
    const declaredOffers = validateIntegerInRange(
      input.declared_offers_made,
      "declared_offers_made",
      ROUND_COUNT_MIN,
      ROUND_COUNT_MAX
    );
    if (!declaredOffers.ok) {
      throw new BridgeAttestationMetricValidationError(declaredOffers.error);
    }
    metrics.declared_offers_made_bucket = bridgeCountBucket(declaredOffers.value);
  }

  if (Object.hasOwn(input, "declared_concession")) {
    const concession = validateFiniteNumber(
      input.declared_concession,
      "declared_concession"
    );
    if (!concession.ok) {
      throw new BridgeAttestationMetricValidationError(concession.error);
    }
    if (concession.value < 0 || concession.value > 1) {
      throw new BridgeAttestationMetricValidationError(
        "Bridge attestation metrics rejected: declared_concession must be " +
          "a ratio from 0 to 1; offending metric key(s): declared_concession."
      );
    }
    metrics.declared_concession_bucket = Math.round(concession.value * 10);
  }

  if (Object.hasOwn(input, "declared_reasoning_provided")) {
    if (typeof input.declared_reasoning_provided !== "boolean") {
      throw new BridgeAttestationMetricValidationError(
        "Bridge attestation metrics rejected: declared_reasoning_provided " +
          "must be a boolean; offending metric key(s): " +
          "declared_reasoning_provided."
      );
    }
    metrics.declared_reasoning_provided = input.declared_reasoning_provided
      ? 1
      : 0;
  }

  if (Object.hasOwn(input, "declared_response_time_ms")) {
    const responseTime = validateIntegerInRange(
      input.declared_response_time_ms,
      "declared_response_time_ms",
      0,
      RESPONSE_TIME_MAX_MS
    );
    if (!responseTime.ok) {
      throw new BridgeAttestationMetricValidationError(responseTime.error);
    }
    metrics.declared_response_time_bucket = responseTimeBucket(responseTime.value);
  }

  return { metrics, policy: BRIDGE_METRIC_POLICY };
}

export function validateBridgePolicyAttestationMetrics(value: unknown):
  | { ok: true; metrics: BridgePolicyMetrics }
  | { ok: false; error: string } {
  const parsed = validateMetricObject(value);
  if (!parsed.ok) return parsed;

  const { input, keys } = parsed;
  const disallowed = keys.filter((key) => !BRIDGE_POLICY_METRICS.has(key));
  if (disallowed.length > 0) {
    return reject(
      "Bridge attestation metrics rejected: policy-tagged bridge " +
        "attestations may only contain policy bucket metrics; " +
        `offending metric key(s): ${metricKeyList(disallowed)}.`
    );
  }

  if (!Object.hasOwn(input, "negotiation_round_bucket")) {
    return reject(
      "Bridge attestation metrics rejected: policy-tagged bridge " +
        "attestations must include negotiation_round_bucket."
    );
  }

  const numericMetrics: Partial<Record<BridgePolicyMetricName, number>> = {};
  for (const key of keys) {
    const numeric = validateFiniteNumber(input[key], key);
    if (!numeric.ok) return numeric;
    numericMetrics[key as BridgePolicyMetricName] = numeric.value;
  }

  for (const key of [
    "negotiation_round_bucket",
    "declared_offers_made_bucket",
    "declared_response_time_bucket",
  ] satisfies BridgePolicyMetricName[]) {
    if (numericMetrics[key] === undefined) continue;
    if (
      !Number.isInteger(numericMetrics[key]) ||
      numericMetrics[key]! < 0 ||
      numericMetrics[key]! > 5
    ) {
      return reject(
        "Bridge attestation metrics rejected: " +
          `${key} must be an integer bucket from 0 to 5; ` +
          `offending metric key(s): ${key}.`
      );
    }
  }

  if (
    numericMetrics.declared_concession_bucket !== undefined &&
    (!Number.isInteger(numericMetrics.declared_concession_bucket) ||
      numericMetrics.declared_concession_bucket < 0 ||
      numericMetrics.declared_concession_bucket > 10)
  ) {
    return reject(
      "Bridge attestation metrics rejected: declared_concession_bucket must " +
        "be an integer bucket from 0 to 10; offending metric key(s): " +
        "declared_concession_bucket."
    );
  }

  if (
    numericMetrics.declared_reasoning_provided !== undefined &&
    numericMetrics.declared_reasoning_provided !== 0 &&
    numericMetrics.declared_reasoning_provided !== 1
  ) {
    return reject(
      "Bridge attestation metrics rejected: declared_reasoning_provided must " +
        "be 0 or 1; offending metric key(s): declared_reasoning_provided."
    );
  }

  return {
    ok: true,
    metrics: numericMetrics as BridgePolicyMetrics,
  };
}

export function validateBridgeAttestationMetrics(value: unknown):
  | { ok: true; metrics: Record<string, number> }
  | { ok: false; error: string } {
  if (value === undefined || value === null) {
    return { ok: true, metrics: {} };
  }
  if (typeof value !== "object" || Array.isArray(value)) {
    return {
      ok: false,
      error:
        "Bridge attestation metrics rejected: metrics must be an object; " +
        "only behavioral metrics are allowed.",
    };
  }

  const input = value as Record<string, unknown>;
  const keys = Object.keys(input);
  const disallowed = keys.filter(
    (key) => !LEGACY_BRIDGE_ATTESTATION_BEHAVIORAL_METRICS.has(key)
  );
  if (disallowed.length > 0) {
    return {
      ok: false,
      error:
        "Bridge attestation metrics rejected: only behavioral metrics are allowed; " +
        `offending metric key(s): ${metricKeyList(disallowed)}.`,
    };
  }

  const nonFiniteOrNonNumeric = keys.filter((key) => {
    const metric = input[key];
    return typeof metric !== "number" || !Number.isFinite(metric);
  });
  if (nonFiniteOrNonNumeric.length > 0) {
    return {
      ok: false,
      error:
        "Bridge attestation metrics rejected: metric values must be finite numbers; " +
        `offending metric key(s): ${metricKeyList(nonFiniteOrNonNumeric)}. ` +
        "Only behavioral metrics are allowed.",
    };
  }

  const invalidCounts = keys.filter((key) => {
    const metric = input[key] as number;
    return (
      COUNT_LIKE_BRIDGE_METRICS.has(key) &&
      (!Number.isInteger(metric) || metric < 0)
    );
  });
  if (invalidCounts.length > 0) {
    return {
      ok: false,
      error:
        "Bridge attestation metrics rejected: count-like metric values must be " +
        "non-negative integers; " +
        `offending metric key(s): ${metricKeyList(invalidCounts)}.`,
    };
  }

  const invalidRatios = keys.filter((key) => {
    const metric = input[key] as number;
    return key === "concession_magnitude" && (metric < 0 || metric > 1);
  });
  if (invalidRatios.length > 0) {
    return {
      ok: false,
      error:
        "Bridge attestation metrics rejected: concession_magnitude must be " +
        "a ratio from 0 to 1; " +
        `offending metric key(s): ${metricKeyList(invalidRatios)}.`,
    };
  }

  const invalidDurations = keys.filter((key) => {
    const metric = input[key] as number;
    return key === "response_time_ms" && metric < 0;
  });
  if (invalidDurations.length > 0) {
    return {
      ok: false,
      error:
        "Bridge attestation metrics rejected: response_time_ms must be " +
        "a non-negative finite number; " +
        `offending metric key(s): ${metricKeyList(invalidDurations)}.`,
    };
  }

  const invalidBooleanNumbers = keys.filter((key) => {
    const metric = input[key] as number;
    return key === "reasoning_provided" && metric !== 0 && metric !== 1;
  });
  if (invalidBooleanNumbers.length > 0) {
    return {
      ok: false,
      error:
        "Bridge attestation metrics rejected: reasoning_provided must be " +
        "0 or 1; " +
        `offending metric key(s): ${metricKeyList(invalidBooleanNumbers)}.`,
    };
  }

  const metrics: Record<string, number> = {};
  for (const key of keys) {
    metrics[key] = input[key] as number;
  }
  return { ok: true, metrics };
}

export function assertBridgeAttestationMetrics(
  value: unknown
): Record<string, number> {
  const validated = validateBridgeAttestationMetrics(value);
  if (!validated.ok) {
    throw new BridgeAttestationMetricValidationError(validated.error);
  }
  return validated.metrics;
}

export function assertRecordableBridgeAttestationMetrics(
  value: unknown,
  metricPolicy: string | undefined
): BridgePolicyMetrics {
  if (metricPolicy !== BRIDGE_METRIC_POLICY) {
    throw new BridgeAttestationMetricValidationError(
      "Bridge attestation metrics rejected: new concordia-bridge " +
        `attestations must use metric_policy "${BRIDGE_METRIC_POLICY}".`
    );
  }
  const validated = validateBridgePolicyAttestationMetrics(value);
  if (!validated.ok) {
    throw new BridgeAttestationMetricValidationError(validated.error);
  }
  return validated.metrics;
}

export function assertImportableBridgeAttestationMetrics(
  value: unknown,
  metricPolicy: string | undefined
): Record<string, number> {
  if (metricPolicy === undefined) {
    throw new BridgeAttestationMetricValidationError(
      "Bridge attestation metrics rejected: imported concordia-bridge " +
        `attestations must use metric_policy "${BRIDGE_METRIC_POLICY}". ` +
        "Legacy exact bridge metrics are no longer importable."
    );
  }
  if (metricPolicy !== BRIDGE_METRIC_POLICY) {
    throw new BridgeAttestationMetricValidationError(
      "Bridge attestation metrics rejected: unsupported bridge metric_policy " +
        `"${metricPolicy}".`
    );
  }
  const validated = validateBridgePolicyAttestationMetrics(value);
  if (!validated.ok) {
    throw new BridgeAttestationMetricValidationError(validated.error);
  }
  return validated.metrics;
}
