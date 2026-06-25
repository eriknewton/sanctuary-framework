/**
 * Concordia-bridge reputation metric validation.
 *
 * Invariant #8: Concordia attestations may include behavioral signals only,
 * never raw deal-term fields.
 */

export const CONCORDIA_BRIDGE_REPUTATION_CONTEXT = "concordia-bridge" as const;

export const BRIDGE_ATTESTATION_BEHAVIORAL_METRIC_ALLOWLIST = [
  "rounds",
  "negotiation_rounds",
  "response_time_ms",
  "concession_magnitude",
  "offers_made",
  "reasoning_provided",
] as const;

export type BridgeAttestationBehavioralMetric =
  typeof BRIDGE_ATTESTATION_BEHAVIORAL_METRIC_ALLOWLIST[number];

const BRIDGE_ATTESTATION_BEHAVIORAL_METRICS = new Set<string>(
  BRIDGE_ATTESTATION_BEHAVIORAL_METRIC_ALLOWLIST
);

const COUNT_LIKE_BRIDGE_METRICS = new Set<string>([
  "rounds",
  "negotiation_rounds",
  "offers_made",
]);

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
    (key) => !BRIDGE_ATTESTATION_BEHAVIORAL_METRICS.has(key)
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
