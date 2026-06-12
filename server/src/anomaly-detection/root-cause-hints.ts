/**
 * Sanctuary v1.3 WP-V1.3-2 Chi-8 Root-cause hints.
 *
 * Lands the "root-cause hints built from existing feature_contributions"
 * entry from the detector catalog's forward list (named there since
 * Chi-7). Translates a finding's drift attribution into operator-facing
 * hint objects: which feature(s) moved, in which direction relative to
 * the learned baseline, and a short plain-English likely cause specific
 * to the detector that fired. Example: a spike in
 * `distinct_credentials_used` on `credential-use-sequence` reads as the
 * credential-enumeration shape; a `band_proportion:night` spike on
 * `time-of-day-activity` reads as off-hours activity.
 *
 * Inputs are ONLY the numeric drift-attribution stats the finding
 * already carries (`feature_contributions`, and for the audit-event
 * class distribution detector its `per_class_drift`), plus the
 * detector id, feature names, and class names. No raw audit payloads,
 * no secrets, no key material flow into a hint. Class names on the
 * audit-event-class detector are audit operation names, which are
 * already part of the finding's attribution surface; because audit
 * operation names can be composed from runtime strings, every
 * data-dependent name is charset-and-length sanitized at the parse
 * boundary before it reaches hint text (see `sanitizeName`).
 *
 * Determinism + degradation contract:
 *  - Pure functions of the finding details; no clock, no randomness,
 *    no I/O. Identical input produces identical hints.
 *  - Hints are sorted highest-deviation-first, then by feature name,
 *    and capped, so the payload stays bounded.
 *  - Unknown detector ids and unknown feature names degrade to a
 *    generic hint built only from the contribution stats.
 *  - Malformed or missing attribution degrades to an empty hint list.
 *  - The dispatcher-facing entry point (`enrichDetailsWithRootCauseHints`)
 *    is fail-closed: a thrown error inside hint generation NEVER blocks
 *    or drops the finding; the finding routes unchanged. The finding
 *    itself is the security signal; hints are an additive convenience.
 *
 * Castle-walking: pure local computation over data already inside the
 * finding. No outbound surface, no LLM call, no new state. Classifier
 * behavior, scoring, severity mapping, and persisted classifier-state
 * shape are untouched; this layer only annotates finding details at
 * routing time.
 */

/**
 * Operator-facing root-cause hint. `feature_names` are the implicated
 * feature keys exactly as the detector emitted them (for class-drift
 * hints, the detector-owned `class_proportion:<class>` key).
 * `z_score` carries the triggering contribution's z-score when the
 * hint came from `feature_contributions`, and null when it came from
 * the audit-event-class detector's proportion-delta attribution.
 */
export interface RootCauseHint {
  feature_names: string[];
  direction: "above_baseline" | "below_baseline";
  z_score: number | null;
  likely_cause: string;
  source: "detector" | "generic";
}

/**
 * Minimum absolute z-score a contribution needs before it earns a
 * hint. Matches the finding floor in `severityFromAnomalyScore` (a
 * sub-1-sigma feature is ordinary noise, not a cause).
 */
export const ROOT_CAUSE_HINT_Z_THRESHOLD = 1;

/** Upper bound on hints attached to one finding. Keeps details bounded. */
export const ROOT_CAUSE_HINT_MAX_HINTS = 5;

/**
 * Upper bound on class-drift hints for the audit-event-class
 * distribution detector. Mirrors the top-3 attribution rendered into
 * that detector's summary and explanation.
 */
export const ROOT_CAUSE_HINT_MAX_CLASS_HINTS = 3;

/** Details key the dispatcher attaches hints under. */
export const ROOT_CAUSE_HINTS_DETAILS_KEY = "root_cause_hints" as const;

type Direction = RootCauseHint["direction"];

/** Parsed, validated FeatureContribution-shaped entry. */
interface ParsedContribution {
  feature_name: string;
  observed: number;
  baseline_mean: number;
  z_score: number;
}

/** Parsed, validated PerClassDriftAttribution-shaped entry. */
interface ParsedClassDrift {
  class_name: string;
  baseline_proportion: number;
  current_proportion: number;
  absolute_delta: number;
  direction: "up" | "down" | "flat";
}

/**
 * Detector-specific hint text. Keyed by detector id, then by exact
 * feature name. Prefixed feature namespaces (`band_count:*`,
 * `peer_z:*`, ...) are handled by the prefix resolvers below because
 * their suffixes are data-dependent. Every feature name here is a
 * REAL emitted feature key from the detector's feature extractor; see
 * `server/docs/anomaly-detection-features.md` for the canonical table.
 */
const DETECTOR_FEATURE_HINTS: Record<
  string,
  Record<string, { above: string; below: string }>
> = {
  "per-agent-activity": {
    tool_call_count: {
      above:
        "Tool-call volume is above this agent's learned baseline. Likely cause: a runaway loop, a newly assigned workload, or an injected task driving extra tool calls.",
      below:
        "Tool-call volume dropped below this agent's learned baseline. Likely cause: a stalled or crashed agent, or activity moving off the audited path.",
    },
    egress_call_count: {
      above:
        "Outbound proxy calls are above baseline. Likely cause: exfiltration-shaped egress, a new external integration, or a retry storm against an external endpoint.",
      below:
        "Outbound proxy calls dropped below baseline. Likely cause: a broken external integration or the agent operating unusually offline.",
    },
    credential_use_count: {
      above:
        "Credential use is above baseline. Likely cause: credential harvesting, a misconfigured retry loop hammering the broker, or a new workload that legitimately needs more secrets.",
      below:
        "Credential use dropped below baseline. Likely cause: a credential pipeline failure or the agent operating outside its normal task profile.",
    },
    audit_event_count: {
      above:
        "Overall audited activity is above baseline. Likely cause: a general activity surge; check which operation classes grew via the audit-event-class-distribution detector.",
      below:
        "Overall audited activity dropped below baseline. Likely cause: an idle, stalled, or partially disconnected agent.",
    },
    recent_receipt_count: {
      above:
        "Receipt and reputation activity is above baseline. Likely cause: an unusual burst of negotiation or attestation traffic.",
      below:
        "Receipt and reputation activity dropped below baseline. Likely cause: negotiation work stopped or moved elsewhere.",
    },
  },
  "cross-agent-timing": {
    co_fire_rate_24h: {
      above:
        "This agent pair is firing within 60 seconds of each other far more than baseline. Likely cause: lockstep coordination, a shared trigger, or one agent driving the other.",
      below:
        "This agent pair stopped co-firing relative to baseline. Likely cause: a previously coupled workflow was split, or one agent in the pair went quiet.",
    },
    inter_event_time_p50_ms: {
      above:
        "The typical gap between this pair's events grew beyond baseline. Likely cause: a coupled workflow slowing down or decoupling.",
      below:
        "The typical gap between this pair's events shrank below baseline. Likely cause: tightened coupling or a shared rapid trigger.",
    },
    inter_event_time_p99_ms: {
      above:
        "The long-tail gap between this pair's events grew beyond baseline. Likely cause: intermittent stalls in a coupled workflow.",
      below:
        "The long-tail gap between this pair's events shrank below baseline. Likely cause: the pair's slowest interactions are tightening into lockstep.",
    },
    correlation_strength: {
      above:
        "The pair's activity time series is more correlated than baseline. Likely cause: coordinated behavior, a shared upstream trigger, or one agent puppeting the other.",
      below:
        "The pair's activity time series decorrelated relative to baseline. Likely cause: a previously synchronized workflow broke apart.",
    },
  },
  "tool-call-sequence": {
    distinct_tools_used: {
      above:
        "The agent called an unusually broad set of tools in a short window. Likely cause: discovery or probing behavior, or a task far outside the agent's normal scope.",
      below:
        "The agent's tool variety narrowed below baseline. Likely cause: a degenerate loop fixated on few tools.",
    },
    max_sequence_length: {
      above:
        "An unusually long unbroken run of tool calls occurred. Likely cause: a runaway loop or a scripted burst.",
      below:
        "Tool-call runs are shorter than baseline. Likely cause: fragmented or interrupted task execution.",
    },
    ngram_3_histogram_entropy: {
      above:
        "Tool-call ordering is more varied than this agent's baseline. Likely cause: erratic or probing behavior replacing a predictable routine.",
      below:
        "Tool-call ordering collapsed into a repeating pattern. Likely cause: mechanical repetition; with a read-then-send pair this is the data-exfiltration pumping shape.",
    },
    repeat_pattern_score: {
      above:
        "One two-call pattern is being hammered repeatedly. Likely cause: an exfiltration-shaped read/send loop or a stuck retry cycle.",
      below:
        "Repeated call-pair patterns dropped below baseline. Likely cause: the agent's habitual routine changed shape.",
    },
  },
  "audit-event-class-distribution": {
    total_events: {
      above:
        "Total audited event volume is above baseline alongside a distribution shift. Likely cause: a new workload changing both volume and mix.",
      below:
        "Total audited event volume is below baseline alongside a distribution shift. Likely cause: part of the agent's normal activity stopped, skewing the remaining mix.",
    },
  },
  "credential-use-sequence": {
    credential_event_count: {
      above:
        "Broker credential operations are above this agent's baseline. Likely cause: credential harvesting or a retry loop hammering the broker.",
      below:
        "Broker credential operations dropped below baseline. Likely cause: a credential pipeline failure or a task-profile change.",
    },
    distinct_credentials_used: {
      above:
        "The agent touched many more distinct credentials than baseline. Likely cause: the credential-enumeration shape, where a compromised agent walks every secret it can reach.",
      below:
        "The agent used fewer distinct credentials than baseline. Likely cause: a narrowed task profile or partial loss of broker access.",
    },
    repeat_pair_score: {
      above:
        "One credential pair is being requested in tight alternation. Likely cause: a credential-replay or stuck-retry loop hammering two secrets.",
      below:
        "Repeated credential-pair patterns dropped below baseline. Likely cause: the agent's habitual credential routine changed shape.",
    },
    burst_max_5min: {
      above:
        "Credential operations spiked inside a single five-minute window. Likely cause: the dump-everything burst shape, even when the daily total looks ordinary.",
      below:
        "Peak credential-burst intensity dropped below baseline. Likely cause: a previously bursty credential routine smoothed out.",
    },
  },
  "cross-agent-distribution": {
    peer_count: {
      above:
        "The peer cohort grew relative to baseline. Likely cause: new agents joined the fortress, changing the comparison population.",
      below:
        "The peer cohort shrank relative to baseline. Likely cause: agents left or went idle, changing the comparison population.",
    },
  },
  "time-of-day-activity": {
    active_band_count: {
      above:
        "The agent is active across more time-of-day bands than baseline. Likely cause: an agent with fixed working hours spreading into new hours; worth correlating with credential and egress activity.",
      below:
        "The agent is active across fewer time-of-day bands than baseline. Likely cause: a schedule contraction or a partially stalled agent.",
    },
  },
};

/** Human-readable UTC ranges for the time-of-day detector's fixed bands. */
const TIME_OF_DAY_BAND_RANGES: Record<string, string> = {
  night: "00:00-06:00 UTC",
  morning: "06:00-12:00 UTC",
  afternoon: "12:00-18:00 UTC",
  evening: "18:00-24:00 UTC",
};

/**
 * Resolve detector-specific hint text for one feature, or null when
 * the (detector, feature) pair has no specific interpretation. Prefix
 * namespaces are resolved here because their suffixes (band names,
 * peer activity-feature names, audit class names) are data-dependent.
 */
function detectorHintText(
  detectorId: string,
  featureName: string,
  direction: Direction,
): string | null {
  const table = DETECTOR_FEATURE_HINTS[detectorId];
  const exact = table?.[featureName];
  if (exact !== undefined) {
    return direction === "above_baseline" ? exact.above : exact.below;
  }
  if (detectorId === "time-of-day-activity") {
    return timeOfDayBandHint(featureName, direction);
  }
  if (detectorId === "cross-agent-distribution") {
    return peerDeviationHint(featureName, direction);
  }
  if (detectorId === "audit-event-class-distribution") {
    return auditClassFeatureHint(featureName, direction);
  }
  return null;
}

function timeOfDayBandHint(
  featureName: string,
  direction: Direction,
): string | null {
  let band: string | null = null;
  if (featureName.startsWith("band_count:")) {
    band = featureName.slice("band_count:".length);
  } else if (featureName.startsWith("band_proportion:")) {
    band = featureName.slice("band_proportion:".length);
  }
  if (band === null || band.length === 0) return null;
  const range = TIME_OF_DAY_BAND_RANGES[band];
  const label = range !== undefined ? `${band} band (${range})` : `${band} band`;
  if (band === "night") {
    return direction === "above_baseline"
      ? `Activity in the ${label} is above this agent's learned baseline. Likely cause: off-hours activity, a classic compromised-credential or exfiltration-window signal; correlate with credential and egress findings.`
      : `Activity in the ${label} dropped below this agent's learned baseline. Likely cause: an off-hours routine stopped; benign unless paired with growth in another band.`;
  }
  return direction === "above_baseline"
    ? `Activity shifted into the ${label} relative to this agent's learned baseline. Likely cause: a schedule change, a new trigger source, or workload moving to different hours.`
    : `Activity shifted out of the ${label} relative to this agent's learned baseline. Likely cause: a schedule change or work moving to different hours; check which band absorbed it.`;
}

function peerDeviationHint(
  featureName: string,
  direction: Direction,
): string | null {
  if (!featureName.startsWith("peer_z:")) return null;
  const activityFeature = featureName.slice("peer_z:".length);
  if (activityFeature.length === 0) return null;
  return direction === "above_baseline"
    ? `This agent moved away from its peer cohort on ${activityFeature}, running hotter relative to peers than its own history predicts. Likely cause: one agent diverging while the cohort holds steady, the pattern self-history baselines cannot see.`
    : `This agent moved away from its peer cohort on ${activityFeature}, running quieter relative to peers than its own history predicts. Likely cause: this agent going dark while its peers stay busy.`;
}

function auditClassFeatureHint(
  featureName: string,
  direction: Direction,
): string | null {
  let className: string | null = null;
  if (featureName.startsWith("class_proportion:")) {
    className = featureName.slice("class_proportion:".length);
  } else if (featureName.startsWith("class_count:")) {
    className = featureName.slice("class_count:".length);
  }
  if (className === null || className.length === 0) return null;
  return classDriftText(className, direction);
}

function classDriftText(className: string, direction: Direction): string {
  return direction === "above_baseline"
    ? `The share of ${className} operations in this agent's audit mix rose above its learned baseline. Likely cause: a behavioral-mix shift toward ${className}; review what changed in the agent's task profile.`
    : `The share of ${className} operations in this agent's audit mix fell below its learned baseline. Likely cause: a behavioral-mix shift away from ${className}; check which operation class grew in its place.`;
}

/** Format a number for hint text: short, deterministic, locale-free. */
function fmt(value: number): string {
  if (Number.isInteger(value)) return String(value);
  return value.toFixed(3);
}

function genericHintText(
  featureName: string,
  contribution: ParsedContribution,
  direction: Direction,
): string {
  const rel = direction === "above_baseline" ? "above" : "below";
  return `Feature ${featureName} is ${rel} the learned baseline (observed ${fmt(contribution.observed)} vs baseline mean ${fmt(contribution.baseline_mean)}, ${fmt(Math.abs(contribution.z_score))} sigma). No detector-specific interpretation is available; review this agent's recent audited activity for the feature.`;
}

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

/**
 * Upper bound on a data-dependent name (feature key, audit class
 * name) after sanitization. Legitimate detector feature keys are far
 * shorter; the cap exists so a hostile name cannot bloat hint text.
 */
export const ROOT_CAUSE_HINT_NAME_MAX_LENGTH = 100;

/**
 * Bound + sanitize a data-dependent name before it flows into
 * operator-facing hint text or `feature_names`. Audit operation
 * names (the audit-event-class detector's class names) can be
 * composed from runtime strings such as tool names, so without this
 * the hint text would be an injection channel for control
 * characters, ANSI escapes, newlines, or unbounded payloads rendered
 * by the dashboard and CLI. Characters outside a small safe charset
 * are replaced with `_` and the result is length-capped. Legitimate
 * detector feature keys (lowercase snake_case, `prefix:suffix`
 * namespaces, dotted audit operation names) pass through unchanged,
 * so detector hint-table lookups are unaffected.
 */
function sanitizeName(name: string): string {
  let safe = name.replace(/[^A-Za-z0-9_.:/-]/g, "_");
  if (safe.length > ROOT_CAUSE_HINT_NAME_MAX_LENGTH) {
    safe = `${safe.slice(0, ROOT_CAUSE_HINT_NAME_MAX_LENGTH)}...`;
  }
  return safe;
}

function parseContributions(value: unknown): ParsedContribution[] {
  if (!Array.isArray(value)) return [];
  const parsed: ParsedContribution[] = [];
  for (const entry of value) {
    if (!isPlainObject(entry)) continue;
    const featureName = entry["feature_name"];
    const observed = entry["observed"];
    const baselineMean = entry["baseline_mean"];
    const zScore = entry["z_score"];
    if (typeof featureName !== "string" || featureName.length === 0) continue;
    if (typeof observed !== "number" || !Number.isFinite(observed)) continue;
    if (typeof baselineMean !== "number" || !Number.isFinite(baselineMean)) {
      continue;
    }
    if (typeof zScore !== "number" || !Number.isFinite(zScore)) continue;
    parsed.push({
      // Sanitized at the parse boundary so every downstream use
      // (hint-table lookups, feature_names, interpolated text) is
      // covered by one chokepoint.
      feature_name: sanitizeName(featureName),
      observed,
      baseline_mean: baselineMean,
      z_score: zScore,
    });
  }
  return parsed;
}

function parseClassDrift(value: unknown): ParsedClassDrift[] {
  if (!Array.isArray(value)) return [];
  const parsed: ParsedClassDrift[] = [];
  for (const entry of value) {
    if (!isPlainObject(entry)) continue;
    const className = entry["class_name"];
    const baselineProportion = entry["baseline_proportion"];
    const currentProportion = entry["current_proportion"];
    const absoluteDelta = entry["absolute_delta"];
    const direction = entry["direction"];
    if (typeof className !== "string" || className.length === 0) continue;
    if (
      typeof baselineProportion !== "number" ||
      !Number.isFinite(baselineProportion)
    ) {
      continue;
    }
    if (
      typeof currentProportion !== "number" ||
      !Number.isFinite(currentProportion)
    ) {
      continue;
    }
    if (typeof absoluteDelta !== "number" || !Number.isFinite(absoluteDelta)) {
      continue;
    }
    if (direction !== "up" && direction !== "down" && direction !== "flat") {
      continue;
    }
    parsed.push({
      // Same parse-boundary chokepoint as parseContributions: class
      // names are audit operation strings, which can be composed
      // from runtime input.
      class_name: sanitizeName(className),
      baseline_proportion: baselineProportion,
      current_proportion: currentProportion,
      absolute_delta: absoluteDelta,
      direction,
    });
  }
  return parsed;
}

/**
 * Build class-drift hints from the audit-event-class detector's
 * `per_class_drift` attribution: top entries by absolute proportion
 * delta (the array arrives pre-sorted by the detector, but the sort
 * is re-applied here so the function is deterministic on any input
 * ordering), `flat` entries skipped, capped at
 * ROOT_CAUSE_HINT_MAX_CLASS_HINTS.
 */
function buildClassDriftHints(drift: ParsedClassDrift[]): RootCauseHint[] {
  const sorted = [...drift].sort((a, b) => {
    const abs = Math.abs(b.absolute_delta) - Math.abs(a.absolute_delta);
    if (abs !== 0) return abs;
    return a.class_name.localeCompare(b.class_name);
  });
  const hints: RootCauseHint[] = [];
  for (const entry of sorted) {
    if (hints.length >= ROOT_CAUSE_HINT_MAX_CLASS_HINTS) break;
    if (entry.direction === "flat") continue;
    const direction: Direction =
      entry.direction === "up" ? "above_baseline" : "below_baseline";
    hints.push({
      feature_names: [`class_proportion:${entry.class_name}`],
      direction,
      z_score: null,
      likely_cause: `${classDriftText(entry.class_name, direction)} (share moved from ${fmt(entry.baseline_proportion)} to ${fmt(entry.current_proportion)}.)`,
      source: "detector",
    });
  }
  return hints;
}

/**
 * Pure mapping from a finding's existing drift attribution to
 * operator-facing root-cause hints.
 *
 * Reads only `detector_id`, `feature_contributions`, and
 * `per_class_drift` out of the finding details. Unknown detector ids
 * and unknown feature names fall back to generic stat-only hints;
 * malformed or missing attribution yields an empty array. The
 * function is deterministic and performs no I/O.
 */
export function buildRootCauseHints(
  details: Record<string, unknown>,
): RootCauseHint[] {
  const detectorIdRaw = details["detector_id"];
  const detectorId = typeof detectorIdRaw === "string" ? detectorIdRaw : "";

  const classDrift = parseClassDrift(details["per_class_drift"]);
  const hasClassDrift = classDrift.length > 0;

  let contributions = parseContributions(details["feature_contributions"]);
  if (hasClassDrift) {
    // The audit-event-class detector mirrors per_class_drift into
    // feature_contributions as class_proportion:* entries; the class
    // hints below already cover them, so skip the mirrored rows to
    // avoid double-hinting.
    contributions = contributions.filter(
      (c) => !c.feature_name.startsWith("class_proportion:"),
    );
  }

  const eligible = contributions
    .filter((c) => Math.abs(c.z_score) >= ROOT_CAUSE_HINT_Z_THRESHOLD)
    .sort((a, b) => {
      const abs = Math.abs(b.z_score) - Math.abs(a.z_score);
      if (abs !== 0) return abs;
      return a.feature_name.localeCompare(b.feature_name);
    });

  const hints: RootCauseHint[] = [];
  for (const contribution of eligible) {
    if (hints.length >= ROOT_CAUSE_HINT_MAX_HINTS) break;
    const direction: Direction =
      contribution.z_score >= 0 ? "above_baseline" : "below_baseline";
    const specific = detectorHintText(
      detectorId,
      contribution.feature_name,
      direction,
    );
    hints.push({
      feature_names: [contribution.feature_name],
      direction,
      z_score: contribution.z_score,
      likely_cause:
        specific ??
        genericHintText(contribution.feature_name, contribution, direction),
      source: specific !== null ? "detector" : "generic",
    });
  }

  if (hasClassDrift) {
    for (const hint of buildClassDriftHints(classDrift)) {
      if (hints.length >= ROOT_CAUSE_HINT_MAX_HINTS) break;
      hints.push(hint);
    }
  }

  return hints;
}

/**
 * Fail-closed enrichment seam used by the anomaly dispatcher when
 * routing a finding. Returns a copy of the details with
 * `root_cause_hints` attached. Any error thrown during hint
 * generation degrades to an empty hints array, and any error thrown
 * while copying the details (hostile getters and similar) degrades
 * to the original details object unchanged. The finding is the
 * security signal and MUST survive; hint enrichment must never block
 * or drop it.
 *
 * The `builder` parameter exists for tests to force a throw and
 * verify the degradation path; production callers use the default.
 */
export function enrichDetailsWithRootCauseHints(
  details: Record<string, unknown>,
  builder: (details: Record<string, unknown>) => RootCauseHint[] = buildRootCauseHints,
): Record<string, unknown> {
  let hints: RootCauseHint[];
  try {
    hints = builder(details);
  } catch {
    hints = [];
  }
  try {
    return { ...details, [ROOT_CAUSE_HINTS_DETAILS_KEY]: hints };
  } catch {
    return details;
  }
}
