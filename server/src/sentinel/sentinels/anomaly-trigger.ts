/**
 * Sanctuary v1.3 WP-V1.3-1 Phi-5 Anomaly Trigger meta-sentinel.
 *
 * Fifth and final baseline sentinel. CLOSES WP-V1.3-1 Sentinel Baseline
 * Pack (Castle Layer 2 anchor). Distinct from Phi-1/2/3/4 in that it
 * reads the per-fortress finding STORE, not the audit log. Phi-5 is a
 * second-order observer: it watches for patterns ACROSS what the other
 * sentinels are saying.
 *
 * Three triggers:
 *
 *   - TRIGGER A, compound finding: at least 2 distinct sentinel-IDs
 *     have fired warn-or-alert findings on the same agent within the
 *     last 24h. Emits one alert per affected agent, with the
 *     contributing sentinel-IDs listed in `details.contributing_sentinels`
 *     and the contributing finding-IDs in `evidence_audit_ids`. (The
 *     `evidence_audit_ids` field's name is inherited from the
 *     `SentinelFinding` contract; Phi-5 reuses it to point at first-
 *     order findings rather than raw audit-log entries. The trigger
 *     class is encoded in `details.trigger` so consumers can branch
 *     without inspecting the evidence shape.)
 *
 *   - TRIGGER B, fortress-level count anomaly: 24h count of all
 *     findings (any sentinel, any severity, any agent) exceeded the
 *     mean + 3 sigma (warn) or mean + 6 sigma (alert) of the rolling
 *     7-day baseline. Surfaces fortress-wide unusual activity even
 *     when individual sentinels stayed below their own thresholds.
 *
 *   - TRIGGER C, novel sentinel-ID combination: the set of distinct
 *     sentinel-IDs that fired in the current 24h window has not
 *     appeared in any of the prior 7 baseline windows. Emits an
 *     `info` finding so the operator can notice an unfamiliar pattern
 *     of cross-sentinel activity (e.g., credential-usage + cross-agent-
 *     chatter co-firing for the first time).
 *
 * Algorithm:
 *
 *   1. Read finding METADATA (no decrypt — `listFindingMetadata`, MUST-FIX
 *      5 fix-round-2 RECHECK) for the last 8 days from `ctx.findingStore`,
 *      filtered to this fortress (the store is per-fortress, so the
 *      filter is implicit; the `since` filter trims the window). Every
 *      field this meta-sentinel needs (finding_id, sentinel_id, agent_id,
 *      severity, observed_at) already lives in the store's plaintext
 *      index; a decrypt-bounded `listFindings({limit})` call previously
 *      let a flood in a RECENT window silently truncate an OLDER baseline
 *      window out of the result before this sentinel ever saw it —
 *      `listFindingMetadata` has no decrypt bound to truncate against.
 *   2. Bucket by 24h window: window 0 = current, windows 1..7 = prior.
 *      Same window math the first-order sentinels use.
 *   3. Trigger A: walk window-0 warn+alert findings; group by
 *      `agent_id`; emit one alert per agent with >= 2 distinct
 *      sentinel-IDs.
 *   4. Trigger B: total count per window; compute mean + stddev over
 *      windows 1..7 (warmup gating: skip when fewer than 7 are
 *      populated, same as Phi-1).
 *   5. Trigger C: per-window set of distinct sentinel-IDs. Skip
 *      Phi-5's own ID so the meta-sentinel does not bootstrap its own
 *      "novel combination" trigger. Compare the current set against
 *      every baseline window; emit when no match is found.
 *
 * Castle-walking discipline:
 *
 *   - No new outbound surface. The finding store is server-local,
 *     encrypted at-rest under the fortress master key, and the
 *     watcher reads through the existing Phi-1 store API.
 *   - Multi-fortress isolation rides on the store itself: the
 *     dispatcher hands Phi-5 the per-fortress store via
 *     `SentinelContext.findingStore`, and the store's HKDF subkey
 *     prevents one fortress decoding another's findings.
 *   - Fail-soft: a finding-store read that throws is caught, the
 *     meta-sentinel emits no findings for the failing tick, and the
 *     surrounding tick continues. The dispatcher's
 *     `sentinel_evaluation_failed` audit emission covers the
 *     observability surface.
 *
 * Out of scope: ML-based anomaly detection (WP-V1.3-2 Chi sequence).
 */

import { Sentinel } from "../sentinel.js";
import type {
  SentinelContext,
  SentinelFinding,
  SentinelSeverity,
} from "../types.js";
import type { SentinelFindingMetadata } from "../sentinel-finding-store.js";

export const ANOMALY_TRIGGER_SENTINEL_ID = "anomaly-trigger" as const;

/** Sigma thresholds for the fortress-count path. */
const WARN_SIGMA = 3;
const ALERT_SIGMA = 6;
/** Days of history required before threshold checks run. */
const BASELINE_WINDOWS = 7;
/** Window duration in ms. */
const WINDOW_MS = 24 * 60 * 60 * 1000;
/** Distinct sentinel-IDs required on one agent to fire Trigger A. */
const COMPOUND_TRIGGER_MIN_SENTINELS = 2;

/**
 * Stable trigger-class enum encoded in `details.trigger`. Lets dashboard
 * consumers branch on cause without inspecting the rest of the details
 * payload.
 */
export type AnomalyTriggerClass = "compound" | "count_spike" | "novel_combo";

export class AnomalyTriggerWatcher extends Sentinel {
  readonly sentinelId = ANOMALY_TRIGGER_SENTINEL_ID;
  readonly description =
    "Meta-sentinel. Watches for patterns ACROSS other sentinels' findings: compound suspicious behavior on one agent, fortress-wide finding-count spikes, and novel cross-sentinel combinations. Closes WP-V1.3-1 Sentinel Baseline Pack.";

  async subscribe(context: SentinelContext): Promise<void> {
    if (!context.findingStore) {
      throw new Error(
        `${ANOMALY_TRIGGER_SENTINEL_ID}: findingStore missing from SentinelContext; this meta-sentinel requires the Phi-1 finding store`,
      );
    }
    await super.subscribe(context);
  }

  async evaluate(): Promise<SentinelFinding[]> {
    const ctx = this.requireContext();
    const findingStore = ctx.findingStore;
    if (!findingStore) {
      // subscribe() already enforces this, but the field is optional
      // on the SentinelContext interface so the runtime check stays
      // here too in case a caller bypassed the gate.
      return [];
    }

    const now = ctx.now();
    const nowMs = now.getTime();
    const windowSpanMs = (BASELINE_WINDOWS + 1) * WINDOW_MS;
    const sinceIso = new Date(nowMs - windowSpanMs).toISOString();

    let findings: SentinelFindingMetadata[];
    try {
      // METADATA ONLY (MUST-FIX 5, fix-round-2 RECHECK): no decrypt, no
      // caller-`limit` truncation — see the class doc's Algorithm step 1
      // and `listFindingMetadata`'s own doc for why a decrypt-bounded
      // `listFindings({limit})` call was the wrong shape for a rolling
      // security baseline.
      findings = await findingStore.listFindingMetadata({ since: sinceIso });
    } catch {
      // Fail-soft: a store read failure produces zero findings this
      // tick. The dispatcher's evaluation_failed audit path covers
      // observability for the failing call.
      return [];
    }

    // Drop Phi-5's own findings so the meta-sentinel does not
    // bootstrap its own outputs into the inputs.
    const firstOrderFindings = findings.filter(
      (f) => f.sentinel_id !== ANOMALY_TRIGGER_SENTINEL_ID,
    );

    // Bucket every first-order finding into a 24h window relative to
    // `now`. Negative ages (clock skew) are dropped. Windows beyond
    // the baseline span are dropped.
    const windowed = bucketByWindow(firstOrderFindings, nowMs);

    const out: SentinelFinding[] = [];

    const compoundFindings = computeCompoundFindings(
      windowed[0] ?? [],
      now,
    );
    out.push(...compoundFindings);

    const countSpikeFinding = computeCountSpikeFinding(windowed, now);
    if (countSpikeFinding) out.push(countSpikeFinding);

    const novelComboFinding = computeNovelComboFinding(windowed, now);
    if (novelComboFinding) out.push(novelComboFinding);

    return out;
  }
}

// ── Trigger A: compound finding on one agent ─────────────────────────────

function computeCompoundFindings(
  windowZero: SentinelFindingMetadata[],
  now: Date,
): SentinelFinding[] {
  const byAgent = new Map<string, SentinelFindingMetadata[]>();
  for (const f of windowZero) {
    if (!f.agent_id) continue;
    if (!isWarnOrAlert(f.severity)) continue;
    let bucket = byAgent.get(f.agent_id);
    if (!bucket) {
      bucket = [];
      byAgent.set(f.agent_id, bucket);
    }
    bucket.push(f);
  }

  const out: SentinelFinding[] = [];
  for (const [agentId, group] of byAgent.entries()) {
    const distinctSentinels = new Set(group.map((f) => f.sentinel_id));
    if (distinctSentinels.size < COMPOUND_TRIGGER_MIN_SENTINELS) continue;
    const contributingSentinels = [...distinctSentinels].sort();
    const evidence = group
      .map((f) => f.finding_id)
      .filter((id) => id.length > 0)
      .slice(0, 50);
    const summary = `${agentId} agent triggered ${distinctSentinels.size} distinct sentinels in the last 24h: ${contributingSentinels.join(", ")}. Compound suspicious behavior; review the contributing findings.`;
    out.push({
      finding_id: "",
      sentinel_id: ANOMALY_TRIGGER_SENTINEL_ID,
      severity: "alert",
      agent_id: agentId,
      summary,
      details: {
        trigger: "compound" satisfies AnomalyTriggerClass,
        agent_id: agentId,
        contributing_sentinels: contributingSentinels,
        contributing_finding_count: group.length,
      },
      observed_at: now.toISOString(),
      evidence_audit_ids: evidence,
      fortress_id: "",
    });
  }
  return out;
}

// ── Trigger B: fortress-level count spike ────────────────────────────────

function computeCountSpikeFinding(
  windowed: SentinelFindingMetadata[][],
  now: Date,
): SentinelFinding | null {
  const currentCount = (windowed[0] ?? []).length;
  const baselineCounts: number[] = [];
  for (let i = 1; i <= BASELINE_WINDOWS; i += 1) {
    baselineCounts.push((windowed[i] ?? []).length);
  }
  const populated = baselineCounts.filter((c) => c > 0).length;
  if (populated < BASELINE_WINDOWS) {
    return null;
  }
  const mean =
    baselineCounts.reduce((sum, c) => sum + c, 0) / baselineCounts.length;
  const variance =
    baselineCounts.reduce((sum, c) => sum + (c - mean) ** 2, 0) /
    baselineCounts.length;
  const stddev = Math.sqrt(variance);

  const warnThreshold = mean + WARN_SIGMA * stddev;
  const alertThreshold = mean + ALERT_SIGMA * stddev;

  if (currentCount > alertThreshold) {
    return buildCountFinding(
      currentCount,
      mean,
      stddev,
      ALERT_SIGMA,
      "alert",
      windowed[0] ?? [],
      now,
    );
  }
  if (currentCount > warnThreshold) {
    return buildCountFinding(
      currentCount,
      mean,
      stddev,
      WARN_SIGMA,
      "warn",
      windowed[0] ?? [],
      now,
    );
  }
  return null;
}

function buildCountFinding(
  currentCount: number,
  mean: number,
  stddev: number,
  sigma: number,
  severity: "warn" | "alert",
  windowZero: SentinelFindingMetadata[],
  now: Date,
): SentinelFinding {
  const ratio = mean === 0 ? Number.POSITIVE_INFINITY : currentCount / mean;
  const ratioStr = Number.isFinite(ratio)
    ? `${ratio.toFixed(1)}x normal`
    : "no prior baseline";
  const summary = `Fortress finding count is ${ratioStr}: ${currentCount} findings in last 24h, baseline ${mean.toFixed(1)} +/- ${stddev.toFixed(1)}. Crossed +${sigma} sigma threshold across all sentinels.`;
  const evidence = windowZero
    .map((f) => f.finding_id)
    .filter((id) => id.length > 0)
    .slice(0, 50);
  return {
    finding_id: "",
    sentinel_id: ANOMALY_TRIGGER_SENTINEL_ID,
    severity,
    summary,
    details: {
      trigger: "count_spike" satisfies AnomalyTriggerClass,
      current_count: currentCount,
      baseline_mean: mean,
      baseline_stddev: stddev,
      sigma_threshold: sigma,
      ratio: Number.isFinite(ratio) ? ratio : null,
    },
    observed_at: now.toISOString(),
    evidence_audit_ids: evidence,
    fortress_id: "",
  };
}

// ── Trigger C: novel sentinel-ID combination ─────────────────────────────

function computeNovelComboFinding(
  windowed: SentinelFindingMetadata[][],
  now: Date,
): SentinelFinding | null {
  // Drop windows that contributed zero distinct sentinel-IDs from the
  // baseline-populated count. Without a prior baseline of combos the
  // trigger cannot say a current combo is "novel".
  const distinctByWindow: Set<string>[] = [];
  for (let i = 0; i <= BASELINE_WINDOWS; i += 1) {
    const set = new Set<string>();
    for (const f of windowed[i] ?? []) {
      set.add(f.sentinel_id);
    }
    distinctByWindow.push(set);
  }

  const populatedBaselineWindows = distinctByWindow
    .slice(1)
    .filter((s) => s.size > 0).length;
  if (populatedBaselineWindows < BASELINE_WINDOWS) {
    return null;
  }

  const currentCombo = distinctByWindow[0]!;
  // Require at least 2 distinct sentinel-IDs to call something a
  // "combo"; one-sentinel windows do not have a combinatorial shape
  // worth flagging at the meta layer.
  if (currentCombo.size < 2) return null;

  const currentKey = comboKey(currentCombo);
  for (let i = 1; i <= BASELINE_WINDOWS; i += 1) {
    if (comboKey(distinctByWindow[i]!) === currentKey) {
      return null;
    }
  }

  const sentinelIds = [...currentCombo].sort();
  const summary = `Novel sentinel-ID combination this 24h window: ${sentinelIds.join(" + ")}. This co-occurrence pattern has not appeared in the prior ${BASELINE_WINDOWS} baseline windows.`;
  const evidence = (windowed[0] ?? [])
    .map((f) => f.finding_id)
    .filter((id) => id.length > 0)
    .slice(0, 50);
  return {
    finding_id: "",
    sentinel_id: ANOMALY_TRIGGER_SENTINEL_ID,
    severity: "info",
    summary,
    details: {
      trigger: "novel_combo" satisfies AnomalyTriggerClass,
      sentinel_ids: sentinelIds,
      baseline_window_count: BASELINE_WINDOWS,
    },
    observed_at: now.toISOString(),
    evidence_audit_ids: evidence,
    fortress_id: "",
  };
}

// ── Helpers ──────────────────────────────────────────────────────────────

function isWarnOrAlert(s: SentinelSeverity): s is "warn" | "alert" {
  return s === "warn" || s === "alert";
}

function bucketByWindow(
  findings: SentinelFindingMetadata[],
  nowMs: number,
): SentinelFindingMetadata[][] {
  const buckets: SentinelFindingMetadata[][] = Array.from(
    { length: BASELINE_WINDOWS + 1 },
    () => [],
  );
  for (const f of findings) {
    const ts = Date.parse(f.observed_at);
    if (!Number.isFinite(ts)) continue;
    const age = nowMs - ts;
    if (age < 0) continue;
    const idx = Math.floor(age / WINDOW_MS);
    if (idx > BASELINE_WINDOWS) continue;
    buckets[idx]!.push(f);
  }
  return buckets;
}

function comboKey(set: Set<string>): string {
  return [...set].sort().join("|");
}
