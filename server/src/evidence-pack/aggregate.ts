/**
 * Sanctuary MCP Server - Law-firm Evidence Pack: quarter aggregation
 *
 * Copyright 2026 Erik Newton
 * SPDX-License-Identifier: Apache-2.0
 *
 * The calendar-quarter aggregation and covered-window shortfall detection.
 * This is the main NEW computation the pack adds. It is pure over an injected
 * `AuditEntry[]` + retention facts, so tests exercise the real bucketing and
 * shortfall logic with synthetic fixtures and never touch `~/.sanctuary`.
 *
 * The decision-category mapping reads the shipped enforcement-gate operation
 * strings (`gate_allow:`, `gate_deny:`, `gate_approval_proof:`, etc., written
 * by `principal-policy/gate.ts`) and the cross-harness approval resolution op
 * (`cross_harness_approval_resolved`, written by the approval aggregator). It
 * never invents a decision the log did not record.
 */

import type { AuditEntry } from "../operational/audit-log.js";
import type {
  DecisionCategory,
  QuarterAggregation,
  QuarterWindow,
  RetentionFacts,
  ShortfallReport,
} from "./types.js";
import { isInWindow } from "./quarter.js";

/**
 * The operation string the approval aggregator writes when a cross-harness
 * Tier-1 approval is resolved. Mirrored here (not imported) so this pure layer
 * does not couple to the aggregator's internals; it is a wire-string constant,
 * not behavior. Kept in lockstep with `APPROVAL_AGGREGATOR_AUDIT_OPS.RESOLVED`.
 *
 * DE-DUP (sweep HIGH-1): this op is DELIBERATELY treated as observational
 * (`other`), NOT a human decision count. When the cross-harness approval inbox
 * is enabled (`approval_redirect.enabled`), a single human approval writes BOTH
 * `cross_harness_approval_resolved` (the aggregator) AND `gate_approve:` /
 * `gate_deny:` (the gate, which is written on EVERY gated Tier-1 path whether
 * redirect is on or off). Counting both would roughly DOUBLE the "human
 * reviewed" figure and inflate `total_in_window` and the denial rows. The gate
 * op is the single source of truth for a human control-point decision; the
 * aggregator op is a paired observation of the same decision, so it is not
 * counted a second time.
 */
const CROSS_HARNESS_APPROVAL_RESOLVED = "cross_harness_approval_resolved";

/** Every decision category, so `by_category` is always fully zero-filled. */
const ALL_CATEGORIES: DecisionCategory[] = [
  "allowed",
  "allowed_proxy",
  "human_approved",
  "human_denied",
  "denied",
  "injection_blocked",
  "unclassified",
  "uncategorized",
  "other",
];

/**
 * The EXPLICIT gate-decision op-prefix -> category map. This is the single
 * source of truth the exhaustiveness test checks against the ops actually
 * emitted by `principal-policy/gate.ts`: adding a new `gate_*` decision op to
 * the gate without adding it here fails that test, so a new op can never
 * silently vanish into `other` or a flattering bucket.
 *
 * `gate_approve` (the live interactive channel decision) and the two-phase
 * `gate_approval_proof` are human approvals; `gate_deny` is the blended denial
 * (human OR automated policy/invalid-proof/channel-failure - not separable from
 * the op alone); the rest are automated. There is no `gate_escalate` producer.
 */
export const GATE_DECISION_OP_CATEGORIES: Readonly<
  Record<string, DecisionCategory>
> = {
  gate_allow: "allowed",
  gate_allow_proxy: "allowed_proxy",
  gate_approve: "human_approved",
  gate_approval_proof: "human_approved",
  gate_deny: "denied",
  gate_injection_block: "injection_blocked",
  gate_unclassified: "unclassified",
};

/**
 * Map one audit entry to a decision category. The gate encodes the decision in
 * the operation prefix before the first colon; the cross-harness approval
 * resolution encodes it in the entry result (success = approved, failure =
 * denied).
 *
 * UNMAPPED-OP GUARD: a `gate_`-shaped op NOT in {@link GATE_DECISION_OP_CATEGORIES}
 * is a control-point decision this version does not classify, so it returns
 * `uncategorized` (surfaced honestly for investigation) rather than falling
 * into `other` or inflating an automated count. Only genuine non-`gate_`
 * operations (identity ops, state writes, heartbeats) return `other`.
 */
export function categorizeEntry(entry: AuditEntry): DecisionCategory {
  // De-dup (HIGH-1): the cross-harness approval resolution is a paired
  // OBSERVATION of a decision the gate already recorded (gate_approve/gate_deny),
  // so it is `other`, never a second human-decision count.
  if (entry.operation === CROSS_HARNESS_APPROVAL_RESOLVED) {
    return "other";
  }
  const prefix = entry.operation.split(":", 1)[0] ?? "";
  const mapped = GATE_DECISION_OP_CATEGORIES[prefix];
  if (mapped !== undefined) return mapped;
  // A gate-shaped op we do not explicitly map is a decision we cannot classify:
  // surface it, never hide it in `other` or a flattering bucket.
  if (prefix.startsWith("gate_")) return "uncategorized";
  return "other";
}

/**
 * Bucket audit entries into a single calendar quarter and count them by
 * decision category. Entries outside the window are ignored. Boundaries are
 * inclusive-start / exclusive-end (see {@link isInWindow}).
 */
export function aggregateQuarter(
  entries: readonly AuditEntry[],
  window: QuarterWindow
): QuarterAggregation {
  const byCategory = {} as Record<DecisionCategory, number>;
  for (const category of ALL_CATEGORIES) byCategory[category] = 0;

  const identities = new Set<string>();
  let firstAtMs = Number.POSITIVE_INFINITY;
  let lastAtMs = Number.NEGATIVE_INFINITY;
  let firstAt: string | null = null;
  let lastAt: string | null = null;
  let total = 0;

  for (const entry of entries) {
    if (!isInWindow(entry.timestamp, window)) continue;
    total++;
    byCategory[categorizeEntry(entry)]++;
    identities.add(entry.identity_id);
    const t = new Date(entry.timestamp).getTime();
    if (t < firstAtMs) {
      firstAtMs = t;
      firstAt = entry.timestamp;
    }
    if (t > lastAtMs) {
      lastAtMs = t;
      lastAt = entry.timestamp;
    }
  }

  return {
    window,
    total_in_window: total,
    by_category: byCategory,
    unique_identities: Array.from(identities).sort(),
    first_entry_at: firstAt,
    last_entry_at: lastAt,
  };
}

/**
 * Detect a covered-window shortfall: whether the retained audit log
 * demonstrably covers the full quarter, on BOTH the start side and the end
 * side (HIGH-2 fix). A shortfall exists when either:
 *  - START: the earliest retained entry is later than the quarter start (so
 *    pre-existing entries are unavailable for this quarter), OR
 *  - END: the quarter had not ended at generation time, so the pack cannot
 *    attest coverage of the portion of the quarter after `generatedAt` (an
 *    in-progress quarter, the default one-command case).
 *
 * `covered_to_exclusive` is `min(quarter end, generation instant)` and is NEVER
 * unconditionally the quarter end: the pack can never attest coverage of a
 * period after the moment it was generated.
 *
 * The start-side disclosure distinguishes retention pruning (log at/above its
 * FIFO cap; early entries LIKELY dropped) from genuine inactivity (log below
 * cap; the fortress simply had no earlier activity), and always states the real
 * covered span. The real last-recorded entry is surfaced so an auditor sees the
 * true tail of activity rather than inferring coverage to the quarter end.
 */
export function detectShortfall(
  window: QuarterWindow,
  retention: RetentionFacts,
  params: { generatedAt: string; lastEntryAt: string | null }
): ShortfallReport {
  const quarterStartMs = new Date(window.start_inclusive).getTime();
  const quarterEndMs = new Date(window.end_exclusive).getTime();
  const generatedMs = new Date(params.generatedAt).getTime();
  const earliestMs =
    retention.earliest_retained_at === null
      ? null
      : new Date(retention.earliest_retained_at).getTime();
  // Either FIFO cap counts as "at cap" (sweep HIGH-5): entries OR total size.
  const atEntryCap =
    retention.max_entries > 0 && retention.retained_total >= retention.max_entries;
  const atSizeCap =
    retention.max_total_size_bytes > 0 &&
    retention.retained_total_size_bytes !== null &&
    retention.retained_total_size_bytes >= retention.max_total_size_bytes;
  const retentionAtCap = atEntryCap || atSizeCap;

  // END SIDE: coverage can never extend past the moment the report was made.
  const inProgress = generatedMs < quarterEndMs;
  const coveredToExclusive = new Date(
    Math.min(quarterEndMs, generatedMs)
  ).toISOString();

  // START SIDE.
  let coveredFrom: string;
  let startShortfall: boolean;
  let startExplanation: string;
  if (earliestMs === null) {
    coveredFrom = window.start_inclusive;
    startShortfall = true;
    startExplanation =
      "The audit log holds no retained entries, so this quarter has no " +
      "covered access history. Confirm the fortress was recording during " +
      "the reporting period.";
  } else if (earliestMs >= quarterEndMs) {
    // M1: the entire retained window post-dates the quarter (all in-quarter
    // entries pruned). Do NOT cite an out-of-quarter covered_from; state plainly
    // that zero of the quarter is covered.
    coveredFrom = window.start_inclusive;
    startShortfall = true;
    startExplanation =
      "NONE of this quarter is covered: the earliest retained audit entry (" +
      retention.earliest_retained_at! +
      ") is at or after the quarter end, so no entries from this quarter " +
      "survive in the retained log. The counts above are therefore zero for " +
      "this quarter. This almost always means earlier entries were pruned by " +
      "size/count (FIFO) retention; raise the retention cap or export monthly " +
      "snapshots.";
  } else if (earliestMs > quarterStartMs) {
    coveredFrom = retention.earliest_retained_at!;
    startShortfall = true;
    // The DEFINITIVE discriminator is whether the log ever pruned (a rotation
    // anchor). Only affirm "genuine inactivity, not pruning" when we KNOW the
    // log never pruned AND it is below both caps; otherwise do not reassure.
    const neverPruned =
      retention.ever_pruned === false && !retentionAtCap;
    startExplanation = neverPruned
      ? "The earliest retained audit entry is after the quarter start, and the " +
        "log has never pruned entries (it is below both its entry and size " +
        "retention caps), so this reflects that the fortress had no recorded " +
        "activity before " +
        coveredFrom +
        ", not that entries were pruned. Coverage begins at that instant."
      : "The retained audit window begins after the quarter start, and " +
        (retentionAtCap
          ? "the log is at a retention cap (entries or size), "
          : retention.ever_pruned === true
            ? "the log has pruned entries at least once, "
            : "size-based pruning of large early entries cannot be ruled out, ") +
        "so earlier-quarter entries may have been pruned by size/count (FIFO) " +
        "retention. This report covers access history from " +
        coveredFrom +
        " onward; whether the gap is pruning or genuine inactivity cannot be " +
        "affirmed here. Raise the retention cap or export monthly snapshots to " +
        "cover the full quarter.";
  } else {
    coveredFrom = window.start_inclusive;
    startShortfall = false;
    startExplanation =
      "The retained audit window reaches the quarter start: the earliest " +
      "retained entry precedes it.";
  }

  const parts: string[] = [];
  if (inProgress) {
    parts.push(
      "PARTIAL QUARTER: this report was generated before the quarter ended, " +
        "so it can only attest coverage through " +
        coveredToExclusive +
        " (the generation time), not the full quarter ending " +
        window.end_exclusive +
        ". Regenerate after the quarter closes for a complete report."
    );
  }
  parts.push(startExplanation);
  if (!inProgress && params.lastEntryAt) {
    parts.push(
      "The last recorded audit entry inside the covered window is " +
        params.lastEntryAt +
        "."
    );
  }

  return {
    shortfall: startShortfall || inProgress,
    covered_from: coveredFrom,
    covered_to_exclusive: coveredToExclusive,
    in_progress_quarter: inProgress,
    last_entry_at: params.lastEntryAt,
    retention_at_cap: retentionAtCap,
    explanation: parts.join(" "),
  };
}
