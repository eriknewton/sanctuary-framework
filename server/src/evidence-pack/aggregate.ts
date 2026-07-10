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
  "other",
];

/**
 * Map one audit entry to a decision category. The gate encodes the decision in
 * the operation prefix before the first colon; the cross-harness approval
 * resolution encodes it in the entry result (success = approved, failure =
 * denied).
 *
 * Verified against the FULL set of `operation:` producers in
 * `principal-policy/gate.ts` (HIGH-1): `gate_allow`, `gate_allow_proxy`,
 * `gate_injection_block`, `gate_unclassified` are automated; `gate_approve`
 * (the live interactive channel decision) and `gate_approval_proof` (the
 * two-phase re-presented proof) are human approvals; `gate_deny` is the shared
 * denial op (human OR automated) kept as the blended `denied`. There is no
 * `gate_escalate` producer, so it is intentionally NOT a case.
 */
export function categorizeEntry(entry: AuditEntry): DecisionCategory {
  if (entry.operation === CROSS_HARNESS_APPROVAL_RESOLVED) {
    return entry.result === "success" ? "human_approved" : "human_denied";
  }
  const prefix = entry.operation.split(":", 1)[0] ?? "";
  switch (prefix) {
    case "gate_allow":
      return "allowed";
    case "gate_allow_proxy":
      return "allowed_proxy";
    // Human approvals: the interactive channel `gate_${decision}:` with
    // decision="approve", and the two-phase re-presented-envelope proof.
    case "gate_approve":
    case "gate_approval_proof":
      return "human_approved";
    // Blended denial: the gate writes gate_deny: for a human control-point
    // denial AND for automated policy / invalid-proof / channel-failure
    // denials. Not attributable to human-vs-automated from the op alone.
    case "gate_deny":
      return "denied";
    case "gate_injection_block":
      return "injection_blocked";
    case "gate_unclassified":
      return "unclassified";
    default:
      return "other";
  }
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
  const retentionAtCap =
    retention.max_entries > 0 && retention.retained_total >= retention.max_entries;

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
  } else if (earliestMs > quarterStartMs) {
    coveredFrom = retention.earliest_retained_at!;
    startShortfall = true;
    startExplanation = retentionAtCap
      ? "The retained audit window begins after the quarter start AND the log " +
        "is at its retention cap, so earlier-quarter entries were likely " +
        "pruned by size-based (FIFO) retention. This report covers access " +
        "history from " +
        coveredFrom +
        " onward. Raise the retention cap or export monthly snapshots to " +
        "cover the full quarter."
      : "The earliest retained audit entry is after the quarter start, but " +
        "the log is below its retention cap, so this reflects that the " +
        "fortress had no recorded activity before " +
        coveredFrom +
        " (not that entries were pruned). Coverage begins at that instant.";
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
