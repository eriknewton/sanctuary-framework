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
  "escalated",
  "injection_blocked",
  "unclassified",
  "other",
];

/**
 * Map one audit entry to a decision category. The gate encodes the decision in
 * the operation prefix before the first colon; the cross-harness approval
 * resolution encodes it in the entry result (success = approved, failure =
 * denied).
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
    case "gate_approval_proof":
      return "human_approved";
    case "gate_deny":
      return "denied";
    case "gate_escalate":
      return "escalated";
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
 * demonstrably covers the full quarter. A shortfall exists when the earliest
 * retained entry (across all time) is later than the quarter start, so entries
 * from before it are simply not available for this quarter.
 *
 * The disclosure distinguishes the two causes honestly:
 *  - retention pruning (the log is at or above its FIFO cap): early-quarter
 *    entries were LIKELY dropped; raise retention caps or export monthly.
 *  - genuine inactivity (the log is below its cap): the fortress simply had no
 *    earlier activity; coverage is complete from the earliest entry.
 *
 * Either way the pack states the real covered span and never implies
 * full-quarter coverage it cannot back.
 */
export function detectShortfall(
  window: QuarterWindow,
  retention: RetentionFacts
): ShortfallReport {
  const quarterStartMs = new Date(window.start_inclusive).getTime();
  const earliestMs =
    retention.earliest_retained_at === null
      ? null
      : new Date(retention.earliest_retained_at).getTime();
  const retentionAtCap =
    retention.max_entries > 0 && retention.retained_total >= retention.max_entries;

  // No retained entries at all: nothing covers the quarter.
  if (earliestMs === null) {
    return {
      shortfall: true,
      covered_from: window.start_inclusive,
      covered_to_exclusive: window.end_exclusive,
      retention_at_cap: retentionAtCap,
      explanation:
        "The audit log holds no retained entries, so this quarter has no " +
        "covered access history. Confirm the fortress was recording during " +
        "the reporting period.",
    };
  }

  if (earliestMs > quarterStartMs) {
    const coveredFrom = retention.earliest_retained_at!;
    const explanation = retentionAtCap
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
        " (not that entries were pruned). Coverage is complete from that " +
        "instant onward.";
    return {
      shortfall: true,
      covered_from: coveredFrom,
      covered_to_exclusive: window.end_exclusive,
      retention_at_cap: retentionAtCap,
      explanation,
    };
  }

  return {
    shortfall: false,
    covered_from: window.start_inclusive,
    covered_to_exclusive: window.end_exclusive,
    retention_at_cap: retentionAtCap,
    explanation:
      "The retained audit window covers the full reporting quarter: the " +
      "earliest retained entry precedes the quarter start.",
  };
}
