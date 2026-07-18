/**
 * Sanctuary MCP Server - Evidence Pack aggregation tests
 *
 * Copyright 2026 Erik Newton
 * SPDX-License-Identifier: Apache-2.0
 *
 * Pure, hermetic tests for the calendar-quarter aggregation and covered-window
 * shortfall detection. No server boot, no real fortress: synthetic AuditEntry
 * fixtures drive the real bucketing and shortfall logic.
 */

import { describe, it, expect } from "vitest";
import type { AuditEntry } from "../../src/operational/audit-log.js";
import {
  aggregateQuarter,
  categorizeEntry,
  detectShortfall,
  retentionDeterminability,
} from "../../src/evidence-pack/aggregate.js";
import {
  parseQuarterLabel,
  quarterWindow,
  isInWindow,
} from "../../src/evidence-pack/quarter.js";
import type { RetentionFacts } from "../../src/evidence-pack/types.js";

const Q3_2026 = quarterWindow({ year: 2026, quarter: 3 });

function entry(
  timestamp: string,
  operation: string,
  result: "success" | "failure" = "success",
  identity = "agent-a",
  details?: Record<string, unknown>
): AuditEntry {
  return { timestamp, layer: "l2", operation, identity_id: identity, result, details };
}

/** A gate entry whose decided_by field marks it a HUMAN control-point decision. */
function humanEntry(timestamp: string, operation: string, result: "success" | "failure" = "success"): AuditEntry {
  return entry(timestamp, operation, result, "agent-a", { decided_by: "human" });
}

describe("quarter window", () => {
  it("maps 2026-Q3 to July 1 (inclusive) through October 1 (exclusive), UTC", () => {
    expect(Q3_2026.start_inclusive).toBe("2026-07-01T00:00:00.000Z");
    expect(Q3_2026.end_exclusive).toBe("2026-10-01T00:00:00.000Z");
    expect(Q3_2026.label).toBe("2026-Q3");
  });

  it("rolls 2026-Q4's end_exclusive into the following year", () => {
    const q4 = quarterWindow({ year: 2026, quarter: 4 });
    expect(q4.start_inclusive).toBe("2026-10-01T00:00:00.000Z");
    expect(q4.end_exclusive).toBe("2027-01-01T00:00:00.000Z");
  });

  it("rejects a malformed quarter label", () => {
    expect(() => parseQuarterLabel("2026-Q5")).toThrow();
    expect(() => parseQuarterLabel("2026Q3")).toThrow();
    expect(parseQuarterLabel(" 2026-Q3 ")).toEqual({ year: 2026, quarter: 3 });
  });
});

describe("window boundaries (inclusive start, exclusive end)", () => {
  it("includes an entry at the exact quarter start", () => {
    expect(isInWindow("2026-07-01T00:00:00.000Z", Q3_2026)).toBe(true);
  });
  it("excludes an entry at the exact quarter end", () => {
    expect(isInWindow("2026-10-01T00:00:00.000Z", Q3_2026)).toBe(false);
  });
  it("excludes an entry one millisecond before the start", () => {
    expect(isInWindow("2026-06-30T23:59:59.999Z", Q3_2026)).toBe(false);
  });
  it("includes an entry one millisecond before the end", () => {
    expect(isInWindow("2026-09-30T23:59:59.999Z", Q3_2026)).toBe(true);
  });
});

describe("aggregateQuarter", () => {
  it("buckets only in-window entries and counts by category", () => {
    const entries: AuditEntry[] = [
      entry("2026-06-30T23:59:59.999Z", "gate_allow:before"), // out (before)
      entry("2026-07-01T00:00:00.000Z", "gate_allow:start"), // in (boundary)
      entry("2026-08-15T12:00:00.000Z", "gate_deny:risky"), // in
      entry("2026-08-16T12:00:00.000Z", "gate_approval_proof:tier1"), // in
      entry("2026-08-17T12:00:00.000Z", "gate_injection_block:x"), // in
      entry("2026-10-01T00:00:00.000Z", "gate_allow:end"), // out (end excl)
    ];
    const agg = aggregateQuarter(entries, Q3_2026);
    expect(agg.total_in_window).toBe(4);
    expect(agg.by_category.allowed).toBe(1);
    expect(agg.by_category.denied).toBe(1);
    expect(agg.by_category.human_approved).toBe(1);
    expect(agg.by_category.injection_blocked).toBe(1);
  });

  it("HIGH-1: cross-harness approval resolution is OBSERVATIONAL (other), not a second human decision", () => {
    // De-dup: this op is paired with a gate_approve/gate_deny for the SAME
    // decision, so counting it would double the human-review figure.
    expect(
      categorizeEntry(entry("2026-08-01T00:00:00.000Z", "cross_harness_approval_resolved", "success"))
    ).toBe("other");
    expect(
      categorizeEntry(entry("2026-08-01T00:00:00.000Z", "cross_harness_approval_resolved", "failure"))
    ).toBe("other");
    expect(
      categorizeEntry(entry("2026-08-01T00:00:00.000Z", "identity_create"))
    ).toBe("other");
  });

  it("HIGH-1: the approval-inbox scenario (both ops for one approval) counts ONE human approval", () => {
    // One human approval via the cross-harness inbox writes BOTH ops: the
    // aggregator op (observational) + gate_approve (decided_by human).
    const agg = aggregateQuarter(
      [
        humanEntry("2026-08-10T00:00:00.000Z", "gate_approve:tool_a"),
        entry("2026-08-10T00:00:00.000Z", "cross_harness_approval_resolved", "success"),
      ],
      Q3_2026
    );
    expect(agg.by_category.human_approved).toBe(1);
  });

  it("N1: the inbox-DENIAL scenario counts EXACTLY ONE human_denied (no double count, not structurally zero)", () => {
    // One human denial via the inbox writes BOTH the aggregator op (failure,
    // observational) AND gate_deny with decided_by "human".
    const agg = aggregateQuarter(
      [
        humanEntry("2026-08-11T00:00:00.000Z", "gate_deny:tool_b", "failure"),
        entry("2026-08-11T00:00:00.000Z", "cross_harness_approval_resolved", "failure"),
      ],
      Q3_2026
    );
    expect(agg.by_category.human_denied).toBe(1); // real producer, not always 0
    expect(agg.by_category.denied).toBe(0); // not double-counted as automated
    expect(agg.by_category.other).toBe(1); // the aggregator op only
  });

  it("N1: an AUTOMATED gate_deny (no human decided_by) stays `denied`, not human_denied", () => {
    const autoDeny = entry("2026-08-12T00:00:00.000Z", "gate_deny:x", "failure", "system", {
      decided_by: "channel_failure",
    });
    const invalidProof = entry("2026-08-12T00:00:00.000Z", "gate_deny:y", "failure"); // no decided_by
    const agg = aggregateQuarter([autoDeny, invalidProof], Q3_2026);
    expect(agg.by_category.denied).toBe(2);
    expect(agg.by_category.human_denied).toBe(0);
  });

  it("maps the LIVE gate op strings to the right human/automated bucket via decided_by", () => {
    const at = "2026-08-01T00:00:00.000Z";
    // Human control-point decisions are attributed by decided_by "human".
    expect(categorizeEntry(humanEntry(at, "gate_approve:some_tool"))).toBe("human_approved");
    expect(categorizeEntry(humanEntry(at, "gate_deny:some_tool", "failure"))).toBe("human_denied");
    // gate_approve/gate_deny WITHOUT a human decided_by are automated.
    expect(categorizeEntry(entry(at, "gate_approve:some_tool"))).toBe("allowed");
    expect(categorizeEntry(entry(at, "gate_deny:some_tool", "failure"))).toBe("denied");
    // Two-phase proof consumption is a human approval by construction.
    expect(categorizeEntry(entry(at, "gate_approval_proof:some_tool"))).toBe("human_approved");
    // Automated tiers.
    expect(categorizeEntry(entry(at, "gate_allow:t"))).toBe("allowed");
    expect(categorizeEntry(entry(at, "gate_allow_proxy:t"))).toBe("allowed_proxy");
    expect(categorizeEntry(entry(at, "gate_injection_block:t"))).toBe("injection_blocked");
    expect(categorizeEntry(entry(at, "gate_unclassified:t"))).toBe("unclassified");
    // UNMAPPED-OP GUARD: an unknown gate-shaped op is surfaced as "uncategorized".
    expect(categorizeEntry(entry(at, "gate_escalate:t"))).toBe("uncategorized");
    expect(categorizeEntry(entry(at, "gate_frobnicate:t"))).toBe("uncategorized");
    // A genuine non-gate operation is "other".
    expect(categorizeEntry(entry(at, "state_write:t"))).toBe("other");
  });

  it("a human gate_approve is counted as human_approved in the aggregation, not other", () => {
    const agg = aggregateQuarter(
      [
        humanEntry("2026-08-10T00:00:00.000Z", "gate_approve:tool_a"),
        humanEntry("2026-08-11T00:00:00.000Z", "gate_approve:tool_b"),
        humanEntry("2026-08-12T00:00:00.000Z", "gate_deny:tool_c", "failure"),
      ],
      Q3_2026
    );
    expect(agg.by_category.human_approved).toBe(2);
    expect(agg.by_category.human_denied).toBe(1);
    expect(agg.by_category.other).toBe(0);
  });

  it("zero-fills every category on empty input", () => {
    const agg = aggregateQuarter([], Q3_2026);
    expect(agg.total_in_window).toBe(0);
    expect(agg.first_entry_at).toBeNull();
    expect(agg.last_entry_at).toBeNull();
    expect(Object.values(agg.by_category).every((n) => n === 0)).toBe(true);
  });

  it("records first/last timestamps and sorted unique identities", () => {
    const entries: AuditEntry[] = [
      entry("2026-09-01T00:00:00.000Z", "gate_allow:b", "success", "agent-b"),
      entry("2026-07-05T00:00:00.000Z", "gate_allow:a", "success", "agent-a"),
      entry("2026-08-05T00:00:00.000Z", "gate_allow:a2", "success", "agent-a"),
    ];
    const agg = aggregateQuarter(entries, Q3_2026);
    expect(agg.first_entry_at).toBe("2026-07-05T00:00:00.000Z");
    expect(agg.last_entry_at).toBe("2026-09-01T00:00:00.000Z");
    expect(agg.unique_identities).toEqual(["agent-a", "agent-b"]);
  });
});

describe("detectShortfall", () => {
  const cap = 100_000;
  const AFTER_Q3 = "2026-11-01T00:00:00.000Z";
  const complete = { generatedAt: AFTER_Q3, lastEntryAt: null };

  function ret(over: Partial<RetentionFacts>): RetentionFacts {
    return {
      max_entries: cap,
      retained_total: 10,
      max_total_size_bytes: 100 * 1024 * 1024,
      retained_total_size_bytes: 0,
      ever_pruned: false,
      earliest_retained_at: "2026-06-15T00:00:00.000Z",
      ...over,
    };
  }

  it("reports no shortfall when the earliest entry precedes the quarter AND the quarter is complete", () => {
    const r = detectShortfall(Q3_2026, ret({ earliest_retained_at: "2026-06-15T00:00:00.000Z" }), complete);
    expect(r.shortfall).toBe(false);
    expect(r.in_progress_quarter).toBe(false);
    expect(r.covered_from).toBe(Q3_2026.start_inclusive);
    expect(r.covered_to_exclusive).toBe(Q3_2026.end_exclusive);
  });

  it("reports a shortfall with retention_at_cap when the entry cap is full and starts mid-quarter", () => {
    const r = detectShortfall(
      Q3_2026,
      ret({ retained_total: cap, earliest_retained_at: "2026-08-01T00:00:00.000Z", ever_pruned: true }),
      complete
    );
    expect(r.shortfall).toBe(true);
    expect(r.retention_at_cap).toBe(true);
    expect(r.covered_from).toBe("2026-08-01T00:00:00.000Z");
    expect(r.explanation).toMatch(/pruned/i);
  });

  it("HIGH-5: a SIZE-cap prune below the entry cap is treated as a possible pruning shortfall", () => {
    // retained_total (42) is far below max_entries, but the on-disk size is at
    // the 100 MB cap -> size-based pruning; must NOT affirm "not pruned".
    const r = detectShortfall(
      Q3_2026,
      ret({
        retained_total: 42,
        retained_total_size_bytes: 100 * 1024 * 1024,
        earliest_retained_at: "2026-08-01T00:00:00.000Z",
        ever_pruned: true,
      }),
      complete
    );
    expect(r.shortfall).toBe(true);
    expect(r.retention_at_cap).toBe(true); // size cap counts
    expect(r.explanation).toMatch(/pruned/i);
    expect(r.explanation).not.toMatch(/no recorded activity/i);
  });

  it("affirms genuine inactivity ONLY when the log never pruned AND is below both caps", () => {
    const r = detectShortfall(
      Q3_2026,
      ret({
        retained_total: 42,
        retained_total_size_bytes: 10,
        earliest_retained_at: "2026-08-01T00:00:00.000Z",
        ever_pruned: false,
      }),
      complete
    );
    expect(r.shortfall).toBe(true);
    expect(r.retention_at_cap).toBe(false);
    expect(r.explanation).toMatch(/no recorded activity/i);
  });

  it("C2: the never-pruned partial-coverage reassurance is SCOPED to the operator store when a daemon store is excluded", () => {
    // Same never-pruned mid-quarter case, but a root-owned daemon store is
    // present-but-unreadable: the daemon may have been enforcing before the
    // earliest OPERATOR entry, so the unqualified "the fortress had no recorded
    // activity before X" completeness claim must NOT be asserted.
    const r = detectShortfall(
      Q3_2026,
      ret({
        retained_total: 42,
        retained_total_size_bytes: 10,
        earliest_retained_at: "2026-08-01T00:00:00.000Z",
        ever_pruned: false,
        daemon_store: {
          status: "present_unreadable",
          included_entry_count: 0,
          unreadable_reason: "privilege",
        },
      }),
      complete
    );
    expect(r.shortfall).toBe(true);
    // Scoped to the operator store, and signposts the excluded daemon store.
    expect(r.explanation).toMatch(/operator (audit )?log|operator store/i);
    expect(r.explanation).toMatch(/_audit-daemon/);
    // Never the unqualified whole-fortress completeness claim.
    expect(r.explanation).not.toMatch(/the fortress had no recorded activity/i);
  });

  it("C2: keeps the neutral whole-fortress wording when the daemon store is ABSENT (no under-claim)", () => {
    const r = detectShortfall(
      Q3_2026,
      ret({
        retained_total: 42,
        retained_total_size_bytes: 10,
        earliest_retained_at: "2026-08-01T00:00:00.000Z",
        ever_pruned: false,
        daemon_store: { status: "absent", included_entry_count: 0 },
      }),
      complete
    );
    expect(r.explanation).toMatch(/the fortress had no recorded activity/i);
    expect(r.explanation).not.toMatch(/_audit-daemon/);
  });

  it("HIGH-5: below both caps but ever_pruned true (or unknown) does NOT affirm 'not pruned'", () => {
    const rUnknown = detectShortfall(
      Q3_2026,
      ret({ retained_total: 42, retained_total_size_bytes: 10, earliest_retained_at: "2026-08-01T00:00:00.000Z", ever_pruned: null }),
      complete
    );
    expect(rUnknown.explanation).not.toMatch(/no recorded activity/i);
    expect(rUnknown.explanation).toMatch(/cannot be ruled out|pruned/i);
  });

  it("M1: the whole retained window post-dating the quarter reports ZERO covered, not a backwards window", () => {
    // Reporting Q3 but the earliest surviving entry is in Q4 (after quarter end).
    const r = detectShortfall(
      Q3_2026,
      ret({ retained_total: 5, earliest_retained_at: "2026-11-01T00:00:00.000Z", ever_pruned: true }),
      complete
    );
    expect(r.shortfall).toBe(true);
    // D9C-2/P1 (Dry-9 fix): covered_from is NOT the out-of-quarter date; a
    // zero-covered quarter attests an EMPTY span, so covered_from collapses to
    // the exclusive end (never a definitive non-empty [quarter-start, end) span
    // the SIGNED manifest / cover / §7 would otherwise back).
    expect(r.covered_from).toBe(r.covered_to_exclusive);
    expect(r.explanation).toMatch(/NONE of this quarter is covered/);
  });

  it("reports a shortfall when the log holds no retained entries", () => {
    const r = detectShortfall(Q3_2026, ret({ retained_total: 0, earliest_retained_at: null }), complete);
    expect(r.shortfall).toBe(true);
  });

  it("HIGH-2: an in-progress quarter caps covered_to at the generation instant", () => {
    const genMid = "2026-08-15T12:00:00.000Z";
    const r = detectShortfall(
      Q3_2026,
      ret({ earliest_retained_at: "2026-06-01T00:00:00.000Z" }),
      { generatedAt: genMid, lastEntryAt: "2026-08-15T11:00:00.000Z" }
    );
    expect(r.shortfall).toBe(true);
    expect(r.in_progress_quarter).toBe(true);
    expect(r.covered_to_exclusive).toBe(genMid);
    expect(r.covered_to_exclusive).not.toBe(Q3_2026.end_exclusive);
    expect(r.explanation).toMatch(/PARTIAL QUARTER/);
  });

  it("HIGH-2: covered_to is the quarter end (never beyond) for a completed quarter generated later", () => {
    const r = detectShortfall(
      Q3_2026,
      ret({ earliest_retained_at: "2026-06-01T00:00:00.000Z" }),
      { generatedAt: "2026-12-01T00:00:00.000Z", lastEntryAt: "2026-09-20T00:00:00.000Z" }
    );
    expect(r.in_progress_quarter).toBe(false);
    expect(r.covered_to_exclusive).toBe(Q3_2026.end_exclusive);
  });

  // ─── D5-1 (dry-bar round 5): at-cap judged PER STORE, not merged vs one cap ──
  it("D5-1: two stores EACH below their own cap (merged total over one cap) is NOT at cap", () => {
    // The falsifying state: operator 60 + daemon 50 retained, each store's own
    // cap 100 (combined capacity 200). Old code summed to 110 and compared vs a
    // single 100-cap -> false 'at cap' + false retention_at_cap in the signed
    // manifest, AND suppressed the earned never-pruned reassurance.
    const r = detectShortfall(
      Q3_2026,
      ret({
        retained_total: 110, // merged display total only
        earliest_retained_at: "2026-08-01T00:00:00.000Z",
        ever_pruned: false,
        per_store_retention: [
          { store: "operator", max_entries: 100, retained_total: 60, max_total_size_bytes: 1_000_000, retained_total_size_bytes: 0 },
          { store: "daemon", max_entries: 100, retained_total: 50, max_total_size_bytes: 1_000_000, retained_total_size_bytes: 0 },
        ],
      }),
      complete
    );
    expect(r.retention_at_cap).toBe(false);
    expect(r.explanation).not.toMatch(/at a retention cap/i);
    // The genuine "no recorded activity before X" reassurance is no longer
    // suppressed by the false at-cap.
    expect(r.explanation).toMatch(/no recorded activity before/i);
  });

  it("D5-1: a single store AT its own entry cap DOES report at cap (real pruning is not hidden)", () => {
    const r = detectShortfall(
      Q3_2026,
      ret({
        retained_total: 150,
        earliest_retained_at: "2026-08-01T00:00:00.000Z",
        ever_pruned: true,
        per_store_retention: [
          { store: "operator", max_entries: 100, retained_total: 50, max_total_size_bytes: 1_000_000, retained_total_size_bytes: 0 },
          { store: "daemon", max_entries: 100, retained_total: 100, max_total_size_bytes: 1_000_000, retained_total_size_bytes: 0 },
        ],
      }),
      complete
    );
    expect(r.retention_at_cap).toBe(true);
    expect(r.explanation).toMatch(/at a retention cap/i);
  });

  it("D5-1: a store AT its own SIZE cap reports at cap (either FIFO cap counts, per store)", () => {
    const r = detectShortfall(
      Q3_2026,
      ret({
        earliest_retained_at: "2026-08-01T00:00:00.000Z",
        ever_pruned: true,
        per_store_retention: [
          { store: "operator", max_entries: 100_000, retained_total: 10, max_total_size_bytes: 100, retained_total_size_bytes: 100 },
        ],
      }),
      complete
    );
    expect(r.retention_at_cap).toBe(true);
  });

  it("D5-1: legacy fallback — no per_store_retention treats the merged fields as ONE store", () => {
    // A caller/fixture predating the field: the merged top-level fields ARE a
    // single conceptual (non-split) store, so retained_total >= cap is the
    // correct single-store at-cap.
    const r = detectShortfall(
      Q3_2026,
      ret({ retained_total: cap, earliest_retained_at: "2026-08-01T00:00:00.000Z", ever_pruned: true }),
      complete
    );
    expect(r.retention_at_cap).toBe(true);
  });

  // ─── P1-B (dry-bar round 6): the single-store fallback must NOT revive the
  // false at-cap on a MERGED census (daemon `included`) that omits the breakdown ─
  it("P1-B: an `included`-daemon MERGED census with NO per_store_retention does NOT falsely assert at-cap", () => {
    // The revival state: a caller of the exported buildEvidencePack supplies a
    // MERGED census (daemon `included`) whose merged retained_total (110) exceeds
    // ONE store's cap (100) but OMITS the per-store breakdown. The real stores are
    // operator 60 + daemon 50, EACH below its own 100 cap. The old fallback
    // compared the merged 110 vs one 100 cap -> a FALSE retention_at_cap:true in
    // the SIGNED manifest + false "at a retention cap" prose. At-cap is NOT
    // DETERMINABLE from a merged total vs one cap, so it is fail-safe (never
    // asserted true) and the flattering reassurance must NOT fire.
    const r = detectShortfall(
      Q3_2026,
      ret({
        max_entries: 100, // one store's cap (mismatched scope vs the merged total)
        retained_total: 110, // MERGED display total (operator 60 + daemon 50)
        earliest_retained_at: "2026-08-01T00:00:00.000Z",
        ever_pruned: false,
        daemon_store: { status: "included", included_entry_count: 50 },
        // per_store_retention intentionally OMITTED (the mismatched-scope state)
      }),
      complete
    );
    // Manifest boolean is NOT falsely true.
    expect(r.retention_at_cap).toBe(false);
    // No false definitive "at a retention cap" prose.
    expect(r.explanation).not.toMatch(/at a retention cap/i);
    // The flattering never-pruned reassurance is NOT revived from an undetermined
    // cap position (it would be a completeness claim the merged total can't back).
    expect(r.explanation).not.toMatch(/no recorded activity before/i);
    // It hedges instead (over-warn is the safe direction).
    expect(r.explanation).toMatch(/cannot be ruled out|pruned/i);
  });

  it("P1-B non-vacuity: the SAME merged-over-cap figures with the daemon NOT `included` STILL report at cap (real single-store pruning is not hidden)", () => {
    // Proves the fail-safe is scoped to the merged-ambiguous case ONLY: when the
    // census is a genuine SINGLE store (daemon absent), the top-level fields ARE
    // that one store's own figures, so retained_total (110) >= cap (100) is a
    // correct, un-suppressed at-cap. Only the `included` status flips the result.
    const r = detectShortfall(
      Q3_2026,
      ret({
        max_entries: 100,
        retained_total: 110,
        earliest_retained_at: "2026-08-01T00:00:00.000Z",
        ever_pruned: true,
        daemon_store: { status: "absent", included_entry_count: 0 },
      }),
      complete
    );
    expect(r.retention_at_cap).toBe(true);
    expect(r.explanation).toMatch(/at a retention cap/i);
  });

  // ─── D7-1 / Codex-F2 (dry-bar round 7): the retention-determinability
  // chokepoint. The P1-B guard keyed on `=== undefined`, so an INCOMPLETE or
  // INCONSISTENT breakdown (empty `[]`, a `null` from an untyped caller, an
  // operator-only row while the daemon is `included`) slipped past it into the
  // single-store fallback, reviving the flattering "never pruned / below both
  // caps / no recorded activity before X" reassurance from a merged census
  // whose cap position was never supplied. Every no-usable-breakdown variant
  // must now classify as NOT determinable on BOTH the prose and manifest paths. ─
  describe("D7-1/F2: not-determinable per_store_retention variants (prose path)", () => {
    // The round-7 revival state: a MERGED census (daemon `included`) whose
    // merged retained_total (110) exceeds ONE store's cap (100), never-pruned,
    // starting mid-quarter.
    const mergedOverCap = (
      perStore: RetentionFacts["per_store_retention"]
    ): RetentionFacts =>
      ret({
        max_entries: 100,
        retained_total: 110,
        earliest_retained_at: "2026-08-01T00:00:00.000Z",
        ever_pruned: false,
        daemon_store: { status: "included", included_entry_count: 50 },
        per_store_retention: perStore,
      });

    const variants: Array<[string, RetentionFacts["per_store_retention"]]> = [
      ["absent (undefined)", undefined],
      ["empty ([])", []],
      // Type-invalid, but reachable from a JS / JSON.parse caller of the
      // exported buildEvidencePack -- the exact Codex round-7 vector.
      ["null (untyped caller)", null as unknown as undefined],
      [
        "operator-only while the daemon store is `included`",
        [
          {
            store: "operator",
            max_entries: 100,
            retained_total: 60,
            max_total_size_bytes: 1_000_000,
            retained_total_size_bytes: 0,
          },
        ],
      ],
      // Fix-round F1: the exact mirror of the operator-only case. The operator
      // store is part of EVERY census, so a daemon-only breakdown leaves the
      // operator store's own cap position unsupplied; before the fix the
      // below-cap daemon row alone earned determinable:true, the flattering
      // reassurance, and a signed definitive retention_at_cap:false.
      [
        "daemon-only (operator row missing)",
        [
          {
            store: "daemon",
            max_entries: 100,
            retained_total: 50,
            max_total_size_bytes: 1_000_000,
            retained_total_size_bytes: 0,
          },
        ],
      ],
      // ─── F2-R2 (Codex second-family review + Dry-8 sweep): row PRESENCE
      // without row FIELD COMPLETENESS. The chokepoint checked WHICH stores had
      // rows but not that the rows carried evaluable cap evidence, so a
      // tags-only breakdown classified determinable: atCapForStore evaluated
      // the missing fields as "not at cap" and the pack SIGNED a definitive
      // flattering retention_at_cap:false plus the never-pruned reassurance --
      // from rows carrying ZERO cap evidence. Duplicate/unknown-store rows fed
      // the at-cap OR directly, which could also sign the OVER-claim. ───
      [
        "tags-only rows with NO cap fields (presence-only exploit)",
        [
          { store: "operator" },
          { store: "daemon" },
        ] as unknown as RetentionFacts["per_store_retention"],
      ],
      [
        "operator row missing retained_total",
        [
          { store: "operator", max_entries: 100, max_total_size_bytes: 1_000_000, retained_total_size_bytes: 0 },
          { store: "daemon", max_entries: 100, retained_total: 50, max_total_size_bytes: 1_000_000, retained_total_size_bytes: 0 },
        ] as unknown as RetentionFacts["per_store_retention"],
      ],
      [
        "operator row with NaN max_entries",
        [
          { store: "operator", max_entries: NaN, retained_total: 60, max_total_size_bytes: 1_000_000, retained_total_size_bytes: 0 },
          { store: "daemon", max_entries: 100, retained_total: 50, max_total_size_bytes: 1_000_000, retained_total_size_bytes: 0 },
        ],
      ],
      [
        "daemon row with Infinity retained_total",
        [
          { store: "operator", max_entries: 100, retained_total: 60, max_total_size_bytes: 1_000_000, retained_total_size_bytes: 0 },
          { store: "daemon", max_entries: 100, retained_total: Infinity, max_total_size_bytes: 1_000_000, retained_total_size_bytes: 0 },
        ],
      ],
      [
        "operator row with string-typed max_entries (wrong type)",
        [
          { store: "operator", max_entries: "100", retained_total: 60, max_total_size_bytes: 1_000_000, retained_total_size_bytes: 0 },
          { store: "daemon", max_entries: 100, retained_total: 50, max_total_size_bytes: 1_000_000, retained_total_size_bytes: 0 },
        ] as unknown as RetentionFacts["per_store_retention"],
      ],
      [
        "operator row with undefined retained_total_size_bytes (contract is null-or-finite)",
        [
          { store: "operator", max_entries: 100, retained_total: 60, max_total_size_bytes: 1_000_000, retained_total_size_bytes: undefined },
          { store: "daemon", max_entries: 100, retained_total: 50, max_total_size_bytes: 1_000_000, retained_total_size_bytes: 0 },
        ] as unknown as RetentionFacts["per_store_retention"],
      ],
      [
        "null row element among complete rows",
        [
          { store: "operator", max_entries: 100, retained_total: 60, max_total_size_bytes: 1_000_000, retained_total_size_bytes: 0 },
          { store: "daemon", max_entries: 100, retained_total: 50, max_total_size_bytes: 1_000_000, retained_total_size_bytes: 0 },
          null,
        ] as unknown as RetentionFacts["per_store_retention"],
      ],
      [
        // Dry-8 HIGH repro: the duplicate is AT its cap, so under the old code
        // the extra row fed the at-cap OR and SIGNED retention_at_cap:true --
        // a signed falsehood in the OVER-claiming direction.
        "duplicate operator rows (second duplicate at cap)",
        [
          { store: "operator", max_entries: 100, retained_total: 60, max_total_size_bytes: 1_000_000, retained_total_size_bytes: 0 },
          { store: "operator", max_entries: 100, retained_total: 100, max_total_size_bytes: 1_000_000, retained_total_size_bytes: 0 },
          { store: "daemon", max_entries: 100, retained_total: 50, max_total_size_bytes: 1_000_000, retained_total_size_bytes: 0 },
        ],
      ],
      [
        "duplicate daemon rows",
        [
          { store: "operator", max_entries: 100, retained_total: 60, max_total_size_bytes: 1_000_000, retained_total_size_bytes: 0 },
          { store: "daemon", max_entries: 100, retained_total: 50, max_total_size_bytes: 1_000_000, retained_total_size_bytes: 0 },
          { store: "daemon", max_entries: 100, retained_total: 50, max_total_size_bytes: 1_000_000, retained_total_size_bytes: 0 },
        ],
      ],
      [
        // Dry-8 HIGH repro: an unknown store tag AT its own (tiny) cap -- under
        // the old code contributing_stores was the ENTIRE raw breakdown, so the
        // invalid "archive" row flipped the at-cap OR to a signed true.
        "unknown-store row (store:'archive' at its own cap) alongside complete rows",
        [
          { store: "operator", max_entries: 100, retained_total: 60, max_total_size_bytes: 1_000_000, retained_total_size_bytes: 0 },
          { store: "daemon", max_entries: 100, retained_total: 50, max_total_size_bytes: 1_000_000, retained_total_size_bytes: 0 },
          { store: "archive", max_entries: 1, retained_total: 1, max_total_size_bytes: 1_000_000, retained_total_size_bytes: 0 },
        ] as unknown as RetentionFacts["per_store_retention"],
      ],
    ];

    for (const [name, perStore] of variants) {
      it(`suppresses at-cap AND the flattering reassurance for ${name}`, () => {
        const r = detectShortfall(Q3_2026, mergedOverCap(perStore), complete);
        // Never a definitive at-cap either way.
        expect(r.retention_at_cap).toBe(false);
        expect(r.retention_at_cap_determinable).toBe(false);
        expect(r.explanation).not.toMatch(/at a retention cap/i);
        // Never the flattering reassurance from an unknown cap position.
        expect(r.explanation).not.toMatch(/never pruned/i);
        expect(r.explanation).not.toMatch(/below both/i);
        expect(r.explanation).not.toMatch(/no recorded activity before/i);
        // Hedges instead (over-warn is the safe direction).
        expect(r.explanation).toMatch(/cannot be ruled out/i);
      });
    }

    it("non-vacuity: a COMPLETE breakdown (operator + daemon rows) stays determinable with unchanged prose", () => {
      const r = detectShortfall(
        Q3_2026,
        mergedOverCap([
          { store: "operator", max_entries: 100, retained_total: 60, max_total_size_bytes: 1_000_000, retained_total_size_bytes: 0 },
          { store: "daemon", max_entries: 100, retained_total: 50, max_total_size_bytes: 1_000_000, retained_total_size_bytes: 0 },
        ]),
        complete
      );
      expect(r.retention_at_cap).toBe(false);
      expect(r.retention_at_cap_determinable).toBe(true);
      // The EARNED reassurance still fires when the breakdown proves below-cap.
      expect(r.explanation).toMatch(/no recorded activity before/i);
    });

    it("non-vacuity: the legacy single-store fallback (undefined breakdown, daemon NOT included) stays determinable", () => {
      const r = detectShortfall(
        Q3_2026,
        ret({
          max_entries: 100,
          retained_total: 110,
          earliest_retained_at: "2026-08-01T00:00:00.000Z",
          ever_pruned: true,
          daemon_store: { status: "absent", included_entry_count: 0 },
        }),
        complete
      );
      expect(r.retention_at_cap).toBe(true);
      expect(r.retention_at_cap_determinable).toBe(true);
      expect(r.explanation).toMatch(/at a retention cap/i);
    });

    it("fail-safe: an explicitly-supplied EMPTY breakdown is not-determinable even on a single-store census", () => {
      // The caller asserted a breakdown and delivered nothing usable; under the
      // old code `[]` made at-cap false and (never-pruned) revived "no recorded
      // activity before X" even with the only present cap figure AT cap.
      const r = detectShortfall(
        Q3_2026,
        ret({
          max_entries: 100,
          retained_total: 100,
          earliest_retained_at: "2026-08-01T00:00:00.000Z",
          ever_pruned: false,
          daemon_store: { status: "absent", included_entry_count: 0 },
          per_store_retention: [],
        }),
        complete
      );
      expect(r.retention_at_cap).toBe(false);
      expect(r.retention_at_cap_determinable).toBe(false);
      expect(r.explanation).not.toMatch(/no recorded activity before/i);
      expect(r.explanation).toMatch(/cannot be ruled out/i);
    });

    it("D8-1 Leg C (DELIBERATE REVERSAL of the F2-R2 null-is-usable allowance): rows with a null ('unread') retained_total_size_bytes are NOT determinable", () => {
      // Pre-D8-1 this test pinned the OPPOSITE: null size stayed determinable
      // and earned the "below both its entry and size retention caps"
      // reassurance -- a signed definitive claim over a size dimension nobody
      // read (and boundary-real: pruning fires only when size EXCEEDS the cap,
      // so ever_pruned=false does not exclude size == cap). The allowance is
      // reversed: an unread size forfeits determinability entirely, so neither
      // the definitive boolean nor the below-caps prose can ride on it.
      const r = detectShortfall(
        Q3_2026,
        mergedOverCap([
          { store: "operator", max_entries: 100, retained_total: 60, max_total_size_bytes: 1_000_000, retained_total_size_bytes: null },
          { store: "daemon", max_entries: 100, retained_total: 50, max_total_size_bytes: 1_000_000, retained_total_size_bytes: null },
        ]),
        complete
      );
      expect(r.retention_at_cap_determinable).toBe(false);
      expect(r.retention_at_cap).toBe(false);
      expect(r.explanation).not.toMatch(/below both/i);
      expect(r.explanation).not.toMatch(/no recorded activity before/i);
      expect(r.explanation).toMatch(/cannot be ruled out/i);
    });
  });

  // ─── F2-R2 (Codex second-family review): the legacy single-store fallback
  // builds a CONTRIBUTING row from the top-level fields, so it must pass the
  // SAME runtime completeness rule -- an untyped caller's missing/NaN/
  // wrong-typed top-level figure is no more evaluable than a field-free
  // breakdown row, yet previously earned a definitive (and with JS coercion
  // sometimes definitively-TRUE) signed at-cap position. ───
  describe("F2-R2: legacy single-store fallback field completeness", () => {
    // AT the entry cap when the figures are real, never-pruned, mid-quarter:
    // the state where a malformed field previously still earned a definitive
    // claim in one direction or the other.
    const singleStore = (over: Partial<RetentionFacts>): RetentionFacts =>
      ret({
        max_entries: 100,
        retained_total: 100,
        earliest_retained_at: "2026-08-01T00:00:00.000Z",
        ever_pruned: false,
        daemon_store: { status: "absent", included_entry_count: 0 },
        ...over,
      });

    const cases: Array<[string, Partial<RetentionFacts>]> = [
      ["NaN max_entries", { max_entries: NaN }],
      ["Infinity max_total_size_bytes", { max_total_size_bytes: Infinity }],
      [
        "missing retained_total (untyped caller)",
        { retained_total: undefined as unknown as number },
      ],
      [
        "missing max_total_size_bytes (untyped caller)",
        { max_total_size_bytes: undefined as unknown as number },
      ],
      [
        "undefined retained_total_size_bytes (contract is null-or-finite)",
        { retained_total_size_bytes: undefined as unknown as number | null },
      ],
      [
        "string-typed retained_total (JS coercion would fabricate at-cap TRUE)",
        { retained_total: "100" as unknown as number },
      ],
    ];

    for (const [name, over] of cases) {
      it(`is NOT determinable with ${name}`, () => {
        const r = detectShortfall(Q3_2026, singleStore(over), complete);
        expect(r.retention_at_cap).toBe(false);
        expect(r.retention_at_cap_determinable).toBe(false);
        expect(r.explanation).not.toMatch(/at a retention cap/i);
        expect(r.explanation).not.toMatch(/no recorded activity before/i);
        expect(r.explanation).toMatch(/cannot be ruled out/i);
      });
    }

    it("D8-1 Leg C (DELIBERATE REVERSAL): a null ('unread') retained_total_size_bytes on the legacy single-store fallback is NOT determinable", () => {
      // Pre-D8-1 this test pinned the OPPOSITE (null size stayed determinable
      // and the entry-dimension at-cap fired). Reversed with the allowance:
      // on every REAL path a null size only arises when getRetentionUsage()
      // threw, where the retained_total is a windowed FALLBACK figure rather
      // than an on-disk census -- so the "entry cap is proven anyway" premise
      // is hollow exactly when null size occurs. The uniform rule fails safe
      // toward hedging (never the flattering direction): the prose warns via
      // the ever-pruned/hedged arm below instead of asserting a definitive
      // at-cap over unverified figures.
      const r = detectShortfall(
        Q3_2026,
        singleStore({ retained_total_size_bytes: null, ever_pruned: true }),
        complete
      );
      expect(r.retention_at_cap_determinable).toBe(false);
      expect(r.retention_at_cap).toBe(false);
      expect(r.explanation).not.toMatch(/at a retention cap/i);
      expect(r.explanation).not.toMatch(/below both/i);
      // Still warns (ever_pruned true): honesty is hedged, not flattering.
      expect(r.explanation).toMatch(/pruned entries at least once/i);
    });
  });

  describe("D7-1: retentionDeterminability chokepoint routing", () => {
    it("routes a usable breakdown through as the contributing stores", () => {
      const rows = [
        { store: "operator" as const, max_entries: 100, retained_total: 60, max_total_size_bytes: 1_000_000, retained_total_size_bytes: 0 },
        { store: "daemon" as const, max_entries: 100, retained_total: 50, max_total_size_bytes: 1_000_000, retained_total_size_bytes: 0 },
      ];
      const d = retentionDeterminability(
        ret({
          daemon_store: { status: "included", included_entry_count: 50 },
          per_store_retention: rows,
        })
      );
      expect(d.at_cap_determinable).toBe(true);
      expect(d.contributing_stores).toBe(rows);
    });

    it("builds the single conceptual store from the top-level fields for the legacy case", () => {
      const d = retentionDeterminability(
        ret({
          max_entries: 100,
          retained_total: 110,
          daemon_store: { status: "absent", included_entry_count: 0 },
        })
      );
      expect(d.at_cap_determinable).toBe(true);
      expect(d.contributing_stores).toEqual([
        {
          max_entries: 100,
          retained_total: 110,
          max_total_size_bytes: 100 * 1024 * 1024,
          retained_total_size_bytes: 0,
        },
      ]);
    });

    it("returns no contributing stores when not determinable (at-cap can never be computed)", () => {
      const d = retentionDeterminability(
        ret({
          daemon_store: { status: "included", included_entry_count: 50 },
          per_store_retention: [],
        })
      );
      expect(d.at_cap_determinable).toBe(false);
      expect(d.contributing_stores).toEqual([]);
    });
  });

  // ─── D5-4 (dry-bar round 5): scope the "last recorded entry" sentence ──────
  it("D5-4: the 'last recorded audit entry' sentence is SCOPED to the operator store when the daemon store is excluded", () => {
    const r = detectShortfall(
      Q3_2026,
      ret({
        earliest_retained_at: "2026-06-01T00:00:00.000Z",
        daemon_store: {
          status: "present_unreadable",
          included_entry_count: 0,
          unreadable_reason: "privilege",
        },
      }),
      { generatedAt: "2026-12-01T00:00:00.000Z", lastEntryAt: "2026-09-20T00:00:00.000Z" }
    );
    expect(r.in_progress_quarter).toBe(false);
    // The excluded daemon store may hold a LATER in-window entry, so the claim is
    // scoped to the operator store rather than the whole census.
    expect(r.explanation).toContain(
      "The last recorded operator-store audit entry inside the covered window is 2026-09-20T00:00:00.000Z."
    );
    expect(r.explanation).not.toContain(
      "The last recorded audit entry inside the covered window is 2026-09-20"
    );
  });

  it("D5-4: keeps the neutral 'last recorded audit entry' wording when the daemon store is absent (whole census)", () => {
    const r = detectShortfall(
      Q3_2026,
      ret({
        earliest_retained_at: "2026-06-01T00:00:00.000Z",
        daemon_store: { status: "absent", included_entry_count: 0 },
      }),
      { generatedAt: "2026-12-01T00:00:00.000Z", lastEntryAt: "2026-09-20T00:00:00.000Z" }
    );
    expect(r.explanation).toContain(
      "The last recorded audit entry inside the covered window is 2026-09-20T00:00:00.000Z."
    );
    expect(r.explanation).not.toContain("operator-store audit entry");
  });

  // ─── D8-1 (Dry-8 sweep): the usable-figures chokepoint. FINITE is not
  // USABLE: a cap of 0/negative is the documented in-band "cap not known to
  // this reporter" encoding (Leg B), and a null size is the documented
  // "size unread" encoding (Leg C) -- yet pre-D8-1 rows carrying them
  // validated and earned a definitive signed retention_at_cap:false plus
  // "below both its entry and size retention caps" prose over caps declared
  // UNKNOWN and size figures nobody read. (This is also why the row fixtures
  // across this file now carry a real 1_000_000 size cap instead of the old
  // 0: the old fixtures leaned on the retired allowance.) ───
  describe("D8-1 Leg B: an unknown (<= 0) cap on any contributing row forfeits determinability", () => {
    const belowEntryCaps = (
      perStore: RetentionFacts["per_store_retention"]
    ): RetentionFacts =>
      ret({
        retained_total: 110,
        earliest_retained_at: "2026-08-01T00:00:00.000Z",
        ever_pruned: false,
        daemon_store: { status: "included", included_entry_count: 50 },
        per_store_retention: perStore,
      });

    it("a breakdown row with max_total_size_bytes: 0 (size cap unknown) is NOT determinable and earns no below-caps reassurance", () => {
      const r = detectShortfall(
        Q3_2026,
        belowEntryCaps([
          { store: "operator", max_entries: 100, retained_total: 60, max_total_size_bytes: 0, retained_total_size_bytes: 100 },
          { store: "daemon", max_entries: 100, retained_total: 50, max_total_size_bytes: 1_000_000, retained_total_size_bytes: 100 },
        ]),
        complete
      );
      expect(r.retention_at_cap_determinable).toBe(false);
      expect(r.retention_at_cap).toBe(false);
      expect(r.explanation).not.toMatch(/below both/i);
      expect(r.explanation).not.toMatch(/no recorded activity before/i);
      expect(r.explanation).toMatch(/cannot be ruled out/i);
    });

    it("a breakdown row with max_entries: 0 (entry cap unknown) is NOT determinable", () => {
      const r = detectShortfall(
        Q3_2026,
        belowEntryCaps([
          { store: "operator", max_entries: 0, retained_total: 60, max_total_size_bytes: 1_000_000, retained_total_size_bytes: 100 },
          { store: "daemon", max_entries: 100, retained_total: 50, max_total_size_bytes: 1_000_000, retained_total_size_bytes: 100 },
        ]),
        complete
      );
      expect(r.retention_at_cap_determinable).toBe(false);
      expect(r.retention_at_cap).toBe(false);
      expect(r.explanation).not.toMatch(/no recorded activity before/i);
      expect(r.explanation).toMatch(/cannot be ruled out/i);
    });

    it("a NEGATIVE cap is equally unknown (<= 0, not === 0)", () => {
      const r = detectShortfall(
        Q3_2026,
        belowEntryCaps([
          { store: "operator", max_entries: 100, retained_total: 60, max_total_size_bytes: -1, retained_total_size_bytes: 100 },
          { store: "daemon", max_entries: 100, retained_total: 50, max_total_size_bytes: 1_000_000, retained_total_size_bytes: 100 },
        ]),
        complete
      );
      expect(r.retention_at_cap_determinable).toBe(false);
    });

    it("the legacy single-store fallback with max_total_size_bytes: 0 is NOT determinable (no below-caps reassurance from an unknown cap)", () => {
      const r = detectShortfall(
        Q3_2026,
        ret({
          max_entries: 100,
          retained_total: 42,
          max_total_size_bytes: 0,
          retained_total_size_bytes: 100,
          earliest_retained_at: "2026-08-01T00:00:00.000Z",
          ever_pruned: false,
          daemon_store: { status: "absent", included_entry_count: 0 },
        }),
        complete
      );
      expect(r.retention_at_cap_determinable).toBe(false);
      expect(r.retention_at_cap).toBe(false);
      expect(r.explanation).not.toMatch(/below both/i);
      expect(r.explanation).not.toMatch(/no recorded activity before/i);
      expect(r.explanation).toMatch(/cannot be ruled out/i);
    });

    it("the legacy single-store fallback with max_entries: 0 is NOT determinable", () => {
      const r = detectShortfall(
        Q3_2026,
        ret({
          max_entries: 0,
          retained_total: 42,
          retained_total_size_bytes: 100,
          earliest_retained_at: "2026-08-01T00:00:00.000Z",
          ever_pruned: false,
          daemon_store: { status: "absent", included_entry_count: 0 },
        }),
        complete
      );
      expect(r.retention_at_cap_determinable).toBe(false);
      expect(r.retention_at_cap).toBe(false);
      expect(r.explanation).not.toMatch(/no recorded activity before/i);
    });

    it("non-vacuity: the same rows with REAL (> 0) caps and read sizes stay determinable with the earned reassurance", () => {
      const r = detectShortfall(
        Q3_2026,
        belowEntryCaps([
          { store: "operator", max_entries: 100, retained_total: 60, max_total_size_bytes: 1_000_000, retained_total_size_bytes: 100 },
          { store: "daemon", max_entries: 100, retained_total: 50, max_total_size_bytes: 1_000_000, retained_total_size_bytes: 100 },
        ]),
        complete
      );
      expect(r.retention_at_cap_determinable).toBe(true);
      expect(r.retention_at_cap).toBe(false);
      expect(r.explanation).toMatch(/no recorded activity before/i);
      expect(r.explanation).toMatch(/below both/i);
    });
  });

  describe("D8-1 Leg C: a null (unread) size on ONE row of an otherwise-usable breakdown forfeits determinability", () => {
    it("operator row size unread, daemon row fully read: NOT determinable (no below-caps claim over the unread dimension)", () => {
      const r = detectShortfall(
        Q3_2026,
        ret({
          retained_total: 110,
          earliest_retained_at: "2026-08-01T00:00:00.000Z",
          ever_pruned: false,
          daemon_store: { status: "included", included_entry_count: 50 },
          per_store_retention: [
            { store: "operator", max_entries: 100, retained_total: 60, max_total_size_bytes: 1_000_000, retained_total_size_bytes: null },
            { store: "daemon", max_entries: 100, retained_total: 50, max_total_size_bytes: 1_000_000, retained_total_size_bytes: 100 },
          ],
        }),
        complete
      );
      expect(r.retention_at_cap_determinable).toBe(false);
      expect(r.retention_at_cap).toBe(false);
      expect(r.explanation).not.toMatch(/below both/i);
      expect(r.explanation).not.toMatch(/no recorded activity before/i);
      expect(r.explanation).toMatch(/cannot be ruled out/i);
    });
  });

  // ─── D9C-2 (Dry-9 sweep): a future-dated in-quarter entry (timestamped AFTER
  // generation but still inside the quarter) must never sign an IMPOSSIBLE
  // coverage span where covered_from > covered_to_exclusive. You cannot attest
  // coverage of the future; the attestable window ends at the generation
  // instant, so an entry after it cannot anchor a covered_from. ───
  describe("D9C-2: a future-dated in-quarter entry never signs a backwards (from > to) span", () => {
    it("an entry dated after generation (still before quarter end) reports zero-covered, never covered_from > covered_to", () => {
      // Q3 in progress: generated 2026-08-01, but the earliest (only) retained
      // entry is timestamped 2026-09-15 -- AFTER generation, still inside Q3.
      // Old code: covered_from = 2026-09-15, covered_to = 2026-08-01 (from > to),
      // SIGNED. The window this report can attest ends at 2026-08-01.
      const gen = "2026-08-01T00:00:00.000Z";
      const r = detectShortfall(
        Q3_2026,
        ret({
          retained_total: 1,
          earliest_retained_at: "2026-09-15T00:00:00.000Z",
          ever_pruned: false,
        }),
        { generatedAt: gen, lastEntryAt: null }
      );
      const fromMs = new Date(r.covered_from).getTime();
      const toMs = new Date(r.covered_to_exclusive).getTime();
      expect(fromMs).toBeLessThanOrEqual(toMs); // never a backwards span
      expect(r.covered_to_exclusive).toBe(gen); // attestable end is generation time
      expect(r.zero_of_quarter_covered).toBe(true);
      expect(r.shortfall).toBe(true);
      // Honest prose: none covered, post-dates the attested window; NOT "pruned"
      // (the entry post-dating generation is clock skew / a future stamp, not a
      // FIFO prune of earlier entries).
      expect(r.explanation).toMatch(/NONE of this quarter is covered/);
      expect(r.explanation).not.toMatch(/pruned/i);
    });

    it("(a) a report generated before its quarter begins never signs a backwards span", () => {
      // generated 2026-06-01, before Q3 starts (2026-07-01), so the attestable
      // end (2026-06-01) precedes even the quarter start. covered_from must be
      // clamped so the SIGNED span is never backwards.
      const gen = "2026-06-01T00:00:00.000Z";
      const r = detectShortfall(
        Q3_2026,
        ret({ retained_total: 1, earliest_retained_at: "2026-08-01T00:00:00.000Z" }),
        { generatedAt: gen, lastEntryAt: null }
      );
      const fromMs = new Date(r.covered_from).getTime();
      const toMs = new Date(r.covered_to_exclusive).getTime();
      expect(fromMs).toBeLessThanOrEqual(toMs);
      expect(r.zero_of_quarter_covered).toBe(true);
    });

    it("M1: an entry at or after the quarter end still says NONE covered, cites the quarter end, and attests an EMPTY span", () => {
      const r = detectShortfall(
        Q3_2026,
        ret({ retained_total: 5, earliest_retained_at: "2026-11-01T00:00:00.000Z", ever_pruned: true }),
        { generatedAt: "2026-11-01T00:00:00.000Z", lastEntryAt: null }
      );
      // D9C-2/P1 (Dry-9 fix): covered_from collapses to the exclusive end so the
      // signed span is EMPTY, never a definitive non-empty one.
      expect(r.covered_from).toBe(r.covered_to_exclusive);
      expect(new Date(r.covered_from).getTime()).toBeLessThanOrEqual(
        new Date(r.covered_to_exclusive).getTime()
      );
      expect(r.explanation).toMatch(/NONE of this quarter is covered/);
      expect(r.explanation).toMatch(/quarter end/i);
    });
  });

  // ─── D9C-3 (Dry-9 sweep): negative and non-safe-integer figures are not
  // USABLE for a definitive cap verdict, exactly like the null/unknown cases
  // (D8-1). A negative size (`-1`) or an unsafe size (> Number.MAX_SAFE_INTEGER,
  // which JS rounds) must forfeit determinability rather than sign a definitive
  // retention_at_cap verdict. ───
  describe("D9C-3: negative / non-safe-integer retained figures are NOT usable", () => {
    it("a negative retained_total_size_bytes forfeits determinability (no signed below-cap verdict)", () => {
      const r = detectShortfall(
        Q3_2026,
        ret({
          retained_total: 110,
          earliest_retained_at: "2026-08-01T00:00:00.000Z",
          ever_pruned: false,
          daemon_store: { status: "included", included_entry_count: 50 },
          per_store_retention: [
            { store: "operator", max_entries: 100, retained_total: 60, max_total_size_bytes: 1_000_000, retained_total_size_bytes: -1 },
            { store: "daemon", max_entries: 100, retained_total: 50, max_total_size_bytes: 1_000_000, retained_total_size_bytes: 100 },
          ],
        }),
        complete
      );
      expect(r.retention_at_cap_determinable).toBe(false);
      expect(r.retention_at_cap).toBe(false);
      expect(r.explanation).not.toMatch(/below both/i);
      expect(r.explanation).not.toMatch(/no recorded activity before/i);
      expect(r.explanation).toMatch(/cannot be ruled out/i);
    });

    it("an unsafe (> Number.MAX_SAFE_INTEGER) size forfeits determinability (no signed at-cap verdict)", () => {
      // The unsafe value rounds in JS; it must never sign a definitive at-cap.
      const unsafe = Number.MAX_SAFE_INTEGER + 100;
      const r = detectShortfall(
        Q3_2026,
        ret({
          earliest_retained_at: "2026-08-01T00:00:00.000Z",
          ever_pruned: true,
          per_store_retention: [
            { store: "operator", max_entries: 100, retained_total: 10, max_total_size_bytes: 100, retained_total_size_bytes: unsafe },
          ],
        }),
        complete
      );
      expect(r.retention_at_cap_determinable).toBe(false);
      expect(r.retention_at_cap).toBe(false);
    });

    it("a negative retained entry count on the legacy single-store fallback forfeits determinability", () => {
      const r = detectShortfall(
        Q3_2026,
        ret({
          max_entries: 100,
          retained_total: -5,
          retained_total_size_bytes: 100,
          earliest_retained_at: "2026-08-01T00:00:00.000Z",
          ever_pruned: false,
          daemon_store: { status: "absent", included_entry_count: 0 },
        }),
        complete
      );
      expect(r.retention_at_cap_determinable).toBe(false);
      expect(r.retention_at_cap).toBe(false);
    });

    it("non-vacuity: the same rows with real non-negative safe-integer sizes stay determinable", () => {
      const r = detectShortfall(
        Q3_2026,
        ret({
          retained_total: 110,
          earliest_retained_at: "2026-08-01T00:00:00.000Z",
          ever_pruned: false,
          daemon_store: { status: "included", included_entry_count: 50 },
          per_store_retention: [
            { store: "operator", max_entries: 100, retained_total: 60, max_total_size_bytes: 1_000_000, retained_total_size_bytes: 100 },
            { store: "daemon", max_entries: 100, retained_total: 50, max_total_size_bytes: 1_000_000, retained_total_size_bytes: 100 },
          ],
        }),
        complete
      );
      expect(r.retention_at_cap_determinable).toBe(true);
      expect(r.retention_at_cap).toBe(false);
      expect(r.explanation).toMatch(/no recorded activity before/i);
    });
  });

  // ─── D9C-1 (Dry-9 sweep): the attested coverage window must never post-date
  // the audit census. The census is read BEFORE the pack stamps its generation
  // time, so entries appended in the gap were never counted; the signed window
  // must stop at the census cut, not the later generation instant. ───
  describe("D9C-1: the attested coverage window never post-dates the census cut", () => {
    it("bounds covered_to at the census cut point, not a later generation instant", () => {
      // Census taken at 11:00; generation stamped at 12:00. Entries appended in
      // the 11:00-12:00 gap were never counted, so the SIGNED window must stop
      // at the census cut (11:00), never claim coverage through 12:00.
      const census = "2026-08-15T11:00:00.000Z";
      const gen = "2026-08-15T12:00:00.000Z";
      const r = detectShortfall(
        Q3_2026,
        ret({ earliest_retained_at: "2026-06-01T00:00:00.000Z" }),
        { generatedAt: gen, lastEntryAt: null, censusTakenAt: census }
      );
      expect(r.covered_to_exclusive).toBe(census);
      expect(r.covered_to_exclusive).not.toBe(gen);
      expect(r.in_progress_quarter).toBe(true);
      expect(r.explanation).toMatch(/audit-census cut point/);
    });

    it("falls back to the generation instant when no census cut is supplied (unchanged)", () => {
      const gen = "2026-08-15T12:00:00.000Z";
      const r = detectShortfall(
        Q3_2026,
        ret({ earliest_retained_at: "2026-06-01T00:00:00.000Z" }),
        { generatedAt: gen, lastEntryAt: null }
      );
      expect(r.covered_to_exclusive).toBe(gen);
    });

    it("uses the generation instant when the census cut is LATER than it (never widens the window)", () => {
      // A census cut after generation must not push the window past generation.
      const gen = "2026-08-15T12:00:00.000Z";
      const r = detectShortfall(
        Q3_2026,
        ret({ earliest_retained_at: "2026-06-01T00:00:00.000Z" }),
        { generatedAt: gen, lastEntryAt: null, censusTakenAt: "2026-08-15T13:00:00.000Z" }
      );
      expect(r.covered_to_exclusive).toBe(gen);
    });
  });

  // ─── D8-2 (late Dry-8 lens): a fully type-valid but UNPARSEABLE
  // `earliest_retained_at` string previously NaN'd through every numeric branch
  // into the definitive "retained audit window reaches the quarter start" arm,
  // signing shortfall:false + full-quarter coverage off a timestamp NOBODY
  // parsed -- even with ever_pruned:true, and could sign the contradictory
  // retention_at_cap:true + shortfall:false pair. The timestamp dimension must
  // mirror the isUsableFigure discipline: unparseable => NOT DETERMINABLE for
  // the start arm, never a definitive no-shortfall verdict. ───
  describe("D8-2: an unparseable earliest_retained_at is never a definitive full-coverage verdict", () => {
    const AFTER_Q3 = "2026-11-01T00:00:00.000Z";
    it("does NOT sign shortfall:false / 'reaches the quarter start' for an unparseable timestamp", () => {
      const r = detectShortfall(
        Q3_2026,
        ret({ earliest_retained_at: "not-a-timestamp", ever_pruned: true }),
        { generatedAt: AFTER_Q3, lastEntryAt: null }
      );
      expect(r.shortfall).toBe(true);
      expect(r.explanation).not.toMatch(/reaches the quarter start/i);
      // Attests an EMPTY span (never a definitive non-empty one).
      expect(r.covered_from).toBe(r.covered_to_exclusive);
      // Honest: names the unparseable timestamp, does NOT falsely diagnose FIFO
      // pruning or claim "no entries survive" (entries exist; the time is unread).
      expect(r.explanation).toMatch(/could not be parsed|not[- ]determinable/i);
    });

    it("does not sign the contradictory retention_at_cap:true + shortfall:false pair", () => {
      // A VALID per-store row at cap would set retention_at_cap:true; the
      // unparseable earliest must still force shortfall:true (never the false pair).
      const r = detectShortfall(
        Q3_2026,
        ret({
          earliest_retained_at: "2026-13-45T99:99:99.999Z", // structurally invalid
          ever_pruned: true,
          per_store_retention: [
            {
              store: "operator",
              max_entries: 100,
              retained_total: 100, // at entry cap
              max_total_size_bytes: 1_000_000,
              retained_total_size_bytes: 0,
            },
          ],
        }),
        { generatedAt: AFTER_Q3, lastEntryAt: null }
      );
      expect(r.shortfall).toBe(true);
    });

    it("still treats a genuinely NULL earliest (empty log) as the empty-log case, not unparseable", () => {
      const r = detectShortfall(
        Q3_2026,
        ret({ retained_total: 0, earliest_retained_at: null }),
        { generatedAt: AFTER_Q3, lastEntryAt: null }
      );
      expect(r.shortfall).toBe(true);
      expect(r.explanation).toMatch(/no retained entries/i);
    });
  });

  // ─── P3 (Dry-9): when the census cut clamps covered_to_exclusive, surfaces
  // that echo the bound must name the CENSUS CUT, not "the generation time". ───
  describe("P3: covered_to_is_census_cut names the actual attestable-end bound", () => {
    it("is true when the audit-census cut bounds the window (precedes generation)", () => {
      const r = detectShortfall(
        Q3_2026,
        ret({ earliest_retained_at: "2026-06-01T00:00:00.000Z" }),
        {
          generatedAt: "2026-08-15T12:00:00.000Z",
          lastEntryAt: null,
          censusTakenAt: "2026-08-15T11:00:00.000Z",
        }
      );
      expect(r.covered_to_is_census_cut).toBe(true);
      expect(r.covered_to_exclusive).toBe("2026-08-15T11:00:00.000Z");
    });

    it("is false when the generation instant (not a census cut) bounds the window", () => {
      const r = detectShortfall(
        Q3_2026,
        ret({ earliest_retained_at: "2026-06-01T00:00:00.000Z" }),
        { generatedAt: "2026-08-15T12:00:00.000Z", lastEntryAt: null }
      );
      expect(r.covered_to_is_census_cut).toBe(false);
    });
  });

  // ─── Dry-9 fix-round-2 (P1): a present-but-UNPARSEABLE census cut is
  // attestation-bearing; it bounds the attested window from above, and falling
  // back to the generation instant would attest coverage the census never
  // proved. It must make the covered window NOT DETERMINABLE, not widen it. ───
  describe("P1: an unparseable census_taken_at makes coverage not determinable", () => {
    it("sets coverage_determinable:false and attests no definitive span (never widened to generation)", () => {
      const gen = "2026-08-15T12:00:00.000Z";
      const r = detectShortfall(
        Q3_2026,
        ret({ earliest_retained_at: "2026-06-01T00:00:00.000Z" }),
        { generatedAt: gen, lastEntryAt: null, censusTakenAt: "not-a-census-timestamp" }
      );
      expect(r.coverage_determinable).toBe(false);
      expect(r.shortfall).toBe(true);
      // The generation instant must NOT become the attested covered_to.
      expect(r.covered_to_exclusive).not.toBe(gen);
      expect(r.explanation).toMatch(/could not be parsed|not[- ]?determinable/i);
    });

    it("a genuinely-usable census cut stays determinable (no regression)", () => {
      const r = detectShortfall(
        Q3_2026,
        ret({ earliest_retained_at: "2026-06-01T00:00:00.000Z" }),
        {
          generatedAt: "2026-08-15T12:00:00.000Z",
          lastEntryAt: null,
          censusTakenAt: "2026-08-15T11:00:00.000Z",
        }
      );
      expect(r.coverage_determinable).toBe(true);
      expect(r.covered_to_exclusive).toBe("2026-08-15T11:00:00.000Z");
    });

    it("no census cut supplied stays determinable (legacy caller, no regression)", () => {
      const r = detectShortfall(
        Q3_2026,
        ret({ earliest_retained_at: "2026-06-01T00:00:00.000Z" }),
        complete
      );
      expect(r.coverage_determinable).toBe(true);
    });
  });

  // ─── Dry-9 fix-round-2 (P3): the zero_of_quarter_covered marker is set
  // UNIFORMLY whenever the signed span is EMPTY, from one code path -- so the
  // unparseable-earliest arm (which attests an empty span) can never omit it. ───
  describe("P3: an EMPTY signed span always carries the zero_of_quarter_covered marker", () => {
    it("sets the marker on the unparseable-earliest empty span", () => {
      const r = detectShortfall(
        Q3_2026,
        ret({ earliest_retained_at: "garbage-not-a-date", ever_pruned: true }),
        complete
      );
      expect(r.covered_from).toBe(r.covered_to_exclusive);
      expect(r.zero_of_quarter_covered).toBe(true);
    });

    it("does NOT set the marker on a real non-empty covered span", () => {
      const r = detectShortfall(
        Q3_2026,
        ret({ earliest_retained_at: "2026-06-15T00:00:00.000Z" }),
        complete
      );
      expect(r.covered_from).not.toBe(r.covered_to_exclusive);
      expect(r.zero_of_quarter_covered).toBe(false);
    });
  });
});
