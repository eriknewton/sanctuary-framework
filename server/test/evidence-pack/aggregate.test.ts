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
    // covered_from is NOT the out-of-quarter date; it stays the quarter start.
    expect(r.covered_from).toBe(Q3_2026.start_inclusive);
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
          { store: "operator", max_entries: 100, retained_total: 60, max_total_size_bytes: 0, retained_total_size_bytes: 0 },
          { store: "daemon", max_entries: 100, retained_total: 50, max_total_size_bytes: 0, retained_total_size_bytes: 0 },
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
          { store: "operator", max_entries: 100, retained_total: 50, max_total_size_bytes: 0, retained_total_size_bytes: 0 },
          { store: "daemon", max_entries: 100, retained_total: 100, max_total_size_bytes: 0, retained_total_size_bytes: 0 },
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
});
