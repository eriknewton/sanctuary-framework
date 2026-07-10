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
  identity = "agent-a"
): AuditEntry {
  return { timestamp, layer: "l2", operation, identity_id: identity, result };
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
    // One human approval via the cross-harness inbox writes BOTH ops.
    const agg = aggregateQuarter(
      [
        entry("2026-08-10T00:00:00.000Z", "gate_approve:tool_a"),
        entry("2026-08-10T00:00:00.000Z", "cross_harness_approval_resolved", "success"),
      ],
      Q3_2026
    );
    expect(agg.by_category.human_approved).toBe(1);
    // One human denial likewise counts once (gate_deny), not twice.
    const agg2 = aggregateQuarter(
      [
        entry("2026-08-11T00:00:00.000Z", "gate_deny:tool_b", "failure"),
        entry("2026-08-11T00:00:00.000Z", "cross_harness_approval_resolved", "failure"),
      ],
      Q3_2026
    );
    expect(agg2.by_category.denied).toBe(1);
    expect(agg2.by_category.human_denied).toBe(0);
  });

  it("HIGH-1: maps the LIVE gate op strings to the right human/automated bucket", () => {
    const at = "2026-08-01T00:00:00.000Z";
    // The live interactive human-approval op (gate_${decision}: with approve)
    // must be a HUMAN approval, not dropped into "other".
    expect(categorizeEntry(entry(at, "gate_approve:some_tool"))).toBe("human_approved");
    expect(categorizeEntry(entry(at, "gate_approval_proof:some_tool"))).toBe("human_approved");
    // gate_deny is the blended denial (human or automated); it stays "denied".
    expect(categorizeEntry(entry(at, "gate_deny:some_tool", "failure"))).toBe("denied");
    // Automated tiers.
    expect(categorizeEntry(entry(at, "gate_allow:t"))).toBe("allowed");
    expect(categorizeEntry(entry(at, "gate_allow_proxy:t"))).toBe("allowed_proxy");
    expect(categorizeEntry(entry(at, "gate_injection_block:t"))).toBe("injection_blocked");
    expect(categorizeEntry(entry(at, "gate_unclassified:t"))).toBe("unclassified");
    // UNMAPPED-OP GUARD: an unknown gate-shaped op is surfaced as
    // "uncategorized", never hidden in "other" or a flattering bucket.
    expect(categorizeEntry(entry(at, "gate_escalate:t"))).toBe("uncategorized");
    expect(categorizeEntry(entry(at, "gate_frobnicate:t"))).toBe("uncategorized");
    // A genuine non-gate operation is "other".
    expect(categorizeEntry(entry(at, "state_write:t"))).toBe("other");
  });

  it("HIGH-1: gate_approve is counted as human_approved in the aggregation, not other", () => {
    const agg = aggregateQuarter(
      [
        entry("2026-08-10T00:00:00.000Z", "gate_approve:tool_a"),
        entry("2026-08-11T00:00:00.000Z", "gate_approve:tool_b"),
        entry("2026-08-12T00:00:00.000Z", "gate_deny:tool_c", "failure"),
      ],
      Q3_2026
    );
    expect(agg.by_category.human_approved).toBe(2);
    expect(agg.by_category.denied).toBe(1);
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
});
