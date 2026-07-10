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

  it("categorizes cross-harness approvals by result", () => {
    expect(
      categorizeEntry(entry("2026-08-01T00:00:00.000Z", "cross_harness_approval_resolved", "success"))
    ).toBe("human_approved");
    expect(
      categorizeEntry(entry("2026-08-01T00:00:00.000Z", "cross_harness_approval_resolved", "failure"))
    ).toBe("human_denied");
    expect(
      categorizeEntry(entry("2026-08-01T00:00:00.000Z", "identity_create"))
    ).toBe("other");
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

  it("reports no shortfall when the earliest retained entry precedes the quarter", () => {
    const retention: RetentionFacts = {
      max_entries: cap,
      retained_total: 10,
      earliest_retained_at: "2026-06-15T00:00:00.000Z",
    };
    const r = detectShortfall(Q3_2026, retention);
    expect(r.shortfall).toBe(false);
    expect(r.covered_from).toBe(Q3_2026.start_inclusive);
  });

  it("reports a shortfall with retention_at_cap when the log is full and starts mid-quarter", () => {
    const retention: RetentionFacts = {
      max_entries: cap,
      retained_total: cap,
      earliest_retained_at: "2026-08-01T00:00:00.000Z",
    };
    const r = detectShortfall(Q3_2026, retention);
    expect(r.shortfall).toBe(true);
    expect(r.retention_at_cap).toBe(true);
    expect(r.covered_from).toBe("2026-08-01T00:00:00.000Z");
    expect(r.explanation).toMatch(/pruned/i);
  });

  it("reports a shortfall attributed to inactivity when the log is below its cap", () => {
    const retention: RetentionFacts = {
      max_entries: cap,
      retained_total: 42,
      earliest_retained_at: "2026-08-01T00:00:00.000Z",
    };
    const r = detectShortfall(Q3_2026, retention);
    expect(r.shortfall).toBe(true);
    expect(r.retention_at_cap).toBe(false);
    expect(r.explanation).toMatch(/no recorded activity/i);
  });

  it("reports a shortfall when the log holds no retained entries", () => {
    const retention: RetentionFacts = {
      max_entries: cap,
      retained_total: 0,
      earliest_retained_at: null,
    };
    const r = detectShortfall(Q3_2026, retention);
    expect(r.shortfall).toBe(true);
  });
});
