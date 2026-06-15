/**
 * Unit tests for the coverage-ratchet diff logic (DoE H-3).
 *
 * These exercise diffAgainstBaseline directly with synthetic reports so the
 * fail-on-drop semantics are proven without running the (slower) real fixtures.
 * This is the mutation-resistance proof for the load-bearing comparison: every
 * regression KIND reds, and every improvement / hold is green.
 */

import { describe, expect, it } from "vitest";
import type { CoverageReport, CoverageRow } from "../report.js";
import { diffAgainstBaseline, type CoverageBaseline } from "../coverage-ratchet.js";

function row(overrides: Partial<CoverageRow> & { assurance_row_id: string }): CoverageRow {
  const passed = overrides.fixtures_passed ?? 0;
  return {
    label: `row ${overrides.assurance_row_id}`,
    assurance_status: "proven",
    // Default synthetic fixtures named f0..fN-1, all passing, unless overridden.
    fixtures: Array.from({ length: passed }, (_unused, i) => ({
      name: `f${i}`,
      passed: true,
      durationMs: 0,
    })),
    fixtures_run: passed,
    fixtures_passed: passed,
    fixtures_failed: 0,
    coverage_state: "covered",
    ...overrides,
  };
}

function report(rows: CoverageRow[]): CoverageReport {
  return {
    generated_at: "now",
    sanctuary_sha: "test",
    platform: "linux",
    rows,
    summary: {
      total_rows: rows.length,
      rows_with_fixtures: rows.filter((r) => r.fixtures_run > 0).length,
      rows_no_fixture: rows.filter((r) => r.coverage_state === "no_fixture").length,
      rows_failing: rows.filter((r) => r.fixtures_failed > 0).length,
    },
  };
}

const BASELINE: CoverageBaseline = {
  rows: [
    {
      assurance_row_id: "1",
      label: "row 1",
      assurance_status: "proven",
      fixtures_passed: 3,
      coverage_state: "covered",
      passing_fixture_names: ["f0", "f1", "f2"],
    },
    {
      assurance_row_id: "2",
      label: "row 2",
      assurance_status: "partial",
      fixtures_passed: 0,
      coverage_state: "no_fixture",
      passing_fixture_names: [],
    },
  ],
};

describe("diffAgainstBaseline", () => {
  it("is green when coverage exactly holds", () => {
    const live = report([
      row({ assurance_row_id: "1", fixtures_passed: 3, coverage_state: "covered" }),
      row({ assurance_row_id: "2", fixtures_passed: 0, coverage_state: "no_fixture" }),
    ]);
    expect(diffAgainstBaseline(live, BASELINE)).toEqual([]);
  });

  it("is green when coverage IMPROVES (more passing fixtures, a row gains coverage)", () => {
    const live = report([
      row({ assurance_row_id: "1", fixtures_passed: 5, coverage_state: "covered" }),
      row({ assurance_row_id: "2", fixtures_passed: 2, coverage_state: "covered" }),
    ]);
    expect(diffAgainstBaseline(live, BASELINE)).toEqual([]);
  });

  it("is green for a brand-new row not in the baseline", () => {
    const live = report([
      row({ assurance_row_id: "1", fixtures_passed: 3, coverage_state: "covered" }),
      row({ assurance_row_id: "2", fixtures_passed: 0, coverage_state: "no_fixture" }),
      row({ assurance_row_id: "99", fixtures_passed: 1, coverage_state: "covered" }),
    ]);
    expect(diffAgainstBaseline(live, BASELINE)).toEqual([]);
  });

  it("REDS when a baselined row is dropped entirely", () => {
    const live = report([
      row({ assurance_row_id: "2", fixtures_passed: 0, coverage_state: "no_fixture" }),
    ]);
    const v = diffAgainstBaseline(live, BASELINE);
    expect(v).toHaveLength(1);
    expect(v[0]!.kind).toBe("row_dropped");
    expect(v[0]!.row_id).toBe("1");
  });

  it("REDS when passing fixtures decrease for a row", () => {
    const live = report([
      row({ assurance_row_id: "1", fixtures_passed: 2, coverage_state: "covered" }),
      row({ assurance_row_id: "2", fixtures_passed: 0, coverage_state: "no_fixture" }),
    ]);
    const v = diffAgainstBaseline(live, BASELINE);
    expect(v.map((x) => x.kind)).toContain("fixtures_passed_decreased");
  });

  it("REDS when coverage_state regresses (covered -> partial)", () => {
    const live = report([
      // keep fixtures_passed flat so only the state regression fires
      row({ assurance_row_id: "1", fixtures_passed: 3, coverage_state: "partial" }),
      row({ assurance_row_id: "2", fixtures_passed: 0, coverage_state: "no_fixture" }),
    ]);
    const v = diffAgainstBaseline(live, BASELINE);
    expect(v.map((x) => x.kind)).toContain("coverage_state_regressed");
  });

  it("REDS when a fixture is now failing (even if counts otherwise hold)", () => {
    const live = report([
      row({ assurance_row_id: "1", fixtures_passed: 3, fixtures_run: 4, fixtures_failed: 1, coverage_state: "partial" }),
      row({ assurance_row_id: "2", fixtures_passed: 0, coverage_state: "no_fixture" }),
    ]);
    const v = diffAgainstBaseline(live, BASELINE);
    expect(v.map((x) => x.kind)).toContain("fixture_now_failing");
  });

  it("REDS on a SAME-COUNT fixture swap (delete a high-value fixture, add a trivial one)", () => {
    // Codex MED finding: count + state are unchanged (still 3 passing, covered),
    // but a baselined passing fixture (f1) was removed and replaced by a new one
    // (f9). The fixture-identity ratchet must catch this.
    const live = report([
      {
        assurance_row_id: "1",
        label: "row 1",
        assurance_status: "proven",
        fixtures: [
          { name: "f0", passed: true, durationMs: 0 },
          { name: "f2", passed: true, durationMs: 0 },
          { name: "f9", passed: true, durationMs: 0 }, // swapped in for f1
        ],
        fixtures_run: 3,
        fixtures_passed: 3,
        fixtures_failed: 0,
        coverage_state: "covered",
      },
      row({ assurance_row_id: "2", fixtures_passed: 0, coverage_state: "no_fixture" }),
    ]);
    const v = diffAgainstBaseline(live, BASELINE);
    const removed = v.find((x) => x.kind === "passing_fixture_removed");
    expect(removed, "expected a passing_fixture_removed violation").toBeDefined();
    expect(removed!.detail).toContain("f1");
    // count + state held, so ONLY the identity ratchet should have fired.
    expect(v.map((x) => x.kind)).toEqual(["passing_fixture_removed"]);
  });
});
