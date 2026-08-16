/**
 * Synthetic-coverage PR ratchet (DoE H-3).
 *
 * The release-tag gate (`synthetic-coverage:gate-a`, rollup-cli.ts) is a HARD
 * gate only on `refs/tags/v*`; on PR/push it runs INFORMATIONAL (it `exit 0`s
 * even on a red gate state). That left a hole: synthetic coverage could silently
 * REGRESS onto main between releases. This module closes that hole with a
 * fail-on-drop ratchet, mirroring the repo's `.test-baseline` and import-cycle
 * baselines:
 *
 *   - the committed baseline (coverage-baseline.json) freezes the CURRENT
 *     per-row coverage snapshot (assurance status, passing-fixture count,
 *     coverage state);
 *   - a change that REDUCES coverage for any row (a dropped row, fewer passing
 *     fixtures, a regressed coverage_state, or a newly-FAILING fixture) reds the
 *     ratchet test in `server/test/structure/`, which runs inside `npm test` and
 *     so bites on every PR and push via the already-required `test` /
 *     `test-baseline-guard` checks — no CI YAML informational-bypass involved;
 *   - IMPROVING coverage (more passing fixtures, a row gaining coverage, a brand
 *     new row) is always allowed and does NOT require a baseline edit; the
 *     ratchet is a directional floor, not a high-water mark that must be bumped
 *     on every gain.
 *
 * The baseline is the in-tree representation of the base-commit coverage, so
 * "fail if coverage drops vs the base commit" is enforced deterministically and
 * locally-provably (same as how `.test-baseline` represents the base passing
 * count). An INTENTIONAL coverage reduction (e.g. retiring a claim) is landed by
 * regenerating the baseline IN THE SAME PR via the sanctioned generator
 * (gen-coverage-baseline.ts) — a visible, reviewable diff, exactly like the
 * import-cycle baseline regen.
 *
 * This is platform-agnostic: the synthetic fixtures are deterministic in-process
 * models (no OS-specific egress shell-outs), so the snapshot is identical on
 * Linux and macOS. If a fixture is ever made genuinely platform-conditional, the
 * floor semantics (>=, never ==) keep a platform that runs FEWER fixtures from
 * false-redding — but it would also let that platform hide a drop, so prefer
 * keeping fixtures platform-agnostic.
 */

import type { CoverageReport, CoverageRow } from "./report.js";

/** Coverage states ordered worst -> best; a move to a LOWER rank is a regression. */
const COVERAGE_RANK: Record<CoverageRow["coverage_state"], number> = {
  not_implemented: 0,
  no_fixture: 1,
  documented_gap: 2,
  partial: 3,
  covered: 4,
};

export interface CoverageBaselineRow {
  assurance_row_id: string;
  label: string;
  assurance_status: CoverageRow["assurance_status"];
  fixtures_passed: number;
  coverage_state: CoverageRow["coverage_state"];
  /**
   * Sorted names of the PASSING fixtures for this row. Recorded so a same-count
   * swap (delete a high-value passing fixture, add a trivial one — count + state
   * unchanged) is still caught as a regression (codex MED finding on the DoE H-3
   * build). A passing fixture present in the baseline but absent (removed or
   * renamed) in the live report reds, unless the baseline is regenerated in-PR.
   */
  passing_fixture_names: string[];
}

export interface CoverageBaseline {
  /** Free-text provenance for human readers; not used in comparison. */
  _comment?: string | string[];
  rows: CoverageBaselineRow[];
}

export interface RatchetViolation {
  row_id: string;
  label: string;
  kind:
    | "row_dropped"
    | "fixtures_passed_decreased"
    | "coverage_state_regressed"
    | "fixture_now_failing"
    | "passing_fixture_removed";
  detail: string;
}

/** Sorted names of the PASSING fixtures in a coverage row. */
function passingFixtureNames(row: CoverageRow): string[] {
  if (row.coverage_state === "not_implemented") {
    return [];
  }
  return row.fixtures
    .filter((fixture) => fixture.passed)
    .map((fixture) => fixture.name)
    .sort();
}

/** Project a live report into the committed-baseline shape (the snapshot we freeze). */
export function snapshotFromReport(report: CoverageReport): CoverageBaseline {
  return {
    rows: report.rows
      .map((row) => ({
        assurance_row_id: row.assurance_row_id,
        label: row.label,
        assurance_status: row.assurance_status,
        fixtures_passed: row.fixtures_passed,
        coverage_state: row.coverage_state,
        passing_fixture_names: passingFixtureNames(row),
      }))
      .sort((a, b) => compareRowIds(a.assurance_row_id, b.assurance_row_id)),
  };
}

function compareRowIds(a: string, b: string): number {
  const na = Number(a);
  const nb = Number(b);
  if (Number.isFinite(na) && Number.isFinite(nb)) return na - nb;
  return a.localeCompare(b);
}

/**
 * Compare a live report against the committed baseline and return every
 * coverage REGRESSION. An empty array means coverage held or improved.
 */
export function diffAgainstBaseline(
  report: CoverageReport,
  baseline: CoverageBaseline,
): RatchetViolation[] {
  const live = new Map(report.rows.map((row) => [row.assurance_row_id, row]));
  const violations: RatchetViolation[] = [];

  for (const base of baseline.rows) {
    const current = live.get(base.assurance_row_id);

    // A baselined row that is no longer present at all is the clearest drop.
    if (!current) {
      violations.push({
        row_id: base.assurance_row_id,
        label: base.label,
        kind: "row_dropped",
        detail: `Row ${base.assurance_row_id} ("${base.label}") was in the coverage baseline but is absent from the live report.`,
      });
      continue;
    }

    if (current.fixtures_passed < base.fixtures_passed) {
      violations.push({
        row_id: base.assurance_row_id,
        label: base.label,
        kind: "fixtures_passed_decreased",
        detail: `Row ${base.assurance_row_id}: passing fixtures dropped ${base.fixtures_passed} -> ${current.fixtures_passed}.`,
      });
    }

    if (COVERAGE_RANK[current.coverage_state] < COVERAGE_RANK[base.coverage_state]) {
      violations.push({
        row_id: base.assurance_row_id,
        label: base.label,
        kind: "coverage_state_regressed",
        detail: `Row ${base.assurance_row_id}: coverage_state regressed ${base.coverage_state} -> ${current.coverage_state}.`,
      });
    }

    // Fixture IDENTITY ratchet: a baselined PASSING fixture that is no longer
    // present-and-passing in the live report is a coverage drop, even if the
    // per-row COUNT held flat (delete a high-value passing fixture, add a
    // trivial one). Catches the same-count swap the count check alone misses.
    // A baseline with no recorded names (older format) skips this check.
    if (base.passing_fixture_names && base.passing_fixture_names.length > 0) {
      const livePassing = new Set(
        current.fixtures.filter((f) => f.passed).map((f) => f.name),
      );
      const removed = base.passing_fixture_names.filter((name) => !livePassing.has(name));
      if (removed.length > 0) {
        violations.push({
          row_id: base.assurance_row_id,
          label: base.label,
          kind: "passing_fixture_removed",
          detail: `Row ${base.assurance_row_id}: baselined passing fixture(s) no longer present-and-passing: ${removed.join(", ")}.`,
        });
      }
    }
  }

  // A newly-failing fixture is a coverage drop regardless of the baseline (a
  // fixture that used to pass and now fails). This also catches a regression in
  // a row that did not exist in the baseline yet (defense in depth).
  for (const row of report.rows) {
    if (row.fixtures_failed > 0) {
      violations.push({
        row_id: row.assurance_row_id,
        label: row.label,
        kind: "fixture_now_failing",
        detail: `Row ${row.assurance_row_id}: ${row.fixtures_failed} fixture(s) failing in the live report.`,
      });
    }
  }

  return violations.sort(
    (a, b) => compareRowIds(a.row_id, b.row_id) || a.kind.localeCompare(b.kind),
  );
}
