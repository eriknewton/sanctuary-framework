import { describe, expect, it } from "vitest";
import { compareReports, type CoverageReport } from "../parity.js";

function report(fixtures: Array<{ name: string; passed: boolean }>): CoverageReport {
  const fixturesFailed = fixtures.filter((fixture) => !fixture.passed).length;
  return {
    generated_at: "2026-05-19T00:00:00.000Z",
    sanctuary_sha: "test-sha",
    platform: "linux",
    rows: [
      {
        assurance_row_id: "4",
        label: "Substrate trust must be independently checkable",
        assurance_status: "fixture-backed",
        fixtures: fixtures.map((fixture) => ({
          ...fixture,
          durationMs: 0,
        })),
        fixtures_run: fixtures.length,
        fixtures_passed: fixtures.length - fixturesFailed,
        fixtures_failed: fixturesFailed,
        coverage_state:
          fixtures.length === 0 ? "no_fixture" : fixturesFailed === 0 ? "covered" : "partial",
      },
    ],
    summary: {
      total_rows: 1,
      rows_with_fixtures: fixtures.length > 0 ? 1 : 0,
      rows_no_fixture: fixtures.length > 0 ? 0 : 1,
      rows_failing: fixturesFailed > 0 ? 1 : 0,
    },
  };
}

describe("synthetic coverage parity", () => {
  it("marks identical reports as clean", () => {
    const linux = report([{ name: "fixture-a", passed: true }]);
    const macos = report([{ name: "fixture-a", passed: true }]);

    const parity = compareReports(linux, macos);

    expect(parity.parity_state).toBe("clean");
    expect(parity.summary.rows_in_parity).toBe(1);
    expect(parity.diverged_rows).toHaveLength(0);
    expect(parity.incomplete_rows).toHaveLength(0);
  });

  it("surfaces a fixture outcome divergence", () => {
    const linux = report([{ name: "fixture-a", passed: true }]);
    const macos = report([{ name: "fixture-a", passed: false }]);

    const parity = compareReports(linux, macos);

    expect(parity.parity_state).toBe("diverged");
    expect(parity.diverged_rows).toHaveLength(1);
    expect(parity.diverged_rows[0]?.diverged_fixtures).toEqual([
      {
        fixture_name: "fixture-a",
        linux_passed: true,
        macos_passed: false,
      },
    ]);
  });

  it("marks a fixture present on one platform as incomplete", () => {
    const linux = report([{ name: "fixture-a", passed: true }]);
    const macos = report([]);

    const parity = compareReports(linux, macos);

    expect(parity.parity_state).toBe("incomplete");
    expect(parity.incomplete_rows).toEqual([
      {
        row_id: "4",
        reason: "fixture_present_only_on_one_platform",
        detail: "fixture-a missing on macOS",
      },
    ]);
  });
});
