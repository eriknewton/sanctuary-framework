import { describe, expect, it } from "vitest";
import { produceGateArtifact } from "../rollup.js";
import type { CoverageReport, CoverageRow } from "../report.js";
import type { ParityReport } from "../parity.js";

type RowStatus = CoverageRow["assurance_status"];

function row(opts: {
  id: string;
  label?: string;
  status?: RowStatus;
  fixturesRun?: number;
  fixturesPassed?: number;
  coverageState?: CoverageRow["coverage_state"];
}): CoverageRow {
  const fixturesRun = opts.fixturesRun ?? 1;
  const fixturesPassed = opts.fixturesPassed ?? fixturesRun;
  const fixturesFailed = fixturesRun - fixturesPassed;
  return {
    assurance_row_id: opts.id,
    label: opts.label ?? `Row ${opts.id}`,
    assurance_status: opts.status ?? "proven",
    fixtures: Array.from({ length: fixturesRun }, (_, index) => ({
      name: `fixture-${opts.id}-${index}`,
      passed: index < fixturesPassed,
      durationMs: 0,
    })),
    fixtures_run: fixturesRun,
    fixtures_passed: fixturesPassed,
    fixtures_failed: fixturesFailed,
    coverage_state:
      opts.coverageState ??
      (fixturesRun === 0 ? "no_fixture" : fixturesFailed === 0 ? "covered" : "partial"),
  };
}

function report(platform: CoverageReport["platform"], rows: CoverageRow[]): CoverageReport {
  return {
    generated_at: "2026-05-19T00:00:00.000Z",
    sanctuary_sha: "test-sha",
    platform,
    rows,
    summary: {
      total_rows: rows.length,
      rows_with_fixtures: rows.filter((coverageRow) => coverageRow.fixtures_run > 0).length,
      rows_no_fixture: rows.filter((coverageRow) => coverageRow.fixtures_run === 0).length,
      rows_failing: rows.filter((coverageRow) => coverageRow.fixtures_failed > 0).length,
    },
  };
}

function cleanParity(): ParityReport {
  return {
    generated_at: "2026-05-19T00:00:00.000Z",
    linux_sha: "test-sha",
    macos_sha: "test-sha",
    parity_state: "clean",
    diverged_rows: [],
    incomplete_rows: [],
    summary: {
      total_rows_compared: 1,
      rows_in_parity: 1,
      rows_diverged: 0,
      rows_incomplete: 0,
    },
  };
}

describe("synthetic coverage gate rollup", () => {
  it("marks all proven rows with fixtures and clean parity as gate_a_green", () => {
    const linux = report("linux", [row({ id: "1" })]);
    const macos = report("macos", [row({ id: "1" })]);

    const artifact = produceGateArtifact(linux, macos, cleanParity());

    expect(artifact.gate_state).toBe("gate_a_green");
    expect(artifact.gate_violations).toHaveLength(0);
    expect(artifact.claim_to_row[0]).toMatchObject({
      row_id: "1",
      linux_fixtures: 1,
      macos_fixtures: 1,
    });
  });

  it("marks one proven row without a fixture as gate_a_red", () => {
    const linux = report("linux", [row({ id: "1", fixturesRun: 0 })]);
    const macos = report("macos", [row({ id: "1" })]);

    const artifact = produceGateArtifact(linux, macos, cleanParity());

    expect(artifact.gate_state).toBe("gate_a_red");
    expect(artifact.gate_violations).toEqual([
      {
        row_id: "1",
        label: "Row 1",
        kind: "proven_without_fixture",
        detail: "Proven row 1 requires at least one fixture on Linux and macOS.",
      },
    ]);
  });

  it("marks parity divergence as gate_a_red", () => {
    const linux = report("linux", [row({ id: "1" })]);
    const macos = report("macos", [row({ id: "1", fixturesPassed: 0 })]);
    const parity: ParityReport = {
      ...cleanParity(),
      parity_state: "diverged",
      diverged_rows: [
        {
          row_id: "1",
          label: "Row 1",
          linux_state: "covered",
          macos_state: "partial",
          diverged_fixtures: [
            {
              fixture_name: "fixture-1-0",
              linux_passed: true,
              macos_passed: false,
            },
          ],
        },
      ],
      summary: {
        total_rows_compared: 1,
        rows_in_parity: 0,
        rows_diverged: 1,
        rows_incomplete: 0,
      },
    };

    const artifact = produceGateArtifact(linux, macos, parity);

    expect(artifact.gate_state).toBe("gate_a_red");
    expect(artifact.gate_violations).toContainEqual({
      row_id: "1",
      label: "Row 1",
      kind: "parity_divergence",
      detail: "Parity diverged: Linux covered, macOS partial.",
    });
  });

  it("does not mark a planned row without fixtures as a gate violation", () => {
    const linux = report("linux", [row({ id: "1", status: "planned", fixturesRun: 0 })]);
    const macos = report("macos", [row({ id: "1", status: "planned", fixturesRun: 0 })]);

    const artifact = produceGateArtifact(linux, macos, cleanParity());

    expect(artifact.gate_state).toBe("gate_a_green");
    expect(artifact.gate_violations).toHaveLength(0);
    expect(artifact.gap_inventory).toEqual([
      {
        row_id: "1",
        label: "Row 1",
        reason: "planned_not_yet_covered",
        blocking_for_gate: false,
      },
    ]);
  });
});
