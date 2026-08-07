import { loadAssuranceMatrix, type AssuranceStatus } from "./assurance-matrix.js";
import { listClaims } from "./registry.js";

export interface CoverageReport {
  generated_at: string;
  sanctuary_sha: string;
  platform: "linux" | "macos";
  rows: CoverageRow[];
  summary: {
    total_rows: number;
    rows_with_fixtures: number;
    rows_no_fixture: number;
    rows_not_implemented: number;
    rows_failing: number;
  };
}

export type CoverageState =
  | "not_implemented"
  | "no_fixture"
  | "documented_gap"
  | "partial"
  | "covered";

export interface CoverageRow {
  assurance_row_id: string;
  label: string;
  assurance_status: AssuranceStatus;
  fixtures: CoverageFixtureOutcome[];
  fixtures_run: number;
  fixtures_passed: number;
  fixtures_failed: number;
  coverage_state: CoverageState;
}

export interface CoverageFixtureOutcome {
  name: string;
  passed: boolean;
  message?: string;
  durationMs: number;
}

export async function buildReport(opts: {
  platform: "linux" | "macos";
  sha: string;
}): Promise<CoverageReport> {
  const assuranceRows = loadAssuranceMatrix();
  const registeredClaims = new Map(listClaims().map((claim) => [claim.id, claim]));
  const rows: CoverageRow[] = [];

  for (const assuranceRow of assuranceRows) {
    const claim = registeredClaims.get(assuranceRow.id);
    const outcomes: CoverageFixtureOutcome[] = [];

    for (const fixture of claim?.fixtures ?? []) {
      const outcome = await fixture.fn();
      outcomes.push({
        name: fixture.name,
        passed: outcome.passed,
        message: outcome.message,
        durationMs: outcome.durationMs,
      });
    }

    const isNotImplemented = assuranceRow.status === "not_implemented";
    const reportedOutcomes = isNotImplemented ? [] : outcomes;
    const fixturesRun = reportedOutcomes.length;
    const fixturesFailed = reportedOutcomes.filter((outcome) => !outcome.passed).length;
    const fixturesPassed = fixturesRun - fixturesFailed;

    rows.push({
      assurance_row_id: assuranceRow.id,
      label: assuranceRow.label,
      assurance_status: assuranceRow.status,
      fixtures: reportedOutcomes,
      fixtures_run: fixturesRun,
      fixtures_passed: fixturesPassed,
      fixtures_failed: fixturesFailed,
      coverage_state:
        isNotImplemented
          ? "not_implemented"
          : fixturesRun === 0
            ? "no_fixture"
            : fixturesFailed === 0
              ? "covered"
              : "partial",
    });
  }

  return {
    generated_at: new Date().toISOString(),
    sanctuary_sha: opts.sha,
    platform: opts.platform,
    rows,
    summary: {
      total_rows: rows.length,
      rows_with_fixtures: rows.filter((row) => row.fixtures_run > 0).length,
      rows_no_fixture: rows.filter((row) => row.coverage_state === "no_fixture").length,
      rows_not_implemented: rows.filter((row) => row.coverage_state === "not_implemented").length,
      rows_failing: rows.filter((row) => row.fixtures_failed > 0).length,
    },
  };
}

export function renderMarkdownSummary(report: CoverageReport): string {
  const lines = [
    `## Synthetic Coverage (${report.platform})`,
    "",
    `- Generated: ${report.generated_at}`,
    `- SHA: ${report.sanctuary_sha}`,
    `- Total rows: ${report.summary.total_rows}`,
    `- Rows with fixtures: ${report.summary.rows_with_fixtures}`,
    `- Rows without fixtures: ${report.summary.rows_no_fixture}`,
    `- Rows not implemented: ${report.summary.rows_not_implemented}`,
    `- Rows failing: ${report.summary.rows_failing}`,
    "",
    "| ID | Claim | Assurance | Fixtures | State |",
    "|---|---|---|---:|---|",
  ];

  for (const row of report.rows) {
    lines.push(
      `| ${row.assurance_row_id} | ${row.label} | ${row.assurance_status} | ${row.fixtures_run} | ${row.coverage_state} |`,
    );
  }

  return `${lines.join("\n")}\n`;
}
