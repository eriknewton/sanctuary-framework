import type { CoverageReport, CoverageRow } from "./report.js";

export type { CoverageReport } from "./report.js";

export type ParityCoverageState = "covered" | "partial" | "no_fixture" | "documented_gap";

export interface ParityReport {
  generated_at: string;
  linux_sha: string;
  macos_sha: string;
  parity_state: "clean" | "diverged" | "incomplete";
  diverged_rows: ParityRowDivergence[];
  incomplete_rows: ParityRowIncomplete[];
  summary: {
    total_rows_compared: number;
    rows_in_parity: number;
    rows_diverged: number;
    rows_incomplete: number;
  };
}

export interface ParityRowDivergence {
  row_id: string;
  label: string;
  linux_state: ParityCoverageState;
  macos_state: ParityCoverageState;
  diverged_fixtures: Array<{
    fixture_name: string;
    linux_passed: boolean;
    macos_passed: boolean;
  }>;
}

export interface ParityRowIncomplete {
  row_id: string;
  reason: "missing_on_linux" | "missing_on_macos" | "fixture_present_only_on_one_platform";
  detail: string;
}

interface IndexedFixture {
  name: string;
  passed: boolean;
}

function indexRows(report: CoverageReport): Map<string, CoverageRow> {
  return new Map(report.rows.map((row) => [row.assurance_row_id, row]));
}

function indexFixtures(row: CoverageRow): Map<string, IndexedFixture> {
  return new Map((row.fixtures ?? []).map((fixture) => [fixture.name, fixture]));
}

function sortedUnion(left: Iterable<string>, right: Iterable<string>): string[] {
  return Array.from(new Set([...left, ...right])).sort((a, b) => {
    const numericA = Number(a);
    const numericB = Number(b);
    if (Number.isFinite(numericA) && Number.isFinite(numericB)) {
      return numericA - numericB;
    }
    return a.localeCompare(b);
  });
}

function stateFor(row: CoverageRow): ParityCoverageState {
  return row.coverage_state;
}

export function compareReports(linux: CoverageReport, macos: CoverageReport): ParityReport {
  const linuxRows = indexRows(linux);
  const macosRows = indexRows(macos);
  const rowIds = sortedUnion(linuxRows.keys(), macosRows.keys());
  const divergedRows: ParityRowDivergence[] = [];
  const incompleteRows: ParityRowIncomplete[] = [];

  for (const rowId of rowIds) {
    const linuxRow = linuxRows.get(rowId);
    const macosRow = macosRows.get(rowId);

    if (!linuxRow) {
      incompleteRows.push({
        row_id: rowId,
        reason: "missing_on_linux",
        detail: `Row ${rowId} exists in macOS report only.`,
      });
      continue;
    }

    if (!macosRow) {
      incompleteRows.push({
        row_id: rowId,
        reason: "missing_on_macos",
        detail: `Row ${rowId} exists in Linux report only.`,
      });
      continue;
    }

    const linuxFixtures = indexFixtures(linuxRow);
    const macosFixtures = indexFixtures(macosRow);
    const fixtureNames = sortedUnion(linuxFixtures.keys(), macosFixtures.keys());
    const missingFixtureNames = fixtureNames.filter(
      (name) => !linuxFixtures.has(name) || !macosFixtures.has(name),
    );

    if (missingFixtureNames.length > 0) {
      incompleteRows.push({
        row_id: rowId,
        reason: "fixture_present_only_on_one_platform",
        detail: missingFixtureNames
          .map((name) => {
            if (!linuxFixtures.has(name)) {
              return `${name} missing on Linux`;
            }
            return `${name} missing on macOS`;
          })
          .join("; "),
      });
      continue;
    }

    const divergedFixtures = fixtureNames
      .map((fixtureName) => {
        const linuxFixture = linuxFixtures.get(fixtureName)!;
        const macosFixture = macosFixtures.get(fixtureName)!;
        if (linuxFixture.passed === macosFixture.passed) {
          return undefined;
        }
        return {
          fixture_name: fixtureName,
          linux_passed: linuxFixture.passed,
          macos_passed: macosFixture.passed,
        };
      })
      .filter((fixture): fixture is NonNullable<typeof fixture> => fixture !== undefined);

    if (divergedFixtures.length > 0 || linuxRow.coverage_state !== macosRow.coverage_state) {
      divergedRows.push({
        row_id: rowId,
        label: linuxRow.label,
        linux_state: stateFor(linuxRow),
        macos_state: stateFor(macosRow),
        diverged_fixtures: divergedFixtures,
      });
    }
  }

  const parityState =
    incompleteRows.length > 0 ? "incomplete" : divergedRows.length > 0 ? "diverged" : "clean";

  return {
    generated_at: new Date().toISOString(),
    linux_sha: linux.sanctuary_sha,
    macos_sha: macos.sanctuary_sha,
    parity_state: parityState,
    diverged_rows: divergedRows,
    incomplete_rows: incompleteRows,
    summary: {
      total_rows_compared: rowIds.length,
      rows_in_parity: rowIds.length - divergedRows.length - incompleteRows.length,
      rows_diverged: divergedRows.length,
      rows_incomplete: incompleteRows.length,
    },
  };
}

export function renderParityMarkdown(report: ParityReport): string {
  const lines = [
    "## Synthetic Coverage Parity",
    "",
    `- Generated: ${report.generated_at}`,
    `- Linux SHA: ${report.linux_sha}`,
    `- macOS SHA: ${report.macos_sha}`,
    `- Parity state: ${report.parity_state}`,
    `- Rows compared: ${report.summary.total_rows_compared}`,
    `- Rows in parity: ${report.summary.rows_in_parity}`,
    `- Rows diverged: ${report.summary.rows_diverged}`,
    `- Rows incomplete: ${report.summary.rows_incomplete}`,
    "",
    "| row_id | label | linux_state | macos_state | parity_state |",
    "|---|---|---|---|---|",
  ];

  if (report.diverged_rows.length === 0 && report.incomplete_rows.length === 0) {
    lines.push("| all | All compared rows | clean | clean | clean |");
  }

  for (const row of report.diverged_rows) {
    lines.push(
      `| ${row.row_id} | ${row.label} | ${row.linux_state} | ${row.macos_state} | diverged |`,
    );
  }

  for (const row of report.incomplete_rows) {
    lines.push(`| ${row.row_id} | ${row.detail} | incomplete | incomplete | ${row.reason} |`);
  }

  return `${lines.join("\n")}\n`;
}
