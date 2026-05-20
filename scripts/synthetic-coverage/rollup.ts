import type { CoverageReport, CoverageRow } from "./report.js";
import type { ParityReport } from "./parity.js";

export type { CoverageReport, ParityReport };

export interface GateArtifact {
  generated_at: string;
  sanctuary_sha: string;
  linux: CoverageReport;
  macos: CoverageReport;
  parity: ParityReport;
  claim_to_row: ClaimRowSummary[];
  gap_inventory: GapEntry[];
  version_matrix: VersionMatrixEntry[];
  gate_state: "gate_a_green" | "gate_a_red";
  gate_violations: GateViolation[];
}

export interface ClaimRowSummary {
  row_id: string;
  label: string;
  assurance_status: "proven" | "partial" | "planned" | "unknown";
  linux_fixtures: number;
  macos_fixtures: number;
  coverage_state_linux: string;
  coverage_state_macos: string;
}

export interface GapEntry {
  row_id: string;
  label: string;
  reason:
    | "proven_without_fixture"
    | "partial_fixture_only"
    | "documented_intentional_gap"
    | "planned_not_yet_covered";
  blocking_for_gate: boolean;
}

export interface VersionMatrixEntry {
  sanctuary_version: string;
  platform: "linux" | "macos";
  fixtures_run: number;
  fixtures_passed: number;
}

export interface GateViolation {
  row_id: string;
  label: string;
  kind: "proven_without_fixture" | "parity_divergence";
  detail: string;
}

type IndexedRows = Map<string, CoverageRow>;

function sortRowIds(rowIds: Iterable<string>): string[] {
  return Array.from(new Set(rowIds)).sort((left, right) => {
    const numericLeft = Number(left);
    const numericRight = Number(right);
    if (Number.isFinite(numericLeft) && Number.isFinite(numericRight)) {
      return numericLeft - numericRight;
    }
    return left.localeCompare(right);
  });
}

function indexRows(report: CoverageReport): IndexedRows {
  return new Map(report.rows.map((row) => [row.assurance_row_id, row]));
}

function rowLabel(rowId: string, linuxRows: IndexedRows, macosRows: IndexedRows): string {
  return linuxRows.get(rowId)?.label ?? macosRows.get(rowId)?.label ?? `Assurance row ${rowId}`;
}

function rowStatus(
  rowId: string,
  linuxRows: IndexedRows,
  macosRows: IndexedRows,
): ClaimRowSummary["assurance_status"] {
  return linuxRows.get(rowId)?.assurance_status ?? macosRows.get(rowId)?.assurance_status ?? "unknown";
}

function fixtureCount(row: CoverageRow | undefined): number {
  return row?.fixtures_run ?? 0;
}

function coverageState(row: CoverageRow | undefined): string {
  return row?.coverage_state ?? "missing";
}

function totalFixtures(report: CoverageReport, field: "fixtures_run" | "fixtures_passed"): number {
  return report.rows.reduce((total, row) => total + row[field], 0);
}

function buildClaimRows(linux: CoverageReport, macos: CoverageReport): ClaimRowSummary[] {
  const linuxRows = indexRows(linux);
  const macosRows = indexRows(macos);
  const rowIds = sortRowIds([...linuxRows.keys(), ...macosRows.keys()]);

  return rowIds.map((rowId) => {
    const linuxRow = linuxRows.get(rowId);
    const macosRow = macosRows.get(rowId);
    return {
      row_id: rowId,
      label: rowLabel(rowId, linuxRows, macosRows),
      assurance_status: rowStatus(rowId, linuxRows, macosRows),
      linux_fixtures: fixtureCount(linuxRow),
      macos_fixtures: fixtureCount(macosRow),
      coverage_state_linux: coverageState(linuxRow),
      coverage_state_macos: coverageState(macosRow),
    };
  });
}

function gapForRow(row: ClaimRowSummary): GapEntry | undefined {
  const missingFixture = row.linux_fixtures === 0 || row.macos_fixtures === 0;
  const documentedGap =
    row.coverage_state_linux === "documented_gap" || row.coverage_state_macos === "documented_gap";

  if (row.assurance_status === "proven" && missingFixture) {
    return {
      row_id: row.row_id,
      label: row.label,
      reason: "proven_without_fixture",
      blocking_for_gate: true,
    };
  }

  if (documentedGap) {
    return {
      row_id: row.row_id,
      label: row.label,
      reason: "documented_intentional_gap",
      blocking_for_gate: false,
    };
  }

  if (row.assurance_status === "partial" && missingFixture) {
    return {
      row_id: row.row_id,
      label: row.label,
      reason: "partial_fixture_only",
      blocking_for_gate: false,
    };
  }

  if (row.assurance_status === "planned" && missingFixture) {
    return {
      row_id: row.row_id,
      label: row.label,
      reason: "planned_not_yet_covered",
      blocking_for_gate: false,
    };
  }

  return undefined;
}

function buildProvenFixtureViolations(rows: ClaimRowSummary[]): GateViolation[] {
  return rows
    .filter(
      (row) => row.assurance_status === "proven" && (row.linux_fixtures === 0 || row.macos_fixtures === 0),
    )
    .map((row) => ({
      row_id: row.row_id,
      label: row.label,
      kind: "proven_without_fixture" as const,
      detail: `Proven row ${row.row_id} requires at least one fixture on Linux and macOS.`,
    }));
}

function buildParityViolations(
  parity: ParityReport,
  linuxRows: IndexedRows,
  macosRows: IndexedRows,
): GateViolation[] {
  if (parity.parity_state === "clean") {
    return [];
  }

  const diverged = parity.diverged_rows.map((row) => ({
    row_id: row.row_id,
    label: row.label,
    kind: "parity_divergence" as const,
    detail: `Parity diverged: Linux ${row.linux_state}, macOS ${row.macos_state}.`,
  }));

  const incomplete = parity.incomplete_rows.map((row) => ({
    row_id: row.row_id,
    label: rowLabel(row.row_id, linuxRows, macosRows),
    kind: "parity_divergence" as const,
    detail: `Parity incomplete: ${row.detail}`,
  }));

  return [...diverged, ...incomplete];
}

export function produceGateArtifact(
  linux: CoverageReport,
  macos: CoverageReport,
  parity: ParityReport,
): GateArtifact {
  const linuxRows = indexRows(linux);
  const macosRows = indexRows(macos);
  const claimRows = buildClaimRows(linux, macos);
  const gapInventory = claimRows
    .map((row) => gapForRow(row))
    .filter((row): row is GapEntry => row !== undefined);
  const gateViolations = [
    ...buildProvenFixtureViolations(claimRows),
    ...buildParityViolations(parity, linuxRows, macosRows),
  ];

  return {
    generated_at: new Date().toISOString(),
    sanctuary_sha:
      linux.sanctuary_sha === macos.sanctuary_sha ? linux.sanctuary_sha : `${linux.sanctuary_sha} / ${macos.sanctuary_sha}`,
    linux,
    macos,
    parity,
    claim_to_row: claimRows,
    gap_inventory: gapInventory,
    version_matrix: [
      {
        sanctuary_version: linux.sanctuary_sha,
        platform: "linux",
        fixtures_run: totalFixtures(linux, "fixtures_run"),
        fixtures_passed: totalFixtures(linux, "fixtures_passed"),
      },
      {
        sanctuary_version: macos.sanctuary_sha,
        platform: "macos",
        fixtures_run: totalFixtures(macos, "fixtures_run"),
        fixtures_passed: totalFixtures(macos, "fixtures_passed"),
      },
    ],
    gate_state: gateViolations.length === 0 ? "gate_a_green" : "gate_a_red",
    gate_violations: gateViolations,
  };
}

export function renderGateArtifactMarkdown(artifact: GateArtifact): string {
  const lines = [
    "## Synthetic Coverage Gate (a)",
    "",
    `- Generated: ${artifact.generated_at}`,
    `- Sanctuary SHA: ${artifact.sanctuary_sha}`,
    `- Gate state: ${artifact.gate_state}`,
    `- Violations: ${artifact.gate_violations.length}`,
    `- Linux fixtures: ${artifact.version_matrix[0]?.fixtures_run ?? 0} run, ${artifact.version_matrix[0]?.fixtures_passed ?? 0} passed`,
    `- macOS fixtures: ${artifact.version_matrix[1]?.fixtures_run ?? 0} run, ${artifact.version_matrix[1]?.fixtures_passed ?? 0} passed`,
    `- Parity state: ${artifact.parity.parity_state}`,
    "",
    "### Gate Violations",
    "",
  ];

  if (artifact.gate_violations.length === 0) {
    lines.push("No gate violations.");
  } else {
    lines.push("| row_id | label | kind | detail |", "|---|---|---|---|");
    for (const violation of artifact.gate_violations) {
      lines.push(`| ${violation.row_id} | ${violation.label} | ${violation.kind} | ${violation.detail} |`);
    }
  }

  lines.push(
    "",
    "### Claim To Row",
    "",
    "| row_id | label | assurance | linux_fixtures | macos_fixtures | linux_state | macos_state |",
    "|---|---|---|---:|---:|---|---|",
  );

  for (const row of artifact.claim_to_row) {
    lines.push(
      `| ${row.row_id} | ${row.label} | ${row.assurance_status} | ${row.linux_fixtures} | ${row.macos_fixtures} | ${row.coverage_state_linux} | ${row.coverage_state_macos} |`,
    );
  }

  lines.push(
    "",
    "### Gap Inventory",
    "",
    "| row_id | label | reason | blocking_for_gate |",
    "|---|---|---|---|",
  );

  if (artifact.gap_inventory.length === 0) {
    lines.push("| all | No gaps | none | false |");
  } else {
    for (const gap of artifact.gap_inventory) {
      lines.push(`| ${gap.row_id} | ${gap.label} | ${gap.reason} | ${gap.blocking_for_gate} |`);
    }
  }

  return `${lines.join("\n")}\n`;
}
