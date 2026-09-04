import { existsSync, readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";

/**
 * The status tokens a matrix row may carry. Must match the "Status enum" line in
 * `ASSURANCE_MATRIX.md` (currently line 5); `unknown` doubles as the parser's
 * fallback for a token that is not in that enum at all.
 *
 * Every enum member is listed here on purpose. A member that is missing from
 * this union does NOT fail the parse: `normalizeStatus` silently downgrades it
 * to `unknown`, so an honest `not_implemented` row would read as an unparsed
 * row, and the two are not the same claim. Adding a token to the matrix enum
 * without adding it here is the failure mode this comment exists to prevent.
 */
export type AssuranceStatus =
  | "proven"
  | "partial"
  | "manual"
  | "not_implemented"
  | "planned"
  | "in_flight"
  | "unknown";

/** Recognized status tokens, mirroring the `ASSURANCE_MATRIX.md` status enum. */
const KNOWN_STATUSES: readonly AssuranceStatus[] = [
  "proven",
  "partial",
  "manual",
  "not_implemented",
  "planned",
  "in_flight",
  "unknown",
];
// 26 = the 23 rows pinned when this harness landed plus the three rows appended
// 2026-09-03 (Rung 1 memory custody, catalog v3 verification, fleet licensing).
// Rows are appended at the END of the table so fixture row IDs stay stable.
export const EXPECTED_ASSURANCE_ROW_COUNT = 26;

export interface AssuranceRow {
  id: string;
  label: string;
  status: AssuranceStatus;
}

function findRepoRoot(start = process.cwd()): string {
  let current = resolve(start);

  while (true) {
    if (existsSync(resolve(current, "ASSURANCE_MATRIX.md"))) {
      return current;
    }

    const parent = dirname(current);
    if (parent === current) {
      throw new Error(`Unable to locate ASSURANCE_MATRIX.md from ${start}`);
    }
    current = parent;
  }
}

function normalizeStatus(status: string): AssuranceStatus {
  // An unrecognized token becomes `unknown` rather than throwing, so a typo in
  // the matrix degrades the report instead of breaking the whole pipeline. That
  // leniency is why KNOWN_STATUSES must stay in lockstep with the matrix enum:
  // a real status the parser has never heard of is indistinguishable from a typo.
  return KNOWN_STATUSES.includes(status as AssuranceStatus)
    ? (status as AssuranceStatus)
    : "unknown";
}

function stripMarkdownLinks(value: string): string {
  return value.replace(/\[([^\]]+)\]\([^)]+\)/g, "$1").trim();
}

export function loadAssuranceMatrix(repoRoot = findRepoRoot()): AssuranceRow[] {
  const matrixPath = resolve(repoRoot, "ASSURANCE_MATRIX.md");
  const contents = readFileSync(matrixPath, "utf8");
  const rows: AssuranceRow[] = [];

  for (const line of contents.split(/\r?\n/)) {
    if (!line.startsWith("|") || line.includes("|---")) {
      continue;
    }

    const cells = line
      .slice(1, -1)
      .split("|")
      .map((cell) => cell.trim());

    if (cells.length < 6 || cells[0] === "Claim") {
      continue;
    }

    rows.push({
      id: String(rows.length + 1),
      label: stripMarkdownLinks(cells[0]),
      status: normalizeStatus(cells[2]),
    });
  }

  if (rows.length !== EXPECTED_ASSURANCE_ROW_COUNT) {
    throw new Error(
      `Expected ${EXPECTED_ASSURANCE_ROW_COUNT} assurance rows in ${matrixPath}, found ${rows.length}`,
    );
  }

  return rows;
}
