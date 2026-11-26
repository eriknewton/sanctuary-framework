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

/**
 * The evidence-qualified spelling of `proven` on the matrix's Status enum line.
 * A `proven (tests)` row is still a proven claim (its proof is tests, pull
 * requests or source links, with no captured drill), so it parses to `proven`
 * here: every check that keys on `proven`, including the ratchet rule that a
 * proven row must have passing fixtures, keeps applying to it. Reading it as an
 * unrecognized token would downgrade it to `unknown` and silently take those
 * rows out of that rule. Must match the `proven (tests)` value on the "Status
 * enum:" line of ASSURANCE_MATRIX.md and PROVEN_TESTS_STATUS in
 * scripts/check-assurance-matrix.mjs.
 */
export const PROVEN_TESTS_STATUS = "proven (tests)";

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
// 30 = the 23 rows pinned when this harness landed, plus the three rows appended
// 2026-09-03 (Rung 1 memory custody, catalog v3 verification, fleet licensing),
// plus the Rung 2 activation row (signed model manifest verified at provisioning),
// plus the credential surrogacy slice 1a row (row 28, `partial`, 2026-09-30),
// plus the zero-outbound drill row (row 29, `proven`, Linux 1.8.4 only, 2026-11-22),
// plus the release verification row (row 30, `partial`, 2026-11-25).
// Rows are appended at the END of the table so fixture row IDs stay stable.
// Must match the data-row count of the table in ASSURANCE_MATRIX.md.
export const EXPECTED_ASSURANCE_ROW_COUNT = 30;

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

export function normalizeStatus(status: string): AssuranceStatus {
  // An unrecognized token becomes `unknown` rather than throwing, so a typo in
  // the matrix degrades the report instead of breaking the whole pipeline. That
  // leniency is why KNOWN_STATUSES must stay in lockstep with the matrix enum:
  // a real status the parser has never heard of is indistinguishable from a typo.
  if (status === PROVEN_TESTS_STATUS) {
    return "proven";
  }
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
