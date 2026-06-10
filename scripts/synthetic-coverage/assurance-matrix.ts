import { existsSync, readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";

export type AssuranceStatus = "proven" | "partial" | "planned" | "unknown";

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
  if (status === "proven" || status === "partial" || status === "planned") {
    return status;
  }
  return "unknown";
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

  if (rows.length !== 21) {
    throw new Error(`Expected 21 assurance rows in ${matrixPath}, found ${rows.length}`);
  }

  return rows;
}
