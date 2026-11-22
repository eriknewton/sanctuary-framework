/**
 * Assurance matrix guard: the `proven` / `proven (tests)` status split.
 *
 * A bare `proven` in ASSURANCE_MATRIX.md tells a reader the shipped product was
 * run on a real machine. A row whose proof is tests, pull requests or source
 * links alone reads `proven (tests)`. scripts/check-assurance-matrix.mjs holds
 * that line in three ways, and each is witnessed here against a fixture matrix
 * in a temporary tree (the guard resolves the matrix from its own location, so
 * a copy of the script beside a fixture matrix checks the fixture, never the
 * real file):
 *
 *   - a bare `proven` row with no drill evidence is refused, enforcement claim
 *     or not;
 *   - `proven (tests)` is still a proven claim, so an enforcement claim can
 *     never carry it, even with a drill link in the cell;
 *   - `proven (tests)` on an ordinary claim, and a bare `proven` row that cites
 *     a drill, both pass.
 *
 * The last case runs the guard on the committed matrix itself.
 */

import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { spawnSync } from "node:child_process";
import { copyFileSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

// server/test/structure/<file> -> repo root is four levels up.
const REPO_ROOT = join(fileURLToPath(import.meta.url), "..", "..", "..", "..");
const GUARD_REL = join("scripts", "check-assurance-matrix.mjs");

const HEADER = [
  "# Fixture matrix",
  "",
  "Status enum: `proven`, `proven (tests)`, `partial`, `manual`, `not_implemented`, `planned`, `in_flight`, `unknown`.",
  "",
  "| Claim | Platform | Status | Evidence | Known Gap | Next Proof Needed |",
  "|---|---|---|---|---|---|",
];

const TEST_LINK = "[server/test/example.test.ts](server/test/example.test.ts)";
const DRILL_LINK = "[docs/audit/example-drill-2026-11-22.md](docs/audit/example-drill-2026-11-22.md)";

function row(claim: string, status: string, evidence: string): string {
  return `| ${claim} | Cross-platform server | ${status} | ${evidence} | gap | next |`;
}

describe("assurance matrix guard: proven and proven (tests)", () => {
  let tree: string;

  beforeEach(() => {
    tree = mkdtempSync(join(tmpdir(), "assurance-guard-"));
    mkdirSync(join(tree, "scripts"), { recursive: true });
    mkdirSync(join(tree, "server", "test"), { recursive: true });
    mkdirSync(join(tree, "docs", "audit"), { recursive: true });
    copyFileSync(join(REPO_ROOT, GUARD_REL), join(tree, GUARD_REL));
    writeFileSync(join(tree, "server", "test", "example.test.ts"), "// fixture evidence target\n");
    writeFileSync(join(tree, "docs", "audit", "example-drill-2026-11-22.md"), "# fixture drill record\n");
  });

  afterEach(() => {
    rmSync(tree, { recursive: true, force: true });
  });

  function runGuard(rows: string[]) {
    writeFileSync(join(tree, "ASSURANCE_MATRIX.md"), [...HEADER, ...rows, ""].join("\n"));
    return spawnSync(process.execPath, [join(tree, GUARD_REL)], { cwd: tree, encoding: "utf8" });
  }

  it("refuses a bare proven ordinary claim that cites tests only", () => {
    const result = runGuard([row("State encryption", "proven", TEST_LINK)]);
    expect(result.status).toBe(1);
    expect(result.stderr).toContain("\"State encryption\"");
    expect(result.stderr).toContain("`proven (tests)`");
  });

  it("accepts proven (tests) on an ordinary claim that cites tests only", () => {
    const result = runGuard([row("State encryption", "proven (tests)", TEST_LINK)]);
    expect(result.stderr).toBe("");
    expect(result.status).toBe(0);
  });

  it("refuses proven (tests) on an enforcement claim even when a drill link is present", () => {
    const result = runGuard([row("Egress enforcement: Example", "proven (tests)", `${DRILL_LINK}; ${TEST_LINK}`)]);
    expect(result.status).toBe(1);
    expect(result.stderr).toContain("cannot be proven by tests");
  });

  it("refuses proven (tests) on an enforcement claim with tests only", () => {
    const result = runGuard([row("Egress enforcement: Example", "proven (tests)", TEST_LINK)]);
    expect(result.status).toBe(1);
    expect(result.stderr).toContain("cannot be proven by tests");
  });

  it("still refuses a bare proven enforcement claim with no drill", () => {
    const result = runGuard([row("Egress enforcement: Example", "proven", TEST_LINK)]);
    expect(result.status).toBe(1);
    expect(result.stderr).toContain("cites no drill evidence");
  });

  it("accepts a bare proven row that cites a docs/audit drill record or a dated drill", () => {
    const result = runGuard([
      row("Egress enforcement: Example", "proven", DRILL_LINK),
      row("Ordinary claim with dated prose", "proven", `${TEST_LINK}; drill 2026-11-22 on one host`),
    ]);
    expect(result.stderr).toBe("");
    expect(result.status).toBe(0);
  });

  it("passes on the committed matrix", () => {
    const result = spawnSync(process.execPath, [join(REPO_ROOT, GUARD_REL)], { cwd: REPO_ROOT, encoding: "utf8" });
    expect(result.stderr).toBe("");
    expect(result.status).toBe(0);
  });
});
