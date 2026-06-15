/**
 * Synthetic-coverage PR ratchet guard (DoE H-3).
 *
 * The release-tag `gate-a` is a HARD gate only on `refs/tags/v*`; on PR/push the
 * coverage workflow runs INFORMATIONAL (it `exit 0`s even on a red gate state).
 * That left coverage able to silently REGRESS onto main between releases. This
 * test closes the hole: it runs inside `npm test` (and is in the vitest include
 * glob), so it bites on every PR and push via the already-required `test` /
 * `test-baseline-guard` checks — without touching the workflow's informational
 * bypass. The release-tag hard gate stays intact.
 *
 * It builds the live coverage report in-process from the SAME fixtures + builder
 * the runner uses, then fails if any row's coverage DROPPED versus the committed
 * `coverage-baseline.json` (a dropped row, fewer passing fixtures, a regressed
 * coverage_state, or a newly-failing fixture). Improvements pass without a
 * regen. An intentional, reviewed reduction is landed by regenerating the
 * baseline in the same PR (`npm run synthetic-coverage:baseline`) — a visible
 * diff, exactly like the import-cycle baseline regen.
 *
 * Mirrors the repo's directional-ratchet pattern (import-cycle-baseline.test.ts,
 * em-dash.test.ts): a committed baseline is the in-tree representation of the
 * base-commit coverage, so "fail if coverage drops vs the base commit" is
 * deterministic and locally provable.
 */

import { describe, expect, it } from "vitest";
import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

// Register the fixtures via the SINGLE source of truth shared with run.ts and
// the baseline generator, so the ratchet can never drift from the actual
// coverage-workflow fixture set (codex H finding: three copied import lists were
// a false-green vector). Importing run.ts directly would execute its main().
import "../register-all.js";
import { buildReport } from "../report.js";
import {
  diffAgainstBaseline,
  snapshotFromReport,
  type CoverageBaseline,
} from "../coverage-ratchet.js";

const HERE = dirname(fileURLToPath(import.meta.url));
const BASELINE_PATH = resolve(HERE, "..", "coverage-baseline.json");

function loadBaseline(): CoverageBaseline {
  return JSON.parse(readFileSync(BASELINE_PATH, "utf8")) as CoverageBaseline;
}

describe("synthetic-coverage PR ratchet", () => {
  it("the committed coverage baseline is non-trivial and well-formed", () => {
    const baseline = loadBaseline();
    // Sanity floor: a resolver/parse bug that empties the baseline must fail
    // loudly, not pass vacuously (same defensive design as the other guards).
    expect(baseline.rows.length).toBeGreaterThanOrEqual(20);
    for (const row of baseline.rows) {
      expect(row.assurance_row_id).toBeTruthy();
      expect(row.fixtures_passed).toBeGreaterThanOrEqual(0);
      // The fixture-identity ratchet only bites if names are recorded; a covered
      // row must carry at least one passing-fixture name.
      if (row.coverage_state === "covered") {
        expect(row.passing_fixture_names.length).toBeGreaterThan(0);
      }
    }
  });

  it("run.ts and the baseline generator register fixtures via the shared register-all (no drift)", () => {
    // Codex H finding: three copied fixture import lists were a false-green
    // vector. Assert at the source level that the runner and the generator BOTH
    // pull the fixture set from register-all.js, so the ratchet can never run a
    // stale list while the actual coverage workflow drops a fixture.
    //
    // Bypass-resistant (codex rounds 2-3): rather than match every import SYNTAX
    // variant (single/double/backtick quotes, static/dynamic, comment-separated),
    // we (a) strip comments first, then (b) reject ANY string literal in ANY quote
    // style whose text contains `fixtures/`. A fixture can only be registered via
    // a module specifier naming a path under fixtures/, and that specifier is
    // always a quoted/backticked string literal — so this catches the whole class
    // (`import "./fixtures/x.js"`, `import('./fixtures/x.js')`, `import(\`./fixtures/x.js\`)`,
    // `import/*c*/("./fixtures/x.js")`) without enumerating syntaxes.
    const stripComments = (s: string): string =>
      s.replace(/\/\*[\s\S]*?\*\//g, "").replace(/(^|[^:])\/\/[^\n]*/g, "$1");
    const importsRegisterAll = /import\s+["']\.\/register-all\.js["']/;
    // Any string/template literal whose contents reference a path under fixtures/.
    const fixtureSpecifier = /["'`][^"'`]*fixtures\/[^"'`]*["'`]/;

    for (const [name, rel] of [
      ["run.ts", "run.ts"],
      ["gen-coverage-baseline.ts", "gen-coverage-baseline.ts"],
    ] as const) {
      const src = stripComments(readFileSync(resolve(HERE, "..", rel), "utf8"));
      expect(importsRegisterAll.test(src), `${name} must import ./register-all.js`).toBe(true);
      expect(
        fixtureSpecifier.test(src),
        `${name} must NOT reference a fixture/ module specifier directly (drift vector); register via register-all.ts`,
      ).toBe(false);
    }
  });

  it("coverage has not dropped versus the committed baseline (build report -> diff)", async () => {
    const report = await buildReport({ platform: "linux", sha: "ratchet-test" });

    // Defensive: the live report must itself be non-trivial, else a builder bug
    // that returns an empty report would diff as "no regressions" vacuously.
    expect(report.rows.length).toBeGreaterThanOrEqual(20);

    const baseline = loadBaseline();
    const violations = diffAgainstBaseline(report, baseline);

    expect(
      violations,
      "Synthetic coverage REGRESSED versus scripts/synthetic-coverage/" +
        "coverage-baseline.json. Restore the lost coverage, or (if the " +
        "reduction is intentional and reviewed) regenerate the baseline IN " +
        "THIS PR with `npm run synthetic-coverage:baseline`. Regression(s):\n  " +
        violations.map((v) => `${v.kind}: ${v.detail}`).join("\n  "),
    ).toEqual([]);
  });

  it("snapshotFromReport round-trips the live report into the baseline shape", async () => {
    // Guards the projection the generator uses: if it silently lost the
    // per-row fields, the baseline would be unenforceable.
    const report = await buildReport({ platform: "linux", sha: "roundtrip" });
    const snapshot = snapshotFromReport(report);
    expect(snapshot.rows.length).toBe(report.rows.length);
    const sample = snapshot.rows.find((r) => r.assurance_row_id === "4");
    expect(sample?.coverage_state).toBeDefined();
    expect(sample?.fixtures_passed).toBeGreaterThan(0);
  });
});
