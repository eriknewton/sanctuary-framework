/**
 * Regenerate `coverage-baseline.json` from the SAME report builder the synthetic
 * coverage runner uses, so the baseline can never drift from what the ratchet
 * compares against. This is the only sanctioned way to rewrite the baseline.
 *
 * Run from the repository root:
 *   server/node_modules/.bin/tsx scripts/synthetic-coverage/gen-coverage-baseline.ts
 * or from server/:
 *   npm run synthetic-coverage:baseline
 *
 * Use it ONLY to (a) seed the baseline initially, (b) lock in a coverage GAIN
 * after adding fixtures (optional — the ratchet is a floor, so gains pass
 * without a regen), or (c) record an INTENTIONAL, reviewed coverage reduction
 * (e.g. retiring a claim) IN THE SAME PR. A regen is a visible, reviewable diff,
 * exactly like the import-cycle baseline regen. It NEVER changes fixtures; it
 * only records the current coverage state so the ratchet stays fail-on-drop.
 */

import { mkdirSync, writeFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
// Single source of truth for the fixture set (shared with run.ts and the PR
// ratchet test) so the three can never drift out of lockstep.
import "./register-all.js";
import { buildReport } from "./report.js";
import { snapshotFromReport } from "./coverage-ratchet.js";

const HERE = dirname(fileURLToPath(import.meta.url));
const BASELINE_PATH = resolve(HERE, "coverage-baseline.json");

const COMMENT = [
  "Synthetic-coverage PR ratchet baseline (DoE H-3).",
  "Frozen per-row coverage snapshot: a change that REDUCES coverage for any row",
  "(dropped row, fewer passing fixtures, regressed coverage_state, or a newly",
  "failing fixture) reds coverage-ratchet.test.ts inside `npm test`. Improvements",
  "pass without a regen (the ratchet is a directional floor). DO NOT hand-edit to",
  "lower a value; regenerate ONLY via `npm run synthetic-coverage:baseline` after",
  "a legitimate, reviewed coverage change, in the same PR. Platform-agnostic: the",
  "synthetic fixtures are deterministic in-process models, identical on Linux and",
  "macOS.",
];

async function main(): Promise<void> {
  // SHA/platform do not affect the snapshot fields (status/passed/state).
  const report = await buildReport({ platform: "linux", sha: "baseline" });
  const snapshot = snapshotFromReport(report);
  snapshot._comment = COMMENT;
  // Put _comment first for readability, then rows.
  const ordered = { _comment: snapshot._comment, rows: snapshot.rows };
  mkdirSync(dirname(BASELINE_PATH), { recursive: true });
  writeFileSync(BASELINE_PATH, `${JSON.stringify(ordered, null, 2)}\n`, "utf8");
  const totalPassed = snapshot.rows.reduce((acc, row) => acc + row.fixtures_passed, 0);
  process.stdout.write(
    `coverage-baseline.json regenerated: ${snapshot.rows.length} rows, ` +
      `${totalPassed} passing fixtures recorded.\n`,
  );
}

main().catch((err: unknown) => {
  console.error(err);
  process.exit(1);
});
