// @ts-check
/**
 * Mutation-testing config for the scoped D4 baseline (decision A164).
 *
 * Scope is intentionally narrow: three core/storage modules, not the whole
 * `server/src` tree. A full-tree run is a separate, much longer exercise;
 * this config exists to answer "does mutation testing tell us anything
 * useful here" before that investment. See docs/audit/mutation-testing.md
 * for how to run it, how to read a score, and the test-pruning rule.
 *
 * Two settings bound the work per mutant: `vitest.related` limits each run
 * to the test files whose import graph reaches the mutated file, and
 * `coverageAnalysis: "perTest"` reruns only the tests whose coverage hit
 * the mutated line. They are different filters; see the doc. `concurrency: 4` bounds worker
 * count so a laptop-class box does not thrash; raise it on a beefier CI
 * runner once this graduates out of a scoped baseline.
 */
export default {
  packageManager: "npm",
  testRunner: "vitest",
  // `vitest.related` (the runner default, pinned here on purpose) selects the
  // test files whose import graph reaches the mutated file; `perTest` then
  // reruns only the tests whose recorded coverage executed the mutated line.
  vitest: { related: true },
  coverageAnalysis: "perTest",
  concurrency: 4,
  // The initial unmutated run for widely imported core modules on one vitest
  // worker can exceed Stryker's 5-minute default; an aborted dry run yields no
  // incremental file and no score, so this is the cap that decides whether a
  // run starts at all. 30 minutes = about 1.5x the CI full-suite shard time.
  dryRunTimeoutMinutes: 30,
  reporters: ["html", "clear-text", "progress", "json"],
  htmlReporter: {
    fileName: "reports/mutation/mutation.html",
  },
  jsonReporter: {
    fileName: "reports/mutation/mutation.json",
  },
  tempDirName: ".stryker-tmp",
  incremental: true,
  incrementalFile: ".stryker-tmp/incremental.json",
  // Scoped baseline: three core/storage modules only. Widen deliberately, one
  // directory at a time. Enforcement and crypto modules are never excluded to
  // protect a score; see docs/audit/mutation-testing.md.
  mutate: [
    "src/core/encoding.ts",
    "src/core/random.ts",
    "src/storage/memory.ts",
  ],
};
