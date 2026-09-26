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
 * `coverageAnalysis: "perTest"` matters for cost, not just correctness: it
 * asks the vitest runner which test files exercise each mutated file so a
 * mutant reruns only those files, not the whole suite. Without it, every
 * mutant would pay the full-suite cost, and the module-scoped mutate list
 * below would not save any wall-clock time. `concurrency: 4` bounds worker
 * count so a laptop-class box does not thrash; raise it on a beefier CI
 * runner once this graduates out of a scoped baseline.
 */
export default {
  packageManager: "npm",
  testRunner: "vitest",
  coverageAnalysis: "perTest",
  concurrency: 4,
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
