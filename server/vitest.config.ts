import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    globals: true,
    // Installs an in-memory credential store for every test so nothing ever
    // writes to the operator's real login keychain. See src/wrap/keychain-exec.ts.
    setupFiles: ["./test/setup/keychain-fake.ts"],
    // Leaves a marker file at the package root for the whole run. setupFiles
    // covers this process and children inherit VITEST by default, but a child
    // spawned with `env: {}` has neither; the marker is what a scrubbed
    // environment cannot erase. See test/setup/test-run-marker.ts.
    globalSetup: ["./test/setup/test-run-marker.ts"],
    environment: "node",
    // No network egress from unit tests: the wrap-time pinned-version
    // resolvability probe (wrap/cli.ts) and the startup update check both
    // honor this documented zero-outbound knob. Tests that exercise the
    // probe itself either delete the var locally and point the probe at a
    // loopback server, or inject a stub via RunWrapDeps.
    env: { SANCTUARY_NO_UPDATE_CHECK: "1" },
    // MUST MATCH: read directly (not copied) by scripts/count-vitest-test-files.mjs,
    // which feeds CI's silent-test-file-drop detector (Gate 2b in
    // .github/workflows/test-baseline-guard.yml and .githooks/pre-commit). Both
    // consumers derive their expected-file count from THIS array via vite's own
    // config loader, so adding or removing an include root here needs no matching
    // edit anywhere else — the old shape (a hand-restated `find server/test` in
    // both places) silently missed the second root below and let up to 14 dropped
    // files pass undetected. If this array ever again needs a manual mirror
    // somewhere, that itself is a sign the derivation broke.
    include: ["test/**/*.test.ts", "../scripts/synthetic-coverage/test/**/*.test.ts"],
    coverage: {
      provider: "v8",
      include: ["src/**/*.ts"],
      exclude: ["src/cli.ts"],
      // text -> human-readable summary in the terminal / CI log;
      // json-summary -> machine-readable totals for tooling;
      // lcov -> standard format for coverage viewers and uploaders.
      // No threshold is set here on purpose: coverage is a reported
      // signal, not yet a hard gate (a flaky threshold would block CI).
      reporter: ["text", "json-summary", "lcov"],
    },
    testTimeout: 30_000, // ZK proofs and crypto ops can be slow
  },
});
