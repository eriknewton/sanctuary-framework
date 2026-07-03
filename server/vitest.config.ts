import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    globals: true,
    environment: "node",
    // No network egress from unit tests: the wrap-time pinned-version
    // resolvability probe (wrap/cli.ts) and the startup update check both
    // honor this documented zero-outbound knob. Tests that exercise the
    // probe itself either delete the var locally and point the probe at a
    // loopback server, or inject a stub via RunWrapDeps.
    env: { SANCTUARY_NO_UPDATE_CHECK: "1" },
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
