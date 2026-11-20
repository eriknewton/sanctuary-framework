// Runs the non-CI recall coverage measurement under the server's own setup files (in-memory keychain, temp homes,
// lease guard), so the measurement inherits the suite's custody isolation. The default `npm test` include globs
// never collect scripts/, so this config is the only way the measurement runs.
// Failure mode: running the measurement with the default config collects nothing and reports "No test files found".
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";
import base from "../vitest.config";

const server = resolve(fileURLToPath(new URL(".", import.meta.url)), "..");
export default {
  ...base,
  root: server,
  test: {
    ...base.test,
    include: [resolve(server, "scripts/recall-coverage.measure.ts")],
    testTimeout: 4 * 3_600_000, // Four hours, matching the measurement's own timeout.
  },
};
