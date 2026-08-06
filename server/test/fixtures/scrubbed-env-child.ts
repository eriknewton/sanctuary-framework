/**
 * Spawned by `test/wrap/keychain-exec-guard.test.ts` with `env: {}` to prove the
 * credential chokepoint still refuses when every environment variable is gone.
 *
 * This is a FIXTURE, not a test: vitest collects only `*.test.ts`, so it never
 * runs on its own. It exists as a real file rather than a string written at test
 * time because the child has to import the same module the suite does, by path,
 * for the check to mean anything.
 *
 * The probe is a READ of a service name nothing ever creates, so on the failure
 * path (chokepoint regressed, real binary reached) it is harmless and merely
 * slow. The point is the assertion in the parent, which requires REFUSED.
 */

import { execKeychain } from "../../src/wrap/keychain-exec.js";

try {
  await execKeychain("security", [
    "find-generic-password",
    "-s",
    "sanctuary-scrubbed-env-probe-should-never-exist",
    "-a",
    "sanctuary",
    "-w",
  ]);
  // Reached the real binary. That is the regression this fixture detects.
  process.stdout.write("SPAWNED_REAL");
} catch (err) {
  const message = (err as Error).message;
  process.stdout.write(
    message.includes("Refusing to run") ? "REFUSED" : `OTHER:${message}`
  );
}
