/**
 * The gate for the networked live test, in one place so a structural test can
 * check it. Must match the `describe.skipIf` gate in
 * server/test/verify-release/live.test.ts.
 */

/** The opt-in variable; only the exact value "1" opts in. */
export const LIVE_OPT_IN_VARIABLE = "SANCTUARY_VERIFY_RELEASE_LIVE";

/**
 * True only outside CI with the opt-in set. CI is checked first and wins
 * whatever the opt-in says, because a CI runner must never install a package
 * from the registry or reach GitHub for this test.
 */
export function liveTestEnabled(env: Readonly<Record<string, string | undefined>>): boolean {
  if (env.CI !== undefined) return false;
  return env[LIVE_OPT_IN_VARIABLE] === "1";
}
