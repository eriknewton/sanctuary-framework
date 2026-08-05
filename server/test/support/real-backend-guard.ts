/**
 * The gate on the ONE test file that removes the in-memory credential store.
 *
 * `test/keychain-linux-real-backend-integration.test.ts` exists to shell out to
 * a genuine `secret-tool`, so it takes the safety net off. Taking the net off is
 * only acceptable against a keyring nobody owns.
 *
 * WHY THIS IS A MODULE AND NOT AN `if` IN THAT FILE. The predicate has to be
 * callable so its truth table can be exercised directly. An earlier version of
 * this gate was asserted by grepping the test file for a string, which would
 * have kept passing if the condition were ORed instead of ANDed, checked after
 * the store was already removed, or never read at all. A substring is not an
 * enforcement.
 *
 * ── WHAT THIS PROVES, AND WHAT IT DOES NOT ──────────────────────────────
 *
 * PROVEN: the process is running inside a GitHub Actions job. A GitHub-hosted
 * runner is created for one job and destroyed with it, so every keyring on it is
 * disposable by construction rather than by assertion. Self-hosted runners are
 * excluded, because those can be long-lived machines with real keyrings.
 *
 * NOT PROVEN: this is not unforgeable, and does not try to be. Anyone who
 * exports `GITHUB_ACTIONS=true` on a Linux desktop with a live Secret Service
 * will write to it. That is a deliberate act. The distinction that matters is
 * that no NATURALLY OCCURRING developer state satisfies this, while the
 * mechanisms it replaced could be satisfied by ACCIDENT.
 *
 * ── WHY IT IS THIS, AND NOT A PROOF OF DISPOSABILITY ────────────────────
 *
 * Three rounds of this change each shipped a proof weaker than its claim:
 *
 *   1. `SANCTUARY_TEST_DISPOSABLE_KEYRING=1`. One stale export in a shell
 *      profile, on a desktop that has `secret-tool` and a session bus, was the
 *      whole distance between "skip" and "write to the operator's real keyring".
 *   2. A nonce round-tripped through the Secret Service. That proves the service
 *      ACCEPTED our probe, which the operator's own service would also do.
 *   3. Requiring the bus socket to sit under a temp root. `dbus-launch` on an
 *      ordinary developer desktop produces exactly a `/tmp/dbus-*` address, and
 *      `RUNNER_TEMP` is mutable env. Path SHAPE is not identity.
 *
 * A fourth heuristic would have invited a fifth. Proving "this keyring is
 * disposable" from inside the test is the wrong problem to solve: only one
 * execution context is known-disposable, so the suite runs there and nowhere
 * else. The cost is that a Linux developer cannot run this one integration file
 * locally. That is the intended trade, not a regression. CI is authoritative,
 * and a disposable backend is this file's entire premise.
 */

import {
  execKeychain,
  setKeychainExec,
  ALLOW_REAL_KEYCHAIN_ENV,
} from "../../src/wrap/keychain-exec.js";
import { installInMemoryKeychainStore } from "../setup/keychain-fake.js";

/**
 * Set to the string "true" by GitHub Actions in every job. If it were ever
 * absent the failure direction is safe: the suite skips, prints its reason, and
 * the exact-count guard in
 * `.github/workflows/keychain-linux-real-backend.yml` fails the job loudly.
 */
const GITHUB_ACTIONS_ENV = "GITHUB_ACTIONS";

/**
 * "github-hosted" or "self-hosted". Checked NEGATIVELY on purpose: an absent
 * value must not block the run, because this variable was not verified to be
 * present in this repo's jobs, and requiring it positively would turn an
 * unverified assumption into a red CI. Excluding a known "self-hosted" is the
 * part that carries the security meaning, and that works whether or not the
 * variable is set.
 */
const RUNNER_ENVIRONMENT_ENV = "RUNNER_ENVIRONMENT";
const SELF_HOSTED = "self-hosted";

export interface CiRunnerEnv {
  githubActions: string | undefined;
  runnerEnvironment: string | undefined;
}

export interface DisposableVerdict {
  disposable: boolean;
  /** Non-secret explanation, printed when the suite skips where it might have run. */
  reason: string;
}

/** Is this the ephemeral CI job whose whole machine dies when the job ends? */
export function probeDisposableCiRunner(env: CiRunnerEnv): DisposableVerdict {
  if (env.githubActions !== "true") {
    return {
      disposable: false,
      reason:
        "not running inside a GitHub Actions job; this suite is CI-only because a " +
        "developer keyring is not disposable and no check inside the test can prove otherwise",
    };
  }
  if (env.runnerEnvironment === SELF_HOSTED) {
    return {
      disposable: false,
      reason:
        "self-hosted runner: the machine outlives the job, so its keyring is not disposable",
    };
  }
  return { disposable: true, reason: "ephemeral GitHub-hosted runner" };
}

/** Live probe of the current process environment. */
export function probeDisposableCiRunnerFromEnv(): DisposableVerdict {
  return probeDisposableCiRunner({
    githubActions: process.env[GITHUB_ACTIONS_ENV],
    runnerEnvironment: process.env[RUNNER_ENVIRONMENT_ENV],
  });
}

// ── The skip decision ───────────────────────────────────────────────────

export interface RealBackendProbe {
  isLinux: boolean;
  hasSecretTool: boolean;
  hasDbus: boolean;
  onDisposableCiRunner: boolean;
}

/**
 * All four conditions are required. The first three are satisfiable by an
 * ordinary Linux desktop, which is exactly why the fourth exists and why this is
 * an AND. The truth table is exercised condition by condition in
 * `test/wrap/keychain-exec-guard.test.ts`.
 */
export function shouldSkipRealBackend(probe: RealBackendProbe): boolean {
  return (
    !probe.isLinux ||
    !probe.hasSecretTool ||
    !probe.hasDbus ||
    !probe.onDisposableCiRunner
  );
}

export interface RealBackendModeState {
  savedAllowReal: string | undefined;
}

/**
 * Remove the in-memory credential store so the production code shells out for
 * real, and REFUSE to do it unless {@link shouldSkipRealBackend} says the run
 * qualifies.
 *
 * This is the enforcement, not the `describe.skipIf`. A skip guard that drifts
 * out of agreement with the gate fails here, loudly, instead of quietly writing
 * to somebody's keyring: the store stays installed and the suite errors.
 */
export function enterRealBackendMode(probe: RealBackendProbe): RealBackendModeState {
  if (shouldSkipRealBackend(probe)) {
    throw new Error(
      "refusing to remove the in-memory credential store: this run is not an " +
        "ephemeral CI job with a Secret Service " +
        `(linux=${probe.isLinux}, secret-tool=${probe.hasSecretTool}, ` +
        `dbus=${probe.hasDbus}, disposable-ci=${probe.onDisposableCiRunner})`
    );
  }
  const savedAllowReal = process.env[ALLOW_REAL_KEYCHAIN_ENV];
  // `execKeychain` consults the store BEFORE the opt-in env var, so removing the
  // store is what actually restores the spawn path; the env var alone is inert.
  // Both are required: the removal to reach `spawn`, the var to get past the
  // under-test refusal.
  process.env[ALLOW_REAL_KEYCHAIN_ENV] = "1";
  setKeychainExec(null);
  return { savedAllowReal };
}

/** Put the safety net back. Runs even when the suite failed or timed out. */
export function leaveRealBackendMode(state: RealBackendModeState): void {
  installInMemoryKeychainStore();
  if (state.savedAllowReal !== undefined) {
    process.env[ALLOW_REAL_KEYCHAIN_ENV] = state.savedAllowReal;
  } else {
    delete process.env[ALLOW_REAL_KEYCHAIN_ENV];
  }
}

/**
 * True when the in-memory store is currently serving, i.e. the safety net is on.
 * Probes by BEHAVIOR (issue a harmless lookup and see whether the chokepoint
 * refuses) rather than by reading module state, so it cannot disagree with what
 * a real call site would experience.
 */
export async function credentialStoreIsInstalled(): Promise<boolean> {
  const savedAllowReal = process.env[ALLOW_REAL_KEYCHAIN_ENV];
  delete process.env[ALLOW_REAL_KEYCHAIN_ENV];
  try {
    await execKeychain("security", [
      "find-generic-password",
      "-s",
      "sanctuary-store-installed-probe",
      "-a",
      "sanctuary",
      "-w",
    ]);
    return true;
  } catch {
    return false;
  } finally {
    if (savedAllowReal !== undefined) {
      process.env[ALLOW_REAL_KEYCHAIN_ENV] = savedAllowReal;
    }
  }
}
