/**
 * Sanctuary wrap - the SINGLE chokepoint for spawning the OS credential CLI.
 *
 * WHY THIS EXISTS (2026-08-04). Three modules each spawned `security` on their
 * own (`keychain-custody.ts`, `passphrase.ts`, and the broker backend). Two of
 * them target the DEFAULT keychain, which under test is the developer's REAL
 * login keychain. A full local suite run wrote ~61 entries into it. That is bad
 * on its own (an operator's personal credential store is not test scratch
 * space), and it degrades: as entries accumulate, keychain-dependent tests slow
 * down, and under vitest's parallel workers they hit the SERIALIZED keychain
 * daemon simultaneously and trip their timeouts. Timed-out workers then survive
 * the run - hung servers, orphaned `security -i` children - and poison every
 * subsequent run with port and boot failures. Measured: a suite that ran in 228s
 * with one known flake later failed to finish inside 30 minutes, with failure
 * counts of 4 -> 32 -> 18 across successive runs and ZERO code change between
 * them.
 *
 * Fixing the three call sites individually is whack-a-mole; a fourth would
 * reintroduce it. So every credential-CLI spawn goes through `execKeychain`,
 * and the guard lives here.
 *
 * THE RULE: tests never touch the operator's login keychain. Under test this
 * module refuses to spawn the real binary unless a test EXPLICITLY opts in, and
 * the default injected store is in-memory - which also removes the subprocess
 * entirely, killing the worker-hang vector rather than just making it rarer.
 *
 * Same family as the standing rule that drill briefs must forbid keychain and
 * browser use (a drill once hijacked the operator's desktop). That rule covered
 * drills; the ordinary unit-test suite was never brought under it.
 */

import { spawn } from "node:child_process";

import type { ExecResult } from "./exec-result.js";

/** Signature every credential-CLI call in the codebase uses. */
export type KeychainExec = (
  cmd: string,
  args: string[],
  input?: string
) => Promise<ExecResult>;

/**
 * Env var a test sets when it genuinely means to exercise the REAL credential
 * CLI. Such a test must target a temporary keychain it creates and deletes -
 * never the login keychain. Deliberately verbose: it should be obvious in a
 * diff that a test opted out of the safety net.
 */
export const ALLOW_REAL_KEYCHAIN_ENV = "SANCTUARY_TEST_ALLOW_REAL_KEYCHAIN";

let override: KeychainExec | null = null;

/**
 * Install a credential-store implementation (the in-memory fake in tests).
 * Passing null restores the real spawn path. Exported for the vitest setup file
 * and for tests that want a bespoke stub; production never calls this.
 */
export function setKeychainExec(fn: KeychainExec | null): void {
  override = fn;
}

/** True when running under vitest, or an explicit test NODE_ENV. */
function underTest(): boolean {
  return (
    process.env.VITEST !== undefined ||
    process.env.VITEST_WORKER_ID !== undefined ||
    process.env.NODE_ENV === "test"
  );
}

async function spawnReal(
  cmd: string,
  args: string[],
  input?: string
): Promise<ExecResult> {
  return new Promise((resolvePromise, reject) => {
    const child = spawn(cmd, args, { stdio: ["pipe", "pipe", "pipe"] });
    let stdout = "";
    let stderr = "";
    child.stdout.on("data", (d) => {
      stdout += d.toString();
    });
    child.stderr.on("data", (d) => {
      stderr += d.toString();
    });
    child.on("error", reject);
    child.on("close", (code) => resolvePromise({ stdout, stderr, code }));
    if (input !== undefined) {
      child.stdin.write(input);
    }
    child.stdin.end();
  });
}

/**
 * Run a credential-CLI command. In production this spawns the real binary. In
 * tests it uses the installed store, and THROWS if neither a store nor an
 * explicit opt-in is present - so a new call site that forgets to inject fails
 * loudly at the first test that reaches it, instead of silently writing to the
 * operator's login keychain.
 */
export async function execKeychain(
  cmd: string,
  args: string[],
  input?: string
): Promise<ExecResult> {
  if (override !== null) return override(cmd, args, input);

  if (underTest() && process.env[ALLOW_REAL_KEYCHAIN_ENV] !== "1") {
    throw new Error(
      `Refusing to run '${cmd}' against the real OS credential store from a test. ` +
        `Tests must never touch the operator's login keychain: entries accumulate in a ` +
        `personal credential store, and under parallel workers the serialized keychain ` +
        `daemon causes timeouts whose workers survive and poison later runs. ` +
        `Fix: let the default in-memory store handle it (test/setup/keychain-fake.ts, ` +
        `installed for every test), or inject your own via setKeychainExec(). ` +
        `If this test genuinely must exercise the real CLI, it must create and delete a ` +
        `TEMPORARY keychain and set ${ALLOW_REAL_KEYCHAIN_ENV}=1.`
    );
  }

  return spawnReal(cmd, args, input);
}
