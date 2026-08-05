/**
 * Sanctuary wrap - the SINGLE chokepoint for spawning the OS credential CLI.
 *
 * WHY THIS EXISTS (2026-08-04). Four modules each spawned the credential CLI on
 * their own: `keychain-custody.ts`, `passphrase.ts`, `cli/reset-passphrase.ts`,
 * and `disclosure/broker/keychain-backend.ts`. Two of
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
 * Fixing the call sites individually is whack-a-mole; the next one added would
 * reintroduce it. So every credential-CLI spawn goes through `execKeychain`,
 * and the guard lives here.
 *
 * That completeness is a CLAIM, so it has a check: "nothing else in the tree
 * spawns a credential CLI" in `test/wrap/keychain-exec-guard.test.ts` fails if
 * any module outside this one both imports `node:child_process` and names
 * `security` or `secret-tool`. Adding a call site that forgets to route here is
 * therefore a red test, not a silent hole.
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

let override: KeychainExec | null = null;

/**
 * Install a credential-store implementation (the in-memory fake in tests).
 * Exported for the vitest setup file and for tests that want a bespoke stub;
 * production never calls this.
 *
 * THERE IS DELIBERATELY NO WAY TO UN-SET IT. The parameter cannot be null and no
 * reset function exists, so once the setup file installs the fake, no code path
 * inside the suite can restore the real spawn path. That is the difference
 * between a guarded capability and an absent one: a test file that could remove
 * the isolation was a loaded weapon on every machine that runs `npm test`, and
 * three attempts to gate it correctly each shipped a check weaker than its
 * claim. The real shell-out is verified by `scripts/real-backend-check.ts`,
 * which runs as a plain node process where spawning is ordinary behavior.
 */
export function setKeychainExec(fn: KeychainExec): void {
  override = fn;
}

/**
 * What `execKeychain` should do, as a pure function of the two inputs that
 * decide it. Extracted so the truth table is testable directly: the property
 * that matters is that NO combination yields `spawn-real` while under test, and
 * that is checked mechanically in `test/wrap/keychain-exec-guard.test.ts` rather
 * than asserted in a comment.
 */
export type KeychainExecDecision = "installed-store" | "refuse-under-test" | "spawn-real";

export function decideKeychainExecution(
  hasInstalledStore: boolean,
  isUnderTest: boolean
): KeychainExecDecision {
  if (hasInstalledStore) return "installed-store";
  return isUnderTest ? "refuse-under-test" : "spawn-real";
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
  switch (decideKeychainExecution(override !== null, underTest())) {
    case "installed-store":
      // Non-null by construction: that is the branch's condition.
      return override!(cmd, args, input);
    case "refuse-under-test":
      throw new Error(
        `Refusing to run '${cmd}' against the real OS credential store from a test. ` +
          `Tests must never touch the operator's login keychain: entries accumulate in a ` +
          `personal credential store, and under parallel workers the serialized keychain ` +
          `daemon causes timeouts whose workers survive and poison later runs. ` +
          `There is NO opt-in; the real credential CLI is unreachable from the suite by ` +
          `design. Fix: let the default in-memory store handle it ` +
          `(test/setup/keychain-fake.ts, installed for every test), or inject your own via ` +
          `setKeychainExec(). To exercise the genuine CLI, add a case to ` +
          `scripts/real-backend-check.ts, which runs outside vitest.`
      );
    case "spawn-real":
      return spawnReal(cmd, args, input);
  }
}
