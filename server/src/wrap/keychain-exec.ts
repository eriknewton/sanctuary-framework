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
import { existsSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import type { ExecResult } from "./exec-result.js";

/** Signature every credential-CLI call in the codebase uses. */
export type KeychainExec = (
  cmd: string,
  args: string[],
  input?: string
) => Promise<ExecResult>;

let override: KeychainExec | null = null;

// Credential helpers run while custody/master locks may be held. Bound both
// time and captured output so a wedged or hostile helper cannot monopolize the
// lock or exhaust the Node process. These are production constants; tests of
// the real-spawn branch compile an isolated copy with shorter values.
const KEYCHAIN_PROCESS_TIMEOUT_MS = 15_000;
const KEYCHAIN_PROCESS_MAX_OUTPUT_BYTES = 64 * 1024;
const KEYCHAIN_PROCESS_TERM_GRACE_MS = 250;

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
 * The marker's path, for the refusal message. A refusal that does not name the
 * file leaves an operator staring at "the CLI suddenly cannot reach my
 * keychain", which is the exact confusion the marker's runbook note exists to
 * prevent. Falls back to the bare filename if the root cannot be resolved,
 * because a partial hint beats none.
 */
function markerPathForDiagnostics(): string {
  const root = packageRoot();
  return root === null
    ? TEST_RUN_MARKER_FILENAME
    : join(root, TEST_RUN_MARKER_FILENAME);
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

/**
 * Filename of the marker a test run leaves at this package's root for its whole
 * duration.
 *
 * MUST MATCH the path built in `test/setup/test-run-marker.ts`, which is the
 * vitest `globalSetup` that creates and removes it. Both sides derive the
 * directory the same way, from the package root; that file carries a pointer
 * back here.
 */
export const TEST_RUN_MARKER_FILENAME = ".sanctuary-test-run";

/**
 * This package's root, found by walking up from this module to the directory
 * holding package.json. Works from `src/wrap/` under vitest or tsx and from the
 * bundled `dist/` in a spawned CLI, because both resolve to the same root.
 */
function packageRoot(): string | null {
  try {
    let dir = dirname(fileURLToPath(import.meta.url));
    // 10 = far more levels than src/wrap (2) or dist (1) ever needs; the loop
    // also stops at the filesystem root, so this only bounds a pathological case.
    for (let i = 0; i < 10; i++) {
      if (existsSync(join(dir, "package.json"))) return dir;
      const parent = dirname(dir);
      if (parent === dir) return null;
      dir = parent;
    }
  } catch {
    // No import.meta (an exotic CJS consumer) or an unreadable path. Falls back
    // to the env signals below, which is the pre-existing behavior.
  }
  return null;
}

function markerOnDiskNow(): boolean {
  const root = packageRoot();
  return root !== null && existsSync(join(root, TEST_RUN_MARKER_FILENAME));
}

/**
 * LATCH. Evaluated at module load, and only ever assigned `true` afterwards.
 *
 * Why at module load: a child spawned during the suite imports this module while
 * the marker still exists. Latching there means the child stays under-test for
 * its entire lifetime no matter when it first asks for a credential. Deciding
 * lazily on the first credential call left a real race, verified on 9a8a3ce6: a
 * scrubbed-env child that outlives global teardown makes its first call after
 * the marker is gone, `underTest()` answers false, and an ordinary call site
 * spawns the real binary. A synchronous `spawnSync` plant cannot see it, because
 * the child always calls while the marker is still there.
 *
 * Why the negative is NEVER cached: a process that started moments BEFORE the
 * marker appeared would otherwise latch "production" permanently and stay wrong
 * for the whole run. So a false reading is recomputed on every call and never
 * stored. The only assignment to this variable after initialization is `= true`.
 */
let observedTestRunMarker = markerOnDiskNow();

/**
 * Latch semantics as a pure function, so the state transition that matters can
 * be tested directly rather than reasoned about: once observed, the marker
 * disappearing must NOT reclassify this process as production.
 */
export function latchUnderTest(
  previouslyObserved: boolean,
  markerOnDisk: boolean
): boolean {
  return previouslyObserved || markerOnDisk;
}

function testRunMarkerPresent(): boolean {
  // `latchUnderTest` is the ONLY decision, on every call, with no short-circuit
  // in front of it. An earlier version returned early when the latch was already
  // set, which left the pure function off the runtime path: mutating it changed
  // nothing but its own unit test, so a plant against it was self-confirming.
  // Re-stat only while the marker has never been seen; once latched, the disk is
  // irrelevant and skipping the stat is just the fast path.
  const markerOnDisk = observedTestRunMarker ? false : markerOnDiskNow();
  const result = latchUnderTest(observedTestRunMarker, markerOnDisk);
  // Store ONLY a true result. See the declaration for why a false is never cached.
  if (result) observedTestRunMarker = true;
  return result;
}

/**
 * True when this process is part of a test run.
 *
 * WHY THIS IS NOT PURELY ENV-DERIVED. The env signals are inherited by children
 * BY DEFAULT, but a test that spawns the CLI with `env: {}` produces a child
 * where VITEST is undefined, vitest setup never loads, no store is installed,
 * and the old purely-env answer was "production", i.e. spawn the real
 * credential binary against the operator's own keychain. That is how the login
 * keychain accumulated tens of thousands of `sanctuary-*` artifacts. Absence of
 * evidence was being read as production.
 *
 * The marker file closes it because a scrubbed environment cannot erase a file.
 * It is a POSITIVE signal for "a test run is in progress" and is scoped to this
 * checkout, so it does not affect an installed package or a drill running the
 * CLI outside `npm test`.
 *
 * Fail direction: if the marker cannot be resolved, this degrades to the env
 * signals, which is the previous behavior; it never turns a test run into
 * production. The case that matters, a child of the suite, always resolves.
 *
 * ── WHAT IS COVERED, AND THE ONE THING THAT IS NOT ──────────────────────
 *
 * This protection is NOT total, and the boundary is exact.
 *
 * COVERED: every child that loads this module while the marker exists. The
 * latch is taken at module load, so such a child stays under test for its whole
 * lifetime however late its first credential call comes, including after global
 * teardown has deleted the marker.
 *
 * NOT COVERED: a child that starts during the suite and first loads this module
 * AFTER teardown. It initializes the latch false, finds no env signal, and would
 * spawn the real binary. Reaching that state requires spawning a child with a
 * scrubbed environment AND deferring the module load past the end of the run.
 *
 * No test in this repo does that: every `env:` option at a child-spawn call site
 * inherits the parent environment. Keeping it that way is enforced, not hoped
 * for, by "no test may spawn a child with a scrubbed environment" in
 * `test/wrap/keychain-exec-guard.test.ts`, which parses each test file and fails
 * on any child_process call whose `env` drops VITEST. That rule is the reason
 * this residual stays unreachable; it is not a claim that the residual does not
 * exist.
 */
function underTest(): boolean {
  return (
    process.env.VITEST !== undefined ||
    process.env.VITEST_WORKER_ID !== undefined ||
    process.env.NODE_ENV === "test" ||
    testRunMarkerPresent()
  );
}

async function spawnReal(
  cmd: string,
  args: string[],
  input?: string
): Promise<ExecResult> {
  return new Promise((resolvePromise, reject) => {
    const detached = process.platform !== "win32";
    const child = spawn(cmd, args, {
      stdio: ["pipe", "pipe", "pipe"],
      detached,
    });
    const stdout: Buffer[] = [];
    const stderr: Buffer[] = [];
    let outputBytes = 0;
    let settled = false;
    let terminationReason: "timed out" | "exceeded output limit" | null = null;
    let timeout: NodeJS.Timeout | null = null;
    let killTimer: NodeJS.Timeout | null = null;

    const killTree = (signal: NodeJS.Signals): void => {
      if (child.pid === undefined) return;
      try {
        // A detached POSIX child is its own process-group leader. Negative PID
        // signals the whole group, including descendants that inherited pipes.
        if (detached) process.kill(-child.pid, signal);
        else child.kill(signal);
      } catch {
        // ESRCH means the group has already exited, which is the desired state.
      }
    };

    const terminate = (
      reason: "timed out" | "exceeded output limit"
    ): void => {
      if (terminationReason !== null) return;
      terminationReason = reason;
      if (timeout !== null) clearTimeout(timeout);
      child.stdin.destroy();
      killTree("SIGTERM");
      // Keep this timer alive even if the direct child exits: a descendant may
      // have inherited the pipes or ignored TERM. The unref prevents it from
      // delaying a process whose entire group is already gone.
      killTimer = setTimeout(() => killTree("SIGKILL"), KEYCHAIN_PROCESS_TERM_GRACE_MS);
      killTimer.unref();
    };

    const collect = (target: Buffer[], chunk: Buffer | string): void => {
      if (terminationReason !== null) return;
      const bytes = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
      const remaining = KEYCHAIN_PROCESS_MAX_OUTPUT_BYTES - outputBytes;
      if (bytes.length > remaining) {
        if (remaining > 0) target.push(bytes.subarray(0, remaining));
        outputBytes = KEYCHAIN_PROCESS_MAX_OUTPUT_BYTES;
        terminate("exceeded output limit");
        return;
      }
      target.push(bytes);
      outputBytes += bytes.length;
    };

    timeout = setTimeout(
      () => terminate("timed out"),
      KEYCHAIN_PROCESS_TIMEOUT_MS,
    );
    timeout.unref();
    child.stdout.on("data", (d: Buffer) => collect(stdout, d));
    child.stderr.on("data", (d: Buffer) => collect(stderr, d));
    // Destroying stdin during timeout can surface EPIPE. It is subordinate to
    // the bounded termination result and must not become an unhandled event.
    child.stdin.on("error", () => {});
    child.on("error", (error) => {
      if (settled) return;
      settled = true;
      if (timeout !== null) clearTimeout(timeout);
      if (terminationReason === null && killTimer !== null) clearTimeout(killTimer);
      reject(
        terminationReason === null
          ? error
          : new Error(`credential helper ${terminationReason}`),
      );
    });
    child.on("close", (code) => {
      if (settled) return;
      settled = true;
      if (timeout !== null) clearTimeout(timeout);
      if (terminationReason !== null) {
        reject(new Error(`credential helper ${terminationReason}`));
        return;
      }
      if (killTimer !== null) clearTimeout(killTimer);
      resolvePromise({
        stdout: Buffer.concat(stdout).toString("utf8"),
        stderr: Buffer.concat(stderr).toString("utf8"),
        code,
      });
    });
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
          `scripts/real-backend-check.ts, which runs outside vitest.\n` +
          `\n` +
          `NOT running a test? Then a previous run was killed before it could clean up, ` +
          `and its marker file is still on disk. Delete it and this refusal stops:\n` +
          `  rm ${markerPathForDiagnostics()}`
      );
    case "spawn-real":
      return spawnReal(cmd, args, input);
  }
}
