/**
 * Test isolation under a shared worker THREAD: make `os.homedir()` follow the
 * thread's `process.env.HOME`, exactly as it does in a process.
 *
 * Why this exists (register row `TEST-ISOLATION-SINGLE-WORKER-01`). Nineteen
 * suites isolate themselves by moving `process.env.HOME` to a temporary
 * directory for the life of one test (`test/helpers/temp-fortress.ts`), and
 * every default-resolution path in `src/` reaches the fortress through
 * `os.homedir()`, which on POSIX reads `$HOME`. That holds in Vitest's default
 * `forks` pool, where each file is a child PROCESS and `process.env` IS the
 * native environment. It does not hold in the `threads` pool that the Stryker
 * vitest runner forces (`pool: 'threads', maxWorkers: 1`): a worker thread's
 * `process.env` is a JavaScript copy, and libuv's `uv_os_homedir` reads the
 * process's native `environ`, so a test that moved `HOME` still resolves
 * `~/.sanctuary` to the OPERATOR's home and `assertHermeticStoragePath` in
 * `src/paths.ts` fires (correctly) with `NonHermeticStoragePathError`. That is
 * the failure the register describes; it was reproduced with one file alone,
 * so it is a pool property, not cross-file leakage.
 *
 * What this does: under Vitest only, replace `os.homedir` with a function that
 * returns `process.env.HOME` (POSIX) or `process.env.USERPROFILE` (Windows)
 * when set and otherwise defers to the original, then re-sync the builtin's
 * ESM named exports so `import { homedir } from "node:os"` sees the same
 * function. This reproduces the main-thread semantics inside a worker thread;
 * it never changes what production resolves, because production never runs
 * under Vitest and in a process the two sources agree.
 *
 * Invariant this must keep: `assertHermeticStoragePath` computes its operator
 * home from `os.userInfo().homedir` (the account record) FIRST, so the guard
 * is unaffected by this shim; the shim only makes the moved `HOME` reach the
 * resolution side. If the guard ever falls back to `homedir()` it must call
 * the ORIGINAL saved below, never the shimmed one.
 *
 * Must match the assertion in `test/structure/homedir-follows-thread-env.test.ts`,
 * which is the fail-before witness for this file (red on the base tree under
 * `--pool=threads --maxWorkers=1`, green with this setup file installed).
 */
import os from "node:os";
import { syncBuiltinESMExports } from "node:module";

const originalHomedir: () => string = os.homedir;

/** Exposed for the structural test, which asserts the shim is installed. */
export const HOMEDIR_SHIM_MARKER = "sanctuary-test-homedir-follows-env";

function homedirFollowingEnv(): string {
  const env =
    process.platform === "win32" ? process.env.USERPROFILE : process.env.HOME;
  if (env !== undefined && env.length > 0) return env;
  return originalHomedir();
}
Object.defineProperty(homedirFollowingEnv, "name", { value: HOMEDIR_SHIM_MARKER });

if (process.env.VITEST) {
  os.homedir = homedirFollowingEnv;
  // Named ESM imports of a builtin are snapshots until this call; without it
  // `import { homedir } from "node:os"` in src/ keeps the native function and
  // the shim reaches only callers that use `os.homedir()` through the default
  // export. Both spellings exist in src/.
  syncBuiltinESMExports();
}
