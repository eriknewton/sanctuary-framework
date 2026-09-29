/**
 * Test-isolation invariant: a moved `process.env.HOME` is what `os.homedir()`
 * returns, in every Vitest pool.
 *
 * Capability: the per-test fortress redirection (`test/helpers/temp-fortress.ts`)
 * isolates a test from the operator's own `~/.sanctuary` whether the file runs
 * in a child process (the default `forks` pool) or in a shared worker thread
 * (the mutation tooling's `pool: 'threads', maxWorkers: 1`). Register row
 * `TEST-ISOLATION-SINGLE-WORKER-01`.
 *
 * Fail-before: on the base tree (setup file not listed), test 1 alone is
 * ALREADY GREEN under the default `forks` pool, because a forked child
 * process's native `os.homedir()` already follows `process.env.HOME`; that
 * test cannot by itself show the shim is installed. Test 2 (the marker) is
 * RED on the base tree in EVERY pool, including the default pool, because
 * `os.homedir.name` is Node's own `wrappedFn`, not this file's marker; under
 * `--pool=threads --maxWorkers=1` test 1 is also red there (a worker thread's
 * `os.homedir()` reads the native environment, not the thread's `process.env`
 * copy), so the base tree shows 2 failed / 1 passed under threads/1. With
 * `test/setup/homedir-follows-env.ts` listed in vitest.config.ts setupFiles,
 * all three tests are green in both pools. Register row
 * `TEST-ISOLATION-SINGLE-WORKER-01`. Must match the shim in that setup file
 * (the marker name and the fallback); the marker is repeated here as a
 * literal, not imported.
 */
import { describe, expect, it } from "vitest";
import os from "node:os";
import { homedir } from "node:os";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
// The marker is a LITERAL here on purpose: importing the setup module would
// install the shim as a side effect and make this file green on a tree whose
// vitest.config.ts does not list it, which is exactly the fail-before this
// file exists to witness. Must match HOMEDIR_SHIM_MARKER in
// test/setup/homedir-follows-env.ts.
const HOMEDIR_SHIM_MARKER = "sanctuary-test-homedir-follows-env";

describe("os.homedir() follows the test's process.env.HOME in every pool", () => {
  it("returns a moved HOME through both the default export and the named import", () => {
    const original = process.env.HOME;
    const moved = mkdtempSync(join(tmpdir(), "sanctuary-homedir-shim-"));
    try {
      process.env.HOME = moved;
      // Both spellings exist in src/; the shim must reach both, or a module
      // that used the named import would still resolve the operator's home.
      expect(os.homedir()).toBe(moved);
      expect(homedir()).toBe(moved);
    } finally {
      if (original === undefined) delete process.env.HOME;
      else process.env.HOME = original;
      rmSync(moved, { recursive: true, force: true });
    }
  });

  it("is the installed shim, not a coincidence of the pool", () => {
    // In the forks pool the native function already follows HOME, so the
    // first test alone cannot tell the shim is installed; this pins it.
    expect(os.homedir.name).toBe(HOMEDIR_SHIM_MARKER);
  });

  it("still defers to the account record when HOME is unset, not to a leftover redirected value", () => {
    const original = process.env.HOME;
    const moved = mkdtempSync(join(tmpdir(), "sanctuary-homedir-unset-"));
    try {
      // Prime the redirected answer first so the fallback below is proven to
      // change, not just to be non-empty (a constant would pass the old
      // assertion without ever reaching originalHomedir()'s native call).
      process.env.HOME = moved;
      expect(os.homedir()).toBe(moved);
      delete process.env.HOME;
      const fromOs = os.homedir();
      // os.userInfo().homedir is unpatched by this shim (see the setup file's
      // invariant comment) and, on POSIX, is exactly what the native
      // os.homedir() falls back to when HOME is unset (the account record via
      // getpwuid), so it is a value the shim cannot coincidentally match
      // unless it truly called the saved native function.
      expect(fromOs).toBe(os.userInfo().homedir);
      expect(fromOs).not.toBe(moved);
    } finally {
      if (original === undefined) delete process.env.HOME;
      else process.env.HOME = original;
      rmSync(moved, { recursive: true, force: true });
    }
  });
});
