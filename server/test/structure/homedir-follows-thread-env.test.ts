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
 * Fail-before: on the base tree this file is red under
 * `npx vitest run --pool=threads --maxWorkers=1 test/structure/homedir-follows-thread-env.test.ts`
 * (a worker thread's `os.homedir()` reads the native environment, not the
 * thread's `process.env` copy) and green under the default pool; with
 * `test/setup/homedir-follows-env.ts` listed in vitest.config.ts setupFiles it is
 * green in both. Must match the shim in that setup file (the marker name and
 * the fallback); the marker is repeated here as a literal, not imported.
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

  it("still defers to the account record when HOME is unset", () => {
    const original = process.env.HOME;
    try {
      delete process.env.HOME;
      const fromOs = os.homedir();
      expect(typeof fromOs).toBe("string");
      expect(fromOs.length).toBeGreaterThan(0);
    } finally {
      if (original !== undefined) process.env.HOME = original;
    }
  });
});
