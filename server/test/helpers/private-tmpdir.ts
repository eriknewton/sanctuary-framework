/**
 * Test-only: give one test file a private OS temp root and delete it when the file finishes.
 *
 * Import this module FIRST in a test file or in a shared fixture module. Importing it points
 * `TMPDIR` at a fresh folder, so every `os.tmpdir()` caller (the test's own `mkdtemp`, the
 * candidate build script, and any child process, which inherits the variable) creates its
 * folders inside that root; the cleanup returned from a `beforeAll` restores `TMPDIR` and removes
 * the root, which also runs when a test in the file failed or timed out. It is a beforeAll-returned
 * cleanup, not an `afterAll`, because the suite's `hooks: "stack"` order runs those after every
 * `afterAll` and after a test's own beforeAll-returned fixture teardown, so a fixture that unlinks
 * a path inside the root at teardown still finds it (an early removal fails that teardown with ENOENT).
 *
 * Why: a full-suite run on a build box left gigabytes of `pack-*`, `recipient-*` and
 * `snapshot-*` folders in the OS temp directory (disk filled three times on 2026-11-16). The
 * failure mode from the outside is a disk that fills slowly across runs with no failing test.
 *
 * Invariant: the root is created under the REAL temp directory captured at import time and is
 * never a path the operator owns (no login keychain, no `~/.sanctuary`); only this root is deleted.
 */
import { beforeAll } from "vitest";
import { chmodSync, lstatSync, mkdtempSync, readdirSync, realpathSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const PREFIX = "sanctuary-test-tmp-";
const previous = process.env.TMPDIR;
// realpath: on macOS tmpdir() sits under the /var symlink to /private/var, and tests compare canonical paths.
const root = realpathSync(mkdtempSync(join(tmpdir(), PREFIX)));
process.env.TMPDIR = root;

/** Fixtures chmod folders to 000 to witness refusals; make them traversable so removal cannot fail on a failed test. */
function reopen(path: string): void {
  let stat;
  try { stat = lstatSync(path); } catch { return; }
  if (!stat.isDirectory()) return;
  try { chmodSync(path, 0o700); } catch { /* Best effort: removal below reports the real failure. */ }
  let names: string[] = [];
  try { names = readdirSync(path); } catch { return; }
  for (const name of names) reopen(join(path, name));
}

let released = false;
/** Idempotent: restores the caller's TMPDIR and deletes the private root. */
export function releasePrivateTmpdir(): void {
  if (released) return;
  released = true;
  if (previous === undefined) delete process.env.TMPDIR; else process.env.TMPDIR = previous;
  // Refuse to delete anything that is not the folder this module created.
  if (!root.includes(PREFIX)) return;
  reopen(root);
  rmSync(root, { recursive: true, force: true });
}

/**
 * Vitest 4 runs a beforeAll-returned cleanup under the hook's own timeout (default 10 s). Removing a
 * root that holds a built evidence pack (about 1.2 GB measured for snapshot-artifact) took longer than
 * that on a hosted runner, so the teardown failed the file with "Hook timed out in 10000ms" although
 * every test passed. 120_000 = 12 x the 10 s default, headroom over the slowest observed removal.
 */
const CLEANUP_TIMEOUT_MS = 120_000;

try {
  beforeAll(() => releasePrivateTmpdir, CLEANUP_TIMEOUT_MS);
} catch {
  // A dynamic import from inside a running test cannot register a hook; fall back to process exit.
  process.once("exit", releasePrivateTmpdir);
}

export const privateTmpdirRoot = root;
