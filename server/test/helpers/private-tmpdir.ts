/**
 * Test-only: give one test file a private OS temp root and delete it when the file finishes.
 *
 * Import this module FIRST in a test file or in a shared fixture module. Importing it points
 * `TMPDIR` at a fresh folder, so every `os.tmpdir()` caller (the test's own `mkdtemp`, the
 * candidate build script, and any child process, which inherits the variable) creates its
 * folders inside that root; the teardown phase of a file-level `aroundAll` restores `TMPDIR` and
 * removes the root. That phase runs when a test failed or timed out and when a `beforeAll` or an
 * `afterAll` of the file threw, and the file still reports its own error. Bound: cleanup applies
 * only after the file-level `aroundAll` hook has been entered. The teardown phase runs after every
 * `afterAll`, every beforeAll-returned cleanup and the file-scoped fixture teardown, so a fixture
 * that unlinks a path inside the root at teardown still finds it (an early removal fails that
 * teardown with ENOENT). test/setup/master-write-leases.ts registers its `aroundAll` from a setup
 * file, which makes it the outer wrapper: its teardown phase follows this one.
 *
 * A Unix socket fixture does not fit under this root on macOS: the root takes 82 of the 103 usable
 * `sun_path` bytes there (56 for `/private/var/folders/<2>/<30>/T`, 26 for the root's own name). A
 * file that binds one keeps the socket directory under a short parent and removes it itself; see
 * SHORT_SOCKET_TMP_PARENT in test/castle-wall/runtime/enforcement-availability.test.ts.
 *
 * Why: a full-suite run on a build box left gigabytes of `pack-*`, `recipient-*` and
 * `snapshot-*` folders in the OS temp directory (disk filled three times on 2026-11-16). The
 * failure mode from the outside is a disk that fills slowly across runs with no failing test.
 *
 * Invariant: the root is created under the REAL temp directory captured at import time and is
 * never a path the operator owns (no login keychain, no `~/.sanctuary`); only this root is deleted.
 */
import { aroundAll } from "vitest";
import { chmodSync, lstatSync, mkdtempSync, readdirSync, realpathSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

// 19 bytes; with the separator and mkdtemp's 6 random characters the root adds 26 bytes to every path
// under it. Must match the 26-byte figure beside `SHORT_SOCKET_TMP_PARENT` in
// test/castle-wall/runtime/enforcement-availability.test.ts.
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
 * Vitest 4 bounds the teardown phase of an `aroundAll` hook by the hook's own timeout (default: the
 * configured `hookTimeout`, 10 s). Removing a root that holds a built evidence pack (about 1.2 GB
 * measured for snapshot-artifact) takes longer than that on a hosted runner.
 * 120_000 = 12 x the 10 s default, headroom over the slowest observed removal.
 */
const CLEANUP_TIMEOUT_MS = 120_000;

try {
  // Invariant: once this hook is entered, the release runs after the suite body returns, whatever the
  // body did. Vitest records a throwing beforeAll, test or afterAll on the file before `runSuite()`
  // resolves, so the release never replaces that error; a release failure is reported beside it.
  aroundAll(async (runSuite) => {
    const errors: unknown[] = [];
    try { await runSuite(); } catch (error) { errors.push(error); }
    try { releasePrivateTmpdir(); } catch (error) { errors.push(error); }
    if (errors.length > 1) throw new AggregateError(errors, "File run and private temp root release both failed");
    if (errors.length > 0) throw errors[0];
  }, CLEANUP_TIMEOUT_MS);
} catch {
  // Registration throws only where no Vitest runner exists (a plain Node process that imports a
  // fixture module); such a process runs its exit handlers, so the release is tied to process exit.
  process.once("exit", releasePrivateTmpdir);
}

export const privateTmpdirRoot = root;
