/**
 * Storage permission migration — tightens pre-existing files in
 * ~/.sanctuary/ to owner-only (dirs 0o700, files 0o600).
 *
 * Runs once per server start. FAIL-CLOSED (LD3, MUST-NEVER #5): a chmod
 * failure on an entry that must be owner-only aborts startup instead of
 * being logged and swallowed. The permission layer is a claimed security
 * control (owner-only at-rest storage); continuing to serve after failing
 * to apply it would silently run with that control absent while every
 * other guarantee (encryption, audit log) implied it was still in force.
 * The only silent case is a MISSING root/entry (first run, or a benign
 * readdir/stat race against a path that vanished mid-walk) — that is not a
 * degrade, there is nothing there to have the wrong permissions.
 */

import { readdir, stat, chmod } from "node:fs/promises";
import { join } from "node:path";

/**
 * Recursively tighten permissions under `root` so that:
 *   - directories are 0o700 (owner rwx only)
 *   - files are 0o600 (owner rw only)
 *
 * Skips entries that are already correct. A missing root or a
 * vanished-mid-walk entry is silently skipped (not a failure: there is
 * nothing on disk to have lax permissions). Any OTHER failure — in
 * particular a `chmod` that does not succeed on an entry that exists and is
 * mispermissioned — throws and is NOT caught here, so it propagates to the
 * caller and fails startup closed. See the module header for why.
 */
export async function tightenStoragePermissions(root: string): Promise<void> {
  await tightenEntry(root);
}

async function tightenEntry(path: string): Promise<void> {
  let info;
  try {
    info = await stat(path);
  } catch {
    return; // Entry vanished, or root/path doesn't exist yet (first run).
  }

  if (info.isDirectory()) {
    const current = info.mode & 0o777;
    if (current !== 0o700) {
      // FAIL-CLOSED: an uncaught chmod failure here aborts startup (see
      // module header). Do not wrap this in a try/catch that logs and
      // continues — that is the exact silent degrade MUST-NEVER #5 forbids.
      await chmod(path, 0o700);
    }
    // Recurse into children
    let entries: string[];
    try {
      entries = await readdir(path);
    } catch {
      return;
    }
    for (const entry of entries) {
      await tightenEntry(join(path, entry));
    }
  } else if (info.isFile()) {
    const current = info.mode & 0o777;
    if (current !== 0o600) {
      // FAIL-CLOSED: see the directory branch above.
      await chmod(path, 0o600);
    }
  }
}
