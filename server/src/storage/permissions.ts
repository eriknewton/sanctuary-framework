/**
 * Storage permission migration — tightens pre-existing files in
 * ~/.sanctuary/ to owner-only (dirs 0o700, files 0o600).
 *
 * Runs once per server start. Non-fatal: logs warnings on failure
 * but does not prevent startup.
 */

import { readdir, stat, chmod } from "node:fs/promises";
import { join } from "node:path";

/**
 * Recursively tighten permissions under `root` so that:
 *   - directories are 0o700 (owner rwx only)
 *   - files are 0o600 (owner rw only)
 *
 * Skips entries that are already correct. Best-effort: errors on
 * individual entries are logged to stderr but do not throw.
 */
export async function tightenStoragePermissions(root: string): Promise<void> {
  try {
    await tightenEntry(root);
  } catch {
    // Root dir itself inaccessible — nothing we can do
  }
}

async function tightenEntry(path: string): Promise<void> {
  let info;
  try {
    info = await stat(path);
  } catch {
    return; // Entry vanished or unreadable
  }

  if (info.isDirectory()) {
    const current = info.mode & 0o777;
    if (current !== 0o700) {
      try {
        await chmod(path, 0o700);
      } catch (err) {
        // SAFETY: no structured logger module is wired in server/src/ yet; until one lands, raw stderr is the runtime warning channel for this site.
        console.error(`  Warning: could not chmod dir ${path}: ${(err as Error).message}`);
      }
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
      try {
        await chmod(path, 0o600);
      } catch (err) {
        // SAFETY: no structured logger module is wired in server/src/ yet; until one lands, raw stderr is the runtime warning channel for this site.
        console.error(`  Warning: could not chmod file ${path}: ${(err as Error).message}`);
      }
    }
  }
}
