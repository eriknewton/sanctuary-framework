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
 * True only for ENOENT (the entry does not exist). This is the ONLY error
 * class this migration treats as benign: a missing root/entry (first run) or
 * an entry that vanished between `stat` and a follow-up op (a benign
 * concurrent-walk race) has nothing on disk to hold lax permissions. Every
 * OTHER error — EACCES/EPERM (cannot read or cannot tighten an entry that
 * DOES exist), EROFS, EIO — must fail startup closed (MUST-NEVER #5): swallowing
 * it would leave the claimed owner-only control silently absent on a real
 * on-disk entry. Distinguishing ENOENT is what keeps "fail closed on a real
 * permission failure" from collapsing into "swallow everything" (the exact
 * bug this file was fixing; a bare `catch {}` masked EACCES as benign-missing).
 */
function isBenignMissing(err: unknown): boolean {
  return (err as NodeJS.ErrnoException)?.code === "ENOENT";
}

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
  } catch (err) {
    // ENOENT only: entry doesn't exist (first run) or vanished mid-walk.
    // A stat failure that is NOT ENOENT (EACCES on an unreadable ancestor,
    // EIO) is a real problem on an existing path — fail closed, do not skip.
    if (isBenignMissing(err)) return;
    throw err;
  }

  if (info.isDirectory()) {
    const current = info.mode & 0o777;
    if (current !== 0o700) {
      // FAIL-CLOSED: a chmod failure on an entry that EXISTS aborts startup
      // (see module header + isBenignMissing). Only a mid-walk vanish
      // (ENOENT) is benign here — every other failure (EPERM/EROFS/EACCES)
      // means the owner-only control could not be applied to a real entry
      // and must not be swallowed (MUST-NEVER #5).
      await tightenMode(path, 0o700);
    }
    // Recurse into children
    let entries: string[];
    try {
      entries = await readdir(path);
    } catch (err) {
      // ENOENT only (dir vanished mid-walk). An EACCES readdir on a dir that
      // exists would silently skip a whole subtree, leaving it un-tightened —
      // that is the silent degrade MUST-NEVER #5 forbids, so it throws.
      if (isBenignMissing(err)) return;
      throw err;
    }
    for (const entry of entries) {
      await tightenEntry(join(path, entry));
    }
  } else if (info.isFile()) {
    const current = info.mode & 0o777;
    if (current !== 0o600) {
      // FAIL-CLOSED: see the directory branch above.
      await tightenMode(path, 0o600);
    }
  }
}

/**
 * chmod that fails startup closed on any real error but tolerates the one
 * benign race: the entry vanished (ENOENT) between the `stat` above and this
 * `chmod`. Without this, a concurrent cleanup deleting a temp file mid-walk
 * would abort an otherwise-healthy startup; WITH a bare swallow, an EPERM
 * (cannot tighten a real mispermissioned entry) would be masked. Only ENOENT
 * is benign — see isBenignMissing.
 *
 * ACCEPTED RESIDUAL (LD3 gate): if an entry is deleted after `stat` and then
 * RE-CREATED permissive before the one-shot boot walk finishes, its ENOENT here
 * reads as benign and the recreated entry is not tightened this boot (it is on
 * the next). This is a narrow boot-time TOCTOU that requires an attacker who
 * ALREADY has write access to ~/.sanctuary (who could simply create permissive
 * files that this walk tightens on the next boot), and the at-rest data stays
 * encrypted regardless — the mode is defense-in-depth, not the confidentiality
 * boundary. Closing it fully needs fd-stable operations (openat + fchmod), a
 * disproportionate rewrite for this exposure; tracked as a disclosed residual.
 */
async function tightenMode(path: string, mode: number): Promise<void> {
  try {
    await chmod(path, mode);
  } catch (err) {
    if (isBenignMissing(err)) return;
    throw err;
  }
}
