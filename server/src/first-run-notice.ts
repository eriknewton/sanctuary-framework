/**
 * Sanctuary MCP Server: zero-outbound-by-default first-run notice.
 *
 * On the FIRST startup against a given fortress (state directory), print a
 * one-time stderr notice explaining that Sanctuary makes no unrequested
 * outbound connection, and how to check for updates on demand. On every
 * subsequent startup the notice is silent (a persisted marker file records
 * that it already fired).
 *
 * FAIL OPEN (AGENTS.md-adjacent invariant: this is a best-effort UX notice,
 * never a gate): any I/O error reading or writing the marker — permission
 * denied, read-only filesystem, missing directory, race with another
 * process — is swallowed. The notice may print more than once (harmless,
 * advisory-only text) or not print at all in a broken environment, but it
 * must NEVER throw, block, or fail server startup.
 */

import { mkdir, readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";

/** Marker filename, resolved under the fortress/storage directory. */
const MARKER_FILENAME = "first-run-notice-shown";

export const ZERO_OUTBOUND_NOTICE =
  "Sanctuary makes no unrequested outbound connection. Run 'sanctuary check-updates' to check for updates.";

/**
 * Print the zero-outbound first-run notice to stderr exactly once per
 * fortress, then persist a marker so it never prints again for that
 * fortress. Never throws; any I/O failure is treated as "could not persist
 * the marker" and swallowed rather than blocking or crashing startup.
 *
 * @param storagePath - the resolved fortress/storage directory (same
 *   resolution other modules use; NOT hardcoded to ~/.sanctuary).
 * @param out - injectable sink for tests; defaults to process.stderr.
 */
export async function printFirstRunNoticeOnce(
  storagePath: string,
  out: { write(chunk: string): unknown } = process.stderr,
): Promise<void> {
  const markerPath = join(storagePath, MARKER_FILENAME);

  try {
    await readFile(markerPath);
    // Marker present: already shown. Stay silent.
    return;
  } catch {
    // ENOENT (not yet shown) or any other read failure (permissions,
    // missing directory, etc.) both fall through to "show the notice";
    // an unreadable marker must never be mistaken for a hard block.
  }

  try {
    out.write(`${ZERO_OUTBOUND_NOTICE}\n`);
  } catch {
    // Even the write itself is best-effort; a broken stderr stream must
    // not prevent marker creation from being attempted below.
  }

  try {
    await mkdir(storagePath, { recursive: true, mode: 0o700 });
    // Owner-only from the first byte: the marker is a direct fortress-root
    // child, and once a file-grant fortress traverse ACE is live the agent
    // uid can open root children by known name. The content is not secret,
    // but every direct-root writer holds the same owner-only-at-create line
    // (see the FORTRESS-DIR TRAVERSAL note in file-grant/fs-ops.ts).
    await writeFile(markerPath, "1\n", { mode: 0o600 });
  } catch {
    // Fail open: could not persist the marker (read-only fs, missing
    // parent, permissions, concurrent writer, etc.). The notice may print
    // again next startup; that is harmless and strictly preferable to
    // blocking or failing the server over a UX nicety.
  }
}
