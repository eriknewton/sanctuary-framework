/**
 * N4 (coordinator gate, 2026-08-22): the shared "is a fortress mid-recovery"
 * check, factored out of server/src/exit/bundle.ts so BOTH the exit module
 * AND the write chokepoints in cognitive/state-store.ts and
 * reputation/reputation-store.ts can depend on it without either of those
 * lower-level modules importing FROM the exit module (bundle.ts already
 * imports StateStore and ReputationStore; the reverse import would be a
 * cycle). This file has no dependency on cognitive/ or reputation/, so it
 * is safe for both to import.
 *
 * CONTRACT PIN: `EXIT_IMPORT_JOURNAL_NAMESPACE` here is the SAME literal
 * server/src/exit/bundle.ts re-exports under the same name (bundle.ts
 * imports it from here rather than defining its own copy) - "must match"
 * is enforced by construction, not by two independent literals.
 */

import type { StorageBackend } from "./interface.js";

export const EXIT_IMPORT_JOURNAL_NAMESPACE = "_exit_import_journal";

/**
 * True iff a durable exit-import rollback journal currently exists on this
 * storage - i.e. an import is either still in flight (the journal is this
 * import's own, not yet cleaned up) or was interrupted and is pending
 * recovery. One `storage.list()` per call, deliberately uncached: the
 * write chokepoints that call this need the CURRENT answer on every write,
 * not a stale one from earlier in the same process's lifetime.
 */
export async function hasInterruptedExitImport(
  storage: StorageBackend
): Promise<boolean> {
  const entries = await storage.list(EXIT_IMPORT_JOURNAL_NAMESPACE);
  return entries.length > 0;
}

/**
 * Thrown by a write chokepoint (StateStore.write, ReputationStore's write
 * paths) when `hasInterruptedExitImport` is true and the caller has not
 * passed the exit-import module's own bypass. Named so a caller can branch
 * on it (an MCP tool handler catches this specifically to audit the
 * refusal and return a clean tool-result error, rather than an unhandled
 * throw).
 */
export class InterruptedExitImportPendingError extends Error {
  constructor(context: string) {
    super(
      `Refusing to write (${context}): an exit-import rollback journal exists ` +
        "for this fortress, meaning an import is in progress or pending " +
        "recovery. Run any `sanctuary exit` verb (for example `sanctuary exit " +
        "verify`) to recover, then retry."
    );
    this.name = "InterruptedExitImportPendingError";
  }
}
