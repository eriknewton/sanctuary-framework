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
import {
  withCrossProcessLock,
  CrossProcessLockError,
  ExitAdmissionLockError,
} from "./cross-process-lock.js";
export { ExitAdmissionLockError };

export const EXIT_IMPORT_JOURNAL_NAMESPACE = "_exit_import_journal";

/**
 * MEDIUM-C (Codex gate, 2026-08-22): one small append-only record per
 * journal-set location the exit-import module actually writes, keyed by
 * `${importId}:${locationDedupeKey(loc)}` (server/src/exit/bundle.ts) -
 * NOT embedded in the main journal record, so recording a post-image is a
 * single small write instead of re-serializing and rewriting every
 * pre-image the journal holds on every entry. Cleaned up alongside the
 * main journal entry (deleteImportJournal, bundle.ts).
 */
export const EXIT_IMPORT_JOURNAL_POSTIMAGE_NAMESPACE =
  "_exit_import_journal_postimage";

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

/**
 * HIGH-B (Codex gate, 2026-08-22, "the final mechanism, authorized"): the
 * check/write gap the journal re-checks (F1) narrow but cannot close - a
 * checked-then-published durable marker still has a window between the
 * check and the publish. `withExitAdmissionLock` makes exactly that step
 * atomic across processes, reusing the proven O_EXCL lock primitive
 * (`withCrossProcessLock`) rather than a new one: acquire, run the
 * check-then-publish-a-durable-marker step, release. Once a marker
 * (the import journal or the rotation journal) is durably on disk, the
 * EXISTING checks (`hasInterruptedExitImport`, a `_meta/ROTATION_JOURNAL_KEY`
 * read) continue to work correctly without holding this lock any longer -
 * this is an ADMISSION lock, not a lock over the whole bulk operation.
 *
 * Four owners share ONE lock file under the exit-import journal's own
 * namespace: `import` (around writeImportJournal), `rotate`/`resume`
 * (around the first conversion write, core/master-rotation.ts), and
 * `recovery` (for the whole of recoverInterruptedExitImports - a bounded,
 * quick pass, unlike the other three).
 *
 * NO AUTO-STALE-BREAK: inherited unchanged from withCrossProcessLock (see
 * that module's header for the #871 TOCTOU lesson this deliberately does
 * not reopen). A stale lock refuses with the SAME operator remediation
 * shape a refused journal already uses - inspect before removing, never
 * remove first.
 */
export type ExitAdmissionOwner = "import" | "rotate" | "resume" | "recovery";

const EXIT_ADMISSION_LOCK_FILE = "admission.lock";

/**
 * Bounded wait before an admission-lock contention fails closed. Short by
 * design: the critical section this lock protects is a single
 * check-then-publish step or a bounded recovery pass, never the whole
 * bulk conversion/rekey loop those durable markers otherwise protect.
 */
const EXIT_ADMISSION_LOCK_TIMEOUT_MS = 10_000;

export async function withExitAdmissionLock<T>(
  storage: StorageBackend,
  owner: ExitAdmissionOwner,
  operation: () => Promise<T>
): Promise<T> {
  try {
    return await withCrossProcessLock(
      storage,
      EXIT_IMPORT_JOURNAL_NAMESPACE,
      EXIT_ADMISSION_LOCK_FILE,
      operation,
      {
        timeoutMs: EXIT_ADMISSION_LOCK_TIMEOUT_MS,
        metadata: { owner, pid: process.pid },
      }
    );
  } catch (err) {
    if (err instanceof CrossProcessLockError) {
      throw new ExitAdmissionLockError(
        `refusing to proceed (${owner}): another exit-import or master-rotation ` +
          "operation holds the admission lock for this fortress, or a prior " +
          "holder crashed while holding it. Run any `sanctuary exit` verb (for " +
          "example `sanctuary exit verify`) to recover, then retry. If no other " +
          "Sanctuary operation is actually running against this fortress, " +
          "inspect the lock directly under <fortress state path>/" +
          `${EXIT_IMPORT_JOURNAL_NAMESPACE}/${EXIT_ADMISSION_LOCK_FILE} before ` +
          "removing it - do not remove it first."
      );
    }
    throw err;
  }
}
