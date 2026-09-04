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
 * CONTRACT PIN (F1, Exit V2 D1 operator finding, 2026-08-23): the one verb
 * name every operator-facing recovery hint in this file (and in
 * `cli/doctor.ts`, which imports this constant via `exit/bundle.ts`'s
 * re-export) must name - and the exact string `exit/cli.ts`'s
 * `command === EXIT_RECOVERY_VERB` dispatch branch matches against. Before
 * this pin existed, every hint below hardcoded `sanctuary exit verify` as
 * "the verb that recovers a fortress"; `verify` only checks a bundle
 * directory and never opens the local fortress, so an operator following
 * that hint got a clean PASS/PASS while the interrupted import stayed on
 * disk (drill D1-OP-F1). Interpolate this constant into every recovery
 * hint instead of retyping the verb name, so a future rename cannot
 * silently strand a hint on a verb that no longer does the job.
 */
export const EXIT_RECOVERY_VERB = "recover";

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
        // F1/round-3: must name EXIT_RECOVERY_VERB (defined above in this
        // same file) AND the exact "--fortress <fortress path>" form -
        // recover takes no ambient path (exit/cli.ts's
        // ExitRecoverFortressPathRequiredError).
        `recovery. Run \`sanctuary exit ${EXIT_RECOVERY_VERB} --fortress ` +
        "<fortress path>` to recover, then retry."
    );
    this.name = "InterruptedExitImportPendingError";
  }
}

/**
 * HIGH-B (Codex gate, 2026-08-22, "the final mechanism, authorized"): the
 * check/write gap the journal re-checks (F1) narrow but cannot close - a
 * checked-then-published durable marker still has a window between the
 * check and the publish. `withExitAdmissionLock` makes that step atomic
 * across processes, reusing the proven O_EXCL lock primitive
 * (`withCrossProcessLock`) rather than a new one.
 *
 * HIGH-1 (Codex gate, 2026-08-22): the lock spans the WHOLE import /
 * rotation / recovery, not only the check-then-publish step - a short
 * lock left every write AFTER publish (the rest of the rekey/reputation
 * loop, or the rest of a rotation's conversion) reachable by a
 * concurrent recovery pass, which could then match a still-running
 * import's own writes against their own just-recorded post-images,
 * classify them safe-restore, and revert a write that import was still
 * making. Holding the lock for the operation's whole duration is what
 * makes that impossible: a concurrent open cannot even acquire the lock
 * until the live operation releases it.
 *
 * Five owners share ONE lock file under the exit-import journal's own
 * namespace: `import` (from the pre-image snapshot through
 * deleteImportJournal, exit/bundle.ts), `rotate`/`resume` (from the
 * journal re-check through finalize, core/master-rotation.ts), and
 * `recovery` (for the whole of recoverInterruptedExitImports), plus the
 * bounded C3 `memory_migration` page/abort/repair transaction. This keeps a
 * page from observing split-key or half-imported corpus state.
 *
 * NO AUTO-STALE-BREAK: inherited unchanged from withCrossProcessLock (see
 * that module's header for the #871 TOCTOU lesson this deliberately does
 * not reopen). A stale lock refuses with the SAME operator remediation
 * shape a refused journal already uses - inspect before removing, never
 * remove first. A kill while an owner holds this lock therefore leaves
 * a fortress that refuses to open (via `recovery`'s own lock acquire)
 * until an operator clears the stale lock file - doctor's admission-lock
 * check (cli/doctor.ts) surfaces this.
 *
 * WHAT THIS LOCK DELIBERATELY DOES NOT COVER (Codex gate HIGH,
 * 2026-08-23): an ORDINARY StateStore.write() never acquires this lock -
 * only import/rotate/resume/recovery do. A writer that races journal
 * publication is detected at recovery, not prevented: post-images are
 * hashed from the import's own known written bytes at the moment they are
 * written, never re-derived afterward, so a racing writer's bytes can
 * never match one, and restoreStorageSnapshots reports the location
 * diverged rather than restoring it. Widening this lock to every ordinary
 * write was considered and rejected - it would serialize the whole
 * fortress behind any in-flight import/rotation/recovery for no
 * correctness gain the post-image check does not already provide.
 */
export type ExitAdmissionOwner =
  | "import"
  | "rotate"
  | "resume"
  | "recovery"
  | "memory_migration"
  | "memory_archive_import"
  | "memory_bad_signer"
  | "memory_signer_prune";

const EXIT_ADMISSION_LOCK_FILE = "admission.lock";

/**
 * Bounded wait before an admission-lock contention fails closed. This
 * bounds how long a CONTENDER waits to acquire, not how long the holder
 * may run - the holder keeps the lock for its whole operation (see the
 * doc comment above); a caller that cannot acquire within this window
 * fails closed rather than waiting indefinitely on a live or crashed
 * holder.
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
    // Only acquisition/reaper failure is an admission refusal. A
    // CrossProcessLockError thrown BY the protected operation (notably custody
    // holder-loss during rotation) must retain its real classification instead
    // of being rewritten as fictitious admission-lock contention.
    if (
      err instanceof CrossProcessLockError
      && err.kind !== "holder-lost"
      && err.kind !== "capability"
      && err.kind !== "poisoned"
    ) {
      throw new ExitAdmissionLockError(
        `refusing to proceed (${owner}): another exit-import, master-rotation, or memory-migration ` +
          "operation holds the admission lock for this fortress, or a prior " +
          // F1/round-3: must name EXIT_RECOVERY_VERB (defined above in
          // this same file) AND the exact "--fortress <fortress path>"
          // form - recover takes no ambient path (exit/cli.ts's
          // ExitRecoverFortressPathRequiredError).
          `holder crashed while holding it. Run \`sanctuary exit ${EXIT_RECOVERY_VERB} ` +
          "--fortress <fortress path>` to recover, then retry. If no other " +
          "Sanctuary operation is actually running against this fortress, " +
          "inspect the lock directly under <fortress state path>/" +
          `${EXIT_IMPORT_JOURNAL_NAMESPACE}/${EXIT_ADMISSION_LOCK_FILE} before ` +
          "removing it - do not remove it first."
      );
    }
    throw err;
  }
}
