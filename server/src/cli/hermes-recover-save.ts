import { channel } from "node:diagnostics_channel";
import { lstat, stat, unlink } from "node:fs/promises";
import { join, resolve } from "node:path";
import { CUSTODY_RELEASE_FAILURE_MESSAGE } from "./custody-release-message.js";
import { consumeFlagValue } from "./argv.js";
import { IdentityManager } from "../cognitive/tools.js";
import {
  CUSTODY_WRITE_LOCK_NAMESPACE, MASTER_ROTATION_BARRIER_NAME,
  unlockExistingMasterReadOnly,
} from "../core/master-custody.js";
import { fortressIdFromStoragePath } from "../dashboard/v1_1/wiring.js";
import { canonicalHermesFortressPath } from "../hermes-memory-bridge/index.js";
import { createSdwMemoryAdapter } from "../index.js";
import { recoverInterruptedExitImportsOrThrow } from "../exit/bundle.js";
import { AuditLog } from "../operational/audit-log.js";
import {
  HERMES_INSERT_INTENT_KEY, HERMES_INSERT_INTENT_NAMESPACE,
  MEMORY_BATCH_LOCK_NAMESPACE,
  readHermesSaveIntent, rollbackHermesSaveRecords, sdwMemoryCorpusBatchLockFile,
} from "../sdw/adapters/sdw-memory-backend.js";
import { SdwMemoryProvenanceMigration } from "../sdw/memory-provenance-migration.js";
import {
  createPrimaryMemoryProvenancePublicKeyResolver, createPrimaryMemoryProvenanceSigningHandleResolver,
} from "../sdw/memory-provenance-signing.js";
import { CrossProcessLockError, withExclusiveMasterRotationBarrier } from "../storage/cross-process-lock.js";
import { FilesystemStorage } from "../storage/filesystem.js";
import { EXIT_IMPORT_JOURNAL_NAMESPACE, hasInterruptedExitImport } from "../storage/exit-import-journal.js";
import { ReadOnlyStorageGuard } from "../storage/read-only-guard.js";

const HELP = "Usage: sanctuary hermes recover-save --fortress <dir> [--apply] [--passphrase <value>] [--json]\nReport an unfinished save; --apply keeps a verified save or rolls back an unpublished save.\n";
const UNCLASSIFIED = "The save could not be classified and nothing was changed.";

// Sixteen examined entries bound both nested causes and wide aggregates, including repeated references.
// Must match REFUSAL_ERROR_NODE_LIMIT in test/cli/hermes-recover-save.test.ts.
const REFUSAL_ERROR_NODE_LIMIT = 16;
const refusalChannel = channel("sanctuary.hermes-recover-save.refusal");

function publishCustodyRefusal(cause: unknown): void {
  if (!refusalChannel.hasSubscribers) return;
  const seen = new Set<Error>();
  const published = new Set<string>();
  let remaining = REFUSAL_ERROR_NODE_LIMIT;
  function visit(error: unknown): void {
    if (remaining === 0) return;
    remaining--;
    if (!(error instanceof Error) || seen.has(error)) return;
    seen.add(error);
    if (error instanceof CrossProcessLockError) {
      const lockKind = error.kind;
      // Runtime allowlisting prevents a mutated error from exporting path-bearing fields.
      switch (lockKind) {
        case "capability": case "scaffold-integrity": case "contention": case "holder-lost":
        case "operation_aborted": case "poisoned": case "io": {
          const reason = error.diagnosticReason === "probe-unknown" || error.diagnosticReason === "reaper-deadline"
            ? error.diagnosticReason : lockKind;
          const key = `${lockKind}:${reason}`;
          if (!published.has(key)) {
            published.add(key);
            refusalChannel.publish({ lockKind, reason });
          }
        }
      }
    }
    if (error instanceof AggregateError && Array.isArray(error.errors)) {
      for (const nested of error.errors) {
        if (remaining === 0) break;
        visit(nested);
      }
    }
    if (error.cause !== undefined) visit(error.cause);
  }
  visit(cause);
}

function containsCustodyError(error: unknown): boolean {
  const seen = new Set<unknown>();
  const matches = (value: unknown): boolean => {
    // Aggregate members can share references or cycles, so each member is examined only once.
    if (seen.has(value)) return false;
    seen.add(value);
    if (value instanceof AggregateError) return value.errors.some(matches);
    return value instanceof CrossProcessLockError;
  };
  return matches(error);
}

/**
 * Inspect or recover one unfinished Hermes save in the explicitly selected, stopped fortress.
 *
 * State                 | Report                 | Apply
 * Interrupted import    | Refuse without changes | Recover first or refuse
 * No intent             | Nothing to recover     | Nothing to recover
 * Unpublished document  | Propose rollback       | Rollback, intent deletion, audit
 * Verified publication  | Propose keeping save   | Intent deletion, audit
 * Unreadable record     | Refuse without changes | Refuse without changes
 * Live custody lease    | Refuse without changes | Refuse without changes
 * Rollback failure      | Unreachable            | Keep intent, refuse
 * Audit failure         | Unreachable            | Report failure after action
 */
export async function runHermesRecoverSave(options: {
  argv: string[];
  env?: NodeJS.ProcessEnv;
  stdout?: Pick<NodeJS.WriteStream, "write">;
  stderr?: Pick<NodeJS.WriteStream, "write">;
}): Promise<number> {
  const out = options.stdout ?? process.stdout;
  const err = options.stderr ?? process.stderr;
  const env = options.env ?? process.env;
  if (options.argv.length === 0 || options.argv.includes("--help") || options.argv.includes("-h")) {
    out.write(HELP);
    return 0;
  }
  if (options.argv[0] !== "recover-save") { err.write(HELP); return 2; }
  const fortress = consumeFlagValue(options.argv.slice(1), "--fortress");
  const passphrase = consumeFlagValue(fortress.argv, "--passphrase");
  const usage = fortress.error ?? passphrase.error ?? (!fortress.value ? "--fortress is required" : undefined);
  if (usage !== undefined) { err.write(`Error: ${usage}\n`); return 2; }
  if (passphrase.argv.some(arg => arg !== "--apply" && arg !== "--json") ||
      new Set(passphrase.argv).size !== passphrase.argv.length) {
    err.write("Only --fortress, --passphrase, --apply and --json are accepted.\n");
    return 2;
  }
  const apply = passphrase.argv.includes("--apply");
  const json = passphrase.argv.includes("--json");
  let admitted = false;
  let callbackReturned = false;
  let actionStarted = false;
  let actionFinished = false;
  let importsRecovered = false;
  const recordCallbackReturn = async (operation: () => Promise<number>): Promise<number> => {
    const result = await operation();
    // Only a resolved callback separates custody finalization from operation failures, including refusal returns.
    callbackReturned = true;
    return result;
  };
  try {
    // Storage and encrypted record identity must use the same canonical path as bridge startup.
    const storagePath = await canonicalHermesFortressPath({ home: env.HOME, fortressDir: resolve(fortress.value!), uid: process.getuid!() });
    const storage = new FilesystemStorage(join(storagePath, "state"));
    // A missing or unsafe fortress must refuse before lock resolution can create its namespace.
    const meta = await lstat(storage.namespacePath(CUSTODY_WRITE_LOCK_NAMESPACE));
    if (!meta.isDirectory() || meta.isSymbolicLink()) throw new Error(UNCLASSIFIED);
    // The existing exclusive side excludes all lifetime bridge leases and blocks new admission through recovery.
    return await withExclusiveMasterRotationBarrier(storage, CUSTODY_WRITE_LOCK_NAMESPACE,
      MASTER_ROTATION_BARRIER_NAME, () => recordCallbackReturn(async () => {
        // Admission is the barrier running this callback; anything thrown after it is not a custody refusal.
        admitted = true;
        const readonlyStorage = new ReadOnlyStorageGuard(storage);
        const credential = passphrase.value ?? env.SANCTUARY_PASSPHRASE;
        if (!credential && !env.SANCTUARY_RECOVERY_KEY) {
          err.write("Recovery requires SANCTUARY_PASSPHRASE, --passphrase, or SANCTUARY_RECOVERY_KEY.\n");
          return 1;
        }
        const masterKey = await unlockExistingMasterReadOnly(readonlyStorage, {
          ...(credential ? { passphrase: credential } : { recoveryKey: env.SANCTUARY_RECOVERY_KEY! }),
          storagePathHint: storagePath,
        });
        try {
          const auditLog = new AuditLog(storage, masterKey);
          if (apply) {
            // Classification and deletion must see the recovered fortress, never a half-applied import.
            try {
              // No journal directory means no import or admission lock; exclusive custody prevents new imports while we skip it.
              const journalExists = await stat(storage.namespacePath(EXIT_IMPORT_JOURNAL_NAMESPACE)).then(() => true, cause => {
                if ((cause as NodeJS.ErrnoException).code === "ENOENT") return false;
                throw cause;
              });
              if (journalExists) importsRecovered = (await recoverInterruptedExitImportsOrThrow(storage, auditLog)).recovered > 0;
            }
            catch {
              err.write("Interrupted exit-import recovery did not finish; save recovery was not attempted.\n");
              return 1;
            }
          } else if (await hasInterruptedExitImport(readonlyStorage)) {
            // Report mode cannot recover an import without breaking its no-mutation contract.
            err.write("An interrupted exit import prevents save classification; report mode changed nothing.\n");
            return 1;
          }
          const fortressId = fortressIdFromStoragePath(storagePath);
          const intent = await readHermesSaveIntent({ storage: readonlyStorage, masterKey, fortressId });
          // Continuing paths: absent -> no action; unpublished -> rollback; verified published -> keep.
          // Every unreadable or unverifiable state throws before actionStarted and cannot reach a delete.
          if (intent === null) {
            out.write(json ? '{"state":"nothing to recover"}\n' : "nothing to recover\n");
            return 0;
          }
          const identities = new IdentityManager(readonlyStorage, masterKey);
          const loaded = await identities.load();
          if (loaded.failed > 0 || loaded.loaded < 1) throw new Error(UNCLASSIFIED);
          const resolvePrimarySigningHandle = createPrimaryMemoryProvenanceSigningHandleResolver(identities, masterKey);
          const resolveSignerPublicKey = createPrimaryMemoryProvenancePublicKeyResolver(identities);
          const adapterOptions = { storage: readonlyStorage, masterKey, fortressId, ownerRef: intent.ownerRef,
            resolvePrimarySigningHandle, resolveSignerPublicKey };
          const migration = new SdwMemoryProvenanceMigration(adapterOptions);
          const adapter = createSdwMemoryAdapter({ ...adapterOptions, mode: "standard",
            resolveMemoryIntegrityState: () => migration.getState() });
          const state = await adapter.classifyHermesSave(intent);
          const outcome = state === "completed" ? "kept" : "rolled_back";
          const action = state === "completed" ? "keep published save and delete intent" : "roll back save records and delete intent";
          const lockPath = join(storage.namespacePath(MEMORY_BATCH_LOCK_NAMESPACE), sdwMemoryCorpusBatchLockFile());
          const corpusLock = await lstat(lockPath).catch(cause => {
            if ((cause as NodeJS.ErrnoException).code === "ENOENT") return null;
            throw cause;
          });
          if (corpusLock !== null && (!corpusLock.isFile() || corpusLock.isSymbolicLink())) throw new Error(UNCLASSIFIED);
          if (!apply) {
            out.write(json ? JSON.stringify({ state, action }) + "\n" : `${state}; --apply would ${action}.\n`);
            return 0;
          }
          actionStarted = true;
          let removed = state === "completed" ? 0 : await rollbackHermesSaveRecords(storage, intent.documentId, intent.chunkKeys);
          // The exclusive barrier proves no bridge can own this crash residue or enter before cleanup finishes.
          if (corpusLock !== null) await unlink(lockPath);
          // The intent is the restart refusal marker and must survive every incomplete rollback.
          // A secure overwrite cut before unlink can strand the fortress with an undecryptable intent; encryption provides its confidentiality.
          if (await storage.delete(HERMES_INSERT_INTENT_NAMESPACE, HERMES_INSERT_INTENT_KEY, false)) removed++;
          actionFinished = true;
          await auditLog.appendCritical({ layer: "l3", operation: "hermes_save_recovered",
            identity_id: "operator", result: "success", details: { outcome, records_removed: removed } });
          out.write(json ? JSON.stringify({ state, outcome, records_removed: removed }) + "\n" : `${state}; ${outcome}; records removed: ${removed}.\n`);
          return 0;
        } finally { masterKey.fill(0); }
      }), { timeoutMs: 0 }); // Zero wait: an active writer is an immediate refusal, never an invitation to run beside it.
  } catch (cause) {
    // Admission diagnostics have no audit authority and must not label post-admission failures, in report or apply mode, as refusals.
    if (!admitted) {
      // A diagnostic fault must never replace the operator's refusal message below.
      try { publishCustodyRefusal(cause); } catch { /* diagnostics are best effort */ }
    }
    const message = actionFinished ? "Recovery completed but the audit append or lock release failed; the action was not reversed."
      : actionStarted ? "Recovery did not finish; retry --apply if the intent is still readable."
      // After an admitted callback returns, typed custody failures belong to finalization, including the barrier's held checks.
      // Must match CUSTODY_RELEASE_FAILURE_MESSAGE in cli/custody-release-message.ts.
      : admitted && callbackReturned && containsCustodyError(cause) ? CUSTODY_RELEASE_FAILURE_MESSAGE
      // An operation-side lock failure cannot truthfully deny custody that was already obtained.
      : !admitted && cause instanceof CrossProcessLockError ? "Recovery requires exclusive custody of the fortress; a live bridge or unavailable custody barrier prevents it."
      : importsRecovered ? "The exit import was recovered, but save recovery did not proceed."
      : UNCLASSIFIED;
    err.write(message + "\n");
    return 1;
  }
}
