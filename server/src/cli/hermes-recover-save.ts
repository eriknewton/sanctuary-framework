import { lstat, unlink } from "node:fs/promises";
import { join, resolve } from "node:path";
import { consumeFlagValue } from "./argv.js";
import { IdentityManager } from "../cognitive/tools.js";
import {
  CUSTODY_WRITE_LOCK_NAMESPACE, MASTER_ROTATION_BARRIER_NAME,
  unlockExistingMasterReadOnly,
} from "../core/master-custody.js";
import { fortressIdFromStoragePath } from "../dashboard/v1_1/wiring.js";
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
import { hasInterruptedExitImport } from "../storage/exit-import-journal.js";
import { ReadOnlyStorageGuard } from "../storage/read-only-guard.js";

const HELP = "Usage: sanctuary hermes recover-save --fortress <dir> [--apply] [--passphrase <value>] [--json]\nReport an unfinished save; --apply keeps a verified save or rolls back an unpublished save.\n";
const UNCLASSIFIED = "The save could not be classified and nothing was changed.";

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
  const storagePath = resolve(fortress.value!);
  const storage = new FilesystemStorage(join(storagePath, "state"));
  let actionStarted = false;
  let actionFinished = false;
  let importsRecovered = false;
  try {
    // A missing or unsafe fortress must refuse before lock resolution can create its namespace.
    const meta = await lstat(storage.namespacePath(CUSTODY_WRITE_LOCK_NAMESPACE));
    if (!meta.isDirectory() || meta.isSymbolicLink()) throw new Error(UNCLASSIFIED);
    // The existing exclusive side excludes all lifetime bridge leases and blocks new admission through recovery.
    return await withExclusiveMasterRotationBarrier(storage, CUSTODY_WRITE_LOCK_NAMESPACE,
      MASTER_ROTATION_BARRIER_NAME, async () => {
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
            try { importsRecovered = (await recoverInterruptedExitImportsOrThrow(storage, auditLog)).recovered > 0; }
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
          if (await storage.delete(HERMES_INSERT_INTENT_NAMESPACE, HERMES_INSERT_INTENT_KEY, true)) removed++;
          actionFinished = true;
          await auditLog.appendCritical({ layer: "l3", operation: "hermes_save_recovered",
            identity_id: "operator", result: "success", details: { outcome, records_removed: removed } });
          out.write(json ? JSON.stringify({ state, outcome, records_removed: removed }) + "\n" : `${state}; ${outcome}; records removed: ${removed}.\n`);
          return 0;
        } finally { masterKey.fill(0); }
      }, { timeoutMs: 0 }); // Zero wait: an active writer is an immediate refusal, never an invitation to run beside it.
  } catch (cause) {
    const message = actionFinished ? "Recovery completed but the audit append or lock release failed; the action was not reversed."
      : actionStarted ? "Recovery did not finish; retry --apply if the intent is still readable."
      : cause instanceof CrossProcessLockError ? "Recovery requires exclusive custody of the fortress; a live bridge or unavailable custody barrier prevents it."
      : importsRecovered ? "The exit import was recovered, but save recovery did not proceed."
      : UNCLASSIFIED;
    err.write(message + "\n");
    return 1;
  }
}
