/**
 * Memory Checkpoint -- restore a known-good checkpoint after compromise.
 *
 * Restore is intentionally local-only and dependency-injected. It refuses
 * unless the harness is observed parked, seals current exportable state as a
 * forensic checkpoint before deleting anything, then reconstructs exportable
 * namespaces from the checkpoint bundle. Reserved underscore-prefixed
 * namespaces are asserted out of the diff and are never deleted here.
 */

import type { StateStore } from "../cognitive/state-store.js";
import { bytesToString, fromBase64url } from "../core/encoding.js";
import type { AuditLog } from "../operational/audit-log.js";
import type { ParkedClaim } from "../egress-gate/parked-claim.js";
import { createCheckpoint } from "./create.js";
import type { MemoryCheckpointStore } from "./store.js";
import {
  MemoryCheckpointError,
  type MemoryCheckpointRecord,
} from "./types.js";

export interface CheckpointPoisonMap {
  added: string[];
  changed: string[];
  removed: string[];
}

export interface CheckpointRestoreReconstructProgress {
  deleted_added: string[];
  delete_remaining: string[];
  import_applied: boolean;
}

export interface RestoreCheckpointResult {
  checkpoint_id: string;
  forensic_id: string;
  poison_map: CheckpointPoisonMap;
  import_result: Awaited<ReturnType<StateStore["import"]>>;
}

export interface RestoreCheckpointDeps {
  stateStore: Pick<
    StateStore,
    "exportNamespaces" | "import" | "delete" | "listCachedExportableNamespaces"
  >;
  checkpointStore: MemoryCheckpointStore;
  masterKey: Uint8Array;
  auditLog: Pick<AuditLog, "append" | "appendCritical">;
  identityId: string;
  checkpointId: string;
  assessParked: () => Promise<ParkedClaim>;
  publicKeyResolver: (kid: string) => Uint8Array | null;
  now?: Date;
}

interface ParsedEntry {
  namespace: string;
  key: string;
  path: string;
  integrity_hash: string;
}

interface ParsedBundleData {
  entriesByPath: Map<string, ParsedEntry>;
}

export class CheckpointRestoreAgentNotParkedError extends MemoryCheckpointError {}

export class CheckpointRestoreCheckpointNotFoundError extends MemoryCheckpointError {}

export class CheckpointRestoreForensicSourceError extends MemoryCheckpointError {}

export class CheckpointRestoreBundleError extends MemoryCheckpointError {}

export class CheckpointRestoreReservedNamespaceError extends MemoryCheckpointError {}

export class CheckpointRestoreExportError extends MemoryCheckpointError {}

export class CheckpointRestoreReconstructError extends MemoryCheckpointError {
  readonly progress: CheckpointRestoreReconstructProgress;

  constructor(
    message: string,
    reason: string,
    progress: CheckpointRestoreReconstructProgress,
    cause?: unknown,
  ) {
    super(message, reason, cause);
    this.progress = progress;
  }
}

export class CheckpointRestoreAuditError extends MemoryCheckpointError {}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function sorted(paths: string[]): string[] {
  return [...paths].sort((a, b) => a.localeCompare(b));
}

function parseExportBundleData(
  bundleBase64: string,
  label: string,
): ParsedBundleData {
  let parsed: unknown;
  try {
    parsed = JSON.parse(bytesToString(fromBase64url(bundleBase64))) as unknown;
  } catch (err) {
    throw new CheckpointRestoreBundleError(
      `memory checkpoint restore failed: ${label} export bundle is not valid base64url JSON`,
      "bundle_decode_failed",
      err,
    );
  }
  if (!isRecord(parsed) || !isRecord(parsed.data)) {
    throw new CheckpointRestoreBundleError(
      `memory checkpoint restore failed: ${label} export bundle data is malformed`,
      "bundle_malformed",
    );
  }

  const declared = parsed.namespaces;
  if (declared !== undefined) {
    if (!Array.isArray(declared) || !declared.every((item) => typeof item === "string")) {
      throw new CheckpointRestoreBundleError(
        `memory checkpoint restore failed: ${label} export bundle namespace metadata is malformed`,
        "bundle_malformed",
      );
    }
    const declaredNamespaces = sorted(declared);
    const actualNamespaces = sorted(Object.keys(parsed.data));
    if (JSON.stringify(declaredNamespaces) !== JSON.stringify(actualNamespaces)) {
      throw new CheckpointRestoreBundleError(
        `memory checkpoint restore failed: ${label} export bundle namespace metadata does not match data`,
        "bundle_namespace_mismatch",
      );
    }
  }

  const entriesByPath = new Map<string, ParsedEntry>();
  for (const [namespace, entries] of Object.entries(parsed.data)) {
    if (namespace.startsWith("_")) {
      throw new CheckpointRestoreReservedNamespaceError(
        `memory checkpoint restore refused: ${label} bundle contains reserved namespace "${namespace}"`,
        "reserved_namespace",
      );
    }
    if (!Array.isArray(entries)) {
      throw new CheckpointRestoreBundleError(
        `memory checkpoint restore failed: ${label} namespace "${namespace}" entries are malformed`,
        "bundle_malformed",
      );
    }
    for (const item of entries) {
      if (!isRecord(item) || typeof item.key !== "string" || !isRecord(item.entry)) {
        throw new CheckpointRestoreBundleError(
          `memory checkpoint restore failed: ${label} namespace "${namespace}" entry is malformed`,
          "bundle_malformed",
        );
      }
      const integrityHash = item.entry.integrity_hash;
      if (typeof integrityHash !== "string") {
        throw new CheckpointRestoreBundleError(
          `memory checkpoint restore failed: ${label} entry "${namespace}/${item.key}" has no integrity_hash`,
          "bundle_malformed",
        );
      }
      const path = `${namespace}/${item.key}`;
      if (entriesByPath.has(path)) {
        throw new CheckpointRestoreBundleError(
          `memory checkpoint restore failed: ${label} bundle repeats entry "${path}"`,
          "bundle_duplicate_key",
        );
      }
      entriesByPath.set(path, {
        namespace,
        key: item.key,
        path,
        integrity_hash: integrityHash,
      });
    }
  }

  return { entriesByPath };
}

function assertCachedNamespacesExportable(namespaces: string[]): void {
  const reserved = namespaces.filter((namespace) => namespace.startsWith("_"));
  if (reserved.length > 0) {
    throw new CheckpointRestoreReservedNamespaceError(
      `memory checkpoint restore refused: StateStore listed reserved namespace(s) as exportable: ${reserved.join(", ")}`,
      "reserved_namespace",
    );
  }
}

function diffBundles(
  checkpoint: ParsedBundleData,
  current: ParsedBundleData,
): { poisonMap: CheckpointPoisonMap; addedEntries: ParsedEntry[] } {
  const addedEntries: ParsedEntry[] = [];
  const changed: string[] = [];
  const removed: string[] = [];

  for (const [path, currentEntry] of current.entriesByPath) {
    const checkpointEntry = checkpoint.entriesByPath.get(path);
    if (!checkpointEntry) {
      addedEntries.push(currentEntry);
    } else if (checkpointEntry.integrity_hash !== currentEntry.integrity_hash) {
      changed.push(path);
    }
  }
  for (const path of checkpoint.entriesByPath.keys()) {
    if (!current.entriesByPath.has(path)) removed.push(path);
  }

  addedEntries.sort((a, b) => a.path.localeCompare(b.path));
  return {
    addedEntries,
    poisonMap: {
      added: addedEntries.map((entry) => entry.path),
      changed: sorted(changed),
      removed: sorted(removed),
    },
  };
}

function poisonMapSummary(poisonMap: CheckpointPoisonMap | undefined): {
  added: number;
  changed: number;
  removed: number;
} {
  return {
    added: poisonMap?.added.length ?? 0,
    changed: poisonMap?.changed.length ?? 0,
    removed: poisonMap?.removed.length ?? 0,
  };
}

function restoreAuditDetails(input: {
  checkpointId: string;
  forensicId?: string;
  poisonMap?: CheckpointPoisonMap;
  error?: unknown;
}): Record<string, unknown> {
  return {
    checkpoint_id: input.checkpointId,
    forensic_id: input.forensicId ?? null,
    poison_map_summary: poisonMapSummary(input.poisonMap),
    ...(input.error instanceof CheckpointRestoreReconstructError
      ? { reconstruct_progress: input.error.progress }
      : {}),
    ...(input.error instanceof MemoryCheckpointError
      ? { error_reason: input.error.reason, error_message: input.error.message }
      : input.error !== undefined
        ? { error_reason: "restore_failed", error_message: String(input.error) }
        : {}),
  };
}

async function appendRestoreAudit(
  deps: RestoreCheckpointDeps,
  result: "success" | "failure",
  details: Record<string, unknown>,
): Promise<void> {
  await deps.auditLog.appendCritical({
    layer: "l1",
    operation: "memory_checkpoint_restore",
    identity_id: deps.identityId,
    result,
    details,
  });
}

function checkpointNotFound(id: string): CheckpointRestoreCheckpointNotFoundError {
  return new CheckpointRestoreCheckpointNotFoundError(
    `memory checkpoint restore failed: checkpoint ${id} was not found`,
    "checkpoint_not_found",
  );
}

function forensicSource(record: MemoryCheckpointRecord): CheckpointRestoreForensicSourceError {
  return new CheckpointRestoreForensicSourceError(
    `memory checkpoint restore refused: checkpoint ${record.id} is a forensic quarantine artifact and cannot be used as a restore source`,
    "forensic_source_refused",
  );
}

/**
 * Restore exportable StateStore state from a known-good checkpoint.
 *
 * The function never starts, stops, or syncs any agent. The caller supplies the
 * parked claim and the local StateStore/checkpoint dependencies. On every
 * successful or failed attempt it writes a critical audit entry with the
 * checkpoint id, forensic id when available, and poison-map counts.
 */
export async function restoreCheckpoint(
  deps: RestoreCheckpointDeps,
): Promise<RestoreCheckpointResult> {
  let forensicId: string | undefined;
  let poisonMap: CheckpointPoisonMap | undefined;

  try {
    const claim = await deps.assessParked();
    if (claim.state !== "parked") {
      throw new CheckpointRestoreAgentNotParkedError(
        `memory checkpoint restore refused: ${claim.sentence} Remedy: stop and park the agent harness, then retry restore.`,
        "agent_not_parked",
      );
    }

    const record = await deps.checkpointStore.get(deps.checkpointId);
    if (!record) throw checkpointNotFound(deps.checkpointId);
    if (record.source === "forensic_quarantine") throw forensicSource(record);

    let checkpointBundle: string;
    try {
      checkpointBundle = await deps.checkpointStore.readBundle(
        deps.checkpointId,
        deps.masterKey,
      );
    } catch (err) {
      throw new CheckpointRestoreBundleError(
        `memory checkpoint restore failed while reading checkpoint ${deps.checkpointId}: ${
          err instanceof Error ? err.message : String(err)
        }`,
        "checkpoint_bundle_read_failed",
        err,
      );
    }

    assertCachedNamespacesExportable(deps.stateStore.listCachedExportableNamespaces());

    let currentBundle: string;
    try {
      currentBundle = (await deps.stateStore.exportNamespaces(undefined)).bundle;
    } catch (err) {
      throw new CheckpointRestoreExportError(
        `memory checkpoint restore failed while exporting current state: ${
          err instanceof Error ? err.message : String(err)
        }`,
        "current_export_failed",
        err,
      );
    }

    const checkpointData = parseExportBundleData(checkpointBundle, "checkpoint");
    const currentData = parseExportBundleData(currentBundle, "current");
    const diff = diffBundles(checkpointData, currentData);
    poisonMap = diff.poisonMap;

    const forensic = await createCheckpoint({
      stateStore: deps.stateStore,
      store: deps.checkpointStore,
      masterKey: deps.masterKey,
      auditLog: deps.auditLog,
      identityId: deps.identityId,
      source: "forensic_quarantine",
      retentionValue: "off",
      ...(deps.now !== undefined ? { now: deps.now } : {}),
    });
    forensicId = forensic.id;

    const deletedAdded: string[] = [];
    const remainingAdded = diff.addedEntries.map((entry) => entry.path);
    for (const entry of diff.addedEntries) {
      try {
        await deps.stateStore.delete(entry.namespace, entry.key);
        deletedAdded.push(entry.path);
        remainingAdded.shift();
      } catch (err) {
        throw new CheckpointRestoreReconstructError(
          `memory checkpoint restore failed while deleting added key ${entry.path}: ${
            err instanceof Error ? err.message : String(err)
          }`,
          "delete_added_failed",
          {
            deleted_added: deletedAdded,
            delete_remaining: remainingAdded,
            import_applied: false,
          },
          err,
        );
      }
    }

    let importResult: Awaited<ReturnType<StateStore["import"]>>;
    try {
      importResult = await deps.stateStore.import(
        checkpointBundle,
        "overwrite",
        deps.publicKeyResolver,
      );
    } catch (err) {
      throw new CheckpointRestoreReconstructError(
        `memory checkpoint restore failed while importing checkpoint ${deps.checkpointId}: ${
          err instanceof Error ? err.message : String(err)
        }`,
        "import_failed",
        {
          deleted_added: deletedAdded,
          delete_remaining: [],
          import_applied: false,
        },
        err,
      );
    }

    if (importResult.skipped_keys > 0) {
      throw new CheckpointRestoreReconstructError(
        `memory checkpoint restore did not import every checkpoint entry: skipped ${importResult.skipped_keys} key(s)`,
        "import_incomplete",
        {
          deleted_added: deletedAdded,
          delete_remaining: [],
          import_applied: true,
        },
      );
    }

    const result: RestoreCheckpointResult = {
      checkpoint_id: deps.checkpointId,
      forensic_id: forensicId,
      poison_map: poisonMap,
      import_result: importResult,
    };

    await appendRestoreAudit(
      deps,
      "success",
      restoreAuditDetails({
        checkpointId: deps.checkpointId,
        forensicId,
        poisonMap,
      }),
    );

    return result;
  } catch (err) {
    try {
      await appendRestoreAudit(
        deps,
        "failure",
        restoreAuditDetails({
          checkpointId: deps.checkpointId,
          forensicId,
          poisonMap,
          error: err,
        }),
      );
    } catch (auditErr) {
      throw new CheckpointRestoreAuditError(
        `memory checkpoint restore failed, and critical failure audit also failed: ${
          auditErr instanceof Error ? auditErr.message : String(auditErr)
        }`,
        "failure_audit_failed",
        err,
      );
    }
    throw err;
  }
}
