/**
 * Memory Checkpoint -- create an encrypted snapshot of exportable state.
 *
 * Creation calls StateStore.exportNamespaces(undefined), so reserved
 * underscore-prefixed namespaces are filtered by the existing StateStore export
 * firewall. There is no namespace override and no network or fleet path here.
 */

import type {
  StateExportCompletenessManifest,
  StateStore,
} from "../cognitive/state-store.js";
import type { AuditLog } from "../operational/audit-log.js";
import {
  buildMemoryCheckpointId,
  MEMORY_CHECKPOINT_FORMAT_VERSION,
  type MemoryCheckpointStore,
} from "./store.js";
import {
  computeRetentionExpiresAt,
  parseRetention,
} from "./retention.js";
import {
  MemoryCheckpointAuditError,
  MemoryCheckpointExportError,
  type MemoryCheckpointRecord,
  type MemoryCheckpointSource,
} from "./types.js";

export interface StateStoreExportResult {
  bundle: string;
  namespaces: string[];
  total_keys: number;
  bundle_hash: string;
  exported_at: string;
  completeness_manifest: StateExportCompletenessManifest;
}

export interface CreateCheckpointDeps {
  stateStore: Pick<StateStore, "exportNamespaces">;
  store: MemoryCheckpointStore;
  masterKey: Uint8Array;
  auditLog: Pick<AuditLog, "append">;
  identityId: string;
  source: MemoryCheckpointSource;
  retentionValue?: string;
  now?: Date;
}

function completenessSummary(manifest: StateExportCompletenessManifest): MemoryCheckpointRecord["completeness_summary"] {
  const perNamespace: MemoryCheckpointRecord["completeness_summary"]["per_namespace"] = {};
  for (const namespace of Object.keys(manifest.namespace_items).sort()) {
    const item = manifest.namespace_items[namespace]!;
    perNamespace[namespace] = {
      content_sha256: item.content_sha256,
      item_count: item.item_count,
    };
  }
  return {
    namespace_count: manifest.namespace_count,
    total_keys: manifest.total_keys,
    per_namespace: perNamespace,
  };
}

export function buildMemoryCheckpointRecord(
  exported: StateStoreExportResult,
  createdAt: string,
  source: MemoryCheckpointSource,
  retentionValue?: string,
): MemoryCheckpointRecord {
  const retentionMs = parseRetention(retentionValue);
  return {
    id: buildMemoryCheckpointId(createdAt, exported.bundle_hash),
    created_at: createdAt,
    source,
    namespaces: [...exported.namespaces].sort(),
    total_keys: exported.total_keys,
    bundle_hash: exported.bundle_hash,
    completeness_summary: completenessSummary(exported.completeness_manifest),
    retention_expires_at: computeRetentionExpiresAt(createdAt, retentionMs),
    format_version: MEMORY_CHECKPOINT_FORMAT_VERSION,
  };
}

export async function createCheckpoint(
  deps: CreateCheckpointDeps,
): Promise<MemoryCheckpointRecord> {
  let exported: StateStoreExportResult;
  try {
    exported = await deps.stateStore.exportNamespaces(undefined);
  } catch (err) {
    throw new MemoryCheckpointExportError(
      `memory checkpoint export failed: ${
        err instanceof Error ? err.message : String(err)
      }`,
      "export_failed",
      err,
    );
  }

  const createdAt = (deps.now ?? deps.store.now()).toISOString();
  const record = buildMemoryCheckpointRecord(
    exported,
    createdAt,
    deps.source,
    deps.retentionValue,
  );
  const created = await deps.store.create({
    record,
    bundle: exported.bundle,
    masterKey: deps.masterKey,
  });

  try {
    await deps.auditLog.append("l1", "memory_checkpoint_created", deps.identityId, {
      id: created.id,
      namespaces: created.namespaces,
      total_keys: created.total_keys,
      bundle_hash: created.bundle_hash,
      source: created.source,
    });
  } catch (err) {
    let rollbackDetail = "";
    try {
      await deps.store.delete(created.id);
    } catch (rollbackErr) {
      rollbackDetail = `; rollback delete also failed: ${
        rollbackErr instanceof Error ? rollbackErr.message : String(rollbackErr)
      }`;
    }
    throw new MemoryCheckpointAuditError(
      `memory checkpoint create audit failed: ${
        err instanceof Error ? err.message : String(err)
      }${rollbackDetail}`,
      "audit_failed",
      err,
    );
  }

  return created;
}
