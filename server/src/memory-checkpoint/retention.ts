/**
 * Memory Checkpoint -- retention parsing and expired-checkpoint pruning.
 *
 * Retention is local only. The parser accepts "off"/"0"/"disabled", plain
 * milliseconds, or `<n>s|m|h|d`, and refuses malformed values rather than
 * silently falling back to a different retention window.
 */

import type { AuditLog } from "../operational/audit-log.js";
import type { MemoryCheckpointStore } from "./store.js";
import {
  MemoryCheckpointAuditError,
  MemoryCheckpointRetentionError,
} from "./types.js";

export const CHECKPOINT_RETENTION_ENV = "SANCTUARY_CHECKPOINT_RETENTION";
export const DEFAULT_CHECKPOINT_RETENTION_MS = 30 * 24 * 60 * 60 * 1000;

function parseDurationMs(
  value: string | undefined,
  envName: string,
  defaultMs: number,
): number | null {
  if (value === undefined || value.trim() === "") {
    return defaultMs;
  }
  const trimmed = value.trim().toLowerCase();
  if (trimmed === "off" || trimmed === "0" || trimmed === "disabled") {
    return null;
  }
  const match = /^(\d+)(ms|s|m|h|d)?$/.exec(trimmed);
  if (!match) {
    throw new MemoryCheckpointRetentionError(
      `invalid ${envName} value "${value}": use "off", milliseconds, or <n>s|m|h|d`,
      "invalid_retention",
    );
  }
  const amount = Number(match[1]);
  const unit = match[2] ?? "ms";
  const multiplier =
    unit === "ms" ? 1 :
    unit === "s" ? 1_000 :
    unit === "m" ? 60_000 :
    unit === "h" ? 3_600_000 :
    86_400_000;
  const ms = amount * multiplier;
  if (!Number.isSafeInteger(ms) || ms <= 0) {
    throw new MemoryCheckpointRetentionError(
      `invalid ${envName} value "${value}": retention must be positive (use "off" to disable expiry)`,
      "invalid_retention",
    );
  }
  return ms;
}

export function parseRetention(value: string | undefined): number | null {
  return parseDurationMs(
    value,
    CHECKPOINT_RETENTION_ENV,
    DEFAULT_CHECKPOINT_RETENTION_MS,
  );
}

export function computeRetentionExpiresAt(
  createdAt: string,
  retentionMs: number | null,
): string | null {
  if (retentionMs === null) return null;
  const createdMs = Date.parse(createdAt);
  if (!Number.isFinite(createdMs)) {
    throw new MemoryCheckpointRetentionError(
      `cannot compute memory checkpoint retention expiry: invalid created_at "${createdAt}"`,
      "invalid_created_at",
    );
  }
  return new Date(createdMs + retentionMs).toISOString();
}

export async function pruneExpired(
  store: MemoryCheckpointStore,
  now: Date,
): Promise<string[]> {
  const nowMs = now.getTime();
  if (!Number.isFinite(nowMs)) {
    throw new MemoryCheckpointRetentionError(
      "memory checkpoint prune failed: now is not a valid Date",
      "invalid_now",
    );
  }

  const records = await store.list().catch((err: unknown) => {
    throw new MemoryCheckpointRetentionError(
      `memory checkpoint prune failed while listing checkpoints: ${
        err instanceof Error ? err.message : String(err)
      }`,
      "prune_list_failed",
      err,
    );
  });

  const prunedIds: string[] = [];
  for (const record of records) {
    if (record.retention_expires_at === null) continue;
    const expiresMs = Date.parse(record.retention_expires_at);
    if (!Number.isFinite(expiresMs)) {
      throw new MemoryCheckpointRetentionError(
        `memory checkpoint prune failed: checkpoint ${record.id} has invalid retention_expires_at "${record.retention_expires_at}"`,
        "invalid_retention_expiry",
      );
    }
    if (expiresMs > nowMs) continue;
    const deleted = await store.delete(record.id).catch((err: unknown) => {
      throw new MemoryCheckpointRetentionError(
        `memory checkpoint prune failed while deleting ${record.id}: ${
          err instanceof Error ? err.message : String(err)
        }`,
        "prune_delete_failed",
        err,
      );
    });
    if (deleted) prunedIds.push(record.id);
  }
  return prunedIds.sort();
}

export interface PruneExpiredCheckpointsDeps {
  store: MemoryCheckpointStore;
  auditLog: Pick<AuditLog, "append">;
  identityId: string;
  now: Date;
}

export async function pruneExpiredCheckpoints(
  deps: PruneExpiredCheckpointsDeps,
): Promise<string[]> {
  const prunedIds = await pruneExpired(deps.store, deps.now);
  try {
    await deps.auditLog.append("l1", "memory_checkpoint_pruned", deps.identityId, {
      pruned_ids: prunedIds,
      reason: "retention_expired",
    });
  } catch (err) {
    throw new MemoryCheckpointAuditError(
      `memory checkpoint prune audit failed: ${
        err instanceof Error ? err.message : String(err)
      }`,
      "audit_failed",
      err,
    );
  }
  return prunedIds;
}
