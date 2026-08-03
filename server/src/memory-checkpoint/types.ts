/**
 * Memory Checkpoint -- shared record and fail-closed error types.
 *
 * Checkpoints are local, encrypted, content-addressed snapshots of the
 * StateStore exportable namespace bundle. This file owns only the public record
 * shape and diagnosable errors for the module.
 */

export type MemoryCheckpointSource = "on_demand" | "scheduled";

export interface MemoryCheckpointRecord {
  id: string;
  created_at: string;
  source: MemoryCheckpointSource;
  namespaces: string[];
  total_keys: number;
  bundle_hash: string;
  completeness_summary: {
    namespace_count: number;
    total_keys: number;
    per_namespace: Record<
      string,
      { content_sha256: string; item_count: number }
    >;
  };
  retention_expires_at: string | null;
  format_version: number;
}

export class MemoryCheckpointError extends Error {
  readonly reason: string;

  constructor(message: string, reason: string, cause?: unknown) {
    super(message, cause === undefined ? undefined : { cause });
    this.name = new.target.name;
    this.reason = reason;
  }
}

export class MemoryCheckpointValidationError extends MemoryCheckpointError {}

export class MemoryCheckpointExportError extends MemoryCheckpointError {}

export class MemoryCheckpointEncryptionError extends MemoryCheckpointError {}

export class MemoryCheckpointPersistenceError extends MemoryCheckpointError {}

export class MemoryCheckpointReadError extends MemoryCheckpointError {}

export class MemoryCheckpointDeleteError extends MemoryCheckpointError {}

export class MemoryCheckpointRetentionError extends MemoryCheckpointError {}

export class MemoryCheckpointSchedulerError extends MemoryCheckpointError {}

export class MemoryCheckpointAuditError extends MemoryCheckpointError {}
