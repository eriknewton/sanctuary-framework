/**
 * Memory Checkpoint -- public module surface.
 *
 * Consumers import from this barrel rather than reaching into individual
 * files, per the repo's barrel convention (see server/src/README.md).
 */

export {
  MemoryCheckpointError,
  MemoryCheckpointValidationError,
  MemoryCheckpointExportError,
  MemoryCheckpointEncryptionError,
  MemoryCheckpointPersistenceError,
  MemoryCheckpointReadError,
  MemoryCheckpointDeleteError,
  MemoryCheckpointRetentionError,
  MemoryCheckpointSchedulerError,
  MemoryCheckpointAuditError,
} from "./types.js";
export type {
  MemoryCheckpointRecord,
  MemoryCheckpointSource,
} from "./types.js";

export {
  MEMORY_CHECKPOINT_FORMAT_VERSION,
  MEMORY_CHECKPOINT_PURPOSE,
  MemoryCheckpointStore,
  assertValidMemoryCheckpointId,
  buildMemoryCheckpointId,
  nodeMemoryCheckpointFsOps,
  parseMemoryCheckpointRecord,
  systemMemoryCheckpointClock,
} from "./store.js";
export type {
  MemoryCheckpointClock,
  MemoryCheckpointDirent,
  MemoryCheckpointFsOps,
  MemoryCheckpointStoreOptions,
  PersistMemoryCheckpointInput,
} from "./store.js";

export {
  buildMemoryCheckpointRecord,
  createCheckpoint,
} from "./create.js";
export type {
  CreateCheckpointDeps,
  StateStoreExportResult,
} from "./create.js";

export {
  CHECKPOINT_RETENTION_ENV,
  DEFAULT_CHECKPOINT_RETENTION_MS,
  computeRetentionExpiresAt,
  parseRetention,
  pruneExpired,
  pruneExpiredCheckpoints,
} from "./retention.js";
export type { PruneExpiredCheckpointsDeps } from "./retention.js";

export {
  CHECKPOINT_INTERVAL_ENV,
  DEFAULT_CHECKPOINT_INTERVAL_MS,
  MIN_CHECKPOINT_INTERVAL_MS,
  buildScheduledCheckpointEmitter,
  parseCheckpointInterval,
  startMemoryCheckpointScheduler,
  startMemoryCheckpointSchedulerFromEnv,
} from "./scheduler.js";

export {
  CheckpointRestoreAgentNotParkedError,
  CheckpointRestoreCheckpointNotFoundError,
  CheckpointRestoreForensicSourceError,
  CheckpointRestoreBundleError,
  CheckpointRestoreBundleHashMismatchError,
  CheckpointRestoreReservedNamespaceError,
  CheckpointRestoreExportError,
  CheckpointRestoreReconstructError,
  CheckpointRestoreAuditError,
  restoreCheckpoint,
} from "./restore.js";
export type {
  CheckpointPoisonMap,
  CheckpointRestoreReconstructProgress,
  RestoreCheckpointDeps,
  RestoreCheckpointResult,
} from "./restore.js";
export type {
  MemoryCheckpointSchedulerHandle,
  MemoryCheckpointSchedulerOptions,
  ScheduledCheckpointEmitterDeps,
  StartMemoryCheckpointSchedulerFromEnvDeps,
} from "./scheduler.js";
