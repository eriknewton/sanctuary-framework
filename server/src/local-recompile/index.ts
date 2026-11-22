/**
 * Local recompile: the operator log, the results store and the job worker
 * client. This slice registers no MCP tool. The worker entry itself is a
 * build root (dist/local-recompile-worker.js), never re-exported here.
 */
export {
  LOCAL_OPLOG_PURPOSE,
  LOCAL_RESULTS_PURPOSE,
  deriveLocalStoreKeys,
  type LocalStoreKeys,
} from "./store-keys.js";
export { canonicalLocalJson, parseLocalJson } from "./canonical.js";
export {
  LOCAL_DISCLOSURE_NAMESPACE,
  LOCAL_OPLOG_NAMESPACE,
  LOCAL_RESULTS_NAMESPACE,
  LOCAL_STORE_FAILURES,
  LocalStoreError,
  type LocalStoreBackend,
  type LocalStoreFailure,
} from "./store-record.js";
export {
  LocalOplog,
  OPLOG_KINDS,
  OPLOG_MAX_BYTES,
  OPLOG_MAX_ROWS,
  OPLOG_PRUNE_MAX_PER_APPEND,
  OPLOG_ROW_MAX_BYTES,
  type OplogAppendState,
  type OplogBodies,
  type OplogKind,
  type OplogRow,
  type OplogStatus,
  type OplogVerification,
} from "./oplog.js";
export {
  HOUSEKEEPING_INTERVAL_MS,
  INDETERMINATE_TTL_MS,
  LOCAL_RESULT_KINDS,
  LOCAL_RESULT_STATES,
  LocalResultsStore,
  PENDING_GRACE_MS,
  RESULTS_MAX_OBJECTS,
  RESULTS_MAX_TOTAL_BYTES,
  RESULT_BODY_MAX_BYTES,
  RESULT_OBJECT_MAX_BYTES,
  RESULT_TTL_MS,
  type LocalResultBody,
  type LocalResultObject,
  type LocalResultState,
} from "./results-store.js";
export { ensureLocalStores, type EnsureLocalStoresResult } from "./ensure-stores.js";
export {
  IPC_MESSAGE_MAX_BYTES,
  WORKER_ENV_NAMES,
  WORKER_FAULT_KINDS,
  WORKER_HEAP_MAX_MB,
  WORKER_READY_TIMEOUT_MS,
  WORKER_RESPAWN_INITIAL_MS,
  WORKER_RESPAWN_MAX_MS,
  WORKER_STATES,
  type ParentMessage,
  type WorkerFaultKind,
  type WorkerMessage,
  type WorkerState,
} from "./worker-protocol.js";
export { LocalWorkerClient, type LocalWorkerClientOptions, type WorkerClientEvent } from "./worker-client.js";
