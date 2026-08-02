export type { StorageBackend, StorageEntryMeta } from "./interface.js";
export {
  CustodyFsError,
  isCustodyFsError,
  openDirectoryCustodyWithinBase,
  readFileCustody,
  readFileCustodyWithStats,
  verifyDirectoryCustodyWithinBase,
  writeFileCustody,
  type CustodyModeCheck,
  type DirectoryCustodyOptions,
  type DirectoryWithinBaseCustodyOptions,
  type NoFollowDirectoryGuard,
  type ReadFileCustodyOptions,
  type WriteFileCustodyOptions,
} from "./custody-fs.js";
export { FilesystemStorage } from "./filesystem.js";
export { MemoryStorage } from "./memory.js";
export {
  withCrossProcessLock,
  CrossProcessLockError,
  CROSS_PROCESS_LOCK_TIMEOUT_MS,
  CROSS_PROCESS_LOCK_RETRY_MS,
  type CrossProcessLockOptions,
} from "./cross-process-lock.js";
