export type { StorageBackend, StorageEntryMeta } from "./interface.js";
export {
  CustodyFsError,
  isCustodyFsError,
  readFileCustody,
  readFileCustodyWithStats,
  writeFileCustody,
  type CustodyModeCheck,
  type DirectoryCustodyOptions,
  type ReadFileCustodyOptions,
  type WriteFileCustodyOptions,
} from "./custody-fs.js";
export { FilesystemStorage } from "./filesystem.js";
export { MemoryStorage } from "./memory.js";
