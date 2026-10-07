/** Pure memory-grant record contract. This module does not mint authority. */
export {
  MEMORY_GRANT_SCHEMA_VERSION,
  MAX_MEMORY_GRANT_LIFETIME_MS,
  MAX_MEMORY_GRANTS_PER_LEDGER,
  parseMemoryGrantRecord,
  parseMemoryGrantLedger,
  addMemoryGrant,
  isMemoryGrantUseAllowed,
  revokeMemoryGrant,
} from "./ledger.js";
export type { MemoryGrantHarness, MemoryGrantSourceRoot, MemoryGrantRecord, MemoryGrantLedger, MemoryGrantUse } from "./ledger.js";
