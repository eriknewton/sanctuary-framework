import type { StorageBackend } from "../storage/interface.js";
import {
  SDW_CATALOG_NAMESPACE,
  type SdwCatalogRecord,
  type SdwRecord,
} from "./records.js";
import { sdwBackendWrite, type Persistable } from "./write-gate.js";

declare const backend: StorageBackend;
declare const key: Uint8Array;
declare const catalogRecord: SdwCatalogRecord;
declare const persistable: Persistable<SdwCatalogRecord>;

void sdwBackendWrite(backend, persistable, key);

// @ts-expect-error sdwBackendWrite requires a branded Persistable, not a raw record.
void sdwBackendWrite(backend, catalogRecord, key);

// @ts-expect-error The Persistable brand is module-private and cannot be forged structurally.
export const forgedPersistable: Persistable<SdwCatalogRecord> = {
  record: catalogRecord,
  namespace: SDW_CATALOG_NAMESPACE,
  storageKey: "catalog.environment",
  aad: new Uint8Array(),
};

// @ts-expect-error The closed SdwRecord union has no unknown/raw payload member.
export const rawUnknownRecord: SdwRecord = { kind: "raw", version: 1, payload: {} };
