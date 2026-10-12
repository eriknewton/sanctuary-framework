import type { StorageBackend } from "../storage/interface.js";
import type { MemoryProvenanceBadSignerAuthority } from "./memory-provenance-bad-signers.js";
import type {
  CreateSdwMemoryAdapterOptions,
  HermesBridgeCommitCheck,
} from "../index.js";
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
declare const fortressId: string;
declare const hermesAdapterBase: Omit<
  CreateSdwMemoryAdapterOptions,
  "mode" | "commitCheck" | "badSignerAuthority"
>;
declare const hermesCommitCheck: HermesBridgeCommitCheck;
declare const badSignerAuthority: MemoryProvenanceBadSignerAuthority;

void sdwBackendWrite(backend, persistable, key, fortressId);

// @ts-expect-error sdwBackendWrite requires a branded Persistable, not a raw record.
void sdwBackendWrite(backend, catalogRecord, key, fortressId);

// @ts-expect-error The Persistable brand is module-private and cannot be forged structurally.
export const forgedPersistable: Persistable<SdwCatalogRecord> = {
  record: catalogRecord,
  namespace: SDW_CATALOG_NAMESPACE,
  storageKey: "catalog.environment",
  aad: new Uint8Array(),
  taint: "system_generated",
};

// @ts-expect-error The closed SdwRecord union has no unknown/raw payload member.
export const rawUnknownRecord: SdwRecord = { kind: "raw", version: 1, payload: {} };

void ({
  ...hermesAdapterBase,
  mode: "standard",
} satisfies CreateSdwMemoryAdapterOptions);

void ({
  ...hermesAdapterBase,
  mode: "hermes-bridge",
  commitCheck: hermesCommitCheck,
  badSignerAuthority,
} satisfies CreateSdwMemoryAdapterOptions);

// @ts-expect-error Hermes bridge mode must carry the bad-signer authority that provenance reads consume.
const missingHermesBadSignerAuthority: CreateSdwMemoryAdapterOptions = {
  ...hermesAdapterBase,
  mode: "hermes-bridge",
  commitCheck: hermesCommitCheck,
};
void missingHermesBadSignerAuthority;

// @ts-expect-error Hermes bridge mode must supply the live commit check.
const missingHermesCommitCheck: CreateSdwMemoryAdapterOptions = {
  ...hermesAdapterBase,
  mode: "hermes-bridge",
  badSignerAuthority,
};
void missingHermesCommitCheck;
