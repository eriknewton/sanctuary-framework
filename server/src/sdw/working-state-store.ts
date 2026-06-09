import type { StorageBackend } from "../storage/interface.js";
import { derivePurposeKey } from "../core/key-derivation.js";
import { stateKey } from "./grammar.js";
import {
  SDW_WORKING_STATE_HKDF_INFO,
  SDW_WORKING_STATE_NAMESPACE,
  type SdwWorkingStateRecord,
} from "./records.js";
import { mintPersistable, sdwBackendWrite, type Taint } from "./write-gate.js";
import { decodeSdwRecord } from "./store-codec.js";

export interface SdwWorkingStateStoreOptions {
  readonly storage: StorageBackend;
  readonly masterKey: Uint8Array;
  readonly fortressId: string;
}

export class SdwWorkingStateStore {
  private readonly storage: StorageBackend;
  private readonly encryptionKey: Uint8Array;
  private readonly fortressId: string;

  constructor(options: SdwWorkingStateStoreOptions) {
    this.storage = options.storage;
    this.encryptionKey = derivePurposeKey(options.masterKey, SDW_WORKING_STATE_HKDF_INFO);
    this.fortressId = options.fortressId;
  }

  async put(record: SdwWorkingStateRecord, taint: Taint): Promise<void> {
    const storageKey = stateKey(record.scope, record.state_id);
    const persistable = mintPersistable(
      { value: record, taint },
      SDW_WORKING_STATE_NAMESPACE,
      storageKey,
      this.fortressId,
    );
    await sdwBackendWrite(this.storage, persistable, this.encryptionKey, this.fortressId);
  }

  async get(scope: SdwWorkingStateRecord["scope"], stateId: string): Promise<SdwWorkingStateRecord | null> {
    const storageKey = stateKey(scope, stateId);
    const raw = await this.storage.read(SDW_WORKING_STATE_NAMESPACE, storageKey);
    if (raw === null) return null;
    return decodeSdwRecord<SdwWorkingStateRecord>(raw, {
      namespace: SDW_WORKING_STATE_NAMESPACE,
      storageKey,
      fortressId: this.fortressId,
      encryptionKey: this.encryptionKey,
      expectedKind: "working_state",
      verifyIdentity: (record) => record.scope === scope && record.state_id === stateId,
    });
  }
}
