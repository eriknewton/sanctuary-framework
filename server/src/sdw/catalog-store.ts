import type { StorageBackend } from "../storage/interface.js";
import { decrypt, type EncryptedPayload } from "../core/encryption.js";
import { derivePurposeKey } from "../core/key-derivation.js";
import { bytesToString } from "../core/encoding.js";
import { catalogKey, sdwAad } from "./grammar.js";
import {
  defaultSdwStoreDescriptors,
  SDW_CATALOG_HKDF_INFO,
  SDW_CATALOG_NAMESPACE,
  type SdwCatalogRecord,
} from "./records.js";
import { mintPersistable, sdwBackendWrite } from "./write-gate.js";
import { SdwCatalogError, UnsupportedRecordVersion } from "./errors.js";
import {
  assertCatalogNotRolledBack,
  assertReplayAnchorPresentForEstablishedStore,
  emptyReplayAnchorData,
  readReplayAnchor,
  writeReplayAnchor,
} from "./replay-anchor.js";

export interface SdwCatalogStoreOptions {
  readonly storage: StorageBackend;
  readonly masterKey: Uint8Array;
  readonly fortressId: string;
}

export interface SdwListAccounting {
  readonly loaded: number;
  readonly auth_failed: number;
  readonly auth_failed_keys: readonly string[];
  readonly unsupported_version: number;
  readonly skipped: readonly string[];
}

export class SdwCatalogStore {
  private readonly storage: StorageBackend;
  private readonly masterKey: Uint8Array;
  private readonly encryptionKey: Uint8Array;
  private readonly fortressId: string;

  constructor(options: SdwCatalogStoreOptions) {
    this.storage = options.storage;
    this.masterKey = options.masterKey;
    this.encryptionKey = derivePurposeKey(options.masterKey, SDW_CATALOG_HKDF_INFO);
    this.fortressId = options.fortressId;
  }

  async initialize(environmentId: string, now = new Date().toISOString()): Promise<SdwCatalogRecord> {
    const record: SdwCatalogRecord = {
      kind: "catalog",
      version: 1,
      fortress_id: this.fortressId,
      environment_id: environmentId,
      created_at: now,
      replay_anchor_seq: 1,
      stores: defaultSdwStoreDescriptors(),
    };
    const anchorData = { ...emptyReplayAnchorData(), catalog: record.replay_anchor_seq };
    await writeReplayAnchor(this.storage, this.masterKey, anchorData);
    const persistable = mintPersistable(
      { value: record, taint: "system_generated" },
      SDW_CATALOG_NAMESPACE,
      catalogKey(),
      this.fortressId,
    );
    await sdwBackendWrite(this.storage, persistable, this.encryptionKey, this.fortressId);
    return record;
  }

  async openExisting(): Promise<SdwCatalogRecord> {
    const raw = await this.storage.read(SDW_CATALOG_NAMESPACE, catalogKey());
    if (raw === null) {
      const hasAny = (await this.storage.totalSize()) > 0;
      throw new SdwCatalogError(
        hasAny ? "missing_catalog" : "empty_environment",
        "SDW catalog missing",
      );
    }
    const anchor = await readReplayAnchor(this.storage, this.masterKey);
    assertReplayAnchorPresentForEstablishedStore(anchor, (await this.storage.totalSize()) > 0, "catalog store");
    const record = this.decodeDirect(raw, catalogKey());
    if (record.fortress_id !== this.fortressId) {
      throw new SdwCatalogError("fortress_mismatch", "SDW catalog fortress mismatch");
    }
    assertCatalogNotRolledBack(record.replay_anchor_seq, anchor);
    return record;
  }

  async loadCatalogList(): Promise<{
    readonly records: readonly SdwCatalogRecord[];
    readonly accounting: SdwListAccounting;
  }> {
    const metas = await this.storage.list(SDW_CATALOG_NAMESPACE, "catalog.");
    const records: SdwCatalogRecord[] = [];
    const skipped: string[] = [];
    const authFailedKeys: string[] = [];
    let unsupported = 0;
    for (const meta of metas) {
      const raw = await this.storage.read(SDW_CATALOG_NAMESPACE, meta.key);
      if (raw === null) continue;
      try {
        records.push(this.decodeDirect(raw, meta.key));
      } catch (error) {
        if (error instanceof SdwCatalogError && error.category === "auth_failed") {
          authFailedKeys.push(meta.key);
        } else {
          skipped.push(meta.key);
          if (error instanceof UnsupportedRecordVersion) unsupported++;
        }
      }
    }
    return {
      records,
      accounting: {
        loaded: records.length,
        auth_failed: authFailedKeys.length,
        auth_failed_keys: authFailedKeys,
        unsupported_version: unsupported,
        skipped,
      },
    };
  }

  private decodeDirect(raw: Uint8Array, storageKey: string): SdwCatalogRecord {
    try {
      const aad = sdwAad(this.fortressId, SDW_CATALOG_NAMESPACE, storageKey);
      const envelope = JSON.parse(bytesToString(raw)) as EncryptedPayload;
      const plaintext = decrypt(envelope, this.encryptionKey, aad);
      const record = JSON.parse(bytesToString(plaintext)) as SdwCatalogRecord & {
        readonly version: number;
      };
      if (record.version !== 1) {
        throw new UnsupportedRecordVersion(
          SDW_CATALOG_NAMESPACE,
          storageKey,
          record.version,
        );
      }
      if (record.kind !== "catalog") {
        throw new SdwCatalogError("identity_mismatch", "SDW catalog identity mismatch");
      }
      return record;
    } catch (error) {
      if (
        error instanceof UnsupportedRecordVersion ||
        error instanceof SdwCatalogError
      ) {
        throw error;
      }
      throw new SdwCatalogError("auth_failed", "SDW catalog authentication failed");
    }
  }
}
