/**
 * Rho-3 reverse-mapping memo.
 *
 * Per-fortress encrypted-at-rest storage keyed by query_id. The AAD is
 * bound to fortressPath + query_id so ciphertext cannot be replayed
 * between fortresses or queries.
 */

import { resolve } from "node:path";

import { decrypt, encrypt, type EncryptedPayload } from "../core/encryption.js";
import { bytesToString, stringToBytes } from "../core/encoding.js";
import { derivePurposeKey } from "../core/key-derivation.js";
import { FilesystemStorage } from "../storage/filesystem.js";
import type { StorageBackend } from "../storage/interface.js";
import { DEFAULT_CONCIERGE_RETENTION_DAYS } from "../chat/concierge-memory-store.js";
import type { ReverseMapping } from "./smart-rewriter.js";

export const REVERSE_MAPPING_NAMESPACE = "_query_anonymity_reverse_map";
const REVERSE_MAPPING_KEY_PREFIX = "query.";
const HKDF_INFO = "query-anonymity-reverse-mapping-v1";
const MAX_MAPPING_BYTES = 1024 * 1024;

interface PersistedReverseMappings {
  version: 1;
  fortress_id: string;
  query_id: string;
  saved_at: string;
  retention_until: string;
  mappings: ReverseMapping[];
}

export class ReverseMappingStore {
  private readonly storage: StorageBackend;
  private readonly encryptionKey: Uint8Array;
  private readonly fortressId: string;
  private readonly retentionDays: number;

  constructor(opts: {
    fortressPath: string;
    masterKey: Buffer | Uint8Array;
    storage?: StorageBackend;
    retentionDays?: number;
  }) {
    this.storage = opts.storage ?? new FilesystemStorage(opts.fortressPath);
    this.encryptionKey = derivePurposeKey(opts.masterKey, HKDF_INFO);
    this.fortressId = resolve(opts.fortressPath);
    this.retentionDays =
      opts.retentionDays !== undefined && opts.retentionDays > 0
        ? opts.retentionDays
        : DEFAULT_CONCIERGE_RETENTION_DAYS;
  }

  async store(query_id: string, mappings: ReverseMapping[]): Promise<void> {
    const now = new Date();
    const retentionUntil = new Date(
      now.getTime() + this.retentionDays * 24 * 60 * 60 * 1000,
    );
    const persisted: PersistedReverseMappings = {
      version: 1,
      fortress_id: this.fortressId,
      query_id,
      saved_at: now.toISOString(),
      retention_until: retentionUntil.toISOString(),
      mappings,
    };
    const envelope = encrypt(
      stringToBytes(JSON.stringify(persisted)),
      this.encryptionKey,
      this.aad(query_id),
    );
    await this.storage.write(
      REVERSE_MAPPING_NAMESPACE,
      keyFor(query_id),
      stringToBytes(JSON.stringify(envelope)),
    );
  }

  async get(query_id: string): Promise<ReverseMapping[] | null> {
    const raw = await this.storage.read(REVERSE_MAPPING_NAMESPACE, keyFor(query_id));
    if (!raw || raw.length > MAX_MAPPING_BYTES) return null;
    try {
      const envelope = JSON.parse(bytesToString(raw)) as EncryptedPayload;
      const plaintext = decrypt(envelope, this.encryptionKey, this.aad(query_id));
      const parsed = JSON.parse(bytesToString(plaintext)) as PersistedReverseMappings;
      if (parsed.version !== 1) return null;
      if (parsed.fortress_id !== this.fortressId) return null;
      if (parsed.query_id !== query_id) return null;
      if (parsed.retention_until <= new Date().toISOString()) return null;
      return parsed.mappings;
    } catch {
      return null;
    }
  }

  async pruneExpired(now?: Date): Promise<{ pruned: number }> {
    const cutoff = (now ?? new Date()).toISOString();
    const entries = await this.storage.list(
      REVERSE_MAPPING_NAMESPACE,
      REVERSE_MAPPING_KEY_PREFIX,
    );
    let pruned = 0;
    for (const entry of entries) {
      const queryId = queryIdFromKey(entry.key);
      if (!queryId) continue;
      const raw = await this.storage.read(REVERSE_MAPPING_NAMESPACE, entry.key);
      if (!raw) continue;
      try {
        const envelope = JSON.parse(bytesToString(raw)) as EncryptedPayload;
        const plaintext = decrypt(envelope, this.encryptionKey, this.aad(queryId));
        const parsed = JSON.parse(bytesToString(plaintext)) as PersistedReverseMappings;
        if (parsed.retention_until > cutoff) continue;
      } catch {
        continue;
      }
      if (await this.storage.delete(REVERSE_MAPPING_NAMESPACE, entry.key)) {
        pruned += 1;
      }
    }
    return { pruned };
  }

  private aad(queryId: string): Uint8Array {
    return stringToBytes(`${this.fortressId}:${queryId}`);
  }
}

function keyFor(queryId: string): string {
  return `${REVERSE_MAPPING_KEY_PREFIX}${queryId}`;
}

function queryIdFromKey(key: string): string | null {
  return key.startsWith(REVERSE_MAPPING_KEY_PREFIX)
    ? key.slice(REVERSE_MAPPING_KEY_PREFIX.length)
    : null;
}
