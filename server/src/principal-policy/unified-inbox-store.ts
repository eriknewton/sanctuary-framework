import { DEFAULT_UNIFIED_INBOX_RETENTION_DAYS, parseBlockedEgressAdmissionRecord } from "./blocked-egress-projection.js";
import { HUB_BLOCKED_EGRESS_FORTRESS_MAX } from "../hub/constants.js";
import { parseBlockedEgressMetadata } from "../contracts/v1.1/index.js";

/**
 * WP-V1.3-4 Psi-2 Unified Inbox encrypted persistence.
 *
 * Storage layout:
 *   namespace: `_unified_inbox`
 *   key:       `entry.{inbox_id}`
 *   payload:   AES-256-GCM ciphertext of one persisted inbox entry.
 *   key:       `principal-policy-unified-inbox-v1` HKDF subkey.
 *   AAD:       UTF-8 bytes of `{fortress_id}|{inbox_id}`.
 */

import { basename } from "node:path";

import type { StorageBackend } from "../storage/interface.js";
import { FilesystemStorage } from "../storage/filesystem.js";
import {
  encrypt,
  decrypt,
  type EncryptedPayload,
} from "../core/encryption.js";
import { derivePurposeKey } from "../core/key-derivation.js";
import { stringToBytes, bytesToString } from "../core/encoding.js";
import type {
  UnifiedInboxEntry,
  UnifiedInboxSourceClass,
} from "./unified-inbox-bridge.js";

export const UNIFIED_INBOX_NAMESPACE = "_unified_inbox";
export const UNIFIED_INBOX_KEY_PREFIX = "entry.";
// Must match DEFAULT_UNIFIED_INBOX_RETENTION_DAYS in blocked-egress-projection.ts; the public store export retains its value.
export { DEFAULT_UNIFIED_INBOX_RETENTION_DAYS } from "./blocked-egress-projection.js";

const HKDF_INFO = "principal-policy-unified-inbox-v1";
const MAX_ENTRY_BYTES = 256 * 1024;

export interface PersistedInboxEntry extends UnifiedInboxEntry {
  fortress_id: string;
  encrypted_at_rest: true;
  retention_until: string;
}

interface PersistedEnvelope {
  version: 1;
  entry: PersistedInboxEntry;
}

export interface UnifiedInboxStoreOptions {
  fortressPath?: string;
  storage?: StorageBackend;
  masterKey: Uint8Array;
  fortressId?: string;
  retentionDays?: number;
  now?: () => Date;
}

export class UnifiedInboxStore {
  private readonly storage: StorageBackend;
  private readonly encryptionKey: Uint8Array;
  private readonly fortressId: string | null;
  readonly retentionDays: number;
  private readonly now: () => Date;

  constructor(opts: UnifiedInboxStoreOptions) {
    if (!opts.storage && !opts.fortressPath) {
      throw new Error("UnifiedInboxStore requires storage or fortressPath");
    }
    this.storage =
      opts.storage ?? new FilesystemStorage(`${opts.fortressPath}/state`);
    this.encryptionKey = derivePurposeKey(opts.masterKey, HKDF_INFO);
    this.fortressId =
      opts.fortressId ?? (opts.fortressPath ? basename(opts.fortressPath) : null);
    this.retentionDays =
      opts.retentionDays !== undefined && opts.retentionDays > 0
        ? opts.retentionDays
        : DEFAULT_UNIFIED_INBOX_RETENTION_DAYS;
    this.now = opts.now ?? (() => new Date());
  }

  async upsert(entry: UnifiedInboxEntry): Promise<PersistedInboxEntry> {
    const existing = await this.get(entry.inbox_id);
    let retentionUntil = existing?.retention_until ?? this.defaultRetentionUntil();
    const admission = parseBlockedEgressAdmissionRecord(entry.blocked_egress_admission);
    if (entry.source_class === "blocked_egress" && admission.ok) {
      // Admission expiry is an immutable upper bound; an upsert can never extend it.
      retentionUntil = retentionUntil < admission.value.expires_at ? retentionUntil : admission.value.expires_at;
    }
    const persisted: PersistedInboxEntry = {
      ...entry,
      encrypted_at_rest: true,
      retention_until: retentionUntil,
    };
    await this.write(persisted);
    return persisted;
  }

  async list(opts?: {
    since?: string;
    source_class?: UnifiedInboxSourceClass;
    exclude_source_class?: UnifiedInboxSourceClass;
    status?: "pending" | "resolved";
    limit?: number;
  }): Promise<PersistedInboxEntry[]> {
    const metas = await this.storage.list(
      UNIFIED_INBOX_NAMESPACE,
      UNIFIED_INBOX_KEY_PREFIX,
    );
    const entries: PersistedInboxEntry[] = [];
    let excludedBlockedIds: Set<string> | undefined;
    for (const meta of metas) {
      const inboxId = stripKeyPrefix(meta.key);
      if (inboxId === null) continue;
      let entry: PersistedInboxEntry | null;
      try {
        entry = await this.get(inboxId);
      } catch (error) {
        // Only an authenticated blocked index reference may isolate a read failure from other sources at startup.
        // Must match the strict restore reader in blocked-egress-projection.ts, which still fails the blocked generation.
        if (opts?.exclude_source_class !== "blocked_egress") throw error;
        excludedBlockedIds ??= new Set(await this.readBlockedEgressIndex());
        if (!excludedBlockedIds.has(inboxId)) throw error;
        continue;
      }
      if (!entry) continue;
      if (entry.source_class === opts?.exclude_source_class) continue;
      if (opts?.since && entry.observed_at < opts.since) continue;
      if (opts?.source_class && entry.source_class !== opts.source_class) {
        continue;
      }
      if (opts?.status === "pending" && entry.resolved_at) continue;
      if (opts?.status === "resolved" && !entry.resolved_at) continue;
      entries.push(entry);
    }
    entries.sort((a, b) => (a.observed_at < b.observed_at ? 1 : -1));
    return entries.slice(0, opts?.limit ?? entries.length);
  }

  /** Restore requests strict reads so unreadable ciphertext cannot be mistaken for an absent projection record. */
  async get(inbox_id: string, options?: { strict: true }): Promise<PersistedInboxEntry | null> {
    const raw = await this.storage.read(
      UNIFIED_INBOX_NAMESPACE,
      entryKey(inbox_id),
    );
    if (!raw) return null;
    // Strict projection restore must distinguish unreadable ciphertext from a missing record; ordinary inbox reads keep their legacy contract.
    if (raw.length > MAX_ENTRY_BYTES) {
      if (options?.strict) throw new Error("Invalid blocked-egress entry size");
      return null;
    }
    try {
      const envelope: EncryptedPayload = JSON.parse(bytesToString(raw));
      const aad = this.aadFor(this.fortressIdForRead(), inbox_id);
      const plaintext = decrypt(envelope, this.encryptionKey, aad);
      const persisted = JSON.parse(bytesToString(plaintext)) as PersistedEnvelope;
      if (persisted.version !== 1) return null;
      if (persisted.entry.inbox_id !== inbox_id) return null;
      if (persisted.entry.encrypted_at_rest !== true) return null;
      if (
        this.fortressId !== null &&
        persisted.entry.fortress_id !== this.fortressId
      ) {
        return null;
      }
      // Must match cachePersistedEntry in unified-inbox-bridge.ts: invalid or non-blocked-egress metadata reads as legacy.
      const { blocked_egress, blocked_egress_admission, ...legacy } = persisted.entry;
      const metadata = parseBlockedEgressMetadata(legacy.source_class === "blocked_egress" ? blocked_egress : undefined);
      // The encrypted store is fortress-owned; verified entries were written only from consumer-minted values.
      // Reads omit malformed or wrong-source metadata; resolve later rewrites that sanitized entry.
      // Must match cachePersistedEntry in unified-inbox-bridge.ts: both consume parseBlockedEgressAdmissionRecord and omit wrong-source records.
      const admission = parseBlockedEgressAdmissionRecord(legacy.source_class === "blocked_egress" ? blocked_egress_admission : undefined);
      return { ...legacy, ...(metadata.ok ? { blocked_egress: metadata.value } : {}), ...(admission.ok ? { blocked_egress_admission: admission.value } : {}) };
    } catch (error) {
      if (options?.strict) throw error;
      return null;
    }
  }

  /** Read the bounded encrypted projection index without enumerating entry keys. */
  async readBlockedEgressIndex(): Promise<string[]> {
    const raw = await this.storage.read(UNIFIED_INBOX_NAMESPACE, BLOCKED_EGRESS_INDEX_KEY);
    if (!raw) return [];
    if (raw.length > MAX_ENTRY_BYTES) throw new Error("Invalid blocked-egress index size");
    const plaintext = decrypt(JSON.parse(bytesToString(raw)) as EncryptedPayload, this.encryptionKey,
      this.aadFor(this.fortressIdForRead(), BLOCKED_EGRESS_INDEX_KEY));
    if (plaintext.length > MAX_ENTRY_BYTES) throw new Error("Invalid blocked-egress index size");
    const value: unknown = JSON.parse(bytesToString(plaintext));
    return validateBlockedEgressIndex(value);
  }

  /** Replace the single index record; ids refer only to bounded blocked-egress admissions. */
  async writeBlockedEgressIndex(ids: string[]): Promise<void> {
    const checked = validateBlockedEgressIndex(ids);
    const plaintext = stringToBytes(JSON.stringify(checked));
    const envelope = encrypt(plaintext, this.encryptionKey, this.aadFor(this.fortressIdForRead(), BLOCKED_EGRESS_INDEX_KEY));
    const bytes = stringToBytes(JSON.stringify(envelope));
    if (bytes.length > MAX_ENTRY_BYTES) throw new Error("Invalid blocked-egress index size");
    await this.storage.write(UNIFIED_INBOX_NAMESPACE, BLOCKED_EGRESS_INDEX_KEY, bytes);
  }

  async resolve(inbox_id: string, resolved_by: string): Promise<void> {
    const entry = await this.get(inbox_id);
    if (!entry) return;
    const resolvedAt = entry.resolved_at ?? this.now().toISOString();
    await this.write({
      ...entry,
      resolved_at: resolvedAt,
      resolved_by,
    });
  }

  async delete(inbox_id: string): Promise<boolean> {
    return await this.storage.delete(
      UNIFIED_INBOX_NAMESPACE,
      entryKey(inbox_id),
    );
  }

  async pruneExpired(now?: Date): Promise<{ pruned: number }> {
    const cutoff = (now ?? this.now()).toISOString();
    const metas = await this.storage.list(
      UNIFIED_INBOX_NAMESPACE,
      UNIFIED_INBOX_KEY_PREFIX,
    );
    let pruned = 0;
    for (const meta of metas) {
      const inboxId = stripKeyPrefix(meta.key);
      if (inboxId === null) continue;
      const entry = await this.get(inboxId);
      if (!entry) continue;
      if (entry.retention_until <= cutoff) {
        if (await this.storage.delete(UNIFIED_INBOX_NAMESPACE, meta.key)) {
          pruned += 1;
        }
      }
    }
    return { pruned };
  }

  private async write(entry: PersistedInboxEntry): Promise<void> {
    const payload: PersistedEnvelope = { version: 1, entry };
    const plaintext = stringToBytes(JSON.stringify(payload));
    const aad = this.aadFor(entry.fortress_id, entry.inbox_id);
    const envelope = encrypt(plaintext, this.encryptionKey, aad);
    await this.storage.write(
      UNIFIED_INBOX_NAMESPACE,
      entryKey(entry.inbox_id),
      stringToBytes(JSON.stringify(envelope)),
    );
  }

  private defaultRetentionUntil(): string {
    return new Date(
      this.now().getTime() + this.retentionDays * 24 * 60 * 60 * 1000,
    ).toISOString();
  }

  private fortressIdForRead(): string {
    if (this.fortressId === null) {
      throw new Error("UnifiedInboxStore get/list requires fortressId");
    }
    return this.fortressId;
  }

  private aadFor(fortressId: string, inboxId: string): Uint8Array {
    return stringToBytes(`${fortressId}|${inboxId}`);
  }
}

function entryKey(inboxId: string): string {
  return `${UNIFIED_INBOX_KEY_PREFIX}${inboxId}`;
}

function stripKeyPrefix(key: string): string | null {
  if (!key.startsWith(UNIFIED_INBOX_KEY_PREFIX)) return null;
  return key.slice(UNIFIED_INBOX_KEY_PREFIX.length);
}

// A separate key keeps projection bookkeeping out of legacy entry scans and pruning.
const BLOCKED_EGRESS_INDEX_KEY = "blocked_egress.index.v1";
function validateBlockedEgressIndex(value: unknown): string[] {
  // Must match HUB_BLOCKED_EGRESS_FORTRESS_MAX in hub/constants.ts and restore in blocked-egress-projection.ts.
  // 128 ASCII characters per id leaves 1000 JSON strings plus encryption/base64 overhead below 256 KiB.
  const MAX_INDEX_ID_CHARS = 128;
  if (!Array.isArray(value) || value.length > HUB_BLOCKED_EGRESS_FORTRESS_MAX ||
      value.some(id => typeof id !== "string" || id.length === 0 || id.length > MAX_INDEX_ID_CHARS || !/^[a-zA-Z0-9_-]+$/.test(id)) || new Set(value).size !== value.length) {
    throw new Error("Invalid blocked-egress index");
  }
  return [...value] as string[];
}
