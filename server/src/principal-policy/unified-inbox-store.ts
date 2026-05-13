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
export const DEFAULT_UNIFIED_INBOX_RETENTION_DAYS = 30;

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
  private readonly retentionDays: number;
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
    const retentionUntil =
      existing?.retention_until ?? this.defaultRetentionUntil();
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
    status?: "pending" | "resolved";
    limit?: number;
  }): Promise<PersistedInboxEntry[]> {
    const metas = await this.storage.list(
      UNIFIED_INBOX_NAMESPACE,
      UNIFIED_INBOX_KEY_PREFIX,
    );
    const entries: PersistedInboxEntry[] = [];
    for (const meta of metas) {
      const inboxId = stripKeyPrefix(meta.key);
      if (inboxId === null) continue;
      const entry = await this.get(inboxId);
      if (!entry) continue;
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

  async get(inbox_id: string): Promise<PersistedInboxEntry | null> {
    const raw = await this.storage.read(
      UNIFIED_INBOX_NAMESPACE,
      entryKey(inbox_id),
    );
    if (!raw || raw.length > MAX_ENTRY_BYTES) return null;
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
      return persisted.entry;
    } catch {
      return null;
    }
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
