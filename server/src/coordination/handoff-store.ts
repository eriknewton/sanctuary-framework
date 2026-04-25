/**
 * Sanctuary v1.1 Coordination — Handoff Persistence
 *
 * Encrypted, append-style storage for `LocalHandoffRecord` snapshots. The
 * canonical timeline of a handoff lives in the L2 audit log via
 * `LocalHandoffAuditPayload` entries; the handoff store keeps the latest
 * record snapshot so reads do not need to replay the audit chain.
 *
 * Storage shape mirrors the privacy and broker modules: AES-256-GCM under a
 * purpose key derived from the fortress master via HKDF info string
 * `sanctuary-v1.1-coordination-handoffs`. The reserved namespace
 * `_handoffs` is underscore-prefixed (per StateStore convention) so L1
 * tooling does not list it as user state.
 */

import type { StorageBackend } from "../storage/interface.js";
import {
  decrypt,
  encrypt,
  type EncryptedPayload,
} from "../core/encryption.js";
import { bytesToString, stringToBytes } from "../core/encoding.js";
import { derivePurposeKey } from "../core/key-derivation.js";
import type { LocalHandoffRecord } from "../contracts/v1.1/handoff-records.js";

export const HANDOFF_NAMESPACE = "_handoffs";
export const HANDOFF_PURPOSE_KEY = "sanctuary-v1.1-coordination-handoffs";

export interface HandoffStoreFilter {
  identity_id?: string;
  sender_agent_id?: string;
  recipient_agent_id?: string;
  status?: LocalHandoffRecord["status"];
}

export class HandoffStore {
  private storage: StorageBackend;
  private encryptionKey: Uint8Array;
  private cache = new Map<string, LocalHandoffRecord>();

  constructor(storage: StorageBackend, masterKey: Uint8Array) {
    this.storage = storage;
    this.encryptionKey = derivePurposeKey(masterKey, HANDOFF_PURPOSE_KEY);
  }

  async put(record: LocalHandoffRecord): Promise<void> {
    const encrypted = encrypt(
      stringToBytes(JSON.stringify(record)),
      this.encryptionKey,
    );
    await this.storage.write(
      HANDOFF_NAMESPACE,
      record.handoff_id,
      stringToBytes(JSON.stringify(encrypted)),
    );
    this.cache.set(record.handoff_id, record);
  }

  async get(handoffId: string): Promise<LocalHandoffRecord | undefined> {
    const cached = this.cache.get(handoffId);
    if (cached) return cached;
    const raw = await this.storage.read(HANDOFF_NAMESPACE, handoffId);
    if (!raw) return undefined;
    try {
      const encrypted: EncryptedPayload = JSON.parse(bytesToString(raw));
      const decrypted = decrypt(encrypted, this.encryptionKey);
      const record = JSON.parse(bytesToString(decrypted)) as LocalHandoffRecord;
      this.cache.set(record.handoff_id, record);
      return record;
    } catch {
      return undefined;
    }
  }

  async list(filter?: HandoffStoreFilter): Promise<LocalHandoffRecord[]> {
    const metas = await this.storage.list(HANDOFF_NAMESPACE);
    const out: LocalHandoffRecord[] = [];
    for (const meta of metas) {
      const record = await this.get(meta.key);
      if (!record) continue;
      if (filter?.identity_id && record.identity_id !== filter.identity_id)
        continue;
      if (
        filter?.sender_agent_id &&
        record.sender_agent_id !== filter.sender_agent_id
      )
        continue;
      if (
        filter?.recipient_agent_id &&
        record.recipient_agent_id !== filter.recipient_agent_id
      )
        continue;
      if (filter?.status && record.status !== filter.status) continue;
      out.push(record);
    }
    return out.sort((a, b) => a.created_at.localeCompare(b.created_at));
  }
}
