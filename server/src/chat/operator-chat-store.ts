/**
 * Sanctuary MCP Server — Operator Chat Persistence
 *
 * Encrypted at-rest store for operator chat threads. Mirrors the
 * `IntelligenceConfigStore` shape but addresses multiple records by
 * `(surface, thread-key)` rather than a single per-fortress record.
 *
 * Storage layout:
 *   namespace: `_chat`              (underscore-prefixed = reserved L1 namespace)
 *   key (concierge):  `concierge.{thread_key}`
 *   key (direct):     `agent.{agent_id}`
 *   payload:   AES-256-GCM-encrypted `OperatorChatThread` JSON, key
 *              derived via HKDF from the fortress master key with info
 *              string `operator-chat-store-v1`.
 *
 * Thread-key namespace:
 * Concierge stores under a single record with sentinel thread-key
 * `_fortress` (CONCIERGE_THREAD_KEY); direct-agent stores under per-
 * agent records keyed by agent id. This keeps the storage layout flat
 * (no nested namespacing) while preventing concierge / agent collision.
 *
 * Append-only semantics:
 * Threads are append-only at the message level. Persist is full-record
 * read-modify-write; the cap on thread length is enforced at append time
 * (oldest messages fall off when `OPERATOR_CHAT_MAX_THREAD_LENGTH` is
 * exceeded). The audit log retains every message regardless.
 */

import type { StorageBackend } from "../storage/interface.js";
import { encrypt, decrypt, type EncryptedPayload } from "../core/encryption.js";
import { derivePurposeKey } from "../core/key-derivation.js";
import { stringToBytes, bytesToString } from "../core/encoding.js";
import {
  CONCIERGE_THREAD_KEY,
  OPERATOR_CHAT_MAX_THREAD_LENGTH,
  type OperatorChatMessage,
  type OperatorChatSurface,
  type OperatorChatThread,
} from "./operator-chat-types.js";

export const OPERATOR_CHAT_NAMESPACE = "_chat";
const HKDF_INFO = "operator-chat-store-v1";

/**
 * Build the storage key for a (surface, thread-key) pair.
 *
 * Concierge: `concierge.{CONCIERGE_THREAD_KEY}` — currently a single
 * record per fortress.
 * Direct-agent: `agent.{agent_id}` — one record per wrapped agent.
 *
 * The dot-separated layout keeps the keys flat in the underlying
 * storage backend list view; the prefix makes per-surface queries
 * clean.
 */
export function chatStorageKey(
  surface: OperatorChatSurface,
  threadKey: string,
): string {
  if (surface === "concierge") return `concierge.${threadKey}`;
  return `agent.${threadKey}`;
}

/**
 * Encrypted operator chat persistence.
 */
export class OperatorChatStore {
  private storage: StorageBackend;
  private encryptionKey: Uint8Array;

  constructor(storage: StorageBackend, masterKey: Uint8Array) {
    this.storage = storage;
    this.encryptionKey = derivePurposeKey(masterKey, HKDF_INFO);
  }

  /**
   * Load a thread. Returns null if no record exists or if the on-disk
   * record is corrupt; callers treat both as "empty thread, start
   * fresh" and emit no audit event for the absence.
   */
  async loadThread(
    surface: OperatorChatSurface,
    threadKey: string,
  ): Promise<OperatorChatThread | null> {
    const key = chatStorageKey(surface, threadKey);
    let raw: Uint8Array | null;
    try {
      raw = await this.storage.read(OPERATOR_CHAT_NAMESPACE, key);
    } catch {
      return null;
    }
    if (!raw) return null;

    try {
      const encrypted: EncryptedPayload = JSON.parse(bytesToString(raw));
      const decrypted = decrypt(encrypted, this.encryptionKey);
      const parsed = JSON.parse(bytesToString(decrypted)) as OperatorChatThread;
      if (parsed.version !== 1) return null;
      return parsed;
    } catch {
      return null;
    }
  }

  /**
   * Persist a thread. Caller is responsible for cap enforcement; the
   * `appendMessage` helper below drops oldest messages before persist
   * when the cap is exceeded.
   */
  async saveThread(thread: OperatorChatThread): Promise<void> {
    const key = chatStorageKey(thread.surface, thread.thread_key);
    const stamped: OperatorChatThread = {
      ...thread,
      updated_at: new Date().toISOString(),
    };
    const serialized = stringToBytes(JSON.stringify(stamped));
    const encrypted = encrypt(serialized, this.encryptionKey);
    await this.storage.write(
      OPERATOR_CHAT_NAMESPACE,
      key,
      stringToBytes(JSON.stringify(encrypted)),
    );
  }

  /**
   * Append a message to a thread, creating the thread if it doesn't
   * exist, and persist. Enforces the per-thread length cap by dropping
   * oldest messages first. Returns the persisted thread.
   */
  async appendMessage(
    surface: OperatorChatSurface,
    threadKey: string,
    message: OperatorChatMessage,
  ): Promise<OperatorChatThread> {
    const existing = await this.loadThread(surface, threadKey);
    const messages = existing ? [...existing.messages, message] : [message];
    while (messages.length > OPERATOR_CHAT_MAX_THREAD_LENGTH) {
      messages.shift();
    }
    const next: OperatorChatThread = {
      version: 1,
      surface,
      thread_key: threadKey,
      messages,
      updated_at: new Date().toISOString(),
    };
    await this.saveThread(next);
    return next;
  }

  /**
   * Delete a thread. Used by operator-driven thread reset and by
   * direct-agent unwrap cleanup. The audit log retains the per-message
   * history regardless.
   */
  async deleteThread(
    surface: OperatorChatSurface,
    threadKey: string,
  ): Promise<void> {
    const key = chatStorageKey(surface, threadKey);
    try {
      await this.storage.delete(OPERATOR_CHAT_NAMESPACE, key);
    } catch {
      // Storage backend may not support delete on missing key; tolerate.
    }
  }
}

export { CONCIERGE_THREAD_KEY };
