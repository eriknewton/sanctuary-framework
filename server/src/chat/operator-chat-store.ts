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
  type OperatorChatSession,
  type OperatorChatSurface,
  type OperatorChatThread,
} from "./operator-chat-types.js";

export const OPERATOR_CHAT_NAMESPACE = "_chat";
const HKDF_INFO = "operator-chat-store-v1";
// v1.2.x F9: separate purpose key for direct-agent session records so
// thread blob keying stays stable. The chat-server subprocess + dashboard
// process both derive this key from the fortress master key, so the two
// processes share the same persisted session record.
const HKDF_INFO_SESSION = "operator-chat-session-store-v1";

/** Storage key prefix for direct-agent session records: `session.<id>`. */
function sessionStorageKey(sessionId: string): string {
  return `session.${sessionId}`;
}

/** Storage key prefix for the per-agent active-session index: `active.<agent_id>`. */
function activeAgentStorageKey(agentId: string): string {
  return `active.${agentId}`;
}

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
  private sessionEncryptionKey: Uint8Array;

  constructor(storage: StorageBackend, masterKey: Uint8Array) {
    this.storage = storage;
    this.encryptionKey = derivePurposeKey(masterKey, HKDF_INFO);
    this.sessionEncryptionKey = derivePurposeKey(masterKey, HKDF_INFO_SESSION);
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

  // ── Direct-agent session records (v1.2.x F9) ────────────────────────────
  //
  // The dashboard process and the chat-server subprocess (a separate
  // process spawned by the harness's MCP runtime via `sanctuary chat-server`)
  // share these encrypted records. The dashboard owns session lifecycle
  // (open / close); the chat-server only mutates the `last_polled_message_id`
  // cursor. Both use the same fortress master key + HKDF info so the
  // ciphertext is mutually decryptable.

  /**
   * Load a persisted direct-agent session record. Returns null when the
   * record is missing or unreadable. Caller treats both as "session not
   * found" without emitting an audit event for the absence.
   */
  async loadSession(
    sessionId: string,
  ): Promise<OperatorChatSession | null> {
    const key = sessionStorageKey(sessionId);
    let raw: Uint8Array | null;
    try {
      raw = await this.storage.read(OPERATOR_CHAT_NAMESPACE, key);
    } catch {
      return null;
    }
    if (!raw) return null;

    try {
      const encrypted: EncryptedPayload = JSON.parse(bytesToString(raw));
      const decrypted = decrypt(encrypted, this.sessionEncryptionKey);
      return JSON.parse(bytesToString(decrypted)) as OperatorChatSession;
    } catch {
      return null;
    }
  }

  /**
   * Persist a direct-agent session record. Used by the dashboard on
   * session open + close, and by the chat-server on cursor advance.
   * Last-write-wins; concurrent writers within the same field race to
   * the storage backend's tail (chat-server only ever writes the cursor
   * field, dashboard only ever writes lifecycle fields, so the two
   * writer roles don't overlap on the same field by design).
   */
  async writeSession(session: OperatorChatSession): Promise<void> {
    const key = sessionStorageKey(session.session_id);
    const serialized = stringToBytes(JSON.stringify(session));
    const encrypted = encrypt(serialized, this.sessionEncryptionKey);
    await this.storage.write(
      OPERATOR_CHAT_NAMESPACE,
      key,
      stringToBytes(JSON.stringify(encrypted)),
    );
  }

  /**
   * Delete a session record. Currently unused — sessions are flipped to
   * `closed_at` and retained for audit completeness rather than hard-
   * deleted. Provided for exit-bundle re-key cleanup paths and tests.
   */
  async deleteSession(sessionId: string): Promise<void> {
    const key = sessionStorageKey(sessionId);
    try {
      await this.storage.delete(OPERATOR_CHAT_NAMESPACE, key);
    } catch {
      // Tolerate missing-key on delete.
    }
  }

  /**
   * Look up the active-session id bound to a given agent id. Used by
   * the chat-server's `chat/poll_inbox` handler to find which session
   * the wrapped agent should poll without scanning every session record.
   */
  async getActiveSessionIdForAgent(
    agentId: string,
  ): Promise<string | null> {
    const key = activeAgentStorageKey(agentId);
    let raw: Uint8Array | null;
    try {
      raw = await this.storage.read(OPERATOR_CHAT_NAMESPACE, key);
    } catch {
      return null;
    }
    if (!raw) return null;
    try {
      const encrypted: EncryptedPayload = JSON.parse(bytesToString(raw));
      const decrypted = decrypt(encrypted, this.sessionEncryptionKey);
      const parsed = JSON.parse(bytesToString(decrypted)) as {
        agent_id: string;
        session_id: string;
      };
      if (parsed.agent_id !== agentId) return null;
      return parsed.session_id;
    } catch {
      return null;
    }
  }

  /**
   * Set or clear the active-session id bound to an agent. Pass null to
   * clear (called on session-close). Idempotent on re-write.
   */
  async setActiveSessionIdForAgent(
    agentId: string,
    sessionId: string | null,
  ): Promise<void> {
    const key = activeAgentStorageKey(agentId);
    if (sessionId === null) {
      try {
        await this.storage.delete(OPERATOR_CHAT_NAMESPACE, key);
      } catch {
        // Tolerate missing-key on delete.
      }
      return;
    }
    const payload = stringToBytes(
      JSON.stringify({ agent_id: agentId, session_id: sessionId }),
    );
    const encrypted = encrypt(payload, this.sessionEncryptionKey);
    await this.storage.write(
      OPERATOR_CHAT_NAMESPACE,
      key,
      stringToBytes(JSON.stringify(encrypted)),
    );
  }
}

export { CONCIERGE_THREAD_KEY };
