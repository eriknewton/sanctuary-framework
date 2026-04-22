/**
 * Sanctuary Chat v1.0 — Chat Log Persistence
 *
 * Every message the fortress sends or receives is persisted to fortress-local
 * encrypted state via the shipped storage path. Chat logs are stored under
 * the `outputs` slot for retention sweep integration (Key 15).
 *
 * Storage namespace: `_chat_messages` (underscore-prefixed = reserved,
 * protected from direct L1 tool access).
 *
 * WP-MVP-7: spawn prompt §7 (chat log persistence).
 */

import { CHAT_STORAGE_NAMESPACE_PREFIX } from "./constants.js";
import type { ChatLogEntry } from "./types.js";

// ═══════════════════════════════════════════════════════════════════════
// Chat log store interface
// ═══════════════════════════════════════════════════════════════════════

/**
 * Storage interface for chat logs. Production wires this to the L1
 * encrypted state store; tests use InMemoryChatLogStore.
 */
export interface ChatLogStore {
  /** Persist a chat log entry. */
  append(entry: ChatLogEntry): Promise<void>;
  /** List entries for a group, ordered by sent_at ascending. */
  listByGroup(groupId: string, limit?: number): Promise<ChatLogEntry[]>;
  /** List entries for a fortress (all groups), ordered by sent_at ascending. */
  listByFortress(fortressId: string, limit?: number): Promise<ChatLogEntry[]>;
  /** Get a single entry by message_id. */
  get(messageId: string): Promise<ChatLogEntry | undefined>;
  /** Delete a single entry (for retention sweep). */
  delete(messageId: string): Promise<void>;
  /** List all entries (for retention sweep enumeration). */
  listAll(): Promise<ChatLogEntry[]>;
  /** Count entries. */
  count(): Promise<number>;
}

// ═══════════════════════════════════════════════════════════════════════
// In-memory implementation (for testing)
// ═══════════════════════════════════════════════════════════════════════

export class InMemoryChatLogStore implements ChatLogStore {
  private entries = new Map<string, ChatLogEntry>();

  async append(entry: ChatLogEntry): Promise<void> {
    this.entries.set(entry.message_id, entry);
  }

  async listByGroup(groupId: string, limit?: number): Promise<ChatLogEntry[]> {
    const results = Array.from(this.entries.values())
      .filter((e) => e.group_id === groupId)
      .sort((a, b) => a.sent_at.localeCompare(b.sent_at));
    return limit ? results.slice(0, limit) : results;
  }

  async listByFortress(fortressId: string, limit?: number): Promise<ChatLogEntry[]> {
    const results = Array.from(this.entries.values())
      .filter((e) => e.fortress_id === fortressId)
      .sort((a, b) => a.sent_at.localeCompare(b.sent_at));
    return limit ? results.slice(0, limit) : results;
  }

  async get(messageId: string): Promise<ChatLogEntry | undefined> {
    return this.entries.get(messageId);
  }

  async delete(messageId: string): Promise<void> {
    this.entries.delete(messageId);
  }

  async listAll(): Promise<ChatLogEntry[]> {
    return Array.from(this.entries.values()).sort((a, b) =>
      a.sent_at.localeCompare(b.sent_at)
    );
  }

  async count(): Promise<number> {
    return this.entries.size;
  }
}

// ═══════════════════════════════════════════════════════════════════════
// Storage key helpers
// ═══════════════════════════════════════════════════════════════════════

/** Generate the state store namespace for chat messages. */
export function chatNamespace(fortressId: string): string {
  return `${CHAT_STORAGE_NAMESPACE_PREFIX}/${fortressId}`;
}

/** Generate the state store key for a single chat message. */
export function chatEntryKey(messageId: string): string {
  return `${CHAT_STORAGE_NAMESPACE_PREFIX}/msg/${messageId}`;
}
