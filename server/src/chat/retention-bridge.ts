/**
 * Sanctuary Chat v1.0 — Retention Bridge
 *
 * Wires chat logs into the WP-MVP-6 retention sweep. Chat messages
 * are stored under the `outputs` policy slot. When the retention sweep
 * runs, it calls the chat retention adapter which deletes expired
 * messages from both the fortress-local store AND the pgvector index.
 *
 * WP-MVP-7: spawn prompt §7 (Key 15 retention applies).
 */

import type { PolicySlot } from "../policy-engine/constants.js";
import type { RetentionStore, SlotEntry } from "../policy-engine/retention-sweep.js";
import type { ChatLogStore } from "./chat-log.js";
import type { InMemoryPgVectorIndex, ChatPgVectorIndex } from "./pgvector-index.js";

/**
 * Adapts chat log storage to the RetentionStore interface used by
 * the WP-MVP-6 retention sweep.
 *
 * Chat messages are surfaced as entries in the `outputs` slot so the
 * existing sweep logic handles them automatically. The adapter handles
 * the cascade: deleting from chat log store + pgvector index.
 */
export class ChatRetentionAdapter implements RetentionStore {
  private chatStore: ChatLogStore;
  private pgIndex: ChatPgVectorIndex | InMemoryPgVectorIndex | null;
  private inner: RetentionStore | null;

  /**
   * @param chatStore The fortress-local chat log store.
   * @param pgIndex The pgvector index (null if Postgres not configured).
   * @param inner Optional inner RetentionStore to delegate non-chat slots to.
   */
  constructor(
    chatStore: ChatLogStore,
    pgIndex: ChatPgVectorIndex | InMemoryPgVectorIndex | null,
    inner: RetentionStore | null = null
  ) {
    this.chatStore = chatStore;
    this.pgIndex = pgIndex;
    this.inner = inner;
  }

  /**
   * List entries for a given agent + slot.
   * For the `outputs` slot, includes chat messages as SlotEntry items.
   * For other slots, delegates to the inner store.
   */
  async listEntries(agent_id: string, slot: PolicySlot): Promise<SlotEntry[]> {
    if (slot === "outputs") {
      // Chat messages stored under outputs slot
      const chatEntries = await this.chatStore.listAll();
      const slotEntries: SlotEntry[] = chatEntries.map((entry) => ({
        key: `chat:${entry.message_id}`,
        created_at: entry.sent_at,
      }));

      // If there's an inner store, merge its outputs entries too
      if (this.inner) {
        const innerEntries = await this.inner.listEntries(agent_id, slot);
        return [...slotEntries, ...innerEntries];
      }
      return slotEntries;
    }

    // Non-outputs slots: delegate to inner
    if (this.inner) {
      return this.inner.listEntries(agent_id, slot);
    }
    return [];
  }

  /**
   * Delete an entry. For chat entries (key starts with "chat:"),
   * cascades to both chat store and pgvector index.
   */
  async deleteEntry(
    agent_id: string,
    slot: PolicySlot,
    key: string
  ): Promise<void> {
    if (slot === "outputs" && key.startsWith("chat:")) {
      const messageId = key.slice(5); // strip "chat:" prefix
      await this.chatStore.delete(messageId);
      if (this.pgIndex) {
        await this.pgIndex.deleteMessage(messageId);
      }
      return;
    }

    // Non-chat entries: delegate to inner
    if (this.inner) {
      await this.inner.deleteEntry(agent_id, slot, key);
    }
  }

  /**
   * Archive an entry (move to archive namespace).
   * Chat messages do not support archival at v1.0; they are deleted.
   */
  async archiveEntry(
    agent_id: string,
    slot: PolicySlot,
    key: string
  ): Promise<void> {
    if (slot === "outputs" && key.startsWith("chat:")) {
      // Chat does not support archive; delete instead.
      // The retention sweep respects the archive flag, but chat
      // messages are volatile by nature. Archival is a v1.x feature.
      await this.deleteEntry(agent_id, slot, key);
      return;
    }

    if (this.inner) {
      await this.inner.archiveEntry(agent_id, slot, key);
    }
  }
}
