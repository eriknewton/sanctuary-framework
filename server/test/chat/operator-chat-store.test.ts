/**
 * Operator Chat Store — Encrypted Persistence Tests (WP-V1.2-4)
 *
 * Verifies:
 *   - load returns null on missing record
 *   - save -> load round-trip preserves OperatorChatThread shape
 *   - on-disk payload is encrypted (no plaintext message body on disk)
 *   - appendMessage creates the thread on first append
 *   - appendMessage caps thread length at OPERATOR_CHAT_MAX_THREAD_LENGTH
 *   - deleteThread removes the record and subsequent load returns null
 *   - chatStorageKey produces the documented per-surface layout
 */

import { describe, it, expect } from "vitest";
import {
  OPERATOR_CHAT_NAMESPACE,
  OperatorChatStore,
  chatStorageKey,
} from "../../src/chat/operator-chat-store.js";
import {
  CONCIERGE_THREAD_KEY,
  OPERATOR_CHAT_MAX_THREAD_LENGTH,
  type OperatorChatMessage,
} from "../../src/chat/operator-chat-types.js";
import { MemoryStorage } from "../../src/storage/memory.js";
import { generateRandomKey } from "../../src/core/random.js";
import { bytesToString } from "../../src/core/encoding.js";

function makeMessage(overrides: Partial<OperatorChatMessage>): OperatorChatMessage {
  const base: OperatorChatMessage = {
    message_id: `msg-${Math.random().toString(36).slice(2, 10)}`,
    surface: "concierge",
    role: "operator",
    body: "hello world",
    created_at: new Date().toISOString(),
  };
  return { ...base, ...overrides };
}

describe("Operator Chat Store", () => {
  it("returns null when no thread record exists", async () => {
    const storage = new MemoryStorage();
    const store = new OperatorChatStore(storage, generateRandomKey());

    const result = await store.loadThread("concierge", CONCIERGE_THREAD_KEY);
    expect(result).toBeNull();
  });

  it("save -> load round-trip preserves the OperatorChatThread shape", async () => {
    const storage = new MemoryStorage();
    const store = new OperatorChatStore(storage, generateRandomKey());

    const message = makeMessage({ body: "what did Cline do today" });
    await store.appendMessage("concierge", CONCIERGE_THREAD_KEY, message);

    const loaded = await store.loadThread("concierge", CONCIERGE_THREAD_KEY);
    expect(loaded).not.toBeNull();
    expect(loaded?.version).toBe(1);
    expect(loaded?.messages.length).toBe(1);
    expect(loaded?.messages[0]?.body).toBe("what did Cline do today");
  });

  it("on-disk payload is encrypted (no plaintext body)", async () => {
    const storage = new MemoryStorage();
    const store = new OperatorChatStore(storage, generateRandomKey());

    const secretBody = "totally-secret-cleartext-body-nobody-must-see";
    await store.appendMessage(
      "concierge",
      CONCIERGE_THREAD_KEY,
      makeMessage({ surface: "concierge", body: secretBody }),
    );

    const raw = await storage.read(
      OPERATOR_CHAT_NAMESPACE,
      chatStorageKey("concierge", CONCIERGE_THREAD_KEY),
    );
    expect(raw).not.toBeNull();
    const onDisk = bytesToString(raw!);
    expect(onDisk).not.toContain("totally-secret-cleartext-body");
  });

  it("appendMessage caps thread length at OPERATOR_CHAT_MAX_THREAD_LENGTH", async () => {
    const storage = new MemoryStorage();
    const store = new OperatorChatStore(storage, generateRandomKey());

    // Append cap+5 messages so the oldest 5 fall off.
    for (let i = 0; i < OPERATOR_CHAT_MAX_THREAD_LENGTH + 5; i++) {
      await store.appendMessage(
        "concierge",
        CONCIERGE_THREAD_KEY,
        makeMessage({ body: `msg-${i}` }),
      );
    }

    const loaded = await store.loadThread("concierge", CONCIERGE_THREAD_KEY);
    expect(loaded?.messages.length).toBe(OPERATOR_CHAT_MAX_THREAD_LENGTH);
    // First-retained body is msg-5 (msg-0..4 fell off).
    expect(loaded?.messages[0]?.body).toBe("msg-5");
    // Last-retained body is msg-(cap+4).
    expect(loaded?.messages[OPERATOR_CHAT_MAX_THREAD_LENGTH - 1]?.body).toBe(
      `msg-${OPERATOR_CHAT_MAX_THREAD_LENGTH + 4}`,
    );
  });

  it("deleteThread removes the record and subsequent load returns null", async () => {
    const storage = new MemoryStorage();
    const store = new OperatorChatStore(storage, generateRandomKey());

    await store.appendMessage(
      "concierge",
      CONCIERGE_THREAD_KEY,
      makeMessage({ body: "to be deleted" }),
    );
    await store.deleteThread("concierge", CONCIERGE_THREAD_KEY);

    const loaded = await store.loadThread("concierge", CONCIERGE_THREAD_KEY);
    expect(loaded).toBeNull();
  });

  it("chatStorageKey uses surface-prefixed flat key layout", () => {
    expect(chatStorageKey("concierge", CONCIERGE_THREAD_KEY)).toBe(
      `concierge.${CONCIERGE_THREAD_KEY}`,
    );
  });

  it("treats a corrupt on-disk record as 'no thread' (returns null)", async () => {
    const storage = new MemoryStorage();
    const store = new OperatorChatStore(storage, generateRandomKey());

    await storage.write(
      OPERATOR_CHAT_NAMESPACE,
      chatStorageKey("concierge", CONCIERGE_THREAD_KEY),
      Buffer.from("not-json-at-all", "utf-8"),
    );

    const loaded = await store.loadThread("concierge", CONCIERGE_THREAD_KEY);
    expect(loaded).toBeNull();
  });
});
