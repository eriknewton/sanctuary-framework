/**
 * Operator Chat Store — Session Record Persistence Tests (v1.2.x F9)
 *
 * Verifies the encrypted session record + per-agent active-session
 * index added by F9 to support the cross-process chat-server subprocess:
 *  - Round-trip writeSession / loadSession against an ephemeral fortress.
 *  - Last-write-wins cursor advance semantics.
 *  - getActiveSessionIdForAgent returns the bound session id; clears
 *    cleanly when set to null.
 *  - Two store instances against the same fortress decrypt each other's
 *    records (cross-process consistency model).
 */

import { describe, it, expect } from "vitest";
import { MemoryStorage } from "../../src/storage/memory.js";
import { generateRandomKey } from "../../src/core/random.js";
import { OperatorChatStore } from "../../src/chat/operator-chat-store.js";
import type { OperatorChatSession } from "../../src/chat/operator-chat-types.js";

function buildSession(
  overrides: Partial<OperatorChatSession> = {},
): OperatorChatSession {
  const nowIso = new Date().toISOString();
  return {
    session_id: "chat-session-test-1",
    agent_id: "agent:claude_code:fortress-test",
    approval_inbox_item_id: "tier1.test",
    created_at: nowIso,
    expires_at: new Date(Date.now() + 60 * 60 * 1000).toISOString(),
    last_polled_message_id: null,
    ...overrides,
  };
}

describe("OperatorChatStore — session records (v1.2.x F9)", () => {
  it("loadSession returns null for an unknown session id", async () => {
    const storage = new MemoryStorage();
    const masterKey = generateRandomKey();
    const store = new OperatorChatStore(storage, masterKey);
    const result = await store.loadSession("does-not-exist");
    expect(result).toBeNull();
  });

  it("writeSession + loadSession round-trip preserves all fields", async () => {
    const storage = new MemoryStorage();
    const masterKey = generateRandomKey();
    const store = new OperatorChatStore(storage, masterKey);
    const original = buildSession({
      last_polled_message_id: "msg-42",
    });
    await store.writeSession(original);
    const loaded = await store.loadSession(original.session_id);
    expect(loaded).toEqual(original);
  });

  it("writeSession overwrites prior record for the same session id", async () => {
    const storage = new MemoryStorage();
    const masterKey = generateRandomKey();
    const store = new OperatorChatStore(storage, masterKey);
    const initial = buildSession({ last_polled_message_id: null });
    await store.writeSession(initial);
    const updated: OperatorChatSession = {
      ...initial,
      last_polled_message_id: "msg-99",
    };
    await store.writeSession(updated);
    const loaded = await store.loadSession(initial.session_id);
    expect(loaded?.last_polled_message_id).toBe("msg-99");
  });

  it("deleteSession removes the record and subsequent load returns null", async () => {
    const storage = new MemoryStorage();
    const masterKey = generateRandomKey();
    const store = new OperatorChatStore(storage, masterKey);
    const session = buildSession();
    await store.writeSession(session);
    await store.deleteSession(session.session_id);
    expect(await store.loadSession(session.session_id)).toBeNull();
  });

  it("loadSession returns null when the record is corrupt", async () => {
    const storage = new MemoryStorage();
    const masterKey = generateRandomKey();
    const store = new OperatorChatStore(storage, masterKey);
    const session = buildSession();
    await store.writeSession(session);

    // Corrupt the on-disk ciphertext by overwriting with non-JSON bytes.
    await storage.write(
      "_chat",
      `session.${session.session_id}`,
      new TextEncoder().encode("not json"),
    );
    expect(await store.loadSession(session.session_id)).toBeNull();
  });

  it("two store instances against the same fortress share session records", async () => {
    // Models the cross-process shape: dashboard process's store and
    // chat-server subprocess's store share storage + master key, so
    // each can decrypt the other's writes.
    const storage = new MemoryStorage();
    const masterKey = generateRandomKey();
    const dashboardStore = new OperatorChatStore(storage, masterKey);
    const chatServerStore = new OperatorChatStore(storage, masterKey);

    const session = buildSession({ last_polled_message_id: null });
    await dashboardStore.writeSession(session);
    const seen = await chatServerStore.loadSession(session.session_id);
    expect(seen).toEqual(session);

    // Chat-server advances cursor; dashboard sees the new value on
    // re-load.
    const advanced: OperatorChatSession = {
      ...session,
      last_polled_message_id: "advanced-id",
    };
    await chatServerStore.writeSession(advanced);
    const dashboardSeesAdvance = await dashboardStore.loadSession(
      session.session_id,
    );
    expect(dashboardSeesAdvance?.last_polled_message_id).toBe("advanced-id");
  });
});

describe("OperatorChatStore — active-agent index (v1.2.x F9)", () => {
  it("returns null when no active session is indexed", async () => {
    const storage = new MemoryStorage();
    const masterKey = generateRandomKey();
    const store = new OperatorChatStore(storage, masterKey);
    expect(
      await store.getActiveSessionIdForAgent("agent:test:f1"),
    ).toBeNull();
  });

  it("setActiveSessionIdForAgent then get returns the bound id", async () => {
    const storage = new MemoryStorage();
    const masterKey = generateRandomKey();
    const store = new OperatorChatStore(storage, masterKey);
    await store.setActiveSessionIdForAgent("agent:test:f1", "chat-session-7");
    expect(
      await store.getActiveSessionIdForAgent("agent:test:f1"),
    ).toBe("chat-session-7");
  });

  it("setActiveSessionIdForAgent(null) clears the index", async () => {
    const storage = new MemoryStorage();
    const masterKey = generateRandomKey();
    const store = new OperatorChatStore(storage, masterKey);
    await store.setActiveSessionIdForAgent("agent:test:f1", "chat-session-7");
    await store.setActiveSessionIdForAgent("agent:test:f1", null);
    expect(
      await store.getActiveSessionIdForAgent("agent:test:f1"),
    ).toBeNull();
  });

  it("the index is per-agent: setting one agent does not affect another", async () => {
    const storage = new MemoryStorage();
    const masterKey = generateRandomKey();
    const store = new OperatorChatStore(storage, masterKey);
    await store.setActiveSessionIdForAgent("agent:a:f1", "chat-session-A");
    await store.setActiveSessionIdForAgent("agent:b:f1", "chat-session-B");
    expect(
      await store.getActiveSessionIdForAgent("agent:a:f1"),
    ).toBe("chat-session-A");
    expect(
      await store.getActiveSessionIdForAgent("agent:b:f1"),
    ).toBe("chat-session-B");
  });
});
