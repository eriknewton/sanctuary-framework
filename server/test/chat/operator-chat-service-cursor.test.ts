/**
 * Operator Chat Service — Cursor Advance + Cross-Process Helpers (v1.2.x F9)
 *
 * Verifies the F9 additions to OperatorChatService:
 *  - advancePollCursor mutates the session record in persistence; the
 *    in-memory cache reflects the new value on subsequent reads.
 *  - findActiveSessionForAgent returns the active session bound to an
 *    agent; null when no active session or when the bound session is
 *    closed.
 *  - resolveSession falls back to persistence on cache miss (the
 *    cross-process consistency model: chat-server's service instance
 *    starts with an empty cache and hydrates from disk).
 */

import { describe, it, expect } from "vitest";
import { MemoryStorage } from "../../src/storage/memory.js";
import { generateRandomKey } from "../../src/core/random.js";
import { AuditLog } from "../../src/l2-operational/audit-log.js";
import {
  OperatorChatService,
  OperatorChatStore,
} from "../../src/chat/operator-chat-index.js";

const TEST_IDENTITY = "test-operator";
const TEST_AGENT = "agent:claude_code:fortress-1";

function makeService(sharedStore?: {
  storage: MemoryStorage;
  masterKey: Uint8Array;
}) {
  const storage = sharedStore?.storage ?? new MemoryStorage();
  const masterKey = sharedStore?.masterKey ?? generateRandomKey();
  const auditLog = new AuditLog(storage, masterKey);
  const store = new OperatorChatStore(storage, masterKey);
  const service = new OperatorChatService({
    store,
    auditLog,
    identityId: TEST_IDENTITY,
  });
  return { service, store, storage, masterKey, auditLog };
}

describe("OperatorChatService — advancePollCursor", () => {
  it("persists the cursor on the session record", async () => {
    const { service, store } = makeService();
    const session = await service.openDirectAgentSession({
      agentId: TEST_AGENT,
      approvalInboxItemId: "tier1.cursor",
      channelTemplateId: null,
    });
    expect(session.last_polled_message_id ?? null).toBeNull();

    await service.advancePollCursor(session.session_id, "msg-1");

    const reloaded = await store.loadSession(session.session_id);
    expect(reloaded?.last_polled_message_id).toBe("msg-1");
  });

  it("subsequent advance overwrites the cursor (LWW)", async () => {
    const { service, store } = makeService();
    const session = await service.openDirectAgentSession({
      agentId: TEST_AGENT,
      approvalInboxItemId: "tier1.lww",
      channelTemplateId: null,
    });
    await service.advancePollCursor(session.session_id, "msg-1");
    await service.advancePollCursor(session.session_id, "msg-7");
    const reloaded = await store.loadSession(session.session_id);
    expect(reloaded?.last_polled_message_id).toBe("msg-7");
  });

  it("no-op when session is closed", async () => {
    const { service, store } = makeService();
    const session = await service.openDirectAgentSession({
      agentId: TEST_AGENT,
      approvalInboxItemId: "tier1.closed-cursor",
      channelTemplateId: null,
    });
    await service.closeDirectAgentSession(session.session_id, "operator_close");
    await service.advancePollCursor(session.session_id, "should-not-stick");
    const reloaded = await store.loadSession(session.session_id);
    // The closed record retains its prior cursor value; advance is silently
    // ignored.
    expect(reloaded?.last_polled_message_id ?? null).toBeNull();
  });

  it("no-op when session id is unknown", async () => {
    const { service } = makeService();
    // Simply does not throw.
    await service.advancePollCursor("unknown-session", "anything");
  });
});

describe("OperatorChatService — findActiveSessionForAgent", () => {
  it("returns the active session for an agent", async () => {
    const { service } = makeService();
    const session = await service.openDirectAgentSession({
      agentId: TEST_AGENT,
      approvalInboxItemId: "tier1.find",
      channelTemplateId: null,
    });
    const found = await service.findActiveSessionForAgent(TEST_AGENT);
    expect(found?.session_id).toBe(session.session_id);
  });

  it("returns null when no active session indexed for the agent", async () => {
    const { service } = makeService();
    expect(await service.findActiveSessionForAgent("agent:none:f1")).toBeNull();
  });

  it("returns null after the session is closed (index is cleared)", async () => {
    const { service } = makeService();
    const session = await service.openDirectAgentSession({
      agentId: TEST_AGENT,
      approvalInboxItemId: "tier1.find-close",
      channelTemplateId: null,
    });
    await service.closeDirectAgentSession(session.session_id, "operator_close");
    expect(await service.findActiveSessionForAgent(TEST_AGENT)).toBeNull();
  });

  it("a fresh session on the same agent rebinds the index cleanly", async () => {
    const { service } = makeService();
    const first = await service.openDirectAgentSession({
      agentId: TEST_AGENT,
      approvalInboxItemId: "tier1.first",
      channelTemplateId: null,
    });
    await service.closeDirectAgentSession(first.session_id, "operator_close");
    const second = await service.openDirectAgentSession({
      agentId: TEST_AGENT,
      approvalInboxItemId: "tier1.second",
      channelTemplateId: null,
    });
    const found = await service.findActiveSessionForAgent(TEST_AGENT);
    expect(found?.session_id).toBe(second.session_id);
  });
});

describe("OperatorChatService — cross-process resolveSession fallback", () => {
  it("a second service instance against the same fortress sees the first's session via persistence", async () => {
    const storage = new MemoryStorage();
    const masterKey = generateRandomKey();
    const { service: dashboard } = makeService({ storage, masterKey });
    const session = await dashboard.openDirectAgentSession({
      agentId: TEST_AGENT,
      approvalInboxItemId: "tier1.cross",
      channelTemplateId: null,
    });

    // Models the chat-server subprocess: separate service instance,
    // empty cache, must hydrate from persistence.
    const { service: chatServer } = makeService({ storage, masterKey });
    const resolved = await chatServer.resolveSession(session.session_id);
    expect(resolved?.session_id).toBe(session.session_id);
    expect(resolved?.agent_id).toBe(TEST_AGENT);
  });

  it("getSession (sync) returns null on a cross-process service that has not resolved yet", async () => {
    // The dashboard process's cache stays hot; the chat-server's
    // does not. getSession is sync + cache-only by design — async
    // callers must use resolveSession.
    const storage = new MemoryStorage();
    const masterKey = generateRandomKey();
    const { service: dashboard } = makeService({ storage, masterKey });
    const session = await dashboard.openDirectAgentSession({
      agentId: TEST_AGENT,
      approvalInboxItemId: "tier1.sync",
      channelTemplateId: null,
    });

    const { service: chatServer } = makeService({ storage, masterKey });
    expect(chatServer.getSession(session.session_id)).toBeNull();

    // After resolveSession, the cache is hot.
    await chatServer.resolveSession(session.session_id);
    expect(chatServer.getSession(session.session_id)?.session_id).toBe(
      session.session_id,
    );
  });
});
