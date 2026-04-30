/**
 * Operator Chat MCP Server Tests (v1.2.x F9)
 *
 * Verifies the harness-side MCP surface (tools that wrapped agents call):
 *  - chat/poll_inbox advertises with no required args; chat/send_reply
 *    advertises session_id + body.
 *  - poll_inbox returns generic error when no active session.
 *  - poll_inbox returns operator messages newer than the cursor + advances
 *    cursor atomically; subsequent polls return empty array.
 *  - send_reply persists the agent reply + audit-emits agent_direct_agent_reply.
 *  - send_reply rejects cross-agent session_ids (load-bearing security
 *    invariant).
 *  - send_reply rejects sessions already closed by the operator.
 *  - end-to-end: dashboard process opens session → chat-server poll picks
 *    it up via persistence → send_reply round-trips into operator history.
 */

import { describe, it, expect } from "vitest";
import { MemoryStorage } from "../../src/storage/memory.js";
import { generateRandomKey } from "../../src/core/random.js";
import { AuditLog } from "../../src/l2-operational/audit-log.js";
import {
  OPERATOR_CHAT_OPS,
  OperatorChatService,
  OperatorChatStore,
} from "../../src/chat/operator-chat-index.js";
import { createChatMcpServer } from "../../src/mcp/chat-server.js";

const TEST_IDENTITY = "test-operator";
const TEST_AGENT = "agent:claude_code:fortress-1";
const OTHER_AGENT = "agent:openclaw:fortress-1";

function makeRig(boundAgent: string = TEST_AGENT) {
  const storage = new MemoryStorage();
  const masterKey = generateRandomKey();
  const auditLog = new AuditLog(storage, masterKey);
  const store = new OperatorChatStore(storage, masterKey);

  // Two service instances against the same fortress: one for the
  // dashboard process (writes session lifecycle), one for the chat-
  // server subprocess (reads sessions + writes cursor + appends agent
  // replies). The two share storage + master key so encrypted records
  // are mutually decryptable.
  const dashboard = new OperatorChatService({
    store,
    auditLog,
    identityId: TEST_IDENTITY,
  });
  const chatServer = new OperatorChatService({
    store,
    auditLog,
    identityId: TEST_IDENTITY,
  });
  const server = createChatMcpServer(chatServer, {
    agentId: boundAgent,
    identityId: TEST_IDENTITY,
  });
  return { server, dashboard, chatServer, store, auditLog, storage };
}

async function callTool(
  server: ReturnType<typeof createChatMcpServer>,
  name: string,
  args: Record<string, unknown>,
) {
  const request = {
    method: "tools/call" as const,
    params: { name, arguments: args },
  };
  const handler = (
    server as unknown as { _requestHandlers: Map<string, Function> }
  )._requestHandlers.get("tools/call");
  if (!handler) throw new Error("tools/call handler not registered");
  return await handler(request, {});
}

async function listTools(server: ReturnType<typeof createChatMcpServer>) {
  const request = { method: "tools/list" as const, params: {} };
  const handler = (
    server as unknown as { _requestHandlers: Map<string, Function> }
  )._requestHandlers.get("tools/list");
  if (!handler) throw new Error("tools/list handler not registered");
  return await handler(request, {});
}

function parseContent(result: { content: Array<{ text: string }> }) {
  return JSON.parse(result.content[0]!.text);
}

describe("Chat MCP Server — tools/list", () => {
  it("advertises chat/poll_inbox + chat/send_reply", async () => {
    const { server } = makeRig();
    const result = await listTools(server);
    const names = (result.tools as Array<{ name: string }>).map(
      (t) => t.name,
    );
    expect(names.sort()).toEqual(["chat/poll_inbox", "chat/send_reply"]);
  });

  it("chat/poll_inbox has empty required args", async () => {
    const { server } = makeRig();
    const result = await listTools(server);
    const tool = (result.tools as Array<{
      name: string;
      inputSchema: { required?: string[] };
    }>).find((t) => t.name === "chat/poll_inbox");
    expect(tool).toBeDefined();
    expect(tool!.inputSchema.required ?? []).toEqual([]);
  });

  it("chat/send_reply requires session_id + body", async () => {
    const { server } = makeRig();
    const result = await listTools(server);
    const tool = (result.tools as Array<{
      name: string;
      inputSchema: { required?: string[] };
    }>).find((t) => t.name === "chat/send_reply");
    expect(tool).toBeDefined();
    expect((tool!.inputSchema.required ?? []).sort()).toEqual([
      "body",
      "session_id",
    ]);
  });
});

describe("Chat MCP Server — chat/poll_inbox", () => {
  it("returns generic error when no active session for this agent", async () => {
    const { server } = makeRig();
    const result = await callTool(server, "chat/poll_inbox", {});
    expect(result.isError).toBe(true);
    const body = parseContent(result);
    expect(body.error).toContain("No active chat session");
  });

  it("returns the operator's pending message and advances the cursor", async () => {
    const { server, dashboard } = makeRig();
    const session = await dashboard.openDirectAgentSession({
      agentId: TEST_AGENT,
      approvalInboxItemId: "tier1.approve",
      channelTemplateId: null,
    });
    await dashboard.sendToAgent({
      sessionId: session.session_id,
      body: "hi from operator",
    });

    const result = await callTool(server, "chat/poll_inbox", {});
    expect(result.isError).toBeUndefined();
    const body = parseContent(result);
    expect(body.session_id).toBe(session.session_id);
    expect(body.session_state).toBe("active");
    expect(body.messages.length).toBe(1);
    expect(body.messages[0].body).toBe("hi from operator");
    expect(body.cursor).toBe(body.messages[0].message_id);
  });

  it("subsequent poll without new operator messages returns empty array", async () => {
    const { server, dashboard } = makeRig();
    const session = await dashboard.openDirectAgentSession({
      agentId: TEST_AGENT,
      approvalInboxItemId: "tier1.approve",
      channelTemplateId: null,
    });
    await dashboard.sendToAgent({
      sessionId: session.session_id,
      body: "first",
    });
    await callTool(server, "chat/poll_inbox", {});
    const second = await callTool(server, "chat/poll_inbox", {});
    expect(second.isError).toBeUndefined();
    const body = parseContent(second);
    expect(body.messages.length).toBe(0);
  });

  it("filters by session_id so prior-session messages stay invisible", async () => {
    const { server, dashboard } = makeRig();
    // Session 1: operator sends, then ends.
    const s1 = await dashboard.openDirectAgentSession({
      agentId: TEST_AGENT,
      approvalInboxItemId: "tier1.s1",
      channelTemplateId: null,
    });
    await dashboard.sendToAgent({
      sessionId: s1.session_id,
      body: "from session 1",
    });
    await dashboard.closeDirectAgentSession(s1.session_id, "operator_close");
    // Session 2: operator sends new message; poll should ONLY see session 2's.
    const s2 = await dashboard.openDirectAgentSession({
      agentId: TEST_AGENT,
      approvalInboxItemId: "tier1.s2",
      channelTemplateId: null,
    });
    await dashboard.sendToAgent({
      sessionId: s2.session_id,
      body: "from session 2",
    });

    const result = await callTool(server, "chat/poll_inbox", {});
    expect(result.isError).toBeUndefined();
    const body = parseContent(result);
    expect(body.session_id).toBe(s2.session_id);
    expect(body.messages.length).toBe(1);
    expect(body.messages[0].body).toBe("from session 2");
  });

  it("returns generic error when bound session has expired", async () => {
    const { server, dashboard } = makeRig();
    // Open session with explicit expiry in the past.
    await dashboard.openDirectAgentSession({
      agentId: TEST_AGENT,
      approvalInboxItemId: "tier1.expired",
      channelTemplateId: null,
      expiresAtIsoOverride: new Date(Date.now() - 60_000).toISOString(),
    });
    const result = await callTool(server, "chat/poll_inbox", {});
    expect(result.isError).toBe(true);
    const body = parseContent(result);
    expect(body.error).toContain("No active chat session");
  });
});

describe("Chat MCP Server — chat/send_reply", () => {
  it("delegates to recordAgentReply and audit-emits", async () => {
    const { server, dashboard, auditLog } = makeRig();
    const session = await dashboard.openDirectAgentSession({
      agentId: TEST_AGENT,
      approvalInboxItemId: "tier1.reply",
      channelTemplateId: null,
    });
    const result = await callTool(server, "chat/send_reply", {
      session_id: session.session_id,
      body: "agent's response",
    });
    expect(result.isError).toBeUndefined();
    const body = parseContent(result);
    expect(body.message.role).toBe("agent");
    expect(body.message.body).toBe("agent's response");
    expect(body.message.session_id).toBe(session.session_id);

    const auditResult = await auditLog.query({ limit: 50 });
    const reply = auditResult.entries.find(
      (e) => e.operation === OPERATOR_CHAT_OPS.DIRECT_AGENT_REPLY,
    );
    expect(reply).toBeDefined();
    // Audit MUST NOT contain the raw reply body (privacy invariant).
    const blob = JSON.stringify(reply!.details ?? {});
    expect(blob).not.toContain("agent's response");
  });

  it("rejects cross-agent session_id (cross-agent isolation guard)", async () => {
    const { server, dashboard } = makeRig(TEST_AGENT);
    // Session bound to a DIFFERENT agent. The chat-server is bound to
    // TEST_AGENT; even though the session record exists in persistence,
    // the chat-server must refuse to act on it.
    const otherSession = await dashboard.openDirectAgentSession({
      agentId: OTHER_AGENT,
      approvalInboxItemId: "tier1.other",
      channelTemplateId: null,
    });
    const result = await callTool(server, "chat/send_reply", {
      session_id: otherSession.session_id,
      body: "would leak across agents",
    });
    expect(result.isError).toBe(true);
    const body = parseContent(result);
    expect(body.error).toContain("Unknown chat session");
  });

  it("rejects send_reply when session is closed", async () => {
    const { server, dashboard } = makeRig();
    const session = await dashboard.openDirectAgentSession({
      agentId: TEST_AGENT,
      approvalInboxItemId: "tier1.closed",
      channelTemplateId: null,
    });
    await dashboard.closeDirectAgentSession(
      session.session_id,
      "operator_close",
    );
    const result = await callTool(server, "chat/send_reply", {
      session_id: session.session_id,
      body: "too late",
    });
    expect(result.isError).toBe(true);
    const body = parseContent(result);
    expect(body.error).toContain("Chat session already closed");
  });

  it("rejects unknown session_id", async () => {
    const { server } = makeRig();
    const result = await callTool(server, "chat/send_reply", {
      session_id: "chat-session-does-not-exist",
      body: "lost",
    });
    expect(result.isError).toBe(true);
  });

  it("rejects empty body", async () => {
    const { server, dashboard } = makeRig();
    const session = await dashboard.openDirectAgentSession({
      agentId: TEST_AGENT,
      approvalInboxItemId: "tier1.empty",
      channelTemplateId: null,
    });
    const result = await callTool(server, "chat/send_reply", {
      session_id: session.session_id,
      body: "",
    });
    expect(result.isError).toBe(true);
  });
});

describe("Chat MCP Server — end-to-end round-trip", () => {
  it("operator submit → poll → reply → operator history shows reply", async () => {
    const { server, dashboard } = makeRig();
    const session = await dashboard.openDirectAgentSession({
      agentId: TEST_AGENT,
      approvalInboxItemId: "tier1.e2e",
      channelTemplateId: null,
    });

    // Operator sends.
    await dashboard.sendToAgent({
      sessionId: session.session_id,
      body: "what files have you touched today?",
    });

    // Wrapped agent's runtime polls.
    const pollResult = await callTool(server, "chat/poll_inbox", {});
    const pollBody = parseContent(pollResult);
    expect(pollBody.messages.length).toBe(1);

    // Wrapped agent's runtime sends a reply.
    const replyResult = await callTool(server, "chat/send_reply", {
      session_id: pollBody.session_id,
      body: "I touched server/src/cli.ts and three tests.",
    });
    expect(replyResult.isError).toBeUndefined();

    // Operator's view of history (dashboard process) sees the reply.
    const history = await dashboard.getDirectAgentHistory(TEST_AGENT);
    expect(history.length).toBe(2);
    expect(history[0]?.role).toBe("operator");
    expect(history[1]?.role).toBe("agent");
    expect(history[1]?.body).toBe(
      "I touched server/src/cli.ts and three tests.",
    );

    // Subsequent poll picks up no new operator messages (cursor advanced).
    const secondPoll = await callTool(server, "chat/poll_inbox", {});
    const secondBody = parseContent(secondPoll);
    expect(secondBody.messages.length).toBe(0);
  });
});
