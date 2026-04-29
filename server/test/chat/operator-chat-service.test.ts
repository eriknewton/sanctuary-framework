/**
 * Operator Chat Service — Behavioral Tests (WP-V1.2-4)
 *
 * Verifies:
 *   - sendConcierge persists operator query + concierge response
 *   - sendConcierge degrades cleanly when no substrate selector is wired
 *   - sendConcierge emits operator_concierge_chat audit with safe metadata
 *   - sendConcierge applies the PII filter pre-substrate when supplied
 *   - openDirectAgentSession + sendToAgent round-trip the operator message
 *   - sendToAgent throws when session is unknown or already closed
 *   - closeDirectAgentSession emits the close event idempotently
 *   - recordAgentReply persists the agent's response under the same session
 *   - audit emissions never carry the raw query, message, or context body
 */

import { describe, it, expect, beforeEach } from "vitest";
import { MemoryStorage } from "../../src/storage/memory.js";
import { generateRandomKey } from "../../src/core/random.js";
import { AuditLog } from "../../src/l2-operational/audit-log.js";
import {
  OPERATOR_CHAT_OPS,
  OperatorChatService,
  OperatorChatStore,
  CONCIERGE_THREAD_KEY,
  type ConciergeContextProviders,
  type ConciergePiiFilter,
} from "../../src/chat/operator-chat-index.js";

const TEST_IDENTITY = "test-operator";

function buildService(opts: {
  substrateSelector?: ConstructorParameters<typeof OperatorChatService>[0]["substrateSelector"];
  contextProviders?: ConciergeContextProviders;
  piiFilter?: ConciergePiiFilter;
}) {
  const storage = new MemoryStorage();
  const masterKey = generateRandomKey();
  const auditLog = new AuditLog(storage, masterKey);
  const store = new OperatorChatStore(storage, masterKey);
  const service = new OperatorChatService({
    store,
    auditLog,
    identityId: TEST_IDENTITY,
    ...(opts.substrateSelector !== undefined
      ? { substrateSelector: opts.substrateSelector }
      : {}),
    ...(opts.contextProviders !== undefined
      ? { conciergeContextProviders: opts.contextProviders }
      : {}),
    ...(opts.piiFilter !== undefined
      ? { conciergePiiFilter: opts.piiFilter }
      : {}),
  });
  return { service, auditLog, store, storage };
}

describe("OperatorChatService — concierge", () => {
  it("degrades cleanly when no substrate selector is wired", async () => {
    const { service } = buildService({});
    const response = await service.sendConcierge("what did Cline do today");

    expect(response.outcome).toBe("substrate_disabled");
    expect(response.served_by).toBe("disabled");
    expect(response.message.role).toBe("concierge");
    expect(response.message.body).toContain("Concierge unavailable");
  });

  it("persists operator query + concierge response in the concierge thread", async () => {
    const { service } = buildService({});
    await service.sendConcierge("what did Cline do today");

    const history = await service.getConciergeHistory();
    expect(history.length).toBe(2);
    expect(history[0]?.role).toBe("operator");
    expect(history[0]?.body).toBe("what did Cline do today");
    expect(history[1]?.role).toBe("concierge");
  });

  it("emits operator_concierge_chat audit with safe metadata only", async () => {
    const { service, auditLog } = buildService({});
    await service.sendConcierge("what did Cline do today");

    const result = await auditLog.query({ limit: 50 });
    const conciergeEvents = result.entries.filter(
      (e) => e.operation === OPERATOR_CHAT_OPS.CONCIERGE_CHAT,
    );
    expect(conciergeEvents.length).toBe(1);
    const evt = conciergeEvents[0]!;
    const detailsBlob = JSON.stringify(evt.details ?? {});
    expect(detailsBlob).not.toContain("what did Cline do today");
    expect(evt.details?.kind).toBe("operator_concierge_chat");
    expect(typeof evt.details?.query_hash).toBe("string");
  });

  it("applies the PII filter pre-substrate when supplied", async () => {
    const filtered: string[] = [];
    const piiFilter: ConciergePiiFilter = {
      filter(input: string) {
        const out = input.replace(/\bCline\b/g, "[REDACTED:NAME]");
        filtered.push(out);
        return { filtered: out, redactions: input === out ? 0 : 1 };
      },
    };
    const { service } = buildService({ piiFilter });
    await service.sendConcierge("what did Cline do today");
    expect(filtered.length).toBe(1);
    expect(filtered[0]).toContain("[REDACTED:NAME]");
  });

  it("throws on empty operator query", async () => {
    const { service } = buildService({});
    await expect(service.sendConcierge("   ")).rejects.toThrow();
  });
});

describe("OperatorChatService — direct-agent", () => {
  it("openDirectAgentSession returns a session with stable id + expiry", async () => {
    const { service } = buildService({});
    const session = await service.openDirectAgentSession({
      agentId: "claude-code",
      approvalInboxItemId: "tier1.test.item",
      channelTemplateId: "request-approve-act",
    });
    expect(session.session_id.length).toBeGreaterThan(0);
    expect(session.agent_id).toBe("claude-code");
    expect(session.approval_inbox_item_id).toBe("tier1.test.item");
    expect(Number.isFinite(Date.parse(session.expires_at))).toBe(true);
  });

  it("emits direct_agent_session_open audit on open", async () => {
    const { service, auditLog } = buildService({});
    await service.openDirectAgentSession({
      agentId: "claude-code",
      approvalInboxItemId: "tier1.test.item",
      channelTemplateId: null,
    });
    const result = await auditLog.query({ limit: 50 });
    const opens = result.entries.filter(
      (e) => e.operation === OPERATOR_CHAT_OPS.DIRECT_AGENT_SESSION_OPEN,
    );
    expect(opens.length).toBe(1);
    expect(opens[0]?.details?.agent_id).toBe("claude-code");
  });

  it("sendToAgent persists the operator message under the session's agent thread", async () => {
    const { service } = buildService({});
    const session = await service.openDirectAgentSession({
      agentId: "claude-code",
      approvalInboxItemId: "tier1.test.item",
      channelTemplateId: null,
    });

    const result = await service.sendToAgent({
      sessionId: session.session_id,
      body: "draft the dashboard PR review please",
    });
    expect(result.message.role).toBe("operator");
    expect(result.message.session_id).toBe(session.session_id);

    const history = await service.getDirectAgentHistory("claude-code");
    expect(history.length).toBe(1);
    expect(history[0]?.body).toBe("draft the dashboard PR review please");
  });

  it("emits operator_direct_agent_chat audit with hashed message body", async () => {
    const { service, auditLog } = buildService({});
    const session = await service.openDirectAgentSession({
      agentId: "claude-code",
      approvalInboxItemId: "tier1.test.item",
      channelTemplateId: null,
    });
    const secretBody = "this body must not appear in the audit log payload";
    await service.sendToAgent({
      sessionId: session.session_id,
      body: secretBody,
    });

    const result = await auditLog.query({ limit: 50 });
    const evt = result.entries.find(
      (e) => e.operation === OPERATOR_CHAT_OPS.DIRECT_AGENT_CHAT,
    );
    expect(evt).toBeDefined();
    const blob = JSON.stringify(evt!.details ?? {});
    expect(blob).not.toContain(secretBody);
    expect(typeof evt!.details?.message_hash).toBe("string");
  });

  it("sendToAgent throws when session is unknown", async () => {
    const { service } = buildService({});
    await expect(
      service.sendToAgent({ sessionId: "nope", body: "test" }),
    ).rejects.toThrow(/unknown chat session/);
  });

  it("sendToAgent throws when session is closed", async () => {
    const { service } = buildService({});
    const session = await service.openDirectAgentSession({
      agentId: "claude-code",
      approvalInboxItemId: "tier1.test.item",
      channelTemplateId: null,
    });
    await service.closeDirectAgentSession(session.session_id, "operator_close");
    await expect(
      service.sendToAgent({ sessionId: session.session_id, body: "test" }),
    ).rejects.toThrow(/already closed/);
  });

  it("recordAgentReply persists agent response in the same thread", async () => {
    const { service } = buildService({});
    const session = await service.openDirectAgentSession({
      agentId: "claude-code",
      approvalInboxItemId: "tier1.test.item",
      channelTemplateId: null,
    });
    await service.sendToAgent({
      sessionId: session.session_id,
      body: "operator message",
    });
    await service.recordAgentReply({
      sessionId: session.session_id,
      body: "agent response",
    });
    const history = await service.getDirectAgentHistory("claude-code");
    expect(history.length).toBe(2);
    expect(history[0]?.role).toBe("operator");
    expect(history[1]?.role).toBe("agent");
  });

  it("closeDirectAgentSession is idempotent on already-closed session", async () => {
    const { service, auditLog } = buildService({});
    const session = await service.openDirectAgentSession({
      agentId: "claude-code",
      approvalInboxItemId: "tier1.test.item",
      channelTemplateId: null,
    });
    const first = await service.closeDirectAgentSession(
      session.session_id,
      "operator_close",
    );
    const second = await service.closeDirectAgentSession(
      session.session_id,
      "operator_close",
    );
    expect(first?.close_reason).toBe("operator_close");
    expect(second?.close_reason).toBe("operator_close");
    const result = await auditLog.query({ limit: 50 });
    const closes = result.entries.filter(
      (e) => e.operation === OPERATOR_CHAT_OPS.DIRECT_AGENT_SESSION_CLOSE,
    );
    expect(closes.length).toBe(1);
  });

  it("listActiveSessions filters out closed sessions", async () => {
    const { service } = buildService({});
    const a = await service.openDirectAgentSession({
      agentId: "claude-code",
      approvalInboxItemId: "tier1.a",
      channelTemplateId: null,
    });
    const b = await service.openDirectAgentSession({
      agentId: "openclaw",
      approvalInboxItemId: "tier1.b",
      channelTemplateId: null,
    });
    await service.closeDirectAgentSession(b.session_id, "operator_close");
    const active = service.listActiveSessions();
    expect(active.length).toBe(1);
    expect(active[0]?.session_id).toBe(a.session_id);
  });
});
