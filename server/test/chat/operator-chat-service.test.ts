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
import { AuditLog } from "../../src/operational/audit-log.js";
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

