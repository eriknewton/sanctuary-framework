/**
 * Sanctuary v1.3 WP-V1.3-9 Tau-3, concierge dynamic context integration tests
 *
 * Service-level coverage for the dynamic-context wiring: confirms the
 * fold lands in the substrate context, the audit payload carries
 * `dynamic_context_categories`, fetcher failures emit the new event
 * class, and the LLM-assist fallback routes through the supplied
 * classifier.
 */

import { describe, it, expect, vi } from "vitest";
import { OperatorChatService } from "../../src/chat/operator-chat-service.js";
import type { OperatorChatServiceDeps } from "../../src/chat/operator-chat-service.js";
import type { SubstrateSelector } from "../../src/intelligence/index.js";
import type { AuditLog } from "../../src/l2-operational/audit-log.js";
import type { OperatorChatStore } from "../../src/chat/operator-chat-store.js";
import type {
  SummarizeRequest,
  SubstrateResponse,
  SubstrateHandle,
} from "../../src/intelligence/types.js";
import type { ContextFetchers } from "../../src/chat/concierge-context-router.js";

function makeStubStore(): OperatorChatStore {
  return {
    appendMessage: vi.fn().mockResolvedValue(undefined),
    loadThread: vi.fn().mockResolvedValue(null),
  } as unknown as OperatorChatStore;
}

interface AuditCall {
  layer: string;
  operation: string;
  identityId: string;
  details: Record<string, unknown>;
  result: string;
}

function makeRecordingAuditLog(calls: AuditCall[]): AuditLog {
  return {
    append: (
      layer: string,
      operation: string,
      identityId: string,
      details: Record<string, unknown>,
      result: string,
    ) => {
      calls.push({ layer, operation, identityId, details, result });
    },
  } as unknown as AuditLog;
}

function makeCapturingSelector(): {
  selector: SubstrateSelector;
  captured: { context: string | null; query: string | null };
} {
  const captured = { context: null as string | null, query: null as string | null };

  const handle: SubstrateHandle = {
    surface: "concierge",
    substrate: "local",
    badge: {
      surface: "concierge",
      substrate: "local",
      labelKey: "test",
      tradeoffKey: "test",
      status: "green",
    },
    capability: { summarize: true, classify: false, redact: false },
    displayLabel: "Test Local",
  };

  const selector = {
    getSubstrate: vi.fn().mockResolvedValue(handle),
    invokeSummarize: vi.fn(
      async (_surface: string, req: SummarizeRequest): Promise<SubstrateResponse> => {
        captured.context = req.context;
        captured.query = req.query;
        return {
          servedBy: "local",
          failureClass: null,
          body: { kind: "summarize" as const, text: "concierge reply" },
          completedAt: new Date().toISOString(),
          latencyMs: 12,
        };
      },
    ),
  } as unknown as SubstrateSelector;

  return { selector, captured };
}

function makeFetchers(overrides: Partial<ContextFetchers> = {}): ContextFetchers {
  const empty = async () => "";
  const base: ContextFetchers = {
    templates: empty,
    agent_state: empty,
    agent_activity: empty,
    audit_log: empty,
    sentinel_findings: empty,
    anomaly_alerts: empty,
    recent_receipts: empty,
    verascore_deltas: empty,
  };
  return { ...base, ...overrides };
}

describe("concierge dynamic context wiring (Tau-3)", () => {
  it("folds matching category into the substrate context", async () => {
    const audit: AuditCall[] = [];
    const { selector, captured } = makeCapturingSelector();
    const deps: OperatorChatServiceDeps = {
      store: makeStubStore(),
      auditLog: makeRecordingAuditLog(audit),
      identityId: "op-1",
      substrateSelector: selector,
      conciergeContextProviders: {
        recentActivity: async () => "(activity)",
        agentInventory: async () => "(agents)",
        openInbox: async () => "(inbox)",
      },
      conciergeContextFetchers: makeFetchers({
        templates: async () => "TEMPLATES_BODY",
      }),
    };
    const service = new OperatorChatService(deps);
    await service.sendConcierge("list available templates please");

    expect(captured.context).toContain("## Live fortress context");
    expect(captured.context).toContain("### Templates");
    expect(captured.context).toContain("TEMPLATES_BODY");
  });

  it("emits dynamic_context_categories in the audit payload (matching turn)", async () => {
    const audit: AuditCall[] = [];
    const { selector } = makeCapturingSelector();
    const deps: OperatorChatServiceDeps = {
      store: makeStubStore(),
      auditLog: makeRecordingAuditLog(audit),
      identityId: "op-1",
      substrateSelector: selector,
      conciergeContextFetchers: makeFetchers({
        templates: async () => "TEMPLATES_BODY",
      }),
    };
    const service = new OperatorChatService(deps);
    await service.sendConcierge("list available templates please");

    const chatEvent = audit.find(
      (c) => c.operation === "operator_concierge_chat",
    );
    expect(chatEvent).toBeDefined();
    expect(chatEvent!.details.dynamic_context_categories).toEqual(["templates"]);
  });

  it("emits dynamic_context_categories=[] when no category matched", async () => {
    const audit: AuditCall[] = [];
    const { selector } = makeCapturingSelector();
    const deps: OperatorChatServiceDeps = {
      store: makeStubStore(),
      auditLog: makeRecordingAuditLog(audit),
      identityId: "op-1",
      substrateSelector: selector,
      conciergeContextFetchers: makeFetchers(),
    };
    const service = new OperatorChatService(deps);
    await service.sendConcierge("hello there general kenobi");

    const chatEvent = audit.find(
      (c) => c.operation === "operator_concierge_chat",
    );
    expect(chatEvent).toBeDefined();
    expect(chatEvent!.details.dynamic_context_categories).toEqual([]);
  });

  it("omits dynamic_context_categories field when fetchers are not wired", async () => {
    const audit: AuditCall[] = [];
    const { selector } = makeCapturingSelector();
    const deps: OperatorChatServiceDeps = {
      store: makeStubStore(),
      auditLog: makeRecordingAuditLog(audit),
      identityId: "op-1",
      substrateSelector: selector,
    };
    const service = new OperatorChatService(deps);
    await service.sendConcierge("list available templates please");

    const chatEvent = audit.find(
      (c) => c.operation === "operator_concierge_chat",
    );
    expect(chatEvent).toBeDefined();
    expect(chatEvent!.details.dynamic_context_categories).toBeUndefined();
  });

  it("emits operator_concierge_context_fetcher_failed when a fetcher throws", async () => {
    const audit: AuditCall[] = [];
    const { selector, captured } = makeCapturingSelector();
    const deps: OperatorChatServiceDeps = {
      store: makeStubStore(),
      auditLog: makeRecordingAuditLog(audit),
      identityId: "op-1",
      substrateSelector: selector,
      conciergeContextFetchers: makeFetchers({
        audit_log: async () => {
          throw new Error("audit-log io_failed");
        },
        recent_receipts: async () => "RECEIPTS_BODY",
      }),
    };
    const service = new OperatorChatService(deps);
    await service.sendConcierge(
      "show me the audit log and recent concordia receipts",
    );

    const failureEvent = audit.find(
      (c) => c.operation === "operator_concierge_context_fetcher_failed",
    );
    expect(failureEvent).toBeDefined();
    expect(failureEvent!.details.category).toBe("audit_log");
    expect(failureEvent!.details.failure_reason).toBe("io_failed");
    expect(failureEvent!.result).toBe("failure");

    // The user-facing query was NOT broken: the surviving category folded.
    expect(captured.context).toContain("RECEIPTS_BODY");
    const chatEvent = audit.find(
      (c) => c.operation === "operator_concierge_chat",
    );
    expect(chatEvent!.details.dynamic_context_categories).toContain(
      "recent_receipts",
    );
    expect(chatEvent!.details.dynamic_context_categories).not.toContain(
      "audit_log",
    );
  });

  it("LLM-assist fallback: zero keyword matches + classifier picks", async () => {
    const audit: AuditCall[] = [];
    const { selector, captured } = makeCapturingSelector();
    const llmAssist = vi.fn(async () => "templates" as const);
    const deps: OperatorChatServiceDeps = {
      store: makeStubStore(),
      auditLog: makeRecordingAuditLog(audit),
      identityId: "op-1",
      substrateSelector: selector,
      conciergeContextFetchers: makeFetchers({
        templates: async () => "FALLBACK_TEMPLATES",
      }),
      conciergeContextLlmAssist: llmAssist,
    };
    const service = new OperatorChatService(deps);
    await service.sendConcierge("what stuff can I spin up here");

    expect(llmAssist).toHaveBeenCalledTimes(1);
    expect(captured.context).toContain("FALLBACK_TEMPLATES");
    const chatEvent = audit.find(
      (c) => c.operation === "operator_concierge_chat",
    );
    expect(chatEvent!.details.dynamic_context_categories).toEqual(["templates"]);
  });

  it("dynamic context section sits BETWEEN Sanctuary reference and Prior conversation", async () => {
    const audit: AuditCall[] = [];
    const { selector, captured } = makeCapturingSelector();
    const deps: OperatorChatServiceDeps = {
      store: makeStubStore(),
      auditLog: makeRecordingAuditLog(audit),
      identityId: "op-1",
      substrateSelector: selector,
      conciergeContextFetchers: makeFetchers({
        templates: async () => "TEMPLATES_BODY",
      }),
    };
    const service = new OperatorChatService(deps);
    await service.sendConcierge("show me available templates");

    const ctx = captured.context!;
    const refIdx = ctx.indexOf("## Sanctuary reference");
    const dynIdx = ctx.indexOf("## Live fortress context");
    const recentIdx = ctx.indexOf("## Recent activity");
    expect(refIdx).toBeGreaterThanOrEqual(0);
    expect(dynIdx).toBeGreaterThan(refIdx);
    expect(recentIdx).toBeGreaterThan(dynIdx);
  });
});
