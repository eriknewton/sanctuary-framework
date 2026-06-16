/**
 * Sanctuary v1.3 WP-V1.3-9 Tau-4, operator-query grammar integration tests
 *
 * Service-level coverage for the Tau-4 wiring: confirms parsed grammar
 * threads into the Tau-3 router's fetchers as `FetcherHints`, the audit
 * payload carries the audit-safe `parsed_grammar` projection, and the
 * privacy invariant (intent_phrase NEVER on the audit surface) holds.
 */

import { describe, it, expect, vi } from "vitest";
import { OperatorChatService } from "../../src/chat/operator-chat-service.js";
import type { OperatorChatServiceDeps } from "../../src/chat/operator-chat-service.js";
import type { SubstrateSelector } from "../../src/intelligence/index.js";
import type { AuditLog } from "../../src/operational/audit-log.js";
import type { OperatorChatStore } from "../../src/chat/operator-chat-store.js";
import type {
  SummarizeRequest,
  SubstrateResponse,
  SubstrateHandle,
} from "../../src/intelligence/types.js";
import type {
  ContextFetchers,
  FetcherHints,
} from "../../src/chat/concierge-context-router.js";
import type { AgentRegistryView } from "../../src/chat/concierge-query-grammar.js";

const REGISTRY: AgentRegistryView = [
  { agent_id: "OpenClaw" },
  { agent_id: "Cline" },
];

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

describe("operator-query grammar integration with Tau-3 router (Tau-4)", () => {
  it("threads parsed time-range into agent_activity fetcher as FetcherHints", async () => {
    const audit: AuditCall[] = [];
    const { selector } = makeCapturingSelector();
    let receivedHints: FetcherHints | undefined;
    let receivedAgentHint: string | null | undefined;

    const deps: OperatorChatServiceDeps = {
      store: makeStubStore(),
      auditLog: makeRecordingAuditLog(audit),
      identityId: "op-1",
      substrateSelector: selector,
      conciergeAgentRegistry: REGISTRY,
      conciergeContextFetchers: makeFetchers({
        agent_activity: async (hint, hints) => {
          receivedAgentHint = hint;
          receivedHints = hints;
          return `activity for ${hint ?? "all"} in window ${hints?.time_range?.relative_label ?? "none"}`;
        },
      }),
    };
    const service = new OperatorChatService(deps);
    await service.sendConcierge("show recent activity for OpenClaw yesterday");

    // The agent-name hint was filled by the parser (registry hit).
    expect(receivedAgentHint).toBe("OpenClaw");
    // The hints object carries the resolved time range.
    expect(receivedHints).toBeDefined();
    expect(receivedHints!.time_range).toBeDefined();
    expect(receivedHints!.time_range!.relative_label).toBe("yesterday");
    expect(receivedHints!.agent_names).toEqual(["OpenClaw"]);
  });

  it("threads parsed event_types into audit_log fetcher hints", async () => {
    const audit: AuditCall[] = [];
    const { selector } = makeCapturingSelector();
    let receivedHints: FetcherHints | undefined;

    const deps: OperatorChatServiceDeps = {
      store: makeStubStore(),
      auditLog: makeRecordingAuditLog(audit),
      identityId: "op-1",
      substrateSelector: selector,
      conciergeContextFetchers: makeFetchers({
        audit_log: async (hints) => {
          receivedHints = hints;
          return `audit entries (${(hints?.event_types ?? []).join(",")})`;
        },
      }),
    };
    const service = new OperatorChatService(deps);
    // Triggers the audit_log keyword route ("audit log") AND a parsed
    // event-type ("policy_change") AND a parsed time range ("this
    // week"). Verifies the hints flow into the fetcher unchanged.
    await service.sendConcierge(
      "show me the audit log policy_change entries from this week",
    );

    expect(receivedHints).toBeDefined();
    expect(receivedHints!.event_types).toContain("policy_change");
    expect(receivedHints!.time_range).toBeDefined();
  });

  it("emits parsed_grammar audit summary with structured fields", async () => {
    const audit: AuditCall[] = [];
    const { selector } = makeCapturingSelector();
    const deps: OperatorChatServiceDeps = {
      store: makeStubStore(),
      auditLog: makeRecordingAuditLog(audit),
      identityId: "op-1",
      substrateSelector: selector,
      conciergeAgentRegistry: REGISTRY,
      conciergeContextFetchers: makeFetchers(),
    };
    const service = new OperatorChatService(deps);
    await service.sendConcierge(
      "what did OpenClaw do yesterday during policy_change events",
    );

    const chatEvent = audit.find(
      (c) => c.operation === "operator_concierge_chat",
    );
    expect(chatEvent).toBeDefined();
    const parsed = chatEvent!.details.parsed_grammar as Record<string, unknown>;
    expect(parsed).toBeDefined();
    expect(parsed.agent_names).toEqual(["OpenClaw"]);
    expect(parsed.event_types).toContain("policy_change");
    expect(parsed.time_range).not.toBeNull();
    expect(parsed.parse_confidence).toBeGreaterThan(0.5);
    // Privacy invariant: the residual operator query phrase MUST NOT
    // appear on the audit summary.
    expect((parsed as { intent_phrase?: unknown }).intent_phrase).toBeUndefined();
  });

  it("emits parsed_grammar even when no fetchers and no registry are wired", async () => {
    const audit: AuditCall[] = [];
    const { selector } = makeCapturingSelector();
    const deps: OperatorChatServiceDeps = {
      store: makeStubStore(),
      auditLog: makeRecordingAuditLog(audit),
      identityId: "op-1",
      substrateSelector: selector,
    };
    const service = new OperatorChatService(deps);
    await service.sendConcierge("what happened today");

    const chatEvent = audit.find(
      (c) => c.operation === "operator_concierge_chat",
    );
    expect(chatEvent).toBeDefined();
    const parsed = chatEvent!.details.parsed_grammar as Record<string, unknown>;
    expect(parsed).toBeDefined();
    expect(parsed.time_range).not.toBeNull();
  });

  it("invokes the grammar LLM-assist hook when the parse is low-confidence", async () => {
    const audit: AuditCall[] = [];
    const { selector } = makeCapturingSelector();
    const grammarLlmAssist = vi.fn(async (_q: string, _partial: unknown) => ({
      event_types: ["policy_change"],
    }));
    const deps: OperatorChatServiceDeps = {
      store: makeStubStore(),
      auditLog: makeRecordingAuditLog(audit),
      identityId: "op-1",
      substrateSelector: selector,
      conciergeGrammarLlmAssist: grammarLlmAssist,
    };
    const service = new OperatorChatService(deps);
    await service.sendConcierge("huh stuff");

    expect(grammarLlmAssist).toHaveBeenCalledTimes(1);
    const chatEvent = audit.find(
      (c) => c.operation === "operator_concierge_chat",
    );
    expect(chatEvent).toBeDefined();
    const parsed = chatEvent!.details.parsed_grammar as Record<string, unknown>;
    expect(parsed.event_types).toContain("policy_change");
  });

  it("passes hints through even on the LLM-assist categorical fallback path", async () => {
    const audit: AuditCall[] = [];
    const { selector } = makeCapturingSelector();
    let receivedHints: FetcherHints | undefined;
    const llmAssist = vi.fn(async () => "templates" as const);

    const deps: OperatorChatServiceDeps = {
      store: makeStubStore(),
      auditLog: makeRecordingAuditLog(audit),
      identityId: "op-1",
      substrateSelector: selector,
      conciergeContextLlmAssist: llmAssist,
      conciergeContextFetchers: makeFetchers({
        templates: async (hints) => {
          receivedHints = hints;
          return "TEMPLATES_BODY";
        },
      }),
    };
    const service = new OperatorChatService(deps);
    // Query has no keyword match, but mentions "yesterday" so the
    // grammar parser still resolves a time range. The category match
    // fires via LLM-assist; hints should still flow through.
    await service.sendConcierge("show me available stuff yesterday");

    expect(llmAssist).toHaveBeenCalled();
    expect(receivedHints).toBeDefined();
    expect(receivedHints!.time_range).toBeDefined();
    expect(receivedHints!.time_range!.relative_label).toBe("yesterday");
  });
});
