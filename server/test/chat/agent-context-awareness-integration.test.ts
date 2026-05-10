/**
 * Sanctuary v1.3 WP-V1.3-9 Tau-5, agent-context awareness integration tests
 *
 * Service-level coverage for the Tau-5 wiring: confirms the cache
 * snapshot folds into the substrate prompt as a "Current agent state"
 * section, the `agent_context_snapshot_count` audit field reflects the
 * rendered count, the proactive starter fires once per fresh thread
 * with the correct trigger class, and a missing cache degrades the
 * concierge surface gracefully.
 */

import { describe, it, expect, vi } from "vitest";
import { OperatorChatService } from "../../src/chat/operator-chat-service.js";
import type { OperatorChatServiceDeps } from "../../src/chat/operator-chat-service.js";
import {
  AgentContextCache,
  type AgentContextSnapshot,
} from "../../src/chat/agent-context-cache.js";
import type { SubstrateSelector } from "../../src/intelligence/index.js";
import type { AuditLog } from "../../src/l2-operational/audit-log.js";
import type { OperatorChatStore } from "../../src/chat/operator-chat-store.js";
import type {
  ConciergeMemoryStore,
  ConciergeTurn,
} from "../../src/chat/concierge-memory-store.js";
import type {
  SummarizeRequest,
  SubstrateResponse,
  SubstrateHandle,
} from "../../src/intelligence/types.js";

const NOW = Date.parse("2026-05-10T15:00:00.000Z");

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
  captured: { context: string | null };
} {
  const captured = { context: null as string | null };
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
        return {
          servedBy: "local",
          failureClass: null,
          body: { kind: "summarize" as const, text: "ok" },
          completedAt: new Date().toISOString(),
          latencyMs: 5,
        };
      },
    ),
  } as unknown as SubstrateSelector;
  return { selector, captured };
}

function makeStubMemoryStore(): ConciergeMemoryStore {
  return {
    appendTurn: vi.fn(async () => ({ turn_id: 1 })),
    readThread: vi.fn(async (): Promise<ConciergeTurn[]> => []),
    readThreadStrict: vi.fn(async () => ({ ok: true as const, turns: [] })),
    listThreads: vi.fn(async () => []),
    deleteThread: vi.fn(async () => true),
    pruneExpired: vi.fn(async () => 0),
  } as unknown as ConciergeMemoryStore;
}

/**
 * Build a stub `AgentContextCache` whose `read()` returns the supplied
 * snapshots without any registry / audit-log dependency. Tests for
 * the wiring path need only this surface; the cache's own refresh
 * + multi-fortress logic is covered by the unit suite.
 */
function makeStubCache(
  snapshots: AgentContextSnapshot[],
): AgentContextCache {
  return {
    read: () => snapshots,
    refresh: async () => snapshots,
    observeChanges: () => () => {},
    start: () => {},
    stop: () => {},
  } as unknown as AgentContextCache;
}

function mkSnap(
  name: string,
  flags: AgentContextSnapshot["state_flags"],
  overrides: Partial<AgentContextSnapshot> = {},
): AgentContextSnapshot {
  return {
    agent_id: name,
    agent_name: name,
    template: "research",
    last_activity_at: new Date(NOW).toISOString(),
    current_work_summary: null,
    recent_audit_count_24h: 0,
    recent_egress_count_24h: 0,
    recent_concordia_receipts_count_24h: 0,
    recent_verascore_delta_24h: null,
    state_flags: flags,
    ...overrides,
  };
}

describe("Tau-5 agent-context wiring into the concierge prompt", () => {
  it("folds the 'Current agent state' section into the substrate context", async () => {
    const audit: AuditCall[] = [];
    const { selector, captured } = makeCapturingSelector();
    const cache = makeStubCache([
      mkSnap("OpenClaw", ["idle"], { recent_audit_count_24h: 12 }),
      mkSnap("Cline", ["has_pending_approvals"], { recent_audit_count_24h: 47 }),
    ]);
    const deps: OperatorChatServiceDeps = {
      store: makeStubStore(),
      auditLog: makeRecordingAuditLog(audit),
      identityId: "op-1",
      substrateSelector: selector,
      conciergeAgentContextCache: cache,
    };
    const service = new OperatorChatService(deps);
    await service.sendConcierge("what is happening");

    expect(captured.context).toContain("## Current agent state");
    expect(captured.context).toContain("- OpenClaw");
    expect(captured.context).toContain("- Cline");
  });

  it("places the agent-state section between dynamic-context and prior-conversation in the prompt", async () => {
    const audit: AuditCall[] = [];
    const { selector, captured } = makeCapturingSelector();
    const cache = makeStubCache([mkSnap("OpenClaw", ["idle"])]);
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
      conciergeAgentContextCache: cache,
    };
    const service = new OperatorChatService(deps);
    await service.sendConcierge("hello");

    const ctx = captured.context!;
    const refIdx = ctx.indexOf("## Sanctuary reference");
    const stateIdx = ctx.indexOf("## Current agent state");
    const recentIdx = ctx.indexOf("## Recent activity");
    expect(refIdx).toBeGreaterThanOrEqual(0);
    expect(stateIdx).toBeGreaterThan(refIdx);
    expect(recentIdx).toBeGreaterThan(stateIdx);
  });

  it("emits agent_context_snapshot_count on the operator_concierge_chat audit event", async () => {
    const audit: AuditCall[] = [];
    const { selector } = makeCapturingSelector();
    const cache = makeStubCache([
      mkSnap("OpenClaw", ["idle"]),
      mkSnap("Cline", ["active"]),
      mkSnap("Cursor", ["idle"]),
    ]);
    const deps: OperatorChatServiceDeps = {
      store: makeStubStore(),
      auditLog: makeRecordingAuditLog(audit),
      identityId: "op-1",
      substrateSelector: selector,
      conciergeAgentContextCache: cache,
    };
    const service = new OperatorChatService(deps);
    await service.sendConcierge("hello");

    const chatEvent = audit.find(
      (c) => c.operation === "operator_concierge_chat",
    );
    expect(chatEvent).toBeDefined();
    expect(chatEvent!.details.agent_context_snapshot_count).toBe(3);
  });

  it("omits agent_context_snapshot_count and section when no cache is wired", async () => {
    const audit: AuditCall[] = [];
    const { selector, captured } = makeCapturingSelector();
    const deps: OperatorChatServiceDeps = {
      store: makeStubStore(),
      auditLog: makeRecordingAuditLog(audit),
      identityId: "op-1",
      substrateSelector: selector,
    };
    const service = new OperatorChatService(deps);
    await service.sendConcierge("hello");

    expect(captured.context).not.toContain("## Current agent state");
    const chatEvent = audit.find(
      (c) => c.operation === "operator_concierge_chat",
    );
    expect(chatEvent!.details.agent_context_snapshot_count).toBeUndefined();
  });

  it("degrades gracefully (no section, snapshot_count=0) when the cache returned [] from a failed refresh", async () => {
    const audit: AuditCall[] = [];
    const { selector, captured } = makeCapturingSelector();
    // Cache wired but read() returns [] (simulating a failed refresh).
    const emptyCache = makeStubCache([]);
    const deps: OperatorChatServiceDeps = {
      store: makeStubStore(),
      auditLog: makeRecordingAuditLog(audit),
      identityId: "op-1",
      substrateSelector: selector,
      conciergeAgentContextCache: emptyCache,
    };
    const service = new OperatorChatService(deps);
    await service.sendConcierge("hello");

    // No section rendered when there are no snapshots.
    expect(captured.context).not.toContain("## Current agent state");
    const chatEvent = audit.find(
      (c) => c.operation === "operator_concierge_chat",
    );
    // Field is still present (cache was wired) but the count is 0.
    expect(chatEvent!.details.agent_context_snapshot_count).toBe(0);
  });
});

describe("Tau-5 proactive starter (getProactiveStarter)", () => {
  it("returns null when no cache is wired", () => {
    const audit: AuditCall[] = [];
    const { selector } = makeCapturingSelector();
    const service = new OperatorChatService({
      store: makeStubStore(),
      auditLog: makeRecordingAuditLog(audit),
      identityId: "op-1",
      substrateSelector: selector,
      conciergeMemory: makeStubMemoryStore(),
    });
    expect(service.getProactiveStarter()).toBeNull();
    expect(audit).toEqual([]);
  });

  it("returns null when no memory store is wired (no thread_id namespace)", () => {
    const audit: AuditCall[] = [];
    const { selector } = makeCapturingSelector();
    const cache = makeStubCache([mkSnap("OpenClaw", ["stuck"])]);
    const service = new OperatorChatService({
      store: makeStubStore(),
      auditLog: makeRecordingAuditLog(audit),
      identityId: "op-1",
      substrateSelector: selector,
      conciergeAgentContextCache: cache,
    });
    expect(service.getProactiveStarter()).toBeNull();
  });

  it("fires a starter on a fresh thread + emits operator_concierge_proactive_suggestion_offered", () => {
    const audit: AuditCall[] = [];
    const { selector } = makeCapturingSelector();
    const cache = makeStubCache([mkSnap("Cursor", ["stuck"])]);
    const service = new OperatorChatService({
      store: makeStubStore(),
      auditLog: makeRecordingAuditLog(audit),
      identityId: "op-1",
      substrateSelector: selector,
      conciergeMemory: makeStubMemoryStore(),
      conciergeAgentContextCache: cache,
    });
    const starter = service.getProactiveStarter();
    expect(starter).not.toBeNull();
    expect(starter!.trigger).toBe("stuck_agent");
    expect(starter!.text).toContain("Cursor");

    const event = audit.find(
      (c) => c.operation === "operator_concierge_proactive_suggestion_offered",
    );
    expect(event).toBeDefined();
    expect(event!.details.trigger).toBe("stuck_agent");
    expect(event!.details.triggered_agents_count).toBe(1);
    expect(typeof event!.details.thread_id).toBe("string");
  });

  it("does NOT re-fire on a second call within the same thread (per-thread guard)", () => {
    const audit: AuditCall[] = [];
    const { selector } = makeCapturingSelector();
    const cache = makeStubCache([mkSnap("Cursor", ["stuck"])]);
    const service = new OperatorChatService({
      store: makeStubStore(),
      auditLog: makeRecordingAuditLog(audit),
      identityId: "op-1",
      substrateSelector: selector,
      conciergeMemory: makeStubMemoryStore(),
      conciergeAgentContextCache: cache,
    });
    expect(service.getProactiveStarter()).not.toBeNull();
    expect(service.getProactiveStarter()).toBeNull();

    const events = audit.filter(
      (c) => c.operation === "operator_concierge_proactive_suggestion_offered",
    );
    expect(events.length).toBe(1);
  });

  it("re-fires after resetConciergeMemoryThread allocates a fresh thread", () => {
    const audit: AuditCall[] = [];
    const { selector } = makeCapturingSelector();
    const cache = makeStubCache([mkSnap("OpenClaw", ["has_pending_approvals"])]);
    const service = new OperatorChatService({
      store: makeStubStore(),
      auditLog: makeRecordingAuditLog(audit),
      identityId: "op-1",
      substrateSelector: selector,
      conciergeMemory: makeStubMemoryStore(),
      conciergeAgentContextCache: cache,
    });
    const first = service.getProactiveStarter();
    service.resetConciergeMemoryThread();
    const second = service.getProactiveStarter();

    expect(first).not.toBeNull();
    expect(second).not.toBeNull();
    const events = audit.filter(
      (c) => c.operation === "operator_concierge_proactive_suggestion_offered",
    );
    expect(events.length).toBe(2);
    // The two events should carry distinct thread_ids.
    expect(events[0]!.details.thread_id).not.toBe(events[1]!.details.thread_id);
  });

  it("returns null when the cache snapshot is empty (no signal-bearing state)", () => {
    const audit: AuditCall[] = [];
    const { selector } = makeCapturingSelector();
    const cache = makeStubCache([]);
    const service = new OperatorChatService({
      store: makeStubStore(),
      auditLog: makeRecordingAuditLog(audit),
      identityId: "op-1",
      substrateSelector: selector,
      conciergeMemory: makeStubMemoryStore(),
      conciergeAgentContextCache: cache,
    });
    expect(service.getProactiveStarter()).toBeNull();
    const events = audit.filter(
      (c) => c.operation === "operator_concierge_proactive_suggestion_offered",
    );
    expect(events.length).toBe(0);
  });
});
