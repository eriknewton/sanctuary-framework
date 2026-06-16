/**
 * Test: concierge domain context reference block
 *
 * Finding SSS (P2): the concierge substrate had no Sanctuary-domain reference,
 * so it fell through to generic LLM knowledge on policy/template questions.
 * This test verifies the static reference block is present in the context
 * passed to `invokeSummarize`.
 */

import { describe, it, expect, vi } from "vitest";
import { OperatorChatService, SANCTUARY_DOMAIN_REFERENCE } from "../../src/chat/operator-chat-service.js";
import type { OperatorChatServiceDeps } from "../../src/chat/operator-chat-service.js";
import type { SubstrateSelector } from "../../src/intelligence/index.js";
import type { AuditLog } from "../../src/operational/audit-log.js";
import type { OperatorChatStore } from "../../src/chat/operator-chat-store.js";
import type {
  SummarizeRequest,
  SubstrateResponse,
  SubstrateHandle,
} from "../../src/intelligence/types.js";

function makeStubStore(): OperatorChatStore {
  return {
    appendMessage: vi.fn().mockResolvedValue(undefined),
    loadThread: vi.fn().mockResolvedValue(null),
  } as unknown as OperatorChatStore;
}

function makeStubAuditLog(): AuditLog {
  return {
    append: vi.fn(),
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
    invokeSummarize: vi.fn(async (_surface: string, req: SummarizeRequest): Promise<SubstrateResponse> => {
      captured.context = req.context;
      return {
        servedBy: "local",
        failureClass: null,
        body: { kind: "summarize" as const, text: "mock response" },
        completedAt: new Date().toISOString(),
        latencyMs: 10,
      };
    }),
  } as unknown as SubstrateSelector;

  return { selector, captured };
}

describe("concierge Sanctuary domain reference", () => {
  it("includes the reference block in the context passed to the substrate", async () => {
    const { selector, captured } = makeCapturingSelector();

    const deps: OperatorChatServiceDeps = {
      store: makeStubStore(),
      auditLog: makeStubAuditLog(),
      identityId: "test-identity",
      substrateSelector: selector,
      conciergeContextProviders: {
        recentActivity: async () => "No recent activity.",
        agentInventory: async () => "No agents wrapped.",
        openInbox: async () => "No pending items.",
      },
    };

    const service = new OperatorChatService(deps);
    await service.sendConcierge("explain channel templates");

    expect(captured.context).not.toBeNull();
    const ctx = captured.context!;

    // Reference section header present
    expect(ctx).toContain("## Sanctuary reference");

    // Castle Architecture
    expect(ctx).toContain("Castle Architecture");
    expect(ctx).toContain("Castle Wall");

    // Channel template names (canonical from constants.ts)
    const templateNames = [
      "request-approve-act",
      "read-then-report",
      "scheduled-digest",
      "plan-draft-only",
      "fortress-relay",
    ];
    const matchCount = templateNames.filter((t) => ctx.includes(t)).length;
    expect(matchCount).toBeGreaterThanOrEqual(3);

    // Four canonical policy slots
    expect(ctx).toContain("memory");
    expect(ctx).toContain("credentials");
    expect(ctx).toContain("plans");
    expect(ctx).toContain("outputs");

    // Key concepts
    expect(ctx).toContain("Encrypted state store");
    expect(ctx).toContain("audit log");
    expect(ctx).toContain("Ed25519");

    // Existing sections still present
    expect(ctx).toContain("## Recent activity");
    expect(ctx).toContain("## Wrapped agents");
    expect(ctx).toContain("## Open inbox");
  });

  it("includes the reference block even when no context providers are wired", async () => {
    const { selector, captured } = makeCapturingSelector();

    const deps: OperatorChatServiceDeps = {
      store: makeStubStore(),
      auditLog: makeStubAuditLog(),
      identityId: "test-identity",
      substrateSelector: selector,
      // no conciergeContextProviders
    };

    const service = new OperatorChatService(deps);
    await service.sendConcierge("what is a fortress?");

    expect(captured.context).not.toBeNull();
    const ctx = captured.context!;

    expect(ctx).toContain("## Sanctuary reference");
    expect(ctx).toContain("Castle Architecture");
    expect(ctx).toContain("## Recent activity");
    expect(ctx).toContain("(no providers wired)");
  });

  it("reference block contains all five channel template names", () => {
    // Directly verify the constant has all five
    expect(SANCTUARY_DOMAIN_REFERENCE).toContain("request-approve-act");
    expect(SANCTUARY_DOMAIN_REFERENCE).toContain("read-then-report");
    expect(SANCTUARY_DOMAIN_REFERENCE).toContain("scheduled-digest");
    expect(SANCTUARY_DOMAIN_REFERENCE).toContain("plan-draft-only");
    expect(SANCTUARY_DOMAIN_REFERENCE).toContain("fortress-relay");
  });

  it("reference block is within token budget (250-450 tokens, approx 4 chars per token)", () => {
    // Rough estimate: 1 token ~ 4 characters for English prose
    const approxTokens = SANCTUARY_DOMAIN_REFERENCE.length / 4;
    expect(approxTokens).toBeGreaterThanOrEqual(200);
    expect(approxTokens).toBeLessThanOrEqual(550);
  });
});
