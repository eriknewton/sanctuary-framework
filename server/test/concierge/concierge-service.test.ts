import { describe, expect, it, vi } from "vitest";
import {
  ConciergeService,
  ConciergeUnavailableError,
  type ConciergeContextBundle,
  type ConciergeSelectorLike,
} from "../../src/concierge/index.js";
import type {
  SubstrateChoice,
  SubstrateHandle,
  SubstrateResponse,
  SubstrateStatusReport,
} from "../../src/intelligence/index.js";

const context: ConciergeContextBundle = {
  generated_at: "2026-05-16T00:00:00.000Z",
  read_surfaces: ["audit_log", "identity_registry", "approval_inbox", "sovereignty_profile", "task_state", "state_store"],
  audit_log: { total_matching: 0, entries: [], integrity_findings: [] },
  identity_registry: { identities: [] },
  approval_inbox: { pending_count: 1, items: [] },
  sovereignty_profile: {
    fortress_id: "fortress-a",
    tier_policy: "policy summaries unavailable",
    context_gating_state: "operator CLI concierge only",
    castle_wall: { dashboard_enabled: false },
  },
  task_state: {
    total: 0,
    status_counts: {
      pending: 0,
      in_progress: 0,
      blocked: 0,
      ready_for_review: 0,
      completed: 0,
      cancelled: 0,
    },
    tasks: [],
    recent_activity: [],
  },
  state_store: { include_payloads: false, namespaces: [] },
};

function selectorRig(args: {
  choice?: SubstrateChoice;
  response?: SubstrateResponse;
  summarizeCapable?: boolean;
} = {}) {
  const choice = args.choice ?? "local";
  const response: SubstrateResponse = args.response ?? {
    servedBy: choice,
    failureClass: null,
    body: { kind: "summarize", text: "There is 1 pending approval." },
    completedAt: "2026-05-16T00:00:00.000Z",
    latencyMs: 4,
  };
  const invokeSummarize = vi.fn(async () => response);
  const selector: ConciergeSelectorLike = {
    getSubstrate: vi.fn(async (): Promise<SubstrateHandle> => ({
      surface: "concierge",
      substrate: choice,
      badge: {
        surface: "concierge",
        substrate: choice,
        labelKey: `intelligence.substrate.${choice}.label`,
        tradeoffKey: `intelligence.substrate.${choice}.tradeoff`,
        status: choice === "disabled" ? "red" : "green",
      },
      capability: {
        summarize: args.summarizeCapable ?? choice !== "disabled",
        classify: false,
        redact: false,
      },
      displayLabel: choice === "local" ? "Local model - Gemma 2 2B" : choice,
    })),
    invokeSummarize,
    getOperatorVisibleStatus: vi.fn(async (): Promise<SubstrateStatusReport> => ({
      version: "1.2",
      generatedAt: "2026-05-16T00:00:00.000Z",
      hardware: {
        totalRamGb: 16,
        cpuArch: "other",
        tier: "mid",
        recommendedLocalModel: "phi-4-mini",
        ollamaReachable: choice === "local",
        ollamaModels: choice === "local" ? ["gemma2:2b"] : [],
      },
      surfaces: [{
        surface: "concierge",
        chosen: choice,
        badge: {
          surface: "concierge",
          substrate: choice,
          labelKey: `intelligence.substrate.${choice}.label`,
          tradeoffKey: `intelligence.substrate.${choice}.tradeoff`,
          status: choice === "disabled" ? "red" : "green",
        },
        health: choice === "disabled" ? "unavailable" : "ok",
        failureClass: choice === "disabled" ? "substrate_disabled" : null,
        recentFailures: [],
      }],
    })),
    getConfig: () => ({
      fallback: {
        concierge: "degrade-silent",
        "direct-agent-gate-advisor": "conservative-deny",
        "sentinel-scoring": "conservative-deny",
        "gate-explanation": "degrade-silent",
        "privacy-filter-tier-2": "degrade-silent",
        "template-suggestion": "degrade-silent",
      },
    }),
  };
  return { selector, invokeSummarize };
}

describe("ConciergeService", () => {
  it("routes context through selector.invokeSummarize at the concierge surface", async () => {
    const { selector, invokeSummarize } = selectorRig();
    const service = new ConciergeService({
      reader: { readContext: async () => context },
      selector,
    });

    const response = await service.ask({ question: "how many pending approvals?", stream: false });

    expect(response.answer).toBe("There is 1 pending approval.");
    expect(response.provider).toBe("local");
    expect(invokeSummarize).toHaveBeenCalledWith(
      "concierge",
      expect.objectContaining({
        kind: "summarize",
        query: "how many pending approvals?",
        context: expect.stringContaining('\\"pending_count\\": 1'),
      }),
    );
  });

  it("preserves explicit selector remote policy and reports the substrate that served", async () => {
    const { selector } = selectorRig({ choice: "venice" });
    const service = new ConciergeService({
      reader: { readContext: async () => context },
      selector,
    });

    const response = await service.ask({ question: "status?", stream: false });

    expect(response.provider).toBe("venice");
    expect(response.model).toBe("venice");
  });

  it("short-circuits empty summarization context without any selector invocation", async () => {
    const emptyContext: ConciergeContextBundle = {
      ...context,
      approval_inbox: { pending_count: 0, items: [] },
    };
    const { selector, invokeSummarize } = selectorRig();
    const service = new ConciergeService({
      reader: { readContext: async () => emptyContext },
      selector,
    });

    const response = await service.ask({ question: "summarize fortress activity", stream: false });

    expect(response.answer).toBe("No fortress activity recorded in the requested window.");
    expect(response.model).toBe("deterministic");
    expect(response.provider).toBe("deterministic");
    expect(invokeSummarize).not.toHaveBeenCalled();
    expect(selector.getSubstrate).not.toHaveBeenCalled();
  });

  it("still invokes the selector for a factual query against empty context", async () => {
    const emptyContext: ConciergeContextBundle = {
      ...context,
      approval_inbox: { pending_count: 0, items: [] },
    };
    const { selector, invokeSummarize } = selectorRig({
      response: {
        servedBy: "frontier-with-filter",
        failureClass: null,
        body: { kind: "summarize", text: "No approvals are open." },
        completedAt: "2026-05-16T00:00:00.000Z",
        latencyMs: 6,
      },
    });
    const service = new ConciergeService({
      reader: { readContext: async () => emptyContext },
      selector,
    });

    const response = await service.ask({ question: "any open approvals?", stream: false });

    expect(invokeSummarize).toHaveBeenCalledOnce();
    expect(response).toMatchObject({
      provider: "frontier-with-filter",
      model: "frontier-with-filter",
    });
  });

  it("fails honestly when the selected substrate is disabled", async () => {
    const { selector, invokeSummarize } = selectorRig({ choice: "disabled" });
    const service = new ConciergeService({
      reader: { readContext: async () => context },
      selector,
    });

    await expect(service.ask({ question: "status?", stream: false }))
      .rejects.toThrow("disabled or does not support summarization");
    expect(invokeSummarize).not.toHaveBeenCalled();
  });

  it("fails honestly when the selector exhausts its configured fallback", async () => {
    const { selector } = selectorRig({
      response: {
        servedBy: "frontier-with-filter",
        failureClass: "substrate_unavailable",
        body: { kind: "failure", message: "all configured substrates unavailable" },
        completedAt: "2026-05-16T00:00:00.000Z",
        latencyMs: 10,
      },
    });
    const service = new ConciergeService({
      reader: { readContext: async () => context },
      selector,
    });

    await expect(service.ask({ question: "status?", stream: false }))
      .rejects.toBeInstanceOf(ConciergeUnavailableError);
  });

  it("maps selector health and fallback policy into the frozen status shape", async () => {
    const { selector } = selectorRig();
    const service = new ConciergeService({
      reader: { readContext: async () => context },
      selector,
    });

    const status = await service.status();

    expect(status).toMatchObject({
      provider: "local",
      configured: true,
      reachable: true,
      fallback: "degrade-silent",
      model: "Local model - Gemma 2 2B",
    });
  });
});
