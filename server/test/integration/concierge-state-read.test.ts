import { describe, expect, it } from "vitest";
import { ConciergeService, SanctuaryContextReader } from "../../src/concierge/index.js";

describe("concierge state read integration", () => {
  it("answers pending approval questions from inbox context passed to the selector", async () => {
    const reader = new SanctuaryContextReader({
      auditLog: {
        query: async () => ({
          total: 1,
          entries: [{
            timestamp: "2026-05-16T00:00:00.000Z",
            layer: "l2",
            operation: "approval_request",
            identity_id: "operator",
            result: "success",
          }],
          integrity_findings: [],
        }),
        append: async () => undefined,
      },
      identityManager: {
        listWithRotationCount: () => [],
        list: () => [],
      },
      inboxSources: {
        listPendingApprovals: () => [
          {
            version: "1.1",
            item_id: "approval-a",
            kind: "approval_pending",
            created_at: "2026-05-16T00:00:00.000Z",
            identity_id: "operator",
            display_template_id: "approval.test",
            display_template_args: [],
            resolved: false,
            tier: "tier1",
            operation_category: "policy_change",
          },
          {
            version: "1.1",
            item_id: "approval-b",
            kind: "approval_pending",
            created_at: "2026-05-16T00:00:00.000Z",
            identity_id: "operator",
            display_template_id: "approval.test",
            display_template_args: [],
            resolved: false,
            tier: "tier2",
            operation_category: "other",
          },
        ],
        listRecentBlockedEgress: () => [],
        listRecentPrivacyEvents: () => [],
        listActiveBudgetWarnings: () => [],
        listActiveRecoveryPrompts: () => [],
        listRecentAgentErrors: () => [],
      },
      taskService: {
        list: async () => [{
          id: "task-1",
          fortress_id: "fortress-a",
          title: "Ship concierge",
          creator: "operator",
          status: "pending",
          created_at: "2026-05-16T00:00:00.000Z",
          updated_at: "2026-05-16T00:00:00.000Z",
          schema_version: 1,
        }],
      },
      stateStore: {
        list: async () => ({ total: 0, keys: [], merkle_root: "root" }),
        read: async () => null,
      },
      policyBudgetSources: {
        listPolicySummaries: () => [],
        listBudgetSummaries: () => [],
      },
      fortressId: "fortress-a",
      identityId: "operator",
    });
    const service = new ConciergeService({
      reader,
      selector: {
        getSubstrate: async () => ({
          surface: "concierge",
          substrate: "local",
          badge: { surface: "concierge", substrate: "local", labelKey: "local", tradeoffKey: "local", status: "green" },
          capability: { summarize: true, classify: true, redact: true },
          displayLabel: "Local model - test",
        }),
        invokeSummarize: async (_surface, request) => {
          const text = request.context.includes('\\"pending_count\\": 2')
            ? "There are 2 pending approvals."
            : "I do not know.";
          return {
            servedBy: "local",
            failureClass: null,
            body: { kind: "summarize" as const, text },
            completedAt: new Date().toISOString(),
            latencyMs: 1,
          };
        },
        getOperatorVisibleStatus: async () => ({
          version: "1.2",
          generatedAt: new Date().toISOString(),
          surfaces: [],
          hardware: { totalRamGb: 16, cpuArch: "other", tier: "mid", recommendedLocalModel: "phi-4-mini", ollamaReachable: true, ollamaModels: ["test"] },
        }),
        getConfig: () => ({ fallback: {
          concierge: "degrade-silent",
          "direct-agent-gate-advisor": "conservative-deny",
          "sentinel-scoring": "conservative-deny",
          "gate-explanation": "degrade-silent",
          "privacy-filter-tier-2": "degrade-silent",
          "template-suggestion": "degrade-silent",
        } }),
      },
    });

    const response = await service.ask({
      question: "how many pending approvals are there?",
      stream: false,
    });

    expect(response.answer).toBe("There are 2 pending approvals.");
    expect(response.context.task_state.total).toBe(1);
    expect(response.context.audit_log.entries[0]!.operation).toBe("approval_request");
  });
});
