import { describe, expect, it } from "vitest";
import { ConciergeService, ConciergeUnavailableError, type ConciergeContextBundle } from "../../src/concierge/index.js";

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

describe("ConciergeService", () => {
  it("gathers context and sends it to Venice", async () => {
    let sawPending = false;
    const service = new ConciergeService({
      reader: { readContext: async () => context },
      venice: {
        model: () => "venice-test",
        checkStatus: async () => ({
          provider: "venice",
          configured: true,
          reachable: true,
          model: "venice-test",
          read_surfaces: context.read_surfaces,
          fallback: "none",
          message: "ok",
        }),
        complete: async ({ messages }) => {
          sawPending = JSON.stringify(messages).includes('\\"pending_count\\": 1');
          return "There is 1 pending approval.";
        },
      },
    });

    const response = await service.ask({ question: "how many pending approvals?", stream: false });
    expect(response.answer).toBe("There is 1 pending approval.");
    expect(sawPending).toBe(true);
  });

  it("fails closed when the provider is unavailable", async () => {
    const service = new ConciergeService({
      reader: { readContext: async () => context },
      venice: {
        model: () => "venice-test",
        checkStatus: async () => ({
          provider: "venice",
          configured: true,
          reachable: false,
          model: "venice-test",
          read_surfaces: context.read_surfaces,
          fallback: "none",
          message: "down",
        }),
        complete: async () => {
          throw new ConciergeUnavailableError("Venice down");
        },
      },
    });

    await expect(service.ask({ question: "status?", stream: false }))
      .rejects.toBeInstanceOf(ConciergeUnavailableError);
  });
});
