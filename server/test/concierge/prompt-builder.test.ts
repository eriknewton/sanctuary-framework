import { describe, expect, it } from "vitest";
import {
  CONCIERGE_PROMPT_DOMAIN,
  type ConciergeContextBundle,
} from "../../src/concierge/index.js";
import { buildConciergePrompt } from "../../src/concierge/prompt-builder.js";

describe("concierge prompt builder", () => {
  it("uses the concierge domain separator and redacts sensitive fields", () => {
    const context: ConciergeContextBundle = {
      generated_at: "2026-05-16T00:00:00.000Z",
      read_surfaces: ["audit_log", "identity_registry", "approval_inbox", "sovereignty_profile", "task_state", "state_store"],
      audit_log: {
        total_matching: 1,
        entries: [{
          timestamp: "2026-05-16T00:00:00.000Z",
          layer: "l2",
          operation: "test",
          identity_id: "id",
          result: "success",
          details: { private_key: "do-not-include", api_token: "nope" },
        }],
        integrity_findings: [],
      },
      identity_registry: { identities: [] },
      approval_inbox: { pending_count: 0, items: [] },
      sovereignty_profile: {
        fortress_id: "fortress-a",
        tier_policy: "policy summaries unavailable",
        context_gating_state: "on",
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

    const messages = buildConciergePrompt({ question: "what happened?", context });
    expect(messages[0]!.content.startsWith(CONCIERGE_PROMPT_DOMAIN)).toBe(true);
    const rendered = JSON.stringify(messages);
    expect(rendered).not.toContain("do-not-include");
    expect(rendered).not.toContain("nope");
    expect(rendered).toContain("[redacted]");
  });
});
