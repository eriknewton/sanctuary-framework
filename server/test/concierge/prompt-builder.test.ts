import { describe, expect, it } from "vitest";
import {
  CONCIERGE_PROMPT_DOMAIN,
  type ConciergeContextBundle,
} from "../../src/concierge/index.js";
import { buildConciergePrompt, isSummarizationQuery } from "../../src/concierge/prompt-builder.js";

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

describe("concierge prompt builder — ZZZZ summarization hardening", () => {
  it("isSummarizationQuery detects summarization-class queries", () => {
    expect(isSummarizationQuery("summarize fortress activity")).toBe(true);
    expect(isSummarizationQuery("give me a summary of the last hour")).toBe(true);
    expect(isSummarizationQuery("what happened in the last day")).toBe(true);
    expect(isSummarizationQuery("recent activity")).toBe(true);
    expect(isSummarizationQuery("activity over the last 24 hours")).toBe(true);
    expect(isSummarizationQuery("fortress activity overview")).toBe(true);
  });

  it("isSummarizationQuery returns false for factual queries", () => {
    expect(isSummarizationQuery("any open approvals?")).toBe(false);
    expect(isSummarizationQuery("how many identities?")).toBe(false);
    expect(isSummarizationQuery("what is the fortress id?")).toBe(false);
    expect(isSummarizationQuery("list tasks")).toBe(false);
  });

  it("summarization queries inject anti-hallucination clause into system prompt", () => {
    const emptyContext: ConciergeContextBundle = {
      generated_at: "2026-05-20T00:00:00.000Z",
      read_surfaces: ["audit_log", "identity_registry", "approval_inbox", "sovereignty_profile", "task_state", "state_store"],
      audit_log: { total_matching: 0, entries: [], integrity_findings: [] },
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
        status_counts: { pending: 0, in_progress: 0, blocked: 0, ready_for_review: 0, completed: 0, cancelled: 0 },
        tasks: [],
        recent_activity: [],
      },
      state_store: { include_payloads: false, namespaces: [] },
    };

    const messages = buildConciergePrompt({ question: "summarize fortress activity", context: emptyContext });
    const systemPrompt = messages[0]!.content;
    expect(systemPrompt).toContain("Do not invent activities");
    expect(systemPrompt).toContain("No fortress activity recorded in the requested window");
  });

  it("factual queries do NOT inject the summarization anti-hallucination clause", () => {
    const emptyContext: ConciergeContextBundle = {
      generated_at: "2026-05-20T00:00:00.000Z",
      read_surfaces: ["audit_log", "identity_registry", "approval_inbox", "sovereignty_profile", "task_state", "state_store"],
      audit_log: { total_matching: 0, entries: [], integrity_findings: [] },
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
        status_counts: { pending: 0, in_progress: 0, blocked: 0, ready_for_review: 0, completed: 0, cancelled: 0 },
        tasks: [],
        recent_activity: [],
      },
      state_store: { include_payloads: false, namespaces: [] },
    };

    const messages = buildConciergePrompt({ question: "any open approvals?", context: emptyContext });
    const systemPrompt = messages[0]!.content;
    expect(systemPrompt).not.toContain("Do not invent activities");
  });
});
