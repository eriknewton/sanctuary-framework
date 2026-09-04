import { describe, expect, it } from "vitest";
import {
  CONCIERGE_PROMPT_DOMAIN,
  type ConciergeContextBundle,
} from "../../src/concierge/index.js";
import {
  boundConciergeRecords,
  buildConciergePrompt,
  isSummarizationQuery,
} from "../../src/concierge/prompt-builder.js";

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

/**
 * Adversarial-complexity coverage for the bounded record projection
 * (AGENTS.md rule 8, and rule 12's standing fault-schedule class).
 *
 * Output size and WORK are different quantities, and capping the first does
 * not cap the second. The per-level caps compose multiplicatively: 24 keys at
 * each of 6 levels admits 24^6, roughly 191 million nodes, so a record shaped
 * as a wide tree could cost minutes of CPU while every individual cap was
 * respected and the rendered bundle stayed small. These fixtures are built
 * from SHARED subtree references, which is exactly how an attacker gets
 * enormous logical fan-out out of a small stored record, and they hang a naive
 * walk rather than merely slowing it.
 */
describe("the concierge record projection is bounded in work, not only in output", () => {
  // A generous ceiling, not a benchmark: the assertion that matters is
  // "terminates in human time", and the unbounded walk did not terminate at
  // all. A tight bound here would flake on a loaded CI runner.
  const WALL_CLOCK_CEILING_MS = 2_000;

  it("bounds a single record object with 200k keys", () => {
    const wide: Record<string, string> = {};
    for (let index = 0; index < 200_000; index++) {
      wide[`agent-authored-key-${index}`] = `value-${index}`;
    }
    const started = Date.now();
    const projected = boundConciergeRecords({ audit_log: { details: wide } });
    const elapsed = Date.now() - started;

    expect(elapsed).toBeLessThan(WALL_CLOCK_CEILING_MS);
    const rendered = JSON.stringify(projected);
    expect(rendered.length).toBeLessThan(10_240);
    // Kept a bounded sample and said so, rather than silently dropping.
    expect(rendered).toContain("[keys-omitted]");
  });

  it("bounds a 200-wide, 6-deep tree that a naive walk would never finish", () => {
    // Built by sharing one subtree per level: cheap to construct, and 200^6
    // (6.4e13) nodes if expanded. Depth and width caps alone do not save the
    // walk here; only the node budget does.
    let level: unknown = { leaf: "agent-authored-leaf-value" };
    for (let depth = 0; depth < 6; depth++) {
      const wide: Record<string, unknown> = {};
      for (let index = 0; index < 200; index++) wide[`child-${index}`] = level;
      level = wide;
    }

    const started = Date.now();
    const projected = boundConciergeRecords({ task_state: level });
    const elapsed = Date.now() - started;

    expect(elapsed).toBeLessThan(WALL_CLOCK_CEILING_MS);
    expect(JSON.stringify(projected).length).toBeLessThan(10_240);
  });

  it("still renders an ordinary bundle in full, so the bound is not just truncation", () => {
    const ordinary = {
      audit_log: {
        entries: [
          { operation: "state_write", identity_id: "operator", result: "success" },
        ],
      },
    };
    expect(boundConciergeRecords(ordinary)).toEqual(ordinary);
  });
});
