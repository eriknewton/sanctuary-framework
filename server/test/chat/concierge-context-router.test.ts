/**
 * Sanctuary v1.3 WP-V1.3-9 Tau-3, concierge dynamic context router tests
 *
 * Pure-module unit coverage for the router. Service-level wiring
 * (audit emission, integration with assembleConciergeContext) is
 * covered separately in concierge-dynamic-context.test.ts.
 */

import { describe, it, expect, vi } from "vitest";
import {
  classifyQuery,
  foldContext,
  CONTEXT_CATEGORIES,
  DYNAMIC_CONTEXT_SECTION_HEADER,
  DEFAULT_DYNAMIC_CONTEXT_TOKEN_BUDGET,
  __testing,
  type ContextCategory,
  type ContextFetchers,
} from "../../src/chat/concierge-context-router.js";

function makeFetchers(
  overrides: Partial<ContextFetchers> = {},
): ContextFetchers {
  const empty = async () => "";
  const base: ContextFetchers = {
    templates: async () => "",
    agent_state: async () => "",
    agent_activity: async () => "",
    audit_log: async () => "",
    sentinel_findings: async () => "",
    anomaly_alerts: async () => "",
    recent_receipts: async () => "",
    verascore_deltas: async () => "",
  };
  return { ...base, ...overrides };
}

function recording<T extends keyof ContextFetchers>(
  category: T,
  payload: string,
  calls: { category: ContextCategory; arg: unknown }[],
): ContextFetchers[T] {
  const fn = async (...args: unknown[]) => {
    calls.push({ category, arg: args[0] ?? null });
    return payload;
  };
  return fn as unknown as ContextFetchers[T];
}

describe("classifyQuery", () => {
  it("returns no matches for an empty query", () => {
    expect(classifyQuery("")).toEqual([]);
  });

  it("matches templates on the bare word", () => {
    const matches = classifyQuery("show me available templates");
    expect(matches[0]?.category).toBe("templates");
    expect(matches[0]?.matched_keywords).toContain("templates");
  });

  it("matches agent_state on `state of agent`", () => {
    const matches = classifyQuery("what is the state of agent foo");
    const cats = matches.map((m) => m.category);
    expect(cats).toContain("agent_state");
  });

  it("matches agent_activity on `recent activity`", () => {
    const matches = classifyQuery("show me recent activity");
    const cats = matches.map((m) => m.category);
    expect(cats).toContain("agent_activity");
  });

  it("matches audit_log on `audit log`", () => {
    const matches = classifyQuery("display the audit log entries");
    const cats = matches.map((m) => m.category);
    expect(cats).toContain("audit_log");
  });

  it("matches sentinel_findings on `whats wrong`", () => {
    const matches = classifyQuery("whats wrong with my fortress");
    const cats = matches.map((m) => m.category);
    expect(cats).toContain("sentinel_findings");
  });

  it("matches anomaly_alerts on `anomaly`", () => {
    const matches = classifyQuery("any anomaly today");
    const cats = matches.map((m) => m.category);
    expect(cats).toContain("anomaly_alerts");
  });

  it("matches recent_receipts on `concordia receipts`", () => {
    const matches = classifyQuery("show me recent concordia receipts");
    const cats = matches.map((m) => m.category);
    expect(cats).toContain("recent_receipts");
  });

  it("matches verascore_deltas on `trust score`", () => {
    const matches = classifyQuery("whats my trust score doing");
    const cats = matches.map((m) => m.category);
    expect(cats).toContain("verascore_deltas");
  });

  it("multi-category match: agent state AND agent activity", () => {
    const matches = classifyQuery(
      "show me agent state and recent activity for cline",
    );
    const cats = matches.map((m) => m.category);
    expect(cats).toContain("agent_state");
    expect(cats).toContain("agent_activity");
  });

  it("does not match `log` inside the word `login`", () => {
    const matches = classifyQuery("the user did a login event");
    const cats = matches.map((m) => m.category);
    expect(cats).not.toContain("audit_log");
  });

  it("does not match `score` inside the word `scoreboard`", () => {
    const matches = classifyQuery("update the scoreboard please");
    const cats = matches.map((m) => m.category);
    expect(cats).not.toContain("verascore_deltas");
  });

  it("orders matches by descending confidence", () => {
    const matches = classifyQuery(
      "list templates and channel template names",
    );
    const templatesMatch = matches.find((m) => m.category === "templates");
    expect(templatesMatch).toBeDefined();
    if (matches.length >= 2) {
      expect(matches[0]!.confidence).toBeGreaterThanOrEqual(
        matches[1]!.confidence,
      );
    }
  });

  it("extracts agent_name_hint for agent_state queries", () => {
    const matches = classifyQuery("status of agent cline");
    const m = matches.find((m) => m.category === "agent_state");
    expect(m?.agent_name_hint).toBe("cline");
  });
});

describe("foldContext", () => {
  it("returns empty section + empty categoriesIncluded on no matches", async () => {
    const result = await foldContext("hello", makeFetchers());
    expect(result.section).toBe("");
    expect(result.categoriesIncluded).toEqual([]);
  });

  it("invokes the matching category fetcher and renders its block", async () => {
    const calls: { category: ContextCategory; arg: unknown }[] = [];
    const result = await foldContext(
      "list channel templates",
      makeFetchers({
        templates: recording("templates", "tmpl-list-payload", calls),
      }),
    );
    expect(result.categoriesIncluded).toEqual(["templates"]);
    expect(result.section).toContain(DYNAMIC_CONTEXT_SECTION_HEADER);
    expect(result.section).toContain("### Templates");
    expect(result.section).toContain("tmpl-list-payload");
    expect(calls).toHaveLength(1);
    expect(calls[0]!.category).toBe("templates");
  });

  it("multi-category: agent_state + agent_activity both fold", async () => {
    const calls: { category: ContextCategory; arg: unknown }[] = [];
    const result = await foldContext(
      "show me agent cline state and recent activity",
      makeFetchers({
        agent_state: recording("agent_state", "STATE BODY", calls),
        agent_activity: recording("agent_activity", "ACTIVITY BODY", calls),
      }),
    );
    expect(result.categoriesIncluded).toContain("agent_state");
    expect(result.categoriesIncluded).toContain("agent_activity");
    expect(result.section).toContain("STATE BODY");
    expect(result.section).toContain("ACTIVITY BODY");
    const agentStateCall = calls.find((c) => c.category === "agent_state");
    expect(agentStateCall?.arg).toBe("cline");
  });

  it("LLM-assist fallback: zero keyword matches + classifier picks a category", async () => {
    const llmAssist = vi.fn(async () => "templates" as const);
    const result = await foldContext(
      "what stuff is available for spinning agents up",
      makeFetchers({
        templates: async () => "TEMPLATES BODY",
      }),
      { llmAssistClassify: llmAssist },
    );
    expect(llmAssist).toHaveBeenCalledTimes(1);
    expect(result.categoriesIncluded).toEqual(["templates"]);
    expect(result.section).toContain("TEMPLATES BODY");
  });

  it("LLM-assist fallback: classifier returns 'none', no fold", async () => {
    const llmAssist = vi.fn(async () => "none" as const);
    const result = await foldContext(
      "what stuff is available for spinning agents up",
      makeFetchers({
        templates: async () => "TEMPLATES BODY",
      }),
      { llmAssistClassify: llmAssist },
    );
    expect(llmAssist).toHaveBeenCalledTimes(1);
    expect(result.section).toBe("");
    expect(result.categoriesIncluded).toEqual([]);
  });

  it("LLM-assist fallback: not invoked on trivial queries (`hi`)", async () => {
    const llmAssist = vi.fn(async () => "templates" as const);
    const result = await foldContext("hi", makeFetchers(), {
      llmAssistClassify: llmAssist,
    });
    expect(llmAssist).not.toHaveBeenCalled();
    expect(result.section).toBe("");
  });

  it("LLM-assist fallback: not invoked when keyword classifier already matched", async () => {
    const llmAssist = vi.fn(async () => "audit_log" as const);
    await foldContext(
      "list channel templates",
      makeFetchers({ templates: async () => "T" }),
      { llmAssistClassify: llmAssist },
    );
    expect(llmAssist).not.toHaveBeenCalled();
  });

  it("LLM-assist fallback: throwing classifier degrades gracefully", async () => {
    const llmAssist = vi.fn(async () => {
      throw new Error("classifier offline");
    });
    const result = await foldContext(
      "what stuff is available for spinning agents up",
      makeFetchers(),
      { llmAssistClassify: llmAssist },
    );
    expect(llmAssist).toHaveBeenCalledTimes(1);
    expect(result.section).toBe("");
  });

  it("fetcher failure: onFetcherFailure invoked, category omitted, others continue", async () => {
    const failures: { category: ContextCategory; error: unknown }[] = [];
    const result = await foldContext(
      "show me audit log and concordia receipts",
      makeFetchers({
        audit_log: async () => {
          throw new Error("audit-log read failed");
        },
        recent_receipts: async () => "RECEIPTS BODY",
      }),
      { onFetcherFailure: (c, e) => failures.push({ category: c, error: e }) },
    );
    expect(failures).toHaveLength(1);
    expect(failures[0]?.category).toBe("audit_log");
    expect(result.categoriesIncluded).toEqual(["recent_receipts"]);
    expect(result.section).toContain("RECEIPTS BODY");
    expect(result.section).not.toContain("audit-log read failed");
  });

  it("fetcher returning empty string drops the category from categoriesIncluded", async () => {
    const result = await foldContext(
      "list templates",
      makeFetchers({ templates: async () => "   " }),
    );
    expect(result.categoriesIncluded).toEqual([]);
    expect(result.section).toBe("");
  });

  it("token budget: low budget keeps highest-confidence category and drops the rest", async () => {
    const long = "X".repeat(2000);
    const result = await foldContext(
      "show me agent cline state and recent activity",
      makeFetchers({
        agent_state: async () => long,
        agent_activity: async () => long,
      }),
      { maxTokens: 200 },
    );
    // Highest-confidence category is always retained even when alone
    // it would breach the budget; this matches the spawn-prompt
    // guarantee that AT LEAST the highest-confidence match folds.
    expect(result.categoriesIncluded.length).toBe(1);
    expect(result.categoriesIncluded[0]).toMatch(/agent_(state|activity)/);
  });

  it("token budget: ample budget keeps every match", async () => {
    const result = await foldContext(
      "show me agent cline state and recent activity",
      makeFetchers({
        agent_state: async () => "STATE",
        agent_activity: async () => "ACTIVITY",
      }),
      { maxTokens: DEFAULT_DYNAMIC_CONTEXT_TOKEN_BUDGET },
    );
    expect(result.categoriesIncluded.length).toBe(2);
  });

  it("isTrivialQuery: short queries + greetings are trivial", () => {
    expect(__testing.isTrivialQuery("hi")).toBe(true);
    expect(__testing.isTrivialQuery("hello")).toBe(true);
    expect(__testing.isTrivialQuery("ok")).toBe(true);
    expect(__testing.isTrivialQuery("")).toBe(true);
    expect(__testing.isTrivialQuery("   ")).toBe(true);
    expect(__testing.isTrivialQuery("what is happening here")).toBe(false);
  });

  it("CONTEXT_CATEGORIES enumerates all 8 expected categories", () => {
    expect(CONTEXT_CATEGORIES).toEqual([
      "templates",
      "agent_state",
      "agent_activity",
      "audit_log",
      "sentinel_findings",
      "anomaly_alerts",
      "recent_receipts",
      "verascore_deltas",
    ]);
  });
});
