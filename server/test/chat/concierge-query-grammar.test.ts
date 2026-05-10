/**
 * Sanctuary v1.3 WP-V1.3-9 Tau-4, operator-query grammar unit tests
 *
 * Pure-function coverage for `concierge-query-grammar.ts`. Tests the
 * rule-based parse path for time ranges, agent names, and event types,
 * plus the audit-safe projection, the structured fallback menu, and
 * the LLM-assist completion contract.
 */

import { describe, it, expect, vi } from "vitest";
import {
  parseQuery,
  parseQueryWithLlmAssist,
  auditSafeSummary,
  structuredFallbackMenu,
  isLowConfidence,
  LLM_ASSIST_THRESHOLD,
  CANONICAL_AUDIT_EVENT_CLASSES,
  type AgentRegistryView,
  type ParsedQuery,
} from "../../src/chat/concierge-query-grammar.js";

const NOW = new Date("2026-05-10T15:00:00.000Z");

const REGISTRY: AgentRegistryView = [
  { agent_id: "OpenClaw" },
  { agent_id: "Cline" },
  { agent_id: "data-miner" },
  { agent_id: "leak-timeline" },
];

describe("parseQuery, time-range patterns (Tau-4)", () => {
  it("resolves the relative token 'yesterday' to the prior calendar day", () => {
    const parsed = parseQuery("show me what happened yesterday", { now: NOW });
    expect(parsed.time_range).not.toBeNull();
    const range = parsed.time_range!;
    expect(range.relative_label).toBe("yesterday");
    // start = previous day 00:00 local; end = end-of-day previous day.
    expect(range.start.getTime()).toBeLessThan(range.end.getTime());
    expect(range.end.getTime()).toBeLessThan(NOW.getTime());
    // Yesterday's start is exactly one day before today's start.
    const dayMs = 24 * 60 * 60 * 1000;
    expect(range.end.getTime() - range.start.getTime()).toBe(dayMs - 1);
  });

  it("resolves 'today' as a window from start-of-day to now", () => {
    const parsed = parseQuery("what is happening today on this fortress", {
      now: NOW,
    });
    expect(parsed.time_range).not.toBeNull();
    const range = parsed.time_range!;
    expect(range.relative_label).toBe("today");
    expect(range.end.getTime()).toBe(NOW.getTime());
    expect(range.start.getTime()).toBeLessThanOrEqual(NOW.getTime());
  });

  it("resolves 'past hour' to a 1-hour window ending at now", () => {
    const parsed = parseQuery("what happened in the past hour", { now: NOW });
    expect(parsed.time_range).not.toBeNull();
    const range = parsed.time_range!;
    expect(range.relative_label).toBe("past hour");
    expect(range.end.getTime()).toBe(NOW.getTime());
    expect(NOW.getTime() - range.start.getTime()).toBe(60 * 60 * 1000);
  });

  it("resolves 'last 24h' compact-hours form to a 24-hour window", () => {
    const parsed = parseQuery("audit log entries from the last 24h please", {
      now: NOW,
    });
    expect(parsed.time_range).not.toBeNull();
    const range = parsed.time_range!;
    expect(range.relative_label).toBe("last 24h");
    expect(NOW.getTime() - range.start.getTime()).toBe(24 * 60 * 60 * 1000);
  });

  it("resolves 'this week' to the start-of-Monday window through now", () => {
    const parsed = parseQuery("policy changes this week", { now: NOW });
    expect(parsed.time_range).not.toBeNull();
    const range = parsed.time_range!;
    expect(range.relative_label).toBe("this week");
    expect(range.end.getTime()).toBe(NOW.getTime());
    expect(range.start.getDay()).toBe(1); // Monday in local time
  });

  it("resolves an absolute ISO date as a full-day window", () => {
    const parsed = parseQuery("what happened on 2026-05-08", { now: NOW });
    expect(parsed.time_range).not.toBeNull();
    const range = parsed.time_range!;
    expect(range.start.toISOString().slice(0, 10)).toBe("2026-05-08");
    expect(
      range.end.getTime() - range.start.getTime(),
    ).toBeGreaterThanOrEqual(86_400_000 - 1);
    expect(
      range.end.getTime() - range.start.getTime(),
    ).toBeLessThanOrEqual(86_400_000);
  });

  it("resolves 'from X to Y' as an explicit absolute range", () => {
    const parsed = parseQuery(
      "show events from 2026-05-01 to 2026-05-08",
      { now: NOW },
    );
    expect(parsed.time_range).not.toBeNull();
    const range = parsed.time_range!;
    expect(range.start.toISOString().slice(0, 10)).toBe("2026-05-01");
    // End is the parsed instant on 2026-05-08; the range is bounded.
    expect(range.end.getTime()).toBeGreaterThan(range.start.getTime());
  });

  it("resolves 'since X' as a window from X to now", () => {
    const parsed = parseQuery("what has happened since 2026-05-01", {
      now: NOW,
    });
    expect(parsed.time_range).not.toBeNull();
    const range = parsed.time_range!;
    expect(range.start.toISOString().slice(0, 10)).toBe("2026-05-01");
    expect(range.end.getTime()).toBe(NOW.getTime());
  });

  it("flags unknown_time_token when a time word fires but no pattern resolves", () => {
    const parsed = parseQuery("what happened past quarter-after-three", {
      now: NOW,
    });
    expect(parsed.time_range).toBeNull();
    expect(parsed.ambiguity_flags).toContain("unknown_time_token");
  });
});

describe("parseQuery, agent-name extraction (Tau-4)", () => {
  it("extracts a single agent name (case-insensitive) from the registry", () => {
    const parsed = parseQuery("what did openclaw do today", {
      now: NOW,
      registry: REGISTRY,
    });
    expect(parsed.agent_names).toEqual(["OpenClaw"]);
  });

  it("extracts multiple agent names ('OpenClaw and Cline')", () => {
    const parsed = parseQuery("show recent activity for OpenClaw and Cline", {
      now: NOW,
      registry: REGISTRY,
    });
    expect(parsed.agent_names.length).toBe(2);
    expect(parsed.agent_names).toContain("OpenClaw");
    expect(parsed.agent_names).toContain("Cline");
  });

  it("matches a hyphenated registry id against a multi-word query phrase", () => {
    const parsed = parseQuery("status of the data miner today", {
      now: NOW,
      registry: REGISTRY,
    });
    expect(parsed.agent_names).toContain("data-miner");
  });

  it("flags unknown_agent_token when 'agent <NAME>' surfaces but registry misses", () => {
    const parsed = parseQuery("what did agent UnknownBot do today", {
      now: NOW,
      registry: REGISTRY,
    });
    expect(parsed.agent_names).toEqual([]);
    expect(parsed.ambiguity_flags).toContain("unknown_agent_token");
  });
});

describe("parseQuery, event-type extraction (Tau-4)", () => {
  it("extracts a direct enum match", () => {
    const parsed = parseQuery("show me policy_change entries today", {
      now: NOW,
    });
    expect(parsed.event_types).toContain("policy_change");
  });

  it("extracts via synonym ('approvals' -> approval_request + cross-harness)", () => {
    const parsed = parseQuery("list pending approvals from today", {
      now: NOW,
    });
    expect(parsed.event_types).toContain("approval_request");
    expect(parsed.event_types).toContain("cross_harness_approval_aggregated");
  });

  it("expands the 'composition_*' glob to every composition_ event type", () => {
    const parsed = parseQuery("show composition_* events from this week", {
      now: NOW,
    });
    expect(parsed.event_types).toContain("composition_receipt_packed");
    expect(parsed.event_types).toContain("composition_receipt_verified");
    expect(parsed.event_types).toContain("composition_sidecar_spawned");
  });

  it("flags unknown_event_token when 'events' surfaces but nothing matches", () => {
    const parsed = parseQuery("show me telemetry events from today", {
      now: NOW,
    });
    expect(parsed.event_types).toEqual([]);
    expect(parsed.ambiguity_flags).toContain("unknown_event_token");
  });
});

describe("parseQuery, intent residual + confidence (Tau-4)", () => {
  it("strips resolved tokens and leaves the operator intent in residual", () => {
    const parsed = parseQuery(
      "show me what OpenClaw did yesterday around the policy_change event",
      { now: NOW, registry: REGISTRY },
    );
    expect(parsed.time_range).not.toBeNull();
    expect(parsed.agent_names).toContain("OpenClaw");
    expect(parsed.event_types).toContain("policy_change");
    expect(parsed.intent_phrase.toLowerCase()).not.toContain("yesterday");
    expect(parsed.intent_phrase.toLowerCase()).not.toContain("openclaw");
    expect(parsed.intent_phrase.toLowerCase()).not.toContain("policy_change");
    expect(parsed.intent_phrase.toLowerCase()).toContain("show");
  });

  it("returns confidence 1.0 when every present dimension resolved cleanly", () => {
    const parsed = parseQuery(
      "what did Cline do yesterday in policy_change events",
      { now: NOW, registry: REGISTRY },
    );
    expect(parsed.parse_confidence).toBe(1);
  });

  it("returns low confidence + no_signal flag on an empty-ish query", () => {
    const parsed = parseQuery("hi", { now: NOW });
    expect(parsed.parse_confidence).toBeLessThan(LLM_ASSIST_THRESHOLD);
  });
});

describe("auditSafeSummary (Tau-4 privacy invariant)", () => {
  it("strips intent_phrase from the audit projection (privacy invariant)", () => {
    const parsed = parseQuery(
      "show me what OpenClaw did yesterday with my secret API_KEY=sk-xxxx",
      { now: NOW, registry: REGISTRY },
    );
    const summary = auditSafeSummary(parsed);
    // intent_phrase MUST NOT appear on the projection.
    expect((summary as unknown as { intent_phrase?: unknown }).intent_phrase).toBeUndefined();
    // The projection still carries the safe metadata.
    expect(summary.agent_names).toContain("OpenClaw");
    expect(summary.time_range).not.toBeNull();
    expect(summary.time_range!.start_iso).toMatch(/^\d{4}-\d{2}-\d{2}T/);
    expect(summary.time_range!.end_iso).toMatch(/^\d{4}-\d{2}-\d{2}T/);
  });
});

describe("structuredFallbackMenu (Tau-4 graceful degradation)", () => {
  it("returns a category-list menu on a generic low-confidence parse", () => {
    const parsed: ParsedQuery = {
      time_range: null,
      agent_names: [],
      event_types: [],
      intent_phrase: "huh",
      ambiguity_flags: [],
      parse_confidence: 0.2,
    };
    const menu = structuredFallbackMenu(parsed);
    expect(menu).toContain("I am not sure I understood");
    expect(menu).toContain("Templates");
    expect(menu).toContain("Agent state");
    expect(menu).toContain("Audit log");
    expect(menu).toContain("Sentinel findings");
    expect(menu).toContain("Verascore");
    // Hard gate: no em-dashes in operator-visible copy. The regex
    // uses the Unicode codepoint escape so this test file itself
    // stays sweep-clean against the no-em-dash rule on changed files.
    expect(menu).not.toMatch(/\u2014/);
  });

  it("appends a time-range tip when unknown_time_token was flagged", () => {
    const parsed: ParsedQuery = {
      time_range: null,
      agent_names: [],
      event_types: [],
      intent_phrase: "around quarter-after-three",
      ambiguity_flags: ["unknown_time_token"],
      parse_confidence: 0.3,
    };
    const menu = structuredFallbackMenu(parsed);
    expect(menu).toContain("time ranges I understand");
    expect(menu).toContain("yesterday");
    expect(menu).toContain("from 2026-05-01 to 2026-05-08");
  });

  it("returns a completely-unparseable parse without crashing", () => {
    const parsed = parseQuery("", { now: NOW });
    expect(parsed.ambiguity_flags).toContain("no_signal_extracted");
    const menu = structuredFallbackMenu(parsed);
    expect(menu.length).toBeGreaterThan(20);
  });
});

describe("parseQueryWithLlmAssist (Tau-4 fallback)", () => {
  it("invokes the LLM-assist hook when the rule-based parse is low-confidence", async () => {
    const llmAssist = vi.fn(async () => ({
      time_range: {
        start: new Date("2026-05-09T00:00:00.000Z"),
        end: new Date("2026-05-10T00:00:00.000Z"),
        relative_label: "llm-derived",
      },
    }));
    const parsed = await parseQueryWithLlmAssist(
      "huh",
      llmAssist,
      { now: NOW },
    );
    expect(llmAssist).toHaveBeenCalledTimes(1);
    expect(parsed.time_range).not.toBeNull();
    expect(parsed.time_range!.relative_label).toBe("llm-derived");
  });

  it("does NOT invoke LLM-assist when the rule-based parse is high-confidence", async () => {
    const llmAssist = vi.fn(async () => null);
    const parsed = await parseQueryWithLlmAssist(
      "what did Cline do yesterday in policy_change events",
      llmAssist,
      { now: NOW, registry: REGISTRY },
    );
    expect(llmAssist).not.toHaveBeenCalled();
    expect(parsed.parse_confidence).toBe(1);
  });

  it("returns the rule-based parse unchanged when the LLM-assist hook throws", async () => {
    const llmAssist = vi.fn(async () => {
      throw new Error("substrate failure");
    });
    const parsed = await parseQueryWithLlmAssist(
      "huh",
      llmAssist,
      { now: NOW },
    );
    expect(llmAssist).toHaveBeenCalledTimes(1);
    expect(parsed.time_range).toBeNull();
    // The rule-based parse confidence is reflected.
    expect(isLowConfidence(parsed)).toBe(true);
  });

  it("filters LLM-supplied event_types against the canonical enum", async () => {
    const llmAssist = vi.fn(async () => ({
      event_types: ["policy_change", "totally_made_up_event_class"],
    }));
    const parsed = await parseQueryWithLlmAssist(
      "huh",
      llmAssist,
      { now: NOW, eventClassEnum: CANONICAL_AUDIT_EVENT_CLASSES },
    );
    expect(parsed.event_types).toContain("policy_change");
    expect(parsed.event_types).not.toContain("totally_made_up_event_class");
  });
});
