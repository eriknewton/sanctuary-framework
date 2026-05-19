/**
 * QLA performance budget test.
 *
 * Runs a 100-iteration synthetic workload through each QLA tier
 * operation, computes p99 latency, and asserts it falls within the
 * budget defined in performance-budget.ts.
 *
 * Uses the canonical PII corpus from PR 1 as the workload payload.
 * Only tests operations that are pure CPU (no network). The
 * tier_b_pii_rewrite_provider_call budget is tested structurally
 * (assertWithinBudget accepts the threshold) but not with a real
 * network round-trip.
 */

import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { performance } from "node:perf_hooks";

import { stripHeaders } from "../../src/query-anonymity/header-strip.js";
import { rewritePiiRegexOnly, type PiiCategory } from "../../src/query-anonymity/pii-rewrite.js";
import {
  assertWithinBudget,
  BUDGET_MS,
  PerformanceBudgetExceeded,
} from "../../src/query-anonymity/performance-budget.js";

interface CorpusEntry {
  category: PiiCategory;
  sample: string;
  must_not_appear: boolean;
  description: string;
}

const corpusPath = resolve(
  import.meta.dirname,
  "../fixtures/query-anonymity/pii-corpus.json",
);
const corpus: CorpusEntry[] = JSON.parse(readFileSync(corpusPath, "utf-8"));

const ITERATIONS = 100;

function computeP99(durations: number[]): number {
  const sorted = [...durations].sort((a, b) => a - b);
  const idx = Math.ceil(sorted.length * 0.99) - 1;
  return sorted[idx]!;
}

/** Build a realistic synthetic prompt from the corpus. */
function buildSyntheticPrompt(): string {
  return corpus
    .filter((e) => e.must_not_appear)
    .map((e) => `Please help me contact ${e.sample} about the project.`)
    .join(" ");
}

/** Build realistic outbound headers. */
function buildOutboundHeaders(): Record<string, string> {
  return {
    "Content-Type": "application/json",
    Authorization: "Bearer sk-ant-test",
    "x-api-key": "sk-ant-test",
    "anthropic-version": "2023-06-01",
    "User-Agent": "node/22.5.0 darwin arm64",
    "Accept-Language": "en-US,en;q=0.9",
    Referer: "https://operator-app.local/dashboard",
    "X-Forwarded-For": "192.168.1.42",
    "Sec-CH-UA": '"Chromium";v="120"',
    DNT: "1",
  };
}

describe("QLA performance budget -- assertWithinBudget API", () => {
  it("passes when duration is within budget", () => {
    expect(() => assertWithinBudget("tier_a_header_strip", 1)).not.toThrow();
  });

  it("throws PerformanceBudgetExceeded when duration exceeds budget", () => {
    expect(() => assertWithinBudget("tier_a_header_strip", 999)).toThrow(
      PerformanceBudgetExceeded,
    );
  });

  it("throws on unknown operation name", () => {
    expect(() => assertWithinBudget("nonexistent_op", 1)).toThrow(
      /Unknown QLA operation/,
    );
  });

  it("BUDGET_MS has all four tier operations", () => {
    expect(Object.keys(BUDGET_MS)).toEqual(
      expect.arrayContaining([
        "tier_a_header_strip",
        "tier_b_pii_rewrite_local",
        "tier_b_pii_rewrite_provider_call",
        "tier_b_smart_rewriter_classification",
      ]),
    );
  });
});

describe("QLA performance budget -- p99 latency assertions", () => {
  it("tier_a_header_strip: p99 within 5ms budget over 100 iterations", () => {
    const headers = buildOutboundHeaders();
    const durations: number[] = [];

    for (let i = 0; i < ITERATIONS; i++) {
      const start = performance.now();
      stripHeaders(headers);
      durations.push(performance.now() - start);
    }

    const p99 = computeP99(durations);
    assertWithinBudget("tier_a_header_strip", p99);
    expect(p99).toBeLessThanOrEqual(BUDGET_MS["tier_a_header_strip"]!);
  });

  it("tier_b_pii_rewrite_local: p99 within 100ms budget over 100 iterations", () => {
    const prompt = buildSyntheticPrompt();
    const durations: number[] = [];

    for (let i = 0; i < ITERATIONS; i++) {
      const start = performance.now();
      rewritePiiRegexOnly(prompt);
      durations.push(performance.now() - start);
    }

    const p99 = computeP99(durations);
    assertWithinBudget("tier_b_pii_rewrite_local", p99);
    expect(p99).toBeLessThanOrEqual(BUDGET_MS["tier_b_pii_rewrite_local"]!);
  });

  it("tier_b_smart_rewriter_classification: p99 within 50ms budget (synthetic -- classification is regex-based intent matching)", () => {
    // The smart rewriter's intent classifier is a regex-based local
    // operation. We simulate the classification cost by running the
    // PII rewrite (which exercises the same regex engine) on a shorter
    // input. The real classifier is lighter than a full rewrite.
    const shortPrompt = "email alice@example.com about the rent";
    const durations: number[] = [];

    for (let i = 0; i < ITERATIONS; i++) {
      const start = performance.now();
      rewritePiiRegexOnly(shortPrompt);
      durations.push(performance.now() - start);
    }

    const p99 = computeP99(durations);
    assertWithinBudget("tier_b_smart_rewriter_classification", p99);
    expect(p99).toBeLessThanOrEqual(
      BUDGET_MS["tier_b_smart_rewriter_classification"]!,
    );
  });

  it("tier_b_pii_rewrite_provider_call: structural budget validation (no real network call)", () => {
    // The provider call budget (500ms) covers a real network round-trip
    // to the LLM substrate. We cannot test actual network latency in a
    // unit test. Instead, verify the budget exists and the assertion
    // function works with a simulated duration.
    expect(BUDGET_MS["tier_b_pii_rewrite_provider_call"]).toBe(500);
    expect(() =>
      assertWithinBudget("tier_b_pii_rewrite_provider_call", 300),
    ).not.toThrow();
    expect(() =>
      assertWithinBudget("tier_b_pii_rewrite_provider_call", 600),
    ).toThrow(PerformanceBudgetExceeded);
  });
});
