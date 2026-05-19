/**
 * QLA gap-fill: zero-PII regression test.
 *
 * Loads the canonical PII corpus from fixtures and verifies that after
 * running the full Tier A (header strip) + Tier B (PII regex rewrite)
 * pipeline, no corpus entry with `must_not_appear: true` survives in
 * the substrate-side payload.
 *
 * This test runs as part of `npm test` (vitest picks it up) AND via
 * the explicit `npm run test:zero-pii-regression` script.
 */

import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";

import { stripHeaders } from "../../src/query-anonymity/header-strip.js";
import { rewritePiiRegexOnly, type PiiCategory } from "../../src/query-anonymity/pii-rewrite.js";

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

describe("QLA zero-PII regression -- canonical corpus", () => {
  it("corpus file loads and contains entries", () => {
    expect(corpus.length).toBeGreaterThan(0);
    for (const entry of corpus) {
      expect(entry.category).toBeDefined();
      expect(entry.sample).toBeDefined();
      expect(typeof entry.must_not_appear).toBe("boolean");
    }
  });

  describe("Tier B (PII rewrite) -- no corpus PII survives in rewritten text", () => {
    for (const entry of corpus.filter((e) => e.must_not_appear)) {
      it(`[${entry.category}] ${entry.description}: "${entry.sample}"`, () => {
        // Build a synthetic agent prompt containing the PII sample.
        const syntheticPrompt = `Please help me contact ${entry.sample} about the project meeting next week.`;
        const result = rewritePiiRegexOnly(syntheticPrompt);

        // The exact PII value must not appear in the rewritten output.
        expect(result.rewritten).not.toContain(entry.sample);

        // At least one redaction should have fired for this category.
        expect(result.redaction_counts[entry.category]).toBeGreaterThanOrEqual(1);
      });
    }
  });

  describe("Tier A (header strip) -- fingerprintable headers stripped from outbound call", () => {
    it("strips all fingerprintable headers from a realistic outbound header set", () => {
      const outboundHeaders: Record<string, string> = {
        "Content-Type": "application/json",
        Authorization: "Bearer sk-ant-test",
        "x-api-key": "sk-ant-test",
        "anthropic-version": "2023-06-01",
        // Fingerprintable headers that MUST be stripped:
        "User-Agent": "node/22.5.0 darwin arm64",
        "Accept-Language": "en-US,en;q=0.9",
        Referer: "https://operator-app.local/dashboard",
        "X-Forwarded-For": "192.168.1.42",
        "Sec-CH-UA": '"Chromium";v="120"',
        "Sec-CH-UA-Platform": '"macOS"',
        DNT: "1",
      };

      const result = stripHeaders(outboundHeaders);

      // Required auth headers survive.
      expect(result.stripped["Authorization"]).toBe("Bearer sk-ant-test");
      expect(result.stripped["x-api-key"]).toBe("sk-ant-test");
      expect(result.stripped["anthropic-version"]).toBe("2023-06-01");
      expect(result.stripped["Content-Type"]).toBe("application/json");

      // Fingerprintable headers are gone.
      expect(result.stripped["User-Agent"]).toBeUndefined();
      expect(result.stripped["Accept-Language"]).toBeUndefined();
      expect(result.stripped["Referer"]).toBeUndefined();
      expect(result.stripped["X-Forwarded-For"]).toBeUndefined();
      expect(result.stripped["Sec-CH-UA"]).toBeUndefined();
      expect(result.stripped["Sec-CH-UA-Platform"]).toBeUndefined();
      expect(result.stripped["DNT"]).toBeUndefined();

      // Removed count matches the fingerprintable set.
      expect(result.removed.length).toBe(7);
    });
  });

  describe("Tier A + Tier B combined -- end-to-end zero-PII gate", () => {
    it("no corpus entry survives the full pipeline (headers + body rewrite)", () => {
      const mustNotAppearEntries = corpus.filter((e) => e.must_not_appear);

      // Simulate a full outbound substrate call:
      // 1. Build a query body containing ALL PII samples.
      const allPiiText = mustNotAppearEntries
        .map((e) => `Contact ${e.sample} regarding the matter.`)
        .join(" ");

      // 2. Run Tier B rewrite on the body.
      const rewriteResult = rewritePiiRegexOnly(allPiiText);

      // 3. Run Tier A strip on headers.
      const headerResult = stripHeaders({
        "User-Agent": "node/22.5.0",
        "Accept-Language": "en-US",
        Authorization: "Bearer sk-test",
        "Content-Type": "application/json",
      });

      // Assert: no PII sample appears in the rewritten body.
      for (const entry of mustNotAppearEntries) {
        expect(rewriteResult.rewritten).not.toContain(entry.sample);
      }

      // Assert: fingerprintable headers are gone.
      expect(headerResult.stripped["User-Agent"]).toBeUndefined();
      expect(headerResult.stripped["Accept-Language"]).toBeUndefined();

      // Assert: auth headers survive.
      expect(headerResult.stripped["Authorization"]).toBe("Bearer sk-test");
    });
  });
});
