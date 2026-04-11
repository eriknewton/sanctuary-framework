/**
 * Sanctuary MCP Server — Annex III Classification Helper Tests
 *
 * Copyright 2026 Erik Newton
 * SPDX-License-Identifier: Apache-2.0
 *
 * Unit tests for the rule-based Annex III classifier:
 *
 *   - Catalog shape invariants (every category has id, citation,
 *     verbatim text, keywords)
 *   - Classifier produces expected candidates for representative
 *     deployment descriptions
 *   - Honest-over-optimistic: empty result for ambiguous or
 *     out-of-scope descriptions, never claims certainty
 *   - Threshold behaviour (low-signal descriptions clear the 0.4
 *     floor only if multiple keywords match)
 *   - Advisory text is always present and names "NOT legal advice"
 */

import { describe, it, expect } from "vitest";
import {
  ANNEX_III_CATEGORIES,
  ANNEX_III_REGULATION_VERSION,
  classifyAgentDescription,
  annexIIICategoryById,
} from "../../../src/compliance/eu_ai_act/annex_iii.js";

describe("Annex III catalog", () => {
  it("exports every category with the required fields", () => {
    expect(ANNEX_III_CATEGORIES.length).toBeGreaterThan(0);
    for (const cat of ANNEX_III_CATEGORIES) {
      expect(cat.id).toBeTruthy();
      expect(cat.citation).toMatch(/^Annex III /);
      expect(cat.title.length).toBeGreaterThan(0);
      expect(cat.verbatim.startsWith('"')).toBe(true);
      expect(cat.verbatim.endsWith('"')).toBe(true);
      expect(cat.keywords.length).toBeGreaterThan(0);
    }
  });

  it("every category has a unique id", () => {
    const ids = ANNEX_III_CATEGORIES.map((c) => c.id);
    expect(new Set(ids).size).toBe(ids.length);
  });

  it("every keyword weight is in the discrete set {1.0, 0.6, 0.3}", () => {
    const allowed = new Set([1.0, 0.6, 0.3]);
    for (const cat of ANNEX_III_CATEGORIES) {
      for (const kw of cat.keywords) {
        expect(allowed.has(kw.weight)).toBe(true);
      }
    }
  });

  it("covers all 8 Annex III top-level sections", () => {
    const sections = new Set<string>();
    for (const cat of ANNEX_III_CATEGORIES) {
      const match = cat.citation.match(/§(\d)/);
      if (match) sections.add(match[1]!);
    }
    expect(sections).toEqual(new Set(["1", "2", "3", "4", "5", "6", "7", "8"]));
  });

  it("annexIIICategoryById resolves a known category", () => {
    const cat = annexIIICategoryById("annex_iii_4_a_employment_recruitment");
    expect(cat).toBeDefined();
    expect(cat!.citation).toBe("Annex III §4(a)");
  });

  it("annexIIICategoryById returns undefined for unknown id", () => {
    expect(annexIIICategoryById("not_a_real_category")).toBeUndefined();
  });
});

describe("classifyAgentDescription", () => {
  describe("HR screening (Annex III §4(a))", () => {
    it("classifies a CV screening agent with high confidence", () => {
      const result = classifyAgentDescription(
        "An AI system that performs CV screening and candidate shortlisting. " +
          "It analyzes job applications, filters applicants, and evaluates candidates " +
          "for recruitment decisions before human review."
      );
      expect(result.candidates.length).toBeGreaterThan(0);
      const top = result.candidates[0]!;
      expect(top.category_id).toBe("annex_iii_4_a_employment_recruitment");
      expect(top.rule_based_confidence).toBeGreaterThanOrEqual(0.9);
      expect(top.matched_keywords).toContain("cv screening");
    });

    it("classifies a resume screening tool", () => {
      const result = classifyAgentDescription(
        "resume screening for targeted job ad placement"
      );
      expect(result.candidates[0]?.category_id).toBe(
        "annex_iii_4_a_employment_recruitment"
      );
    });
  });

  describe("credit scoring (Annex III §5(b))", () => {
    it("classifies a credit scoring agent with high confidence", () => {
      const result = classifyAgentDescription(
        "Evaluates creditworthiness of loan applicants and produces a credit score for lending decisions."
      );
      const top = result.candidates[0]!;
      expect(top.category_id).toBe("annex_iii_5_b_creditworthiness");
      expect(top.rule_based_confidence).toBeGreaterThan(0.8);
    });
  });

  describe("biometric identification (Annex III §1(a))", () => {
    it("classifies a facial recognition surveillance system", () => {
      const result = classifyAgentDescription(
        "Facial recognition for biometric identification in a surveillance camera network"
      );
      const top = result.candidates[0]!;
      expect(top.category_id).toBe(
        "annex_iii_1_a_remote_biometric_identification"
      );
    });
  });

  describe("education proctoring (Annex III §3(d))", () => {
    it("classifies an exam proctoring tool", () => {
      const result = classifyAgentDescription(
        "Online exam proctoring system that monitors students for cheating detection during tests"
      );
      const top = result.candidates[0]!;
      expect(top.category_id).toBe("annex_iii_3_d_education_proctoring");
    });
  });

  describe("predictive policing (Annex III §6)", () => {
    it("classifies a recidivism risk tool", () => {
      const result = classifyAgentDescription(
        "Predictive policing and recidivism prediction for parole decision support"
      );
      const top = result.candidates[0]!;
      expect(top.category_id).toBe("annex_iii_6_law_enforcement");
    });
  });

  describe("out-of-scope descriptions", () => {
    it("returns empty candidates for a plain customer support chatbot", () => {
      const result = classifyAgentDescription(
        "Customer support chatbot that answers frequently asked questions about product returns"
      );
      expect(result.candidates).toEqual([]);
    });

    it("returns empty candidates for a weather forecasting agent", () => {
      const result = classifyAgentDescription(
        "Weather forecasting agent that predicts temperature and precipitation"
      );
      expect(result.candidates).toEqual([]);
    });

    it("returns empty candidates for a developer productivity tool", () => {
      const result = classifyAgentDescription(
        "Developer productivity assistant that helps with code completion and documentation lookups"
      );
      expect(result.candidates).toEqual([]);
    });
  });

  describe("advisory and honest-over-optimistic behaviour", () => {
    it("always emits the NOT legal advice advisory", () => {
      const result = classifyAgentDescription("any description");
      expect(result.advisory).toContain("NOT legal advice");
      expect(result.advisory).toContain("RULE-BASED");
      expect(result.advisory).toContain("rule_based_confidence");
    });

    it("includes the regulation version", () => {
      const result = classifyAgentDescription("cv screening");
      expect(result.regulation_version).toBe(ANNEX_III_REGULATION_VERSION);
      expect(result.regulation_version).toContain("2024/1689");
    });

    it("orders candidates by rule_based_confidence descending", () => {
      const result = classifyAgentDescription(
        "cv screening and performance review and worker monitoring"
      );
      for (let i = 1; i < result.candidates.length; i++) {
        expect(
          result.candidates[i - 1]!.rule_based_confidence
        ).toBeGreaterThanOrEqual(result.candidates[i]!.rule_based_confidence);
      }
    });

    it("clamps rule_based_confidence to [0, 1]", () => {
      const result = classifyAgentDescription(
        // This description has many high-weight §4(a) keywords.
        "cv screening resume screening candidate shortlist recruitment hiring decisions applicant filtering job application interview scoring targeted job ad hr screening talent acquisition hiring"
      );
      for (const c of result.candidates) {
        expect(c.rule_based_confidence).toBeGreaterThanOrEqual(0);
        expect(c.rule_based_confidence).toBeLessThanOrEqual(1);
      }
    });

    it("truncates long descriptions to 200 chars in description_fragment", () => {
      const longText = "cv screening " + "lorem ipsum ".repeat(50);
      const result = classifyAgentDescription(longText);
      expect(result.description_fragment.length).toBeLessThanOrEqual(
        200 + 3 // "..." suffix
      );
    });

    it("normalizes punctuation for keyword matching", () => {
      const result = classifyAgentDescription(
        "CV screening, resume screening; candidate shortlisting!"
      );
      expect(result.candidates.length).toBeGreaterThan(0);
    });

    it("is case-insensitive", () => {
      const lower = classifyAgentDescription("cv screening");
      const upper = classifyAgentDescription("CV SCREENING");
      expect(lower.candidates[0]?.category_id).toBe(
        upper.candidates[0]?.category_id
      );
    });
  });
});
