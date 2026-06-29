/**
 * Sanctuary MCP Server, NIST AI RMF Crosswalk Types
 *
 * Copyright 2026 Erik Newton
 * SPDX-License-Identifier: Apache-2.0
 *
 * Shared types for the NIST AI Risk Management Framework (AI RMF 1.0,
 * NIST AI 100-1) crosswalk. This crosswalk maps NIST AI RMF
 * subcategories to the SAME Sanctuary control catalog used by the EU
 * AI Act compliance pack (the evidence_emitter MCP tool names), so a
 * reviewer can see where EU AI Act and NIST AI RMF coverage overlap.
 *
 * NOT A CERTIFICATION. This is a tooling-coverage map: it states which
 * NIST AI RMF subcategories a shipped Sanctuary mechanism bears on. It
 * is not a NIST conformity assessment and does not assert that an
 * organisation has implemented the AI RMF.
 */

/**
 * The four functions of the NIST AI RMF 1.0 (AI 100-1).
 */
export type NistFunction = "GOVERN" | "MAP" | "MEASURE" | "MANAGE";

/**
 * Coverage classification for a NIST AI RMF subcategory against the
 * Sanctuary control catalog. Deliberately distinct from the EU pack's
 * { full | partial | manual_only } vocabulary because the honest
 * shapes differ: the AI RMF has many organisational/process
 * subcategories a software framework structurally cannot satisfy.
 *
 *   - "covered", a real, shipped Sanctuary mechanism enforces or
 *                        directly produces evidence for this subcategory
 *                        with zero organisational input. Machine-
 *                        verifiable by running the listed tool(s).
 *   - "partial", Sanctuary emits structured evidence that bears
 *                        on this subcategory, but the organisation must
 *                        supply context (a risk narrative, a mapping to
 *                        their process) to complete it.
 *   - "not-applicable", this subcategory is purely organisational /
 *                        governance / workforce / process and a runtime
 *                        software framework has no mechanism for it.
 *                        Honestly out of scope, NOT a deficiency in
 *                        Sanctuary.
 *   - "gap", this subcategory IS technical and a tool could
 *                        plausibly bear on it, but Sanctuary ships no
 *                        mechanism that does today. An honest hole.
 */
export type NistCoverageFlag =
  | "covered"
  | "partial"
  | "not-applicable"
  | "gap";

/**
 * One NIST AI RMF subcategory mapped to the Sanctuary control catalog.
 */
export interface NistSubcategory {
  /**
   * Canonical NIST subcategory identifier, e.g. "GOVERN 1.1",
   * "MAP 4.1", "MEASURE 2.7", "MANAGE 4.1". Used as the stable row id.
   */
  id: string;
  /** Parent function. */
  function: NistFunction;
  /** Parent category, e.g. "GOVERN 1", "MEASURE 2". */
  category: string;
  /**
   * Short paraphrase of the subcategory's intent. NIST AI RMF
   * subcategory text is summarised here for navigation; this is NOT a
   * verbatim quote of NIST AI 100-1 (unlike the EU pack, whose source
   * text is reproduced verbatim under a different licence posture).
   */
  summary: string;
  coverage: NistCoverageFlag;
  /**
   * Sanctuary MCP tool name(s) (unprefixed) whose output is the
   * evidence for this row. MUST be drawn from the shared control
   * catalog (the union of evidence_emitter names in the EU AI Act
   * coverage matrix). Empty for "not-applicable" and most "gap" rows.
   */
  evidence_emitter: string[];
  /**
   * One-line evidence pointer: the shipped mechanism that backs the
   * mapping (audit log, approval gate, custody, transparency receipts,
   * exit/portability, etc.). For not-applicable/gap rows this states
   * why there is no Sanctuary mechanism.
   */
  evidence_note: string;
  /**
   * Per-row rationale for the classification, load-bearing for the
   * compliance reviewer. Flags any mapping the author was unsure about.
   */
  review_notes: string;
}

/**
 * The complete NIST AI RMF crosswalk.
 */
export interface NistCrosswalk {
  crosswalk_version: "v1";
  /** Human-readable framework anchor rendered into the document header. */
  framework_version: string;
  framework: {
    name: "NIST AI Risk Management Framework";
    official_reference: "NIST AI 100-1 (AI RMF 1.0)";
    published: "2023-01-26";
    aligned_to: "AI RMF 1.0 core (GOVERN, MAP, MEASURE, MANAGE)";
    last_full_review: string;
  };
  notes: string[];
  subcategories: NistSubcategory[];
}

/**
 * Coverage statistics for the crosswalk.
 */
export interface NistCoverageStats {
  total: number;
  covered: number;
  partial: number;
  not_applicable: number;
  gap: number;
  covered_pct: number;
  partial_pct: number;
  not_applicable_pct: number;
  gap_pct: number;
}
