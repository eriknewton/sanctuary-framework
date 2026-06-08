/**
 * Sanctuary MCP Server — EU AI Act Coverage Matrix Tests
 *
 * Copyright 2026 Erik Newton
 * SPDX-License-Identifier: Apache-2.0
 *
 * Schema invariants, coverage distribution, and emitter referential
 * integrity checks for the v1 coverage matrix.
 */

import { describe, it, expect } from "vitest";
import {
  COVERAGE_MATRIX_V1,
  REGULATION_VERSION,
  rowsByCoverage,
  rowById,
  rowsByInstrument,
  allEvidenceEmitters,
  coverageStats,
} from "../../../src/compliance/eu_ai_act/coverage_matrix.js";

describe("EU AI Act coverage matrix v1", () => {
  describe("top-level metadata", () => {
    it("has matrix_version v1", () => {
      expect(COVERAGE_MATRIX_V1.matrix_version).toBe("v1");
    });

    it("carries the display-level REGULATION_VERSION anchor", () => {
      expect(COVERAGE_MATRIX_V1.regulation_version).toBe(REGULATION_VERSION);
      expect(REGULATION_VERSION).toContain("EU AI Act");
      expect(REGULATION_VERSION).toContain("2024/1689");
    });

    it("has structured regulation metadata with enforcement date", () => {
      expect(COVERAGE_MATRIX_V1.regulation.name).toBe("EU AI Act");
      expect(COVERAGE_MATRIX_V1.regulation.official_reference).toBe(
        "Regulation (EU) 2024/1689"
      );
      expect(COVERAGE_MATRIX_V1.regulation.full_enforcement_date).toBe(
        "2026-08-02"
      );
    });

    it("has a next_review_due date for forward-committed review cadence", () => {
      expect(COVERAGE_MATRIX_V1.regulation.next_review_due).toBeTruthy();
      expect(() =>
        new Date(COVERAGE_MATRIX_V1.regulation.next_review_due).toISOString()
      ).not.toThrow();
    });

    it("carries the NOT LEGAL ADVICE disclaimer in notes", () => {
      const notesText = COVERAGE_MATRIX_V1.notes.join(" ");
      expect(notesText).toContain("NOT LEGAL ADVICE");
    });
  });

  describe("schema invariants", () => {
    it("every row has a unique id", () => {
      const ids = COVERAGE_MATRIX_V1.rows.map((r) => r.id);
      const uniqueIds = new Set(ids);
      expect(uniqueIds.size).toBe(ids.length);
    });

    it("every row has a unique clause_id", () => {
      const clauseIds = COVERAGE_MATRIX_V1.rows.map((r) => r.citation.clause_id);
      const uniqueClauseIds = new Set(clauseIds);
      expect(uniqueClauseIds.size).toBe(clauseIds.length);
    });

    it("every row has a non-empty verbatim requirement", () => {
      for (const row of COVERAGE_MATRIX_V1.rows) {
        expect(row.requirement.length).toBeGreaterThan(20);
      }
    });

    it("every row's requirement is quoted as verbatim (starts with a quote char)", () => {
      // Verbatim quotes in the matrix begin with an ASCII double-quote.
      for (const row of COVERAGE_MATRIX_V1.rows) {
        expect(row.requirement.startsWith('"')).toBe(true);
      }
    });

    it("every row has a valid coverage flag", () => {
      for (const row of COVERAGE_MATRIX_V1.rows) {
        expect(["full", "partial", "manual_only"]).toContain(row.coverage);
      }
    });

    it("every row has last_reviewed_date and last_reviewed_by", () => {
      for (const row of COVERAGE_MATRIX_V1.rows) {
        expect(row.last_reviewed_date).toBeTruthy();
        expect(row.last_reviewed_by).toBe("Erik Newton");
        expect(() =>
          new Date(row.last_reviewed_date).toISOString()
        ).not.toThrow();
      }
    });

    it("every row has a review_notes entry (load-bearing rationale)", () => {
      for (const row of COVERAGE_MATRIX_V1.rows) {
        expect(row.review_notes).toBeTruthy();
        expect(row.review_notes.length).toBeGreaterThan(10);
      }
    });

    it("every citation has a structured clause_id matching its instrument/section", () => {
      for (const row of COVERAGE_MATRIX_V1.rows) {
        const { instrument, clause_id } = row.citation;
        if (instrument === "Annex IV") {
          expect(clause_id).toMatch(/^annex-iv-/);
        } else if (instrument === "Article") {
          expect(clause_id).toMatch(/^art-/);
        }
      }
    });
  });

  describe("coverage-specific invariants", () => {
    it("every full row has manual_carveout === null", () => {
      for (const row of rowsByCoverage(COVERAGE_MATRIX_V1, "full")) {
        expect(row.manual_carveout).toBeNull();
      }
    });

    it("every full row has at least one evidence_emitter tool", () => {
      for (const row of rowsByCoverage(COVERAGE_MATRIX_V1, "full")) {
        expect(row.evidence_emitter.length).toBeGreaterThan(0);
      }
    });

    it("every partial row has a non-null manual_carveout", () => {
      for (const row of rowsByCoverage(COVERAGE_MATRIX_V1, "partial")) {
        expect(row.manual_carveout).not.toBeNull();
        expect(row.manual_carveout!.length).toBeGreaterThan(10);
      }
    });

    it("every partial row has at least one evidence_emitter tool", () => {
      for (const row of rowsByCoverage(COVERAGE_MATRIX_V1, "partial")) {
        expect(row.evidence_emitter.length).toBeGreaterThan(0);
      }
    });

    it("every manual_only row has an empty evidence_emitter array", () => {
      for (const row of rowsByCoverage(COVERAGE_MATRIX_V1, "manual_only")) {
        expect(row.evidence_emitter).toEqual([]);
      }
    });

    it("every manual_only row has a non-null manual_carveout explaining why", () => {
      for (const row of rowsByCoverage(COVERAGE_MATRIX_V1, "manual_only")) {
        expect(row.manual_carveout).not.toBeNull();
      }
    });
  });

  describe("coverage distribution (regression lock)", () => {
    it("has exactly 46 rows (matrix v1 baseline)", () => {
      expect(COVERAGE_MATRIX_V1.rows.length).toBe(46);
    });

    it("has exactly 5 full rows", () => {
      expect(rowsByCoverage(COVERAGE_MATRIX_V1, "full").length).toBe(5);
    });

    it("has exactly 24 partial rows", () => {
      expect(rowsByCoverage(COVERAGE_MATRIX_V1, "partial").length).toBe(24);
    });

    it("has exactly 17 manual_only rows", () => {
      expect(rowsByCoverage(COVERAGE_MATRIX_V1, "manual_only").length).toBe(
        17
      );
    });

    it("the 5 full rows are the expected canonical spine", () => {
      const fullIds = rowsByCoverage(COVERAGE_MATRIX_V1, "full")
        .map((r) => r.id)
        .sort();
      expect(fullIds).toEqual(
        [
          "annex_iv_2_h_cybersecurity",
          "art_12_automatic_logging",
          "art_12_post_market_monitoring_support",
          "art_12_risk_management_support",
          "art_15_resilience_alteration",
        ].sort()
      );
    });

    it("coverageStats returns consistent percentages", () => {
      const stats = coverageStats(COVERAGE_MATRIX_V1);
      expect(stats.total_rows).toBe(46);
      expect(stats.full).toBe(5);
      expect(stats.partial).toBe(24);
      expect(stats.manual_only).toBe(17);
      expect(stats.full_pct + stats.partial_pct + stats.manual_only_pct).toBe(
        100
      );
    });
  });

  describe("helper function behaviour", () => {
    it("rowById returns the correct row", () => {
      const row = rowById(COVERAGE_MATRIX_V1, "annex_iv_2_h_cybersecurity");
      expect(row).toBeDefined();
      expect(row?.coverage).toBe("full");
    });

    it("rowById returns undefined for unknown id", () => {
      expect(rowById(COVERAGE_MATRIX_V1, "nonexistent")).toBeUndefined();
    });

    it("rowsByInstrument filters Annex IV rows", () => {
      const annexRows = rowsByInstrument(COVERAGE_MATRIX_V1, "Annex IV");
      expect(annexRows.length).toBe(21);
      for (const row of annexRows) {
        expect(row.citation.instrument).toBe("Annex IV");
      }
    });

    it("rowsByInstrument filters Article rows", () => {
      const articleRows = rowsByInstrument(COVERAGE_MATRIX_V1, "Article");
      expect(articleRows.length).toBe(25);
      for (const row of articleRows) {
        expect(row.citation.instrument).toBe("Article");
      }
    });

    it("allEvidenceEmitters returns sorted unique tool names", () => {
      const emitters = allEvidenceEmitters(COVERAGE_MATRIX_V1);
      expect(emitters.length).toBeGreaterThan(0);
      // Sorted
      const sorted = [...emitters].sort();
      expect(emitters).toEqual(sorted);
      // Unique
      expect(new Set(emitters).size).toBe(emitters.length);
    });
  });

  describe("referential integrity — every evidence_emitter is a real v0.7.0 tool", () => {
    // This is the guard against the matrix silently referencing a
    // tool that does not exist. Updated manually when tools are
    // added, renamed, or removed.
    const KNOWN_V0_7_0_TOOLS = new Set([
      "audit_export_siem",
      "bridge_attest",
      "bridge_commit",
      "bridge_verify",
      "context_gate_apply_template",
      "context_gate_enforcer_configure",
      "context_gate_enforcer_status",
      "context_gate_filter",
      "context_gate_list_policies",
      "context_gate_recommend",
      "context_gate_set_policy",
      "disclosure_evaluate",
      "disclosure_set_policy",
      "exec_attest",
      "federation_peers",
      "federation_status",
      "federation_trust_evaluate",
      "governor_reset",
      "governor_status",
      "handshake_complete",
      "handshake_exchange",
      "handshake_initiate",
      "handshake_respond",
      "handshake_status",
      "handshake_verify_attestation",
      "identity_create",
      "identity_list",
      "identity_rotate",
      "identity_set_primary",
      "identity_sign",
      "identity_verify",
      "manifest",
      "memory_attest",
      "monitor_audit_log",
      "monitor_health",
      "principal_baseline_view",
      "principal_policy_view",
      "proof_commitment",
      "proof_reveal",
      "reputation_export",
      "reputation_import",
      "reputation_publish",
      "reputation_query",
      "reputation_query_weighted",
      "reputation_record",
      "sanctuary_bootstrap",
      "sanctuary_export_identity_bundle",
      "sanctuary_link_to_human",
      "sanctuary_policy_status",
      "sanctuary_sign_challenge",
      "shr_gateway_export",
      "shr_generate",
      "shr_verify",
      "sovereignty_audit",
      "sovereignty_profile_generate_prompt",
      "sovereignty_profile_get",
      "sovereignty_profile_update",
      "state_delete",
      "state_export",
      "state_import",
      "state_list",
      "state_read",
      "state_write",
      "zk_commit",
      "zk_prove",
      "zk_range_prove",
      "zk_range_verify",
      "zk_verify",
    ]);

    it("every evidence_emitter tool is registered in v0.7.0", () => {
      const emitters = allEvidenceEmitters(COVERAGE_MATRIX_V1);
      const unknown = emitters.filter((t) => !KNOWN_V0_7_0_TOOLS.has(t));
      if (unknown.length > 0) {
        throw new Error(
          `Coverage matrix references unknown tool(s): ${unknown.join(", ")}. ` +
            `Either add to KNOWN_V0_7_0_TOOLS in this test (if the tool is real and I missed it), ` +
            `or correct the matrix to reference a real tool.`
        );
      }
    });
  });
});
