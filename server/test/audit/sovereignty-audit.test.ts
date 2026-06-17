/**
 * Sovereignty Audit Tool — Tests
 *
 * Tests for environment detection, gap analysis, scoring, and report formatting.
 */

import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { defaultConfig } from "../../src/config.js";
import type { SanctuaryConfig } from "../../src/config.js";
import {
  analyzeSovereignty,
  formatAuditReport,
  type SovereigntyRuntimeSignals,
} from "../../src/audit/analyzer.js";
import { detectEnvironment } from "../../src/audit/detector.js";

// Honesty (audit seam #5): context-gating and zero-knowledge proofs default
// OFF and are only credited from the live profile. Tests that intend a
// FULLY-configured fortress must pass these explicitly enabled — the analyzer
// no longer auto-credits them from `sanctuary_installed`.
const ALL_FEATURES_ON: SovereigntyRuntimeSignals = {
  contextGatingEnabled: true,
  zkProofsEnabled: true,
};
import type {
  EnvironmentFingerprint,
  OpenClawConfigAudit,
  SovereigntyAuditResult,
} from "../../src/audit/types.js";

// ── Helpers ─────────────────────────────────────────────────────────────

function makeFingerprint(overrides?: Partial<EnvironmentFingerprint>): EnvironmentFingerprint {
  return {
    sanctuary_installed: true,
    sanctuary_version: "0.3.0",
    openclaw_detected: false,
    openclaw_version: null,
    openclaw_config: null,
    node_version: process.version,
    platform: `${process.platform}-${process.arch}`,
    ...overrides,
  };
}

function makeOpenClawConfig(overrides?: Partial<OpenClawConfigAudit>): OpenClawConfigAudit {
  return {
    config_path: "/home/user/.openclaw/openclaw.json",
    require_approval_enabled: false,
    sandbox_policy_active: false,
    sandbox_allow_list: [],
    sandbox_deny_list: [],
    memory_encrypted: false,
    env_file_exposed: false,
    gateway_token_set: false,
    dm_pairing_enabled: false,
    mcp_bridge_active: false,
    ...overrides,
  };
}

// ── Tests ───────────────────────────────────────────────────────────────

describe("Sovereignty Audit", () => {
  let config: SanctuaryConfig;

  beforeEach(() => {
    config = defaultConfig();
  });

  describe("Scoring", () => {
    it("scores high for fully configured Sanctuary (no OpenClaw)", () => {
      const env = makeFingerprint();
      // Honesty (audit seam #5): "fully configured" now means the optional,
      // default-off features (context-gating, ZK) are explicitly enabled.
      const result = analyzeSovereignty(env, config, ALL_FEATURES_ON);

      // Sanctuary provides all four layers → score should be 100
      expect(result.overall_score).toBe(100);
      expect(result.sovereignty_level).toBe("full");
      expect(result.gaps).toHaveLength(0);
    });

    // Honesty (audit seam #5): a fresh install (context-gating + ZK default OFF)
    // must NOT score 100, must surface the gaps, and must not credit the
    // disabled features as active. The diagnostic that is supposed to catch a
    // degraded setup previously could not report any drop at all.
    it("does NOT score 100 for a fresh install with default-off features", () => {
      const env = makeFingerprint();
      const result = analyzeSovereignty(env, config); // no runtime signals

      expect(result.overall_score).toBeLessThan(100);
      // The fresh install surfaces the context-gating gap and a non-active L3,
      // and does not credit the disabled features.
      expect(result.layers.l2_operational.context_gating).toBe(false);
      expect(result.layers.l3_selective_disclosure.zero_knowledge_proofs).toBe(false);
      expect(result.layers.l3_selective_disclosure.status).not.toBe("active");
      expect(result.gaps.map((g) => g.id)).toContain("GAP-L2-003");
    });

    // Honesty (audit seam #5, level layer): even though a fresh install scores
    // a high 89, the one-word headline verdict must NOT read "full" while the
    // optional sovereignty layers (context-gating, ZK) are off. "full" is
    // reserved for a posture where nothing optional is left off; otherwise the
    // level label re-commits a milder form of the score overclaim.
    it("does NOT report sovereignty_level 'full' for a fresh default-off install", () => {
      const env = makeFingerprint();
      const result = analyzeSovereignty(env, config); // no runtime signals

      // The numeric score is high enough to clear the >= 80 numeric cut, but the
      // optional layers are off, so the headline verdict must drop a band.
      expect(result.overall_score).toBeGreaterThanOrEqual(80);
      expect(result.sovereignty_level).not.toBe("full");
      expect(result.sovereignty_level).toBe("partial");
      // The headline verdict and the gaps are mutually consistent: the very
      // gap that keeps it out of "full" is surfaced for the operator to close.
      expect(result.gaps.map((g) => g.id)).toContain("GAP-L2-003");
    });

    // The level gate must NOT make "full" unreachable: a legitimately
    // fully-configured install (optional layers explicitly enabled) still reads
    // "full" at both the numeric and level layers.
    it("reports sovereignty_level 'full' once the optional layers are enabled", () => {
      const env = makeFingerprint();
      const result = analyzeSovereignty(env, config, ALL_FEATURES_ON);

      expect(result.overall_score).toBe(100);
      expect(result.layers.l2_operational.context_gating).toBe(true);
      expect(result.layers.l3_selective_disclosure.zero_knowledge_proofs).toBe(true);
      expect(result.sovereignty_level).toBe("full");
    });

    // Honesty (audit seam #5): enabling only one optional feature scores
    // between the fresh-install floor and a fully-enabled fortress.
    it("credits each default-off feature only when the live profile enables it", () => {
      const env = makeFingerprint();
      const fresh = analyzeSovereignty(env, config).overall_score;
      const ctxOnly = analyzeSovereignty(env, config, {
        contextGatingEnabled: true,
      }).overall_score;
      const both = analyzeSovereignty(env, config, ALL_FEATURES_ON).overall_score;

      expect(ctxOnly).toBeGreaterThan(fresh);
      expect(both).toBeGreaterThan(ctxOnly);
      expect(both).toBe(100);
    });

    it("scores near-zero for OpenClaw-only (no Sanctuary layers)", () => {
      const env = makeFingerprint({
        sanctuary_installed: false,
        sanctuary_version: null,
        openclaw_detected: true,
        openclaw_config: makeOpenClawConfig({
          memory_encrypted: false,
          env_file_exposed: true,
        }),
      });

      const result = analyzeSovereignty(env, config);

      // No Sanctuary → score should be very low
      expect(result.overall_score).toBeLessThanOrEqual(5);
      expect(result.sovereignty_level).toBe("none");
      // Should generate OpenClaw-specific gap messages
      expect(result.gaps.length).toBeGreaterThanOrEqual(4);
      const gapIds = result.gaps.map((g) => g.id);
      expect(gapIds).toContain("GAP-L1-001"); // plaintext memory
      expect(gapIds).toContain("GAP-L1-002"); // env file exposed
      expect(gapIds).toContain("GAP-L1-003"); // no identity
    });

    it("gives partial L2 credit for OpenClaw requireApproval + sandbox", () => {
      const env = makeFingerprint({
        sanctuary_installed: false,
        sanctuary_version: null,
        openclaw_detected: true,
        openclaw_config: makeOpenClawConfig({
          require_approval_enabled: true,
          sandbox_policy_active: true,
          sandbox_allow_list: ["read", "write"],
          sandbox_deny_list: ["delete"],
        }),
      });

      const result = analyzeSovereignty(env, config);

      // Binary gate = 3, basic sandbox = 1 → L2 score = 4
      expect(result.layers.l2_operational.approval_gate).toBe("binary");
      expect(result.layers.l2_operational.tool_sandboxing).toBe("basic");
      expect(result.overall_score).toBeGreaterThan(0);
      expect(result.overall_score).toBeLessThan(20);

      // Should generate gap about binary gate
      const l2Gaps = result.gaps.filter((g) => g.layer === "L2");
      expect(l2Gaps.length).toBeGreaterThanOrEqual(1);
      expect(l2Gaps.some((g) => g.id === "GAP-L2-001")).toBe(true);
    });

    it("scores near-100 for full Sanctuary + OpenClaw", () => {
      const env = makeFingerprint({
        openclaw_detected: true,
        openclaw_config: makeOpenClawConfig({
          require_approval_enabled: true,
          sandbox_policy_active: true,
          memory_encrypted: true, // hypothetical encrypted memory
        }),
      });

      const result = analyzeSovereignty(env, config, ALL_FEATURES_ON);

      expect(result.overall_score).toBe(100);
      expect(result.sovereignty_level).toBe("full");
      // No critical gaps when Sanctuary is fully active
      const criticalGaps = result.gaps.filter((g) => g.severity === "critical");
      expect(criticalGaps).toHaveLength(0);
    });

    it("subtracts at least 20 points for a single audit sequence gap", () => {
      const env = makeFingerprint({
        audit_subsystem_health: {
          integrity_findings: [
            {
              kind: "sequence_gap",
              sequence: 4,
              expected: 3,
              actual: 4,
              message: "audit sequence break",
            },
          ],
          exit_export_aborted_by_integrity_gate: false,
          mcp_tools_bricked_by_integrity_gate: false,
        },
      });

      // ALL_FEATURES_ON isolates the audit-penalty math from the default-off
      // feature scoring (audit seam #5): base 100, single finding -20 -> 80.
      const result = analyzeSovereignty(env, config, ALL_FEATURES_ON);

      expect(result.overall_score).toBeLessThanOrEqual(80);
      expect(result.overall_score).toBeLessThan(100);
      expect(result.gaps.map((g) => g.id)).toContain("GAP-AUDIT-001");
    });

    it("subtracts proportionally for audit integrity findings and never reports 100 on a broken fortress", () => {
      const env = makeFingerprint({
        audit_subsystem_health: {
          integrity_findings: [
            { kind: "sequence_gap_or_reorder", sequence: 2 },
            { kind: "prev_hash_mismatch", sequence: 3 },
            { kind: "entry_hash_mismatch", sequence: 4 },
            { kind: "checkpoint_root_mismatch", sequence: 4 },
          ],
          exit_export_aborted_by_integrity_gate: false,
          mcp_tools_bricked_by_integrity_gate: false,
        },
      });

      // ALL_FEATURES_ON: base 100, four findings cap penalty at 70 -> 30.
      const result = analyzeSovereignty(env, config, ALL_FEATURES_ON);

      expect(result.overall_score).toBe(30);
      expect(result.sovereignty_level).toBe("minimal");
      expect(result.gaps.map((g) => g.id)).toContain("GAP-AUDIT-001");
    });

    it("subtracts additional severe penalties for exit export aborts and bricked MCP tools", () => {
      const env = makeFingerprint({
        audit_subsystem_health: {
          integrity_findings: [
            { kind: "sequence_gap_or_reorder", sequence: 2 },
          ],
          exit_export_aborted_by_integrity_gate: true,
          mcp_tools_bricked_by_integrity_gate: true,
        },
      });

      // ALL_FEATURES_ON: base 100; 1 finding (-20) + export abort (-25) +
      // bricked tools (-25) = -70 -> 30.
      const result = analyzeSovereignty(env, config, ALL_FEATURES_ON);

      expect(result.overall_score).toBe(30);
      expect(result.overall_score).toBeLessThan(100);
      expect(result.gaps.map((g) => g.id)).toEqual(
        expect.arrayContaining(["GAP-AUDIT-001", "GAP-AUDIT-002", "GAP-AUDIT-003"])
      );
    });
  });

  describe("OpenClaw Memory Detection", () => {
    it("flags MEMORY.md as unencrypted when openclaw is detected", () => {
      const env = makeFingerprint({
        openclaw_detected: true,
        openclaw_config: makeOpenClawConfig({
          memory_encrypted: false,
        }),
      });

      const result = analyzeSovereignty(env, config);

      // Should flag plaintext memory even though Sanctuary is installed
      const memGap = result.gaps.find((g) => g.id === "GAP-L1-001");
      expect(memGap).toBeDefined();
      expect(memGap!.severity).toBe("critical");
      expect(memGap!.title).toContain("plaintext");
      expect(memGap!.openclaw_relevance).toBeTruthy();
    });
  });

  describe("OpenClaw .env Detection", () => {
    it("flags exposed .env with plaintext API keys", () => {
      const env = makeFingerprint({
        openclaw_detected: true,
        openclaw_config: makeOpenClawConfig({
          env_file_exposed: true,
        }),
      });

      const result = analyzeSovereignty(env, config);

      const envGap = result.gaps.find((g) => g.id === "GAP-L1-002");
      expect(envGap).toBeDefined();
      expect(envGap!.severity).toBe("critical");
      expect(envGap!.title).toContain("API keys");
    });
  });

  describe("Recommendation Ordering", () => {
    it("always outputs recommendations in priority order", () => {
      const env = makeFingerprint({
        sanctuary_installed: false,
        sanctuary_version: null,
        openclaw_detected: true,
        openclaw_config: makeOpenClawConfig({
          memory_encrypted: false,
          env_file_exposed: true,
        }),
      });

      const result = analyzeSovereignty(env, config);

      expect(result.recommendations.length).toBeGreaterThanOrEqual(3);
      for (let i = 1; i < result.recommendations.length; i++) {
        expect(result.recommendations[i].priority).toBeGreaterThanOrEqual(
          result.recommendations[i - 1].priority
        );
      }

      // First recommendation should always be identity creation
      expect(result.recommendations[0].tool).toBe("identity_create");
    });
  });

  describe("Read-only Verification", () => {
    it("detector source code contains no write operations", async () => {
      // Verify by reading the detector source code — it must not import or call
      // any write functions (writeFile, mkdir, appendFile, rm, unlink, rename).
      const fs = await import("node:fs/promises");
      const detectorSource = await fs.readFile(
        new URL("../../src/audit/detector.ts", import.meta.url),
        "utf-8"
      );

      // The detector should only import read-only fs functions
      expect(detectorSource).not.toContain("writeFile");
      expect(detectorSource).not.toContain("appendFile");
      expect(detectorSource).not.toContain("rm(");
      expect(detectorSource).not.toContain("rmdir");
      expect(detectorSource).not.toContain("unlink");
      expect(detectorSource).not.toContain("rename");
      expect(detectorSource).not.toContain("mkdir");
      expect(detectorSource).not.toContain("copyFile");

      // Also verify it makes no network requests
      expect(detectorSource).not.toContain("fetch(");
      expect(detectorSource).not.toContain("http.request");
      expect(detectorSource).not.toContain("https.request");
      expect(detectorSource).not.toContain("net.connect");
    });

    it("detector runs without side effects on the filesystem", async () => {
      // Run the detector and verify it returns a valid fingerprint
      // without throwing or modifying anything
      const env = await detectEnvironment(config, true);

      expect(env.sanctuary_installed).toBe(true);
      expect(env.sanctuary_version).toBe(config.version);
      expect(env.node_version).toBe(process.version);
      expect(typeof env.platform).toBe("string");
    });
  });

  describe("Deterministic Scoring", () => {
    it("produces identical scores for identical environments", () => {
      const env = makeFingerprint({
        openclaw_detected: true,
        openclaw_config: makeOpenClawConfig({
          require_approval_enabled: true,
          sandbox_policy_active: true,
        }),
      });

      const result1 = analyzeSovereignty(env, config);
      const result2 = analyzeSovereignty(env, config);

      expect(result1.overall_score).toBe(result2.overall_score);
      expect(result1.sovereignty_level).toBe(result2.sovereignty_level);
      expect(result1.gaps.length).toBe(result2.gaps.length);
      expect(result1.recommendations.length).toBe(result2.recommendations.length);
    });
  });

  describe("Report Formatting", () => {
    it("produces a human-readable report with all sections", () => {
      const env = makeFingerprint({
        openclaw_detected: true,
        openclaw_config: makeOpenClawConfig({
          require_approval_enabled: true,
          memory_encrypted: false,
          env_file_exposed: true,
        }),
      });

      const result = analyzeSovereignty(env, config);
      const report = formatAuditReport(result);

      expect(report).toContain("SOVEREIGNTY AUDIT REPORT");
      expect(report).toContain("Overall Score:");
      expect(report).toContain("Layer Assessment:");
      expect(report).toContain("L1 Cognitive Sovereignty");
      expect(report).toContain("L2 Operational Isolation");
      expect(report).toContain("L3 Selective Disclosure");
      expect(report).toContain("L4 Verifiable Reputation");
      expect(report).toContain("RECOMMENDED NEXT STEPS");
    });
  });

  describe("L3 ZK Proofs Scoring", () => {
    it("scores L3 as Full (20/20) with Schnorr + range proofs when ZK is enabled", () => {
      const env = makeFingerprint({
        sanctuary_installed: true,
      });
      // Honesty (audit seam #5): ZK proofs are credited only when the live
      // profile enables them; they default OFF.
      const result = analyzeSovereignty(env, config, ALL_FEATURES_ON);
      const l3 = result.layers.l3_selective_disclosure;

      // With ZK enabled, L3 should be active with full score
      expect(l3.status).toBe("active");
      expect(l3.commitment_scheme).toBe("pedersen+sha256");
      expect(l3.zero_knowledge_proofs).toBe(true);
      expect(l3.selective_disclosure_policy).toBe(true);

      // Score should be: 8 (commitment) + 7 (proofs) + 5 (policies) = 20
      const l3Score = 8 + 7 + 5;
      expect(result.layers.l3_selective_disclosure).toBeDefined();

      // Verify findings explicitly mention genuine ZK proofs
      expect(l3.findings.join(" ")).toContain("zero-knowledge");
      expect(l3.findings.join(" ")).toContain("Fiat-Shamir");
    });

    // Honesty (audit seam #5): with ZK disabled (the default), L3 is NOT active
    // and zero_knowledge_proofs is false even though Sanctuary is installed.
    it("does not credit ZK proofs when the profile toggle is OFF (default)", () => {
      const env = makeFingerprint({ sanctuary_installed: true });
      const result = analyzeSovereignty(env, config); // ZK default OFF
      const l3 = result.layers.l3_selective_disclosure;

      expect(l3.status).not.toBe("active");
      expect(l3.zero_knowledge_proofs).toBe(false);
      // Commitment primitives are still available, so the scheme is present.
      expect(l3.commitment_scheme).toBe("pedersen+sha256");
      expect(l3.findings.join(" ")).toContain("NOT enabled");
    });

    it("L3 findings clarify that Schnorr + range proofs are genuine ZK proofs when enabled", () => {
      const env = makeFingerprint({
        sanctuary_installed: true,
      });
      const result = analyzeSovereignty(env, config, ALL_FEATURES_ON);
      const l3 = result.layers.l3_selective_disclosure;

      const findingsText = l3.findings.join(" ");
      expect(findingsText).toContain("genuine ZK");
      expect(findingsText).toContain("Schnorr");
      expect(findingsText).toContain("Range proofs");
      expect(findingsText).toContain("domain separation");
    });

    it("does not generate L3 gap when commitments are available (proofs optional)", () => {
      const env = makeFingerprint({
        sanctuary_installed: true,
      });
      const result = analyzeSovereignty(env, config, ALL_FEATURES_ON);

      // Should NOT have GAP-L3-001 (no selective disclosure)
      const l3Gaps = result.gaps.filter((g) => g.id === "GAP-L3-001");
      expect(l3Gaps).toHaveLength(0);
    });

    it("generates L3 gap only when commitment_scheme is none", () => {
      const env = makeFingerprint({
        sanctuary_installed: false,
        sanctuary_version: null,
        openclaw_detected: false,
      });
      const result = analyzeSovereignty(env, config);

      // Should have GAP-L3-001 (no selective disclosure at all)
      const l3Gaps = result.gaps.filter((g) => g.id === "GAP-L3-001");
      expect(l3Gaps).toHaveLength(1);
      expect(l3Gaps[0].title).toContain("No selective disclosure capability");
    });
  });

  describe("Incident Class Mapping", () => {
    it("maps plaintext memory gap to Meta Sev 1 incident", () => {
      const env = makeFingerprint({
        sanctuary_installed: true,
        openclaw_detected: true,
        openclaw_config: makeOpenClawConfig({
          memory_encrypted: false,
        }),
      });

      const result = analyzeSovereignty(env, config);
      const memGap = result.gaps.find((g) => g.id === "GAP-L1-001");
      expect(memGap).toBeDefined();
      expect(memGap!.incident_class).toBeDefined();
      expect(memGap!.incident_class!.id).toBe("META-SEV1-2026");
      expect(memGap!.incident_class!.date).toBe("2026-03-18");
    });

    it("maps no-approval-gate gap to Meta Sev 1 incident", () => {
      const env = makeFingerprint({
        sanctuary_installed: false,
        sanctuary_version: null,
        openclaw_detected: false,
        openclaw_config: null,
      });

      const result = analyzeSovereignty(env, config);
      const gateGap = result.gaps.find((g) => g.id === "GAP-L2-001");
      expect(gateGap).toBeDefined();
      expect(gateGap!.incident_class).toBeDefined();
      expect(gateGap!.incident_class!.id).toBe("META-SEV1-2026");
    });

    it("maps basic-sandbox gap to OpenClaw CVE incident", () => {
      const env = makeFingerprint({
        sanctuary_installed: false,
        sanctuary_version: null,
        openclaw_detected: true,
        openclaw_config: makeOpenClawConfig({
          sandbox_policy_active: true,
          sandbox_allow_list: ["read"],
          sandbox_deny_list: ["delete"],
        }),
      });

      const result = analyzeSovereignty(env, config);
      const sandboxGap = result.gaps.find((g) => g.id === "GAP-L2-002");
      expect(sandboxGap).toBeDefined();
      expect(sandboxGap!.incident_class).toBeDefined();
      expect(sandboxGap!.incident_class!.id).toBe("OPENCLAW-CVE-2026");
      expect(sandboxGap!.incident_class!.cves).toContain("CVE-2026-32048");
    });

    it("maps no-context-gating gap to context leakage incident", () => {
      const env = makeFingerprint({
        sanctuary_installed: false,
        sanctuary_version: null,
        openclaw_detected: true,
        openclaw_config: makeOpenClawConfig(),
      });

      const result = analyzeSovereignty(env, config);
      const ctxGap = result.gaps.find((g) => g.id === "GAP-L2-003");
      expect(ctxGap).toBeDefined();
      expect(ctxGap!.incident_class).toBeDefined();
      expect(ctxGap!.incident_class!.id).toBe("CONTEXT-LEAK-CLASS");
    });

    it("maps no-selective-disclosure gap to Meta Sev 1 incident", () => {
      const env = makeFingerprint({
        sanctuary_installed: false,
        sanctuary_version: null,
        openclaw_detected: false,
        openclaw_config: null,
      });

      const result = analyzeSovereignty(env, config);
      const discGap = result.gaps.find((g) => g.id === "GAP-L3-001");
      expect(discGap).toBeDefined();
      expect(discGap!.incident_class).toBeDefined();
      expect(discGap!.incident_class!.id).toBe("META-SEV1-2026");
    });

    it("renders incident class in formatted report", () => {
      const env = makeFingerprint({
        sanctuary_installed: false,
        sanctuary_version: null,
        openclaw_detected: true,
        openclaw_config: makeOpenClawConfig({
          memory_encrypted: false,
        }),
      });

      const result = analyzeSovereignty(env, config);
      const report = formatAuditReport(result);
      expect(report).toContain("Incident precedent:");
      expect(report).toContain("Meta Sev 1");
    });

    it("does not include incident class for full Sanctuary (no gaps)", () => {
      const env = makeFingerprint();
      const result = analyzeSovereignty(env, config, ALL_FEATURES_ON);
      expect(result.gaps).toHaveLength(0);
    });
  });

  describe("Graceful OpenClaw Absence", () => {
    it("works cleanly when OpenClaw is not installed", () => {
      const env = makeFingerprint({
        openclaw_detected: false,
        openclaw_config: null,
      });

      const result = analyzeSovereignty(env, config, ALL_FEATURES_ON);

      expect(result.overall_score).toBe(100);
      expect(result.sovereignty_level).toBe("full");
      // No OpenClaw-specific gaps
      const openclawGaps = result.gaps.filter((g) => g.openclaw_relevance !== null);
      expect(openclawGaps).toHaveLength(0);
    });
  });
});
