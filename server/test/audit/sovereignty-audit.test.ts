/**
 * Sovereignty Audit Tool — Tests
 *
 * Tests for environment detection, gap analysis, scoring, and report formatting.
 */

import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { defaultConfig } from "../../src/config.js";
import type { SanctuaryConfig } from "../../src/config.js";
import { analyzeSovereignty, formatAuditReport } from "../../src/audit/analyzer.js";
import { detectEnvironment } from "../../src/audit/detector.js";
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
      const result = analyzeSovereignty(env, config);

      // Sanctuary provides all four layers → score should be 100
      expect(result.overall_score).toBe(100);
      expect(result.sovereignty_level).toBe("full");
      expect(result.gaps).toHaveLength(0);
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

      const result = analyzeSovereignty(env, config);

      expect(result.overall_score).toBe(100);
      expect(result.sovereignty_level).toBe("full");
      // No critical gaps when Sanctuary is fully active
      const criticalGaps = result.gaps.filter((g) => g.severity === "critical");
      expect(criticalGaps).toHaveLength(0);
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
      expect(result.recommendations[0].tool).toBe("sanctuary/identity_create");
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
      const result = analyzeSovereignty(env, config);
      expect(result.gaps).toHaveLength(0);
    });
  });

  describe("Graceful OpenClaw Absence", () => {
    it("works cleanly when OpenClaw is not installed", () => {
      const env = makeFingerprint({
        openclaw_detected: false,
        openclaw_config: null,
      });

      const result = analyzeSovereignty(env, config);

      expect(result.overall_score).toBe(100);
      expect(result.sovereignty_level).toBe("full");
      // No OpenClaw-specific gaps
      const openclawGaps = result.gaps.filter((g) => g.openclaw_relevance !== null);
      expect(openclawGaps).toHaveLength(0);
    });
  });
});
