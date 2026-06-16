/**
 * Sovereignty Audit Tool tests
 *
 * Covers: sovereignty_audit tool handler, deep_scan flag, output format.
 * Not covered: real environment detection, OpenClaw config scanning.
 */

import { describe, it, expect, vi } from "vitest";
import { createAuditTools } from "../../src/audit/tools.js";
import type { SanctuaryConfig } from "../../src/config.js";
import { AuditIntegrityError } from "../../src/operational/audit-log.js";

// Mock the detector and analyzer modules
vi.mock("../../src/audit/detector.js", () => ({
  detectEnvironment: vi.fn(async (_config: unknown, deepScan: boolean) => ({
    platform: "darwin",
    node_version: "v22.0.0",
    sanctuary_version: "0.9.0-rc.1",
    deep_scan: deepScan,
    sanctuary_state_dir: "/tmp/.sanctuary",
    sanctuary_state_exists: true,
    openclaw_detected: deepScan,
    env_files: [],
    memory_files: [],
  })),
}));

vi.mock("../../src/audit/analyzer.js", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../../src/audit/analyzer.js")>();
  return {
    ...actual,
    analyzeSovereignty: vi.fn((_env: unknown, _config: unknown) => ({
      overall_score: 72,
      layer_scores: { l1: 85, l2: 60, l3: 70, l4: 75 },
      gaps: [{ layer: "l2", description: "No TEE detected", severity: "medium" }],
      recommendations: ["Consider TEE deployment for full L2 compliance"],
    })),
    formatAuditReport: vi.fn((_result: unknown) =>
      "=== Sovereignty Audit Report ===\nOverall Score: 72/100\n"
    ),
  };
});

function minimalConfig(): SanctuaryConfig {
  return {
    version: "0.9.0-rc.1",
    state_dir: "/tmp/.sanctuary",
    master_key_source: "passphrase",
  } as SanctuaryConfig;
}

describe("Sovereignty Audit Tool", () => {
  it("returns two content items (report + JSON)", async () => {
    const { tools } = createAuditTools(minimalConfig());
    const tool = tools.find(t => t.name === "sovereignty_audit")!;
    const result = await tool.handler({});
    expect(result.content).toHaveLength(2);
    expect(result.content[0].type).toBe("text");
    expect(result.content[1].type).toBe("text");
  });

  it("first content item is the formatted report", async () => {
    const { tools } = createAuditTools(minimalConfig());
    const tool = tools.find(t => t.name === "sovereignty_audit")!;
    const result = await tool.handler({});
    expect(result.content[0].text).toContain("Sovereignty Audit Report");
  });

  it("second content item is structured JSON", async () => {
    const { tools } = createAuditTools(minimalConfig());
    const tool = tools.find(t => t.name === "sovereignty_audit")!;
    const result = await tool.handler({});
    const parsed = JSON.parse(result.content[1].text);
    expect(parsed.overall_score).toBe(72);
    expect(parsed.layer_scores).toBeDefined();
  });

  it("defaults deep_scan to true", async () => {
    const { detectEnvironment } = await import("../../src/audit/detector.js");
    const { tools } = createAuditTools(minimalConfig());
    const tool = tools.find(t => t.name === "sovereignty_audit")!;
    await tool.handler({});
    expect(detectEnvironment).toHaveBeenCalledWith(expect.anything(), true);
  });

  it("passes deep_scan: false when requested", async () => {
    const { detectEnvironment } = await import("../../src/audit/detector.js");
    const { tools } = createAuditTools(minimalConfig());
    const tool = tools.find(t => t.name === "sovereignty_audit")!;
    await tool.handler({ deep_scan: false });
    expect(detectEnvironment).toHaveBeenCalledWith(expect.anything(), false);
  });

  it("passes strict-mode audit integrity failures into the sovereignty analysis", async () => {
    const { analyzeSovereignty } = await import("../../src/audit/analyzer.js");
    const auditLog = {
      query: vi.fn(async () => {
        throw new AuditIntegrityError([
          {
            kind: "sequence_gap_or_reorder",
            sequence: 7,
            expected: 6,
            actual: 7,
            message: "audit sequence break",
          },
        ]);
      }),
    };
    const { tools } = createAuditTools(minimalConfig(), auditLog);
    const tool = tools.find(t => t.name === "sovereignty_audit")!;

    await tool.handler({});

    expect(analyzeSovereignty).toHaveBeenCalledWith(
      expect.objectContaining({
        audit_subsystem_health: {
          integrity_findings: [
            expect.objectContaining({ kind: "sequence_gap_or_reorder" }),
          ],
          exit_export_aborted_by_integrity_gate: true,
          mcp_tools_bricked_by_integrity_gate: true,
        },
      }),
      expect.anything()
    );
  });

  it("registers exactly one tool", () => {
    const { tools } = createAuditTools(minimalConfig());
    expect(tools).toHaveLength(1);
    expect(tools[0]!.name).toBe("sovereignty_audit");
  });
});
