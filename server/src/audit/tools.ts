/**
 * Sanctuary MCP Server — Sovereignty Audit MCP Tool
 *
 * Registers the sanctuary/sovereignty_audit tool that inspects the local
 * environment, detects sovereignty protections (including OpenClaw-specific
 * configurations), and produces a structured gap analysis report.
 *
 * This tool is Tier 3 (auto-allow) — it is read-only and diagnostic.
 */

import type { ToolDefinition } from "../router.js";
import type { SanctuaryConfig } from "../config.js";
import { detectEnvironment } from "./detector.js";
import { analyzeSovereignty, formatAuditReport } from "./analyzer.js";

export function createAuditTools(
  config: SanctuaryConfig
): { tools: ToolDefinition[] } {
  const tools: ToolDefinition[] = [
    {
      name: "sanctuary/sovereignty_audit",
      description:
        "Audit your agent's sovereignty posture. Inspects the local environment for " +
        "encryption, identity, approval gates, selective disclosure, and reputation — " +
        "including OpenClaw-specific configurations. Returns a scored gap analysis with " +
        "prioritized recommendations.",
      inputSchema: {
        type: "object",
        properties: {
          deep_scan: {
            type: "boolean",
            description:
              "If true (default), also scans for OpenClaw config, .env files, and " +
              "memory files. Set to false for a Sanctuary-only assessment.",
          },
        },
      },
      handler: async (args) => {
        const deepScan = args.deep_scan !== false; // Default true

        // Detect environment (read-only)
        const env = await detectEnvironment(config, deepScan);

        // Analyze sovereignty posture
        const result = analyzeSovereignty(env, config);

        // Format human-readable report
        const report = formatAuditReport(result);

        return {
          content: [
            { type: "text" as const, text: report },
            { type: "text" as const, text: JSON.stringify(result, null, 2) },
          ],
        };
      },
    },
  ];

  return { tools };
}
