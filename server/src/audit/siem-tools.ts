/**
 * Sanctuary MCP Server — SIEM Export Tool
 *
 * Registers the audit_export_siem MCP tool that exports audit log entries
 * in standard SIEM formats (CEF and OCSF).
 *
 * Tier 3: Auto-allow with audit logging (read-only operation).
 * No approval required in non-interactive (stdio) mode.
 */

import type { ToolDefinition } from "../router.js";
import type { AuditLog, AuditEntry } from "../l2-operational/audit-log.js";
import { formatAsCEF, formatAsOCSF } from "./siem-formatter.js";

export function createSIEMTools(auditLog: AuditLog): { tools: ToolDefinition[] } {
  const tools: ToolDefinition[] = [
    {
      name: "audit_export_siem",
      description:
        "Export audit log events in SIEM-standard formats (CEF or OCSF) for ingestion into " +
        "Splunk, Datadog, QRadar, and other security information and event management (SIEM) platforms. " +
        "Encrypted audit entries are decrypted and formatted according to your chosen standard. " +
        "Tier 3 — auto-allow (read-only, audit logging only).",
      inputSchema: {
        type: "object",
        properties: {
          format: {
            type: "string",
            enum: ["cef", "ocsf"],
            description:
              'Output format: "cef" (Common Event Format, newline-delimited) or "ocsf" (Open Cybersecurity Schema Framework, JSON array)',
          },
          since: {
            type: "string",
            description:
              "Optional ISO 8601 timestamp. Export only events on or after this time. Defaults to 24 hours ago.",
          },
          until: {
            type: "string",
            description:
              "Optional ISO 8601 timestamp. Export only events before this time. Defaults to now.",
          },
          limit: {
            type: "number",
            description:
              "Maximum number of events to export (default 100, max 1000). " +
              "Set to 1000 for bulk exports to SIEMs.",
          },
          filter_tool: {
            type: "string",
            description:
              'Optional. Export only events from this tool name (e.g., "sovereignty_audit", "state_set"). ' +
              "Case-insensitive substring matching.",
          },
          filter_decision: {
            type: "string",
            enum: ["approve", "deny", "auto-allow"],
            description:
              'Optional. Export only events with this gate decision: "approve" (manual approval), ' +
              '"deny" (blocked), or "auto-allow" (Tier 3 auto-allowed).',
          },
          filter_layer: {
            type: "string",
            enum: ["l1", "l2", "l3", "l4"],
            description:
              "Optional. Export only events from this sovereignty layer (L1=Cognitive, " +
              "L2=Operational, L3=Disclosure, L4=Reputation).",
          },
          filter_result: {
            type: "string",
            enum: ["success", "failure"],
            description:
              'Optional. Export only events with this result: "success" or "failure".',
          },
        },
        required: ["format"],
      },
      handler: async (args) => {
        // Parse and validate inputs
        const format = String(args.format || "").toLowerCase();
        if (format !== "cef" && format !== "ocsf") {
          return {
            content: [
              {
                type: "text" as const,
                text: JSON.stringify({
                  error: "Invalid format. Must be 'cef' or 'ocsf'.",
                }),
              },
            ],
          };
        }

        // Parse time range (default to 24 hours ago if since not specified)
        let since: string | undefined;
        if (args.since) {
          since = String(args.since);
          // Validate ISO 8601
          const sinceDate = new Date(since);
          if (isNaN(sinceDate.getTime())) {
            return {
              content: [
                {
                  type: "text" as const,
                  text: JSON.stringify({
                    error: `Invalid 'since' timestamp: ${since}. Must be ISO 8601.`,
                  }),
                },
              ],
            };
          }
        } else {
          // Default to 24 hours ago
          const now = new Date();
          const oneDayAgo = new Date(now.getTime() - 24 * 60 * 60 * 1000);
          since = oneDayAgo.toISOString();
        }

        let until: string | undefined;
        if (args.until) {
          until = String(args.until);
          const untilDate = new Date(until);
          if (isNaN(untilDate.getTime())) {
            return {
              content: [
                {
                  type: "text" as const,
                  text: JSON.stringify({
                    error: `Invalid 'until' timestamp: ${until}. Must be ISO 8601.`,
                  }),
                },
              ],
            };
          }
        }

        // Parse limit (default 100, max 1000)
        let limit = 100;
        if (typeof args.limit === "number") {
          limit = Math.max(1, Math.min(1000, args.limit));
        }

        // Parse optional filters
        const filterTool = args.filter_tool
          ? String(args.filter_tool).toLowerCase()
          : undefined;
        const filterDecision = args.filter_decision
          ? String(args.filter_decision).toLowerCase()
          : undefined;
        const filterLayer = args.filter_layer
          ? (String(args.filter_layer).toLowerCase() as "l1" | "l2" | "l3" | "l4" | undefined)
          : undefined;
        const filterResult = args.filter_result
          ? (String(args.filter_result).toLowerCase() as "success" | "failure" | undefined)
          : undefined;

        // Query audit log
        const result = await auditLog.query({
          since,
          layer: filterLayer,
          operation_type: undefined, // Will filter after
          limit,
        });

        // Apply additional filters (tool name, gate decision, result)
        let filtered = result.entries;

        if (filterTool) {
          filtered = filtered.filter((e: AuditEntry) =>
            e.operation.toLowerCase().includes(filterTool)
          );
        }

        if (filterDecision) {
          filtered = filtered.filter((e: AuditEntry) => {
            const decision = String(e.details?.gate_decision || "auto-allow").toLowerCase();
            return decision === filterDecision;
          });
        }

        if (filterResult) {
          filtered = filtered.filter((e: AuditEntry) => e.result === filterResult);
        }

        // Apply until filter if specified
        if (until) {
          const untilDate = new Date(until);
          filtered = filtered.filter((e: AuditEntry) => new Date(e.timestamp) < untilDate);
        }

        // Format output
        let output: string;

        if (format === "cef") {
          // CEF: newline-delimited strings
          const cefLines = filtered.map((entry: AuditEntry) => formatAsCEF(entry));
          output = cefLines.join("\n");
        } else {
          // OCSF: JSON array
          const ocsfObjects = filtered.map((entry: AuditEntry) => formatAsOCSF(entry));
          output = JSON.stringify(ocsfObjects, null, 2);
        }

        return {
          content: [
            {
              type: "text" as const,
              text: JSON.stringify({
                format,
                count: filtered.length,
                total_available: result.total,
                time_range: {
                  since,
                  until: until || new Date().toISOString(),
                },
                filters: {
                  tool: filterTool,
                  decision: filterDecision,
                  layer: filterLayer,
                  result: filterResult,
                },
                note:
                  format === "cef"
                    ? `${filtered.length} CEF events (newline-delimited). Each line is a complete CEF event.`
                    : `${filtered.length} OCSF objects in JSON array format.`,
              }),
            },
            {
              type: "text" as const,
              text: output,
            },
          ],
        };
      },
    },
  ];

  return { tools };
}
