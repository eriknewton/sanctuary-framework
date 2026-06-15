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
import type { SessionBinding } from "../agent-native/safety-base.js";
import { formatAsCEF, formatAsOCSF, agentDecision } from "./siem-formatter.js";
import {
  redactAuditEntryForAgent,
  buildAgentSearchCorpus,
} from "../l2-operational/agent-audit-redaction.js";

export function createSIEMTools(
  auditLog: AuditLog,
  // OWN-IDENTITY FILTER (CISO MED-3): `audit_export_siem` is agent-callable, so
  // it must export only the CALLER's own entries (system/gate entries — which
  // carry operator-only context — are never returned). Optional so existing
  // callers that pre-date the filter still construct; when absent, the tool
  // fails closed (exports nothing) rather than degrading open.
  currentSessionBinding?: () => SessionBinding | undefined
): { tools: ToolDefinition[] } {
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

        // OWN-IDENTITY FILTER (CISO MED-3, property #11): resolve the caller's
        // identity and export ONLY their own entries. No bound session identity
        // → fail closed (export nothing) rather than exposing other identities'
        // or system entries. Never degrade open.
        const binding = currentSessionBinding?.();
        if (!binding) {
          return {
            content: [
              {
                type: "text" as const,
                text: JSON.stringify({
                  format,
                  count: 0,
                  total_available: 0,
                  time_range: { since, until: until || new Date().toISOString() },
                  filters: {
                    tool: filterTool,
                    decision: filterDecision,
                    layer: filterLayer,
                    result: filterResult,
                  },
                  note: "No bound session identity; SIEM export is scoped to the caller's own entries.",
                }),
              },
              { type: "text" as const, text: "" },
            ],
          };
        }

        // Query audit log (over-fetch, then own-identity filter, then bound by
        // limit so `limit` bounds the caller's OWN entries).
        const result = await auditLog.query({
          since,
          layer: filterLayer,
          operation_type: undefined, // Will filter after
          limit: 1000,
        });

        const totalAvailable = result.entries.filter(
          (e: AuditEntry) => e.identity_id === binding.identity_id
        ).length;

        // Apply additional filters (own-identity, tool name, decision, result).
        let filtered = result.entries.filter(
          (e: AuditEntry) => e.identity_id === binding.identity_id
        );

        if (filterTool) {
          filtered = filtered.filter((e: AuditEntry) =>
            e.operation.toLowerCase().includes(filterTool)
          );
        }

        if (filterDecision) {
          // Filter on the AGENT-SAFE coarse decision (2-valued allow/deny),
          // derived from the allowlisted `decision` value + result — never the
          // raw operator `gate_decision` detail (which would re-introduce a
          // policy read). The schema enum keeps approve/deny/auto-allow for
          // back-compat, but "approve" and "auto-allow" both map to the coarse
          // "allow" (the approve-vs-auto distinction is a tier signal we do not
          // expose).
          const wantDeny = filterDecision === "deny";
          filtered = filtered.filter((e: AuditEntry) => {
            const view = redactAuditEntryForAgent(e);
            const safeDecision = buildAgentSearchCorpus(e).decision as
              | string
              | undefined;
            const coarse = agentDecision(view, safeDecision);
            return wantDeny ? coarse === "deny" : coarse === "allow";
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

        // Bound by the requested limit AFTER own-identity + filters.
        filtered = filtered.slice(-limit);

        // Format output from the ALLOWLISTED agent view only. The raw entry is
        // never handed to a formatter, so no `tier` / `rule_id` / agent DID /
        // session id / free-text `reason` can ride out through a SIEM record.
        let output: string;

        if (format === "cef") {
          const cefLines = filtered.map((entry: AuditEntry) =>
            formatAsCEF(
              redactAuditEntryForAgent(entry),
              buildAgentSearchCorpus(entry).decision as string | undefined
            )
          );
          output = cefLines.join("\n");
        } else {
          const ocsfObjects = filtered.map((entry: AuditEntry) =>
            formatAsOCSF(
              redactAuditEntryForAgent(entry),
              buildAgentSearchCorpus(entry).decision as string | undefined
            )
          );
          output = JSON.stringify(ocsfObjects, null, 2);
        }

        return {
          content: [
            {
              type: "text" as const,
              text: JSON.stringify({
                format,
                count: filtered.length,
                total_available: totalAvailable,
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
