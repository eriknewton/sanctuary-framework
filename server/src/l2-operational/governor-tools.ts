/**
 * Sanctuary MCP Server — L2 Call Governor MCP Tools
 *
 * Two MCP tools for monitoring and managing the Call Governor:
 * - sanctuary/governor_status — View current counters (Tier 3)
 * - sanctuary/governor_reset — Reset all counters (Tier 1 — requires approval)
 *
 * All operations are audit-logged.
 */

import type { ToolDefinition } from "../router.js";
import { toolResult } from "../router.js";
import type { AuditLog } from "./audit-log.js";
import type { CallGovernor } from "./call-governor.js";

/**
 * Create the Call Governor MCP tools.
 */
export function createGovernorTools(
  governor: CallGovernor,
  auditLog: AuditLog
): { tools: ToolDefinition[] } {
  const tools: ToolDefinition[] = [
    // ── Governor Status ─────────────────────────────────────────────
    {
      name: "governor_status",
      description:
        "View the current Call Governor status including volume counters, " +
        "per-tool rate counts, duplicate cache size, and lifetime counter. " +
        "Use this to monitor tool call consumption, detect potential loops, " +
        "and check how close you are to governance limits. " +
        "The governor protects against runaway tool calls by enforcing " +
        "volume limits, rate limits, duplicate detection, and a session " +
        "lifetime cap.",
      inputSchema: {
        type: "object",
        properties: {},
      },
      handler: async () => {
        const status = governor.getStatus();

        auditLog.append("l2", "governor_status", "system", {
          volume_current: status.volume_current,
          volume_limit: status.volume_limit,
          lifetime_current: status.lifetime_current,
          lifetime_limit: status.lifetime_limit,
          duplicate_cache_size: status.duplicate_cache_size,
          hard_stopped: status.hard_stopped,
        });

        const volumePercent = status.volume_limit > 0
          ? Math.round((status.volume_current / status.volume_limit) * 100)
          : 0;
        const lifetimePercent = status.lifetime_limit > 0
          ? Math.round((status.lifetime_current / status.lifetime_limit) * 100)
          : 0;

        const toolRateEntries = Object.entries(status.rate_by_tool);
        const highRateTools = toolRateEntries
          .filter(([, count]) => count > 10)
          .map(([tool, count]) => `${tool} (${count} calls/min)`);

        return toolResult({
          governor_status: status,
          summary: {
            volume_usage: `${status.volume_current}/${status.volume_limit} (${volumePercent}%)`,
            lifetime_usage: `${status.lifetime_current}/${status.lifetime_limit} (${lifetimePercent}%)`,
            active_tools: toolRateEntries.length,
            cached_duplicates: status.duplicate_cache_size,
          },
          warnings: [
            ...(status.hard_stopped
              ? ["HARD STOP: Lifetime limit reached. Use sanctuary/governor_reset to continue."]
              : []),
            ...(volumePercent > 80
              ? [`Volume usage at ${volumePercent}% — approaching limit.`]
              : []),
            ...(lifetimePercent > 80
              ? [`Lifetime usage at ${lifetimePercent}% — approaching hard stop.`]
              : []),
            ...(highRateTools.length > 0
              ? [`High-rate tools detected: ${highRateTools.join(", ")}`]
              : []),
          ],
          guidance: status.hard_stopped
            ? "The governor has stopped all proxied tool calls because the session " +
              "lifetime limit was reached. Use sanctuary/governor_reset (requires " +
              "human approval) to reset counters and resume."
            : "The governor is monitoring all proxied tool calls. Counters reset " +
              "automatically on server restart.",
        });
      },
    },

    // ── Governor Reset ──────────────────────────────────────────────
    {
      name: "governor_reset",
      description:
        "Reset all Call Governor counters: volume window, per-tool rate " +
        "windows, duplicate cache, and lifetime counter. This clears the " +
        "hard stop if the lifetime limit was reached. " +
        "This is a Tier 1 operation — requires human approval because it " +
        "removes all runtime governance state and could allow previously " +
        "blocked behavior to resume.",
      inputSchema: {
        type: "object",
        properties: {
          confirm: {
            type: "boolean",
            description:
              "Must be true to confirm the reset. This clears all governor " +
              "state including the lifetime counter.",
          },
        },
        required: ["confirm"],
      },
      handler: async (args) => {
        const confirm = args.confirm as boolean;

        if (!confirm) {
          return toolResult({
            error: "confirmation_required",
            message:
              "Set confirm: true to reset all governor counters. " +
              "This will clear volume limits, rate tracking, duplicate cache, " +
              "and the lifetime counter.",
          });
        }

        // Capture pre-reset state for audit
        const preResetStatus = governor.getStatus();

        governor.reset();

        const postResetStatus = governor.getStatus();

        auditLog.append("l2", "governor_reset", "system", {
          pre_reset: {
            volume_current: preResetStatus.volume_current,
            lifetime_current: preResetStatus.lifetime_current,
            duplicate_cache_size: preResetStatus.duplicate_cache_size,
            hard_stopped: preResetStatus.hard_stopped,
          },
          post_reset: {
            volume_current: postResetStatus.volume_current,
            lifetime_current: postResetStatus.lifetime_current,
            duplicate_cache_size: postResetStatus.duplicate_cache_size,
            hard_stopped: postResetStatus.hard_stopped,
          },
        });

        return toolResult({
          reset: true,
          previous_state: {
            lifetime_calls: preResetStatus.lifetime_current,
            was_hard_stopped: preResetStatus.hard_stopped,
            volume_at_reset: preResetStatus.volume_current,
            cached_duplicates_cleared: preResetStatus.duplicate_cache_size,
          },
          current_state: postResetStatus,
          message:
            "All governor counters have been reset. " +
            (preResetStatus.hard_stopped
              ? "Hard stop has been cleared — proxied tool calls will resume."
              : "Volume, rate, duplicate, and lifetime counters are now at zero."),
        });
      },
    },
  ];

  return { tools };
}
