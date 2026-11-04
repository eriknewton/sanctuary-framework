/** Fixed-size informational accounting for root flows, independent of audit chain state. */

/** Audit-dump operation for cumulative informational root observations. */
// Must match CASTLE_WALL_AUDIT_OPERATIONS in cli/castle-wall.ts.
export const NON_AGENT_FLOW_SUMMARY_OPERATION = "castle_wall_non_agent_flows_observed";

/** Cumulative counters since consumer construction; no per-origin state is retained. */
export interface NonAgentRootFlowCounters {
  root_verified_total: number;
  root_unverified_total: number;
  root_allow_total: number;
  root_drop_total: number;
  summaries_written: number;
  summaries_skipped_in_flight: number;
  summaries_failed: number;
}

/** Allocate the entire counter vocabulary once, regardless of traffic cardinality. */
export function createNonAgentRootFlowCounters(): NonAgentRootFlowCounters {
  return {
    root_verified_total: 0,
    root_unverified_total: 0,
    root_allow_total: 0,
    root_drop_total: 0,
    summaries_written: 0,
    summaries_skipped_in_flight: 0,
    summaries_failed: 0,
  };
}

/** Count one observation in constant space and work; repeated observations count again. */
export function countNonAgentRootFlow(
  counters: NonAgentRootFlowCounters,
  decision: "allow" | "drop",
  verified: boolean,
): void {
  counters[verified ? "root_verified_total" : "root_unverified_total"] += 1;
  counters[decision === "allow" ? "root_allow_total" : "root_drop_total"] += 1;
}
