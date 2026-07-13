/**
 * Agent egress deny-spike watcher (MED-3, confined-agent egress design
 * 2026-07-10 section 5): the runtime tail of the refuse-to-arm guarantee.
 *
 * Refuse-to-arm protects the ARM moment only. After arm, a harness update
 * adding a host, an OAuth host rotation, or an SNI-less fallback path
 * silently re-confines a live 24/7 agent into exactly the non-functionality
 * the egress design exists to prevent -- with the only passive surfacing a
 * deny-and-record candidate list nobody is paged on. This sentinel turns
 * that into an ACTIVE operator-visible alert through the existing finding
 * surface:
 *
 *  1. DENY-SPIKE (primary): the wall already per-flow audits every denial
 *     with rule attribution (`egress_blocked`, layer "l1"). Under an armed
 *     uid-mode wall, OPERATOR flows take the classifier fast-path allow, so
 *     a default-deny denial (null matched rule) is an agent-or-unattributed
 *     flow by construction. A sustained burst of default-deny denials to the
 *     SAME host within the window raises an `alert` finding naming the host,
 *     so the operator can promote-or-refuse it through the observe/learn
 *     Tier-1 gate in one step.
 *  2. PROBE-FAILURE (secondary): the policy daemon's periodic as-agent-uid
 *     liveness probe appends an `egress_probe_failed` audit entry when a
 *     provisioned endpoint stops being reachable as the agent uid; this
 *     sentinel surfaces each as the same alert rail.
 *
 * Castle-walking discipline: read-only against the audit log, NO outbound
 * network, NO blocking -- observation only (the sentinel contract). The
 * enforcement stays in the wall; this watcher only makes silent degradation
 * loud, bounding it to the alert latency instead of "whenever a human reads
 * the candidate list".
 */

import { Sentinel } from "../sentinel.js";
import type { SentinelFinding } from "../types.js";
import {
  attributeFlows,
  filterFlowsByRule,
} from "../../castle-wall/audit/per-rule-report.js";

export const AGENT_EGRESS_SENTINEL_ID = "agent-egress-deny-spike" as const;

/**
 * Default-deny denials to ONE host within the window that trip the alert.
 * "Order of tens of denials to the same host within minutes" (design
 * section 5); a live harness retry loop crosses this within one cycle while
 * an operator's one-off typo does not.
 */
export const DENY_SPIKE_THRESHOLD = 20;

/** Sliding evaluation window (minutes). */
export const DENY_SPIKE_WINDOW_MINUTES = 10;

/** The stored operation tag the policy daemon's periodic as-uid probe writes on failure. */
export const EGRESS_PROBE_FAILED_OPERATION = "egress_probe_failed";

/** Max audit-log entries to consider per evaluation. */
const QUERY_LIMIT = 10_000;

export class AgentEgressWatcher extends Sentinel {
  readonly sentinelId = AGENT_EGRESS_SENTINEL_ID;
  readonly description =
    "Watches the confined agent's default-deny egress denials and the periodic as-agent-uid endpoint probe. " +
    "Raises an alert when a sustained deny burst hits one host (a silently re-confined agent, or drift toward a " +
    "new endpoint) or when a provisioned endpoint stops being reachable as the agent uid.";

  /**
   * Per-host timestamp (epoch ms) of the last emitted deny-spike alert, so a
   * continuing burst re-alerts at most once per window instead of every
   * dispatcher tick. A fresh burst after a quiet window re-alerts.
   */
  private readonly lastAlertedAtMs = new Map<string, number>();

  async evaluate(): Promise<SentinelFinding[]> {
    const ctx = this.requireContext();
    const now = ctx.now();
    const windowMs = DENY_SPIKE_WINDOW_MINUTES * 60 * 1000;
    const sinceIso = new Date(now.getTime() - windowMs).toISOString();

    const queryResult = await ctx.auditLog.query({
      since: sinceIso,
      layer: "l1",
      limit: QUERY_LIMIT,
    });

    const findings: SentinelFinding[] = [];

    // 1. Deny-spike: default-deny (null matched rule) denials grouped by host.
    const flows = attributeFlows(queryResult.entries);
    const defaultDenyFlows = filterFlowsByRule(flows, null).filter(
      (flow) => flow.decision === "deny" && flow.destinationHost !== null,
    );
    const byHost = new Map<string, { count: number; evidence: string[] }>();
    for (const flow of defaultDenyFlows) {
      const host = flow.destinationHost!;
      let bucket = byHost.get(host);
      if (!bucket) {
        bucket = { count: 0, evidence: [] };
        byHost.set(host, bucket);
      }
      bucket.count += 1;
      if (bucket.evidence.length < 50) {
        bucket.evidence.push(`${flow.timestamp}:${flow.operation}`);
      }
    }
    for (const [host, bucket] of byHost.entries()) {
      if (bucket.count < DENY_SPIKE_THRESHOLD) continue;
      const lastAlerted = this.lastAlertedAtMs.get(host);
      if (lastAlerted !== undefined && now.getTime() - lastAlerted < windowMs) continue;
      this.lastAlertedAtMs.set(host, now.getTime());
      findings.push({
        finding_id: "",
        sentinel_id: this.sentinelId,
        severity: "alert",
        summary:
          `sustained default-deny egress burst: ${bucket.count} denials to ${host} in the last ` +
          `${DENY_SPIKE_WINDOW_MINUTES}m. The confined agent may be silently degraded (a needed endpoint is ` +
          `being denied). Review the observe candidates and promote-or-refuse ${host} through the Tier-1 gate.`,
        details: {
          host,
          deny_count: bucket.count,
          window_minutes: DENY_SPIKE_WINDOW_MINUTES,
          threshold: DENY_SPIKE_THRESHOLD,
          signal: "deny-spike",
        },
        observed_at: now.toISOString(),
        evidence_audit_ids: bucket.evidence,
        fortress_id: "",
      });
    }

    // 2. Probe-failure: surface every as-uid endpoint liveness failure the
    //    policy daemon recorded in the window (one finding per failed host,
    //    deduped through the same per-host memo).
    for (const entry of queryResult.entries) {
      if (entry.operation !== EGRESS_PROBE_FAILED_OPERATION) continue;
      const details = entry.details as Record<string, unknown> | undefined;
      const host = typeof details?.host === "string" ? details.host : "(unknown host)";
      const memoKey = `probe:${host}`;
      const lastAlerted = this.lastAlertedAtMs.get(memoKey);
      if (lastAlerted !== undefined && now.getTime() - lastAlerted < windowMs) continue;
      this.lastAlertedAtMs.set(memoKey, now.getTime());
      findings.push({
        finding_id: "",
        sentinel_id: this.sentinelId,
        severity: "alert",
        summary:
          `as-agent-uid egress liveness probe FAILED for ${host}: a provisioned endpoint is no longer ` +
          `reachable as the agent uid. The confined agent may be degraded; investigate before it is ` +
          `noticed as silence.`,
        details: {
          host,
          signal: "as-uid-probe-failure",
          probe_details: details ?? {},
        },
        observed_at: now.toISOString(),
        evidence_audit_ids: [`${entry.timestamp}:${entry.operation}`],
        fortress_id: "",
      });
    }

    return findings;
  }

  /** Reset the per-host alert memo. Tests use this between runs. */
  resetAlertMemo(): void {
    this.lastAlertedAtMs.clear();
  }
}
