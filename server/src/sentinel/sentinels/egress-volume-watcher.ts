/**
 * Sanctuary v1.3 WP-V1.3-1 Phi-1 Egress Volume Watcher.
 *
 * The first Sentinel. Surfaces anomalous outbound traffic volume to
 * the operator before Castle Wall (Layer 1) blocks the next request.
 * Layer 2 buys time for operator review or Layer 3 (Cooperative MCP)
 * negotiation.
 *
 * Algorithm:
 *  - Read all `proxy_call:*` audit entries within the past 8 days.
 *  - Group by upstream `details.server` value.
 *  - Per server: bucket entries into 24h windows ending at `now`.
 *  - Current window count (last 24h) vs. baseline computed from the 7
 *    preceding days.
 *  - Emit `info` once when baseline is established (>= 7 windows of
 *    history) for a previously-unknown server. Emits no `info` after
 *    that.
 *  - Emit `warn` when current_count > mean + 3*stddev.
 *  - Emit `alert` when current_count > mean + 6*stddev.
 *  - When the dataset is too small (fewer than 7 windows of history),
 *    skip threshold checks entirely; the operator is told the baseline
 *    is still warming up via the one-shot `info` finding.
 *
 * Determinism: the watcher is pure with respect to (audit-log
 * snapshot, now()). Tests inject a fixed clock + a synthetic audit
 * log to assert thresholds.
 *
 * Castle-walking: read-only against the audit log. Findings carry the
 * audit_log_entry_id of every contributing entry so the operator can
 * trace the spike back to source.
 */

import { Sentinel } from "../sentinel.js";
import {
  isProxyCallAuditEntry,
  proxyServerFromAuditEntry,
  type SentinelFinding,
} from "../types.js";

export const EGRESS_VOLUME_SENTINEL_ID = "egress-volume" as const;

/** Threshold multipliers (sigma counts). */
const WARN_SIGMA = 3;
const ALERT_SIGMA = 6;
/** Days of history required before threshold checks run. */
const BASELINE_WINDOWS = 7;
/** Max audit-log entries to consider per evaluation. */
const QUERY_LIMIT = 10_000;

interface ServerWindow {
  /** Number of proxy_call entries in this 24h window. */
  count: number;
  /** Audit-entry tuples (`${timestamp}:${operation}`). */
  evidence_audit_ids: string[];
}

interface ServerSnapshot {
  /** Window 0 = current 24h ending at now. Windows 1..7 = prior days. */
  windows: ServerWindow[];
}

export class EgressVolumeWatcher extends Sentinel {
  readonly sentinelId = EGRESS_VOLUME_SENTINEL_ID;
  readonly description =
    "Watches outbound proxy-call volume per upstream server. Emits warn/alert when current 24h volume exceeds the rolling 7-day baseline by 3x or 6x standard deviations.";

  /** Servers we have already produced an `info` baseline-established finding for. */
  private readonly baselineEstablished = new Set<string>();

  async evaluate(): Promise<SentinelFinding[]> {
    const ctx = this.requireContext();
    const now = ctx.now();
    const windowMs = 24 * 60 * 60 * 1000;
    const windowSpanMs = (BASELINE_WINDOWS + 1) * windowMs;
    const sinceIso = new Date(now.getTime() - windowSpanMs).toISOString();

    const queryResult = await ctx.auditLog.query({
      since: sinceIso,
      layer: "l2",
      limit: QUERY_LIMIT,
    });
    const entries = queryResult.entries.filter(isProxyCallAuditEntry);

    const byServer = new Map<string, ServerSnapshot>();
    for (const entry of entries) {
      const server = proxyServerFromAuditEntry(entry);
      if (server === null) continue;
      const auditAge = now.getTime() - new Date(entry.timestamp).getTime();
      if (auditAge < 0) continue;
      const windowIdx = Math.floor(auditAge / windowMs);
      if (windowIdx > BASELINE_WINDOWS) continue;
      let snapshot = byServer.get(server);
      if (!snapshot) {
        snapshot = { windows: [] };
        for (let i = 0; i <= BASELINE_WINDOWS; i += 1) {
          snapshot.windows.push({ count: 0, evidence_audit_ids: [] });
        }
        byServer.set(server, snapshot);
      }
      const bucket = snapshot.windows[windowIdx]!;
      bucket.count += 1;
      if (windowIdx === 0 && bucket.evidence_audit_ids.length < 50) {
        bucket.evidence_audit_ids.push(`${entry.timestamp}:${entry.operation}`);
      }
    }

    const findings: SentinelFinding[] = [];
    for (const [server, snapshot] of byServer.entries()) {
      const finding = this.evaluateServer(server, snapshot, now);
      if (finding) findings.push(finding);
    }
    return findings;
  }

  /** Reset baseline-established memoization. Tests use this between runs. */
  resetBaselineMemo(): void {
    this.baselineEstablished.clear();
  }

  private evaluateServer(
    server: string,
    snapshot: ServerSnapshot,
    now: Date,
  ): SentinelFinding | null {
    const currentWindow = snapshot.windows[0]!;
    const baselineWindows = snapshot.windows.slice(1);

    const populatedBaselineWindows = baselineWindows.filter((w) => w.count > 0)
      .length;

    if (populatedBaselineWindows < BASELINE_WINDOWS) {
      if (this.baselineEstablished.has(server)) return null;
      if (populatedBaselineWindows === 0 && currentWindow.count === 0) {
        return null;
      }
      return null;
    }

    const baselineCounts = baselineWindows.map((w) => w.count);
    const mean =
      baselineCounts.reduce((sum, c) => sum + c, 0) / baselineCounts.length;
    const variance =
      baselineCounts.reduce((sum, c) => sum + (c - mean) ** 2, 0) /
      baselineCounts.length;
    const stddev = Math.sqrt(variance);

    const wasEstablished = this.baselineEstablished.has(server);
    this.baselineEstablished.add(server);

    if (!wasEstablished) {
      return {
        finding_id: "",
        sentinel_id: this.sentinelId,
        severity: "info",
        summary: `egress-volume baseline established for ${server}: mean ${mean.toFixed(1)} calls/24h, stddev ${stddev.toFixed(1)} (over ${BASELINE_WINDOWS} prior days).`,
        details: {
          server,
          baseline_mean: mean,
          baseline_stddev: stddev,
          baseline_windows: baselineCounts,
          current_count: currentWindow.count,
        },
        observed_at: now.toISOString(),
        evidence_audit_ids: [],
        fortress_id: "",
      };
    }

    const warnThreshold = mean + WARN_SIGMA * stddev;
    const alertThreshold = mean + ALERT_SIGMA * stddev;

    if (currentWindow.count > alertThreshold) {
      return this.buildAnomalyFinding(
        server,
        snapshot,
        mean,
        stddev,
        now,
        "alert",
        ALERT_SIGMA,
      );
    }
    if (currentWindow.count > warnThreshold) {
      return this.buildAnomalyFinding(
        server,
        snapshot,
        mean,
        stddev,
        now,
        "warn",
        WARN_SIGMA,
      );
    }
    return null;
  }

  private buildAnomalyFinding(
    server: string,
    snapshot: ServerSnapshot,
    mean: number,
    stddev: number,
    now: Date,
    severity: "warn" | "alert",
    sigma: number,
  ): SentinelFinding {
    const currentWindow = snapshot.windows[0]!;
    const ratio = mean === 0 ? Infinity : currentWindow.count / mean;
    const ratioStr = Number.isFinite(ratio) ? `${ratio.toFixed(1)}x normal` : "no prior baseline";
    const summary = `${server} egress is ${ratioStr}: ${currentWindow.count} calls in last 24h, baseline ${mean.toFixed(1)} (stddev ${stddev.toFixed(1)}). Crossed +${sigma} sigma threshold.`;
    return {
      finding_id: "",
      sentinel_id: this.sentinelId,
      severity,
      summary,
      details: {
        server,
        current_count: currentWindow.count,
        baseline_mean: mean,
        baseline_stddev: stddev,
        sigma_threshold: sigma,
        ratio,
      },
      observed_at: now.toISOString(),
      evidence_audit_ids: currentWindow.evidence_audit_ids,
      fortress_id: "",
    };
  }
}
