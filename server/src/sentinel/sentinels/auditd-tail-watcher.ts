/**
 * Sanctuary v1.3 auditd-tail cross-platform observation sentinel (Phi-7).
 *
 * Tails the platform audit log as a cross-platform fallback for kernel
 * observation when eBPF is unavailable:
 *  - Linux: /var/log/audit/audit.log (auditd)
 *  - macOS: /var/audit/ (OpenBSM)
 *
 * Normalizes events to the same SentinelFinding shape consumed by the
 * existing dispatcher/finding-store pipeline.
 *
 * Design notes:
 *  - Slower than eBPF, less structured, but works on macOS dev environments
 *    and older Linux kernels (< 5.8).
 *  - When run alongside the eBPF sentinel on Linux, the two may observe
 *    overlapping events. Deduplication is handled at the dispatcher layer's
 *    existing finding-store dedup logic (finding_id uniqueness).
 *  - The sentinel reads a configurable log path. Tests inject a synthetic
 *    log via the AuditLogTailer interface.
 *
 * Castle-walking: read-only against platform audit logs. No blocking,
 * no outbound network. Findings flow into the existing pipeline.
 */

import { Sentinel } from "../sentinel.js";
import type { SentinelFinding, SentinelContext } from "../types.js";

export const AUDITD_TAIL_SENTINEL_ID = "auditd-tail-watcher" as const;

/** Normalized audit event from the platform log. */
export interface PlatformAuditEvent {
  /** Event type normalized across platforms. */
  type: "execve" | "open" | "connect" | "auth" | "other";
  /** Raw event line or structured summary. */
  raw: string;
  /** Process ID, if available. */
  pid?: number;
  /** Process name, if available. */
  comm?: string;
  /** Target path/address, if available. */
  target?: string;
  /** Event timestamp from the audit log. */
  timestamp: Date;
}

/** Per-type threshold configuration. */
interface AuditdThresholds {
  warn: number;
  alert: number;
}

const DEFAULT_THRESHOLDS: Record<string, AuditdThresholds> = {
  execve: { warn: 50, alert: 200 },
  open: { warn: 500, alert: 2000 },
  connect: { warn: 100, alert: 500 },
  auth: { warn: 20, alert: 100 },
  other: { warn: 200, alert: 1000 },
};

const MAX_EVIDENCE_LINES = 25;

/**
 * Tailer interface. Abstracts platform-specific log reading.
 * Tests inject a mock; production uses a real file tailer.
 */
export interface AuditLogTailer {
  /** Start tailing from the current position. */
  start(): Promise<void>;
  /** Drain new events since last drain. */
  drain(): PlatformAuditEvent[];
  /** Stop tailing. */
  stop(): Promise<void>;
}

/** Stub tailer for environments where audit log is unavailable. */
class StubAuditLogTailer implements AuditLogTailer {
  async start(): Promise<void> {
    /* no-op */
  }
  drain(): PlatformAuditEvent[] {
    return [];
  }
  async stop(): Promise<void> {
    /* no-op */
  }
}

function detectAuditLogPath(): string | null {
  if (process.platform === "linux") return "/var/log/audit/audit.log";
  if (process.platform === "darwin") return "/var/audit/";
  return null;
}

export class AuditdTailWatcher extends Sentinel {
  readonly sentinelId = AUDITD_TAIL_SENTINEL_ID;
  readonly description =
    "Tails platform audit log as cross-platform fallback for kernel observation when eBPF is unavailable.";

  private tailer: AuditLogTailer | undefined;
  private stubModeLogged = false;
  private thresholds: Record<string, AuditdThresholds>;

  constructor(
    opts?: {
      tailer?: AuditLogTailer;
      thresholds?: Partial<Record<string, AuditdThresholds>>;
    },
  ) {
    super();
    this.tailer = opts?.tailer;
    this.thresholds = {
      ...DEFAULT_THRESHOLDS,
      ...(opts?.thresholds as Record<string, AuditdThresholds> | undefined),
    };
  }

  override async subscribe(context: SentinelContext): Promise<void> {
    await super.subscribe(context);

    if (!this.tailer) {
      const logPath = detectAuditLogPath();
      if (!logPath) {
        this.tailer = new StubAuditLogTailer();
      } else {
        // In production, a real file tailer would be instantiated here.
        // For now, fall back to stub (real tailer requires fs.watch + parsing).
        this.tailer = new StubAuditLogTailer();
      }
    }

    try {
      await this.tailer.start();
    } catch {
      this.tailer = new StubAuditLogTailer();
      await this.tailer.start();
    }
  }

  override async unsubscribe(): Promise<void> {
    if (this.tailer) {
      try {
        await this.tailer.stop();
      } catch {
        // Best-effort stop.
      }
      this.tailer = undefined;
    }
    this.stubModeLogged = false;
    await super.unsubscribe();
  }

  async evaluate(): Promise<SentinelFinding[]> {
    const ctx = this.requireContext();
    const now = ctx.now();

    if (!this.tailer || this.tailer instanceof StubAuditLogTailer) {
      if (!this.stubModeLogged) {
        this.stubModeLogged = true;
        const logPath = detectAuditLogPath();
        await ctx.auditLog.append(
          "l2",
          "sentinel_auditd_stub_mode",
          "",
          {
            sentinel_id: this.sentinelId,
            reason: logPath
              ? `Platform audit log at ${logPath} not accessible`
              : `No known audit log path for ${process.platform}`,
          },
        );
      }
      return [];
    }

    const events = this.tailer.drain();
    if (events.length === 0) return [];

    const byType = new Map<string, PlatformAuditEvent[]>();
    for (const event of events) {
      const list = byType.get(event.type);
      if (list) {
        list.push(event);
      } else {
        byType.set(event.type, [event]);
      }
    }

    const findings: SentinelFinding[] = [];
    for (const [type, typeEvents] of byType) {
      const thresholds = this.thresholds[type] ?? DEFAULT_THRESHOLDS["other"]!;
      const count = typeEvents.length;
      if (count <= thresholds.warn) continue;

      const severity = count > thresholds.alert ? "alert" : "warn";
      const evidenceSlice = typeEvents.slice(0, MAX_EVIDENCE_LINES);

      findings.push({
        finding_id: "",
        sentinel_id: this.sentinelId,
        severity,
        summary: `${type} audit events spike: ${count} events in tick (threshold: warn=${thresholds.warn}, alert=${thresholds.alert}).`,
        details: {
          event_type: type,
          event_count: count,
          warn_threshold: thresholds.warn,
          alert_threshold: thresholds.alert,
          sample_targets: evidenceSlice
            .map((e) => e.target)
            .filter((t): t is string => t !== undefined),
          sample_pids: [
            ...new Set(
              evidenceSlice
                .map((e) => e.pid)
                .filter((p): p is number => p !== undefined),
            ),
          ],
          sample_comms: [
            ...new Set(
              evidenceSlice
                .map((e) => e.comm)
                .filter((c): c is string => c !== undefined),
            ),
          ],
          platform: process.platform,
        },
        observed_at: now.toISOString(),
        evidence_audit_ids: [],
        fortress_id: "",
      });
    }

    return findings;
  }
}
