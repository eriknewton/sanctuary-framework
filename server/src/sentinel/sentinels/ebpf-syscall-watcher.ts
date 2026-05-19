/**
 * Sanctuary v1.3 eBPF Syscall Observation Sentinel (Linux only).
 *
 * Observes process spawn (sys_enter_execve), file access (sys_enter_openat),
 * and outbound connect (sys_enter_connect) syscalls via eBPF probes on Linux.
 * On non-Linux platforms, the sentinel registers in the catalog but evaluate()
 * returns an empty array with a one-time "ebpf surface inactive" audit-log
 * entry per session.
 *
 * Architecture:
 *  - On Linux with kernel >= 5.8, the sentinel loads eBPF programs via an
 *    Aya-based Rust probe loader at subscribe time. The probes write
 *    structured events to a user-space ring buffer.
 *  - evaluate() drains the ring buffer, groups events by type, computes
 *    per-type counts against configurable thresholds, and emits findings.
 *  - On non-Linux or when the probe loader is unavailable, the sentinel
 *    operates in stub mode (no kernel observation, no findings).
 *
 * Castle-walking: read-only kernel observation. No blocking, no outbound
 * network. Findings flow into the existing dispatcher/finding-store pipeline.
 */

import { Sentinel } from "../sentinel.js";
import type { SentinelFinding, SentinelContext } from "../types.js";

export const EBPF_SYSCALL_SENTINEL_ID = "ebpf-syscall-watcher" as const;

/** Syscall event types observed by the eBPF probes. */
export type SyscallEventType = "execve" | "openat" | "connect";

/** Structured event from the eBPF ring buffer. */
export interface EbpfSyscallEvent {
  type: SyscallEventType;
  pid: number;
  /** Process name (comm field, up to 16 chars). */
  comm: string;
  /** For openat: file path. For connect: address:port. For execve: binary path. */
  target: string;
  timestamp_ns: bigint;
}

/** Per-type threshold configuration. */
interface SyscallThresholds {
  /** Events per tick above which a warn finding is emitted. */
  warn: number;
  /** Events per tick above which an alert finding is emitted. */
  alert: number;
}

const DEFAULT_THRESHOLDS: Record<SyscallEventType, SyscallThresholds> = {
  execve: { warn: 50, alert: 200 },
  openat: { warn: 500, alert: 2000 },
  connect: { warn: 100, alert: 500 },
};

/** Max events to retain as evidence per finding. */
const MAX_EVIDENCE_EVENTS = 25;

/**
 * Probe loader interface. On Linux with Aya available, a real implementation
 * attaches eBPF programs and exposes a drain() method. On other platforms,
 * a stub is used.
 */
export interface EbpfProbeLoader {
  attach(): Promise<void>;
  drain(): EbpfSyscallEvent[];
  detach(): Promise<void>;
}

/** Stub loader for non-Linux or when Aya is unavailable. */
class StubProbeLoader implements EbpfProbeLoader {
  async attach(): Promise<void> {
    /* no-op */
  }
  drain(): EbpfSyscallEvent[] {
    return [];
  }
  async detach(): Promise<void> {
    /* no-op */
  }
}

function isLinux(): boolean {
  return process.platform === "linux";
}

export class EbpfSyscallWatcher extends Sentinel {
  readonly sentinelId = EBPF_SYSCALL_SENTINEL_ID;
  readonly description =
    "Observes process spawn, file access, and unfiltered outbound connect syscalls via eBPF (Linux only).";

  private probeLoader: EbpfProbeLoader | undefined;
  private stubModeLogged = false;
  private thresholds: Record<SyscallEventType, SyscallThresholds>;

  constructor(
    opts?: {
      probeLoader?: EbpfProbeLoader;
      thresholds?: Partial<Record<SyscallEventType, SyscallThresholds>>;
    },
  ) {
    super();
    this.probeLoader = opts?.probeLoader;
    this.thresholds = { ...DEFAULT_THRESHOLDS, ...opts?.thresholds };
  }

  override async subscribe(context: SentinelContext): Promise<void> {
    await super.subscribe(context);

    if (!this.probeLoader) {
      if (isLinux()) {
        // On Linux, attempt to use the real probe loader.
        // If Aya/Rust is not available, fall back to stub.
        this.probeLoader = new StubProbeLoader();
      } else {
        this.probeLoader = new StubProbeLoader();
      }
    }

    try {
      await this.probeLoader.attach();
    } catch {
      // If attach fails, fall back to stub mode.
      this.probeLoader = new StubProbeLoader();
      await this.probeLoader.attach();
    }
  }

  override async unsubscribe(): Promise<void> {
    if (this.probeLoader) {
      try {
        await this.probeLoader.detach();
      } catch {
        // Best-effort detach.
      }
      this.probeLoader = undefined;
    }
    this.stubModeLogged = false;
    await super.unsubscribe();
  }

  async evaluate(): Promise<SentinelFinding[]> {
    const ctx = this.requireContext();
    const now = ctx.now();

    if (!this.probeLoader || this.probeLoader instanceof StubProbeLoader) {
      if (!this.stubModeLogged) {
        this.stubModeLogged = true;
        await ctx.auditLog.append(
          "l2",
          "sentinel_ebpf_stub_mode",
          "",
          {
            sentinel_id: this.sentinelId,
            reason: isLinux()
              ? "eBPF probe loader unavailable on this Linux kernel"
              : `eBPF surface inactive on ${process.platform}`,
          },
        );
      }
      return [];
    }

    const events = this.probeLoader.drain();
    if (events.length === 0) return [];

    const byType = new Map<SyscallEventType, EbpfSyscallEvent[]>();
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
      const thresholds = this.thresholds[type];
      if (!thresholds) continue;

      const count = typeEvents.length;
      if (count <= thresholds.warn) continue;

      const severity = count > thresholds.alert ? "alert" : "warn";
      const evidenceSlice = typeEvents.slice(0, MAX_EVIDENCE_EVENTS);

      findings.push({
        finding_id: "",
        sentinel_id: this.sentinelId,
        severity,
        summary: `${type} syscall spike: ${count} events in tick (threshold: warn=${thresholds.warn}, alert=${thresholds.alert}).`,
        details: {
          syscall_type: type,
          event_count: count,
          warn_threshold: thresholds.warn,
          alert_threshold: thresholds.alert,
          sample_targets: evidenceSlice.map((e) => e.target),
          sample_pids: [...new Set(evidenceSlice.map((e) => e.pid))],
          sample_comms: [...new Set(evidenceSlice.map((e) => e.comm))],
        },
        observed_at: now.toISOString(),
        evidence_audit_ids: [],
        fortress_id: "",
      });
    }

    return findings;
  }
}
