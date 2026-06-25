import type { UnifiedInboxBridge } from "./unified-inbox-bridge.js";

export const UNIFIED_INBOX_SCHEDULER_INTERVAL_MS = 60_000;

/**
 * Architectural decision: dedicated scheduler module for unified-inbox tick.
 *
 * Considered: reusing dashboard SSE keepalives, anomaly pipeline ticks,
 * chat presence/cache timers, and the policy-engine retention sweep.
 * Rejected because those timers are either transport-specific, optional
 * feature-local lifecycles, or agent-policy retention lifecycles rather
 * than the operator inbox lifecycle. Coupling snooze resurface to them
 * would make operator attention state depend on unrelated feature wiring.
 * Coordinator-CTO ratified 2026-05-14 (PR #230 round-2 review).
 *
 * Single-responsibility: this scheduler owns the inbox snooze-resurface tick.
 * Lifecycle: starts at server boot from index.ts; stops on graceful shutdown.
 * Tick interval: 60s (operator doesn't need sub-minute precision for resurface).
 */
export class UnifiedInboxScheduler {
  private timer: ReturnType<typeof setInterval> | null = null;

  constructor(
    private readonly opts: {
      bridge: UnifiedInboxBridge;
      intervalMs?: number;
      now?: () => Date;
      /**
       * Optional additional work to run on each tick, on the SAME operator-inbox
       * cadence. The feature-health observability layer wires its fault-raise
       * evaluation here (see `feature-fault-raise.ts:FeatureFaultRaiser`), so the
       * raise rides the existing operator-attention lifecycle instead of owning a
       * second timer. A rejected/throwing hook never breaks the snooze tick.
       */
      onTick?: () => void | Promise<void>;
    },
  ) {}

  start(): void {
    if (this.timer) return;
    this.timer = setInterval(() => {
      this.tick();
    }, this.opts.intervalMs ?? UNIFIED_INBOX_SCHEDULER_INTERVAL_MS);
    if (typeof this.timer.unref === "function") {
      this.timer.unref();
    }
  }

  stop(): void {
    if (!this.timer) return;
    clearInterval(this.timer);
    this.timer = null;
  }

  isRunning(): boolean {
    return this.timer !== null;
  }

  tick(): number {
    const resurfaced = this.opts.bridge.resurfaceDueSnoozes(
      this.opts.now?.() ?? new Date(),
    );
    if (this.opts.onTick) {
      try {
        const result = this.opts.onTick();
        if (result instanceof Promise) result.catch(() => {});
      } catch {
        // Additional-work hook must never break the snooze tick.
      }
    }
    return resurfaced;
  }
}
