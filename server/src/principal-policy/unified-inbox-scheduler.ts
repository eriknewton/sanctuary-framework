import type { UnifiedInboxBridge } from "./unified-inbox-bridge.js";

export const UNIFIED_INBOX_SCHEDULER_INTERVAL_MS = 60_000;

export class UnifiedInboxScheduler {
  private timer: ReturnType<typeof setInterval> | null = null;

  constructor(
    private readonly opts: {
      bridge: UnifiedInboxBridge;
      intervalMs?: number;
      now?: () => Date;
    },
  ) {}

  start(): void {
    if (this.timer) return;
    this.timer = setInterval(() => {
      this.tick();
    }, this.opts.intervalMs ?? UNIFIED_INBOX_SCHEDULER_INTERVAL_MS);
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
    return this.opts.bridge.resurfaceDueSnoozes(
      this.opts.now?.() ?? new Date(),
    );
  }
}
