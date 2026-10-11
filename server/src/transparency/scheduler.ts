/**
 * Periodic transparency-checkpoint emission.
 *
 * The Castle Wall daemon (and any long-running fortress process that opts
 * in) emits an enforcement checkpoint on a fixed cadence so the published
 * chain stays fresh without operator action. Emission failures are LOUD
 * (reported through onError, surfaced on the operator console by the
 * caller) but never crash the host process, and a failed tick never
 * persists anything (the emitter is fail-closed).
 */

export const TRANSPARENCY_INTERVAL_ENV = "SANCTUARY_TRANSPARENCY_INTERVAL";
export const DEFAULT_TRANSPARENCY_INTERVAL_MS = 6 * 60 * 60 * 1000; // 6h
export const MIN_TRANSPARENCY_INTERVAL_MS = 60_000;
// 30_000 ms = the 60_000 ms minimum checkpoint cadence divided by two; shutdown
// drains an entered tick briefly, then releases the daemon's master session so
// any late storage write is refused by the master-write barrier.
export const TRANSPARENCY_STOP_DRAIN_DEADLINE_MS =
  MIN_TRANSPARENCY_INTERVAL_MS / 2;

/**
 * Parse the cadence config. Accepts "off"/"0" (disabled), plain
 * milliseconds, or `<n>s|m|h|d`. Invalid values throw (a misconfigured
 * cadence must not silently fall back to some other cadence).
 */
export function parseTransparencyInterval(
  value: string | undefined
): number | null {
  if (value === undefined || value.trim() === "") {
    return DEFAULT_TRANSPARENCY_INTERVAL_MS;
  }
  const trimmed = value.trim().toLowerCase();
  if (trimmed === "off" || trimmed === "0" || trimmed === "disabled") {
    return null;
  }
  const match = /^(\d+)(ms|s|m|h|d)?$/.exec(trimmed);
  if (!match) {
    throw new Error(
      `invalid ${TRANSPARENCY_INTERVAL_ENV} value "${value}": use "off", milliseconds, or <n>s|m|h|d`
    );
  }
  const amount = Number(match[1]);
  const unit = match[2] ?? "ms";
  const multiplier =
    unit === "ms" ? 1 :
    unit === "s" ? 1_000 :
    unit === "m" ? 60_000 :
    unit === "h" ? 3_600_000 :
    86_400_000;
  const ms = amount * multiplier;
  if (!Number.isSafeInteger(ms) || ms < MIN_TRANSPARENCY_INTERVAL_MS) {
    throw new Error(
      `invalid ${TRANSPARENCY_INTERVAL_ENV} value "${value}": minimum interval is ${MIN_TRANSPARENCY_INTERVAL_MS}ms (use "off" to disable)`
    );
  }
  return ms;
}

export interface TransparencySchedulerOptions {
  intervalMs: number;
  /** Emits one checkpoint; throws on failure (the emitter is fail-closed). */
  emit: () => Promise<unknown>;
  /** Invoked with every tick failure; must not throw. */
  onError: (err: unknown) => void;
  /** Test hooks. */
  setIntervalFn?: typeof setInterval;
  clearIntervalFn?: typeof clearInterval;
}

export interface TransparencySchedulerHandle {
  stop(): Promise<void>;
}

export function startTransparencyScheduler(
  options: TransparencySchedulerOptions
): TransparencySchedulerHandle {
  const setIntervalFn = options.setIntervalFn ?? setInterval;
  const clearIntervalFn = options.clearIntervalFn ?? clearInterval;
  let inFlight: Promise<void> | undefined;
  let stopped = false;
  const timer = setIntervalFn(() => {
    if (inFlight !== undefined || stopped) return; // never overlap emissions
    inFlight = options
      .emit()
      .then(() => undefined)
      .catch((err) => {
        try {
          options.onError(err);
        } catch {
          // onError must not take the scheduler down.
        }
      })
      .finally(() => {
        inFlight = undefined;
      });
  }, options.intervalMs);
  // Never keep the host process alive solely for checkpointing.
  if (typeof (timer as NodeJS.Timeout).unref === "function") {
    (timer as NodeJS.Timeout).unref();
  }
  return {
    async stop() {
      stopped = true;
      clearIntervalFn(timer);
      // Shutdown drains a tick that already entered its master-derived writes,
      // but only to the named deadline; after that the daemon drops its reader
      // and late writes fail closed through the storage barrier.
      const current = inFlight;
      if (current === undefined) return;
      let drainTimer: NodeJS.Timeout | undefined;
      try {
        await Promise.race([
          current,
          new Promise<void>((resolve) => {
            drainTimer = setTimeout(resolve, TRANSPARENCY_STOP_DRAIN_DEADLINE_MS);
            drainTimer.unref?.();
          }),
        ]);
      } finally {
        if (drainTimer !== undefined) clearTimeout(drainTimer);
      }
    },
  };
}
