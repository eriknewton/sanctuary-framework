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
  stop(): void;
}

export function startTransparencyScheduler(
  options: TransparencySchedulerOptions
): TransparencySchedulerHandle {
  const setIntervalFn = options.setIntervalFn ?? setInterval;
  const clearIntervalFn = options.clearIntervalFn ?? clearInterval;
  let inFlight = false;
  let stopped = false;
  const timer = setIntervalFn(() => {
    if (inFlight || stopped) return; // never overlap emissions
    inFlight = true;
    void options
      .emit()
      .catch((err) => {
        try {
          options.onError(err);
        } catch {
          // onError must not take the scheduler down.
        }
      })
      .finally(() => {
        inFlight = false;
      });
  }, options.intervalMs);
  // Never keep the host process alive solely for checkpointing.
  if (typeof (timer as NodeJS.Timeout).unref === "function") {
    (timer as NodeJS.Timeout).unref();
  }
  return {
    stop() {
      stopped = true;
      clearIntervalFn(timer);
    },
  };
}
