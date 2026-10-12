/**
 * Periodic transparency-checkpoint emission.
 *
 * The Castle Wall daemon (and any long-running fortress process that opts
 * in) emits an enforcement checkpoint on a fixed cadence so the published
 * chain stays fresh without operator action. Emission failures are LOUD
 * (reported through onError, surfaced on the operator console by the
 * caller) but never crash the host process, and a refused tick never starts a
 * new checkpoint write after shutdown begins (the emitter is fail-closed).
 */

import { channel } from "node:diagnostics_channel";

import { REKOR_SUBMIT_TIMEOUT_MS } from "./rekor-client.js";

export const TRANSPARENCY_INTERVAL_ENV = "SANCTUARY_TRANSPARENCY_INTERVAL";
export const DEFAULT_TRANSPARENCY_INTERVAL_MS = 6 * 60 * 60 * 1000; // 6h
export const MIN_TRANSPARENCY_INTERVAL_MS = 60_000;
// Must match the emission lock wait used by emitEnforcementCheckpoint in
// ./emitter.ts; shutdown cannot be shorter than a real tick's admission wait.
export const TRANSPARENCY_EMIT_LOCK_TIMEOUT_MS = 5_000;
// 3_000 ms budgets local signer/helper latency plus checkpoint/audit append work;
// Rekor's HTTP submit carries its own named 30_000 ms timeout.
export const TRANSPARENCY_LOCAL_SIGN_APPEND_BUDGET_MS = 3_000;
// 2_000 ms is the shutdown scheduling margin after all named tick work budgets.
export const TRANSPARENCY_STOP_DRAIN_MARGIN_MS = 2_000;
// DEBT(TRANSPARENCY-DRAIN-STRADDLE): the local sign/append term is a named
// estimate, not a code-enforced budget; chain verification and writes already
// admitted before release can still straddle this drain deadline.
// Shutdown drains to the named estimate, then releases the daemon's master
// session; writes that begin after that release are refused by the
// master-write barrier.
export const TRANSPARENCY_STOP_DRAIN_DEADLINE_MS =
  TRANSPARENCY_EMIT_LOCK_TIMEOUT_MS +
  REKOR_SUBMIT_TIMEOUT_MS +
  TRANSPARENCY_LOCAL_SIGN_APPEND_BUDGET_MS +
  TRANSPARENCY_STOP_DRAIN_MARGIN_MS;

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
  emit: (state: TransparencySchedulerAbortState) => Promise<unknown>;
  /** Invoked with every tick failure; must not throw. */
  onError: (err: unknown) => void;
  /** Test hooks. */
  setIntervalFn?: typeof setInterval;
  clearIntervalFn?: typeof clearInterval;
  captureAbortState?: (state: TransparencySchedulerAbortState) => void;
}

export interface TransparencySchedulerHandle {
  stop(): Promise<void>;
}

export class TransparencySchedulerAbortedError extends Error {
  constructor(phase: string) {
    super(`transparency checkpoint emission aborted before ${phase}`);
    this.name = "TransparencySchedulerAbortedError";
  }
}

const TRANSPARENCY_SCHEDULER_ABORT_STATE_MINT = Symbol(
  "TransparencySchedulerAbortState.mint"
);
// Must match TRANSPARENCY_ABORT_STATE_CHECK_DIAGNOSTIC_CHANNEL in
// ../../test/helpers/transparency-abort-checks.ts; subscribers observe guard
// coverage only and cannot change the fail-closed decision below.
const TRANSPARENCY_ABORT_STATE_CHECK_DIAGNOSTIC_CHANNEL =
  "sanctuary.transparency.abort-state-check";
const transparencyAbortStateChecks = channel(
  TRANSPARENCY_ABORT_STATE_CHECK_DIAGNOSTIC_CHANNEL
);

export class TransparencySchedulerAbortState {
  readonly #brand = true;
  readonly #isAborted: () => boolean;

  constructor(
    mint: symbol,
    isAborted: () => boolean
  ) {
    // INVARIANT (shutdown/key custody): the constructor itself authenticates
    // the module-private mint, so Reflect.construct/subclasses cannot create a
    // branded state outside this module.
    if (mint !== TRANSPARENCY_SCHEDULER_ABORT_STATE_MINT) {
      throw new TransparencySchedulerAbortedError("abort state authentication");
    }
    this.#isAborted = isAborted;
  }

  get aborted(): boolean {
    return this.#isAborted();
  }

  static assertNotAborted(
    value: unknown,
    phase: string
  ): void {
    // INVARIANT (shutdown/key custody): the abort state is minted only by this
    // module; a same-shape object must fail closed before any guarded key use.
    if (
      typeof value !== "object" ||
      value === null ||
      !(#brand in value)
    ) {
      throw new TransparencySchedulerAbortedError(phase);
    }
    transparencyAbortStateChecks.publish({ state: value, phase });
    if (value.#isAborted()) {
      throw new TransparencySchedulerAbortedError(phase);
    }
  }
}

Object.freeze(TransparencySchedulerAbortState);

export const TRANSPARENCY_NEVER_ABORTED: TransparencySchedulerAbortState =
  Object.freeze(
    new TransparencySchedulerAbortState(
      TRANSPARENCY_SCHEDULER_ABORT_STATE_MINT,
      () => false
    )
  ) as TransparencySchedulerAbortState;

function createSchedulerAbortState(
  isAborted: () => boolean
): TransparencySchedulerAbortState {
  return new TransparencySchedulerAbortState(
    TRANSPARENCY_SCHEDULER_ABORT_STATE_MINT,
    isAborted
  );
}

export function startTransparencyScheduler(
  options: TransparencySchedulerOptions
): TransparencySchedulerHandle {
  const setIntervalFn = options.setIntervalFn ?? setInterval;
  const clearIntervalFn = options.clearIntervalFn ?? clearInterval;
  let inFlight: Promise<void> | undefined;
  let stopped = false;
  let aborted = false;
  const abortState = createSchedulerAbortState(() => aborted);
  options.captureAbortState?.(abortState);
  const timer = setIntervalFn(() => {
    if (inFlight !== undefined || stopped || aborted) return; // never overlap emissions
    inFlight = options
      .emit(abortState)
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
      // but only to the named estimate deadline; after that the daemon drops
      // its reader and writes that begin later fail closed through the storage
      // barrier.
      const current = inFlight;
      if (current === undefined) {
        // The caller releases master custody after stop() resolves; every
        // production key-use site relies on this flag already being raised.
        aborted = true;
        return;
      }
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
        // The caller releases master custody after stop() resolves; every
        // production key-use site relies on this flag already being raised.
        aborted = true;
        if (drainTimer !== undefined) clearTimeout(drainTimer);
      }
    },
  };
}
