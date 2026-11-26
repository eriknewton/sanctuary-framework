/**
 * The whole-run deadline and the clock seam it reads.
 *
 * One Deadline is created per run. Every step re-checks it before its evidence
 * is accepted, and the verdict constructor checks it once more, so a step that
 * finishes late, or a response that completes after expiry, can never
 * contribute to `verified`. Expiry aborts the shared signal, which cancels
 * in-flight requests and the archive stream.
 */

export interface Clock {
  /** Monotonic milliseconds. Production: performance.now(). */
  now(): number;
  setTimeout(fire: () => void, ms: number): unknown;
  clearTimeout(handle: unknown): void;
}

export const SYSTEM_CLOCK: Clock = {
  now: () => performance.now(),
  setTimeout: (fire, ms) => {
    const handle = setTimeout(fire, ms);
    // A pending deadline timer must never keep the process alive after the verdict.
    handle.unref();
    return handle;
  },
  clearTimeout: handle => clearTimeout(handle as NodeJS.Timeout),
};

export class Deadline {
  readonly #clock: Clock;
  readonly #expiresAt: number;
  readonly #controller = new AbortController();
  readonly #timer: unknown;

  constructor(clock: Clock, budgetMs: number) {
    this.#clock = clock;
    this.#expiresAt = clock.now() + budgetMs;
    this.#timer = clock.setTimeout(() => this.#controller.abort(), budgetMs);
  }

  /** Aborted at expiry; passed to every request and stream of the run. */
  get signal(): AbortSignal {
    return this.#controller.signal;
  }

  /** Read monotonic time, not only the timer: a timer can fire late, the clock cannot. */
  expired(): boolean {
    if (this.#controller.signal.aborted) return true;
    if (this.#clock.now() >= this.#expiresAt) {
      this.#controller.abort();
      return true;
    }
    return false;
  }

  remainingMs(): number {
    return Math.max(0, this.#expiresAt - this.#clock.now());
  }

  dispose(): void {
    this.#clock.clearTimeout(this.#timer);
  }

  get clock(): Clock {
    return this.#clock;
  }
}
