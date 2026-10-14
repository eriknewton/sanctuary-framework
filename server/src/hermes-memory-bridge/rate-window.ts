export type HermesRateWindowAdmission =
  | { readonly allowed: true }
  | { readonly allowed: false; readonly reason: "rate_limited" };

export class HermesRateWindow {
  private readonly timestamps: number[];
  private nextIndex = 0;
  private count = 0;
  private lastNowMs = Number.NEGATIVE_INFINITY;

  constructor(
    private readonly limit: number,
    private readonly windowMs: number,
  ) {
    if (!Number.isSafeInteger(limit) || limit < 1) {
      throw new Error("Hermes rate window limit must be a positive integer");
    }
    if (!Number.isSafeInteger(windowMs) || windowMs < 1) {
      throw new Error("Hermes rate window duration must be a positive integer");
    }
    this.timestamps = new Array<number>(limit);
  }

  get retainedCount(): number {
    return this.count;
  }

  admit(nowMs: number): HermesRateWindowAdmission {
    const now = this.clampNow(nowMs);
    this.prune(now);
    if (this.count >= this.limit) {
      return { allowed: false, reason: "rate_limited" };
    }
    this.timestamps[(this.nextIndex + this.count) % this.limit] = now;
    this.count += 1;
    return { allowed: true };
  }

  check(nowMs: number): HermesRateWindowAdmission {
    const now = this.clampNow(nowMs);
    this.prune(now);
    if (this.count >= this.limit) return { allowed: false, reason: "rate_limited" };
    return { allowed: true };
  }

  record(nowMs: number): void {
    const admitted = this.admit(nowMs);
    if (!admitted.allowed) {
      throw new Error("Hermes rate window record requires available capacity");
    }
  }

  private clampNow(nowMs: number): number {
    const finiteNow = Number.isFinite(nowMs) ? nowMs : this.lastNowMs;
    const now = Math.max(finiteNow, this.lastNowMs);
    this.lastNowMs = now;
    return now;
  }

  private prune(nowMs: number): void {
    // The ring retains only admitted timestamps still inside the window, so memory stays O(limit).
    while (this.count > 0) {
      const oldest = this.timestamps[this.nextIndex];
      if (oldest === undefined || nowMs - oldest < this.windowMs) return;
      this.timestamps[this.nextIndex] = undefined as unknown as number;
      this.nextIndex = (this.nextIndex + 1) % this.limit;
      this.count -= 1;
    }
    if (this.count === 0) this.nextIndex = 0;
  }
}
