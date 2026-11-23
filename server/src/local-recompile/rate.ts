/**
 * Per-seat submission rate for the local task tool. Bounded in both
 * dimensions: at most RATE_SEATS_MAX seats (least recently used evicted) and
 * at most SEAT_SUBMIT_PER_HOUR timestamps per seat, so the table's size and
 * the work per call are constant whatever the caller sends.
 */
import { RATE_SEATS_MAX, SEAT_SUBMIT_PER_HOUR, SEAT_SUBMIT_PER_MINUTE } from "./limits.js";
import { MINUTE_MS } from "./store-record.js";

const HOUR_MS = 60 * MINUTE_MS;

export class SeatRateTable {
  // Map iteration order is insertion order; re-inserting on use keeps the least recently used seat first.
  private readonly seats = new Map<string, number[]>();

  get seatCount(): number {
    return this.seats.size;
  }

  timestampsFor(seat: string): number {
    return this.seats.get(seat)?.length ?? 0;
  }

  /** Admit one call at `now`, or refuse it; an admitted call counts against both windows. */
  admit(seat: string, now: number): boolean {
    const kept = (this.seats.get(seat) ?? []).filter((at) => at > now - HOUR_MS && at <= now);
    this.seats.delete(seat);
    const lastMinute = kept.filter((at) => at > now - MINUTE_MS).length;
    const admitted = lastMinute < SEAT_SUBMIT_PER_MINUTE && kept.length < SEAT_SUBMIT_PER_HOUR;
    if (admitted) kept.push(now);
    this.seats.set(seat, kept);
    while (this.seats.size > RATE_SEATS_MAX) {
      const oldest = this.seats.keys().next().value as string;
      this.seats.delete(oldest);
    }
    return admitted;
  }
}
