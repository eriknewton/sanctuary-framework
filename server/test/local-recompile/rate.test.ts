// fail-before-exempt: new module; base has no rate table.
import { describe, expect, it } from "vitest";
import { RATE_SEATS_MAX, SEAT_SUBMIT_PER_HOUR, SEAT_SUBMIT_PER_MINUTE } from "../../src/local-recompile/limits.js";
import { SeatRateTable } from "../../src/local-recompile/rate.js";

const MINUTE = 60_000;
const HOUR = 60 * MINUTE;

describe("local task seat rate", () => {
  it("admits four calls a minute and twenty an hour per seat", () => {
    const table = new SeatRateTable();
    const t0 = 1_000_000;
    const minute = Array.from({ length: SEAT_SUBMIT_PER_MINUTE + 1 }, () => table.admit("agent:a", t0));
    expect(minute).toEqual([true, true, true, true, false]);
    expect(table.admit("agent:a", t0 + MINUTE + 1)).toBe(true);
    const hourly = new SeatRateTable();
    const admitted = Array.from({ length: SEAT_SUBMIT_PER_HOUR + 5 }, (_, i) => hourly.admit("agent:a", t0 + i * 2 * MINUTE));
    expect(admitted.filter(Boolean)).toHaveLength(SEAT_SUBMIT_PER_HOUR);
    expect(hourly.admit("agent:a", t0 + HOUR + 1)).toBe(true);
  });

  it("a refused call does not count", () => {
    const table = new SeatRateTable();
    for (let i = 0; i < 100; i += 1) table.admit("agent:a", 5_000);
    expect(table.timestampsFor("agent:a")).toBe(SEAT_SUBMIT_PER_MINUTE);
  });

  it("stays bounded in seats and timestamps under a flood of seats and calls", () => {
    const table = new SeatRateTable();
    const started = performance.now();
    for (let i = 0; i < 20_000; i += 1) table.admit(`agent:seat-${i % 500}`, i * 1_000);
    const elapsed = performance.now() - started;
    expect(table.seatCount).toBe(RATE_SEATS_MAX);
    for (let i = 0; i < 500; i += 1) expect(table.timestampsFor(`agent:seat-${i}`)).toBeLessThanOrEqual(SEAT_SUBMIT_PER_HOUR);
    // Constant work per call: 20,000 calls finish far inside a second.
    expect(elapsed).toBeLessThan(1_000);
  });

  it("evicts the least recently used seat", () => {
    const table = new SeatRateTable();
    for (let i = 0; i < RATE_SEATS_MAX; i += 1) table.admit(`agent:${i}`, 1);
    table.admit("agent:0", 2);
    table.admit("agent:new", 3);
    expect(table.timestampsFor("agent:0")).toBe(2);
    expect(table.timestampsFor("agent:1")).toBe(0);
  });
});
