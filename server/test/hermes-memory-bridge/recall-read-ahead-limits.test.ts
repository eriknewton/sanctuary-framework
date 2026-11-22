// The read-ahead window is a derived, tighten-only recall limit, and the read-ahead's stop question changes no budget state.
import { expect, it } from "vitest";
import {
  HermesRecallBudget,
  RECALL_READ_AHEAD_PASSAGES,
  RECALL_READS_PER_SLOT,
  RECALL_VERIFY_RESERVE_MS,
  RECALL_WALL_BUDGET_MS,
} from "../../src/hermes-memory-bridge/recall.js";

const signal = () => new AbortController().signal;

/** Every observable field of a budget, so a change anywhere shows as a difference. */
function snapshot(budget: HermesRecallBudget) {
  return JSON.stringify({ truncated: budget.truncated, candidatesScanned: budget.candidatesScanned,
    unitsScanned: budget.unitsScanned, maximumRetained: budget.maximumRetained, maximumHeld: budget.maximumHeld,
    retainedCount: budget.retainedCount, result: budget.result(), limits: budget.limits });
}

const scannedUnitsCap = 4; // A tightened unit cap small enough to reach with one scan call.
/** One budget per stop condition, each brought to the point where the scan must stop, with truncated still clear. */
function stopped(kind: "abort" | "reserve" | "wall" | "units") {
  let now = 0;
  const abort = new AbortController();
  const budget = new HermesRecallBudget("alpha", () => now, abort.signal, { scannedUnits: scannedUnitsCap });
  if (kind === "abort") abort.abort();
  if (kind === "reserve") now = RECALL_WALL_BUDGET_MS - RECALL_VERIFY_RESERVE_MS;
  if (kind === "wall") now = RECALL_WALL_BUDGET_MS;
  if (kind === "units") expect(budget.scan(scannedUnitsCap)).toBe(true);
  expect(budget.truncated).toBe(false);
  return budget;
}

it.each(["abort", "reserve", "wall", "units"] as const)("scanOpen answers %s without changing the budget", kind => {
  const budget = stopped(kind);
  const before = snapshot(budget);
  expect(budget.scanOpen()).toBe(false);
  expect(snapshot(budget)).toBe(before);
  // Positive control: the commit's own stop check records the stop in the same state.
  expect(budget.scanning()).toBe(false);
  expect(snapshot(budget)).not.toBe(before);
  expect(budget.truncated).toBe(true);
});

it("scanOpen is open, and changes nothing, while the scan may continue", () => {
  let now = 0;
  const budget = new HermesRecallBudget("alpha", () => now, signal());
  now = RECALL_WALL_BUDGET_MS - RECALL_VERIFY_RESERVE_MS - 1;
  const before = snapshot(budget);
  expect(budget.scanOpen()).toBe(true);
  expect(snapshot(budget)).toBe(before);
  expect(budget.scanning()).toBe(true);
  now += 1;
  expect(budget.scanOpen()).toBe(false);
  expect(budget.truncated).toBe(false);
});

it("defaults the window to RECALL_READ_AHEAD_PASSAGES and accepts only a tighter one", () => {
  expect(RECALL_READS_PER_SLOT).toBe(2);
  expect(new HermesRecallBudget("alpha", () => 0, signal()).limits.readAhead).toBe(RECALL_READ_AHEAD_PASSAGES);
  for (let window = 1; window <= RECALL_READ_AHEAD_PASSAGES; window++) {
    expect(new HermesRecallBudget("alpha", () => 0, signal(), { readAhead: window }).limits.readAhead).toBe(window);
  }
  for (const refused of [RECALL_READ_AHEAD_PASSAGES + 1, 0, -1, 1.5, Number.NaN, Number.POSITIVE_INFINITY]) {
    expect(() => new HermesRecallBudget("alpha", () => 0, signal(), { readAhead: refused })).toThrow(RangeError);
  }
});
