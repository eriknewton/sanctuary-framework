// The verification limits are derived, tighten-only, and bound the unverified candidates one recall holds.
import { expect, it } from "vitest";
import {
  HermesRecallBudget,
  HermesRecallCandidateHeap,
  RECALL_MAX_PASSAGES,
  RECALL_VERIFY_CANDIDATES,
  RECALL_VERIFY_RESERVE_MS,
  RECALL_WALL_BUDGET_MS,
  compareRecallCandidates,
  type HermesRecallCandidate,
} from "../../src/hermes-memory-bridge/recall.js";

const signal = () => new AbortController().signal;
const candidate = (n: number, distinct = 1): HermesRecallCandidate => ({ passage_id: `p${String(n).padStart(3, "0")}`,
  created_at: "2026-11-01T00:00:00.000Z", instant: 0, excerpt: `excerpt ${n}`, distinct, occurrences: n });

it("derives the candidate and reserve limits from the passage limit", () => {
  expect(RECALL_VERIFY_CANDIDATES).toBe(RECALL_MAX_PASSAGES + 5);
  expect(RECALL_VERIFY_CANDIDATES).toBe(8);
  expect(RECALL_VERIFY_RESERVE_MS).toBe(RECALL_VERIFY_CANDIDATES * 25);
  expect(RECALL_VERIFY_RESERVE_MS).toBe(200);
  const limits = new HermesRecallBudget("alpha", () => 0, signal()).limits;
  expect(limits.verifyCandidates).toBe(RECALL_VERIFY_CANDIDATES);
  expect(limits.verifyReserveMs).toBe(RECALL_VERIFY_RESERVE_MS);
});

it.each(["verifyCandidates", "verifyReserveMs"] as const)("accepts only a tighter %s", key => {
  const production = key === "verifyCandidates" ? RECALL_VERIFY_CANDIDATES : RECALL_VERIFY_RESERVE_MS;
  expect(new HermesRecallBudget("alpha", () => 0, signal(), { [key]: 1 }).limits[key]).toBe(1);
  for (const refused of [production + 1, 0, 1.5, Number.NaN]) {
    expect(() => new HermesRecallBudget("alpha", () => 0, signal(), { [key]: refused })).toThrow(RangeError);
  }
});

it("holds at most the candidate limit, keeps the best in rank order and records the overflow", () => {
  const budget = new HermesRecallBudget("alpha", () => 0, signal());
  const heap = new HermesRecallCandidateHeap<number>(budget);
  const offered = Array.from({ length: 100 }, (_, n) => candidate(n)); // One hundred offers, twelve times the bound.
  for (const item of [...offered].reverse()) heap.offer(item, Number(item.passage_id.slice(1)));
  expect(heap.size).toBe(RECALL_VERIFY_CANDIDATES);
  expect(budget.maximumHeld).toBe(RECALL_VERIFY_CANDIDATES);
  expect(heap.overflowed).toBe(true);
  const taken = [];
  for (let next = heap.take(); next !== undefined; next = heap.take()) taken.push(next);
  expect(taken.map(entry => entry.candidate)).toEqual([...offered].sort(compareRecallCandidates).slice(0, RECALL_VERIFY_CANDIDATES));
  expect(taken.every(entry => entry.bound === Number(entry.candidate.passage_id.slice(1)))).toBe(true);
});

it("does not report an overflow when every scored candidate fits", () => {
  const budget = new HermesRecallBudget("alpha", () => 0, signal());
  const heap = new HermesRecallCandidateHeap<null>(budget);
  for (let n = 0; n < RECALL_VERIFY_CANDIDATES; n++) heap.offer(candidate(n), null);
  expect(heap.overflowed).toBe(false);
  heap.offer(candidate(RECALL_VERIFY_CANDIDATES), null);
  expect(heap.overflowed).toBe(true);
  expect(heap.size).toBe(RECALL_VERIFY_CANDIDATES);
});

it("ends the scan at the reserve and verification at the wall", () => {
  let now = 0;
  const budget = new HermesRecallBudget("alpha", () => now, signal());
  now = RECALL_WALL_BUDGET_MS - RECALL_VERIFY_RESERVE_MS - 1;
  expect(budget.scanning()).toBe(true);
  expect(budget.truncated).toBe(false);
  now += 1;
  expect(budget.scanning()).toBe(false);
  expect(budget.candidate()).toBe(false);
  expect(budget.verifying()).toBe(true);
  now = RECALL_WALL_BUDGET_MS;
  expect(budget.verifying()).toBe(false);
  expect(budget.truncated).toBe(true);
});

it("keeps verifying after the scanned-unit cap ends the scan, and stops for abort", () => {
  const abort = new AbortController();
  const budget = new HermesRecallBudget("alpha", () => 0, abort.signal, { scannedUnits: 4 });
  expect(budget.scan(5)).toBe(false);
  expect(budget.scanning()).toBe(false);
  expect(budget.verifying()).toBe(true);
  abort.abort();
  expect(budget.verifying()).toBe(false);
});
