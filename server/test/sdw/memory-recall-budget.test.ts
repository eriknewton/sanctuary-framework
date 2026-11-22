// The real encrypted adapter bounds per-call scan work and retained context.
import { describe, expect, it } from "vitest";
import { HermesRecallBudget, RECALL_VERIFY_RESERVE_MS, RECALL_WALL_BUDGET_MS, type HermesRecallLimits } from "../../src/hermes-memory-bridge/recall.js";
import { KeyOrderMemoryStorage, RECALL_TEST_WINDOWS } from "./recall-score-first-fixture.js";
import { TestSdwMemoryBackendAdapter } from "./test-memory-backend.js";

class CountingStorage extends KeyOrderMemoryStorage {
  chunkReads = 0;
  now = 0;
  step = 0;
  beforeRead?: (key: string) => void;
  listings = 0;
  override async list(namespace: string, prefix?: string) { this.listings++; return super.list(namespace, prefix); }
  override async read(namespace: string, key: string) {
    this.beforeRead?.(key);
    this.now += this.step;
    if (key.startsWith("chunk.")) this.chunkReads++;
    return super.read(namespace, key);
  }
}
async function fixture() {
  const storage = new CountingStorage();
  const adapter = new TestSdwMemoryBackendAdapter({ storage, masterKey: new Uint8Array(32).fill(17),
    fortressId: "recall-fixture", ownerRef: "agent", now: () => "2026-11-01T00:00:00.000Z", maxChunkChars: 8 }); // Eight-unit chunks make the read bound measurable.
  for (let n = 0; n < 15; n++) await adapter.insertPassage({ passage_id: `p${String(n).padStart(2, "0")}`,
    text: n === 0 ? "board meeting ".repeat(100) : "board meeting" }, "user_content");
  storage.chunkReads = 0;
  return { storage, adapter };
}
describe.each(RECALL_TEST_WINDOWS)("read-ahead window %i", readAhead => {
  const budgetOf = (query: string, nowMs: () => number, signal: AbortSignal, tighten: Partial<HermesRecallLimits> = {}) =>
    new HermesRecallBudget(query, nowMs, signal, { ...tighten, readAhead });
  it("stops at the scanned-unit cap and retains at most three candidates", async () => {
    const { storage, adapter } = await fixture();
    const limits = { candidates: 10, passageUnits: 64, scannedUnits: 64 };
    const budget = budgetOf("board meeting", () => 0, new AbortController().signal, limits);
    const result = await adapter.recallPassages(budget);
    expect(budget.maximumRetained).toBeLessThanOrEqual(3);
    expect(budget.unitsScanned).toBeLessThanOrEqual(limits.scannedUnits);
    expect(budget.candidatesScanned).toBeLessThanOrEqual(limits.candidates);
    expect(budget.candidatesScanned).toBeLessThan(limits.candidates);
    expect(storage.chunkReads).toBeLessThanOrEqual(Math.ceil(limits.scannedUnits / 8) + limits.candidates);
    expect(result.truncated).toBe(true);
    expect(result.passages.some(p => p.passage_id === "p00")).toBe(false);
  });
  it("stops at the candidate cap", async () => {
    const { adapter } = await fixture();
    const budget = budgetOf("board meeting", () => 0, new AbortController().signal, { candidates: 4, passageUnits: 64 });
    expect((await adapter.recallPassages(budget)).truncated).toBe(true);
    expect(budget.candidatesScanned).toBe(4);
  });
  it("stops when storage reads advance the wall clock", async () => {
    const { storage, adapter } = await fixture();
    storage.step = RECALL_WALL_BUDGET_MS / 2; // Two reads consume the production wall budget.
    const budget = budgetOf("board meeting", () => storage.now, new AbortController().signal);
    expect((await adapter.recallPassages(budget)).truncated).toBe(true);
    expect(budget.candidatesScanned).toBeLessThan(15);
    expect(storage.chunkReads).toBe(0);
  });
  it("returns bounded partial context on abort and skips scanning with no terms", async () => {
    const { storage, adapter } = await fixture();
    const abort = new AbortController(); abort.abort();
    const budget = budgetOf("board meeting", () => 0, abort.signal);
    expect((await adapter.recallPassages(budget)).truncated).toBe(true);
    expect(budget.candidatesScanned).toBe(0);
    expect(await adapter.recallPassages(budgetOf("when is the", () => 0, abort.signal)))
      .toEqual({ outcome: "recalled", context: "", passages: [], truncated: false });
    expect(storage.chunkReads).toBe(0);
  });

  it.each(["abort", "wall"] as const)("checks %s before key listing", async kind => {
    const { storage, adapter } = await fixture();
    const abort = new AbortController();
    const budget = budgetOf("board meeting", () => storage.now, abort.signal);
    if (kind === "abort") abort.abort(); else storage.now += RECALL_WALL_BUDGET_MS;
    const before = storage.listings;
    expect(await adapter.recallPassages(budget)).toEqual({ outcome: "recalled", truncated: true, passages: [], context: "" });
    expect(storage.listings).toBe(before);
  });

  it("skips an oversized passage during chunk reads without scoring its prefix", async () => {
    const storage = new CountingStorage();
    const perPassage = 64; // Tightened unit ceiling; two chunks prove the incremental skip path.
    const adapter = new TestSdwMemoryBackendAdapter({ storage, masterKey: new Uint8Array(32).fill(17),
      fortressId: "incremental-skip", ownerRef: "agent", maxChunkChars: perPassage });
    await adapter.insertPassage({ passage_id: "oversized", text: "board ".repeat(perPassage) }, "user_content");
    await adapter.insertPassage({ passage_id: "small", text: "board meeting" }, "user_content");
    storage.chunkReads = 0;
    const budget = budgetOf("board meeting", () => 0, new AbortController().signal, { passageUnits: perPassage });
    const result = await adapter.recallPassages(budget);
    expect(result.passages.map(p => p.passage_id)).toEqual(["small"]);
    expect(result.truncated).toBe(true);
    expect(storage.chunkReads).toBe(3); // Two reads establish oversize, one reads the small passage.
  });
});

// The candidate and unit caps are decided at the commit, so they hold at every window; the clock kinds jump when b's
// read is issued, which the read-ahead does before a commits, so they run one passage at a time (window 1), and
// memory-recall-read-ahead-clock.test.ts covers the default window on a clock driven by read completion.
const EXHAUSTION_CASES = [
  ...RECALL_TEST_WINDOWS.flatMap(readAhead => (["candidates", "units"] as const).map(kind => [kind, readAhead] as const)),
  ...(["wall", "abort", "full wall"] as const).map(kind => [kind, 1] as const),
];

// Each exhausted scan budget preserves exactly the match ranked before exhaustion, verified inside the wall.
it.each(EXHAUSTION_CASES)("retains known context before exhausting %s at read-ahead window %i", async (kind, readAhead) => {
  const storage = new CountingStorage();
  const created = "2026-11-01T00:00:00.000Z";
  const adapter = new TestSdwMemoryBackendAdapter({ storage, masterKey: new Uint8Array(32).fill(17),
    fortressId: "retained-match", ownerRef: "agent", now: () => created });
  const text = "board meeting";
  await adapter.insertPassage({ passage_id: "a", text }, "user_content");
  await adapter.insertPassage({ passage_id: "b", text: "board meeting later" }, "user_content");
  const abort = new AbortController();
  storage.beforeRead = key => {
    if (key === "doc.mem.agent.b") {
      // The scan stops at the reserve; the reserved slice still verifies what was ranked.
      if (kind === "wall") storage.now = RECALL_WALL_BUDGET_MS - RECALL_VERIFY_RESERVE_MS;
      if (kind === "full wall") storage.now = RECALL_WALL_BUDGET_MS;
      if (kind === "abort") abort.abort();
    }
  };
  const budget = new HermesRecallBudget("board meeting", () => storage.now, abort.signal,
    { ...(kind === "candidates" ? { candidates: 1 } : kind === "units" ? { scannedUnits: text.length + 1 } : {}), readAhead });
  const result = await adapter.recallPassages(budget);
  // Abort and the full wall stop verification too, so nothing ranked but unverified is returned.
  expect(result).toEqual(kind === "abort" || kind === "full wall"
    ? { outcome: "recalled", truncated: true, passages: [], context: "" }
    : { outcome: "recalled", truncated: true,
      passages: [{ passage_id: "a", created_at: created }], context: "- (saved 2026-11-01) board meeting\n" });
});
