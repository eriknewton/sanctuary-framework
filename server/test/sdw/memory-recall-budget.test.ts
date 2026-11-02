// The real encrypted adapter bounds per-call scan work and retained context.
import { expect, it } from "vitest";
import { MemoryStorage } from "../../src/storage/memory.js";
import { HermesRecallBudget, RECALL_WALL_BUDGET_MS } from "../../src/hermes-memory-bridge/recall.js";
import { TestSdwMemoryBackendAdapter } from "./test-memory-backend.js";

class CountingStorage extends MemoryStorage {
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
it("stops at the scanned-unit cap and retains at most three candidates", async () => {
  const { storage, adapter } = await fixture();
  const limits = { candidates: 10, passageUnits: 64, scannedUnits: 64 };
  const budget = new HermesRecallBudget("board meeting", () => 0, new AbortController().signal, limits);
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
  const budget = new HermesRecallBudget("board meeting", () => 0, new AbortController().signal, { candidates: 4, passageUnits: 64 });
  expect((await adapter.recallPassages(budget)).truncated).toBe(true);
  expect(budget.candidatesScanned).toBe(4);
});
it("stops when storage reads advance the wall clock", async () => {
  const { storage, adapter } = await fixture();
  storage.step = RECALL_WALL_BUDGET_MS / 2; // Two reads consume the production wall budget.
  const budget = new HermesRecallBudget("board meeting", () => storage.now, new AbortController().signal);
  expect((await adapter.recallPassages(budget)).truncated).toBe(true);
  expect(budget.candidatesScanned).toBeLessThan(15);
  expect(storage.chunkReads).toBe(0);
});
it("returns bounded partial context on abort and skips scanning with no terms", async () => {
  const { storage, adapter } = await fixture();
  const abort = new AbortController(); abort.abort();
  const budget = new HermesRecallBudget("board meeting", () => 0, abort.signal);
  expect((await adapter.recallPassages(budget)).truncated).toBe(true);
  expect(budget.candidatesScanned).toBe(0);
  expect(await adapter.recallPassages(new HermesRecallBudget("when is the", () => 0, abort.signal)))
    .toEqual({ outcome: "recalled", context: "", passages: [], truncated: false });
  expect(storage.chunkReads).toBe(0);
});

// Each exhausted budget preserves exactly the verified match retained before exhaustion.
it.each(["candidates", "units", "wall", "abort"] as const)("retains known context before exhausting %s", async kind => {
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
      if (kind === "wall") storage.now = RECALL_WALL_BUDGET_MS;
      if (kind === "abort") abort.abort();
    }
  };
  const budget = new HermesRecallBudget("board meeting", () => storage.now, abort.signal,
    kind === "candidates" ? { candidates: 1 } : kind === "units" ? { scannedUnits: text.length + 1 } : {});
  const result = await adapter.recallPassages(budget);
  expect(result).toEqual({ outcome: "recalled", truncated: true,
    passages: [{ passage_id: "a", created_at: created }], context: "- (saved 2026-11-01) board meeting\n" });
});

it.each(["abort", "wall"] as const)("checks %s before key listing", async kind => {
  const { storage, adapter } = await fixture();
  const abort = new AbortController();
  const budget = new HermesRecallBudget("board meeting", () => storage.now, abort.signal);
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
  const budget = new HermesRecallBudget("board meeting", () => 0, new AbortController().signal, { passageUnits: perPassage });
  const result = await adapter.recallPassages(budget);
  expect(result.passages.map(p => p.passage_id)).toEqual(["small"]);
  expect(result.truncated).toBe(true);
  expect(storage.chunkReads).toBe(3); // Two reads establish oversize, one reads the small passage.
});
