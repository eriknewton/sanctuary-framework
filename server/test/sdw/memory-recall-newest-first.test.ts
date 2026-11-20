// Recall scans the most recently modified passage files first, from the listing's own modification times, ties by
// key; a backend with no times keeps key order; a document gone after the listing is skipped.
import { describe, expect, it } from "vitest";
import { HermesRecallBudget, RECALL_READ_AHEAD_PASSAGES, RECALL_VERIFY_RESERVE_MS } from "../../src/hermes-memory-bridge/recall.js";
import type { StorageEntryMeta } from "../../src/storage/interface.js";
import { NOW, recallFixture } from "./recall-score-first-fixture.js";

const CORPUS = 200; // Two hundred passages, half of which the tightened wall lets the commit reach.
const COMMITTED = CORPUS / 2;
const id = (n: number) => `p${String(n).padStart(3, "0")}`;

/** A budget whose clock is the number of passages committed, with the scan's deadline at COMMITTED of them. */
class CommitClockBudget extends HermesRecallBudget {
  readonly committed: string[] = [];
  constructor() {
    let budget: CommitClockBudget | undefined;
    super("alpha", () => budget?.committed.length ?? 0, new AbortController().signal,
      { wallMs: COMMITTED + RECALL_VERIFY_RESERVE_MS, readAhead: RECALL_READ_AHEAD_PASSAGES });
    budget = this;
  }
  // Every passage is valid and matches, so a passage is scored exactly when the commit decided it.
  override score(...args: Parameters<HermesRecallBudget["score"]>) { this.committed.push(args[0].passage_id); return super.score(...args); }
}

async function corpus(times: (n: number) => string | undefined, extra: readonly StorageEntryMeta[] = []) {
  const f = await recallFixture({ readAhead: RECALL_READ_AHEAD_PASSAGES });
  for (let n = 0; n < CORPUS; n++) await f.seed({ kind: "valid", passageId: id(n), text: `alpha note ${n}`, createdAt: NOW });
  const list = f.storage.list.bind(f.storage);
  f.storage.list = async (namespace, prefix) => {
    const entries = await list(namespace, prefix);
    if (!prefix?.startsWith("doc.")) return entries;
    // The listing reports the times the test chose, as a host file system reports modification times.
    return [...entries.map(entry => {
      const n = Number(entry.key.slice(-3));
      const at = times(n);
      return at === undefined ? { ...entry, modified_at: undefined as unknown as string } : { ...entry, modified_at: at };
    }), ...extra].sort((a, b) => a.key.localeCompare(b.key));
  };
  f.storage.writes = 0;
  return f;
}
// Times against key order: the higher the passage number, the more recently its file was modified.
const againstKeys = (n: number) => new Date(Date.parse(NOW) + n * 1000).toISOString();

describe("newest-first scan order", () => {
  it("commits the most recently modified half when the wall stops the scan halfway", async () => {
    const f = await corpus(againstKeys);
    const budget = new CommitClockBudget();
    const result = await f.adapter.recallPassages(budget);
    expect([...budget.committed].sort()).toEqual(Array.from({ length: COMMITTED }, (_, k) => id(CORPUS - COMMITTED + k)));
    expect(budget.committed[0]).toBe(id(CORPUS - 1));
    expect(result.truncated).toBe(true);
    expect(f.storage.writes).toBe(0);
  });

  it("keeps key order among equal times", async () => {
    const f = await corpus(() => NOW);
    const budget = new CommitClockBudget();
    await f.adapter.recallPassages(budget);
    expect(budget.committed).toEqual(Array.from({ length: COMMITTED }, (_, k) => id(k)));
  });

  it("keeps key order on a backend that reports no times", async () => {
    const f = await corpus(() => undefined);
    const budget = new CommitClockBudget();
    await f.adapter.recallPassages(budget);
    expect(budget.committed).toEqual(Array.from({ length: COMMITTED }, (_, k) => id(k)));
  });

  it("skips a document that vanished after the listing, even when it is listed as the newest", async () => {
    const ghost = { key: `doc.${"mem.agent.ghost"}`, namespace: "_sdw_document_corpus", size_bytes: 0,
      modified_at: new Date(Date.parse(NOW) + 10 * CORPUS * 1000).toISOString() }; // Later than every real file.
    const f = await corpus(againstKeys, [ghost]);
    const budget = new CommitClockBudget();
    const result = await f.adapter.recallPassages(budget);
    // The ghost is first in the order and is skipped without being scored; the newest real passages follow.
    expect([...budget.committed].sort()).toEqual(Array.from({ length: COMMITTED }, (_, k) => id(CORPUS - COMMITTED + k)));
    expect(budget.candidatesScanned).toBe(COMMITTED + 1); // The ghost and the committed half.
    expect(result.passages.length).toBe(3);
    expect(f.storage.writes).toBe(0);
  });
});
