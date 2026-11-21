// A recall whose scan has already stopped still waits for a read-ahead read it issued past the stop point: the
// drain holds the call, and the reads it issued, until that read settles. Then it returns only verified passages.
import { expect, it } from "vitest";
import { HermesRecallBudget, RECALL_READ_AHEAD_PASSAGES } from "../../src/hermes-memory-bridge/recall.js";
import { NOW, QUERY, recallFixture } from "./recall-score-first-fixture.js";

const BOUNDED_TURNS = 200; // Two hundred event-loop turns: far longer than this in-memory store needs for any read.
const turn = () => new Promise<void>(resolve => setImmediate(resolve));

it("holds the call and its reads while a read-ahead read past the stop point is stalled, then returns the verified match", async () => {
  const f = await recallFixture({ readAhead: RECALL_READ_AHEAD_PASSAGES });
  await f.seed({ kind: "valid", passageId: "a", text: "alpha bravo", createdAt: NOW });
  await f.seed({ kind: "valid", passageId: "b", text: "alpha charlie", createdAt: NOW });
  f.storage.writes = 0;
  const stalled: (() => void)[] = [];
  let inFlight = 0;
  const original = f.storage.read.bind(f.storage);
  f.storage.read = async (namespace, key) => {
    inFlight++;
    try {
      // Both of b's first reads stall; a's reads complete at once, so a is the ready candidate.
      if (key === `doc.${f.documentIdOf("b")}` || key === `prov.${f.documentIdOf("b")}`) await new Promise<void>(resolve => stalled.push(resolve));
      return await original(namespace, key);
    } finally { inFlight--; }
  };
  const verifications = f.countVerifications();
  // The candidate limit of one stops the scan after a; b was already read ahead in the same window.
  const budget = new HermesRecallBudget(QUERY, () => 0, new AbortController().signal, { candidates: 1, readAhead: RECALL_READ_AHEAD_PASSAGES });
  let settledResult: Awaited<ReturnType<typeof f.adapter.recallPassages>> | undefined;
  const call = f.adapter.recallPassages(budget).then(result => { settledResult = result; return result; });
  for (let n = 0; n < BOUNDED_TURNS; n++) await turn();
  // 1. The call has not completed after the bounded wait, although its scan stopped at a.
  expect(settledResult).toBeUndefined();
  expect(budget.candidatesScanned).toBe(1);
  // 2. The capacity it holds meanwhile: b's two stalled reads, and nothing verified yet.
  expect(stalled.length).toBe(2);
  expect(inFlight).toBe(2);
  expect(verifications.count()).toBe(0);
  // 3. Released, it returns with no read in flight and only the verified match.
  for (const release of stalled.splice(0)) release();
  const result = await call;
  expect(inFlight).toBe(0);
  expect(result.passages.map(passage => passage.passage_id)).toEqual(["a"]);
  expect(result.truncated).toBe(true);
  expect(verifications.count()).toBe(1);
  expect(f.storage.writes).toBe(0);
});
