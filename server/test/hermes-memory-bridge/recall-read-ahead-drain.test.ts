// Every read a recall issues has settled before the bridge sees the call return and releases its admission record,
// under a parked read beside a failed one, repeated admission waves, abort, the wall and concurrent calls.
import { describe, expect, it } from "vitest";
import { HERMES_MAX_CALL_RECORDS, HERMES_MAX_PUBLIC_CONNECTIONS } from "../../src/hermes-memory-bridge/constants.js";
import { RECALL_READ_AHEAD_PASSAGES, RECALL_READS_PER_SLOT, RECALL_WALL_BUDGET_MS } from "../../src/hermes-memory-bridge/recall.js";
import { prng } from "../sdw/recall-score-first-fixture.js";
import { quiesce, recallBridge, turnsUntil } from "./recall-read-ahead-harness.js";

const PER_CALL_BOUND = RECALL_READ_AHEAD_PASSAGES * RECALL_READS_PER_SLOT;
const PRODUCT_BOUND = PER_CALL_BOUND * HERMES_MAX_CALL_RECORDS;
const passages = (count: number) => Array.from({ length: count }, (_, n) => ({ id: `p${String(n).padStart(2, "0")}`, text: `board meeting ${n}` }));
const isDoc = (key: string, id: string) => key === `doc.mem.agent.${id}`;
const isProv = (key: string, id: string) => key === `prov.mem.agent.${id}`;

describe("a parked read beside a failed sibling", () => {
  it("holds the call and its admission record until the parked read settles", async () => {
    const h = await recallBridge(passages(6));
    try {
      h.storage.rule = key => isProv(key, "p01") ? "park" : isDoc(key, "p01") ? "reject" : undefined;
      h.accept("c1"); h.call("c1", "r1");
      await turnsUntil(() => h.storage.parked.length === 1);
      await quiesce();
      // The property: p01's document read failed, but its provenance read is still pending, so the call is held.
      expect(h.responses("r1")).toEqual([]);
      expect(h.recordCount()).toBe(1);
      expect(h.storage.inFlight).toBe(1);
      h.storage.release();
      await turnsUntil(() => h.recordCount() === 0);
      expect(h.storage.inFlight).toBe(0);
      expect(h.storage.settled).toBe(h.storage.issued);
      // The failed document read is raised at p01's turn: the call is refused, and no recall audit row is written.
      expect(h.body("r1")).toMatchObject({ outcome: "unavailable" });
      expect(h.recallAudits()).toEqual([]);
      expect(h.storage.writes).toBe(0);
    } finally { h.storage.release(); h.core.relayEof(); }
  });
});

describe("repeated admission waves of the parked-sibling schedule", () => {
  it("returns reads in flight to zero after every call, and never passes the product-wide bound", async () => {
    // A leak of one read per slot per call passes the product-wide bound after this many calls.
    const calls = Math.floor(PRODUCT_BOUND / RECALL_READ_AHEAD_PASSAGES) + 1;
    const h = await recallBridge(passages(6));
    const afterEachCall: number[] = [];
    try {
      // Every document read fails and every provenance read parks, in every slot of every call.
      h.storage.rule = key => key.startsWith("prov.mem.") ? "park" : key.startsWith("doc.mem.") ? "reject" : undefined;
      h.accept("c1");
      for (let n = 0; n < calls; n++) {
        h.storage.tag = n;
        h.call("c1", `wave-${n}`);
        // Release only this call's parked reads, and only once the call is held on them: a read the call leaves
        // behind is never released by a later call, so a leak accumulates across the waves.
        for (let turn = 0; turn < 5000 && h.responses(`wave-${n}`).length === 0; turn++) {
          await quiesce(5);
          if (h.responses(`wave-${n}`).length === 0 && h.storage.parked.some(read => read.tag === n)) h.storage.release(n);
        }
        await turnsUntil(() => h.recordCount() === 0);
        afterEachCall.push(h.storage.inFlight);
      }
      expect(afterEachCall).toEqual(Array.from({ length: calls }, () => 0));
      expect(h.storage.peakInFlight).toBeLessThanOrEqual(PRODUCT_BOUND);
      expect(h.storage.writes).toBe(0);
    } finally { h.storage.release(); h.core.relayEof(); }
  });
});

describe("issued equals settled at return, and nothing settles afterwards", () => {
  it.each(["abort", "wall"] as const)("under %s with a read parked past the stop point", async fault => {
    const h = await recallBridge(passages(8));
    let atReturn: { issued: number; settled: number } | undefined;
    h.onAudit.push(row => { if (row.kind === "memory_recall") atReturn = { issued: h.storage.issued, settled: h.storage.settled }; });
    try {
      // The commit waits on p01's parked document read; p03's, in the same read-ahead window, parks past it.
      h.storage.rule = key => isDoc(key, "p01") || isDoc(key, "p03") ? "park" : undefined;
      h.accept("c1"); h.call("c1", "r1");
      await turnsUntil(() => h.storage.parked.length === 2);
      if (fault === "abort") h.core.relayEof(); else h.advance(RECALL_WALL_BUDGET_MS);
      // The commit's turn for p01 sees the stop, so the scan ends at p01 with p03's read still pending.
      expect(h.storage.release(key => isDoc(key, "p01"))).toBe(1);
      await quiesce();
      // The property: the call has not returned while a read it issued past the stop is still pending.
      expect(atReturn).toBeUndefined();
      expect(h.recordCount()).toBe(1);
      h.storage.release();
      await turnsUntil(() => atReturn !== undefined);
      expect(atReturn!.settled).toBe(atReturn!.issued);
      const settledAtReturn = h.storage.settled;
      await quiesce();
      expect(h.storage.settled).toBe(settledAtReturn);
      expect(h.recallAudits()[0]).toMatchObject({ truncated: true, passage_ids: [] });
      expect(h.storage.writes).toBe(0);
    } finally { h.storage.release(); h.core.relayEof(); }
  });
});

describe("reads in flight stay within the per-call and product-wide bounds (row 5)", () => {
  it("one call never has more than RECALL_READ_AHEAD_PASSAGES x RECALL_READS_PER_SLOT reads in flight", async () => {
    const h = await recallBridge(passages(20)); // Twenty passages: five windows.
    const random = prng(0x5107);
    try {
      h.storage.rule = () => ({ turns: Math.floor(random() * 4) }); // Zero to three turns, so reads overlap and finish out of order.
      h.accept("c1"); h.call("c1", "r1");
      await turnsUntil(() => h.recordCount() === 0);
      expect(h.storage.peakInFlight).toBeLessThanOrEqual(PER_CALL_BOUND);
      expect(h.storage.peakInFlight).toBeGreaterThan(RECALL_READS_PER_SLOT); // Positive control: slots overlapped.
      expect(h.body("r1")).toMatchObject({ outcome: "recalled" });
    } finally { h.core.relayEof(); }
  });

  it("HERMES_MAX_CALL_RECORDS concurrent calls never pass that bound times HERMES_MAX_CALL_RECORDS", async () => {
    const h = await recallBridge(passages(20));
    const random = prng(0x5108);
    try {
      // The first live connections each start a recall, then close, so their records stay admitted while detached.
      h.storage.rule = key => key.startsWith("doc.mem.") ? "park" : undefined;
      for (let n = 0; n < HERMES_MAX_PUBLIC_CONNECTIONS; n++) { h.accept(`a${n}`); h.call(`a${n}`, `ra${n}`); }
      await turnsUntil(() => h.storage.parked.length === HERMES_MAX_PUBLIC_CONNECTIONS * RECALL_READ_AHEAD_PASSAGES);
      for (let n = 0; n < HERMES_MAX_PUBLIC_CONNECTIONS; n++) h.close(`a${n}`);
      for (let n = 0; n < HERMES_MAX_CALL_RECORDS - HERMES_MAX_PUBLIC_CONNECTIONS; n++) { h.accept(`b${n}`); h.call(`b${n}`, `rb${n}`); }
      await turnsUntil(() => h.storage.parked.length === HERMES_MAX_CALL_RECORDS * RECALL_READ_AHEAD_PASSAGES);
      expect(h.recordCount()).toBe(HERMES_MAX_CALL_RECORDS);
      h.storage.rule = () => ({ turns: Math.floor(random() * 4) });
      h.storage.release();
      await turnsUntil(() => h.recordCount() === 0, 20_000);
      expect(h.storage.peakInFlight).toBeLessThanOrEqual(PRODUCT_BOUND);
      expect(h.storage.peakInFlight).toBeGreaterThan(PER_CALL_BOUND); // Positive control: the calls overlapped.
      expect(h.storage.inFlight).toBe(0);
      expect(h.storage.writes).toBe(0);
    } finally { h.storage.release(); h.core.relayEof(); }
  });
});
