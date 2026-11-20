// Score-first recall bounds its verification work whatever the corpus size or scan order, returns only
// verified passages under abort, the wall and integrity-state changes, and never writes or waits on a lock.
import { describe, expect, it } from "vitest";
import {
  RECALL_MAX_PASSAGES,
  RECALL_VERIFY_CANDIDATES,
  RECALL_WALL_BUDGET_MS,
} from "../../src/hermes-memory-bridge/recall.js";
import { NOW, oracleRecall, prng, recallFixture, referenceRecall, type Seed, RECALL_TEST_WINDOWS } from "./recall-score-first-fixture.js";

describe.each(RECALL_TEST_WINDOWS)("read-ahead window %i", readAhead => {
  const LARGE_CORPUS = 2000; // The memory corpus ceiling, MEMORY_CORPUS_SCAN_CAP.
  const ORDER_CORPUS = 200; // Two hundred passages make every scan order costly for verify-on-scan.
  const instant = (offsetMs: number) => new Date(Date.parse(NOW) + offsetMs).toISOString();
  const fillerText = (n: number) => `Note ${n}: the garden item moved to week ${n % 52}.`; // 52 weeks in a year.

  async function seeded(seeds: readonly Seed[]) {
    const f = await recallFixture({ readAhead });
    for (const seed of seeds) await f.seed(seed);
    return f;
  }
  async function largeCorpus(matchEverything: boolean) {
    const seeds: Seed[] = [];
    for (let n = 0; n < LARGE_CORPUS; n++) {
      seeds.push({ kind: "valid", passageId: `p${String(n).padStart(4, "0")}`, createdAt: instant(n),
        // The matching wording differs from the filler wording only by a suffix; one "alpha "-prefixed wording
        // produced a record the write gate's secret-token classifier refused, so this wording is used instead.
        text: matchEverything ? `${fillerText(n)} alpha` : n === LARGE_CORPUS / 2 ? "the alpha handover is Friday" : fillerText(n) });
    }
    return { f: await seeded(seeds), seeds };
  }

  describe("verification work is bounded by the candidate heap", () => {
    it("verifies exactly one companion for a one-match query over 2000 passages", async () => {
      const { f, seeds } = await largeCorpus(false);
      const verifications = f.countVerifications();
      const result = await f.adapter.recallPassages(f.budget("alpha"));
      expect(result).toEqual(oracleRecall(seeds, "state_PRE_MIGRATION", "alpha"));
      expect(result.passages).toHaveLength(1);
      expect(verifications.count()).toBe(1);
    }, 240_000);
    it("verifies at most the heap's candidates for a query matching all 2000 passages", async () => {
      const { f, seeds } = await largeCorpus(true);
      const verifications = f.countVerifications();
      const budget = f.budget("alpha");
      const result = await f.adapter.recallPassages(budget);
      expect(result).toEqual(oracleRecall(seeds, "state_PRE_MIGRATION", "alpha"));
      expect(verifications.count()).toBeLessThanOrEqual(RECALL_VERIFY_CANDIDATES);
      expect(verifications.count()).toBe(RECALL_MAX_PASSAGES); // Every top candidate verifies, so three suffice.
      expect(budget.maximumHeld).toBe(RECALL_VERIFY_CANDIDATES);
    }, 240_000);
    it("absorbs up to five failed candidates and still equals verifying everything", async () => {
      const seeds: Seed[] = [];
      // Eight matching passages fill the heap exactly; the five best fail verification, the other three verify.
      for (let n = 0; n < RECALL_VERIFY_CANDIDATES; n++) {
        seeds.push({ kind: n < RECALL_VERIFY_CANDIDATES - RECALL_MAX_PASSAGES ? "invalid-signature" : "valid",
          passageId: `m${n}`, text: "alpha ".repeat(RECALL_VERIFY_CANDIDATES - n), createdAt: NOW });
      }
      const f = await seeded(seeds);
      const verifications = f.countVerifications();
      const result = await f.adapter.recallPassages(f.budget("alpha"));
      expect(verifications.count()).toBe(RECALL_VERIFY_CANDIDATES);
      expect(result).toEqual(oracleRecall(seeds, "state_PRE_MIGRATION", "alpha"));
      expect(result.truncated).toBe(false);
      expect(result).toEqual(await referenceRecall(f.adapter, f.budget("alpha")));
    });
    it("sets truncated when more ranked candidates fail than the heap absorbs", async () => {
      const seeds: Seed[] = [];
      // Ten failing passages outrank five valid ones, so the heap empties with nothing verified.
      for (let n = 0; n < 15; n++) {
        seeds.push({ kind: n < 10 ? "invalid-signature" : "valid", passageId: `m${String(n).padStart(2, "0")}`,
          text: "alpha ".repeat(20 - n), createdAt: NOW });
      }
      const f = await seeded(seeds);
      const verifications = f.countVerifications();
      const result = await f.adapter.recallPassages(f.budget("alpha"));
      expect(verifications.count()).toBe(RECALL_VERIFY_CANDIDATES);
      expect(result).toEqual({ outcome: "recalled", context: "", passages: [], truncated: true });
    });
  });

  describe("verification work does not depend on scan order", () => {
    const orders = {
      // Each later passage in key order scores higher, so verify-on-scan admits every one of them.
      rising: (n: number): Pick<Seed, "text" | "createdAt"> => ({ text: "alpha ".repeat(n + 1), createdAt: NOW }),
      // Equal scores scanned oldest first: the newer instant wins every tie, so each later passage is better.
      "equal scores oldest first": (n: number) => ({ text: "alpha bravo", createdAt: instant(n) }),
      random: (n: number, random = prng(0x0a11ce + n)) => ({ text: "alpha ".repeat(1 + Math.floor(random() * 50)), createdAt: instant(n % 7) }),
    } as const;
    it.each(Object.keys(orders) as (keyof typeof orders)[])("%s order verifies at most the heap and equals verifying everything", async order => {
      const seeds: Seed[] = Array.from({ length: ORDER_CORPUS }, (_, n) => ({ kind: "valid" as const,
        passageId: `p${String(n).padStart(4, "0")}`, ...orders[order](n) }));
      const f = await seeded(seeds);
      const verifications = f.countVerifications();
      const result = await f.adapter.recallPassages(f.budget("alpha"));
      expect(verifications.count()).toBeLessThanOrEqual(RECALL_VERIFY_CANDIDATES);
      expect(result).toEqual(oracleRecall(seeds, "state_PRE_MIGRATION", "alpha"));
      if (order !== "random") expect(result.passages[0]!.passage_id).toBe(`p${String(ORDER_CORPUS - 1).padStart(4, "0")}`);
      expect(result).toEqual(await referenceRecall(f.adapter, f.budget("alpha")));
    }, 120_000);
  });

  describe("fault schedules on the recall path", () => {
    // Five matching passages; key order puts the best last, so rank order and scan order disagree.
    const ranked: Seed[] = Array.from({ length: 5 }, (_, n) => ({ kind: "valid", passageId: `r${n}`,
      text: "alpha ".repeat(n + 1), createdAt: NOW }));
    it.each(["abort", "wall"] as const)("%s during verification returns only passages that had verified", async fault => {
      const f = await seeded(ranked);
      const abort = new AbortController();
      f.countVerifications(count => {
        if (count !== 2) return;
        if (fault === "abort") abort.abort(); else f.storage.now = RECALL_WALL_BUDGET_MS;
      });
      const result = await f.adapter.recallPassages(f.budget("alpha", () => f.storage.now, abort.signal));
      expect(result).toEqual({ ...oracleRecall([ranked[4]!], "state_PRE_MIGRATION", "alpha"), truncated: true });
    });
    it("refuses when a migration completes while the call runs", async () => {
      const f = await seeded(ranked);
      let reads = 0;
      f.setState(async () => reads++ === 0 ? "state_MIGRATING" : "state_COMPLETE");
      await expect(f.adapter.recallPassages(f.budget("alpha"))).rejects.toThrow("integrity state changed");
    });
    it("refuses a missing completion marker even when the query matches nothing", async () => {
      const f = await seeded(ranked);
      // Positive control: the same corpus and query answer an empty recall in a readable state.
      expect(await f.adapter.recallPassages(f.budget("zebra"))).toEqual({ outcome: "recalled", context: "", passages: [], truncated: false });
      f.setState("state_MARKER_ABSENT_POST_COMPLETE");
      f.storage.chunkReads = 0;
      await expect(f.adapter.recallPassages(f.budget("zebra"))).rejects.toThrow("completion marker is absent");
      expect(f.storage.chunkReads).toBe(0);
    });
    it("finishes inside the wall without writing while another holder keeps the corpus and document locks", async () => {
      const seeds: Seed[] = [...ranked, { kind: "invalid-signature", passageId: "bad", text: "alpha ".repeat(10), createdAt: NOW }];
      const f = await seeded(seeds);
      const withDocumentLock = (f.adapter as unknown as {
        withDocumentLock<T>(documentId: string, fn: () => Promise<T>): Promise<T>;
      }).withDocumentLock.bind(f.adapter);
      let release!: () => void;
      let held = false;
      const holder = withDocumentLock(f.documentIdOf("bad"), () => { held = true; return new Promise<void>(resolve => { release = resolve; }); });
      try {
        for (let turn = 0; turn < 100 && !held; turn++) await Promise.resolve(); // Bounded: the in-memory lock grants within a few turns.
        expect(held).toBe(true);
        f.storage.writes = 0;
        f.storage.step = 1; // One millisecond per storage read is the call's whole clock.
        let settled: { value?: unknown; error?: unknown } | undefined;
        void f.adapter.recallPassages(f.budget("alpha", () => f.storage.now))
          .then(value => { settled = { value }; }, error => { settled = { error }; });
        // Bounded turns, no timers: an in-memory recall that waits on the held lock never settles here.
        for (let turn = 0; turn < 1000 && settled === undefined; turn++) await new Promise(resolve => setImmediate(resolve));
        expect(settled).toEqual({ value: oracleRecall(ranked, "state_PRE_MIGRATION", "alpha") });
        expect(f.storage.now).toBeLessThan(RECALL_WALL_BUDGET_MS);
        expect(f.storage.writes).toBe(0);
      } finally {
        release?.();
        await holder;
      }
    });
  });
});
