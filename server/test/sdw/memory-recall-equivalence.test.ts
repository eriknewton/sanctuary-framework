// Score-first recall returns exactly what verifying every passage returns, on seeded corpora that mix every
// passage kind recall can meet, and it throws exactly when verifying everything throws a document, chunk or
// integrity-state error. A per-passage provenance error is the one case it may answer instead of throwing.
import { describe, expect, it } from "vitest";
import { RECALL_VERIFY_CANDIDATES } from "../../src/hermes-memory-bridge/recall.js";
import type { SdwMemoryIntegrityState } from "../../src/sdw/records.js";
import {
  CLASS_A_KINDS, FILLER_WORDS, NOW, QUERY_WORDS, SCORED_THEN_REJECTED_KINDS, SEED_KINDS,
  classC, oracleRecall, prng, recallFixture, referenceRecall, settle,
  type Seed, type SeedKind,
  RECALL_TEST_WINDOWS,
} from "./recall-score-first-fixture.js";

describe.each(RECALL_TEST_WINDOWS)("read-ahead window %i", readAhead => {
  const CASES = 64; // Sixty-four seeded corpora cover every kind, matching and not, in every integrity state.
  const MAX_PASSAGES = 14; // Fourteen passages keep each case fast while still overflowing the eight-entry heap.
  // Three instants, one millisecond apart, force created_at ties so passage_id ordering is exercised.
  const INSTANTS = ["2026-10-01T00:00:00.000Z", "2026-10-01T00:00:00.001Z", "2026-10-01T00:00:00.002Z"] as const;
  const STATES: readonly SdwMemoryIntegrityState[] = ["state_PRE_MIGRATION", "state_MIGRATING", "state_COMPLETE"];
  const MAX_BODY_UNITS = 65_536; // RECALL_MAX_PASSAGE_SCAN_UNITS: the largest body recall scores in full.

  function caseSeeds(random: () => number, index: number): { seeds: Seed[]; state: SdwMemoryIntegrityState | "throws" | "state_MARKER_ABSENT_POST_COMPLETE" } {
    const pick = <T,>(items: readonly T[]) => items[Math.floor(random() * items.length)]!;
    // One case in sixteen exercises an integrity-state refusal; the rest rotate through the readable states.
    const state = index % 16 === 7 ? "throws" : index % 16 === 15 ? "state_MARKER_ABSENT_POST_COMPLETE" : pick(STATES);
    const count = 4 + Math.floor(random() * (MAX_PASSAGES - 3));
    const seeds: Seed[] = [];
    let rejectedMatches = 0;
    for (let n = 0; n < count; n++) {
      // Rotate the first kind so every kind appears in early cases; the rest are random, valid passages weighted up.
      let kind: SeedKind = n === 0 ? SEED_KINDS[index % SEED_KINDS.length]! : random() < 0.4 ? "valid" : pick(SEED_KINDS);
      // Throwing kinds are rare so most cases still compare full results.
      if (n > 0 && (CLASS_A_KINDS.includes(kind) || kind === "undecodable-status" || kind === "is-marked-throws") && random() < 0.7) kind = "valid";
      const matching = n === 0 ? Math.floor(index / SEED_KINDS.length) % 2 === 0 : random() < 0.6;
      // At most five scored-then-rejected matches, the headroom the eight-entry heap absorbs exactly.
      if (matching && SCORED_THEN_REJECTED_KINDS.includes(kind) && ++rejectedMatches > RECALL_VERIFY_CANDIDATES - 3) kind = "valid";
      const words: string[] = [];
      const length = 3 + Math.floor(random() * 8);
      for (let w = 0; w < length; w++) words.push(matching && random() < 0.5 ? pick(QUERY_WORDS) : pick(FILLER_WORDS));
      if (matching && !words.some(word => (QUERY_WORDS as readonly string[]).includes(word))) words.push(pick(QUERY_WORDS));
      let text = words.join(" ");
      if (kind === "bad-signer-max-body") text = (text + " ").repeat(Math.ceil(MAX_BODY_UNITS / (text.length + 1))).slice(0, MAX_BODY_UNITS);
      seeds.push({ kind, passageId: `p${index}x${n}${Math.floor(random() * 1000)}`, text, createdAt: pick(INSTANTS) });
    }
    return { seeds, state };
  }

  describe("score-first recall equals verifying every passage", () => {
    const seen = new Map<string, number>();
    const outcomes = { compared: 0, comparedWithPassages: 0, overflowedHeap: 0, classA: 0, classB: 0, classC: 0, classCAnswered: 0 };
    it.each(Array.from({ length: CASES }, (_, index) => index))("seeded corpus %i", async index => {
      const random = prng(0x5eed0000 + index);
      const { seeds, state } = caseSeeds(random, index);
      const f = await recallFixture({ readAhead });
      for (const seed of seeds) {
        await f.seed(seed);
        const matches = QUERY_WORDS.some(word => seed.text.includes(word));
        seen.set(`${seed.kind}:${matches}`, (seen.get(`${seed.kind}:${matches}`) ?? 0) + 1);
      }
      const readable = state !== "throws" && state !== "state_MARKER_ABSENT_POST_COMPLETE";
      f.setState(state === "throws" ? async () => { throw new Error("integrity journal mismatch"); } : state);
      f.storage.writes = 0;
      const scoreFirst = await settle(() => f.adapter.recallPassages(f.budget()));
      // Recall is write-free on every outcome, including the ones that throw.
      expect(f.storage.writes).toBe(0);
      const reference = await settle(() => referenceRecall(f.adapter, f.budget()));
      const effectiveState = readable ? state : "state_COMPLETE";
      const hasClassC = readable && seeds.some(seed => classC(seed.kind, effectiveState));
      const hasClassA = seeds.some(seed => CLASS_A_KINDS.includes(seed.kind));
      // The fixture itself: verifying everything throws exactly when an abort-class seed or state is present.
      expect(reference.ok).toBe(readable && !hasClassA && !hasClassC);
      // Score-first throws only when verifying everything throws.
      if (!scoreFirst.ok) expect(reference.ok).toBe(false);
      if (!readable) outcomes.classB++; else if (hasClassC) outcomes.classC++; else if (hasClassA) outcomes.classA++;
      if (!hasClassC) {
        // Without a per-passage provenance abort, both throw or neither does, and the full results are equal.
        expect(scoreFirst.ok).toBe(reference.ok);
        if (scoreFirst.ok && reference.ok) {
          expect(scoreFirst.value).toEqual(reference.value);
          expect(scoreFirst.value).toEqual(oracleRecall(seeds, effectiveState));
          outcomes.compared++;
          if (scoreFirst.value.passages.length > 0) outcomes.comparedWithPassages++;
          if (seeds.filter(seed => QUERY_WORDS.some(word => seed.text.includes(word))).length > RECALL_VERIFY_CANDIDATES) outcomes.overflowedHeap++;
        }
      } else if (scoreFirst.ok) {
        outcomes.classCAnswered++;
        // The accepted narrowing: when score-first answers anyway, it answers with the best verified passages.
        expect(scoreFirst.value).toEqual(oracleRecall(seeds, effectiveState));
      }
    });
    it("covered every seed kind both matching and not matching the query, and every outcome class", () => {
      console.info(`recall equivalence outcomes ${JSON.stringify(outcomes)}`);
      // Floors, not exact counts: each comparison class must actually occur for the property to mean anything.
      expect(outcomes.compared).toBeGreaterThanOrEqual(CASES / 4);
      expect(outcomes.comparedWithPassages).toBeGreaterThanOrEqual(CASES / 4);
      expect(outcomes.overflowedHeap).toBeGreaterThan(0);
      expect(outcomes.classA).toBeGreaterThan(0);
      expect(outcomes.classB).toBeGreaterThan(0);
      expect(outcomes.classC).toBeGreaterThan(0);
      expect(outcomes.classCAnswered).toBeGreaterThan(0);
      for (const kind of SEED_KINDS) {
        expect.soft(seen.get(`${kind}:true`) ?? 0, `${kind} matching`).toBeGreaterThan(0);
        expect.soft(seen.get(`${kind}:false`) ?? 0, `${kind} not matching`).toBeGreaterThan(0);
      }
    });
  });

  it("returns a skipped passage's neighbours unchanged and reads none of its chunks", async () => {
    const f = await recallFixture({ readAhead });
    const valid: Seed = { kind: "valid", passageId: "z-valid", text: "alpha bravo", createdAt: NOW };
    await f.seed(valid);
    const body = "alpha ".repeat(MAX_BODY_UNITS / "alpha ".length) + "alpha";
    await f.seed({ kind: "bad-signer-max-body", passageId: "a-bad-signer", text: body.slice(0, MAX_BODY_UNITS), createdAt: NOW });
    f.storage.chunkReads = 0;
    const budget = f.budget();
    expect(await f.adapter.recallPassages(budget)).toEqual(oracleRecall([valid], "state_PRE_MIGRATION"));
    // The bad-signer body is skipped before its chunks: only the valid passage's one chunk is read and counted.
    expect(budget.unitsScanned).toBe(valid.text.length);
    expect(f.storage.chunkReads).toBe(1);
  });

  describe("the accepted narrowing of the unsigned-after-completion abort", () => {
    it("answers with verified passages when the unsigned passage is never ranked", async () => {
      const f = await recallFixture({ readAhead });
      const valid: Seed = { kind: "valid", passageId: "valid", text: "alpha bravo", createdAt: NOW };
      await f.seed(valid);
      await f.seed({ kind: "unsigned", passageId: "unsigned", text: "garden budget", createdAt: NOW });
      f.setState("state_COMPLETE");
      expect(await f.adapter.recallPassages(f.budget())).toEqual(oracleRecall([valid], "state_COMPLETE"));
      // Verifying every passage aborts on the unsigned passage although it matches nothing.
      await expect(referenceRecall(f.adapter, f.budget())).rejects.toThrow("unsigned after provenance migration completion");
    });
    it("still refuses when the unsigned passage is ranked for verification", async () => {
      const f = await recallFixture({ readAhead });
      await f.seed({ kind: "valid", passageId: "valid", text: "alpha garden", createdAt: NOW });
      await f.seed({ kind: "unsigned", passageId: "unsigned", text: "alpha bravo charlie", createdAt: NOW });
      f.setState("state_COMPLETE");
      await expect(f.adapter.recallPassages(f.budget())).rejects.toThrow("unsigned after provenance migration completion");
    });
  });
});
