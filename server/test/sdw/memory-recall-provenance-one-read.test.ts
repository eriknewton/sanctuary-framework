// The recall screen reads each passage's provenance file once: the bytes it hashes for the status match are the
// bytes it decodes, so a provenance file replaced while recall runs is judged by one version, never by two.
import { describe, expect, it } from "vitest";
import { documentProvenanceKey } from "../../src/sdw/grammar.js";
import { NOW, oracleRecall, recallFixture, referenceRecall, type Seed } from "./recall-score-first-fixture.js";

const CORPUS = 20; // Enough passages that a per-passage read count cannot be mistaken for a per-call one.
const filler = (n: number): Seed => ({ kind: "valid", passageId: `p${String(n).padStart(2, "0")}`, createdAt: NOW,
  text: `Note ${n}: the garden item moved to week ${n}.` });
const corpus = (target: Seed): Seed[] => [...Array.from({ length: CORPUS - 1 }, (_, n) => filler(n)), target];

async function seeded(seeds: readonly Seed[]) {
  const f = await recallFixture();
  for (const seed of seeds) await f.seed(seed);
  const reads = new Map<string, number>();
  f.storage.beforeRead = key => { reads.set(key, (reads.get(key) ?? 0) + 1); };
  return { f, reads, provenanceReads: (passageId: string) => reads.get(documentProvenanceKey(f.documentIdOf(passageId))) ?? 0 };
}

describe("one provenance read per screened passage", () => {
  it("reads each screened passage's provenance once, and the verified candidate's once more", async () => {
    const target: Seed = { kind: "valid", passageId: "target", createdAt: NOW, text: "the alpha handover is Friday" };
    const seeds = corpus(target);
    const { f, reads, provenanceReads } = await seeded(seeds);
    const verifications = f.countVerifications();
    const result = await f.adapter.recallPassages(f.budget("alpha"));
    expect(result).toEqual(oracleRecall(seeds, "state_PRE_MIGRATION", "alpha"));
    expect(verifications.count()).toBe(1);
    for (const seed of seeds) {
      // The target's second read is the verification phase's own, the positive control that reads are counted.
      expect(provenanceReads(seed.passageId)).toBe(seed === target ? 2 : 1);
    }
    const total = [...reads].filter(([key]) => key.startsWith("prov.")).reduce((sum, [, count]) => sum + count, 0);
    expect(total).toBe(CORPUS + verifications.count());
  });
});

describe("a provenance file replaced between the two reads round 1 made", () => {
  // Two matching passages: the target outranks the other, so the target's fate decides the first passage returned.
  const target: Seed = { kind: "valid", passageId: "target", createdAt: NOW, text: "alpha alpha bravo" };
  const other: Seed = { kind: "valid", passageId: "other", createdAt: NOW, text: "alpha" };
  const seeds = [...corpus(target), other];
  /** Replaces the target's provenance with an undecodable file, or restores it, just before its second read. */
  function replaceAtSecondRead(f: Awaited<ReturnType<typeof seeded>>, to: "undecodable" | "decodable") {
    const key = documentProvenanceKey(f.f.documentIdOf(target.passageId));
    f.f.storage.beforeRead = readKey => {
      f.reads.set(readKey, (f.reads.get(readKey) ?? 0) + 1);
      if (readKey !== key || f.reads.get(readKey) !== 2) return;
      if (to === "undecodable") f.f.storage.corrupt.add(key); else f.f.storage.corrupt.delete(key);
    };
  }
  const chunkReadsOf = (f: Awaited<ReturnType<typeof seeded>>) =>
    f.reads.get(f.f.firstChunkKey(f.f.documentIdOf(target.passageId))) ?? 0;

  it("decodable when read, undecodable after: equals the reference on the final state", async () => {
    const run = await seeded(seeds);
    replaceAtSecondRead(run, "undecodable");
    const result = await run.f.adapter.recallPassages(run.f.budget("alpha"));
    // The screen decoded the version it hashed, so the target was scored (its chunk was read). Round 1 decoded the
    // replaced file at its second read and skipped the target in the screen, before any chunk read.
    expect(chunkReadsOf(run)).toBe(1);
    // The verification phase reads the file afresh and refuses the replaced version, so nothing unverified escapes.
    expect(result).toEqual(oracleRecall([...seeds.filter(seed => seed !== target), { ...target, kind: "undecodable-provenance" }],
      "state_PRE_MIGRATION", "alpha"));
    expect(result.passages.map(passage => passage.passage_id)).toEqual(["other"]);
    run.f.storage.beforeRead = undefined;
    expect(result).toEqual(await referenceRecall(run.f.adapter, run.f.budget("alpha")));
  });

  it("undecodable when read, decodable after: equals the reference on the state the screen read", async () => {
    const run = await seeded(seeds);
    run.f.storage.corrupt.add(documentProvenanceKey(run.f.documentIdOf(target.passageId)));
    replaceAtSecondRead(run, "decodable");
    const result = await run.f.adapter.recallPassages(run.f.budget("alpha"));
    // The screen skipped the target on the version it read; round 1 hashed that version but decoded the
    // replacement, passed the target and returned it.
    expect(result.passages.map(passage => passage.passage_id)).toEqual(["other"]);
    expect(chunkReadsOf(run)).toBe(0);
    const asRead = await seeded(seeds);
    asRead.f.storage.corrupt.add(documentProvenanceKey(asRead.f.documentIdOf(target.passageId)));
    expect(result).toEqual(await referenceRecall(asRead.f.adapter, asRead.f.budget("alpha")));
    // Positive control: with the replacement in place from the start, the target is returned first.
    const replaced = await seeded(seeds);
    expect((await replaced.f.adapter.recallPassages(replaced.f.budget("alpha"))).passages.map(passage => passage.passage_id))
      .toEqual(["target", "other"]);
    expect(chunkReadsOf(replaced)).toBe(1); // And chunk reads are counted.
  });
});
