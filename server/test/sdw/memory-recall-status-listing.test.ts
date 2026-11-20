// The recall screen learns which passages have a status record from one listing per call, so a passage
// without one costs no status read there; verification still re-reads every candidate's status record itself.
import { describe, expect, it } from "vitest";
import { toBase64url } from "../../src/core/encoding.js";
import { hash } from "../../src/core/hashing.js";
import { MEMORY_CORPUS_SCAN_CAP } from "../../src/hermes-memory-bridge/constants.js";
import { documentProvenanceKey, documentProvenanceStatusKey } from "../../src/sdw/grammar.js";
import { SDW_DOCUMENT_CORPUS_NAMESPACE } from "../../src/sdw/records.js";
import { passageContentHash } from "../../src/sdw/write-gate.js";
import { NOW, OWNER, oracleRecall, recallFixture, referenceRecall, type Seed } from "./recall-score-first-fixture.js";

const CORPUS = 20; // Enough passages that a per-passage read count cannot be mistaken for a per-call one.
const STATUS_PREFIX = `prov-status.mem.${OWNER}.`; // documentProvenanceStatusKey for this owner's document ids.
const filler = (n: number): Seed => ({ kind: "valid", passageId: `p${String(n).padStart(2, "0")}`, createdAt: NOW,
  text: `Note ${n}: the garden item moved to week ${n}.` });

async function seeded(seeds: readonly Seed[]) {
  const f = await recallFixture();
  for (const seed of seeds) await f.seed(seed);
  const reads = new Map<string, number>();
  const lists: string[] = [];
  f.storage.beforeRead = key => { reads.set(key, (reads.get(key) ?? 0) + 1); };
  const list = f.storage.list.bind(f.storage);
  let afterStatusList: (() => Promise<void>) | undefined;
  f.storage.list = async (namespace, prefix) => {
    const entries = await list(namespace, prefix);
    lists.push(prefix ?? "");
    if (prefix === STATUS_PREFIX) await afterStatusList?.();
    return entries;
  };
  const statusReads = (passageId: string) => reads.get(documentProvenanceStatusKey(f.documentIdOf(passageId))) ?? 0;
  const chunkReads = (passageId: string) => reads.get(f.firstChunkKey(f.documentIdOf(passageId))) ?? 0;
  return { f, reads, lists, statusReads, chunkReads, onStatusList(run: () => Promise<void>) { afterStatusList = run; } };
}

/** A quarantine status record matching the passage's current document and provenance, as memory_get would write. */
async function quarantine(f: Awaited<ReturnType<typeof recallFixture>>, passageId: string): Promise<void> {
  const documentId = f.documentIdOf(passageId);
  const document = (await f.corpus.getDocument(documentId))!;
  const raw = await f.storage.read(SDW_DOCUMENT_CORPUS_NAMESPACE, documentProvenanceKey(documentId));
  await f.corpus.putProvenanceStatus({ kind: "memory_provenance_status", version: 1, document_id: documentId,
    status: "quarantined", reason: "origin_signature_invalid", observed_content_hash: document.content_hash,
    observed_provenance_sha256: toBase64url(hash(raw!)), updated_at: NOW }, "agent_derived_clean");
}

/** Status records for documents that do not exist: listed under the owner's prefix, never read by recall. */
async function orphanStatuses(f: Awaited<ReturnType<typeof recallFixture>>, count: number): Promise<void> {
  for (let n = 0; n < count; n++) {
    await f.corpus.putProvenanceStatus({ kind: "memory_provenance_status", version: 1,
      document_id: f.documentIdOf(`orphan${String(n).padStart(4, "0")}`), status: "quarantined",
      reason: "origin_signature_invalid", observed_content_hash: passageContentHash(`orphan ${n}`),
      observed_provenance_sha256: toBase64url(hash(new Uint8Array())), updated_at: NOW }, "agent_derived_clean");
  }
}

describe("status presence from one listing, in the screen only", () => {
  it("reads no status record in the screen for a passage without one", async () => {
    const target: Seed = { kind: "valid", passageId: "target", createdAt: NOW, text: "the alpha handover is Friday" };
    const quarantined: Seed = { kind: "quarantined", passageId: "held", createdAt: NOW, text: "alpha alpha alpha" };
    const seeds = [...Array.from({ length: CORPUS }, (_, n) => filler(n)), target, quarantined];
    const run = await seeded(seeds);
    const result = await run.f.adapter.recallPassages(run.f.budget("alpha"));
    expect(result).toEqual(oracleRecall(seeds, "state_PRE_MIGRATION", "alpha"));
    expect(run.lists.filter(prefix => prefix === STATUS_PREFIX)).toHaveLength(1);
    for (const seed of seeds) {
      // Positive controls: the listed quarantined passage is read and skipped; the verified candidate re-reads its own.
      expect(run.statusReads(seed.passageId)).toBe(seed === target || seed === quarantined ? 1 : 0);
    }
    expect(run.chunkReads("held")).toBe(0);
    expect(run.chunkReads("target")).toBe(1); // Positive control: chunk reads are counted.
  });

  it("skips a candidate whose status record is written after the listing, and equals the reference on the final state", async () => {
    const ranked: Seed[] = [3, 2, 1].map(n => ({ kind: "valid", passageId: `r${n}`, createdAt: NOW, text: "alpha ".repeat(n) }));
    const seeds = [...Array.from({ length: CORPUS }, (_, n) => filler(n)), ...ranked];
    const run = await seeded(seeds);
    run.onStatusList(() => quarantine(run.f, "r3"));
    const verifications = run.f.countVerifications();
    const result = await run.f.adapter.recallPassages(run.f.budget("alpha"));
    expect(result.passages.map(passage => passage.passage_id)).toEqual(["r2", "r1"]);
    // The screen trusted the listing and scored the top candidate (its chunk was read, its units spent); the
    // verification phase re-read its status record and skipped it before verifying its companion.
    expect(run.chunkReads("r3")).toBe(1);
    expect(run.statusReads("r3")).toBe(1);
    expect(verifications.count()).toBe(2);
    expect(result).toEqual(oracleRecall([...seeds.filter(seed => seed.passageId !== "r3"), { ...ranked[0]!, kind: "quarantined" }],
      "state_PRE_MIGRATION", "alpha"));
    run.f.storage.beforeRead = undefined;
    expect(result).toEqual(await referenceRecall(run.f.adapter, run.f.budget("alpha")));
  });
});

describe("the status listing is bounded by MEMORY_CORPUS_SCAN_CAP", () => {
  const target: Seed = { kind: "valid", passageId: "target", createdAt: NOW, text: "the alpha handover is Friday" };
  const seeds = [...Array.from({ length: CORPUS }, (_, n) => filler(n)), target];
  it.each([
    { listed: MEMORY_CORPUS_SCAN_CAP, hinted: true },
    { listed: MEMORY_CORPUS_SCAN_CAP + 1, hinted: false },
  ])("$listed listed status records: the screen trusts the listing: $hinted", async ({ listed, hinted }) => {
    const run = await seeded(seeds);
    await orphanStatuses(run.f, listed);
    run.reads.clear();
    const result = await run.f.adapter.recallPassages(run.f.budget("alpha"));
    expect(result).toEqual(oracleRecall(seeds, "state_PRE_MIGRATION", "alpha"));
    // Past the cap the hint is dropped and every screened passage reads its status record, as before the hint.
    for (const seed of seeds) expect(run.statusReads(seed.passageId)).toBe((hinted ? 0 : 1) + (seed === target ? 1 : 0));
    // No orphan status record is ever read: the listing holds keys only.
    expect([...run.reads.keys()].filter(key => key.includes(".orphan"))).toEqual([]);
    run.f.storage.beforeRead = undefined;
    expect(result).toEqual(await referenceRecall(run.f.adapter, run.f.budget("alpha")));
  }, 120_000);
});
