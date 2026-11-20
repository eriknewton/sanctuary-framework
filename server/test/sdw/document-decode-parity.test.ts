// Decoding document bytes a caller already read authenticates them exactly as the corpus store's own document read does.
import { expect, it } from "vitest";
import { bytesToString, stringToBytes } from "../../src/core/encoding.js";
import { encrypt } from "../../src/core/encryption.js";
import { derivePurposeKey } from "../../src/core/key-derivation.js";
import { SdwDocumentCorpusStore } from "../../src/sdw/document-corpus-store.js";
import { documentKey, sdwAad } from "../../src/sdw/grammar.js";
import { SDW_DOCUMENT_CORPUS_HKDF_INFO, SDW_DOCUMENT_CORPUS_NAMESPACE } from "../../src/sdw/records.js";
import { MemoryStorage } from "../../src/storage/memory.js";
import { TestSdwMemoryBackendAdapter } from "./test-memory-backend.js";

const MASTER = new Uint8Array(32).fill(41);
const FORTRESS = "decode-parity";
const OWNER = "agent";
const A = `mem.${OWNER}.alpha`;
const B = `mem.${OWNER}.bravo`;

/** Serves planted bytes for a key, as a file replaced on disk would read back; the write gate refuses writing them. */
class PlantingStorage extends MemoryStorage {
  readonly planted = new Map<string, Uint8Array>();
  override async read(namespace: string, key: string) {
    return this.planted.get(key)?.slice() ?? super.read(namespace, key);
  }
}

type Outcome = { readonly record: unknown } | { readonly error: string };
async function outcome(run: () => unknown): Promise<Outcome> {
  try {
    return { record: await run() };
  } catch (error) {
    const category = (error as { category?: string }).category;
    return { error: `${(error as Error).constructor.name}:${category ?? ""}` };
  }
}

async function fixture() {
  const storage = new PlantingStorage();
  const adapter = new TestSdwMemoryBackendAdapter({ storage, masterKey: MASTER, fortressId: FORTRESS, ownerRef: OWNER });
  await adapter.insertPassage({ passage_id: "alpha", text: "alpha passage" }, "user_content");
  await adapter.insertPassage({ passage_id: "bravo", text: "bravo passage" }, "user_content");
  const corpus = new SdwDocumentCorpusStore({ storage, masterKey: MASTER, fortressId: FORTRESS });
  const raw = async (documentId: string) => (await storage.read(SDW_DOCUMENT_CORPUS_NAMESPACE, documentKey(documentId)))!;
  /** Seal a plaintext record under the AAD of `atDocumentId`'s key, as a well-formed record stored there would be. */
  const sealAt = (atDocumentId: string, record: unknown) => stringToBytes(JSON.stringify(encrypt(
    stringToBytes(JSON.stringify(record)), derivePurposeKey(MASTER, SDW_DOCUMENT_CORPUS_HKDF_INFO),
    sdwAad(FORTRESS, SDW_DOCUMENT_CORPUS_NAMESPACE, documentKey(atDocumentId)))));
  const plant = (documentId: string, bytes: Uint8Array) => { storage.planted.set(documentKey(documentId), bytes); };
  return { storage, corpus, raw, sealAt, plant };
}

const cases = {
  "a valid record": { expected: "record" as const, async build(f: Awaited<ReturnType<typeof fixture>>) {
    return f.raw(A);
  } },
  "a record naming another document id": { expected: "SdwValidationError:identity_mismatch", async build(f: Awaited<ReturnType<typeof fixture>>) {
    return f.sealAt(A, (await f.corpus.getDocument(B))!);
  } },
  "a record of another kind": { expected: "SdwValidationError:identity_mismatch", async build(f: Awaited<ReturnType<typeof fixture>>) {
    return f.sealAt(A, { ...(await f.corpus.getDocument(A))!, kind: "document_chunk" });
  } },
  "another fortress's record": { expected: "SdwValidationError:auth_failed", async build() {
    const other = new MemoryStorage();
    const adapter = new TestSdwMemoryBackendAdapter({ storage: other, masterKey: MASTER, fortressId: "other-fortress", ownerRef: OWNER });
    await adapter.insertPassage({ passage_id: "alpha", text: "alpha passage" }, "user_content");
    return (await other.read(SDW_DOCUMENT_CORPUS_NAMESPACE, documentKey(A)))!;
  } },
  "altered bytes": { expected: "SdwValidationError:auth_failed", async build(f: Awaited<ReturnType<typeof fixture>>) {
    const envelope = JSON.parse(bytesToString(await f.raw(A))) as Record<string, string>;
    const field = Object.keys(envelope).find(key => key !== "v" && typeof envelope[key] === "string" && envelope[key]!.length > 4)!;
    const value = envelope[field]!;
    envelope[field] = (value[0] === "A" ? "B" : "A") + value.slice(1);
    return stringToBytes(JSON.stringify(envelope));
  } },
};

it.each(Object.keys(cases) as (keyof typeof cases)[])("decodeDocument and getDocumentRaw agree on %s", async name => {
  const f = await fixture();
  const bytes = await cases[name].build(f);
  f.plant(A, bytes);
  const decoded = await outcome(() => f.corpus.decodeDocument(A, bytes));
  const read = await outcome(async () => (await f.corpus.getDocumentRaw(A))!.record);
  const expected = cases[name].expected;
  // The property: the decode refuses exactly what the store's read refuses, with the same error class.
  if (expected === "record") expect("record" in decoded && (decoded.record as { document_id: string }).document_id).toBe(A);
  else expect(decoded).toEqual({ error: expected });
  expect(decoded).toEqual(read);
});
