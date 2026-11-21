// fail-before-exempt: coverage pin for the refusal arm on a storage backend without readBounded; the bounded-read fail-before witness is the error round trip in test/storage/capability-error-read-bound.test.ts.
// Recall refuses, rather than reading a chunk record whole, when the storage backend offers no bounded read: the
// whole-record read is never substituted for the bounded one. The control recalls the same corpus on a backend that
// does offer it, so the refusal is the missing method and nothing else.
import { describe, expect, it } from "vitest";
import { HermesRecallBudget } from "../../src/hermes-memory-bridge/recall.js";
import { SdwValidationError } from "../../src/sdw/errors.js";
import { SDW_DOCUMENT_CORPUS_NAMESPACE } from "../../src/sdw/records.js";
import type { StorageBackend } from "../../src/storage/interface.js";
import { MemoryStorage } from "../../src/storage/memory.js";
import { TestSdwMemoryBackendAdapter } from "./test-memory-backend.js";

const MASTER = new Uint8Array(32).fill(54);
const FORTRESS = "no-bounded-read-refused";
const CREATED = "2026-11-01T00:00:00.000Z";

/** Records the key of every whole-record read call the store serves in the corpus namespace. */
function recordWholeReads(storage: StorageBackend): string[] {
  const keys: string[] = [];
  const read = storage.read.bind(storage);
  storage.read = async (namespace, key) => {
    if (namespace === SDW_DOCUMENT_CORPUS_NAMESPACE) keys.push(key);
    return read(namespace, key);
  };
  return keys;
}

async function corpus(withBoundedRead: boolean) {
  const storage = new MemoryStorage();
  const adapter = new TestSdwMemoryBackendAdapter({ storage, masterKey: MASTER, fortressId: FORTRESS, ownerRef: "agent",
    now: () => CREATED });
  await adapter.insertPassage({ passage_id: "notes", text: "board meeting notes" }, "user_content");
  // An own property shadows the class method, so this one store presents as a backend without the optional method.
  if (!withBoundedRead) Object.defineProperty(storage, "readBounded", { value: undefined });
  return { storage, adapter };
}

const recall = (adapter: TestSdwMemoryBackendAdapter) =>
  adapter.recallPassages(new HermesRecallBudget("board meeting", () => 0, new AbortController().signal));

describe("recall on a storage backend without readBounded", () => {
  it("refuses with operation_refused and never reads a chunk record with the whole-record read", async () => {
    const { storage, adapter } = await corpus(false);
    expect(storage.readBounded).toBeUndefined();
    const wholeReads = recordWholeReads(storage);
    const refusal = await recall(adapter).then(() => undefined, (error: unknown) => error);
    expect(refusal).toBeInstanceOf(SdwValidationError);
    expect((refusal as SdwValidationError).category).toBe("operation_refused");
    // The precondition for the read assertion: recall did reach the passage, so its document record was read.
    expect(wholeReads.some(key => key.startsWith("doc."))).toBe(true);
    expect(wholeReads.filter(key => key.startsWith("chunk."))).toEqual([]);
  });

  it("recalls the same corpus when the backend offers readBounded", async () => {
    const { adapter } = await corpus(true);
    const result = await recall(adapter);
    expect(result.passages.map(passage => passage.passage_id)).toEqual(["notes"]);
  });
});
