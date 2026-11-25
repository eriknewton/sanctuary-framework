// A bounded-read refusal keeps its type across the macOS directory-capability worker's IPC: the worker
// serializes the error to plain data and the parent rebuilds it. The worker itself runs only on macOS, so this
// drives the two halves of that encoding directly, with a JSON round trip standing in for the channel, and runs
// on every platform.
import { describe, expect, it } from "vitest";
import { deserializeCapabilityError, serializeCapabilityError } from "../../src/storage/filesystem.js";
import { StorageEnumerationBoundError, StorageReadBoundError } from "../../src/storage/interface.js";

/** What the parent sees after the worker sends this error: serialize, cross a plain-data channel, deserialize. */
function acrossWorker(error: unknown): Error {
  return deserializeCapabilityError(JSON.parse(JSON.stringify(serializeCapabilityError(error))));
}

describe("worker error encoding", () => {
  it("rebuilds StorageReadBoundError as that class, with its name and message", () => {
    const result = acrossWorker(new StorageReadBoundError());
    expect(result).toBeInstanceOf(StorageReadBoundError);
    expect(result.name).toBe("StorageReadBoundError");
    expect(result.message).toBe(new StorageReadBoundError().message);
  });

  it("an enumeration bound error crosses the capability worker as its own type", () => {
    const result = acrossWorker(new StorageEnumerationBoundError());
    expect(result).toBeInstanceOf(StorageEnumerationBoundError);
    expect(result).not.toBeInstanceOf(StorageReadBoundError);
    expect(result.name).toBe("StorageEnumerationBoundError");
    expect(result.message).toBe("Stored entries exceed the enumeration bound");
    expect(acrossWorker(new StorageReadBoundError())).not.toBeInstanceOf(StorageEnumerationBoundError);
  });

  it("does not type a generic error as a bounded-read refusal, even one carrying the same message", () => {
    const lookalike = new Error(new StorageReadBoundError().message);
    const result = acrossWorker(lookalike);
    expect(result).not.toBeInstanceOf(StorageReadBoundError);
    expect(result.message).toBe(lookalike.message);
  });
});
