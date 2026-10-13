import { describe, expect, it } from "vitest";

import { MemoryStorage } from "../../src/storage/memory.js";
import { withSdwMemoryCorpusMutationLock } from "../../src/sdw/adapters/sdw-memory-backend.js";

// A finished holder retires the queue tail only while that tail is still the
// current one; a later holder's tail must survive, so a third caller queues
// behind the running second holder instead of running beside it.

async function microtasks(n: number): Promise<void> {
  for (let i = 0; i < n; i += 1) await Promise.resolve();
}
const tick = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));

type Lock = (fn: () => Promise<void>) => Promise<void>;

async function thirdCallerOverlapsSecondHolder(lock: Lock): Promise<boolean | null> {
  let releaseA!: () => void;
  let releaseB!: () => void;
  const heldA = new Promise<void>((resolve) => { releaseA = resolve; });
  const heldB = new Promise<void>((resolve) => { releaseB = resolve; });
  let bEntered = false;
  let bExited = false;
  let cOverlapped: boolean | null = null;
  const a = lock(async () => { await heldA; });
  const b = lock(async () => { bEntered = true; await heldB; bExited = true; });
  await microtasks(5);
  releaseA();
  await a;
  await tick(5);
  expect(bEntered).toBe(true);
  const c = lock(async () => { cOverlapped = !bExited; });
  await tick(20);
  releaseB();
  await b;
  await c;
  return cOverlapped;
}

describe("lock queue tail retirement", () => {
  it("namespace lock: a caller arriving while the second holder runs waits for it", async () => {
    const storage = new MemoryStorage();
    const overlapped = await thirdCallerOverlapsSecondHolder((fn) =>
      storage.withNamespaceLock("tail_probe", "tail.lock", fn),
    );
    expect(overlapped).toBe(false);
  });

  it("memory corpus lock: a caller arriving while the second holder runs waits for it", async () => {
    const storage = new MemoryStorage();
    const overlapped = await thirdCallerOverlapsSecondHolder((fn) =>
      withSdwMemoryCorpusMutationLock(storage, fn),
    );
    expect(overlapped).toBe(false);
  });
});
