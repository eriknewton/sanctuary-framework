import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";

import { createSdwMemoryAdapter, type HermesBridgeCommitCheck } from "../../src/index.js";
import { FilesystemStorage } from "../../src/storage/filesystem.js";
import { MemoryStorage } from "../../src/storage/memory.js";
import type { StorageBackend } from "../../src/storage/interface.js";
import { withRequiredCrossProcessLock } from "../../src/storage/cross-process-lock.js";
import {
  SdwMemoryBackendAdapter,
  withSdwMemoryCorpusMutationLock,
} from "../../src/sdw/adapters/sdw-memory-backend.js";
import { SDW_DOCUMENT_CORPUS_NAMESPACE } from "../../src/sdw/records.js";
import { memoryInsertIngress } from "../../src/sdw/memory-provenance-ingress.js";
import { testMemoryProvenanceDependencies } from "./test-memory-backend.js";

const MASTER_KEY = new Uint8Array(32).fill(13);
const OWNER_REF = "fleet-self";
const BAD = { async isMarked(): Promise<boolean> { return false; } };
const tempDirs: string[] = [];

afterEach(async () => {
  for (const dir of tempDirs.splice(0)) {
    await rm(dir, { recursive: true, force: true }).catch(() => undefined);
  }
});

async function tempDir(prefix: string): Promise<string> {
  const dir = await mkdtemp(join(tmpdir(), `${prefix}-`));
  tempDirs.push(dir);
  return dir;
}

function input(id: string, text: string) {
  return { passage_id: id, text, provenanceContext: memoryInsertIngress(() => "agent:probe", "user_content") };
}
function bridge(
  storage: StorageBackend,
  commitCheck: HermesBridgeCommitCheck,
  extra: Record<string, unknown> = {},
): SdwMemoryBackendAdapter {
  const deps = testMemoryProvenanceDependencies(MASTER_KEY);
  return new SdwMemoryBackendAdapter({
    mode: "hermes-bridge", storage, masterKey: MASTER_KEY, fortressId: "fortress:probe", ownerRef: OWNER_REF,
    resolvePrimarySigningHandle: deps.resolvePrimarySigningHandle,
    resolveSignerPublicKey: deps.resolveSignerPublicKey,
    resolveMemoryIntegrityState: async () => "state_PRE_MIGRATION",
    badSignerAuthority: BAD, commitCheck, ...extra,
  } as never);
}
async function microtasks(n: number): Promise<void> { for (let i = 0; i < n; i += 1) await Promise.resolve(); }
const tick = (ms = 20) => new Promise((r) => setTimeout(r, ms));

async function memKeys(storage: StorageBackend): Promise<string[]> {
  return (await storage.list(SDW_DOCUMENT_CORPUS_NAMESPACE))
    .map((entry) => entry.key)
    .filter((key) => key.includes("mem."));
}

function makeLateTransactional(storage: MemoryStorage): void {
  Object.assign(storage, {
    async sdwTransaction<T>(fn: (txn: unknown) => Promise<T>): Promise<T> {
      return fn({
        read: (namespace: string, key: string) => storage.read(namespace, key),
        write: (namespace: string, key: string, data: Uint8Array) =>
          storage.write(namespace, key, data),
        delete: (namespace: string, key: string) => storage.delete(namespace, key),
        list: (namespace: string, prefix?: string) => storage.list(namespace, prefix),
        exists: (namespace: string, key: string) => storage.exists(namespace, key),
      });
    },
  });
}

describe("Hermes memory adapter invariants", () => {
  it("custody-grade required locks refuse a namespacePath-only decorator", async () => {
    const dir = await tempDir("hermes-required-lock");
    const inner = new MemoryStorage();
    const decorator = {
      read: (n: string, k: string) => inner.read(n, k),
      write: (n: string, k: string, d: Uint8Array) => inner.write(n, k, d),
      delete: (n: string, k: string) => inner.delete(n, k),
      list: (n: string, p?: string) => inner.list(n, p),
      exists: (n: string, k: string) => inner.exists(n, k),
      totalSize: () => inner.totalSize(),
      namespacePath: (n: string) => join(dir, n),
      writeDurable: (n: string, k: string, d: Uint8Array) => inner.write(n, k, d),
    } as unknown as StorageBackend;
    let ran = false;
    await expect(withRequiredCrossProcessLock(decorator, "ns", "x.lock", async () => { ran = true; }))
      .rejects.toMatchObject({ kind: "capability" });
    expect(ran).toBe(false);
  });

  for (const depth of [0, 1, 2, 3, 4, 5, 6, 7, 8]) {
    it(`corpus waits refuse before the critical section after abort at microtask depth ${depth}`, async () => {
      const storage = new MemoryStorage();
      const controller = new AbortController();
      let ranAborted = false;
      const b = withSdwMemoryCorpusMutationLock(storage, async () => {
        if (controller.signal.aborted) ranAborted = true;
      }, { abortSignal: controller.signal });
      await microtasks(depth);
      controller.abort();
      await b.catch(() => undefined);
      expect(ranAborted).toBe(false);
    });
    it(`namespace waits refuse before the critical section after abort at microtask depth ${depth}`, async () => {
      const storage = new MemoryStorage();
      const controller = new AbortController();
      let ranAborted = false;
      const b = storage.withNamespaceLock("probe_ns", "x.lock", async () => {
        if (controller.signal.aborted) ranAborted = true;
      }, { abortSignal: controller.signal });
      await microtasks(depth);
      controller.abort();
      await b.catch(() => undefined);
      expect(ranAborted).toBe(false);
    });
  }

  it("duplicate inserts refuse before the commit check", async () => {
    const storage = new MemoryStorage();
    let calls = 0;
    const a = bridge(storage, { async assertAllowedToCommit() { calls += 1; } });
    await a.insertPassage(input("dup", "one"), "user_content");
    expect(calls).toBe(1);
    await expect(a.insertPassage(input("dup", "one"), "user_content")).rejects.toMatchObject({ category: "duplicate_passage" });
    expect(calls).toBe(1);
  });

  it("candidate capacity refuses before the commit check", async () => {
    const storage = new MemoryStorage();
    let calls = 0;
    const a = bridge(storage, { async assertAllowedToCommit() { calls += 1; } }, { provenanceCandidateCap: 1 });
    await a.insertPassage(input("cap1", "one"), "user_content");
    await expect(a.insertPassage(input("cap2", "two"), "user_content")).rejects.toMatchObject({ category: "candidate_cap" });
    expect(calls).toBe(1);
  });

  it("late transactional storage refuses before the commit check and writes nothing", async () => {
    const storage = new MemoryStorage();
    let calls = 0;
    const a = bridge(storage, { async assertAllowedToCommit() { calls += 1; } });
    makeLateTransactional(storage);
    await expect(a.insertPassage(input("tx", "late transactional"), "user_content"))
      .rejects.toMatchObject({ category: "operation_refused" });
    expect({ calls, keys: await memKeys(storage) }).toEqual({ calls: 0, keys: [] });
  });

  it("standard mode refuses a commit check passed at runtime", () => {
    const deps = testMemoryProvenanceDependencies(MASTER_KEY);
    expect(() => new SdwMemoryBackendAdapter({
      storage: new MemoryStorage(), masterKey: MASTER_KEY, fortressId: "f", ownerRef: OWNER_REF,
      resolvePrimarySigningHandle: deps.resolvePrimarySigningHandle,
      resolveSignerPublicKey: deps.resolveSignerPublicKey,
      resolveMemoryIntegrityState: async () => "state_PRE_MIGRATION",
      commitCheck: { async assertAllowedToCommit() {} },
    } as never)).toThrow(/commit check/);
  });

  it("factory Hermes refusal leaves nothing and the next pass commits exactly one", async () => {
    const storage = new MemoryStorage();
    let refuse = true;
    const deps = testMemoryProvenanceDependencies(MASTER_KEY);
    const a = createSdwMemoryAdapter({
      mode: "hermes-bridge", storage, masterKey: MASTER_KEY, fortressId: "f", ownerRef: OWNER_REF,
      resolvePrimarySigningHandle: deps.resolvePrimarySigningHandle,
      resolveSignerPublicKey: deps.resolveSignerPublicKey,
      resolveMemoryIntegrityState: async () => "state_PRE_MIGRATION",
      badSignerAuthority: BAD,
      commitCheck: { async assertAllowedToCommit() { if (refuse) throw new Error("no"); } },
    });
    await expect(a.insertPassage(input("w1", "x"), "user_content")).rejects.toThrow();
    expect((await storage.list(SDW_DOCUMENT_CORPUS_NAMESPACE)).filter((e) => e.key.includes("mem."))).toEqual([]);
    refuse = false;
    await a.insertPassage(input("w1", "x"), "user_content");
    expect((await storage.list(SDW_DOCUMENT_CORPUS_NAMESPACE, `doc.mem.${OWNER_REF}.`))).toHaveLength(1);
  });

  it("bridge inserts refuse if the namespace lock capability disappears after construction", async () => {
    const storage = new MemoryStorage();
    const a = bridge(storage, { async assertAllowedToCommit() {} });
    Object.defineProperty(storage, "withNamespaceLock", { value: undefined, configurable: true });
    await expect(a.insertPassage(input("gone", "x"), "user_content"))
      .rejects.toMatchObject({ kind: "capability" });
    expect(await memKeys(storage)).toEqual([]);
  });

  it("bridge inserts hold the batch namespace lock before the commit check", async () => {
    const storage = new MemoryStorage();
    let reached = false;
    const a = bridge(storage, { async assertAllowedToCommit() { reached = true; } });
    let releaseExternal!: () => void;
    const held = new Promise<void>((resolve) => { releaseExternal = resolve; });
    const external = storage.withNamespaceLock(
      "sdw_memory_locks",
      (a as unknown as { ownerScopeBatchLockFile(): string }).ownerScopeBatchLockFile(),
      async () => { await held; },
    );
    await tick(5);
    const insert = a.insertPassage(input("ext", "x"), "user_content");
    await tick(50);
    expect(reached).toBe(false);
    releaseExternal();
    await external;
    await insert;
    expect(reached).toBe(true);
  });

  it("filesystem bridge inserts share the real namespace lock and forward abort", async () => {
    const dir = await tempDir("hermes-fs-lock");
    const firstStorage = new FilesystemStorage(dir);
    const secondStorage = new FilesystemStorage(dir);
    let releaseFirst!: () => void;
    const parked = new Promise<void>((resolve) => { releaseFirst = resolve; });
    let firstAtCheck = false;
    let secondAtCheck = false;
    const firstAdapter = bridge(firstStorage, {
      async assertAllowedToCommit() {
        firstAtCheck = true;
        await parked;
      },
    });
    const controller = new AbortController();
    const secondAdapter = bridge(secondStorage, {
      abortSignal: controller.signal,
      async assertAllowedToCommit() {
        secondAtCheck = true;
      },
    });

    const first = firstAdapter.insertPassage(input("fsone", "a"), "user_content");
    for (let i = 0; i < 200 && !firstAtCheck; i += 1) await tick(10);
    expect(firstAtCheck).toBe(true);

    const second = secondAdapter.insertPassage(input("fstwo", "b"), "user_content");
    await tick(300);
    expect(secondAtCheck).toBe(false);
    controller.abort();
    await expect(second).rejects.toMatchObject({ kind: "operation_aborted" });
    expect(secondAtCheck).toBe(false);

    releaseFirst();
    await first;
    expect((await memKeys(firstStorage)).some((key) => key.includes("doc."))).toBe(true);

    const freshAdapter = bridge(new FilesystemStorage(dir), { async assertAllowedToCommit() {} });
    await freshAdapter.insertPassage(input("fsthree", "c"), "user_content");
  }, 20_000);
});
