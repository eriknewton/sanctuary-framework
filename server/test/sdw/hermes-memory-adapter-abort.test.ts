import { describe, expect, it, vi } from "vitest";

import { createSdwMemoryAdapter, type HermesBridgeCommitCheck } from "../../src/index.js";
import { MemoryStorage } from "../../src/storage/memory.js";
import type { StorageBackend } from "../../src/storage/interface.js";
import {
  SdwMemoryBackendAdapter,
  withSdwMemoryCorpusMutationLock,
} from "../../src/sdw/adapters/sdw-memory-backend.js";
import { documentKey } from "../../src/sdw/grammar.js";
import { SDW_DOCUMENT_CORPUS_NAMESPACE } from "../../src/sdw/records.js";
import { SdwValidationError } from "../../src/sdw/errors.js";
import { memoryInsertIngress } from "../../src/sdw/memory-provenance-ingress.js";
import { testMemoryProvenanceDependencies } from "./test-memory-backend.js";

const MASTER_KEY = new Uint8Array(32).fill(13);
const OWNER_REF = "fleet-self";
const BAD_SIGNER_AUTHORITY = { async isMarked(): Promise<boolean> { return false; } };

function input(id: string, text: string) {
  return { passage_id: id, text, provenanceContext: memoryInsertIngress(() => "agent:probe", "user_content") };
}

function adapter(storage: StorageBackend, commitCheck: HermesBridgeCommitCheck): SdwMemoryBackendAdapter {
  const deps = testMemoryProvenanceDependencies(MASTER_KEY);
  return createSdwMemoryAdapter({
    mode: "hermes-bridge",
    storage,
    masterKey: MASTER_KEY,
    fortressId: "fortress:probe",
    ownerRef: OWNER_REF,
    resolvePrimarySigningHandle: deps.resolvePrimarySigningHandle,
    resolveSignerPublicKey: deps.resolveSignerPublicKey,
    resolveMemoryIntegrityState: async () => "state_PRE_MIGRATION",
    badSignerAuthority: BAD_SIGNER_AUTHORITY,
    commitCheck,
  });
}

function within<T>(p: Promise<T>, ms: number): Promise<T | "TIMEOUT"> {
  return Promise.race([p, new Promise<"TIMEOUT">((r) => setTimeout(() => r("TIMEOUT"), ms))]);
}

const tick = (ms = 20) => new Promise((r) => setTimeout(r, ms));

describe("Hermes bridge SDW memory abort boundary", () => {
  it("releases an in-memory namespace lock after an aborted waiter refuses", async () => {
    const storage = new MemoryStorage();
    let releaseHolder!: () => void;
    const held = new Promise<void>((r) => { releaseHolder = r; });
    const holder = storage.withNamespaceLock("probe_ns", "x.lock", async () => { await held; });
    const controller = new AbortController();
    const waiter = storage.withNamespaceLock("probe_ns", "x.lock", async () => undefined, {
      abortSignal: controller.signal,
    });
    controller.abort();
    await expect(waiter).rejects.toThrow(/aborted/);
    releaseHolder();
    await holder;
    const third = storage.withNamespaceLock("probe_ns", "x.lock", async () => "ran");
    expect(await within(third, 1000)).toBe("ran");
  });

  it("keeps a later corpus waiter behind the original holder when the middle waiter aborts", async () => {
    const storage = new MemoryStorage();
    let releaseA!: () => void;
    const heldA = new Promise<void>((r) => { releaseA = r; });
    let aRunning = false;
    let overlap = false;
    const a = withSdwMemoryCorpusMutationLock(storage, async () => {
      aRunning = true;
      await heldA;
      aRunning = false;
    });
    await tick();
    const controller = new AbortController();
    const b = withSdwMemoryCorpusMutationLock(storage, async () => undefined, {
      abortSignal: controller.signal,
      pollIntervalMs: 5,
    });
    const c = withSdwMemoryCorpusMutationLock(storage, async () => {
      if (aRunning) overlap = true;
    });
    controller.abort();
    await expect(b).rejects.toMatchObject({ category: "operation_aborted" });
    await tick(50);
    releaseA();
    await a;
    await c;
    expect(overlap).toBe(false);
  });

  it("refuses instead of entering the corpus critical section when abort races the grant", async () => {
    const storage = new MemoryStorage();
    let releaseA!: () => void;
    const heldA = new Promise<void>((r) => { releaseA = r; });
    const a = withSdwMemoryCorpusMutationLock(storage, async () => { await heldA; });
    await tick();
    const controller = new AbortController();
    let ranAfterAbort = false;
    const b = withSdwMemoryCorpusMutationLock(storage, async () => {
      if (controller.signal.aborted) ranAfterAbort = true;
    }, { abortSignal: controller.signal, pollIntervalMs: 1000 });
    releaseA();
    controller.abort();
    await a;
    await b.catch(() => undefined);
    expect(ranAfterAbort).toBe(false);
  });

  it("keeps the shared store usable after an adapter abort races the grant", async () => {
    const storage = new MemoryStorage();
    const controller = new AbortController();
    let releaseFirst!: () => void;
    const parked = new Promise<void>((r) => { releaseFirst = r; });
    let firstAtCheck = false;
    const one = adapter(storage, {
      abortSignal: controller.signal,
      async assertAllowedToCommit(ctx) {
        if (ctx.passageId === "first") {
          firstAtCheck = true;
          await parked;
        }
      },
    });
    const first = one.insertPassage(input("first", "a"), "user_content");
    for (let i = 0; i < 100 && !firstAtCheck; i += 1) await tick(5);
    const second = one.insertPassage(input("second", "b"), "user_content");
    await tick(30);
    releaseFirst();
    controller.abort();
    await first;
    await second.catch(() => undefined);
    const fresh = adapter(storage, { async assertAllowedToCommit() {} });
    const r = await within(fresh.insertPassage(input("third", "c"), "user_content"), 2000);
    expect(r).not.toBe("TIMEOUT");
  });

  it("does not arm a poll timer for default no-signal corpus callers", async () => {
    vi.useFakeTimers();
    try {
      const storage = new MemoryStorage();
      await withSdwMemoryCorpusMutationLock(storage, async () => undefined);
      expect(vi.getTimerCount()).toBe(0);
    } finally {
      vi.useRealTimers();
    }
  });

  it("refuses a queued insert after a prior insert latches the bridge", async () => {
    const storage = new (class extends MemoryStorage {
      failOnce = true;
      override async write(ns: string, key: string, data: Uint8Array): Promise<void> {
        if (this.failOnce && key === documentKey(`mem.${OWNER_REF}.first`)) {
          throw new Error("doc write fails");
        }
        await super.write(ns, key, data);
      }
      override async delete(ns: string, key: string, s?: boolean): Promise<boolean> {
        if (key.includes(`mem.${OWNER_REF}.first`)) {
          throw new SdwValidationError("partial_scope", "rollback delete failed");
        }
        return super.delete(ns, key, s);
      }
    })();
    let firstAtCheck = false;
    let release!: () => void;
    const parked = new Promise<void>((r) => { release = r; });
    const a = adapter(storage, {
      async assertAllowedToCommit(ctx) {
        if (ctx.passageId === "first") {
          firstAtCheck = true;
          await parked;
        }
      },
    });
    const first = a.insertPassage(input("first", "abcd"), "user_content");
    for (let i = 0; i < 100 && !firstAtCheck; i += 1) await tick(5);
    const second = a.insertPassage(input("second", "later"), "user_content");
    await tick(30);
    release();
    const firstResult = await first.then(() => "ok", (e) => e);
    expect(a.getHermesBridgeLatchReason()).not.toBeNull();
    expect(firstResult).toMatchObject({ category: "partial_scope" });
    const secondResult = await second.then(() => "committed", () => "refused");
    expect(secondResult).toBe("refused");
  });

  it("refuses Hermes bridge construction over storage without a lock capability", () => {
    const inner = new MemoryStorage();
    const bare: StorageBackend = {
      read: (namespace: string, key: string) => inner.read(namespace, key),
      write: (namespace: string, key: string, data: Uint8Array) =>
        inner.write(namespace, key, data),
      delete: (namespace: string, key: string, secureOverwrite?: boolean) =>
        inner.delete(namespace, key, secureOverwrite),
      list: (namespace: string, prefix?: string) => inner.list(namespace, prefix),
      exists: (namespace: string, key: string) => inner.exists(namespace, key),
      totalSize: () => inner.totalSize(),
    } as unknown as StorageBackend;
    expect(() => adapter(bare, { async assertAllowedToCommit() {} })).toThrow();
  });

  it("refuses an explicit undefined commit check at Hermes bridge construction", () => {
    const deps = testMemoryProvenanceDependencies(MASTER_KEY);
    expect(() => new SdwMemoryBackendAdapter({
      mode: "hermes-bridge",
      storage: new MemoryStorage(),
      masterKey: MASTER_KEY,
      fortressId: "fortress:probe",
      ownerRef: OWNER_REF,
      resolvePrimarySigningHandle: deps.resolvePrimarySigningHandle,
      resolveSignerPublicKey: deps.resolveSignerPublicKey,
      resolveMemoryIntegrityState: async () => "state_PRE_MIGRATION",
      badSignerAuthority: BAD_SIGNER_AUTHORITY,
      commitCheck: undefined as unknown as HermesBridgeCommitCheck,
    })).toThrow(/commit check/);
  });

  it("releases locks after a post-hook write failure rolls back cleanly", async () => {
    const storage = new (class extends MemoryStorage {
      fail = true;
      override async write(ns: string, key: string, data: Uint8Array): Promise<void> {
        if (this.fail && ns === SDW_DOCUMENT_CORPUS_NAMESPACE && key.startsWith("prov.")) {
          this.fail = false;
          throw new Error("provenance write fails");
        }
        await super.write(ns, key, data);
      }
    })();
    const a = adapter(storage, { async assertAllowedToCommit() {} });
    await expect(a.insertPassage(input("x1", "abcd"), "user_content")).rejects.toThrow();
    const keys = (await storage.list(SDW_DOCUMENT_CORPUS_NAMESPACE))
      .map((e) => e.key)
      .filter((k) => k.includes(`mem.${OWNER_REF}.`));
    expect(keys).toEqual([]);
    expect(a.getHermesBridgeLatchReason()).toBeNull();
    const r = await within(a.insertPassage(input("x2", "efgh"), "user_content"), 2000);
    expect(r).not.toBe("TIMEOUT");
  });
});
