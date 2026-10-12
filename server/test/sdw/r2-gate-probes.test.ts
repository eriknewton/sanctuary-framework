import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";

import { createSdwMemoryAdapter, type HermesBridgeCommitCheck } from "../../src/index.js";
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
function input(id: string, text: string) {
  return { passage_id: id, text, provenanceContext: memoryInsertIngress(() => "agent:probe", "user_content") };
}
function bridge(storage: StorageBackend, commitCheck: HermesBridgeCommitCheck, extra: Record<string, unknown> = {}) {
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

describe("r2 gate probes", () => {
  it("G1 custody-grade required lock still refuses a namespacePath-only decorator (main contract)", async () => {
    const dir = mkdtempSync(join(tmpdir(), "r2probe-"));
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
    it(`G2 corpus wait never runs fn after abort (abort at microtask depth ${depth})`, async () => {
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
    it(`G3 namespace wait never runs op after abort (abort at microtask depth ${depth})`, async () => {
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

  it("G4a duplicate insert refuses before the commit check (absence precedes hook)", async () => {
    const storage = new MemoryStorage();
    let calls = 0;
    const a = bridge(storage, { async assertAllowedToCommit() { calls += 1; } });
    await a.insertPassage(input("dup", "one"), "user_content");
    expect(calls).toBe(1);
    await expect(a.insertPassage(input("dup", "one"), "user_content")).rejects.toMatchObject({ category: "duplicate_passage" });
    expect(calls).toBe(1);
  });

  it("G4b candidate cap refuses before the commit check (capacity precedes hook)", async () => {
    const storage = new MemoryStorage();
    let calls = 0;
    const a = bridge(storage, { async assertAllowedToCommit() { calls += 1; } }, { provenanceCandidateCap: 1 });
    await a.insertPassage(input("cap1", "one"), "user_content");
    await expect(a.insertPassage(input("cap2", "two"), "user_content")).rejects.toMatchObject({ category: "candidate_cap" });
    expect(calls).toBe(1);
  });

  it("G5 a storage that becomes transactional after construction cannot commit around the hook", async () => {
    const storage = new MemoryStorage();
    let calls = 0;
    const a = bridge(storage, { async assertAllowedToCommit() { calls += 1; throw new Error("refuse"); } });
    Object.assign(storage, {
      async sdwTransaction<T>(fn: (txn: unknown) => Promise<T>): Promise<T> {
        return fn({
          read: (n: string, k: string) => storage.read(n, k),
          write: (n: string, k: string, d: Uint8Array) => storage.write(n, k, d),
          delete: (n: string, k: string) => storage.delete(n, k),
          list: (n: string, p?: string) => storage.list(n, p),
          exists: (n: string, k: string) => storage.exists(n, k),
        });
      },
    });
    await a.insertPassage(input("tx", "late transactional"), "user_content").catch(() => undefined);
    const keys = (await storage.list(SDW_DOCUMENT_CORPUS_NAMESPACE)).map((e) => e.key).filter((k) => k.includes("mem."));
    expect({ calls, keys }).toEqual({ calls: 1, keys: [] });
  });

  it("G6 standard mode refuses a commit check passed at runtime", () => {
    const deps = testMemoryProvenanceDependencies(MASTER_KEY);
    expect(() => new SdwMemoryBackendAdapter({
      storage: new MemoryStorage(), masterKey: MASTER_KEY, fortressId: "f", ownerRef: OWNER_REF,
      resolvePrimarySigningHandle: deps.resolvePrimarySigningHandle,
      resolveSignerPublicKey: deps.resolveSignerPublicKey,
      resolveMemoryIntegrityState: async () => "state_PRE_MIGRATION",
      commitCheck: { async assertAllowedToCommit() {} },
    } as never)).toThrow(/commit check/);
  });

  it("G7 factory hermes refusal through createSdwMemoryAdapter leaves nothing and next pass commits exactly one", async () => {
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
});
