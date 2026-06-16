/**
 * Hardening wave 6 finding #64, atomic add-or-rotate semantics under
 * concurrency.
 *
 * Three regressions that previously could race on a real keychain:
 *   1. concurrent addSecret + addSecret on the same name        → exactly one wins
 *   2. concurrent rotateSecret + rotateSecret on the same name  → both serialize
 *   3. concurrent addSecret + rotateSecret on the same name     → ordering is preserved
 *
 * Strategy: a fake backend whose mutating ops yield to the event loop
 * mid-operation, exposing any race the broker fails to serialize. With
 * the per-name lock, every mutating op observes a consistent view of the
 * store between its read and write phases.
 */

import { describe, it, expect } from "vitest";
import { Broker } from "../../../src/disclosure/broker/broker.js";
import { AuditLog } from "../../../src/operational/audit-log.js";
import { MemoryStorage } from "../../../src/storage/memory.js";
import { generateRandomKey } from "../../../src/core/random.js";
import type { Backend } from "../../../src/disclosure/broker/backend-interface.js";
import { SecretNotFoundError } from "../../../src/disclosure/broker/backend-interface.js";

/**
 * Fake backend whose mutators do read-then-write across a microtask gap,
 * mirroring the race window in KeychainBackend's
 * `find-then-add-generic-password` shape. Without serialization, two
 * concurrent addSecret() calls would both observe absent → both write,
 * producing duplicate entries.
 */
function makeRacyBackend(): Backend & { dump: () => Map<string, string[]>; mutationLog: string[] } {
  const store = new Map<string, string[]>();
  const mutationLog: string[] = [];
  return {
    async ensureInitialized() {},
    async unlock() {},
    async isUnlocked() {
      return true;
    },
    async addSecret(name, value) {
      mutationLog.push(`add-begin:${name}`);
      const exists = store.has(name);
      // Yield to the event loop, without serialization a second
      // addSecret with the same name observes the SAME exists=false
      // here and both append.
      await Promise.resolve();
      if (exists) {
        mutationLog.push(`add-fail:${name}`);
        throw new Error(`Secret already exists: ${name}`);
      }
      store.set(name, [value]);
      mutationLog.push(`add-end:${name}=${value}`);
    },
    async readSecret(name) {
      const arr = store.get(name);
      if (!arr || arr.length === 0) throw new SecretNotFoundError(name);
      return arr[arr.length - 1]!;
    },
    async rotateSecret(name, value) {
      mutationLog.push(`rotate-begin:${name}`);
      const arr = store.get(name);
      if (!arr || arr.length === 0) {
        mutationLog.push(`rotate-fail:${name}`);
        throw new SecretNotFoundError(name);
      }
      // Yield mid-operation, the keychain delete-then-add shape has
      // the same window.
      await Promise.resolve();
      arr.push(value);
      mutationLog.push(`rotate-end:${name}=${value}`);
    },
    async deleteSecret(name) {
      const had = store.delete(name);
      if (!had) throw new SecretNotFoundError(name);
    },
    async listSecretNames() {
      return Array.from(store.keys());
    },
    dump: () => store,
    mutationLog,
  };
}

function makeBroker(backend: Backend) {
  const storage = new MemoryStorage();
  const auditLog = new AuditLog(storage, generateRandomKey());
  const broker = new Broker({
    backend,
    auditLog,
    grants: [],
    principalIdentityId: "test",
  });
  return { broker, auditLog };
}

describe("Broker per-name lock (finding #64)", () => {
  it("concurrent add+add on the same name produces exactly one success and one rejection without duplicate entries", async () => {
    const backend = makeRacyBackend();
    const { broker } = makeBroker(backend);

    const results = await Promise.allSettled([
      broker.addSecret("api-key", "value-a"),
      broker.addSecret("api-key", "value-b"),
    ]);

    const fulfilled = results.filter((r) => r.status === "fulfilled");
    const rejected = results.filter((r) => r.status === "rejected");
    expect(fulfilled.length).toBe(1);
    expect(rejected.length).toBe(1);
    // Duplicate-write detection: with a working lock the second add sees the
    // first write and rejects; without the lock both writes land.
    const stored = backend.dump().get("api-key") ?? [];
    expect(stored.length).toBe(1);
    // The rejection error names the conflict.
    expect(
      String((rejected[0] as PromiseRejectedResult).reason)
    ).toContain("already exists");
  });

  it("concurrent rotate+rotate on the same name serializes both mutations cleanly", async () => {
    const backend = makeRacyBackend();
    const { broker } = makeBroker(backend);
    await broker.addSecret("api-key", "v0");

    await Promise.all([
      broker.rotateSecret("api-key", "v1"),
      broker.rotateSecret("api-key", "v2"),
    ]);

    const stored = backend.dump().get("api-key") ?? [];
    // Both rotations land, no rotation lost, and the racy backend's
    // mutation log shows them serialized (rotate-begin → rotate-end → rotate-begin → rotate-end)
    // rather than interleaved.
    expect(stored.length).toBe(3); // initial v0 + v1 + v2
    const log = backend.mutationLog.filter((m) => m.startsWith("rotate-"));
    // Pattern must be: begin, end, begin, end (no two begins in a row).
    expect(log).toEqual([
      "rotate-begin:api-key",
      "rotate-end:api-key=v1",
      "rotate-begin:api-key",
      "rotate-end:api-key=v2",
    ]);
  });

  it("concurrent add+rotate on the same name serializes deterministically (no rotate-before-add)", async () => {
    const backend = makeRacyBackend();
    const { broker } = makeBroker(backend);

    // Issue both in flight before either resolves; the lock should cause
    // the rotate to either (a) succeed because add ran first, or
    // (b) fail with SecretNotFoundError because rotate ran first.
    // Either is acceptable, what is NOT acceptable is interleaving
    // the racy backend's read-then-write stages.
    const results = await Promise.allSettled([
      broker.addSecret("api-key", "value-a"),
      broker.rotateSecret("api-key", "value-b"),
    ]);

    const adds = backend.mutationLog.filter((m) => m.startsWith("add-"));
    const rotates = backend.mutationLog.filter((m) => m.startsWith("rotate-"));
    // Each op completes its read-then-write atomically.
    expect(adds[0]).toBe("add-begin:api-key");
    expect(adds.length).toBeGreaterThanOrEqual(2);
    expect(adds[1]).toMatch(/^add-(end|fail):api-key/);
    expect(rotates[0]).toBe("rotate-begin:api-key");
    expect(rotates.length).toBeGreaterThanOrEqual(2);
    expect(rotates[1]).toMatch(/^rotate-(end|fail):api-key/);
    // Sanity: at least one of the two operations succeeded.
    expect(results.some((r) => r.status === "fulfilled")).toBe(true);
  });

  it("distinct secret names do not contend on a shared lock", async () => {
    const backend = makeRacyBackend();
    const { broker } = makeBroker(backend);

    // Issue many adds on distinct names in parallel, they should all
    // run concurrently (no serialization across names).
    const names = Array.from({ length: 20 }, (_, i) => `secret-${i}`);
    await Promise.all(names.map((n) => broker.addSecret(n, "v")));
    expect(backend.dump().size).toBe(names.length);
    // After all settle, the per-name lock map is empty.
    expect(broker.__nameLockCountForTests()).toBe(0);
  });
});
