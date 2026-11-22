import { mkdir, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { FilesystemStorage } from "../../src/storage/filesystem.js";
import { MemoryStorage } from "../../src/storage/memory.js";
import { StateStore, isReservedNamespace } from "../../src/cognitive/state-store.js";
import { AGENT_DISCOVERY_SKIPPED_NAMESPACES, isAgentDiscoverySkippedNamespace, isAgentAggregateReservedNamespace } from "../../src/storage/agent-discovery.js";
import { MAX_DISCOVERED_NAMESPACES, MAX_NAMESPACE_DISCOVERY_ENTRIES, NAMESPACE_DISCOVERY_LIMIT_REMEDIATION, type StorageBackend } from "../../src/storage/interface.js";
import { withRequiredCrossProcessLock } from "../../src/storage/cross-process-lock.js";
import { generateRandomKey } from "../../src/core/random.js";
import { createTempFortress } from "../helpers/temp-fortress.js";

const cleanups: Array<() => Promise<void>> = [];
afterEach(async () => { for (const cleanup of cleanups.splice(0).reverse()) await cleanup(); });
async function filesystem() {
  const fortress = await createTempFortress("agent-aggregates");
  cleanups.push(fortress.cleanup);
  return { storage: new FilesystemStorage(fortress.storagePath), root: fortress.storagePath };
}
// The fallback lets the base witness reach the existing behavior and fail by assertion.
const size = (storage: StorageBackend) => storage.totalSizeOfNonReservedNamespaces?.() ?? storage.totalSize();
const discover = (storage: StorageBackend) => storage.listNamespacesForAgentDiscovery?.() ?? storage.listNamespaces!();

describe.each(["filesystem", "memory"] as const)("%s aggregates", (backend) => {
  async function storage() { return backend === "filesystem" ? (await filesystem()).storage : new MemoryStorage(); }
  it("health size counts only non-reserved namespaces", async () => {
    const s = await storage();
    // Three bytes are the complete ordinary fixture, independent of encrypted record formats.
    const ordinary = new Uint8Array([1, 2, 3]);
    await s.write("notes", "one", ordinary);
    expect(await size(s)).toBe(ordinary.length);
    for (const namespace of [...AGENT_DISCOVERY_SKIPPED_NAMESPACES, "_audit", "_identities"]) {
      await s.write(namespace, "one", ordinary);
      expect(await size(s)).toBe(ordinary.length);
    }
    await s.write("notes", "two", ordinary);
    expect(await size(s)).toBe(ordinary.length * 2); // Two ordinary records.
  });
  it("agent discovery returns the same set as before for every other namespace", async () => {
    const s = await storage();
    const ordinary = ["notes", "alpha", "_audit", "_identities"];
    for (const namespace of [...ordinary, ...AGENT_DISCOVERY_SKIPPED_NAMESPACES]) await s.write(namespace, "one", new Uint8Array([1]));
    expect(await discover(s)).toEqual((await s.listNamespaces!()).filter((ns) => !isAgentDiscoverySkippedNamespace(ns)));
    expect(await discover(s)).toEqual(ordinary.sort());
  });
  it("a backend without the agent discovery method makes export refuse", async () => {
    const s = await storage();
    Object.defineProperty(s, "listNamespacesForAgentDiscovery", { value: undefined });
    await expect(new StateStore(s, generateRandomKey()).listExportableNamespaces()).rejects.toThrow("cannot enumerate");
  });
});

it("filesystem agent discovery skips a local directory before charging its noise entries", async () => {
  const { storage, root } = await filesystem();
  await storage.write("notes", "one", new Uint8Array([1]));
  const noise = join(root, "_local_oplog");
  await mkdir(noise);
  // One beyond the shared discovery budget, with no encrypted entry to end the scan early.
  for (let i = 0; i <= MAX_NAMESPACE_DISCOVERY_ENTRIES; i++) await writeFile(join(noise, `noise-${i}`), "");
  await expect(storage.listNamespaces()).rejects.toThrow(NAMESPACE_DISCOVERY_LIMIT_REMEDIATION);
  await expect(discover(storage)).resolves.toEqual(["notes"]);
}, 120_000); // Two minutes bounds the production-size filesystem fixture, including cleanup.

it("memory agent discovery skips local namespaces before charging its namespace budget", async () => {
  const storage = new MemoryStorage();
  const ordinary = Array.from({ length: MAX_DISCOVERED_NAMESPACES }, (_, i) => `notes-${i}`).sort();
  for (const namespace of [...ordinary, "_local_oplog", "_local_results"]) await storage.write(namespace, "one", new Uint8Array([1]));
  await expect(storage.listNamespaces()).rejects.toThrow(NAMESPACE_DISCOVERY_LIMIT_REMEDIATION);
  await expect(discover(storage)).resolves.toEqual(ordinary);
});

it("pins aggregate reserved-name parity and the complete local skip set", () => {
  // Must match AGENT_DISCOVERY_SKIPPED_NAMESPACES in storage/agent-discovery.ts.
  expect(AGENT_DISCOVERY_SKIPPED_NAMESPACES).toEqual(["_local_results", "_local_disclosure", "_local_oplog"]);
  for (const name of ["", "notes", "notes/sub", "_", "__", "_audit", ...AGENT_DISCOVERY_SKIPPED_NAMESPACES]) {
    expect(isAgentAggregateReservedNamespace(name)).toBe(isReservedNamespace(name));
  }
});

it.runIf(process.platform === "darwin")("Darwin directory capabilities preserve the aggregate and discovery policy", async () => {
  const { storage } = await filesystem();
  const ordinary = new Uint8Array([1]);
  await storage.write("notes", "one", ordinary);
  await storage.write("_local_oplog", "one", ordinary);
  await withRequiredCrossProcessLock(storage, "_local_oplog", "test.lock", async () => {
    expect(await storage.totalSizeOfNonReservedNamespaces!()).toBe(ordinary.length);
    expect(await storage.listNamespacesForAgentDiscovery!()).toEqual(["notes"]);
    expect(await storage.listNamespaces()).toEqual(["_local_oplog", "notes"]);
  }, { kernelBacked: true });
});
