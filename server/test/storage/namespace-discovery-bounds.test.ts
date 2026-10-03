/**
 * Durable namespace discovery fails closed within fixed space and work budgets.
 * LEGACY-BUG-001
 */
import { afterEach, describe, expect, it, vi } from "vitest";
import * as fs from "node:fs/promises";
import type { Dir, Dirent } from "node:fs";
import { FilesystemStorage } from "../../src/storage/filesystem.js";
import { MemoryStorage } from "../../src/storage/memory.js";
import { MAX_DISCOVERED_NAMESPACES, MAX_NAMESPACE_DISCOVERY_ENTRIES, NAMESPACE_DISCOVERY_LIMIT_REMEDIATION } from "../../src/storage/interface.js";

vi.mock("node:fs/promises", async (original) => {
  const actual = await original<typeof import("node:fs/promises")>();
  return { ...actual, opendir: vi.fn(actual.opendir), stat: vi.fn(actual.stat) };
});
afterEach(() => vi.resetAllMocks());

function entries(count: number, name: (index: number) => string, consumed: () => void, closed: () => void): Dir {
  return {
    async *[Symbol.asyncIterator]() {
      try {
        for (let i = 0; i < count; i++) {
          consumed();
          yield { name: name(i) } as Dirent;
        }
      } finally { closed(); }
    },
  } as Dir;
}

describe("namespace discovery bounds", () => {
  it("caps memory namespace snapshots including internal names", async () => {
    const storage = new MemoryStorage();
    for (let i = 0; i < MAX_DISCOVERED_NAMESPACES; i++) {
      await storage.write(`_internal-${i}`, "k", new Uint8Array());
    }
    expect(await storage.listNamespaces()).toHaveLength(MAX_DISCOVERED_NAMESPACES);
    await storage.write("one-more", "k", new Uint8Array());
    await expect(storage.listNamespaces()).rejects.toThrow(NAMESPACE_DISCOVERY_LIMIT_REMEDIATION);
  });

  it("bounds filesystem namespace retention and closes the iterator on overflow", async () => {
    let rootClosed = false;
    let seen = 0;
    vi.mocked(fs.stat).mockResolvedValue({ isDirectory: () => true } as Awaited<ReturnType<typeof fs.stat>>);
    vi.mocked(fs.opendir).mockImplementation(async (path) => path === "/discovery-test"
      ? entries(MAX_DISCOVERED_NAMESPACES * 2, (i) => `ns-${i}`, () => seen++, () => { rootClosed = true; })
      : entries(1, () => "k.enc", () => {}, () => {}));
    await expect(new FilesystemStorage("/discovery-test").listNamespaces()).rejects.toThrow(NAMESPACE_DISCOVERY_LIMIT_REMEDIATION);
    expect(seen).toBe(MAX_DISCOVERED_NAMESPACES + 1);
    expect(rootClosed).toBe(true);
  });

  it("charges one shared work budget and stops a hostile directory scan early", async () => {
    let seen = 0;
    let rootClosed = false;
    let childClosed = false;
    vi.mocked(fs.stat).mockResolvedValue({ isDirectory: () => true } as Awaited<ReturnType<typeof fs.stat>>);
    vi.mocked(fs.opendir).mockImplementation(async (path) => path === "/discovery-test"
      ? entries(1, () => "_internal", () => seen++, () => { rootClosed = true; })
      : entries(MAX_NAMESPACE_DISCOVERY_ENTRIES * 2, (i) => `junk-${i}`, () => seen++, () => { childClosed = true; }));
    await expect(new FilesystemStorage("/discovery-test").listNamespaces()).rejects.toThrow(NAMESPACE_DISCOVERY_LIMIT_REMEDIATION);
    expect(seen).toBe(MAX_NAMESPACE_DISCOVERY_ENTRIES + 1);
    expect(rootClosed && childClosed).toBe(true);
  });

  it("propagates root enumeration errors instead of declaring an empty store", async () => {
    vi.mocked(fs.opendir).mockRejectedValue(Object.assign(new Error("unreadable root"), { code: "EACCES" }));
    await expect(new FilesystemStorage("/discovery-test").listNamespaces()).rejects.toThrow("unreadable root");
  });

  it("propagates child enumeration errors instead of dropping a namespace", async () => {
    vi.mocked(fs.stat).mockResolvedValue({ isDirectory: () => true } as Awaited<ReturnType<typeof fs.stat>>);
    vi.mocked(fs.opendir)
      .mockResolvedValueOnce(entries(1, () => "notes", () => {}, () => {}))
      .mockRejectedValueOnce(Object.assign(new Error("unreadable namespace"), { code: "EACCES" }));
    await expect(new FilesystemStorage("/discovery-test").listNamespaces()).rejects.toThrow("unreadable namespace");
  });

  it("propagates metadata errors instead of dropping a namespace", async () => {
    vi.mocked(fs.opendir).mockResolvedValue(entries(1, () => "notes", () => {}, () => {}));
    vi.mocked(fs.stat).mockRejectedValue(Object.assign(new Error("metadata unavailable"), { code: "EIO" }));
    await expect(new FilesystemStorage("/discovery-test").listNamespaces()).rejects.toThrow("metadata unavailable");
  });

  it("allows a genuinely absent root as an empty store", async () => {
    vi.mocked(fs.opendir).mockRejectedValue(Object.assign(new Error("absent"), { code: "ENOENT" }));
    expect(await new FilesystemStorage("/discovery-test").listNamespaces()).toEqual([]);
  });
});
