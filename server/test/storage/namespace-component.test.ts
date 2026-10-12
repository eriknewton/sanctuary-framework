import { describe, expect, it } from "vitest";
import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { FilesystemStorage } from "../../src/storage/filesystem.js";
import { MemoryStorage } from "../../src/storage/memory.js";
import type { StorageBackend } from "../../src/storage/interface.js";

const INVALID_NAMESPACES = ["", ".", ".."];

const selfOwner = () => ({
  uid: process.getuid?.() ?? 0,
  gid: process.getgid?.() ?? 0,
});

async function expectStorageOperationsRefuse(
  storage: StorageBackend & {
    namespacePath?: (namespace: string) => string;
    withNamespaceLock?: <T>(
      namespace: string,
      lockFileName: string,
      operation: () => Promise<T>
    ) => Promise<T>;
  },
  namespace: string
): Promise<void> {
  await expect(storage.write(namespace, "k", new Uint8Array([1]))).rejects.toThrow(
    /namespace/
  );
  if ("writeDurable" in storage && typeof storage.writeDurable === "function") {
    await expect(
      storage.writeDurable(namespace, "k", new Uint8Array([1]))
    ).rejects.toThrow(/namespace/);
  }
  await expect(
    storage.writeIfAbsent?.(namespace, "k", new Uint8Array([1])) ??
      Promise.resolve(false)
  ).rejects.toThrow(/namespace/);
  await expect(
    storage.replaceIfEquals?.(
      namespace,
      "k",
      new Uint8Array([1]),
      new Uint8Array([2])
    ) ?? Promise.resolve(false)
  ).rejects.toThrow(/namespace/);
  await expect(storage.read(namespace, "k")).rejects.toThrow(/namespace/);
  await expect(storage.delete(namespace, "k")).rejects.toThrow(/namespace/);
  await expect(storage.list(namespace)).rejects.toThrow(/namespace/);
  await expect(storage.exists(namespace, "k")).rejects.toThrow(/namespace/);
  if (storage.namespacePath) {
    expect(() => storage.namespacePath!(namespace)).toThrow(/namespace/);
  }
  if (storage.withNamespaceLock) {
    await expect(
      storage.withNamespaceLock(namespace, "lock", async () => undefined)
    ).rejects.toThrow(/namespace/);
  }
}

describe("storage namespace names", () => {
  it("refuses namespace names that are not a single path component in filesystem and memory backends", async () => {
    const basePath = await mkdtemp(join(tmpdir(), "sanctuary-ns-component-"));
    try {
      const backends: Array<[string, StorageBackend]> = [
        ["filesystem", new FilesystemStorage(basePath)],
        ["memory", new MemoryStorage()],
      ];
      for (const [label, backend] of backends) {
        for (const namespace of INVALID_NAMESPACES) {
          await expectStorageOperationsRefuse(backend, namespace).catch((error) => {
            throw new Error(`${label} accepted ${JSON.stringify(namespace)}`, {
              cause: error,
            });
          });
        }
      }
    } finally {
      await rm(basePath, { recursive: true, force: true });
    }
  });

  it("refuses namespace names that are not a single path component in owner and non-owner filesystem modes", async () => {
    const basePath = await mkdtemp(join(tmpdir(), "sanctuary-ns-owner-"));
    try {
      const plain = new FilesystemStorage(join(basePath, "plain"));
      const ownedRoot = join(basePath, "owned");
      await mkdir(ownedRoot, { recursive: true, mode: 0o700 });
      const owned = new FilesystemStorage(ownedRoot, { owner: selfOwner() });

      for (const namespace of INVALID_NAMESPACES) {
        await expect(plain.write(namespace, "k", new Uint8Array([1]))).rejects.toThrow(
          /namespace/
        );
        await expect(owned.write(namespace, "k", new Uint8Array([1]))).rejects.toThrow(
          /namespace/
        );
      }
    } finally {
      await rm(basePath, { recursive: true, force: true });
    }
  });

  it("refuses namespace names decoded from existing directory components", async () => {
    const basePath = await mkdtemp(join(tmpdir(), "sanctuary-ns-existing-"));
    try {
      for (const encoded of ["!2E", "!2E!2E"]) {
        const nsPath = join(basePath, encoded);
        await mkdir(nsPath, { recursive: true, mode: 0o700 });
        await writeFile(join(nsPath, "k.enc"), new Uint8Array([1]));
      }
      await expect(new FilesystemStorage(basePath).listNamespaces()).rejects.toThrow(
        /namespace/
      );
    } finally {
      await rm(basePath, { recursive: true, force: true });
    }
  });

  it("keeps ordinary namespace names working", async () => {
    const basePath = await mkdtemp(join(tmpdir(), "sanctuary-ns-legit-"));
    try {
      const filesystem = new FilesystemStorage(basePath);
      const memory = new MemoryStorage();
      for (const storage of [filesystem, memory]) {
        for (const namespace of ["notes", "a.b", ".visible", "..notes", "..visible"]) {
          await storage.write(namespace, "k", new Uint8Array([namespace.length]));
          expect(await storage.read(namespace, "k")).toEqual(
            new Uint8Array([namespace.length])
          );
        }
      }
    } finally {
      await rm(basePath, { recursive: true, force: true });
    }
  });
});
