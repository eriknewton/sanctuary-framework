// Bounded names-only enumeration: a namespace's keys come back complete, or the call refuses once it has
// seen one entry more than its bound, so a caller holds at most bound plus one names. Both backends run the
// same cases; the filesystem backend also counts non-key directory entries, and the capability worker
// applies the bound to its own scan.
import { spawn, type ChildProcess } from "node:child_process";
import { once } from "node:events";
import fs, { mkdir, mkdtemp, rm, stat, writeFile } from "node:fs/promises";
import { createRequire, syncBuiltinESMExports } from "node:module";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { FilesystemStorage } from "../../src/storage/filesystem.js";
import { MemoryStorage } from "../../src/storage/memory.js";
import { ReadOnlyStorageGuard } from "../../src/storage/read-only-guard.js";
import { StorageEnumerationBoundError, type StorageBackend } from "../../src/storage/interface.js";

let root: string;
const children: ChildProcess[] = [];
beforeEach(async () => {
  root = await mkdtemp(join(tmpdir(), "list-keys-bounded-"));
  vi.stubEnv("HOME", root);
});
afterEach(async () => {
  for (const child of children.splice(0)) {
    if (child.exitCode === null && child.signalCode === null) {
      const exit = once(child, "exit"); child.kill("SIGKILL"); await exit;
    }
  }
  vi.restoreAllMocks();
  syncBuiltinESMExports();
  vi.unstubAllEnvs();
  await rm(root, { recursive: true, force: true });
});

const NAMESPACE = "fixture";

interface Backend {
  name: string;
  make(): StorageBackend;
  /** Count every entry the implementation sees while it enumerates. */
  countSeen(storage: StorageBackend): { seen: () => number };
}

const backends: Backend[] = [
  {
    name: "MemoryStorage",
    make: () => new MemoryStorage(),
    countSeen(storage) {
      let seen = 0;
      const store = (storage as unknown as { store: Map<string, unknown> }).store;
      const keys = store.keys.bind(store);
      store.keys = function* () { for (const key of keys()) { seen++; yield key; } } as typeof store.keys;
      return { seen: () => seen };
    },
  },
  {
    name: "FilesystemStorage",
    make: () => new FilesystemStorage(join(root, "fortress")),
    countSeen() {
      let seen = 0;
      const real = fs.opendir;
      vi.spyOn(fs, "opendir").mockImplementation(async (...args: Parameters<typeof fs.opendir>) => {
        const dir = await real(...args);
        return { async *[Symbol.asyncIterator]() { for await (const entry of dir) { seen++; yield entry; } } } as never;
      });
      syncBuiltinESMExports();
      return { seen: () => seen };
    },
  },
];

async function seed(storage: StorageBackend, keys: string[]): Promise<void> {
  for (const key of keys) await storage.write(NAMESPACE, key, new Uint8Array([1]));
}

describe.each(backends)("$name", (backend) => {
  it("listKeysBounded returns every key at the bound", async () => {
    const storage = backend.make();
    await seed(storage, ["b", "a", "C"]);
    expect(await storage.listKeysBounded!(NAMESPACE, 3)).toEqual(["C", "a", "b"]);
    expect(await new ReadOnlyStorageGuard(storage).listKeysBounded!(NAMESPACE, 3)).toEqual(["C", "a", "b"]);
  });

  it("listKeysBounded throws past its bound and never holds more than bound plus one names", async () => {
    const storage = backend.make();
    await seed(storage, ["k1", "k2", "k3", "k4", "k5", "k6", "k7", "k8"]);
    const counter = backend.countSeen(storage);
    await expect(storage.listKeysBounded!(NAMESPACE, 3)).rejects.toBeInstanceOf(StorageEnumerationBoundError);
    expect(counter.seen()).toBe(4);
  });

  it("listKeysBounded refuses a bound that is not a non-negative safe integer", async () => {
    const storage = backend.make();
    await seed(storage, ["a"]);
    for (const bound of [-1, 1.5, Number.NaN, Number.POSITIVE_INFINITY, Number.MAX_SAFE_INTEGER + 1]) {
      await expect(storage.listKeysBounded!(NAMESPACE, bound)).rejects.toThrow(
        "Enumeration bound must be a non-negative safe integer",
      );
    }
  });

  it("listKeysBounded on a missing namespace returns an empty list", async () => {
    const storage = backend.make();
    expect(await storage.listKeysBounded!("absent", 0)).toEqual([]);
    expect(await storage.listKeysBounded!("absent", 4)).toEqual([]);
  });
});

describe("FilesystemStorage scan bound", () => {
  it("listKeysBounded counts non-key directory entries toward its bound", async () => {
    const base = join(root, "fortress");
    const storage = new FilesystemStorage(base);
    await seed(storage, ["a", "b"]);
    await writeFile(join(base, NAMESPACE, "a.enc.tmp-1"), "partial");
    await mkdir(join(base, NAMESPACE, "nested"));
    await expect(storage.listKeysBounded(NAMESPACE, 3)).rejects.toBeInstanceOf(StorageEnumerationBoundError);
    expect(await storage.listKeysBounded(NAMESPACE, 4)).toEqual(["a", "b"]);
  });
});

async function worker(cwd: string) {
  const identity = await stat(cwd, { bigint: true });
  const child = spawn(process.execPath, ["--import", createRequire(import.meta.url).resolve("tsx"),
    fileURLToPath(new URL("../../src/storage/directory-capability-worker.ts", import.meta.url)),
    String(identity.dev), String(identity.ino)], {
    cwd, stdio: ["ignore", "ignore", "pipe", "ipc"], env: { ...process.env, HOME: root, SANCTUARY_STORAGE_PATH: root },
  });
  children.push(child);
  let stderr = ""; child.stderr?.on("data", (data) => { stderr += String(data); });
  await new Promise<void>((resolve, reject) => {
    child.once("error", reject);
    child.once("exit", (code) => reject(new Error(`worker exited before ready: ${code}: ${stderr}`)));
    child.on("message", (message: { ready?: boolean }) => { if (message.ready) resolve(); });
  });
  let id = 0;
  return async (op: string, args: unknown[]): Promise<unknown> => {
    const requestId = ++id;
    return new Promise((resolve, reject) => {
      const receive = (message: { id?: number; ok?: boolean; value?: unknown; error?: { message: string } }) => {
        if (message.id !== requestId) return;
        child.off("message", receive);
        if (message.ok) resolve(message.value);
        else reject(Object.assign(new Error(message.error!.message), message.error));
      };
      child.on("message", receive);
      child.send({ id: requestId, op, args, boundNamespace: true });
    });
  };
}

describe("capability worker", () => {
  it("the capability worker refuses an invalid bound and reports an over-bound scan as its own type", async () => {
    const dir = join(root, NAMESPACE);
    await mkdir(dir);
    for (const key of ["a", "b", "c"]) await writeFile(join(dir, `${key}.enc`), "fixture");
    const call = await worker(dir);
    expect(await call("listKeysBounded", [3])).toEqual(["a", "b", "c"]);
    await expect(call("listKeysBounded", [2])).rejects.toMatchObject({ type: "storage_enumeration_bound" });
    for (const bound of [-1, 1.5, "x"]) {
      await expect(call("listKeysBounded", [bound])).rejects.toMatchObject({
        message: "Enumeration bound must be a non-negative safe integer",
      });
    }
  }, 30_000); // One real worker startup includes the production CLI import graph.

  it("the capability worker refuses a bound that is not a number, as the direct backend does", async () => {
    const dir = join(root, NAMESPACE);
    await mkdir(dir);
    await writeFile(join(dir, "a.enc"), "fixture");
    const direct = new FilesystemStorage(join(root, "direct"));
    await direct.write(NAMESPACE, "a", new Uint8Array([1]));
    const call = await worker(dir);
    for (const bound of [null, true, "3", []]) {
      await expect(direct.listKeysBounded(NAMESPACE, bound as never)).rejects.toThrow(RangeError);
      await expect(direct.listKeysBounded(NAMESPACE, bound as never)).rejects.toThrow(
        "Enumeration bound must be a non-negative safe integer",
      );
      // Across the worker the refusal carries the same message and no enumeration-bound discriminator.
      const refusal = await call("listKeysBounded", [bound]).then(
        (value) => ({ accepted: value }),
        (error: { message: string; type?: string }) => ({ message: error.message, type: error.type }),
      );
      expect(refusal).toEqual({ message: "Enumeration bound must be a non-negative safe integer", type: undefined });
    }
  }, 30_000); // One real worker startup includes the production CLI import graph.
});
