import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { mkdtemp, readFile, rename, stat, mkdir, open, realpath, symlink, readdir } from "node:fs/promises";
import { createRequire } from "node:module";
const ts = createRequire(import.meta.url)("typescript") as typeof import("typescript");
import { runInNewContext } from "node:vm";
import { fork } from "node:child_process";
import { once } from "node:events";
import { fileURLToPath } from "node:url";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { FilesystemStorage, withFilesystemLockTestHooks } from "../../src/storage/filesystem.js";
import type { NamespaceLockOptions } from "../../src/storage/interface.js";
import * as sdwWriteGate from "../../src/sdw/write-gate.js";
import { prepareSdwOwnerPinWrite } from "../../src/sdw/write-gate.js";
import { syncDirectoryStrict, writeFileCustody } from "../../src/storage/custody-fs.js";
import * as filesystemModule from "../../src/storage/filesystem.js";
import * as lockModule from "../../src/storage/cross-process-lock.js";
import { ReadOnlyStorageGuard } from "../../src/storage/read-only-guard.js";

const faults = vi.hoisted(() => ({
  swapBeforeSync: "", syncedInodes: [] as number[], custodyPublished: false, swapAfterLeafClose: "", swapAfterCustody: "", swapCompare: "", compareCleanup: false,
  path: "", code: "EINVAL", fileSynced: false, afterFile: false, closeFailure: false, once: false,
  swapOnOpen: "", swapOnPublish: "", capturedOnly: "", syncAfterAbsent: false, fileClose: false, linkError: false, cleanupError: "", openFlags: [] as Array<{ path: string; flags: unknown }>,
  events: [] as Array<{ path: string; directory: boolean }>,
}));
vi.mock("node:fs/promises", async (original) => {
  const fs = await original<typeof import("node:fs/promises")>();
  return { ...fs,
    rm: async (...args: Parameters<typeof fs.rm>) => {
      if (faults.compareCleanup && String(args[0]).endsWith(".compare-replace.lock")) throw Object.assign(new Error("compare cleanup failed"), { code: "EBUSY" });
      return fs.rm(...args);
    },
    rename: async (...args: Parameters<typeof fs.rename>) => {
      await fs.rename(...args);
      if (String(args[1]).endsWith(".claim")) faults.custodyPublished = true;
      if (faults.swapOnPublish && String(args[1]).endsWith(".enc")) {
        const directory = faults.swapOnPublish;
        faults.swapOnPublish = "";
        await fs.rename(directory, `${directory}-held`);
        await fs.mkdir(directory);
      }
    },
    link: async (...args: Parameters<typeof fs.link>) => {
      if (faults.cleanupError === "sync") faults.path = await fs.realpath(String(args[0]).slice(0, String(args[0]).lastIndexOf("/")));
      if (faults.linkError) throw Object.assign(new Error("publication failed"), { code: "EPERM" });
      return fs.link(...args);
    },
    unlink: async (...args: Parameters<typeof fs.unlink>) => {
      if (String(args[0]).endsWith(".claim") && faults.cleanupError && faults.cleanupError !== "sync") {
        if (faults.cleanupError === "ENOENT") {
          await fs.unlink(...args);
          if (faults.syncAfterAbsent) faults.path = await fs.realpath(String(args[0]).slice(0, String(args[0]).lastIndexOf("/")));
        }
        throw Object.assign(new Error("cleanup failed"), { code: faults.cleanupError });
      }
      return fs.unlink(...args);
    },
    open: async (...args: Parameters<typeof fs.open>) => {
    faults.openFlags.push({ path: String(args[0]), flags: args[1] });
    const handle = await fs.open(...args);
    const observedPath = /^\/(?:proc\/self\/fd|dev\/fd)\//.test(String(args[0])) ? await fs.realpath(String(args[0])) : String(args[0]);
    const isFile = !(await handle.stat()).isDirectory();
    if (faults.swapCompare && String(args[0]).endsWith(".compare-replace.lock")) {
      const directory = faults.swapCompare;
      faults.swapCompare = "";
      await fs.rename(directory, `${directory}-held`);
      await fs.mkdir(directory);
    }
    if (faults.swapOnOpen === String(args[0])) {
      faults.swapOnOpen = "";
      await fs.rename(String(args[0]), `${String(args[0])}-held`);
      await fs.mkdir(String(args[0]));
    }
    const sync = handle.sync.bind(handle);
    const close = handle.close.bind(handle);
    handle.close = async () => {
      await close();
      if (!isFile && faults.swapAfterLeafClose && String(args[0]).endsWith("/leaf")) {
        const directory = faults.swapAfterLeafClose;
        faults.swapAfterLeafClose = "";
        await fs.rename(directory, `${directory}-held`);
        await fs.mkdir(join(directory, "leaf"), { recursive: true });
      }
      if (!isFile && faults.swapAfterCustody && faults.custodyPublished) {
        const directory = faults.swapAfterCustody;
        faults.swapAfterCustody = "";
        await fs.rename(directory, `${directory}-held`);
        await fs.mkdir(directory);
        for (const name of await fs.readdir(`${directory}-held`)) {
          await fs.rename(join(`${directory}-held`, name), join(directory, name));
        }
      }
      if (faults.fileClose && isFile && observedPath.endsWith(".tmp")) throw Object.assign(new Error("file close failed"), { code: "EBADF" });
      if (faults.closeFailure && String(args[0]) === faults.path) throw Object.assign(new Error("injected close failure"), { code: "EIO" });
    };
    handle.sync = async () => {
      const descriptor = await handle.stat();
      const directory = descriptor.isDirectory();
      if (directory && faults.swapBeforeSync && faults.fileSynced && observedPath === faults.swapBeforeSync) {
        const path = faults.swapBeforeSync;
        faults.swapBeforeSync = "";
        await fs.rename(path, `${path}-held`);
        await fs.mkdir(path, { mode: 0o700 });
        faults.syncedInodes.push(descriptor.ino);
      }
      const path = observedPath;
      faults.events.push({ path, directory });
      if (path === faults.capturedOnly && (args[1] === "r" || (typeof args[1] === "number" && args[1] !== 0))) {
        throw Object.assign(new Error("captured barrier failed"), { code: "EIO" });
      }
      if (!directory && path.endsWith(".tmp")) faults.fileSynced = true;
      if ((faults.path === "FILE" ? !directory && path.endsWith(".tmp") : path === faults.path) &&
          (!faults.afterFile || faults.fileSynced)) {
        if (faults.once) faults.path = "";
        throw Object.assign(new Error("injected sync failure"), { code: faults.code });
      }
      await sync();
    };
    return handle;
  } };
});

const PRIVATE_FILE_MODE = 0o600;
const DATA = Buffer.from("fixture strict bytes");
const NEXT = Buffer.from("fixture replacement");
const NS = "fixture";
let root: string;
let storage: FilesystemStorage;
beforeEach(async () => {
  root = await realpath(await mkdtemp(join(tmpdir(), "s1a-")));
  storage = new FilesystemStorage(root);
  faults.swapBeforeSync = ""; faults.syncedInodes = [];
  faults.custodyPublished = false; faults.swapAfterLeafClose = ""; faults.swapAfterCustody = ""; faults.swapCompare = ""; faults.compareCleanup = false;
  faults.path = "";
  faults.code = "EINVAL";
  faults.fileSynced = false;
  faults.afterFile = false;
  faults.closeFailure = false;
  faults.once = false;
  faults.events = [];
  faults.swapOnOpen = "";
  faults.swapOnPublish = "";
  faults.capturedOnly = "";
  faults.syncAfterAbsent = false;
  faults.fileClose = false;
  faults.linkError = false;
  faults.cleanupError = "";
  faults.openFlags = [];
});
afterEach(() => vi.restoreAllMocks());

let insideStrictLock = false;
async function strictLock<T>(...args: Parameters<FilesystemStorage["withStrictNamespaceLock"]>): Promise<T> {
  const [namespace, name, operation, options] = args;
  return storage.withStrictNamespaceLock(namespace, name, async lease => {
    insideStrictLock = true;
    try { return await operation(lease) as T; }
    finally { insideStrictLock = false; }
  }, options);
}
async function boundOperation<T>(operation: () => Promise<T>): Promise<T> {
  if (insideStrictLock) return operation();
  const runtimeRoot = await realpath(await mkdtemp(join(tmpdir(), "s1r-")));
  return strictLock<T>(NS, ".strict.lock", operation, { runtimeRoot });
}
const strictWrite = (namespace: string, key: string, data: Uint8Array): Promise<void> => boundOperation(() => storage.writeStrict(namespace, key, data));
const strictCreate = (namespace: string, key: string, data: Uint8Array): Promise<boolean> => boundOperation(() => storage.writeIfAbsentStrict(namespace, key, data));
const strictReplace = (namespace: string, key: string, expected: Uint8Array, data: Uint8Array): Promise<boolean> => boundOperation(() => storage.replaceIfEqualsStrict(namespace, key, expected, data));
const strictMethod = (method: "writeStrict" | "writeIfAbsentStrict", namespace: string, key: string, data: Uint8Array) => method === "writeStrict" ? strictWrite(namespace, key, data) : strictCreate(namespace, key, data);
// Strict mutations stay in this process only on Linux; on Darwin they run in the forked worker, which this file's vi.mock never reaches.
const inProcessStrictPath = it.runIf(process.platform === "linux");

function requireStrict(): void {
  // An old tree fails this loaded assertion rather than failing collection or calling an absent method.
  expect(typeof storage.writeStrict, "ENTRYPOINT_ABSENT writeStrict").toBe("function");
  expect(typeof storage.writeIfAbsentStrict, "ENTRYPOINT_ABSENT writeIfAbsentStrict").toBe("function");
  expect(typeof storage.replaceIfEqualsStrict, "ENTRYPOINT_ABSENT replaceIfEqualsStrict").toBe("function");
}

describe("strict file and directory barriers", () => {
  it("publishes exact bytes with file, leaf and every new parent barrier", async () => {
    requireStrict();
    const base = join(root, "new-child");
    storage = new FilesystemStorage(base);
    await strictWrite(NS, "key", DATA);
    expect(Buffer.from((await storage.read(NS, "key"))!)).toEqual(DATA);
    const directories = faults.events.filter(event => event.directory).map(event => event.path);
    for (const path of [root, base, join(base, NS)]) expect(directories).toContain(path);
    expect(faults.events.some(event => !event.directory)).toBe(true);
    expect((await stat(join(base, NS, "key.enc"))).mode & 0o777).toBe(PRIVATE_FILE_MODE);
  });

  for (const barrier of ["file", "leaf", "parent", "ancestor"] as const) {
    it(`custody propagates the ${barrier} barrier failure`, async () => {
      const parent = join(root, "parent");
      const leaf = join(parent, "leaf");
      faults.path = { file: "FILE", leaf, parent, ancestor: root }[barrier];
      await expect(writeFileCustody(join(leaf, "row"), DATA, {
        mode: PRIVATE_FILE_MODE, strictDurability: true, strictDirectoryBase: root,
      })).rejects.toMatchObject({ code: "EINVAL" });
      await expect(readFile(join(leaf, "row"))).rejects.toMatchObject({ code: "ENOENT" });
    });
  }

  it("strict parent barriers preserve relative directory authority", async () => {
    const originalCwd = process.cwd();
    try {
      process.chdir(root);
      await writeFileCustody("parent/leaf/row", DATA, { mode: PRIVATE_FILE_MODE, strictDurability: true, strictDirectoryBase: "." });
      const directories = faults.events.filter(event => event.directory).map(event => event.path);
      for (const path of ["parent/leaf", "parent", "."]) expect(directories).toContain(path);
      expect(directories.some(path => path.startsWith(root))).toBe(false);
    } finally {
      process.chdir(originalCwd);
    }
  });

  it("directory close failure retains the original sync error", async () => {
    faults.path = join(root, "leaf");
    faults.closeFailure = true;
    await expect(writeFileCustody(join(faults.path, "row"), DATA, {
      mode: PRIVATE_FILE_MODE, strictDurability: true, strictDirectoryBase: root,
    })).rejects.toMatchObject({ errors: [{ code: "EINVAL" }, { code: "EIO" }] });
  });

  inProcessStrictPath("successful readback does not excuse a post-publication directory failure", async () => {
    requireStrict();
    faults.path = join(root, NS);
    faults.afterFile = true;
    await expect(strictWrite(NS, "key", DATA)).rejects.toMatchObject({ code: "EINVAL" });
    expect(Buffer.from((await storage.read(NS, "key"))!)).toEqual(DATA);
  });

  it("legacy directory tolerance stays separate from strict propagation", async () => {
    faults.path = join(root, NS);
    await expect(storage.writeDurable(NS, "legacy", DATA)).resolves.toBeUndefined();
    requireStrict();
    await expect(strictWrite(NS, "strict", DATA)).rejects.toMatchObject({ code: "EINVAL" });
    expect(await storage.read(NS, "strict")).toBeNull();
  });

  for (const code of ["EIO", "ENOTSUP", "EOPNOTSUPP"]) {
    it(`strict writes propagate ${code}`, async () => {
      requireStrict();
      faults.code = code;
      faults.path = join(root, NS);
      await expect(strictWrite(NS, "key", DATA)).rejects.toMatchObject({ code });
    });
  }

  it("exclusive create and serialized replacement preserve comparison semantics", async () => {
    requireStrict();
    expect(await strictReplace(NS, "absent", DATA, NEXT)).toBe(false);
    expect(await strictCreate(NS, "key", DATA)).toBe(true);
    expect(await strictCreate(NS, "key", NEXT)).toBe(false);
    expect(Buffer.from((await storage.read(NS, "key"))!)).toEqual(DATA);
    expect(await strictReplace(NS, "key", NEXT, DATA)).toBe(false);
    expect(await strictReplace(NS, "key", DATA, NEXT)).toBe(true);
    expect(Buffer.from((await storage.read(NS, "key"))!)).toEqual(NEXT);
  });

  it("absent strict comparison still syncs its new lock parents", async () => {
    requireStrict();
    storage = new FilesystemStorage(join(root, "new-parent"));
    faults.path = root;
    await expect(strictReplace(NS, "absent", DATA, NEXT)).rejects.toMatchObject({ code: "EINVAL" });
    expect(await storage.read(NS, "absent")).toBeNull();
  });

  for (const operation of ["create", "replace"] as const) {
    inProcessStrictPath(`${operation} propagates directory failure after a file barrier`, async () => {
      requireStrict();
      if (operation === "replace") await strictWrite(NS, "key", DATA);
      faults.fileSynced = false;
      faults.path = join(root, NS);
      faults.afterFile = true;
      faults.once = operation === "replace";
      const pending = operation === "create"
        ? strictCreate(NS, "key", DATA)
        : strictReplace(NS, "key", DATA, NEXT);
      await expect(pending).rejects.toMatchObject(operation === "create"
        ? { errors: [{ code: "EINVAL" }, { code: "EINVAL" }] }
        : { code: "EINVAL" });
      if (operation === "create") expect(await storage.read(NS, "key")).toBeNull();
    });
  }

  it("read-only strict methods never invoke the wrapped backend", async () => {
    requireStrict();
    const guard = new ReadOnlyStorageGuard(storage);
    const writes = vi.spyOn(storage, "writeStrict");
    const creates = vi.spyOn(storage, "writeIfAbsentStrict");
    const replacements = vi.spyOn(storage, "replaceIfEqualsStrict");
    const locks = vi.spyOn(storage, "withStrictNamespaceLock");
    await expect(guard.writeStrict(NS, "key", DATA)).rejects.toMatchObject({ name: "ReadOnlyStorageViolationError" });
    await expect(guard.writeIfAbsentStrict(NS, "key", DATA)).rejects.toMatchObject({ name: "ReadOnlyStorageViolationError" });
    await expect(guard.replaceIfEqualsStrict(NS, "key", DATA, NEXT)).rejects.toMatchObject({ name: "ReadOnlyStorageViolationError" });
    await expect(guard.withStrictNamespaceLock(NS, ".lock", async () => {})).rejects.toMatchObject({ name: "ReadOnlyStorageViolationError" });
    for (const spy of [writes, creates, replacements, locks]) expect(spy).not.toHaveBeenCalled();
  });

  it("strict methods preserve the SDW raw write gate", async () => {
    requireStrict();
    for (const operation of [
      () => strictWrite("_sdw_document_corpus", "key", DATA),
      () => strictCreate("_sdw_document_corpus", "key", DATA),
      () => strictReplace("_sdw_document_corpus", "key", DATA, NEXT),
    ]) await expect(operation()).rejects.toThrow();
  });

  it.runIf(process.platform === "linux" || process.platform === "darwin")("strict namespace binding keeps writes on the held inode", async () => {
    requireStrict();
    expect(typeof storage.withStrictNamespaceLock, "ENTRYPOINT_ABSENT withStrictNamespaceLock").toBe("function");
    const runtimeRoot = await realpath(await mkdtemp(join(tmpdir(), "s1r-")));
    const moved = `${root}-held`;
    let entered = false;
    await expect(strictLock(NS, ".strict.lock", async () => {
      entered = true;
      await rename(root, moved);
      await strictWrite(NS, "key", DATA);
      expect(await readFile(join(moved, NS, "key.enc"))).toEqual(DATA);
    }, { runtimeRoot })).rejects.toThrow(/changed/);
    expect(entered).toBe(true);
  });

  it.runIf(process.platform === "linux" || process.platform === "darwin")("legacy namespace bindings cannot advertise strict parent durability", async () => {
    requireStrict();
    const runtimeRoot = await realpath(await mkdtemp(join(tmpdir(), "s1r-")));
    let entered = false;
    await storage.withNamespaceLock(NS, ".legacy.lock", async () => {
      entered = true;
      await expect(storage.writeStrict(NS, "key", DATA)).rejects.toThrow(/strict namespace binding/);
    }, { runtimeRoot, kernelBacked: true });
    expect(entered).toBe(true);
  });
  it.runIf(process.platform === "linux" || process.platform === "darwin")("strict namespace binding completes create, replace and stable file writes", async () => {
    requireStrict();
    storage = new FilesystemStorage(join(root, "state"));
    const runtimeRoot = await realpath(await mkdtemp(join(tmpdir(), "s1r-")));
    await strictLock(NS, ".strict.lock", async (lease) => {
      expect(await strictCreate(NS, "key", DATA)).toBe(true);
      expect(await strictReplace(NS, "key", DATA, NEXT)).toBe(true);
      await lease.stableFortressFiles!.write("fixture.control", DATA);
      expect(await readFile(join(root, "fixture.control"))).toEqual(DATA);
    }, { runtimeRoot });
    expect(Buffer.from((await storage.read(NS, "key"))!)).toEqual(NEXT);
  });

  it.runIf(process.platform === "darwin")("Darwin worker creates strict parent directories through its held capability", async () => {
    requireStrict();
    storage = new FilesystemStorage(join(root, "state"));
    const runtimeRoot = await realpath(await mkdtemp(join(tmpdir(), "s1r-")));
    await strictLock(NS, ".strict.lock", async (lease) => {
      const PRIVATE_DIRECTORY_MODE = 0o700;
      await lease.stableFortressCapability!.mkdir("parent/child", PRIVATE_DIRECTORY_MODE);
      expect((await stat(join(root, "parent", "child"))).isDirectory()).toBe(true);
    }, { runtimeRoot });
  });

});

describe("strict completion witnesses", () => {
  inProcessStrictPath("preserves file sync and close failures together", async () => {
    faults.path = "FILE";
    faults.fileClose = true;
    await expect(strictWrite(NS, "key", DATA)).rejects.toMatchObject({ errors: [{ code: "EINVAL" }, { code: "EBADF" }] });
  });
  inProcessStrictPath("refuses a file close failure after successful sync", async () => {
    faults.fileClose = true;
    await expect(strictWrite(NS, "key", DATA)).rejects.toMatchObject({ code: "EBADF" });
  });
  for (const cleanup of ["ENOENT", "EIO", "sync"]) {
    inProcessStrictPath(`preserves publication failure through cleanup ${cleanup}`, async () => {
      faults.linkError = true;
      faults.cleanupError = cleanup;
      const failure = await strictCreate(NS, "key", DATA).catch(error => error);
      if (cleanup === "ENOENT") expect(failure).toMatchObject({ code: "EPERM" });
      else expect(failure).toMatchObject({ errors: [{ code: "EPERM" }, { code: cleanup === "sync" ? "EINVAL" : "EIO" }] });
    });
  }
  it("refuses symlink directory barriers", async () => {
    const target = join(root, "target");
    await mkdir(target);
    const alias = join(root, "alias");
    await symlink(target, alias);
    await expect(syncDirectoryStrict(alias)).rejects.toThrow();
  });
  it("syncs the verified owner parent chain", async () => {
    await mkdir(join(root, NS), { mode: 0o700 });
    storage = new FilesystemStorage(root, { owner: { uid: process.getuid!(), gid: process.getgid!() } });
    await strictWrite(NS, "key", DATA);
    expect(faults.events.filter(event => event.directory).map(event => event.path)).toContain(root);
    expect(Buffer.from((await storage.read(NS, "key"))!)).toEqual(DATA);
  });
  it("strict lock overrides environmental degradation", async () => {
    const lock = vi.spyOn(storage, "withNamespaceLock").mockResolvedValue(undefined);
    const options = { degradeOnEnvironmentalLoss: "inert", kernelBacked: false };
    await strictLock(NS, ".lock", async () => {}, options);
    expect(lock.mock.calls[0]?.[3]).toMatchObject({ kernelBacked: true, degradeOnEnvironmentalLoss: undefined });
  });
  for (const method of ["writeStrict", "writeIfAbsentStrict", "replaceIfEqualsStrict"] as const) {
    it(`authorized SDW payload succeeds through ${method}`, async () => {
      const KEY_BYTES = 32; // The owner pin MAC uses a 256-bit master key.
      const prepared = prepareSdwOwnerPinWrite(new Uint8Array(KEY_BYTES), {
        version: 1, fortress_id: "fixture-fortress", owner_ref: "fixture-owner", agent_id: "fixture-agent", pinned_at: "2026-11-08T00:00:00Z",
      });
      if (method === "replaceIfEqualsStrict") await strictWrite(prepared.namespace, prepared.storageKey, prepared.data);
      const gate = vi.spyOn(sdwWriteGate, "assertSdwRawWriteAuthorized");
      const result = method === "replaceIfEqualsStrict"
        ? await strictReplace(prepared.namespace, prepared.storageKey, prepared.data, prepared.data)
        : await strictMethod(method, prepared.namespace, prepared.storageKey, prepared.data);
      expect(result).toBe(method === "writeStrict" ? undefined : true);
      expect(gate).toHaveBeenCalledExactlyOnceWith(prepared.namespace, prepared.storageKey, prepared.data);
      expect(await storage.read(prepared.namespace, prepared.storageKey)).toEqual(prepared.data);
    });
  }
});

it("refuses a directory replaced during barrier capture", async () => {
  const directory = join(root, "swapped");
  await mkdir(directory);
  faults.swapOnOpen = directory;
  await expect(syncDirectoryStrict(directory)).rejects.toThrow(/identity changed/);
});
inProcessStrictPath("refuses a publishing directory replaced after rename", async () => {
  await mkdir(join(root, NS), { mode: 0o700 });
  faults.swapOnPublish = join(root, NS);
  await expect(strictWrite(NS, "key", DATA)).rejects.toThrow(/changed/);
  expect(await readFile(join(root, `${NS}-held`, "key.enc"))).toEqual(DATA);
});
it.runIf(process.platform === "linux" || process.platform === "darwin")("strict binding syncs captured root authority", async () => {
  const runtimeRoot = await realpath(await mkdtemp(join(tmpdir(), "s1r-")));
  faults.capturedOnly = root;
  let entered = false;
  await expect(strictLock(NS, ".strict.lock", async () => { entered = true; }, { runtimeRoot })).rejects.toMatchObject({ code: "EIO" });
  expect(entered).toBe(false);
});

for (const method of ["writeStrict", "writeIfAbsentStrict", "replaceIfEqualsStrict"] as const) {
  it(`authorized SDW bytes cross the worker through ${method}`, async () => {
    const KEY_BYTES = 32; // The owner pin MAC uses a 256-bit master key.
    const prepared = prepareSdwOwnerPinWrite(new Uint8Array(KEY_BYTES), {
      version: 1, fortress_id: "fixture-fortress", owner_ref: "fixture-owner", agent_id: "fixture-agent", pinned_at: "2026-11-08T00:00:00Z",
    });
    if (method === "replaceIfEqualsStrict") await strictWrite(prepared.namespace, prepared.storageKey, prepared.data);
    const identity = await stat(root);
    const worker = fork(fileURLToPath(new URL("../../src/storage/directory-capability-worker.ts", import.meta.url)), [String(identity.dev), String(identity.ino)], {
      cwd: root, execArgv: ["--import", import.meta.resolve("tsx")], stdio: ["ignore", "ignore", "pipe", "ipc"],
    });
    try {
      const [ready] = await once(worker, "message");
      expect(ready).toMatchObject({ ready: true });
      const response = once(worker, "message");
      const bytes = Buffer.from(prepared.data).toString("base64");
      const REQUEST_ID = 1; // Each fixture worker receives exactly one request.
      worker.send({ id: REQUEST_ID, op: method, args: [prepared.namespace, prepared.storageKey, ...(method === "replaceIfEqualsStrict" ? [bytes, bytes] : [bytes])] });
      const [result] = await response;
      expect(result).toMatchObject({ ok: true, value: method === "writeStrict" ? null : true });
      expect(await storage.read(prepared.namespace, prepared.storageKey)).toEqual(prepared.data);
    } finally {
      const exited = once(worker, "exit");
      worker.kill();
      await exited;
    }
  });
}

for (const [file, helper] of [
  ["filesystem.ts", "atomicWriteFile"],
  ["filesystem.ts", "writeIfAbsentMode"],
  ["filesystem.ts", "replaceIfEqualsMode"],
  ["filesystem.ts", "writeStableFortressFile"],
  ["directory-capability-worker.ts", "mkdirRelative"],
] as const) {
  it(`internal durability choice is required for ${helper}`, async () => {
    const source = await readFile(new URL(`../../src/storage/${file}`, import.meta.url), "utf8");
    expect(source).toMatch(new RegExp(`${helper}\\([\\s\\S]*?strictDurability: boolean`));
    expect(source).not.toMatch(new RegExp(`${helper}\\([\\s\\S]*?strictDurability = false`));
  });
}
it("internal custody durability choice is required", async () => {
  const source = await readFile(new URL("../../src/storage/custody-fs.ts", import.meta.url), "utf8");
  expect(source, "ENTRYPOINT_ABSENT required custody entrypoint").toContain("export async function writeFileCustodyWithDurability(");
  expect(source).toContain("options: WriteFileCustodyOptions & { strictDurability: boolean }");
});

inProcessStrictPath("cleans a staged publication after its directory barrier fails", async () => {
  faults.path = join(root, NS);
  faults.afterFile = true;
  faults.once = true;
  await expect(strictCreate(NS, "key", DATA)).rejects.toMatchObject({ code: "EINVAL" });
  expect((await readdir(join(root, NS))).filter(name => name.endsWith(".claim"))).toEqual([]);
});

it("successful exclusive publication tolerates an absent staging name", async () => {
  faults.cleanupError = "ENOENT";
  expect(await strictCreate(NS, "key", DATA)).toBe(true);
  expect(Buffer.from((await storage.read(NS, "key"))!)).toEqual(DATA);
});
inProcessStrictPath("absent staging still performs the final directory barrier", async () => {
  faults.cleanupError = "ENOENT";
  faults.syncAfterAbsent = true;
  await expect(strictCreate(NS, "key", DATA)).rejects.toMatchObject({ code: "EINVAL" });
  expect(Buffer.from((await storage.read(NS, "key"))!)).toEqual(DATA);
});


describe("strict authority closure", () => {
  for (const method of ["writeStrict", "writeIfAbsentStrict", "replaceIfEqualsStrict"] as const) {
    it(`unbound ${method} refuses before creating parents`, async () => {
      const result = method === "replaceIfEqualsStrict"
        ? storage.replaceIfEqualsStrict(NS, "key", DATA, NEXT)
        : storage[method](NS, "key", DATA);
      await expect(result).rejects.toThrow(/strict namespace binding/);
      expect(await readdir(root)).toEqual([]);
    });
  }
  it("strict lock refuses a missing root parent on every retry", async () => {
    storage = new FilesystemStorage(join(root, "missing", "state"));
    const runtimeRoot = await realpath(await mkdtemp(join(tmpdir(), "s1r-")));
    for (let attempt = 0; attempt < 2; attempt++) {
      await expect(storage.withStrictNamespaceLock(NS, ".lock", async () => true, { runtimeRoot })).rejects.toThrow();
      expect(await readdir(root)).toEqual([]);
    }
  });
  for (const directory of ["namespace", "root", "parent"] as const) {
    it(`strict lock retries the held ${directory} barrier`, async () => {
      storage = new FilesystemStorage(join(root, "state"));
      const runtimeRoot = await realpath(await mkdtemp(join(tmpdir(), "s1r-")));
      const path = { namespace: join(root, "state", NS), root: join(root, "state"), parent: root }[directory];
      faults.path = path;
      await expect(storage.withStrictNamespaceLock(NS, ".lock", async () => true, { runtimeRoot })).rejects.toMatchObject({ code: "EINVAL" });
      faults.path = ""; faults.events = [];
      expect(await storage.withStrictNamespaceLock(NS, ".lock", async () => true, { runtimeRoot })).toBe(true);
      expect(faults.events.filter(event => event.directory).map(event => event.path)).toContain(path);
    });
  }
  it("created parent identity survives the child barrier window", async () => {
    const parent = join(root, "parent");
    faults.swapAfterLeafClose = parent;
    await expect(writeFileCustody(join(parent, "leaf", "row"), DATA, { mode: PRIVATE_FILE_MODE, strictDurability: true, strictDirectoryBase: root })).rejects.toThrow(/identity changed/);
  });
  it("retry after a failed new ancestor barrier resyncs that ancestor", async () => {
    const parent = join(root, "parent");
    faults.path = parent;
    await expect(writeFileCustody(join(parent, "leaf", "row"), DATA, { mode: PRIVATE_FILE_MODE, strictDurability: true, strictDirectoryBase: root })).rejects.toMatchObject({ code: "EINVAL" });
    faults.path = ""; faults.events = [];
    await writeFileCustody(join(parent, "leaf", "row"), DATA, { mode: PRIVATE_FILE_MODE, strictDurability: true, strictDirectoryBase: root });
    for (const path of [root, parent, join(parent, "leaf")]) {
      expect(faults.events.filter(event => event.directory).map(event => event.path)).toContain(path);
    }
  });
  inProcessStrictPath("comparison revalidates its parent after taking the path lock", async () => {
    const runtimeRoot = await realpath(await mkdtemp(join(tmpdir(), "s1r-")));
    await storage.withStrictNamespaceLock(NS, ".lock", async () => {
      faults.swapCompare = join(root, "other");
      await expect(storage.replaceIfEqualsStrict("other", "absent", DATA, NEXT)).rejects.toThrow(/identity changed/);
    }, { runtimeRoot });
  });
  inProcessStrictPath("exclusive publication retains the custody descriptor identity", async () => {
    const runtimeRoot = await realpath(await mkdtemp(join(tmpdir(), "s1r-")));
    await storage.withStrictNamespaceLock(NS, ".lock", async () => {
      faults.swapAfterCustody = join(root, "other");
      await expect(storage.writeIfAbsentStrict("other", "key", DATA)).rejects.toThrow(/identity changed|publication and cleanup/);
    }, { runtimeRoot });
  });
  inProcessStrictPath("comparison cleanup retains the primary strict error", async () => {
    const runtimeRoot = await realpath(await mkdtemp(join(tmpdir(), "s1r-")));
    await storage.withStrictNamespaceLock(NS, ".lock", async () => {
      await storage.writeStrict(NS, "key", DATA);
      faults.path = "FILE"; faults.compareCleanup = true;
      await expect(storage.replaceIfEqualsStrict(NS, "key", DATA, NEXT)).rejects.toMatchObject({ errors: [{ code: "EINVAL" }, { code: "EBUSY" }] });
    }, { runtimeRoot });
  });
  it("strict lock options discard every test hook even inside the test environment", async () => {
    const lock = vi.spyOn(storage, "withNamespaceLock").mockResolvedValue(undefined);
    expect(process.env.VITEST).toBeDefined();
    const smuggled = { __testCloseNamespaceCapability: async () => {}, __testPlatform: "win32" } as unknown as NamespaceLockOptions;
    await storage.withStrictNamespaceLock(NS, ".lock", async () => {}, smuggled);
    expect(Object.keys(lock.mock.calls[0]![3]!).filter(key => key.startsWith("__test"))).toEqual([]);
  });
  for (const method of ["writeStrict", "writeIfAbsentStrict", "replaceIfEqualsStrict"] as const) {
    it(`${method} checks the master barrier before the SDW gate`, async () => {
      const gate = vi.spyOn(sdwWriteGate, "assertSdwRawWriteAuthorized");
      vi.spyOn(lockModule, "assertStorageMasterWriteBarrierHeld").mockImplementation(() => { throw new Error("master barrier refused"); });
      const result = method === "replaceIfEqualsStrict" ? storage.replaceIfEqualsStrict(NS, "key", DATA, NEXT) : storage[method](NS, "key", DATA);
      await expect(result).rejects.toThrow("master barrier refused");
      expect(gate).not.toHaveBeenCalled();
    });
  }
  it("worker error serialization preserves nested error codes", async () => {
    const source = await readFile(new URL("../../src/storage/directory-capability-worker.ts", import.meta.url), "utf8");
    const error = new AggregateError([Object.assign(new Error("sync"), { code: "EIO" }), new AggregateError([Object.assign(new Error("close"), { code: "EBADF" })], "cleanup")], "combined");
    const helpers = filesystemModule as unknown as { serializeCapabilityError?: (error: unknown) => unknown; deserializeCapabilityError?: (error: unknown) => unknown };
    // The baseline encoder drops inner failures, so the same payload assertion witnesses the old wire behavior.
    const legacyBody = source.match(/error: (\{[\s\S]*?\n          \}),/)?.[1];
    const legacyEncode = legacyBody ? runInNewContext(ts.transpile(`(error: unknown) => (${legacyBody})`), { Error }) as (error: unknown) => unknown : undefined;
    const encoded = helpers.serializeCapabilityError ? helpers.serializeCapabilityError(error) : legacyEncode!(error);
    const result = helpers.deserializeCapabilityError ? helpers.deserializeCapabilityError(JSON.parse(JSON.stringify(encoded))) : encoded;
    expect(result).toMatchObject({ errors: [{ code: "EIO" }, { errors: [{ code: "EBADF" }] }] });
  });
});

it("strict documentation states the lock and Darwin bounds with sentence spacing", async () => {
  const readme = await readFile(new URL("../../src/README.md", import.meta.url), "utf8");
  const manifest = await readFile(new URL("../../reorg-surface-manifest.md", import.meta.url), "utf8");
  expect(readme).not.toContain("fallback.  Default-off strict");
  expect(readme).not.toContain("`complete:false` Audit receipts");
  expect(manifest).toMatch(/writeStrict[^\n]*inside a strict lock[^\n]*Darwin[^\n]*not proven/);
});

it("publication barrier keeps its verified descriptor through a pre-sync directory swap", async () => {
  const directory = join(root, "other");
  await mkdir(directory, { mode: 0o700 });
  const identity = await stat(directory);
  faults.swapBeforeSync = directory;
  await expect(writeFileCustody(join(directory, "row"), DATA, { mode: PRIVATE_FILE_MODE, strictDurability: true, strictDirectoryBase: root })).rejects.toThrow(/directory changed/);
  expect(faults.syncedInodes).toEqual([identity.ino]);
  expect((await stat(directory)).ino).not.toBe(identity.ino);
  expect(await readFile(join(`${directory}-held`, "row"))).toEqual(DATA);
});

it("continuing strict operations cover both namespaces and every comparison result", async () => {
  const runtimeRoot = await realpath(await mkdtemp(join(tmpdir(), "s1r-")));
  storage = new FilesystemStorage(join(root, "state"));
  await storage.withStrictNamespaceLock(NS, ".lock", async lease => {
    for (const namespace of [NS, "other"]) {
      await storage.writeStrict(namespace, "key", DATA);
      expect(await storage.writeIfAbsentStrict(namespace, "key", NEXT)).toBe(false);
      expect(await storage.writeIfAbsentStrict(namespace, "created", DATA)).toBe(true);
      expect(await storage.replaceIfEqualsStrict(namespace, "absent", DATA, NEXT)).toBe(false);
      expect(await storage.replaceIfEqualsStrict(namespace, "key", NEXT, DATA)).toBe(false);
      expect(await storage.replaceIfEqualsStrict(namespace, "key", DATA, NEXT)).toBe(true);
      expect(Buffer.from((await storage.read(namespace, "key"))!)).toEqual(NEXT);
    }
    await lease.stableFortressFiles!.write("control", DATA);
    expect(await lease.stableFortressFiles!.read("control")).toEqual(new Uint8Array(DATA));
  }, { runtimeRoot });
});

it.runIf(process.platform === "darwin")("Darwin worker preserves combined sync and close error codes", async () => {
  const identity = await stat(root);
  // The worker imports named bindings, which see a patched default export only after syncBuiltinESMExports.
  const preload = `import fs from "node:fs/promises";
import { syncBuiltinESMExports } from "node:module";
const original = fs.open;
fs.open = async (...args) => {
  const handle = await original(...args);
  if (String(args[0]).endsWith(".tmp")) {
    const close = handle.close.bind(handle);
    handle.sync = async () => { throw Object.assign(new Error("injected file sync"), { code: "EIO" }); };
    handle.close = async () => { await close(); throw Object.assign(new Error("injected file close"), { code: "EBADF" }); };
  }
  return handle;
};
syncBuiltinESMExports();`;
  const worker = fork(fileURLToPath(new URL("../../src/storage/directory-capability-worker.ts", import.meta.url)), [String(identity.dev), String(identity.ino)], {
    cwd: root, execArgv: ["--import", import.meta.resolve("tsx"), "--import", `data:text/javascript,${encodeURIComponent(preload)}`], stdio: ["ignore", "ignore", "pipe", "ipc"],
  });
  try {
    const [ready] = await once(worker, "message");
    expect(ready).toMatchObject({ ready: true });
    const response = once(worker, "message");
    worker.send({ id: 1, op: "writeFileStrict", args: ["row", DATA.toString("base64")] });
    const [result] = await response;
    expect(result).toMatchObject({ ok: false, error: { errors: [{ code: "EIO" }, { code: "EBADF" }] } });
  } finally {
    const exited = once(worker, "exit"); worker.kill(); await exited;
  }
});

it("strict authority refuses mutations before the lock callback acquires its lease", async () => {
  const runtimeRoot = await realpath(await mkdtemp(join(tmpdir(), "s1r-")));
  const pathLock = lockModule.withPathLock;
  let observed = false;
  vi.spyOn(lockModule, "withPathLock").mockImplementation(async (directory, name, operation, options) => {
    if (options?.kernelBacked) {
      observed = true;
      await expect(storage.writeStrict(NS, "early", DATA)).rejects.toThrow(/strict namespace binding/);
    }
    return pathLock(directory, name, operation, options);
  });
  await storage.withStrictNamespaceLock(NS, ".lock", async () => {
    await storage.writeStrict(NS, "key", DATA);
  }, { runtimeRoot });
  expect(observed).toBe(true);
  expect(await storage.read(NS, "early")).toBeNull();
});

/** Faults the Darwin worker preload injects; must match __testDirectoryCapabilityPreload in filesystem.ts. */
interface WorkerFaults {
  fileSync?: string;
  fileClose?: string;
  directoryIno?: number;
  directoryCode?: string;
  directoryAfterFile?: boolean;
  directoryOnce?: boolean;
  directoryArmedBy?: "link" | "absentCleanup";
  linkCode?: string;
  claimCleanup?: "ENOENT" | "EIO";
  swapOnPublish?: string;
  swapOnCompareLock?: string;
  swapAfterClaim?: string;
  compareCleanup?: string;
}

/**
 * Build a module the worker imports before it runs. It patches the default
 * export of node:fs/promises and then calls syncBuiltinESMExports, because the
 * worker and custody modules import named bindings that never see a default
 * export patch otherwise. Directories are matched by inode, since each worker's
 * paths are relative to its own held cwd.
 */
function workerFaultPreload(faults: WorkerFaults): string {
  const source = `import fs from "node:fs/promises";
import { syncBuiltinESMExports } from "node:module";
const faults = ${JSON.stringify(faults)};
const original = { open: fs.open, rename: fs.rename, link: fs.link, unlink: fs.unlink, rm: fs.rm, mkdir: fs.mkdir, readdir: fs.readdir };
const state = { fileSynced: false, armed: faults.directoryArmedBy === undefined, claimed: false, fired: false };
const injected = (code, message) => Object.assign(new Error(message), { code });
async function swap(directory, moveEntries) {
  await original.rename(directory, directory + "-held");
  await original.mkdir(directory);
  if (moveEntries) for (const name of await original.readdir(directory + "-held")) await original.rename(directory + "-held/" + name, directory + "/" + name);
}
fs.rename = async (...args) => {
  await original.rename(...args);
  if (String(args[1]).endsWith(".claim")) state.claimed = true;
  if (faults.swapOnPublish && String(args[1]).endsWith(".enc")) { const directory = faults.swapOnPublish; faults.swapOnPublish = ""; await swap(directory, false); }
};
fs.link = async (...args) => {
  if (faults.directoryArmedBy === "link") state.armed = true;
  if (faults.linkCode) throw injected(faults.linkCode, "injected publication failure");
  return original.link(...args);
};
fs.unlink = async (...args) => {
  if (faults.claimCleanup && String(args[0]).endsWith(".claim")) {
    if (faults.claimCleanup === "ENOENT") {
      await original.unlink(...args);
      if (faults.directoryArmedBy === "absentCleanup") state.armed = true;
    }
    throw injected(faults.claimCleanup, "injected cleanup failure");
  }
  return original.unlink(...args);
};
fs.rm = async (...args) => {
  if (faults.compareCleanup && String(args[0]).endsWith(".compare-replace.lock")) throw injected(faults.compareCleanup, "injected comparison cleanup failure");
  return original.rm(...args);
};
fs.open = async (...args) => {
  const handle = await original.open(...args);
  const path = String(args[0]);
  if (faults.swapOnCompareLock && path.endsWith(".compare-replace.lock")) { const directory = faults.swapOnCompareLock; faults.swapOnCompareLock = ""; await swap(directory, false); }
  const directory = (await handle.stat()).isDirectory();
  const stagedFile = !directory && path.endsWith(".tmp");
  const sync = handle.sync.bind(handle);
  const close = handle.close.bind(handle);
  handle.sync = async () => {
    if (stagedFile) {
      if (faults.fileSync) throw injected(faults.fileSync, "injected file barrier failure");
      await sync();
      state.fileSynced = true;
      return;
    }
    if (directory && faults.directoryIno !== undefined && state.armed && (!faults.directoryAfterFile || state.fileSynced) &&
        !(faults.directoryOnce && state.fired) && (await handle.stat()).ino === faults.directoryIno) {
      state.fired = true;
      throw injected(faults.directoryCode, "injected directory barrier failure");
    }
    return sync();
  };
  handle.close = async () => {
    await close();
    if (directory && faults.swapAfterClaim && state.claimed) { const directory = faults.swapAfterClaim; faults.swapAfterClaim = ""; await swap(directory, true); }
    if (stagedFile && faults.fileClose) throw injected(faults.fileClose, "injected file close failure");
  };
  return handle;
};
syncBuiltinESMExports();
`;
  return `data:text/javascript,${encodeURIComponent(source)}`;
}

const darwinWorkerPath = it.runIf(process.platform === "darwin");
async function inWorkerLock<T>(faults: WorkerFaults | undefined, operation: () => Promise<T>, target: FilesystemStorage = storage): Promise<T> {
  const runtimeRoot = await realpath(await mkdtemp(join(tmpdir(), "s1r-")));
  const lock = (): Promise<T> => target.withStrictNamespaceLock(NS, ".strict.lock", operation, { runtimeRoot });
  return faults ? withFilesystemLockTestHooks({ directoryCapabilityPreload: workerFaultPreload(faults) }, lock) : lock();
}
async function namespaceInode(namespace = NS): Promise<number> {
  await mkdir(join(root, namespace), { recursive: true, mode: 0o700 });
  return (await stat(join(root, namespace))).ino;
}

describe("Darwin worker barrier witnesses", () => {
  darwinWorkerPath("worker: successful readback does not excuse a post-publication directory failure", async () => {
    const directoryIno = await namespaceInode();
    await inWorkerLock({ directoryIno, directoryCode: "EINVAL", directoryAfterFile: true }, async () => {
      await expect(storage.writeStrict(NS, "key", DATA)).rejects.toMatchObject({ code: "EINVAL" });
    });
    expect(Buffer.from((await storage.read(NS, "key"))!)).toEqual(DATA);
  });
  darwinWorkerPath("worker: create propagates directory failure after a file barrier", async () => {
    const directoryIno = await namespaceInode();
    await inWorkerLock({ directoryIno, directoryCode: "EINVAL", directoryAfterFile: true }, async () => {
      await expect(storage.writeIfAbsentStrict(NS, "key", DATA)).rejects.toMatchObject({ errors: [{ code: "EINVAL" }, { code: "EINVAL" }] });
    });
    expect(await storage.read(NS, "key")).toBeNull();
  });
  darwinWorkerPath("worker: replace propagates directory failure after a file barrier", async () => {
    const directoryIno = await namespaceInode();
    await inWorkerLock(undefined, () => storage.writeStrict(NS, "key", DATA));
    await inWorkerLock({ directoryIno, directoryCode: "EINVAL", directoryAfterFile: true, directoryOnce: true }, async () => {
      await expect(storage.replaceIfEqualsStrict(NS, "key", DATA, NEXT)).rejects.toMatchObject({ code: "EINVAL" });
    });
  });
  darwinWorkerPath("worker: preserves file sync and close failures together", async () => {
    await inWorkerLock({ fileSync: "EINVAL", fileClose: "EBADF" }, async () => {
      await expect(storage.writeStrict(NS, "key", DATA)).rejects.toMatchObject({ errors: [{ code: "EINVAL" }, { code: "EBADF" }] });
    });
  });
  darwinWorkerPath("worker: refuses a file close failure after successful sync", async () => {
    await inWorkerLock({ fileClose: "EBADF" }, async () => {
      await expect(storage.writeStrict(NS, "key", DATA)).rejects.toMatchObject({ code: "EBADF" });
    });
  });
  darwinWorkerPath("worker: preserves publication failure through cleanup ENOENT", async () => {
    await inWorkerLock({ linkCode: "EPERM", claimCleanup: "ENOENT" }, async () => {
      await expect(storage.writeIfAbsentStrict(NS, "key", DATA)).rejects.toMatchObject({ code: "EPERM" });
    });
  });
  darwinWorkerPath("worker: preserves publication failure through cleanup EIO", async () => {
    await inWorkerLock({ linkCode: "EPERM", claimCleanup: "EIO" }, async () => {
      await expect(storage.writeIfAbsentStrict(NS, "key", DATA)).rejects.toMatchObject({ errors: [{ code: "EPERM" }, { code: "EIO" }] });
    });
  });
  darwinWorkerPath("worker: preserves publication failure through cleanup sync", async () => {
    const directoryIno = await namespaceInode();
    await inWorkerLock({ linkCode: "EPERM", directoryIno, directoryCode: "EINVAL", directoryArmedBy: "link" }, async () => {
      await expect(storage.writeIfAbsentStrict(NS, "key", DATA)).rejects.toMatchObject({ errors: [{ code: "EPERM" }, { code: "EINVAL" }] });
    });
  });
  darwinWorkerPath("worker: refuses a publishing directory replaced after rename", async () => {
    await inWorkerLock({ swapOnPublish: join(root, "other") }, async () => {
      await expect(storage.writeStrict("other", "key", DATA)).rejects.toThrow(/changed/);
    });
    expect(await readFile(join(root, "other-held", "key.enc"))).toEqual(DATA);
  });
  darwinWorkerPath("worker: cleans a staged publication after its directory barrier fails", async () => {
    const directoryIno = await namespaceInode();
    await inWorkerLock({ directoryIno, directoryCode: "EINVAL", directoryAfterFile: true, directoryOnce: true }, async () => {
      await expect(storage.writeIfAbsentStrict(NS, "key", DATA)).rejects.toMatchObject({ code: "EINVAL" });
    });
    expect((await readdir(join(root, NS))).filter(name => name.endsWith(".claim"))).toEqual([]);
  });
  darwinWorkerPath("worker: absent staging still performs the final directory barrier", async () => {
    const directoryIno = await namespaceInode();
    await inWorkerLock({ claimCleanup: "ENOENT", directoryIno, directoryCode: "EINVAL", directoryArmedBy: "absentCleanup" }, async () => {
      await expect(storage.writeIfAbsentStrict(NS, "key", DATA)).rejects.toMatchObject({ code: "EINVAL" });
    });
    expect(Buffer.from((await storage.read(NS, "key"))!)).toEqual(DATA);
  });
  darwinWorkerPath("worker: successful exclusive publication tolerates an absent staging name", async () => {
    await inWorkerLock({ claimCleanup: "ENOENT" }, async () => {
      expect(await storage.writeIfAbsentStrict(NS, "key", DATA)).toBe(true);
    });
    expect(Buffer.from((await storage.read(NS, "key"))!)).toEqual(DATA);
  });
  darwinWorkerPath("worker: comparison revalidates its parent after taking the path lock", async () => {
    await inWorkerLock({ swapOnCompareLock: join(root, "other") }, async () => {
      await expect(storage.replaceIfEqualsStrict("other", "absent", DATA, NEXT)).rejects.toThrow(/identity changed/);
    });
  });
  darwinWorkerPath("worker: exclusive publication retains the custody descriptor identity", async () => {
    await inWorkerLock({ swapAfterClaim: join(root, "other") }, async () => {
      await expect(storage.writeIfAbsentStrict("other", "key", DATA)).rejects.toThrow(/identity changed|publication and cleanup/);
    });
  });
  darwinWorkerPath("worker: comparison cleanup retains the primary strict error", async () => {
    await inWorkerLock(undefined, () => storage.writeStrict(NS, "key", DATA));
    await inWorkerLock({ fileSync: "EINVAL", compareCleanup: "EBUSY" }, async () => {
      await expect(storage.replaceIfEqualsStrict(NS, "key", DATA, NEXT)).rejects.toMatchObject({ errors: [{ code: "EINVAL" }, { code: "EBUSY" }] });
    });
  });
});

describe("strict owner barriers, worker exemption, lease and nesting", () => {
  const owner = (): { uid: number; gid: number } => ({ uid: process.getuid!(), gid: process.getgid!() });

  inProcessStrictPath("owner-mode strict write syncs the root for a namespace created after acquisition", async () => {
    const ownerStorage = new FilesystemStorage(root, { owner: owner() });
    const runtimeRoot = await realpath(await mkdtemp(join(tmpdir(), "s1r-")));
    await ownerStorage.withStrictNamespaceLock("locked", ".strict.lock", async () => {
      await new FilesystemStorage(root).write("later", "seed", DATA);
      faults.path = root;
      try {
        await expect(ownerStorage.writeStrict("later", "key", DATA)).rejects.toMatchObject({ code: "EINVAL" });
      } finally { faults.path = ""; }
    }, { runtimeRoot });
  });
  darwinWorkerPath("worker: owner-mode strict write syncs the root for a namespace created after acquisition", async () => {
    const ownerStorage = new FilesystemStorage(root, { owner: owner() });
    await mkdir(join(root, NS), { mode: 0o700 });
    const rootIno = (await stat(root)).ino;
    await inWorkerLock({ directoryIno: rootIno, directoryCode: "EIO" }, async () => {
      await new FilesystemStorage(root).write("later", "seed", DATA);
      await expect(ownerStorage.writeStrict("later", "key", DATA)).rejects.toMatchObject({ code: "EIO" });
    }, ownerStorage);
  });

  it("the public constructor cannot set the worker executor exemption", async () => {
    const originalCwd = process.cwd();
    try {
      process.chdir(root);
      const exemptOptions = { allowDirectoryCapabilityRootNamespace: true } as unknown as ConstructorParameters<typeof FilesystemStorage>[1];
      const exempt = new FilesystemStorage(join(root, "state"), exemptOptions);
      await expect(exempt.writeStrict(NS, "key", DATA)).rejects.toThrow(/strict namespace binding/);
      expect(await readdir(root)).toEqual([]);
    } finally { process.chdir(originalCwd); }
    for (const index of ["../../src/index.ts", "../../src/storage/index.ts"]) {
      const source = await readFile(new URL(index, import.meta.url), "utf8");
      expect(source, `${index} must not re-export the worker factory`).not.toContain("createDirectoryCapabilityWorkerStorage");
    }
  });

  it.runIf(process.platform === "linux" || process.platform === "darwin")("a kept strict lease refuses every method after its callback settles", async () => {
    storage = new FilesystemStorage(join(root, "state"));
    const runtimeRoot = await realpath(await mkdtemp(join(tmpdir(), "s1r-")));
    let kept: lockModule.CrossProcessLockLease | undefined;
    await storage.withStrictNamespaceLock(NS, ".strict.lock", async lease => { kept = lease; }, { runtimeRoot });
    const decoy = join(root, "decoy");
    await mkdir(decoy);
    const held: Array<Awaited<ReturnType<typeof open>>> = [];
    try {
      // A Linux lease names its parent by descriptor number, so open the lowest free descriptors until that number points at the decoy.
      const parentDescriptor = /^\/proc\/self\/fd\/(\d+)$/.exec(String(kept!.stableStorageParent))?.[1];
      // Bound on descriptors opened while searching for reuse; one settlement frees far fewer than this.
      const DECOY_DESCRIPTOR_LIMIT = 64;
      while (parentDescriptor !== undefined && held.length < DECOY_DESCRIPTOR_LIMIT) {
        const handle = await open(decoy, "r");
        held.push(handle);
        if (String(handle.fd) === parentDescriptor) break;
      }
      const methods = [
        ...Object.entries(kept!.stableFortressFiles ?? {}),
        ...Object.entries(kept!.stableFortressCapability ?? {}),
      ] as Array<[string, (...args: unknown[]) => Promise<unknown>]>;
      expect(methods.length).toBeGreaterThan(0);
      for (const [name, method] of methods) {
        await expect(method("leak", DATA), name).rejects.toThrow(/strict lock lease is no longer active/);
      }
    } finally {
      for (const handle of held) await handle.close();
    }
    expect(await readdir(decoy)).toEqual([]);
    expect(await readdir(root)).not.toContain("leak");
  });

  it.runIf(process.platform === "linux" || process.platform === "darwin")("a public lock nested in a strict callback does not inherit strict mode", async () => {
    const runtimeRoot = await realpath(await mkdtemp(join(tmpdir(), "s1r-")));
    const nestedRuntimeRoot = await realpath(await mkdtemp(join(tmpdir(), "s1r-")));
    await storage.withStrictNamespaceLock(NS, ".strict.lock", async () => {
      await storage.withNamespaceLock("nested", ".nested.lock", async () => {
        await expect(storage.writeStrict("nested", "key", DATA)).rejects.toThrow(/strict namespace binding/);
      }, { runtimeRoot: nestedRuntimeRoot, kernelBacked: true });
    }, { runtimeRoot });
    expect(await storage.read("nested", "key")).toBeNull();
  });

  it.runIf(process.platform === "linux" || process.platform === "darwin")("a lock nested in strict authority discards test hooks", async () => {
    const runtimeRoot = await realpath(await mkdtemp(join(tmpdir(), "s1r-")));
    const nestedRuntimeRoot = await realpath(await mkdtemp(join(tmpdir(), "s1r-")));
    const calls: string[] = [];
    await storage.withStrictNamespaceLock(NS, ".strict.lock", async () => {
      await storage.withNamespaceLock("nested", ".nested.lock", async () => undefined, {
        runtimeRoot: nestedRuntimeRoot,
        kernelBacked: true,
        __testCloseNamespaceCapability: async (kind: string, close: () => Promise<unknown>) => { calls.push(kind); await close(); },
      } as unknown as NamespaceLockOptions);
    }, { runtimeRoot });
    expect(calls).toEqual([]);
  });
});

describe("test hooks off the public surface, kept-lease fence, typed owner refusal", () => {
  const owner = (): { uid: number; gid: number } => ({ uid: process.getuid!(), gid: process.getgid!() });
  const lockKinds = (calls: string[]) => async (kind: string, close: () => Promise<unknown>): Promise<unknown> => { calls.push(kind); return close(); };

  darwinWorkerPath("a worker preload in public lock options is never honored", async () => {
    const directoryIno = await namespaceInode();
    const runtimeRoot = await realpath(await mkdtemp(join(tmpdir(), "s1r-")));
    expect(process.env.VITEST).toBeDefined();
    const smuggled = { runtimeRoot, __testDirectoryCapabilityPreload: workerFaultPreload({ directoryIno, directoryCode: "EIO" }) } as unknown as NamespaceLockOptions;
    await storage.withStrictNamespaceLock(NS, ".strict.lock", () => storage.writeStrict(NS, "key", DATA), smuggled);
    expect(Buffer.from((await storage.read(NS, "key"))!)).toEqual(DATA);
  });

  it.runIf(process.platform === "linux" || process.platform === "darwin")("public lock entries discard filesystem test hooks inside the test environment", async () => {
    for (const entry of ["strict", "legacy"] as const) {
      const calls: string[] = [];
      const acquired: number[] = [];
      const runtimeRoot = await realpath(await mkdtemp(join(tmpdir(), "s1r-")));
      const smuggled = {
        runtimeRoot,
        kernelBacked: true,
        __testCloseNamespaceCapability: lockKinds(calls),
        __testAfterDirectoryCapabilityAcquired: (pid: number) => { acquired.push(pid); },
      } as unknown as NamespaceLockOptions;
      if (entry === "strict") await storage.withStrictNamespaceLock(NS, ".strict.lock", async () => undefined, smuggled);
      else await storage.withNamespaceLock(NS, ".legacy.lock", async () => undefined, smuggled);
      expect({ entry, calls, acquired }).toEqual({ entry, calls: [], acquired: [] });
    }
  });

  it.runIf(process.platform === "linux" || process.platform === "darwin")("the test-hook injection still reaches the lock", async () => {
    const calls: string[] = [];
    const runtimeRoot = await realpath(await mkdtemp(join(tmpdir(), "s1r-")));
    await withFilesystemLockTestHooks({ closeNamespaceCapability: lockKinds(calls) }, () =>
      storage.withStrictNamespaceLock(NS, ".strict.lock", async () => undefined, { runtimeRoot }));
    expect(calls).toContain("namespace-fd");
  });

  it.runIf(process.platform === "linux" || process.platform === "darwin")("a kept strict lease no longer asserts that it is held", async () => {
    const runtimeRoot = await realpath(await mkdtemp(join(tmpdir(), "s1r-")));
    let kept: lockModule.CrossProcessLockLease | undefined;
    await storage.withStrictNamespaceLock(NS, ".strict.lock", async lease => {
      kept = lease;
      expect(() => lease.assertHeld()).not.toThrow();
    }, { runtimeRoot });
    expect(() => kept!.assertHeld()).toThrow(/strict lock lease is no longer active/);
  });

  it("the strict marker never mutates the caller's options", async () => {
    vi.spyOn(storage, "withNamespaceLock").mockResolvedValue(undefined);
    const options = { timeoutMs: 1 } as NamespaceLockOptions;
    await storage.withStrictNamespaceLock(NS, ".lock", async () => {}, options);
    expect(Object.getOwnPropertySymbols(options)).toEqual([]);
    expect(options).toEqual({ timeoutMs: 1 });
  });

  const ownerMissing = async (method: "writeStrict" | "writeIfAbsentStrict" | "replaceIfEqualsStrict"): Promise<void> => {
    const ownerStorage = new FilesystemStorage(root, { owner: owner() });
    const runtimeRoot = await realpath(await mkdtemp(join(tmpdir(), "s1r-")));
    await ownerStorage.withStrictNamespaceLock("locked", ".strict.lock", async () => {
      const pending = method === "replaceIfEqualsStrict"
        ? ownerStorage.replaceIfEqualsStrict("missing", "key", DATA, NEXT)
        : ownerStorage[method]("missing", "key", DATA);
      await expect(pending).rejects.toMatchObject({ code: "strict_directory_missing" });
    }, { runtimeRoot });
    expect(await readdir(root)).not.toContain("missing");
  };
  for (const method of ["writeStrict", "writeIfAbsentStrict", "replaceIfEqualsStrict"] as const) {
    inProcessStrictPath(`owner-mode ${method} into a missing namespace refuses with a typed code`, () => ownerMissing(method));
    darwinWorkerPath(`worker: owner-mode ${method} into a missing namespace refuses with a typed code`, () => ownerMissing(method));
  }
});
