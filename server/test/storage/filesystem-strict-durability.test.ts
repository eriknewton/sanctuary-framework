import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { mkdtemp, readFile, rename, stat, mkdir, realpath, symlink, readdir } from "node:fs/promises";
import { fork } from "node:child_process";
import { once } from "node:events";
import { fileURLToPath } from "node:url";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { FilesystemStorage } from "../../src/storage/filesystem.js";
import * as sdwWriteGate from "../../src/sdw/write-gate.js";
import { prepareSdwOwnerPinWrite } from "../../src/sdw/write-gate.js";
import { syncDirectoryStrict, writeFileCustody } from "../../src/storage/custody-fs.js";
import { ReadOnlyStorageGuard } from "../../src/storage/read-only-guard.js";

const faults = vi.hoisted(() => ({
  path: "", code: "EINVAL", fileSynced: false, afterFile: false, closeFailure: false, once: false,
  swapOnOpen: "", swapOnPublish: "", capturedOnly: "", syncAfterAbsent: false, fileClose: false, linkError: false, cleanupError: "", openFlags: [] as Array<{ path: string; flags: unknown }>,
  events: [] as Array<{ path: string; directory: boolean }>,
}));
vi.mock("node:fs/promises", async (original) => {
  const fs = await original<typeof import("node:fs/promises")>();
  return { ...fs,
    rename: async (...args: Parameters<typeof fs.rename>) => {
      await fs.rename(...args);
      if (faults.swapOnPublish && String(args[1]).endsWith(".enc")) {
        const directory = faults.swapOnPublish;
        faults.swapOnPublish = "";
        await fs.rename(directory, `${directory}-held`);
        await fs.mkdir(directory);
      }
    },
    link: async (...args: Parameters<typeof fs.link>) => {
      if (faults.cleanupError === "sync") faults.path = String(args[0]).slice(0, String(args[0]).lastIndexOf("/"));
      if (faults.linkError) throw Object.assign(new Error("publication failed"), { code: "EPERM" });
      return fs.link(...args);
    },
    unlink: async (...args: Parameters<typeof fs.unlink>) => {
      if (String(args[0]).endsWith(".claim") && faults.cleanupError && faults.cleanupError !== "sync") {
        if (faults.cleanupError === "ENOENT") {
          await fs.unlink(...args);
          if (faults.syncAfterAbsent) faults.path = String(args[0]).slice(0, String(args[0]).lastIndexOf("/"));
        }
        throw Object.assign(new Error("cleanup failed"), { code: faults.cleanupError });
      }
      return fs.unlink(...args);
    },
    open: async (...args: Parameters<typeof fs.open>) => {
    faults.openFlags.push({ path: String(args[0]), flags: args[1] });
    const handle = await fs.open(...args);
    const isFile = !(await handle.stat()).isDirectory();
    if (faults.swapOnOpen === String(args[0])) {
      faults.swapOnOpen = "";
      await fs.rename(String(args[0]), `${String(args[0])}-held`);
      await fs.mkdir(String(args[0]));
    }
    const sync = handle.sync.bind(handle);
    const close = handle.close.bind(handle);
    handle.close = async () => {
      await close();
      if (faults.fileClose && isFile) throw Object.assign(new Error("file close failed"), { code: "EBADF" });
      if (faults.closeFailure && String(args[0]) === faults.path) throw Object.assign(new Error("injected close failure"), { code: "EIO" });
    };
    handle.sync = async () => {
      const directory = (await handle.stat()).isDirectory();
      const path = String(args[0]);
      faults.events.push({ path, directory });
      if (path === faults.capturedOnly && (args[1] === "r" || (typeof args[1] === "number" && args[1] !== 0))) {
        throw Object.assign(new Error("captured barrier failed"), { code: "EIO" });
      }
      if (!directory) faults.fileSynced = true;
      if ((faults.path === "FILE" ? !directory : path === faults.path) &&
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

function requireStrict(): void {
  // An old tree fails this loaded assertion rather than failing collection or calling an absent method.
  expect(typeof storage.writeStrict, "ENTRYPOINT_ABSENT writeStrict").toBe("function");
  expect(typeof storage.writeIfAbsentStrict, "ENTRYPOINT_ABSENT writeIfAbsentStrict").toBe("function");
  expect(typeof storage.replaceIfEqualsStrict, "ENTRYPOINT_ABSENT replaceIfEqualsStrict").toBe("function");
}

describe("strict file and directory barriers", () => {
  it("publishes exact bytes with file, leaf and every new parent barrier", async () => {
    requireStrict();
    const base = join(root, "new-parent", "new-child");
    storage = new FilesystemStorage(base);
    await storage.writeStrict(NS, "key", DATA);
    expect(Buffer.from((await storage.read(NS, "key"))!)).toEqual(DATA);
    const directories = faults.events.filter(event => event.directory).map(event => event.path);
    for (const path of [root, join(root, "new-parent"), base, join(base, NS)]) expect(directories).toContain(path);
    expect(faults.events.some(event => !event.directory)).toBe(true);
    expect((await stat(join(base, NS, "key.enc"))).mode & 0o777).toBe(PRIVATE_FILE_MODE);
  });

  for (const barrier of ["file", "leaf", "parent", "ancestor"] as const) {
    it(`custody propagates the ${barrier} barrier failure`, async () => {
      const parent = join(root, "parent");
      const leaf = join(parent, "leaf");
      faults.path = { file: "FILE", leaf, parent, ancestor: root }[barrier];
      await expect(writeFileCustody(join(leaf, "row"), DATA, {
        mode: PRIVATE_FILE_MODE, strictDurability: true,
      })).rejects.toMatchObject({ code: "EINVAL" });
      await expect(readFile(join(leaf, "row"))).rejects.toMatchObject({ code: "ENOENT" });
    });
  }

  it("strict parent barriers preserve relative directory authority", async () => {
    const originalCwd = process.cwd();
    try {
      process.chdir(root);
      await writeFileCustody("parent/leaf/row", DATA, { mode: PRIVATE_FILE_MODE, strictDurability: true });
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
      mode: PRIVATE_FILE_MODE, strictDurability: true,
    })).rejects.toMatchObject({ errors: [{ code: "EINVAL" }, { code: "EIO" }] });
  });

  it("successful readback does not excuse a post-publication directory failure", async () => {
    requireStrict();
    faults.path = join(root, NS);
    faults.afterFile = true;
    await expect(storage.writeStrict(NS, "key", DATA)).rejects.toMatchObject({ code: "EINVAL" });
    expect(Buffer.from((await storage.read(NS, "key"))!)).toEqual(DATA);
  });

  it("legacy directory tolerance stays separate from strict propagation", async () => {
    faults.path = join(root, NS);
    await expect(storage.writeDurable(NS, "legacy", DATA)).resolves.toBeUndefined();
    requireStrict();
    await expect(storage.writeStrict(NS, "strict", DATA)).rejects.toMatchObject({ code: "EINVAL" });
    expect(await storage.read(NS, "strict")).toBeNull();
  });

  for (const code of ["EIO", "ENOTSUP", "EOPNOTSUPP"]) {
    it(`strict writes propagate ${code}`, async () => {
      requireStrict();
      faults.code = code;
      faults.path = join(root, NS);
      await expect(storage.writeStrict(NS, "key", DATA)).rejects.toMatchObject({ code });
    });
  }

  it("exclusive create and serialized replacement preserve comparison semantics", async () => {
    requireStrict();
    expect(await storage.replaceIfEqualsStrict(NS, "absent", DATA, NEXT)).toBe(false);
    expect(await storage.writeIfAbsentStrict(NS, "key", DATA)).toBe(true);
    expect(await storage.writeIfAbsentStrict(NS, "key", NEXT)).toBe(false);
    expect(Buffer.from((await storage.read(NS, "key"))!)).toEqual(DATA);
    expect(await storage.replaceIfEqualsStrict(NS, "key", NEXT, DATA)).toBe(false);
    expect(await storage.replaceIfEqualsStrict(NS, "key", DATA, NEXT)).toBe(true);
    expect(Buffer.from((await storage.read(NS, "key"))!)).toEqual(NEXT);
  });

  it("absent strict comparison still syncs its new lock parents", async () => {
    requireStrict();
    storage = new FilesystemStorage(join(root, "new-parent"));
    faults.path = root;
    await expect(storage.replaceIfEqualsStrict(NS, "absent", DATA, NEXT)).rejects.toMatchObject({ code: "EINVAL" });
    expect(await storage.read(NS, "absent")).toBeNull();
  });

  for (const operation of ["create", "replace"] as const) {
    it(`${operation} propagates directory failure after a file barrier`, async () => {
      requireStrict();
      if (operation === "replace") await storage.writeStrict(NS, "key", DATA);
      faults.fileSynced = false;
      faults.path = join(root, NS);
      faults.afterFile = true;
      faults.once = operation === "replace";
      const pending = operation === "create"
        ? storage.writeIfAbsentStrict(NS, "key", DATA)
        : storage.replaceIfEqualsStrict(NS, "key", DATA, NEXT);
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
    for (const pending of [
      storage.writeStrict("_sdw_document_corpus", "key", DATA),
      storage.writeIfAbsentStrict("_sdw_document_corpus", "key", DATA),
      storage.replaceIfEqualsStrict("_sdw_document_corpus", "key", DATA, NEXT),
    ]) await expect(pending).rejects.toThrow();
  });

  it.runIf(process.platform === "linux" || process.platform === "darwin")("strict namespace binding keeps writes on the held inode", async () => {
    requireStrict();
    expect(typeof storage.withStrictNamespaceLock, "ENTRYPOINT_ABSENT withStrictNamespaceLock").toBe("function");
    const runtimeRoot = await realpath(await mkdtemp(join(tmpdir(), "s1r-")));
    const moved = `${root}-held`;
    let entered = false;
    await expect(storage.withStrictNamespaceLock(NS, ".strict.lock", async () => {
      entered = true;
      await rename(root, moved);
      await storage.writeStrict(NS, "key", DATA);
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
    await storage.withStrictNamespaceLock(NS, ".strict.lock", async (lease) => {
      expect(await storage.writeIfAbsentStrict(NS, "key", DATA)).toBe(true);
      expect(await storage.replaceIfEqualsStrict(NS, "key", DATA, NEXT)).toBe(true);
      await lease.stableFortressFiles!.write("fixture.control", DATA);
      expect(await readFile(join(root, "fixture.control"))).toEqual(DATA);
    }, { runtimeRoot });
    expect(Buffer.from((await storage.read(NS, "key"))!)).toEqual(NEXT);
  });

  it.runIf(process.platform === "darwin")("Darwin worker creates strict parent directories through its held capability", async () => {
    requireStrict();
    storage = new FilesystemStorage(join(root, "state"));
    const runtimeRoot = await realpath(await mkdtemp(join(tmpdir(), "s1r-")));
    await storage.withStrictNamespaceLock(NS, ".strict.lock", async (lease) => {
      const PRIVATE_DIRECTORY_MODE = 0o700;
      await lease.stableFortressCapability!.mkdir("parent/child", PRIVATE_DIRECTORY_MODE);
      expect((await stat(join(root, "parent", "child"))).isDirectory()).toBe(true);
    }, { runtimeRoot });
  });

});

describe("strict completion witnesses", () => {
  it("preserves file sync and close failures together", async () => {
    faults.path = "FILE";
    faults.fileClose = true;
    await expect(storage.writeStrict(NS, "key", DATA)).rejects.toMatchObject({ errors: [{ code: "EINVAL" }, { code: "EBADF" }] });
  });
  it("refuses a file close failure after successful sync", async () => {
    faults.fileClose = true;
    await expect(storage.writeStrict(NS, "key", DATA)).rejects.toMatchObject({ code: "EBADF" });
  });
  for (const cleanup of ["ENOENT", "EIO", "sync"]) {
    it(`preserves publication failure through cleanup ${cleanup}`, async () => {
      faults.linkError = true;
      faults.cleanupError = cleanup;
      const failure = await storage.writeIfAbsentStrict(NS, "key", DATA).catch(error => error);
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
  it("limits existing unbound directory barriers to the final directory", async () => {
    await mkdir(join(root, NS));
    await storage.writeStrict(NS, "key", DATA);
    const directories = faults.events.filter(event => event.directory).map(event => event.path);
    expect(directories).toContain(join(root, NS));
    expect(directories).not.toContain(root);
    expect(directories).not.toContain("/");
  });
  it("syncs the verified owner parent chain", async () => {
    await mkdir(join(root, NS));
    storage = new FilesystemStorage(root, { owner: { uid: process.getuid!(), gid: process.getgid!() } });
    await storage.writeStrict(NS, "key", DATA);
    expect(faults.events.filter(event => event.directory).map(event => event.path)).toContain(root);
    expect(Buffer.from((await storage.read(NS, "key"))!)).toEqual(DATA);
  });
  it("strict lock overrides environmental degradation", async () => {
    const lock = vi.spyOn(storage, "withNamespaceLock").mockResolvedValue(undefined);
    const options = { degradeOnEnvironmentalLoss: "inert", kernelBacked: false };
    await storage.withStrictNamespaceLock(NS, ".lock", async () => {}, options);
    expect(lock.mock.calls[0]?.[3]).toMatchObject({ kernelBacked: true, degradeOnEnvironmentalLoss: undefined });
  });
  for (const method of ["writeStrict", "writeIfAbsentStrict", "replaceIfEqualsStrict"] as const) {
    it(`authorized SDW payload succeeds through ${method}`, async () => {
      const KEY_BYTES = 32; // The owner pin MAC uses a 256-bit master key.
      const prepared = prepareSdwOwnerPinWrite(new Uint8Array(KEY_BYTES), {
        version: 1, fortress_id: "fixture-fortress", owner_ref: "fixture-owner", agent_id: "fixture-agent", pinned_at: "2026-11-08T00:00:00Z",
      });
      if (method === "replaceIfEqualsStrict") await storage.writeStrict(prepared.namespace, prepared.storageKey, prepared.data);
      const gate = vi.spyOn(sdwWriteGate, "assertSdwRawWriteAuthorized");
      const result = method === "replaceIfEqualsStrict"
        ? await storage.replaceIfEqualsStrict(prepared.namespace, prepared.storageKey, prepared.data, prepared.data)
        : await storage[method](prepared.namespace, prepared.storageKey, prepared.data);
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
it("refuses a publishing directory replaced after rename", async () => {
  await mkdir(join(root, NS));
  faults.swapOnPublish = join(root, NS);
  await expect(storage.writeStrict(NS, "key", DATA)).rejects.toThrow(/directory changed/);
  expect(await readFile(join(root, `${NS}-held`, "key.enc"))).toEqual(DATA);
});
it.runIf(process.platform === "linux")("strict binding syncs captured root authority", async () => {
  const runtimeRoot = await realpath(await mkdtemp(join(tmpdir(), "s1r-")));
  faults.capturedOnly = root;
  let entered = false;
  await expect(storage.withStrictNamespaceLock(NS, ".strict.lock", async () => { entered = true; }, { runtimeRoot })).rejects.toMatchObject({ code: "EIO" });
  expect(entered).toBe(false);
});

for (const method of ["writeStrict", "writeIfAbsentStrict", "replaceIfEqualsStrict"] as const) {
  it(`authorized SDW bytes cross the worker through ${method}`, async () => {
    const KEY_BYTES = 32; // The owner pin MAC uses a 256-bit master key.
    const prepared = prepareSdwOwnerPinWrite(new Uint8Array(KEY_BYTES), {
      version: 1, fortress_id: "fixture-fortress", owner_ref: "fixture-owner", agent_id: "fixture-agent", pinned_at: "2026-11-08T00:00:00Z",
    });
    if (method === "replaceIfEqualsStrict") await storage.writeStrict(prepared.namespace, prepared.storageKey, prepared.data);
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

it("cleans a staged publication after its directory barrier fails", async () => {
  faults.path = join(root, NS);
  faults.afterFile = true;
  faults.once = true;
  await expect(storage.writeIfAbsentStrict(NS, "key", DATA)).rejects.toMatchObject({ code: "EINVAL" });
  expect((await readdir(join(root, NS))).filter(name => name.endsWith(".claim"))).toEqual([]);
});

it("successful exclusive publication tolerates an absent staging name", async () => {
  faults.cleanupError = "ENOENT";
  expect(await storage.writeIfAbsentStrict(NS, "key", DATA)).toBe(true);
  expect(Buffer.from((await storage.read(NS, "key"))!)).toEqual(DATA);
});
it("absent staging still performs the final directory barrier", async () => {
  faults.cleanupError = "ENOENT";
  faults.syncAfterAbsent = true;
  await expect(storage.writeIfAbsentStrict(NS, "key", DATA)).rejects.toMatchObject({ code: "EINVAL" });
  expect(Buffer.from((await storage.read(NS, "key"))!)).toEqual(DATA);
});
