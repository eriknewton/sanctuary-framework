import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { mkdtemp, readFile, rename, stat } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { FilesystemStorage } from "../../src/storage/filesystem.js";
import { writeFileCustody } from "../../src/storage/custody-fs.js";
import { ReadOnlyStorageGuard } from "../../src/storage/read-only-guard.js";

const faults = vi.hoisted(() => ({
  path: "", code: "EINVAL", fileSynced: false, afterFile: false, closeFailure: false, once: false,
  events: [] as Array<{ path: string; directory: boolean }>,
}));
vi.mock("node:fs/promises", async (original) => {
  const fs = await original<typeof import("node:fs/promises")>();
  return { ...fs, open: async (...args: Parameters<typeof fs.open>) => {
    const handle = await fs.open(...args);
    const sync = handle.sync.bind(handle);
    const close = handle.close.bind(handle);
    handle.close = async () => {
      await close();
      if (faults.closeFailure && String(args[0]) === faults.path) throw Object.assign(new Error("injected close failure"), { code: "EIO" });
    };
    handle.sync = async () => {
      const directory = (await handle.stat()).isDirectory();
      const path = String(args[0]);
      faults.events.push({ path, directory });
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
  root = await mkdtemp(join(tmpdir(), "s1a-"));
  storage = new FilesystemStorage(root);
  faults.path = "";
  faults.code = "EINVAL";
  faults.fileSynced = false;
  faults.afterFile = false;
  faults.closeFailure = false;
  faults.once = false;
  faults.events = [];
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
      await expect(pending).rejects.toMatchObject({ code: "EINVAL" });
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
    const runtimeRoot = await mkdtemp(join(tmpdir(), "s1r-"));
    const moved = `${root}-held`;
    await expect(storage.withStrictNamespaceLock(NS, ".strict.lock", async () => {
      await rename(root, moved);
      await storage.writeStrict(NS, "key", DATA);
      expect(await readFile(join(moved, NS, "key.enc"))).toEqual(DATA);
    }, { runtimeRoot })).rejects.toThrow(/changed/);
  });

  it.runIf(process.platform === "linux" || process.platform === "darwin")("legacy namespace bindings cannot advertise strict parent durability", async () => {
    requireStrict();
    const runtimeRoot = await mkdtemp(join(tmpdir(), "s1r-"));
    await storage.withNamespaceLock(NS, ".legacy.lock", async () => {
      await expect(storage.writeStrict(NS, "key", DATA)).rejects.toThrow(/strict namespace binding/);
    }, { runtimeRoot, kernelBacked: true });
  });
  it.runIf(process.platform === "linux" || process.platform === "darwin")("strict namespace binding completes create, replace and stable file writes", async () => {
    requireStrict();
    storage = new FilesystemStorage(join(root, "state"));
    const runtimeRoot = await mkdtemp(join(tmpdir(), "s1r-"));
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
    const runtimeRoot = await mkdtemp(join(tmpdir(), "s1r-"));
    await storage.withStrictNamespaceLock(NS, ".strict.lock", async (lease) => {
      const PRIVATE_DIRECTORY_MODE = 0o700;
      await lease.stableFortressCapability!.mkdir("parent/child", PRIVATE_DIRECTORY_MODE);
      expect((await stat(join(root, "parent", "child"))).isDirectory()).toBe(true);
    }, { runtimeRoot });
  });

});
