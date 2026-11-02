import * as fs from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, expect, it, vi } from "vitest";
import { AuditLog, AuditLockContentionError, AuditLockRecoveryUnavailableError } from "../../src/operational/audit-log.js";
import { FilesystemStorage } from "../../src/storage/filesystem.js";
import * as locks from "../../src/storage/cross-process-lock.js";
vi.mock("../../src/storage/cross-process-lock.js", async original => ({ ...await original<typeof import("../../src/storage/cross-process-lock.js")>() }));
vi.mock("node:fs/promises", async original => ({ ...await original<typeof import("node:fs/promises")>() }));
let root: string;
afterEach(async () => { vi.restoreAllMocks(); vi.unstubAllEnvs(); if (root) await fs.rm(root, { recursive: true, force: true }); });
async function fixture() {
  root = await fs.mkdtemp(join(process.platform === "darwin" ? "/private/tmp" : tmpdir(), "age-")); vi.stubEnv("HOME", root); const dir = join(root, "s", "_audit");
  await fs.mkdir(dir, { recursive: true, mode: 0o700 });
  const lock = join(dir, ".audit-write.lock"); const bytes = JSON.stringify({ pid: 2147483647 });
  await fs.writeFile(lock, bytes); const ino = (await fs.stat(lock)).ino;
  const log = new AuditLog(new FilesystemStorage(join(root, "s")), Buffer.alloc(32, 1), { __testAuditGuardLockRoot: join(root, "g") }) as unknown as { breakStaleAuditLock(path: string): Promise<boolean> };
  return { dir, lock, bytes, ino, log };
}
it.each(["capability", "scaffold-integrity", "holder-lost", "operation_aborted", "poisoned", "io", "plain"])("normalizes guard %s failure without removing the lock", async kind => {
  const f = await fixture();
  const cause = kind === "plain" ? new Error("obstruction") : new locks.CrossProcessLockError("obstruction", kind as locks.CrossProcessLockErrorKind);
  vi.spyOn(locks, "withPathLock").mockRejectedValue(cause);
  const error = await f.log.breakStaleAuditLock(f.lock).catch(e => e);
  expect(error).toBeInstanceOf(AuditLockRecoveryUnavailableError); expect(error.cause).toBe(cause);
  expect(error.message).toMatch(/required owner uid.*0700.*owner or root/s);
  expect(await fs.readFile(f.lock, "utf8")).toBe(f.bytes); expect((await fs.stat(f.lock)).ino).toBe(f.ino);
});
it("maps guard contention to the base contention error", async () => {
  const f = await fixture(); vi.spyOn(locks, "withPathLock").mockRejectedValue(new locks.CrossProcessLockError("held", "contention"));
  const error = await f.log.breakStaleAuditLock(f.lock).catch(e => e);
  expect(error).toBeInstanceOf(AuditLockContentionError); expect(error).not.toBeInstanceOf(AuditLockRecoveryUnavailableError);
  expect(await fs.readFile(f.lock, "utf8")).toBe(f.bytes);
});
it.each([false, true])("guard release failure retains the verified inode; successor=%s", async successor => {
  const f = await fixture(); const pathLock = locks.withPathLock;
  vi.spyOn(locks, "withPathLock").mockImplementation(async (...args) => {
    await pathLock(...args);
    if (successor) await fs.writeFile(f.lock, "successor");
    throw new locks.CrossProcessLockError("injected release failure", "io");
  });
  const stderr = vi.spyOn(console, "error").mockImplementation(() => {});
  await expect(f.log.breakStaleAuditLock(f.lock)).rejects.toBeInstanceOf(AuditLockRecoveryUnavailableError);
  const tombs = (await fs.readdir(f.dir)).filter(n => n.endsWith(".tomb"));
  if (successor) {
    expect(await fs.readFile(f.lock, "utf8")).toBe("successor"); expect(tombs).toHaveLength(1);
    expect((await fs.stat(join(f.dir, tombs[0]))).ino).toBe(f.ino);
    expect(stderr).toHaveBeenCalledTimes(1);
  } else {
    expect(await fs.readFile(f.lock, "utf8")).toBe(f.bytes); expect((await fs.stat(f.lock)).ino).toBe(f.ino);
    expect(tombs).toEqual([]);
  }
});
it("restores on claim unlink failure and preserves the original inode", async () => {
  const f = await fixture(); const realUnlink = fs.unlink; let failed = false;
  vi.spyOn(fs, "unlink").mockImplementation(async path => {
    if (!failed && String(path).endsWith(".tomb")) { failed = true; throw new Error("injected claim unlink failure"); }
    return realUnlink(path);
  });
  await expect(f.log.breakStaleAuditLock(f.lock)).rejects.toBeInstanceOf(AuditLockRecoveryUnavailableError);
  expect(failed).toBe(true); expect(await fs.readFile(f.lock, "utf8")).toBe(f.bytes);
  expect((await fs.stat(f.lock)).ino).toBe(f.ino);
  expect((await fs.readdir(f.dir)).filter(n => n.endsWith(".tomb"))).toEqual([]);
});
it("tomb byte comparison rejects in-place replacement even when dev and ino match", async () => {
  const f = await fixture(); const rename = fs.rename;
  vi.spyOn(fs, "rename").mockImplementationOnce(async (from, to) => {
    await fs.writeFile(f.lock, "in-place replacement");
    return rename(from, to);
  });
  expect(await f.log.breakStaleAuditLock(f.lock)).toBe(false);
  expect(await fs.readFile(f.lock, "utf8")).toBe("in-place replacement");
  expect((await fs.stat(f.lock)).ino).toBe(f.ino);
});
