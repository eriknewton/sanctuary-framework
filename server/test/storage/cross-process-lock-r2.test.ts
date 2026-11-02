import { mkdtemp, mkdir, readdir, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import * as childProcess from "node:child_process";
import { afterEach, expect, it, vi } from "vitest";
import { withPathLock, auditGuardDarwinUserTempDir } from "../../src/storage/cross-process-lock.js";
vi.mock("node:child_process", async original => ({ ...await original<typeof import("node:child_process")>() }));
let root: string | undefined;
afterEach(async () => { vi.restoreAllMocks(); vi.unstubAllEnvs(); if (root) await rm(root, { recursive: true, force: true }); });
it("zero timeout admits exactly one free bind and refuses an occupied lock", async () => {
  root = await mkdtemp(join(process.platform === "darwin" ? "/private/tmp" : tmpdir(), "kr2-")); vi.stubEnv("HOME", root);
  const target = join(root, "d"); await mkdir(target, { mode: 0o700 });
  const runtimeRoot = join(root, "g"); const callback = vi.fn(async () => {});
  const options = { kernelBacked: true, runtimeRoot, timeoutMs: 0 };
  const result = await withPathLock(target, ".test", callback, options).then(() => "admitted", error => error);
  expect(result).toBe("admitted"); expect(callback).toHaveBeenCalledTimes(1);
  await withPathLock(target, ".test", async () => {
    await expect(withPathLock(target, ".test", callback, options)).rejects.toMatchObject({ kind: "contention" });
  }, { kernelBacked: true, runtimeRoot });
  expect(callback).toHaveBeenCalledTimes(1);
  expect((await readdir(runtimeRoot)).filter(name => name.endsWith(".sock"))).toEqual([]);
});
it("retries a failed Darwin getconf probe and caches only the successful result", async () => {
  let calls = 0;
  const probe = vi.spyOn(childProcess, "execFile").mockImplementation((file: any, args: any, options: any, callback: any) => {
    expect(file).toBe("/usr/bin/getconf"); expect(args).toEqual(["DARWIN_USER_TEMP_DIR"]); expect(options.env).toEqual({});
    calls++;
    callback(calls === 1 ? new Error("temporary probe failure") : null, "/var/folders/u/T/\n");
    return {} as any;
  });
  await expect(auditGuardDarwinUserTempDir()).rejects.toThrow("temporary probe failure");
  const retried = await auditGuardDarwinUserTempDir().catch(error => String(error));
  expect(retried).toBe("/var/folders/u/T/");
  expect(await auditGuardDarwinUserTempDir()).toBe(retried); expect(probe).toHaveBeenCalledTimes(2);
});
