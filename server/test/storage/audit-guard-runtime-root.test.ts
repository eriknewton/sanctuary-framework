import { readFile } from "node:fs/promises";
import { afterEach, expect, it, vi } from "vitest";
import * as childProcess from "node:child_process";
import { resolveAuditGuardRuntimeRoot, auditGuardDarwinUserTempDir, AUDIT_GUARD_GETCONF_TIMEOUT_MS } from "../../src/storage/cross-process-lock.js";
vi.mock("node:child_process", async original => ({ ...await original<typeof import("node:child_process")>() }));
afterEach(() => { vi.restoreAllMocks(); vi.unstubAllEnvs(); });
it("resolves every real uid without environment input or fallback", () => {
  vi.stubEnv("SANCTUARY_CUSTODY_LOCK_ROOT", "relative-obstruction");
  {
    expect(resolveAuditGuardRuntimeRoot(0, "linux")).toBe("/run/sanctuary-audit-guard-0");
    expect(resolveAuditGuardRuntimeRoot(1001, "linux")).toBe("/run/user/1001/sanctuary-audit-guard");
    for (const uid of [0, 501, 1001]) expect(resolveAuditGuardRuntimeRoot(uid, "darwin", "/var/folders/u/T/")).toBe("/var/folders/u/T");
    expect(() => resolveAuditGuardRuntimeRoot(501, "darwin", "/" + "a".repeat(100))).toThrow(/too long/);
    expect(() => resolveAuditGuardRuntimeRoot(501, "darwin")).toThrow(/unavailable/);
    expect(() => resolveAuditGuardRuntimeRoot(501, "darwin", "relative")).toThrow(/invalid/);
  }
});
it("reads captured Darwin getconf with an empty environment once and retains the directory itself", async () => {
  const capture = JSON.parse(await readFile(new URL("../fixtures/audit-lock/getconf-darwin-user-temp-dir-mac.json", import.meta.url), "utf8"));
  const output = Buffer.from(capture.bytes_base64, "base64").toString();
  const exec = vi.spyOn(childProcess, "execFile").mockImplementation((file: any, args: any, options: any, callback: any) => {
    expect(file).toBe("/usr/bin/getconf"); expect(args).toEqual(["DARWIN_USER_TEMP_DIR"]);
    expect(options.env).toEqual({}); expect(options.timeout).toBe(AUDIT_GUARD_GETCONF_TIMEOUT_MS);
    callback(null, output); return {} as any;
  });
  const root = await auditGuardDarwinUserTempDir();
  expect(await auditGuardDarwinUserTempDir()).toBe(root);
  expect(exec).toHaveBeenCalledTimes(1);
  expect(resolveAuditGuardRuntimeRoot(501, "darwin", root)).toBe(output.trim().replace(/\/$/, ""));
  expect(resolveAuditGuardRuntimeRoot(0, "darwin", "/var/folders/zz/zyxvpxvq6csfxvn_n0000000000000/T/")).toBe("/var/folders/zz/zyxvpxvq6csfxvn_n0000000000000/T");
});
