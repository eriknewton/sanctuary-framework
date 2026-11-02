import * as fs from "node:fs/promises";
import { spawn, type ChildProcess } from "node:child_process";
import { once } from "node:events";
import { createHash } from "node:crypto";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { afterEach, expect, it, vi } from "vitest";
import { AuditLog, AuditLockContentionError, AuditLockRecoveryUnavailableError, __testResetAuditLockTempSweepBudget } from "../../src/operational/audit-log.js";
import { FilesystemStorage } from "../../src/storage/filesystem.js";
import * as tokens from "../../src/operational/process-start-token.js";
import * as locks from "../../src/storage/cross-process-lock.js";
vi.mock("node:fs/promises", async original => ({ ...await original<typeof import("node:fs/promises")>() }));
vi.mock("../../src/operational/process-start-token.js", async original => ({ ...await original<typeof import("../../src/operational/process-start-token.js")>() }));
vi.mock("../../src/storage/cross-process-lock.js", async original => ({ ...await original<typeof import("../../src/storage/cross-process-lock.js")>() }));
const roots: string[] = [];
const children: ChildProcess[] = [];
const UUID = "11111111-1111-4111-8111-111111111111";
const OTHER_UUID = "22222222-2222-4222-8222-222222222222";
const BOOTTIME = "{ sec = 1793520000, usec = 0 } Sun Nov  1 08:00:00 2026";
const DEAD = 2147483647; // Maximum signed pid, beyond the host's allocatable pid range.
const TOKEN = process.platform === "darwin" ? "Sun Nov  1 10:46:41 2026" : "12345";
const OTHER_TOKEN = process.platform === "darwin" ? "Sun Nov  1 10:46:42 2026" : "12346";
type Internals = {
  currentLockBootId(): string | undefined;
  decideStaleAuditLock(path: string): Promise<{ verdict: string; reason?: string }>;
  breakStaleAuditLock(path: string): Promise<boolean>;
  withAuditWriteLock(op: () => Promise<void>): Promise<void>;
  sweepStaleAcquireTempsOnce(path: string): Promise<void>;
};
afterEach(async () => {
  vi.restoreAllMocks(); vi.unstubAllEnvs();
  for (const child of children.splice(0)) {
    if (child.exitCode === null && child.signalCode === null) {
      const exited = once(child, "exit"); child.kill("SIGKILL"); await exited;
    }
  }
  for (const root of roots.splice(0)) await fs.rm(root, { recursive: true, force: true });
});
async function fixture() {
  __testResetAuditLockTempSweepBudget();
  const root = await fs.mkdtemp(join(process.platform === "darwin" ? "/private/tmp" : tmpdir(), "ar2-"));
  roots.push(root); vi.stubEnv("HOME", root);
  const dir = join(root, "s", "_audit"); await fs.mkdir(dir, { recursive: true, mode: 0o700 });
  const lock = join(dir, ".audit-write.lock"); let clock = 0;
  const make = () => new AuditLog(new FilesystemStorage(join(root, "s")), Buffer.alloc(32, 1), {
    __testAuditGuardLockRoot: join(root, "g"), __testMonotonicNow: () => clock,
  }) as unknown as Internals;
  const log = make();
  return { root, dir, lock, log, make, expire: () => { clock = 5001; }, // Production acquisition budget is 5000 ms.
    plant: (record: unknown) => fs.writeFile(lock, JSON.stringify(record)) };
}
it.each([
  ["UUID holder with contender boottime fallback", UUID, BOOTTIME],
  ["unknown holder boot shape", "boot", UUID],
  ["UUID with trailing newline", `${UUID}\n`, UUID],
  ["different boottime values", BOOTTIME, BOOTTIME.replace("1793520000", "1793520001")],
])("preserves live lock with boot unknown: %s", async (_label, holder, current) => {
  const f = await fixture();
  vi.spyOn(f.log, "currentLockBootId").mockReturnValue(current);
  vi.spyOn(tokens, "readProcessStartToken").mockResolvedValue(TOKEN);
  vi.spyOn(process, "kill").mockReturnValue(true);
  await f.plant({ pid: 1, boot_id: holder, start_token: TOKEN });
  const bytes = await fs.readFile(f.lock); const inode = (await fs.stat(f.lock)).ino;
  expect(await f.log.breakStaleAuditLock(f.lock)).toBe(false);
  expect(await fs.readFile(f.lock)).toEqual(bytes); expect((await fs.stat(f.lock)).ino).toBe(inode);
});
it("two different UUIDs still prove different_boot", async () => {
  const f = await fixture(); vi.spyOn(f.log, "currentLockBootId").mockReturnValue(UUID);
  await f.plant({ pid: 1, boot_id: OTHER_UUID });
  expect(await f.log.decideStaleAuditLock(f.lock)).toMatchObject({ verdict: "stale", reason: "different_boot" });
});
it("late post-link cleanup never admits the audit callback and releases the captured inode", async () => {
  const f = await fixture(); const unlink = fs.unlink; const callback = vi.fn(async () => {});
  vi.spyOn(fs, "unlink").mockImplementation(async path => {
    await unlink(path);
    if (String(path).endsWith(".tmp")) f.expire();
  });
  const outcome = await f.log.withAuditWriteLock(callback).catch(error => error);
  expect(callback).not.toHaveBeenCalled();
  expect(outcome).toBeInstanceOf(AuditLockContentionError);
  await expect(fs.stat(f.lock)).rejects.toMatchObject({ code: "ENOENT" });
});
it.each([["self", "old"], ["foreign", "old"], ["self", `${TOKEN}\n`], ["foreign", `${TOKEN}\n`]])("non-shaped token is unknown for a live %s holder: %j", async (principal, malformedToken) => {
  const f = await fixture(); vi.spyOn(f.log, "currentLockBootId").mockReturnValue(UUID);
  vi.spyOn(tokens, "ownProcessStartToken").mockResolvedValue(TOKEN);
  vi.spyOn(tokens, "readProcessStartToken").mockResolvedValue(TOKEN);
  vi.spyOn(process, "kill").mockReturnValue(true);
  await f.plant({ pid: principal === "self" ? process.pid : 1, boot_id: UUID, start_token: malformedToken, acquired_at: new Date().toISOString() });
  const bytes = await fs.readFile(f.lock);
  expect(await f.log.breakStaleAuditLock(f.lock)).toBe(false);
  expect(await fs.readFile(f.lock)).toEqual(bytes);
  // A different valid-shaped token remains independent evidence of pid reuse.
  await f.plant({ pid: principal === "self" ? process.pid : 1, boot_id: UUID, start_token: OTHER_TOKEN });
  expect(await f.log.breakStaleAuditLock(f.lock)).toBe(true);
});
it.runIf(process.platform === "linux")("real AuditLog child uses the production root and guard name without a seam", async () => {
  const f = await fixture();
  const root = locks.resolveAuditGuardRuntimeRoot(process.getuid!(), process.platform);
  let scaffold = "";
  // Keep rejected directory inodes allocated so previous runs' scaffolds cannot satisfy this witness through inode reuse.
  const maxDirectories = 128; // Harness bound on inode candidates; no production allocation policy changes.
  for (let attempt = 0; attempt < maxDirectories; attempt++) {
    const stats = await fs.stat(f.dir, { bigint: true });
    // Must match guard name in operational/audit-log.ts and dev:ino:name hashing in storage/cross-process-lock.ts.
    const digest = createHash("sha256").update(`${stats.dev}:${stats.ino}:.audit-write.lock.guard`).digest("hex").slice(0, 40);
    const candidate = join(root, `${digest}.reaper`);
    if (await fs.stat(candidate).then(() => false, error => { if (error.code === "ENOENT") return true; throw error; })) {
      scaffold = candidate; break;
    }
    await fs.rename(f.dir, `${f.dir}-occupied-${attempt}`); await fs.mkdir(f.dir, { mode: 0o700 });
  }
  expect(scaffold).not.toBe("");
  await f.plant({ pid: DEAD });
  const child = spawn(process.execPath, ["--import", "tsx", fileURLToPath(new URL("./audit-log-r2-recovery-child.ts", import.meta.url)), f.root], {
    env: { ...process.env, HOME: f.root, SANCTUARY_CUSTODY_LOCK_ROOT: "relative-obstruction" }, stdio: ["ignore", "pipe", "pipe"],
  });
  children.push(child); let output = ""; let stderr = "";
  child.stdout!.on("data", data => { output += data; }); child.stderr!.on("data", data => { stderr += data; });
  await once(child, "close");
  expect(JSON.parse(output).recovered, stderr || output).toBe(true);
  expect((await fs.stat(scaffold)).size).toBe(0);
  await expect(fs.stat(f.lock)).rejects.toMatchObject({ code: "ENOENT" });
});
it.each(["mismatch", "unlink", "release"])("retains %s restore-EEXIST evidence after the recoverer dies, with one diagnostic", async fault => {
  const f = await fixture(); await f.plant({ pid: DEAD });
  const rename = fs.rename; const pathLock = locks.withPathLock;
  if (fault === "mismatch") vi.spyOn(fs, "rename").mockImplementationOnce(async (from, to) => {
    await fs.writeFile(f.lock, "replacement evidence"); await rename(from, to); await fs.writeFile(f.lock, "successor");
  });
  if (fault === "unlink") vi.spyOn(fs, "unlink").mockImplementationOnce(async path => {
    await fs.writeFile(f.lock, "successor"); throw new Error("claim unlink failed");
  });
  if (fault === "release") vi.spyOn(locks, "withPathLock").mockImplementation(async (...args) => {
    await pathLock(...args); await fs.writeFile(f.lock, "successor"); throw new Error("guard release failed");
  });
  const stderr = vi.spyOn(console, "error").mockImplementation(() => {});
  await expect(f.log.breakStaleAuditLock(f.lock)).rejects.toBeInstanceOf(AuditLockRecoveryUnavailableError);
  expect(stderr).toHaveBeenCalledTimes(1);
  const names = (await fs.readdir(f.dir)).filter(name => name.endsWith(".tomb"));
  expect(names.length).toBeGreaterThan(0);
  const before = await Promise.all(names.map(async name => ({ name, bytes: await fs.readFile(join(f.dir, name)), inode: (await fs.stat(join(f.dir, name))).ino })));
  // Simulate the recoverer's death only at the liveness chokepoint; no real process is signalled.
  vi.spyOn(process, "kill").mockImplementation(() => { throw Object.assign(new Error("dead"), { code: "ESRCH" }); });
  await f.make().sweepStaleAcquireTempsOnce(f.lock);
  expect((await fs.readdir(f.dir)).filter(name => name.endsWith(".tomb"))).toEqual(names);
  for (const entry of before) {
    expect(await fs.readFile(join(f.dir, entry.name))).toEqual(entry.bytes);
    expect((await fs.stat(join(f.dir, entry.name))).ino).toBe(entry.inode);
  }
  expect(await fs.readFile(f.lock, "utf8")).toBe("successor");
});
