// fail-before-exempt: A1b r2 coordinator rulings normalize only planted and mocked identity shapes; all existing assertions and token/boot relationships are unchanged.
import * as fs from "node:fs/promises";
import { tmpdir, uptime } from "node:os";
import { join } from "node:path";
import type { Stats } from "node:fs";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { AuditLog, AuditLockContentionError, AuditLockRecoveryUnavailableError, auditGuardExpectedDirOwnerUid, probePidLiveness, __testResetAuditLockTempSweepBudget, type AuditLogConfig } from "../../src/operational/audit-log.js";
import { createDaemonAuditLog } from "../../src/operational/audit-store-split.js";
import * as tokens from "../../src/operational/process-start-token.js";
import * as locks from "../../src/storage/cross-process-lock.js";
import { FilesystemStorage } from "../../src/storage/filesystem.js";
import { generateRandomKey } from "../../src/core/random.js";

vi.mock("node:fs/promises", async importOriginal => ({ ...await importOriginal<typeof import("node:fs/promises")>() }));
vi.mock("../../src/operational/process-start-token.js", async importOriginal => ({ ...await importOriginal<typeof import("../../src/operational/process-start-token.js")>() }));
vi.mock("../../src/storage/cross-process-lock.js", async importOriginal => ({ ...await importOriginal<typeof import("../../src/storage/cross-process-lock.js")>() }));

type Decision = { verdict: string; reason?: string };
type Internals = {
  withAuditWriteLock<T>(op: () => Promise<T>): Promise<T>;
  decideStaleAuditLock(path: string, strict?: boolean): Promise<Decision>;
  breakStaleAuditLock(path: string, deadline?: number): Promise<boolean>;
  unlinkIfSameInode(path: string, st: Stats): Promise<boolean>;
  currentLockBootId(): string | undefined;
};
const roots: string[] = [];
const DEAD = 2147483647; // Maximum signed pid value, outside this host's allocatable pid range.
const FOREIGN = 1;
const BOOT = "11111111-1111-4111-8111-111111111111";
const OTHER_BOOT = "22222222-2222-4222-8222-222222222222";
const OWN_TOKEN = process.platform === "darwin" ? "Sun Nov  1 10:46:41 2026" : "12345";
const FOREIGN_TOKEN = process.platform === "darwin" ? "Sun Nov  1 10:46:42 2026" : "12346";
const OLD_TOKEN = process.platform === "darwin" ? "Sun Nov  1 10:46:43 2026" : "12347";
const NOW = () => new Date().toISOString();
const PREBOOT = "2000-01-01T00:00:00.000Z";
beforeEach(() => __testResetAuditLockTempSweepBudget());
afterEach(async () => { vi.restoreAllMocks(); vi.unstubAllEnvs(); vi.useRealTimers(); for (const root of roots.splice(0)) await fs.rm(root, { recursive: true, force: true }); });
async function fixture(config: AuditLogConfig = {}) {
  const root = await fs.mkdtemp(join(process.platform === "darwin" ? "/private/tmp" : tmpdir(), "a1b-")); roots.push(root); vi.stubEnv("HOME", root);
  const dir = join(root, "s", "_audit");
  await fs.mkdir(dir, { recursive: true, mode: 0o700 });
  const runtimeRoot = join(root, "g");
  const key = generateRandomKey();
  let clock = 0;
  const settings = { integrityMode: "lenient" as const, __testAuditGuardLockRoot: runtimeRoot, __testMonotonicNow: () => clock, ...config };
  const storage = new FilesystemStorage(join(root, "s"));
  const log = new AuditLog(storage, key, settings);
  const internals = log as unknown as Internals;
  const lock = join(dir, ".audit-write.lock");
  const plant = async (record: unknown) => fs.writeFile(lock, typeof record === "string" ? record : JSON.stringify(record));
  return { root, dir, runtimeRoot, key, log, internals, lock, plant, storage, settings, advance: (ms: number) => { clock += ms; } };
}

it("uses the one tri-state probe for success, ESRCH, EPERM, every unknown error and invalid pid", () => {
  const kill = vi.spyOn(process, "kill").mockReturnValue(true);
  expect(probePidLiveness(FOREIGN)).toBe("alive");
  for (const [code, expected] of [["ESRCH", "dead"], ["EPERM", "alive"], ["EIO", "unknown"], ["EINVAL", "unknown"], [undefined, "unknown"]]) {
    kill.mockImplementation(() => { throw Object.assign(new Error("probe"), { code }); });
    expect(probePidLiveness(FOREIGN)).toBe(expected);
  }
  kill.mockClear();
  for (const pid of [0, -1, 1.5, NaN, Number.MAX_SAFE_INTEGER + 1]) expect(probePidLiveness(pid)).toBe("unknown");
  expect(kill).not.toHaveBeenCalled();
});

it("tables rows 1 through 11 with planted records and preserves token-less proofs", async () => {
  const f = await fixture();
  vi.spyOn(f.internals, "currentLockBootId").mockReturnValue(BOOT);
  vi.spyOn(tokens, "ownProcessStartToken").mockResolvedValue(OWN_TOKEN);
  vi.spyOn(tokens, "readProcessStartToken").mockResolvedValue(FOREIGN_TOKEN);
  vi.spyOn(process, "kill").mockImplementation(pid => { if (pid === DEAD) throw Object.assign(new Error(), { code: "ESRCH" }); return true; });
  const current = uptime() * 1000;
  const started = current - process.uptime() * 1000;
  const rows: Array<[string, unknown, string, string?]> = [
    ["1 different boot", { pid: FOREIGN, boot_id: OTHER_BOOT, start_token: FOREIGN_TOKEN }, "stale", "different_boot"],
    ["2 self token differs", { pid: process.pid, start_token: OLD_TOKEN }, "stale", "reused_self_pid"],
    ["2 self token equal", { pid: process.pid, start_token: OWN_TOKEN, acquired_at: PREBOOT }, "in_progress"],
    ["3 self before start", { pid: process.pid, boot_id: BOOT, uptime_ms: started - 5000 }, "stale", "reused_self_pid"],
    ["3 self after start", { pid: process.pid, boot_id: BOOT, uptime_ms: current }, "in_progress"],
    ["4 self old wall stamp", { pid: process.pid, acquired_at: PREBOOT }, "stale"],
    ["4 self recent wall stamp", { pid: process.pid, acquired_at: NOW() }, "in_progress"],
    ["5 self held stale", { pid: process.pid, boot_id: BOOT, start_token: OWN_TOKEN, uptime_ms: current - 120000 }, "stale", "self_held_stale_forced_release"],
    ["6 dead foreign", { pid: DEAD, acquired_at: NOW() }, "stale", "dead_holder"],
    ["7 equal token shields clock step", { pid: FOREIGN, start_token: FOREIGN_TOKEN, acquired_at: PREBOOT }, "in_progress"],
    ["7 differing token", { pid: FOREIGN, start_token: OLD_TOKEN, acquired_at: NOW() }, "stale", "start_token_differs"],
    ["8 same boot protects foreign", { pid: FOREIGN, boot_id: BOOT, acquired_at: PREBOOT }, "in_progress"],
    ["9 unknown boot preboot stamp", { pid: FOREIGN, acquired_at: PREBOOT }, "stale"],
    ["9 unknown boot recent stamp", { pid: FOREIGN, acquired_at: NOW() }, "in_progress"],
    ["10 recent empty", "", "in_progress"],
    ["11 fieldless", {}, "in_progress"],
    ["11 malformed", "malformed", "in_progress"],
  ];
  for (const [label, record, verdict, reason] of rows) {
    await f.plant(record);
    const result = await f.internals.decideStaleAuditLock(f.lock);
    expect(result.verdict, label).toBe(verdict);
    if (reason) expect(result.reason, label).toBe(reason);
  }
  await f.plant("");
  await fs.utimes(f.lock, new Date(PREBOOT), new Date(PREBOOT));
  expect((await f.internals.decideStaleAuditLock(f.lock)).verdict).toBe("stale");
  vi.mocked(tokens.readProcessStartToken).mockResolvedValue(undefined);
  await f.plant({ pid: FOREIGN, start_token: FOREIGN_TOKEN, acquired_at: PREBOOT });
  expect((await f.internals.decideStaleAuditLock(f.lock)).verdict).toBe("stale");
  await f.plant({ pid: FOREIGN, start_token: FOREIGN_TOKEN, acquired_at: NOW() });
  expect((await f.internals.decideStaleAuditLock(f.lock)).verdict).toBe("in_progress");
});

it("breaks own different token when neither boot id is available", async () => {
  const f = await fixture();
  vi.spyOn(f.internals, "currentLockBootId").mockReturnValue(undefined);
  vi.spyOn(tokens, "ownProcessStartToken").mockResolvedValue(OWN_TOKEN);
  await f.plant({ pid: process.pid, start_token: OLD_TOKEN, acquired_at: NOW() });
  expect(await f.internals.breakStaleAuditLock(f.lock)).toBe(true);
  await expect(fs.stat(f.lock)).rejects.toMatchObject({ code: "ENOENT" });
});

it("refuses malformed pids and unknown syscall errors with an unprovable-lock instruction", async () => {
  const f = await fixture();
  const kill = vi.spyOn(process, "kill").mockImplementation(() => { throw Object.assign(new Error("unknown"), { code: "EIO" }); });
  for (const pid of [0, -1, 1.5, "1", FOREIGN]) {
    await f.plant({ pid, acquired_at: NOW() });
    expect((await f.internals.decideStaleAuditLock(f.lock)).verdict).toBe("in_progress");
  }
  expect(kill).toHaveBeenCalledTimes(1);
  await f.plant({ pid: FOREIGN, acquired_at: NOW() });
  vi.spyOn(f.internals, "decideStaleAuditLock").mockImplementation(async () => { f.advance(5000); return { verdict: "in_progress" }; });
  await expect(f.internals.withAuditWriteLock(async () => undefined)).rejects.toThrow(/unprovable.*stop all/s);
});

it.each([OTHER_BOOT, BOOT])("row 0 protects an in-place aged inode across instances: %s boot", async boot => {
  const f = await fixture({ selfHeldStaleLockMs: 60000 });
  const b = new AuditLog(f.storage, f.key, f.settings) as unknown as Internals;
  vi.spyOn(b, "currentLockBootId").mockReturnValue(BOOT);
  vi.spyOn(tokens, "ownProcessStartToken").mockResolvedValue(OWN_TOKEN);
  await f.internals.withAuditWriteLock(async () => {
    await f.plant({ pid: process.pid, boot_id: boot, start_token: OWN_TOKEN, uptime_ms: uptime() * 1000 - 120000, acquired_at: PREBOOT });
    const original = await fs.readFile(f.lock, "utf8");
    const decide = b.decideStaleAuditLock.bind(b);
    vi.spyOn(b, "decideStaleAuditLock").mockImplementation(async (...args) => { const result = await decide(...args); if (result.verdict === "in_progress") f.advance(5000); return result; });
    await expect(b.withAuditWriteLock(async () => undefined)).rejects.toBeInstanceOf(AuditLockContentionError);
    expect(await fs.readFile(f.lock, "utf8")).toBe(original);
  });
});

it("release failure retires the registry but preserves the base self-held age threshold", async () => {
  const f = await fixture({ writeLockHoldDeadlineMs: 500, selfHeldStaleLockMs: 1000 });
  const release = vi.spyOn(f.internals, "unlinkIfSameInode").mockRejectedValueOnce(new Error("release failed"));
  await expect(f.internals.withAuditWriteLock(async () => undefined)).rejects.toThrow("release failed");
  release.mockRestore();
  const b = new AuditLog(f.storage, f.key, f.settings) as unknown as Internals;
  expect(await b.breakStaleAuditLock(f.lock)).toBe(false);
  const stamp = JSON.parse(await fs.readFile(f.lock, "utf8"));
  // Move the monotonic stamp past the one-second bound and tolerance, without moving wall time.
  await f.plant({ ...stamp, uptime_ms: uptime() * 1000 - 5000 });
  const stderr = vi.spyOn(console, "error").mockImplementation(() => {});
  expect(await b.breakStaleAuditLock(f.lock)).toBe(true);
  expect(stderr).toHaveBeenCalledWith(expect.stringContaining("self_held_stale_forced_release"));
  expect((b as unknown as AuditLog).getWriteLockRecoveryCount()).toBe(1);
});

it("a delayed breaker re-reads under the guard and preserves the winner's live hold", async () => {
  const f = await fixture();
  await f.plant({ pid: DEAD });
  const b = new AuditLog(f.storage, f.key, f.settings) as unknown as Internals;
  const decide = f.internals.decideStaleAuditLock.bind(f.internals);
  let resume!: () => void;
  let reached!: () => void;
  const paused = new Promise<void>(resolve => { reached = resolve; });
  const gate = new Promise<void>(resolve => { resume = resolve; });
  vi.spyOn(f.internals, "decideStaleAuditLock").mockImplementationOnce(async (...args) => { const result = await decide(...args); reached(); await gate; return result; });
  const c = f.internals.breakStaleAuditLock(f.lock);
  try {
    await paused;
    expect(await b.breakStaleAuditLock(f.lock)).toBe(true);
    await b.withAuditWriteLock(async () => {
      const before = await fs.readFile(f.lock);
      const ino = (await fs.stat(f.lock)).ino;
      resume();
      expect(await c).toBe(false);
      expect(await fs.readFile(f.lock)).toEqual(before);
      expect((await fs.stat(f.lock)).ino).toBe(ino);
    });
  } finally { resume(); await c; }
});

it.each([false, true])("witness d restores an out-of-protocol replacement; successor present=%s", async successor => {
  const f = await fixture(); await f.plant({ pid: DEAD });
  const realRename = fs.rename;
  let replacementIno = 0;
  vi.spyOn(fs, "rename").mockImplementationOnce(async (from, to) => {
    await fs.writeFile(join(f.dir, "replacement"), "replacement bytes");
    await realRename(join(f.dir, "replacement"), f.lock);
    replacementIno = (await fs.stat(f.lock)).ino;
    await realRename(from, to);
    if (successor) await fs.writeFile(f.lock, "successor");
  });
  const stderr = vi.spyOn(console, "error").mockImplementation(() => {});
  if (successor) {
    await expect(f.internals.breakStaleAuditLock(f.lock)).rejects.toBeInstanceOf(AuditLockRecoveryUnavailableError);
    expect(await fs.readFile(f.lock, "utf8")).toBe("successor");
    const tomb = (await fs.readdir(f.dir)).find(name => name.endsWith(".tomb"))!;
    expect(await fs.readFile(join(f.dir, tomb), "utf8")).toBe("replacement bytes");
    expect((await fs.stat(join(f.dir, tomb))).ino).toBe(replacementIno);
    expect(stderr).toHaveBeenCalledTimes(1);
  } else {
    expect(await f.internals.breakStaleAuditLock(f.lock)).toBe(false);
    expect(await fs.readFile(f.lock, "utf8")).toBe("replacement bytes");
    expect((await fs.stat(f.lock)).ino).toBe(replacementIno);
  }
});

it.each(["owner", "file", "symlink"])("normalizes obstructed guard root %s and keeps the planted lock", async shape => {
  const f = await fixture();
  let root = f.runtimeRoot;
  if (shape === "owner") root = "/usr/share";
  if (shape === "file") await fs.writeFile(root, "obstruction");
  if (shape === "symlink") await fs.symlink(f.root, root);
  const log = new AuditLog(f.storage, f.key, { ...f.settings, __testAuditGuardLockRoot: root }) as unknown as Internals;
  await f.plant({ pid: DEAD });
  const before = await fs.readFile(f.lock);
  const error = await log.breakStaleAuditLock(f.lock).catch(error => error);
  expect(error).toBeInstanceOf(AuditLockRecoveryUnavailableError);
  expect(error.message).toContain(root);
  expect(error.message).toContain("required owner uid");
  expect(error.cause).toBeDefined();
  expect(await fs.readFile(f.lock)).toEqual(before);
});

it("guard path never consults custody environment selection", async () => {
  vi.stubEnv("SANCTUARY_CUSTODY_LOCK_ROOT", "relative-obstruction");
  const f = await fixture();
  const resolver = vi.spyOn(locks, "resolveCustodyLockRoot");
  await f.plant({ pid: DEAD });
  expect(await f.internals.breakStaleAuditLock(f.lock)).toBe(true);
  expect(resolver).not.toHaveBeenCalled();
});

it("uses authority uid only for target custody, including root handback", async () => {
  const uid = process.getuid!();
  expect(auditGuardExpectedDirOwnerUid(uid, { uid: 9 })).toBe(uid);
  expect(auditGuardExpectedDirOwnerUid(0, { uid })).toBe(uid);
  expect(auditGuardExpectedDirOwnerUid(0)).toBe(0);
  const f = await fixture({ chainWriterRole: "root_daemon", __testAuditAuthorityUid: () => 0, createOwner: { uid, gid: process.getgid!() } });
  const daemon = createDaemonAuditLog(f.storage, f.key, f.settings) as unknown as Internals;
  const daemonDir = join(f.root, "s", "_audit-daemon");
  await fs.mkdir(daemonDir, { mode: 0o700 });
  const daemonLock = join(daemonDir, ".audit-write.lock");
  await fs.writeFile(daemonLock, JSON.stringify({ pid: DEAD }));
  await daemon.withAuditWriteLock(async () => { expect((await fs.stat(daemonLock)).uid).toBe(uid); });
  await expect(fs.stat(daemonLock)).rejects.toMatchObject({ code: "ENOENT" });
});

it("restores the claimed inode when tomb verification I/O fails", async () => {
  const f = await fixture(); await f.plant({ pid: DEAD });
  const before = await fs.readFile(f.lock);
  const ino = (await fs.stat(f.lock)).ino;
  const realOpen = fs.open;
  vi.spyOn(fs, "open").mockImplementation(async (...args) => {
    if (String(args[0]).endsWith(".tomb")) throw new Error("injected tomb read failure");
    return realOpen(...args);
  });
  await expect(f.internals.breakStaleAuditLock(f.lock)).rejects.toBeInstanceOf(AuditLockRecoveryUnavailableError);
  expect(await fs.readFile(f.lock)).toEqual(before);
  expect((await fs.stat(f.lock)).ino).toBe(ino);
});

// Must match sweepStaleAcquireTempsOnce in operational/audit-log.ts: 12 random bytes become 24 hex digits.
const tempName = (pid: number, n: number) => `.audit-write.lock.acquire.${pid}.${n.toString(36)}.${n.toString(16).padStart(24, "0")}.tmp`;
const tombName = (pid: number, n: number) => `.audit-write.lock.claim.${pid}.${n.toString(16).padStart(24, "0")}.tomb`;

it("sweeps dead fresh temps and tombs unread, keeps live old and malformed names", async () => {
  const f = await fixture();
  const dead = join(f.dir, tempName(DEAD, 1));
  const tomb = join(f.dir, tombName(DEAD, 2));
  const live = join(f.dir, tempName(process.pid, 3));
  const malformed = join(f.dir, ".audit-write.lock.acquire.424242.tmp");
  await fs.writeFile(dead, Buffer.alloc(1024 * 1024)); // One MiB must not be read by the sweep.
  await fs.writeFile(tomb, "fresh"); await fs.writeFile(live, "old"); await fs.writeFile(malformed, "kept");
  await fs.utimes(live, new Date(PREBOOT), new Date(PREBOOT));
  const read = vi.spyOn(fs, "readFile");
  const listing = vi.spyOn(fs, "readdir");
  await f.internals.withAuditWriteLock(async () => undefined);
  await f.internals.withAuditWriteLock(async () => undefined);
  expect(listing.mock.calls.filter(([path]) => path === f.dir)).toHaveLength(1);
  expect(read.mock.calls.some(([path]) => [dead, tomb, live].includes(String(path)))).toBe(false);
  await expect(fs.stat(dead)).rejects.toMatchObject({ code: "ENOENT" });
  await expect(fs.stat(tomb)).rejects.toMatchObject({ code: "ENOENT" });
  expect(await fs.readFile(live, "utf8")).toBe("old");
  expect(await fs.readFile(malformed, "utf8")).toBe("kept");
});

it("caps 70 dead temps at 64 attempts across instances and reports once", async () => {
  const f = await fixture();
  for (let n = 0; n < 70; n++) await fs.writeFile(join(f.dir, tempName(DEAD, n)), "");
  const stderr = vi.spyOn(console, "error").mockImplementation(() => {});
  await f.internals.withAuditWriteLock(async () => undefined);
  expect((await fs.readdir(f.dir)).filter(n => n.endsWith(".tmp"))).toHaveLength(6);
  const b = new AuditLog(f.storage, f.key, f.settings) as unknown as Internals;
  await b.withAuditWriteLock(async () => undefined);
  expect((await fs.readdir(f.dir)).filter(n => n.endsWith(".tmp"))).toHaveLength(6);
  expect(stderr).toHaveBeenCalledTimes(1);
  expect(stderr).toHaveBeenCalledWith(expect.stringContaining("64 unlink attempts"));
});

it("counts failed sweep unlinks against the shared attempt cap", async () => {
  const f = await fixture();
  for (let n = 0; n < 70; n++) await fs.writeFile(join(f.dir, tempName(DEAD, n)), "");
  const realUnlink = fs.unlink;
  let attempts = 0;
  vi.spyOn(fs, "unlink").mockImplementation(async path => {
    if (String(path).includes(`.acquire.${DEAD}.`)) { attempts++; throw new Error("unlink denied"); }
    return realUnlink(path);
  });
  vi.spyOn(console, "error").mockImplementation(() => {});
  await f.internals.withAuditWriteLock(async () => undefined);
  expect(attempts).toBe(64);
  expect((await fs.readdir(f.dir)).filter(n => n.endsWith(".tmp"))).toHaveLength(70);
});

it.each(["readOnly", "unauthorized"])("%s instance never lists or sweeps acquire temps", async shape => {
  const f = await fixture(shape === "readOnly" ? { readOnly: true } : { __testAuditAuthorityUid: () => 0 });
  const temp = join(f.dir, tempName(DEAD, 1)); await fs.writeFile(temp, "keep");
  const list = vi.spyOn(fs, "readdir"); const unlink = vi.spyOn(fs, "unlink");
  await expect(f.internals.withAuditWriteLock(async () => undefined)).rejects.toThrow();
  expect(list).not.toHaveBeenCalled(); expect(unlink).not.toHaveBeenCalled();
  expect(await fs.readFile(temp, "utf8")).toBe("keep");
});


it("readable tokens remain independent proof when the liveness syscall is unknown", async () => {
  const f = await fixture();
  vi.spyOn(f.internals, "currentLockBootId").mockReturnValue(undefined);
  vi.spyOn(process, "kill").mockImplementation(() => { throw Object.assign(new Error("probe unavailable"), { code: "EIO" }); });
  vi.spyOn(tokens, "readProcessStartToken").mockResolvedValue(OWN_TOKEN);
  await f.plant({ pid: FOREIGN, start_token: OWN_TOKEN, acquired_at: PREBOOT });
  const before = await fs.readFile(f.lock);
  expect(await f.internals.breakStaleAuditLock(f.lock)).toBe(false);
  expect(await fs.readFile(f.lock)).toEqual(before);
  await f.plant({ pid: FOREIGN, start_token: OLD_TOKEN, acquired_at: NOW() });
  expect(await f.internals.breakStaleAuditLock(f.lock)).toBe(true);
});
