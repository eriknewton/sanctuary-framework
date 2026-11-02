import { spawn, type ChildProcess } from "node:child_process";
import { once } from "node:events";
import { mkdtemp, readFile, rm, stat, writeFile } from "node:fs/promises";
import { tmpdir, uptime } from "node:os";
import { join } from "node:path";
import { afterEach, expect, it, vi } from "vitest";
import { AuditLog, AuditLockContentionError } from "../../src/operational/audit-log.js";
import { FilesystemStorage } from "../../src/storage/filesystem.js";
import { generateRandomKey } from "../../src/core/random.js";

const HOUR_MS = 60 * 60 * 1000;
// Production acquisition budget is five seconds; the sentinel allows three seconds of scheduling slack.
const SENTINEL_MS = 8000;
let root: string | undefined;
let child: ChildProcess | undefined;
let pending: Promise<unknown> | undefined;
let sentinel: ReturnType<typeof setTimeout> | undefined;
const entry = (operation: string) => ({ layer: "l1" as const, operation, identity_id: "acceptance", result: "success" as const, details: {} });

afterEach(async () => {
  vi.useRealTimers(); vi.unstubAllEnvs();
  if (sentinel) clearTimeout(sentinel);
  if (child && child.exitCode === null && child.signalCode === null) {
    const exited = once(child, "exit");
    child.kill("SIGKILL");
    await exited;
  }
  await pending;
  if (root) await rm(root, { recursive: true, force: true });
  child = undefined;
  pending = undefined;
});

async function fixture() {
  root = await mkdtemp(join(tmpdir(), "audit-accept-")); vi.stubEnv("HOME", root);
  const log = new AuditLog(new FilesystemStorage(join(root, "state")), generateRandomKey(), { integrityMode: "lenient" });
  await log.appendCritical(entry("seed"));
  child = spawn(process.execPath, ["-e", "process.stdin.resume()"], { stdio: ["pipe", "ignore", "ignore"] });
  await once(child, "spawn");
  const pid = child.pid!;
  const proc = await readFile(`/proc/${pid}/stat`, "utf8");
  // Field 3 begins after the last ')'; field 22 is the twentieth token there.
  const start_token = proc.slice(proc.lastIndexOf(")") + 1).trim().split(/\s+/)[19];
  expect(start_token).toMatch(/^\d+$/);
  const boot_id = (await readFile("/proc/sys/kernel/random/boot_id", "utf8")).trim();
  return { log, lock: join(root, "state", "_audit", ".audit-write.lock"), pid, start_token, boot_id };
}

it.runIf(process.platform === "linux")("R3: a lock this build writes survives a wall-clock step", async () => {
  const { log, lock, pid, start_token } = await fixture();
  const planted = JSON.stringify({ pid, acquired_at: new Date(Date.now() - uptime() * 1000 - HOUR_MS).toISOString(), uptime_ms: uptime() * 1000, start_token });
  await writeFile(lock, planted);
  const before = await stat(lock);
  pending = log.appendCritical(entry("clock-step")).then(() => undefined, error => error);
  const outcome = await pending;
  expect(await readFile(lock, "utf8").catch(() => null), "planted bytes survive").toBe(planted);
  expect((await stat(lock)).ino).toBe(before.ino);
  expect(outcome).toBeInstanceOf(AuditLockContentionError);
});

it.runIf(process.platform === "linux")("R4: the acquisition budget ignores the wall clock", async () => {
  const { log, lock, pid, start_token, boot_id } = await fixture();
  await writeFile(lock, JSON.stringify({ pid, acquired_at: new Date().toISOString(), uptime_ms: uptime() * 1000, start_token, boot_id }));
  vi.useFakeTimers({ toFake: ["Date"] });
  pending = log.appendCritical(entry("frozen-date")).then(() => undefined, error => error);
  const outcome = await Promise.race([pending, new Promise(resolve => { sentinel = setTimeout(() => resolve("sentinel"), SENTINEL_MS); })]);
  expect(outcome, "contention before the real sentinel").toBeInstanceOf(AuditLockContentionError);
});
