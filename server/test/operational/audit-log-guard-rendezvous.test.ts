import { spawn, type ChildProcess } from "node:child_process";
import { once } from "node:events";
import { mkdtemp, mkdir, rm, writeFile, readFile, readdir } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { fileURLToPath } from "node:url";
import { afterEach, expect, it, vi } from "vitest";
import { AuditLog, AuditLockContentionError } from "../../src/operational/audit-log.js";
import { FilesystemStorage } from "../../src/storage/filesystem.js";
import * as locks from "../../src/storage/cross-process-lock.js";
vi.mock("../../src/storage/cross-process-lock.js", async original => ({ ...await original<typeof import("../../src/storage/cross-process-lock.js")>() }));
const children: ChildProcess[] = [];
const roots: string[] = [];
afterEach(async () => {
  vi.useRealTimers(); vi.restoreAllMocks(); vi.unstubAllEnvs();
  for (const child of children.splice(0)) {
    if (child.exitCode === null && child.signalCode === null) { const exited = once(child, "exit"); child.kill("SIGKILL"); await exited; }
  }
  for (const root of roots.splice(0)) await rm(root, { recursive: true, force: true });
});
async function fixture() {
  const root = await mkdtemp(join(process.platform === "darwin" ? "/private/tmp" : tmpdir(), "agr-")); roots.push(root); vi.stubEnv("HOME", root);
  const dir = join(root, "s", "_audit"); await mkdir(dir, { recursive: true, mode: 0o700 });
  return { root, dir };
}
function start(directory: string, home: string, custodyOverride: string, runtimeRoot?: string) {
  const child = spawn(process.execPath, ["--import", "tsx", fileURLToPath(new URL("./audit-log-guard-rendezvous-child.ts", import.meta.url)), directory, ...(runtimeRoot ? [runtimeRoot] : [])], {
    env: { ...process.env, HOME: home, SANCTUARY_CUSTODY_LOCK_ROOT: custodyOverride }, stdio: ["ignore", "pipe", "pipe", "ipc"],
  });
  children.push(child);
  const messages: Array<{ state: string; root?: string }> = [];
  child.on("message", message => messages.push(message as { state: string }));
  let stderr = ""; child.stderr!.on("data", data => { stderr += data; });
  const wait = async (state: string) => {
    if (messages.some(m => m.state === state)) return messages.find(m => m.state === state)!;
    return new Promise<{ state: string; root?: string }>((resolve, reject) => {
      // A 10-second harness bound detects a failed child; it is not an acquisition budget.
      const timer = setTimeout(() => { cleanup(); reject(new Error(`child missing ${state}: ${stderr}`)); }, 10_000);
      const message = (m: any) => { if (m.state === state) { cleanup(); resolve(m); } };
      const exit = () => { cleanup(); reject(new Error(`child exited before ${state}: ${stderr}`)); };
      function cleanup() { clearTimeout(timer); child.off("message", message); child.off("exit", exit); }
      child.on("message", message); child.once("exit", exit);
    });
  };
  return { child, messages, wait };
}
it.runIf(process.platform === "linux" && process.getuid?.() === 1001)("two children ignore different valid and relative custody overrides at the real uid rendezvous", async () => {
  expect(process.getuid!()).toBe(1001);
  const f = await fixture();
  const a = start(f.dir, f.root, join(f.root, "valid"));
  const held = await a.wait("acquired");
  expect(held.root).toBe("/run/user/1001/sanctuary-audit-guard");
  const b = start(f.dir, f.root, "relative");
  await b.wait("contended");
  expect(b.messages.some(m => m.state === "acquired")).toBe(false);
  a.child.send("release"); await a.wait("released");
  expect((await b.wait("acquired")).root).toBe(held.root);
  b.child.send("release"); await b.wait("released");
  expect(await readdir(f.dir)).toEqual([]); // scaffold:false creates no target file.
});
it("hands the remaining monotonic budget to a child-held guard despite wall-clock steps", async () => {
  const f = await fixture(); const runtimeRoot = join(f.root, "g");
  const holder = start(f.dir, f.root, "relative", runtimeRoot); await holder.wait("acquired");
  const path = join(f.dir, ".audit-write.lock");
  const bytes = JSON.stringify({ pid: 2147483647 }); // Outside the Linux allocatable pid range.
  await writeFile(path, bytes);
  let clock = 0;
  const log = new AuditLog(new FilesystemStorage(join(f.root, "s")), Buffer.alloc(32, 1), {
    __testAuditGuardLockRoot: runtimeRoot, __testMonotonicNow: () => clock,
  });
  const internal = log as unknown as { withAuditWriteLock(op: () => Promise<void>): Promise<void>; decideStaleAuditLock(...args: any[]): Promise<any> };
  const decide = internal.decideStaleAuditLock.bind(internal);
  vi.spyOn(internal, "decideStaleAuditLock").mockImplementationOnce(async (...args) => { const result = await decide(...args); clock = 4700; return result; });
  vi.useFakeTimers({ toFake: ["Date"] });
  const pathLock = locks.withPathLock;
  let entered = false; let contentions = 0;
  vi.spyOn(locks, "withPathLock").mockImplementation((dir, name, op, options) => {
    expect(options?.monotonicDeadlineMs).toBe(5000);
    expect(options?.__testMonotonicNow?.()).toBe(4700);
    return pathLock(dir, name, async lease => { entered = true; return op(lease); }, {
      ...options, retryMs: 1,
      onContended: () => { clock += 100; contentions++; vi.setSystemTime(contentions % 2 ? 0 : 4_000_000_000_000); },
    });
  });
  await expect(internal.withAuditWriteLock(async () => { entered = true; })).rejects.toBeInstanceOf(AuditLockContentionError);
  expect(clock).toBe(5000); expect(contentions).toBe(3); expect(entered).toBe(false);
  expect(await readFile(path, "utf8")).toBe(bytes);
  holder.child.send("release"); await holder.wait("released");
  expect(entered).toBe(false); // The settled acquisition has no detached promise to enter later.
});
