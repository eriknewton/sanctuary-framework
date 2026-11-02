import { spawn, type ChildProcess } from "node:child_process";
import { createRequire } from "node:module";
import { once } from "node:events";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { AuditLog } from "../../src/operational/audit-log.js";
import { FilesystemStorage } from "../../src/storage/filesystem.js";
import { MEASURE_CONFIG, MEASURE_MASTER_KEY, prepopulateAudit } from "../../scripts/measure-audit-append.js";

const children: ChildProcess[] = [];
let root: string;
beforeEach(async () => { root = await mkdtemp(join(tmpdir(), "two-pid-tail-")); vi.stubEnv("HOME", root); });
async function reap(child: ChildProcess) {
  if (child.exitCode === null && child.signalCode === null) {
    const exited = once(child, "exit"); child.kill("SIGKILL"); await exited;
  }
}
afterEach(async () => {
  await Promise.all(children.splice(0).map(reap));
  vi.unstubAllEnvs(); await rm(root, { recursive: true, force: true });
});
function start(path: string, role: string, schedule: string) {
  const child = spawn(process.execPath, ["--import", createRequire(import.meta.url).resolve("tsx"),
    fileURLToPath(new URL("./audit-log-two-process-tail-child.ts", import.meta.url)), path, role, schedule], {
    stdio: ["ignore", "ignore", "pipe", "ipc"], env: { ...process.env, HOME: root, SANCTUARY_STORAGE_PATH: path },
  });
  children.push(child); return child;
}
function message(child: ChildProcess, field: string): Promise<any> {
  return new Promise((resolve, reject) => {
    let stderr = ""; child.stderr?.on("data", (data) => { stderr += String(data); });
    const exit = (code: number | null) => reject(new Error(`child exited ${code}: ${stderr}`));
    const receive = (value: any) => {
      if (value.error) reject(new Error(value.error));
      if (!value[field]) return;
      child.off("message", receive); child.off("exit", exit); resolve(value);
    };
    child.on("message", receive); child.once("exit", exit); child.once("error", reject);
  });
}
for (const schedule of ["interrupted", "regressed"]) {
  it(`discovers B's durable tail after its ${schedule} anchor and PID death`, async () => {
    const path = join(root, "state"); await prepopulateAudit(path, 1);
    const a = start(path, "A", schedule); await message(a, "ready");
    const b = start(path, "B", schedule); await message(b, "durable");
    expect(a.pid).not.toBe(b.pid); await reap(b);
    const appended = message(a, "appended"); a.send({ append: true });
    expect(await appended).toMatchObject({ sequence: 3, auditListings: 1 });
    const reader = new AuditLog(new FilesystemStorage(path), MEASURE_MASTER_KEY, MEASURE_CONFIG);
    expect((await reader.query({ limit: 10 })).integrity_findings).toEqual([]);
    expect(reader.currentInMemorySequence()).toBe(3);
  });
}
