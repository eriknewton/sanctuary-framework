import { spawn, type ChildProcess } from "node:child_process";
import { once } from "node:events";
import { createRequire } from "node:module";
import { fileURLToPath } from "node:url";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { AuditLog, AUDIT_PRUNE_EPISODE_BUDGET_MS } from "../../src/operational/audit-log.js";
import { FilesystemStorage } from "../../src/storage/filesystem.js";
import { MEASURE_CONFIG, MEASURE_MASTER_KEY, measureEntry, prepopulateAudit } from "../../scripts/measure-audit-append.js";

// Two hundred entries give a two-entry margin and three steps per full episode.
const CAP = 200;
let root: string;
const children: ChildProcess[] = [];
beforeEach(async () => { root = await mkdtemp(join(tmpdir(), "stepped-prune-")); vi.stubEnv("HOME", root); });
async function reap(child: ChildProcess) {
  if (child.exitCode === null && child.signalCode === null) {
    const exited = once(child, "exit"); child.kill("SIGKILL"); await exited;
  }
}
afterEach(async () => {
  await Promise.all(children.splice(0).map(reap));
  vi.restoreAllMocks(); vi.unstubAllEnvs(); await rm(root, { recursive: true, force: true });
});
function gate() { let release!: () => void; const wait = new Promise<void>((resolve) => { release = resolve; }); return { wait, release }; }
async function setup(deadline?: number) {
  const path = join(root, "state"); await prepopulateAudit(path, CAP);
  const raw = new FilesystemStorage(path);
  const log = new AuditLog(raw, MEASURE_MASTER_KEY, { ...MEASURE_CONFIG, maxEntries: CAP,
    ...(deadline ? { writeLockHoldDeadlineMs: deadline } : {}) });
  await log.query({ limit: 1 }); return { path, raw, log };
}
async function strict(raw: FilesystemStorage) {
  const reader = new AuditLog(raw, MEASURE_MASTER_KEY, MEASURE_CONFIG);
  expect((await reader.query({ limit: 1 })).integrity_findings).toEqual([]);
}
async function belowCut(raw: FilesystemStorage) {
  const anchor = JSON.parse(new TextDecoder().decode((await raw.read("_audit_checkpoints", "__rotation_anchor"))!));
  const sequences = ((await raw.list("_audit")).map((meta) => meta.key)).map((key) => Number(key.split("-")[1]));
  return sequences.filter((sequence) => sequence < anchor.data.base_sequence);
}

it("stops a hold deadline between prune steps before publishing the next anchor", async () => {
  // The short real hold expires while the second step reads its prospective base.
  const { raw, log } = await setup(200);
  const read = raw.read.bind(raw); const hold = gate(); const entered = gate(); const settled = gate();
  let deletes = 0; let delay = true;
  const remove = raw.delete.bind(raw);
  vi.spyOn(raw, "delete").mockImplementation(async (...args) => { const ok = await remove(...args); deletes++; return ok; });
  vi.spyOn(raw, "read").mockImplementation(async (...args) => {
    const value = await read(...args);
    if (delay && deletes === 1 && args[0] === "_audit") {
      delay = false; entered.release(); await hold.wait; settled.release();
    }
    return value;
  });
  const callbackFinished = gate();
  const withLock = (log as any).withAuditWriteLock.bind(log);
  vi.spyOn(log as any, "withAuditWriteLock").mockImplementation((callback: any) => withLock(async (signal: unknown) => {
    try { return await callback(signal); }
    finally { if (deletes > 0) callbackFinished.release(); }
  }));
  const append = log.appendCritical(measureEntry(CAP));
  try {
    await Promise.race([entered.wait, append.then(() => { throw new Error("prune did not reach the second step"); })]);
    await append;
  } finally {
    hold.release();
    if (!delay) { await settled.wait; await callbackFinished.wait; }
  }
  expect(deletes).toBe(1);
  expect(await belowCut(raw)).toEqual([]);
  await strict(raw);
});

it("keeps the base one-delete window when delete throws at step two", async () => {
  const { raw, log } = await setup(); const remove = raw.delete.bind(raw); let calls = 0;
  vi.spyOn(raw, "delete").mockImplementation(async (...args) => {
    if (++calls === 2) throw new Error("step two delete fault");
    return remove(...args);
  });
  await log.appendCritical(measureEntry(CAP));
  expect((log as any).bytesProvenance).toBe("unknown");
  expect(await belowCut(raw)).toHaveLength(1);
  // As at the base's anchor-before-delete window, a surviving old base is hard.
  const reader = new AuditLog(raw, MEASURE_MASTER_KEY, MEASURE_CONFIG);
  await expect(reader.query({ limit: 1 })).rejects.toMatchObject({ name: "AuditIntegrityError",
    findings: expect.arrayContaining([expect.objectContaining({ kind: "rotation_anchor_invalid" })]) });
});

it("leaves a clean cut and unknown provenance when a foreign delete returns false", async () => {
  const { raw, log } = await setup(); const remove = raw.delete.bind(raw); let calls = 0;
  vi.spyOn(raw, "delete").mockImplementation(async (...args) => {
    const result = await remove(...args);
    return ++calls === 2 ? false : result;
  });
  await log.appendCritical(measureEntry(CAP));
  expect((log as any).bytesProvenance).toBe("unknown");
  expect(await belowCut(raw)).toEqual([]);
  await strict(raw);
});

it("seeds exact survivors at the episode budget and later appends reach the low target", async () => {
  const { raw, log } = await setup(); const remove = raw.delete.bind(raw);
  const realNow = performance.now.bind(performance); let offset = 0; let slow = true;
  // Virtual elapsed I/O time avoids a ten-second wall wait without changing timers.
  vi.spyOn(performance, "now").mockImplementation(() => realNow() + offset);
  vi.spyOn(raw, "delete").mockImplementation(async (...args) => {
    const result = await remove(...args); if (slow) offset += AUDIT_PRUNE_EPISODE_BUDGET_MS; return result;
  });
  await log.appendCritical(measureEntry(CAP));
  expect((log as any).bytesProvenance).toBe("seeded");
  expect((log as any).retainedCountExpected).toBe(CAP);
  const metas = await raw.list("_audit");
  expect((log as any).retainedBytesEstimate).toBe(metas.reduce((sum, meta) => sum + meta.size_bytes, 0));
  await strict(raw);
  slow = false; await log.appendCritical(measureEntry(CAP + 1));
  expect(((await raw.list("_audit")).map((meta) => meta.key)).length).toBe(CAP - 2);
  await strict(raw);
});

it("reloads clean after SIGKILL between steps and a fresh writer finishes pruning", async () => {
  const { path, raw } = await setup();
  const child = spawn(process.execPath, ["--import", createRequire(import.meta.url).resolve("tsx"),
    fileURLToPath(new URL("./audit-log-stepped-prune-child.ts", import.meta.url)), path, String(CAP)], {
    stdio: ["ignore", "ignore", "pipe", "ipc"], env: { ...process.env, HOME: root, SANCTUARY_STORAGE_PATH: path },
  });
  children.push(child);
  await new Promise<void>((resolve, reject) => {
    let stderr = ""; child.stderr?.on("data", (data) => { stderr += String(data); });
    child.once("error", reject); child.once("exit", () => reject(new Error(stderr || "child exited before step")));
    child.on("message", (value: any) => { if (value.betweenSteps) resolve(); if (value.error) reject(new Error(value.error)); });
  });
  await reap(child);
  expect(await belowCut(raw)).toEqual([]);
  await strict(raw);
  const fresh = new AuditLog(raw, MEASURE_MASTER_KEY, { ...MEASURE_CONFIG, maxEntries: CAP });
  await fresh.appendCritical(measureEntry(CAP + 1));
  expect(((await raw.list("_audit")).map((meta) => meta.key)).length).toBe(CAP - 2);
  await strict(raw);
});
