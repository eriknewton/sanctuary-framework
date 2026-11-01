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
  try {
    expect((await reader.query({ limit: 1 })).integrity_findings).toEqual([]);
  } catch (error) {
    expect((error as { findings?: unknown }).findings, "fresh strict reader findings").toEqual([]);
    throw error;
  }
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
  // Virtual elapsed I/O time avoids a full-budget wall wait without changing timers.
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

async function exactRetention(raw: FilesystemStorage, log: AuditLog) {
  const metas = await raw.list("_audit");
  expect((log as any).bytesProvenance).toBe("seeded");
  expect((log as any).retainedCountExpected).toBe(metas.length);
  expect((log as any).retainedBytesEstimate).toBe(metas.reduce((sum, meta) => sum + meta.size_bytes, 0));
}

it("repairs a step-three throwing delete on the very next append below the cap", async () => {
  const { raw, log } = await setup(); const remove = raw.delete.bind(raw); let calls = 0;
  let survivor = "";
  vi.spyOn(raw, "delete").mockImplementation(async (...args) => {
    if (++calls === 3) { survivor = args[1]; throw new Error("step three delete fault"); }
    return remove(...args);
  });
  await log.appendCritical(measureEntry(CAP));
  expect((log as any).bytesProvenance).toBe("unknown");
  expect(await belowCut(raw)).toEqual([3]);
  expect((log as any).unconfirmedPruneCutKey).toContain("00000000000000000004");
  await log.appendCritical(measureEntry(CAP + 1));
  // Keep this first: ignoring the recorded cut must fail with rotation_anchor_invalid.
  await strict(raw);
  expect(await raw.exists("_audit", survivor)).toBe(false);
  expect(await belowCut(raw)).toEqual([]);
  expect((log as any).unconfirmedPruneCutKey).toBeNull();
  await exactRetention(raw, log);
});

it("repairs a step-three anchor that lands after the hold deadline on the next append", async () => {
  // A one-second hold allows three fast steps before the deliberately blocked anchor.
  const { raw, log } = await setup(1_000);
  const write = raw.writeDurable.bind(raw); const entered = gate(); const release = gate(); const finished = gate();
  let anchors = 0;
  vi.spyOn(raw, "writeDurable").mockImplementation(async (...args) => {
    if (args[0] === "_audit_checkpoints" && args[1] === "__rotation_anchor" && ++anchors === 3) {
      entered.release(); await release.wait;
    }
    return write(...args);
  });
  const withLock = (log as any).withAuditWriteLock.bind(log);
  vi.spyOn(log as any, "withAuditWriteLock").mockImplementation((callback: any) => withLock(async (signal: unknown) => {
    try { return await callback(signal); }
    finally { if (anchors === 3) finished.release(); }
  }));
  const append = log.appendCritical(measureEntry(CAP));
  try {
    await Promise.race([entered.wait, append.then(() => { throw new Error("third anchor not reached"); })]);
    await append;
    expect((log as any).bytesProvenance).toBe("unknown");
    expect((log as any).unconfirmedPruneCutKey).not.toBeNull();
  } finally {
    release.release();
    if (anchors === 3) await finished.wait;
  }
  expect(await belowCut(raw)).toEqual([3]);
  await log.appendCritical(measureEntry(CAP + 1));
  await strict(raw);
  expect(await belowCut(raw)).toEqual([]);
  expect((log as any).unconfirmedPruneCutKey).toBeNull();
  await exactRetention(raw, log);
});

it("clears the recorded cut after a foreign prune moves past its key", async () => {
  const { raw, log } = await setup();
  // Warm the foreign writer before the fault; five entries below the cap moves its cut past ours.
  const foreign = new AuditLog(raw, MEASURE_MASTER_KEY, { ...MEASURE_CONFIG, maxEntries: CAP - 5 });
  await foreign.query({ limit: 1 });
  const remove = raw.delete.bind(raw); let calls = 0;
  const fault = vi.spyOn(raw, "delete").mockImplementation(async (...args) => {
    if (++calls === 3) throw new Error("step three delete fault");
    return remove(...args);
  });
  await log.appendCritical(measureEntry(CAP));
  const cut = (log as any).unconfirmedPruneCutKey;
  expect(cut).not.toBeNull(); fault.mockRestore();
  await foreign.appendCritical(measureEntry(CAP + 1));
  expect(await raw.exists("_audit", cut)).toBe(false);
  await log.appendCritical(measureEntry(CAP + 2));
  expect((log as any).unconfirmedPruneCutKey).toBeNull();
  await exactRetention(raw, log);
  await strict(raw);
});

it("limits a configured 300 ms hold episode to 100 ms plus one step", async () => {
  const { raw, log } = await setup(300);
  const remove = raw.delete.bind(raw); const realNow = performance.now.bind(performance);
  // Two sixty-millisecond steps cross the one-third budget, so no third step may start.
  const stepMs = 60; const budgetMs = 100; let elapsed = 0; let steps = 0;
  vi.spyOn(performance, "now").mockImplementation(() => realNow() + elapsed);
  vi.spyOn(raw, "delete").mockImplementation(async (...args) => {
    const result = await remove(...args); elapsed += stepMs; steps++; return result;
  });
  await log.appendCritical(measureEntry(CAP));
  expect(steps).toBeGreaterThan(0);
  expect(elapsed, "configured episode budget plus one step").toBeLessThanOrEqual(budgetMs + stepMs);
  expect((log as any).unconfirmedPruneCutKey).toBeNull();
  await exactRetention(raw, log);
  expect((log as any).retainedCountExpected).toBeLessThanOrEqual(CAP);
  await strict(raw);
});

it("clears a step-three already-gone false delete on the next append", async () => {
  const { raw, log } = await setup(); const remove = raw.delete.bind(raw); let calls = 0;
  vi.spyOn(raw, "delete").mockImplementation(async (...args) => {
    const deleted = await remove(...args);
    return ++calls === 3 ? false : deleted;
  });
  await log.appendCritical(measureEntry(CAP));
  expect((log as any).bytesProvenance).toBe("unknown");
  expect((log as any).unconfirmedPruneCutKey).not.toBeNull();
  expect(await belowCut(raw)).toEqual([]);
  await log.appendCritical(measureEntry(CAP + 1));
  await strict(raw);
  await exactRetention(raw, log);
  expect((log as any).unconfirmedPruneCutKey, "already-completed cut cleared by next recount").toBeNull();
});

async function warmWritersWithSurvivor(cap: number, faultStep: number, mode: "throw" | "false") {
  const path = join(root, "state"); await prepopulateAudit(path, cap);
  const raw = new FilesystemStorage(path);
  const config = { ...MEASURE_CONFIG, maxEntries: cap };
  const writerA = new AuditLog(raw, MEASURE_MASTER_KEY, config);
  const writerB = new AuditLog(raw, MEASURE_MASTER_KEY, config);
  await writerA.query({ limit: 1 }); await writerB.query({ limit: 1 });
  const remove = raw.delete.bind(raw); let calls = 0; let survivor = "";
  const fault = vi.spyOn(raw, "delete").mockImplementation(async (...args) => {
    if (args[0] === "_audit" && ++calls === faultStep) {
      survivor = args[1];
      if (mode === "throw") throw new Error("scheduled delete fault");
      return false;
    }
    return remove(...args);
  });
  await writerA.appendCritical(measureEntry(cap));
  expect(calls).toBe(faultStep);
  expect(await belowCut(raw)).toEqual([faultStep]);
  expect(await raw.exists("_audit", survivor)).toBe(true);
  fault.mockRestore();
  return { raw, writerB, survivor };
}

it.each([
  { cap: CAP, faultStep: 3, mode: "throw" as const },
  { cap: CAP, faultStep: 3, mode: "false" as const },
  // Two thousand entries give a twenty-entry margin, allowing the tenth delete.
  { cap: 2_000, faultStep: 10, mode: "throw" as const },
])("any writer repairs the durable cut: cap $cap, step $faultStep, $mode", async ({ cap, faultStep, mode }) => {
  const { raw, writerB, survivor } = await warmWritersWithSurvivor(cap, faultStep, mode);
  await writerB.appendCritical(measureEntry(cap + 1));
  await strict(raw);
  expect(await raw.exists("_audit", survivor)).toBe(false);
  expect(await belowCut(raw)).toEqual([]);
  // Prepopulation starts at one; A and B each allocate the next sequence.
  expect(writerB.currentInMemorySequence()).toBe(cap + 2);
  await exactRetention(raw, writerB);
});

it("does not raise the count cut for an invalid durable anchor", async () => {
  const { raw, writerB, survivor } = await warmWritersWithSurvivor(CAP, 3, "throw");
  const anchorBytes = (await raw.read("_audit_checkpoints", "__rotation_anchor"))!;
  const anchor = JSON.parse(new TextDecoder().decode(anchorBytes));
  anchor.mac = (anchor.mac[0] === "A" ? "B" : "A") + anchor.mac.slice(1);
  const corruptBytes = new TextEncoder().encode(JSON.stringify(anchor));
  await raw.writeDurable("_audit_checkpoints", "__rotation_anchor", corruptBytes);
  const remove = vi.spyOn(raw, "delete");
  const read = vi.spyOn(raw, "read");
  await writerB.appendCritical(measureEntry(CAP + 1));
  expect(writerB.currentInMemorySequence()).toBe(CAP + 2);
  expect(read).toHaveBeenCalledWith("_audit_checkpoints", "__rotation_anchor");
  // Two completed deletes offset the two appends, so the count rule requires none.
  expect(await raw.list("_audit")).toHaveLength(CAP);
  expect(remove).not.toHaveBeenCalled();
  expect(await raw.exists("_audit", survivor)).toBe(true);
  expect(await raw.read("_audit_checkpoints", "__rotation_anchor")).toEqual(corruptBytes);
  const reader = new AuditLog(raw, MEASURE_MASTER_KEY, MEASURE_CONFIG);
  await expect(reader.query({ limit: 1 })).rejects.toMatchObject({ name: "AuditIntegrityError",
    findings: [expect.objectContaining({ kind: "rotation_anchor_invalid" })] });
});

it("leaves a never-rotated store below the cap unchanged when the anchor is absent", async () => {
  const path = join(root, "state");
  // One initial entry and two appends stay strictly below the small cap.
  const initialCount = 1; const cap = 5;
  await prepopulateAudit(path, initialCount);
  const raw = new FilesystemStorage(path);
  const config = { ...MEASURE_CONFIG, maxEntries: cap };
  const writerA = new AuditLog(raw, MEASURE_MASTER_KEY, config);
  const writerB = new AuditLog(raw, MEASURE_MASTER_KEY, config);
  await writerA.query({ limit: 1 }); await writerB.query({ limit: 1 });
  await writerA.appendCritical(measureEntry(initialCount));
  const originalKeys = (await raw.list("_audit")).map((meta) => meta.key);
  const remove = vi.spyOn(raw, "delete");
  const read = vi.spyOn(raw, "read");
  await writerB.appendCritical(measureEntry(initialCount + 1));
  expect(writerB.currentInMemorySequence()).toBe(initialCount + 2);
  expect(read).toHaveBeenCalledWith("_audit_checkpoints", "__rotation_anchor");
  expect(remove).not.toHaveBeenCalled();
  const keys = (await raw.list("_audit")).map((meta) => meta.key);
  expect(keys).toHaveLength(initialCount + 2);
  expect(keys).toEqual(expect.arrayContaining(originalKeys));
  expect(await raw.read("_audit_checkpoints", "__rotation_anchor")).toBeNull();
  await strict(raw);
  await exactRetention(raw, writerB);
});
