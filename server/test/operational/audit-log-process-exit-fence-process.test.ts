/** Real process exits preserve the daemon chain across publication cuts. Job 996. */
import { spawn, type ChildProcess } from "node:child_process";
import { mkdir, mkdtemp, readFile, rm, stat } from "node:fs/promises";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { afterEach, beforeEach, describe, expect, it } from "vitest";

const modulePath = "../../src/cli/castle-wall-full-agent-state.js";
const api = await import(modulePath).catch(() => null) as typeof import("../../src/cli/castle-wall-full-agent-state.js") | null;
beforeEach(() => expect(api, "daemon fence action is shipped").not.toBeNull());
const fixture = fileURLToPath(new URL("../fixtures/audit-exit-fence/child.ts", import.meta.url));
const DEADLINE_MS = 1000; // must match DEADLINE_MS in test/fixtures/audit-exit-fence/child.ts.
const EXIT_ALLOWANCE_MS = 2000; // Required upper allowance beyond the fence deadline.
const IMPORT_BUDGET_MS = 10 * DEADLINE_MS;
const OUTPUT_CAP_BYTES = 16 * 1024; // 16 KiB per fixture output stream.
type End = { code: number | null; signal: NodeJS.Signals | null };
const roots: string[] = [];
const owned: Array<{ child: ChildProcess; done: Promise<End> }> = [];
let serial = 0;
async function bounded<T>(promise: Promise<T>, ms: number): Promise<T | "timeout"> {
  let timer: ReturnType<typeof setTimeout> | undefined;
  try { return await Promise.race([promise, new Promise<"timeout">(resolve => { timer = setTimeout(() => resolve("timeout"), ms); })]); }
  finally { if (timer) clearTimeout(timer); }
}
afterEach(async () => {
  try {
    for (const { child, done } of owned.splice(0)) {
      if (child.exitCode === null && child.signalCode === null && child.pid) {
        try { process.kill(-child.pid, "SIGKILL"); } catch { child.kill("SIGKILL"); }
      }
      await done;
    }
  } finally { for (const root of roots.splice(0)) await rm(root, { recursive: true, force: true }); }
});
async function root() {
  const result = await mkdtemp("/tmp/j996-process-"); roots.push(result); return result;
}
async function start(root: string, mode: string) {
  const home = join(root, `home-${serial++}`); await mkdir(home, { mode: 0o700 });
  const child = spawn(process.execPath, ["--import", "tsx", fixture, root, mode], {
    detached: true,
    env: { ...process.env, HOME: home, TMPDIR: "/tmp", VITEST: "true", SANCTUARY_STORAGE_PATH: root, SANCTUARY_NO_UPDATE_CHECK: "1" },
    stdio: ["ignore", "pipe", "pipe", "ipc"],
  });
  let stdout = "", stderr = "";
  child.stdout!.on("data", (bytes: Buffer) => { stdout = (stdout + bytes.toString()).slice(-OUTPUT_CAP_BYTES); });
  child.stderr!.on("data", (bytes: Buffer) => { stderr = (stderr + bytes.toString()).slice(-OUTPUT_CAP_BYTES); });
  let ready!: () => void, hung!: () => void;
  const readyPromise = new Promise<void>(resolve => { ready = resolve; });
  const hangPromise = new Promise<void>(resolve => { hung = resolve; });
  child.on("message", (message: { phase?: string }) => { if (message.phase === "READY") ready(); if (message.phase === "HANG") hung(); });
  const done = new Promise<End>((resolve, reject) => {
    child.once("error", reject);
    child.once("close", (code, signal) => resolve({ code, signal }));
  });
  owned.push({ child, done });
  expect(await bounded(Promise.race([readyPromise.then(() => "ready"), done.then(() => "exited")]), IMPORT_BUDGET_MS), stderr).toBe("ready");
  return { child, done, hangPromise, stdout: () => stdout, stderr: () => stderr };
}
async function healthy(root: string) {
  const run = await start(root, "healthy");
  expect(await bounded(run.done, IMPORT_BUDGET_MS), run.stderr()).toEqual({ code: 0, signal: null });
  return JSON.parse(run.stdout()) as { before: number[]; after: number[]; findings: unknown[] };
}
async function fenced(root: string, mode: "before" | "after" | "load") {
  const run = await start(root, mode);
  const started = Date.now();
  expect(await bounded(run.hangPromise, DEADLINE_MS + EXIT_ALLOWANCE_MS)).not.toBe("timeout");
  const lock = join(root, "state", "_audit-daemon", ".audit-write.lock");
  if (mode === "load") await expect(stat(lock)).rejects.toMatchObject({ code: "ENOENT" });
  else {
    expect(JSON.parse(await readFile(lock, "utf8")).pid).toBe(run.child.pid);
    expect(() => process.kill(run.child.pid!, 0)).not.toThrow();
  }
  expect(await bounded(run.done, DEADLINE_MS + EXIT_ALLOWANCE_MS), run.stderr()).toEqual({ code: 74, signal: null });
  expect(Date.now() - started).toBeLessThan(DEADLINE_MS + EXIT_ALLOWANCE_MS);
  const state = mode === "load" ? "fence_FIRST_LOAD_UNSETTLED" : "fence_HOLD_DEADLINE_LAPSED";
  expect(run.stderr()).toBe(`[castle-wall] AUDIT-EXIT-FENCE fence=${state} deadline_ms=${DEADLINE_MS} - exiting 74 so no abandoned audit write can publish after another writer proceeds\n`);
  if (mode !== "load") {
    expect((await stat(lock)).isFile()).toBe(true);
    expect(() => process.kill(run.child.pid!, 0)).toThrow();
  }
}

describe("audit daemon process fence", () => {
  it.each(["after", "before"] as const)("S2 %s durable publication: successor starts after reap and allocates from disk", async cut => {
    const path = await root(); expect((await healthy(path)).after).toEqual([1]);
    await fenced(path, cut);
    const successor = await healthy(path);
    expect(successor.before).toEqual(cut === "after" ? [1, 2] : [1]);
    expect(successor.after).toEqual(cut === "after" ? [1, 2, 3] : [1, 2]);
    expect(successor.findings).toEqual([]);
  });
  it("three hanging waves exit 74 and never duplicate a sequence", async () => {
    const path = await root(); await healthy(path);
    const WAVES = 3; // Required repeated-admission fault schedule.
    for (let wave = 0; wave < WAVES; wave++) await fenced(path, "after");
    const successor = await healthy(path);
    expect(successor.before).toEqual([1, 2, 3, 4]);
    expect(successor.after).toEqual([1, 2, 3, 4, 5]);
    expect(successor.findings).toEqual([]);
  });
  it("first-read stall exits 74 and healthy restart loads and appends", async () => {
    const path = await root(); await healthy(path);
    await fenced(path, "load");
    const successor = await healthy(path);
    expect(successor.before).toEqual([1]);
    expect(successor.after).toEqual([1, 2]);
    expect(successor.findings).toEqual([]);
  });
});
