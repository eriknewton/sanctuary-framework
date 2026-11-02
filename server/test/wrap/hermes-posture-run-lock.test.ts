import * as fs from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import net from "node:net";
import { spawn, type ChildProcess } from "node:child_process";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
  hermesPostureHome, hermesPostureLockPaths, HERMES_POSTURE_LOCK_TIMEOUT_MS, runHermesPosture,
  type HermesPostureHooks,
} from "../../src/wrap/hermes-posture.js";
import { CrossProcessLockError, withPathLock } from "../../src/storage/cross-process-lock.js";

vi.mock("node:fs/promises", async original => ({ ...await original<typeof import("node:fs/promises")>() }));
vi.mock("../../src/storage/cross-process-lock.js", async original => ({ ...await original<typeof import("../../src/storage/cross-process-lock.js")>() }));
import * as lockModule from "../../src/storage/cross-process-lock.js";

// Must match LOCK_BUSY and LOCK_UNAVAILABLE in server/src/wrap/hermes-posture.ts.
const BUSY = "Another Hermes memory install or removal is running for this Hermes home; wait for it to finish, then run the command again.";
const UNAVAILABLE = "Hermes memory changes need a private lock directory under ~/.sanctuary/locks; fix its owner and permissions, then run the command again.";
const INCOMPLETE = "Hermes installation is incomplete; unwrap it before installing again.";
const PRIVATE_DIRECTORY_MODE = 0o700; // Owner read, write and traversal.
const PUBLIC_DIRECTORY_MODE = 0o755; // Owner write, everyone read and traversal.
const PERMISSION_MASK = 0o7777; // Permission and special mode bits.
const SCHEDULING_MARGIN_MS = 1_000; // One second of CI scheduling slack beyond the acquisition deadline.
const CHILD_READY_TIMEOUT_MS = 10_000; // Ten seconds allows tsx startup on a busy runner.
const postureModule = new URL("../../src/wrap/hermes-posture.ts", import.meta.url).href;
const lockModuleUrl = new URL("../../src/storage/cross-process-lock.ts", import.meta.url).href;
let home: string;
let root: string;
let relay: net.Server;
let hooks: HermesPostureHooks;
const children = new Map<ChildProcess, Promise<void>>();
const parser = { pythonPath: "/fixture/python", exec: async () => ({ stdout: '{"ok": true}', stderr: "", code: 0 }) };
const run = (options: { unwrap?: boolean; dryRun?: boolean } = {}, extra: HermesPostureHooks = {}) =>
  runHermesPosture(options, { ...hooks, ...extra }, parser);

async function tree(): Promise<Record<string, string>> {
  const entries: Record<string, string> = {};
  async function walk(relative: string) {
    for (const name of await fs.readdir(join(root, relative))) {
      const child = join(relative, name);
      const stat = await fs.lstat(join(root, child));
      entries[child] = `${stat.mode & PERMISSION_MASK}:` + (stat.isDirectory() ? "directory" : (await fs.readFile(join(root, child))).toString("base64"));
      if (stat.isDirectory()) await walk(child);
    }
  }
  await walk("");
  return entries;
}

async function startChild(body: string): Promise<ChildProcess> {
  const script = `
    import { withPathLock } from ${JSON.stringify(lockModuleUrl)};
    import { hermesPostureHome, hermesPostureLockPaths, runHermesPosture } from ${JSON.stringify(postureModule)};
    import { existsSync } from 'node:fs';
    const root = await hermesPostureHome();
    const { lockDir, lockFileName } = hermesPostureLockPaths(root);
    ${body}
  `;
  const child = spawn(process.execPath, ["--import", "tsx", "--input-type=module", "-e", script], {
    env: { ...process.env }, stdio: ["ignore", "pipe", "pipe", "ipc"],
  });
  children.set(child, new Promise(done => child.once("close", () => done())));
  let stderr = "";
  child.stderr!.on("data", chunk => { stderr += String(chunk); });
  child.stdout!.resume();
  await new Promise<void>((resolveReady, reject) => {
    const timer = setTimeout(() => { child.kill("SIGKILL"); reject(new Error(`Child readiness timeout: ${stderr}`)); }, CHILD_READY_TIMEOUT_MS);
    child.once("message", message => { clearTimeout(timer); message === "ready" ? resolveReady() : reject(new Error(String(message))); });
    child.once("error", error => { clearTimeout(timer); reject(error); });
    child.once("close", () => { clearTimeout(timer); reject(new Error(`Child exited before ready: ${stderr}`)); });
  });
  return child;
}
async function holder(): Promise<ChildProcess> {
  const { lockDir } = hermesPostureLockPaths(await hermesPostureHome());
  await fs.mkdir(lockDir, { recursive: true, mode: PRIVATE_DIRECTORY_MODE });
  return startChild(`await withPathLock(lockDir, lockFileName, async () => {
    process.send('ready');
    await new Promise(() => {});
  }, { kernelBacked: true });`);
}
async function kill(child: ChildProcess): Promise<void> {
  if (child.exitCode === null && child.signalCode === null) child.kill("SIGKILL");
  await children.get(child);
  children.delete(child);
}
async function assertAvailable(): Promise<void> {
  const { lockDir, lockFileName } = hermesPostureLockPaths(await hermesPostureHome());
  const start = performance.now();
  await withPathLock(lockDir, lockFileName, async () => {}, { kernelBacked: true, timeoutMs: HERMES_POSTURE_LOCK_TIMEOUT_MS });
  expect(performance.now() - start).toBeLessThan(HERMES_POSTURE_LOCK_TIMEOUT_MS);
}

beforeEach(async () => {
  home = await fs.mkdtemp(join(tmpdir(), "hrlock-"));
  root = join(home, "hermes");
  await fs.mkdir(root);
  vi.stubEnv("HOME", home);
  vi.stubEnv("HERMES_HOME", root);
  // Keep even the kernel socket rendezvous inside this test's temporary home.
  vi.stubEnv("SANCTUARY_CUSTODY_LOCK_ROOT", join(home, "kernel"));
  vi.spyOn(console, "log").mockImplementation(() => {});
  hooks = { relaySocketPath: join(home, "relay"), shimCommand: [process.execPath, "fixture"] };
  relay = net.createServer();
  await new Promise<void>(done => {
    // port-discipline: ignore - temporary Unix socket, no TCP listener.
    relay.listen(hooks.relaySocketPath, done);
  });
  await fs.writeFile(join(root, "config.yaml"), "model: fixture\n");
  await fs.writeFile(join(root, "SOUL.md"), "Identity.\n");
  for (const directory of ["plugins", "skills", "memories"]) await fs.mkdir(join(root, directory));
  await fs.writeFile(join(root, "memories/kept.txt"), "Original memory.\n");
});
afterEach(async () => {
  try { for (const child of children.keys()) await kill(child); }
  finally {
    vi.restoreAllMocks();
    vi.unstubAllEnvs();
    if (relay) await new Promise<void>(done => relay.close(() => done()));
    if (home) await fs.rm(home, { recursive: true, force: true });
  }
});

describe("Hermes per-home process-owned run lock", () => {
  it.each([false, true])("T1 refuses contention before reading or changing Hermes files (unwrap=%s)", async unwrap => {
    if (unwrap) await run();
    const before = await tree();
    await holder();
    const reads = vi.spyOn(fs, "readFile");
    const lists = vi.spyOn(fs, "readdir");
    const start = performance.now();
    await expect(run({ unwrap })).rejects.toThrow(new Error(BUSY));
    expect(performance.now() - start).toBeLessThan(HERMES_POSTURE_LOCK_TIMEOUT_MS + SCHEDULING_MARGIN_MS);
    expect(reads.mock.calls.filter(([path]) => String(path).startsWith(root))).toEqual([]);
    expect(lists.mock.calls.filter(([path]) => String(path).startsWith(root))).toEqual([]);
    expect(await tree()).toEqual(before);
  });

  it("T2 immediately installs after SIGKILL releases a holder", async () => {
    const child = await holder();
    await kill(child);
    const start = performance.now();
    await run();
    expect(performance.now() - start).toBeLessThan(HERMES_POSTURE_LOCK_TIMEOUT_MS);
    expect(await fs.readFile(join(root, "config.yaml"), "utf8")).toContain("provider: sanctuary_memory");
  });

  it("T2 keeps the lock through partial writes and recovers after SIGKILL", async () => {
    const before = await tree();
    const child = await startChild(`
      const hooks = ${JSON.stringify(hooks)};
      Object.defineProperty(hooks, 'interruptAfterStep', { get() {
        // The existing interruption seam runs after each write; pause after the backup is published.
        if (existsSync(root + '/sanctuary-install/config.yaml.before')) {
          process.send('ready');
          // Keep the current operation pending before its interruption check can throw and release.
          Atomics.wait(new Int32Array(new SharedArrayBuffer(Int32Array.BYTES_PER_ELEMENT)), 0, 0);
          return 'backup';
        }
      }});
      await runHermesPosture({}, hooks, { pythonPath: '/fixture/python', exec: async () => ({ stdout: '{"ok": true}', stderr: '', code: 0 }) });
    `);
    await expect(run()).rejects.toThrow(new Error(BUSY));
    await kill(child);
    const start = performance.now();
    await expect(run()).rejects.toThrow(new Error(INCOMPLETE));
    expect(performance.now() - start).toBeLessThan(HERMES_POSTURE_LOCK_TIMEOUT_MS);
    await run({ unwrap: true });
    expect(await tree()).toEqual(before);
  });

  it("T3 restores the populated home and leaves only the external inert scaffold", async () => {
    const before = await tree();
    await run();
    await assertAvailable();
    await run(); // The already-installed return must release too.
    await assertAvailable();
    await run({ unwrap: true });
    await assertAvailable();
    await run({ unwrap: true }); // The nothing-to-remove return must release too.
    await assertAvailable();
    expect(await tree()).toEqual(before);
    expect(Object.keys(await tree()).some(path => /\.(lock|sock)$/.test(path))).toBe(false);
    const { lockDir, lockFileName } = hermesPostureLockPaths(await hermesPostureHome());
    expect(lockDir).toBe(join(home, ".sanctuary/locks/hermes-posture"));
    expect(lockFileName).toMatch(/^[a-f0-9]{32}\.lock$/); // 128 digest bits at four bits per hex character.
    expect(await fs.readdir(lockDir)).toEqual([lockFileName]);
    expect((await fs.stat(join(lockDir, lockFileName))).size).toBe(0);
    for (let dir = lockDir; dir !== home; dir = dirname(dir)) {
      expect((await fs.stat(dir)).mode & PERMISSION_MASK).toBe(PRIVATE_DIRECTORY_MODE);
    }
  });

  it("T4 dry runs create no Sanctuary directory and ignore a held lock", async () => {
    const before = await tree();
    await run({ dryRun: true });
    await run({ dryRun: true, unwrap: true });
    await expect(fs.lstat(join(home, ".sanctuary"))).rejects.toMatchObject({ code: "ENOENT" });
    await holder();
    await run({ dryRun: true });
    await run({ dryRun: true, unwrap: true });
    expect(await tree()).toEqual(before);
  });

  it.each(["mode", "symlink", "ancestor symlink"])("T5 fails closed for an unsafe lock directory: %s", async kind => {
    const before = await tree();
    const { lockDir } = hermesPostureLockPaths(await hermesPostureHome());
    if (kind === "ancestor symlink") {
      const target = join(home, "target");
      await fs.mkdir(target);
      await fs.symlink(target, join(home, ".sanctuary"));
    } else {
      await fs.mkdir(dirname(lockDir), { recursive: true, mode: PRIVATE_DIRECTORY_MODE });
      if (kind === "mode") { await fs.mkdir(lockDir); await fs.chmod(lockDir, PUBLIC_DIRECTORY_MODE); }
      else await fs.symlink(root, lockDir);
    }
    await expect(run()).rejects.toThrow(new Error(UNAVAILABLE));
    expect(await tree()).toEqual(before);
  });

  it.each(["capability", "io", "scaffold-integrity"] as const)("hides unavailable-lock details and never enters the plan: %s", async kind => {
    const before = await tree();
    vi.spyOn(lockModule, "withPathLock").mockRejectedValueOnce(new CrossProcessLockError("private diagnostic", kind));
    const read = vi.spyOn(fs, "readFile");
    await expect(run()).rejects.toThrow(new Error(UNAVAILABLE));
    expect(read.mock.calls.filter(([path]) => String(path).startsWith(root))).toEqual([]);
    expect(await tree()).toEqual(before);
  });

  it.each([".sanctuary", ".sanctuary/locks", ".sanctuary/locks/hermes-posture"])("refuses a home containing the lock directory: %s", async relative => {
    root = join(home, relative);
    await fs.mkdir(root, { recursive: true, mode: PRIVATE_DIRECTORY_MODE });
    vi.stubEnv("HERMES_HOME", root);
    const before = await tree();
    await expect(run()).rejects.toThrow(new Error(UNAVAILABLE));
    expect(await tree()).toEqual(before);
  });

  it.each(["refusal", "failure", "interruption"])("releases the lock on %s", async exit => {
    if (exit === "refusal") {
      await expect(run({}, { relaySocketPath: join(home, "absent") })).rejects.toThrow("Relay socket is missing");
    } else {
      const extra = exit === "failure" ? { failAfterStep: "config" } : { interruptAfterStep: "config" };
      await expect(run({}, extra)).rejects.toThrow(exit === "failure" ? "Injected write failure" : "Interrupted install");
    }
    await assertAvailable();
    if (exit === "interruption") await run({ unwrap: true });
    await run();
  });

  it("uses one key for normalized spellings and different keys for distinct homes", async () => {
    const coordinates = hermesPostureLockPaths(await hermesPostureHome());
    vi.stubEnv("HERMES_HOME", root + "/../hermes/");
    expect(hermesPostureLockPaths(await hermesPostureHome())).toEqual(coordinates);
    await holder();
    await expect(run()).rejects.toThrow(new Error(BUSY));
    vi.stubEnv("HERMES_HOME", join(home, "other-hermes"));
    expect(hermesPostureLockPaths(await hermesPostureHome()).lockFileName).not.toBe(coordinates.lockFileName);
    await run({ unwrap: true });
  });
});
