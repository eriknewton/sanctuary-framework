import * as fs from "node:fs/promises";
import { createHash } from "node:crypto";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import net from "node:net";
import { spawn, type ChildProcess } from "node:child_process";
import { afterAll, afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
  hermesPostureHome, hermesPostureLockPaths, HERMES_POSTURE_LOCK_TIMEOUT_MS, runHermesPosture,
  type HermesPostureHooks,
} from "../../src/wrap/hermes-posture.js";
import { CrossProcessLockError, resolveCustodyLockRoot, withPathLock } from "../../src/storage/cross-process-lock.js";

vi.mock("node:fs/promises", async original => ({ ...await original<typeof import("node:fs/promises")>() }));
vi.mock("../../src/storage/cross-process-lock.js", async original => ({ ...await original<typeof import("../../src/storage/cross-process-lock.js")>() }));
import * as lockModule from "../../src/storage/cross-process-lock.js";

// Must match LOCK_BUSY and LOCK_UNAVAILABLE in server/src/wrap/hermes-posture.ts.
const BUSY = "Another Hermes memory install or removal is running for this account; wait for it to finish, then run the command again.";
const UNAVAILABLE = "Hermes memory changes need a private lock directory under ~/.sanctuary/locks; fix its owner and permissions, then run the command again.";
// Must match the incomplete-install refusal in planAndApplyHermesPosture in server/src/wrap/hermes-posture.ts.
const INCOMPLETE = "Hermes installation is incomplete; unwrap it before installing again.";
// Must match LOCK_RELEASE_WARNING in server/src/wrap/hermes-posture.ts.
const RELEASE_WARNING = "The change finished, but its lock could not be released cleanly; the next run may report it as busy for a moment.";
// Darwin: /private/tmp/hrlock-XXXXXX/kernel is 33 bytes; 33 + 1 separator +
// 47 (40 digest characters + .reaper) = 81, below the custody limit of 100 bytes.
const SHORT_SOCKET_TMP_PARENT = process.platform === "darwin" ? "/private/tmp" : tmpdir();
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
const fixtureCoordinates = new Map<string, Set<string>>();
const attributableRuntimeEntries = new Set<string>();
let isolatedScaffoldObserved = false;
const parser = { pythonPath: "/fixture/python", exec: async () => ({ stdout: '{"ok": true}', stderr: "", code: 0 }) };
const run = async (options: { unwrap?: boolean; dryRun?: boolean } = {}, extra: HermesPostureHooks = {}) => {
  fixtureLockPaths(await hermesPostureHome());
  return runHermesPosture(options, { ...hooks, ...extra }, parser);
};

function fixtureLockPaths(hermesHome: string) {
  const coordinates = hermesPostureLockPaths(hermesHome);
  const names = fixtureCoordinates.get(coordinates.lockDir) ?? new Set<string>();
  names.add(coordinates.lockFileName);
  fixtureCoordinates.set(coordinates.lockDir, names);
  return coordinates;
}

async function kernelEntryNames(lockDir: string, lockFileName: string): Promise<string[]> {
  const { dev, ino } = await fs.stat(lockDir, { bigint: true });
  // Mirrors withKernelPathLock/acquireKernelLock in server/src/storage/cross-process-lock.ts; the full-set parity test is the tripwire.
  const digest = createHash("sha256").update(`${dev}:${ino}:${lockFileName}`).digest("hex");
  const digestHexChars = 40; // The primitive retains 160 bits, encoded as 40 hexadecimal characters.
  return [".reaper", ".sock"].map(suffix => digest.slice(0, digestHexChars) + suffix);
}

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
  fixtureLockPaths(await hermesPostureHome());
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
  const { lockDir } = fixtureLockPaths(await hermesPostureHome());
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
  const { lockDir, lockFileName } = fixtureLockPaths(await hermesPostureHome());
  const start = performance.now();
  await withPathLock(lockDir, lockFileName, async () => {}, { kernelBacked: true, timeoutMs: HERMES_POSTURE_LOCK_TIMEOUT_MS });
  expect(performance.now() - start).toBeLessThan(HERMES_POSTURE_LOCK_TIMEOUT_MS);
}

// Observe only directory entries, never operator state or credentials, and never create this root.
const realRuntimeRoot = resolveCustodyLockRoot(process.getuid!(), {
  platform: process.platform, env: { TMPDIR: process.env.TMPDIR },
});
async function runtimeEntries(): Promise<string[]> {
  try { return await fs.readdir(realRuntimeRoot); }
  catch (error) { if ((error as NodeJS.ErrnoException).code === "ENOENT") return []; throw error; }
}
afterAll(async () => {
  // Other workers may use this root; only this file's directory identities are attributable to its fixtures.
  expect((await runtimeEntries()).filter(entry => attributableRuntimeEntries.has(entry)),
    "Fixture-attributable scaffolds must not exist in the shared custody root").toEqual([]);
  expect(isolatedScaffoldObserved, "The per-test custody root must receive a real scaffold").toBe(true);
});

beforeEach(async () => {
  fixtureCoordinates.clear();
  home = await fs.mkdtemp(join(SHORT_SOCKET_TMP_PARENT, "hrlock-"));
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
  try {
    for (const child of children.keys()) await kill(child);
    for (const [lockDir, names] of fixtureCoordinates) {
      for (const name of names) {
        let entries: string[];
        try { entries = await kernelEntryNames(lockDir, name); }
        catch (error) { if ((error as NodeJS.ErrnoException).code === "ENOENT") continue; throw error; }
        for (const entry of entries) attributableRuntimeEntries.add(entry);
        const isolatedEntries = await fs.readdir(join(home, "kernel")).catch(error => {
          if (error.code === "ENOENT") return [] as string[];
          throw error;
        });
        if (isolatedEntries.includes(entries[0])) isolatedScaffoldObserved = true;
      }
    }
  }
  finally {
    vi.restoreAllMocks();
    vi.unstubAllEnvs();
    if (relay) await new Promise<void>(done => relay.close(() => done()));
    if (home) await fs.rm(home, { recursive: true, force: true });
  }
});

describe("Hermes account-home process-owned run lock", () => {
  it("matches the primitive's full set of kernel entry names in a fresh temporary root", async () => {
    const { lockDir, lockFileName } = fixtureLockPaths(await hermesPostureHome());
    await withPathLock(lockDir, lockFileName, async () => {
      const expected = await kernelEntryNames(lockDir, lockFileName);
      expect((await fs.readdir(join(home, "kernel"))).sort()).toEqual(expected.sort());
    }, { kernelBacked: true });
  });

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
    // Must match hermesPostureLockPaths in server/src/wrap/hermes-posture.ts.
    expect(lockDir).toBe(join(home, ".sanctuary/locks/hermes-posture"));
    expect(lockFileName).toBe("hermes-posture.lock");
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

  it("uses one account key for normalized spellings and distinct Hermes homes", async () => {
    const coordinates = hermesPostureLockPaths(await hermesPostureHome());
    vi.stubEnv("HERMES_HOME", root + "/../hermes/");
    expect(hermesPostureLockPaths(await hermesPostureHome())).toEqual(coordinates);
    await holder();
    vi.stubEnv("HERMES_HOME", join(home, "other-hermes"));
    await expect(run({ unwrap: true })).rejects.toThrow(new Error(BUSY));
    expect(hermesPostureLockPaths(await hermesPostureHome()).lockFileName).toBe(coordinates.lockFileName);
    vi.stubEnv("HERMES_HOME", root + "/../hermes/");
    await expect(run()).rejects.toThrow(new Error(BUSY));
  });

  it.each(["Hermes home", "account home"])("contends with the plain spelling when %s has a trailing slash", async spelling => {
    await holder();
    if (spelling === "Hermes home") vi.stubEnv("HERMES_HOME", root + "/../hermes/");
    else vi.stubEnv("HOME", home + "/");
    const before = await tree();
    await expect(run()).rejects.toThrow(new Error(BUSY));
    expect(await tree()).toEqual(before);
  });

  it("contends with a case variant on a case-insensitive temporary volume", async context => {
    const variant = join(home, "HERMES");
    const sameDirectory = await fs.stat(variant).then(
      async stat => { const original = await fs.stat(root); return stat.dev === original.dev && stat.ino === original.ino; },
      error => { if (error.code === "ENOENT") return false; throw error; },
    );
    // A case-sensitive volume cannot witness two differently cased names for this directory.
    if (!sameDirectory) { context.skip(); return; }
    await holder();
    vi.stubEnv("HERMES_HOME", variant);
    const before = await tree();
    await expect(run()).rejects.toThrow(new Error(BUSY));
    expect(await tree()).toEqual(before);
  });

  it.each([false, true])("reports success and one warning when release fails after completion (unwrap=%s)", async unwrap => {
    const before = await tree();
    if (unwrap) await run();
    vi.mocked(console.log).mockClear();
    vi.spyOn(lockModule, "withPathLock").mockImplementationOnce(async (dir, name, operation, options) => {
      await withPathLock(dir, name, operation, options);
      throw new CrossProcessLockError("private release diagnostic", "holder-lost");
    });
    await expect(run({ unwrap })).resolves.toBeUndefined();
    const lines = vi.mocked(console.log).mock.calls.map(args => args.join(" "));
    expect(lines.at(-2)).toBe(unwrap ? "Removed Sanctuary memory configuration; original files restored." : "Sanctuary memory installed. Restart Hermes.");
    expect(lines.at(-1)).toBe(RELEASE_WARNING);
    expect(lines.filter(line => line === RELEASE_WARNING)).toHaveLength(1);
    expect(lines.join("\n")).not.toContain("private release diagnostic");
    if (unwrap) expect(await tree()).toEqual(before);
    else expect(await fs.readFile(join(root, "config.yaml"), "utf8")).toContain("provider: sanctuary_memory");
    await assertAvailable();
  });

  it("preserves the operation refusal when release also fails", async () => {
    const before = await tree();
    vi.spyOn(lockModule, "withPathLock").mockImplementationOnce(async (dir, name, operation, options) => {
      try { return await withPathLock(dir, name, operation, options); }
      catch (error) {
        throw new AggregateError([error, new CrossProcessLockError("private release diagnostic", "holder-lost")],
          "custody operation failed and the process-owned lock did not release cleanly", { cause: error });
      }
    });
    await expect(run({}, { relaySocketPath: join(home, "absent") })).rejects.toThrow("Relay socket is missing");
    expect(vi.mocked(console.log).mock.calls.flat()).not.toContain(RELEASE_WARNING);
    expect(await tree()).toEqual(before);
    await assertAvailable();
  });

});
