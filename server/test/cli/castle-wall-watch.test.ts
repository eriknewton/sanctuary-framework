/**
 * The observer verbs over temp directories, an injected runner and injected
 * facts: stable runtime refusal, install and its rollback, uninstall and the
 * canary removal handoff, and run-watch preflight, shutdown and silence.
 * Nothing here runs launchctl, id, ps or sysctl, touches a real LaunchAgents
 * or LaunchDaemons directory, or reads a credential.
 */
import { createHash } from "node:crypto";
import { EventEmitter } from "node:events";
import * as fs from "node:fs";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmdirSync, symlinkSync, unlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Writable } from "node:stream";
import { afterEach, describe, expect, it, vi } from "vitest";
import { CANARY_LABEL, CHILD_READ_DEADLINE, OBSERVER_LABEL, SECOND, WATCH_THROTTLE_INTERVAL_S } from "../../src/castle-wall/liveness/constants.js";
import { CensusSampler, CensusSeries } from "../../src/castle-wall/liveness/census-sampler.js";
import { CANARY_INSTALLED_PLIST_PATH, generateCanaryPlist, parseSystemJobPrint } from "../../src/castle-wall/liveness/launchd-plists.js";
import { LivenessObserver, type ObserverCollectors } from "../../src/castle-wall/liveness/observer.js";
import { parseFullAgentPrint } from "../../src/cli/castle-wall-full-agent.js";
import {
  COMMISSIONING_LINE,
  OBSERVER_STAYS_LOADED_LINE,
  WATCH_EXIT_CANARY_PENDING,
  WATCH_EXIT_CANARY_STILL_INSTALLED,
  WATCH_EXIT_FAILED,
  WATCH_EXIT_INSTALLED,
  WATCH_EXIT_ROLLBACK_INCOMPLETE,
  runInstallWatch,
  runRunWatch,
  runUninstallWatch,
  watchConfigPath,
  type WatchCommandContext,
  type WatchVerbFs,
} from "../../src/cli/castle-wall-watch.js";
import { BoundedChildRunner, type WatchChild, type WatchSpawn } from "../../src/cli/castle-wall-watch-collectors.js";
import { resolveStableRuntime, SANCTUARY_PACKAGE_NAME, STABLE_RUNTIME_REFUSAL_EXIT_CODE } from "../../src/cli/stable-runtime-path.js";
import { inMemoryKeychainCalls } from "../setup/keychain-memory-store.js";

const UID = process.getuid!();
const AGENT_UID = UID + 1;
const NAME = "sanctuary-agent-fixture";
const FIX = join(__dirname, "..", "castle-wall", "liveness", "fixtures");
const PRINTS = JSON.parse(readFileSync(join(FIX, "launchctl-print.json"), "utf8")).entries as Record<string, { code: number; stdout: string; stderr: string }>;
const BASE_CONFIG = (JSON.parse(readFileSync(join(FIX, "states.json"), "utf8")).base.config.value) as Record<string, unknown>;
const OBSERVER_PID = parseFullAgentPrint(PRINTS.observer_gui!.stdout).pid!;
const OPT_NODE = "/opt/homebrew/opt/node/bin/node";
const CLI = "/opt/homebrew/lib/node_modules/@sanctuary-framework/mcp-server/dist/cli.js";
const ATTENDED_REMOVAL =
  "Run these two commands as root (for example with sudo):\n" +
  "/bin/launchctl bootout system/ai.sanctuaryprotocol.castle-wall.canary\n" +
  "/bin/rm /Library/LaunchDaemons/ai.sanctuaryprotocol.castle-wall.canary.plist\n";
const attendedInstall = (fortress: string) =>
  "Run these two commands as root (for example with sudo):\n" +
  `/usr/bin/install -o root -g wheel -m 0644 '${fortress}/liveness/canary.plist' /Library/LaunchDaemons/ai.sanctuaryprotocol.castle-wall.canary.plist\n` +
  "/bin/launchctl bootstrap system /Library/LaunchDaemons/ai.sanctuaryprotocol.castle-wall.canary.plist\n";

// The shared in-memory credential store logs every call it serves; no verb may reach it.

class Sink extends Writable {
  text = "";
  override _write(chunk: Buffer, _enc: string, done: () => void): void { this.text += chunk.toString(); done(); }
}

/** A modelled launchd: answers each closed-enum argv the runner spawns, and records every call. */
class Launchd {
  observerLoaded = false;
  bootstrapOk = true;
  bootoutUnloads = true;
  canaryPrint: { code: number; stdout: string; stderr: string } | "hang" = PRINTS.captured_system_not_found!;
  idName = NAME;
  idUid = String(AGENT_UID);
  /** Pids the loaded observer print reports, one per print; the last one repeats. Empty keeps the fixture pid. */
  observerPids: number[] = [];
  lastObserverPid: number | null = null;
  calls: string[][] = [];
  envs: Array<Record<string, string>> = [];
  spawn: WatchSpawn = (file, args, options) => {
    this.calls.push([file, ...args]);
    this.envs.push(options.env);
    const child = Object.assign(new EventEmitter(), { pid: 7000 + this.calls.length, stdout: new EventEmitter(), stderr: new EventEmitter() }) as unknown as WatchChild & EventEmitter & { stdout: EventEmitter; stderr: EventEmitter };
    child.kill = () => { queueMicrotask(() => { child.emit("exit", null, "SIGTERM"); child.emit("close", null, "SIGTERM"); }); return true; };
    const answer = this.answer(file, args);
    if (answer !== "hang") {
      queueMicrotask(() => {
        if (answer.stdout) child.stdout.emit("data", Buffer.from(answer.stdout));
        if (answer.stderr) child.stderr.emit("data", Buffer.from(answer.stderr));
        child.emit("exit", answer.code, null);
        child.emit("close", answer.code, null);
      });
    }
    return child;
  };
  private answer(file: string, args: readonly string[]): { code: number; stdout: string; stderr: string } | "hang" {
    if (file === "/usr/bin/id") return args[0] === "-un" ? { code: 0, stdout: `${this.idName}\n`, stderr: "" } : { code: 0, stdout: `${this.idUid}\n`, stderr: "" };
    if (file !== "/bin/launchctl") return { code: 1, stdout: "", stderr: "unexpected" };
    if (args[0] === "print" && args[1]!.startsWith("gui/")) {
      if (!this.observerLoaded) return PRINTS.gui_not_found!;
      if (this.observerPids.length === 0) return PRINTS.observer_gui!;
      const pid = this.observerPids.length > 1 ? this.observerPids.shift()! : this.observerPids[0]!;
      this.lastObserverPid = pid;
      return { ...PRINTS.observer_gui!, stdout: PRINTS.observer_gui!.stdout.replace(`pid = ${OBSERVER_PID}`, `pid = ${pid}`) };
    }
    if (args[0] === "print" && args[1] === `system/${CANARY_LABEL}`) return this.canaryPrint;
    if (args[0] === "bootstrap") { if (!this.bootstrapOk) return { code: 5, stdout: "", stderr: "Bootstrap failed: 5: Input/output error\n" }; this.observerLoaded = true; return { code: 0, stdout: "", stderr: "" }; }
    if (args[0] === "bootout") { if (this.bootoutUnloads) this.observerLoaded = false; return { code: 0, stdout: "", stderr: "" }; }
    return { code: 1, stdout: "", stderr: "unexpected" };
  }
}

const passingFacts = () => {
  const bytes = Buffer.from(generateCanaryPlist(NAME));
  return {
    plistStat: { status: "ok" as const, value: { isFile: true, isSymbolicLink: false, uid: 0, gid: 0, mode: 0o100644, size: bytes.byteLength } },
    plistBytes: { status: "ok" as const, value: bytes },
    account: { status: "ok" as const, value: { name: NAME, reverseUid: AGENT_UID } },
    print: { status: "ok" as const, value: parseSystemJobPrint(PRINTS.canary_system!.stdout) },
  };
};

const created: string[] = [];
/** Files and directories a test created beyond the world layout, removed deepest first. */
const extraFiles: string[] = [];
const extraDirs: string[] = [];
/** Remove only the known files and directories a world creates, one entry at a time. */
afterEach(() => {
  for (const file of extraFiles.splice(0)) { try { unlinkSync(file); } catch { /* absent */ } }
  for (const dir of extraDirs.splice(0)) { try { rmdirSync(dir); } catch { /* absent or not empty */ } }
  for (const root of created.splice(0)) {
    for (const file of [join(root, "fortress", "liveness", "canary.plist"), join(root, "fortress", "liveness", "observer.json"), join(root, "home", "Library", "LaunchAgents", `${OBSERVER_LABEL}.plist`)]) {
      try { unlinkSync(file); } catch { /* absent */ }
    }
    for (const dir of [join(root, "fortress", "liveness"), join(root, "fortress"), join(root, "home", "Library", "LaunchAgents"), join(root, "home", "Library"), join(root, "home"), root]) {
      try { rmdirSync(dir); } catch { /* absent or holds a stray temp */ }
    }
  }
  expect(inMemoryKeychainCalls()).toEqual([]);
  vi.useRealTimers();
});

interface World {
  root: string; fortress: string; home: string; out: Sink; err: Sink; launchd: Launchd; runner: BoundedChildRunner; io: WatchVerbFs;
  writeOpens: string[]; canaryFile: "absent" | "present"; corruptStaged: boolean; unlinkFails: string | null; statUid: number | null;
  config: Record<string, unknown> | null; facts: ReturnType<typeof passingFacts>;
}
function world(options: { fortressName?: string; liveness?: boolean } = {}): World {
  const root = mkdtempSync(join(tmpdir(), "lv-watch-"));
  created.push(root);
  const fortress = join(root, options.fortressName ?? "fortress");
  mkdirSync(fortress, { mode: 0o700 });
  if (options.liveness !== false) mkdirSync(join(fortress, "liveness"), { mode: 0o700 });
  const home = join(root, "home");
  mkdirSync(home, { mode: 0o700 });
  const launchd = new Launchd();
  const w = {
    root, fortress, home, out: new Sink(), err: new Sink(), launchd,
    runner: new BoundedChildRunner({ spawn: launchd.spawn, timers: { setTimeout: (f: () => void, ms: number) => setTimeout(f, ms), clearTimeout: (h: unknown) => clearTimeout(h as NodeJS.Timeout) } }),
    writeOpens: [] as string[], canaryFile: "absent" as "absent" | "present", corruptStaged: false, unlinkFails: null as string | null, statUid: null as number | null,
    config: { ...BASE_CONFIG, agent_uid: AGENT_UID, gate_uid: UID + 2 } as Record<string, unknown> | null, facts: passingFacts(),
  } as World;
  const fdPaths = new Map<number, string>();
  const WRITE_FLAGS = fs.constants.O_WRONLY | fs.constants.O_RDWR | fs.constants.O_CREAT | fs.constants.O_TRUNC | fs.constants.O_APPEND;
  w.io = {
    lstatSync: ((path: string) => {
      // The real system path is never touched: the installed canary is modelled.
      if (path === CANARY_INSTALLED_PLIST_PATH) {
        if (w.canaryFile === "absent") throw Object.assign(new Error("absent"), { code: "ENOENT" });
        return { isFile: () => true, isSymbolicLink: () => false, isDirectory: () => false, uid: 0, gid: 0, mode: 0o100644, size: 1 };
      }
      return fs.lstatSync(path);
    }) as WatchVerbFs["lstatSync"],
    statSync: ((path: string) => {
      const real = fs.statSync(path);
      return w.statUid === null ? real : Object.assign(Object.create(Object.getPrototypeOf(real)), real, { uid: w.statUid });
    }) as WatchVerbFs["statSync"],
    openSync: (path: string, flags: number, mode?: number) => {
      if (path.startsWith("/Library/") || path.includes("/Library/LaunchDaemons")) throw new Error("a real system path was opened");
      if ((flags & WRITE_FLAGS) !== 0) w.writeOpens.push(path);
      const fd = fs.openSync(path, flags, mode);
      fdPaths.set(fd, path);
      return fd;
    },
    fstatSync: fd => fs.fstatSync(fd),
    readSync: (fd, buffer, offset, length, position) => fs.readSync(fd, buffer, offset, length, position),
    closeSync: fd => { fdPaths.delete(fd); fs.closeSync(fd); },
    writeSync: ((fd: number, buffer: Buffer, offset: number, length: number, position: number | null) => {
      const path = fdPaths.get(fd) ?? "";
      if (w.corruptStaged && path.includes(`${join("liveness", "canary.plist")}.`)) {
        const altered = Buffer.from(buffer);
        altered[altered.length - 2] = 0x41;
        return fs.writeSync(fd, altered, offset, length, position);
      }
      return fs.writeSync(fd, buffer, offset, length, position);
    }) as WatchVerbFs["writeSync"],
    fsyncSync: fd => fs.fsyncSync(fd),
    fchmodSync: (fd, mode) => fs.fchmodSync(fd, mode),
    renameSync: (from, to) => fs.renameSync(from, to),
    unlinkSync: path => { if (w.unlinkFails !== null && String(path) === w.unlinkFails) throw Object.assign(new Error("denied"), { code: "EACCES" }); fs.unlinkSync(path); },
    mkdirSync: ((path: string, opts?: fs.MakeDirectoryOptions) => fs.mkdirSync(path, opts)) as WatchVerbFs["mkdirSync"],
  };
  return w;
}
function ctx(w: World, over: Partial<WatchCommandContext> = {}): WatchCommandContext {
  return {
    out: w.out, err: w.err, env: {}, home: w.home, platform: "darwin", euid: UID, execPath: OPT_NODE, cliPath: CLI, fs: w.io, runner: w.runner,
    sleep: async () => undefined, nowMs: () => 1_794_225_600_000,
    stableRuntime: () => ({ ok: true, node: OPT_NODE, cli: CLI, nodeVersion: "22.11.0" }),
    collectCanaryFacts: async () => structuredClone(w.facts),
    readConfig: async () => (w.config === null ? { status: "absent" } : { status: "present", value: structuredClone(w.config) }),
    ...over,
  };
}
const observerPlist = (w: World) => join(w.home, "Library", "LaunchAgents", `${OBSERVER_LABEL}.plist`);
const stagedPath = (w: World) => join(w.fortress, "liveness", "canary.plist");
function expectNoEscalationOrConfigWrite(w: World): void {
  for (const call of w.launchd.calls) for (const token of call) expect(token).not.toMatch(/^(sudo|su|osascript)$|\/(sudo|su|osascript)$/);
  for (const env of w.launchd.envs) expect(env).toEqual({ PATH: "/usr/bin:/bin:/usr/sbin:/sbin", LC_ALL: "C" });
  expect(w.writeOpens.filter(p => p === watchConfigPath(w.fortress) || p.startsWith(`${watchConfigPath(w.fortress)}.`))).toEqual([]);
  expect(existsSync(watchConfigPath(w.fortress))).toBe(false);
  expect(inMemoryKeychainCalls()).toEqual([]);
}

// ---------------------------------------------------------------------------
describe("stable runtime", () => {
  /** A Homebrew-shaped temp prefix; `withOpt` adds the maintained opt alias. */
  function prefix(root: string, withOpt: boolean) {
    const version = "22.11.0";
    const keg = join(root, "brew", "Cellar", "node", version, "bin");
    mkdirSync(keg, { recursive: true, mode: 0o755 });
    writeFileSync(join(keg, "node"), "#!/bin/sh\n", { mode: 0o755 });
    mkdirSync(join(root, "brew", "opt"), { mode: 0o755 });
    if (withOpt) symlinkSync(join("..", "Cellar", "node", version), join(root, "brew", "opt", "node"));
    const pkg = join(root, "brew", "lib", "node_modules", "@sanctuary-framework", "mcp-server");
    mkdirSync(join(pkg, "dist"), { recursive: true, mode: 0o755 });
    writeFileSync(join(pkg, "dist", "cli.js"), "// fixture entry\n", { mode: 0o644 });
    writeFileSync(join(pkg, "package.json"), JSON.stringify({ name: SANCTUARY_PACKAGE_NAME, engines: { node: ">=20" } }), { mode: 0o644 });
    const optNode = join(root, "brew", "opt", "node", "bin", "node");
    const cli = join(pkg, "dist", "cli.js");
    extraFiles.push(cli, join(pkg, "package.json"), join(keg, "node"), join(root, "brew", "opt", "node"));
    extraDirs.push(join(pkg, "dist"), pkg, join(pkg, ".."), join(pkg, "..", ".."), join(pkg, "..", "..", ".."), keg, join(keg, ".."), join(keg, "..", ".."), join(keg, "..", "..", ".."),
      join(root, "brew", "opt"), join(root, "brew"));
    const stableRuntime = (running: { execPath: string; cliPath: string; operatorUid: number }) => resolveStableRuntime({
      ...running, nodeCandidates: [optNode], cliCandidates: [cli], tempRoots: [], runningNodeVersion: version, versionProbe: () => `v${version}`,
    });
    return { cellarNode: join(keg, "node"), optNode, cli, stableRuntime };
  }

  it("exits 78 before any write or runner call when only a Cellar node exists", async () => {
    const w = world();
    const p = prefix(w.root, false);
    const code = await runInstallWatch(["--fortress", w.fortress], ctx(w, { execPath: p.cellarNode, cliPath: p.cli, stableRuntime: p.stableRuntime }));
    expect(code).toBe(STABLE_RUNTIME_REFUSAL_EXIT_CODE);
    expect(w.launchd.calls).toEqual([]);
    expect(w.writeOpens).toEqual([]);
    expect(existsSync(join(w.home, "Library"))).toBe(false);
  });

  it("writes the opt path into the plist, never a Cellar or versioned path", async () => {
    const w = world();
    const p = prefix(w.root, true);
    w.launchd.bootstrapOk = true;
    const code = await runInstallWatch(["--fortress", w.fortress], ctx(w, { execPath: p.cellarNode, cliPath: p.cli, stableRuntime: p.stableRuntime }));
    expect(code).toBe(WATCH_EXIT_INSTALLED);
    const plist = readFileSync(observerPlist(w), "utf8");
    expect(plist).toContain(`<string>${p.optNode}</string>`);
    expect(plist).not.toContain("Cellar");
    expect(plist).not.toMatch(/node@\d|\/v\d+\./);
  });
});

describe("install-watch", () => {
  it("exits 0 when integrity passes, with the staged file equal to the generator's bytes", async () => {
    const w = world();
    expect(await runInstallWatch(["--fortress", w.fortress], ctx(w))).toBe(WATCH_EXIT_INSTALLED);
    expect(w.out.text).toBe(`Observer LaunchAgent installed; running pid=${OBSERVER_PID}.\nCanary integrity passes. This is an installer result; read liveness with \`castle-wall liveness-status\`.\n`);
    const staged = readFileSync(stagedPath(w));
    expect(createHash("sha256").update(staged).digest("hex")).toBe(createHash("sha256").update(generateCanaryPlist(NAME)).digest("hex"));
    expect(w.launchd.calls).toContainEqual(["/bin/launchctl", "bootstrap", `gui/${UID}`, observerPlist(w)]);
    expect(w.launchd.calls).toContainEqual(["/usr/bin/id", "-un", String(AGENT_UID)]);
    expect(w.launchd.calls).toContainEqual(["/usr/bin/id", "-u", NAME]);
    expectNoEscalationOrConfigWrite(w);
  });

  it("reaches exit 0 only after sleeping a full stable window past the restart throttle, restarting the window on a pid change", async () => {
    // One sample interval beyond the observer's launchd ThrottleInterval, as the installer's stable window is defined.
    const STABLE_WINDOW = WATCH_THROTTLE_INTERVAL_S * SECOND + SECOND;
    for (const restartAfter of [0, 3]) {
      const w = world();
      const RESTARTED_PID = OBSERVER_PID + 1;
      w.launchd.observerPids = [...Array<number>(restartAfter).fill(OBSERVER_PID), RESTARTED_PID];
      const slept: Array<{ ms: number; afterPid: number | null }> = [];
      const code = await runInstallWatch(["--fortress", w.fortress], ctx(w, { sleep: async ms => { slept.push({ ms, afterPid: w.launchd.lastObserverPid }); } }));
      expect(code, `restart after ${restartAfter}`).toBe(WATCH_EXIT_INSTALLED);
      expect(w.out.text).toContain(`running pid=${RESTARTED_PID}.`);
      // Only time slept after the restarted pid was first seen counts toward its window.
      const sinceRestart = slept.filter(entry => entry.afterPid === RESTARTED_PID).reduce((sum, entry) => sum + entry.ms, 0);
      expect(sinceRestart, `restart after ${restartAfter}`).toBeGreaterThanOrEqual(STABLE_WINDOW);
    }
  });

  it("prints exactly the attended install text and exits 5 when integrity fails", async () => {
    const w = world();
    w.facts.plistStat = { status: "failed" } as never;
    expect(await runInstallWatch(["--fortress", w.fortress], ctx(w))).toBe(WATCH_EXIT_CANARY_PENDING);
    expect(w.out.text).toBe(`Observer LaunchAgent installed; running pid=${OBSERVER_PID}.\n${attendedInstall(w.fortress)}`);
    expect(readFileSync(stagedPath(w), "utf8")).toBe(generateCanaryPlist(NAME));
    expectNoEscalationOrConfigWrite(w);
  });

  it("prints the commissioning line, creates no directory and exits 5 with no config", async () => {
    const w = world();
    w.config = null;
    expect(await runInstallWatch(["--fortress", w.fortress], ctx(w))).toBe(WATCH_EXIT_CANARY_PENDING);
    expect(w.out.text.endsWith(COMMISSIONING_LINE)).toBe(true);
    expect(existsSync(stagedPath(w))).toBe(false);
    expectNoEscalationOrConfigWrite(w);
  });

  it("prints the commissioning line, creates no directory and exits 5 with no liveness directory", async () => {
    const w = world({ liveness: false });
    expect(await runInstallWatch(["--fortress", w.fortress], ctx(w))).toBe(WATCH_EXIT_CANARY_PENDING);
    expect(w.out.text.endsWith(COMMISSIONING_LINE)).toBe(true);
    expect(existsSync(join(w.fortress, "liveness"))).toBe(false);
    expect(w.launchd.calls.filter(c => c[0] === "/usr/bin/id")).toEqual([]);
  });

  it("exits 1 before any write when the config names this operator as the agent", async () => {
    const w = world();
    w.config = { ...w.config!, agent_uid: UID };
    expect(await runInstallWatch(["--fortress", w.fortress], ctx(w))).toBe(WATCH_EXIT_FAILED);
    expect(w.launchd.calls).toEqual([]);
    expect(w.writeOpens).toEqual([]);
    expect(existsSync(join(w.home, "Library"))).toBe(false);
  });

  it("exits 1 before any write for a fortress path containing a single quote", async () => {
    const w = world({ fortressName: "it's" });
    expect(await runInstallWatch(["--fortress", w.fortress], ctx(w))).toBe(WATCH_EXIT_FAILED);
    expect(w.launchd.calls).toEqual([]);
    expect(w.writeOpens).toEqual([]);
    rmdirSync(join(w.fortress, "liveness"));
    rmdirSync(w.fortress);
  });

  it("exits 1 and prints no attended text when a write fault alters the staged bytes", async () => {
    const w = world();
    w.corruptStaged = true;
    w.facts.plistStat = { status: "failed" } as never;
    expect(await runInstallWatch(["--fortress", w.fortress], ctx(w))).toBe(WATCH_EXIT_FAILED);
    expect(w.out.text).not.toContain("Run these two commands");
    expect(w.err.text).toContain("does not match the generated bytes");
    expect(w.err.text.endsWith(OBSERVER_STAYS_LOADED_LINE)).toBe(true);
    expect(w.launchd.observerLoaded).toBe(true);
  });

  it("exits 1 before any write when the fortress is owned by another uid", async () => {
    const w = world();
    w.statUid = UID + 1;
    expect(await runInstallWatch(["--fortress", w.fortress], ctx(w))).toBe(WATCH_EXIT_FAILED);
    expect(w.launchd.calls).toEqual([]);
    expect(w.writeOpens).toEqual([]);
    expect(w.err.text).toContain("not a directory owned by this user");
  });

  it("exits 1 and stages nothing when the agent account name does not resolve back to the agent uid", async () => {
    const w = world();
    w.launchd.idUid = String(AGENT_UID + 1);
    expect(await runInstallWatch(["--fortress", w.fortress], ctx(w))).toBe(WATCH_EXIT_FAILED);
    expect(existsSync(stagedPath(w))).toBe(false);
    expect(w.out.text).not.toContain("Run these two commands");
    expect(w.err.text).toContain("could not be resolved in both directions");
    // Rollback covers the write and bootstrap steps only, so the operator is told the observer is still loaded.
    expect(w.err.text.endsWith(OBSERVER_STAYS_LOADED_LINE)).toBe(true);
    expect(w.launchd.observerLoaded).toBe(true);
  });

  it("refuses non-darwin and root before any write", async () => {
    for (const over of [{ platform: "linux" }, { euid: 0 }]) {
      const w = world();
      expect(await runInstallWatch(["--fortress", w.fortress], ctx(w, over))).toBe(WATCH_EXIT_FAILED);
      expect(w.launchd.calls).toEqual([]);
      expect(w.writeOpens).toEqual([]);
    }
  });
});

describe("install-watch rollback", () => {
  it("boots out and removes the plist on a bootstrap failure and exits 1", async () => {
    const w = world();
    w.launchd.bootstrapOk = false;
    expect(await runInstallWatch(["--fortress", w.fortress], ctx(w))).toBe(WATCH_EXIT_FAILED);
    expect(w.launchd.calls).toContainEqual(["/bin/launchctl", "bootout", `gui/${UID}/${OBSERVER_LABEL}`]);
    expect(existsSync(observerPlist(w))).toBe(false);
    expect(w.out.text).toBe("");
  });

  it("exits 3 when the plist cannot be removed during rollback", async () => {
    const w = world();
    w.launchd.bootstrapOk = false;
    w.unlinkFails = observerPlist(w);
    expect(await runInstallWatch(["--fortress", w.fortress], ctx(w))).toBe(WATCH_EXIT_ROLLBACK_INCOMPLETE);
    w.unlinkFails = null;
  });

  it("exits 3 when the job is not confirmed unloaded during rollback", async () => {
    const w = world();
    w.launchd.bootstrapOk = false;
    const original = w.launchd.spawn;
    // Bootstrap fails but leaves the job loaded, and bootout does not unload it.
    w.launchd.spawn = (file, args, options) => { if (args[0] === "bootstrap") w.launchd.observerLoaded = true; return original(file, args, options); };
    w.runner = new BoundedChildRunner({ spawn: w.launchd.spawn, timers: { setTimeout: (f: () => void, ms: number) => setTimeout(f, ms), clearTimeout: (h: unknown) => clearTimeout(h as NodeJS.Timeout) } });
    w.launchd.bootoutUnloads = false;
    expect(await runInstallWatch(["--fortress", w.fortress], ctx(w))).toBe(WATCH_EXIT_ROLLBACK_INCOMPLETE);
  });
});

describe("uninstall-watch", () => {
  function withObserverRecord(w: World): string {
    const path = join(w.fortress, "liveness", "observer.json");
    writeFileSync(path, "{}\n", { mode: 0o600 });
    return path;
  }

  it("exits 0 with the canary file absent and the modelled not-found print, and never removes observer.json", async () => {
    const w = world();
    const record = withObserverRecord(w);
    w.launchd.observerLoaded = true;
    expect(await runUninstallWatch(["--fortress", w.fortress], ctx(w))).toBe(0);
    expect(w.launchd.calls).toContainEqual(["/bin/launchctl", "bootout", `gui/${UID}/${OBSERVER_LABEL}`]);
    expect(w.launchd.calls).toContainEqual(["/bin/launchctl", "print", `system/${CANARY_LABEL}`]);
    expect(existsSync(record)).toBe(true);
    expectNoEscalationOrConfigWrite(w);
  });

  it.each<[string, (w: World) => void]>([
    ["the canary file present", w => { w.canaryFile = "present"; }],
    ["a print showing the job", w => { w.launchd.canaryPrint = PRINTS.canary_system!; }],
  ])("prints exactly the attended removal text and exits 6 with %s", async (_case, edit) => {
    const w = world();
    const record = withObserverRecord(w);
    edit(w);
    expect(await runUninstallWatch(["--fortress", w.fortress], ctx(w))).toBe(WATCH_EXIT_CANARY_STILL_INSTALLED);
    expect(w.out.text).toBe(`The canary LaunchDaemon is still installed. A canary left loaded keeps producing drops that no observer reads.\n${ATTENDED_REMOVAL}`);
    expect(existsSync(record)).toBe(true);
  });

  it.each<[string, { code: number; stdout: string; stderr: string }]>([
    ["a refused print", { code: 1, stdout: "", stderr: "Operation not permitted\n" }],
    ["unparsable output", { code: 0, stdout: "garbage\n", stderr: "" }],
    ["a not-found code with another label", { ...PRINTS.captured_system_not_found!, stderr: PRINTS.captured_system_not_found!.stderr.replace(CANARY_LABEL, "other.label") }],
  ])("exits 1, never 0, on %s", async (_case, print) => {
    const w = world();
    const record = withObserverRecord(w);
    w.launchd.canaryPrint = print;
    expect(await runUninstallWatch(["--fortress", w.fortress], ctx(w))).toBe(WATCH_EXIT_FAILED);
    expect(existsSync(record)).toBe(true);
  });

  it("exits 1 when the observer job is not confirmed unloaded, and removes nothing", async () => {
    const w = world();
    const record = withObserverRecord(w);
    w.launchd.observerLoaded = true;
    w.launchd.bootoutUnloads = false;
    expect(await runUninstallWatch(["--fortress", w.fortress], ctx(w))).toBe(WATCH_EXIT_FAILED);
    expect(w.err.text).toContain("not confirmed unloaded");
    expect(w.launchd.calls).not.toContainEqual(["/bin/launchctl", "print", `system/${CANARY_LABEL}`]);
    expect(existsSync(record)).toBe(true);
  });

  it("exits 3 when the unloaded observer's plist cannot be removed", async () => {
    const w = world();
    const record = withObserverRecord(w);
    mkdirSync(join(w.home, "Library", "LaunchAgents"), { recursive: true, mode: 0o700 });
    writeFileSync(observerPlist(w), "<plist/>\n", { mode: 0o600 });
    w.unlinkFails = observerPlist(w);
    expect(await runUninstallWatch(["--fortress", w.fortress], ctx(w))).toBe(WATCH_EXIT_ROLLBACK_INCOMPLETE);
    expect(w.err.text).toContain("a plist could not be removed");
    expect(existsSync(record)).toBe(true);
    w.unlinkFails = null;
  });

  it("exits 1, never 0, when the print misses its deadline", async () => {
    vi.useFakeTimers();
    const w = world();
    w.launchd.canaryPrint = "hang";
    const code = runUninstallWatch(["--fortress", w.fortress], ctx(w));
    await vi.advanceTimersByTimeAsync(CHILD_READ_DEADLINE);
    expect(await code).toBe(WATCH_EXIT_FAILED);
  });
});

// ---------------------------------------------------------------------------
describe("run-watch", () => {
  const refuse = () => Promise.reject(new Error("fixture collector refused"));
  /**
   * Every collector fails, except that the first cycle's boot and record reads resolve the instance start (an instance
   * publishes nothing until it has read its own record and a boot), so the later failing cycles still publish.
   */
  function failingCollectors(): ObserverCollectors {
    let bootReads = 0;
    let recordReads = 0;
    const absent = { status: "absent" as const };
    return {
      readRecords: () => recordReads++ === 0 ? Promise.resolve({ directory: absent, daemon: absent, observer: absent, config: absent, readDeadlineHit: false }) : refuse(),
      readBootId: () => bootReads++ === 0 ? Promise.resolve("boot-fixture-current") : refuse(),
      queryAvailability: refuse, printFullAgent: refuse, readFullAgentState: refuse,
      readProcesses: refuse, printHarness: refuse, collectCanaryFacts: refuse,
    };
  }
  class CountingTimers {
    active = new Set<number>();
    private next = 1;
    setInterval(): unknown { const id = this.next++; this.active.add(id); return id; }
    clearInterval(h: unknown): void { this.active.delete(h as number); }
    setTimeout(): unknown { return 0; }
    clearTimeout(): void { /* inert */ }
  }
  function composition() {
    const timers = new CountingTimers();
    const series = new CensusSeries();
    let observer: LivenessObserver | null = null;
    const sampler = new CensusSampler({ series, runNetstat: async () => ({ status: "failed" }), context: () => observer!.samplingContext(), clock: { nowMs: () => 1, uptimeMs: () => 1 }, timers });
    const publishes = { started: 0, finished: 0 };
    observer = new LivenessObserver({
      fortressId: "fortress-0123456789abcdef", hostId: "host-fixture", operatorUid: UID, collectors: failingCollectors(), sampler, series,
      publisher: { publish: () => { publishes.started++; return new Promise<void>(done => setImmediate(() => { publishes.finished++; done(); })); } },
      clock: { nowMs: () => 1_794_225_600_000, uptimeMs: () => 36_000_000 }, timers, instance: "observer-run-watch-1",
    });
    const compose = vi.fn<(input: unknown) => { start(): void; stop(): Promise<void> }>(() => ({ start: () => observer!.start(), stop: () => observer!.stop() }));
    return { observer, timers, publishes, compose };
  }

  it.each<[string, Partial<WatchCommandContext>, (w: World) => void, string]>([
    // The fortress is modelled as root-owned here, so only the euid rule can refuse.
    ["euid 0", { euid: 0 }, w => { w.statUid = 0; }, "never as root"],
    ["non-darwin", { platform: "linux" }, () => undefined, "macOS only"],
    ["a fortress owned by another uid", {}, w => { w.statUid = UID + 7; }, "not a directory owned by this user"],
  ])("refuses %s with exit 1 and starts no cycle, silently in --launch-agent mode", async (_case, over, edit, reason) => {
    for (const launchAgent of [false, true]) {
      const w = world();
      edit(w);
      const c = composition();
      const argv = ["--fortress", w.fortress, ...(launchAgent ? ["--launch-agent"] : [])];
      expect(await runRunWatch(argv, ctx(w, { ...over, compose: c.compose, waitForStop: async () => undefined }))).toBe(WATCH_EXIT_FAILED);
      expect(c.compose).not.toHaveBeenCalled();
      expect(c.observer.stats().cycles).toBe(0);
      if (launchAgent) expect(w.out.text + w.err.text).toBe("");
      else expect(w.err.text).toContain(reason);
    }
  });

  it("on stop clears its timers, awaits the in-flight publish and exits 0; 100 failing cycles write nothing in --launch-agent mode", async () => {
    const w = world();
    const c = composition();
    const code = await runRunWatch(["--fortress", w.fortress, "--launch-agent"], ctx(w, {
      compose: c.compose,
      // The first cycle starts with the composition; drive the rest until 100 have completed.
      waitForStop: async () => { for (let i = 0; i < 200 && c.observer.stats().cycles < 100; i++) await c.observer.tick(); },
    }));
    expect(code).toBe(0);
    expect(c.compose).toHaveBeenCalledTimes(1);
    expect(c.compose.mock.calls[0]![0]).toMatchObject({ fortressPath: w.fortress, operatorUid: UID });
    expect(c.observer.stats().cycles).toBe(100);
    expect(c.timers.active.size).toBe(0);
    expect(c.publishes.started).toBeGreaterThan(0);
    expect(c.publishes.finished).toBe(c.publishes.started);
    expect(w.out.text).toBe("");
    expect(w.err.text).toBe("");
    expectNoEscalationOrConfigWrite(w);
  });

  it("refuses an unknown argument with usage exit 2 and no echo of the token", async () => {
    const w = world();
    const c = composition();
    expect(await runRunWatch(["--fortress", w.fortress, "--secret-token-value"], ctx(w, { compose: c.compose }))).toBe(2);
    expect(w.err.text).not.toContain("secret-token-value");
    expect(c.compose).not.toHaveBeenCalled();
  });
});
