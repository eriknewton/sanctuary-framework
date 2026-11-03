import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { cp, lstat, mkdir, mkdtemp, rm, unlink } from "node:fs/promises";
import { dirname, join } from "node:path";
import { tmpdir } from "node:os";
import { fileURLToPath } from "node:url";

const castleWallMocks = vi.hoisted(() => {
  const stop = vi.fn(async () => undefined);
  return {
    runProvisionPin: vi.fn(async () => 0),
    stop,
    startMacOSCastleWallDaemon: vi.fn(async () => ({
      stop,
    })),
  };
});

vi.mock("../../src/cli/castle-wall.js", () => ({
  runProvisionPin: castleWallMocks.runProvisionPin,
}));

vi.mock("../../src/castle-wall/runtime/index.js", () => ({
  startMacOSCastleWallDaemon: castleWallMocks.startMacOSCastleWallDaemon,
  isLinuxProducerSignedActivationRequested: () => false,
}));

import {
  __processShutdownCleanupCountForTest,
  __resetProcessShutdownStateForTest,
  handleProcessShutdownSignal,
  runWrap,
  type RunWrapDeps,
} from "../../src/wrap/cli.js";
import { AuditLog } from "../../src/operational/audit-log.js";
import type { AutoProvisionSummary } from "../../src/wrap/auto-provision.js";
import {
  agreeingHermesParity,
  clearHermesParityHook,
  installHermesParityHook,
} from "../helpers/hermes-parity.js";

const __dirname = dirname(fileURLToPath(import.meta.url));
const fixturesDir = join(__dirname, "..", "harness", "fixtures");

function deferred<T = void>(): {
  promise: Promise<T>;
  resolve: (value?: T | PromiseLike<T>) => void;
} {
  let resolve!: (value?: T | PromiseLike<T>) => void;
  const promise = new Promise<T>((res) => {
    resolve = res;
  });
  return { promise, resolve };
}

describe("protect --hermes --no-dashboard transient Castle Wall cleanup", () => {
  let tmpHome: string;
  let originalHome: string | undefined;
  let originalStoragePath: string | undefined;
  let originalPassphrase: string | undefined;

  beforeEach(async () => {
    tmpHome = await mkdtemp(join(tmpdir(), "sanctuary-no-dashboard-daemon-"));
    originalHome = process.env.HOME;
    originalStoragePath = process.env.SANCTUARY_STORAGE_PATH;
    originalPassphrase = process.env.SANCTUARY_PASSPHRASE;
    process.env.HOME = tmpHome;
    process.env.SANCTUARY_STORAGE_PATH = join(tmpHome, ".sanctuary");
    process.env.SANCTUARY_PASSPHRASE = "test-passphrase";
    installHermesParityHook(agreeingHermesParity);
    vi.spyOn(console, "error").mockImplementation(() => {});
    castleWallMocks.runProvisionPin.mockClear();
    castleWallMocks.stop.mockClear();
    castleWallMocks.startMacOSCastleWallDaemon.mockClear();
    castleWallMocks.startMacOSCastleWallDaemon.mockResolvedValue({
      stop: castleWallMocks.stop,
    });

    const hermesDir = join(tmpHome, ".hermes");
    await mkdir(hermesDir, { recursive: true });
    await cp(join(fixturesDir, "hermes.json"), join(hermesDir, "cli-config.json"));
  });

  afterEach(async () => {
    __resetProcessShutdownStateForTest();
    vi.restoreAllMocks();
    clearHermesParityHook();
    if (originalHome === undefined) delete process.env.HOME;
    else process.env.HOME = originalHome;
    if (originalStoragePath === undefined) delete process.env.SANCTUARY_STORAGE_PATH;
    else process.env.SANCTUARY_STORAGE_PATH = originalStoragePath;
    if (originalPassphrase === undefined) delete process.env.SANCTUARY_PASSPHRASE;
    else process.env.SANCTUARY_PASSPHRASE = originalPassphrase;
    await rm(tmpHome, { recursive: true, force: true });
  });

  it("F10: stops the transient daemon on normal --no-dashboard exit even when provisioning refused before install-boot", async () => {
    const runAutoProvisionForWrap = vi.fn(async (): Promise<AutoProvisionSummary> => ({
      ran: true,
      outcome: {
        kind: "aborted",
        stage: "root-check",
        reason: "auto-provisioning requires root; re-run with sudo.",
        rolledBack: false,
        rehomeAttempted: false,
      },
    }));
    const deps: RunWrapDeps = {
      runAutoProvisionForWrap,
      startDashboard: vi.fn(),
      openBrowser: vi.fn(async () => undefined),
      resolvePassphrase: async () => ({
        value: "test-passphrase",
        location: "test-keychain",
        source: "generated",
      }),
    };

    await runWrap({ hermes: true, noOpen: true, noDashboard: true }, deps);

    expect(castleWallMocks.startMacOSCastleWallDaemon).toHaveBeenCalledTimes(1);
    expect(runAutoProvisionForWrap).toHaveBeenCalledTimes(1);
    expect(castleWallMocks.stop).toHaveBeenCalledTimes(1);
    expect(__processShutdownCleanupCountForTest()).toBe(0);
  });

  it("registers the --no-dashboard audit flush during setup, then unregisters it after the explicit flush", async () => {
    const exitSpy = vi.spyOn(process, "exit").mockImplementation(((
      _code?: number,
    ) => undefined) as never);
    const flushSpy = vi.spyOn(AuditLog.prototype, "flush");
    const registeredFlushEntered = deferred();
    const releaseRegisteredFlush = deferred();
    let flushCalls = 0;
    let blockedRegisteredFlush = false;
    flushSpy.mockImplementation(async function (
    ): Promise<void> {
      flushCalls += 1;
      if (!blockedRegisteredFlush && __processShutdownCleanupCountForTest() > 0) {
        blockedRegisteredFlush = true;
        registeredFlushEntered.resolve();
        await releaseRegisteredFlush.promise;
      }
    });
    const runAutoProvisionForWrap = vi.fn(async (): Promise<AutoProvisionSummary> => ({
      ran: true,
      outcome: {
        kind: "aborted",
        stage: "root-check",
        reason: "auto-provisioning requires root; re-run with sudo.",
        rolledBack: false,
        rehomeAttempted: false,
      },
    }));
    const deps: RunWrapDeps = {
      runAutoProvisionForWrap,
      startDashboard: vi.fn(),
      openBrowser: vi.fn(async () => undefined),
      resolvePassphrase: async () => ({
        value: "test-passphrase",
        location: "test-keychain",
        source: "generated",
      }),
    };

    const run = runWrap({ hermes: true, noOpen: true, noDashboard: true }, deps);
    await registeredFlushEntered.promise;
    const flushCallsBeforeSignal = flushCalls;

    await handleProcessShutdownSignal("SIGTERM");

    expect(exitSpy).toHaveBeenCalledWith(143);
    expect(flushCalls).toBeGreaterThan(flushCallsBeforeSignal);

    releaseRegisteredFlush.resolve();
    await run;
    expect(__processShutdownCleanupCountForTest()).toBe(0);
  });
});

import { spawn, type ChildProcess } from "node:child_process";
import { connect } from "node:net";
// Must match the wrap role in test/fixtures/lock-teardown-child.ts.
describe.runIf(process.platform === "linux")("lock teardown through protect", () => {
const fixture = fileURLToPath(new URL("../fixtures/lock-teardown-child.ts", import.meta.url));
// Must match test/fixtures/lock-teardown-child.ts: one command and response per role.
type Command = "RELEASE" | "CHECK" | "EXIT" | "EXPIRE" | "CONTINUE";
type Message = { directory?: string; overflowDenied?: boolean; denied?: number; queue?: number; writes?: number; spent?: number; expectedSpent?: number; boundaryLosses?: number; live?: number; before?: number; afterResult?: number; afterEvent?: number; pendingBefore?: boolean; afterEventPending?: boolean; closeCalls?: number; firstKind?: string; firstFailed?: boolean; sameRepeat?: boolean; sameConcurrent?: boolean; delivered?: number; aborts?: number; unregistered?: boolean; successorIntact?: boolean; reacquired?: number; exists?: boolean; primaryPreserved?: boolean; guardInCatch?: number; sameLockCallbacks?: number; sameLockKind?: string; otherCallbacks?: number; contendingCallbacks?: number; refusals?: number; heldStats?: number; readOnly?: number; inert?: number; reached?: boolean; available?: boolean; originalCause?: boolean; closes?: number; closeEvents?: number; observed?: string; phase: string; path?: string; held?: boolean; errors?: Array<{ kind?: string; message: string }>; guardAtUnref?: number; callbackCount?: number;
  losses?: number; refused?: number; callbacks?: number; unexpected?: number; artifacts?: number; binds?: number; retained?: number; guards?: number; exportedBudget?: number };
const STDERR_CAP_BYTES = 16_384; // 16 KiB, 1024 bytes per KiB.
const LINE_BUFFER_CAP_BYTES = 65_536; // 64 KiB, 1024 bytes per KiB.
const STEP_TIMEOUT_MS = 15_000; // One lifecycle fixture RPC budget.
const TEST_TIMEOUT_MS = STEP_TIMEOUT_MS * 10; // Two imports plus eight protocol steps.
const owned: Array<{ child: ChildProcess; done: Promise<{ code: number | null; signal: string | null }> }> = [];
const roots: string[] = [];

async function launch(root: string, role: string, shape = "numeric0", implementation = "source", extraEnv: Record<string, string> = {}) {
  const home = join(root, role);
  await mkdir(home, { mode: 0o700 });
  const child = spawn(process.execPath, ["--unhandled-rejections=throw", "--import", "tsx", fixture, role, shape, implementation], {
    detached: true,
    stdio: ["ignore", "pipe", "pipe", "ipc"],
    env: { PATH: process.env.PATH, HOME: home, TMPDIR: home, VITEST: "true",
      SANCTUARY_CUSTODY_LOCK_ROOT: join(root, "locks"), SANCTUARY_STORAGE_PATH: join(home, "fortress"),
      SANCTUARY_NO_UPDATE_CHECK: "1", LK1_TARGET: join(root, "state"), ...extraEnv },
  });
  let stderr = "", stdout = "";
  let failure: Error | undefined;
  let receiver: { phase: string; resolve: (message: Message) => void; reject: (error: Error) => void } | undefined;
  const queued: Message[] = [];
  child.stderr!.on("data", (data: Buffer) => { stderr = (stderr + data.toString()).slice(-STDERR_CAP_BYTES); });
  child.stdout!.on("data", (data: Buffer) => {
    stdout += data.toString();
    if (Buffer.byteLength(stdout) > LINE_BUFFER_CAP_BYTES) fail(new Error("fixture stdout overflow"));
  });
  function fail(error: Error) { failure = error; receiver?.reject(error); }
  child.on("message", (message: Message) => {
    if (receiver) {
      const current = receiver; receiver = undefined;
      if (message.phase === current.phase) current.resolve(message);
      else current.reject(new Error(`expected ${current.phase}, received ${message.phase}`));
    } else {
      if (queued.length >= 2) fail(new Error("fixture message overflow")); // READY and HELD may arrive before observation.
      else queued.push(message);
    }
  });
  const done = new Promise<{ code: number | null; signal: string | null }>((resolve, reject) => {
    child.once("error", error => { fail(error); reject(error); });
    child.once("close", (code, signal) => {
      if (receiver) fail(new Error(`fixture exited before ${receiver.phase}: ${stderr}`));
      resolve({ code, signal });
    });
  });
  owned.push({ child, done });
  function phase(name: string): Promise<Message> {
    if (failure) return Promise.reject(failure);
    const message = queued.shift();
    if (message) return message.phase === name ? Promise.resolve(message) : Promise.reject(new Error(`unexpected ${message.phase}`));
    if (receiver) return Promise.reject(new Error("duplicate fixture observer"));
    let timer: ReturnType<typeof setTimeout>;
    return new Promise<Message>((resolve, reject) => {
      timer = setTimeout(() => { receiver = undefined; reject(new Error(`fixture phase timeout ${name}: ${stderr}`)); }, STEP_TIMEOUT_MS);
      receiver = { phase: name, resolve, reject };
    }).finally(() => clearTimeout(timer));
  }
  function command(value: Command) { child.send(value); }
  return { child, done, phase, command, stderr: () => stderr, stdout: () => stdout };
}

afterEach(async () => {
  for (const { child, done } of owned.splice(0)) {
    if (child.exitCode === null && child.signalCode === null && child.pid) {
      try { process.kill(-child.pid, "SIGKILL"); } catch { child.kill("SIGKILL"); }
    }
    await done;
  }
  for (const root of roots.splice(0)) await rm(root, { recursive: true, force: true });
});

async function connectable(path: string): Promise<boolean> {
  return new Promise(resolve => {
    const socket = connect(path);
    socket.once("connect", () => { socket.destroy(); resolve(true); });
    socket.once("error", () => { socket.destroy(); resolve(false); });
    socket.setTimeout(STEP_TIMEOUT_MS, () => { socket.destroy(); resolve(false); });
  });
}

  for (const shape of ["pin", "identity", "healthy"] as const) {
    it(`T11 ${shape === "healthy" ? "E" : "R"}: real wrap ${shape} returns after daemon stop`, async () => {
      const root = await mkdtemp(join(tmpdir(), "lk1-")); roots.push(root);
      const holder = await launch(root, "wrap", shape);
      await holder.phase("READY");
      let successor: Awaited<ReturnType<typeof launch>> | undefined;
      let path: string | undefined, ino: bigint | undefined;
      if (shape !== "healthy") {
        const fault = await holder.phase("FAULT_REACHED");
        expect(fault.reached).toBe(true);
        if (shape === "identity") expect((fault as Message & { floorReached: boolean }).floorReached).toBe(true);
        path = fault.path!;
        await unlink(path); await expect(lstat(path)).rejects.toMatchObject({ code: "ENOENT" });
        successor = await launch(root, "successor", "numeric0", "source", { LK1_TARGET: fault.directory!, LK1_DIRECT_LOCK: "custody-master.lock" });
        await successor.phase("READY"); expect((await successor.phase("HELD")).path).toBe(path);
        ino = (await lstat(path, { bigint: true })).ino;
        holder.command("RELEASE");
      }
      expect(await holder.phase("DISPOSAL_SETTLED")).toMatchObject({ reached: shape !== "healthy", starts: 1, stops: 1 });
      if (shape === "pin") expect(holder.stderr()).toContain("auto-bootstrap exited 1");
      holder.command("EXIT"); await holder.phase("RETURNED"); expect(await holder.done).toEqual({ code: 0, signal: null });
      if (successor && path) {
        expect((await lstat(path, { bigint: true }).catch(() => null))?.ino, "wrap successor survives returned process").toBe(ino);
        expect(await connectable(path)).toBe(true);
        successor.command("CHECK"); expect((await successor.phase("CHECKED")).held).toBe(true);
        successor.command("RELEASE"); expect((await successor.phase("DISPOSAL_SETTLED")).errors).toEqual([]);
        successor.command("EXIT"); await successor.phase("RETURNED"); expect(await successor.done).toEqual({ code: 0, signal: null });
      }
    }, TEST_TIMEOUT_MS);
  }
});
