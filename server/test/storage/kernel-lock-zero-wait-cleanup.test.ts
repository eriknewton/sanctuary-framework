/** Zero-wait kernel lock acquisition and stale socket cleanup invariants. */
import { spawn } from "node:child_process";
import { linkSync, lstatSync } from "node:fs";
import { chmod, mkdir, mkdtemp, rm } from "node:fs/promises";
import { createConnection, createServer, Server } from "node:net";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";
import {
  KERNEL_SOCKET_PATH_MAX_BYTES,
  withExclusiveMasterRotationBarrier,
  withPathLock,
} from "../../src/storage/cross-process-lock.js";
import { FilesystemStorage } from "../../src/storage/filesystem.js";

const SHORT_SOCKET_TMP_PARENT = process.platform === "darwin" ? "/private/tmp" : tmpdir();
const LOCK = ".unit";
// Must match CUSTODY_WRITE_LOCK_NAMESPACE / MASTER_ROTATION_BARRIER_NAME in src/core/master-custody.ts.
const NAMESPACE = "_meta";
const BARRIER = "custody-master-rotation";
const PRIVATE_DIRECTORY_MODE = 0o700;
const PRIVATE_SOCKET_MODE = 0o600;
const PERMISSION_BITS = 0o777;
const INITIAL_BINDS = 1;
const POST_CLEANUP_BINDS = 1;
const TOTAL_BINDS = INITIAL_BINDS + POST_CLEANUP_BINDS;
// Must match STALE_REAPER_TIMEOUT_MS in src/storage/cross-process-lock.ts.
const STALE_REAPER_TIMEOUT_MS = 2_000;
const CASE_TIMEOUT_MS = STALE_REAPER_TIMEOUT_MS * 5; // Five helper deadlines cover setup and disposal.
const CALLER_DEADLINE = 100; // Controlled monotonic units, independent of wall time.
const LOCAL_WAIT_MS = CALLER_DEADLINE + CALLER_DEADLINE;
// Must match BARRIER_SCAFFOLD_DIGEST_HEX_CHARS in src/storage/cross-process-lock.ts.
const DIGEST_HEX_CHARS = 40;
const roots: string[] = [];
const holders: Array<{ release: () => void; done: Promise<unknown> }> = [];
const children: Array<{ stop: () => void; done: Promise<unknown> }> = [];

function deferred() {
  let resolve!: () => void;
  const promise = new Promise<void>(done => { resolve = done; });
  return { promise, resolve };
}

function identity(path: string) {
  try {
    const stats = lstatSync(path, { bigint: true });
    return { dev: String(stats.dev), ino: String(stats.ino) };
  } catch {
    return undefined;
  }
}

function connectionResult(path: string): Promise<string> {
  return new Promise(resolve => {
    const socket = createConnection(path);
    let result = "closed";
    socket.once("connect", () => { result = "connected"; socket.destroy(); });
    socket.once("error", (error: NodeJS.ErrnoException) => { result = error.code ?? "error"; });
    socket.once("close", () => resolve(result));
  });
}

async function isolatedPaths() {
  const root = await mkdtemp(join(SHORT_SOCKET_TMP_PARENT, "zw-"));
  roots.push(root);
  vi.stubEnv("HOME", root);
  const target = join(root, "d");
  const runtimeRoot = join(root, "r");
  await mkdir(target, { mode: PRIVATE_DIRECTORY_MODE });
  // Longest socket is runtimeRoot + separator + 40 hex characters + '.sock'.
  // The sibling source name is shorter; capability names contain a pid and six random bytes in hex.
  const targetBytes = Buffer.byteLength(runtimeRoot) + Buffer.byteLength("/") + DIGEST_HEX_CHARS + Buffer.byteLength(".sock");
  const probeBytes = Buffer.byteLength(join(runtimeRoot, `.probe-${process.pid}-${"a".repeat(12)}.sock`)); // Six bytes yield twelve hex characters.
  expect(Math.max(targetBytes, probeBytes)).toBeLessThanOrEqual(KERNEL_SOCKET_PATH_MAX_BYTES);
  return { root, target, runtimeRoot };
}

async function learnPath(target: string, runtimeRoot: string) {
  let path = "";
  await withPathLock(target, LOCK, async () => undefined, {
    kernelBacked: true, runtimeRoot,
    __testAfterKernelSocketAcquired: value => { path = value; },
  });
  return path;
}

async function plantStale(path: string) {
  const source = join(dirname(path), "s.sock");
  const server = createServer(socket => socket.destroy());
  try {
    await new Promise<void>((resolve, reject) => {
      server.once("error", reject);
      server.listen({ path: source }, resolve);
    });
    linkSync(source, path);
  } finally {
    if (server.listening) await new Promise<void>(resolve => server.close(() => resolve()));
  }
  await chmod(path, PRIVATE_SOCKET_MODE);
  return identity(path);
}

function countBinds(path: string, included = () => true) {
  const original = Server.prototype.listen;
  let count = 0;
  vi.spyOn(Server.prototype, "listen").mockImplementation(function (this: Server, ...args: Parameters<Server["listen"]>) {
    const options: unknown = args[0];
    if (included() && typeof options === "object" && options !== null && "path" in options && options.path === path) count++;
    return Reflect.apply(original, this, args);
  } as Server["listen"]);
  return () => count;
}

async function startHolder(target: string, runtimeRoot: string) {
  const acquired = deferred();
  const released = deferred();
  let path = "";
  let acquiredIdentity: ReturnType<typeof identity>;
  const done = withPathLock(target, LOCK, async () => {
    acquired.resolve();
    await released.promise;
  }, {
    kernelBacked: true, runtimeRoot,
    __testAfterKernelSocketAcquired: value => { path = value; acquiredIdentity = identity(value); },
  }).then(() => "released", error => { acquired.resolve(); return error; });
  const holder = { release: released.resolve, done };
  holders.push(holder);
  await acquired.promise;
  return { ...holder, path, acquiredIdentity };
}

async function settled(operation: Promise<unknown>) {
  return operation.then(() => "admitted", (error: { kind?: string }) => error.kind ?? "unexpected");
}

afterEach(async () => {
  for (const holder of holders.splice(0)) { holder.release(); await holder.done; }
  for (const child of children.splice(0)) { child.stop(); await child.done; }
  vi.restoreAllMocks();
  vi.unstubAllEnvs();
  for (const root of roots.splice(0)) await rm(root, { recursive: true, force: true });
});

describe.runIf(process.platform === "linux" || process.platform === "darwin")("zero-wait kernel lock acquisition", () => {
  it("Z1: one zero-wait exclusive barrier call is admitted after cleaning up a socket left by an exited holder", async () => {
    const { root, runtimeRoot } = await isolatedPaths();
    vi.stubEnv("SANCTUARY_CUSTODY_LOCK_ROOT", runtimeRoot);
    const storage = new FilesystemStorage(join(root, "f"));
    await storage.write(NAMESPACE, "seed", Buffer.from("seed"));
    let path = "";
    await withExclusiveMasterRotationBarrier(storage, NAMESPACE, BARRIER, async () => undefined, {
      __testAfterExclusiveSocketAcquired: value => { path = value; },
    });
    const child = spawn(process.execPath, ["-e", `
      const { createServer } = require('node:net');
      const { chmodSync } = require('node:fs');
      const path = process.argv[1];
      const server = createServer(socket => socket.destroy());
      server.listen({ path }, () => {
        chmodSync(path, ${PRIVATE_SOCKET_MODE});
        process.stdout.write('ready\\n', () => process.exit(0));
      });
    `, path], { stdio: ["ignore", "pipe", "pipe"] });
    let output = "";
    const ready = deferred();
    child.stdout.on("data", (chunk: Buffer) => { output += chunk.toString(); if (output.includes("ready\n")) ready.resolve(); });
    const exited = new Promise<{ code: number | null; signal: string | null }>(resolve => {
      child.once("exit", (code, signal) => { ready.resolve(); resolve({ code, signal }); });
      child.once("error", () => { ready.resolve(); resolve({ code: null, signal: "error" }); });
    });
    const closed = new Promise<void>(resolve => child.once("close", () => resolve()));
    children.push({ stop: () => { if (child.exitCode === null && child.signalCode === null) child.kill("SIGKILL"); }, done: closed });
    await ready.promise;
    expect(await exited).toEqual({ code: 0, signal: null });
    await closed;
    expect(output).toBe("ready\n");
    expect(lstatSync(path).isSocket()).toBe(true);
    expect(await connectionResult(path)).toBe("ECONNREFUSED");
    const staleIdentity = identity(path);
    // Retain the old inode so allocator reuse cannot obscure listener identity.
    linkSync(path, join(runtimeRoot, "retained"));
    let callbacks = 0;
    let observed: unknown;
    const outcome = await settled(withExclusiveMasterRotationBarrier(storage, NAMESPACE, BARRIER, async () => {
      callbacks++;
      const stats = lstatSync(path);
      observed = { socket: stats.isSocket(), mode: stats.mode & PERMISSION_BITS, uid: stats.uid,
        connection: await connectionResult(path), fresh: identity(path)?.ino !== staleIdentity?.ino };
    }, { timeoutMs: 0, __testAfterExclusiveSocketAcquired: value => { path = value; } }));
    expect({ outcome, callbacks }, "zero-wait admission").toEqual({ outcome: "admitted", callbacks: 1 });
    expect(observed, "post-cleanup listener").toEqual({ socket: true, mode: PRIVATE_SOCKET_MODE,
      uid: process.getuid!(), connection: "connected", fresh: true });
  }, CASE_TIMEOUT_MS);

  it("Z2: a live holder is refused at once with no cleanup and no further bind", async () => {
    const { target, runtimeRoot } = await isolatedPaths();
    const holder = await startHolder(target, runtimeRoot);
    const binds = countBinds(holder.path);
    let callbacks = 0;
    let cleanups = 0;
    let captured: ReturnType<typeof identity>;
    const outcome = await settled(withPathLock(target, LOCK, async () => { callbacks++; }, {
      kernelBacked: true, runtimeRoot, timeoutMs: 0,
      __testAfterStaleReaperStarted: () => { cleanups++; },
      onContended: () => { if (captured === undefined) captured = identity(holder.path); }, // Records only; the holder is released after the call settles.
    }));
    holder.release();
    await holder.done;
    expect(outcome, "live holder outcome").toBe("contention");
    expect(callbacks, "live holder callbacks").toBe(0);
    expect(binds(), "live holder binds").toBe(INITIAL_BINDS);
    expect(cleanups, "live holder cleanup").toBe(0);
    expect(captured, "live holder intact").toEqual(holder.acquiredIdentity);
  }, CASE_TIMEOUT_MS);

  it("Z3: a holder that binds after cleanup is refused without waiting for its release", async () => {
    const { target, runtimeRoot } = await isolatedPaths();
    const path = await learnPath(target, runtimeRoot);
    await plantStale(path);
    let inHook = false;
    const binds = countBinds(path, () => !inHook);
    let holder: Awaited<ReturnType<typeof startHolder>> | undefined;
    let captured: ReturnType<typeof identity>;
    let callbacks = 0;
    let cleanups = 0;
    let hookCalls = 0;
    const outcome = await settled(withPathLock(target, LOCK, async () => { callbacks++; }, {
      kernelBacked: true, runtimeRoot, timeoutMs: 0,
      __testAfterStaleReaperStarted: () => { cleanups++; },
      __testAfterStaleSocketReaped: async () => {
        hookCalls++;
        if (hookCalls !== 1) return;
        inHook = true;
        try { holder = await startHolder(target, runtimeRoot); } finally { inHook = false; }
      },
      onContended: () => { if (holder && captured === undefined) captured = identity(path); }, // Records only; the holder is released after the call settles.
    }));
    holder?.release();
    await holder?.done;
    expect(outcome, "rebind outcome").toBe("contention");
    expect(callbacks, "rebind callbacks").toBe(0);
    expect(binds(), "rebind binds").toBe(TOTAL_BINDS);
    expect({ captured, acquired: holder?.acquiredIdentity, cleanups }, "rebind holder intact").toEqual({
      captured: expect.objectContaining({ dev: expect.any(String), ino: expect.any(String) }),
      acquired: captured, cleanups: 1,
    });
  }, CASE_TIMEOUT_MS);

  it("Z4: a second stale socket after cleanup is refused without another cleanup or bind", async () => {
    const { target, runtimeRoot } = await isolatedPaths();
    const path = await learnPath(target, runtimeRoot);
    await plantStale(path);
    const binds = countBinds(path);
    let callbacks = 0;
    let cleanups = 0;
    let hookCalls = 0;
    let planted: ReturnType<typeof identity>;
    const outcome = await settled(withPathLock(target, LOCK, async () => { callbacks++; }, {
      kernelBacked: true, runtimeRoot, timeoutMs: 0,
      __testAfterStaleReaperStarted: () => { cleanups++; },
      __testAfterStaleSocketReaped: async () => { hookCalls++; if (hookCalls === 1) planted = await plantStale(path); },
    }));
    expect(outcome, "second stale outcome").toBe("contention");
    expect(callbacks, "second stale callbacks").toBe(0);
    expect(binds(), "second stale binds").toBe(TOTAL_BINDS);
    expect(cleanups, "second stale cleanup").toBe(1);
    expect(identity(path), "second stale inode kept").toEqual(planted);
  }, CASE_TIMEOUT_MS);

  it("Z5: a caller deadline that expires during cleanup gains no bind attempt", async () => {
    const { target, runtimeRoot } = await isolatedPaths();
    const path = await learnPath(target, runtimeRoot);
    await plantStale(path);
    const binds = countBinds(path);
    let clock = 0;
    let callbacks = 0;
    let cleanups = 0;
    const outcome = await settled(withPathLock(target, LOCK, async () => { callbacks++; }, {
      kernelBacked: true, runtimeRoot, timeoutMs: LOCAL_WAIT_MS, monotonicDeadlineMs: CALLER_DEADLINE,
      __testMonotonicNow: () => clock,
      __testAfterStaleReaperStarted: () => { cleanups++; },
      __testAfterStaleSocketReaped: () => { clock = CALLER_DEADLINE; },
    }));
    expect(outcome, "deadline outcome").toBe("contention");
    expect(callbacks, "deadline callbacks").toBe(0);
    expect(binds(), "deadline binds").toBe(INITIAL_BINDS);
    expect(cleanups, "deadline cleanup").toBe(1);
  }, CASE_TIMEOUT_MS);

  it("Z6: a zero local wait that carries a caller deadline stays ineligible and never binds", async () => {
    const { target, runtimeRoot } = await isolatedPaths();
    const path = await learnPath(target, runtimeRoot);
    await plantStale(path);
    const binds = countBinds(path);
    let callbacks = 0;
    let cleanups = 0;
    // An explicit deadline makes the call ineligible, so the zero local wait expires at the first loop-head budget check.
    const outcome = await settled(withPathLock(target, LOCK, async () => { callbacks++; }, {
      kernelBacked: true, runtimeRoot, timeoutMs: 0, monotonicDeadlineMs: CALLER_DEADLINE,
      __testMonotonicNow: () => 0,
      __testAfterStaleReaperStarted: () => { cleanups++; },
    }));
    expect(outcome, "ineligible outcome").toBe("contention");
    expect(callbacks, "ineligible callbacks").toBe(0);
    expect(binds(), "ineligible binds").toBe(0);
    expect(cleanups, "ineligible cleanup").toBe(0);
  }, CASE_TIMEOUT_MS);
});
