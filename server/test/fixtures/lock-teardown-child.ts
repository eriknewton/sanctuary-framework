import { syncBuiltinESMExports } from "node:module";
import { Server } from "node:net";
import fsPromises from "node:fs/promises";
import { installInMemoryKeychainStore } from "../setup/keychain-memory-store.js";

installInMemoryKeychainStore();

// Must match the command protocols in test/storage/lock-teardown-ownership.test.ts
// and test/wrap/protect-no-dashboard-daemon-cleanup.test.ts.
type Command = "RELEASE" | "CHECK" | "EXIT" | "EXPIRE" | "CONTINUE";
let pending: { command: Command; resolve: () => void } | undefined;
process.on("message", (message: unknown) => {
  if (!pending || message !== pending.command) throw new Error("unexpected lock fixture command");
  const resolve = pending.resolve;
  pending = undefined;
  resolve();
});
function next(command: Command): Promise<void> {
  if (pending) throw new Error("duplicate lock fixture command");
  return new Promise(resolve => { pending = { command, resolve }; });
}
function report(phase: string, data: Record<string, unknown> = {}): void {
  process.send!({ phase, ...data });
}
function errors(error: unknown): Array<{ kind?: string; message: string }> {
  if (error instanceof AggregateError) return error.errors.flatMap(errors);
  return [{ kind: (error as { kind?: string })?.kind, message: error instanceof Error ? error.message : String(error) }];
}

const role = process.argv[2]!;
const shape = process.argv[3]!;
const implementation = process.argv[4]!;
const target = process.env.LK1_TARGET!;
let guardAtUnref = -1;
const originalUnref = Server.prototype.unref;
Server.prototype.unref = function () {
  const count = process.listenerCount("beforeExit");
  guardAtUnref = guardAtUnref < 0 ? count : Math.min(guardAtUnref, count);
  return originalUnref.call(this);
};
syncBuiltinESMExports();

const { FilesystemStorage } = implementation === "built"
  ? await import("../../dist/index.js")
  : await import("../../src/storage/filesystem.js");
if (role === "wrap") {
  const { registerHooks } = await import("node:module");
  const { join } = await import("node:path");
  const { createHash } = await import("node:crypto");
  let stops = 0, starts = 0;
  const runtimeKey = Symbol.for("lk1.fixture.wrap.runtime");
  (globalThis as Record<symbol, unknown>)[runtimeKey] = {
    start: async () => { starts++; return { stop: async () => { stops++; } }; },
  };
  registerHooks({ resolve(specifier, context, nextResolve) {
    if (specifier === "../castle-wall/runtime/index.js" && context.parentURL?.includes("/wrap/cli.")) {
      const source = 'const stub = globalThis[Symbol.for("lk1.fixture.wrap.runtime")]; export const startMacOSCastleWallDaemon = stub.start; export const isLinuxProducerSignedActivationRequested = () => false;';
      return { url: `data:text/javascript,${encodeURIComponent(source)}`, shortCircuit: true };
    }
    return nextResolve(specifier, context);
  } });
  const { CUSTODY_ENVELOPE_COMMIT_JOURNAL_KEY, CUSTODY_WRITE_LOCK_FILE } = await import("../../src/core/master-custody.js");
  let journal: Uint8Array | undefined, reached = false, floorReached = false;
  const remove = FilesystemStorage.prototype.delete;
  FilesystemStorage.prototype.delete = async function (...args: Parameters<typeof remove>) {
    if (args[0] === "_meta" && args[1] === CUSTODY_ENVELOPE_COMMIT_JOURNAL_KEY) {
      const raw = await this.read(args[0], args[1]); if (raw) journal = raw.slice();
    }
    return Reflect.apply(remove, this, args);
  };
  const { IdentityManager } = await import("../../src/cognitive/tools.js");
  const save = IdentityManager.prototype.save;
  IdentityManager.prototype.save = async function (...args: Parameters<typeof save>) {
    if (shape === "identity") {
      if (!journal) throw new Error("wrap journal capture missing");
      const storage = new FilesystemStorage(join(process.env.SANCTUARY_STORAGE_PATH!, "state"));
      await storage.write("_meta", CUSTODY_ENVELOPE_COMMIT_JOURNAL_KEY, journal);
    }
    return Reflect.apply(save, this, args);
  };
  const withLock = FilesystemStorage.prototype.withNamespaceLock;
  FilesystemStorage.prototype.withNamespaceLock = async function (this: InstanceType<typeof FilesystemStorage>, namespace, filename, operation, options) {
    const stack = new Error().stack ?? "";
    const selected = shape === "pin" ? stack.includes("runProvisionPin") : stack.includes("enforceCustodyFloor");
    if (shape === "healthy" || reached || namespace !== "_meta" || filename !== CUSTODY_WRITE_LOCK_FILE || !selected) {
      return withLock.call(this, namespace, filename, operation, options);
    }
    floorReached = stack.includes("enforceCustodyFloor");
    const directory = this.namespacePath(namespace);
    return withLock.call(this, namespace, filename, async lease => {
      reached = true;
      const stats = await fsPromises.lstat(directory, { bigint: true });
      const digest = createHash("sha256").update(`${stats.dev}:${stats.ino}:${filename}`).digest("hex");
      const path = join(process.env.SANCTUARY_CUSTODY_LOCK_ROOT!, `${digest.slice(0, 40)}.sock`);
      const released = next("RELEASE");
      report("FAULT_REACHED", { reached, floorReached, directory, path });
      await released;
      return operation(lease);
    }, options);
  } as typeof withLock;
  const home = process.env.HOME!;
  await fsPromises.mkdir(join(home, ".hermes"), { mode: 0o700 });
  await fsPromises.copyFile(new URL("../harness/fixtures/hermes.json", import.meta.url), join(home, ".hermes/cli-config.json"));
  const { runWrap } = await import("../../src/wrap/cli.js");
  report("READY");
  await runWrap({ hermes: true, noOpen: true, noDashboard: true }, {
    runAutoProvisionForWrap: async () => ({ ran: true, outcome: { kind: "aborted", stage: "root-check", reason: "fixture install refused", rolledBack: false, rehomeAttempted: false } }),
    openBrowser: async () => undefined,
    resolvePassphrase: async () => ({ value: "fixture-passphrase", location: "test-keychain", source: "generated" }),
  });
  const exit = next("EXIT");
  report("DISPOSAL_SETTLED", { reached, floorReached, starts, stops });
  await exit; report("RETURNED"); process.disconnect!();
} else if (role === "quota-waves") {
  const { createHash } = await import("node:crypto");
  const { join } = await import("node:path");
  const gateModule = await import("../../src/principal-policy/gate.js");
  const { DEFAULT_POLICY } = await import("../../src/principal-policy/loader.js");
  const { CallbackApprovalChannel } = await import("../../src/principal-policy/approval-channel.js");
  const { OWN_SCOPE_SAVE_MAX_PER_WINDOW: cap, OWN_SCOPE_SAVE_MAX_QUEUED_ADMISSIONS: queue, OWN_SCOPE_SAVE_ADMISSION_DEADLINE_MS: deadline } = gateModule;
  await fsPromises.mkdir(target, { recursive: true, mode: 0o700 });
  const quotaPath = join(target, "own-scope-save-quota.json");
  const caller = createHash("sha256").update("agent:owner").digest("hex");
  await fsPromises.writeFile(quotaPath, JSON.stringify([[caller, Date.now(), cap - 3, cap - 3]]));
  const directory = await fsPromises.lstat(target, { bigint: true });
  const digest = createHash("sha256").update(`${directory.dev}:${directory.ino}:own-scope-save-quota.lock`).digest("hex");
  const path = join(process.env.SANCTUARY_CUSTODY_LOCK_ROOT!, `${digest.slice(0, 40)}.sock`);
  const originalOpen = fsPromises.open;
  let releaseWriter!: () => void, enteredWriter!: () => void;
  let pausedWrite: Promise<void>, writeReached: Promise<void>;
  let writes = 0;
  fsPromises.open = (async (...args: Parameters<typeof originalOpen>) => {
    const handle = await originalOpen(...args);
    if (!String(args[0]).includes(".own-scope-save-quota.json.")) return handle;
    return new Proxy(handle, { get(object, key) {
      if (key === "writeFile") return async (...writeArgs: unknown[]) => {
        writes++; enteredWriter(); await pausedWrite;
        return Reflect.apply(object.writeFile, object, writeArgs);
      };
      const value = Reflect.get(object, key, object);
      return typeof value === "function" ? value.bind(object) : value;
    } });
  }) as typeof originalOpen;
  syncBuiltinESMExports();
  const originalTimeout = globalThis.setTimeout, originalClear = globalThis.clearTimeout;
  const timers = new Map<object, () => void>();
  globalThis.setTimeout = ((callback: () => void, ms?: number, ...args: unknown[]) => {
    if (ms === deadline) { const key = {}; timers.set(key, callback); return key; }
    return Reflect.apply(originalTimeout, globalThis, [callback, ms, ...args]);
  }) as typeof setTimeout;
  globalThis.clearTimeout = ((timer: object) => { if (!timers.delete(timer)) Reflect.apply(originalClear, globalThis, [timer]); }) as typeof clearTimeout;
  const originalCatch = Promise.prototype.catch;
  const boundary: unknown[] = [];
  Promise.prototype.catch = function (onRejected) {
    const gateBoundary = new Error().stack?.includes("principal-policy/gate.ts") === true;
    if (!gateBoundary) return Reflect.apply(originalCatch, this, [onRejected]);
    return Reflect.apply(originalCatch, this, [(error: unknown) => {
      if (boundary.length >= 3 * (queue + 1)) throw new Error("fixture boundary observation bound");
      boundary.push(error);
      return onRejected?.(error);
    }]);
  };
  const gate = new gateModule.ApprovalGate(DEFAULT_POLICY, {
    recordToolCall() {}, isFirstSession: false, isNewNamespace: () => false, getCallRate: () => 0, getAverageCallRate: () => 0,
  } as unknown as import("../../src/principal-policy/baseline.js").BaselineTracker,
  new CallbackApprovalChannel(async () => ({ decision: "deny", decided_by: "human", decided_at: new Date().toISOString() })),
  { appendCritical: async () => {} } as unknown as import("../../src/operational/audit-log.js").AuditLog,
  undefined, undefined, undefined, { currentAgentId: () => "owner", ownScopeSaveStateDirectory: target });
  const save = () => gate.evaluate("memory_insert", { text_bytes: 1 }, undefined, undefined, "memory_insert");
  report("READY");
  for (let wave = 0; wave < 3; wave++) { // Initial, repeated and post-settlement admission waves.
    pausedWrite = new Promise<void>(resolve => { releaseWriter = resolve; });
    writeReached = new Promise<void>(resolve => { enteredWriter = resolve; });
    const first = save(); await writeReached;
    const queued = Array.from({ length: queue }, save);
    const overflow = await save();
    const expire = next("EXPIRE"); report("WRITE_PAUSED", { path, directory: target, wave, overflowDenied: !overflow.allowed });
    await expire;
    for (const timer of [...timers.values()]) timer();
    const results = await Promise.all([first, ...queued]);
    const release = next("RELEASE"); report("EXPIRED", { denied: results.filter(result => !result.allowed).length, queue });
    await release; releaseWriter();
    await (gate as unknown as { ownScopeSaveTail: Promise<unknown> }).ownScopeSaveTail;
    const rows = JSON.parse(await fsPromises.readFile(quotaPath, "utf8"));
    const nextWave = next(wave === 2 ? "EXIT" : "CONTINUE");
    report("DISPOSAL_SETTLED", { writes, spent: rows[0][2], expectedSpent: cap - 3 + wave + 1,
      boundaryLosses: boundary.filter(error => errors(error).some(atom => atom.kind === "holder-lost")).length });
    await nextWave;
  }
  fsPromises.open = originalOpen; syncBuiltinESMExports();
  globalThis.setTimeout = originalTimeout; globalThis.clearTimeout = originalClear; Promise.prototype.catch = originalCatch;
  report("RETURNED"); process.disconnect!();
} else if (role === "malformed") {
  const locks = await import("../../src/storage/cross-process-lock.js");
  const registry = Symbol.for("sanctuary.default-kernel-lock-retention.v1");
  (globalThis as Record<symbol, unknown>)[registry] = { version: 2, records: new Map() }; // Unsupported successor schema must not be replaced.
  report("READY");
  let result: unknown, callbacks = 0;
  try { await locks.withPathLock(target, ".malformed", async () => { callbacks++; }, { kernelBacked: true }); }
  catch (error) { result = error; }
  const exit = next("EXIT"); report("FAULT_REACHED", { reached: true });
  report("DISPOSAL_SETTLED", { errors: errors(result), callbacks, artifacts: await fsPromises.lstat(target).then(() => 1, () => 0) });
  await exit; report("RETURNED"); process.disconnect!();
} else if (role === "fallback") {
  const fs = (await import("node:fs")).default;
  const locks = await import("../../src/storage/cross-process-lock.js");
  const originalClose = Server.prototype.close;
  let path = "", closes = 0, fallbackReached = false, result: unknown;
  Server.prototype.close = function (this: Server, callback?: (error?: Error) => void) {
    const address = this.address();
    if (typeof address !== "string" || !address.includes("/.probe-")) return originalClose.call(this, callback);
    path = address; closes++;
    fs.renameSync(path, `${path}.saved`);
    return originalClose.call(this, error => {
      fs.renameSync(`${path}.saved`, path); fallbackReached = true; callback?.(error);
    });
  };
  report("READY");
  try { await locks.probeKernelBackedCrossProcessLockCapability(); } catch (error) { result = error; }
  Server.prototype.close = originalClose;
  const exit = next("EXIT"); report("FAULT_REACHED", { reached: fallbackReached });
  report("DISPOSAL_SETTLED", { closes, errors: result === undefined ? [] : errors(result), exists: fs.existsSync(path) });
  await exit; report("RETURNED"); process.disconnect!();
} else if (role === "helper") {
  const childProcess = (await import("node:child_process")).default;
  const { EventEmitter } = await import("node:events");
  const { PassThrough } = await import("node:stream");
  const locks = await import("../../src/storage/cross-process-lock.js");
  const spawn = childProcess.spawn;
  let helper: import("node:child_process").ChildProcess | undefined;
  let closed = false, callbacks = 0, result: unknown;
  childProcess.spawn = ((...args: Parameters<typeof spawn>) => {
    if (shape !== "no-pid") {
      const child = Reflect.apply(spawn, childProcess, args);
      helper = child; child.once("close", () => { closed = true; }); return child;
    }
    const child = new EventEmitter() as import("node:child_process").ChildProcess;
    Object.assign(child, { stdin: new PassThrough(), stdout: new PassThrough(), stderr: new PassThrough(), kill() { return false; } });
    helper = child;
    queueMicrotask(() => { child.emit("error", new Error("fixture spawn refused")); closed = true; child.emit("close", -1, null); });
    return child;
  }) as typeof spawn;
  syncBuiltinESMExports(); report("READY");
  try {
    await locks.withPathLock(target, ".helper", async () => { callbacks++; }, {
      kernelBacked: true, __testAfterKernelHolderAcquired: () => { if (shape === "hook-throws") throw new Error("fixture helper hook"); },
    });
  } catch (error) { result = error; }
  childProcess.spawn = spawn; syncBuiltinESMExports();
  const closedAtSettlement = closed;
  // A failed implementation still reaps the fixture child before its root can be deleted.
  if (helper && !closed) await new Promise<void>(resolve => { helper!.once("close", () => resolve()); helper!.kill("SIGKILL"); });
  const exit = next("EXIT"); report("FAULT_REACHED", { reached: true });
  report("DISPOSAL_SETTLED", { closedAtSettlement, callbacks, errors: result === undefined ? [] : errors(result) });
  await exit; report("RETURNED"); process.disconnect!();
} else if (role === "close-order") {
  const locks = await import("../../src/storage/cross-process-lock.js");
  const storage = new FilesystemStorage(target);
  const originalListen = Server.prototype.listen;
  let server: Server | undefined;
  Server.prototype.listen = function (this: Server, ...args: Parameters<Server["listen"]>) {
    const path = (args[0] as unknown as { path?: string })?.path;
    if (path?.includes(".reader-")) server = this;
    return Reflect.apply(originalListen, this, args);
  } as Server["listen"];
  report("READY");
  const lease = await locks.acquireMasterWriteBarrier(storage, "_meta", "close-order");
  if (!server) throw new Error("reader listener not observed");
  const listener = server;
  Server.prototype.listen = originalListen;
  const originalClose = listener.close;
  const originalTimeout = globalThis.setTimeout;
  const originalClear = globalThis.clearTimeout;
  let timerCallback: (() => void) | undefined;
  let closeCallback: ((error?: Error) => void) | undefined;
  let closeCalls = 0, settled = false, concurrentSettled = false;
  let closeReached!: () => void;
  const closing = new Promise<void>(resolve => { closeReached = resolve; });
  const timerHandle = { unref() { return this; } };
  globalThis.setTimeout = ((callback: () => void, ms?: number, ...args: unknown[]) => {
    if (ms === locks.KERNEL_LOCK_RELEASE_TIMEOUT_MS) { timerCallback = callback; return timerHandle; }
    return Reflect.apply(originalTimeout, globalThis, [callback, ms, ...args]);
  }) as typeof setTimeout;
  globalThis.clearTimeout = ((timer: unknown) => { if (timer !== timerHandle) Reflect.apply(originalClear, globalThis, [timer]); }) as typeof clearTimeout;
  const callbackCause = new Error("fixture close callback failure");
  listener.close = function (callback?: (error?: Error) => void) {
    closeCalls++; if (callback) closeCallback = callback;
    Object.defineProperty(listener, "listening", { configurable: true, value: false });
    closeReached();
    if (shape === "throw") throw callbackCause;
    return this;
  };
  let firstError: unknown, repeatError: unknown, concurrentError: unknown;
  const first = lease.release().then(() => { settled = true; }, error => { firstError = error; settled = true; });
  const concurrent = lease.release().then(() => { concurrentSettled = true; }, error => { concurrentError = error; concurrentSettled = true; });
  await closing;
  const occupancy = () => (globalThis as Record<symbol, { records?: Map<unknown, unknown> }>)[Symbol.for("sanctuary.default-kernel-lock-retention.v1")]?.records?.size;
  const before = occupancy();
  const pendingBefore = !settled && !concurrentSettled;
  report("FAULT_REACHED", { reached: true });
  if (shape === "timeout") timerCallback!();
  else if (shape === "callback-error") closeCallback!(callbackCause);
  else if (shape === "event-first") {
    listener.emit("close");
    await Promise.resolve();
  }
  const afterEventPending = !settled && !concurrentSettled;
  if (shape === "event-first" || shape === "callback-first") {
    await fsPromises.unlink(lease.socketPath!);
    closeCallback!();
  }
  await first; await concurrent;
  const afterResult = occupancy();
  listener.emit("close");
  if (shape === "timeout") closeCallback!();
  const afterEvent = occupancy();
  try { await lease.release(); } catch (error) { repeatError = error; }
  globalThis.setTimeout = originalTimeout; globalThis.clearTimeout = originalClear;
  listener.close = originalClose;
  delete (listener as unknown as { listening?: boolean }).listening;
  await new Promise<void>((resolve, reject) => originalClose.call(listener, error => error ? reject(error) : resolve()));
  const exit = next("EXIT");
  report("DISPOSAL_SETTLED", { before, afterResult, afterEvent, pendingBefore, afterEventPending, closeCalls,
    firstKind: (firstError as { kind?: string })?.kind, firstFailed: firstError !== undefined,
    sameRepeat: repeatError === firstError, sameConcurrent: concurrentError === firstError,
    originalCause: firstError instanceof Error && firstError.cause === callbackCause,
    guards: process.listenerCount("beforeExit") });
  await exit; report("RETURNED"); process.disconnect!();
} else if (role === "reader-eviction") {
  const fs = (await import("node:fs")).default;
  const locks = await import("../../src/storage/cross-process-lock.js");
  const storage = new FilesystemStorage(target);
  const original = fsPromises.readdir;
  const originalAbort = AbortController.prototype.abort;
  let path = "", reached = false, delivered = 0, aborts = 0, result: unknown;
  let successor: Server | undefined;
  let successorInode: bigint | undefined;
  AbortController.prototype.abort = function (...args) { aborts++; return Reflect.apply(originalAbort, this, args); };
  fsPromises.readdir = (async (...args: Parameters<typeof original>) => {
    if (path && !reached) {
      reached = true;
      if (shape === "replace") {
        await fsPromises.unlink(path);
        successor = new Server(socket => socket.destroy());
        await new Promise<void>((resolve, reject) => { successor!.once("error", reject); successor!.listen(path, resolve); });
        fs.chmodSync(path, 0o600);
        successorInode = fs.lstatSync(path, { bigint: true }).ino;
      }
      report("FAULT_REACHED", { reached });
    }
    return Reflect.apply(original, fsPromises, args);
  }) as typeof original;
  syncBuiltinESMExports(); report("READY");
  try {
    const lease = await locks.acquireMasterWriteBarrier(storage, "_meta", "eviction", {
      __testAfterSharedSocketAcquired: socket => { path = socket; },
    });
    delivered++; await lease.release();
  } catch (error) { result = error; }
  fsPromises.readdir = original; AbortController.prototype.abort = originalAbort; syncBuiltinESMExports();
  let unregistered = false;
  try { locks.assertStorageMasterWriteBarrierHeld(storage); }
  catch (error) { unregistered = error instanceof locks.CrossProcessLockError && error.message === "master write session was released; refusing a later raw fortress mutation"; }
  const successorIntact = !successor || fs.lstatSync(path, { bigint: true }).ino === successorInode;
  if (successor) await new Promise<void>((resolve, reject) => successor!.close(error => error ? reject(error) : resolve()));
  const exit = next("EXIT");
  report("DISPOSAL_SETTLED", { delivered, aborts, unregistered, successorIntact, errors: result === undefined ? [] : errors(result) });
  await exit; report("RETURNED"); process.disconnect!();
} else if (role === "capture-fault") {
  const fs = (await import("node:fs")).default;
  const locks = await import("../../src/storage/cross-process-lock.js");
  const originalStat = fs.lstatSync, originalChmod = fs.chmodSync, originalAsyncChmod = fsPromises.chmod;
  const fault = Object.assign(new Error("fixture capture fault"), { code: "EIO" });
  let reached = false, callbackCount = 0, closes = 0, path = "", result: unknown;
  const targetPath = (value: unknown) => String(value).endsWith(".sock") && !String(value).includes("/.probe-");
  const originalClose = Server.prototype.close;
  Server.prototype.close = function (this: Server, ...args: Parameters<Server["close"]>) {
    const address = this.address();
    if (typeof address === "string" && targetPath(address)) closes++;
    return Reflect.apply(originalClose, this, args);
  };
  if (shape === "unknown") {
    fs.lstatSync = ((...args: Parameters<typeof originalStat>) => {
      if (targetPath(args[0]) && !reached) { reached = true; path = String(args[0]); throw fault; }
      return Reflect.apply(originalStat, fs, args);
    }) as typeof originalStat;
  } else {
    fs.chmodSync = ((...args: Parameters<typeof originalChmod>) => {
      if (targetPath(args[0]) && !reached) { reached = true; path = String(args[0]); throw fault; }
      return Reflect.apply(originalChmod, fs, args);
    }) as typeof originalChmod;
    fsPromises.chmod = (async (...args: Parameters<typeof originalAsyncChmod>) => {
      if (targetPath(args[0]) && !reached) { reached = true; path = String(args[0]); throw fault; }
      return Reflect.apply(originalAsyncChmod, fsPromises, args);
    }) as typeof originalAsyncChmod;
  }
  syncBuiltinESMExports(); report("READY");
  try { await locks.withPathLock(target, ".capture", async () => { callbackCount++; }, { kernelBacked: true }); }
  catch (error) { result = error; }
  fs.lstatSync = originalStat; fs.chmodSync = originalChmod; fsPromises.chmod = originalAsyncChmod; syncBuiltinESMExports();
  let reacquired = 0;
  if (shape !== "unknown") await locks.withPathLock(target, ".capture", async () => { reacquired++; }, { kernelBacked: true });
  const exit = next("EXIT"); report("FAULT_REACHED", { reached });
  report("DISPOSAL_SETTLED", { callbackCount, errors: errors(result), closes, reacquired,
    guards: process.listenerCount("beforeExit"), exists: path !== "" && fs.existsSync(path) });
  await exit; report("RETURNED"); process.disconnect!();
} else if (role === "invalid-shape") {
  const fs = (await import("node:fs")).default;
  const locks = await import("../../src/storage/cross-process-lock.js");
  const originalSync = fs.lstatSync, originalAsync = fsPromises.lstat, originalClose = Server.prototype.close;
  let path = "", armed = false, closes = 0, result: unknown, guardInCatch = 0;
  const altered = (name: unknown, stats: any) => {
    if (!armed || String(name) !== path) return stats;
    return new Proxy(stats, { get(object, key) {
      if (shape === "uid" && key === "uid") return stats.uid + 1n;
      return Reflect.get(object, key);
    } });
  };
  fs.lstatSync = ((...args: Parameters<typeof originalSync>) => altered(args[0], Reflect.apply(originalSync, fs, args))) as typeof originalSync;
  fsPromises.lstat = (async (...args: Parameters<typeof originalAsync>) => altered(args[0], await Reflect.apply(originalAsync, fsPromises, args))) as typeof originalAsync;
  Server.prototype.close = function (this: Server, ...args: Parameters<Server["close"]>) {
    if (this.address() === path) closes++;
    return Reflect.apply(originalClose, this, args);
  };
  syncBuiltinESMExports(); report("READY");
  try {
    await locks.withPathLock(target, ".invalid", async lease => {
      if (shape === "mode" || shape === "owner-read") await fsPromises.chmod(path, shape === "mode" ? 0o666 : 0o400);
      if (shape === "file" || shape === "symlink") {
        await fsPromises.unlink(path);
        if (shape === "file") await fsPromises.writeFile(path, "fixture", { mode: 0o600 });
        else await fsPromises.symlink("missing-fixture-target", path);
      }
      armed = true; report("FAULT_REACHED", { reached: true });
      try { lease.assertHeld(); } catch { guardInCatch = process.listenerCount("beforeExit"); }
    }, { kernelBacked: true, __testAfterKernelSocketAcquired: socket => { path = socket; } });
  } catch (error) { result = error; }
  armed = false; fs.lstatSync = originalSync; fsPromises.lstat = originalAsync; Server.prototype.close = originalClose; syncBuiltinESMExports();
  const exit = next("EXIT");
  report("DISPOSAL_SETTLED", { errors: result === undefined ? [] : errors(result), closes, guardInCatch, guardAtUnref });
  await exit; report("RETURNED"); process.disconnect!();
} else if (role === "listen-refund") {
  const locks = await import("../../src/storage/cross-process-lock.js");
  const originalListen = Server.prototype.listen, originalClose = Server.prototype.close;
  const abort = new AbortController();
  let binds = 0, closes = 0, callbacks = 0;
  Server.prototype.listen = function (this: Server, ...args: Parameters<Server["listen"]>) {
    binds++; return Reflect.apply(originalListen, this, args);
  } as Server["listen"];
  Server.prototype.close = function (this: Server, ...args: Parameters<Server["close"]>) {
    closes++; return Reflect.apply(originalClose, this, args);
  };
  const occupancy = () => (globalThis as Record<symbol, { records?: Map<unknown, unknown> }>)[Symbol.for("sanctuary.default-kernel-lock-retention.v1")]?.records?.size ?? 0;
  const exit = next("EXIT");
  report("READY");
  let result: unknown, before = 0, afterResult = 0;
  if (shape === "preabort") {
    abort.abort();
    try { await locks.withPathLock(target, ".listen", async () => { callbacks++; }, { kernelBacked: true, abortSignal: abort.signal }); }
    catch (error) { result = error; }
  } else {
    await locks.withPathLock(target, ".listen", async () => {
      binds = 0; closes = 0; before = occupancy();
      try { await locks.withPathLock(target, ".listen", async () => { callbacks++; }, { kernelBacked: true, timeoutMs: 0 }); }
      catch (error) { result = error; }
      afterResult = occupancy();
      report("FAULT_REACHED", { reached: true });
      report("DISPOSAL_SETTLED", { errors: errors(result), callbacks, binds, closes, before, afterResult });
    }, { kernelBacked: true });
  }
  if (shape === "preabort") {
    report("FAULT_REACHED", { reached: true });
    report("DISPOSAL_SETTLED", { errors: errors(result), callbacks, binds, closes, before, afterResult: occupancy() });
  }
  await exit; report("RETURNED"); process.disconnect!();
} else if (role === "stat-fault") {
  const fs = (await import("node:fs")).default;
  const locks = await import("../../src/storage/cross-process-lock.js");
  const originalSync = fs.lstatSync, originalAsync = fsPromises.lstat;
  const cause = Object.assign(new Error("fixture stat cause"), shape === "unexpected" ? {} : { code: shape });
  const primary = new Error("fixture body failure");
  let path = "", armed = false, guardInCatch = -1, result: unknown;
  const failStat = (name: unknown) => {
    if (armed && String(name) === path) throw cause;
  };
  fs.lstatSync = ((...args: Parameters<typeof originalSync>) => { failStat(args[0]); return Reflect.apply(originalSync, fs, args); }) as typeof originalSync;
  fsPromises.lstat = (async (...args: Parameters<typeof originalAsync>) => { failStat(args[0]); return Reflect.apply(originalAsync, fsPromises, args); }) as typeof originalAsync;
  syncBuiltinESMExports();
  report("READY");
  try {
    await locks.withPathLock(target, ".fault", async lease => {
      armed = true;
      report("FAULT_REACHED", { reached: true });
      try { lease.assertHeld(); } catch { guardInCatch = process.listenerCount("beforeExit"); }
      throw primary;
    }, { kernelBacked: true, __testAfterKernelSocketAcquired: socket => { path = socket; } });
  } catch (error) { result = error; }
  armed = false; fs.lstatSync = originalSync; fsPromises.lstat = originalAsync; syncBuiltinESMExports();
  const members = result instanceof AggregateError ? result.errors : [result];
  let sameLockCallbacks = 0, sameLockKind: string | undefined, otherCallbacks = 0;
  try { await locks.withPathLock(target, ".fault", async () => { sameLockCallbacks++; }, { kernelBacked: true, timeoutMs: 0 }); }
  catch (error) { sameLockKind = errors(error)[0]?.kind; }
  try { await locks.withPathLock(target, ".other", async () => { otherCallbacks++; }, { kernelBacked: true }); }
  catch { /* Callback count is the behavioral observation for independent admission. */ }
  const exit = next("EXIT");
  report("DISPOSAL_SETTLED", { errors: errors(result), originalCause: members.some(error => error instanceof Error && error.cause === cause),
    primaryPreserved: members.includes(primary), guardInCatch, guardAtUnref, sameLockCallbacks, sameLockKind, otherCallbacks });
  await exit; report("RETURNED"); process.disconnect!();
} else if (role === "healthy-family") {
  const locks = await import("../../src/storage/cross-process-lock.js");
  const fs = (await import("node:fs")).default;
  const storage = new FilesystemStorage(target);
  let callbacks = 0, contendingCallbacks = 0, refusals = 0, closeEvents = 0, heldStats = 0;
  const originalClose = Server.prototype.close;
  Server.prototype.close = function (this: Server, ...args: Parameters<Server["close"]>) {
    this.once("close", () => { closeEvents++; });
    return Reflect.apply(originalClose, this, args);
  };
  const assertHeld = (lease: { assertHeld(): void }) => {
    const original = fs.lstatSync;
    fs.lstatSync = ((...args: Parameters<typeof original>) => { heldStats++; return Reflect.apply(original, fs, args); }) as typeof original;
    syncBuiltinESMExports();
    try { lease.assertHeld(); } finally { fs.lstatSync = original; syncBuiltinESMExports(); }
  };
  report("READY");
  for (let round = 0; round < 2; round++) { // Initial acquisition and reacquisition after completed release.
    if (shape === "ordinary") {
      await locks.withPathLock(target, ".healthy", async lease => {
        callbacks++; assertHeld(lease);
        try { await locks.withPathLock(target, ".healthy", async () => { contendingCallbacks++; }, { kernelBacked: true, timeoutMs: 0 }); }
        catch (error) { if (errors(error).some(e => e.kind === "contention")) refusals++; else throw error; }
      }, { kernelBacked: true });
    } else if (shape === "reader") {
      const lease = await locks.acquireMasterWriteBarrier(storage, "_meta", "healthy");
      callbacks++; assertHeld(lease);
      try { await locks.withExclusiveMasterRotationBarrier(storage, "_meta", "healthy", async () => { contendingCallbacks++; }, { timeoutMs: 0 }); }
      catch (error) { if (errors(error).some(e => e.kind === "contention")) refusals++; else throw error; }
      await lease.release();
    } else {
      await locks.withExclusiveMasterRotationBarrier(storage, "_meta", "healthy", async () => {
        callbacks++;
        try { const lease = await locks.acquireMasterWriteBarrier(storage, "_meta", "healthy", { timeoutMs: 0 }); contendingCallbacks++; await lease.release(); }
        catch (error) { if (errors(error).some(e => e.kind === "contention")) refusals++; else throw error; }
      });
    }
  }
  const exit = next("EXIT");
  report("FAULT_REACHED", { reached: true });
  report("DISPOSAL_SETTLED", { callbacks, contendingCallbacks, refusals, closeEvents, heldStats, guards: process.listenerCount("beforeExit") });
  await exit; report("RETURNED"); process.disconnect!();
} else if (role === "modes") {
  const locks = await import("../../src/storage/cross-process-lock.js");
  const { MemoryStorage } = await import("../../src/storage/memory.js");
  const { join } = await import("node:path");
  const memory = new MemoryStorage();
  report("READY");
  let callbacks = 0, readOnly = 0, inert = 0;
  const lease = await locks.acquireMasterWriteBarrier(memory, "_meta", "mode");
  lease.assertHeld(); await lease.release(); inert++;
  await locks.withExclusiveMasterRotationBarrier(memory, "_meta", "mode", async () => { callbacks++; });
  for (const mode of ["unsupported", "inert", "read-only"] as const) {
    const storage = new FilesystemStorage(join(target, mode));
    const lease = await locks.acquireMasterWriteBarrier(storage, "_meta", "mode", mode === "unsupported"
      ? { __testPlatform: "win32" }
      : { __testGetuid: () => process.getuid!() + 1, degradeOnEnvironmentalLoss: mode });
    lease.assertSessionHeld();
    try { lease.assertHeld(); inert++; } catch (error) { if (errors(error).some(e => e.kind === "capability")) readOnly++; else throw error; }
    await lease.release();
  }
  const exit = next("EXIT"); report("FAULT_REACHED", { reached: true });
  report("DISPOSAL_SETTLED", { callbacks, readOnly, inert, guards: process.listenerCount("beforeExit") });
  await exit; report("RETURNED"); process.disconnect!();
} else if (role === "probe") {
  const fs = (await import("node:fs")).default;
  const locks = await import("../../src/storage/cross-process-lock.js");
  const originalAsync = fsPromises.chmod;
  const originalSync = fs.chmodSync;
  const originalAccess = fsPromises.access;
  const fault = Object.assign(new Error("fixture probe permission failure"), { code: "EIO" });
  let reached = false, closes = 0, closeEvents = 0;
  const originalClose = Server.prototype.close;
  Server.prototype.close = function (this: Server, ...args: Parameters<Server["close"]>) {
    closes++; this.once("close", () => { closeEvents++; });
    return Reflect.apply(originalClose, this, args);
  };
  if (shape === "postbind") {
    fsPromises.chmod = (async (...args: Parameters<typeof originalAsync>) => {
      reached = true; throw fault;
    }) as typeof originalAsync;
    fs.chmodSync = (() => { reached = true; throw fault; }) as typeof originalSync;
  } else if (shape === "prebind") {
    fsPromises.access = (async () => { reached = true; throw fault; }) as typeof originalAccess;
  }
  syncBuiltinESMExports();
  report("READY");
  let thrown: unknown, available: boolean | undefined;
  try { available = (await locks.probeKernelBackedCrossProcessLockCapability()).available; }
  catch (error) { thrown = error; }
  report("FAULT_REACHED", { reached: shape === "healthy" || reached });
  const { probeCustodyAccess } = await import("../../src/cli/install.js");
  const observed = await probeCustodyAccess(target, process.platform, async () => null,
    () => locks.probeKernelBackedCrossProcessLockCapability(), async () => ({ status: "not-found" }));
  fsPromises.chmod = originalAsync; fs.chmodSync = originalSync; fsPromises.access = originalAccess;
  syncBuiltinESMExports();
  const exit = next("EXIT");
  report("DISPOSAL_SETTLED", { available, errors: thrown === undefined ? [] : errors(thrown),
    originalCause: thrown instanceof Error && thrown.cause === fault,
    closes, closeEvents, observed: observed.custodyMutation });
  await exit; report("RETURNED"); process.disconnect!();
} else if (role === "budget") {
  const locks = await import("../../src/storage/cross-process-lock.js");
  const { unlink, lstat, readdir } = await import("node:fs/promises");
  const { join } = await import("node:path");
  const budget = 64; // Must match MAX_RETAINED_KERNEL_LOCK_LISTENERS: 2^ceil(log2(6 * 8)).
  const storage = new FilesystemStorage(target);
  const run = async (index: number, loss: boolean) => {
    let path = "";
    return locks.withPathLock(target, `.loss-${index}`, async () => {
      if (loss) await unlink(path);
    }, { kernelBacked: true, __testAfterKernelSocketAcquired: socket => { path = socket; } });
  };
  report("READY");
  let losses = 0;
  const active: Array<{ release(): void; done: Promise<void> }> = [];
  for (let index = 0; index < budget; index++) {
    if (shape === "live") {
      let release!: () => void, entered!: () => void;
      const held = new Promise<void>(resolve => { entered = resolve; });
      const released = new Promise<void>(resolve => { release = resolve; });
      const done = locks.withPathLock(target, `.live-${index}`, async () => { entered(); await released; }, { kernelBacked: true });
      active.push({ release, done }); await held;
    } else {
      try { await run(index, true); } catch (error) {
        if (errors(error).some(atom => atom.kind === "holder-lost")) losses++;
        else throw error;
      }
    }
  }
  locks.resetKernelLockPoisonForTests();
  report("FAULT_REACHED", { losses, live: active.length });
  let binds = 0;
  const originalListen = Server.prototype.listen;
  Server.prototype.listen = function (this: Server, ...args: Parameters<Server["listen"]>) {
    binds++;
    return Reflect.apply(originalListen, this, args);
  } as Server["listen"];
  let refused = 0, callbacks = 0, unexpected = 0, artifacts = 0;
  for (let attempt = 0; attempt < budget * 2; attempt++) {
    const directory = join(target, `absent-${attempt}`);
    const directNamespace = `direct-${attempt}`;
    try {
      switch (attempt % 5) { // Five public kernel admission families.
        case 0: await locks.withPathLock(directory, ".cap", async () => { callbacks++; }, { kernelBacked: true }); break;
        case 1: await locks.probeKernelBackedCrossProcessLockCapability(); break;
        case 2: {
          const lease = await locks.acquireMasterWriteBarrier(new FilesystemStorage(directory), "_meta", "cap", { degradeOnEnvironmentalLoss: "inert" });
          callbacks++; await lease.release(); break;
        }
        case 3: await locks.withExclusiveMasterRotationBarrier(new FilesystemStorage(directory), "_meta", "cap", async () => { callbacks++; }); break;
        default: await storage.withNamespaceLock(directNamespace, ".cap", async () => { callbacks++; }, { kernelBacked: true });
      }
    } catch (error) {
      if (errors(error).some(atom => atom.kind === "poisoned")) refused++;
      else unexpected++;
    }
    if (attempt % 5 === 4) {
      const direct = storage.namespacePath(directNamespace);
      const entries = await readdir(direct).catch(error => { if (error.code === "ENOENT") return []; throw error; });
      if (entries.length) artifacts++;
    } else if (await lstat(directory).then(() => true, error => { if (error.code === "ENOENT") return false; throw error; })) artifacts++;
  }
  const exit = next("EXIT");
  const registry = (globalThis as Record<symbol, { records?: Map<unknown, unknown> }>)[Symbol.for("sanctuary.default-kernel-lock-retention.v1")];
  report("DISPOSAL_SETTLED", { losses, refused, callbacks, unexpected, artifacts, binds,
    retained: registry?.records?.size ?? 0, guards: process.listenerCount("beforeExit"),
    exportedBudget: (locks as unknown as Record<string, unknown>).MAX_RETAINED_KERNEL_LOCK_LISTENERS });
  await exit;
  for (const item of active) item.release();
  await Promise.all(active.map(item => item.done));
  report("RETURNED");
  process.disconnect!();
} else {
const storage = new FilesystemStorage(target);
let path = "";
let failure: unknown;
let heldCheck = false;
let callbackCount = 0, guardInCatch = -1;
const released = next(role === "successor" ? "CHECK" : "RELEASE");
let faultReached = false;
async function pauseBind(socketPath: string): Promise<void> {
  if (faultReached) return;
  faultReached = true;
  path = socketPath;
  report("FAULT_REACHED", { path });
  await released;
}
if (role === "postbind-holder") {
  const originalLstat = fsPromises.lstat;
  fsPromises.lstat = (async (...args: Parameters<typeof originalLstat>) => {
    const socketPath = String(args[0]);
    if (socketPath.endsWith(".sock") && !socketPath.includes("/.probe-") && !faultReached) await pauseBind(socketPath);
    return Reflect.apply(originalLstat, fsPromises, args);
  }) as typeof originalLstat;
  syncBuiltinESMExports();
}
report("READY");
try {
  const operation = async (lease: { assertHeld(): void }) => {
    callbackCount++;
    if (role === "postbind-holder") return;
    report("HELD", { path });
    await released;
    if (shape === "sync-loss") {
      try { lease.assertHeld(); } catch (error) { guardInCatch = process.listenerCount("beforeExit"); throw error; }
    }
    if (role === "successor") {
      try { lease.assertHeld(); heldCheck = true; } catch { /* The parent asserts the result. */ }
      const release = next("RELEASE");
      report("CHECKED", { held: heldCheck });
      await release;
    }
  };
  const options = {
    kernelBacked: true,
    ...(role.startsWith("contender") ? { timeoutMs: 0 } : {}),
    __testAfterKernelSocketAcquired: async (socketPath: string) => {
      path = socketPath;
      if (role === "postbind-holder") await pauseBind(socketPath);
    },
  };
  if (process.env.LK1_DIRECT_LOCK) {
    const { withPathLock } = await import("../../src/storage/cross-process-lock.js");
    await withPathLock(target, process.env.LK1_DIRECT_LOCK, operation, options);
  } else if (role === "postbind-holder") {
    // Direct admission observes the lock boundary before a storage consumer can reject the lease itself.
    const { withPathLock } = await import("../../src/storage/cross-process-lock.js");
    await withPathLock(storage.namespacePath("_lock_test"), ".unit.lock", operation, options);
  } else await storage.withNamespaceLock("_lock_test", ".unit.lock", operation, options);
} catch (error) { failure = error; }
// Refusal before callback admission owes no RELEASE command from the parent.
if (callbackCount === 0 && pending?.command === "RELEASE") pending = undefined;
const exit = next("EXIT");
report("DISPOSAL_SETTLED", { errors: failure === undefined ? [] : errors(failure), guardAtUnref, guardInCatch, callbackCount });
await exit;
if (shape === "handled-term" || shape === "handled-int" || shape === "cleanup-reject") {
  const signal = shape === "handled-int" ? "SIGINT" : "SIGTERM";
  await new Promise<void>((resolve, reject) => {
    process.once(signal, () => {
      void (async () => {
        let rejected = false;
        try {
          await fsPromises.writeFile(new URL("./lk1-cleanup", `file://${process.env.HOME}/`), "completed");
          if (shape === "cleanup-reject") throw new Error("fixture completed cleanup rejection");
        } catch { rejected = true; }
        process.exitCode = rejected ? 1 : 0;
        report("CLEANUP_DONE", { rejected });
        resolve();
      })().catch(reject);
    });
    process.kill(process.pid, signal);
  });
}
report("RETURNED");
process.disconnect!();
if (shape === "explicit") process.exit(0);
if (shape === "fatal") setImmediate(() => { throw new Error("fixture fatal exit"); });
else if (shape === "rejection") void Promise.reject(new Error("fixture fatal rejection"));
else if (shape.startsWith("string")) process.exitCode = shape.slice("string".length) as `${number}`;
else if (shape.startsWith("numeric")) process.exitCode = Number(shape.slice("numeric".length));

}
