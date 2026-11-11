/** Scheduled and attended checkpoints consume the daemon's resolved signing client. */
import { generateKeyPairSync } from "node:crypto";
import { existsSync } from "node:fs";
import { clearTimeout as clearRealTimeout, setTimeout as setRealTimeout } from "node:timers";
import { mkdir, mkdtemp, readFile, realpath, rm, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { Writable } from "node:stream";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { runDaemon, runProvisionPin, type CastleWallCommandContext } from "../../src/cli/castle-wall.js";
import { runTransparencyCommand } from "../../src/cli/transparency.js";
import { startMacOSCastleWallDaemon, type MacOSCastleWallDaemonInput } from "../../src/castle-wall/runtime/macos-daemon.js";
import { FilesystemStorage } from "../../src/storage/filesystem.js";
import { readPersistedCheckpoints, TRANSPARENCY_FLOOR_META_KEY } from "../../src/transparency/emitter.js";
import * as scheduler from "../../src/transparency/scheduler.js";
import { ED25519_PUBLIC_KEY_BYTES } from "../../src/core/crypto-suite-registry.js";
import * as custodyFs from "../../src/storage/custody-fs.js";
import * as helperReadiness from "../../src/cli/castle-wall-signer-helper.js";
import { CASTLE_GLOBAL_PINNED_PUBKEY_PATH } from "../../src/transparency/signer.js";
import type { ChildProcess } from "node:child_process";
import { initializeTestCustody } from "../helpers/custody-fixture.js";

// Only the host pin read is redirected; all fortress reads still use the real filesystem.
const boundary = vi.hoisted(() => ({ pin: "", shim: "", children: new Map<ChildProcess, Promise<void>>() }));
vi.mock("node:fs/promises", async importOriginal => {
  const actual = await importOriginal<typeof import("node:fs/promises")>();
  return {
    ...actual,
    readFile: (path: Parameters<typeof actual.readFile>[0], options: Parameters<typeof actual.readFile>[1]) =>
      actual.readFile(path === CASTLE_GLOBAL_PINNED_PUBKEY_PATH ? boundary.pin : path, options),
  };
});
vi.mock("node:child_process", async importOriginal => {
  const actual = await importOriginal<typeof import("node:child_process")>();
  return {
    ...actual,
    spawn: (...args: Parameters<typeof actual.spawn>) => {
      const child = actual.spawn(...args);
      if (args[0] === boundary.shim) {
        // Register before returning so a timeout cannot leave an unowned fixture executable.
        boundary.children.set(child, new Promise<void>(resolve => child.once("close", () => {
          boundary.children.delete(child);
          resolve();
        })));
      }
      return child;
    },
  };
});
const roots = new Set<string>();
const daemonCleanups = new Set<() => Promise<void>>();
const ROOT_UID = 0; // POSIX identity of an authoritative global pin, simulated only in the read result.
const CUSTODY_MODE = 0o700; // Owner-only fixture custody.
const PASSPHRASE = "checkpoint-fixture-passphrase";
const POLL_MS = 10; // Ten milliseconds between filesystem completion observations.
const WAIT_MS = 5_000; // Five seconds bounds observation of fixture startup and emission completion.
// A stop requested during startup also waits out the remaining startup, so it gets the whole observation budget.
const DAEMON_STOP_DEADLINE_MS = WAIT_MS;
const CHILD_REAP_DEADLINE_MS = WAIT_MS / 2; // Half the observation budget for actual executable closure on a loaded host.
const ROOT_REMOVAL_DEADLINE_MS = CHILD_REAP_DEADLINE_MS; // Filesystem cleanup gets the same budget as child closure.
const CHILD_REAP_CALL_DEADLINE_MS = CHILD_REAP_DEADLINE_MS + POLL_MS; // One poll lets the inner child deadline report first.
const ROOT_REMOVAL_CALL_DEADLINE_MS = ROOT_REMOVAL_DEADLINE_MS + POLL_MS; // One poll lets individual removal deadlines report first.
// Two child reaps surround daemon termination, followed by root removal and one poll of scheduling margin.
const cleanupDeadlineMs = (stopMs = DAEMON_STOP_DEADLINE_MS) => stopMs + CHILD_REAP_CALL_DEADLINE_MS * 2 + ROOT_REMOVAL_CALL_DEADLINE_MS + POLL_MS;
// A deadline measures elapsed wall time, so a caller that asserts on elapsed time allows one observation budget for a descheduled worker.
const SCHEDULING_ALLOWANCE_MS = WAIT_MS;
// The hook runs registered cleanups, one more child reap and one more root removal; its own timeout must exceed their sum.
const AFTER_EACH_TIMEOUT_MS = cleanupDeadlineMs() + CHILD_REAP_CALL_DEADLINE_MS + ROOT_REMOVAL_CALL_DEADLINE_MS + SCHEDULING_ALLOWANCE_MS;
// CHECKPOINT_WIRING_KEEP_FIXTURES=1 opts into retaining fixture material for diagnosis.
const KEEP_FIXTURES_VALUE = "1";
const SUCCESS = 0;
const REFUSED = 1;
const ONE_CHECKPOINT = 1;
class Capture extends Writable {
  text = "";
  override _write(chunk: unknown, _encoding: BufferEncoding, done: () => void) { this.text += String(chunk); done(); }
}
let root: string;
let home: string;
let shim: string;
let invocations: string;
let storage: FilesystemStorage;
beforeEach(async () => {
  root = await mkdtemp("/tmp/checkpoint-wiring-");
  // Register immediately so partial setup and observation timeouts still remove fixture keys.
  roots.add(root);
  boundary.pin = join(root, "observed-global-pin");
  const readCustody = custodyFs.readFileCustodyWithStats;
  vi.spyOn(custodyFs, "readFileCustodyWithStats").mockImplementation(async (path, options) => {
    if (path !== CASTLE_GLOBAL_PINNED_PUBKEY_PATH && path !== boundary.pin) return readCustody(path, options);
    const result = await readCustody(boundary.pin, options);
    // Simulated root ownership makes the isolated pin authoritative without privileged filesystem writes.
    result.stats.uid = ROOT_UID;
    return result;
  });
  const assessReadiness = helperReadiness.assessSignerHelperReadiness;
  vi.spyOn(helperReadiness, "assessSignerHelperReadiness").mockImplementation(input => assessReadiness({
    ...input,
    execFileFn: () => ({ code: REFUSED, stdout: "", stderr: "fixture service absent" }),
    readGlobalPin: () => readFile(boundary.pin),
    statCustodyDir: async () => ({ uid: ROOT_UID, mode: CUSTODY_MODE }),
  }));
  home = join(root, "home");
  await mkdir(home);
  vi.stubEnv("HOME", home);
  vi.stubEnv("SANCTUARY_CUSTODY_LOCK_ROOT", join(root, "locks"));
  vi.stubEnv("SANCTUARY_CASTLE_LOCAL_SIGN", "");
  vi.stubEnv("SANCTUARY_CASTLE_SIGNER_CLIENT", "");
  await initializeTestCustody(root, { passphrase: PASSPHRASE });
  expect(await runProvisionPin(["--fortress", root], {
    out: new Capture(), err: new Capture(),
    env: { HOME: home, SANCTUARY_PASSPHRASE: PASSPHRASE },
    globalPinnedPublicKeyPath: join(root, "global-pin"),
  })).toBe(SUCCESS);
  await mkdir(join(root, "policy", "egress", "rules"), { recursive: true });
  await writeFile(join(root, "policy", "egress", "rules", "fixture.json"), JSON.stringify({ rule_id: "fixture" }));
  storage = new FilesystemStorage(join(root, "state"));
  shim = join(root, "signer-client.mjs");
  boundary.shim = shim;
  invocations = join(root, "invocations.jsonl");
  const keys = generateKeyPairSync("ed25519");
  const publicKey = keys.publicKey.export({ type: "spki", format: "der" }).subarray(-ED25519_PUBLIC_KEY_BYTES).toString("base64url");
  const privateKey = keys.privateKey.export({ type: "pkcs8", format: "pem" });
  await writeFile(shim, `#!${process.execPath}
import { appendFileSync } from "node:fs";
import { sign } from "node:crypto";
import { fileURLToPath } from "node:url";
const chunks = [];
// The interpreter and script occupy the first two argv entries.
const verb = process.argv[2];
for await (const chunk of process.stdin) chunks.push(chunk);
appendFileSync(${JSON.stringify(invocations)}, JSON.stringify({ path: fileURLToPath(import.meta.url), verb }) + "\\n");
if (verb === "get-pubkey") console.log(${JSON.stringify(publicKey)});
else if (verb === "sign-manifest") console.log(sign(null, Buffer.concat(chunks), ${JSON.stringify(privateKey)}).toString("base64url"));
else process.exitCode = ${REFUSED};
`, { mode: 0o700 }); // Owner-only executable fixture exercises the real shim spawning path.
});
class DaemonTeardownDeadlineError extends Error {
  override name = "DaemonTeardownDeadlineError";
  constructor(phase: string) { super(`daemon under test did not stop before the teardown deadline (${phase})`); }
}

async function withinDeadline<T>(work: Promise<T>, deadlineMs: number, phase: string): Promise<T> {
  let timer: ReturnType<typeof setRealTimeout> | undefined;
  const expired = new Promise<never>((_resolve, reject) => {
    timer = setRealTimeout(() => reject(new DaemonTeardownDeadlineError(phase)), deadlineMs);
  });
  try {
    // Real timers keep teardown bounded even while the scheduler's interval clock is faked.
    return await Promise.race([work, expired]);
  } finally { clearRealTimeout(timer); }
}

function throwTeardownErrors(errors: unknown[]) {
  if (errors.length === 0) return;
  const failure = errors.find(error => error instanceof DaemonTeardownDeadlineError) ?? errors[0];
  if (failure instanceof Error) Object.assign(failure, { teardownErrors: errors.filter(error => error !== failure) });
  throw failure;
}

async function reapChildren() {
  const pending = [...boundary.children];
  const errors: unknown[] = [];
  // A helper timeout settles before close, so teardown must kill and join every actual executable independently.
  for (const [child] of pending) {
    try { child.kill("SIGKILL"); } catch (error) { errors.push(error); }
  }
  await withinDeadline(Promise.all(pending.map(([, closed]) => closed)), CHILD_REAP_DEADLINE_MS, "fixture executables");
  throwTeardownErrors(errors);
}

async function removeRoots() {
  if (process.env.CHECKPOINT_WIRING_KEEP_FIXTURES === KEEP_FIXTURES_VALUE) { roots.clear(); return; }
  // Register all removals before waiting so one failed removal cannot skip another fixture root.
  const removed = await withinDeadline(Promise.allSettled([...roots].map(async path => {
    await withinDeadline(rm(path, { recursive: true, force: true }), ROOT_REMOVAL_DEADLINE_MS, "fixture root");
    roots.delete(path);
  })), ROOT_REMOVAL_CALL_DEADLINE_MS, "fixture roots");
  throwTeardownErrors(removed.flatMap(result => result.status === "rejected" ? [result.reason] : []));
}

afterEach(async () => {
  const errors: unknown[] = [];
  try {
    try {
      // A run that never settles must not prevent child reaping or removal of registered roots.
      const stopped = await withinDeadline(Promise.allSettled([...daemonCleanups].map(cleanup => cleanup())), cleanupDeadlineMs(), "registered daemons");
      errors.push(...stopped.flatMap(result => result.status === "rejected" ? [result.reason] : []));
    } catch (error) { errors.push(error); }
    try { await withinDeadline(reapChildren(), CHILD_REAP_CALL_DEADLINE_MS, "remaining executables"); }
    catch (error) { errors.push(error); }
    try { await withinDeadline(removeRoots(), ROOT_REMOVAL_CALL_DEADLINE_MS, "remaining roots"); }
    catch (error) { errors.push(error); }
  } finally {
    vi.restoreAllMocks();
    vi.unstubAllEnvs();
    vi.useRealTimers();
  }
  // Vitest records a failed hook alongside a primary test failure rather than replacing that failure.
  throwTeardownErrors(errors);
}, AFTER_EACH_TIMEOUT_MS);

function fixture() {
  const out = new Capture(), err = new Capture();
  let captured: MacOSCastleWallDaemonInput | undefined;
  const stop = vi.fn(async () => {});
  const start = vi.fn(async (input: MacOSCastleWallDaemonInput) => {
    captured = input;
    return { socketPath: join(root, "daemon.sock"), stop };
  });
  const ctx: CastleWallCommandContext = {
    platform: "darwin", getuid: process.getuid?.bind(process), out, err,
    env: { HOME: home, SANCTUARY_PASSPHRASE: PASSPHRASE, SANCTUARY_TRANSPARENCY_INTERVAL: "1m" },
    signerClientCandidates: [shim],
    globalPinnedPublicKeyPath: boundary.pin,
    fullDaemonStart: start,
  };
  return { ctx, out, err, start, stop, captured: () => captured };
}

async function observe(predicate: () => boolean, waitMs = WAIT_MS) {
  for (let elapsed = 0; elapsed < waitMs; elapsed += POLL_MS) {
    if (predicate()) return;
    await new Promise(resolve => setTimeout(resolve, POLL_MS));
  }
  throw new Error("fixture observation deadline exceeded");
}

function startDaemon(
  f: ReturnType<typeof fixture>,
  stopDeadlineMs = DAEMON_STOP_DEADLINE_MS,
  start = () => runDaemon(["--fortress", root], f.ctx),
) {
  const prior = new Map(["SIGINT", "SIGTERM"].map(signal => [signal, new Set(process.rawListeners(signal))]));
  let result: number | undefined;
  let failure: unknown;
  let settled = false;
  let cancellationPending = false;
  const signal = () => process.rawListeners("SIGTERM").find(listener => !prior.get("SIGTERM")!.has(listener));
  const deliverCancellation = () => { if (cancellationPending) signal()?.("SIGTERM"); };
  const onListener = (name: string | symbol) => {
    // newListener fires before registration, so deferred delivery sees the ready invocation's listener.
    if (name === "SIGTERM") queueMicrotask(deliverCancellation);
  };
  process.on("newListener", onListener);
  vi.useFakeTimers({ toFake: ["setInterval", "clearInterval"] });
  const running = start().then(
    code => { result = code; },
    error => { failure = error; },
  ).finally(() => { settled = true; });
  const disposeListeners = () => {
    process.removeListener("newListener", onListener);
    for (const name of ["SIGINT", "SIGTERM"]) {
      for (const listener of process.rawListeners(name)) if (!prior.get(name)!.has(listener)) process.removeListener(name, listener);
    }
  };
  let cleaning: Promise<void> | undefined;
  const cleanup = () => cleaning ??= (async () => {
    const errors: unknown[] = [];
    try {
      cancellationPending = true;
      deliverCancellation();
      await withinDeadline(reapChildren(), CHILD_REAP_CALL_DEADLINE_MS, "initial executable reap");
      // In-process work that never settles ends with this test file's worker process, and the suite's master-write lease guard reports any lease it leaves.
      await withinDeadline(running, stopDeadlineMs, "daemon termination");
    } catch (error) { errors.push(error); }
    finally {
      try { await withinDeadline(reapChildren(), CHILD_REAP_CALL_DEADLINE_MS, "final executable reap"); }
      catch (error) { errors.push(error); }
      if (errors.length > 0) {
        try { await withinDeadline(removeRoots(), ROOT_REMOVAL_CALL_DEADLINE_MS, "deadline roots"); }
        catch (error) { errors.push(error); }
      }
      // Late readiness still needs the pending stop, so listener disposal follows settlement without an unbounded wait.
      if (settled) disposeListeners();
      else void running.then(disposeListeners);
      daemonCleanups.delete(cleanup);
    }
    throwTeardownErrors(errors);
  })();
  daemonCleanups.add(cleanup);
  return { cleanup, running, ready: () => settled || signal() !== undefined, result: () => result, failure: () => failure };
}

async function finishCleanup(cleanup: () => Promise<void>, primary?: { error: unknown }) {
  try { await withinDeadline(cleanup(), cleanupDeadlineMs(), "daemon cleanup"); }
  catch (error) {
    // A cleanup failure remains attached to the original test error so it cannot replace the assertion or observation failure.
    if (!primary) throw error;
    if (primary.error instanceof Error) Object.assign(primary.error, { teardownError: error });
    else console.error(error);
  }
  if (primary) throw primary.error;
}

async function withDaemon(
  f: ReturnType<typeof fixture>,
  check: (state: { result: () => number | undefined }) => Promise<void>,
  waitMs = WAIT_MS,
) {
  const run = startDaemon(f);
  let primary: { error: unknown } | undefined;
  try {
    await observe(run.ready, waitMs);
    if (run.failure()) throw run.failure();
    await check(run);
  } catch (error) { primary = { error }; }
  await withinDeadline(finishCleanup(run.cleanup, primary), cleanupDeadlineMs() + POLL_MS, "test cleanup");
  if (run.failure()) throw run.failure();
}

async function tick(f: ReturnType<typeof fixture>) {
  await vi.advanceTimersByTimeAsync(scheduler.MIN_TRANSPARENCY_INTERVAL_MS);
  await observe(() => f.out.text.includes("emitted (audit head seq") || f.err.text.includes("checkpoint emission FAILED"));
}

describe("checkpoint signer production wiring", () => {
  it("the scheduled checkpoint uses the daemon's resolved signer path", async () => {
    const f = fixture();
    await withDaemon(f, async () => {
      expect(f.captured()?.signerClientPath, f.err.text).toBe(shim);
      await tick(f);
      expect(f.err.text).not.toContain("checkpoint emission FAILED");
      const calls = (await readFile(invocations, "utf8")).trim().split("\n").map(line => JSON.parse(line));
      // The stand-in reports the path its interpreter resolved; the root stays under /tmp for the lock socket path cap, and on macOS /tmp is a symlink, so the expectation is canonical.
      const invoked = await realpath(f.captured()!.signerClientPath!);
      expect(calls).toEqual([
        { path: invoked, verb: "get-pubkey" },
        { path: invoked, verb: "sign-manifest" },
      ]);
      expect(await readPersistedCheckpoints(storage)).toHaveLength(ONE_CHECKPOINT);
      expect(f.out.text).toContain(`checkpoint signer: helper ${shim}`);
    });
    expect(f.stop).toHaveBeenCalledOnce();
  });

  it("missing scheduled signer refuses before enforcement or scheduler startup", async () => {
    const f = fixture();
    f.ctx.signerClientCandidates = [join(root, "absent-shim")];
    const schedule = vi.spyOn(scheduler, "startTransparencyScheduler");
    await withDaemon(f, async state => {
      expect(state.result(), f.err.text).toBe(REFUSED);
      expect(f.start).not.toHaveBeenCalled();
      expect(schedule).not.toHaveBeenCalled();
      expect(f.err.text).toContain("Refusing to start: scheduled checkpoint signer unavailable");
      expect(await readPersistedCheckpoints(storage)).toHaveLength(0);
      expect(await storage.read("_meta", TRANSPARENCY_FLOOR_META_KEY)).toBeNull();
    });
  });

  it("interval off reaches the enforcement signer refusal", async () => {
    const f = fixture();
    f.ctx.env!.SANCTUARY_TRANSPARENCY_INTERVAL = "off";
    f.ctx.signerClientCandidates = [join(root, "absent-shim")];
    const start = vi.fn((input: MacOSCastleWallDaemonInput) => startMacOSCastleWallDaemon({
      ...input, platform: "darwin", socketPath: join(root, "daemon.sock"), activeConfigPath: join(root, "active.json"),
    }));
    f.ctx.fullDaemonStart = start;
    expect(await runDaemon(["--fortress", root], f.ctx)).toBe(REFUSED);
    expect(start).toHaveBeenCalledOnce();
    expect(f.err.text).toContain("Castle Wall helper signing is unavailable: set SANCTUARY_CASTLE_SIGNER_CLIENT");
    expect(f.err.text).not.toContain("scheduled checkpoint signer unavailable");
    expect(await readPersistedCheckpoints(storage)).toHaveLength(0);
  });

  it("local signing schedules without consulting helper discovery", async () => {
    const f = fixture();
    f.ctx.env!.SANCTUARY_CASTLE_LOCAL_SIGN = "1";
    const discovery = vi.fn(async () => { throw new Error("local signing must not discover a helper"); });
    f.ctx.fileExistsFn = discovery;
    await withDaemon(f, async () => {
      expect(f.captured()?.localSign).toBe(true);
      await tick(f);
      expect(f.err.text).not.toContain("checkpoint emission FAILED");
      expect(await readPersistedCheckpoints(storage)).toHaveLength(ONE_CHECKPOINT);
      expect(discovery).not.toHaveBeenCalled();
      expect(f.out.text).toContain("checkpoint signer: local key");
    });
  });

  it("an unrelated isolated pin refuses both attended and scheduled signing", async () => {
    const unrelated = generateKeyPairSync("ed25519").publicKey.export({ type: "spki", format: "der" }).subarray(-ED25519_PUBLIC_KEY_BYTES);
    await writeFile(boundary.pin, unrelated);
    const out = new Capture(), err = new Capture();
    expect(await runTransparencyCommand({
      argv: ["checkpoint", "--fortress", root, "--binary", shim], out, err,
      env: { HOME: home, SANCTUARY_PASSPHRASE: PASSPHRASE },
      platform: "darwin", signerClientCandidates: [shim],
    })).toBe(REFUSED);
    expect(err.text).toContain("trust-anchor mismatch");
    const f = fixture();
    await withDaemon(f, async () => {
      await tick(f);
      expect(f.err.text).toContain("trust-anchor mismatch");
      expect(await readPersistedCheckpoints(storage)).toHaveLength(0);
    });
    expect(await readFile(boundary.pin)).toEqual(unrelated);
  });

  it("a stop requested before delayed readiness is delivered and joined", async () => {
    const f = fixture();
    const listeners = process.rawListeners("SIGTERM");
    const delayMs = POLL_MS * 4; // Readiness follows the one-poll observation deadline.
    f.ctx.fullDaemonStart = async input => {
      await new Promise(resolve => setTimeout(resolve, delayMs));
      return f.start(input);
    };
    const schedule = vi.spyOn(scheduler, "startTransparencyScheduler");
    await expect(withDaemon(f, async () => {}, POLL_MS)).rejects.toThrow("fixture observation deadline exceeded");
    expect(f.start).toHaveBeenCalledOnce();
    expect(f.stop).toHaveBeenCalledOnce();
    expect(schedule).toHaveBeenCalledOnce();
    expect(process.rawListeners("SIGTERM")).toEqual(listeners);
    expect(daemonCleanups.size).toBe(0);
    expect(boundary.children.size).toBe(0);
    expect(vi.getTimerCount()).toBe(0);
  });

  it("a pending start reports its teardown deadline, removes roots, and can still be released and joined", async () => {
    const f = fixture();
    const signals = ["SIGINT", "SIGTERM", "newListener"];
    const listeners = signals.map(signal => process.rawListeners(signal));
    const extraRoot = await mkdtemp("/tmp/checkpoint-wiring-");
    roots.add(extraRoot);
    const fixtureRoots = [...roots];
    // The retention switch keeps fixture directories on purpose, so root presence is asserted against it.
    const retained = process.env.CHECKPOINT_WIRING_KEEP_FIXTURES === KEEP_FIXTURES_VALUE;
    let release!: () => void;
    let entered = false;
    const held = new Promise<void>(resolve => { release = resolve; });
    // Stand in before custody acquisition because a real lease requires its directory ancestry to remain intact until release.
    const start = vi.fn(async () => {
      entered = true;
      await held;
      await new Promise<void>(resolve => process.once("SIGTERM", () => { void f.stop().then(resolve); }));
      return SUCCESS;
    });
    const shortStopDeadlineMs = POLL_MS; // One observation poll deliberately expires while startup is held.
    const returnDeadlineMs = cleanupDeadlineMs(shortStopDeadlineMs); // Includes both child joins and root removal after expiry.
    const run = startDaemon(f, shortStopDeadlineMs, start);
    try {
      await observe(() => entered);
      const started = performance.now();
      const failure = await withinDeadline(run.cleanup(), returnDeadlineMs + SCHEDULING_ALLOWANCE_MS, "held start cleanup").catch((error: unknown) => error);
      expect(performance.now() - started).toBeLessThan(returnDeadlineMs + SCHEDULING_ALLOWANCE_MS);
      expect(failure).toBeInstanceOf(DaemonTeardownDeadlineError);
      expect(failure).toMatchObject({ name: "DaemonTeardownDeadlineError", message: "daemon under test did not stop before the teardown deadline (daemon termination)" });
      expect(fixtureRoots.every(path => existsSync(path) === retained)).toBe(true);
      expect(roots.size).toBe(0);
      expect(f.stop).not.toHaveBeenCalled();
      const primary = new Error("fixture primary assertion failure");
      await expect(finishCleanup(run.cleanup, { error: primary })).rejects.toBe(primary);
      expect(primary).toHaveProperty("teardownError", failure);
    } finally {
      release();
      // Release only after the deadline assertions so joining proves that pending cancellation removes the late listener.
      await withinDeadline(run.running, DAEMON_STOP_DEADLINE_MS, "released stand-in");
    }
    expect(run.failure()).toBeUndefined();
    expect(run.result()).toBe(SUCCESS);
    expect(f.stop).toHaveBeenCalledOnce();
    expect(signals.map(signal => process.rawListeners(signal))).toEqual(listeners);
    expect(fixtureRoots.every(path => existsSync(path) === retained)).toBe(true);
    expect(daemonCleanups.size).toBe(0);
    expect(boundary.children.size).toBe(0);
    expect(vi.getTimerCount()).toBe(0);
  });

  it("a stalled fixture executable is killed and joined after an observation timeout", async () => {
    const f = fixture();
    await writeFile(shim, `#!${process.execPath}\nprocess.stdin.resume(); setInterval(() => {}, ${WAIT_MS});\n`);
    let child: ChildProcess | undefined;
    await expect(withDaemon(f, async () => {
      await vi.advanceTimersByTimeAsync(scheduler.MIN_TRANSPARENCY_INTERVAL_MS);
      await observe(() => boundary.children.size > 0);
      child = [...boundary.children.keys()][0];
      await observe(() => false, POLL_MS);
    })).rejects.toThrow("fixture observation deadline exceeded");
    expect(child).toBeDefined();
    expect(child!.signalCode).toBe("SIGKILL");
    expect(f.stop).toHaveBeenCalledOnce();
    expect(boundary.children.size).toBe(0);
    expect(daemonCleanups.size).toBe(0);
    expect(vi.getTimerCount()).toBe(0);
  });

  it("the attended checkpoint discovers and invokes the fixture signer", async () => {
    const out = new Capture(), err = new Capture();
    expect(await runTransparencyCommand({
      argv: ["checkpoint", "--fortress", root, "--binary", shim], out, err,
      env: { HOME: home, SANCTUARY_PASSPHRASE: PASSPHRASE },
      platform: "darwin", signerClientCandidates: [shim],
    }), err.text).toBe(SUCCESS);
    expect(await readPersistedCheckpoints(storage)).toHaveLength(ONE_CHECKPOINT);
    const calls = (await readFile(invocations, "utf8")).trim().split("\n").map(line => JSON.parse(line));
    const invoked = await realpath(shim); // Canonical for the same reason as the scheduled case.
    expect(calls).toEqual([{ path: invoked, verb: "get-pubkey" }, { path: invoked, verb: "sign-manifest" }]);
  });
});
