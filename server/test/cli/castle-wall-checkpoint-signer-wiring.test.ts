/** Scheduled and attended checkpoints consume the daemon's resolved signing client. */
import { generateKeyPairSync } from "node:crypto";
import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
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
const WAIT_MS = 5_000; // Five seconds bounds fixture startup and emission completion.
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
async function reapChildren() {
  const pending = [...boundary.children];
  // A helper timeout settles before close, so teardown must join the actual executable independently.
  for (const [child] of pending) child.kill("SIGKILL");
  await Promise.all(pending.map(([, closed]) => closed));
}

afterEach(async () => {
  try {
    // Pending cancellation survives slow startup and every registered run is awaited even after rejection.
    await Promise.allSettled([...daemonCleanups].map(cleanup => cleanup()));
    await reapChildren();
  } finally {
    vi.restoreAllMocks();
    vi.unstubAllEnvs();
    vi.useRealTimers();
    // CHECKPOINT_WIRING_KEEP_FIXTURES=1 opts into retaining fixture material for diagnosis.
    if (process.env.CHECKPOINT_WIRING_KEEP_FIXTURES !== "1") {
      await Promise.all([...roots].map(path => rm(path, { recursive: true, force: true })));
    }
    roots.clear();
  }
});

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

async function withDaemon(
  f: ReturnType<typeof fixture>,
  check: (state: { result: () => number | undefined }) => Promise<void>,
  waitMs = WAIT_MS,
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
  const running = runDaemon(["--fortress", root], f.ctx).then(
    code => { result = code; },
    error => { failure = error; },
  ).finally(() => { settled = true; });
  const cleanup = async () => {
    cancellationPending = true;
    deliverCancellation();
    await reapChildren();
    try {
      // This awaits daemon termination and session release; fixture child close is joined separately.
      await running;
      await reapChildren();
    } finally {
      process.removeListener("newListener", onListener);
      for (const name of ["SIGINT", "SIGTERM"]) {
        for (const listener of process.rawListeners(name)) if (!prior.get(name)!.has(listener)) process.removeListener(name, listener);
      }
      daemonCleanups.delete(cleanup);
    }
  };
  daemonCleanups.add(cleanup);
  try {
    await observe(() => settled || signal() !== undefined, waitMs);
    if (failure) throw failure;
    await check({ result: () => result });
  } finally {
    await cleanup();
  }
  if (failure) throw failure;
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
      expect(calls).toEqual([
        { path: f.captured()!.signerClientPath, verb: "get-pubkey" },
        { path: f.captured()!.signerClientPath, verb: "sign-manifest" },
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
    expect(calls).toEqual([{ path: shim, verb: "get-pubkey" }, { path: shim, verb: "sign-manifest" }]);
  });
});
