/** Scheduled and attended checkpoints consume the daemon's resolved signing client. */
import { generateKeyPairSync } from "node:crypto";
import { mkdir, mkdtemp, readFile, writeFile } from "node:fs/promises";
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
import { initializeTestCustody } from "../helpers/custody-fixture.js";

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
afterEach(() => {
  vi.restoreAllMocks();
  vi.unstubAllEnvs();
  vi.useRealTimers();
  // Temporary fixture directories are retained for inspection without recursive deletion.
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
    globalPinnedPublicKeyPath: join(root, "absent-global-pin"),
    fullDaemonStart: start,
  };
  return { ctx, out, err, start, stop, captured: () => captured };
}

async function observe(predicate: () => boolean) {
  for (let elapsed = 0; elapsed < WAIT_MS; elapsed += POLL_MS) {
    if (predicate()) return;
    await new Promise(resolve => setTimeout(resolve, POLL_MS));
  }
  throw new Error("fixture observation deadline exceeded");
}

async function withDaemon(f: ReturnType<typeof fixture>, check: (state: { result: () => number | undefined }) => Promise<void>) {
  const prior = new Map(["SIGINT", "SIGTERM"].map(signal => [signal, new Set(process.rawListeners(signal))]));
  let result: number | undefined;
  vi.useFakeTimers({ toFake: ["setInterval", "clearInterval"] });
  const running = runDaemon(["--fortress", root], f.ctx).then(code => { result = code; return code; });
  const signal = () => process.rawListeners("SIGTERM").find(listener => !prior.get("SIGTERM")!.has(listener));
  try {
    await observe(() => result !== undefined || signal() !== undefined);
    await check({ result: () => result });
  } finally {
    // Call only this invocation's listener, then await its session release and every shim child close.
    signal()?.("SIGTERM");
    await running;
    for (const name of ["SIGINT", "SIGTERM"]) {
      for (const listener of process.rawListeners(name)) if (!prior.get(name)!.has(listener)) process.removeListener(name, listener);
    }
  }
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
