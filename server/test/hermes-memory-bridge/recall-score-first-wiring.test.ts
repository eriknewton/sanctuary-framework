// The bridge process composition reaches score-first recall: a one-match recall over the production adapter
// verifies one companion, not one per saved passage, and reads several passages at once at the default read-ahead
// window. Temporary fortress, injected in-memory keychain, no child process.
import { Buffer } from "node:buffer";
import { chmod, mkdtemp, mkdir, rm } from "node:fs/promises";
import net from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { PassThrough, type Duplex } from "node:stream";
import { afterEach, expect, it, vi } from "vitest";
import { IdentityManager } from "../../src/cognitive/tools.js";
import { fromBase64url } from "../../src/core/encoding.js";
import { createIdentity } from "../../src/core/identity.js";
import { derivePurposeKey } from "../../src/core/key-derivation.js";
import { establishMaster } from "../../src/core/master-custody.js";
import { PrivateFrameDecoder, encodePrivateFrame, runHermesBridgeProcess } from "../../src/hermes-memory-bridge/index.js";
import { RECALL_READ_AHEAD_PASSAGES } from "../../src/hermes-memory-bridge/recall.js";
import { HermesMemoryClient, type ClientPorts } from "../../src/hermes-memory-client/client.js";
import { SdwMemoryBackendAdapter } from "../../src/sdw/adapters/sdw-memory-backend.js";
import { memoryProvenancePublicKeyFingerprint } from "../../src/sdw/memory-provenance-bad-signers.js";
import { FilesystemStorage } from "../../src/storage/filesystem.js";
import { persistUserProvidedPassphrase } from "../../src/wrap/passphrase.js";

const PASS = "correct horse battery staple recall";
const SAVED = 12; // Twelve saves: a verify-everything recall would verify twelve companions, score-first one.
const encoder = new TextEncoder();
const cleanups: Array<() => Promise<void>> = [];
afterEach(async () => { for (const clean of cleanups.splice(0).reverse()) await clean(); vi.restoreAllMocks(); });

it("reaches score-first recall through the bridge process composition", async () => {
  const fixture = await seededFortress();
  const pair = await socketPair();
  const shell = await runHermesBridgeProcess({
    env: fixture.env,
    relaySocketFactory: () => pair.shell,
    storageFor: fortressDir => new FilesystemStorage(join(fortressDir, "state")),
    uid: process.getuid?.() ?? 0,
  });
  cleanups.push(async () => { shell.signalStop("SIGTERM"); await shell.exited; });
  const prototype = SdwMemoryBackendAdapter.prototype as unknown as {
    verifyCompanion: (...args: unknown[]) => unknown; recallPassages: (...args: unknown[]) => unknown;
  };
  const verifications = vi.spyOn(prototype, "verifyCompanion");
  const recalls = vi.spyOn(prototype, "recallPassages");
  const input = new PassThrough();
  const relayInput = new PassThrough();
  const replies = new Map<number, (value: any) => void>();
  const timers = new Set<ReturnType<typeof setTimeout>>();
  let client: HermesMemoryClient | undefined;
  try {
    expect(await readNodeFrame(pair.relay)).toEqual({ type: "ready" });
    const decoder = new PrivateFrameDecoder();
    pair.relay.on("data", (bytes: Buffer) => {
      decoder.push(bytes);
      for (;;) {
        const next = decoder.next();
        if (next.kind === "need_more") return;
        if (next.kind === "fatal") throw next.error;
        const frame = JSON.parse(Buffer.from(next.body).toString());
        if (frame.type === "probe") pair.relay.write(privateFrame({ type: "probe_reply", connection_id: frame.connection_id, nonce: frame.nonce }));
        if (frame.type === "response") relayInput.write(encodePrivateFrame(Buffer.from(frame.result_b64, "base64")));
      }
    });
    pair.relay.write(privateFrame({ type: "accepted", connection_id: "c1" }));
    const ports: ClientPorts = {
      input, relayInput, stopOutput() {}, connect: ready => ready(), close() {}, now: () => performance.now(),
      schedule: run => queueMicrotask(run),
      timer: (run, ms) => { const handle = setTimeout(run, ms); timers.add(handle); return handle; },
      clearTimer: handle => { clearTimeout(handle); timers.delete(handle); },
      relayOutput: { write(bytes, done) {
        pair.relay.write(privateFrame({ type: "frame", connection_id: "c1", frame_b64: bytes.subarray(4).toString("base64") }));
        done(null, bytes.length);
      } },
      output: { write(bytes, done) {
        const response = JSON.parse(bytes.toString());
        done(null, bytes.length);
        replies.get(response.id)?.(response);
        replies.delete(response.id);
      } },
    };
    client = new HermesMemoryClient(ports, "test-version");
    void client.run();
    let id = 0;
    const request = (method: string, params?: unknown) => new Promise<any>(resolve => {
      const requestId = id++;
      replies.set(requestId, resolve);
      input.write(JSON.stringify({ jsonrpc: "2.0", id: requestId, method, params }) + "\n");
    });
    const call = async (name: string, args: unknown) => JSON.parse((await request("tools/call", { name, arguments: args })).result.content[0].text);
    await request("initialize", { protocolVersion: "2025-11-25", capabilities: {}, clientInfo: { name: "fixture", version: "1" } });
    input.write(JSON.stringify({ jsonrpc: "2.0", method: "notifications/initialized" }) + "\n");
    let target = "";
    for (let n = 0; n < SAVED; n++) {
      const text = n === SAVED / 2 ? "The quarterly handover moved to Friday." : `Garden note ${n} moved to week ${n}.`;
      const saved = await call("memory_insert", { text, taint: "user_content" });
      expect(saved.outcome).toBe("saved");
      if (n === SAVED / 2) target = saved.passage.passage_id;
    }
    verifications.mockClear();
    recalls.mockClear();
    // Count, on the real file store, the distinct passages with a read in flight at once; two reads of one passage
    // (its document and provenance, issued together) count once.
    const passageOf = (key: string) => /^(?:doc|prov|prov-status|chunk)\.(mem\.[^.]+\.[^.]+)(?:\.|$)/.exec(key)?.[1];
    const inFlight = new Map<string, number>();
    let maximumDistinct = 0;
    const read = FilesystemStorage.prototype.read;
    vi.spyOn(FilesystemStorage.prototype, "read").mockImplementation(async function (this: FilesystemStorage, namespace, key) {
      const passage = passageOf(key);
      if (passage !== undefined) {
        inFlight.set(passage, (inFlight.get(passage) ?? 0) + 1);
        maximumDistinct = Math.max(maximumDistinct, inFlight.size);
      }
      try {
        return await read.call(this, namespace, key);
      } finally {
        if (passage !== undefined) {
          const left = inFlight.get(passage)! - 1;
          if (left === 0) inFlight.delete(passage); else inFlight.set(passage, left);
        }
      }
    });
    const recalled = await call("memory_recall", { query: "when is the handover?" });
    expect(recalled).toMatchObject({ outcome: "recalled", truncated: false, passages: [{ passage_id: target }] });
    // The read-ahead is live in the shipped graph: more than one passage had a read in flight at the same time.
    expect(maximumDistinct).toBeGreaterThan(1);
    expect(maximumDistinct).toBeLessThanOrEqual(RECALL_READ_AHEAD_PASSAGES);
    expect(inFlight.size).toBe(0);
    expect(recalls).toHaveBeenCalledTimes(1);
    expect(recalls.mock.contexts[0]).toBeInstanceOf(SdwMemoryBackendAdapter);
    expect((recalls.mock.contexts[0] as SdwMemoryBackendAdapter).mode).toBe("hermes-bridge");
    expect(verifications).toHaveBeenCalledTimes(1);
  } finally {
    client?.signal();
    input.destroy(); relayInput.destroy();
    for (const timer of timers) clearTimeout(timer);
    shell.signalStop("SIGTERM");
    await shell.exited;
    pair.close();
  }
}, 120_000);

async function seededFortress(): Promise<{ readonly env: NodeJS.ProcessEnv; readonly fortressDir: string }> {
  const home = await mkdtemp(join(tmpdir(), "hermes-home-score-first-"));
  await chmod(home, 0o700);
  cleanups.push(() => rm(home, { recursive: true, force: true }));
  const fortressId = `fortress-score-first-${process.pid}`;
  const fortressDir = join(home, "Library", "Application Support", "Sanctuary", "Fortresses", fortressId);
  for (const path of [join(home, "Library"), join(home, "Library", "Application Support"),
    join(home, "Library", "Application Support", "Sanctuary"), join(home, "Library", "Application Support", "Sanctuary", "Fortresses"),
    fortressDir, join(fortressDir, "state")]) {
    await mkdir(path, { recursive: true, mode: 0o700 });
    await chmod(path, 0o700);
  }
  const storage = new FilesystemStorage(join(fortressDir, "state"));
  await persistUserProvidedPassphrase(PASS, { home, storagePath: fortressDir, platformOverride: "freebsd" });
  const custody = await establishMaster({ storage, passphrase: PASS, firstRun: { installMode: "headless", mintRecoveryKey: false } });
  const identityManager = new IdentityManager(storage, custody.masterKey);
  await identityManager.load();
  const { storedIdentity } = createIdentity("hermes-score-first", derivePurposeKey(custody.masterKey, "identity-encryption"), "passphrase");
  await identityManager.save(storedIdentity);
  const bridgeIdentity = memoryProvenancePublicKeyFingerprint(fromBase64url(storedIdentity.public_key));
  await custody.masterWriteBarrier?.release();
  custody.masterKey.fill(0);
  return { fortressDir, env: { HOME: home, LANG: "C", TMPDIR: tmpdir(), HERMES_MEMORY_BRIDGE_IDENTITY: bridgeIdentity,
    HERMES_MEMORY_AGENT_ID: "agent-score-first", HERMES_MEMORY_FORTRESS_ID: fortressId } };
}

function privateFrame(value: Record<string, unknown>): Buffer {
  return encodePrivateFrame(encoder.encode(JSON.stringify(value)));
}

async function socketPair(): Promise<{ relay: net.Socket; shell: net.Socket; close(): void }> {
  const dir = await mkdtemp(join(tmpdir(), "hermes-score-first-socket-"));
  cleanups.push(() => rm(dir, { recursive: true, force: true }));
  const server = net.createServer();
  const accepted = new Promise<net.Socket>(resolve => { server.once("connection", resolve); });
  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    // port-discipline: ignore - unique temporary Unix socket, not a TCP port.
    server.listen(join(dir, "pair.sock"), resolve);
  });
  const relay = net.createConnection(join(dir, "pair.sock"));
  const shell = await accepted;
  // A test may fail before its local finally; close peers before the directory cleanup.
  cleanups.push(async () => { relay.destroy(); shell.destroy(); });
  server.close();
  return { relay, shell, close() { relay.destroy(); shell.destroy(); } };
}

function readNodeFrame(socket: Pick<Duplex, "on" | "off">): Promise<Record<string, unknown>> {
  const decoder = new PrivateFrameDecoder();
  return new Promise((resolve, reject) => {
    const onData = (chunk: Buffer) => {
      decoder.push(chunk);
      const next = decoder.next();
      if (next.kind === "need_more") return;
      socket.off("data", onData);
      if (next.kind === "fatal") reject(next.error);
      else resolve(JSON.parse(Buffer.from(next.body).toString("utf8")) as Record<string, unknown>);
    };
    socket.on("data", onData);
  });
}
