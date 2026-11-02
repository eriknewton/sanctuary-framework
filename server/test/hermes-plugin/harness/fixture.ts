// Temporary fortress helpers mirror the bridge catalog fixture and keep credentials in the test store.
import { Buffer } from "node:buffer";
import { chmod, mkdtemp, mkdir, rm } from "node:fs/promises";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import net from "node:net";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { Duplex } from "node:stream";
import { expect } from "vitest";
import { IdentityManager } from "../../../src/cognitive/tools.js";
import { fromBase64url } from "../../../src/core/encoding.js";
import { createIdentity } from "../../../src/core/identity.js";
import { derivePurposeKey } from "../../../src/core/key-derivation.js";
import { establishMaster } from "../../../src/core/master-custody.js";
import { PrivateFrameDecoder, encodePrivateFrame, runHermesBridgeProcess } from "../../../src/hermes-memory-bridge/index.js";
import { HERMES_MAX_PUBLIC_CONNECTIONS } from "../../../src/hermes-memory-bridge/constants.js";
import { AuditLog } from "../../../src/operational/audit-log.js";
import { memoryProvenancePublicKeyFingerprint } from "../../../src/sdw/memory-provenance-bad-signers.js";
import { SdwDocumentCorpusStore, padChunkOrdinal } from "../../../src/sdw/document-corpus-store.js";
import { FilesystemStorage } from "../../../src/storage/filesystem.js";
import { persistUserProvidedPassphrase } from "../../../src/wrap/passphrase.js";
const PASS = "correct horse battery staple hermes";
const encoder = new TextEncoder();
const cleanups: Array<() => Promise<void>> = [];
let fortressCounter = 0;
const run = promisify(execFile);
export type Fixture = Awaited<ReturnType<typeof startFixture>>;
export async function startFixture() {
  const close = async () => { for (const cleanup of cleanups.splice(0).reverse()) await cleanup(); };
  try {
    const seed = await seededFortress("plugin");
    const pair = await socketPair();
    const ready = readNodeFrame(pair.relay);
    const shell = await runHermesBridgeProcess({ env: seed.env, relaySocketFactory: () => pair.shell,
      storageFor: path => new FilesystemStorage(join(path, "state")), uid: process.getuid?.() ?? 0 });
    cleanups.push(async () => { shell.signalStop("SIGTERM"); await shell.exited; });
    expect(await ready).toEqual({ type: "ready" });
    const storage = new FilesystemStorage(join(seed.fortressDir, "state"));
    const custody = await establishMaster({ storage, passphrase: PASS });
    cleanups.push(async () => { await custody.masterWriteBarrier?.release(); custody.masterKey.fill(0); });
    // The running shell's reported identity is the corpus decoding contract.
    const corpus = new SdwDocumentCorpusStore({ storage, masterKey: custody.masterKey, fortressId: shell.report.fortressId });
    const responses: Record<string, any>[] = [];
    const sockets = new Map<string, net.Socket>();
    let counter = 0;
    const send = (value: Record<string, unknown>) => pair.relay.write(privateFrame(value));
    const decoder = new PrivateFrameDecoder();
    pair.relay.on("data", (bytes: Buffer) => {
      decoder.push(bytes);
      for (;;) {
        const next = decoder.next();
        if (next.kind === "need_more") return;
        if (next.kind === "fatal") throw next.error;
        const frame = JSON.parse(Buffer.from(next.body).toString());
        if (frame.type === "probe") send({ type: "probe_reply", connection_id: frame.connection_id, nonce: frame.nonce });
        if (frame.type === "close") sockets.get(frame.connection_id)?.destroy();
        if (frame.type === "response") {
          const body = Buffer.from(frame.result_b64, "base64");
          const publicResult = JSON.parse(body.toString());
          for (const item of publicResult.payload?.content ?? []) if (item.type === "text") responses.push(JSON.parse(item.text));
          sockets.get(frame.connection_id)?.write(encodePrivateFrame(body));
        }
      }
    });
    const socketDir = await mkdtemp(join(tmpdir(), "hp-"));
    cleanups.push(() => rm(socketDir, { recursive: true, force: true }));
    const socket = join(socketDir, "s");
    expect(Buffer.byteLength(socket)).toBeLessThan(100); // macOS Unix socket names must fit below this bound.
    const relay = net.createServer(peer => {
      if (sockets.size >= HERMES_MAX_PUBLIC_CONNECTIONS) { peer.destroy(); return; }
      const id = `c${++counter}`;
      sockets.set(id, peer);
      send({ type: "accepted", connection_id: id });
      const frames = new PrivateFrameDecoder();
      peer.on("data", bytes => {
        frames.push(Buffer.isBuffer(bytes) ? bytes : Buffer.from(bytes));
        for (;;) {
          const next = frames.next();
          if (next.kind === "need_more") return;
          if (next.kind === "fatal") { peer.destroy(); return; }
          const body = Buffer.from(next.body);
          const value = JSON.parse(body.toString());
          if (value.type === "ping") peer.write(privateFrame({ type: "pong" }));
          else send({ type: "frame", connection_id: id, frame_b64: body.toString("base64") });
        }
      });
      peer.on("error", () => peer.destroy());
      peer.on("close", () => { sockets.delete(id); send({ type: "closed", connection_id: id }); });
    });
    cleanups.push(async () => {
      for (const peer of sockets.values()) peer.destroy();
      await new Promise<void>(resolveClose => relay.close(() => resolveClose()));
    });
    await new Promise<void>((resolveListen, reject) => {
      relay.once("error", reject);
      // port-discipline: ignore - temporary Unix socket, no TCP listener.
      relay.listen(socket, resolveListen);
    });
    const shimCommand = (home: string) => [process.execPath, "--import", "tsx", resolve("test/hermes-plugin/harness/shim.ts"), socket, join(home, "shim.log")];
    return { close, responses, socket, shimCommand,
      preinstalledSession: async (interpreter: string, scenario: string, home: string): Promise<Record<string, any>> => {
        const { stdout } = await run(interpreter, ["-I", resolve("../hermes-plugin/tests/harness/drive_hermes.py"),
          "--preinstalled", "--scenario", scenario, "--home", home, "--socket", socket], {
          cwd: resolve(".."), env: { ...process.env, HOME: home, HERMES_HOME: join(home, "hermes") },
          timeout: 60_000, maxBuffer: 1024 * 1024 }); // One minute and one MiB bound an offline report.
        return JSON.parse(stdout);
      },
      audit: async () => (await new AuditLog(storage, custody.masterKey).query({ limit: 100 })).entries,
      document: async (id: string) => {
        const document = await corpus.getDocument(id);
        expect(document).not.toBeNull();
        const texts = [];
        for (let ordinal = 0; ordinal < document!.chunk_count; ordinal++) {
          // Must match chunkId in sdw-memory-backend.ts: padded ordinal prefixed with c.
          texts.push((await corpus.getChunk(id, ordinal, `c${padChunkOrdinal(ordinal)}`))?.text);
        }
        return texts.join("");
      },
      session: async (interpreter: string, scenario: string): Promise<Record<string, any>> => {
        const home = await tempHome("session");
        const { stdout } = await run(interpreter, ["-I", "-B", resolve("../hermes-plugin/tests/harness/drive_hermes.py"),
          "--scenario", scenario, "--home", home, "--socket", socket], {
          cwd: resolve(".."), env: { ...process.env, HOME: home, HERMES_HOME: join(home, "hermes") },
          timeout: 60_000, maxBuffer: 1024 * 1024 }); // One minute and one MiB bound each offline report.
        return JSON.parse(stdout);
      },
    };
  } catch (error) { await close(); throw error; }
}

async function seededFortress(label: string): Promise<{
  readonly env: NodeJS.ProcessEnv;
  readonly fortressDir: string;
}> {
  const home = await tempHome(label);
  const unique = `${label}-${process.pid}-${fortressCounter++}`.replace(/[^a-z0-9-]/g, "-").slice(0, 50);
  const fortressId = `fortress-${unique}`;
  const fortressDir = join(home, "Library", "Application Support", "Sanctuary", "Fortresses", fortressId);
  cleanups.push(() => rm(fortressDir, { recursive: true, force: true }));
  await mkdirChain([
    join(home, "Library"),
    join(home, "Library", "Application Support"),
    join(home, "Library", "Application Support", "Sanctuary"),
    join(home, "Library", "Application Support", "Sanctuary", "Fortresses"),
    fortressDir,
    join(fortressDir, "state"),
  ]);
  const storage = new FilesystemStorage(join(fortressDir, "state"));
  await persistUserProvidedPassphrase(PASS, {
    home,
    storagePath: fortressDir,
    platformOverride: "freebsd",
  });
  const custody = await establishMaster({
    storage,
    passphrase: PASS,
    firstRun: { installMode: "headless", mintRecoveryKey: false },
  });
  const identityManager = new IdentityManager(storage, custody.masterKey);
  await identityManager.load();
  const { storedIdentity } = createIdentity(
    `hermes-${label}`,
    derivePurposeKey(custody.masterKey, "identity-encryption"),
    "passphrase",
  );
  await identityManager.save(storedIdentity);
  const bridgeIdentity = memoryProvenancePublicKeyFingerprint(fromBase64url(storedIdentity.public_key));
  await custody.masterWriteBarrier?.release();
  custody.masterKey.fill(0);
  return {
    fortressDir,
    env: allowlistedEnv(home, bridgeIdentity, `agent-${label}`, fortressId),
  };
}


async function tempHome(label: string): Promise<string> {
  const home = await mkdtemp(join(tmpdir(), `hermes-home-${label}-`));
  await chmod(home, 0o700);
  cleanups.push(() => rm(home, { recursive: true, force: true }));
  return home;
}


function allowlistedEnv(home: string, bridgeIdentity: string, agentId: string, fortressId: string): NodeJS.ProcessEnv {
  return {
    HOME: home,
    LANG: "C",
    TMPDIR: tmpdir(),
    HERMES_MEMORY_BRIDGE_IDENTITY: bridgeIdentity,
    HERMES_MEMORY_AGENT_ID: agentId,
    HERMES_MEMORY_FORTRESS_ID: fortressId,
  };
}


async function mkdirChain(paths: readonly string[]): Promise<void> {
  for (const path of paths) {
    await mkdir(path, { recursive: true, mode: 0o700 });
    await chmod(path, 0o700);
  }
}


function privateFrame(value: Record<string, unknown>): Buffer {
  return encodePrivateFrame(encoder.encode(JSON.stringify(value)));
}


async function socketPair(allowHalfOpen = false): Promise<{ relay: net.Socket; shell: net.Socket; close(): void }> {
  const dir = await mkdtemp(join(tmpdir(), "hermes-shell-socket-"));
  cleanups.push(() => rm(dir, { recursive: true, force: true }));
  const path = join(dir, "pair.sock");
  const server = net.createServer({ allowHalfOpen });
  cleanups.push(async () => {
    await new Promise<void>((resolve) => {
      try {
        server.close(() => resolve());
      } catch {
        resolve();
      }
    });
  });
  const accepted = new Promise<net.Socket>((resolve) => {
    server.once("connection", resolve);
  });
  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    // port-discipline: ignore - unique temporary Unix socket, not a TCP port.
    server.listen(path, resolve);
  });
  const relay = net.createConnection(path);
  const shell = await accepted;
  // A test may fail before its local finally; close peers before server cleanup.
  cleanups.push(async () => { relay.destroy(); shell.destroy(); });
  server.close();
  return {
    relay,
    shell,
    close() {
      relay.destroy();
      shell.destroy();
      try { server.close(); } catch { /* already closed */ }
    },
  };
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
