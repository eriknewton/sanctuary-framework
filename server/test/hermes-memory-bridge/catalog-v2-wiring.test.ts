// Catalog v2 runs through the production bridge and real stdio client with a temporary fortress.
// The test relay implements only SEAM framing and probe replies. Native Swift is macOS-only,
// with platform evidence supplied by the attended H2-0 drill, outside this Linux test.
import { Buffer } from "node:buffer";
import { chmod, mkdtemp, mkdir, rm } from "node:fs/promises";
import net from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Duplex, PassThrough } from "node:stream";
import { afterEach, expect, it, vi } from "vitest";
import { fortressIdFromStoragePath } from "../../src/dashboard/v1_1/wiring.js";
import { IdentityManager } from "../../src/cognitive/tools.js";
import { fromBase64url } from "../../src/core/encoding.js";
import { createIdentity } from "../../src/core/identity.js";
import { derivePurposeKey } from "../../src/core/key-derivation.js";
import { establishMaster } from "../../src/core/master-custody.js";
import { PrivateFrameDecoder, encodePrivateFrame, runHermesBridgeProcess } from "../../src/hermes-memory-bridge/index.js";
import { HermesBridgeCore } from "../../src/hermes-memory-bridge/bridge-core.js";
import { HermesMemoryClient, type ClientPorts } from "../../src/hermes-memory-client/client.js";
import { AuditLog } from "../../src/operational/audit-log.js";
import { OWN_SCOPE_MEMORY_SAVES } from "../../src/principal-policy/gate.js";
import { memoryProvenancePublicKeyFingerprint } from "../../src/sdw/memory-provenance-bad-signers.js";
import { SdwDocumentCorpusStore } from "../../src/sdw/document-corpus-store.js";
import { FilesystemStorage } from "../../src/storage/filesystem.js";
import { persistUserProvidedPassphrase } from "../../src/wrap/passphrase.js";

const PASS = "correct horse battery staple hermes";
const encoder = new TextEncoder();
const cleanups: Array<() => Promise<void>> = [];
let fortressCounter = 0;
afterEach(async () => { for (const clean of cleanups.splice(0).reverse()) await clean(); vi.restoreAllMocks(); });

it("serves catalog v2, saves without a hold, recalls and preserves three ordinary refusals", () => runScenario("full"));
it("exposes exactly seven tools through the production client", () => runScenario("catalog"));
it("returns a recall result through the production client", () => runScenario("recall"));
it("returns three consecutive refusals as ordinary results through the production client", () => runScenario("refusals"));
it("refuses malformed recall arguments as an ordinary result through the production client", () => runScenario("malformed"));

async function runScenario(scenario: "full" | "catalog" | "recall" | "refusals" | "malformed") {
  const fixture = await seededFortress("catalog-v2");
  const pair = await socketPair();
  let core: HermesBridgeCore | undefined;
  const original = HermesBridgeCore.prototype.relayFrame;
  vi.spyOn(HermesBridgeCore.prototype, "relayFrame").mockImplementation(function (this: HermesBridgeCore, frame) {
    core = this;
    return original.call(this, frame);
  });
  const shell = await runHermesBridgeProcess({
    env: fixture.env,
    relaySocketFactory: () => pair.shell,
    storageFor: (fortressDir) => new FilesystemStorage(join(fortressDir, "state")),
    uid: process.getuid?.() ?? 0,
  });
  cleanups.push(async () => { shell.signalStop("SIGTERM"); await shell.exited; });
  const input = new PassThrough();
  const relayInput = new PassThrough();
  const frames: Record<string, unknown>[] = [];
  const lines: string[] = [];
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
        frames.push(frame);
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
        lines.push(bytes.toString());
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
    const call = (name: string, args: unknown) => request("tools/call", { name, arguments: args });
    const tool = (response: any) => {
      expect(response).toHaveProperty("result");
      expect(response).not.toHaveProperty("error");
      return JSON.parse(response.result.content[0].text);
    };
    await request("initialize", { protocolVersion: "2025-11-25", capabilities: {}, clientInfo: { name: "fixture", version: "1" } });
    input.write(JSON.stringify({ jsonrpc: "2.0", method: "notifications/initialized" }) + "\n");
    const catalog = await request("tools/list");
    const names = catalog.result.tools.map((entry: any) => entry.name);
    if (scenario === "full" || scenario === "catalog") {
    expect.soft(names).toHaveLength(7);
    expect.soft(new Set(names)).toEqual(new Set(["memory_insert", "memory_get", "memory_search", "memory_recall", "sign_statement", "export_memory", "protection_rules"]));
    }
    if (scenario === "catalog") return;
    if (scenario === "recall") {
      expect(tool(await call("memory_recall", { query: "when is the board meeting?" })))
        .toEqual({ outcome: "recalled", context: "", passages: [], truncated: false });
      return;
    }
    if (scenario === "malformed") {
      expect(tool(await call("memory_recall", { query: 7 }))).toEqual({ outcome: "denied", message: "Request denied." });
      return;
    }
    if (scenario === "refusals") {
      const before = frames.length;
      for (const [name, args, expected] of [
        ["sign_statement", { statement: "I approve the Q3 plan." }, { outcome: "unavailable", message: "This is not available yet; nothing was done." }],
        ["protection_rules", {}, { outcome: "denied", message: "Request denied." }],
        ["export_memory", { scope: "all" }, { outcome: "unavailable", message: "This is not available yet; nothing was done." }],
      ] as const) {
        expect(tool(await call(name, args))).toEqual(expected);
        expect(core!.snapshot().slot).toBeUndefined();
      }
      expect(frames.slice(before).map(frame => frame.type)).toEqual(["response", "response", "response"]);
      expect(lines.join("")).not.toMatch(/error|failed/i);
      return;
    }
    const savedText = "The board meeting moved to Thursday 3pm.";
    const saved = tool(await call("memory_insert", { text: savedText, taint: "user_content" }));
    expect(saved.outcome).toBe("saved");
    const passageId = saved.passage.passage_id;
    expect(passageId).toEqual(expect.any(String));
    const query = "when is the board meeting?";
    const recalled = tool(await call("memory_recall", { query }));
    expect(recalled.outcome).toBe("recalled");
    expect(recalled.context).toContain("Thursday 3pm");
    expect(recalled.passages.map((p: any) => p.passage_id)).toContain(passageId);
    expect(recalled.truncated).toBe(false);
    const internal = core as unknown as { ports: { adapter: {
      insertPassage: (...args: any[]) => unknown; getPassage: (...args: any[]) => unknown;
      searchPassages: (...args: any[]) => unknown; recallPassages: (...args: any[]) => unknown;
    }; appendAudit: (...args: any[]) => unknown } };
    const unusedPorts = [vi.spyOn(internal.ports.adapter, "insertPassage"), vi.spyOn(internal.ports.adapter, "getPassage"),
      vi.spyOn(internal.ports.adapter, "searchPassages"), vi.spyOn(internal.ports.adapter, "recallPassages"), vi.spyOn(internal.ports, "appendAudit")];
    const before = frames.length;
    const fixed = { outcome: "unavailable", message: "This is not available yet; nothing was done." };
    expect(tool(await call("sign_statement", { statement: "I approve the Q3 plan." }))).toEqual(fixed);
    expect(core!.snapshot().slot).toBeUndefined();
    expect(tool(await call("protection_rules", {}))).toEqual({ outcome: "denied", message: "Request denied." });
    expect(core!.snapshot().slot).toBeUndefined();
    expect(tool(await call("export_memory", { scope: "all" }))).toEqual(fixed);
    expect(core!.snapshot().slot).toBeUndefined();
    expect(frames.slice(before).map(frame => frame.type)).toEqual(["response", "response", "response"]);
    for (const unused of unusedPorts) { expect(unused).not.toHaveBeenCalled(); unused.mockRestore(); }
    expect(JSON.stringify(tool(await call("memory_get", { passage_id: passageId })))).toContain(savedText);
    expect(tool(await call("memory_recall", { query: 7 }))).toEqual({ outcome: "denied", message: "Request denied." });
    expect(lines.every(line => !/error|failed/i.test(line))).toBe(true);
    expect(lines.map(line => JSON.parse(line)).filter(line => "error" in line)).toHaveLength(0);
    pair.relay.write(privateFrame({ type: "relay_shutdown" }));
    expect(await shell.exited).toBe(0);
    const storage = new FilesystemStorage(join(fixture.fortressDir, "state"));
    const custody = await establishMaster({ storage, passphrase: PASS });
    try {
      const audit = new AuditLog(storage, custody.masterKey);
      const all = (await audit.query({ limit: 100 })).entries;
      const entries = all.filter(entry => entry.operation === "hermes_memory_bridge");
      expect(entries).toHaveLength(2); // One insert and one recall; refusals add no rows.
      const inserted = entries.filter(entry => entry.details?.kind === "insert_admitted");
      expect(inserted).toHaveLength(1);
      expect(inserted[0]!.details).toMatchObject({ operation: OWN_SCOPE_MEMORY_SAVES.memory_insert,
        agent_id: `agent:${fixture.env.HERMES_MEMORY_AGENT_ID}`, requester_verified: false, passage_id: passageId });
      const recalls = entries.filter(entry => entry.details?.kind === "memory_recall");
      expect(recalls).toHaveLength(1);
      expect(recalls[0]!.details).toMatchObject({ term_count: 2, passage_ids: [passageId], query_sha256: expect.any(String),
        agent_id: `agent:${fixture.env.HERMES_MEMORY_AGENT_ID}`, requester_verified: false });
      expect(JSON.stringify(all)).not.toContain(savedText);
      expect(JSON.stringify(all)).not.toContain(query);
      const corpus = new SdwDocumentCorpusStore({ storage, masterKey: custody.masterKey, fortressId: fortressIdFromStoragePath(fixture.fortressDir) });
      expect(await corpus.getDocument(String(inserted[0]!.details!.document_id))).not.toBeNull();
    } finally {
      await custody.masterWriteBarrier?.release();
      custody.masterKey.fill(0);
    }
  } finally {
    client?.signal();
    input.destroy(); relayInput.destroy();
    for (const timer of timers) clearTimeout(timer);
    shell.signalStop("SIGTERM");
    await shell.exited;
    pair.close();
  }
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


function relayPublicFrame(connectionId: string, value: Record<string, unknown>): Buffer {
  return privateFrame({
    type: "frame",
    connection_id: connectionId,
    frame_b64: Buffer.from(JSON.stringify(value), "utf8").toString("base64"),
  });
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
