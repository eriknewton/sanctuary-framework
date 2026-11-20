// Recall coverage measurement. NOT a CI test: `npm test` collects only test/**/*.test.ts and the synthetic-coverage
// tests, so this file runs only through its own config:
//
//   cd server && MEASURE_OUT=/abs/path/recall-coverage.json npx vitest run --config scripts/recall-coverage.vitest.config.ts
//
// What it does. Seeds one temporary filesystem fortress to 250, 500, 1000 and 2000 short passages (owner-side,
// through createSdwMemoryAdapter, the factory the bridge process composes) and, at each size, runs five
// memory_recall calls through the real bridge process (runHermesBridgeProcess), the relay framing and the real
// shim over stdio, timed as the Python client sees it. Each call's query carries one unique term found in exactly
// one target passage. At the largest size (2000 by default) it adds two query shapes, five calls each: a common term that matches every passage
// plus the unique term, and a six-term natural question. A call passes when its target is returned and it is not
// truncated. The JSON records the host (label from the hostname and CPU), the bounds and the storage composition.
//
// Failure modes worth knowing before reading a result:
// - MEASURE_OUT unset writes to the OS temp directory; the path is printed, and a result that "vanished" is there.
// - A busy host inflates wall times; nothing here detects contention, so rerun on an idle machine before quoting.
// - A query with a seventh distinct term reads truncated whatever the coverage; the six-term shape is exactly six.
// - Seeding uses the standard-mode adapter, not the bridge's memory_insert, so save-path costs are not measured.
// - The bridge and shim run as this test's children; a crash mid-run still reaps them in the cleanup, but a
//   SIGKILL of the vitest process itself leaves the shim behind (look for `shim.ts` in the process list).
// - Temporary fortresses live under the OS temp directory and are removed at the end, pass or fail.
import { Buffer } from "node:buffer";
import { spawn, type ChildProcessWithoutNullStreams } from "node:child_process";
import { readFileSync, realpathSync } from "node:fs";
import { chmod, mkdtemp, mkdir, rm, writeFile } from "node:fs/promises";
import net from "node:net";
import { arch, cpus, hostname, platform, release, tmpdir, totalmem } from "node:os";
import { dirname, join, resolve } from "node:path";
import { randomInt } from "node:crypto";
import { performance } from "node:perf_hooks";
import { fileURLToPath } from "node:url";
import { it } from "vitest";
import { IdentityManager } from "../src/cognitive/tools.js";
import { fromBase64url } from "../src/core/encoding.js";
import { createIdentity } from "../src/core/identity.js";
import { derivePurposeKey } from "../src/core/key-derivation.js";
import { establishMaster } from "../src/core/master-custody.js";
import { fortressIdFromStoragePath } from "../src/dashboard/v1_1/wiring.js";
import { PrivateFrameDecoder, encodePrivateFrame, runHermesBridgeProcess } from "../src/hermes-memory-bridge/index.js";
import { HERMES_MAX_PUBLIC_CONNECTIONS, MEMORY_CORPUS_SCAN_CAP } from "../src/hermes-memory-bridge/constants.js";
import {
  RECALL_MAX_SCANNED_UNITS_PER_CALL, RECALL_MAX_TERMS, RECALL_PREFETCH_BUDGET_MS, RECALL_WALL_BUDGET_MS, recallTerms,
} from "../src/hermes-memory-bridge/recall.js";
import * as recallLimits from "../src/hermes-memory-bridge/recall.js";
import { createSdwMemoryAdapter } from "../src/index.js";
import { AuditLog } from "../src/operational/audit-log.js";
import { memoryProvenancePublicKeyFingerprint } from "../src/sdw/memory-provenance-bad-signers.js";
import { memoryInsertIngress } from "../src/sdw/memory-provenance-ingress.js";
import { SdwMemoryProvenanceMigration } from "../src/sdw/memory-provenance-migration.js";
import { createPrimaryMemoryProvenancePublicKeyResolver, createPrimaryMemoryProvenanceSigningHandleResolver } from "../src/sdw/memory-provenance-signing.js";
import { SDW_DOCUMENT_CORPUS_NAMESPACE } from "../src/sdw/records.js";
import { FilesystemStorage } from "../src/storage/filesystem.js";
import { persistUserProvidedPassphrase } from "../src/wrap/passphrase.js";

const SERVER = resolve(dirname(fileURLToPath(import.meta.url)), "..");
// An explicit MEASURE_OUT is the operator's chosen path; the default lives in a fresh private directory, never a
// predictable name in the shared temp directory.
const OUT_OVERRIDE = process.env.MEASURE_OUT;
const PASS = "correct horse battery staple hermes measure"; // Fixture passphrase for a throwaway fortress.
const SIZES = process.env.MEASURE_SIZES ? process.env.MEASURE_SIZES.split(",").map(Number) : [250, 500, 1000, 2000];
// The extra query shapes run at the largest size only: 2000 by default, the corpus ceiling MEMORY_CORPUS_SCAN_CAP.
const EXTRA_SHAPES_AT = Math.max(...SIZES);
const RUNS = 5;
const UNIQUE_TERM_LETTERS = 12; // Twelve random letters: about 26^12 values, so a collision with filler is negligible.
const AGENT = "agent-measure";
const COMMON_TERM = "item"; // Every filler passage and every target contains it.
const encoder = new TextEncoder();
const cleanups: Array<() => Promise<void>> = [];
const letters = (n: number) => Array.from({ length: n }, () => "abcdefghijklmnopqrstuvwxyz"[randomInt(26)]).join("");
const FILLER_SUBJECTS = ["garden", "budget", "review", "dentist", "flight", "library", "printer", "school", "kitchen", "meeting"];
// Fifty-two weeks in a year; about 75 characters per passage.
const filler = (i: number) => `Note ${i}: the ${FILLER_SUBJECTS[i % FILLER_SUBJECTS.length]} ${COMMON_TERM} moved to week ${i % 52} with owner number ${i}.`;
const target = (term: string) => `Reminder: the ${term} handover ${COMMON_TERM} is on Friday afternoon.`;
const SHAPES = {
  // One unique term: the target is the only match.
  unique: (term: string) => `what about the ${term}`,
  // A term every passage contains plus the unique term: the heap fills, and the target ranks first on two terms.
  common: (term: string) => `the ${COMMON_TERM} for ${term}`,
  // A natural question with exactly six distinct terms (decide, term, handover, garden, meeting, friday).
  natural: (term: string) => `what did we decide about the ${term} handover for the garden meeting on friday`,
} as const;
type Shape = keyof typeof SHAPES;

async function tempDir(label: string) {
  const dir = await mkdtemp(join(tmpdir(), label));
  await chmod(dir, 0o700);
  cleanups.push(() => rm(dir, { recursive: true, force: true }));
  return dir;
}

async function seedFortress() {
  const home = await tempDir("hermes-measure-");
  const fortressId = `fortress-measure-${process.pid}`;
  const fortressDir = join(home, "Library", "Application Support", "Sanctuary", "Fortresses", fortressId);
  for (const path of [join(home, "Library"), join(home, "Library", "Application Support"), join(home, "Library", "Application Support", "Sanctuary"),
    join(home, "Library", "Application Support", "Sanctuary", "Fortresses"), fortressDir, join(fortressDir, "state")]) {
    await mkdir(path, { recursive: true, mode: 0o700 });
    await chmod(path, 0o700);
  }
  const storage = new FilesystemStorage(join(fortressDir, "state"));
  await persistUserProvidedPassphrase(PASS, { home, storagePath: fortressDir, platformOverride: "freebsd" });
  const custody = await establishMaster({ storage, passphrase: PASS, firstRun: { installMode: "headless", mintRecoveryKey: false } });
  const identities = new IdentityManager(storage, custody.masterKey);
  await identities.load();
  const { storedIdentity } = createIdentity("hermes-measure", derivePurposeKey(custody.masterKey, "identity-encryption"), "passphrase");
  await identities.save(storedIdentity);
  const bridgeIdentity = memoryProvenancePublicKeyFingerprint(fromBase64url(storedIdentity.public_key));
  await custody.masterWriteBarrier?.release();
  custody.masterKey.fill(0);
  const env = { HOME: home, LANG: "C", TMPDIR: tmpdir(), HERMES_MEMORY_BRIDGE_IDENTITY: bridgeIdentity,
    HERMES_MEMORY_AGENT_ID: AGENT, HERMES_MEMORY_FORTRESS_ID: fortressId };
  return { home, fortressDir, storage, env };
}
type Fortress = Awaited<ReturnType<typeof seedFortress>>;

// Owner-side seeding with the same adapter factory the process shell composes; the bridge is stopped meanwhile.
async function seed(fortress: Fortress, texts: readonly string[]) {
  const custody = await establishMaster({ storage: fortress.storage, passphrase: PASS });
  try {
    // Must match resolveHermesBridgeFortress in process-shell.ts: the bridge keys records by the fortress directory's real path.
    const storagePath = realpathSync(fortress.fortressDir);
    const identities = new IdentityManager(fortress.storage, custody.masterKey);
    await identities.load();
    const options = { storage: fortress.storage, masterKey: custody.masterKey, fortressId: fortressIdFromStoragePath(storagePath), ownerRef: AGENT,
      resolvePrimarySigningHandle: createPrimaryMemoryProvenanceSigningHandleResolver(identities, custody.masterKey),
      resolveSignerPublicKey: createPrimaryMemoryProvenancePublicKeyResolver(identities) };
    const migration = new SdwMemoryProvenanceMigration(options);
    const adapter = createSdwMemoryAdapter({ ...options, mode: "standard", resolveMemoryIntegrityState: () => migration.getState() });
    const ids: string[] = [];
    for (const text of texts) {
      const passage = await adapter.insertPassage({ text, tags: ["turn-capture"], provenanceContext: memoryInsertIngress(() => undefined, "user_content") }, "user_content");
      ids.push(passage.passage_id);
    }
    return ids;
  } finally {
    await custody.masterWriteBarrier?.release();
    custody.masterKey.fill(0);
  }
}

/** Record counts and bytes by record kind in the corpus namespace, plus the filesystem the fortress sits on. */
async function storageComposition(fortress: Fortress) {
  const entries = await fortress.storage.list(SDW_DOCUMENT_CORPUS_NAMESPACE);
  const kinds: Record<string, { records: number; bytes: number }> = {};
  for (const entry of entries) {
    const kind = entry.key.split(".")[0] ?? "other";
    const row = kinds[kind] ??= { records: 0, bytes: 0 };
    row.records++;
    row.bytes += entry.size_bytes;
  }
  let filesystem = "unknown";
  try {
    // Longest mount point that prefixes the fortress path; Linux only, other hosts report "unknown".
    const path = realpathSync(fortress.fortressDir);
    const mounts = readFileSync("/proc/mounts", "utf8").split("\n").map(line => line.split(" "))
      .filter(fields => fields.length > 2 && path.startsWith(fields[1]!)).sort((a, b) => b[1]!.length - a[1]!.length);
    if (mounts[0] !== undefined) filesystem = `${mounts[0][2]} at ${mounts[0][1]}`;
  } catch { /* not Linux */ }
  return { backend: "FilesystemStorage", filesystem, corpus_namespace: SDW_DOCUMENT_CORPUS_NAMESPACE, records_by_kind: kinds };
}

async function startBridge(fortress: Fortress) {
  const local: Array<() => Promise<void>> = [];
  const close = async () => { for (const step of local.splice(0).reverse()) await step(); };
  cleanups.push(close);
  const bridgeLog: string[] = [];
  const dir = await tempDir("hm-pair-");
  const pairPath = join(dir, "p.sock");
  const server = net.createServer();
  const accepted = new Promise<net.Socket>(ok => server.once("connection", ok));
  // port-discipline: ignore - unique temporary Unix socket, not a TCP port.
  await new Promise<void>((ok, fail) => { server.once("error", fail); server.listen(pairPath, ok); });
  const relaySide = net.createConnection(pairPath);
  const shellSide = await accepted;
  server.close();
  local.push(async () => { relaySide.destroy(); shellSide.destroy(); });
  const readyDecoder = new PrivateFrameDecoder();
  const ready = new Promise<void>(ok => {
    const onData = (bytes: Buffer) => { readyDecoder.push(bytes); if (readyDecoder.next().kind !== "need_more") { relaySide.off("data", onData); ok(); } };
    relaySide.on("data", onData);
  });
  const shell = await runHermesBridgeProcess({ env: fortress.env, relaySocketFactory: () => shellSide,
    storageFor: path => new FilesystemStorage(join(path, "state")), uid: process.getuid?.() ?? 0,
    stderr: { write: (text: string) => { bridgeLog.push(text); return true; } } });
  local.push(async () => { shell.signalStop("SIGTERM"); await shell.exited; });
  await ready;
  const sockets = new Map<string, net.Socket>();
  let counter = 0;
  const send = (value: Record<string, unknown>) => relaySide.write(encodePrivateFrame(encoder.encode(JSON.stringify(value))));
  const decoder = new PrivateFrameDecoder();
  relaySide.on("data", (bytes: Buffer) => {
    decoder.push(bytes);
    for (;;) {
      const next = decoder.next();
      if (next.kind === "need_more") return;
      if (next.kind === "fatal") throw next.error;
      const frame = JSON.parse(Buffer.from(next.body).toString());
      if (frame.type === "probe") send({ type: "probe_reply", connection_id: frame.connection_id, nonce: frame.nonce });
      if (frame.type === "close") sockets.get(frame.connection_id)?.destroy();
      if (frame.type === "response") sockets.get(frame.connection_id)?.write(encodePrivateFrame(Buffer.from(frame.result_b64, "base64")));
    }
  });
  const socketDir = await tempDir("hm-");
  const socket = join(socketDir, "s");
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
        if (value.type === "ping") peer.write(encodePrivateFrame(encoder.encode(JSON.stringify({ type: "pong" }))));
        else send({ type: "frame", connection_id: id, frame_b64: body.toString("base64") });
      }
    });
    peer.on("error", () => peer.destroy());
    peer.on("close", () => { sockets.delete(id); send({ type: "closed", connection_id: id }); });
  });
  // port-discipline: ignore - unique temporary Unix socket, not a TCP port.
  await new Promise<void>((ok, fail) => { relay.once("error", fail); relay.listen(socket, ok); });
  local.push(async () => { for (const peer of sockets.values()) peer.destroy(); await new Promise<void>(ok => relay.close(() => ok())); });
  return { socket, bridgeLog, close };
}

// The real shim over stdio, spoken to line by line as the Python client does. Its cleanup reaps it on any exit path.
async function shimSession(socket: string, log: string) {
  const child: ChildProcessWithoutNullStreams = spawn(process.execPath, ["--import", "tsx", join(SERVER, "test/hermes-plugin/harness/shim.ts"), socket, log],
    { cwd: SERVER, stdio: ["pipe", "pipe", "pipe"] });
  const exited = new Promise<void>(ok => child.once("exit", () => ok()));
  const reap = async () => {
    if (child.exitCode !== null || child.signalCode !== null) return;
    child.stdin.end();
    const graceful = await Promise.race([exited.then(() => true), new Promise<boolean>(ok => setTimeout(() => ok(false), 5000).unref())]);
    if (!graceful) { child.kill("SIGKILL"); await exited; }
  };
  cleanups.push(reap);
  let buffer = "";
  const waiters: Array<(line: string) => void> = [];
  child.stdout.on("data", (bytes: Buffer) => {
    buffer += bytes.toString();
    for (let end = buffer.indexOf("\n"); end >= 0; end = buffer.indexOf("\n")) {
      const line = buffer.slice(0, end); buffer = buffer.slice(end + 1);
      waiters.shift()?.(line);
    }
  });
  child.stderr.resume();
  let id = 0;
  const request = (method: string, params: Record<string, unknown>) => new Promise<any>((ok, fail) => {
    const onExit = () => fail(new Error("shim exited before replying"));
    child.once("exit", onExit);
    waiters.push(line => { child.off("exit", onExit); ok(JSON.parse(line)); });
    child.stdin.write(JSON.stringify({ jsonrpc: "2.0", id: ++id, method, params }) + "\n");
  });
  await request("initialize", { protocolVersion: "2025-11-25", capabilities: {}, clientInfo: { name: "sanctuary-hermes-memory-client", version: "1" } });
  child.stdin.write(JSON.stringify({ jsonrpc: "2.0", method: "notifications/initialized" }) + "\n");
  await request("tools/list", {});
  return {
    recall: async (query: string) => {
      const started = performance.now();
      const reply = await request("tools/call", { name: "memory_recall", arguments: { query } });
      const wall_ms = performance.now() - started;
      return { wall_ms, value: JSON.parse(reply.result.content[0].text) };
    },
    close: reap,
  };
}

const median = (values: readonly number[]) => {
  const sorted = [...values].sort((a, b) => a - b);
  const middle = Math.floor(sorted.length / 2);
  return sorted.length % 2 === 1 ? sorted[middle]! : (sorted[middle - 1]! + sorted[middle]!) / 2;
};

it("measures recall coverage at 250, 500, 1000 and 2000 passages", async () => {
  // The six-term shape must not reach the term limit, or it would read truncated whatever the coverage.
  if (recallTerms(SHAPES.natural(letters(UNIQUE_TERM_LETTERS))).terms.length !== RECALL_MAX_TERMS) throw new Error("natural query is not six terms");
  const rows: Record<string, unknown>[] = [];
  let seeded = 0;
  try {
    const fortress = await seedFortress();
    for (const size of SIZES) {
      // Five target passages per size, each the only one carrying its unique term; filler fills the rest.
      const terms = Array.from({ length: RUNS }, () => letters(UNIQUE_TERM_LETTERS));
      const texts = Array.from({ length: size - seeded - terms.length }, (_, i) => filler(seeded + i));
      const seedStarted = performance.now();
      await seed(fortress, texts);
      const targetIds = await seed(fortress, terms.map(target));
      seeded = size;
      const seed_ms = performance.now() - seedStarted;
      const bridge = await startBridge(fortress);
      try {
        const shim = await shimSession(bridge.socket, join(fortress.home, `shim-${size}.log`));
        try {
          const shapes: Shape[] = size === EXTRA_SHAPES_AT ? ["unique", "common", "natural"] : ["unique"];
          for (const shape of shapes) {
            const runs = [];
            for (let run = 0; run < RUNS; run++) {
              const { wall_ms, value } = await shim.recall(SHAPES[shape](terms[run]!));
              const ids = (value.passages ?? []).map((p: { passage_id: string }) => p.passage_id);
              runs.push({ run: run + 1, wall_ms: Math.round(wall_ms), outcome: value.outcome, truncated: value.truncated,
                target_returned: ids.includes(targetIds[run]), passages_returned: ids.length });
            }
            const walls = runs.map(run => run.wall_ms);
            rows.push({ passages: size, shape, query_example: SHAPES[shape]("<unique>"), seed_ms: Math.round(seed_ms),
              found: runs.filter(run => run.target_returned).length, truncated: runs.filter(run => run.truncated).length,
              median_wall_ms: median(walls), max_wall_ms: Math.max(...walls), runs });
            console.log(JSON.stringify(rows.at(-1)));
          }
        } finally { await shim.close(); }
      } finally { await bridge.close(); }
    }
    const composition = await storageComposition(fortress);
    // The bridge's own memory_recall audit rows carry truncated too; read them as a cross-check.
    const custody = await establishMaster({ storage: fortress.storage, passphrase: PASS });
    let audited: unknown[] = [];
    try {
      const entries = (await new AuditLog(fortress.storage, custody.masterKey).query({ limit: 100 })).entries;
      audited = entries.filter((row: any) => row.details?.kind === "memory_recall").map((row: any) => ({ truncated: row.details.truncated, passage_count: row.details.passage_ids.length }));
    } finally { await custody.masterWriteBarrier?.release(); custody.masterKey.fill(0); }
    const verifyLimits = recallLimits as Record<string, unknown>;
    const result = {
      measured_at: new Date().toISOString(),
      box: { label: `${hostname()} (${cpus()[0]?.model ?? "unknown cpu"}, ${cpus().length} cpus)`, hostname: hostname(),
        platform: platform(), release: release(), arch: arch(), cpu: cpus()[0]?.model, cpu_count: cpus().length,
        memory_gib: Math.round(totalmem() / 2 ** 30), node: process.version }, // 2^30 bytes per GiB.
      bounds: { prefetch_budget_ms: RECALL_PREFETCH_BUDGET_MS, recall_wall_budget_ms: RECALL_WALL_BUDGET_MS, candidate_cap: MEMORY_CORPUS_SCAN_CAP,
        scanned_units_cap: RECALL_MAX_SCANNED_UNITS_PER_CALL,
        // Absent before score-first recall; recorded so a base-versus-change comparison names its code.
        verify_candidates: verifyLimits.RECALL_VERIFY_CANDIDATES ?? null, verify_reserve_ms: verifyLimits.RECALL_VERIFY_RESERVE_MS ?? null },
      storage: composition,
      method: "One temporary filesystem-backed fortress, seeded owner-side through createSdwMemoryAdapter (the factory the bridge process composes) with short passages of about 75 characters, tagged turn-capture; recall through the real bridge process (runHermesBridgeProcess), the relay framing from the plugin acceptance fixture and the real shim, timed at the shim's stdio as the Python client sees it. Shapes: unique (one unique term, one match), common (a term in every passage plus the unique term), natural (six distinct terms including the unique term). Scan order is the store's key order, which is independent of insertion order.",
      rows,
      audit_memory_recall_rows: audited,
    };
    const out = OUT_OVERRIDE ?? join(await mkdtemp(join(tmpdir(), "recall-coverage-")), "recall-coverage.json");
    // 0o600: owner read and write only; "wx" refuses to follow or overwrite an existing file.
    await writeFile(out, JSON.stringify(result, null, 1) + "\n", { flag: "wx", mode: 0o600 });
    console.log(`recall coverage written to ${out}`);
  } finally {
    for (const cleanup of cleanups.splice(0).reverse()) await cleanup();
  }
}, 4 * 3_600_000); // Four hours: seeding 2000 signed passages on a slow disk dominates.
