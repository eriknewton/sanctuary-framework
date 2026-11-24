// fail-before-exempt: new worker job module, no base behaviour.
import { fork, type ChildProcess } from "node:child_process";
import { once } from "node:events";
import { mkdtemp, realpath, rm } from "node:fs/promises";
import { createRequire } from "node:module";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { ed25519 } from "@noble/curves/ed25519";
import { afterEach, describe, expect, it } from "vitest";
import { StateStore } from "../../src/cognitive/state-store.js";
import { toBase64url, stringToBytes } from "../../src/core/encoding.js";
import { encrypt } from "../../src/core/encryption.js";
import type { StoredIdentity } from "../../src/core/identity.js";
import { derivePurposeKey, deriveNamespaceKey } from "../../src/core/key-derivation.js";
import { generateRandomKey } from "../../src/core/random.js";
import { LocalAuthority } from "../../src/local-recompile/authority.js";
import { LocalJobQueue } from "../../src/local-recompile/job-queue.js";
import { CHUNK_BYTES, CHUNK_SUMMARY_MAX_BYTES, RECORD_PLAINTEXT_MAX_BYTES, NUM_PREDICT_CHUNK, NUM_PREDICT_COMBINE, PROMPT_TOKEN_BOUND, WORKER_QUEUE_MAX, WORKER_QUEUE_PER_SEAT_MAX } from "../../src/local-recompile/limits.js";
import { LocalOplog, type OplogRow } from "../../src/local-recompile/oplog.js";
import { frameAndChunk, recordClose, recordOpen, SUMMARY_SYSTEM_TEXT, truncateUtf8 } from "../../src/local-recompile/prompts.js";
import { LocalResultsStore, PENDING_GRACE_MS } from "../../src/local-recompile/results-store.js";
import { deriveLocalStoreKeys } from "../../src/local-recompile/store-keys.js";
import { RECORD_STORED_MAX_BYTES, resultSeatId } from "../../src/local-recompile/summarize-job.js";
import { LocalWorkerClient, type WorkerClientEvent } from "../../src/local-recompile/worker-client.js";
import type { LocalTaskJob, WorkerLimits } from "../../src/local-recompile/worker-protocol.js";
import { DEFAULT_POLICY } from "../../src/principal-policy/loader.js";
import type { PrincipalPolicy } from "../../src/principal-policy/types.js";
import { resolveCustodyLockRoot } from "../../src/storage/cross-process-lock.js";
import { FilesystemStorage } from "../../src/storage/filesystem.js";
import { isAlive } from "./helpers/local-task-server.js";

const FAKE_CHILD = fileURLToPath(new URL("./fixtures/fake-ollama-child.ts", import.meta.url));
const TSX = createRequire(import.meta.url).resolve("tsx");
const LOCK_ROOT = resolveCustodyLockRoot(process.getuid!(), { env: process.env, platform: process.platform });
const TAG = "qwen2.5:1.5b";
const DIGEST = "1".repeat(64);
const RECORD_SENTINEL = "RECORD-SENTINEL-7f3a";
const MODEL_SENTINEL = "MODEL-SENTINEL-91c2";
const KID = "writer-one";
// Long enough for a job over a few fake calls to reach its final row on a loaded machine.
const JOB_WAIT_MS = 60_000;
const SEAT = "agent:summarize-test";
// Must match the record frame in src/local-recompile/prompts.ts.
const OPEN_1 = "\n<<<record [1]>>>\n";
const CLOSE_1 = "\n<<<end of record [1]>>>\n";

const cleanups: Array<() => Promise<void>> = [];
afterEach(async () => {
  const failures: unknown[] = [];
  for (const step of cleanups.splice(0).reverse()) {
    try { await step(); } catch (error) { failures.push(error); }
  }
  if (failures.length > 0) throw failures[0];
});

interface FakeModel {
  port: number;
  requests: Array<{ method: string; path: string; body: string; local_address: string; host: string }>;
  script(update: Record<string, unknown>): void;
}

async function startFake(script: Record<string, unknown> = {}): Promise<FakeModel> {
  const child: ChildProcess = fork(FAKE_CHILD, [], { execArgv: ["--import", TSX], stdio: ["ignore", "ignore", "ignore", "ipc"] });
  cleanups.push(async () => {
    if (child.exitCode === null && child.signalCode === null) {
      const exited = once(child, "exit");
      child.kill("SIGKILL");
      await exited;
    }
    expect(isAlive(child.pid)).toBe(false);
  });
  const requests: FakeModel["requests"] = [];
  const port = await new Promise<number>((resolve, reject) => {
    child.on("message", (message: { type: string; port?: number } & FakeModel["requests"][number]) => {
      if (message.type === "listening") resolve(message.port!);
      if (message.type === "request") requests.push(message);
    });
    child.once("exit", () => reject(new Error("fake model exited")));
  });
  const fake: FakeModel = { port, requests, script: (update) => child.send({ type: "script", script: update }) };
  fake.script({ tag: TAG, digest: DIGEST, reply: `summary ${MODEL_SENTINEL}`, ...script });
  return fake;
}

interface Fortress {
  root: string;
  storage: FilesystemStorage;
  masterKey: Uint8Array;
  identity: StoredIdentity;
  write(namespace: string, key: string, value: string): Promise<void>;
}

async function fortress(): Promise<Fortress> {
  const root = await realpath(await mkdtemp(join(tmpdir(), "lr1b-job-")));
  cleanups.push(() => rm(root, { recursive: true, force: true }));
  const storage = new FilesystemStorage(join(root, "state"));
  const masterKey = generateRandomKey();
  const seed = generateRandomKey();
  const idKey = derivePurposeKey(masterKey, "identity-encryption");
  const identity: StoredIdentity = {
    identity_id: KID,
    label: "writer",
    public_key: toBase64url(ed25519.getPublicKey(seed)),
    did: "did:key:test",
    created_at: new Date().toISOString(),
    key_type: "ed25519",
    key_protection: "passphrase",
    encrypted_private_key: encrypt(seed, idKey),
    rotation_history: [],
  };
  await storage.write("_identities", KID, stringToBytes(JSON.stringify(encrypt(stringToBytes(JSON.stringify(identity)), idKey))));
  const store = new StateStore(storage, masterKey);
  return {
    root,
    storage,
    masterKey,
    identity,
    write: async (namespace, key, value) => {
      await store.write(namespace, key, value, KID, identity.encrypted_private_key, idKey);
    },
  };
}

interface Rig {
  f: Fortress;
  client: LocalWorkerClient;
  authority: LocalAuthority;
  events: WorkerClientEvent[];
  submit(refs: Array<{ namespace: string; key: string }>, options?: { seat?: string; instruction?: string }): string;
  rows(): Promise<OplogRow[]>;
  waitForEnd(requestId: string): Promise<OplogRow>;
  results(): LocalResultsStore;
}

let counter = 0;
function requestId(): string {
  counter += 1;
  return `${process.pid.toString(16)}${counter.toString(16)}`.padStart(32, "0");
}

async function rig(f: Fortress, fake: FakeModel | null, options: { policy?: PrincipalPolicy; limits?: WorkerLimits; deriveKey?: (m: Uint8Array, l: string) => Uint8Array } = {}): Promise<Rig> {
  const descriptor = Object.freeze({ runtime_tag: TAG, manifest_digest: DIGEST, endpoint: Object.freeze({ address: "127.0.0.1", port: fake?.port ?? 9 }) });
  const authority = new LocalAuthority({
    binding: { describeVerifiedLocalBinding: () => ({ ok: true, epoch: 1, descriptor }) },
    policy: options.policy ?? DEFAULT_POLICY,
    masterKey: f.masterKey,
    identities: () => [f.identity],
    ...(options.deriveKey ? { deriveKey: options.deriveKey } : {}),
  });
  authority.arm();
  const keys = deriveLocalStoreKeys(f.masterKey);
  const events: WorkerClientEvent[] = [];
  const client = new LocalWorkerClient({
    storageRoot: join(f.root, "state"),
    custodyLockRoot: LOCK_ROOT,
    oplogKey: keys.oplogKey,
    resultsKey: keys.resultsKey,
    answerAuthority: (id) => authority.reply(id),
    onEvent: (event) => events.push(event),
    ...(options.limits ? { limits: options.limits } : {}),
  });
  const pids: number[] = [];
  cleanups.push(async () => {
    await client.close();
    for (const pid of pids) expect(isAlive(pid)).toBe(false);
  });
  client.start();
  const deadline = Date.now() + JOB_WAIT_MS;
  while (client.state !== "state_READY") {
    if (Date.now() > deadline) throw new Error("worker not ready");
    await new Promise((resolve) => setTimeout(resolve, 20));
  }
  pids.push(client.pid!);
  const readRows = async () => {
    const oplog = new LocalOplog(f.storage, keys.oplogKey);
    try { return await oplog.readRows(0, 10_000); } finally { oplog.close(); }
  };
  return {
    f,
    client,
    authority,
    events,
    submit: (refs, submitOptions = {}) => {
      const id = requestId();
      authority.register({ request_id: id, refs });
      const job: LocalTaskJob = { type: "job", request_id: id, seat: submitOptions.seat ?? SEAT, kind: "summarize", refs, instruction: submitOptions.instruction ?? "Focus on decisions." };
      expect(client.send(job)).toBe(true);
      return id;
    },
    rows: readRows,
    waitForEnd: async (id) => {
      const end = Date.now() + JOB_WAIT_MS;
      for (;;) {
        const final = (await readRows()).find((row) =>
          "request_id" in row.body && row.body.request_id === id && ["job_committed", "job_refused", "job_failed", "job_dropped"].includes(row.kind));
        if (final) return final;
        if (Date.now() > end) throw new Error("job did not end");
        await new Promise((resolve) => setTimeout(resolve, 50));
      }
    },
    results: () => new LocalResultsStore(f.storage, keys.resultsKey, new LocalOplog(f.storage, keys.oplogKey)),
  };
}

function rowsFor(rows: OplogRow[], id: string): OplogRow[] {
  return rows.filter((row) => "request_id" in row.body && row.body.request_id === id);
}

const generateRequests = (fake: FakeModel) => fake.requests.filter((request) => request.path === "/api/generate");

describe("summarize job", () => {
  it("pins the record frame and the stored-size derivation", () => {
    expect(recordOpen(1)).toBe(OPEN_1);
    expect(recordClose(1)).toBe(CLOSE_1);
    // Two unpadded base64url copies of 64 KiB plus the 16-byte tag, and a 16 KiB envelope allowance.
    expect(RECORD_STORED_MAX_BYTES).toBe(2 * Math.ceil((4 * (64 * 1024 + 16)) / 3) + 16 * 1024);
    expect(Buffer.byteLength(SUMMARY_SYSTEM_TEXT)).toBeLessThan(1_024);
  });

  it("chunks never split a character and cite the records each chunk covers", () => {
    const records = ["€".repeat(20_000), "plain text record"];
    const chunks = frameAndChunk(records)!;
    expect(chunks.length).toBeGreaterThan(1);
    for (const chunk of chunks) {
      expect(chunk.bytes).toBeLessThanOrEqual(CHUNK_BYTES);
      expect(chunk.text).not.toContain("�");
    }
    expect(chunks.map((chunk) => chunk.text).join("")).toBe(records.map((text, i) => `${recordOpen(i + 1)}${text}${recordClose(i + 1)}`).join(""));
    expect(chunks.at(-1)!.cites).toContain(2);
    expect(chunks[0]!.cites).toEqual([1]);
    expect(truncateUtf8("€€", 4)).toEqual({ text: "€", truncated: true });
  });

  it("the happy path for one record: one call, no combine, a committed result with code-attached citations", async () => {
    const f = await fortress();
    await f.write("notes", "one", `The team decided to ship on Friday. ${RECORD_SENTINEL}`);
    const fake = await startFake();
    const r = await rig(f, fake);
    const id = r.submit([{ namespace: "notes", key: "one" }]);
    expect((await r.waitForEnd(id)).kind).toBe("job_committed");
    expect(generateRequests(fake)).toHaveLength(1);
    expect(rowsFor(await r.rows(), id).map((row) => row.kind)).toEqual([
      "job_queued", "job_started", "result_pending", "job_call", "result_committed", "job_committed",
    ]);
    const object = await r.results().get(id);
    expect(object).toMatchObject({ request_id: id, seat: resultSeatId(SEAT), kind: "summarize", state: "committed" });
    expect(object!.body).toEqual({
      summary: `summary ${MODEL_SENTINEL} 1`,
      refs: ['{"key":"one","n":1,"namespace":"notes"}'],
      chunk_cites: ["1"],
      model_runtime_tag: TAG,
      model_manifest_digest: DIGEST,
      truncated: "false",
    });
    expect(r.events.filter((event) => event.type === "job_state").map((event) => (event as { state: string }).state))
      .toEqual(["state_QUEUED", "state_AUTHORITY", "state_DIGEST", "state_READ", "state_GENERATE", "state_COMMIT", "state_DONE"]);
  }, 120_000);

  it("the happy path for a 100 KiB set: seven chunk calls and one combine", async () => {
    const f = await fortress();
    for (let i = 0; i < 4; i += 1) await f.write("notes", `part-${i}`, `${String.fromCharCode(97 + i)}`.repeat(25 * 1024));
    const fake = await startFake();
    const r = await rig(f, fake);
    const refs = [0, 1, 2, 3].map((i) => ({ namespace: "notes", key: `part-${i}` }));
    const id = r.submit(refs);
    expect((await r.waitForEnd(id)).kind).toBe("job_committed");
    const calls = rowsFor(await r.rows(), id).filter((row) => row.kind === "job_call").map((row) => (row.body as { phase: string }).phase);
    expect(calls).toEqual([...Array(7).fill("chunk"), "combine"]);
    const object = await r.results().get(id);
    expect(object!.body!.summary).toBe(`summary ${MODEL_SENTINEL} 8`);
    // Citations are what the framing attached to each chunk, recomputed here from the same record texts.
    const texts = [0, 1, 2, 3].map((i) => String.fromCharCode(97 + i).repeat(25 * 1024));
    expect(object!.body!.chunk_cites).toEqual(frameAndChunk(texts)!.map((chunk) => chunk.cites.join(",")));
    expect(object!.body!.chunk_cites).toHaveLength(7);
    // Every call carries its generation bounds and streams, over the literal loopback address.
    const requests = generateRequests(fake);
    expect(requests).toHaveLength(8);
    for (const [index, request] of requests.entries()) {
      const body = JSON.parse(request.body);
      expect(body.stream).toBe(true);
      expect(body.model).toBe(TAG);
      expect(body.options).toEqual({ num_predict: index < 7 ? NUM_PREDICT_CHUNK : NUM_PREDICT_COMBINE, num_ctx: PROMPT_TOKEN_BOUND });
      expect(request.host).toBe(`127.0.0.1:${fake.port}`);
      expect(request.local_address).toBe("127.0.0.1");
    }
    expect(fake.requests.filter((request) => request.path === "/api/tags")).toHaveLength(1);
  }, 120_000);

  const refusals: Array<[string, string, (f: Fortress) => Promise<{ refs: Array<{ namespace: string; key: string }>; fake?: Record<string, unknown>; options?: Parameters<typeof rig>[2] }>]> = [
    ["a bad model digest", "model_digest_mismatch", async (f) => { await f.write("notes", "one", "text"); return { refs: [{ namespace: "notes", key: "one" }], fake: { mode: "bad_digest" } }; }],
    ["a missing model", "model_unavailable", async (f) => { await f.write("notes", "one", "text"); return { refs: [{ namespace: "notes", key: "one" }], fake: { mode: "missing" } }; }],
    ["a missing record", "record_missing", async () => ({ refs: [{ namespace: "notes", key: "absent" }] })],
    ["an oversized record", "record_oversized", async (f) => {
      await f.storage.write("notes", "big", new Uint8Array(RECORD_STORED_MAX_BYTES + 1));
      return { refs: [{ namespace: "notes", key: "big" }] };
    }],
    ["a record whose writer is not known", "record_unverifiable", async (f) => {
      await f.write("notes", "one", "text");
      const raw = JSON.parse(new TextDecoder().decode((await f.storage.read("notes", "one"))!));
      raw.kid = "someone-else";
      await f.storage.write("notes", "one", stringToBytes(JSON.stringify(raw)));
      return { refs: [{ namespace: "notes", key: "one" }] };
    }],
    ["a record whose signature is corrupted under its known writer", "record_unverifiable", async (f) => {
      await f.write("notes", "one", "text");
      const raw = JSON.parse(new TextDecoder().decode((await f.storage.read("notes", "one"))!)) as { kid?: string; sig: string; envelope_sig?: string };
      // One base64url character changed in each signature; the writer id is left as written.
      const flip = (text: string) => `${text[0] === "A" ? "B" : "A"}${text.slice(1)}`;
      raw.sig = flip(raw.sig);
      if (raw.envelope_sig !== undefined) raw.envelope_sig = flip(raw.envelope_sig);
      await f.storage.write("notes", "one", stringToBytes(JSON.stringify(raw)));
      return { refs: [{ namespace: "notes", key: "one" }] };
    }],
    ["one record over its plaintext cap that fits the stored cap", "record_oversized", async (f) => {
      await f.write("notes", "wide", "y".repeat(RECORD_PLAINTEXT_MAX_BYTES + 1));
      expect((await f.storage.read("notes", "wide"))!.length).toBeLessThanOrEqual(RECORD_STORED_MAX_BYTES);
      return { refs: [{ namespace: "notes", key: "wide" }] };
    }],
    ["an undecryptable record", "record_undecryptable", async (f) => {
      await f.write("notes", "one", "text");
      return { refs: [{ namespace: "notes", key: "one" }], options: { deriveKey: (m: Uint8Array, label: string) => deriveNamespaceKey(m, `${label}-wrong`) } };
    }],
    ["input over its total cap", "input_too_large", async (f) => {
      for (let i = 0; i < 3; i += 1) await f.write("notes", `big-${i}`, "z".repeat(60 * 1024));
      return { refs: [0, 1, 2].map((i) => ({ namespace: "notes", key: `big-${i}` })) };
    }],
    ["an uncovered ref", "uncovered", async (f) => {
      await f.write("notes", "one", "text");
      const policy = { ...DEFAULT_POLICY, tier1_always_approve: [...DEFAULT_POLICY.tier1_always_approve, "state_read"] };
      return { refs: [{ namespace: "notes", key: "one" }], options: { policy } };
    }],
  ];
  it.each(refusals)("the job is refused for %s", async (_label, cause, prepare) => {
    const f = await fortress();
    const plan = await prepare(f);
    const fake = await startFake(plan.fake ?? {});
    const r = await rig(f, fake, plan.options ?? {});
    const id = r.submit(plan.refs);
    const final = await r.waitForEnd(id);
    expect(final.kind).toBe("job_refused");
    expect((final.body as { cause: string }).cause).toBe(cause);
    expect(rowsFor(await r.rows(), id).filter((row) => row.kind === "job_refused")).toHaveLength(1);
    expect(await r.results().get(id, { includeUncommitted: true })).toBeNull();
    expect(generateRequests(fake)).toHaveLength(0);
  }, 120_000);

  it.each([
    ["a redirect", "redirect", "redirect"],
    ["a non-success status", "non200", "http_status"],
  ])("a model reply that is %s fails the job and commits nothing", async (_label, mode, outcome) => {
    const f = await fortress();
    await f.write("notes", "one", "text");
    const fake = await startFake({ mode });
    const r = await rig(f, fake);
    const id = r.submit([{ namespace: "notes", key: "one" }]);
    const final = await r.waitForEnd(id);
    expect(final).toMatchObject({ kind: "job_failed", body: { cause: "call_failed" } });
    expect(rowsFor(await r.rows(), id).find((row) => row.kind === "job_call")?.body).toMatchObject({ outcome });
    expect(await r.results().get(id)).toBeNull();
  }, 120_000);

  it("an output over its cap is cut at a character boundary and marked truncated", async () => {
    const f = await fortress();
    await f.write("notes", "one", "text");
    const fake = await startFake({ mode: "oversized" });
    const r = await rig(f, fake);
    const id = r.submit([{ namespace: "notes", key: "one" }]);
    expect((await r.waitForEnd(id)).kind).toBe("job_committed");
    const object = await r.results().get(id);
    const summary = object!.body!.summary as string;
    expect(Buffer.byteLength(summary)).toBeLessThanOrEqual(CHUNK_SUMMARY_MAX_BYTES);
    expect(summary).toBe("€".repeat(Math.floor(CHUNK_SUMMARY_MAX_BYTES / 3)));
    expect(object!.body!.truncated).toBe("true");
    const call = rowsFor(await r.rows(), id).find((row) => row.kind === "job_call")!;
    expect(call.body).toMatchObject({ truncated: true, outcome: "ok" });
  }, 120_000);

  it("a stalled call times out and a stalled job stops at its deadline", async () => {
    const f = await fortress();
    await f.write("notes", "one", "text");
    const fake = await startFake({ mode: "stall" });
    const timed = await rig(f, fake, { limits: { call_timeout_ms: 500, job_deadline_ms: 60_000 } });
    const first = timed.submit([{ namespace: "notes", key: "one" }]);
    const firstEnd = await timed.waitForEnd(first);
    expect(firstEnd).toMatchObject({ kind: "job_failed", body: { cause: "call_failed" } });
    expect(rowsFor(await timed.rows(), first).find((row) => row.kind === "job_call")!.body).toMatchObject({ outcome: "timeout" });
    await timed.client.close();

    const deadlined = await rig(f, fake, { limits: { call_timeout_ms: 60_000, job_deadline_ms: 1_500 } });
    const second = deadlined.submit([{ namespace: "notes", key: "one" }]);
    const secondEnd = await deadlined.waitForEnd(second);
    expect(secondEnd).toMatchObject({ kind: "job_failed", body: { cause: "deadline" } });
    expect(rowsFor(await deadlined.rows(), second).find((row) => row.kind === "job_call")!.body).toMatchObject({ outcome: "cancelled" });
  }, 120_000);

  it("a reply arriving after the deadline never commits", async () => {
    const f = await fortress();
    await f.write("notes", "one", "text");
    const fake = await startFake({ mode: "late_final", delay_ms: 3_000 });
    const r = await rig(f, fake, { limits: { call_timeout_ms: 60_000, job_deadline_ms: 1_000 } });
    const id = r.submit([{ namespace: "notes", key: "one" }]);
    expect(await r.waitForEnd(id)).toMatchObject({ kind: "job_failed", body: { cause: "deadline" } });
    // Wait past the moment the fake would have finished its reply.
    await new Promise((resolve) => setTimeout(resolve, 3_500));
    const kinds = rowsFor(await r.rows(), id).map((row) => row.kind);
    expect(kinds).not.toContain("job_committed");
    expect(kinds).not.toContain("result_committed");
    expect((await r.results().get(id, { includeUncommitted: true }))!.state).toBe("pending");
  }, 120_000);

  it("a full queue and a full seat drop work on the operator side only", async () => {
    const f = await fortress();
    await f.write("notes", "one", "text");
    const fake = await startFake({ mode: "stall" });
    const r = await rig(f, fake);
    const seatIds = Array.from({ length: WORKER_QUEUE_PER_SEAT_MAX + 1 }, () => r.submit([{ namespace: "notes", key: "one" }], { seat: "agent:busy" }));
    const seatDrop = await r.waitForEnd(seatIds.at(-1)!);
    expect(seatDrop).toMatchObject({ kind: "job_dropped", body: { cause: "seat_full" } });
    // The seat's drop ended its watch, so the server tracks the queue's own cap and no more.
    Array.from({ length: WORKER_QUEUE_MAX - WORKER_QUEUE_PER_SEAT_MAX }, (_, i) =>
      r.submit([{ namespace: "notes", key: "one" }], { seat: `agent:other-${i % 4}` }));
    expect(r.client.outstandingJobs).toBe(WORKER_QUEUE_MAX);
    const overflow = requestId();
    r.authority.register({ request_id: overflow, refs: [{ namespace: "notes", key: "one" }] });
    expect(r.client.submit({ type: "job", request_id: overflow, seat: "agent:late", kind: "summarize", refs: [{ namespace: "notes", key: "one" }], instruction: "x" }))
      .toBe("queue_full");
    const drops = (await r.rows()).filter((row) => row.kind === "job_dropped");
    expect(drops).toHaveLength(1);
  }, 120_000);

  it("the worker crashing mid-job leaves a pending object the sweep later marks indeterminate", async () => {
    const f = await fortress();
    await f.write("notes", "one", "text");
    const fake = await startFake({ mode: "stall" });
    const r = await rig(f, fake);
    const id = r.submit([{ namespace: "notes", key: "one" }]);
    const end = Date.now() + JOB_WAIT_MS;
    while (generateRequests(fake).length === 0) {
      if (Date.now() > end) throw new Error("generation did not start");
      await new Promise((resolve) => setTimeout(resolve, 20));
    }
    const pid = r.client.pid!;
    process.kill(pid, "SIGKILL");
    await r.client.close();
    expect(isAlive(pid)).toBe(false);
    const pending = await r.results().get(id, { includeUncommitted: true });
    expect(pending!.state).toBe("pending");
    const keys = deriveLocalStoreKeys(f.masterKey);
    const later = new LocalResultsStore(f.storage, keys.resultsKey, new LocalOplog(f.storage, keys.oplogKey), { now: () => pending!.deadline + PENDING_GRACE_MS + 1 });
    await later.sweep();
    expect((await later.get(id, { includeUncommitted: true }))!.state).toBe("indeterminate");
  }, 120_000);

  it("the job queue holds no record text", async () => {
    const started: string[] = [];
    let release: () => void = () => undefined;
    const queue = new LocalJobQueue(async (entry) => { started.push(entry.job.request_id); await new Promise<void>((resolve) => { release = resolve; }); });
    const job: LocalTaskJob = { type: "job", request_id: "a".repeat(32), seat: SEAT, kind: "summarize", refs: [{ namespace: "notes", key: "one" }], instruction: "focus" };
    queue.offer(job);
    queue.offer({ ...job, request_id: "b".repeat(32) });
    await Promise.resolve();
    const snapshot = queue.snapshot();
    expect(snapshot).toHaveLength(1);
    expect(Object.keys(snapshot[0]!).sort()).toEqual(["job", "queued_at"]);
    expect(Object.keys(snapshot[0]!.job).sort()).toEqual(["instruction", "kind", "refs", "request_id", "seat", "type"]);
    expect(JSON.stringify(snapshot)).not.toContain(RECORD_SENTINEL);
    release();
  });

  it("the queue stays bounded and does constant work per offer under a flood", () => {
    const queue = new LocalJobQueue(() => new Promise(() => undefined));
    const job: LocalTaskJob = { type: "job", request_id: "c".repeat(32), seat: SEAT, kind: "summarize", refs: [{ namespace: "notes", key: "one" }], instruction: "" };
    const started = performance.now();
    let dropped = 0;
    for (let i = 0; i < 50_000; i += 1) if (!queue.offer({ ...job, seat: `agent:${i % 100}` }).queued) dropped += 1;
    expect(queue.depth).toBeLessThanOrEqual(WORKER_QUEUE_MAX);
    expect(dropped).toBe(50_000 - WORKER_QUEUE_MAX);
    expect(performance.now() - started).toBeLessThan(2_000);
  });

  it("oplog rows carry no record or model text", async () => {
    const f = await fortress();
    await f.write("notes", "one", `secret detail ${RECORD_SENTINEL}`);
    await f.write("notes", "two", `${RECORD_SENTINEL} again`.repeat(2_000));
    const fake = await startFake();
    const r = await rig(f, fake);
    const id = r.submit([{ namespace: "notes", key: "one" }, { namespace: "notes", key: "two" }], { instruction: `instruction ${RECORD_SENTINEL}` });
    expect((await r.waitForEnd(id)).kind).toBe("job_committed");
    const text = JSON.stringify(await r.rows());
    expect(text).not.toContain(RECORD_SENTINEL);
    expect(text).not.toContain(MODEL_SENTINEL);
    // The control: the model text did reach the results object.
    expect(JSON.stringify((await r.results().get(id))!.body)).toContain(MODEL_SENTINEL);
  }, 120_000);
});
