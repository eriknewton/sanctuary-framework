// The job's deadline and commit order, run in process against the real results store and operator log.
import { ed25519 } from "@noble/curves/ed25519";
import { afterEach, describe, expect, it } from "vitest";
import { StateStore } from "../../src/cognitive/state-store.js";
import { stringToBytes, toBase64url } from "../../src/core/encoding.js";
import { encrypt } from "../../src/core/encryption.js";
import type { StoredIdentity } from "../../src/core/identity.js";
import { derivePurposeKey } from "../../src/core/key-derivation.js";
import { generateRandomKey } from "../../src/core/random.js";
import { LocalAuthority } from "../../src/local-recompile/authority.js";
import type { QueuedJob } from "../../src/local-recompile/job-queue.js";
import { LocalOplog, type OplogAppendKind, type OplogBodies } from "../../src/local-recompile/oplog.js";
import { LocalResultsStore } from "../../src/local-recompile/results-store.js";
import { runSummarizeJob, type GenerationClient, type SummarizeJobDependencies } from "../../src/local-recompile/summarize-job.js";
import { DEFAULT_POLICY } from "../../src/principal-policy/loader.js";
import { MemoryStorage } from "../../src/storage/memory.js";
import { StrictMemoryStorage, fixtureRequestId, fixtureStoreKeys } from "./__fixtures__/strict-memory-storage.js";

const START = Date.UTC(2026, 0, 1);
const DEADLINE_MS = 60_000;
const TAG = "qwen2.5:1.5b";
const DIGEST = "1".repeat(64);
const KID = "writer-one";
const SEAT = "agent:commit-order";

const cleanups: Array<() => void> = [];
afterEach(() => {
  for (const step of cleanups.splice(0).reverse()) step();
});

async function world(options: { resultsMaxTotalBytes?: number } = {}) {
  const clock = { now: START };
  const now = () => clock.now;
  const storage = new StrictMemoryStorage();
  const keys = fixtureStoreKeys();
  const oplog = new LocalOplog(storage, keys.oplogKey, { now });
  const results = new LocalResultsStore(storage, keys.resultsKey, oplog, {
    now,
    ...(options.resultsMaxTotalBytes === undefined ? {} : { caps: { maxTotalBytes: options.resultsMaxTotalBytes } }),
  });
  await oplog.ensure();
  await results.ensure();

  // One signed record in the fortress's state store, read by the job the way the worker reads it.
  const records = new MemoryStorage();
  const masterKey = generateRandomKey();
  const seed = generateRandomKey();
  const idKey = derivePurposeKey(masterKey, "identity-encryption");
  const identity: StoredIdentity = {
    identity_id: KID,
    label: "writer",
    public_key: toBase64url(ed25519.getPublicKey(seed)),
    did: "did:key:test",
    created_at: new Date(START).toISOString(),
    key_type: "ed25519",
    key_protection: "passphrase",
    encrypted_private_key: encrypt(seed, idKey),
    rotation_history: [],
  };
  await records.write("_identities", KID, stringToBytes(JSON.stringify(encrypt(stringToBytes(JSON.stringify(identity)), idKey))));
  await new StateStore(records, masterKey).write("notes", "one", "The team decided to ship.", KID, identity.encrypted_private_key, idKey, { provenance: { origin_actor: "operator" } });

  const descriptor = Object.freeze({ runtime_tag: TAG, manifest_digest: DIGEST, endpoint: Object.freeze({ address: "127.0.0.1", port: 9 }) });
  const authority = new LocalAuthority({
    binding: { describeVerifiedLocalBinding: () => ({ ok: true, epoch: 1, descriptor }) },
    policy: DEFAULT_POLICY,
    masterKey,
    identities: () => [identity],
  });
  authority.arm();
  cleanups.push(() => {
    results.close();
    oplog.close();
    keys.oplogKey.fill(0);
    keys.resultsKey.fill(0);
  });

  const calls: string[] = [];
  const client: GenerationClient = {
    fetchTags: async () => ({ ok: true, payload: { models: [{ name: TAG, digest: DIGEST }] } }),
    generate: async () => {
      calls.push("generate");
      return { ok: true, text: "the summary", done_reason: "stop" };
    },
  };
  const logRow = <K extends OplogAppendKind>(kind: K, body: OplogBodies[K]) => oplog.append(kind, body);
  const deps = (overrides: Partial<SummarizeJobDependencies> = {}): SummarizeJobDependencies => ({
    readRecord: (namespace, key, maxBytes) => records.readBounded!(namespace, key, maxBytes),
    log: logRow,
    putPending: (input) => results.putPending(input),
    markCommitted: (id, body, committedRow) => results.markCommitted(id, body, { committedRow }),
    requestAuthority: async (id) => authority.reply(id),
    reportState: () => undefined,
    makeClient: () => client,
    callTimeoutMs: DEADLINE_MS,
    jobDeadlineMs: DEADLINE_MS,
    now,
    // The deadline timer never fires here, so only the job's own clock checks can stop it.
    setTimer: () => 0,
    clearTimer: () => undefined,
    ...overrides,
  });
  const job = (n: number, queuedAt: number): QueuedJob => {
    const refs = [{ namespace: "notes", key: "one" }];
    authority.register({ request_id: fixtureRequestId(n), refs });
    return { job: { type: "job", request_id: fixtureRequestId(n), seat: SEAT, kind: "summarize", refs, instruction: "Focus on decisions." }, queued_at: queuedAt };
  };
  const rows = async (n: number) => {
    const status = await oplog.status();
    return (await oplog.readRows(status.base_seq, status.rows)).filter((row) => "request_id" in row.body && row.body.request_id === fixtureRequestId(n));
  };
  return { clock, results, oplog, deps, job, rows, calls };
}

describe("a summary job's deadline and commit", () => {
  it("a job dequeued already past its deadline makes no model call and commits nothing", async () => {
    const w = await world();
    const entry = w.job(1, START - DEADLINE_MS - 1);
    expect(await runSummarizeJob(entry, w.deps())).toBe("state_REFUSED");
    expect(w.calls).toEqual([]);
    expect(await w.results.get(fixtureRequestId(1), { includeUncommitted: true })).toBeNull();
    expect((await w.rows(1)).map((row) => [row.kind, row.body])).toEqual([["job_failed", { request_id: fixtureRequestId(1), cause: "deadline" }]]);
  });

  it("a reply before the deadline and a commit held past it commits nothing and writes no job_committed", async () => {
    const w = await world();
    const entry = w.job(2, START);
    const deps = w.deps({
      // The commit path is held past the deadline before it reaches the results lock.
      markCommitted: async (id, body, committedRow) => {
        w.clock.now = START + DEADLINE_MS + 1;
        return w.results.markCommitted(id, body, { committedRow });
      },
    });
    expect(await runSummarizeJob(entry, deps)).toBe("state_REFUSED");
    expect(w.calls).toEqual(["generate"]);
    const object = await w.results.get(fixtureRequestId(2), { includeUncommitted: true });
    expect(object?.state).toBe("pending");
    const kinds = (await w.rows(2)).map((row) => row.kind);
    expect(kinds).not.toContain("job_committed");
    expect(kinds).not.toContain("result_committed");
    expect(kinds.at(-1)).toBe("job_failed");
    expect((await w.rows(2)).at(-1)!.body).toEqual({ request_id: fixtureRequestId(2), cause: "deadline" });
  });

  it("a job_committed append that fails never leaves a committed result beside a job_failed row", async () => {
    const w = await world();
    const entry = w.job(3, START);
    const deps = w.deps({
      log: async (kind, body) => {
        if (kind === "job_committed") throw new Error("injected append failure");
        return w.oplog.append(kind, body);
      },
    });
    expect(await runSummarizeJob(entry, deps)).toBe("state_REFUSED");
    const object = await w.results.get(fixtureRequestId(3), { includeUncommitted: true });
    const kinds = (await w.rows(3)).map((row) => row.kind);
    expect(kinds).not.toContain("job_committed");
    // The object went back to pending under the same lock, so the failed row is accurate.
    expect(object?.state).toBe("pending");
    expect(kinds.at(-1)).toBe("job_failed");
    expect(object?.state === "committed" && kinds.includes("job_failed")).toBe(false);
  });

  it("the committed row is written inside the store's commit, after the object", async () => {
    const w = await world();
    const entry = w.job(4, START);
    let rowRan = false;
    const deps = w.deps({
      markCommitted: async (id, body, committedRow) => {
        const committed = await w.results.markCommitted(id, body, { committedRow: async () => { rowRan = true; await committedRow(); } });
        // The row ran before the store's commit returned, so it was inside the commit's lock.
        expect(rowRan).toBe(true);
        return committed;
      },
    });
    expect(await runSummarizeJob(entry, deps)).toBe("state_DONE");
    expect(rowRan).toBe(true);
    expect((await w.rows(4)).map((row) => row.kind).slice(-2)).toEqual(["result_committed", "job_committed"]);
  });

  it("a results store with no room fails the job as results_full and makes no model call", async () => {
    // A cap smaller than one pending object: the store refuses the reservation outright.
    const w = await world({ resultsMaxTotalBytes: 1 });
    expect(await runSummarizeJob(w.job(5, START), w.deps())).toBe("state_REFUSED");
    expect(w.calls).toEqual([]);
    expect((await w.rows(5)).at(-1)).toMatchObject({ kind: "job_failed", body: { cause: "results_full" } });
  });
});
