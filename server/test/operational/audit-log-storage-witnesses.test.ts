// fail-before-exempt: new storage and checkpoint witnesses for behaviour main already has; regression coverage that passes against pre-fix source by construction.
/** Audit storage observations and checkpoint ownership. */
import { afterEach, describe, expect, it, vi } from "vitest";
import { mkdir, mkdtemp, readdir, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { ed25519 } from "@noble/curves/ed25519";
import { AuditLog, type AuditLogConfig, type PersistedAuditEnvelopeV2 } from "../../src/operational/audit-log.js";
import { checkpointSigningBytes, computeAuditRoot, type AuditCheckpointRecord } from "../../src/audit/chain.js";
import type { StorageBackend } from "../../src/storage/interface.js";
import { FilesystemStorage } from "../../src/storage/filesystem.js";

// Twenty decimal places preserve sequence ordering; must match persistChainedEntry / parseEntryKeySequence in server/src/operational/audit-log.ts.
const ENTRY_SEQUENCE_WIDTH = 20;
const GENESIS_SEQUENCE = 0; // Genesis is the position before the first persisted append.
const SEQUENCE_STEP = 1; // Each persisted append advances the chain once.
const SEEDED_ENTRY_COUNT = SEQUENCE_STEP; // One named head precedes the held append.
const CHECKPOINT_CADENCE = SEEDED_ENTRY_COUNT + SEQUENCE_STEP;
const RETENTION_CAPACITY = CHECKPOINT_CADENCE * 2; // Twice the held range excludes pruning.
const PRIVATE_DIRECTORY_MODE = 0o700; // Only the owner may read, write or search the lock namespace.
const SNAPSHOT_BUDGET_MS = 250; // One quarter second bounds each small raw-file snapshot.
const CALLBACK_DRAIN_BUDGET_MS = SNAPSHOT_BUDGET_MS * 2; // Release plus complete callback settlement.
const SUCCESSOR_WORK_BUDGET_MS = SNAPSHOT_BUDGET_MS * 2 + CALLBACK_DRAIN_BUDGET_MS;
const HOLD_SAFETY_FACTOR = 4; // Observed work plus three equal portions reserved for admission and commit.
const HOLD_DEADLINE_MS = SUCCESSOR_WORK_BUDGET_MS * HOLD_SAFETY_FACTOR;
const OBSERVATION_BOUND_MS = SUCCESSOR_WORK_BUDGET_MS;
const CALLER_BOUND_MS = HOLD_DEADLINE_MS + OBSERVATION_BOUND_MS;
const RETAINED_CAPACITY = 2; // The third append crosses capacity and retains the newest entry.
const RETAINED_CADENCE = 100; // Count stays below the ordinary hundred-entry checkpoint cadence.
const TAIL_AGE_MS = 10 * 60_000; // Ten minutes reaches the production tail-age barrier.
const MASTER_KEY = ed25519.utils.randomPrivateKey();
const SIGNING_KEY = ed25519.utils.randomPrivateKey();
const PUBLIC_KEY = Buffer.from(ed25519.getPublicKey(SIGNING_KEY)).toString("base64url");
const ENTRY = { layer: "l1" as const, operation: "storage_observation", identity_id: "fixture", result: "success" as const, details: {} };
const AUDIT = "_audit";
const CHECKPOINTS = "_audit_checkpoints";
const HEAD = "__head_anchor";
const ROTATION = "__rotation_anchor";
const roots: string[] = [];
const logs: AuditLog[] = [];
const decode = <T>(bytes: Uint8Array): T => JSON.parse(Buffer.from(bytes).toString()) as T;

type Outcome<T> = { status: "resolved"; value: T } | { status: "rejected"; name: string; message: string } | { status: "timeout" };
const capture = <T>(promise: Promise<T>): Promise<Outcome<T>> => promise.then(
  value => ({ status: "resolved", value }),
  (reason: unknown) => ({ status: "rejected", name: reason instanceof Error ? reason.name : typeof reason, message: String(reason) }),
);
async function settleWithin<T>(promise: Promise<T>, ms = OBSERVATION_BOUND_MS): Promise<Outcome<T>> {
  let timer: ReturnType<typeof setTimeout> | undefined;
  try {
    return await Promise.race([capture(promise), new Promise<Outcome<T>>(resolve => {
      timer = setTimeout(() => resolve({ status: "timeout" }), ms);
    })]);
  } finally { if (timer) clearTimeout(timer); }
}
function gate() {
  let release!: () => void;
  const wait = new Promise<void>(resolve => { release = resolve; });
  return { wait, release };
}
type Signal = { aborted: boolean; checkpointReadAbort: AbortSignal };
type Internals = {
  auditWriteLockPath?: string;
  withAuditWriteLock(operation: (signal: Signal) => Promise<void>): Promise<void>;
  checkpointFlightGeneration: number; checkpointInFlight: boolean; checkpointFlightSignal?: Signal;
  lastCheckpointSequence: number; hashesSinceCheckpoint: string[];
  ownCoveredThroughSequence: number; ownHighestPersistedSequence: number;
  criticalAppendsSinceCheckpoint: number; oldestUncheckpointedOwnEntryAt?: number;
  nextSequence: number; lastEntryHash: string; knownV2HighWater: number; cachedSealedTip: number;
};
const internals = (log: AuditLog) => log as unknown as Internals;
function cached(log: AuditLog) {
  const s = internals(log);
  return { generation: s.checkpointFlightGeneration, inFlight: s.checkpointInFlight,
    lastCheckpoint: s.lastCheckpointSequence, hashes: [...s.hashesSinceCheckpoint],
    covered: s.ownCoveredThroughSequence, ownHighWater: s.ownHighestPersistedSequence,
    count: s.criticalAppendsSinceCheckpoint, age: s.oldestUncheckpointedOwnEntryAt,
    nextSequence: s.nextSequence, lastHash: s.lastEntryHash, highWater: s.knownV2HighWater, sealed: s.cachedSealedTip };
}
function observeCallbacks(log: AuditLog) {
  const target = internals(log);
  const original = target.withAuditWriteLock.bind(log);
  const callbacks: { signal: Signal; started: number; settled: Promise<Outcome<void>> }[] = [];
  const spy = vi.spyOn(target, "withAuditWriteLock").mockImplementation(operation => original(signal => {
    const started = performance.now();
    const pending = operation(signal);
    callbacks.push({ signal, started, settled: capture(pending) });
    return pending;
  }));
  return { callbacks, spy };
}
type Write = { namespace: string; key: string; record: Record<string, unknown>; bytes: string };
function observeWrites(storage: FilesystemStorage) {
  const writes: Write[] = [];
  const record = (namespace: string, key: string, bytes: Uint8Array) => {
    writes.push({ namespace, key, record: decode(bytes), bytes: Buffer.from(bytes).toString("base64") });
  };
  const write = storage.write.bind(storage);
  const durable = storage.writeDurable.bind(storage);
  vi.spyOn(storage, "write").mockImplementation(async (ns, key, bytes) => { record(ns, key, bytes); await write(ns, key, bytes); });
  vi.spyOn(storage, "writeDurable").mockImplementation(async (ns, key, bytes) => { record(ns, key, bytes); await durable(ns, key, bytes); });
  return writes;
}
async function readSnapshot(path: string) {
  // Direct file reads keep byte observations independent of storage spies.
  const result: Record<string, string> = {};
  for (const ns of [AUDIT, CHECKPOINTS, "_meta", "_audit_migration"]) {
    const dir = join(path, ns);
    for (const name of await readdir(dir).catch(() => [] as string[])) {
      if (name.endsWith(".enc") || name.endsWith(".json")) result[`${ns}/${name}`] = (await readFile(join(dir, name))).toString("base64");
    }
  }
  return result;
}
async function snapshot(path: string) {
  const pending = readSnapshot(path);
  try {
    const result = await settleWithin(pending, SNAPSHOT_BUDGET_MS);
    expect(result.status, "raw snapshot settlement").toBe("resolved");
    return result.status === "resolved" ? result.value : {};
  } finally { await pending; }
}
const signedConfig: AuditLogConfig = {
  integrityMode: "strict", checkpointInterval: CHECKPOINT_CADENCE, maxEntries: RETENTION_CAPACITY,
  writeLockHoldDeadlineMs: HOLD_DEADLINE_MS,
  checkpointSigner: async payload => ({ signer_kid: "storage-fixture", public_key: PUBLIC_KEY,
    signature: Buffer.from(ed25519.sign(checkpointSigningBytes(payload), SIGNING_KEY)).toString("base64url") }),
  checkpointPublicKeyResolver: () => PUBLIC_KEY,
};
async function fixture(namesOnly = true, config: AuditLogConfig = {}) {
  const root = await mkdtemp(join(tmpdir(), "audit-storage-observations-")); roots.push(root);
  vi.stubEnv("HOME", root);
  const path = join(root, "state");
  await mkdir(join(path, AUDIT), { recursive: true, mode: PRIVATE_DIRECTORY_MODE });
  const make = async (extra: AuditLogConfig = {}, useNamesOnly = namesOnly) => {
    const storage = new FilesystemStorage(path);
    // Binding every remaining method preserves filesystem lease capabilities.
    const backend: StorageBackend = useNamesOnly ? storage : new Proxy(storage, { get(target, property) {
      if (property === "listKeys") return undefined;
      const value = Reflect.get(target, property);
      return typeof value === "function" ? value.bind(target) : value;
    } });
    const log = new AuditLog(backend, MASTER_KEY, { ...signedConfig, ...config, ...extra, __testAuditGuardLockRoot: join(root, "guard") });
    logs.push(log); await log.getChainHead();
    expect(internals(log).auditWriteLockPath).toBe(join(path, AUDIT, ".audit-write.lock"));
    expect(log.processExitFence).toBeUndefined();
    return { storage, backend, log };
  };
  return { path, make, ...await make() };
}
async function entries(storage: StorageBackend) {
  const keys = (await storage.list(AUDIT, "entry-")).map(meta => meta.key).sort();
  return Promise.all(keys.map(async key => ({ key, envelope: decode<PersistedAuditEnvelopeV2>((await storage.read(AUDIT, key))!) })));
}
async function checkpoints(storage: StorageBackend) {
  const keys = await storage.list(CHECKPOINTS, "audit-checkpoint-");
  return Promise.all(keys.map(async ({ key }) => decode<AuditCheckpointRecord>((await storage.read(CHECKPOINTS, key))!)));
}
async function anchored(storage: StorageBackend) {
  const head = decode<{ data: { highest_sequence: number; head_hash: string } }>((await storage.read(CHECKPOINTS, HEAD))!);
  const listed = await entries(storage);
  expect(listed.find(({ envelope }) => envelope.sequence === head.data.highest_sequence)?.envelope.entry_hash).toBe(head.data.head_hash);
  return head;
}
function signature(record: AuditCheckpointRecord) {
  expect(record.unsigned).toBe(false);
  expect(record.signer_kid).toBe("storage-fixture");
  const { checkpoint_kind, checkpoint_sequence, from_sequence, root_hash, previous_checkpoint_sequence, signed_at } = record;
  const payload = { checkpoint_kind, checkpoint_sequence, from_sequence, root_hash, previous_checkpoint_sequence, signed_at };
  expect(ed25519.verify(Buffer.from(record.signature!, "base64url"), checkpointSigningBytes(payload), Buffer.from(PUBLIC_KEY, "base64url"))).toBe(true);
}
afterEach(async () => {
  vi.restoreAllMocks();
  // AuditLog owns no background worker; flush is its shutdown barrier.
  for (const log of logs.splice(0)) await capture(log.flush());
  vi.unstubAllEnvs();
  for (const root of roots.splice(0)) await rm(root, { recursive: true, force: true });
});

describe("audit storage observations", () => {
  it("checkpoint ownership follows the current lease", async () => {
    // Each release ordering has its own bytes, holders and read latches.
    for (const releaseAfterCommit of [false, true]) {
      const f = await fixture();
      for (let seeded = 0; seeded < SEEDED_ENTRY_COUNT; seeded++) await f.log.appendCritical(ENTRY);
      await anchored(f.storage);
      const oldHolderGate = gate(); const oldEntered = gate();
      const successorGate = gate(); const successorEntered = gate();
      const observed = observeCallbacks(f.log);
      const writes = observeWrites(f.storage);
      // The instance retains the configured signer, so observe its actual call boundary.
      const signing = vi.spyOn(f.log as unknown as { checkpointSigner: NonNullable<AuditLogConfig["checkpointSigner"]> }, "checkpointSigner");
      const events: string[] = [];
      const listKeys = f.storage.listKeys.bind(f.storage);
      const listing = vi.spyOn(f.storage, "listKeys").mockImplementation(async (ns, prefix) => {
        if (ns === CHECKPOINTS && prefix === "audit-checkpoint-") events.push("predecessor listing");
        return listKeys(ns, prefix);
      });
      const read = f.storage.read.bind(f.storage); let rotationReads = 0;
      const reads = vi.spyOn(f.storage, "read").mockImplementation(async (ns, key) => {
        const bytes = await read(ns, key);
        if (ns === CHECKPOINTS && key === ROTATION) {
          rotationReads++; events.push("rotation read");
          if (rotationReads === SEQUENCE_STEP) { oldEntered.release(); await oldHolderGate.wait; }
          else if (rotationReads === CHECKPOINT_CADENCE) { successorEntered.release(); await successorGate.wait; }
        }
        return bytes;
      });
      const oldCaller = capture(f.log.appendCritical(ENTRY));
      let successor: Promise<Outcome<void>> | undefined;
      let committedHold: number | undefined;
      try {
        expect(await settleWithin(oldEntered.wait)).toMatchObject({ status: "resolved" });
        expect(events).toEqual(["predecessor listing", "rotation read"]);
        expect(cached(f.log)).toMatchObject({ inFlight: true, ownHighWater: CHECKPOINT_CADENCE, lastCheckpoint: GENESIS_SEQUENCE, count: CHECKPOINT_CADENCE });
        expect(cached(f.log).hashes).toHaveLength(CHECKPOINT_CADENCE);
        expect(await settleWithin(oldCaller, CALLER_BOUND_MS)).toMatchObject({ status: "resolved", value: { status: "rejected", name: "AuditLockHoldDeadlineError" } });
        const oldGeneration = internals(f.log).checkpointFlightGeneration;
        successor = capture(f.log.flush());
        expect(await settleWithin(successorEntered.wait)).toMatchObject({ status: "resolved" });
        const successorCallback = observed.callbacks.at(-1)!;
        const timeToGate = performance.now() - successorCallback.started;
        expect(timeToGate + SUCCESSOR_WORK_BUDGET_MS).toBeLessThanOrEqual(HOLD_DEADLINE_MS);
        expect(internals(f.log).checkpointFlightGeneration).toBeGreaterThan(oldGeneration);
        expect(internals(f.log).checkpointFlightSignal).toBe(successorCallback.signal);
        expect(successorCallback.signal.aborted).toBe(false);
        expect(events).toEqual(["predecessor listing", "rotation read", "predecessor listing", "rotation read"]);
        if (releaseAfterCommit) {
          successorGate.release();
          expect(await settleWithin(successor)).toMatchObject({ status: "resolved", value: { status: "resolved" } });
          committedHold = performance.now() - successorCallback.started;
        }
        const pauseStart = performance.now();
        const before = cached(f.log); const signalBefore = internals(f.log).checkpointFlightSignal;
        const bytesBefore = await snapshot(f.path); const startWrites = writes.length; const startSigning = signing.mock.calls.length;
        oldHolderGate.release();
        const oldCallback = await settleWithin(observed.callbacks[0]!.settled, CALLBACK_DRAIN_BUDGET_MS);
        const oldWrites = writes.slice(startWrites);
        const oldCheckpointWrites = oldWrites.filter(write => write.namespace === CHECKPOINTS && write.key.startsWith("audit-checkpoint-"));
        const successorState = { inFlight: internals(f.log).checkpointInFlight, signal: internals(f.log).checkpointFlightSignal };
        const bytesAfter = await snapshot(f.path);
        const pauseWork = performance.now() - pauseStart;
        const holdElapsed = performance.now() - successorCallback.started;
        console.info("checkpoint observations", JSON.stringify({ releaseAfterCommit, timeToGate, pauseWork, holdElapsed,
          remainingCommitBudget: HOLD_DEADLINE_MS - holdElapsed, oldCallback, oldWrites, signingCalls: signing.mock.calls.slice(startSigning) }));
        expect(oldCheckpointWrites, "old checkpoint writes after release").toEqual([]);
        expect(successorState, "successor checkpoint ownership").toEqual({ inFlight: before.inFlight, signal: signalBefore });
        expect(oldWrites).toEqual([]);
        expect(signing.mock.calls.slice(startSigning)).toEqual([]);
        expect(oldCallback).toMatchObject({ status: "resolved", value: { status: "rejected", name: "AuditLockHoldDeadlineError" } });
        expect(cached(f.log)).toEqual(before); expect(bytesAfter).toEqual(bytesBefore);
        expect(pauseWork).toBeLessThan(HOLD_DEADLINE_MS / 2);
        if (!releaseAfterCommit) expect(holdElapsed + SUCCESSOR_WORK_BUDGET_MS).toBeLessThan(HOLD_DEADLINE_MS);
        successorGate.release();
        expect(await settleWithin(successor)).toMatchObject({ status: "resolved", value: { status: "resolved" } });
        committedHold ??= performance.now() - successorCallback.started;
        console.info("checkpoint committed hold", { releaseAfterCommit, committedHold });
        expect(committedHold).toBeLessThan(HOLD_DEADLINE_MS);
        const records = await checkpoints(f.storage); const listed = await entries(f.storage);
        expect(records).toHaveLength(SEQUENCE_STEP);
        expect(records[0]).toMatchObject({ from_sequence: SEQUENCE_STEP, checkpoint_sequence: CHECKPOINT_CADENCE,
          previous_checkpoint_sequence: GENESIS_SEQUENCE, root_hash: computeAuditRoot(listed.map(row => row.envelope.entry_hash)) });
        signature(records[0]!);
        expect(rotationReads).toBe(CHECKPOINT_CADENCE);
      } finally {
        oldHolderGate.release(); successorGate.release();
        await oldCaller; await successor;
        await Promise.all(observed.callbacks.map(callback => callback.settled));
        reads.mockRestore(); listing.mockRestore(); signing.mockRestore(); observed.spy.mockRestore();
      }
    }
  });

  it.each(["while active", "after commit"] as const)("discovery ownership follows the current lease %s", async releaseArm => {
    const f = await fixture(); await f.log.appendCritical(ENTRY);
    const next = await f.make({ checkpointInterval: SEQUENCE_STEP });
    const oldHolderGate = gate(); const oldEntered = gate();
    const successorGate = gate(); const successorEntered = gate();
    const observed = observeCallbacks(f.log); const successorCallbacks = observeCallbacks(next.log);
    const writes = observeWrites(f.storage);
    const read = f.storage.read.bind(f.storage); let heldHeadReads = 0;
    const reads = vi.spyOn(f.storage, "read").mockImplementation(async (ns, key) => {
      const bytes = await read(ns, key);
      if (ns === CHECKPOINTS && key === HEAD && heldHeadReads === GENESIS_SEQUENCE) {
        heldHeadReads++; oldEntered.release(); await oldHolderGate.wait;
      }
      return bytes;
    });
    const durable = next.storage.writeDurable.bind(next.storage); let capturedHead = false;
    const successorWrites = vi.spyOn(next.storage, "writeDurable").mockImplementation(async (ns, key, bytes) => {
      // Entry bytes are visible while the prior authenticated head remains durable.
      if (ns === CHECKPOINTS && key === HEAD && !capturedHead) {
        capturedHead = true; successorEntered.release(); await successorGate.wait;
      }
      await durable(ns, key, bytes);
    });
    const oldCaller = capture(f.log.appendCritical(ENTRY)); let successor: Promise<Outcome<void>> | undefined;
    let committedHold: number | undefined;
    try {
      expect(await settleWithin(oldEntered.wait)).toMatchObject({ status: "resolved" });
      expect(await settleWithin(oldCaller, CALLER_BOUND_MS)).toMatchObject({ status: "resolved", value: { status: "rejected", name: "AuditLockHoldDeadlineError" } });
      successor = capture(next.log.appendCritical(ENTRY));
      expect(await settleWithin(successorEntered.wait)).toMatchObject({ status: "resolved" });
      const callback = successorCallbacks.callbacks[0]!;
      const timeToGate = performance.now() - callback.started;
      expect(timeToGate + SUCCESSOR_WORK_BUDGET_MS).toBeLessThanOrEqual(HOLD_DEADLINE_MS);
      expect(callback.signal.aborted).toBe(false);
      expect((await entries(next.storage)).map(row => row.envelope.sequence)).toEqual([SEEDED_ENTRY_COUNT, CHECKPOINT_CADENCE]);
      expect((await anchored(next.storage)).data.highest_sequence).toBe(SEEDED_ENTRY_COUNT);
      if (releaseArm === "after commit") {
        successorGate.release();
        expect(await settleWithin(successor)).toMatchObject({ status: "resolved", value: { status: "resolved" } });
        committedHold = performance.now() - callback.started;
      }
      const pauseStart = performance.now(); const before = cached(next.log); const bytesBefore = await snapshot(f.path);
      const startWrites = writes.length;
      oldHolderGate.release();
      const oldCallback = await settleWithin(observed.callbacks[0]!.settled, CALLBACK_DRAIN_BUDGET_MS);
      const oldWrites = writes.slice(startWrites);
      const oldEntryWrites = oldWrites.filter(write => write.namespace === AUDIT && write.key.startsWith("entry-"));
      const bytesAfter = await snapshot(f.path);
      const pauseWork = performance.now() - pauseStart; const holdElapsed = performance.now() - callback.started;
      console.info("discovery observations", JSON.stringify({ releaseArm, timeToGate, pauseWork, holdElapsed,
        remainingCommitBudget: HOLD_DEADLINE_MS - holdElapsed, oldCallback, oldWrites }));
      expect(oldEntryWrites, "old entry writes after release").toEqual([]);
      expect(oldWrites).toEqual([]); expect(cached(next.log)).toEqual(before); expect(bytesAfter).toEqual(bytesBefore);
      expect(oldCallback).toMatchObject({ status: "resolved", value: { status: "rejected", name: "AuditLockHoldDeadlineError" } });
      expect(pauseWork).toBeLessThan(HOLD_DEADLINE_MS / 2);
      if (releaseArm === "while active") expect(holdElapsed + SUCCESSOR_WORK_BUDGET_MS).toBeLessThan(HOLD_DEADLINE_MS);
      successorGate.release();
      expect(await settleWithin(successor)).toMatchObject({ status: "resolved", value: { status: "resolved" } });
      committedHold ??= performance.now() - callback.started;
      console.info("discovery committed hold", { releaseArm, committedHold });
      expect(committedHold).toBeLessThan(HOLD_DEADLINE_MS);
      const head = await next.log.getChainHead();
      const records = await checkpoints(next.storage); expect(records.at(-1)?.checkpoint_sequence).toBe(CHECKPOINT_CADENCE);
      await next.log.appendCritical(ENTRY);
      expect((await entries(next.storage)).at(-1)?.envelope).toMatchObject({ sequence: CHECKPOINT_CADENCE + SEQUENCE_STEP, prev_hash: head.entry_hash });
      expect(heldHeadReads).toBe(SEQUENCE_STEP);
    } finally {
      oldHolderGate.release(); successorGate.release();
      await oldCaller; await successor;
      await Promise.all([...observed.callbacks, ...successorCallbacks.callbacks].map(callback => callback.settled));
      reads.mockRestore(); successorWrites.mockRestore(); observed.spy.mockRestore(); successorCallbacks.spy.mockRestore();
    }
  });

  it("entry keys preserve their persisted sequence component", async () => {
    const f = await fixture(); await f.log.appendCritical(ENTRY);
    const listed = await entries(f.storage); expect(listed).toHaveLength(SEEDED_ENTRY_COUNT);
    const row = listed[0]!; const decimal = row.key.split("-")[SEQUENCE_STEP]!;
    expect(decimal).toHaveLength(ENTRY_SEQUENCE_WIDTH);
    expect(decimal).toMatch(/^\d+$/); expect(Number(decimal)).toBe(row.envelope.sequence);
    const reopened = await f.make();
    const queried = await reopened.log.query({ limit: SEEDED_ENTRY_COUNT });
    expect(queried.entries).toHaveLength(SEEDED_ENTRY_COUNT);
    expect(queried.entries[0]).toMatchObject(ENTRY);
    expect((await reopened.log.getChainHead()).entry_hash).toBe(row.envelope.entry_hash);
  });

  it("fallback discovery continues the observed chain", async () => {
    const f = await fixture(false); expect(typeof f.backend.listKeys).toBe("undefined");
    await f.log.appendCritical(ENTRY);
    // The foreign writer seeds the tail through names-only discovery before the original writer's metadata scan.
    const other = await f.make({}, true); await other.log.appendCritical(ENTRY);
    const previous = (await entries(f.storage)).at(-1)!.envelope;
    const listing = vi.spyOn(f.storage, "list");
    const result = await capture(f.log.appendCritical(ENTRY));
    expect(result.status).toBe("resolved");
    expect(listing.mock.calls).toContainEqual([AUDIT, "entry-"]);
    expect((await entries(f.storage)).at(-1)!.envelope).toMatchObject({ sequence: previous.sequence + SEQUENCE_STEP, prev_hash: previous.entry_hash });
  });

  it("fallback barriers retain complete checkpoint ranges", async () => {
    const predecessor = GENESIS_SEQUENCE + SEQUENCE_STEP;
    const pruned = predecessor + SEQUENCE_STEP;
    const retained = pruned + SEQUENCE_STEP;
    for (const namesOnly of [true, false]) {
      let now = GENESIS_SEQUENCE;
      const f = await fixture(namesOnly, { maxEntries: RETAINED_CAPACITY, checkpointInterval: RETAINED_CADENCE, __testMonotonicNow: () => now });
      expect(typeof f.backend.listKeys).toBe(namesOnly ? "function" : "undefined");
      await f.log.appendCritical(ENTRY); await f.log.flushDurable();
      await f.log.appendCritical(ENTRY); await f.log.appendCritical(ENTRY);
      const listed = await entries(f.storage); expect(listed.map(row => row.envelope.sequence)).toEqual([retained]);
      expect((await checkpoints(f.storage)).map(record => record.checkpoint_sequence)).toEqual([predecessor]);
      const anchor = decode<{ data: { base_sequence: number } }>((await f.storage.read(CHECKPOINTS, ROTATION))!);
      expect(anchor.data.base_sequence).toBe(retained);
      expect(anchor.data.base_sequence).toBeGreaterThan(predecessor + SEQUENCE_STEP);
      expect(anchor.data.base_sequence).toBeGreaterThan(internals(f.log).cachedSealedTip + SEQUENCE_STEP);
      const listing = vi.spyOn(f.storage, "list");
      now += TAIL_AGE_MS;
      const result = await capture(f.log.flushDurable());
      const calls = Object.freeze(listing.mock.calls.map(call => Object.freeze([...call])));
      listing.mockRestore();
      expect(result.status).toBe("resolved");
      if (!namesOnly) {
        expect(calls).toContainEqual([AUDIT, "entry-"]);
        expect(calls).toContainEqual([CHECKPOINTS, "audit-checkpoint-"]);
      }
      const records = await checkpoints(f.storage);
      expect(records.map(record => record.checkpoint_sequence)).toEqual([predecessor, retained]);
      const record = records.at(-1)!;
      expect(record).toMatchObject({ from_sequence: retained, checkpoint_sequence: retained, previous_checkpoint_sequence: predecessor,
        root_hash: computeAuditRoot([listed[0]!.envelope.entry_hash]), checkpoint_kind: "audit-checkpoint", signature_algorithm: "Ed25519",
        payload_encoding: "domain-separated-canonical-json-v1" });
      signature(record);
    }
  });

  it("fallback listing outcomes preserve committed bytes", async () => {
    const f = await fixture(false); expect(typeof f.backend.listKeys).toBe("undefined");
    const before = cached(f.log); const bytesBefore = await snapshot(f.path);
    const list = f.storage.list.bind(f.storage);
    const error = Object.assign(new Error("entry listing unavailable"), { code: "EIO" });
    const listing = vi.spyOn(f.storage, "list").mockImplementation((ns, prefix) => ns === AUDIT && prefix === "entry-" ? Promise.reject(error) : list(ns, prefix));
    const result = await capture(f.log.appendCritical(ENTRY));
    expect(result).toMatchObject({ status: "rejected", name: "AuditChainStateUnknownError" });
    expect(cached(f.log)).toEqual(before); expect(await snapshot(f.path)).toEqual(bytesBefore);
    listing.mockRestore();
    expect(await capture(f.log.appendCritical(ENTRY))).toMatchObject({ status: "resolved" });
    expect((await entries(f.storage))[0]?.envelope).toMatchObject({ sequence: SEQUENCE_STEP, prev_hash: "GENESIS" });
  });
});
