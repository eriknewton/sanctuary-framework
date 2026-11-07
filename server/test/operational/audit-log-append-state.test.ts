/** Audit append state and checkpoint accounting invariants. */
import { mkdtemp, readFile, rm, stat } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Writable } from "node:stream";
import { ed25519 } from "@noble/curves/ed25519";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import {
  AuditLog, AuditLockHoldDeadlineError, AuditPersistenceError,
  AUDIT_TAIL_CHECKPOINT_MAX_AGE_MS, deriveAuditStoreSplitBoundaryMacKey,
  writeAuditStoreSplitBoundary, type AuditEntryInput, type AuditLogConfig, type PersistedAuditEnvelopeV2,
} from "../../src/operational/audit-log.js";
import { checkpointSigningBytes } from "../../src/audit/chain.js";
import { AUDIT_HEAD_ANCHOR_KEY } from "../../src/audit/checkpoint-shape.js";
import { exportAuditChain } from "../../src/cli/audit-chain-export.js";
import { verifyAuditChainRecords } from "../../src/cli/audit-chain-verify.js";
import { FilesystemStorage } from "../../src/storage/filesystem.js";
import { MemoryStorage } from "../../src/storage/memory.js";
import type { StorageBackend } from "../../src/storage/interface.js";
import { CHECKPOINT_NAMESPACE, checkpointKey, FaultInjectingStorage } from "../helpers/signing-fixture.js";

const ZERO = 0; // Empty population and clock origin.
const ONE = 1; // One entry, acquisition, or sequence step.
const PREFIX_LENGTH = ONE;
const INTERVAL_DISABLED = ZERO; // Zero disables interval-triggered checkpoints.
const CLOCK_ORIGIN = ZERO;
const HOLD_MS = 1_000; // One second, advanced only after a queued storage gate.
const HELD = "held"; // Race tag: the schedule gate opened first.
const SETTLED = "settled"; // Race tag: the guarded operation settled first.
// Must match MIN_IN_MEMORY_ENTRY_FLOOR in ../../src/operational/audit-log.ts.
const CACHE_FLOOR = 256; // The production minimum recent-entry window.
const DISK_CAP = CACHE_FLOOR * (ONE + ONE); // Room for a full window and subsequent appends.
// About five times the per-append cost measured on a loaded Mac (about 47 ms: 12 s for one CACHE_FLOOR fill).
const DURABLE_APPEND_BUDGET_MS = 250;
// A full-window schedule performs CACHE_FLOOR durable appends before its hold, so its budget scales with the window.
const FULL_WINDOW_TIMEOUT_MS = CACHE_FLOOR * DURABLE_APPEND_BUDGET_MS;
// Must match AUDIT_NAMESPACE in ../../src/operational/audit-log.ts.
const ENTRY_NAMESPACE = "_audit";
// Must match AUDIT_META_NAMESPACE in ../../src/operational/audit-log.ts.
const META_NAMESPACE = "_meta";
// Must match AUDIT_POST_SPLIT_SUFFIX_ESTABLISHED_KEY in ../../src/operational/audit-log.ts.
const SUFFIX_MARKER = "audit-post-split-suffix-established-v1";
const markerTarget = { namespace: META_NAMESPACE, key: SUFFIX_MARKER };
const signingKey = ed25519.utils.randomPrivateKey();
const masterKey = ed25519.utils.randomPrivateKey();
const publicKey = Buffer.from(ed25519.getPublicKey(signingKey)).toString("base64url");
const signedConfig: AuditLogConfig = {
  integrityMode: "strict", checkpointInterval: INTERVAL_DISABLED,
  maxEntries: DISK_CAP, maxInMemoryEntries: CACHE_FLOOR, writeLockHoldDeadlineMs: HOLD_MS,
  checkpointSigner: async payload => ({ signer_kid: "fixture", public_key: publicKey,
    signature: Buffer.from(ed25519.sign(checkpointSigningBytes(payload), signingKey)).toString("base64url") }),
  checkpointPublicKeyResolver: () => publicKey,
};
let fixtureHome: string;
beforeEach(async () => {
  fixtureHome = await mkdtemp(join(tmpdir(), "audit-append-state-"));
  vi.stubEnv("HOME", fixtureHome);
});
afterEach(async () => {
  vi.restoreAllMocks();
  vi.useRealTimers();
  vi.unstubAllEnvs();
  await rm(fixtureHome, { recursive: true, force: true });
});
function gate() {
  let release!: () => void;
  const wait = new Promise<void>(resolve => { release = resolve; });
  return { wait, release };
}
type Outcome = { status: "fulfilled" } | { status: "rejected"; error: unknown };
function outcome(promise: Promise<unknown>): Promise<Outcome> {
  return promise.then(() => ({ status: "fulfilled" }), error => ({ status: "rejected", error }));
}
function entry(operation: string): AuditEntryInput {
  return { layer: "l2", operation, identity_id: "fixture", result: "success" };
}
function append(log: AuditLog, critical: boolean, operation: string) {
  return critical ? log.appendCritical(entry(operation)) : log.append("l2", operation, "fixture");
}
async function envelopes(storage: StorageBackend) {
  const keys = (await storage.list(ENTRY_NAMESPACE, "entry-")).map(meta => meta.key).sort();
  return Promise.all(keys.map(async key => {
    const bytes = (await storage.read(ENTRY_NAMESPACE, key))!;
    return { key, bytes, envelope: JSON.parse(Buffer.from(bytes).toString()) as PersistedAuditEnvelopeV2 };
  }));
}
async function checkpointSequences(storage: StorageBackend) {
  const records = await storage.list(CHECKPOINT_NAMESPACE, "audit-checkpoint-");
  return Promise.all(records.map(async ({ key }) => {
    const bytes = (await storage.read(CHECKPOINT_NAMESPACE, key))!;
    return JSON.parse(Buffer.from(bytes).toString()).checkpoint_sequence as number;
  })).then(sequences => sequences.sort((a, b) => a - b));
}
async function verify(storage: StorageBackend) {
  let text = "";
  const stream = new Writable({ write(chunk, _encoding, done) { text += String(chunk); done(); } });
  await exportAuditChain(storage, stream);
  const report = verifyAuditChainRecords(text.trim().split("\n").map(line => JSON.parse(line)), { publicKey, strict: true });
  expect(report.findings, "persisted chain findings").toEqual([]);
  expect(report.verdict, "persisted chain verification").toBe("PASS");
}
async function filesystemFixture(config: AuditLogConfig = {}, fillWindow = false, sealPrefix = true) {
  const statePath = join(fixtureHome, "state");
  const storage = new FilesystemStorage(statePath);
  const seed = new AuditLog(storage, masterKey, { ...signedConfig, consultSplitBoundary: false });
  if (sealPrefix) {
    for (let index = ZERO; index < PREFIX_LENGTH; index += ONE) await seed.appendCritical(entry(`prefix-${index}`));
    await seed.flushDurable();
    const head = await seed.getChainHead();
    await writeAuditStoreSplitBoundary(statePath, deriveAuditStoreSplitBoundaryMacKey(masterKey), {
      sealed_tip_sequence: head.sequence, sealed_base_sequence: ONE,
      sealed_tip_entry_hash: head.entry_hash, daemon_namespace: "_audit-daemon",
    });
  }
  const log = new AuditLog(storage, masterKey, { ...signedConfig, ...config });
  if (fillWindow) {
    const population = (log as any).maxInMemoryEntries as number;
    expect(population, "hold setup cache floor").toBeGreaterThanOrEqual(CACHE_FLOOR);
    for (let index = ZERO; index < population; index += ONE) await seed.appendCritical(entry(`window-${index}`));
  }
  await log.query({ limit: ONE });
  return { storage, log };
}
function snapshot(log: AuditLog) {
  const state = log as any;
  return {
    entries: structuredClone(state.entries),
    chain: structuredClone(state.chainEntries),
    sequenceAndHead: [state.nextSequence, state.lastEntryHash],
    own: { highest: state.ownHighestPersistedSequence, covered: state.ownCoveredThroughSequence,
      hashes: [...state.hashesSinceCheckpoint], age: state.oldestUncheckpointedOwnEntryAt,
      count: state.criticalAppendsSinceCheckpoint },
    retention: { bytes: state.retainedBytesEstimate, count: state.retainedCountExpected,
      low: state.retainedLowestKey, high: state.retainedHighestKey, signature: state.retainedSignatureExpected,
      generation: state.retentionGeneration, known: state.knownV2HighWater,
      fingerprint: state.expectedStoreFingerprint, ensured: state.postSplitSuffixMarkerEnsured },
    flight: { active: state.checkpointInFlight, generation: state.checkpointFlightGeneration,
      signal: state.checkpointFlightSignal, sequence: state.lastCheckpointSequence },
  };
}
async function diskSnapshot(storage: StorageBackend) {
  const result: Record<string, string> = {};
  for (const namespace of [ENTRY_NAMESPACE, CHECKPOINT_NAMESPACE, META_NAMESPACE]) {
    for (const { key } of await storage.list(namespace)) {
      if (namespace === META_NAMESPACE && key === SUFFIX_MARKER) continue;
      result[`${namespace}/${key}`] = Buffer.from((await storage.read(namespace, key))!).toString("base64");
    }
  }
  return result;
}
function faultAdapter(storage: StorageBackend, write: StorageBackend["write"]): StorageBackend {
  return { write, read: storage.read.bind(storage), delete: storage.delete.bind(storage),
    list: storage.list.bind(storage), exists: storage.exists.bind(storage), totalSize: storage.totalSize.bind(storage) };
}
class MarkerStorageError extends Error {}
type Schedule = { critical: boolean; rejectMarker: boolean; direct?: boolean; full?: boolean; interval?: boolean };
async function heldSchedule(schedule: Schedule) {
  // Only the hold timer and monotonic clock are virtual; filesystem promises retain their normal scheduling.
  vi.useFakeTimers({ toFake: ["setTimeout", "clearTimeout", "performance"] });
  const { log, storage } = await filesystemFixture({
    __testMonotonicNow: () => CLOCK_ORIGIN,
    checkpointInterval: schedule.interval ? ONE : INTERVAL_DISABLED,
  }, schedule.full);
  const state = log as any;
  const originalWrite = storage.write.bind(storage);
  let rejectOnRelease = false;
  const faults = new FaultInjectingStorage(faultAdapter(storage, async (...args) => {
    if (rejectOnRelease) throw new MarkerStorageError("selected marker write unavailable");
    return originalWrite(...args);
  }));
  faults.deferWritesTo = markerTarget;
  const state_WRITE_PENDING = gate();
  const state_FIRST_HOLD_RETIRED = gate();
  const state_SECOND_HOLD = gate();
  const state_FIRST_CALLBACK_SETTLED = gate();
  const releaseSecond = gate();
  let firstSignal: any;
  let secondSignal: any;
  let firstCallbackOutcome: Outcome | undefined;
  let firstCallback = true;
  const callbackSettlements: Promise<Outcome>[] = [];
  const withLock = state.withAuditWriteLock.bind(log);
  vi.spyOn(state, "withAuditWriteLock").mockImplementation((callback: any) => withLock(async (signal: any) => {
    const observeFirst = firstCallback;
    firstCallback = false;
    if (observeFirst) firstSignal = signal;
    const running = Promise.resolve().then(() => callback(signal));
    const settled = outcome(running);
    callbackSettlements.push(settled);
    if (observeFirst) void settled.then(value => {
      firstCallbackOutcome = value;
      state_FIRST_CALLBACK_SETTLED.release();
    });
    return running;
  }));
  const writes = vi.spyOn(storage, "write").mockImplementation((namespace, key, bytes) => {
    if (namespace === META_NAMESPACE && key === SUFFIX_MARKER && faults.deferWritesTo) {
      const pending = faults.write(namespace, key, bytes);
      state_WRITE_PENDING.release();
      return pending;
    }
    return originalWrite(namespace, key, bytes);
  });
  const durableWrites = vi.spyOn(storage, "writeDurable");
  const deletes = vi.spyOn(storage, "delete");
  const recovery = vi.fn();
  log.onWriteLockRecovery(recovery);
  const diagnostics = vi.spyOn(console, "error").mockImplementation(() => undefined);
  const publicOutcome = outcome(append(log, schedule.critical, "held-append"));
  let secondOutcome: Promise<Outcome> | undefined;
  try {
    // The race resolves to a tag, so the losing branch never carries an assertion that could fire after the test.
    const admission = await Promise.race([state_WRITE_PENDING.wait.then(() => HELD), publicOutcome.then(() => SETTLED)]);
    expect(admission, "hold setup marker admission").toBe(HELD);
    expect(faults.deferWritesTo, "hold setup marker target").toEqual(markerTarget);
    expect(faults.deferredCount, "hold setup marker queue").toBe(ONE);
    expect(writes.mock.calls.at(-ONE)?.slice(ZERO, ONE + ONE), "hold setup selected write").toEqual([META_NAMESPACE, SUFFIX_MARKER]);
    const persisted = await envelopes(storage);
    const pendingEntry = persisted.at(-ONE)!;
    const suffixSequence = PREFIX_LENGTH + (schedule.full ? state.maxInMemoryEntries : ZERO) + ONE;
    expect(pendingEntry.envelope.sequence, "hold setup suffix sequence").toBe(suffixSequence);
    const pendingHead = (await storage.read(CHECKPOINT_NAMESPACE, AUDIT_HEAD_ANCHOR_KEY))!;
    expect(JSON.parse(Buffer.from(pendingHead).toString()).data.highest_sequence, "hold setup persisted head").toBe(suffixSequence);
    const beforePublication = snapshot(log);
    if (schedule.full) expect(beforePublication.entries.length, "hold setup filled window").toBe(state.maxInMemoryEntries);
    expect(beforePublication.chain.some((item: any) => item.sequence === suffixSequence), "hold setup publication boundary").toBe(false);
    expect(beforePublication.own.highest, "hold setup own floor").toBeLessThan(suffixSequence);
    expect(beforePublication.own.age, "hold setup own age").toBeUndefined();

    await vi.advanceTimersByTimeAsync(log.writeLockHoldDeadlineMs);
    const caller = await publicOutcome;
    expect(caller.status, "hold setup caller outcome").toBe("rejected");
    if (caller.status === "rejected") expect(caller.error, "hold setup caller error").toBeInstanceOf(AuditLockHoldDeadlineError);
    expect(firstSignal.aborted, "hold setup first signal").toBe(true);
    expect(firstCallbackOutcome, "hold setup callback pending").toBeUndefined();
    expect(log.getWriteLockRecoveryCount(), "hold setup recovery count").toBe(ONE);
    expect(recovery, "hold setup recovery notification").toHaveBeenCalledTimes(ONE);
    expect(diagnostics, "hold setup recovery diagnostic").toHaveBeenCalledTimes(ONE);
    const lockPath = state.auditWriteLockPath as string;
    const released = await stat(lockPath).then(() => false, error => error.code === "ENOENT");
    expect(released, "hold setup first release").toBe(true);
    state_FIRST_HOLD_RETIRED.release();
    await state_FIRST_HOLD_RETIRED.wait;

    faults.deferWritesTo = null;
    if (!schedule.direct) await log.appendCritical(entry("independent-append"));
    secondOutcome = outcome(state.withAuditWriteLock(async (signal: any) => {
      secondSignal = signal;
      state_SECOND_HOLD.release();
      await releaseSecond.wait;
    }));
    const acquisition = await Promise.race([state_SECOND_HOLD.wait.then(() => HELD), secondOutcome.then(() => SETTLED)]);
    expect(acquisition, "hold setup second acquisition").toBe(HELD);
    const secondSnapshot = snapshot(log);
    if (schedule.direct) {
      expect(secondSnapshot.own.highest, "hold setup consecutive own floor").toBeLessThan(suffixSequence);
      expect(secondSnapshot.own.age, "hold setup consecutive own age").toBeUndefined();
    } else {
      expect(secondSnapshot.own.count, "hold setup independent own count").toBeGreaterThan(ZERO);
      expect(secondSnapshot.own.hashes.length, "hold setup independent own hashes").toBeGreaterThan(ZERO);
      expect(secondSnapshot.sequenceAndHead, "hold setup independent head").not.toEqual(beforePublication.sequenceAndHead);
    }
    const secondDisk = await diskSnapshot(storage);
    const secondLock = { stats: await stat(lockPath), bytes: await readFile(lockPath) };
    const writeCount = writes.mock.calls.length;
    const durableCount = durableWrites.mock.calls.length;
    const deleteCount = deletes.mock.calls.length;
    rejectOnRelease = schedule.rejectMarker;
    await faults.releaseDeferredWrites();
    await state_FIRST_CALLBACK_SETTLED.wait;
    const settledSnapshot = snapshot(log);
    expect(settledSnapshot.entries, "second hold entries").toEqual(secondSnapshot.entries);
    expect(settledSnapshot.chain, "second hold chain").toEqual(secondSnapshot.chain);
    expect(settledSnapshot.sequenceAndHead, "second hold sequence and head").toEqual(secondSnapshot.sequenceAndHead);
    expect(settledSnapshot.own, "second hold own accounting").toEqual(secondSnapshot.own);
    expect(settledSnapshot.retention, "second hold retention").toEqual(secondSnapshot.retention);
    expect(settledSnapshot.flight, "second hold checkpoint flight").toEqual(secondSnapshot.flight);
    expect(firstCallbackOutcome?.status, "first callback outcome").toBe("rejected");
    if (firstCallbackOutcome?.status === "rejected") {
      expect(firstCallbackOutcome.error, "first callback outcome").toBeInstanceOf(AuditPersistenceError);
      expect((firstCallbackOutcome.error as AuditPersistenceError).cause, "first callback outcome").toBeInstanceOf(AuditLockHoldDeadlineError);
    }
    expect(state.bytesProvenance, "first callback provenance").toBe("unknown");
    expect(await diskSnapshot(storage), "second hold persisted bytes").toEqual(secondDisk);
    expect([writes.mock.calls.length, durableWrites.mock.calls.length, deletes.mock.calls.length], "second hold storage calls")
      .toEqual([writeCount, durableCount, deleteCount]);
    expect(secondSignal.aborted, "second hold active signal").toBe(false);
    const currentLock = await stat(lockPath);
    expect([currentLock.dev, currentLock.ino], "second hold lock identity").toEqual([secondLock.stats.dev, secondLock.stats.ino]);
    expect(await readFile(lockPath), "second hold lock payload").toEqual(secondLock.bytes);
    if (schedule.direct) {
      expect(state.postSplitSuffixMarkerEnsured, "second hold marker accounting").toBe(false);
      expect(await storage.read(META_NAMESPACE, SUFFIX_MARKER), "second hold marker bytes")
        .toEqual(schedule.rejectMarker ? null : new TextEncoder().encode("1"));
    }
    releaseSecond.release();
    expect((await secondOutcome).status, "independent hold outcome").toBe("fulfilled");
    if (schedule.direct) await log.appendCritical(entry("independent-append"));
    const complete = await envelopes(storage);
    expect(await storage.read(ENTRY_NAMESPACE, pendingEntry.key), "persisted append bytes").toEqual(pendingEntry.bytes);
    expect(complete.map(item => item.envelope.sequence), "persisted sequence continuity")
      .toEqual(Array.from({ length: persisted.length + ONE }, (_, index) => index + ONE));
    const nextEntry = complete.at(-ONE)!.envelope;
    expect(nextEntry.prev_hash, "persisted hash continuity").toBe(pendingEntry.envelope.entry_hash);
    const reader = new AuditLog(storage, masterKey, { ...signedConfig, consultSplitBoundary: false });
    expect(await reader.getIntegrityFindings(), "persisted reader findings").toEqual([]);
    expect(await reader.getChainHead(), "persisted reader head")
      .toEqual({ sequence: nextEntry.sequence, entry_hash: nextEntry.entry_hash });
    await reader.flush();
    await verify(storage);
  } finally {
    try {
      faults.deferWritesTo = null;
      releaseSecond.release();
      state_WRITE_PENDING.release();
      state_FIRST_HOLD_RETIRED.release();
      state_SECOND_HOLD.release();
      state_FIRST_CALLBACK_SETTLED.release();
      await faults.releaseDeferredWrites();
      await publicOutcome;
      if (secondOutcome) await secondOutcome;
      await Promise.all(callbackSettlements);
    } finally {
      vi.restoreAllMocks();
      vi.useRealTimers();
    }
  }
}

for (const critical of [false, true]) {
  for (const rejectMarker of [false, true]) {
    it(`A1: append state stays consistent with the write lock (${critical ? "critical" : "ordinary"}, ${rejectMarker ? "write refusal" : "write success"})`,
      () => heldSchedule({ critical, rejectMarker }));
  }
}
for (const rejectMarker of [false, true]) {
  it(`A1: a full recent window stays consistent with the write lock (${rejectMarker ? "write refusal" : "write success"})`,
    () => heldSchedule({ critical: true, rejectMarker, full: true }), FULL_WINDOW_TIMEOUT_MS);
  it(`A1: own accounting stays consistent across consecutive holds (${rejectMarker ? "write refusal" : "write success"})`,
    () => heldSchedule({ critical: true, rejectMarker, direct: true }));
  it(`A1: checkpoint flight stays consistent with the write lock (${rejectMarker ? "write refusal" : "write success"})`,
    () => heldSchedule({ critical: true, rejectMarker, direct: true, interval: true }));
}

it("A2: a live hold publishes once when marker storage is unavailable", async () => {
  const { log, storage } = await filesystemFixture();
  const originalWrite = storage.write.bind(storage);
  const faults = new FaultInjectingStorage(faultAdapter(storage, originalWrite));
  faults.failWriteOnCall = { namespace: META_NAMESPACE, keyPrefix: SUFFIX_MARKER, calls: [ONE] };
  vi.spyOn(storage, "write").mockImplementation((namespace, key, bytes) =>
    namespace === META_NAMESPACE && key === SUFFIX_MARKER ? faults.write(namespace, key, bytes) : originalWrite(namespace, key, bytes));
  const before = snapshot(log);
  const result = await outcome(log.appendCritical(entry("live-append")));
  expect(result.status, "live hold append outcome").toBe("fulfilled");
  expect(snapshot(log).entries.length, "live hold publication count").toBe(before.entries.length + ONE);
  expect((log as any).postSplitSuffixMarkerEnsured, "live hold marker retry").toBe(false);
  await log.appendCritical(entry("next-append"));
  expect((log as any).postSplitSuffixMarkerEnsured, "live hold marker establishment").toBe(true);
  expect(await storage.read(META_NAMESPACE, SUFFIX_MARKER), "live hold marker bytes").not.toBeNull();
});

it("A2: established marker publication remains singular", async () => {
  const { log, storage } = await filesystemFixture();
  const writes = vi.spyOn(storage, "write");
  await log.appendCritical(entry("marker-establishment"));
  const before = snapshot(log);
  expect((log as any).postSplitSuffixMarkerEnsured, "live hold marker establishment").toBe(true);
  writes.mockClear();
  await log.appendCritical(entry("marker-established"));
  expect(snapshot(log).entries.length, "live hold publication count").toBe(before.entries.length + ONE);
  expect(writes.mock.calls.filter(([namespace, key]) => namespace === META_NAMESPACE && key === SUFFIX_MARKER), "live hold marker reuse").toEqual([]);
});
for (const consultSplitBoundary of [false, true]) {
  it(`A2: publication respects boundary consultation (${consultSplitBoundary ? "empty floor" : "disabled consultation"})`, async () => {
    const { log, storage } = await filesystemFixture({ consultSplitBoundary }, false, !consultSplitBoundary);
    const writes = vi.spyOn(storage, "write");
    const before = snapshot(log);
    await log.appendCritical(entry("boundary-append"));
    expect(snapshot(log).entries.length, "live hold publication count").toBe(before.entries.length + ONE);
    expect(writes.mock.calls.filter(([namespace, key]) => namespace === META_NAMESPACE && key === SUFFIX_MARKER), "live hold boundary marker").toEqual([]);
  });
}
it("A3: persisted history remains continuous across independent holds", () => heldSchedule({ critical: true, rejectMarker: false }));

async function coverageSchedule(property: "accounting" | "buffer") {
  let now = CLOCK_ORIGIN;
  const raw = new MemoryStorage();
  const storage = new FaultInjectingStorage(raw);
  const log = new AuditLog(storage, masterKey, { ...signedConfig, __testMonotonicNow: () => now });
  await log.appendCritical(entry("seed"));
  await log.flushDurable();
  const seedSequence = ONE;
  const capturedSequence = seedSequence + ONE;
  const ownSequence = capturedSequence + ONE;
  expect(await checkpointSequences(storage), "coverage setup seed seal").toEqual([seedSequence]);
  await log.appendCritical(entry("captured-entry"));
  now += AUDIT_TAIL_CHECKPOINT_MAX_AGE_MS;
  const target = { namespace: CHECKPOINT_NAMESPACE, key: checkpointKey(capturedSequence) };
  storage.deferWritesTo = target;
  const entered = gate();
  const write = storage.write.bind(storage);
  vi.spyOn(storage, "write").mockImplementation((namespace, key, bytes) => {
    const pending = write(namespace, key, bytes);
    if (namespace === target.namespace && key === target.key) entered.release();
    return pending;
  });
  const barrier = outcome(log.flushDurable());
  try {
    const admission = await Promise.race([entered.wait.then(() => HELD), barrier.then(() => SETTLED)]);
    expect(admission, "coverage setup checkpoint admission").toBe(HELD);
    expect(storage.deferredCount, "coverage setup checkpoint queue").toBe(ONE);
    await log.appendCritical(entry("uncovered-entry"));
    const own = (await envelopes(storage)).at(-ONE)!.envelope;
    const before = snapshot(log).own;
    expect(own.sequence, "coverage setup own sequence").toBe(ownSequence);
    expect(before.highest, "coverage setup own high water").toBeGreaterThan(capturedSequence);
    expect(before.hashes, "coverage setup own hash").toContain(own.entry_hash);
    expect(before.count, "coverage setup own count").toBeGreaterThan(ZERO);
    expect(before.age, "coverage setup own age").toBeDefined();
    storage.deferWritesTo = null;
    await storage.releaseDeferredWrites();
    expect((await barrier).status, "coverage checkpoint outcome").toBe("fulfilled");
    const after = snapshot(log).own;
    if (property === "accounting") {
      expect({ count: after.count, age: after.age }, "uncovered own accounting").toEqual({ count: before.count, age: before.age });
    } else {
      expect(after.hashes, "uncovered own hash buffered").toEqual([own.entry_hash]);
    }
    expect(await checkpointSequences(storage), "coverage captured checkpoints").toEqual([seedSequence, capturedSequence]);
    expect(after.covered, "coverage own floor").toBeLessThan(ownSequence);
    await log.flushDurable();
    expect(await checkpointSequences(storage), "coverage complete checkpoints").toEqual([seedSequence, capturedSequence, ownSequence]);
    expect(snapshot(log).own, "coverage complete accounting").toEqual({
      highest: ownSequence, covered: ownSequence, hashes: [], age: undefined, count: ZERO,
    });
    await verify(storage);
  } finally {
    storage.deferWritesTo = null;
    await storage.releaseDeferredWrites();
    await barrier;
  }
}
it("C1: own accounting remains until checkpoint coverage", () => coverageSchedule("accounting"));
it("C2: own hashes remain buffered until checkpoint coverage", () => coverageSchedule("buffer"));
