// fail-before-exempt: comment-only change that states the derivation of a key-width literal; no assertion changes, so it passes against pre-fix source by construction.
/** Ordered checkpoint decisions, shared read admission and lock retirement. */
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import fs, { mkdtemp, rm } from "node:fs/promises";
import { syncBuiltinESMExports } from "node:module";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import * as auditModule from "../../src/operational/audit-log.js";
import { AuditLog } from "../../src/operational/audit-log.js";
import { isAuditCheckpointRecord, AUDIT_CHAIN_SCHEMA_VERSION, AUDIT_CHECKPOINT_SCHEMA_VERSION } from "../../src/audit/checkpoint-shape.js";
import { MemoryStorage } from "../../src/storage/memory.js";
import { FilesystemStorage } from "../../src/storage/filesystem.js";
import { MEASURE_CONFIG, MEASURE_MASTER_KEY, measureEntry, prepopulateAudit } from "../../scripts/measure-audit-append.js";

// Three admissions is the empirical production budget; must match
// AUDIT_CHECKPOINT_READ_CONCURRENCY in operational/audit-log.ts.
const P = 3;
const HOLD_MS = 1_000; // Real hold used to distinguish prompt completion from retirement.
const OBSERVE_MS = HOLD_MS / 10;
const POPULATION = 64; // Several full windows before and after the fifth body.
const CHECKPOINTS = 3 * P;
const AUDIT_NAMESPACE = "_audit";
const AUDIT_CHECKPOINT_NAMESPACE = "_audit_checkpoints";
type Signal = { aborted: boolean; checkpointReadAbort?: AbortSignal };
type PersistedAuditEnvelopeV2 = { sequence: number; entry_hash: string };
type PersistedEntryHashCollection =
  | { status: "complete"; hashes: string[] }
  | { status: "incomplete"; reason: "gap" | "duplicate"; atSequence: number };
const encode = (value: unknown) => new TextEncoder().encode(JSON.stringify(value));
const bytesToString = (value: Uint8Array) => new TextDecoder().decode(value);
// Storage keys use a 20-digit sequence; hashes use 64 hex digits for SHA-256.
const checkpointKey = (n: number) => `audit-checkpoint-${String(n).padStart(20, "0")}`; // Twenty decimal places preserve persisted sequence ordering; must match writeCheckpointRecord / parseCheckpointKeySequence in server/src/operational/audit-log.ts.
const entryKey = (n: number) => `entry-${String(n).padStart(20, "0")}-fixture`; // Twenty decimal places preserve persisted sequence ordering; must match persistChainedEntry / parseEntryKeySequence in server/src/operational/audit-log.ts.
const entry = (sequence: number, hash = "a") => encode({ schema_version: AUDIT_CHAIN_SCHEMA_VERSION, sequence,
  prev_hash: "GENESIS", entry_hash: hash.repeat(64), timestamp: "fixture", encrypted_payload_bytes: "" });
const checkpoint = (sequence: number) => encode({ schema_version: AUDIT_CHECKPOINT_SCHEMA_VERSION, checkpoint_kind: "audit-checkpoint",
  checkpoint_sequence: sequence, from_sequence: 1, previous_checkpoint_sequence: 0,
  root_hash: "a".repeat(64), signed_at: "fixture", signer_kid: null, signature: null,
  signature_algorithm: null, payload_encoding: "domain-separated-canonical-json-v1", unsigned: true });
const delay = (ms: number) => new Promise<void>((resolve) => setTimeout(resolve, ms));
function gate() { let release!: () => void; const wait = new Promise<void>((resolve) => { release = resolve; }); return { wait, release }; }
async function turns(count = P * P) { for (let i = 0; i < count; i++) await new Promise<void>((resolve) => setImmediate(resolve)); }
const settle = <T>(promise: Promise<T>) => promise.then(value => ({ state: "read" as const, value }), error => ({ state: "faulted" as const, error }));
let root: string;
beforeEach(async () => { root = await mkdtemp(join(tmpdir(), "checkpoint-schedule-")); vi.stubEnv("HOME", root); });
afterEach(async () => { vi.restoreAllMocks(); syncBuiltinESMExports(); vi.unstubAllEnvs(); await rm(root, { recursive: true, force: true }); });

// Oracle support must match the corresponding f1a35781 helpers in operational/audit-log.ts.
function compareAuditKeys(a: string, b: string): number {
  return a.localeCompare(b) || (a < b ? -1 : a > b ? 1 : 0);
}

function parseEntryKeySequence(key: string): number | null {
  const match = /^entry-(\d{20})-/.exec(key); // Twenty decimal places preserve persisted sequence ordering; must match persistChainedEntry / parseEntryKeySequence in server/src/operational/audit-log.ts.
  if (!match) return null;
  const seq = Number(match[1]);
  return Number.isSafeInteger(seq) ? seq : null;
}

function parseCheckpointKeySequence(key: string): number | null {
  const match = /-(\d{20})$/.exec(key); // Twenty decimal places preserve persisted sequence ordering; must match writeCheckpointRecord / parseCheckpointKeySequence in server/src/operational/audit-log.ts.
  if (!match) return null;
  const seq = Number(match[1]);
  return Number.isSafeInteger(seq) ? seq : null;
}

function isPermissionError(err: unknown): boolean {
  const code =
    err instanceof Error && "code" in err
      ? String((err as NodeJS.ErrnoException).code)
      : "";
  return code === "EACCES" || code === "EPERM";
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return !!value && typeof value === "object" && !Array.isArray(value);
}

function isPersistedAuditEnvelopeV2(
  value: unknown
): value is PersistedAuditEnvelopeV2 {
  return (
    isRecord(value) &&
    value.schema_version === AUDIT_CHAIN_SCHEMA_VERSION &&
    typeof value.sequence === "number" &&
    Number.isSafeInteger(value.sequence) &&
    value.sequence > 0 &&
    typeof value.prev_hash === "string" &&
    typeof value.entry_hash === "string" &&
    /^[0-9a-f]{64}$/.test(value.entry_hash) &&
    typeof value.timestamp === "string" &&
    typeof value.encrypted_payload_bytes === "string"
  );
}

class SequentialOracle {
  constructor(readonly storage: MemoryStorage) {}
  // Must match the decision logic of readHighestAuditCheckpointSequence at f1a35781
  // in operational/audit-log.ts; the loop below is copied verbatim.
  async predecessor(keys: string[], sealedTipSequence: number) {
    keys.sort(compareAuditKeys);
    let highest = 0;
    for (const key of keys) {
      // F2 Option A: the operator's own checkpoints are always ABOVE the sealed
      // tip, so a sealed-region checkpoint the operator uid cannot open on an
      // armed box (root-owned legacy file) is never the highest and can be
      // skipped silently. A non-permission fault, or an unreadable checkpoint
      // above the tip, still surfaces (rethrown to the append/checkpoint caller,
      // which fails closed rather than under-counting the checkpoint floor).
      const keySeq = parseCheckpointKeySequence(key);
      const inSealedRegion =
        sealedTipSequence > 0 && keySeq !== null && keySeq <= sealedTipSequence;
      let raw: Uint8Array | null;
      try {
        raw = await this.storage.read(AUDIT_CHECKPOINT_NAMESPACE, key);
      } catch (err) {
        if (inSealedRegion && isPermissionError(err)) continue;
        throw err;
      }
      if (!raw) continue;
      try {
        const parsed = JSON.parse(bytesToString(raw));
        if (
          isAuditCheckpointRecord(parsed) &&
          parsed.checkpoint_kind === "audit-checkpoint"
        ) {
          highest = Math.max(highest, parsed.checkpoint_sequence);
        }
      } catch {
        // Full verification reports malformed checkpoints.
      }
    }
    return highest;
  }
  // Must match the decision logic of collectPersistedEntryHashes at f1a35781
  // in operational/audit-log.ts; the loop and final verdict are copied verbatim.
  async collector(fromSequence: number, toSequence: number, sealedTipSequence: number, keys: readonly string[]): Promise<PersistedEntryHashCollection> {
    const bySequence = new Map<number, string>();
    let duplicate: number | undefined;
    for (const key of [...keys].sort(compareAuditKeys)) {
      if (!key.startsWith("entry-")) continue;
      const seq = parseEntryKeySequence(key);
      if (seq !== null && seq <= sealedTipSequence) continue;
      const raw = await this.storage.read(AUDIT_NAMESPACE, key);
      if (!raw) continue;
      try {
        const parsed = JSON.parse(bytesToString(raw));
        if (isPersistedAuditEnvelopeV2(parsed)) {
          // Envelope sequence is authoritative, including identical copies
          // under out-of-range filenames; never collapse duplicate occupancy.
          if (bySequence.has(parsed.sequence) &&
              parsed.sequence >= fromSequence && parsed.sequence <= toSequence) {
            duplicate = duplicate === undefined ? parsed.sequence : Math.min(duplicate, parsed.sequence);
          }
          bySequence.set(parsed.sequence, parsed.entry_hash);
        }
      } catch {
        // Full verification reports malformed entries; missing occupancy is a gap.
      }
    }
    if (duplicate !== undefined) return { status: "incomplete", reason: "duplicate", atSequence: duplicate };
    const hashes: string[] = [];
    for (let sequence = fromSequence; sequence <= toSequence; sequence++) {
      const hash = bySequence.get(sequence);
      if (!hash) return { status: "incomplete", reason: "gap", atSequence: sequence };
      hashes.push(hash);
    }
    return { status: "complete", hashes };
  }
}

type Mode = "collector" | "predecessor";
const modes: Mode[] = ["collector", "predecessor"];
function invoke(log: AuditLog, mode: Mode, keys: string[], signal?: Signal, sealed = 0) {
  return mode === "collector"
    ? (log as any).collectPersistedEntryHashes(1, P, sealed, keys, signal)
    : (log as any).readHighestAuditCheckpointSequence(sealed, signal);
}
function fixture(mode: Mode, count = CHECKPOINTS) {
  const keys = Array.from({ length: count }, (_, i) => mode === "collector" ? entryKey(i + 1) : checkpointKey(i + 1));
  const storage = new MemoryStorage();
  vi.spyOn(storage, "listKeys").mockResolvedValue(keys);
  const log = new AuditLog(storage, MEASURE_MASTER_KEY, MEASURE_CONFIG);
  return { keys, storage, log };
}

// Match withAuditWriteLock's paired retirement fields in operational/audit-log.ts;
// the production reader composes checkpointReadAbort with its own stop signal.
function permitSchedule() {
  let outstanding = 0; let maximum = 0;
  const admissions: number[] = [];
  const flights: { retire: () => void; holds: ReturnType<typeof gate>[]; run: Promise<unknown> }[] = [];
  return {
    admissions,
    outstanding: () => outstanding,
    maximum: () => maximum,
    start(mode: Mode, count = P) {
      const { keys, storage, log } = fixture(mode, count);
      const holds = keys.map(() => gate());
      const controller = new AbortController();
      const signal = { aborted: false, checkpointReadAbort: controller.signal };
      const id = flights.length; const issued: string[] = [];
      vi.spyOn(storage, "read").mockImplementation(async (_ns, key) => {
        issued.push(key); admissions.push(id);
        outstanding++; maximum = Math.max(maximum, outstanding);
        try { await holds[keys.indexOf(key)]!.wait; return null; }
        finally { outstanding--; }
      });
      const retire = () => { signal.aborted = true; controller.abort(new Error("hold retired")); };
      const run = settle(invoke(log, mode, keys, signal));
      flights.push({ retire, holds, run });
      return { id, keys, holds, issued, retire, run };
    },
    async close() {
      // Retire queued admissions before releasing gates, including assertion failures.
      for (const flight of flights) flight.retire();
      for (const flight of flights) for (const hold of flight.holds) hold.release();
      await Promise.all(flights.map(flight => flight.run));
      await turns();
    },
  };
}

type Scripted = Uint8Array | null | { error: unknown; sync?: boolean } | { plain: true; raw: Uint8Array | null };
function scriptedStorage(keys: string[], outcomes: Scripted[], scrambled: boolean, delays?: number[]) {
  const storage = new MemoryStorage();
  const issued: string[] = [];
  let outstanding = 0;
  vi.spyOn(storage, "listKeys").mockResolvedValue(keys);
  vi.spyOn(storage, "read").mockImplementation((_ns, key) => {
    issued.push(key);
    const index = keys.indexOf(key);
    const result = outcomes[index]!;
    if (result && !(result instanceof Uint8Array) && "plain" in result) return result.raw as any;
    if (result && !(result instanceof Uint8Array) && result.sync) throw result.error;
    outstanding++;
    return (async () => {
      try {
        // Reverse every window's settle order independently of its issue order.
        if (scrambled) await turns(delays?.[index] ?? (P - index % P));
        if (result && !(result instanceof Uint8Array)) throw result.error;
        return result;
      } finally { outstanding--; }
    })();
  });
  return { storage, issued, outstanding: () => outstanding };
}

for (const mode of modes) describe(mode, () => {
  it("T-EQ preserves every ordered oracle verdict and read prefix", async () => {
    const fault = (code: string, sync = false) => ({ error: Object.assign(new Error(code), { code }), sync });
    const body = mode === "collector" ? entry : checkpoint;
    const key = mode === "collector" ? entryKey : checkpointKey;
    const normal = Array.from({ length: CHECKPOINTS }, (_, i) => body(i + 1));
    const keys = Array.from({ length: CHECKPOINTS }, (_, i) => key(i + 1));
    const cases: { keys: string[]; outcomes: Scripted[]; sealed?: number; delays?: number[] }[] = [
      { keys, outcomes: normal },
      { keys, outcomes: normal.map(raw => ({ plain: true, raw })) },
    ];
    for (const index of [0, Math.floor(CHECKPOINTS / 2), CHECKPOINTS - 1]) {
      for (const code of ["EIO", "EACCES"]) {
        for (const sync of [false, true]) {
          const outcomes: Scripted[] = [...normal]; outcomes[index] = fault(code, sync);
          cases.push({ keys, outcomes }, { keys, outcomes, sealed: P });
        }
      }
    }
    cases.push({ keys, outcomes: [fault("EIO"), fault("EACCES"), ...normal.slice(2)] });
    for (const replacement of [null, encode({}), new TextEncoder().encode("{"), body(1), body(CHECKPOINTS + 1)]) {
      cases.push({ keys, outcomes: [normal[0]!, replacement, ...normal.slice(2)] });
    }
    if (mode === "collector") {
      cases.push({ keys: [keys[0]!, entryKey(CHECKPOINTS + 1)], outcomes: [entry(1), entry(1, "b")] });
      cases.push({ keys: [entryKey(CHECKPOINTS + 1), keys[1]!, keys[2]!], outcomes: [entry(1), entry(2), entry(3)] });
      const tie = `${entryKey(CHECKPOINTS + 1)}z`;
      cases.push({ keys: [keys[0]!, `${tie}\u00ad`, tie], outcomes: [entry(1), entry(2), entry(3)] });
      cases.push({ keys: ["legacy", keys[0]!, keys[1]!], outcomes: [fault("EIO"), fault("EIO"), entry(2)], sealed: 1 });
    }
    const copies = 1_000; // Multiplicity fixture from the design's oracle inventory.
    cases.push({ keys: Array.from({ length: copies }, (_, i) => `${key(1)}-copy-${i}`), outcomes: Array.from({ length: copies }, () => encode({})) });
    let seed = 1000; // Stable job seed, independent of the scheduler.
    const random = () => { seed = (Math.imul(seed, 1664525) + 1013904223) >>> 0; return seed >>> 16; }; // Numerical Recipes LCG, using its high 16 bits.
    const vectors = 200; // Design-required randomized outcome vectors per function.
    const choices: Scripted[] = [null, encode({}), new TextEncoder().encode("{"), fault("EIO"), fault("EACCES"), fault("EPERM", true)];
    for (let i = 0; i < vectors; i++) cases.push({ keys, sealed: i % (P + 1),
      outcomes: normal.map(bytes => random() % 2 ? bytes : choices[random() % choices.length]!),
      delays: normal.map(() => 1 + random() % (P * P)),
    });
    for (const sample of cases) {
      const oracle = scriptedStorage(sample.keys, sample.outcomes, false);
      const reference = new SequentialOracle(oracle.storage);
      const expected = await settle<unknown>(mode === "collector"
        ? reference.collector(1, P, sample.sealed ?? 0, sample.keys)
        : reference.predecessor([...sample.keys], sample.sealed ?? 0));
      const actual = scriptedStorage(sample.keys, sample.outcomes, true, sample.delays);
      const log = new AuditLog(actual.storage, MEASURE_MASTER_KEY, MEASURE_CONFIG);
      const result = await settle(invoke(log, mode, sample.keys, undefined, sample.sealed));
      if (expected.state === "faulted") {
        expect(result.state).toBe("faulted");
        expect((result as any).error).toBe(expected.error);
        const ordered = [...sample.keys].sort(compareAuditKeys).filter(k => mode === "predecessor" ||
          (k.startsWith("entry-") && !(parseEntryKeySequence(k) !== null && parseEntryKeySequence(k)! <= (sample.sealed ?? 0))));
        const j = oracle.issued.length - 1;
        expect(actual.issued.slice(0, j + 1)).toEqual(oracle.issued);
        expect(actual.issued).toEqual(ordered.slice(0, actual.issued.length));
        expect(actual.issued.length).toBeLessThanOrEqual(j + P);
      } else {
        expect(result).toEqual(expected);
        expect(actual.issued).toEqual(oracle.issued);
        expect(actual.outstanding()).toBe(0);
      }
      // Throwing verdicts are prompt; captured tail reads are released by this fixture.
      await turns(); expect(actual.outstanding()).toBe(0);
      vi.restoreAllMocks();
    }
  });

  it("T-EQ reversed faults preserve the first fault in key order", async () => {
    const faultCount = 2; // Two distinct faults separate key order from settlement order.
    const { keys, storage, log } = fixture(mode, faultCount);
    const holds = keys.map(() => gate());
    const faults = keys.map(key => new Error(`read fault for ${key}`));
    const issued: string[] = []; const settled: string[] = [];
    vi.spyOn(storage, "read").mockImplementation(async (_ns, key) => {
      const index = keys.indexOf(key); issued.push(key);
      await holds[index]!.wait; settled.push(key); throw faults[index];
    });
    const oracle = scriptedStorage(keys, faults.map(error => ({ error })), false);
    const reference = new SequentialOracle(oracle.storage);
    const expected = await settle<unknown>(mode === "collector"
      ? reference.collector(1, P, 0, keys)
      : reference.predecessor([...keys], 0));
    const run = settle(invoke(log, mode, keys));
    try {
      await turns(); expect(issued).toEqual(keys);
      // Keep the earlier key pending until the later fault has settled.
      holds[faultCount - 1]!.release(); await turns();
      expect(settled).toEqual([keys[faultCount - 1]]);
      holds[0]!.release();
      const result = await run;
      expect(settled).toEqual([...keys].reverse());
      expect(expected).toMatchObject({ state: "faulted", error: faults[0] });
      expect(result.state).toBe("faulted");
      expect((result as { error: unknown }).error).toBe(faults[0]);
    } finally { for (const hold of holds) hold.release(); await run; await turns(); }
  });

  it("T-CAP admits exactly one window and waits for the head decision", async () => {
    expect((auditModule as any).AUDIT_CHECKPOINT_READ_CONCURRENCY).toBe(P);
    const { keys, storage, log } = fixture(mode);
    const holds = keys.map(() => gate());
    let active = 0; let max = 0; const issued: string[] = [];
    vi.spyOn(storage, "read").mockImplementation(async (_ns, key) => {
      issued.push(key); active++; max = Math.max(max, active);
      try { await holds[keys.indexOf(key)]!.wait; return null; } finally { active--; }
    });
    const run = settle(invoke(log, mode, keys));
    try {
      await turns(); expect(active).toBe(P); expect(max).toBe(P);
      for (const hold of holds.slice(1)) hold.release();
      await turns(); expect(issued).toEqual(keys.slice(0, P));
    } finally { for (const hold of holds) hold.release(); await run; }
    expect(max).toBe(P); expect(active).toBe(0);
  });

  it("T-ABORT rejects a pre-retired hold without reads", async () => {
    const { keys, storage, log } = fixture(mode);
    const read = vi.spyOn(storage, "read");
    const result = await settle(invoke(log, mode, keys, { aborted: true }));
    expect(result).toMatchObject({ state: "faulted", error: { name: "AuditLockHoldDeadlineError" } });
    expect(read).not.toHaveBeenCalled();
  });

  it("T-ABORT checks retirement before storage admission", async () => {
    const { keys, storage, log } = fixture(mode);
    const signal = { aborted: false }; const issued: string[] = [];
    vi.spyOn(storage, "read").mockImplementation(async (_ns, key) => { issued.push(key); signal.aborted = true; return null; });
    const result = await settle(invoke(log, mode, keys, signal));
    expect(result).toMatchObject({ state: "faulted", error: { name: "AuditLockHoldDeadlineError" } });
    expect(issued).toEqual(keys.slice(0, 1));
  });

  it("T-ABORT removes a waiter before any permit is released", async () => {
    const first = fixture(mode); const second = fixture(mode);
    const hold = gate(); const issued: string[] = [];
    vi.spyOn(first.storage, "read").mockImplementation(async () => { await hold.wait; return null; });
    vi.spyOn(second.storage, "read").mockImplementation(async (_ns, key) => { issued.push(key); return null; });
    const firstRun = settle(invoke(first.log, mode, first.keys));
    const controller = new AbortController(); const signal = { aborted: false, checkpointReadAbort: controller.signal };
    let result: any;
    try {
      await turns();
      const run = settle(invoke(second.log, mode, second.keys, signal)).then(value => { result = value; });
      await turns(); signal.aborted = true; controller.abort(new Error("retired"));
      await turns();
      expect(result).toMatchObject({ state: "faulted", error: { name: "AuditLockHoldDeadlineError" } });
      expect(issued).toEqual([]);
      await run;
    } finally { hold.release(); await firstRun; await turns(); }
    expect(issued).toEqual([]);
  });
});

it("T-WAVES shares permits across logs and releases on settlement", async () => {
  const first = fixture("collector"); const hold = gate();
  const held = first.keys[0]!; const firstSignal = { aborted: false };
  let active = 0; let maximum = 0;
  vi.spyOn(first.storage, "read").mockImplementation(async (_ns, key) => {
    active++; maximum = Math.max(maximum, active);
    try { if (key === held) await hold.wait; return null; } finally { active--; }
  });
  const firstRun = settle(invoke(first.log, "collector", first.keys, firstSignal));
  const waveRuns: Promise<unknown>[] = [];
  try {
    await turns(); firstSignal.aborted = true;
    // Settled later slots must free permits even while the oldest outcome waits.
    for (const mode of [...modes, ...modes]) {
      const wave = fixture(mode); const controller = new AbortController();
      const signal = { aborted: false, checkpointReadAbort: controller.signal };
      let admitted = 0;
      vi.spyOn(wave.storage, "read").mockImplementation(async () => {
        active++; admitted++; maximum = Math.max(maximum, active);
        try { await delay(OBSERVE_MS); return null; } finally { active--; }
      });
      const run = settle(invoke(wave.log, mode, wave.keys, signal)); waveRuns.push(run);
      await turns(); expect(admitted).toBe(P - 1); expect(active).toBe(P);
      signal.aborted = true; controller.abort(new Error("wave retired"));
      await delay(OBSERVE_MS * 2); await run;
      expect(active).toBe(1); expect(maximum).toBe(P);
    }
  } finally { hold.release(); await firstRun; await Promise.all(waveRuns); await turns(); }
  expect(active).toBe(0);
});

it("T-WAVES-R retains permits for pending reads from each abandoned hold", async () => {
  const schedule = permitSchedule();
  const waves: Mode[] = ["collector", "predecessor", "collector"]; // Three successive holds share the process budget.
  try {
    for (const [index, mode] of waves.entries()) {
      const before = schedule.outstanding();
      const wave = schedule.start(mode);
      await turns();
      expect(wave.issued).toHaveLength(P - before);
      expect(schedule.outstanding()).toBe(P);
      expect(schedule.maximum()).toBeLessThanOrEqual(auditModule.AUDIT_CHECKPOINT_READ_CONCURRENCY);
      wave.retire(); await turns();
      // Retirement alone cannot free the permit of a storage read still pending.
      expect(schedule.outstanding()).toBe(P);
      if (index === 0) {
        // Only this tail settles; the first hold's other reads span both later waves.
        wave.holds[P - 1]!.release(); await turns();
        expect(schedule.outstanding()).toBe(P - 1);
      }
    }
  } finally { await schedule.close(); }
  expect(schedule.outstanding()).toBe(0);
});

it("T-HANDOFF grants a live waiter on a single read settlement", async () => {
  const schedule = permitSchedule();
  try {
    const active = schedule.start("collector"); await turns();
    expect(active.issued).toHaveLength(P);
    const live = schedule.start("predecessor", 1); await turns();
    expect(live.issued).toEqual([]);
    active.holds[P - 1]!.release(); await turns();
    // No new acquirer or second settlement can supply this handoff.
    expect(live.issued).toEqual(live.keys);
    expect(schedule.outstanding()).toBe(P);
    expect(schedule.maximum()).toBe(P);
  } finally { await schedule.close(); }
  expect(schedule.outstanding()).toBe(0);
});

it("T-ABORT-QUEUE grants the live waiter after an earlier waiter retires", async () => {
  const schedule = permitSchedule();
  try {
    const active = schedule.start("collector"); await turns();
    expect(active.issued).toHaveLength(P);
    const aborted = schedule.start("predecessor", 1); await turns();
    const live = schedule.start("collector", 1); await turns();
    expect(aborted.issued).toEqual([]); expect(live.issued).toEqual([]);
    aborted.retire(); await turns();
    expect(await aborted.run).toMatchObject({ state: "faulted", error: { name: "AuditLockHoldDeadlineError" } });
    expect(schedule.outstanding()).toBe(P);
    active.holds[P - 1]!.release(); await turns();
    // A retired queue entry cannot consume the only handoff to a live waiter.
    expect(live.issued).toEqual(live.keys);
    expect(aborted.issued).toEqual([]);
    expect(schedule.outstanding()).toBe(P);
    expect(schedule.maximum()).toBe(P);
  } finally { await schedule.close(); }
  expect(schedule.outstanding()).toBe(0);
});

it("T-FIFO grants several live waiters in arrival order", async () => {
  const schedule = permitSchedule();
  try {
    const active = schedule.start("collector"); await turns();
    expect(active.issued).toHaveLength(P);
    const waiters = [];
    for (let index = 0; index < P; index++) {
      const waiter = schedule.start(modes[index % modes.length]!, 1);
      waiters.push(waiter); await turns(); expect(waiter.issued).toEqual([]);
    }
    for (let index = 0; index < waiters.length; index++) {
      active.holds[index]!.release(); await turns();
      expect(schedule.admissions.slice(P)).toEqual(waiters.slice(0, index + 1).map(waiter => waiter.id));
      expect(schedule.outstanding()).toBe(P);
      expect(schedule.maximum()).toBe(P);
    }
  } finally { await schedule.close(); }
  expect(schedule.outstanding()).toBe(0);
});

async function productionFixture() {
  const path = join(root, "state"); await prepopulateAudit(path, POPULATION);
  const storage = new FilesystemStorage(path);
  const log = new AuditLog(storage, MEASURE_MASTER_KEY, { ...MEASURE_CONFIG, checkpointInterval: 1, writeLockHoldDeadlineMs: HOLD_MS });
  await log.query({ limit: 1 });
  for (let i = 0; i < CHECKPOINTS; i++) await log.appendCritical(measureEntry(POPULATION + i));
  return { storage, log, sequence: POPULATION + CHECKPOINTS + 1 };
}

for (const mode of modes) {
  it(`T-ABORT forwards the ${mode} signal through the real hold`, async () => {
    const { storage, log, sequence } = await productionFixture();
    const method = mode === "collector" ? "collectPersistedEntryHashes" : "readHighestAuditCheckpointSequence";
    const ns = mode === "collector" ? AUDIT_NAMESPACE : AUDIT_CHECKPOINT_NAMESPACE;
    const original = (log as any)[method].bind(log); const completed = gate();
    let collecting = false;
    vi.spyOn(log as any, method).mockImplementation(async (...args) => {
      collecting = true;
      try { return await original(...args); } finally { collecting = false; completed.release(); }
    });
    const hold = gate(); const read = storage.read.bind(storage);
    let count = 0; let recovered = false; let afterRecovery = 0;
    const fifth = P + 2; // The fifth body is in the second window.
    vi.spyOn(console, "error").mockImplementation((line) => { if (String(line).includes("AUDIT-WRITE-LOCK-RECOVERY")) recovered = true; });
    vi.spyOn(storage, "read").mockImplementation(async (namespace, key) => {
      if (collecting && namespace === ns && (key.startsWith("entry-") || key.startsWith("audit-checkpoint-"))) {
        count++; if (recovered) afterRecovery++;
        if (count === fifth) await hold.wait;
      }
      return read(namespace, key);
    });
    const result = settle(log.appendCritical(measureEntry(sequence)));
    try {
      expect(await result).toMatchObject({ state: "faulted", error: { name: "AuditLockHoldDeadlineError" } });
      expect(recovered).toBe(true);
    } finally { hold.release(); await completed.wait; await turns(); }
    expect(afterRecovery).toBe(0);
    expect(await read(AUDIT_CHECKPOINT_NAMESPACE, checkpointKey(sequence))).toBeNull();
    expect((log as any).criticalAppendsSinceCheckpoint).toBe(1);
  });

  it(`T-PROMPT returns the ${mode} fault before later reads settle`, async () => {
    const { storage, log } = await productionFixture();
    const method = mode === "collector" ? "collectPersistedEntryHashes" : "readHighestAuditCheckpointSequence";
    const ns = mode === "collector" ? AUDIT_NAMESPACE : AUDIT_CHECKPOINT_NAMESPACE;
    const original = (log as any)[method].bind(log);
    let collecting = false;
    vi.spyOn(log as any, method).mockImplementation(async (...args) => {
      collecting = true; try { return await original(...args); } finally { collecting = false; }
    });
    const hold = gate(); const read = storage.read.bind(storage); const error = new Error("ordered read fault");
    let count = 0; let outstanding = 0;
    vi.spyOn(storage, "read").mockImplementation(async (namespace, key) => {
      if (collecting && namespace === ns && (key.startsWith("entry-") || key.startsWith("audit-checkpoint-"))) {
        if (++count === 1) throw error;
        outstanding++;
        try { await hold.wait; return null; } finally { outstanding--; }
      }
      return read(namespace, key);
    });
    const diagnostic = vi.spyOn(console, "error").mockImplementation(() => {});
    const recovery = vi.spyOn(log as any, "recordWriteLockRecoveryEvent");
    let result: any;
    const run = settle(log.appendCritical(measureEntry(POPULATION))).then(value => { result = value; });
    try {
      await delay(HOLD_MS / 2);
      expect(result).toEqual({ state: "faulted", error });
      expect(result.error).toBe(error);
      const atVerdict = count; await turns(); expect(count).toBe(atVerdict);
      expect(outstanding).toBe(P - 1);
      expect(recovery).not.toHaveBeenCalled();
      expect(diagnostic.mock.calls.filter(([line]) => String(line).includes("AUDIT-WRITE-LOCK-RECOVERY"))).toEqual([]);
    } finally { hold.release(); await run; await turns(); }
    expect(outstanding).toBe(0);
  });
}

it("captures a later rejection while its head is still pending", async () => {
  // A child isolates Node's rejection events from the test runner's own listeners.
  const moduleUrl = new URL("../../src/operational/audit-log.ts", import.meta.url).href;
  const storageUrl = new URL("../../src/storage/memory.ts", import.meta.url).href;
  const configUrl = new URL("../../scripts/measure-audit-append.ts", import.meta.url).href;
  const keychainUrl = new URL("../setup/keychain-memory-store.ts", import.meta.url).href;
  const program = `
    import { AuditLog } from ${JSON.stringify(moduleUrl)};
    import { MemoryStorage } from ${JSON.stringify(storageUrl)};
    import { MEASURE_CONFIG, MEASURE_MASTER_KEY } from ${JSON.stringify(configUrl)};
    import { installInMemoryKeychainStore } from ${JSON.stringify(keychainUrl)};
    installInMemoryKeychainStore();
    const events = []; process.on("unhandledRejection", error => events.push(String(error)));
    const store = new MemoryStorage(); let release; let calls = 0;
    const hold = new Promise(resolve => { release = resolve; });
    store.read = (_ns, key) => { calls++; return key === "entry-a" ? hold.then(() => null) : Promise.reject(new Error("later")); };
    const log = new AuditLog(store, MEASURE_MASTER_KEY, MEASURE_CONFIG);
    const run = log.collectPersistedEntryHashes(1, 1, 0, ["entry-a", "entry-b"]).catch(() => {});
    await new Promise(resolve => setTimeout(resolve, ${OBSERVE_MS}));
    const before = calls; release(); await run;
    await new Promise(resolve => setImmediate(resolve));
    console.log(JSON.stringify({ events, before }));
  `;
  const result = await promisify(execFile)(process.execPath,
    ["--import", "tsx", "--input-type=module", "-e", program],
    { cwd: process.cwd(), env: { ...process.env, HOME: root }, timeout: HOLD_MS * 10 });
  expect(JSON.parse(result.stdout.trim())).toEqual({ events: [], before: 2 });
});

it("T-WIRED overlaps both namespaces through appendCritical", async () => {
  const { log } = await productionFixture();
  const original = fs.open;
  const active = new Map<string, number>(); const maximum = new Map<string, number>();
  vi.spyOn(fs, "open").mockImplementation((async (...args: any[]) => {
    const path = String(args[0]);
    const ns = [AUDIT_NAMESPACE, AUDIT_CHECKPOINT_NAMESPACE].find(n => path.includes(`/${n}/`) &&
      (path.includes("/entry-") || path.includes("/audit-checkpoint-")));
    const handle = await (original as any)(...args);
    if (ns) {
      active.set(ns, (active.get(ns) ?? 0) + 1);
      maximum.set(ns, Math.max(maximum.get(ns) ?? 0, active.get(ns)!));
      const close = handle.close.bind(handle);
      handle.close = async () => { try { return await close(); } finally { active.set(ns, active.get(ns)! - 1); } };
    }
    return handle;
  }) as any); syncBuiltinESMExports();
  await log.appendCritical(measureEntry(POPULATION));
  for (const ns of [AUDIT_NAMESPACE, AUDIT_CHECKPOINT_NAMESPACE]) {
    expect(maximum.get(ns)).toBeGreaterThan(1);
    expect(maximum.get(ns)).toBeLessThanOrEqual(P);
    expect(active.get(ns)).toBe(0);
  }
});
