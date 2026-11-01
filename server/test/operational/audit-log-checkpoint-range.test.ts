import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import fs, { mkdtemp, rm } from "node:fs/promises";
import { syncBuiltinESMExports } from "node:module";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { AuditLog, writeAuditStoreSplitBoundary, deriveAuditStoreSplitBoundaryMacKey } from "../../src/operational/audit-log.js";
import { MemoryStorage } from "../../src/storage/memory.js";
import { FilesystemStorage } from "../../src/storage/filesystem.js";
import { computeAuditRoot } from "../../src/audit/chain.js";
import { countedStorage, MEASURE_CONFIG, MEASURE_MASTER_KEY, measureEntry, prepopulateAudit } from "../../scripts/measure-audit-append.js";

let root: string;
beforeEach(async () => { root = await mkdtemp(join(tmpdir(), "checkpoint-range-")); vi.stubEnv("HOME", root); });
afterEach(async () => { vi.restoreAllMocks(); syncBuiltinESMExports(); vi.unstubAllEnvs(); await rm(root, { recursive: true, force: true }); });

const encode = (value: unknown) => new TextEncoder().encode(JSON.stringify(value));
const decode = (value: Uint8Array) => JSON.parse(new TextDecoder().decode(value));
const checkpointKey = (sequence: number) => `audit-checkpoint-${String(sequence).padStart(20, "0")}`;

describe("complete persisted checkpoint ranges", () => {
  it("shares one audit listing and reads every checkpoint among a thousand", async () => {
    const population = 1_000; // A long checkpoint namespace exposes any skipped record.
    const path = join(root, "state");
    await prepopulateAudit(path, population);
    const raw = new FilesystemStorage(path);
    const counted = countedStorage(raw);
    const reads = vi.spyOn(raw, "read");
    const log = new AuditLog(counted.storage, MEASURE_MASTER_KEY, { ...MEASURE_CONFIG, checkpointInterval: 1 });
    await log.query({ limit: 1 });
    const entries = await raw.listKeys("_audit");
    for (const key of entries) {
      const envelope = decode((await raw.read("_audit", key))!);
      await raw.write("_audit_checkpoints", checkpointKey(envelope.sequence), encode({
        schema_version: 1, checkpoint_kind: "audit-checkpoint", checkpoint_sequence: envelope.sequence,
        from_sequence: envelope.sequence, previous_checkpoint_sequence: envelope.sequence - 1,
        root_hash: computeAuditRoot([envelope.entry_hash]), signed_at: envelope.timestamp,
        signer_kid: null, signature: null, signature_algorithm: null,
        payload_encoding: "domain-separated-canonical-json-v1", unsigned: true,
      }));
    }
    counted.reset(); reads.mockClear();
    await log.appendCritical(measureEntry(population));
    expect(counted.calls.get("list:_audit") ?? 0).toBe(0);
    expect(counted.calls.get("listKeys:_audit")).toBe(1);
    expect(counted.calls.get("listKeys:_audit_checkpoints")).toBe(1);
    expect(reads.mock.calls.filter(([namespace, key]) => namespace === "_audit_checkpoints" && key.startsWith("audit-checkpoint-"))).toHaveLength(population);
    const checkpoint = decode((await raw.read("_audit_checkpoints", checkpointKey(population + 1)))!);
    expect(checkpoint.previous_checkpoint_sequence).toBe(population);
  });

  it("preserves refusal on EIO at the oldest unsealed checkpoint", async () => {
    const storage = new FilesystemStorage(join(root, "old-record"));
    const log = new AuditLog(storage, MEASURE_MASTER_KEY, { ...MEASURE_CONFIG, checkpointInterval: 1 });
    // Three genuine checkpoints place the failure strictly behind a valid tail.
    for (let index = 0; index < 3; index++) await log.appendCritical(measureEntry(index));
    const records = await storage.list("_audit_checkpoints", "audit-checkpoint-");
    expect(records).toHaveLength(3);
    const read = storage.read.bind(storage);
    const fault = Object.assign(new Error("injected unsealed checkpoint EIO"), { code: "EIO" });
    const open = fs.open;
    vi.spyOn(fs, "open").mockImplementation((async (...args: any[]) => {
      const handle = await (open as any)(...args);
      if (String(args[0]) === join(root, "old-record", "_audit_checkpoints", `${records[0]!.key}.enc`)) {
        handle.readFile = async () => { throw fault; };
      }
      return handle;
    }) as any);
    syncBuiltinESMExports();
    await expect(log.appendCritical(measureEntry(3))).rejects.toThrow(fault);
    expect(await read("_audit_checkpoints", checkpointKey(4))).toBeNull();
  });

  for (const shape of ["gap", "identical", "different", "out-of-range"] as const) {
    it(`refuses ${shape} coverage without signing or clearing pending hashes`, async () => {
      const storage = new MemoryStorage();
      const signer = vi.fn(async () => null);
      const events: any[] = [];
      const log = new AuditLog(storage, MEASURE_MASTER_KEY, { ...MEASURE_CONFIG, checkpointInterval: 4,
        checkpointSigner: signer, integrityAnomalySubscribers: [(event) => { events.push(event); }] });
      for (let index = 0; index < 3; index++) await log.appendCritical(measureEntry(index));
      const keys = await storage.listKeys("_audit");
      const source = keys[1]!;
      const bytes = (await storage.read("_audit", source))!;
      if (shape === "gap") await storage.delete("_audit", source);
      else {
        // The out-of-range name is the job-851 witness: only a full body pass
        // can see this copy's in-range envelope sequence. Range-first must fail.
        const copyKey = shape === "out-of-range"
          ? `entry-${String(900).padStart(20, "0")}-copy` : `${source}-copy`;
        const copy = shape === "different" ? encode({ ...decode(bytes), entry_hash: "a".repeat(64) }) : bytes;
        await storage.write("_audit", copyKey, copy);
      }
      const pending = (log as any).hashesSinceCheckpoint.length;
      const diagnostic = vi.spyOn(console, "error").mockImplementation(() => {});
      await log.appendCritical(measureEntry(3));
      const reason = shape === "gap" ? "gap" : "duplicate";
      expect(signer).not.toHaveBeenCalled();
      expect(await storage.listKeys("_audit_checkpoints", "audit-checkpoint-")).toEqual([]);
      expect((log as any).hashesSinceCheckpoint).toHaveLength(pending + 1);
      expect(diagnostic).toHaveBeenCalledWith(expect.stringContaining(reason));
      expect(events).toEqual([]);
    });
  }

  it("accepts filename/envelope disagreement through the full body pass", async () => {
    const storage = new MemoryStorage();
    const writer = new AuditLog(storage, MEASURE_MASTER_KEY, MEASURE_CONFIG);
    for (let index = 0; index < 3; index++) await writer.appendCritical(measureEntry(index));
    const keys = await storage.listKeys("_audit");
    const mismatched = `entry-${String(1).padStart(20, "0")}-z`;
    await storage.write("_audit", mismatched, (await storage.read("_audit", keys[1]!))!);
    await storage.delete("_audit", keys[1]!);
    const counted = vi.spyOn(storage, "listKeys");
    const reader = new AuditLog(storage, MEASURE_MASTER_KEY, { ...MEASURE_CONFIG, checkpointInterval: 1 });
    expect((await reader.query({ limit: 10 })).integrity_findings).toEqual([]);
    counted.mockClear();
    await reader.appendCritical(measureEntry(3));
    expect(counted.mock.calls.filter(([namespace]) => namespace === "_audit")).toHaveLength(1);
    const checkpoint = decode((await storage.read("_audit_checkpoints", checkpointKey(4)))!);
    expect(checkpoint).toMatchObject({ from_sequence: 1, checkpoint_sequence: 4 });
    expect((await new AuditLog(storage, MEASURE_MASTER_KEY, MEASURE_CONFIG).query({ limit: 10 })).integrity_findings).toEqual([]);
  });
});

function gate() { let release!: () => void; const wait = new Promise<void>((resolve) => { release = resolve; }); return { wait, release }; }
const delay = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));
async function checkpointSetup(deadline = 500) {
  // Half a second leaves ample filesystem time while making fault schedules fast.
  const path = join(root, "state"); await prepopulateAudit(path, 3);
  const raw = new FilesystemStorage(path);
  const log = new AuditLog(raw, MEASURE_MASTER_KEY, { ...MEASURE_CONFIG, checkpointInterval: 1, writeLockHoldDeadlineMs: deadline });
  await log.query({ limit: 1 });
  return { path, raw, log };
}
async function anchored(raw: FilesystemStorage, sequence: number) {
  const anchor = decode((await raw.read("_audit_checkpoints", "__head_anchor"))!);
  expect(anchor.data.highest_sequence).toBe(sequence);
  const tailKey = (await raw.list("_audit")).map((meta) => meta.key).find((key) => key.startsWith(`entry-${String(sequence).padStart(20, "0")}-`))!;
  expect(decode((await raw.read("_audit", tailKey))!).entry_hash).toBe(anchor.data.head_hash);
}

for (const namespace of ["_audit", "_audit_checkpoints"]) {
  it(`does not stat readable ${namespace} bodies during checkpoint collection`, async () => {
    const { raw, path, log } = await checkpointSetup();
    await log.appendCritical(measureEntry(3));
    const key = (await raw.list(namespace, namespace === "_audit" ? "entry-" : "audit-checkpoint-"))[0]!.key;
    const original = fs.stat;
    let hits = 0;
    vi.spyOn(fs, "stat").mockImplementation((async (...args: any[]) => {
      if (String(args[0]) === join(path, namespace, `${key}.enc`)) {
        hits++; throw Object.assign(new Error("readable record metadata EIO"), { code: "EIO" });
      }
      return (original as any)(...args);
    }) as any); syncBuiltinESMExports();
    await log.appendCritical(measureEntry(4));
    expect(await raw.read("_audit_checkpoints", checkpointKey(5))).not.toBeNull();
    expect(hits).toBe(0);
  });
}

it("shares D across 0.6D entry/anchor and 0.6D collection, rejecting before checkpoint persistence", async () => {
  const deadline = 500; // Two phases of 300 ms each fit separately, but exceed the shared 500 ms hold.
  const { raw, log } = await checkpointSetup(deadline);
  const anchor = (log as any).writeHeadAnchor.bind(log);
  vi.spyOn(log as any, "writeHeadAnchor").mockImplementation(async (...args) => { await anchor(...args); await delay(deadline * 0.6); });
  const collect = (log as any).collectPersistedEntryHashes.bind(log);
  const settled = gate();
  vi.spyOn(log as any, "collectPersistedEntryHashes").mockImplementation(async (...args) => {
    try { await delay(deadline * 0.6); return await collect(...args); } finally { settled.release(); }
  });
  vi.spyOn(console, "error").mockImplementation(() => {});
  const start = performance.now();
  await expect(log.appendCritical(measureEntry(3))).rejects.toMatchObject({ name: "AuditLockHoldDeadlineError" });
  expect(performance.now() - start).toBeLessThan(deadline * 1.2);
  await anchored(raw, 4);
  await settled.wait; await new Promise((resolve) => setImmediate(resolve));
  expect(await raw.read("_audit_checkpoints", checkpointKey(4))).toBeNull();
  expect((log as any).criticalAppendsSinceCheckpoint).toBe(1);
});

it("counts a late-landing checkpoint after settlement and never rewrites that sequence on retry", async () => {
  const deadline = 500; // The same 0.6D + 0.6D schedule, with expiry during persistence.
  const { raw, log } = await checkpointSetup(deadline);
  const anchor = (log as any).writeHeadAnchor.bind(log);
  vi.spyOn(log as any, "writeHeadAnchor").mockImplementationOnce(async (...args) => {
    await anchor(...args); await delay(deadline * 0.6);
  });
  const entered = gate(); const settled = gate();
  const write = raw.write.bind(raw); const recordWrites: string[] = [];
  vi.spyOn(raw, "write").mockImplementation(async (ns, key, bytes) => {
    if (ns === "_audit_checkpoints" && key.startsWith("audit-checkpoint-")) {
      recordWrites.push(key);
      if (key === checkpointKey(4)) {
        entered.release(); await delay(deadline * 0.6);
        try { await write(ns, key, bytes); } finally { settled.release(); }
        return;
      }
    }
    await write(ns, key, bytes);
  });
  vi.spyOn(console, "error").mockImplementation(() => {});
  const append = log.appendCritical(measureEntry(3));
  const rejected = expect(append).rejects.toMatchObject({ name: "AuditLockHoldDeadlineError" });
  try {
    await entered.wait; await rejected;
    await anchored(raw, 4);
    expect(await raw.read("_audit_checkpoints", checkpointKey(4))).toBeNull();
  } finally { await settled.wait; }
  await new Promise((resolve) => setImmediate(resolve));
  expect(await raw.read("_audit_checkpoints", checkpointKey(4))).not.toBeNull();
  expect((log as any).criticalAppendsSinceCheckpoint).toBe(1);
  await log.appendCritical(measureEntry(4));
  expect(recordWrites).toEqual([checkpointKey(4), checkpointKey(5)]);
  expect(decode((await raw.read("_audit_checkpoints", checkpointKey(5)))!).previous_checkpoint_sequence).toBe(4);
});

for (const lateCleanup of [false, true]) {
  it(`gives the successor ownership after abandoned collection, late cleanup=${lateCleanup}`, async () => {
    const { raw, log } = await checkpointSetup();
    const abandoned = gate(); const firstEntered = gate(); const firstSettled = gate();
    const successor = gate(); const successorEntered = gate();
    const collect = (log as any).collectPersistedEntryHashes.bind(log);
    let flights = 0;
    vi.spyOn(log as any, "collectPersistedEntryHashes").mockImplementation(async (...args) => {
      if (++flights === 1) {
        firstEntered.release(); await abandoned.wait;
        try { return await collect(...args); } finally { firstSettled.release(); }
      }
      successorEntered.release();
      if (lateCleanup) await successor.wait;
      return collect(...args);
    });
    vi.spyOn(console, "error").mockImplementation(() => {});
    const write = vi.spyOn(raw, "write");
    const append = log.appendCritical(measureEntry(3));
    const rejected = expect(append).rejects.toMatchObject({ name: "AuditLockHoldDeadlineError" });
    let next: Promise<void> | undefined;
    try {
      await firstEntered.wait; await rejected;
      expect((log as any).checkpointInFlight).toBe(false);
      next = log.appendCritical(measureEntry(4));
      if (lateCleanup) {
        await successorEntered.wait;
        expect((log as any).checkpointInFlight).toBe(true);
        abandoned.release(); await firstSettled.wait;
        await new Promise((resolve) => setImmediate(resolve));
        expect((log as any).checkpointInFlight).toBe(true);
        successor.release();
      }
      await next;
      expect(write.mock.calls.filter(([ns, key]) => ns === "_audit_checkpoints" && key.startsWith("audit-checkpoint-"))).toHaveLength(1);
      expect(await raw.read("_audit_checkpoints", checkpointKey(5))).not.toBeNull();
    } finally {
      abandoned.release(); successor.release(); await firstSettled.wait;
      await next?.catch(() => {}); await new Promise((resolve) => setImmediate(resolve));
    }
  });
}

it("keeps the base standalone checkpoint own-deadline retry behavior", async () => {
  const { raw, log } = await checkpointSetup();
  const collect = (log as any).collectPersistedEntryHashes.bind(log);
  const hold = gate(); const settled = gate();
  vi.spyOn(log as any, "collectPersistedEntryHashes").mockImplementationOnce(async (...args) => {
    await hold.wait; try { return await collect(...args); } finally { settled.release(); }
  });
  vi.spyOn(console, "error").mockImplementation(() => {});
  try {
    await expect(log.flush()).rejects.toMatchObject({ name: "AuditLockHoldDeadlineError" });
    expect((log as any).checkpointInFlight).toBe(false);
    await log.flush();
    expect(await raw.read("_audit_checkpoints", checkpointKey(3))).not.toBeNull();
  } finally { hold.release(); await settled.wait; await new Promise((resolve) => setImmediate(resolve)); }
});

it("does not issue checkpoint persistence after a signer outlives the hold", async () => {
  const { raw, log } = await checkpointSetup();
  const hold = gate(); const entered = gate(); const settled = gate();
  (log as any).checkpointSigner = async () => {
    entered.release(); await hold.wait; settled.release(); return null;
  };
  vi.spyOn(console, "error").mockImplementation(() => {});
  const write = vi.spyOn(raw, "write");
  const append = log.appendCritical(measureEntry(3));
  const rejected = expect(append).rejects.toMatchObject({ name: "AuditLockHoldDeadlineError" });
  try { await entered.wait; await rejected; await anchored(raw, 4); }
  finally { hold.release(); await settled.wait; await new Promise((resolve) => setImmediate(resolve)); }
  expect(write.mock.calls.filter(([ns, key]) => ns === "_audit_checkpoints" && key.startsWith("audit-checkpoint-"))).toEqual([]);
  expect(await raw.read("_audit_checkpoints", checkpointKey(4))).toBeNull();
});

for (const fault of [false, true]) {
  it(`reads older unsealed bodies even when another writer covered the range, EIO=${fault}`, async () => {
    const { raw, log: a } = await checkpointSetup();
    const b = new AuditLog(raw, MEASURE_MASTER_KEY, MEASURE_CONFIG);
    await b.query({ limit: 1 }); await b.flush();
    const oldest = ((await raw.list("_audit")).map((meta) => meta.key))[0]!;
    const read = raw.read.bind(raw); const error = Object.assign(new Error("covered-range body EIO"), { code: "EIO" });
    const reads = vi.spyOn(raw, "read").mockImplementation(async (ns, key) => {
      if (fault && ns === "_audit" && key === oldest) throw error;
      return read(ns, key);
    });
    const writes = vi.spyOn(raw, "write");
    if (fault) await expect(a.flush()).rejects.toBe(error);
    else await a.flush();
    expect(reads.mock.calls).toContainEqual(["_audit", oldest]);
    expect(writes.mock.calls.filter(([ns, key]) => ns === "_audit_checkpoints" && key.startsWith("audit-checkpoint-"))).toEqual([]);
  });
}

it("latches incomplete range stderr and reports recovery without signing-control events", async () => {
  const raw = new MemoryStorage(); const events: unknown[] = [];
  const log = new AuditLog(raw, MEASURE_MASTER_KEY, { ...MEASURE_CONFIG, checkpointInterval: 4,
    integrityAnomalySubscribers: [(event) => { events.push(event); }] });
  for (let i = 0; i < 3; i++) await log.appendCritical(measureEntry(i));
  const key = ((await raw.list("_audit")).map((meta) => meta.key))[1]!; const bytes = (await raw.read("_audit", key))!;
  await raw.delete("_audit", key);
  const diagnostic = vi.spyOn(console, "error").mockImplementation(() => {});
  const writes = vi.spyOn(raw, "write");
  for (let i = 0; i < 4; i++) await log.appendCritical(measureEntry(i));
  expect(diagnostic.mock.calls.filter(([line]) => String(line).includes("AUDIT-CHECKPOINT-RANGE"))).toEqual([
    [expect.stringContaining("incomplete (gap")],
  ]);
  expect(events).toEqual([]);
  expect((log as any).integrityFindings).toEqual([]);
  expect(writes.mock.calls.filter(([ns, key]) => ns !== "_audit" && key !== "__head_anchor" && key !== "audit-head-anchor-established-v1")).toEqual([]);
  await raw.write("_audit", key, bytes); await log.appendCritical(measureEntry(7));
  expect(diagnostic.mock.calls.filter(([line]) => String(line).includes("AUDIT-CHECKPOINT-RANGE"))).toEqual([
    [expect.stringContaining("incomplete (gap")], ["[audit-log] AUDIT-CHECKPOINT-RANGE recovered"],
  ]);
});

it("uses a total order for collation ties across memory insertion orders and filesystem", async () => {
  const source = new MemoryStorage(); const generator = new AuditLog(source, MEASURE_MASTER_KEY, MEASURE_CONFIG);
  for (let i = 0; i < 3; i++) await generator.appendCritical(measureEntry(i));
  const canonical = (await source.list("_audit")).map((meta) => meta.key);
  const first = (await source.read("_audit", canonical[0]!))!;
  const second = (await source.read("_audit", canonical[1]!))!;
  const third = (await source.read("_audit", canonical[2]!))!;
  const prefix = `entry-${String(9).padStart(20, "0")}-`;
  // Soft hyphen is collation-ignorable and round-trips through the byte-sized filesystem codec.
  const ties = [`${prefix}z\u00ad`, `${prefix}z`];
  expect(ties[0]!.localeCompare(ties[1]!)).toBe(0);
  const outcomes: number[] = [];
  for (const [index, storage] of [new MemoryStorage(), new MemoryStorage(), new FilesystemStorage(join(root, "ties"))].entries()) {
    await storage.write("_audit", canonical[0]!, first);
    const log = new AuditLog(storage, MEASURE_MASTER_KEY, MEASURE_CONFIG);
    await (log as any).writeHeadAnchor(1, decode(first).entry_hash);
    await log.query({ limit: 1 });
    for (const i of index === 1 ? [1, 0] : [0, 1]) await storage.write("_audit", ties[i]!, i === 0 ? third : second);
    const discovered = await (log as any).withAuditWriteLock((signal: unknown) => (log as any).readLatestPersistedChainState(signal));
    // The base returned the chain state directly; the candidate also returns its held keys.
    expect((discovered.latest ?? discovered).nextSequence).toBe(4);
    await log.appendCritical(measureEntry(3)); outcomes.push(log.currentInMemorySequence());
  }
  expect(outcomes).toEqual([4, 4, 4]);
});

it("accepts both records sharing a predecessor when the successor persists before an abandoned write", async () => {
  const { raw, log } = await checkpointSetup();
  const write = raw.write.bind(raw); const hold = gate(); const entered = gate(); const settled = gate();
  vi.spyOn(raw, "write").mockImplementation(async (ns, key, bytes) => {
    if (ns === "_audit_checkpoints" && key === checkpointKey(4)) {
      entered.release(); await hold.wait;
      try { await write(ns, key, bytes); } finally { settled.release(); }
      return;
    }
    await write(ns, key, bytes);
  });
  const append = log.appendCritical(measureEntry(3));
  const rejected = expect(append).rejects.toMatchObject({ name: "AuditLockHoldDeadlineError" });
  try {
    await entered.wait; await rejected;
    await log.appendCritical(measureEntry(4));
    expect(await raw.read("_audit_checkpoints", checkpointKey(4))).toBeNull();
  } finally { hold.release(); await settled.wait; await new Promise((resolve) => setImmediate(resolve)); }
  const records = await Promise.all([4, 5].map(async (seq) => decode((await raw.read("_audit_checkpoints", checkpointKey(seq)))!)));
  expect(records.map((record) => record.previous_checkpoint_sequence)).toEqual([0, 0]);
  expect((await new AuditLog(raw, MEASURE_MASTER_KEY, MEASURE_CONFIG).query({ limit: 1 })).integrity_findings).toEqual([]);
});

async function sealFixture(raw: FilesystemStorage, path: string, log: AuditLog) {
  const head = await log.getChainHead();
  await writeAuditStoreSplitBoundary(path, deriveAuditStoreSplitBoundaryMacKey(MEASURE_MASTER_KEY), {
    sealed_tip_sequence: head.sequence, sealed_base_sequence: 1,
    sealed_tip_entry_hash: head.entry_hash, daemon_namespace: "_audit-daemon",
  });
}

it("refuses sealed checkpoint non-permission EIO on the real checkpoint append path", async () => {
  const { raw, path, log: original } = await checkpointSetup();
  await original.flush(); await sealFixture(raw, path, original);
  const log = new AuditLog(raw, MEASURE_MASTER_KEY, { ...MEASURE_CONFIG, checkpointInterval: 1, consultSplitBoundary: true });
  await log.query({ limit: 1 });
  const read = raw.read.bind(raw); const error = Object.assign(new Error("sealed checkpoint EIO"), { code: "EIO" });
  vi.spyOn(raw, "read").mockImplementation(async (ns, key) => {
    if (ns === "_audit_checkpoints" && key === checkpointKey(3)) throw error;
    return read(ns, key);
  });
  await expect(log.appendCritical(measureEntry(3))).rejects.toBe(error);
  expect(await read("_audit_checkpoints", checkpointKey(4))).toBeNull();
  await anchored(raw, 4);
});

it("continues after a suffix-marker write failure and retries on the next append", async () => {
  const { raw, path, log: original } = await checkpointSetup();
  await sealFixture(raw, path, original);
  const log = new AuditLog(raw, MEASURE_MASTER_KEY, { ...MEASURE_CONFIG, consultSplitBoundary: true });
  await log.query({ limit: 1 });
  const write = raw.write.bind(raw); let failedKey = "";
  const writes = vi.spyOn(raw, "write").mockImplementation(async (ns, key, bytes) => {
    if (ns === "_meta" && key === "audit-post-split-suffix-established-v1" && !failedKey) { failedKey = key; throw new Error("suffix marker fault"); }
    await write(ns, key, bytes);
  });
  await log.appendCritical(measureEntry(3));
  expect(failedKey).not.toBe(""); expect((log as any).postSplitSuffixMarkerEnsured).toBe(false);
  await anchored(raw, 4);
  await log.appendCritical(measureEntry(4));
  expect((log as any).postSplitSuffixMarkerEnsured).toBe(true);
  expect(writes.mock.calls.filter(([ns, key]) => ns === "_meta" && key === failedKey)).toHaveLength(2);
  expect(await raw.read("_meta", failedKey)).not.toBeNull();
});
