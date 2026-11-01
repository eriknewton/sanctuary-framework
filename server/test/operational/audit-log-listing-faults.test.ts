import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import fs from "node:fs/promises";
import { syncBuiltinESMExports } from "node:module";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { AuditLog, AUDIT_RECOUNT_DIAGNOSTIC_PREFIX, AUDIT_ROTATION_MARGIN_FRACTION, AUDIT_EAGER_SENTINEL_INTERVAL_MS } from "../../src/operational/audit-log.js";
import { FilesystemStorage } from "../../src/storage/filesystem.js";
import { MemoryStorage } from "../../src/storage/memory.js";
import { countedStorage, MEASURE_CONFIG, MEASURE_MASTER_KEY, measureEntry, prepopulateAudit } from "../../scripts/measure-audit-append.js";
import { encrypt } from "../../src/core/encryption.js";
import { derivePurposeKey } from "../../src/core/key-derivation.js";

let root: string;
beforeEach(async () => { root = await fs.mkdtemp(join(tmpdir(), "audit-faults-")); vi.stubEnv("HOME", root); });
afterEach(async () => { vi.restoreAllMocks(); syncBuiltinESMExports(); vi.unstubAllEnvs(); await fs.rm(root, { recursive: true, force: true }); });
function gate() { let release!: () => void; const wait = new Promise<void>((resolve) => { release = resolve; }); return { wait, release }; }
async function setup(cap = Number.MAX_SAFE_INTEGER) {
  const path = join(root, "state"); await prepopulateAudit(path, 3);
  const raw = new FilesystemStorage(path); const counted = countedStorage(raw);
  const log = new AuditLog(counted.storage, MEASURE_MASTER_KEY, { ...MEASURE_CONFIG, maxEntries: cap });
  await log.query({ limit: 1 }); counted.reset(); return { raw, counted, log, path };
}

describe("listing and accounting fault schedules", () => {
  it("discards a readdir that completes after the hold deadline without allocating a sequence", async () => {
    const { raw, path } = await setup();
    // A short injected hold bound applies only after the cold load has finished.
    const log = new AuditLog(raw, MEASURE_MASTER_KEY, { ...MEASURE_CONFIG, writeLockHoldDeadlineMs: 100 });
    await log.query({ limit: 1 });
    // Complete the once-per-instance stale-temp sweep before delaying the
    // in-lock discovery readdir, which is the fault schedule under test.
    await (log as any).withAuditWriteLock(async () => {});
    const hold = gate(); const entered = gate(); const finished = gate();
    const original = fs.readdir;
    vi.spyOn(fs, "readdir").mockImplementation((async (...args: any[]) => {
      if (String(args[0]) === join(path, "_audit")) {
        entered.release(); await hold.wait;
        try { return await (original as any)(...args); } finally { finished.release(); }
      }
      return (original as any)(...args);
    }) as any);
    syncBuiltinESMExports();
    try {
      const append = log.appendCritical(measureEntry(3));
      const rejected = expect(append).rejects.toMatchObject({ name: "AuditLockHoldDeadlineError" });
      await entered.wait; await rejected;
      expect(log.currentInMemorySequence()).toBe(3);
    } finally { hold.release(); await finished.wait; }
    // Drain the detached continuation before inspecting or removing the fixture.
    await new Promise((resolve) => setImmediate(resolve));
    expect(await raw.listKeys("_audit")).toHaveLength(3);
    expect(log.currentInMemorySequence()).toBe(3);
  });

  it("invalidates the hint before an anchor error and discovers the durable entry next time", async () => {
    const { raw, counted, log } = await setup();
    const write = raw.writeDurable.bind(raw); let fail = true;
    vi.spyOn(raw, "writeDurable").mockImplementation(async (namespace, key, data) => {
      if (key === "__head_anchor" && fail) { fail = false; throw new Error("anchor fault"); }
      await write(namespace, key, data);
    });
    const verifiedAt = (log as any).lastFullVerifyAtMs;
    await expect(log.appendCritical(measureEntry(3))).rejects.toThrow("anchor fault");
    expect((log as any).expectedStoreFingerprint).toBeNull();
    expect((log as any).lastFullVerifyAtMs).toBe(verifiedAt);
    counted.reset(); await log.appendCritical(measureEntry(4));
    expect(log.currentInMemorySequence()).toBe(5);
    expect(counted.calls.get("listKeys:_audit")).toBe(1);
  });

  it("keeps provenance unknown after a partial prune and recounts on the next append", async () => {
    const { raw, counted, log } = await setup(3);
    const remove = raw.delete.bind(raw); let deletes = 0;
    vi.spyOn(raw, "delete").mockImplementation(async (...args) => {
      if (++deletes === 2) throw new Error("second delete fails after sized listing");
      return remove(...args);
    });
    await log.appendCritical(measureEntry(3));
    expect((log as any).bytesProvenance).toBe("unknown");
    counted.reset(); await log.appendCritical(measureEntry(4));
    expect(counted.calls.get("list:_audit")).toBe(1);
    const metas = await raw.list("_audit");
    expect((log as any).retainedBytesEstimate).toBe(metas.reduce((sum, meta) => sum + meta.size_bytes, 0));
    expect((log as any).bytesProvenance).toBe("seeded");
  });

  it("reports a recount deadline immediately and ignores abandoned recount cleanup", async () => {
    const { raw } = await setup();
    const log = new AuditLog(raw, MEASURE_MASTER_KEY, {
      ...MEASURE_CONFIG, maxEntries: 5, // Three initial entries plus two appends fit without prune I/O.
      writeLockHoldDeadlineMs: 100, // Short bound isolates the delayed recount after a cold load.
    });
    await log.query({ limit: 1 });
    // Force the recount under test without spending its short hold on pruning.
    (log as any).bytesProvenance = "unknown";
    const hold = gate(); const entered = gate(); const finished = gate();
    const list = raw.list.bind(raw); let delay = true;
    vi.spyOn(raw, "list").mockImplementation(async (...args) => {
      if (args[0] === "_audit" && delay) {
        delay = false; entered.release(); await hold.wait;
        try { return await list(...args); } finally { finished.release(); }
      }
      return list(...args);
    });
    const diagnostic = vi.spyOn(console, "error").mockImplementation(() => {});
    try {
      const append = log.appendCritical(measureEntry(3));
      await entered.wait; await append;
      expect((log as any).bytesProvenance).toBe("unknown");
      expect(recountLines(diagnostic)).toEqual([[`${AUDIT_RECOUNT_DIAGNOSTIC_PREFIX} failed`]]);
      // The successor recovers before the abandoned listing returns.
      await log.appendCritical(measureEntry(4));
      expect((log as any).bytesProvenance).toBe("seeded");
      expect(recountLines(diagnostic)).toEqual([
        [`${AUDIT_RECOUNT_DIAGNOSTIC_PREFIX} failed`],
        [`${AUDIT_RECOUNT_DIAGNOSTIC_PREFIX} recovered`],
      ]);
    } finally { hold.release(); await finished.wait; }
    await new Promise((resolve) => setImmediate(resolve));
    expect((log as any).bytesProvenance).toBe("seeded");
    expect(recountLines(diagnostic)).toHaveLength(2);
    expect((log as any).recountFaultLatched).toBe(false);
  });

  it("does not publish an older load seed across an own append", async () => {
    const { raw, log } = await setup();
    const hold = gate(); const entered = gate(); const read = raw.read.bind(raw); let pause = true;
    vi.spyOn(raw, "read").mockImplementation(async (namespace, key) => {
      const value = await read(namespace, key);
      if (pause && namespace === "_audit") { pause = false; entered.release(); await hold.wait; }
      return value;
    });
    const load = (log as any).loadPersistedEntries();
    await entered.wait;
    try { await log.appendCritical(measureEntry(3)); } finally { hold.release(); }
    await load;
    expect((log as any).retainedCountExpected).toBe(4);
    expect((log as any).retentionGeneration).toBeGreaterThan(0);
  });

  it("does not subtract a false-returning delete or publish its seed", async () => {
    const { raw, counted, log } = await setup(3);
    const remove = vi.spyOn(raw, "delete").mockResolvedValueOnce(false);
    await log.appendCritical(measureEntry(3));
    expect((log as any).bytesProvenance).toBe("unknown");
    expect(await raw.list("_audit")).toHaveLength(4);
    remove.mockRestore(); counted.reset();
    await log.appendCritical(measureEntry(4));
    expect(counted.calls.get("list:_audit")).toBe(1);
    const survivors = await raw.list("_audit");
    expect((log as any).retainedBytesEstimate).toBe(survivors.reduce((sum, meta) => sum + meta.size_bytes, 0));
    expect((log as any).bytesProvenance).toBe("seeded");
  });

  for (const failure of ["finding", "listing", "body"] as const) {
    it(`preserves ${failure} evidence through continuous own appends without a clean pass`, async () => {
      const path = join(root, failure); await prepopulateAudit(path, 3);
      const raw = new FilesystemStorage(path);
      const log = new AuditLog(raw, MEASURE_MASTER_KEY, { ...MEASURE_CONFIG, integrityMode: "lenient" });
      await log.query({ limit: 1 });
      if (failure === "finding") {
        const first = (await raw.list("_audit"))[0]!.key;
        const envelope = JSON.parse(new TextDecoder().decode((await raw.read("_audit", first))!));
        envelope.entry_hash = "0".repeat(64); // A SHA-256 digest has 64 hexadecimal characters.
        await raw.write("_audit", first, new TextEncoder().encode(JSON.stringify(envelope)));
      } else {
        const method = failure === "listing" ? "list" : "read";
        vi.spyOn(raw, method).mockRejectedValueOnce(new Error(`injected ${failure} failure`));
      }
      await (log as any).loadPersistedEntries();
      const findings = structuredClone((log as any).integrityFindings);
      expect(findings.length).toBeGreaterThan(0);
      const verifiedAt = (log as any).lastFullVerifyAtMs;
      for (let index = 0; index < 3; index++) {
        await log.appendCritical(measureEntry(index));
        expect((log as any).expectedStoreFingerprint).toBeNull();
        expect((log as any).lastFullVerifyAtMs).toBe(verifiedAt);
        expect((log as any).integrityFindings).toEqual(findings);
      }
    });
  }

  it("marks a streaming load unknown and recounts before the next rotation decision", async () => {
    const { counted, log } = await setup();
    await log.streamVerifiedChain({ onEntry: () => {}, reset: () => {} });
    expect((log as any).bytesProvenance).toBe("unknown");
    counted.reset(); await log.appendCritical(measureEntry(3));
    expect(counted.calls.get("list:_audit")).toBe(1);
    expect(counted.calls.get("listKeys:_audit")).toBe(1);
  });

  it("counts legacy keys for rotation but never reads them in the tail walk", async () => {
    const storage = new MemoryStorage();
    const encryptionKey = derivePurposeKey(MEASURE_MASTER_KEY, "audit-log");
    const legacyKeys = ["1700000000000-0", "1700000000000-1"];
    for (const key of legacyKeys) {
      const entry = { ...measureEntry(0), timestamp: new Date().toISOString() };
      await storage.write("_audit", key, new TextEncoder().encode(JSON.stringify(encrypt(new TextEncoder().encode(JSON.stringify(entry)), encryptionKey))));
    }
    const log = new AuditLog(storage, MEASURE_MASTER_KEY, { ...MEASURE_CONFIG, maxEntries: 3 });
    await log.query({ limit: 10 });
    const reads = vi.spyOn(storage, "read"); const names = vi.spyOn(storage, "listKeys");
    await log.appendCritical(measureEntry(2));
    expect(reads.mock.calls.filter(([ns, key]) => ns === "_audit" && legacyKeys.includes(key))).toEqual([]);
    expect(await storage.list("_audit")).toHaveLength(3);
    await log.appendCritical(measureEntry(3));
    expect(await storage.list("_audit")).toHaveLength(2);
    expect(names.mock.calls.filter(([ns]) => ns === "_audit")).toHaveLength(2);
  });

  it("finds same-size mtime-preserving tamper after an own append and one sentinel interval", async () => {
    const { raw, log, path } = await setup();
    const key = (await raw.listKeys("_audit"))[0]!;
    const file = join(path, "_audit", `${key}.enc`); const before = await fs.stat(file);
    const rawBytes = await fs.readFile(file, "utf8"); const envelope = JSON.parse(rawBytes);
    envelope.entry_hash = (envelope.entry_hash[0] === "a" ? "b" : "a") + envelope.entry_hash.slice(1);
    await fs.writeFile(file, JSON.stringify(envelope)); await fs.utimes(file, before.atime, before.mtime);
    expect((await fs.stat(file)).size).toBe(before.size);
    let now = Date.now(); vi.spyOn(Date, "now").mockImplementation(() => now);
    const verifiedAt = (log as any).lastFullVerifyAtMs;
    for (let index = 0; index < 3; index++) {
      now += AUDIT_EAGER_SENTINEL_INTERVAL_MS;
      await log.appendCritical(measureEntry(index));
      expect((log as any).lastFullVerifyAtMs).toBe(verifiedAt);
      expect((log as any).expectedStoreFingerprint).toBeNull();
    }
    now += AUDIT_EAGER_SENTINEL_INTERVAL_MS;
    await expect(log.queryEager({ limit: 1 })).rejects.toMatchObject({ name: "AuditIntegrityError" });
    expect((await log.getIntegrityFindings()).some((finding) => finding.kind === "entry_hash_mismatch")).toBe(true);
  });
});

const decode = (value: Uint8Array) => JSON.parse(new TextDecoder().decode(value));
const encode = (value: unknown) => new TextEncoder().encode(JSON.stringify(value));
const eio = (message: string) => Object.assign(new Error(message), { code: "EIO" });
function injectFsFault(method: "stat" | "readFile" | "readdir", file: string) {
  let hits = 0;
  if (method === "readFile") {
    const originalOpen = fs.open;
    const spy = vi.spyOn(fs, "open").mockImplementation((async (...args: any[]) => {
      const handle = await (originalOpen as any)(...args);
      if (String(args[0]) === file) handle.readFile = async () => { hits++; throw eio("injected readFile EIO"); };
      return handle;
    }) as any);
    syncBuiltinESMExports();
    return { hits: () => hits, restore: () => { spy.mockRestore(); syncBuiltinESMExports(); } };
  }
  const original = fs[method];
  const spy = vi.spyOn(fs, method).mockImplementation((async (...args: any[]) => {
    if (String(args[0]) === file) { hits++; throw eio(`injected ${method} EIO`); }
    return (original as any)(...args);
  }) as any);
  syncBuiltinESMExports();
  return { hits: () => hits, restore: () => { spy.mockRestore(); syncBuiltinESMExports(); } };
}
async function assertTip(raw: FilesystemStorage, sequence: number) {
  const metas = await raw.listKeys("_audit");
  const entries = [];
  for (const key of metas) {
    if (key.endsWith("-dangling")) continue;
    const bytes = await raw.read("_audit", key);
    if (bytes) entries.push(decode(bytes));
  }
  const tail = entries.find((entry) => entry.sequence === sequence);
  const previous = entries.find((entry) => entry.sequence === sequence - 1);
  expect(tail.prev_hash).toBe(previous.entry_hash);
  expect(decode((await raw.read("_audit_checkpoints", "__head_anchor"))!))
    .toMatchObject({ data: { highest_sequence: sequence, head_hash: tail.entry_hash } });
}
function recountLines(spy: ReturnType<typeof vi.spyOn>) {
  return spy.mock.calls.filter(([line]: unknown[]) => String(line).startsWith(AUDIT_RECOUNT_DIAGNOSTIC_PREFIX));
}

describe("metadata observation contract on real files", () => {
  it("inverted arm A: admits the fourth entry under old-entry stat EIO, then the writing strict reader refuses", async () => {
    const { raw, path } = await setup();
    const interval = 1; // A positive one-millisecond byte-pass interval makes the eager detector due.
    const log = new AuditLog(raw, MEASURE_MASTER_KEY, { ...MEASURE_CONFIG, eagerBytePassIntervalMs: interval });
    await log.query({ limit: 1 });
    const oldest = (await raw.list("_audit"))[0]!.key;
    const fault = injectFsFault("stat", join(path, "_audit", `${oldest}.enc`));
    // On the base this exact await rejects with injected stat EIO, before allocation.
    await log.appendCritical(measureEntry(3));
    expect(log.currentInMemorySequence()).toBe(4);
    expect(fault.hits()).toBe(0);
    await assertTip(raw, 4);
    await new Promise((resolve) => setTimeout(resolve, interval * 2));
    await expect(log.runEagerReads(() => log.query({ limit: 1 }))).rejects.toMatchObject({ name: "AuditIntegrityError" });
    expect((await log.getIntegrityFindings()).map((finding) => finding.kind)).toContain("storage_unavailable");
    expect((await log.getAuditChainVerdict()).status).not.toBe("verified");
    await expect(log.appendCritical(measureEntry(4))).rejects.toMatchObject({ name: "AuditIntegrityError" });
    const reader = new AuditLog(raw, MEASURE_MASTER_KEY, MEASURE_CONFIG);
    await expect(reader.query({ limit: 1 })).rejects.toMatchObject({
      name: "AuditIntegrityError", findings: expect.arrayContaining([expect.objectContaining({ kind: "storage_unavailable" })]),
    });
    fault.restore();
    expect((await log.query({ limit: 1 })).integrity_findings).toEqual([]);
    await log.appendCritical(measureEntry(4));
    expect(log.currentInMemorySequence()).toBe(5);
  });

  it("discovers an unanchored foreign tail without stats, then makes one failing recount", async () => {
    const { raw, counted, log, path } = await setup();
    const bStorage = new FilesystemStorage(path);
    const b = new AuditLog(bStorage, MEASURE_MASTER_KEY, MEASURE_CONFIG);
    await b.query({ limit: 1 });
    const write = bStorage.writeDurable.bind(bStorage);
    vi.spyOn(bStorage, "writeDurable").mockImplementation(async (ns, key, bytes) => {
      if (key === "__head_anchor") throw eio("foreign anchor interrupted");
      await write(ns, key, bytes);
    });
    await expect(b.appendCritical(measureEntry(3))).rejects.toThrow("foreign anchor interrupted");
    const oldest = (await raw.listKeys("_audit"))[0]!;
    const fault = injectFsFault("stat", join(path, "_audit", `${oldest}.enc`));
    const discover = (log as any).freshenChainStateFromDisk.bind(log);
    const discovery = vi.spyOn(log as any, "freshenChainStateFromDisk").mockImplementation(async (...args) => {
      const result = await discover(...args); expect(fault.hits()).toBe(0); return result;
    });
    const diagnostic = vi.spyOn(console, "error").mockImplementation(() => {});
    counted.reset(); await log.appendCritical(measureEntry(4));
    expect(discovery).toHaveBeenCalledOnce();
    expect(log.currentInMemorySequence()).toBe(5);
    await assertTip(raw, 5);
    expect(counted.calls.get("list:_audit")).toBe(1);
    expect(fault.hits()).toBe(1);
    expect((log as any).bytesProvenance).toBe("unknown");
    expect(recountLines(diagnostic)).toHaveLength(1);
  });

  it("reports an old body EIO on eager read and refuses collection while the tail walk still succeeds", async () => {
    const { raw, log, path } = await setup();
    const oldest = (await raw.listKeys("_audit"))[0]!;
    injectFsFault("readFile", join(path, "_audit", `${oldest}.enc`));
    await log.appendCritical(measureEntry(3));
    await expect((log as any).writeCheckpointIfNeeded("body-fault")).rejects.toThrow("injected readFile EIO");
    (log as any).lastFullVerifyAtMs = 0;
    await expect(log.runEagerReads(() => log.query({ limit: 1 }))).rejects.toMatchObject({ name: "AuditIntegrityError" });
    expect((await log.getIntegrityFindings()).map((finding) => finding.kind)).toContain("entry_unreadable");
  });

  for (const bodyReadable of [true, false]) {
    it(`tail metadata EIO with body readable=${bodyReadable}`, async () => {
      const { raw, log, path } = await setup();
      const tail = (await raw.listKeys("_audit")).at(-1)!;
      const file = join(path, "_audit", `${tail}.enc`);
      const fault = injectFsFault("stat", file);
      if (!bodyReadable) injectFsFault("readFile", file);
      if (bodyReadable) { await log.appendCritical(measureEntry(3)); await assertTip(raw, 4); }
      else await expect(log.appendCritical(measureEntry(3))).rejects.toThrow("injected readFile EIO");
      expect(fault.hits()).toBe(0);
    });
  }

  it("latches recount failure through persistent growth and recovers without diagnostic side effects", async () => {
    const cap = 3; // Three seeded entries put the next append at a due prune.
    const waves = 4; // Repeated admissions prove the diagnostic is latched across retries.
    const { raw, counted, log, path } = await setup(cap);
    const oldest = (await raw.listKeys("_audit"))[0]!;
    const fault = injectFsFault("stat", join(path, "_audit", `${oldest}.enc`));
    const diagnostic = vi.spyOn(console, "error").mockImplementation(() => {});
    const notify = vi.spyOn(log as any, "notifySigningControlWriteFailure");
    const subscriber = vi.fn(); (log as any).integrityAnomalySubscribers.push(subscriber);
    const seed = vi.spyOn(log as any, "seedRetention");
    const mutations: string[] = [];
    for (const method of ["write", "writeDurable", "delete", "replaceIfEquals"] as const) {
      const original = (raw as any)[method].bind(raw);
      vi.spyOn(raw as any, method).mockImplementation(async (...args) => {
        mutations.push(`${method}:${args[0]}:${args[1]}`); return original(...args);
      });
    }
    const rotate = (log as any).maybeRotate.bind(log);
    vi.spyOn(log as any, "maybeRotate").mockImplementation(async (...args) => {
      const before = mutations.length;
      try { return await rotate(...args); }
      finally {
        // A failed recount has no control writes, incident-ring writes, or other mutations.
        if (fault.hits() > 0 && (log as any).bytesProvenance === "unknown") expect(mutations.length).toBe(before);
      }
    });
    for (let index = 0; index < waves; index++) await log.appendCritical(measureEntry(cap + index));
    expect(await raw.listKeys("_audit")).toHaveLength(cap + waves);
    expect(counted.calls.get("list:_audit")).toBe(waves);
    expect(recountLines(diagnostic)).toHaveLength(1);
    expect(notify).not.toHaveBeenCalled(); expect(subscriber).not.toHaveBeenCalled();
    expect((log as any).integrityFindings).toEqual([]); expect(seed).not.toHaveBeenCalled();
    expect(mutations.filter((operation) => operation.includes("signing"))).toEqual([]);
    expect((log as any).bytesProvenance).toBe("unknown");
    fault.restore();
    await log.appendCritical(measureEntry(cap + waves));
    const survivors = await raw.list("_audit");
    const margin = Math.max(1, Math.floor(cap * AUDIT_ROTATION_MARGIN_FRACTION));
    expect(survivors.length).toBeLessThanOrEqual(Math.max(1, cap - margin));
    expect(survivors.length).toBeGreaterThanOrEqual(1);
    expect((log as any).bytesProvenance).toBe("seeded");
    expect(recountLines(diagnostic)).toEqual([[`${AUDIT_RECOUNT_DIAGNOSTIC_PREFIX} failed`], [`${AUDIT_RECOUNT_DIAGNOSTIC_PREFIX} recovered`]]);
  });

  it("rejects a raw empty recount caused by a dangling name without seeding empty accounting", async () => {
    const { raw, log, path } = await setup(3);
    await fs.symlink(join(root, "missing"), join(path, "_audit", "entry-00000000000000000000-dangling.enc"));
    const before = (log as any).retainedBytesEstimate;
    const seed = vi.spyOn(log as any, "seedRetention");
    const diagnostic = vi.spyOn(console, "error").mockImplementation(() => {});
    await log.appendCritical(measureEntry(3));
    expect(await raw.list("_audit")).toEqual([]);
    expect(seed).not.toHaveBeenCalled();
    const tail = (await raw.listKeys("_audit")).filter((key) => key.startsWith("entry-00000000000000000004-"))[0]!;
    expect((log as any).retainedBytesEstimate).toBe(before + (await raw.read("_audit", tail))!.length);
    expect((log as any).bytesProvenance).toBe("unknown");
    expect(recountLines(diagnostic)).toHaveLength(1);
  });

  it("accepts a shorter raw recount after a foreign prefix prune between holds", async () => {
    const { raw, log, path } = await setup();
    const b = new AuditLog(new FilesystemStorage(path), MEASURE_MASTER_KEY, { ...MEASURE_CONFIG, maxEntries: 3 });
    await b.query({ limit: 1 });
    const rotate = (log as any).maybeRotate.bind(log);
    vi.spyOn(log as any, "maybeRotate").mockImplementationOnce(async (...args) => {
      await b.appendCritical(measureEntry(4));
      (log as any).bytesProvenance = "unknown";
      return rotate(...args);
    });
    const diagnostic = vi.spyOn(console, "error").mockImplementation(() => {});
    await log.appendCritical(measureEntry(3));
    const survivors = await raw.list("_audit");
    expect(survivors.length).toBeLessThan(4);
    expect((log as any).retainedCountExpected).toBe(survivors.length);
    expect((log as any).bytesProvenance).toBe("seeded");
    expect(recountLines(diagnostic)).toEqual([]);
  });

  it("reports nothing when metadata heals before an observing read", async () => {
    const { raw, log, path } = await setup();
    const oldest = (await raw.listKeys("_audit"))[0]!;
    const fault = injectFsFault("stat", join(path, "_audit", `${oldest}.enc`));
    await log.appendCritical(measureEntry(3));
    expect(fault.hits()).toBe(0); fault.restore();
    expect((await log.query({ limit: 1 })).integrity_findings).toEqual([]);
  });

  it("inverted arm G: dangling metadata cannot hide the foreign durable tail", async () => {
    const { raw, log, path } = await setup();
    const b = new AuditLog(new FilesystemStorage(path), MEASURE_MASTER_KEY, MEASURE_CONFIG);
    await b.appendCritical(measureEntry(3));
    await fs.symlink(join(root, "missing"), join(path, "_audit", "entry-00000000000000000000-dangling.enc"));
    const original = fs.stat;
    const stats = vi.spyOn(fs, "stat").mockImplementation(original); syncBuiltinESMExports();
    const discovery = (log as any).freshenChainStateFromDisk.bind(log);
    let discoveryStats = -1;
    vi.spyOn(log as any, "freshenChainStateFromDisk").mockImplementation(async (...args) => {
      const result = await discovery(...args);
      discoveryStats = stats.mock.calls.filter(([file]) => String(file).includes("/_audit/") && String(file).endsWith(".enc")).length;
      return result;
    });
    vi.spyOn(console, "error").mockImplementation(() => {});
    await log.appendCritical(measureEntry(4));
    // On the base the collapsed listing allocates sequence 4 from memory instead of 5.
    expect(log.currentInMemorySequence()).toBe(5);
    expect(discoveryStats).toBe(0);
    await assertTip(raw, 5);
  });

  it("uses the held checkpoint snapshot when audit readdir fails after the anchor", async () => {
    const { raw, path } = await setup();
    const log = new AuditLog(raw, MEASURE_MASTER_KEY, { ...MEASURE_CONFIG, checkpointInterval: 1 });
    await log.query({ limit: 1 });
    const write = raw.writeDurable.bind(raw);
    vi.spyOn(raw, "writeDurable").mockImplementation(async (...args) => {
      await write(...args);
      if (args[1] === "__head_anchor") injectFsFault("readdir", join(path, "_audit"));
    });
    await log.appendCritical(measureEntry(3));
    expect(await raw.read("_audit_checkpoints", "audit-checkpoint-00000000000000000004")).not.toBeNull();
    await expect(new AuditLog(raw, MEASURE_MASTER_KEY, MEASURE_CONFIG).query({ limit: 1 }))
      .rejects.toMatchObject({ name: "AuditIntegrityError", findings: expect.arrayContaining([expect.objectContaining({ kind: "storage_unavailable" })]) });
  });
});

it("skips an absent listed tail body and continues backward to the real tail", async () => {
  const { raw, log, path } = await setup();
  const b = new AuditLog(new FilesystemStorage(path), MEASURE_MASTER_KEY, MEASURE_CONFIG);
  await b.appendCritical(measureEntry(3));
  const vanishedKey = "entry-99999999999999999999-vanished";
  await raw.write("_audit", vanishedKey, encode({ malformed: true }));
  const names = raw.listKeys.bind(raw);
  vi.spyOn(raw, "listKeys").mockImplementation(async (ns, prefix) => {
    const result = await names(ns, prefix);
    if (ns === "_audit") await fs.unlink(join(path, ns, `${vanishedKey}.enc`));
    return result;
  });
  await log.appendCritical(measureEntry(4));
  expect(log.currentInMemorySequence()).toBe(5);
});

it("retains the custody refusal when the tail candidate itself is a dangling symlink", async () => {
  const { log, path } = await setup();
  await fs.symlink(join(root, "missing"), join(path, "_audit", "entry-99999999999999999999-dangling.enc"));
  await expect(log.appendCritical(measureEntry(3))).rejects.toMatchObject({ code: "symlink_rejected" });
  expect(log.currentInMemorySequence()).toBe(3);
});

for (const collapse of [false, true]) {
  it(`compares raw observations across a boundary transition, collapse=${collapse}`, async () => {
    const { migrateFortressAuditStoreSplit } = await import("../../src/operational/audit-store-split.js");
    const { raw, log, path } = await setup();
    const rotate = (log as any).maybeRotate.bind(log);
    const diagnostic = vi.spyOn(console, "error").mockImplementation(() => {});
    let seedBefore = 0;
    vi.spyOn(log as any, "maybeRotate").mockImplementationOnce(async (...args) => {
      const migrated = await migrateFortressAuditStoreSplit({ storage: raw, masterKey: MEASURE_MASTER_KEY, identityId: "fixture" });
      expect(migrated.status).toBe("migrated");
      const b = new AuditLog(new FilesystemStorage(path), MEASURE_MASTER_KEY, MEASURE_CONFIG);
      await b.appendCritical(measureEntry(4));
      (log as any).bytesProvenance = "unknown";
      seedBefore = (log as any).retainedBytesEstimate;
      if (collapse) await fs.symlink(join(root, "missing"), join(path, "_audit", "entry-00000000000000000000-dangling.enc"));
      return rotate(...args);
    });
    await log.appendCritical(measureEntry(3));
    if (collapse) {
      expect((log as any).bytesProvenance).toBe("unknown");
      expect((log as any).retainedBytesEstimate).toBe(seedBefore);
      expect(recountLines(diagnostic)).toHaveLength(1);
    } else {
      const suffix = (await raw.list("_audit")).filter((meta) => meta.key.startsWith("entry-00000000000000000005-"));
      expect(suffix).toHaveLength(1);
      expect((log as any).retainedCountExpected).toBe(1);
      expect((log as any).retainedBytesEstimate).toBe(suffix[0]!.size_bytes);
      expect((log as any).bytesProvenance).toBe("seeded");
      expect(recountLines(diagnostic)).toEqual([]);
    }
  });
}

for (const namesOnly of [false, true]) {
  for (const legacy of ["1700000000000-0", "zz-legacy"]) {
    it(`preserves the foreign legacy-key stat refusal boundary, listKeys=${namesOnly}, key=${legacy}`, async () => {
      const path = join(root, "legacy");
      const raw = new FilesystemStorage(path);
      const encryptionKey = derivePurposeKey(MEASURE_MASTER_KEY, "audit-log");
      await raw.write("_audit", legacy, encode(encrypt(encode({ ...measureEntry(0), timestamp: new Date().toISOString() }), encryptionKey)));
      const wrapper = new Proxy(raw, { get(target, key) {
        if (key === "listKeys" && !namesOnly) return undefined;
        const value = Reflect.get(target, key); return typeof value === "function" ? value.bind(target) : value;
      } });
      const log = new AuditLog(wrapper, MEASURE_MASTER_KEY, MEASURE_CONFIG);
      for (let index = 0; index < 3; index++) await log.appendCritical(measureEntry(index));
      const fault = injectFsFault("stat", join(path, "_audit", `${legacy}.enc`));
      const diagnostic = vi.spyOn(console, "error").mockImplementation(() => {});
      const previousSequence = log.currentInMemorySequence();
      await log.appendCritical(measureEntry(3));
      expect(log.currentInMemorySequence()).toBe(previousSequence + 1);
      if (namesOnly) expect(fault.hits()).toBe(0);
      else expect(recountLines(diagnostic)).toHaveLength(1);
    });
  }
}

it("recounts the full legacy population on each fallback append and preserves prefix refusal", async () => {
  const path = join(root, "legacy-fallback");
  const raw = new FilesystemStorage(path);
  const legacy = "1700000000000-0";
  const encryptionKey = derivePurposeKey(MEASURE_MASTER_KEY, "audit-log");
  await raw.write("_audit", legacy, encode(encrypt(encode({ ...measureEntry(0), timestamp: new Date().toISOString() }), encryptionKey)));
  const wrapper = new Proxy(raw, { get(target, key) {
    if (key === "listKeys") return undefined;
    const value = Reflect.get(target, key); return typeof value === "function" ? value.bind(target) : value;
  } });
  const log = new AuditLog(wrapper, MEASURE_MASTER_KEY, MEASURE_CONFIG);
  for (let index = 0; index < 3; index++) await log.appendCritical(measureEntry(index));
  const listings = vi.spyOn(raw, "list");
  for (let index = 0; index < 3; index++) {
    listings.mockClear(); await log.appendCritical(measureEntry(index + 3));
    expect(listings.mock.calls.filter(([ns, prefix]) => ns === "_audit" && prefix === undefined)).toHaveLength(1);
    expect(listings.mock.calls.filter(([ns, prefix]) => ns === "_audit" && prefix === "entry-")).toHaveLength(1);
    expect((log as any).retainedCountExpected).toBe(5 + index);
    const metas = await raw.list("_audit");
    expect((log as any).retainedBytesEstimate).toBe(metas.reduce((total, meta) => total + meta.size_bytes, 0));
    expect(await raw.exists("_audit", legacy)).toBe(true);
  }
  const tail = (await raw.listKeys("_audit")).at(-1)!;
  injectFsFault("stat", join(path, "_audit", `${tail}.enc`));
  await expect(log.appendCritical(measureEntry(6))).rejects.toThrow("injected stat EIO");
});

for (const faultKind of ["readdir", "raw-name"] as const) {
  it(`refuses discovery ${faultKind} faults before allocating or writing`, async () => {
    const { raw, log, path } = await setup();
    await (log as any).withAuditWriteLock(async () => {});
    if (faultKind === "readdir") injectFsFault("readdir", join(path, "_audit"));
    else await fs.writeFile(join(path, "_audit", "key-!4E2D.enc"), "unaddressable fixture name");
    const write = vi.spyOn(raw, "writeDurable");
    await expect(log.appendCritical(measureEntry(3))).rejects.toMatchObject({
      code: faultKind === "readdir" ? "EIO" : "FILESYSTEM_STORAGE_NAME_UNADDRESSABLE",
    });
    expect(log.currentInMemorySequence()).toBe(3);
    expect(write).not.toHaveBeenCalled();
  });
}

it("lets the original writer continue after a separate strict reader detects a metadata fault", async () => {
  const { raw, log, path } = await setup();
  const oldest = ((await raw.list("_audit")).map((meta) => meta.key))[0]!;
  const fault = injectFsFault("stat", join(path, "_audit", `${oldest}.enc`));
  const separate = new AuditLog(new FilesystemStorage(path), MEASURE_MASTER_KEY, MEASURE_CONFIG);
  await expect(separate.query({ limit: 1 })).rejects.toMatchObject({ name: "AuditIntegrityError",
    findings: expect.arrayContaining([expect.objectContaining({ kind: "storage_unavailable" })]) });
  await log.appendCritical(measureEntry(3));
  expect(log.currentInMemorySequence()).toBe(4);
  expect((log as any).integrityFindings).toEqual([]);
  fault.restore();
});

it("marks a timed-out entry write unknown after its late landing and recounts next append", async () => {
  const { raw } = await setup();
  const counted = countedStorage(raw);
  const log = new AuditLog(counted.storage, MEASURE_MASTER_KEY, { ...MEASURE_CONFIG, writeLockHoldDeadlineMs: 200 });
  await log.query({ limit: 1 });
  const write = raw.writeDurable.bind(raw); const hold = gate(); const entered = gate(); const settled = gate();
  let pause = true;
  vi.spyOn(raw, "writeDurable").mockImplementation(async (ns, key, bytes) => {
    if (pause && ns === "_audit") {
      pause = false; entered.release(); await hold.wait;
      try { await write(ns, key, bytes); } finally { settled.release(); }
      return;
    }
    await write(ns, key, bytes);
  });
  const append = log.appendCritical(measureEntry(3));
  const rejected = expect(append).rejects.toMatchObject({ name: "AuditLockHoldDeadlineError" });
  try { await entered.wait; await rejected; }
  finally { hold.release(); await settled.wait; await new Promise((resolve) => setImmediate(resolve)); }
  expect((log as any).bytesProvenance).toBe("unknown");
  expect((await raw.list("_audit")).map((meta) => meta.key)).toHaveLength(4);
  counted.reset(); await log.appendCritical(measureEntry(4));
  expect(counted.calls.get("list:_audit")).toBe(1);
  expect((log as any).bytesProvenance).toBe("seeded");
  expect(log.currentInMemorySequence()).toBe(5);
});

it("crosses the fallback cap twice with full E plus L accounting and surviving legacy records", async () => {
  const raw = new MemoryStorage(); const legacy = ["z-legacy-0", "z-legacy-1"];
  const encryptionKey = derivePurposeKey(MEASURE_MASTER_KEY, "audit-log");
  for (const key of legacy) await raw.write("_audit", key,
    encode(encrypt(encode({ ...measureEntry(0), timestamp: new Date().toISOString() }), encryptionKey)));
  const wrapper = new Proxy(raw, { get(target, key) {
    if (key === "listKeys") return undefined;
    const value = Reflect.get(target, key); return typeof value === "function" ? value.bind(target) : value;
  } });
  // A cap of five and a one-entry margin gives two deletes at each crossing.
  const log = new AuditLog(wrapper, MEASURE_MASTER_KEY, { ...MEASURE_CONFIG, maxEntries: 5 });
  const remove = vi.spyOn(raw, "delete");
  const anchors = vi.spyOn(log as any, "writeRotationAnchor");
  for (let i = 0; i < 6; i++) {
    await log.appendCritical(measureEntry(i));
    const metas = await raw.list("_audit");
    expect((log as any).retainedCountExpected).toBe(metas.length);
    expect((log as any).retainedBytesEstimate).toBe(metas.reduce((sum, meta) => sum + meta.size_bytes, 0));
    for (const key of legacy) expect(await raw.exists("_audit", key)).toBe(true);
  }
  expect(remove).toHaveBeenCalledTimes(4);
  expect(anchors.mock.calls.map(([seq]) => seq)).toEqual([4, 5, 6, 7]);
  expect((await new AuditLog(wrapper, MEASURE_MASTER_KEY, MEASURE_CONFIG).query({ limit: 10 })).integrity_findings).toEqual([]);
});
