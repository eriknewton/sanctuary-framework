/** Namespace insert records: one encrypted record per saved namespace, created once, loaded within a bound and kept only when intact. */
import { createHash, randomBytes } from "node:crypto";
import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
  BaselineNamespaceInserts,
  BaselineTracker,
} from "../../src/principal-policy/baseline.js";
import { MemoryStorage } from "../../src/storage/memory.js";
import { FilesystemStorage } from "../../src/storage/filesystem.js";
import type { StorageBackend } from "../../src/storage/interface.js";
import { encrypt } from "../../src/core/encryption.js";
import { derivePurposeKey } from "../../src/core/key-derivation.js";
import { stringToBytes } from "../../src/core/encoding.js";
import type { AuditEntryInput } from "../../src/operational/audit-log.js";
import { createSanctuaryServer } from "../../src/index.js";
import { generateDefaultPolicyYaml } from "../../src/principal-policy/loader.js";
import type { ApprovalResponse } from "../../src/principal-policy/types.js";
import { createTempHome, TEST_PASSPHRASE } from "../helpers/temp-fortress.js";

const NS = "_principal_ns";
const recordKey = (namespace: string) => createHash("sha256").update("ns:" + namespace, "utf8").digest("hex");
const sealed = (plaintext: string, masterKey: Uint8Array) =>
  stringToBytes(JSON.stringify(encrypt(stringToBytes(plaintext), derivePurposeKey(masterKey, "principal-baseline"))));

interface Harness {
  storage: MemoryStorage;
  masterKey: Uint8Array;
  rows: AuditEntryInput[];
  lines: string[];
  clock: { now: number };
  appendFails: { value: boolean };
  inserts: BaselineNamespaceInserts;
}

function harness(storage = new MemoryStorage()): Harness {
  const masterKey = new Uint8Array(randomBytes(32));
  const rows: AuditEntryInput[] = [];
  const lines: string[] = [];
  const clock = { now: 1_000_000 };
  const appendFails = { value: false };
  const inserts = new BaselineNamespaceInserts({
    storage,
    masterKey,
    auditLog: {
      appendCritical: async (entry) => {
        if (appendFails.value) throw new Error("injected append failure");
        rows.push(entry);
      },
    },
    stderr: (line) => { lines.push(line); },
    now: () => clock.now,
  });
  return { storage, masterKey, rows, lines, clock, appendFails, inserts };
}

async function load(storage: StorageBackend, masterKey: Uint8Array) {
  const tracker = new BaselineTracker(storage, masterKey);
  const report = await tracker.load();
  return { tracker, report };
}

/** Make every write to the record namespace fail. */
function failingRecordWrites(storage: MemoryStorage): void {
  const writeIfAbsent = storage.writeIfAbsent.bind(storage);
  vi.spyOn(storage, "writeIfAbsent").mockImplementation(async (namespace, key, data) => {
    if (namespace === NS) throw new Error("injected write failure");
    return writeIfAbsent(namespace, key, data);
  });
}

afterEach(() => { vi.restoreAllMocks(); });

describe("insert records", () => {
  it("after restart without clean shutdown, an inserted namespace is known", async () => {
    const h = harness();
    expect(await h.inserts.record("notes")).toEqual(["insert_PERSISTED"]);
    expect(await h.inserts.record("notes")).toEqual(["insert_ALREADY_PRESENT"]);
    const { tracker, report } = await load(h.storage, h.masterKey);
    expect(tracker.isNewNamespace("notes")).toBe(false);
    expect(report).toEqual({ inserts: { state: "load_COMPLETE", loaded: 1, skipped: 0 } });
  });

  it("1,025 insert records load none and hold the extra namespaces new", async () => {
    const h = harness();
    const namespaces = Array.from({ length: 1025 }, (_, index) => `ns-${index}`);
    for (const namespace of namespaces.slice(0, 1024)) await h.inserts.record(namespace);
    const atBound = await load(h.storage, h.masterKey);
    expect(atBound.report.inserts).toEqual({ state: "load_COMPLETE", loaded: 1024, skipped: 0 });
    await h.inserts.record(namespaces[1024]!);
    const { tracker, report } = await load(h.storage, h.masterKey);
    expect(report.inserts).toEqual({ state: "load_BOUNDED_NONE", code: "enumeration_over_bound", loaded: 0, skipped: 0 });
    expect(namespaces.filter((namespace) => !tracker.isNewNamespace(namespace))).toEqual([]);
  });

  it("a record over 4,096 bytes is skipped and the others load", async () => {
    const dir = await mkdtemp(join(tmpdir(), "ns-inserts-oversize-"));
    try {
      const storage = new FilesystemStorage(join(dir, "fortress"));
      const h = harness(storage as unknown as MemoryStorage);
      await h.inserts.record("small");
      const big = "b".repeat(4096);
      await storage.write(NS, recordKey(big), sealed(big, h.masterKey));
      const readBounded = vi.spyOn(storage, "readBounded");
      const read = vi.spyOn(storage, "read");
      const { tracker, report } = await load(storage, h.masterKey);
      expect(report.inserts).toEqual({ state: "load_COMPLETE", code: "records_skipped", loaded: 1, skipped: 1 });
      expect(readBounded.mock.calls.every(([namespace, , maxBytes]) => namespace === NS && maxBytes === 4096)).toBe(true);
      expect(readBounded).toHaveBeenCalledTimes(2);
      // Every record is read through the bounded read, which refuses on the descriptor's size before reading the body.
      expect(read.mock.calls.filter(([namespace]) => namespace === NS)).toEqual([]);
      expect(tracker.isNewNamespace("small")).toBe(false);
      expect(tracker.isNewNamespace(big)).toBe(true);
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });

  it("an insert record whose plaintext does not hash to its key is skipped and the others load", async () => {
    const h = harness();
    await h.inserts.record("kept");
    await h.inserts.record("victim");
    // A valid ciphertext of another namespace copied under this record's key.
    await h.storage.write(NS, recordKey("victim"), sealed("planted", h.masterKey));
    const { tracker, report } = await load(h.storage, h.masterKey);
    expect(report.inserts).toEqual({ state: "load_COMPLETE", code: "records_skipped", loaded: 1, skipped: 1 });
    expect(tracker.isNewNamespace("kept")).toBe(false);
    expect(tracker.isNewNamespace("planted")).toBe(true);
    expect(tracker.isNewNamespace("victim")).toBe(true);
  });

  it("an insert record whose plaintext is empty or starts with an underscore is skipped", async () => {
    const h = harness();
    await h.inserts.record("kept");
    await h.storage.write(NS, recordKey(""), sealed("", h.masterKey));
    await h.storage.write(NS, recordKey("_secret"), sealed("_secret", h.masterKey));
    const { tracker, report } = await load(h.storage, h.masterKey);
    expect(report.inserts).toEqual({ state: "load_COMPLETE", code: "records_skipped", loaded: 1, skipped: 2 });
    expect(tracker.getProfile().known_namespaces).toEqual(["kept"]);
  });

  it("an insert record that does not decrypt is skipped and the others load", async () => {
    const h = harness();
    await h.inserts.record("kept");
    await h.storage.write(NS, recordKey("wrong-key"), sealed("wrong-key", new Uint8Array(randomBytes(32))));
    await h.storage.write(NS, recordKey("garbage"), stringToBytes("not an envelope"));
    const { tracker, report } = await load(h.storage, h.masterKey);
    expect(report.inserts).toEqual({ state: "load_COMPLETE", code: "records_skipped", loaded: 1, skipped: 2 });
    expect(tracker.getProfile().known_namespaces).toEqual(["kept"]);
  });

  it.each([
    ["returns null", async () => null],
    ["throws a plain error", async () => { throw new Error("injected read failure"); }],
  ])("an insert record that disappears or cannot be read between listing and reading is skipped (readBounded %s)", async (_label, behaviour) => {
    const h = harness();
    await h.inserts.record("kept");
    await h.inserts.record("lost");
    const readBounded = h.storage.readBounded.bind(h.storage);
    vi.spyOn(h.storage, "readBounded").mockImplementation(async (namespace, key, maxBytes) =>
      key === recordKey("lost") ? behaviour() : readBounded(namespace, key, maxBytes));
    const { tracker, report } = await load(h.storage, h.masterKey);
    expect(report.inserts).toEqual({ state: "load_COMPLETE", code: "records_skipped", loaded: 1, skipped: 1 });
    expect(tracker.getProfile().known_namespaces).toEqual(["kept"]);
  });

  it("a non-bound listing failure loads no insert records", async () => {
    const h = harness();
    await h.inserts.record("kept");
    vi.spyOn(h.storage, "listKeysBounded").mockRejectedValue(new Error("injected listing failure"));
    const { tracker, report } = await load(h.storage, h.masterKey);
    expect(report.inserts).toEqual({ state: "load_BOUNDED_NONE", code: "enumeration_failed", loaded: 0, skipped: 0 });
    expect(tracker.isNewNamespace("kept")).toBe(true);
  });

  it.each(["listKeysBounded", "readBounded"] as const)("a storage without bounded listing or without bounded reading loads no insert records (%s absent)", async (method) => {
    const h = harness();
    await h.inserts.record("kept");
    const view = Object.create(h.storage) as MemoryStorage;
    Object.defineProperty(view, method, { value: undefined });
    const { tracker, report } = await load(view, h.masterKey);
    expect(report.inserts).toEqual({ state: "load_BOUNDED_NONE", code: "bounded_method_unavailable", loaded: 0, skipped: 0 });
    expect(tracker.isNewNamespace("kept")).toBe(true);
  });

  it("a storage without an absent-write never overwrites an insert record", async () => {
    const backing = new MemoryStorage();
    const storage = Object.create(backing) as MemoryStorage;
    Object.defineProperty(storage, "writeIfAbsent", { value: undefined });
    const write = vi.spyOn(backing, "write");
    const h = harness(storage);
    expect(await h.inserts.record("notes")).toEqual(["insert_PENDING", "insert_ROW_WRITTEN"]);
    expect(write.mock.calls.filter(([namespace]) => namespace === NS)).toEqual([]);
    expect(h.inserts.pendingCount).toBe(1);
    expect(h.rows).toEqual([{
      layer: "l2",
      operation: "baseline_namespace_persist_failed",
      identity_id: "system",
      result: "failure",
      details: { code: "absent_write_unavailable", count: 1 },
    }]);
  });

  it("record skips internal namespaces", async () => {
    const h = harness();
    const writeIfAbsent = vi.spyOn(h.storage, "writeIfAbsent");
    expect(await h.inserts.record("_principal")).toEqual([]);
    expect(await h.inserts.record("")).toEqual([]);
    expect(writeIfAbsent).not.toHaveBeenCalled();
    expect(await h.storage.listKeys(NS)).toEqual([]);
  });
});

describe("durable publication", () => {
  it("on the filesystem backend the first insert publishes inside the strict namespace lock and reports success only after that publication", async () => {
    const dir = await mkdtemp(join(tmpdir(), "ns-inserts-durable-"));
    try {
      const storage = new FilesystemStorage(join(dir, "fortress"));
      const h = harness(storage as unknown as MemoryStorage);
      const events: string[] = [];
      let inLock = false;
      const lock = storage.withStrictNamespaceLock.bind(storage);
      vi.spyOn(storage, "withStrictNamespaceLock").mockImplementation(async (namespace, lockFileName, operation, options) =>
        lock(namespace, lockFileName, async (lease) => {
          inLock = true;
          try { return await operation(lease); } finally { inLock = false; }
        }, options));
      let release!: () => void;
      const gate = new Promise<void>((resolve) => { release = resolve; });
      const strictWrite = storage.writeIfAbsentStrict.bind(storage);
      vi.spyOn(storage, "writeIfAbsentStrict").mockImplementation(async (namespace, key, data) => {
        events.push(`strict:${namespace}:${inLock}`);
        await gate;
        const created = await strictWrite(namespace, key, data);
        events.push("published");
        return created;
      });
      const plainWrite = vi.spyOn(storage, "writeIfAbsent");
      const settled = h.inserts.record("notes").then((states) => { events.push("reported"); return states; });
      await vi.waitFor(() => { expect(events).toEqual([`strict:${NS}:true`]); });
      release();
      expect(await settled).toEqual(["insert_PERSISTED"]);
      expect(events).toEqual([`strict:${NS}:true`, "published", "reported"]);
      expect(plainWrite.mock.calls.filter(([namespace]) => namespace === NS)).toEqual([]);
      const { tracker } = await load(storage, h.masterKey);
      expect(tracker.isNewNamespace("notes")).toBe(false);
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });

  it("a namespace already recorded by this process is not inserted again", async () => {
    const h = harness();
    const writes = vi.spyOn(h.storage, "writeIfAbsent");
    expect(await h.inserts.record("notes")).toEqual(["insert_PERSISTED"]);
    expect(await h.inserts.record("notes")).toEqual(["insert_ALREADY_PRESENT"]);
    expect(writes.mock.calls.filter(([namespace]) => namespace === NS)).toHaveLength(1);
  });
});

describe("work and state per record call", () => {
  it("one record call performs at most two storage writes", async () => {
    const h = harness();
    const writeIfAbsent = h.storage.writeIfAbsent.bind(h.storage);
    const failing = { value: true };
    const writes: string[] = [];
    vi.spyOn(h.storage, "writeIfAbsent").mockImplementation(async (namespace, key, data) => {
      writes.push(key);
      if (failing.value) throw new Error("injected write failure");
      return writeIfAbsent(namespace, key, data);
    });
    const write = vi.spyOn(h.storage, "write");
    for (let index = 0; index < 1024; index++) await h.inserts.record(`pending-${index}`);
    expect(h.inserts.pendingCount).toBe(1024);
    failing.value = false;
    writes.length = 0;
    expect(await h.inserts.record("pending-7")).toEqual(["insert_PERSISTED"]);
    expect(writes.length + write.mock.calls.length).toBeLessThanOrEqual(2);
    expect(writes).toEqual([recordKey("pending-7")]);
    expect(h.inserts.pendingCount).toBe(1023);
  });

  it("over 1,024 failing namespaces in one minute, failure rows and stderr lines stay bounded", async () => {
    const h = harness();
    failingRecordWrites(h.storage);
    for (let index = 0; index < 2048; index++) {
      await h.inserts.record(`flood-${index}`);
      h.clock.now += 10;
    }
    expect(h.rows.length).toBeLessThanOrEqual(1024);
    expect(h.rows).toHaveLength(1024);
    expect(h.lines).toEqual([
      "Sanctuary: too many memory namespaces are waiting to be recorded; further failures this minute are not audited one by one.\n",
    ]);
    expect(h.inserts.pendingCount).toBe(1024);
    expect(h.inserts.throttledCount).toBe(1024);
  });

  it.each([
    ["the append succeeds", false],
    ["the append also fails", true],
  ])("an insert failure row is written at most once per namespace per minute (%s)", async (_label, appendFails) => {
    const h = harness();
    failingRecordWrites(h.storage);
    h.appendFails.value = appendFails;
    const outcomes = [];
    for (const step of [0, 1_000, 59_999, 60_000, 61_000]) {
      h.clock.now = 1_000_000 + step;
      outcomes.push(await h.inserts.record("notes"));
    }
    const reported = appendFails ? h.lines.length : h.rows.length;
    expect(reported).toBe(2);
    expect(appendFails ? h.rows : h.lines).toEqual([]);
    expect(outcomes.filter((states) => states.includes("insert_ROW_THROTTLED"))).toHaveLength(3);
    if (appendFails) {
      expect(h.lines).toEqual(Array(2).fill(
        "Sanctuary: a memory namespace could not be recorded for the next session, and the failure could not be audited.\n",
      ));
    }
  });
});

describe("records and the snapshot", () => {
  it("a snapshot save does not remove insert records", async () => {
    const h = harness();
    await h.inserts.record("alpha");
    await h.inserts.record("beta");
    const { tracker } = await load(h.storage, h.masterKey);
    await tracker.save();
    expect((await h.storage.listKeys(NS)).sort()).toEqual([recordKey("alpha"), recordKey("beta")].sort());
    const empty = new MemoryStorage();
    for (const key of await h.storage.listKeys(NS)) await empty.write(NS, key, (await h.storage.read(NS, key))!);
    const reloaded = await load(empty, h.masterKey);
    expect(reloaded.tracker.getProfile().known_namespaces.sort()).toEqual(["alpha", "beta"]);
  });

  it("inserted namespaces do not end the first session", async () => {
    const h = harness();
    await h.inserts.record("notes");
    const { tracker } = await load(h.storage, h.masterKey);
    expect(tracker.isNewNamespace("notes")).toBe(false);
    expect(tracker.isFirstSession).toBe(true);
  });
});

describe("clean shutdown", () => {
  let home: Awaited<ReturnType<typeof createTempHome>>;
  let originalSession: string | undefined;
  beforeEach(async () => {
    originalSession = process.env.SANCTUARY_SESSION_IDENTITY_ID;
    home = await createTempHome("sanctuary-ns-inserts");
    await mkdir(home.defaultFortressPath, { recursive: true, mode: 0o700 });
  });
  afterEach(async () => {
    if (originalSession === undefined) delete process.env.SANCTUARY_SESSION_IDENTITY_ID;
    else process.env.SANCTUARY_SESSION_IDENTITY_ID = originalSession;
    await home.cleanup();
  });

  it("a pending insert is flushed at clean shutdown before the snapshot is saved", async () => {
    const yaml = generateDefaultPolicyYaml().replace(/approval_channel:\n {2}type: \w+/, "approval_channel:\n  type: callback");
    await writeFile(join(home.defaultFortressPath, "principal-policy.yaml"), yaml, { mode: 0o600 });
    const storage = new MemoryStorage();
    const order: string[] = [];
    const failing = { value: true };
    const writeIfAbsent = storage.writeIfAbsent.bind(storage);
    vi.spyOn(storage, "writeIfAbsent").mockImplementation(async (namespace, key, data) => {
      if (namespace === NS) {
        order.push(failing.value ? "insert_failed" : "insert");
        if (failing.value) throw new Error("injected write failure");
      }
      return writeIfAbsent(namespace, key, data);
    });
    const write = storage.write.bind(storage);
    vi.spyOn(storage, "write").mockImplementation(async (namespace, key, data) => {
      if (namespace === "_principal") order.push("snapshot");
      return write(namespace, key, data);
    });
    const deny = async (): Promise<ApprovalResponse> =>
      ({ decision: "deny", decided_at: new Date().toISOString(), decided_by: "human" });
    const booted = await createSanctuaryServer({ storage, passphrase: TEST_PASSPHRASE, approvalCallback: deny });
    let cleaned = false;
    try {
      const handler = (booted.server as unknown as { _requestHandlers: Map<string, (request: unknown, extra: unknown) => Promise<{ content: Array<{ text: string }> }>> })._requestHandlers.get("tools/call")!;
      const call = (name: string, args: Record<string, unknown>) => handler({ method: "tools/call", params: { name, arguments: args } }, {});
      const identity = JSON.parse((await call("identity_create", { label: "flush-owner" })).content[0].text);
      process.env.SANCTUARY_SESSION_IDENTITY_ID = identity.identity_id;
      expect(JSON.parse((await call("sanctuary_remember", { key: "cup", value: "blue" })).content[0].text).key).toBe("cup");
      expect(order).toEqual(["insert_failed"]);
      failing.value = false;
      cleaned = true;
      await booted.cleanup();
    } finally {
      if (!cleaned) await booted.cleanup();
    }
    expect(order).toEqual(["insert_failed", "insert", "snapshot"]);
    expect(await storage.listKeys(NS)).toHaveLength(1);
  });
});
