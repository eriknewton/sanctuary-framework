import * as fs from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";
import {
  AuditLog, type AuditLogConfig, type PersistedAuditEnvelopeV2,
  __testSetAuditWriterUidForRole, auditStoreSplitBoundaryPath,
  deriveAuditStoreSplitBoundaryMacKey, writeAuditStoreSplitBoundary,
} from "../../src/operational/audit-log.js";
import { createDaemonAuditLog, migrateFortressAuditStoreSplit } from "../../src/operational/audit-store-split.js";
import { FilesystemStorage } from "../../src/storage/filesystem.js";
import { encrypt, decrypt } from "../../src/core/encryption.js";
import { derivePurposeKey } from "../../src/core/key-derivation.js";
import { fromBase64url } from "../../src/core/encoding.js";

vi.mock("node:fs/promises", async original => ({ ...await original<typeof import("node:fs/promises")>() }));
const roots: string[] = [];
const master = Buffer.alloc(32, 7); // AES-256 fixture key.
const ENTRY = { layer: "l1" as const, operation: "discovery", identity_id: "fixture", result: "success" as const, details: { witness: true } };
// Must match the persisted marker keys in operational/audit-log.ts.
const HEAD = "__head_anchor";
const ESTABLISHED = "audit-head-anchor-established-v1";
const SUFFIX = "audit-post-split-suffix-established-v1";
const MIGRATED = "audit-store-split-established-v1";
const bytes = (value: unknown) => Buffer.from(JSON.stringify(value));
const fault = (code: string) => Object.assign(new Error(`injected ${code}`), { code });
type State = { nextSequence: number; lastEntryHash: string; cachedSealedTip: number; knownV2HighWater: number; verifiedLegacyCount: number; verifiedLegacyRoot: string };
function state(log: AuditLog) {
  const value = log as unknown as State;
  return [value.nextSequence, value.lastEntryHash, value.cachedSealedTip, value.knownV2HighWater, value.verifiedLegacyCount, value.verifiedLegacyRoot];
}
function gate() { let release!: () => void; const wait = new Promise<void>(resolve => { release = resolve; }); return { release, wait }; }
afterEach(async () => {
  vi.restoreAllMocks(); vi.unstubAllEnvs(); __testSetAuditWriterUidForRole("root_daemon", undefined);
  for (const root of roots.splice(0)) await fs.rm(root, { recursive: true, force: true });
});
async function fixture(namesOnly = true, config: AuditLogConfig = {}) {
  const root = await fs.mkdtemp(join(tmpdir(), "audit-discovery-outcomes-")); roots.push(root); vi.stubEnv("HOME", root);
  const path = join(root, "state"); const storage = new FilesystemStorage(path);
  // Hide only this writer's optional capability; the daemon adapter still receives a real FilesystemStorage.
  const writerStorage = namesOnly ? storage : new Proxy(storage, { get(target, property) {
    if (property === "listKeys") return undefined;
    const value = Reflect.get(target, property);
    return typeof value === "function" ? value.bind(target) : value;
  } });
  const make = (extra: AuditLogConfig = {}) => new AuditLog(writerStorage, master, { checkpointInterval: 0, __testAuditGuardLockRoot: join(root, "guard"), ...config, ...extra });
  const log = make(); await log.getChainHead();
  return { root, path, storage, make, log };
}
type Fixture = Awaited<ReturnType<typeof fixture>>;
async function append(f: Fixture, count = 1, log = f.log) { for (let i = 0; i < count; i++) await log.appendCritical(ENTRY); }
async function keys(f: Fixture) { return (await f.storage.list("_audit")).map(meta => meta.key).sort(); }
async function envelope(f: Fixture, key = ""): Promise<PersistedAuditEnvelopeV2> {
  key ||= (await keys(f)).filter(name => name.startsWith("entry-")).at(-1)!;
  return JSON.parse(Buffer.from((await f.storage.read("_audit", key))!).toString());
}
async function erase(f: Fixture, namespaces = ["_audit", "_audit_checkpoints"]) {
  for (const ns of namespaces) for (const meta of await f.storage.list(ns)) await f.storage.delete(ns, meta.key);
}
async function corrupt(f: Fixture) { for (const key of await keys(f)) await f.storage.write("_audit", key, Buffer.from("{")); }
async function seal(f: Fixture, sequence?: number, hash?: string) {
  const tip = await envelope(f).catch(() => undefined);
  const count = sequence ?? tip?.sequence ?? 0;
  await writeAuditStoreSplitBoundary(f.path, deriveAuditStoreSplitBoundaryMacKey(master), {
    sealed_tip_sequence: count, sealed_base_sequence: count === 0 ? 0 : 1,
    sealed_tip_entry_hash: hash ?? tip?.entry_hash ?? "GENESIS", daemon_namespace: "_audit-daemon",
  });
}
async function snapshot(f: Fixture) {
  // Snapshot raw files so injected read/list faults do not mask a write witness.
  const result: Record<string, string> = {};
  for (const ns of ["_audit", "_audit_checkpoints", "_meta", "_audit_migration"]) {
    const dir = join(f.path, ns);
    for (const name of await fs.readdir(dir).catch(() => [] as string[])) {
      if (!name.endsWith(".enc") && !name.endsWith(".json")) continue;
      result[`${ns}/${name}`] = (await fs.readFile(join(dir, name))).toString("base64");
    }
  }
  return result;
}
async function refuses(f: Fixture, cause?: Error) {
  const cached = state(f.log); const before = await snapshot(f);
  for (let attempt = 0; attempt < 2; attempt++) {
    await expect(f.log.appendCritical(ENTRY)).rejects.toMatchObject({ name: "AuditChainStateUnknownError", classification: "unknown", ...(cause ? { cause, code: (cause as NodeJS.ErrnoException).code } : {}) });
    expect(state(f.log)).toEqual(cached); expect(await snapshot(f)).toEqual(before);
  }
}
function denyRead(f: Fixture, ns: string, key: string, code = "EIO") {
  const error = fault(code); const read = f.storage.read.bind(f.storage);
  const spy = vi.spyOn(f.storage, "read").mockImplementation((namespace, name) => namespace === ns && name === key ? Promise.reject(error) : read(namespace, name));
  return { error, spy };
}

for (const namesOnly of [true, false]) describe(namesOnly ? "names-only discovery" : "sized fallback discovery", () => {
  it("S0 adopts a foreign usable tail, skipping malformed newer names", async () => {
    const f = await fixture(namesOnly); await append(f);
    await append(f, 1, f.make()); const previous = await envelope(f);
    await f.storage.write("_audit", `entry-${String(99).padStart(20, "0")}-malformed`, Buffer.from("{"));
    await append(f);
    const written = await envelope(f, (await keys(f)).find(key => key.startsWith("entry-00000000000000000003"))!);
    expect(written).toMatchObject({ sequence: 3, prev_hash: previous.entry_hash });
  });
  it.each(["EIO", "invalid"])("D0 retains usable-tail continuation with head %s", async kind => {
    const f = await fixture(namesOnly); await append(f);
    if (kind === "EIO") denyRead(f, "_audit_checkpoints", HEAD);
    else await f.storage.write("_audit_checkpoints", HEAD, Buffer.from("{"));
    await append(f); expect((await envelope(f)).sequence).toBe(2);
  });
  it("D0 refuses a valid head beyond the adopted usable tip", async () => {
    const f = await fixture(namesOnly); await append(f, 10); await append(f, 1, f.make());
    await f.storage.write("_audit", (await keys(f)).at(-1)!, Buffer.from("{"));
    await refuses(f);
  });
  it("edit 5 D0 advances the prior floor and a later load cannot erase it", async () => {
    const f = await fixture(namesOnly, { integrityMode: "lenient" }); await append(f);
    const first = await envelope(f); await append(f, 1, f.make());
    await seal(f, first.sequence, first.entry_hash); await append(f);
    expect(state(f.log)[2]).toBe(1); expect(state(f.log)[3]).toBe(3);
    await fs.unlink(auditStoreSplitBoundaryPath(f.path));
    await f.log.runEagerReads(() => f.log.query({ limit: 1 }));
    expect(state(f.log)[2]).toBe(1); expect(state(f.log)[3]).toBe(3);
  });
  it.each(["boundary", "migration", "head"])("S1 refuses exhausted %s evidence", async kind => {
    const f = await fixture(namesOnly);
    if (kind === "boundary") { await seal(f); await fs.writeFile(auditStoreSplitBoundaryPath(f.path), "{"); }
    if (kind === "migration") await f.storage.write("_meta", MIGRATED, Buffer.from("{"));
    if (kind === "head") { await append(f); await erase(f, ["_audit"]); await f.storage.write("_audit_checkpoints", HEAD, Buffer.from("{")); }
    await refuses(f);
  });
  it.each(["EACCES", "EIO"])("S1 boundary %s retains absent helper semantics and migration evidence", async code => {
    const f = await fixture(namesOnly); await f.storage.write("_meta", MIGRATED, Buffer.from("{"));
    const read = fs.readFile;
    vi.spyOn(fs, "readFile").mockImplementation(((path: Parameters<typeof fs.readFile>[0], ...args: unknown[]) => String(path) === auditStoreSplitBoundaryPath(f.path) ? Promise.reject(fault(code)) : (read as Function)(path, ...args)) as typeof fs.readFile);
    await refuses(f);
  });
  it.each(["listing", "body", "head", "suffix"])("S1 I/O %s retains the original cause", async kind => {
    const f = await fixture(namesOnly); let error: Error;
    if (kind === "body") { await append(f); error = denyRead(f, "_audit", (await keys(f))[0]!).error; }
    else if (kind === "head") error = denyRead(f, "_audit_checkpoints", HEAD).error;
    else if (kind === "suffix") { await seal(f, 0, "GENESIS"); error = denyRead(f, "_meta", SUFFIX, "EACCES").error; }
    else {
      error = fault("EIO");
      if (namesOnly) vi.spyOn(f.storage, "listKeys").mockRejectedValue(error);
      else { const list = f.storage.list.bind(f.storage); vi.spyOn(f.storage, "list").mockImplementation((ns, prefix) => ns === "_audit" ? Promise.reject(error) : list(ns, prefix)); }
    }
    await refuses(f, error);
  });
  it.each(["EACCES", "EIO"])("S1e marker %s is uncertainty even when stat sees it", async code => {
    const f = await fixture(namesOnly); await f.storage.write("_meta", ESTABLISHED, Buffer.from("1"));
    const { error, spy } = denyRead(f, "_meta", ESTABLISHED, code);
    expect(await f.storage.exists("_meta", ESTABLISHED)).toBe(true);
    await refuses(f, error); spy.mockRestore();
    // The transient heals on the same instance only after the evidence supports a baseline.
    await f.storage.delete("_meta", ESTABLISHED); await append(f);
    expect((await envelope(f)).sequence).toBe(1);
  });
  it.each(["marker", "list", "both"])("S1e %s failure preserves independent positive evidence in load and discovery", async kind => {
    const f = await fixture(namesOnly);
    if (kind === "marker") await f.storage.write("_audit_checkpoints", "retained-proof", Buffer.from("proof"));
    if (kind === "list") await f.storage.write("_meta", ESTABLISHED, Buffer.from("1"));
    if (kind !== "list") denyRead(f, "_meta", ESTABLISHED, "EACCES");
    if (kind !== "marker") {
      const list = f.storage.list.bind(f.storage); vi.spyOn(f.storage, "list").mockImplementation((ns, prefix) => ns === "_audit_checkpoints" ? Promise.reject(fault("EIO")) : list(ns, prefix));
    }
    await refuses(f);
    const reader = f.make({ integrityMode: "lenient", chainWriterRole: "root_daemon" });
    const findings = await reader.getIntegrityFindings();
    expect(findings).toEqual(expect.arrayContaining([expect.objectContaining({ kind: kind === "both" ? "storage_unavailable" : "tail_anchor_missing" })]));
    await expect(f.make({ chainWriterRole: "root_daemon" }).query({ limit: 1 })).rejects.toMatchObject({ name: "AuditIntegrityError" });
  });
  it("C1 load retains the maximum observed sequence despite listing order", async () => {
    const f = await fixture(namesOnly); await append(f, 2);
    const original = await keys(f);
    const first = (await f.storage.read("_audit", original[0]!))!;
    const second = (await f.storage.read("_audit", original[1]!))!;
    await erase(f);
    await f.storage.write("_audit", "entry-00000000000000000001-a", second);
    await f.storage.write("_audit", "entry-00000000000000000001-z", first);
    f.log = f.make({ integrityMode: "lenient" });
    expect((await f.log.getIntegrityFindings()).length).toBeGreaterThan(0);
    expect(state(f.log)[0]).toBe(3); // T = 2, so the next allocation would be 3.
    expect(state(f.log)[3]).toBe(2);
    expect(state(f.log)[1]).toBe(JSON.parse(Buffer.from(second).toString()).entry_hash);
    await corrupt(f); await refuses(f);
  });
  it.each([
    ["cached", "absent"], ["fresh-lenient", "absent"],
    ["cached", "EACCES"], ["fresh-lenient", "EACCES"],
  ])("H1 zero boundary erased history refuses for %s with head %s", async (reader, head) => {
    const f = await fixture(namesOnly); __testSetAuditWriterUidForRole("root_daemon", 0);
    expect((await migrateFortressAuditStoreSplit({ storage: f.storage, masterKey: master })).status).toBe("migrated");
    f.log = f.make(); await f.log.getChainHead();
    await append(f, 2, f.make()); await erase(f);
    expect(await f.storage.read("_meta", ESTABLISHED)).not.toBeNull();
    expect(await f.storage.read("_meta", SUFFIX)).toBeNull();
    if (head === "EACCES") denyRead(f, "_audit_checkpoints", HEAD, head);
    if (reader === "fresh-lenient") { f.log = f.make({ integrityMode: "lenient" }); await f.log.getChainHead(); }
    const reads = vi.spyOn(f.storage, "read"); const lists = vi.spyOn(f.storage, "list");
    await refuses(f);
    // refuses makes two attempts; each must gather establishment exactly once.
    expect(reads.mock.calls.filter(([ns, key]) => ns === "_meta" && key === ESTABLISHED)).toHaveLength(2);
    expect(lists.mock.calls.filter(([ns]) => ns === "_audit_checkpoints")).toHaveLength(2);
  });
  it.each(["EACCES", "EIO"])("H1 boundary establishment %s uncertainty refuses then heals", async code => {
    // Fault-free controls share the regression case so every new item-2 test fails on the base.
    for (const floor of [0, 2]) {
      const f = await fixture(namesOnly); await append(f, floor);
      const previous = floor === 0 ? "GENESIS" : (await envelope(f)).entry_hash;
      __testSetAuditWriterUidForRole("root_daemon", 0);
      expect((await migrateFortressAuditStoreSplit({ storage: f.storage, masterKey: master })).status).toBe("migrated");
      await append(f);
      expect(await envelope(f)).toMatchObject({ sequence: floor + 1, prev_hash: previous });
      const cached = await envelope(f); await append(f, 1, f.make());
      expect(await envelope(f)).toMatchObject({ sequence: floor + 2, prev_hash: cached.entry_hash });
    }
    const f = await fixture(namesOnly); __testSetAuditWriterUidForRole("root_daemon", 0);
    await migrateFortressAuditStoreSplit({ storage: f.storage, masterKey: master });
    const { error, spy } = denyRead(f, "_meta", ESTABLISHED, code);
    await refuses(f, error); spy.mockRestore();
    await append(f); expect(await envelope(f)).toMatchObject({ sequence: 1, prev_hash: "GENESIS" });
  });
  it.each(["EACCES", "EIO"])("C2 marker %s alone prevents a clean fresh load", async code => {
    const f = await fixture(namesOnly);
    denyRead(f, "_meta", ESTABLISHED, code);
    const list = vi.spyOn(f.storage, "list");
    const reader = f.make({ integrityMode: "lenient", readOnly: true });
    expect(await reader.getIntegrityFindings()).toEqual(expect.arrayContaining([
      expect.objectContaining({ kind: "storage_unavailable" }),
    ]));
    await expect(f.make({ integrityMode: "strict", readOnly: true }).query({ limit: 1 })).rejects.toMatchObject({ name: "AuditIntegrityError" });
    const checkpointReads = list.mock.calls.flatMap(([ns], index) => ns === "_audit_checkpoints" ? [list.mock.results[index]!.value] : []);
    expect(checkpointReads.length).toBeGreaterThan(0);
    for (const result of checkpointReads) expect(await result).toEqual([]);
  });
  it("H2 prior trusted floor alone refuses after boundary loss", async () => {
    const f = await fixture(namesOnly); await append(f, 2); await seal(f);
    // Standalone checkpoint discovery observes the seal without creating a suffix.
    await f.log.flush();
    expect(state(f.log)[2]).toBe(2); expect(state(f.log)[3]).toBe(2);
    await fs.unlink(auditStoreSplitBoundaryPath(f.path)); await corrupt(f);
    await refuses(f);
  });
  it("H2 head and boundary hash disagreement alone refuses above the cached tip", async () => {
    const f = await fixture(namesOnly); await append(f);
    await append(f, 1, f.make());
    await seal(f, 2, "0".repeat(64)); // SHA-256 hex width; differs from the authentic foreign head.
    expect(state(f.log)[0]).toBe(2); expect(state(f.log)[3]).toBe(1);
    await refuses(f);
  });
  it.each(["boundary-hash", "head-hash", "floor-lost", "boundary-below-legacy"])("S2 refuses %s inconsistency", async kind => {
    const f = await fixture(namesOnly); await append(f, 2);
    const original = await envelope(f);
    if (kind === "boundary-hash") await seal(f, 2, "0".repeat(64)); // SHA-256 hex width.
    else if (kind === "head-hash") {
      const other = await fixture(namesOnly); await append(other, 2);
      await f.storage.write("_audit_checkpoints", HEAD, (await other.storage.read("_audit_checkpoints", HEAD))!);
      await corrupt(f);
    } else if (kind === "floor-lost") {
      await seal(f); await append(f); await erase(f);
      await fs.unlink(auditStoreSplitBoundaryPath(f.path));
    } else {
      // Verified legacy count must not be rewound by a later lower boundary.
      await erase(f); await f.storage.delete("_meta", ESTABLISHED);
      await f.storage.write("_audit", "legacy-1", bytes(encrypt(bytes({ ...ENTRY, timestamp: "2026-01-01T00:00:00.000Z" }), derivePurposeKey(master, "audit-log"))));
      f.log = f.make(); await f.log.getChainHead(); await seal(f, 0, "GENESIS");
    }
    await refuses(f); expect(original.sequence).toBe(2);
  });
  it("S3 newer head defeats malformed known-tip candidates", async () => {
    const f = await fixture(namesOnly); await append(f, 2); const old = await keys(f);
    await append(f, 9, f.make());
    for (const key of await keys(f)) if (!old.includes(key)) await f.storage.delete("_audit", key);
    await corrupt(f); await refuses(f);
  });
  it.each([false, true])("S4 suffix proof defeats malformed suffix, hidden head=%s", async hidden => {
    const f = await fixture(namesOnly); await append(f, 2); await seal(f); await append(f);
    await f.storage.write("_audit", (await keys(f)).at(-1)!, Buffer.from("{"));
    await f.storage.delete("_audit_checkpoints", HEAD);
    if (hidden) denyRead(f, "_audit_checkpoints", HEAD, "EACCES");
    await refuses(f);
  });
  it.each([false, true])("S5 unseen malformed candidate refuses, vanishes=%s", async vanishes => {
    const f = await fixture(namesOnly); const key = "entry-00000000000000000001-planted";
    await f.storage.write("_audit", key, Buffer.from("{"));
    if (vanishes) { const read = f.storage.read.bind(f.storage); vi.spyOn(f.storage, "read").mockImplementation((ns, name) => ns === "_audit" && name === key ? Promise.resolve(null) : read(ns, name)); }
    await refuses(f);
  });
  it.each(["none", "lower", "null-at-K"])("S6 vanished known tip refuses with %s evidence", async kind => {
    const f = await fixture(namesOnly); await append(f, 2); const old = await keys(f); await erase(f);
    if (kind !== "none") await f.storage.write("_audit", old[0]!, Buffer.from("{"));
    if (kind === "null-at-K") {
      await f.storage.write("_audit", old[1]!, Buffer.from("{")); const read = f.storage.read.bind(f.storage);
      vi.spyOn(f.storage, "read").mockImplementation((ns, key) => ns === "_audit" && key === old[1] ? Promise.resolve(null) : read(ns, key));
    }
    await refuses(f);
  });
  it("S7 hidden sealed head cannot excuse a known malformed suffix", async () => {
    const f = await fixture(namesOnly); await append(f, 2); await seal(f); await append(f);
    await f.storage.write("_audit", (await keys(f)).at(-1)!, Buffer.from("{"));
    await f.storage.delete("_meta", SUFFIX); const { error } = denyRead(f, "_audit_checkpoints", HEAD, "EACCES");
    await refuses(f, error);
  });
  it("S8 continues at cached hash only with surviving known-tip bytes", async () => {
    const f = await fixture(namesOnly); await append(f, 2); const before = await envelope(f); await corrupt(f);
    await append(f); expect(await envelope(f)).toMatchObject({ sequence: 3, prev_hash: before.entry_hash });
    await expect(f.make().query({ limit: 1 })).rejects.toMatchObject({ name: "AuditIntegrityError" });
  });
  it.each([false, true])("S9a loaded at sealed tip continues without sealed body reads, hidden=%s", async hidden => {
    const f = await fixture(namesOnly); await append(f, 2); const before = await envelope(f); await seal(f);
    const read = f.storage.read.bind(f.storage); const sealed = new Set(await keys(f));
    const spy = vi.spyOn(f.storage, "read").mockImplementation((ns, key) => {
      if (ns === "_audit" && sealed.has(key)) throw new Error("sealed body read");
      if (hidden && ns === "_audit_checkpoints" && key === HEAD) throw fault("EACCES");
      return read(ns, key);
    });
    await append(f); spy.mockRestore();
    expect(await envelope(f)).toMatchObject({ sequence: 3, prev_hash: before.entry_hash });
    expect(Buffer.from((await f.storage.read("_meta", SUFFIX))!).toString()).toBe("1");
  });
  it.each(["warm-empty", "cold", "zero"])("S9b %s seeds this read's boundary", async kind => {
    const f = await fixture(namesOnly);
    if (kind !== "zero") await append(f, 2, f.make());
    const before = kind === "zero" ? undefined : await envelope(f); await seal(f);
    if (kind === "cold") f.log = f.make();
    await append(f);
    expect(await envelope(f)).toMatchObject({ sequence: kind === "zero" ? 1 : 3, prev_hash: before?.entry_hash ?? "GENESIS" });
    if (kind === "zero") expect(await f.storage.read("_meta", SUFFIX)).toBeNull();
  });
  it("S10 daemon genesis performs no unmapped migration probe", async () => {
    const f = await fixture(namesOnly); await append(f, 2);
    __testSetAuditWriterUidForRole("root_daemon", 0);
    const daemon = createDaemonAuditLog(f.storage, master, { checkpointInterval: 0, __testAuditGuardLockRoot: join(f.root, "guard") });
    await daemon.appendCritical(ENTRY);
    const record = (await f.storage.list("_audit-daemon"))[0]!;
    expect(JSON.parse(Buffer.from((await f.storage.read("_audit-daemon", record.key))!).toString())).toMatchObject({ sequence: 1, prev_hash: "GENESIS" });
  });
  it("S10 guards genuine genesis and bounds exhaustion listings", async () => {
    const f = await fixture(namesOnly); const read = f.storage.read.bind(f.storage);
    const marker = vi.spyOn(f.storage, "read").mockImplementation((ns, key) => { if (key === SUFFIX) throw new Error("unexpected suffix probe"); return read(ns, key); });
    const list = vi.spyOn(f.storage, "list"); await append(f);
    expect(marker.mock.calls.some(([, key]) => key === SUFFIX)).toBe(false);
    for (const ns of ["_audit_checkpoints", "_audit-daemon", "_audit-daemon_checkpoints", "_audit-daemon_meta"]) {
      expect(list.mock.calls.filter(([namespace]) => namespace === ns)).toHaveLength(1);
    }
    expect(await envelope(f)).toMatchObject({ sequence: 1, prev_hash: "GENESIS" });
  });
  it("edit 7 migration window refuses then heals on the same instance", async () => {
    const f = await fixture(namesOnly); __testSetAuditWriterUidForRole("root_daemon", 0);
    const write = f.storage.write.bind(f.storage);
    // The real migration publishes its daemon genesis and marker before the boundary.
    const markerWritten = gate(); const continueMigration = gate();
    vi.spyOn(f.storage, "write").mockImplementation(async (ns, key, value) => {
      await write(ns, key, value);
      if (ns === "_meta" && key === MIGRATED) { markerWritten.release(); await continueMigration.wait; }
    });
    const migration = migrateFortressAuditStoreSplit({ storage: f.storage, masterKey: master });
    try { await Promise.race([markerWritten.wait, migration.then(() => { throw new Error("migration never paused"); })]); await refuses(f); } finally { continueMigration.release(); await migration; }
    await append(f); expect(await envelope(f)).toMatchObject({ sequence: 1, prev_hash: "GENESIS" });
  });
  it.each(["strict", "lenient"] as const)("S11 verified legacy %s load continues from its full root", async mode => {
    const f = await fixture(namesOnly);
    await f.storage.write("_audit", "legacy-1", bytes(encrypt(bytes({ ...ENTRY, timestamp: "2026-01-01T00:00:00.000Z" }), derivePurposeKey(master, "audit-log"))));
    f.log = f.make({ integrityMode: mode }); const head = await f.log.getChainHead();
    await append(f); expect(await envelope(f)).toMatchObject({ sequence: 2, prev_hash: head.entry_hash });
  });
  it.each([false, true])("S11 read-only legacy load preserves absent head; writer continues with establishment=%s", async established => {
    const f = await fixture(namesOnly);
    await f.storage.write("_audit", "legacy-1", bytes(encrypt(bytes({ ...ENTRY, timestamp: "2026-01-01T00:00:00.000Z" }), derivePurposeKey(master, "audit-log"))));
    const before = await snapshot(f);
    const reader = f.make({ readOnly: true }); const readHead = await reader.getChainHead();
    expect(await snapshot(f)).toEqual(before);
    expect(await f.storage.read("_audit_checkpoints", HEAD)).toBeNull();
    expect(state(reader)[4]).toBe(1); expect(state(reader)[3]).toBe(0);
    f.log = f.make({ integrityMode: "lenient" }); await f.log.getChainHead();
    // Authorized load may seed anchors. Remove them after loading to exercise D11 with no current head.
    await erase(f, ["_audit_checkpoints"]);
    if (established) await f.storage.write("_meta", ESTABLISHED, Buffer.from("1"));
    else await f.storage.delete("_meta", ESTABLISHED);
    await append(f);
    expect(await envelope(f)).toMatchObject({ sequence: 2, prev_hash: readHead.entry_hash });
  });
  it.each(["marker", "checkpoint"])("S12b lenient %s-only load cannot authorize discovery", async kind => {
    const f = await fixture(namesOnly);
    await f.storage.write(kind === "marker" ? "_meta" : "_audit_checkpoints", kind === "marker" ? ESTABLISHED : "proof", Buffer.from("1"));
    f.log = f.make({ integrityMode: "lenient" });
    expect(await f.log.getIntegrityFindings()).toEqual(expect.arrayContaining([expect.objectContaining({ kind: "tail_anchor_missing" })]));
    await refuses(f);
  });
});

it("standalone checkpoint refuses unknown discovery before writing", async () => {
  const f = await fixture(); await append(f); await erase(f);
  const before = await snapshot(f); const cached = state(f.log);
  await expect(f.log.flush()).rejects.toMatchObject({ name: "AuditChainStateUnknownError" });
  expect(await snapshot(f)).toEqual(before); expect(state(f.log)).toEqual(cached);
});

for (const namesOnly of [true, false]) {
  it.each(["S0", "S9a", "S9b-stale", "S9b-warm-empty", "S9b-cold", "S9b-zero", "S10-operator", "S10-daemon", "S10-migration", "S11-strict", "S11-lenient"])(
    `fault-free payload linkage %s namesOnly=${namesOnly}`, async schedule => {
      const f = await fixture(namesOnly);
      const encryptionKey = derivePurposeKey(master, "audit-log");
      const hashes = new Map<string, number | string>([["GENESIS", "GENESIS"]]);
      let boundaryHash: string | undefined;
      const write = (log: AuditLog, step: string) => log.appendCritical({ ...ENTRY, details: { step } });
      const migrate = async () => {
        __testSetAuditWriterUidForRole("root_daemon", 0);
        expect((await migrateFortressAuditStoreSplit({ storage: f.storage, masterKey: master })).status).toBe("migrated");
      };
      if (schedule === "S0") {
        await write(f.log, "first"); await write(f.make(), "second"); await write(f.log, "final");
      } else if (schedule.startsWith("S9")) {
        if (schedule === "S9a") { await write(f.log, "first"); await write(f.log, "second"); }
        if (schedule === "S9b-stale") { await write(f.log, "first"); await write(f.make(), "second"); }
        if (schedule === "S9b-warm-empty" || schedule === "S9b-cold") {
          const foreign = f.make(); await write(foreign, "first"); await write(foreign, "second");
        }
        if (schedule !== "S9b-zero") boundaryHash = (await envelope(f)).entry_hash;
        await migrate();
        if (schedule === "S9b-cold") f.log = f.make();
        await write(f.log, "final");
      } else if (schedule.startsWith("S11")) {
        await f.storage.write("_audit", "legacy-1", bytes(encrypt(bytes({ ...ENTRY, timestamp: "2026-01-01T00:00:00.000Z" }), encryptionKey)));
        f.log = f.make({ integrityMode: schedule === "S11-strict" ? "strict" : "lenient" });
        hashes.set((await f.log.getChainHead()).entry_hash, "LEGACY_ROOT"); await write(f.log, "final");
      } else if (schedule === "S10-daemon") {
        await write(f.log, "first"); __testSetAuditWriterUidForRole("root_daemon", 0);
        await write(createDaemonAuditLog(f.storage, master, { checkpointInterval: 0, __testAuditGuardLockRoot: join(f.root, "guard") }), "daemon-first");
      } else {
        if (schedule === "S10-migration") await migrate();
        await write(f.log, "final");
      }
      const records: { namespace: string; envelope: PersistedAuditEnvelopeV2; payload: Record<string, unknown>; label: string }[] = [];
      for (const namespace of ["_audit", "_audit-daemon"]) {
        for (const { key } of await f.storage.list(namespace)) {
          if (!key.startsWith("entry-")) continue;
          const envelope: PersistedAuditEnvelopeV2 = JSON.parse(Buffer.from((await f.storage.read(namespace, key))!).toString());
          const payload = JSON.parse(Buffer.from(decrypt(JSON.parse(Buffer.from(fromBase64url(envelope.encrypted_payload_bytes)).toString()), encryptionKey)).toString());
          const label = `${namespace}:${payload.details?.step ?? payload.operation}`;
          hashes.set(envelope.entry_hash, envelope.sequence); records.push({ namespace, envelope, payload, label });
        }
      }
      // Pin every edge in each namespace; the split boundary and legacy root are explicit anchors.
      const entries = records.map(({ namespace, envelope }) => ({
        namespace, sequence: envelope.sequence,
        previous: envelope.prev_hash === boundaryHash ? "BOUNDARY" : hashes.get(envelope.prev_hash),
      }));
      const expected: Record<string, { sequence: number; previous: number | string }[]> = {
        _audit: schedule.startsWith("S11") ? [{ sequence: 2, previous: "LEGACY_ROOT" }]
          : schedule === "S0" ? [{ sequence: 1, previous: "GENESIS" }, { sequence: 2, previous: 1 }, { sequence: 3, previous: 2 }]
          : schedule.startsWith("S9") && schedule !== "S9b-zero"
            ? [{ sequence: 1, previous: "GENESIS" }, { sequence: 2, previous: 1 }, { sequence: 3, previous: "BOUNDARY" }]
            : [{ sequence: 1, previous: "GENESIS" }],
      };
      // Every migration creates one daemon genesis; an explicit daemon append does the same.
      const daemon = schedule.startsWith("S9") || schedule === "S10-migration" || schedule === "S10-daemon"
        ? [{ namespace: "_audit-daemon", sequence: 1, previous: "GENESIS" }] : [];
      expect(entries).toEqual([...expected._audit!.map(entry => ({ namespace: "_audit", ...entry })), ...daemon]);
    });
}

for (const evidence of ["boundary", "head", "migration", "suffix", "establishment-marker", "establishment-list", "body"] as const) {
  it(`deadline wins over delayed ${evidence} evidence with no late history or allocation`, async () => {
    const f = await fixture(true, { writeLockHoldDeadlineMs: 1_000 }); // Barriers fix the completion order; one second covers healthy filesystem latency on a loaded runner.
    if (evidence === "body") await append(f, 1, f.make());
    if (evidence === "suffix" || evidence === "boundary") await seal(f, 0, "GENESIS");
    const before = await snapshot(f); const cached = state(f.log);
    const entered = gate(); const release = gate(); const settled = gate();
    const delay = async <T>(read: () => Promise<T>): Promise<T> => { entered.release(); await release.wait; try { return await read(); } finally { settled.release(); } };
    if (evidence === "boundary") {
      const read = fs.readFile; let first = true;
      vi.spyOn(fs, "readFile").mockImplementation(((path: Parameters<typeof fs.readFile>[0], ...args: unknown[]) => {
        if (first && String(path) === auditStoreSplitBoundaryPath(f.path)) { first = false; return delay(() => (read as Function)(path, ...args)); }
        return (read as Function)(path, ...args);
      }) as typeof fs.readFile);
    } else if (evidence === "establishment-list") {
      const list = f.storage.list.bind(f.storage); let first = true;
      vi.spyOn(f.storage, "list").mockImplementation((ns, prefix) => { if (first && ns === "_audit_checkpoints") { first = false; return delay(() => list(ns, prefix)); } return list(ns, prefix); });
    } else {
      const read = f.storage.read.bind(f.storage); let first = true;
      const target = { head: HEAD, migration: MIGRATED, suffix: SUFFIX, "establishment-marker": ESTABLISHED, body: (await keys(f))[0] }[evidence];
      vi.spyOn(f.storage, "read").mockImplementation((ns, key) => { if (first && key === target) { first = false; return delay(() => read(ns, key)); } return read(ns, key); });
    }
    const pending = f.log.appendCritical(ENTRY); const rejected = expect(pending).rejects.toMatchObject({ name: "AuditLockHoldDeadlineError" });
    try { await entered.wait; await rejected; } finally { release.release(); await settled.wait; }
    // Drain the detached continuation's microtasks without a timer or poller.
    await new Promise<void>(resolve => setImmediate(resolve));
    expect(state(f.log)).toEqual(cached); expect(await snapshot(f)).toEqual(before);
  });
}
