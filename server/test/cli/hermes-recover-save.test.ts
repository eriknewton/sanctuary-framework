import { createHash } from "node:crypto";
import { spawn, type ChildProcess } from "node:child_process";
import { chmod, mkdtemp, mkdir, readdir, readFile, realpath, symlink, writeFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { Duplex } from "node:stream";
import { afterEach, describe, expect, it, vi } from "vitest";
import { runHermesRecoverSave } from "../../src/cli/hermes-recover-save.js";
import { IdentityManager } from "../../src/cognitive/tools.js";
import { createIdentity } from "../../src/core/identity.js";
import { derivePurposeKey } from "../../src/core/key-derivation.js";
import { fromBase64url } from "../../src/core/encoding.js";
import { establishMaster, unlockExistingMasterReadOnly } from "../../src/core/master-custody.js";
import { FilesystemStorage } from "../../src/storage/filesystem.js";
import { persistUserProvidedPassphrase } from "../../src/wrap/passphrase.js";
import { memoryProvenancePublicKeyFingerprint } from "../../src/sdw/memory-provenance-bad-signers.js";
import { PrivateFrameDecoder, encodePrivateFrame, MAX_PUBLIC_FRAME_BYTES, EXIT_STARTUP_REFUSED } from "../../src/hermes-memory-bridge/index.js";
import { AuditLog } from "../../src/operational/audit-log.js";
import { ReadOnlyStorageGuard } from "../../src/storage/read-only-guard.js";
import { SdwWorkingStateStore } from "../../src/sdw/working-state-store.js";
import { fortressIdFromStoragePath } from "../../src/dashboard/v1_1/wiring.js";
import { HERMES_INSERT_INTENT_KEY, HERMES_INSERT_INTENT_NAMESPACE, DEFAULT_MAX_CHUNK_CHARS, readHermesSaveIntent } from "../../src/sdw/adapters/sdw-memory-backend.js";
import { SDW_DOCUMENT_CORPUS_NAMESPACE } from "../../src/sdw/records.js";
import { EXIT_IMPORT_JOURNAL_NAMESPACE } from "../../src/storage/exit-import-journal.js";

const PASS = "operator recovery fixture passphrase";
const INTERRUPTED_CHUNKS = 2; // S2 requires two durable chunks before the process stops.
const SAVE_SENTENCE = "Remember the blue garden beside the library. ";
// One additional chunk beyond S2's stopping point guarantees an unfinished multi-chunk save.
const SAVE_TEXT = SAVE_SENTENCE.repeat(Math.ceil(DEFAULT_MAX_CHUNK_CHARS * (INTERRUPTED_CHUNKS + 1) / SAVE_SENTENCE.length));
const cleanups: Array<() => Promise<unknown>> = [];
const source = (path: string) => new URL(path, import.meta.url).href;
const cli = source("../../src/cli.ts");
const filesystem = source("../../src/storage/filesystem.ts");
const keychain = source("../setup/keychain-memory-store.ts");
type Fault = "S1" | "S2" | "S3" | "S3-unlink";

// Each child installs the injected credential store before importing the real dispatcher.
const preamble = `const { installInMemoryKeychainStore } = await import(${JSON.stringify(keychain)}); installInMemoryKeychainStore();`;

afterEach(async () => {
  vi.restoreAllMocks();
  const failures: unknown[] = [];
  while (cleanups.length) {
    try { await cleanups.pop()!(); } catch (cause) { failures.push(cause); }
  }
  if (failures.length) throw new AggregateError(failures, "Recovery fixture cleanup failed");
});

async function fixture(aliasedParent = false) {
  const root = await realpath(await mkdtemp(join(tmpdir(), "hermes-recover-")));
  cleanups.push(() => rm(root, { recursive: true, force: true }));
  await mkdir(join(root, "home"), { mode: 0o700 });
  if (aliasedParent) await symlink(root, join(root, "alias"), "dir");
  const home = join(root, ...(aliasedParent ? ["alias"] : []), "home");
  const fortressId = "fortress-recovery";
  const fortress = join(home, "Library", "Application Support", "Sanctuary", "Fortresses", fortressId);
  let dir = home;
  for (const part of ["Library", "Application Support", "Sanctuary", "Fortresses", fortressId, "state"]) {
    dir = join(dir, part);
    await mkdir(dir, { mode: 0o700 });
  }
  const storage = new FilesystemStorage(join(fortress, "state"));
  await persistUserProvidedPassphrase(PASS, { home, storagePath: fortress, platformOverride: "freebsd" });
  const custody = await establishMaster({ storage, passphrase: PASS,
    firstRun: { installMode: "headless", mintRecoveryKey: false } });
  try {
    const identities = new IdentityManager(storage, custody.masterKey);
    await identities.load();
    const { storedIdentity } = createIdentity("recovery fixture", derivePurposeKey(custody.masterKey, "identity-encryption"), "passphrase");
    await identities.save(storedIdentity);
    return { home, fortress, storage, env: { HOME: home, LANG: "C", TMPDIR: tmpdir(),
      HERMES_MEMORY_BRIDGE_IDENTITY: memoryProvenancePublicKeyFingerprint(fromBase64url(storedIdentity.public_key)),
      HERMES_MEMORY_AGENT_ID: "agent-recovery", HERMES_MEMORY_FORTRESS_ID: fortressId } };
  } finally { await custody.masterWriteBarrier?.release(); custody.masterKey.fill(0); }
}
type Fixture = Awaited<ReturnType<typeof fixture>>;

function observe(child: ChildProcess) {
  let stderr = "";
  let stdout = "";
  child.stderr?.on("data", bytes => { stderr += String(bytes); });
  child.stdout?.on("data", bytes => { stdout += String(bytes); });
  const exit = new Promise<number | null>((resolve, reject) => {
    child.once("error", reject);
    child.once("exit", code => resolve(code));
  });
  cleanups.push(async () => {
    if (child.exitCode === null && child.signalCode === null) child.kill("SIGKILL");
    await exit;
  });
  return { exit, stderr: () => stderr, stdout: () => stdout };
}

function bridge(f: Fixture, fault?: Fault) {
  const script = `${preamble}
    const { FilesystemStorage } = await import(${JSON.stringify(filesystem)});
    const { chmod } = await import("node:fs/promises");
    const write = FilesystemStorage.prototype.write;
    const del = FilesystemStorage.prototype.delete;
    let chunks = 0;
    const fault = ${JSON.stringify(fault ?? null)};
    FilesystemStorage.prototype.write = async function(ns,key,bytes) {
      const target = ns === ${JSON.stringify(SDW_DOCUMENT_CORPUS_NAMESPACE)} && key.startsWith('chunk.') && key.includes('.target.');
      if (target && fault === 'S1') throw new Error('first chunk refused');
      await write.call(this,ns,key,bytes);
      if (target && fault === 'S2' && ++chunks === ${INTERRUPTED_CHUNKS}) process.kill(process.pid,'SIGKILL');
    };
    FilesystemStorage.prototype.delete = async function(ns,key,secure) {
      if (fault === 'S1' && ns === ${JSON.stringify(SDW_DOCUMENT_CORPUS_NAMESPACE)}) throw new Error('rollback refused');
      if (fault === 'S3' && ns === ${JSON.stringify(HERMES_INSERT_INTENT_NAMESPACE)} && key === ${JSON.stringify(HERMES_INSERT_INTENT_KEY)}) throw new Error('intent delete refused');
      if (fault === 'S3-unlink' && ns === ${JSON.stringify(HERMES_INSERT_INTENT_NAMESPACE)} && key === ${JSON.stringify(HERMES_INSERT_INTENT_KEY)}) {
        await chmod(${JSON.stringify(join(f.fortress, "state", HERMES_INSERT_INTENT_NAMESPACE))}, 0o555); // Read and search remain allowed; unlink must fail.
      }
      return del.call(this,ns,key,secure);
    };
    process.env = ${JSON.stringify(f.env)};
    process.argv = [process.execPath, ${JSON.stringify(cli)}, 'hermes-memory-bridge', 'run', '--relay-fd', '3'];
    await import(${JSON.stringify(cli)});
  `;
  const child = spawn(process.execPath, ["--import", "tsx", "--input-type=module", "-e", script],
    { stdio: ["ignore", "pipe", "pipe", "pipe"], env: { ...process.env, VITEST: "true" } });
  const observed = observe(child);
  const socket = child.stdio[3] as Duplex;
  const decoder = new PrivateFrameDecoder();
  const frames: Record<string, unknown>[] = [];
  let wake: (() => void) | undefined;
  socket.on("data", (bytes: Buffer) => {
    decoder.push(bytes);
    for (;;) {
      const frame = decoder.next();
      if (frame.kind === "need_more") break;
      if (frame.kind === "fatal") throw frame.error;
      frames.push(JSON.parse(Buffer.from(frame.body).toString("utf8")) as Record<string, unknown>);
    }
    wake?.();
  });
  socket.on("error", () => undefined);
  const next = async () => {
    if (frames.length === 0) await Promise.race([
      new Promise<void>(resolve => { wake = resolve; }),
      observed.exit.then(() => { throw new Error(`bridge exited: ${observed.stderr()}`); }),
    ]);
    const frame = frames.shift();
    if (frame === undefined) throw new Error("missing bridge frame");
    return frame;
  };
  const send = (value: Record<string, unknown>) => socket.write(encodePrivateFrame(Buffer.from(JSON.stringify(value))));
  const call = async (name: string, args: Record<string, unknown>) => {
    send({ type: "accepted", connection_id: "c1" });
    send({ type: "frame", connection_id: "c1", frame_b64: Buffer.from(JSON.stringify({ type: "tools_call", request_id: "request", name, arguments: args })).toString("base64") });
    for (;;) {
      const frame = await next();
      if (frame.type === "probe") send({ type: "probe_reply", connection_id: "c1", nonce: frame.nonce });
      if (frame.type === "response") {
        const response = JSON.parse(Buffer.from(String(frame.result_b64), "base64").toString("utf8"));
        send({ type: "closed", connection_id: "c1" });
        return JSON.parse(response.payload.content[0].text) as Record<string, unknown>;
      }
    }
  };
  const stop = async () => { send({ type: "relay_shutdown" }); expect(await observed.exit, observed.stderr()).toBe(0); };
  return { ...observed, next, call, stop, child };
}

async function save(f: Fixture, passageId: string, text: string, fault?: Fault) {
  const b = bridge(f, fault);
  expect(await b.next()).toEqual({ type: "ready" });
  const result = b.call("memory_insert", { text, taint: "user_content", passage_id: passageId });
  if (fault === "S2") {
    await expect(result).rejects.toThrow("bridge exited");
    expect(b.child.signalCode).toBe("SIGKILL");
  } else {
    const response = await result;
    expect(response.outcome).toBe(fault ? "unconfirmed" : "saved");
    await b.stop();
  }
}

async function command(f: Fixture, apply = false, overrideArgv?: string[]) {
  const argv = overrideArgv ?? ["hermes", "recover-save", "--fortress", f.fortress, ...(apply ? ["--apply"] : [])];
  const script = `${preamble} process.argv = [process.execPath, ${JSON.stringify(cli)}, ...${JSON.stringify(argv)}]; await import(${JSON.stringify(cli)});`;
  const child = spawn(process.execPath, ["--import", "tsx", "--input-type=module", "-e", script], {
    stdio: ["ignore", "pipe", "pipe"], env: { ...process.env, HOME: f.home, SANCTUARY_PASSPHRASE: PASS, VITEST: "true", SANCTUARY_SKIP_UPDATE_CHECK: "1" },
  });
  const observed = observe(child);
  const code = await observed.exit;
  return { code, out: observed.stdout(), err: observed.stderr() };
}

async function direct(f: Fixture, apply = true) {
  let out = "";
  let err = "";
  const code = await runHermesRecoverSave({ argv: ["recover-save", "--fortress", f.fortress, ...(apply ? ["--apply"] : [])],
    env: { HOME: f.home, SANCTUARY_PASSPHRASE: PASS }, stdout: { write: value => { out += String(value); return true; } }, stderr: { write: value => { err += String(value); return true; } } });
  return { code, out, err };
}

async function hashes(root: string): Promise<Record<string, string>> {
  const result: Record<string, string> = {};
  async function visit(dir: string, prefix: string) {
    for (const entry of await readdir(dir, { withFileTypes: true })) {
      const name = prefix + entry.name;
      if (entry.isDirectory()) {
        result[name + "/"] = "directory";
        await visit(join(dir, entry.name), name + "/");
      }
      else if (entry.isFile()) result[name] = createHash("sha256").update(await readFile(join(dir, entry.name))).digest("hex");
    }
  }
  await visit(root, "");
  return result;
}

async function corpusBytes(f: Fixture): Promise<Record<string, Buffer>> {
  const dir = join(f.fortress, "state", SDW_DOCUMENT_CORPUS_NAMESPACE);
  return Object.fromEntries(await Promise.all((await readdir(dir)).map(async name => [name, await readFile(join(dir, name))])));
}

async function audit(f: Fixture) {
  const storage = new ReadOnlyStorageGuard(f.storage);
  const master = await unlockExistingMasterReadOnly(storage, { passphrase: PASS });
  try { return (await new AuditLog(storage, master, { readOnly: true }).query({ operation_type: "hermes_save_recovered" })).entries; }
  finally { master.fill(0); }
}

async function readIntent(f: Fixture) {
  const storage = new ReadOnlyStorageGuard(f.storage);
  const masterKey = await unlockExistingMasterReadOnly(storage, { passphrase: PASS });
  try {
    return await readHermesSaveIntent({ storage, masterKey, fortressId: fortressIdFromStoragePath(await realpath(f.fortress)) });
  } finally { masterKey.fill(0); }
}

async function refusedStartup(f: Fixture) {
  const b = bridge(f);
  expect(await b.exit).toBe(EXIT_STARTUP_REFUSED);
  expect(b.stderr()).toContain("startup refused");
}

describe("Hermes save operator recovery", () => {
  it("command unlink failure preserves a decryptable intent and retry restores readiness", async () => {
    const f = await fixture();
    await save(f, "target", SAVE_TEXT, "S1");
    const beforeIntent = await readIntent(f);
    expect(beforeIntent).not.toBeNull();
    const intentDir = join(f.fortress, "state", HERMES_INSERT_INTENT_NAMESPACE);
    try {
      await chmod(intentDir, 0o555); // Read and search remain allowed; unlink must fail.
      const result = await command(f, true);
      expect(result.code).not.toBe(0);
      expect(result.err).toBe("Recovery did not finish; retry --apply if the intent is still readable.\n");
      expect(await readIntent(f)).toEqual(beforeIntent);
      await refusedStartup(f);
    } finally { await chmod(intentDir, 0o700); }
    expect(await command(f, true)).toMatchObject({ code: 0, out: expect.stringContaining("rolled_back") });
    const b = bridge(f);
    expect(await b.next()).toEqual({ type: "ready" });
    await b.stop();
  });

  it("bridge unlink failure preserves a decryptable completed intent and recovery keeps the save", async () => {
    const f = await fixture();
    const intentDir = join(f.fortress, "state", HERMES_INSERT_INTENT_NAMESPACE);
    try {
      await save(f, "target", SAVE_TEXT, "S3-unlink");
      expect(await readIntent(f)).toMatchObject({ documentId: "mem.agent-recovery.target" });
      await refusedStartup(f);
      const before = await hashes(f.fortress);
      expect(await command(f)).toMatchObject({ code: 0, out: expect.stringContaining("completed; --apply would keep") });
      expect(await hashes(f.fortress)).toEqual(before);
    } finally { await chmod(intentDir, 0o700); }
    const beforeCorpus = await corpusBytes(f);
    expect(await command(f, true)).toMatchObject({ code: 0, out: expect.stringContaining("completed; kept") });
    expect(await corpusBytes(f)).toEqual(beforeCorpus);
    const b = bridge(f);
    expect(await b.next()).toEqual({ type: "ready" });
    expect(JSON.stringify(await b.call("memory_get", { passage_id: "target" }))).toContain(SAVE_TEXT);
    await b.stop();
  });

  it("real startup prints the fixed unfinished-save recovery sentence on its own line", async () => {
    const f = await fixture();
    await save(f, "target", SAVE_TEXT, "S1");
    const b = bridge(f);
    expect(await b.exit).toBe(EXIT_STARTUP_REFUSED);
    expect(b.stderr().split("\n")).toContain("An earlier save did not finish; run `sanctuary hermes recover-save --fortress <dir>` to recover it.");
  });

  it("canonical fortress path reads a bridge intent through an accepted parent alias", async () => {
    const f = await fixture(true);
    expect(await realpath(f.fortress)).not.toBe(f.fortress);
    await save(f, "target", SAVE_TEXT, "S3");
    const before = await hashes(f.fortress);
    expect(await command(f)).toMatchObject({ code: 0, out: expect.stringContaining("completed; --apply would keep") });
    expect(await hashes(f.fortress)).toEqual(before);
    expect(await command(f, true)).toMatchObject({ code: 0, out: expect.stringContaining("completed; kept") });
    const b = bridge(f);
    expect(await b.next()).toEqual({ type: "ready" });
    await b.stop();
  });

  it("nothing to recover creates no files or directories in either mode", async () => {
    const f = await fixture();
    const b = bridge(f);
    expect(await b.next()).toEqual({ type: "ready" });
    await b.stop();
    const before = await hashes(f.fortress);
    expect(before[`state/${EXIT_IMPORT_JOURNAL_NAMESPACE}/`]).toBeUndefined();
    for (const apply of [false, true]) {
      expect(await command(f, apply)).toMatchObject({ code: 0, out: "nothing to recover\n" });
      expect(await hashes(f.fortress)).toEqual(before);
    }
  });

  it.each(["S1", "S2", "S3"] as const)("%s real save: report is unchanged, dispatcher apply restores readiness and recall", async state => {
    const f = await fixture();
    await save(f, "other", "An unrelated blue garden memory.");
    const others = await corpusBytes(f);
    await save(f, "target", SAVE_TEXT, state);
    expect(await f.storage.read(HERMES_INSERT_INTENT_NAMESPACE, HERMES_INSERT_INTENT_KEY)).not.toBeNull();
    const corpus = await f.storage.list(SDW_DOCUMENT_CORPUS_NAMESPACE);
    const chunks = corpus.filter(row => row.key.startsWith("chunk.") && row.key.includes(".target."));
    expect(chunks.length).toBe(state === "S1" ? 0 : state === "S2" ? INTERRUPTED_CHUNKS : Math.ceil(SAVE_TEXT.length / DEFAULT_MAX_CHUNK_CHARS));
    expect(corpus.some(row => row.key === "doc.mem.agent-recovery.target")).toBe(state === "S3");
    await refusedStartup(f);
    const before = await hashes(f.fortress);
    const beforeCorpus = await corpusBytes(f);
    const report = await command(f);
    expect(report.code, report.err).toBe(0);
    expect(report.out.split(";")[0]).toBe(state === "S3" ? "completed" : "not_completed");
    expect(report.out).toContain("--apply would");
    expect(await hashes(f.fortress)).toEqual(before);
    const applied = await command(f, true);
    expect(applied.code, applied.err).toBe(0);
    process.stdout.write(`${state} report: ${report.out.trim()}\n${state} apply: ${applied.out.trim()}\n`);
    const afterCorpus = await corpusBytes(f);
    for (const [name, digest] of Object.entries(others)) expect(afterCorpus[name]).toEqual(digest);
    if (state === "S3") expect(afterCorpus).toEqual(beforeCorpus);
    else expect(afterCorpus).toEqual(others);
    expect(await f.storage.read(HERMES_INSERT_INTENT_NAMESPACE, HERMES_INSERT_INTENT_KEY)).toBeNull();
    const rows = await audit(f);
    expect(rows).toHaveLength(1);
    expect(rows[0]!.details).toEqual({ outcome: state === "S3" ? "kept" : "rolled_back", records_removed: (state === "S2" ? INTERRUPTED_CHUNKS : 0) + 1 });
    expect(JSON.stringify(rows)).not.toContain("target");
    expect(JSON.stringify(rows)).not.toContain("blue garden");
    await save(f, "new", "A new blue garden memory.");
    const restarted = bridge(f);
    expect(await restarted.next()).toEqual({ type: "ready" });
    const recall = await restarted.call("memory_recall", { query: "blue garden" });
    expect(JSON.stringify(recall)).toContain("unrelated blue garden");
    expect(JSON.stringify(recall)).toContain("new blue garden");
    expect(JSON.stringify(recall).includes("Remember the blue garden")).toBe(state === "S3");
    await restarted.stop();
    const settled = await hashes(f.fortress);
    expect(await command(f, true)).toMatchObject({ code: 0, out: "nothing to recover\n" });
    expect(await hashes(f.fortress)).toEqual(settled);
  });

  it("recovers an interrupted exit import before save classification or corpus deletion, and refuses unrecoverable imports", async () => {
    const f = await fixture();
    await save(f, "target", SAVE_TEXT, "S2");
    const importId = "planted-save-recovery-import";
    const journalStorage = new FilesystemStorage(join(f.fortress, "state"));
    // Same plaintext journal shape as fortress-open-recovery-wiring.test.ts's open-context fixture.
    const journal = { import_id: importId, identity_id: "operator", started_at: new Date().toISOString(), snapshots: [] };
    await journalStorage.write(EXIT_IMPORT_JOURNAL_NAMESPACE, importId, Buffer.from("{}\n"));
    const before = await hashes(f.fortress);
    const events: Array<{ kind: "read" | "delete"; pendingImports: number }> = [];
    let refuseClassification = false;
    const originalRead = FilesystemStorage.prototype.read;
    const originalDelete = FilesystemStorage.prototype.delete;
    vi.spyOn(FilesystemStorage.prototype, "read").mockImplementation(async function(this: FilesystemStorage, ns, key) {
      if (ns === SDW_DOCUMENT_CORPUS_NAMESPACE || (ns === HERMES_INSERT_INTENT_NAMESPACE && key === HERMES_INSERT_INTENT_KEY)) {
        events.push({ kind: "read", pendingImports: (await this.list(EXIT_IMPORT_JOURNAL_NAMESPACE)).length });
        if (refuseClassification) throw new Error("classification read refused");
      }
      return originalRead.call(this, ns, key);
    });
    vi.spyOn(FilesystemStorage.prototype, "delete").mockImplementation(async function(this: FilesystemStorage, ns, key, secure) {
      if (ns === SDW_DOCUMENT_CORPUS_NAMESPACE) {
        events.push({ kind: "delete", pendingImports: (await this.list(EXIT_IMPORT_JOURNAL_NAMESPACE)).length });
      }
      return originalDelete.call(this, ns, key, secure);
    });

    const refused = await direct(f);
    expect(refused.code, refused.err).toBe(1);
    expect(refused.err).toContain("exit-import recovery did not finish");
    expect(events).toEqual([]);
    expect(await hashes(f.fortress)).toEqual(before);
    expect(await audit(f)).toHaveLength(0);

    await journalStorage.write(EXIT_IMPORT_JOURNAL_NAMESPACE, importId, Buffer.from(JSON.stringify(journal) + "\n"));
    const beforeReport = await hashes(f.fortress);
    const report = await direct(f, false);
    expect(report.code, report.err).toBe(1);
    expect(events).toEqual([]);
    expect(await hashes(f.fortress)).toEqual(beforeReport);

    const beforeCorpus = await corpusBytes(f);
    refuseClassification = true;
    const unclassified = await direct(f);
    expect(unclassified).toMatchObject({ code: 1, err: "The exit import was recovered, but save recovery did not proceed.\n" });
    expect(await f.storage.list(EXIT_IMPORT_JOURNAL_NAMESPACE)).toHaveLength(0);
    expect(events).toEqual([{ kind: "read", pendingImports: 0 }]);
    expect(await corpusBytes(f)).toEqual(beforeCorpus);
    expect(await audit(f)).toHaveLength(0);

    refuseClassification = false;
    events.length = 0;
    await journalStorage.write(EXIT_IMPORT_JOURNAL_NAMESPACE, importId, Buffer.from(JSON.stringify(journal) + "\n"));
    const applied = await direct(f);
    expect(applied.code, applied.err).toBe(0);
    expect(applied.out).toContain("not_completed; rolled_back");
    expect(events.some(event => event.kind === "read")).toBe(true);
    expect(events.some(event => event.kind === "delete")).toBe(true);
    expect(events.every(event => event.pendingImports === 0)).toBe(true);
    expect(await f.storage.list(EXIT_IMPORT_JOURNAL_NAMESPACE)).toHaveLength(0);
    expect(await f.storage.read(HERMES_INSERT_INTENT_NAMESPACE, HERMES_INSERT_INTENT_KEY)).toBeNull();
    expect(await corpusBytes(f)).toEqual({});
    expect(await audit(f)).toHaveLength(1);
  });

  it("intent is last: interrupted rollback still refuses startup and retry completes", async () => {
    const f = await fixture();
    await save(f, "target", SAVE_TEXT, "S2");
    const original = FilesystemStorage.prototype.delete;
    const events: string[] = [];
    const spy = vi.spyOn(FilesystemStorage.prototype, "delete").mockImplementation(async function(this: FilesystemStorage, ns, key, secure) {
      events.push(ns);
      if (events.length > 1) throw new Error("delete interrupted");
      return original.call(this, ns, key, secure);
    });
    expect((await direct(f)).code).toBe(1);
    spy.mockRestore();
    expect(events[0]).toBe(SDW_DOCUMENT_CORPUS_NAMESPACE);
    expect(events).not.toContain(HERMES_INSERT_INTENT_NAMESPACE);
    expect(await f.storage.read(HERMES_INSERT_INTENT_NAMESPACE, HERMES_INSERT_INTENT_KEY)).not.toBeNull();
    await refusedStartup(f);
    expect(await audit(f)).toHaveLength(0);
    expect((await direct(f)).code).toBe(0);
    expect(await audit(f)).toHaveLength(1);
    expect(await command(f, true)).toMatchObject({ code: 0, out: "nothing to recover\n" });
  });

  it("live bridge refuses report and apply with identical fortress hashes", async () => {
    const f = await fixture();
    const b = bridge(f);
    expect(await b.next()).toEqual({ type: "ready" });
    // The bridge is idle here: only its lifetime custody lease is held.
    const before = await hashes(f.fortress);
    for (const apply of [false, true]) {
      const result = await command(f, apply);
      expect(result.code).not.toBe(0);
      expect(result.err).toContain("exclusive custody");
      expect(await hashes(f.fortress)).toEqual(before);
    }
    await b.stop();
    expect(await audit(f)).toHaveLength(0);
  });

  it.each(["intent", "invalid-intent", "duplicate-chunk", "too-many-chunks", "chunk", "provenance", "document", "missing-chunk", "missing-provenance"])("unclassifiable %s refuses without mutation or audit", async damage => {
    const f = await fixture();
    await save(f, "target", SAVE_TEXT, "S3");
    const custody = await establishMaster({ storage: f.storage, passphrase: PASS });
    try {
      if (["invalid-intent", "duplicate-chunk", "too-many-chunks"].includes(damage)) {
        const store = new SdwWorkingStateStore({ storage: f.storage, masterKey: custody.masterKey, fortressId: fortressIdFromStoragePath(await realpath(f.fortress)) });
        const record = await store.get("tool", "hermes-insert-intent");
        if (record?.state.kind !== "task_checkpoint") throw new Error("missing checkpoint");
        const nextSteps = damage === "invalid-intent" ? ["doc.mem.agent-recovery.other"]
          : Array.from({ length: damage === "duplicate-chunk" ? record.state.next_steps!.length
            : Math.ceil(MAX_PUBLIC_FRAME_BYTES / DEFAULT_MAX_CHUNK_CHARS) + 1 }, () => record.state.kind === "task_checkpoint" ? record.state.next_steps![0]! : "");
        await store.put({ ...record, state: { ...record.state, next_steps: nextSteps } }, "system_generated");
      } else {
        const ns = damage === "intent" ? HERMES_INSERT_INTENT_NAMESPACE : SDW_DOCUMENT_CORPUS_NAMESPACE;
        const prefix = damage.includes("chunk") ? "chunk." : damage.includes("provenance") ? "prov." : "doc.";
        const key = damage === "intent" ? HERMES_INSERT_INTENT_KEY : (await f.storage.list(ns)).find(row => row.key.startsWith(prefix))!.key;
        if (damage.startsWith("missing")) await f.storage.delete(ns, key, true);
        else await writeFile(join(f.fortress, "state", ns, `${key}.enc`), "unreadable fixture");
      }
    } finally { await custody.masterWriteBarrier?.release(); custody.masterKey.fill(0); }
    const before = await hashes(f.fortress);
    for (const apply of [false, true]) {
      const result = await direct(f, apply);
      expect(result).toMatchObject({ code: 1, err: "The save could not be classified and nothing was changed.\n" });
      expect(await hashes(f.fortress)).toEqual(before);
    }
    expect(await audit(f)).toHaveLength(0);
  });

  it("audit failure after recovery is nonzero and does not reverse the action", async () => {
    const f = await fixture();
    await save(f, "target", SAVE_TEXT, "S3");
    const before = await hashes(join(f.fortress, "state", SDW_DOCUMENT_CORPUS_NAMESPACE));
    const spy = vi.spyOn(AuditLog.prototype, "appendCritical").mockRejectedValue(new Error("audit refused"));
    const result = await direct(f);
    spy.mockRestore();
    expect(result.code).toBe(1);
    expect(result.err).toContain("audit append");
    expect(await f.storage.read(HERMES_INSERT_INTENT_NAMESPACE, HERMES_INSERT_INTENT_KEY)).toBeNull();
    expect(await hashes(join(f.fortress, "state", SDW_DOCUMENT_CORPUS_NAMESPACE))).toEqual(before);
    const b = bridge(f);
    expect(await b.next()).toEqual({ type: "ready" });
    await b.stop();
  });

  it("requires fortress values by name and lists recover-save in hermes help", async () => {
    for (const argv of [["recover-save"], ["recover-save", "--fortress", "--json"]]) {
      let err = "";
      expect(await runHermesRecoverSave({ argv, stderr: { write: value => { err += String(value); return true; } } })).toBe(2);
      expect(err).toContain("--fortress");
    }
    const f = await fixture();
    expect(await command(f, false, ["hermes", "--help"])).toMatchObject({ code: 0, out: expect.stringContaining("hermes recover-save") });
    expect((await command(f, false, ["--help"])).out).toContain("hermes               recover-save");
    let out = "";
    expect(await runHermesRecoverSave({ argv: ["--help"], stdout: { write: value => { out += String(value); return true; } } })).toBe(0);
    expect(out).toContain("hermes recover-save");
  });
});
