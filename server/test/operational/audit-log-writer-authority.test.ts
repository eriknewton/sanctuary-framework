import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import * as fs from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { AuditLog, AuditPersistenceError } from "../../src/operational/audit-log.js";
import { FilesystemStorage } from "../../src/storage/filesystem.js";
import { acquireMasterWriteBarrier } from "../../src/storage/cross-process-lock.js";
import { createDaemonAuditLog, migrateFortressAuditStoreSplit } from "../../src/operational/audit-store-split.js";
import { seedStoredIdentity } from "../helpers/signing-fixture.js";
import { encrypt } from "../../src/core/encryption.js";
import { derivePurposeKey } from "../../src/core/key-derivation.js";
import { appendCastleWallCliAuditBestEffort } from "../../src/cli/castle-wall.js";
import { initializeTestCustody } from "../helpers/custody-fixture.js";
import { Writable } from "node:stream";

vi.mock("node:fs/promises", async (original) => {
  const actual = await original<typeof import("node:fs/promises")>();
  return { ...actual, mkdir: vi.fn(actual.mkdir), link: vi.fn(actual.link), open: vi.fn(actual.open),
    lstat: vi.fn(actual.lstat), stat: vi.fn(actual.stat) };
});

const master = new Uint8Array(32).fill(7); // AES-256 fixture key.
const entry = { layer: "l1" as const, operation: "authority-test", identity_id: "test", result: "success" as const, details: {} };
let root: string;
const leases: Array<{ release(): Promise<void> }> = [];

async function snapshot(path: string): Promise<Record<string, string>> {
  const result: Record<string, string> = {};
  async function walk(dir: string, prefix: string): Promise<void> {
    for (const name of (await fs.readdir(dir)).sort()) {
      const key = `${prefix}/${name}`;
      const child = join(dir, name);
      const metadata = await fs.lstat(child);
      result[key] = metadata.isSymbolicLink() ? `link:${await fs.readlink(child)}` : metadata.isDirectory() ? "directory" : (await fs.readFile(child)).toString("base64");
      if (metadata.isDirectory()) await walk(child, key);
    }
  }
  await walk(path, "");
  return result;
}

beforeEach(async () => {
  root = await fs.mkdtemp(join(tmpdir(), "audit-authority-"));
  vi.stubEnv("HOME", root);
  // Read-consistency retries are deterministic microtasks, without wall-clock waits.
  const realSetTimeout = globalThis.setTimeout;
  vi.spyOn(globalThis, "setTimeout").mockImplementation(((fn: (...args: unknown[]) => void, delay?: number, ...args: unknown[]) => {
    if (delay === 10) { // Must match AUDIT_READ_CONSISTENCY_RETRY_MS in audit-log.ts.
      queueMicrotask(() => fn(...args));
      return { unref() {} } as NodeJS.Timeout;
    }
    return realSetTimeout(fn, delay, ...args);
  }) as typeof setTimeout);
});

async function pretendOwners(owners: Record<string, number>): Promise<void> {
  const actual = await vi.importActual<typeof import("node:fs/promises")>("node:fs/promises");
  vi.mocked(fs.lstat).mockImplementation((async (...args: Parameters<typeof fs.lstat>) => {
    const identity = await actual.lstat(...args);
    const uid = owners[String(args[0])];
    return uid === undefined ? identity : Object.assign(identity, { uid });
  }) as typeof fs.lstat);
}

describe.skipIf(process.platform !== "linux" || process.getuid?.() === 0)("writer admission and observational loads", () => {
  it("an operator daemon-chain reader reports a hard finding without changing lock evidence", async () => {
    const storage = new FilesystemStorage(join(root, "state"));
    const writer = createDaemonAuditLog(storage, master, { __testAuditAuthorityUid: () => 0, checkpointInterval: 0 });
    for (const operation of ["one", "two", "three"]) await writer.appendCritical({ ...entry, operation });
    await storage.delete("_audit-daemon", (await storage.list("_audit-daemon")).at(-1)!.key);
    await fs.writeFile(join(storage.namespacePath("_audit-daemon"), ".audit-write.lock"), JSON.stringify({ pid: 2_147_483_647 }));
    const before = await snapshot(root);
    const reader = createDaemonAuditLog(storage, master, { integrityMode: "lenient" });
    expect((await reader.getIntegrityFindings()).map(({ kind }) => kind)).toContain("tail_anchor_invalid");
    expect(await snapshot(root)).toEqual(before);
  });

  it.each([0, 1001])("boot-token writer admission with uid %i", async (uid) => {
    const storage = new FilesystemStorage(join(root, "boot-chain"));
    const config = { chainWriterRole: "boot_token" as const, __testAuditAuthorityUid: () => uid };
    const log = new AuditLog(storage, master, config);
    if (uid === 0) {
      await log.appendCritical(entry);
      expect(await storage.list("_audit")).toHaveLength(1);
    } else {
      const before = await snapshot(root);
      await expect(log.appendCritical(entry)).rejects.toMatchObject({ name: "AuditWriterAuthorityError" });
      expect(await snapshot(root)).toEqual(before);
    }
  });

  it("the CLI best-effort audit helper resolves when writer authority is refused", async () => {
    const passphrase = "authority-fixture-passphrase";
    await initializeTestCustody(root, { passphrase });
    let warning = "";
    const err = new Writable({ write(chunk, _encoding, done) { warning += String(chunk); done(); } });
    await expect(appendCastleWallCliAuditBestEffort("authority-refusal", {}, root,
      { SANCTUARY_PASSPHRASE: passphrase }, err, {
        __testBeforeAuditAppend: async (session) => {
          // The session already owns its barrier; change only the authority observation.
          await pretendOwners({ [join(root, "state", "_meta")]: 0 });
          expect(session.storage).toBeDefined();
        },
      })).resolves.toBeUndefined();
    expect(warning).toContain("audit writer role operator");
    await expect(fs.lstat(join(root, "state", "_audit"))).rejects.toMatchObject({ code: "ENOENT" });
  });

  it("matching createOwner never authorizes root on an operator chain", async () => {
    const storage = new FilesystemStorage(join(root, "state"));
    await fs.mkdir(storage.namespacePath("_meta"), { recursive: true });
    const before = await snapshot(root);
    const config = { __testAuditAuthorityUid: () => 0, createOwner: { uid: process.getuid!(), gid: process.getgid!() } };
    await expect(new AuditLog(storage, master, config).appendCritical(entry)).rejects.toMatchObject({ name: "AuditWriterAuthorityError", classification: "permission_denied" });
    expect(await snapshot(root)).toEqual(before);
  });

  it.each([0, 1001])("daemon genesis with authority uid %i", async (uid) => {
    const storage = new FilesystemStorage(join(root, "state"));
    const config = { __testAuditAuthorityUid: () => uid, checkpointInterval: 0 };
    const log = createDaemonAuditLog(storage, master, { ...config, chainWriterRole: "operator" });
    const before = await snapshot(root);
    if (uid === 0) {
      await log.appendCritical(entry);
      expect(await storage.list("_audit-daemon")).toHaveLength(1);
    } else {
      vi.mocked(fs.mkdir).mockClear();
      await expect(log.appendCritical(entry)).rejects.toMatchObject({ name: "AuditWriterAuthorityError" });
      expect(vi.mocked(fs.mkdir)).not.toHaveBeenCalled();
      expect(await snapshot(root)).toEqual(before);
    }
  });

  it("admits a root daemon and repairs its custody remnant after admission", async () => {
    const storage = new FilesystemStorage(join(root, "state"));
    for (const ns of ["_audit-daemon", "_audit-daemon_checkpoints", "_audit-daemon_meta"]) await fs.mkdir(storage.namespacePath(ns), { recursive: true });
    const owner = { uid: process.getuid!(), gid: process.getgid!() };
    const repaired = new Set<string>();
    const handback = vi.fn(async (_first: string, leaf: string) => { repaired.add(leaf); });
    const log = createDaemonAuditLog(storage, master, {
      __testAuditAuthorityUid: () => 0, createOwner: owner, createOwnerChown: async () => {}, createOwnerChownDirChain: handback,
      namespaceDirLstat: async (path) => ({ uid: path.endsWith("state") || repaired.has(path) ? owner.uid : 0, gid: owner.gid, isDirectory: () => true, isSymbolicLink: () => false }),
    });
    await log.appendCritical(entry);
    expect(handback).toHaveBeenCalledTimes(3); // Entry, checkpoint and metadata directories.
  });

  it.each(["existing", "absent-root", "foreign-ancestor", "meta-owner"])("operator owner resolution: %s", async (shape) => {
    const state = join(root, "state");
    const storage = new FilesystemStorage(state);
    if (shape === "existing" || shape === "meta-owner") await fs.mkdir(storage.namespacePath("_meta"), { recursive: true });
    await pretendOwners(shape === "existing" ? { [state]: 0, [storage.namespacePath("_meta")]: 0 }
      : shape === "absent-root" ? { [root]: 0 }
      : shape === "meta-owner" ? { [state]: 0 } : {});
    const before = await snapshot(root);
    const config = { __testAuditAuthorityUid: () => 0, checkpointInterval: 0 };
    if (shape === "foreign-ancestor" || shape === "meta-owner") {
      await expect(new AuditLog(storage, master, config).appendCritical(entry)).rejects.toMatchObject({ name: "AuditWriterAuthorityError" });
      expect(await snapshot(root)).toEqual(before);
      if (shape === "meta-owner") await new AuditLog(storage, master).appendCritical(entry);
    } else {
      await new AuditLog(storage, master, config).appendCritical(entry);
      expect(await storage.list("_audit")).toHaveLength(1);
    }
  });

  it("refuses an authority-owned lexical storage-root symlink", async () => {
    const foreign = join(root, "foreign");
    await fs.mkdir(foreign);
    await fs.symlink(foreign, join(root, "alias"));
    const storage = new FilesystemStorage(join(root, "alias"));
    const before = await snapshot(root);
    await expect(new AuditLog(storage, master).appendCritical(entry)).rejects.toMatchObject({ name: "AuditWriterAuthorityError" });
    expect(await snapshot(root)).toEqual(before);
  });

  it("refuses daemon namespace aliases before changing operator bytes or names", async () => {
    const storage = new FilesystemStorage(join(root, "state"));
    await new AuditLog(storage, master).appendCritical(entry);
    for (const [daemon, operator] of [["_audit-daemon", "_audit"], ["_audit-daemon_checkpoints", "_audit_checkpoints"], ["_audit-daemon_meta", "_meta"]]) {
      await fs.symlink(storage.namespacePath(operator!), storage.namespacePath(daemon!));
    }
    const before = await snapshot(root);
    const config = { __testAuditAuthorityUid: () => 0 };
    await expect(createDaemonAuditLog(storage, master, config).appendCritical(entry)).rejects.toMatchObject({ name: "AuditWriterAuthorityError" });
    expect(await snapshot(root)).toEqual(before);
  });

  for (const shape of ["legacy", "truncated", "signing-recovery"] as const) {
    it(`unauthorized ${shape} load observes without writes; migration probe preserves chain evidence`, async () => {
      const storage = new FilesystemStorage(join(root, "state"));
      if (shape === "legacy") {
        const payload = Buffer.from(JSON.stringify({ ...entry, timestamp: "2026-01-01T00:00:00.000Z" }));
        await storage.write("_audit", "1700000000000-0", Buffer.from(JSON.stringify(encrypt(payload, derivePurposeKey(master, "audit-log")))));
      } else {
        if (shape === "signing-recovery") await seedStoredIdentity(storage, master);
        const writer = new AuditLog(storage, master, { checkpointInterval: shape === "signing-recovery" ? 1 : 0 });
        for (const operation of ["one", "two", "three"]) await writer.appendCritical({ ...entry, operation });
        if (shape === "truncated") await storage.delete("_audit", (await storage.list("_audit")).at(-1)!.key);
        else {
          await storage.delete("_audit_checkpoints", "__signing_latch_v2");
          await storage.delete("_audit_checkpoints", "__signing_head");
        }
      }
      await fs.mkdir(storage.namespacePath("_meta"), { recursive: true });
      const before = await snapshot(root);
      const config = { integrityMode: "lenient" as const, __testAuditAuthorityUid: () => 0 };
      const findings = await new AuditLog(storage, master, config).getIntegrityFindings();
      expect(await snapshot(root)).toEqual(before);
      if (shape === "signing-recovery") {
        const messages = findings.filter(({ kind }) => kind.endsWith("_recovered")).map(({ message }) => message);
        expect(messages.length).toBeGreaterThan(0);
        for (const message of messages) expect(message).toContain("performs no recovery writes");
      }
      // Deny the daemon genesis after the production migration probe; isolate probe effects.
      await expect(migrateFortressAuditStoreSplit({ storage, masterKey: master })).rejects.toThrow();
      expect(await snapshot(root)).toEqual(before);
    });
  }

  it("an authorized mutable reader preserves a dead lock and writes one integrity alert", async () => {
    const storage = new FilesystemStorage(join(root, "state"));
    const writer = new AuditLog(storage, master, { checkpointInterval: 0 });
    for (const operation of ["one", "two", "three"]) await writer.appendCritical({ ...entry, operation });
    await storage.delete("_audit", (await storage.list("_audit")).at(-1)!.key);
    await fs.writeFile(join(storage.namespacePath("_audit"), ".audit-write.lock"), JSON.stringify({ pid: 2_147_483_647 }));
    const before = await snapshot(root);
    const reader = new AuditLog(storage, master, { integrityMode: "lenient" });
    await reader.getIntegrityFindings(); await reader.getIntegrityFindings();
    const after = await snapshot(root);
    for (const [path, bytes] of Object.entries(before)) expect(after[path]).toBe(bytes);
    expect(Object.keys(after).filter((path) => !(path in before))).toEqual(["/state/_audit_integrity_alert", "/state/_audit_integrity_alert/audit-integrity-alert.log.enc"]);
    const alert = await storage.read("_audit_integrity_alert", "audit-integrity-alert.log");
    expect(Buffer.from(alert!).toString().trim().split("\n")).toHaveLength(1);
  });

  it("a stale decision followed by a different inode reports in progress without removal", async () => {
    const storage = new FilesystemStorage(join(root, "state"));
    await fs.mkdir(storage.namespacePath("_audit"), { recursive: true });
    const lock = join(storage.namespacePath("_audit"), ".audit-write.lock");
    await fs.writeFile(lock, JSON.stringify({ pid: 2_147_483_647 }));
    const actual = await vi.importActual<typeof import("node:fs/promises")>("node:fs/promises");
    let replaced = false;
    vi.mocked(fs.stat).mockImplementation((async (...args: Parameters<typeof fs.stat>) => {
      if (String(args[0]) === lock && !replaced) {
        replaced = true;
        await fs.rename(lock, `${lock}.old`);
        await fs.writeFile(lock, "replacement");
      }
      return actual.stat(...args);
    }) as typeof fs.stat);
    const log = new AuditLog(storage, master, { readOnly: true });
    expect(await (log as any).isAuditWriterInProgress()).toBe(true);
    expect(await fs.readFile(lock, "utf8")).toBe("replacement");
    expect(await fs.readFile(`${lock}.old`, "utf8")).toContain("2147483647");
  });
});

afterEach(async () => {
  for (const lease of leases.splice(0)) await lease.release();
  vi.restoreAllMocks();
  vi.unstubAllEnvs();
  await fs.rm(root, { recursive: true, force: true });
});

describe.skipIf(process.platform !== "linux" || process.getuid?.() === 0)("audit writer authority", () => {
  it("R1: a root-simulated critical append on the operator chain is refused before any namespace or lock-file operation", async () => {
    const storage = new FilesystemStorage(join(root, "state"));
    leases.push(await acquireMasterWriteBarrier(storage, "_meta", "custody-master-rotation", {
      __testGetuid: () => 0, degradeOnEnvironmentalLoss: "read-only",
    }));
    const before = await snapshot(root);
    vi.mocked(fs.mkdir).mockClear(); vi.mocked(fs.link).mockClear(); vi.mocked(fs.open).mockClear();
    const config = { checkpointInterval: 0, __testAuditAuthorityUid: () => 0 };
    const log = new AuditLog(storage, master, config);
    await expect(log.appendCritical(entry)).rejects.toBeInstanceOf(AuditPersistenceError);
    const namespaces = ["_audit", "_audit_checkpoints", "_meta"].map((name) => storage.namespacePath(name));
    expect.soft(vi.mocked(fs.mkdir).mock.calls.filter(([path]) => namespaces.includes(String(path)))).toHaveLength(0);
    expect.soft(vi.mocked(fs.link).mock.calls.filter(([from, to]) => [from, to].some((path) => String(path).startsWith(`${storage.namespacePath("_audit")}/`)))).toHaveLength(0);
    expect.soft(vi.mocked(fs.open).mock.calls.filter(([path, flags]) => flags === "wx" && String(path).startsWith(`${storage.namespacePath("_audit")}/`))).toHaveLength(0);
    const after = await snapshot(root);
    expect.soft(Object.keys(after).filter((name) => name.split("/").at(-1)!.startsWith(".audit-write.lock"))).toEqual([]);
    expect.soft(after).toEqual(before);
  });

  it("R2: no reader of a damaged operator chain removes a lock", async () => {
    const source = join(root, "source");
    const storage = new FilesystemStorage(join(source, "state"));
    const writer = new AuditLog(storage, master, { checkpointInterval: 0 });
    for (const operation of ["one", "two", "three"]) await writer.appendCritical({ ...entry, operation });
    const keys = (await storage.list("_audit")).map(({ key }) => key);
    await storage.delete("_audit", keys.at(-1)!);
    // Linux pid_max is below this signed pid ceiling; the holder cannot exist.
    await fs.writeFile(join(storage.namespacePath("_audit"), ".audit-write.lock"), JSON.stringify({ pid: 2_147_483_647, acquired_at: "2000-01-01T00:00:00.000Z" }));
    const findings: string[][] = [];
    for (const [name, uid, readOnly] of [["unauthorized", 0, false], ["readonly", process.getuid!(), true]] as const) {
      const copy = join(root, name);
      await fs.cp(source, copy, { recursive: true });
      const copyStorage = new FilesystemStorage(join(copy, "state"));
      leases.push(await acquireMasterWriteBarrier(copyStorage, "_meta", "custody-master-rotation", {
        __testGetuid: () => 0, degradeOnEnvironmentalLoss: "read-only",
      }));
      const before = await snapshot(copy);
      const config = { integrityMode: "lenient" as const, readOnly, __testAuditAuthorityUid: () => uid };
      const reader = new AuditLog(copyStorage, master, config);
      findings.push((await reader.getIntegrityFindings()).map(({ kind }) => kind));
      expect.soft(await snapshot(copy), name).toEqual(before);
    }
    expect(findings[0]).toContain("tail_anchor_invalid");
    expect(findings[0]).toEqual(findings[1]);
  });
});
