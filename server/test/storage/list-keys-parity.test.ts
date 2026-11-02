import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import fs, { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { syncBuiltinESMExports } from "node:module";
import { AuditLog } from "../../src/operational/audit-log.js";
import { MEASURE_CONFIG, MEASURE_MASTER_KEY, measureEntry } from "../../scripts/measure-audit-append.js";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { FilesystemStorage } from "../../src/storage/filesystem.js";
import { MemoryStorage } from "../../src/storage/memory.js";
import { ReadOnlyStorageGuard } from "../../src/storage/read-only-guard.js";
import { DaemonAuditStorageAdapter } from "../../src/operational/audit-store-split.js";
import type { StorageBackend } from "../../src/storage/interface.js";

let root: string;
beforeEach(async () => { root = await mkdtemp(join(tmpdir(), "keys-parity-")); vi.stubEnv("HOME", root); });
afterEach(async () => { vi.restoreAllMocks(); syncBuiltinESMExports(); vi.unstubAllEnvs(); await rm(root, { recursive: true, force: true }); });

async function parity(writer: StorageBackend, namespace: string): Promise<void> {
  const readers = [writer, new ReadOnlyStorageGuard(writer)];
  // Case and punctuation deliberately differ in code-unit and locale order.
  for (const keys of [[], ["a"], ["B", "a-0", "a/1", "z!"]]) {
    for (const old of await writer.list(namespace)) await writer.delete(namespace, old.key);
    for (const key of keys) await writer.write(namespace, key, new Uint8Array([1]));
    for (const prefix of [undefined, "", "a", "absent"]) {
      for (const reader of readers) {
        expect(typeof reader.listKeys).toBe("function");
        const expected = (await reader.list(namespace, prefix)).map((meta) => meta.key).sort();
        expect(await reader.listKeys!(namespace, prefix)).toEqual(expected);
      }
    }
  }
}

describe("complete names-only storage enumeration", () => {
  it("has full-set parity on memory, filesystem, daemon remapping and each read-only guard", async () => {
    await parity(new MemoryStorage(), "_audit");
    await parity(new FilesystemStorage(join(root, "filesystem")), "_audit");
    const raw = new FilesystemStorage(join(root, "daemon"));
    const daemon = new DaemonAuditStorageAdapter(raw);
    await parity(daemon, "_audit");
    expect(await raw.listKeys("_audit")).toEqual([]);
    expect(await daemon.listKeys("_audit")).toEqual(await raw.listKeys("_audit-daemon"));
    await expect(daemon.listKeys("_identities")).rejects.toMatchObject({ code: "SANCTUARY_AUDIT_NAMESPACE_UNSUPPORTED" });
  });

  it("refuses a planted non-round-tripping raw name through both listing methods and decorators", async () => {
    const raw = new FilesystemStorage(root);
    const daemon = new DaemonAuditStorageAdapter(raw);
    for (const namespace of ["_audit", "_audit-daemon"]) {
      await mkdir(join(root, namespace), { recursive: true });
      await writeFile(join(root, namespace, "key-!4E2D.enc"), "invalid raw name");
    }
    for (const reader of [raw, daemon, new ReadOnlyStorageGuard(raw), new ReadOnlyStorageGuard(daemon)]) {
      for (const prefix of [undefined, "", "missing"]) {
        await expect(reader.list("_audit", prefix)).rejects.toMatchObject({ code: "FILESYSTEM_STORAGE_NAME_UNADDRESSABLE" });
        await expect(reader.listKeys!("_audit", prefix)).rejects.toMatchObject({ code: "FILESYSTEM_STORAGE_NAME_UNADDRESSABLE" });
      }
    }
  });

  it("mirrors actual absence through the guard rather than fabricating a callable method", async () => {
    const inner = new MemoryStorage();
    const old: StorageBackend = { write: inner.write.bind(inner), read: inner.read.bind(inner), delete: inner.delete.bind(inner),
      list: inner.list.bind(inner), exists: inner.exists.bind(inner), totalSize: inner.totalSize.bind(inner) };
    expect(typeof new ReadOnlyStorageGuard(old).listKeys).toBe("undefined");
    expect(typeof new ReadOnlyStorageGuard(inner).listKeys).toBe("function");
  });
});

it("keeps entry-stat refusal through a backend stub without listKeys", async () => {
  const raw = new FilesystemStorage(join(root, "fallback"));
  const stub: StorageBackend = { write: raw.write.bind(raw), read: raw.read.bind(raw),
    delete: raw.delete.bind(raw), list: raw.list.bind(raw), exists: raw.exists.bind(raw), totalSize: raw.totalSize.bind(raw) };
  const log = new AuditLog(stub, MEASURE_MASTER_KEY, MEASURE_CONFIG);
  await log.appendCritical(measureEntry(0));
  const key = (await raw.list("_audit"))[0]!.key;
  const original = fs.stat;
  vi.spyOn(fs, "stat").mockImplementation((async (...args: any[]) => {
    if (String(args[0]) === join(root, "fallback", "_audit", `${key}.enc`)) {
      throw Object.assign(new Error("fallback entry stat EIO"), { code: "EIO" });
    }
    return (original as any)(...args);
  }) as any); syncBuiltinESMExports();
  await expect(log.appendCritical(measureEntry(1))).rejects.toThrow("fallback entry stat EIO");
  expect(log.currentInMemorySequence()).toBe(1);
});
