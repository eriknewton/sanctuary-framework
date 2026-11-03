import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, expect, it, vi } from "vitest";
import { AuditLog, __testSetAuditWriterUidForRole } from "../../src/operational/audit-log.js";
import { migrateFortressAuditStoreSplit } from "../../src/operational/audit-store-split.js";
import { FilesystemStorage } from "../../src/storage/filesystem.js";

const roots: string[] = [];
const master = Buffer.alloc(32, 7); // AES-256 fixture key.
const entry = { layer: "l1" as const, operation: "discovery", identity_id: "fixture", result: "success" as const };
afterEach(async () => {
  vi.restoreAllMocks(); vi.unstubAllEnvs();
  __testSetAuditWriterUidForRole("root_daemon", undefined);
  for (const root of roots.splice(0)) await rm(root, { recursive: true, force: true });
});
async function fixture() {
  const root = await mkdtemp(join(tmpdir(), "audit-discovery-acceptance-"));
  roots.push(root); vi.stubEnv("HOME", root);
  const storage = new FilesystemStorage(join(root, "state"));
  const make = () => new AuditLog(storage, master, { checkpointInterval: 0, __testAuditGuardLockRoot: join(root, "guard") });
  return { storage, make };
}
async function snapshot(storage: FilesystemStorage) {
  const result: Record<string, string> = {};
  for (const ns of ["_audit", "_audit_checkpoints", "_meta"]) {
    for (const { key } of await storage.list(ns)) result[`${ns}/${key}`] = Buffer.from((await storage.read(ns, key))!).toString("base64");
  }
  return result;
}
function allocation(log: AuditLog) {
  const state = log as unknown as { nextSequence: number; lastEntryHash: string; cachedSealedTip: number };
  return [state.nextSequence, state.lastEntryHash, state.cachedSealedTip];
}

it("R5 previously empty instance refuses erased established store", async () => {
  const { storage, make } = await fixture();
  const a = make(); await a.getChainHead();
  const b = make(); await b.appendCritical(entry);
  for (const ns of ["_audit", "_audit_checkpoints"]) {
    for (const { key } of await storage.list(ns)) await storage.delete(ns, key);
  }
  const before = await snapshot(storage); const cached = allocation(a);
  for (let attempt = 0; attempt < 2; attempt++) {
    await expect(a.appendCritical(entry)).rejects.toMatchObject({ name: "AuditChainStateUnknownError", classification: "unknown" });
    expect(allocation(a)).toEqual(cached);
    expect(await snapshot(storage)).toEqual(before);
  }
  await expect(make().appendCritical(entry)).rejects.toMatchObject({ name: "AuditIntegrityError" });
});

it("R6 first suffix after a foreign seal uses F+1 and the boundary hash", async () => {
  const { storage, make } = await fixture();
  const a = make(); await a.appendCritical(entry);
  const b = make(); await b.appendCritical(entry);
  __testSetAuditWriterUidForRole("root_daemon", 0);
  const migration = await migrateFortressAuditStoreSplit({ storage, masterKey: master });
  expect(migration.status).toBe("migrated");
  if (migration.status !== "migrated") throw new Error("migration fixture failed");
  await a.appendCritical(entry);
  const newest = (await storage.list("_audit")).at(-1)!;
  const envelope = JSON.parse(Buffer.from((await storage.read("_audit", newest.key))!).toString());
  expect(envelope.sequence).toBe(3);
  expect(envelope.prev_hash).toBe(migration.boundary.sealed_tip_entry_hash);
  expect(Buffer.from((await storage.read("_meta", "audit-post-split-suffix-established-v1"))!).toString()).toBe("1");
});
