// A sealed audit log refuses its whole write path before the raw-filesystem preamble. The Hermes
// bridge shell seals the log just before it releases the master write barrier, so a queued append,
// a timed-out shutdown checkpoint or a rotation pass cannot create a namespace directory or a lock
// file in a fortress the process no longer owns.
import { mkdtemp, readdir, rm, stat } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { AuditLog } from "../../src/operational/audit-log.js";
import { generateRandomKey } from "../../src/core/random.js";
import { FilesystemStorage } from "../../src/storage/filesystem.js";
import { MemoryStorage } from "../../src/storage/memory.js";

const entry = {
  layer: "l1" as const,
  operation: "seal_probe",
  identity_id: "seal-probe",
  result: "success" as const,
  details: {},
};

const cleanups: Array<() => Promise<void>> = [];
afterEach(async () => {
  for (const cleanup of cleanups.splice(0)) await cleanup();
});

async function exists(path: string): Promise<boolean> {
  return stat(path).then(() => true, () => false);
}

describe("AuditLog.sealWritePath", () => {
  it("refuses appends and the shutdown checkpoint after sealing, without touching storage", async () => {
    const storage = new MemoryStorage();
    const log = new AuditLog(storage, generateRandomKey());
    await log.appendCritical(entry);
    const before = (await storage.list("_audit")).length;
    log.sealWritePath("test exit");
    await expect(log.appendCritical(entry)).rejects.toThrow(/write path sealed \(test exit\)/);
    await expect(log.flush()).rejects.toThrow(/write path sealed/);
    expect((await storage.list("_audit")).length).toBe(before);
  });

  it("creates no namespace directory or lock file after sealing a filesystem fortress", async () => {
    const root = await mkdtemp(join(tmpdir(), "audit-seal-"));
    cleanups.push(() => rm(root, { recursive: true, force: true }));
    const state = join(root, "state");
    const log = new AuditLog(new FilesystemStorage(state), generateRandomKey());
    await log.appendCritical(entry);
    await log.flush();
    // Remove what the first append's preamble created, then prove a sealed append recreates none of it.
    await rm(join(state, "_meta"), { recursive: true, force: true });
    await rm(join(state, "_audit_checkpoints"), { recursive: true, force: true });
    const auditEntriesBefore = await readdir(join(state, "_audit"));
    log.sealWritePath("test exit");
    log.sealWritePath("second reason is ignored");
    await expect(log.appendCritical(entry)).rejects.toThrow(/write path sealed \(test exit\)/);
    expect(await exists(join(state, "_meta"))).toBe(false);
    expect(await exists(join(state, "_audit_checkpoints"))).toBe(false);
    expect(await readdir(join(state, "_audit"))).toEqual(auditEntriesBefore);
  });
});
