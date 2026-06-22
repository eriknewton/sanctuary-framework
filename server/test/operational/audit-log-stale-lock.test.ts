import { mkdtemp, rm, writeFile, mkdir, stat } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";

import { AuditLog } from "../../src/operational/audit-log.js";
import { generateRandomKey } from "../../src/core/random.js";
import { FilesystemStorage } from "../../src/storage/filesystem.js";

// Finding F (A1 acceptance drill, 2026-06-04, reboot 2): the audit-write lock is
// a plain lock file with no liveness check, and the graceful unlink runs only in
// a finally that a reboot/SIGKILL skips. A stranded lock from a dead holder
// would block the next daemon for the full timeout and fail its restart. The fix
// breaks a PROVABLY-stale lock (holder dead, or acquired before the current
// boot) and proceeds; it must NEVER break a lock a live process holds.
describe("AuditLog stale write-lock recovery (Finding F)", () => {
  const dirs: string[] = [];

  afterEach(async () => {
    for (const d of dirs.splice(0)) {
      await rm(d, { recursive: true, force: true });
    }
  });

  async function makeLog() {
    const root = await mkdtemp(join(tmpdir(), "sanctuary-audit-stale-lock-"));
    dirs.push(root);
    const storagePath = join(root, "state");
    const log = new AuditLog(new FilesystemStorage(storagePath), generateRandomKey(), {
      integrityMode: "lenient",
    });
    const lockPath = join(storagePath, "_audit", ".audit-write.lock");
    return { log, lockPath };
  }

  it("breaks a stale lock left by a dead holder and proceeds", async () => {
    const { log, lockPath } = await makeLog();
    await log.append("l1", "egress_allowed", "id-1", { n: 1 });
    await log.flush();

    // A crashed/rebooted daemon stranded the lock with a dead holder pid.
    await mkdir(dirname(lockPath), { recursive: true });
    await writeFile(
      lockPath,
      JSON.stringify({ pid: 999_999, acquired_at: new Date().toISOString() }),
    );

    await log.append("l1", "egress_allowed", "id-2", { n: 2 });
    await expect(log.flush()).resolves.toBeUndefined();
    // Lock released after the write (proves the stale lock was broken, not waited on).
    await expect(stat(lockPath)).rejects.toMatchObject({ code: "ENOENT" });
  });

  it("breaks a lock that predates the current boot (PID-reuse-safe)", async () => {
    const { log, lockPath } = await makeLog();
    await log.append("l1", "egress_allowed", "id-1", { n: 1 });
    await log.flush();

    // pid 1 is always alive, but the lock was acquired long before this boot, so
    // it survived a reboot and is orphaned regardless of PID reuse.
    await mkdir(dirname(lockPath), { recursive: true });
    await writeFile(
      lockPath,
      JSON.stringify({ pid: 1, acquired_at: "2020-01-01T00:00:00.000Z" }),
    );

    await log.append("l1", "egress_allowed", "id-2", { n: 2 });
    await expect(log.flush()).resolves.toBeUndefined();
    await expect(stat(lockPath)).rejects.toMatchObject({ code: "ENOENT" });
  });
});
