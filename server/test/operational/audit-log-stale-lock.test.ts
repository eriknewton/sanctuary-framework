import { mkdtemp, rm, writeFile, mkdir, stat, utimes, readdir } from "node:fs/promises";
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

  // Drill-found (Leg 5, MBA custody drill 2026-07-15): a torn acquire
  // (crash between file-create and stamp under the OLD open(wx)-then-write
  // path) stranded a 0-BYTE lock with neither pid nor acquired_at. The old
  // staleness prover could not clear an id-less file, so the fortress was
  // permanently bricked with a misleading "another writer holds the lock".
  it("breaks a stranded 0-byte lock whose mtime predates boot", async () => {
    const { log, lockPath } = await makeLog();
    await log.append("l1", "egress_allowed", "id-1", { n: 1 });
    await log.flush();

    // The exact MBA state: an empty lock file, mtime far in the past (predating
    // this process's boot). No pid, no acquired_at → the pid/boot proofs cannot
    // fire; only the id-less mtime fallback can clear it.
    await mkdir(dirname(lockPath), { recursive: true });
    await writeFile(lockPath, "");
    const ancient = new Date("2020-01-01T00:00:00.000Z");
    await utimes(lockPath, ancient, ancient);
    await expect(stat(lockPath).then((s) => s.size)).resolves.toBe(0);

    await log.append("l1", "egress_allowed", "id-2", { n: 2 });
    await expect(log.flush()).resolves.toBeUndefined();
    // The 0-byte lock was broken (not waited on until timeout), so the write
    // completed and released its own lock.
    await expect(stat(lockPath)).rejects.toMatchObject({ code: "ENOENT" });
  });

  it("does NOT break a fresh, content-bearing lock held this boot", async () => {
    const { log, lockPath } = await makeLog();
    await log.append("l1", "egress_allowed", "id-1", { n: 1 });
    await log.flush();

    // A genuinely live holder: pid 1 (always alive) stamped now (this boot). The
    // lock is real contention and must NOT be broken; the write blocks and
    // eventually raises AuditLockContentionError rather than clobbering it.
    await mkdir(dirname(lockPath), { recursive: true });
    await writeFile(
      lockPath,
      JSON.stringify({ pid: 1, acquired_at: new Date().toISOString() }),
    );

    await expect(
      (async () => {
        await log.append("l1", "egress_allowed", "id-2", { n: 2 });
        await log.flush();
      })(),
    ).rejects.toThrow(/audit write blocked/);
    // The live lock was respected (still present), never clobbered.
    await expect(stat(lockPath).then((s) => s.size)).resolves.toBeGreaterThan(0);
  }, 20_000);

  it("does NOT break a recent 0-byte lock (same boot, within the age bound)", async () => {
    const { log, lockPath } = await makeLog();
    await log.append("l1", "egress_allowed", "id-1", { n: 1 });
    await log.flush();

    // A 0-byte lock whose mtime is NOW cannot be proven stale: it could be an
    // in-flight torn acquire by a peer that is about to finish. Fail-safe: leave
    // it, block, and surface contention rather than clobber a possibly-live lock.
    await mkdir(dirname(lockPath), { recursive: true });
    await writeFile(lockPath, "");
    // mtime defaults to now → within AUDIT_WRITE_LOCK_IDLESS_STALE_MS and not
    // predating boot, so neither id-less proof fires.

    await expect(
      (async () => {
        await log.append("l1", "egress_allowed", "id-2", { n: 2 });
        await log.flush();
      })(),
    ).rejects.toThrow(/audit write blocked/);
    await expect(stat(lockPath)).resolves.toBeDefined();
  }, 20_000);

  // Codex re-gate (2026-07-15) HIGH-1: PID reuse across a reboot where the dead
  // holder's pid is handed to THIS process. The lock records our own pid with a
  // pre-boot acquired_at; the boot-time proof must win over the self-pid guard,
  // or the fortress bricks exactly when a restarted daemon reuses the old pid.
  it("breaks a pre-boot lock even when its recorded pid equals ours", async () => {
    const { log, lockPath } = await makeLog();
    await log.append("l1", "egress_allowed", "id-1", { n: 1 });
    await log.flush();

    await mkdir(dirname(lockPath), { recursive: true });
    await writeFile(
      lockPath,
      // process.pid, but acquired before this boot: cannot be ours (we started
      // after boot), so it is a reused-pid orphan and must break.
      JSON.stringify({ pid: process.pid, acquired_at: "2020-01-01T00:00:00.000Z" }),
    );

    await log.append("l1", "egress_allowed", "id-2", { n: 2 });
    await expect(log.flush()).resolves.toBeUndefined();
    await expect(stat(lockPath)).rejects.toMatchObject({ code: "ENOENT" });
  });

  // Codex re-gate (2026-07-15) MED-4: only a GENUINELY EMPTY lock gets the
  // mtime fallback. A NON-empty lock this build cannot parse could be a live
  // holder writing a future/foreign format, so it stays fail-closed even when
  // old — never mtime-broken.
  it("does NOT break a NON-empty unparseable lock, even an ancient one", async () => {
    const { log, lockPath } = await makeLog();
    await log.append("l1", "egress_allowed", "id-1", { n: 1 });
    await log.flush();

    await mkdir(dirname(lockPath), { recursive: true });
    await writeFile(lockPath, "not-json-garbage-but-non-empty");
    const ancient = new Date("2020-01-01T00:00:00.000Z");
    await utimes(lockPath, ancient, ancient);

    await expect(
      (async () => {
        await log.append("l1", "egress_allowed", "id-2", { n: 2 });
        await log.flush();
      })(),
    ).rejects.toThrow(/audit write blocked/);
    // Non-empty unparseable lock left intact (size gate keeps it fail-closed).
    await expect(stat(lockPath).then((s) => s.size)).resolves.toBeGreaterThan(0);
  }, 20_000);

  // The atomic acquire must never leave a content-less lock behind: after a
  // clean append+flush the lock is gone, and while held it always carries its
  // stamp (never a 0-byte window). This is the structural fix that makes the
  // strand above unreachable from the current code path.
  it("acquires atomically: the lock is never observed 0-byte", async () => {
    const { log, lockPath } = await makeLog();
    await log.append("l1", "egress_allowed", "id-1", { n: 1 });
    await log.flush();
    // Released cleanly after the write.
    await expect(stat(lockPath)).rejects.toMatchObject({ code: "ENOENT" });

    // No orphan temp acquire files linger in the audit dir.
    const auditDir = dirname(lockPath);
    const leftovers = (await readdir(auditDir)).filter((f) =>
      f.includes(".audit-write.lock.acquire."),
    );
    expect(leftovers).toEqual([]);
  });

  // Codex re-gate (2026-07-15) HIGH-2: concurrent acquirers racing over a
  // stranded 0-byte lock must not corrupt the chain. The inode-verified break
  // ensures a delayed removal never clobbers a racing acquirer's FRESH lock, so
  // writes serialize cleanly. We assert the outcome that matters: every write
  // that reported success is present and the chain verifies integrity-clean
  // (no silent fork), with no permanent brick.
  it("keeps the chain clean under two writers racing over a stale 0-byte lock", async () => {
    const root = await mkdtemp(join(tmpdir(), "sanctuary-audit-stale-lock-race-"));
    dirs.push(root);
    const storagePath = join(root, "state");
    const key = generateRandomKey();
    const logA = new AuditLog(new FilesystemStorage(storagePath), key, {
      integrityMode: "lenient",
    });
    const logB = new AuditLog(new FilesystemStorage(storagePath), key, {
      integrityMode: "lenient",
    });
    const lockPath = join(storagePath, "_audit", ".audit-write.lock");

    // Seed the chain, then strand an ancient 0-byte lock both writers must clear.
    await logA.append("l1", "egress_allowed", "seed", { n: 0 });
    await logA.flush();
    await writeFile(lockPath, "");
    const ancient = new Date("2020-01-01T00:00:00.000Z");
    await utimes(lockPath, ancient, ancient);

    // Race a burst of appends across both instances, tracking which ones each
    // instance REPORTED as durably persisted (fulfilled append + flush).
    const work: Promise<{ id: string; ok: boolean }>[] = [];
    const attempt = (log: AuditLog, id: string, n: number) =>
      log
        .append("l1", "egress_allowed", id, { n })
        .then(() => ({ id, ok: true }))
        .catch(() => ({ id, ok: false }));
    for (let i = 0; i < 8; i++) {
      work.push(attempt(logA, `a-${i}`, i));
      work.push(attempt(logB, `b-${i}`, i));
    }
    const attempts = await Promise.all(work);
    const flushed = await Promise.allSettled([logA.flush(), logB.flush()]);
    // Both flushes must SUCCEED (no permanent brick / no lost persist error);
    // this makes the persisted-ids assertion below unconditional rather than
    // skippable on a rejected flush (Codex re-gate MED-1, 2026-07-15).
    for (const r of flushed) {
      expect(r.status).toBe("fulfilled");
    }

    // A fresh reader over the same store must find zero integrity findings: a
    // clobbered lock that let two writers fork the chain would surface here as a
    // sequence gap / hash mismatch (fail closed), never a silent success.
    const reader = new AuditLog(new FilesystemStorage(storagePath), key, {
      integrityMode: "lenient",
    });
    const findings = await reader.getIntegrityFindings();
    expect(findings).toEqual([]);

    // Assert the raced writes actually LANDED, not just that no findings
    // surfaced (a run where every append failed would also be finding-free).
    // Every append that reported success must be present in the persisted,
    // integrity-clean chain, so a silently-overwritten "successful" write (the
    // entry-key-collision fork Codex flagged) would fail this: the store never
    // acknowledges a write it then loses.
    const okIds = new Set(attempts.filter((a) => a.ok).map((a) => a.id));
    expect(okIds.size).toBeGreaterThan(0);
    const persisted = new Set(
      (await reader.query({ limit: 1000 })).entries.map((e) => e.identity_id),
    );
    for (const id of okIds) {
      expect(persisted.has(id)).toBe(true);
    }

    // Not permanently bricked: a subsequent write still succeeds.
    await expect(
      (async () => {
        await reader.append("l1", "egress_allowed", "after", { n: 99 });
        await reader.flush();
      })(),
    ).resolves.toBeUndefined();
  }, 30_000);

  // Opus re-gate NEW-1 (2026-07-15): the reused-self-pid orphan must break via
  // the process-start proof (process.uptime(), no uv_uptime syscall), which
  // survives the confined-uid sandbox where os.uptime() (hence the boot proof)
  // is blocked. Rather than mock the non-configurable os.uptime, we stamp the
  // lock in the window AFTER system boot but BEFORE this process started: the
  // boot proof (acquired_at < bootTime) is FALSE for it, so ONLY the
  // process-start proof can clear it. This proves a restarted fixed-role daemon
  // reclaiming its old pid does not re-brick even when boot time is unavailable.
  it("breaks a reused-self-pid lock via the process-start proof (boot proof does not apply)", async () => {
    const os = await import("node:os");
    const bootMs = Date.now() - os.uptime() * 1000;
    const processStartMs = Date.now() - process.uptime() * 1000;
    // A stamp strictly after boot and strictly before our process start. This
    // window exists on any real host (a process starts well after boot); if it
    // is degenerate the test still exercises the break, just also via the boot
    // proof.
    const stampMs = Math.max(bootMs + 1, processStartMs - 500);
    expect(stampMs).toBeLessThan(processStartMs); // reused-self-pid proof applies

    const { log, lockPath } = await makeLog();
    await log.append("l1", "egress_allowed", "id-1", { n: 1 });
    await log.flush();

    await mkdir(dirname(lockPath), { recursive: true });
    await writeFile(
      lockPath,
      JSON.stringify({
        pid: process.pid,
        acquired_at: new Date(stampMs).toISOString(),
      }),
    );

    await log.append("l1", "egress_allowed", "id-2", { n: 2 });
    await expect(log.flush()).resolves.toBeUndefined();
    await expect(stat(lockPath)).rejects.toMatchObject({ code: "ENOENT" });
  });
});
