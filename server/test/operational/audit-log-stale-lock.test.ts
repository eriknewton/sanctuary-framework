import { mkdtemp, rm, writeFile, readFile, rename, mkdir, stat, utimes, readdir } from "node:fs/promises";
import { tmpdir, uptime as osUptime } from "node:os";
import type { Stats } from "node:fs";
import { dirname, join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";

import { AuditLog, type AuditLogConfig } from "../../src/operational/audit-log.js";
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

// #944 write-lock robustness cluster (sweep fix 5, 2026-07-16): clock-skew-safe
// staleness via a monotonic `uptime_ms` stamp, inode-verified graceful release,
// orphan acquire-temp GC, and the previously-missing #944 branch cases. These
// are white-box tests over the private lock internals: they drive the staleness
// decision and the release path directly so the security-critical branches are
// exercised deterministically, without racing the 5s contention timeout.
describe("AuditLog write-lock robustness (#944 cluster)", () => {
  const dirs: string[] = [];

  afterEach(async () => {
    for (const d of dirs.splice(0)) {
      await rm(d, { recursive: true, force: true });
    }
  });

  // Minimal white-box surface onto the private lock internals under test.
  type LockInternals = {
    breakStaleAuditLock(lockPath: string): Promise<boolean>;
    unlinkIfSameInode(lockPath: string, proven: Stats): Promise<boolean>;
    withAuditWriteLock<T>(operation: () => Promise<T>): Promise<T>;
    readonly auditWriteLockPath?: string;
  };
  type AuditLogCreateOwnerTestConfig = AuditLogConfig & {
    createOwner?: { uid: number; gid: number };
    createOwnerChown?: (
      handle: unknown,
      owner: { uid: number; gid: number },
    ) => Promise<void>;
  };

  async function makeLog(config?: AuditLogConfig) {
    const root = await mkdtemp(join(tmpdir(), "sanctuary-audit-lock-robust-"));
    dirs.push(root);
    const storagePath = join(root, "state");
    const log = new AuditLog(new FilesystemStorage(storagePath), generateRandomKey(), {
      integrityMode: "lenient",
      ...config,
    });
    const lockPath = join(storagePath, "_audit", ".audit-write.lock");
    await mkdir(dirname(lockPath), { recursive: true });
    return { log, lockPath, internals: log as unknown as LockInternals };
  }

  // Monotonic reference points captured the same way the production code does.
  function monotonicNow() {
    const currentUptimeMs = osUptime() * 1000;
    const ourStartUptimeMs = currentUptimeMs - process.uptime() * 1000;
    return { currentUptimeMs, ourStartUptimeMs };
  }

  const PRE_BOOT = "2020-01-01T00:00:00.000Z";
  // A boot-identity token guaranteed to differ from the current boot's (a UUID
  // that no real boot mints), used to simulate a PREVIOUS boot's lock (a reboot
  // orphan). currentBootId reads a per-boot UUID; this fixed one cannot collide.
  const DIFFERENT_BOOT = "00000000-0000-4000-8000-000000000000";
  const OWNER = { uid: 501, gid: 20 };

  // The EXACT boot-identity token production stamps THIS boot, read back from a
  // real acquire so the test can never drift from currentBootId's platform read
  // (mirrors how monotonicNow re-derives os.uptime the way production does).
  // Precondition-asserts availability: every CI host (Linux /proc/.../boot_id,
  // macOS kern.bootsessionuuid) exposes one, and the boot-identity path under
  // test is meaningless without it.
  async function currentStampedBootId(
    internals: LockInternals,
    lockPath: string,
  ): Promise<string> {
    let id: unknown;
    await internals.withAuditWriteLock(async () => {
      id = JSON.parse(await readFile(lockPath, "utf8")).boot_id;
    });
    expect(typeof id).toBe("string");
    expect(id).not.toBe(DIFFERENT_BOOT);
    return id as string;
  }

  // Finding 2 (clock-skew), row E — the headline protect-test. A forward
  // wall-clock step (VM resume, NTP correction) inflates the DERIVED boot time,
  // making a LIVE same-boot lock's acquired_at look pre-boot. The OLD wall-clock
  // proof would break this live lock (→ two writers → chain fork). The lock's
  // `boot_id` PROVES it was stamped THIS boot (a per-boot UUID is invariant to a
  // clock step), so it is left intact regardless of the wall clock. (pid 1 is
  // always alive.)
  it("does NOT break a LIVE same-boot lock whose acquired_at looks pre-boot (forward clock step)", async () => {
    const { lockPath, internals } = await makeLog();
    const bootId = await currentStampedBootId(internals, lockPath);
    const { currentUptimeMs } = monotonicNow();
    await writeFile(
      lockPath,
      JSON.stringify({
        pid: 1,
        acquired_at: PRE_BOOT, // as a forward clock step would make it appear
        uptime_ms: Math.round(currentUptimeMs - 1000), // stamped ~1s ago, this boot
        boot_id: bootId, // PROVES this boot → protected despite the pre-boot stamp
      }),
    );

    await expect(internals.breakStaleAuditLock(lockPath)).resolves.toBe(false);
    await expect(stat(lockPath)).resolves.toBeDefined();
  });

  // Finding 2 — the same protection for our OWN pid: a live sibling instance in
  // THIS process holds the lock, stamped after our start, but a forward step made
  // its acquired_at look pre-boot. Same boot is PROVEN by `boot_id`; within that,
  // the monotonic uptime_ms (>= our start) confirms it as our own live hold, so
  // it wins over the wall-clock predatesBoot proof and is not broken. This is the
  // exact "2 in-process instances + forward step" trigger.
  it("does NOT break our own live lock stamped after our start, despite a pre-boot acquired_at", async () => {
    const { lockPath, internals } = await makeLog();
    const bootId = await currentStampedBootId(internals, lockPath);
    const { currentUptimeMs, ourStartUptimeMs } = monotonicNow();
    expect(ourStartUptimeMs).toBeGreaterThan(2000); // precondition for the stamp below
    await writeFile(
      lockPath,
      JSON.stringify({
        pid: process.pid,
        acquired_at: PRE_BOOT,
        // Between our start and now → unambiguously our own live hold.
        uptime_ms: Math.round((ourStartUptimeMs + currentUptimeMs) / 2),
        boot_id: bootId, // PROVES this boot → the uptime reasoning is trusted
      }),
    );

    await expect(internals.breakStaleAuditLock(lockPath)).resolves.toBe(false);
    await expect(stat(lockPath)).resolves.toBeDefined();
  });

  // Finding 2 — the fix must NOT over-protect: a genuinely dead holder is still
  // broken even though its lock is PROVEN same-boot (matching boot_id + recent
  // uptime_ms). Proves the same-boot path gates on liveness, not merely on
  // "stamped this boot" — a same-boot crash orphan is still cleared.
  it("STILL breaks a dead holder's same-boot lock (proven boot_id, recent uptime_ms)", async () => {
    const { lockPath, internals } = await makeLog();
    const bootId = await currentStampedBootId(internals, lockPath);
    const { currentUptimeMs } = monotonicNow();
    await writeFile(
      lockPath,
      JSON.stringify({
        pid: 999_999, // not a live process
        acquired_at: new Date().toISOString(),
        uptime_ms: Math.round(currentUptimeMs - 1000),
        boot_id: bootId, // same boot proven, yet the holder is dead → break
      }),
    );

    await expect(internals.breakStaleAuditLock(lockPath)).resolves.toBe(true);
    await expect(stat(lockPath)).rejects.toMatchObject({ code: "ENOENT" });
  });

  // Finding 2 — reused-self-pid orphan proven MONOTONICALLY within a proven-same
  // boot (immune to a clock step): matching boot_id proves same boot, and the
  // uptime_ms stamp predates THIS process's start, so a dead predecessor
  // reclaimed our pid this boot. Must break.
  it("breaks a reused-self-pid orphan via the monotonic uptime proof (same boot)", async () => {
    const { lockPath, internals } = await makeLog();
    const bootId = await currentStampedBootId(internals, lockPath);
    const { ourStartUptimeMs } = monotonicNow();
    expect(ourStartUptimeMs).toBeGreaterThan(2000);
    await writeFile(
      lockPath,
      JSON.stringify({
        pid: process.pid,
        acquired_at: new Date().toISOString(), // recent wall clock is irrelevant here
        uptime_ms: Math.round(ourStartUptimeMs / 2), // before we started, same boot
        boot_id: bootId, // same boot proven → the uptime predates-our-start proof applies
      }),
    );

    await expect(internals.breakStaleAuditLock(lockPath)).resolves.toBe(true);
    await expect(stat(lockPath)).rejects.toMatchObject({ code: "ENOENT" });
  });

  // ── HIGH regression (two-family gate, 2026-07-16): the reboot-orphan brick ──
  // os.uptime() RESETS on reboot, so a previous boot's uptime_ms falls in the
  // SAME numeric range as this boot's. Gating "protect this live lock" on that
  // magnitude alone would let a reboot orphan whose recorded pid a reboot then
  // reused for a LIVE process masquerade as a live same-boot lock → never broken
  // → the fortress retries to the 5s timeout → AuditLockContentionError → audit
  // writes bricked. Boot-identity (a per-boot UUID) closes it: a mismatch is
  // proven reboot evidence and wins over any pid-liveness protect path.

  // Row A: reboot orphan whose reused pid is a LIVE FOREIGN process. The exact
  // brick vector — MUST be broken despite the live pid and the aliasing uptime.
  it("breaks a reboot orphan whose reused pid is a LIVE foreign process (boot-identity mismatch)", async () => {
    const { lockPath, internals } = await makeLog();
    const realBoot = await currentStampedBootId(internals, lockPath);
    const { currentUptimeMs } = monotonicNow();
    // Previous boot's uptime_ms aliased BELOW the current uptime (the norm for an
    // early-boot daemon at reboot-recovery); pid 1 is always alive; acquired_at
    // predates boot. Only the boot-identity mismatch proves it is a reboot orphan.
    await writeFile(
      lockPath,
      JSON.stringify({
        pid: 1,
        acquired_at: PRE_BOOT,
        uptime_ms: Math.max(0, Math.round(currentUptimeMs - 1000)),
        boot_id: DIFFERENT_BOOT,
      }),
    );
    expect(DIFFERENT_BOOT).not.toBe(realBoot);

    await expect(internals.breakStaleAuditLock(lockPath)).resolves.toBe(true);
    await expect(stat(lockPath)).rejects.toMatchObject({ code: "ENOENT" });
  });

  // Row B: reboot orphan on our OWN reused pid whose uptime_ms is >= our process
  // start. The buggy magnitude path treated this as "genuinely ours, live" and
  // refused to break; the boot-identity mismatch proves it is a reboot orphan.
  it("breaks a reboot orphan on our OWN reused pid even when uptime_ms >= our start (boot-identity mismatch)", async () => {
    const { lockPath, internals } = await makeLog();
    const realBoot = await currentStampedBootId(internals, lockPath);
    const { currentUptimeMs, ourStartUptimeMs } = monotonicNow();
    const aliasedUptime = Math.round((ourStartUptimeMs + currentUptimeMs) / 2);
    expect(aliasedUptime).toBeGreaterThan(ourStartUptimeMs); // >= our start
    await writeFile(
      lockPath,
      JSON.stringify({
        pid: process.pid,
        acquired_at: PRE_BOOT,
        uptime_ms: aliasedUptime,
        boot_id: DIFFERENT_BOOT,
      }),
    );
    expect(DIFFERENT_BOOT).not.toBe(realBoot);

    await expect(internals.breakStaleAuditLock(lockPath)).resolves.toBe(true);
    await expect(stat(lockPath)).rejects.toMatchObject({ code: "ENOENT" });
  });

  // NON-VACUITY: the boot-identity gate is load-bearing. The SAME lock bytes are
  // PROTECTED when boot_id matches this boot (rows D/E) and BROKEN when only the
  // boot_id is flipped to a different boot (rows A/B). Flipping that one field is
  // what flips the outcome — proving the guard is not a no-op.
  it("boot-identity is load-bearing: same lock PROTECTED on match, BROKEN on mismatch", async () => {
    const { lockPath, internals } = await makeLog();
    const realBoot = await currentStampedBootId(internals, lockPath);
    const { currentUptimeMs } = monotonicNow();
    const base = {
      pid: 1, // always alive
      acquired_at: PRE_BOOT, // forward-clock-step appearance
      uptime_ms: Math.max(0, Math.round(currentUptimeMs - 1000)),
    };

    // Same boot proven → a live foreign holder is legitimate contention → kept.
    await writeFile(lockPath, JSON.stringify({ ...base, boot_id: realBoot }));
    await expect(internals.breakStaleAuditLock(lockPath)).resolves.toBe(false);
    await expect(stat(lockPath)).resolves.toBeDefined();

    // Flip ONLY boot_id → proven reboot orphan → broken. Same bytes otherwise.
    expect(DIFFERENT_BOOT).not.toBe(realBoot);
    await writeFile(lockPath, JSON.stringify({ ...base, boot_id: DIFFERENT_BOOT }));
    await expect(internals.breakStaleAuditLock(lockPath)).resolves.toBe(true);
    await expect(stat(lockPath)).rejects.toMatchObject({ code: "ENOENT" });
  });

  // Tie-break for an OLD-format lock (no boot_id): absent boot-identity must NOT
  // leave a reboot orphan intact. pid 1 is alive and acquired_at predates boot —
  // the pre-PR fail-safe wins (predatesBoot breaks it) rather than the buggy
  // magnitude path protecting it. Guards the "fall back to predatesBoot-
  // unconditional" contract for locks an old binary / out-of-band tool wrote.
  it("old-format lock (no boot_id) still breaks a reboot orphan via predatesBoot (live pid)", async () => {
    const { lockPath, internals } = await makeLog();
    await writeFile(
      lockPath,
      JSON.stringify({ pid: 1, acquired_at: PRE_BOOT }),
    );

    await expect(internals.breakStaleAuditLock(lockPath)).resolves.toBe(true);
    await expect(stat(lockPath)).rejects.toMatchObject({ code: "ENOENT" });
  });

  it("applies createOwner to the write lock on the open descriptor before visibility", async () => {
    let lockPath = "";
    const calls: Array<{ owner: { uid: number; gid: number }; visibleAtChown: boolean }> = [];
    const config: AuditLogCreateOwnerTestConfig = {
      createOwner: OWNER,
      createOwnerChown: async (_handle, owner) => {
        let visibleAtChown = true;
        try {
          await stat(lockPath);
        } catch (err) {
          if ((err as NodeJS.ErrnoException).code === "ENOENT") {
            visibleAtChown = false;
          } else {
            throw err;
          }
        }
        calls.push({ owner, visibleAtChown });
      },
    };
    const made = await makeLog(config);
    lockPath = made.lockPath;

    await made.internals.withAuditWriteLock(async () => {
      expect(calls).toEqual([{ owner: OWNER, visibleAtChown: false }]);
      await expect(stat(lockPath)).resolves.toBeDefined();
    });
    await expect(stat(lockPath)).rejects.toMatchObject({ code: "ENOENT" });
  });

  it("does not attempt write-lock chown when createOwner is absent", async () => {
    let chownCalls = 0;
    const config: AuditLogCreateOwnerTestConfig = {
      createOwnerChown: async () => {
        chownCalls++;
      },
    };
    const { internals } = await makeLog(config);

    await internals.withAuditWriteLock(async () => undefined);

    expect(chownCalls).toBe(0);
  });

  it("applies createOwner when a stale lock is broken and replaced", async () => {
    const calls: Array<{ uid: number; gid: number }> = [];
    const config: AuditLogCreateOwnerTestConfig = {
      createOwner: OWNER,
      createOwnerChown: async (_handle, owner) => {
        calls.push(owner);
      },
    };
    const { log, lockPath } = await makeLog(config);
    await writeFile(
      lockPath,
      JSON.stringify({ pid: 999_999, acquired_at: new Date().toISOString() }),
    );

    await expect(
      log.append("l1", "egress_allowed", "after-stale-break", { n: 1 }),
    ).resolves.toBeUndefined();

    expect(calls.length).toBeGreaterThanOrEqual(2);
    expect(calls.every((call) => call.uid === OWNER.uid && call.gid === OWNER.gid)).toBe(true);
    await expect(stat(lockPath)).rejects.toMatchObject({ code: "ENOENT" });
  });

  // MEDIUM (invariant 5): a REAL removal error must be SURFACED, not swallowed.
  // The lock path is a non-empty directory: the identity re-stat matches, but the
  // removal throws a genuine fs error (EISDIR / EPERM / …). unlinkIfSameInode
  // must propagate it — the graceful release relies on this so a failed release
  // never silently leaves our lock on disk (self-brick), only the benign
  // already-gone / inode-mismatch outcomes are swallowed.
  it("unlinkIfSameInode surfaces a REAL removal error instead of swallowing it", async () => {
    const { lockPath, internals } = await makeLog();
    await mkdir(lockPath, { recursive: true });
    await writeFile(join(lockPath, "child"), "x");
    const proven = await stat(lockPath);

    await expect(internals.unlinkIfSameInode(lockPath, proven)).rejects.toBeDefined();
    // The un-removable object is still present: the release did not silently
    // claim success (which would have leaked the lock).
    await expect(stat(lockPath)).resolves.toBeDefined();
  });

  // Finding 4 — the same-boot `exceedsIdlessAgeBound` 0-byte branch (distinct
  // from the mtime-predates-boot branch the existing suite covers). A 0-byte lock
  // whose mtime is AFTER boot but older than the (test-lowered) id-less bound is
  // provably not a live sub-second hold → break.
  it("breaks a same-boot 0-byte lock via the id-less age bound (not the boot proof)", async () => {
    const { lockPath, internals } = await makeLog({ idlessStaleLockMs: 100 });
    await writeFile(lockPath, "");
    const mtime = new Date(Date.now() - 1000); // ~1s ago: after boot, > 100ms bound
    await utimes(lockPath, mtime, mtime);
    await expect(stat(lockPath).then((s) => s.size)).resolves.toBe(0);

    await expect(internals.breakStaleAuditLock(lockPath)).resolves.toBe(true);
    await expect(stat(lockPath)).rejects.toMatchObject({ code: "ENOENT" });
  });

  // Finding 4 — a field-less but non-empty `{}` lock (valid JSON, no pid /
  // acquired_at / uptime_ms) is NOT 0-byte, so the id-less fallback cannot fire,
  // and it carries no id to prove liveness from → it stays fail-closed (never
  // broken), exactly like a foreign live holder writing an unknown format.
  it("does NOT break a field-less {} lock (stays fail-closed)", async () => {
    const { lockPath, internals } = await makeLog();
    await writeFile(lockPath, "{}");

    await expect(internals.breakStaleAuditLock(lockPath)).resolves.toBe(false);
    await expect(stat(lockPath)).resolves.toBeDefined();
  });

  // Finding 4 — the `unlinkIfSameInode` inode-MISMATCH branch directly (the
  // existing suite only reaches it through the concurrent-race outcome). A
  // delayed break must NOT remove a DIFFERENT file that now occupies the path
  // (a racing acquirer's fresh lock), and must remove the proven one, and must
  // treat an already-vanished file as broken.
  it("unlinkIfSameInode removes only the proven inode (mismatch left intact)", async () => {
    const { lockPath, internals } = await makeLog();
    const sibling = lockPath + ".sibling";

    // MISMATCH: a racing acquirer republished a fresh lock (a NEW inode) at the
    // same path. We publish it at a sibling path first, then rename it over the
    // lock: two coexisting files always have distinct inodes, so the republished
    // inode is guaranteed != `proven` even on a filesystem that AGGRESSIVELY
    // reuses freed inode numbers (Linux ext4/tmpfs) — a plain rm+recreate can
    // reuse the number and is flaky. The delayed break must leave it intact.
    await writeFile(lockPath, "original");
    const proven = await stat(lockPath);
    await writeFile(sibling, "republished");
    await rename(sibling, lockPath); // atomic replace → lockPath now has a NEW inode
    const republished = await stat(lockPath);
    expect(republished.ino).not.toBe(proven.ino);
    await expect(internals.unlinkIfSameInode(lockPath, proven)).resolves.toBe(false);
    await expect(stat(lockPath).then((s) => s.ino)).resolves.toBe(republished.ino);

    // MATCH: proving the CURRENT file stale removes it and returns true.
    const current = await stat(lockPath);
    await expect(internals.unlinkIfSameInode(lockPath, current)).resolves.toBe(true);
    await expect(stat(lockPath)).rejects.toMatchObject({ code: "ENOENT" });

    // ABSENT: nothing at the path → treated as already-broken, returns true.
    await expect(internals.unlinkIfSameInode(lockPath, current)).resolves.toBe(true);
  });

  // Finding 1 — inode-verified GRACEFUL release. If the lock this instance holds
  // is broken-and-republished under it (a fresh inode at the same path) while its
  // operation runs, the finally-release must NOT delete the new holder's lock (a
  // bare rm-by-path would → double-acquire cascade). We drive withAuditWriteLock
  // with an operation that republishes the lock, then assert the republished lock
  // survives the release.
  it("graceful release does not clobber a lock republished under it", async () => {
    const { lockPath, internals } = await makeLog();
    let republishedIno = -1;

    await internals.withAuditWriteLock(async () => {
      const held = await stat(lockPath);
      // Simulate a break-and-republish by another acquirer. Publish the fresh
      // lock at a sibling path, then rename it over ours: coexisting files have
      // distinct inodes, so the republished inode is guaranteed != held even on a
      // filesystem that reuses freed inode numbers (a plain rm+recreate is flaky
      // on Linux ext4/tmpfs, which immediately reuses the just-freed inode).
      const sibling = lockPath + ".sibling";
      await writeFile(
        sibling,
        JSON.stringify({ pid: 4242, acquired_at: new Date().toISOString() }),
      );
      await rename(sibling, lockPath);
      republishedIno = (await stat(lockPath)).ino;
      expect(republishedIno).not.toBe(held.ino);
    });

    // The republished (different-inode) lock must still be present: our release
    // recognized it was not the file we acquired and left it alone.
    await expect(stat(lockPath).then((s) => s.ino)).resolves.toBe(republishedIno);
  });

  // Finding 3 — orphan `.acquire.*.tmp` GC. A crash between link() and cleanup
  // strands an acquire-temp permanently. The once-per-process startup sweep GCs
  // temps older than the id-less bound, and age-gates so a CONCURRENT acquirer's
  // in-flight temp is never reaped. One append triggers the lazy sweep.
  it("sweeps an orphaned acquire-temp older than the bound but keeps a recent one", async () => {
    // Bound of 3s: the 5s-old temp exceeds it (swept); a "now" temp stays under
    // it even allowing for the append+flush latency below (kept).
    const { log, lockPath } = await makeLog({ idlessStaleLockMs: 3000 });
    const auditDir = dirname(lockPath);
    const oldTemp = join(auditDir, ".audit-write.lock.acquire.99999.0.deadbeef.tmp");
    const recentTemp = join(auditDir, ".audit-write.lock.acquire.88888.0.cafef00d.tmp");
    await writeFile(oldTemp, JSON.stringify({ pid: 99999 }));
    await writeFile(recentTemp, JSON.stringify({ pid: 88888 }));
    const old = new Date(Date.now() - 5000); // 5s old, > 3s bound → swept
    await utimes(oldTemp, old, old);
    // recentTemp keeps its "now" mtime → within the bound → NOT swept.

    // The first write-lock acquire runs the one-shot sweep.
    await log.append("l1", "egress_allowed", "id-1", { n: 1 });
    await log.flush();

    await expect(stat(oldTemp)).rejects.toMatchObject({ code: "ENOENT" });
    await expect(stat(recentTemp)).resolves.toBeDefined();
    // The append's own acquire-temp left no litter either.
    const leftovers = (await readdir(auditDir)).filter(
      (f) => f.includes(".audit-write.lock.acquire.") && f !== ".audit-write.lock.acquire.88888.0.cafef00d.tmp",
    );
    expect(leftovers).toEqual([]);
  });
});
