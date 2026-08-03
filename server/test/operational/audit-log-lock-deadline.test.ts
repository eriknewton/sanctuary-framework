import { mkdir, mkdtemp, readFile, rm, stat, writeFile } from "node:fs/promises";
import type { Stats } from "node:fs";
import { tmpdir, uptime as osUptime } from "node:os";
import { dirname, join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";

import {
  AuditLockContentionError,
  AuditLockHoldDeadlineError,
  AuditLog,
  type AuditLogConfig,
} from "../../src/operational/audit-log.js";
import { generateRandomKey } from "../../src/core/random.js";
import { FilesystemStorage } from "../../src/storage/filesystem.js";

const AUDIT_NAMESPACE = "_audit";
const LOCK_FILE = ".audit-write.lock";
const DIFFERENT_BOOT = "00000000-0000-4000-8000-000000000000";

class ControllableFilesystemStorage extends FilesystemStorage {
  hangEntryWrites = false;

  override async writeDurable(
    namespace: string,
    key: string,
    data: Uint8Array,
  ): Promise<void> {
    if (
      this.hangEntryWrites &&
      namespace === AUDIT_NAMESPACE &&
      key.startsWith("entry-")
    ) {
      await new Promise<never>(() => {});
    }
    await super.writeDurable(namespace, key, data);
  }
}

type LockInternals = {
  withAuditWriteLock<T>(operation: () => Promise<T>): Promise<T>;
  breakStaleAuditLock(lockPath: string): Promise<boolean>;
  readonly auditWriteLockPath?: string;
};

type TimedResult<T> =
  | { status: "resolved"; value: T }
  | { status: "rejected"; reason: unknown }
  | { status: "timeout" };

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

async function settleWithin<T>(promise: Promise<T>, ms: number): Promise<TimedResult<T>> {
  return Promise.race([
    promise.then(
      (value): TimedResult<T> => ({ status: "resolved", value }),
      (reason: unknown): TimedResult<T> => ({ status: "rejected", reason }),
    ),
    sleep(ms).then((): TimedResult<T> => ({ status: "timeout" })),
  ]);
}

function entry(operation: string, n = 1) {
  return {
    layer: "l1" as const,
    operation,
    identity_id: `id-${n}`,
    result: "success" as const,
    details: { n },
  };
}

describe("AuditLog write-lock hold deadline and self-held recovery", () => {
  const dirs: string[] = [];

  afterEach(async () => {
    for (const dir of dirs.splice(0)) {
      await rm(dir, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
    }
  });

  async function makeLog(config: AuditLogConfig = {}) {
    const root = await mkdtemp(join(tmpdir(), "sanctuary-audit-lock-deadline-"));
    dirs.push(root);
    const storagePath = join(root, "state");
    const storage = new ControllableFilesystemStorage(storagePath);
    const log = new AuditLog(storage, generateRandomKey(), {
      checkpointInterval: 0,
      integrityMode: "lenient",
      ...config,
    });
    const lockPath = join(storagePath, AUDIT_NAMESPACE, LOCK_FILE);
    await mkdir(dirname(lockPath), { recursive: true });
    return { log, storage, lockPath, internals: log as unknown as LockInternals };
  }

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

  it("abandons a hung entry write, releases the lock, and the same log appends again", async () => {
    const { log, storage, lockPath } = await makeLog({
      writeLockHoldDeadlineMs: 250,
      selfHeldStaleLockMs: 1_500,
    });

    storage.hangEntryWrites = true;
    const started = Date.now();
    const result = await settleWithin(log.appendCritical(entry("hung-entry", 1)), 2_000);

    expect(result.status).toBe("rejected");
    if (result.status !== "rejected") return;
    expect(result.reason).toBeInstanceOf(AuditLockHoldDeadlineError);
    expect(Date.now() - started).toBeLessThan(2_000);
    await expect(stat(lockPath)).rejects.toMatchObject({ code: "ENOENT" });
    expect(log.getWriteLockRecoveryCount()).toBe(1);

    storage.hangEntryWrites = false;
    await expect(log.appendCritical(entry("after-recovery", 2))).resolves.toBeUndefined();
    await expect(stat(lockPath)).rejects.toMatchObject({ code: "ENOENT" });

    const read = await log.query({ limit: 20 });
    expect(read.integrity_findings).toEqual([]);
    expect(read.entries.map((e) => e.operation)).toContain("after-recovery");
  });

  it("forces release of a same-process same-boot lock older than the self-held bound", async () => {
    const { log, lockPath, internals } = await makeLog({
      writeLockHoldDeadlineMs: 2_000,
      selfHeldStaleLockMs: 3_000,
    });
    await log.appendCritical(entry("seed", 1));
    const bootId = await currentStampedBootId(internals, lockPath);

    // The mini2 defect shape is a lock OUR OWN long-running process stamped
    // AFTER its start and then held past the bound. Stamping it BEFORE our
    // process start would instead hit the pre-existing reused-self-pid orphan
    // branch (which breaks silently, no recovery event), so the plant must sit
    // between our process-start uptime and (now - selfHeldStaleLockMs -
    // tolerance). Ensure the worker process is old enough first.
    const toleranceMs = 1_000; // AUDIT_LOCK_MONO_UPTIME_TOLERANCE_MS in src
    const marginMs = 500;
    const requiredAgeMs = 1_500 + toleranceMs + marginMs;
    if (process.uptime() * 1000 < requiredAgeMs) {
      await sleep(requiredAgeMs - process.uptime() * 1000);
    }
    const currentUptimeMs = osUptime() * 1000;
    const ourStartUptimeMs = currentUptimeMs - process.uptime() * 1000;
    const lockUptimeMs = Math.max(1, Math.round(ourStartUptimeMs + marginMs / 2));
    const heldForMs = currentUptimeMs - lockUptimeMs;
    await writeFile(
      lockPath,
      JSON.stringify({
        pid: process.pid,
        acquired_at: new Date(Date.now() - heldForMs).toISOString(),
        uptime_ms: lockUptimeMs,
        boot_id: bootId,
      }),
    );

    await expect(log.appendCritical(entry("after-self-held-stale", 2))).resolves.toBeUndefined();
    await expect(stat(lockPath)).rejects.toMatchObject({ code: "ENOENT" });
    expect(log.getWriteLockRecoveryCount()).toBe(1);
  });

  it("healthy appends do not trip recovery", async () => {
    const { log } = await makeLog({
      writeLockHoldDeadlineMs: 2_000,
      selfHeldStaleLockMs: 3_000,
    });

    await log.appendCritical(entry("healthy-1", 1));
    await log.appendCritical(entry("healthy-2", 2));
    await log.appendCritical(entry("healthy-3", 3));

    expect(log.getWriteLockRecoveryCount()).toBe(0);
    const read = await log.query({ limit: 10 });
    expect(read.integrity_findings).toEqual([]);
  });

  it("still refuses to break a live different-pid same-boot lock", async () => {
    const { log, lockPath, internals } = await makeLog({
      writeLockHoldDeadlineMs: 2_000,
      selfHeldStaleLockMs: 3_000,
    });
    await log.appendCritical(entry("seed", 1));
    const bootId = await currentStampedBootId(internals, lockPath);
    const currentUptimeMs = osUptime() * 1000;

    await writeFile(
      lockPath,
      JSON.stringify({
        pid: 1,
        acquired_at: new Date().toISOString(),
        uptime_ms: Math.max(1, Math.round(currentUptimeMs - 500)),
        boot_id: bootId,
      }),
    );

    const result = await settleWithin(log.appendCritical(entry("blocked-by-live-pid", 2)), 8_000);

    expect(result.status).toBe("rejected");
    if (result.status !== "rejected") return;
    expect(result.reason).toBeInstanceOf(AuditLockContentionError);
    expect(log.getWriteLockRecoveryCount()).toBe(0);
    await expect(stat(lockPath).then((s: Stats) => s.size)).resolves.toBeGreaterThan(0);
  }, 12_000);
});
