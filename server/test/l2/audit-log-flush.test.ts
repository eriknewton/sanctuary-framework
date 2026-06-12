/**
 * AuditLog flush() — v0.10.1 regression guard for the v0.10.0-rc.2 soak
 * finding where `sanctuary secrets audit` returned empty after a clean
 * 7-verb broker lifecycle. Root cause: every CLI invocation `process.exit()`s
 * immediately after `runSecretsCommand` returns, killing the event loop
 * mid-write on AuditLog's fire-and-forget persistEntry. The fix tracks
 * in-flight write promises and exposes `flush()` so short-lived callers
 * can drain them before exiting.
 *
 * The existing in-process CLI tests in test/cli/secrets.test.ts can NOT
 * reproduce the bug — between `await run([...])` calls the event loop
 * keeps draining, so fire-and-forget writes settle naturally. We use a
 * slow storage adapter here to deterministically simulate the
 * process.exit() race.
 */

import { describe, it, expect } from "vitest";
import {
  AuditLog,
  AuditPersistenceError,
  AuditLogPersistenceError,
  BROKER_OPS,
} from "../../src/l2-operational/audit-log.js";
import { MemoryStorage } from "../../src/storage/memory.js";
import { generateRandomKey } from "../../src/core/random.js";

class SlowMemoryStorage extends MemoryStorage {
  constructor(private readonly writeDelayMs: number) {
    super();
  }
  async write(namespace: string, key: string, data: Uint8Array): Promise<void> {
    await new Promise((r) => setTimeout(r, this.writeDelayMs));
    return super.write(namespace, key, data);
  }
}

class FaultingWriteStorage extends MemoryStorage {
  async write(namespace: string, key: string, data: Uint8Array): Promise<void> {
    if (namespace === "_audit") {
      throw new Error("audit disk unavailable");
    }
    return super.write(namespace, key, data);
  }
}

class ClassifiedFailureStorage extends MemoryStorage {
  constructor(private readonly code: string) {
    super();
  }

  async write(namespace: string, key: string, data: Uint8Array): Promise<void> {
    if (namespace === "_audit") {
      const err = new Error(`simulated ${this.code}`) as NodeJS.ErrnoException;
      err.code = this.code;
      throw err;
    }
    return super.write(namespace, key, data);
  }
}

class PartialWriteStorage extends MemoryStorage {
  async write(namespace: string, key: string, data: Uint8Array): Promise<void> {
    if (namespace === "_audit") {
      return super.write(namespace, key, data.slice(0, Math.max(0, data.length - 1)));
    }
    return super.write(namespace, key, data);
  }
}

describe("AuditLog flush() — rc.2 audit-visibility regression", () => {
  it("without flush(), pending writes can lag behind storage list()", async () => {
    const storage = new SlowMemoryStorage(40);
    const log = new AuditLog(storage, generateRandomKey());

    // Intentionally fire-and-forget: this test proves storage can lag before flush().
    void log.append("l3", BROKER_OPS.SECRET_ADDED, "id", { secret: "S1" });
    void log.append("l3", BROKER_OPS.SECRET_GRANTED, "id", { secret: "S1", skill: "k" });
    void log.append("l3", BROKER_OPS.SECRET_DELETED, "id", { secret: "S1" });

    const beforeFlush = await storage.list("_audit");
    expect(beforeFlush.length).toBeLessThan(3);
  });

  it("flush() blocks until every appended entry is persisted", async () => {
    const storage = new SlowMemoryStorage(40);
    const log = new AuditLog(storage, generateRandomKey());

    await log.append("l3", BROKER_OPS.SECRET_ADDED, "id", { secret: "S1" });
    await log.append("l3", BROKER_OPS.SECRET_GRANTED, "id", { secret: "S1", skill: "k" });
    await log.append("l3", BROKER_OPS.SECRET_ROTATED, "id", { secret: "S1" });
    await log.append("l3", BROKER_OPS.SECRET_REVOKED, "id", { secret: "S1", skill: "k" });
    await log.append("l3", BROKER_OPS.SECRET_DELETED, "id", { secret: "S1" });

    await log.flush();

    const afterFlush = await storage.list("_audit");
    expect(afterFlush.length).toBe(5);
  });

  it("entries appended-and-flushed survive a fresh AuditLog instance", async () => {
    // Simulates the production CLI cycle: each `sanctuary secrets …` call is
    // a new process. Writer process calls flush() before exit; reader
    // process opens a fresh AuditLog against the same storage and key.
    const storage = new SlowMemoryStorage(20);
    const masterKey = generateRandomKey();

    const writer = new AuditLog(storage, masterKey);
    await writer.append("l3", BROKER_OPS.SECRET_ADDED, "id", { secret: "STRIPE_KEY" });
    await writer.append("l3", BROKER_OPS.SECRET_GRANTED, "id", { secret: "STRIPE_KEY", skill: "demo" });
    await writer.append("l3", BROKER_OPS.SECRET_ROTATED, "id", { secret: "STRIPE_KEY" });
    await writer.append("l3", BROKER_OPS.SECRET_REVOKED, "id", { secret: "STRIPE_KEY", skill: "demo" });
    await writer.append("l3", BROKER_OPS.SECRET_DELETED, "id", { secret: "STRIPE_KEY" });
    await writer.flush();

    const reader = new AuditLog(storage, masterKey);
    const result = await reader.query({ layer: "l3", limit: 100 });
    const ops = result.entries.map((e) => e.operation).sort();
    expect(ops).toContain(BROKER_OPS.SECRET_ADDED);
    expect(ops).toContain(BROKER_OPS.SECRET_GRANTED);
    expect(ops).toContain(BROKER_OPS.SECRET_ROTATED);
    expect(ops).toContain(BROKER_OPS.SECRET_REVOKED);
    expect(ops).toContain(BROKER_OPS.SECRET_DELETED);
  });

  it("flush() is safe to call multiple times and on an idle log", async () => {
    const storage = new MemoryStorage();
    const log = new AuditLog(storage, generateRandomKey());
    await log.flush();
    await log.append("l3", BROKER_OPS.SECRET_ADDED, "id", { secret: "S" });
    await log.flush();
    await log.flush();
    const entries = await storage.list("_audit");
    expect(entries.length).toBe(1);
  });

  it("flush() rejects when audit persistence fails and no entry is durable", async () => {
    const storage = new FaultingWriteStorage();
    const log = new AuditLog(storage, generateRandomKey());

    // Intentionally fire-and-forget. append() supports BOTH fail-loud
    // boundaries: awaiting the returned promise rejects immediately, while an
    // un-awaited call stays tracked in pendingWrites and the failure is
    // rethrown by flush() (asserted below). Awaiting here would throw before
    // flush() and never exercise the flush-time surfacing this test guards.
    void log.append("l1", "egress_allowed", "fortress-1", { seq: 0 });

    await expect(log.flush()).rejects.toThrow(AuditLogPersistenceError);
    await expect(log.flush()).resolves.toBeUndefined();
    const entries = await storage.list("_audit");
    expect(entries).toHaveLength(0);
  });

  it("awaited append() rejects immediately on persistence failure", async () => {
    // The other half of the append() contract: a caller that DOES await the
    // returned promise gets the failure at the call site instead of at
    // flush(). Both boundaries are fail-loud; neither silently degrades.
    const storage = new FaultingWriteStorage();
    const log = new AuditLog(storage, generateRandomKey());

    await expect(
      log.append("l1", "egress_allowed", "fortress-1", { seq: 0 })
    ).rejects.toThrow(AuditPersistenceError);

    // The awaited rejection consumed the tracked failure; flush() does not
    // re-report it.
    await expect(log.flush()).resolves.toBeUndefined();
    const entries = await storage.list("_audit");
    expect(entries).toHaveLength(0);
  });

  it("appendCritical resolves only after the entry round-trips from storage", async () => {
    const storage = new SlowMemoryStorage(40);
    const log = new AuditLog(storage, generateRandomKey());
    const started = Date.now();

    await log.appendCritical({
      layer: "l1",
      operation: "state_write",
      identity_id: "id",
      result: "success",
      details: { namespace: "memory", key: "k" },
    });

    expect(Date.now() - started).toBeGreaterThanOrEqual(35);
    const entries = await storage.list("_audit");
    expect(entries).toHaveLength(1);
  });

  it("appendCritical classifies storage-full failures", async () => {
    const log = new AuditLog(new ClassifiedFailureStorage("ENOSPC"), generateRandomKey());

    await expect(
      log.appendCritical({
        layer: "l1",
        operation: "state_write",
        identity_id: "id",
        result: "success",
      })
    ).rejects.toMatchObject({
      name: "AuditPersistenceError",
      classification: "storage_full",
    } satisfies Partial<AuditPersistenceError>);
  });

  it("appendCritical classifies fsync-style disk failures", async () => {
    const log = new AuditLog(new ClassifiedFailureStorage("EIO"), generateRandomKey());

    await expect(
      log.appendCritical({
        layer: "l1",
        operation: "state_delete",
        identity_id: "id",
        result: "success",
      })
    ).rejects.toMatchObject({
      name: "AuditPersistenceError",
      classification: "disk_failure",
    } satisfies Partial<AuditPersistenceError>);
  });

  it("appendCritical rejects partial writes", async () => {
    const log = new AuditLog(new PartialWriteStorage(), generateRandomKey());

    await expect(
      log.appendCritical({
        layer: "l1",
        operation: "state_write",
        identity_id: "id",
        result: "success",
      })
    ).rejects.toMatchObject({
      name: "AuditPersistenceError",
      classification: "partial_write",
    } satisfies Partial<AuditPersistenceError>);
  });

  it("telemetry-class append() failures do not block the caller", async () => {
    const storage = new FaultingWriteStorage();
    const log = new AuditLog(storage, generateRandomKey());

    const callerResult = (() => {
      // Intentionally fire-and-forget: this test proves append does not block caller flow.
      void log.append("l1", "state_read", "id", { namespace: "memory", key: "k" });
      return "continued";
    })();

    expect(callerResult).toBe("continued");
    await expect(log.flush()).rejects.toThrow(AuditLogPersistenceError);
  });
});
