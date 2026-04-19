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
import { AuditLog, BROKER_OPS } from "../../src/l2-operational/audit-log.js";
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

describe("AuditLog flush() — rc.2 audit-visibility regression", () => {
  it("without flush(), pending writes can lag behind storage list()", async () => {
    const storage = new SlowMemoryStorage(40);
    const log = new AuditLog(storage, generateRandomKey());

    log.append("l3", BROKER_OPS.SECRET_ADDED, "id", { secret: "S1" });
    log.append("l3", BROKER_OPS.SECRET_GRANTED, "id", { secret: "S1", skill: "k" });
    log.append("l3", BROKER_OPS.SECRET_DELETED, "id", { secret: "S1" });

    const beforeFlush = await storage.list("_audit");
    expect(beforeFlush.length).toBeLessThan(3);
  });

  it("flush() blocks until every appended entry is persisted", async () => {
    const storage = new SlowMemoryStorage(40);
    const log = new AuditLog(storage, generateRandomKey());

    log.append("l3", BROKER_OPS.SECRET_ADDED, "id", { secret: "S1" });
    log.append("l3", BROKER_OPS.SECRET_GRANTED, "id", { secret: "S1", skill: "k" });
    log.append("l3", BROKER_OPS.SECRET_ROTATED, "id", { secret: "S1" });
    log.append("l3", BROKER_OPS.SECRET_REVOKED, "id", { secret: "S1", skill: "k" });
    log.append("l3", BROKER_OPS.SECRET_DELETED, "id", { secret: "S1" });

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
    writer.append("l3", BROKER_OPS.SECRET_ADDED, "id", { secret: "STRIPE_KEY" });
    writer.append("l3", BROKER_OPS.SECRET_GRANTED, "id", { secret: "STRIPE_KEY", skill: "demo" });
    writer.append("l3", BROKER_OPS.SECRET_ROTATED, "id", { secret: "STRIPE_KEY" });
    writer.append("l3", BROKER_OPS.SECRET_REVOKED, "id", { secret: "STRIPE_KEY", skill: "demo" });
    writer.append("l3", BROKER_OPS.SECRET_DELETED, "id", { secret: "STRIPE_KEY" });
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
    log.append("l3", BROKER_OPS.SECRET_ADDED, "id", { secret: "S" });
    await log.flush();
    await log.flush();
    const entries = await storage.list("_audit");
    expect(entries.length).toBe(1);
  });
});
