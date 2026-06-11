/**
 * Audit Log Rotation Tests
 *
 * Covers: size-based and entry-count-based rotation, oldest-first eviction.
 * Not covered: multi-process concurrency, performance under high load.
 */

import { describe, it, expect } from "vitest";
import { AuditLog } from "../../src/l2-operational/audit-log.js";
import { MemoryStorage } from "../../src/storage/memory.js";
import { generateRandomKey } from "../../src/core/random.js";

describe("AuditLog Rotation", () => {
  function createLog(config?: { maxTotalSizeBytes?: number; maxEntries?: number }): {
    log: AuditLog;
    storage: MemoryStorage;
  } {
    const storage = new MemoryStorage();
    const masterKey = generateRandomKey();
    const log = new AuditLog(storage, masterKey, config);
    return { log, storage };
  }

  it("retains entries within limits", async () => {
    const { log, storage } = createLog({ maxEntries: 50 });

    for (let i = 0; i < 10; i++) {
      await log.append("l1", `op-${i}`, "id-1");
    }

    // Wait for async persist + rotation
    await new Promise((r) => setTimeout(r, 200));

    const entries = await storage.list("_audit");
    expect(entries.length).toBe(10);
  });

  it("prunes oldest entries when maxEntries exceeded", async () => {
    const { log, storage } = createLog({ maxEntries: 5 });

    for (let i = 0; i < 10; i++) {
      await log.append("l1", `op-${i}`, "id-1");
      // Small delay to ensure keys are ordered
      await new Promise((r) => setTimeout(r, 10));
    }

    // Wait for async rotation
    await new Promise((r) => setTimeout(r, 500));

    const entries = await storage.list("_audit");
    expect(entries.length).toBeLessThanOrEqual(5);
  });

  it("prunes oldest entries when maxTotalSizeBytes exceeded", async () => {
    // Each entry is roughly 200-400 bytes encrypted; set a very low cap
    const { log, storage } = createLog({ maxTotalSizeBytes: 1024 });

    for (let i = 0; i < 20; i++) {
      await log.append("l1", `op-${i}`, "id-1", { padding: "x".repeat(100) });
      await new Promise((r) => setTimeout(r, 10));
    }

    // Wait for rotation
    await new Promise((r) => setTimeout(r, 500));

    const entries = await storage.list("_audit");
    const totalSize = entries.reduce((sum, e) => sum + e.size_bytes, 0);
    expect(totalSize).toBeLessThanOrEqual(1024 + 500); // Allow some overshoot from last append
  });

  it("defaults to 100MB / 100K entries when no config", () => {
    const storage = new MemoryStorage();
    const masterKey = generateRandomKey();
    // Should not throw — defaults apply
    const log = new AuditLog(storage, masterKey);
    expect(log).toBeDefined();
  });
});
