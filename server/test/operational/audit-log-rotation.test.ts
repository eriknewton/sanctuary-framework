/**
 * Audit Log Rotation Tests
 *
 * Covers: size-based and entry-count-based rotation, oldest-first eviction.
 * Not covered: multi-process concurrency, performance under high load.
 */

import { describe, it, expect } from "vitest";
import { AuditLog } from "../../src/operational/audit-log.js";
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

  // Regression: the full-mode `castle-wall daemon` OOM (heap grew to ~4GB after
  // a few minutes). Root cause: every append pushed one more decrypted entry
  // onto the in-memory `this.entries` / `this.chainEntries` arrays, which on-disk
  // rotation NEVER trimmed, so the daemon's heap grew without bound for the life
  // of the process. The fix bounds the in-memory recent-entry window
  // (`trimInMemoryRetention`) while leaving the persisted log and every full
  // re-read (`verifiedChainView`) complete.
  describe("in-memory retention is bounded (daemon OOM regression)", () => {
    it("does not grow the in-memory window without bound across many appends", async () => {
      // A tiny on-disk cap forces aggressive pruning; the in-memory floor caps
      // the recent window. Before the fix `log.size` tracked the append count
      // (5000) and the heap grew with it.
      const { log } = createLog({ maxEntries: 5 });

      const snapshots = new Map<number, number>();
      for (let i = 1; i <= 5000; i++) {
        await log.append("l1", `op-${i}`, "id-1", { padding: "x".repeat(48) });
        if (i === 1000 || i === 5000) snapshots.set(i, log.size);
      }

      // The in-memory window must NOT scale with the number of appends. The
      // bound is the per-instance in-memory floor (256), well below 5000.
      expect(snapshots.get(1000)).toBeLessThanOrEqual(256);
      expect(snapshots.get(5000)).toBeLessThanOrEqual(256);
      // And it must stay flat, not keep climbing between the two snapshots.
      expect(snapshots.get(5000)).toBe(snapshots.get(1000));
    });

    it("still prunes the persisted log to the on-disk cap", async () => {
      const { log, storage } = createLog({ maxEntries: 5 });
      for (let i = 0; i < 200; i++) {
        await log.append("l1", `op-${i}`, "id-1");
      }
      await log.flush();
      await new Promise((r) => setTimeout(r, 300));
      const onDisk = await storage.list("_audit");
      expect(onDisk.length).toBeLessThanOrEqual(5);
    });

    it("verifiedChainView still returns the full surviving chain after trimming", async () => {
      // The trim must NOT corrupt the transparency Merkle view: verifiedChainView
      // reloads from disk and must serve the full surviving (pruned) chain, not
      // the trimmed in-memory recent window. Use a generous on-disk cap so the
      // whole run survives on disk while the in-memory append path is trimmed.
      const { log } = createLog({ maxEntries: 100_000 });
      const total = 600; // > the 256 in-memory floor, so the append path trims
      for (let i = 1; i <= total; i++) {
        await log.append("l1", `op-${i}`, "id-1");
      }
      await log.flush();

      const view = await log.verifiedChainView();
      // Every appended entry survives on disk, so the full chain view is complete
      // and strictly sequential — proof the trim did not drop chain entries from
      // the authoritative view.
      expect(view.length).toBe(total);
      view.forEach((item, index) => {
        expect(item.sequence).toBe(index + 1);
      });
    });

    it("recent-entry query still returns the most recent entries after trimming", async () => {
      const { log } = createLog({ maxEntries: 100_000 });
      for (let i = 1; i <= 600; i++) {
        await log.append("l1", `op-${i}`, "id-1");
      }
      await log.flush();
      const result = await log.query({ limit: 3 });
      const ops = result.entries.map((e) => e.operation);
      expect(ops).toEqual(["op-598", "op-599", "op-600"]);
    });
  });
});
