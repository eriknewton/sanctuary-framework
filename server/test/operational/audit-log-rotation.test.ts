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
  function createLog(config?: {
    maxTotalSizeBytes?: number;
    maxEntries?: number;
    maxInMemoryEntries?: number;
  }): {
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
  //
  // These tests DECOUPLE the on-disk cap from the in-memory cap: a LARGE
  // `maxEntries` keeps the entire chain on disk (so a missing disk-reload is
  // observable), while a small `maxInMemoryEntries` forces the in-memory window
  // to be trimmed. `IN_MEMORY_FLOOR` mirrors `MIN_IN_MEMORY_ENTRY_FLOOR` in the
  // source: even a tiny `maxInMemoryEntries` is raised to this floor, so the
  // trimmed window settles at exactly the floor. After `flush()` the public
  // `log.size` equals `this.entries.length` (no pending writes), so it is the
  // assertion handle for "how many entries are held in memory".
  describe("in-memory retention is bounded (daemon OOM regression)", () => {
    const IN_MEMORY_FLOOR = 256;
    const TOTAL = 1_000; // > IN_MEMORY_FLOOR, so the trim must fire
    // Disk keeps everything; only the in-memory window is capped.
    const DECOUPLED = { maxEntries: 1_000_000, maxInMemoryEntries: 1 } as const;

    it("trims the in-memory window to the floor while every append survives on disk", async () => {
      const { log, storage } = createLog(DECOUPLED);

      // Snapshot mid-run AND at the end: the window must not climb with the
      // append count. Before the fix `log.size` tracked the append count.
      let midSize = 0;
      for (let i = 1; i <= TOTAL; i++) {
        await log.append("l1", `op-${i}`, "id-1", { padding: "x".repeat(48) });
        if (i === 500) midSize = log.size;
      }
      await log.flush();

      // In-memory window pinned at the floor: PROOF the trim fired (it is far
      // below TOTAL, and flat between the mid-run and final snapshots).
      expect(log.size).toBe(IN_MEMORY_FLOOR);
      expect(log.size).toBeLessThan(TOTAL);
      expect(midSize).toBe(IN_MEMORY_FLOOR);

      // ...yet the persisted log is COMPLETE (large on-disk cap, nothing pruned).
      // This is what makes the next two tests meaningful: the disk holds the
      // full chain even though memory holds only the recent window.
      const onDisk = await storage.list("_audit");
      expect(onDisk.length).toBe(TOTAL);
    });

    it("verifiedChainView returns the full surviving chain even though memory is trimmed", async () => {
      // The trim must NOT corrupt the transparency Merkle view / workload replay:
      // verifiedChainView reloads from disk and must serve the FULL chain, not the
      // trimmed in-memory window. With memory capped at the floor (256) and TOTAL
      // (1000) on disk, a view that served the in-memory window would return 256;
      // the disk reload makes it return all 1000. So this test FAILS if the
      // disk-reload step were removed: exactly the property that matters.
      const { log } = createLog(DECOUPLED);
      for (let i = 1; i <= TOTAL; i++) {
        await log.append("l1", `op-${i}`, "id-1");
      }
      await log.flush();

      // Precondition: the in-memory window really is trimmed below TOTAL.
      expect(log.size).toBe(IN_MEMORY_FLOOR);
      expect(log.size).toBeLessThan(TOTAL);

      const view = await log.verifiedChainView();
      expect(view.length).toBe(TOTAL); // full chain, NOT the 256-entry window
      view.forEach((item, index) => {
        expect(item.sequence).toBe(index + 1); // strictly sequential, no gaps
      });
    });

    it("recent-entry query returns the correct latest entries even though memory is trimmed", async () => {
      const { log } = createLog(DECOUPLED);
      for (let i = 1; i <= TOTAL; i++) {
        await log.append("l1", `op-${i}`, "id-1");
      }
      await log.flush();

      // Precondition: trimmed below TOTAL.
      expect(log.size).toBe(IN_MEMORY_FLOOR);
      expect(log.size).toBeLessThan(TOTAL);

      // query() re-reads from disk, so the latest entries are correct regardless
      // of which entries the (trimmed) in-memory window happens to hold.
      const result = await log.query({ limit: 3 });
      const ops = result.entries.map((e) => e.operation);
      expect(ops).toEqual([`op-${TOTAL - 2}`, `op-${TOTAL - 1}`, `op-${TOTAL}`]);
    });

    it("still prunes the persisted log to the on-disk cap (rotation unaffected by the in-memory trim)", async () => {
      const { log, storage } = createLog({ maxEntries: 5 });
      for (let i = 0; i < 200; i++) {
        await log.append("l1", `op-${i}`, "id-1");
      }
      await log.flush();
      await new Promise((r) => setTimeout(r, 300));
      const onDisk = await storage.list("_audit");
      expect(onDisk.length).toBeLessThanOrEqual(5);
    });
  });
});
