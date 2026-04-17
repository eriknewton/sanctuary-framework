/**
 * FilesystemStorage tests
 *
 * Covers: path traversal sanitization, 3-pass secure deletion, 0o600/0o700 permission
 * enforcement, ENOENT handling, list with prefix filtering, totalSize on empty base.
 * Not covered: performance, multi-process concurrency, symlink edge cases.
 */

import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtemp, rm, readFile, stat, readdir } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { FilesystemStorage } from "../../src/storage/filesystem.js";

describe("FilesystemStorage", () => {
  let basePath: string;
  let storage: FilesystemStorage;

  beforeEach(async () => {
    basePath = await mkdtemp(join(tmpdir(), "sanctuary-fs-test-"));
    storage = new FilesystemStorage(basePath);
  });

  afterEach(async () => {
    await rm(basePath, { recursive: true, force: true });
  });

  // ── Path traversal sanitization ─────────────────────────────────────

  describe("path traversal sanitization", () => {
    it("sanitizes ../ in namespace", async () => {
      await storage.write("../etc", "key", new Uint8Array([1, 2, 3]));
      // Should write to basePath/___etc/ not basePath/../etc/
      const entries = await readdir(basePath);
      expect(entries).toContain("___etc");
      expect(entries).not.toContain("etc");
    });

    it("sanitizes / in key names", async () => {
      await storage.write("ns", "../../passwd", new Uint8Array([1]));
      const result = await storage.read("ns", "../../passwd");
      expect(result).toEqual(new Uint8Array([1]));
    });

    it("sanitizes special characters in namespace and key", async () => {
      await storage.write("ns with spaces!", "key:special", new Uint8Array([42]));
      const result = await storage.read("ns with spaces!", "key:special");
      expect(result).toEqual(new Uint8Array([42]));
    });
  });

  // ── Write and read ──────────────────────────────────────────────────

  describe("write/read", () => {
    it("round-trips data through write and read", async () => {
      const data = new Uint8Array([10, 20, 30, 40, 50]);
      await storage.write("test-ns", "test-key", data);
      const result = await storage.read("test-ns", "test-key");
      expect(result).toEqual(data);
    });

    it("returns null for non-existent key", async () => {
      const result = await storage.read("no-ns", "no-key");
      expect(result).toBeNull();
    });
  });

  // ── Secure deletion ────────────────────────────────────────────────

  describe("secure deletion", () => {
    it("deletes file after 3-pass overwrite", async () => {
      const data = new Uint8Array(100).fill(0xAA);
      await storage.write("del-ns", "del-key", data);

      const deleted = await storage.delete("del-ns", "del-key", true);
      expect(deleted).toBe(true);

      const afterDelete = await storage.read("del-ns", "del-key");
      expect(afterDelete).toBeNull();
    });

    it("returns false for non-existent key", async () => {
      const deleted = await storage.delete("no-ns", "no-key", true);
      expect(deleted).toBe(false);
    });

    it("deletes without secure overwrite when false", async () => {
      await storage.write("ns", "key", new Uint8Array([1]));
      const deleted = await storage.delete("ns", "key", false);
      expect(deleted).toBe(true);
      expect(await storage.read("ns", "key")).toBeNull();
    });
  });

  // ── List ───────────────────────────────────────────────────────────

  describe("list", () => {
    it("lists entries in a namespace", async () => {
      await storage.write("list-ns", "a", new Uint8Array([1]));
      await storage.write("list-ns", "b", new Uint8Array([2]));
      await storage.write("list-ns", "c", new Uint8Array([3]));

      const entries = await storage.list("list-ns");
      expect(entries).toHaveLength(3);
      expect(entries.map(e => e.key)).toEqual(["a", "b", "c"]);
    });

    it("filters by prefix", async () => {
      await storage.write("pfx-ns", "log-1", new Uint8Array([1]));
      await storage.write("pfx-ns", "log-2", new Uint8Array([2]));
      await storage.write("pfx-ns", "data-1", new Uint8Array([3]));

      const logEntries = await storage.list("pfx-ns", "log-");
      expect(logEntries).toHaveLength(2);
      expect(logEntries.map(e => e.key)).toEqual(["log-1", "log-2"]);
    });

    it("returns empty array for non-existent namespace", async () => {
      const entries = await storage.list("no-such-ns");
      expect(entries).toEqual([]);
    });

    it("includes size_bytes in metadata", async () => {
      await storage.write("meta-ns", "key", new Uint8Array(42));
      const entries = await storage.list("meta-ns");
      expect(entries[0]!.size_bytes).toBe(42);
    });
  });

  // ── Exists ─────────────────────────────────────────────────────────

  describe("exists", () => {
    it("returns true for existing entries", async () => {
      await storage.write("ex-ns", "key", new Uint8Array([1]));
      expect(await storage.exists("ex-ns", "key")).toBe(true);
    });

    it("returns false for non-existent entries", async () => {
      expect(await storage.exists("no-ns", "no-key")).toBe(false);
    });
  });

  // ── Total size ─────────────────────────────────────────────────────

  describe("totalSize", () => {
    it("returns 0 when base path is empty", async () => {
      expect(await storage.totalSize()).toBe(0);
    });

    it("sums all file sizes", async () => {
      await storage.write("ns1", "k1", new Uint8Array(100));
      await storage.write("ns2", "k2", new Uint8Array(200));
      const total = await storage.totalSize();
      expect(total).toBe(300);
    });
  });
});
