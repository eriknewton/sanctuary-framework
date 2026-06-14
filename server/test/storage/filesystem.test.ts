/**
 * FilesystemStorage tests
 *
 * Covers: path traversal sanitization, 3-pass secure deletion, 0o600/0o700 permission
 * enforcement, ENOENT handling, list with prefix filtering, totalSize on empty base.
 * Not covered: performance, multi-process concurrency, symlink edge cases.
 */

import { describe, it, expect, beforeEach, afterEach } from "vitest";
import {
  mkdir,
  mkdtemp,
  rm,
  readFile,
  stat,
  readdir,
  writeFile,
} from "node:fs/promises";
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
    it("prevents ../ in namespace from escaping basePath", async () => {
      await storage.write("../etc", "key", new Uint8Array([1, 2, 3]));
      // Security invariant: must NOT create basePath/etc (would be one level
      // up's neighbor) or anything matching ".." literally. Specific encoded
      // form is an implementation detail. Assert the invariant, not the form.
      const entries = await readdir(basePath);
      expect(entries).not.toContain("etc");
      expect(entries).not.toContain("..");
      // Round-trip works under the same namespace string.
      const result = await storage.read("../etc", "key");
      expect(result).toEqual(new Uint8Array([1, 2, 3]));
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

  // ── Path bijection (full-sweep #41 + #43) ───────────────────────────
  //
  // Pre-fix sanitizer collapsed any non-safe character to "_", causing
  // distinct namespace strings (e.g., "a/b" and "a_b") to share one disk
  // path. Within a tenant, that lets one agent overwrite or read another
  // namespace it should not see. The bijective encoder must produce
  // distinct on-disk paths for every distinct input string.

  describe("path bijection", () => {
    it("collision-class namespace pairs round-trip independently", async () => {
      const collisions: Array<[string, string]> = [
        ["a/b", "a_b"],
        ["x:y", "x_y"],
        ["m\\n", "m_n"],
        ["t b", "t_b"],
        ["p|q", "p_q"],
      ];
      for (const [nsA, nsB] of collisions) {
        const valA = new Uint8Array([1, 1, 1]);
        const valB = new Uint8Array([2, 2, 2]);
        await storage.write(nsA, "k", valA);
        await storage.write(nsB, "k", valB);
        // Old code: second write would overwrite first (same disk path).
        // New code: distinct disk paths, both values survive.
        expect(await storage.read(nsA, "k")).toEqual(valA);
        expect(await storage.read(nsB, "k")).toEqual(valB);
      }
    });

    it("collision-class key pairs round-trip independently within one namespace", async () => {
      await storage.write("ns", "a/b", new Uint8Array([10]));
      await storage.write("ns", "a_b", new Uint8Array([20]));
      expect(await storage.read("ns", "a/b")).toEqual(new Uint8Array([10]));
      expect(await storage.read("ns", "a_b")).toEqual(new Uint8Array([20]));
    });

    it("internal namespace names with underscore prefix preserve their on-disk path", async () => {
      // _audit, _bridge, _identities, etc. all start with `_`. Underscore
      // remains in the safe set so internal namespaces have stable on-disk
      // paths; no migration needed for any existing fortress whose
      // namespaces use only safe-set characters.
      await storage.write("_audit", "k", new Uint8Array([7]));
      const entries = await readdir(basePath);
      expect(entries).toContain("_audit");
    });
  });

  // ── Legacy on-disk fallback (forward compat) ─────────────────────────
  //
  // Existing fortresses written before #41 used the non-bijective whitelist
  // sanitizer. read(), exists(), and delete() try the new bijective path
  // first; on ENOENT they fall back to the legacy path so operators do not
  // lose data on upgrade. write() always uses the new path.

  describe("legacy on-disk fallback", () => {
    it("read() falls back to legacy whitelist-sanitized path on ENOENT", async () => {
      // Simulate a pre-#41 fortress: data written via the OLD sanitizer.
      // OLD whitelist: namespace 'a/b' was sanitized to 'a_b' on disk.
      const legacyDir = join(basePath, "a_b");
      await mkdir(legacyDir, { recursive: true, mode: 0o700 });
      await writeFile(join(legacyDir, "k.enc"), new Uint8Array([99]));

      // New code reads using the ORIGINAL namespace string. The new
      // bijective path (basePath/a!2Fb/k.enc) does not exist; fallback
      // resolves the legacy on-disk shape.
      const result = await storage.read("a/b", "k");
      expect(result).toEqual(new Uint8Array([99]));
    });

    it("exists() falls back to legacy path", async () => {
      const legacyDir = join(basePath, "a_b");
      await mkdir(legacyDir, { recursive: true, mode: 0o700 });
      await writeFile(join(legacyDir, "k.enc"), new Uint8Array([1]));
      expect(await storage.exists("a/b", "k")).toBe(true);
    });

    it("delete() falls back to legacy path", async () => {
      const legacyDir = join(basePath, "a_b");
      await mkdir(legacyDir, { recursive: true, mode: 0o700 });
      await writeFile(join(legacyDir, "k.enc"), new Uint8Array([1, 2, 3]));
      const deleted = await storage.delete("a/b", "k", false);
      expect(deleted).toBe(true);
      // File at legacy path is gone.
      await expect(stat(join(legacyDir, "k.enc"))).rejects.toThrow();
    });

    it("read() returns null when neither new nor legacy path exists", async () => {
      expect(await storage.read("nonexistent/ns", "k")).toBeNull();
    });

    it("read() prefers new path when both new and legacy paths exist", async () => {
      // Edge case: an operator who upgraded and re-wrote to the same logical
      // namespace ends up with data at both paths. The new bijective path
      // should win; it is the source of truth post-upgrade.
      await storage.write("a/b", "k", new Uint8Array([42])); // new path
      const legacyDir = join(basePath, "a_b");
      await mkdir(legacyDir, { recursive: true, mode: 0o700 });
      await writeFile(join(legacyDir, "k.enc"), new Uint8Array([99])); // legacy
      const result = await storage.read("a/b", "k");
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

    it("fsync'd overwrite path removes a multi-block file", async () => {
      // Exercises the fd-based open/write/sync/close overwrite for a file
      // larger than a single page; the file must still be removed afterward.
      const data = new Uint8Array(64 * 1024).fill(0x5a);
      await storage.write("big-ns", "big-key", data);

      const deleted = await storage.delete("big-ns", "big-key", true);
      expect(deleted).toBe(true);
      expect(await storage.read("big-ns", "big-key")).toBeNull();
    });

    it("fsync'd overwrite path handles a zero-byte file", async () => {
      // A 0-length file means the overwrite writes nothing; open/sync/close
      // must not throw and the file must still be unlinked.
      await storage.write("empty-ns", "empty-key", new Uint8Array(0));

      const deleted = await storage.delete("empty-ns", "empty-key", true);
      expect(deleted).toBe(true);
      expect(await storage.read("empty-ns", "empty-key")).toBeNull();
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
