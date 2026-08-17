/**
 * `ReadOnlyStorageGuard` — the decorator that makes a "read-only" code path
 * read-only structurally rather than by convention.
 *
 * Two things are asserted here and one in
 * `test/structure/read-only-storage-guard-parity.test.ts`:
 *   1. every mutating method THROWS (never a silent no-op — MUST-NEVER #5);
 *   2. every read method delegates unchanged;
 *   3. (parity test) the two method lists together cover the whole storage
 *      interface, so a method can neither be silently inherited nor omitted.
 */

import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";

import { FilesystemStorage } from "../../src/storage/filesystem.js";
import { MemoryStorage } from "../../src/storage/memory.js";
import {
  ReadOnlyStorageGuard,
  ReadOnlyStorageViolationError,
} from "../../src/storage/read-only-guard.js";

describe("ReadOnlyStorageGuard", () => {
  const tempDirs: string[] = [];
  afterEach(async () => {
    for (const dir of tempDirs.splice(0)) {
      await rm(dir, { recursive: true, force: true }).catch(() => undefined);
    }
  });

  async function seededBackend(): Promise<{ root: string; inner: FilesystemStorage }> {
    const root = await mkdtemp(join(tmpdir(), "sanctuary-ro-guard-"));
    tempDirs.push(root);
    const inner = new FilesystemStorage(root);
    await inner.write("ns", "key", new TextEncoder().encode("hello"));
    return { root, inner };
  }

  it("refuses write, writeDurable, and delete by throwing", async () => {
    const { inner } = await seededBackend();
    const guard = new ReadOnlyStorageGuard(inner);
    const payload = new TextEncoder().encode("nope");

    await expect(guard.write("ns", "key", payload)).rejects.toBeInstanceOf(
      ReadOnlyStorageViolationError
    );
    await expect(guard.writeDurable("ns", "key", payload)).rejects.toBeInstanceOf(
      ReadOnlyStorageViolationError
    );
    await expect(guard.delete("ns", "key")).rejects.toBeInstanceOf(
      ReadOnlyStorageViolationError
    );

    // A refusal that silently no-op'd would leave the caller believing the
    // write landed; assert the underlying bytes are also untouched.
    expect(new TextDecoder().decode((await inner.read("ns", "key"))!)).toBe("hello");
  });

  it("delegates every read method unchanged", async () => {
    const { inner } = await seededBackend();
    const guard = new ReadOnlyStorageGuard(inner);

    expect(new TextDecoder().decode((await guard.read("ns", "key"))!)).toBe("hello");
    expect(await guard.read("ns", "absent")).toBeNull();
    expect((await guard.list("ns")).map((m) => m.key)).toEqual(["key"]);
    expect(await guard.exists("ns", "key")).toBe(true);
    expect(await guard.exists("ns", "absent")).toBe(false);
    expect(await guard.totalSize()).toBe(await inner.totalSize());
    expect(guard.namespacePath("ns")).toBe(inner.namespacePath("ns"));
    expect(await guard.listNamespaces?.()).toEqual(await inner.listNamespaces());
  });

  it("mirrors listNamespaces presence rather than always defining it", () => {
    // Master-key rotation reads an ABSENT `listNamespaces` as "this backend
    // cannot enumerate, fail closed". A guard that always defined the method
    // would turn that fail-closed refusal into a runtime error, so presence
    // must track the wrapped backend exactly.
    const withCapability = new ReadOnlyStorageGuard(new MemoryStorage());
    expect(typeof withCapability.listNamespaces).toBe("function");

    const withoutCapability = new ReadOnlyStorageGuard({
      write: async () => undefined,
      read: async () => null,
      delete: async () => false,
      list: async () => [],
      exists: async () => false,
      totalSize: async () => 0,
    });
    expect(withoutCapability.listNamespaces).toBeUndefined();
  });

  it("reports which method was refused, on which key", async () => {
    const { inner } = await seededBackend();
    const guard = new ReadOnlyStorageGuard(inner);
    await expect(guard.delete("_audit", "entry-000001")).rejects.toMatchObject({
      method: "delete",
      namespace: "_audit",
      key: "entry-000001",
    });
  });
});
