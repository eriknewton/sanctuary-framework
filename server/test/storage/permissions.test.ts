/**
 * Tests for tightenStoragePermissions — verifies that pre-existing
 * files and directories get tightened to owner-only permissions.
 */

import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtemp, mkdir, writeFile, stat, chmod, rm } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { tightenStoragePermissions } from "../../src/storage/permissions.js";

describe("tightenStoragePermissions", () => {
  let root: string;

  beforeEach(async () => {
    root = await mkdtemp(join(tmpdir(), "sanctuary-perm-test-"));
  });

  afterEach(async () => {
    await rm(root, { recursive: true, force: true });
  });

  it("tightens a file at 0644 to 0600", async () => {
    const filePath = join(root, "test.enc");
    await writeFile(filePath, "data", { mode: 0o644 });
    await tightenStoragePermissions(root);
    const info = await stat(filePath);
    expect(info.mode & 0o777).toBe(0o600);
  });

  it("tightens a directory at 0755 to 0700", async () => {
    const dirPath = join(root, "identities");
    await mkdir(dirPath, { mode: 0o755 });
    await tightenStoragePermissions(root);
    const info = await stat(dirPath);
    expect(info.mode & 0o777).toBe(0o700);
  });

  it("leaves already-correct permissions unchanged", async () => {
    const filePath = join(root, "correct.enc");
    await writeFile(filePath, "data", { mode: 0o600 });
    const dirPath = join(root, "correct-dir");
    await mkdir(dirPath, { mode: 0o700 });
    await tightenStoragePermissions(root);
    expect((await stat(filePath)).mode & 0o777).toBe(0o600);
    expect((await stat(dirPath)).mode & 0o777).toBe(0o700);
  });

  it("recurses into subdirectories", async () => {
    const subDir = join(root, "state", "_audit");
    await mkdir(subDir, { recursive: true, mode: 0o755 });
    const nestedFile = join(subDir, "entry.enc");
    await writeFile(nestedFile, "data", { mode: 0o644 });
    await tightenStoragePermissions(root);
    expect((await stat(subDir)).mode & 0o777).toBe(0o700);
    expect((await stat(nestedFile)).mode & 0o777).toBe(0o600);
  });

  it("does not throw on a non-existent root", async () => {
    await expect(
      tightenStoragePermissions("/tmp/nonexistent-sanctuary-path-xyz")
    ).resolves.not.toThrow();
  });
});
