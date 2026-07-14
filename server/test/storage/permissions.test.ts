/**
 * Tests for tightenStoragePermissions — verifies that pre-existing
 * files and directories get tightened to owner-only permissions.
 */

import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtemp, mkdir, writeFile, stat, chmod, rm } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { tightenStoragePermissions } from "../../src/storage/permissions.js";
import { saveBrokerPolicy } from "../../src/disclosure/broker/open.js";
import { printFirstRunNoticeOnce } from "../../src/first-run-notice.js";

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

  it("leaves NO direct fortress-root child group/other-accessible (fortress traverse ACE guard)", async () => {
    // With the file-grant fortress traverse ACE (F1 fix, 2026-07-14), the
    // agent uid can reach direct fortress-root children by known name; the
    // 0700 fortress dir is no longer a masking layer for lax child modes.
    // The startup tightener is the structural backstop: after it runs, every
    // direct child of the fortress root must be owner-only. (Writers must
    // ALSO create owner-only from the first byte -- broker-policy.json and
    // first-run-notice-shown were fixed for exactly that create-window; see
    // the FORTRESS-DIR TRAVERSAL note in src/file-grant/fs-ops.ts.)
    const children = [
      { name: "broker-policy.json", kind: "file", mode: 0o644 },
      { name: "first-run-notice-shown", kind: "file", mode: 0o644 },
      { name: "sanctuary.json", kind: "file", mode: 0o664 },
      { name: "grants", kind: "dir", mode: 0o711 },
      { name: "policy", kind: "dir", mode: 0o755 },
    ] as const;
    for (const child of children) {
      const p = join(root, child.name);
      if (child.kind === "dir") {
        await mkdir(p, { mode: child.mode });
      } else {
        await writeFile(p, "x", { mode: child.mode });
      }
      // mkdir/writeFile modes are masked by umask; force the lax mode.
      await chmod(p, child.mode);
    }

    await tightenStoragePermissions(root);

    for (const child of children) {
      const info = await stat(join(root, child.name));
      expect(
        info.mode & 0o077,
        `${child.name} must be owner-only after tightening`
      ).toBe(0);
    }
  });

  it("direct fortress-root writers create owner-only from the first byte (no tightener, umask 022)", async () => {
    // These writers were the create-window class (default-0644-then-chmod, or
    // no mode at all) closed by the F1 fix-round. The guarantee under test is
    // that the file is owner-only AT CREATION, BEFORE any tightener runs --
    // otherwise a live file-grant fortress traverse ACE could read it by known
    // name during the lax window. Force a lax umask to make a regression
    // (default-mode create) visible.
    const priorUmask = process.umask(0o022);
    try {
      // broker-policy.json: holds secret NAMES/scopes/TTLs (P1, Codex #3).
      await saveBrokerPolicy(root, [
        { name: "skill", secrets: [{ name: "api_key", scope: "read" }] },
      ]);
      const broker = await stat(join(root, "broker-policy.json"));
      expect(broker.mode & 0o077, "broker-policy.json owner-only at create").toBe(0);

      // first-run-notice-shown marker (P2, Codex #4).
      await printFirstRunNoticeOnce(root, { write: () => true });
      const marker = await stat(join(root, "first-run-notice-shown"));
      expect(marker.mode & 0o077, "first-run-notice-shown owner-only at create").toBe(0);
    } finally {
      process.umask(priorUmask);
    }
  });
});
