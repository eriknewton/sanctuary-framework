/**
 * Governed File-Grant v1 -- real POSIX FsOps smoke test.
 *
 * Exercises the production `PosixFileGrantFsOps` wiring against a real
 * temp directory (mkdtemp, matching the repo's safe temp-dir pattern in
 * `egress-gate/pf-anchor.ts`). This deliberately stays in the same-uid /
 * no-agent-origin-descriptor lane: no chown-to-a-different-uid is attempted
 * (that requires root and is out of scope for CI; see the module's own
 * doc-comment). Every OTHER file-grant test uses the injected `FakeFsOps`
 * fake per the build spec's testability shape -- this file is the one place
 * that proves the real implementation's plumbing (realpath / place /
 * removeEntry / no-descriptor-configured uid resolution) actually works.
 */

import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { mkdtemp, readFile, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { PosixFileGrantFsOps } from "../../src/file-grant/fs-ops.js";

describe("PosixFileGrantFsOps (real filesystem, same-uid lane)", () => {
  let fortressDir: string;
  let sourceDir: string;

  beforeEach(async () => {
    fortressDir = await mkdtemp(join(tmpdir(), "sanctuary-file-grant-fortress-"));
    sourceDir = await mkdtemp(join(tmpdir(), "sanctuary-file-grant-source-"));
  });

  afterEach(async () => {
    await rm(fortressDir, { recursive: true, force: true });
    await rm(sourceDir, { recursive: true, force: true });
  });

  it("realpath canonicalizes a path, following a symlink", async () => {
    const target = join(sourceDir, "real.txt");
    await writeFile(target, "hello");
    const link = join(sourceDir, "link.txt");
    await symlink(target, link);

    const fsOps = new PosixFileGrantFsOps(fortressDir);
    expect(await fsOps.realpath(link)).toBe(await fsOps.realpath(target));
  });

  it("place() links the canonical source into the tree, and removeEntry() scrubs it", async () => {
    const source = join(sourceDir, "granted.txt");
    await writeFile(source, "operator data");

    const fsOps = new PosixFileGrantFsOps(fortressDir);
    const canonical = await fsOps.realpath(source);
    await fsOps.place(canonical, "agent-1/fg_abc123");

    const placedPath = join(fortressDir, "grants", "agent-1", "fg_abc123");
    const content = await readFile(placedPath, "utf-8");
    expect(content).toBe("operator data");

    await fsOps.removeEntry("agent-1/fg_abc123");
    await expect(readFile(placedPath, "utf-8")).rejects.toThrow();

    // Idempotent: removing an already-absent entry does not throw.
    await expect(fsOps.removeEntry("agent-1/fg_abc123")).resolves.toBeUndefined();
  });

  it("agentUid resolves null when no agent-origin descriptor is configured (honest same-uid default)", async () => {
    const fsOps = new PosixFileGrantFsOps(fortressDir);
    expect(await fsOps.agentUid("agent-1")).toBeNull();
  });

  it("operatorUid reflects the current process uid", async () => {
    const fsOps = new PosixFileGrantFsOps(fortressDir);
    const expected = process.getuid?.() ?? null;
    expect(await fsOps.operatorUid()).toBe(expected);
  });
});
