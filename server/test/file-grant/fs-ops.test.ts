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
import { mkdir, mkdtemp, readFile, rm, symlink, writeFile } from "node:fs/promises";
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

  it("sourceOwnerUid reflects the OWNER of the source file (not process.getuid())", async () => {
    const source = join(sourceDir, "owned.txt");
    await writeFile(source, "data");
    const fsOps = new PosixFileGrantFsOps(fortressDir);
    // In this single-uid CI lane the file's owner is the running uid, but the
    // key property is that the value comes from stat(source), not the process.
    const expected = process.getuid?.() ?? null;
    expect(await fsOps.sourceOwnerUid(await fsOps.realpath(source))).toBe(expected);
  });

  it("sourceOwnerUid returns null for a vanished path (fails toward unmet, never throws)", async () => {
    const fsOps = new PosixFileGrantFsOps(fortressDir);
    expect(await fsOps.sourceOwnerUid(join(sourceDir, "does-not-exist"))).toBeNull();
  });

  it("place() rejects a traversing tree entry and creates nothing outside the root", async () => {
    const source = join(sourceDir, "granted.txt");
    await writeFile(source, "operator data");
    const fsOps = new PosixFileGrantFsOps(fortressDir);
    const canonical = await fsOps.realpath(source);

    await expect(fsOps.place(canonical, "../escape/pwned")).rejects.toThrow(/escapes the grant-tree root/);

    // Nothing was created at the escaped location.
    const escaped = join(fortressDir, "escape", "pwned");
    await expect(readFile(escaped, "utf-8")).rejects.toThrow();
  });

  it("removeEntry() rejects a traversing tree entry", async () => {
    const fsOps = new PosixFileGrantFsOps(fortressDir);
    await expect(fsOps.removeEntry("../../etc/passwd")).rejects.toThrow(/escapes the grant-tree root/);
  });

  it("place() still records the grant on a NON-root uid-split box (chown is privilege-gated, not fatal) (R2-5)", async () => {
    const processUid = process.getuid?.();
    if (processUid === undefined) return; // POSIX-only path

    // Configure a dedicated agent uid DISTINCT from the running process uid, so
    // place() would attempt a cross-uid chown. On a NON-root operator that chown
    // is skipped (privilege-gated) rather than EPERM-ing the whole mint; on a
    // root runner it succeeds. Either way place() must NOT throw and the symlink
    // must still be placed (grant recordable on the target host; enforcement
    // stays the honest `unverified`).
    const originDir = join(fortressDir, "policy", "egress");
    await mkdir(originDir, { recursive: true });
    await writeFile(
      join(originDir, "agent-origin.json"),
      JSON.stringify({
        mode: "uid",
        agent_uid: processUid + 1000,
        system_uid_allow_ceiling: 1,
      }),
    );

    const source = join(sourceDir, "granted.txt");
    await writeFile(source, "operator data");
    const fsOps = new PosixFileGrantFsOps(fortressDir);
    const canonical = await fsOps.realpath(source);

    // Must NOT throw even though a distinct agent uid is configured.
    await expect(fsOps.place(canonical, "agent-1/fg_r2_5")).resolves.toBeUndefined();

    // The symlink was placed and resolves to the source.
    const placedPath = join(fortressDir, "grants", "agent-1", "fg_r2_5");
    expect(await readFile(placedPath, "utf-8")).toBe("operator data");
  });

  it("place() still FAILS CLOSED on a non-chown filesystem error (R2-5 relaxes chown-EPERM only)", async () => {
    // Put a FILE where the grants tree root must be a directory, so
    // ensureTreeRoot (mkdir) fails with EEXIST. This is a genuine placement
    // error, not a privilege/chown skip, so place() must still throw -- the R2-5
    // relaxation is chown-EPERM only, never a blanket swallow of place() errors.
    await writeFile(join(fortressDir, "grants"), "not a directory");
    const source = join(sourceDir, "granted.txt");
    await writeFile(source, "operator data");
    const fsOps = new PosixFileGrantFsOps(fortressDir);
    const canonical = await fsOps.realpath(source);

    await expect(fsOps.place(canonical, "agent-1/fg_fatal")).rejects.toThrow();
  });
});
