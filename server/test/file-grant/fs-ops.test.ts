// fail-before-exempt: inherited supporting file-grant coverage still passes against pre-fix source; key-resolution fail-before coverage lives in state-envelope-integrity.test.ts and master-rotation.test.ts
/**
 * Governed File-Grant v1 -- real POSIX FsOps smoke test.
 *
 * Exercises the production `PosixFileGrantFsOps` wiring against a real
 * temp directory (mkdtemp, matching the repo's safe temp-dir pattern in
 * `egress-gate/pf-anchor.ts`). `place()` never chowns the per-agent
 * subdirectory to a different uid at all. The read primitive is the explicit
 * source-inode ACL plus execute-only grant-tree ancestor traversal, so
 * placement stays operator-owned and non-root revoke can unlink it. Every
 * OTHER file-grant test uses the
 * injected `FakeFsOps` fake per the build spec's testability shape -- this
 * file is the one place that proves the real implementation's plumbing
 * (realpath / place / removeEntry / no-descriptor-configured uid resolution)
 * actually works.
 */

import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { execFile as nodeExecFile } from "node:child_process";
import { mkdir, mkdtemp, readFile, rm, stat, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { mintFileGrant } from "../../src/file-grant/mint.js";
import {
  PosixFileGrantFsOps,
  type FileGrantExecCommand,
  type FileGrantMacAclLinkOps,
} from "../../src/file-grant/fs-ops.js";
import { makeFileGrantTestStore } from "./fixtures.js";

function execFile(file: string, args: string[]): Promise<void> {
  return new Promise((resolvePromise, rejectPromise) => {
    nodeExecFile(file, args, (error) => {
      if (error) {
        rejectPromise(error);
        return;
      }
      resolvePromise();
    });
  });
}

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

    const removed = await fsOps.removeEntry("agent-1/fg_abc123");
    expect(removed).toEqual({
      treeEntryRemoved: true,
      aclRemoval: { status: "not_applicable" },
      scrubbed: true,
    });
    await expect(readFile(placedPath, "utf-8")).rejects.toThrow();

    // Idempotent: removing an already-absent entry does not throw.
    await expect(fsOps.removeEntry("agent-1/fg_abc123")).resolves.toEqual({
      treeEntryRemoved: false,
      aclRemoval: { status: "not_applicable" },
      scrubbed: true,
    });
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

  it("place() records the grant on a uid-split box WITHOUT chowning the subdir (R2-5 + R3-3)", async () => {
    const processUid = process.getuid?.();
    if (processUid === undefined) return; // POSIX-only path

    // Configure a dedicated agent uid DISTINCT from the running process uid.
    // v1 never applies a cross-uid chown at all. The source-inode ACL carries
    // the read grant, while the grant-tree symlink stays operator-owned.
    // place() must NOT throw, must place the symlink, and must leave the
    // per-agent subdir OPERATOR-owned (the running process uid), never chowned
    // to the configured agent uid.
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

    // R3-3: the per-agent subdir stays operator-owned; no chown to the
    // configured (and here nonexistent) agent uid was attempted.
    const agentSubdir = join(fortressDir, "grants", "agent-1");
    const subdirStat = await stat(agentSubdir);
    expect(subdirStat.uid).toBe(processUid);
  });

  it("place() still FAILS CLOSED on a genuine filesystem error (R3-3: no chown left to relax)", async () => {
    // Put a FILE where the grants tree root must be a directory, so
    // ensureTreeRoot (mkdir) fails with EEXIST. This is a genuine placement
    // error, so place() must still throw. R3-3 removed the chown entirely (it
    // is never attempted, privilege-gated or otherwise), so there is no
    // remaining error class place() swallows: every mkdir/realpath/symlink
    // failure stays fatal (fail-closed).
    await writeFile(join(fortressDir, "grants"), "not a directory");
    const source = join(sourceDir, "granted.txt");
    await writeFile(source, "operator data");
    const fsOps = new PosixFileGrantFsOps(fortressDir);
    const canonical = await fsOps.realpath(source);

    await expect(fsOps.place(canonical, "agent-1/fg_fatal")).rejects.toThrow();
  });

  it("mint refuses a FIFO before any hard link, ACE, probe, or grant record", async () => {
    if (process.platform === "win32" || process.getuid === undefined) return;

    const originDir = join(fortressDir, "policy", "egress");
    await mkdir(originDir, { recursive: true });
    await writeFile(
      join(originDir, "agent-origin.json"),
      JSON.stringify({
        mode: "uid",
        agent_uid: process.getuid() + 1,
        system_uid_allow_ceiling: 1,
      })
    );

    const fifo = join(sourceDir, "source.fifo");
    await execFile("mkfifo", [fifo]);
    const commands: FileGrantExecCommand[] = [];
    const hardLinks: Array<{ existingPath: string; newPath: string }> = [];
    const macAclLinkOps: FileGrantMacAclLinkOps = {
      link: async (existingPath, newPath) => {
        hardLinks.push({ existingPath, newPath });
      },
      open: async () => {
        throw new Error("unexpected macOS ACL hard-link open");
      },
      rm: async () => {},
    };
    const fsOps = new PosixFileGrantFsOps(fortressDir, {
      platform: "darwin",
      macAclLinkOps,
      execRunner: {
        execFile: async (command) => {
          commands.push(command);
          if (command.file === "id") return { stdout: "agentuser\n", stderr: "" };
          return { stdout: "", stderr: "" };
        },
      },
    });
    const { grantStore } = await makeFileGrantTestStore();

    await expect(
      mintFileGrant(
        {
          subjectAgentId: "agent-1",
          scope: { kind: "file", path: fifo },
          mode: "read",
          ttlSeconds: 3600,
          createdBy: "operator-1",
        },
        { fsOps, store: grantStore, now: new Date("2026-07-13T00:00:00.000Z") }
      )
    ).rejects.toThrow(/not a regular file or directory/);

    expect(await grantStore.list()).toHaveLength(0);
    expect(commands).toHaveLength(0);
    expect(hardLinks).toHaveLength(0);
    await expect(stat(join(fortressDir, "grants"))).rejects.toThrow();
  });
});
