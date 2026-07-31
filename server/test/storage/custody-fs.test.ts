import { afterEach, beforeEach, describe, expect, it } from "vitest";
import {
  chmod,
  mkdir,
  mkdtemp,
  readFile,
  rename,
  rm,
  symlink,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { lstat, open } from "node:fs/promises";
import {
  CustodyFsError,
  readFileCustody,
  writeFileCustody,
} from "../../src/storage/custody-fs.js";
import { FilesystemStorage } from "../../src/storage/filesystem.js";

describe("custody-fs descriptor-first file API", () => {
  let dir: string;

  beforeEach(async () => {
    dir = await mkdtemp(join(tmpdir(), "sanctuary-custody-fs-"));
  });

  afterEach(async () => {
    await rm(dir, { recursive: true, force: true });
  });

  it("rejects a symlink leaf before reading through it", async () => {
    const target = join(dir, "target.txt");
    const link = join(dir, "link.txt");
    await writeFile(target, "secret", { mode: 0o600 });
    await symlink(target, link);

    await expect(readFileCustody(link)).rejects.toMatchObject({
      code: "symlink_rejected",
    });
  });

  it("rejects a file-type mismatch", async () => {
    const path = join(dir, "not-a-file");
    await mkdir(path);

    await expect(readFileCustody(path)).rejects.toMatchObject({
      code: "not_regular_file",
    });
  });

  it("rejects wrong mode and wrong uid without reading bytes", async () => {
    const path = join(dir, "token.bin");
    await writeFile(path, "token", { mode: 0o600 });
    await chmod(path, 0o644);

    await expect(
      readFileCustody(path, { mode: { rejectGroupOrOther: true } }),
    ).rejects.toMatchObject({ code: "mode_rejected" });

    const currentUid = process.getuid?.();
    if (currentUid !== undefined) {
      await expect(
        readFileCustody(path, { uid: currentUid + 1 }),
      ).rejects.toMatchObject({ code: "uid_rejected" });
    }
  });

  it("detects a path swap between descriptor verification and read", async () => {
    const path = join(dir, "state.enc");
    const oldPath = join(dir, "state.enc.old");
    await writeFile(path, "original", { mode: 0o600 });

    await expect(
      readFileCustody(path, {
        verifyPathIdentity: true,
        onDescriptorVerified: async () => {
          await rename(path, oldPath);
          await writeFile(path, "swapped", { mode: 0o600 });
        },
      }),
    ).rejects.toMatchObject({ code: "path_identity_changed" });
  });

  it("writes atomically with the target mode before exposing the final path", async () => {
    const path = join(dir, "written.bin");
    await writeFileCustody(path, Buffer.from("payload"), { mode: 0o600 });

    await expect(readFile(path, "utf8")).resolves.toBe("payload");
    await expect(
      readFileCustody(path, { mode: { exact: 0o600 }, encoding: "utf8" }),
    ).resolves.toBe("payload");
  });
});

describe("CustodyFsError", () => {
  it("carries a stable code for production callers to map without parsing text", () => {
    const error = new CustodyFsError("mode_rejected", "redacted");
    expect(error.code).toBe("mode_rejected");
    expect(error.message).toBe("redacted");
  });
});

describe("create-with-fchown owner option (fortress-ownership spec 2026-07-30)", () => {
  let dir: string;

  beforeEach(async () => {
    dir = await mkdtemp(join(tmpdir(), "sanctuary-custody-owner-"));
  });

  afterEach(async () => {
    await rm(dir, { recursive: true, force: true });
  });

  const selfOwner = () => ({
    uid: process.getuid?.() ?? 0,
    gid: process.getgid?.() ?? 0,
  });

  it("applies the owner on the descriptor before the atomic rename (and to created parent dirs)", async () => {
    const target = join(dir, "made", "deep", "file.enc");
    await writeFileCustody(target, "payload", {
      mode: 0o600,
      owner: selfOwner(),
      ownerBase: dir,
    });
    // Owner + contents are read through ONE descriptor (no stat-then-open
    // check-then-use race on the path).
    const handle = await open(target, "r");
    try {
      const stats = await handle.stat();
      expect(stats.uid).toBe(selfOwner().uid);
      expect(await handle.readFile("utf8")).toBe("payload");
    } finally {
      await handle.close();
    }
    expect((await lstat(join(dir, "made"))).uid).toBe(selfOwner().uid);
    expect((await lstat(join(dir, "made", "deep"))).uid).toBe(selfOwner().uid);
  });

  it("FAILS CLOSED: an impossible owner fails the whole write and leaves no destination file", async function (this: void) {
    if (process.getuid?.() === 0) {
      // Root can chown to anyone; the fail-closed branch is unreachable.
      return;
    }
    const target = join(dir, "file.enc");
    await expect(
      writeFileCustody(target, "payload", {
        mode: 0o600,
        // A non-root process cannot give a file away to root: fchown EPERM.
        // ownerBase is supplied so the failure is the CHOWN, not the missing
        // containment root (otherwise this test would pass for the wrong reason).
        owner: { uid: 0, gid: 0 },
        ownerBase: dir,
      }),
    ).rejects.toThrow(/EPERM|operation not permitted/i);
    // Never a silent degradation: no destination file with the wrong owner.
    await expect(lstat(target)).rejects.toThrow();
  });

  it("REFUSES an owner-write with no declared ownerBase (fail-closed containment root)", async () => {
    await expect(
      writeFileCustody(join(dir, "x.enc"), "payload", {
        mode: 0o600,
        owner: selfOwner(),
      }),
    ).rejects.toThrow(/requires `ownerBase`/);
  });

  it("REFUSES an owner-write through a PRE-EXISTING symlinked ancestor when mkdir creates nothing (gate round 3)", async () => {
    // The round-3 BLOCKER: when every directory already exists, recursive
    // mkdir returns undefined, so the created-chain check never runs. The
    // temp-file open then followed the symlinked ancestor and the file was
    // created, chowned, and renamed OUTSIDE the tree. The base-to-leaf
    // no-follow verification must refuse regardless of what mkdir created.
    const outside = await mkdtemp(join(tmpdir(), "custody-outside-"));
    try {
      await mkdir(join(outside, "egress", "rules"), { recursive: true });
      await symlink(outside, join(dir, "policy"));
      const target = join(dir, "policy", "egress", "rules", "file.enc");
      await expect(
        writeFileCustody(target, "payload", {
          mode: 0o600,
          owner: selfOwner(),
          ownerBase: dir,
        }),
      ).rejects.toThrow(/refusing an owner-write through/);
      // Nothing was planted outside.
      await expect(lstat(join(outside, "egress", "rules", "file.enc"))).rejects.toThrow();
    } finally {
      await rm(outside, { recursive: true, force: true });
    }
  });

  it("FilesystemStorage threads its owner into every write (fail-closed proves the call path)", async function (this: void) {
    if (process.getuid?.() === 0) {
      return;
    }
    const good = new FilesystemStorage(join(dir, "store"), { owner: selfOwner() });
    await good.write("ns", "key", new TextEncoder().encode("v"));
    expect(await good.read("ns", "key")).not.toBeNull();

    // With an impossible owner the SAME write must fail: proof the owner
    // actually reaches fchown (a storage that ignored the option would pass).
    const bad = new FilesystemStorage(join(dir, "store-bad"), { owner: { uid: 0, gid: 0 } });
    await expect(bad.write("ns", "key", new TextEncoder().encode("v"))).rejects.toThrow();
    expect(await bad.read("ns", "key")).toBeNull();
  });

  it("REFUSES to chown created dirs through a symlinked ANCESTOR (2026-07-31 re-gate BLOCKER)", async () => {
    // The reported primitive: a pre-existing symlinked path component made
    // the recursive mkdir create the tree OUTSIDE and the chain chown hand
    // that outside tree away. Now every component is opened O_NOFOLLOW, so
    // the write fails closed instead.
    const outside = await mkdtemp(join(tmpdir(), "custody-outside-"));
    try {
      await symlink(outside, join(dir, "policy"));
      const target = join(dir, "policy", "egress", "rules", "file.enc");
      await expect(
        writeFileCustody(target, "payload", { mode: 0o600, owner: selfOwner(), ownerBase: dir }),
      ).rejects.toThrow(/refusing to chown through/);
    } finally {
      await rm(outside, { recursive: true, force: true });
    }
  });

  it("still chowns a legitimately created chain (no symlink on the path)", async () => {
    const target = join(dir, "a", "b", "c", "file.enc");
    await writeFileCustody(target, "payload", { mode: 0o600, owner: selfOwner(), ownerBase: dir });
    for (const created of [join(dir, "a"), join(dir, "a", "b"), join(dir, "a", "b", "c")]) {
      expect((await lstat(created)).uid).toBe(selfOwner().uid);
    }
  });

  it("no owner option means no chown call and unchanged behavior", async () => {
    const target = join(dir, "plain.enc");
    await writeFileCustody(target, "payload", { mode: 0o600 });
    const stats = await lstat(target);
    expect(stats.uid).toBe(process.getuid?.() ?? stats.uid);
  });
});
