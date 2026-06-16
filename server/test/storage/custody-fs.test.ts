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

import {
  CustodyFsError,
  readFileCustody,
  writeFileCustody,
} from "../../src/storage/custody-fs.js";

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
