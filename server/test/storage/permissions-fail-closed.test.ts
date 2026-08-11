/**
 * LD3 (STORAGE-PERMISSION-FAIL-WEAKER, MED, MUST-NEVER #5): reproduces and
 * closes the silent-degrade defect in `tightenStoragePermissions`.
 *
 * Pre-fix, a `chmod` failure on a mispermissioned pre-existing storage
 * entry was logged to stderr and swallowed, so startup continued as if the
 * owner-only at-rest permission layer had been applied. `readFileCustody`
 * (used by every storage read) applies no mode check by default, so a file
 * left group/other-readable by the failed chmod stayed readable by anyone
 * who could reach it at the OS level for the life of the process.
 *
 * This suite mocks `node:fs/promises` so `chmod` fails ONLY for one
 * specific target file inside a real temp directory (the rest of the walk
 * — stat/readdir/other chmods — runs against the real filesystem, exactly
 * like `test/storage/permissions.test.ts`). No operator machine state is
 * touched; the root is a fresh `mkdtemp` directory removed in `afterEach`.
 */

import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import { mkdtemp, mkdir, writeFile, stat, rm } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";

const { failChmodFor } = vi.hoisted(() => ({
  // Absolute path (set per-test) whose chmod call must fail; every other
  // path's chmod runs against the real filesystem unchanged.
  failChmodFor: { path: undefined as string | undefined },
}));

vi.mock("node:fs/promises", async (importOriginal) => {
  const actual = await importOriginal<typeof import("node:fs/promises")>();
  return {
    ...actual,
    chmod: async (path: string, mode: number) => {
      if (path === failChmodFor.path) {
        const err = new Error(
          `EPERM: operation not permitted, chmod '${path}'`
        ) as NodeJS.ErrnoException;
        err.code = "EPERM";
        throw err;
      }
      return actual.chmod(path, mode);
    },
  };
});

// Imported AFTER the mock so the module under test picks up the mocked chmod.
const { tightenStoragePermissions } = await import(
  "../../src/storage/permissions.js"
);

describe("tightenStoragePermissions — fail-closed on chmod failure (LD3)", () => {
  let root: string;

  beforeEach(async () => {
    root = await mkdtemp(join(tmpdir(), "sanctuary-perm-failclosed-test-"));
    failChmodFor.path = undefined;
  });

  afterEach(async () => {
    failChmodFor.path = undefined;
    await rm(root, { recursive: true, force: true });
  });

  it("throws (fails startup closed) when a file's chmod fails, instead of logging and continuing", async () => {
    const filePath = join(root, "secret.enc");
    await writeFile(filePath, "data", { mode: 0o644 });
    failChmodFor.path = filePath;

    await expect(tightenStoragePermissions(root)).rejects.toThrow(/EPERM/);

    // The permission control genuinely was NOT applied -- the fix must not
    // report failure while somehow still leaving the file tightened, nor
    // silently succeed with the lax mode still in place.
    const info = await stat(filePath);
    expect(info.mode & 0o777).toBe(0o644);
  });

  it("throws (fails startup closed) when a directory's chmod fails, instead of logging and continuing", async () => {
    const dirPath = join(root, "identities");
    await mkdir(dirPath, { mode: 0o755 });
    failChmodFor.path = dirPath;

    await expect(tightenStoragePermissions(root)).rejects.toThrow(/EPERM/);

    const info = await stat(dirPath);
    expect(info.mode & 0o777).toBe(0o755);
  });

  it("still does not throw when the root itself does not exist (first run, not a chmod failure)", async () => {
    failChmodFor.path = undefined;
    await expect(
      tightenStoragePermissions(join(root, "does-not-exist"))
    ).resolves.not.toThrow();
  });
});
