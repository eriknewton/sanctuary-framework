/**
 * The exclusive master-rotation barrier's `requireKernelAdmission` option:
 * with no kernel coordinates it refuses before the operation runs, while the
 * default keeps running the operation for every existing caller.
 */
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";

import { CUSTODY_WRITE_LOCK_NAMESPACE, MASTER_ROTATION_BARRIER_NAME } from "../../src/core/master-custody.js";
import { CrossProcessLockError, withExclusiveMasterRotationBarrier } from "../../src/storage/cross-process-lock.js";
import { FilesystemStorage } from "../../src/storage/filesystem.js";
import { MemoryStorage } from "../../src/storage/memory.js";

const NAMESPACE = CUSTODY_WRITE_LOCK_NAMESPACE;
const BARRIER = MASTER_ROTATION_BARRIER_NAME;
const dirs: string[] = [];
afterEach(async () => { for (const dir of dirs.splice(0)) await rm(dir, { recursive: true, force: true }); });

describe("exclusive barrier kernel admission", () => {
  it("refuses with a capability error and never runs the operation when coordinates are null", async () => {
    let ran = false;
    const refusal = await withExclusiveMasterRotationBarrier(new MemoryStorage(), NAMESPACE, BARRIER, async () => { ran = true; },
      { requireKernelAdmission: true }).catch(cause => cause);
    expect(refusal).toBeInstanceOf(CrossProcessLockError);
    expect(refusal).toMatchObject({ kind: "capability" });
    expect(ran).toBe(false);
  });

  it("keeps the default unchanged: null coordinates still run the operation for existing callers", async () => {
    for (const options of [undefined, {}, { timeoutMs: 0 }, { requireKernelAdmission: false }]) {
      let ran = false;
      await expect(withExclusiveMasterRotationBarrier(new MemoryStorage(), NAMESPACE, BARRIER, async () => { ran = true; return 7; }, options))
        .resolves.toBe(7);
      expect(ran).toBe(true);
    }
  });

  it("admits a kernel-backed filesystem fortress with the option set", async () => {
    const dir = await mkdtemp(join(tmpdir(), "kernel-admission-"));
    dirs.push(dir);
    const storage = new FilesystemStorage(join(dir, "state"));
    await expect(withExclusiveMasterRotationBarrier(storage, NAMESPACE, BARRIER, async () => "admitted",
      { timeoutMs: 0, requireKernelAdmission: true })).resolves.toBe("admitted");
  });
});
