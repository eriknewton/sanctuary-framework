/**
 * S7: a crash mid `reset-passphrase --mode recovery-key` can leave a
 * `custody-rekey-journal` record under `_meta`. classifyMetaKey had no case for
 * it, so master rotation aborted with the opaque "not a record this rotation
 * engine recognizes" message. The fix classifies it and refuses with a remedy
 * that names the heal step (re-run the recovery-key rekey).
 *
 * Planted divergence: an unrelated unknown `_meta` key still gets the generic
 * refusal, so the new case is specific and not a blanket accept.
 */

import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";

import { establishMaster } from "../../src/core/master-custody.js";
import { rotateMaster } from "../../src/core/master-rotation.js";
import { FilesystemStorage } from "../../src/storage/filesystem.js";
import { stringToBytes } from "../../src/core/encoding.js";

const supported = process.platform === "darwin" || process.platform === "linux";
const PASSPHRASE = "rotation-rekey-journal-fortress-passphrase";

describe.skipIf(!supported)("rotation refuses a stray recovery-key rekey journal (S7)", () => {
  const cleanup: string[] = [];
  afterEach(async () => {
    await Promise.all(
      cleanup.splice(0).map((p) => rm(p, { recursive: true, force: true })),
    );
  });

  async function seed(): Promise<{ root: string; statePath: string }> {
    const root = await mkdtemp(join(tmpdir(), "rotation-rekey-journal-"));
    cleanup.push(root);
    const statePath = join(root, "state");
    // A distinct storage instance per phase: the per-instance master-write
    // barrier registry refuses raw writes once a barrier was released, so the
    // seed write and the rotation each use a FRESH instance (the WeakMap keys on
    // the instance).
    const est = await establishMaster({
      storage: new FilesystemStorage(statePath),
      passphrase: PASSPHRASE,
      firstRun: { installMode: "headless", mintRecoveryKey: true },
    });
    await est.masterWriteBarrier?.release();
    est.masterKey.fill(0);
    return { root, statePath };
  }

  async function attemptRotate(storage: FilesystemStorage, root: string): Promise<unknown> {
    try {
      await rotateMaster({
        storage,
        fortressPath: root,
        fortressId: "rotation-rekey-journal",
        passphrase: PASSPHRASE,
        approve: async () => true,
        captureRecoveryKey: async (key, verify) => verify(key),
      });
      return null;
    } catch (error) {
      return error;
    }
  }

  it("refuses rotation with a heal remedy naming the recovery-key rekey", async () => {
    const { root, statePath } = await seed();
    // A crash left the authenticated rekey journal behind.
    await new FilesystemStorage(statePath).write(
      "_meta",
      "custody-rekey-journal",
      stringToBytes("{}"),
    );

    const error = await attemptRotate(new FilesystemStorage(statePath), root);
    expect(error).toBeInstanceOf(Error);
    expect((error as Error).message).toMatch(/recovery-key/i);
    expect((error as Error).message).toMatch(/reset-passphrase/i);
  });

  it("PLANTED DIVERGENCE: an unrelated unknown _meta key still gets the generic refusal", async () => {
    const { root, statePath } = await seed();
    await new FilesystemStorage(statePath).write(
      "_meta",
      "totally-unknown-record",
      stringToBytes("{}"),
    );

    const error = await attemptRotate(new FilesystemStorage(statePath), root);
    expect(error).toBeInstanceOf(Error);
    expect((error as Error).message).toMatch(/not a record this rotation engine recognizes/i);
  });
});
