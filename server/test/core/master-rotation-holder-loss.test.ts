import { afterEach, describe, expect, it } from "vitest";
import { mkdtemp, readFile, rm, unlink, writeFile } from "node:fs/promises";
import { mkdirSync, renameSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import {
  establishMaster,
  CUSTODY_ENVELOPE_KEY,
  ROTATION_JOURNAL_KEY,
  STAGED_CUSTODY_ENVELOPE_KEY,
  STAGED_CUSTODY_SENTINEL_KEY,
} from "../../src/core/master-custody.js";
import { resumeRotation, rotateMaster } from "../../src/core/master-rotation.js";
import { FilesystemStorage } from "../../src/storage/filesystem.js";
import { resetKernelLockPoisonForTests } from "../../src/storage/cross-process-lock.js";
import { decrypt, encrypt, type EncryptedPayload } from "../../src/core/encryption.js";
import { generateRandomKey } from "../../src/core/random.js";

const supported = process.platform === "darwin" || process.platform === "linux";

describe.skipIf(!supported)("master rotation kernel-holder fencing", () => {
  const cleanup: string[] = [];

  afterEach(async () => {
    resetKernelLockPoisonForTests();
    await Promise.all(
      cleanup.splice(0).map((path) => rm(path, { recursive: true, force: true })),
    );
  });

  it("aborts before the first durable rotation mutation when socket ownership is lost", async () => {
    const root = await mkdtemp(join(tmpdir(), "sanctuary-rotate-holder-loss-"));
    cleanup.push(root);
    const storage = new FilesystemStorage(join(root, "state"));
    const passphrase = "holder-loss-rotation-passphrase";
    const initialized = await establishMaster({
      storage,
      passphrase,
      firstRun: { installMode: "interactive", mintRecoveryKey: true },
    });
    await initialized.masterWriteBarrier?.release();
    const originalEnvelope = await storage.read("_meta", CUSTODY_ENVELOPE_KEY);
    expect(originalEnvelope).not.toBeNull();

    let socketPath: string | null = null;
    const lostBeforeMutation = await rotateMaster({
      storage,
      fortressId: "holder-loss-regression",
      passphrase,
      __testAfterKernelSocketAcquired: (path) => {
        socketPath = path;
      },
      approve: async () => {
        if (socketPath === null) throw new Error("holder socket was not observed");
        await unlink(socketPath);
        return true;
      },
      captureRecoveryKey: async (key, verify) => verify(key),
    }).catch((error) => error as unknown);
    expect(lostBeforeMutation).toBeInstanceOf(AggregateError);
    expect((lostBeforeMutation as AggregateError).errors.map(String).join("\n"))
      .toMatch(/socket (?:identity was lost|changed before release)|holder.*(?:lost|exited|closed)/i);

    expect(await storage.read("_meta", CUSTODY_ENVELOPE_KEY)).toEqual(
      originalEnvelope,
    );
    expect(await storage.read("_meta", ROTATION_JOURNAL_KEY)).toBeNull();
    expect(await storage.read("_meta", STAGED_CUSTODY_ENVELOPE_KEY)).toBeNull();
    expect(await storage.read("_meta", STAGED_CUSTODY_SENTINEL_KEY)).toBeNull();
  });

  it("refuses a post-acquire fortress replacement without mutating either tree", async () => {
    const root = await mkdtemp(join(tmpdir(), "sanctuary-rotate-root-swap-"));
    const displaced = `${root}.displaced`;
    cleanup.push(root, displaced);
    const storage = new FilesystemStorage(join(root, "state"));
    const passphrase = "root-swap-rotation-passphrase";
    const initialized = await establishMaster({
      storage,
      passphrase,
      firstRun: { installMode: "interactive", mintRecoveryKey: true },
    });
    await initialized.masterWriteBarrier?.release();
    const originalEnvelope = await storage.read("_meta", CUSTODY_ENVELOPE_KEY);
    expect(originalEnvelope).not.toBeNull();
    const marker = join(root, "replacement-marker");

    await expect(rotateMaster({
      storage,
      fortressPath: root,
      fortressId: "root-swap-rotation",
      passphrase,
      __testAfterKernelHolderAcquired: () => {
        renameSync(root, displaced);
        mkdirSync(root, { recursive: true, mode: 0o700 });
        writeFileSync(marker, "replacement", { mode: 0o600 });
      },
      approve: async () => true,
      captureRecoveryKey: async (key, verify) => verify(key),
    })).rejects.toThrow(/root.*changed|identity changed/i);

    expect(await storage.read("_meta", CUSTODY_ENVELOPE_KEY)).toBeNull();
    const displacedStorage = new FilesystemStorage(join(displaced, "state"));
    expect(await displacedStorage.read("_meta", CUSTODY_ENVELOPE_KEY)).toEqual(
      originalEnvelope,
    );
    expect(await displacedStorage.read("_meta", ROTATION_JOURNAL_KEY)).toBeNull();
  });

  it("resumes after holder loss immediately following an atomic Castle-pin publish", async () => {
    const root = await mkdtemp(join(tmpdir(), "sanctuary-rotate-pin-loss-"));
    cleanup.push(root);
    const storage = new FilesystemStorage(join(root, "state"));
    const passphrase = "pin-holder-loss-passphrase";
    const established = await establishMaster({
      storage,
      passphrase,
      firstRun: { installMode: "interactive", mintRecoveryKey: true },
    });
    const seed = generateRandomKey();
    await writeFile(
      join(root, "castle-pinned-privkey.enc"),
      JSON.stringify(encrypt(seed, established.masterKey)),
      { mode: 0o600 },
    );
    await established.masterWriteBarrier?.release();
    established.masterKey.fill(0);
    let socketPath = "";
    const lostAfterPin = await rotateMaster({
      storage,
      fortressPath: root,
      fortressId: "pin-holder-loss",
      passphrase,
      __testAfterKernelSocketAcquired: (path) => { socketPath = path; },
      __testAfterCastlePinPublished: async () => {
        await unlink(socketPath);
      },
      approve: async () => true,
      captureRecoveryKey: async (key, verify) => verify(key),
    }).catch((error) => error as unknown);
    expect(lostAfterPin).toBeInstanceOf(AggregateError);
    expect((lostAfterPin as AggregateError).errors.map(String).join("\n"))
      .toMatch(/socket (?:identity was lost|changed before release)|holder.*(?:lost|exited|closed)/i);
    expect(await storage.read("_meta", ROTATION_JOURNAL_KEY)).not.toBeNull();

    resetKernelLockPoisonForTests();
    await resumeRotation({
      storage,
      fortressPath: root,
      fortressId: "pin-holder-loss",
      passphrase,
    });
    const final = await establishMaster({ storage, passphrase });
    try {
      const pin = JSON.parse(
        await readFile(join(root, "castle-pinned-privkey.enc"), "utf8"),
      ) as EncryptedPayload;
      expect(decrypt(pin, final.masterKey)).toEqual(seed);
    } finally {
      await final.masterWriteBarrier?.release();
      final.masterKey.fill(0);
      seed.fill(0);
    }
  });
});
