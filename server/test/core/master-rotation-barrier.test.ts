// fail-before-exempt: race-condition test fix whose old form was intermittently green.
import { spawn, type ChildProcess } from "node:child_process";
import { fileURLToPath } from "node:url";
import { mkdtemp, rm } from "node:fs/promises";
import { mkdirSync, renameSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";

import { establishMaster } from "../../src/core/master-custody.js";
import { decrypt, encrypt, type EncryptedPayload } from "../../src/core/encryption.js";
import { bytesToString, stringToBytes } from "../../src/core/encoding.js";
import { derivePurposeKey } from "../../src/core/key-derivation.js";
import { rotateMaster } from "../../src/core/master-rotation.js";
import { FilesystemStorage } from "../../src/storage/filesystem.js";

const supported = process.platform === "darwin" || process.platform === "linux";

describe.skipIf(!supported)("master rotation shared/exclusive writer barrier", () => {
  const cleanup: string[] = [];
  // Child processes spawned by a test (the two-process rotation-barrier
  // writer fixture). Killed only on the happy path inline below; tracked
  // here so a failing assertion or timeout before that point cannot strand
  // a live writer holding the fortress lock past the test.
  const children: ChildProcess[] = [];

  afterEach(async () => {
    for (const child of children.splice(0)) {
      if (child.exitCode === null && child.signalCode === null) {
        child.kill("SIGKILL");
      }
    }
    await Promise.all(cleanup.splice(0).map((path) =>
      rm(path, { recursive: true, force: true })));
  });

  it("drains an admitted old-master process before conversion and rotates its final write", async () => {
    const root = await mkdtemp(join(tmpdir(), "sanctuary-master-barrier-"));
    cleanup.push(root);
    const storagePath = join(root, "state");
    const storage = new FilesystemStorage(storagePath);
    const passphrase = "two-process-master-barrier-passphrase";
    const initial = await establishMaster({
      storage,
      passphrase,
      firstRun: { installMode: "interactive", mintRecoveryKey: true },
    });
    try {
      const payload = encrypt(
        stringToBytes(JSON.stringify({ source: "initial-writer" })),
        derivePurposeKey(initial.masterKey, "l4-reputation"),
      );
      await storage.write(
        "_reputation",
        "initial-writer",
        stringToBytes(JSON.stringify(payload)),
      );
    } finally {
      await initial.masterWriteBarrier?.release();
      initial.masterKey.fill(0);
    }

    const fixture = fileURLToPath(
      new URL("./master-rotation-barrier-child.ts", import.meta.url),
    );
    const writer = spawn(
      process.execPath,
      ["--import", "tsx", fixture, storagePath, passphrase],
      { stdio: ["pipe", "pipe", "pipe"] },
    );
    children.push(writer);
    const eventOrder: Array<"writer-final-write" | "conversion"> = [];
    let releaseExclusiveDrain: () => void = () => {};
    let stdout = "";
    let stderr = "";
    let sawWriterFinalWrite = false;
    writer.stdout.on("data", (chunk: Buffer) => {
      stdout += chunk.toString("utf8");
      if (!sawWriterFinalWrite && stdout.includes("WROTE\n")) {
        sawWriterFinalWrite = true;
        eventOrder.push("writer-final-write");
        releaseExclusiveDrain();
      }
    });
    writer.stderr.on("data", (chunk: Buffer) => { stderr += chunk.toString("utf8"); });
    await new Promise<void>((resolve, reject) => {
      writer.once("error", reject);
      const inspect = (): void => {
        if (stdout.includes("READY\n")) resolve();
        else writer.stdout.once("data", inspect);
      };
      inspect();
    });

    let exclusiveBound!: () => void;
    const exclusiveIsBound = new Promise<void>((resolve) => { exclusiveBound = resolve; });
    let allowExclusiveDrain!: () => void;
    let exclusiveDrainReleased = false;
    releaseExclusiveDrain = (): void => {
      if (exclusiveDrainReleased) return;
      exclusiveDrainReleased = true;
      allowExclusiveDrain();
    };
    const exclusiveDrainMayStart = new Promise<void>((resolve) => {
      allowExclusiveDrain = resolve;
    });
    const rotation = rotateMaster({
      storage,
      fortressPath: root,
      fortressId: "two-process-master-barrier",
      passphrase,
      approve: async () => true,
      captureRecoveryKey: async (key, verify) => verify(key),
      failpoint: (point) => {
        if (point === "journal-converting-written") {
          eventOrder.push("conversion");
        }
      },
      __testMasterRotationBarrierOptions: {
        timeoutMs: 10_000,
        retryMs: 10,
        __testAfterExclusiveSocketAcquired: async () => {
          exclusiveBound();
          await exclusiveDrainMayStart;
        },
      },
    }).then(
      (value) => ({ status: "fulfilled", value } as const),
      (error) => ({ status: "rejected", error } as const),
    );
    await exclusiveIsBound;

    // The writer was admitted before the exclusive gate. Its last write is
    // allowed to finish; no later reader can unlock until rotation finalizes.
    const writerExit = new Promise<number | null>((resolve, reject) => {
      writer.once("error", reject);
      writer.once("close", resolve);
    }).finally(() => releaseExclusiveDrain());
    writer.stdin.end("WRITE\n");
    expect(await writerExit, stderr).toBe(0);
    expect(stdout).toContain("WROTE\n");
    expect(eventOrder).toContain("writer-final-write");
    const rotationOutcome = await rotation;
    if (rotationOutcome.status === "rejected") {
      throw rotationOutcome.error;
    }
    expect(eventOrder).toEqual(["writer-final-write", "conversion"]);

    const final = await establishMaster({ storage, passphrase });
    try {
      for (const key of ["initial-writer", "late-writer"]) {
        const raw = await storage.read("_reputation", key);
        expect(raw).not.toBeNull();
        const envelope = JSON.parse(bytesToString(raw!)) as EncryptedPayload;
        const plain = decrypt(
          envelope,
          derivePurposeKey(final.masterKey, "l4-reputation"),
        );
        expect(JSON.parse(bytesToString(plain)).source).toContain("writer");
      }
    } finally {
      await final.masterWriteBarrier?.release();
      final.masterKey.fill(0);
    }
  }, 20_000);

  it("refuses unlock if the fortress root changes after shared-barrier admission", async () => {
    const root = await mkdtemp(join(tmpdir(), "sanctuary-master-barrier-swap-"));
    const displaced = `${root}.displaced`;
    cleanup.push(root, displaced);
    const storage = new FilesystemStorage(join(root, "state"));
    const passphrase = "shared-admission-root-swap-passphrase";
    const initialized = await establishMaster({
      storage,
      passphrase,
      firstRun: { installMode: "interactive", mintRecoveryKey: true },
    });
    await initialized.masterWriteBarrier?.release();
    initialized.masterKey.fill(0);

    await expect(establishMaster({
      storage,
      passphrase,
      __testMasterWriteBarrierOptions: {
        __testAfterSharedSocketAcquired: () => {
          renameSync(root, displaced);
          mkdirSync(join(root, "state", "_meta"), { recursive: true, mode: 0o700 });
        },
      },
    })).rejects.toMatchObject({ kind: "holder-lost" });
  });
});
