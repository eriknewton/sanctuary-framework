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
const CHILD_RELEASE_EVENT_TIMEOUT_MS = 2_000;
const BARRIER_RETRY_MS = 1_000;
// 250 = BARRIER_RETRY_MS / 4, long enough for one live-reader probe to block.
const DRAIN_BLOCK_PROBE_MS = BARRIER_RETRY_MS / 4;

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function deferred<T = void>(): {
  promise: Promise<T>;
  resolve: (value: T | PromiseLike<T>) => void;
  reject: (error: unknown) => void;
} {
  let resolve!: (value: T | PromiseLike<T>) => void;
  let reject!: (error: unknown) => void;
  const promise = new Promise<T>((res, rej) => {
    resolve = res;
    reject = rej;
  });
  return { promise, resolve, reject };
}

describe.skipIf(!supported)("master rotation shared/exclusive writer barrier", () => {
  const cleanup: string[] = [];
  // Child processes spawned by a test (the two-process rotation-barrier
  // writer fixture). Killed only on the happy path inline below; tracked
  // here so a failing assertion or timeout before that point cannot strand
  // a live writer holding the fortress lock past the test.
  const children: ChildProcess[] = [];
  const rotations: Promise<unknown>[] = [];

  afterEach(async () => {
    const spawned = children.splice(0);
    for (const child of spawned) {
      if (child.exitCode === null && child.signalCode === null) {
        child.kill("SIGKILL");
      }
    }
    await Promise.all(spawned.map((child) =>
      child.exitCode !== null || child.signalCode !== null
        ? Promise.resolve()
        : new Promise<void>((resolve) => child.once("close", () => resolve()))));
    await Promise.allSettled(rotations.splice(0));
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
    const writerClosed = deferred<number | null>();
    writer.once("error", writerClosed.reject);
    writer.once("close", writerClosed.resolve);

    const eventOrder: Array<"writer-final-write" | "conversion"> = [];
    const writerReady = deferred<void>();
    const writerWrote = deferred<void>();
    const writerReleased = deferred<void>();
    let stdout = "";
    let stderr = "";
    let sawWriterFinalWrite = false;
    let sawWriterReleased = false;
    writer.stdout.on("data", (chunk: Buffer) => {
      stdout += chunk.toString("utf8");
      if (stdout.includes("READY\n")) writerReady.resolve();
      if (!sawWriterFinalWrite && stdout.includes("WROTE\n")) {
        sawWriterFinalWrite = true;
        eventOrder.push("writer-final-write");
        writerWrote.resolve();
      }
      if (!sawWriterReleased && stdout.includes("RELEASED\n")) {
        sawWriterReleased = true;
        writerReleased.resolve();
      }
    });
    writer.stderr.on("data", (chunk: Buffer) => { stderr += chunk.toString("utf8"); });
    await Promise.race([
      writerReady.promise,
      writerClosed.promise.then((code) => {
        throw new Error(`writer fixture closed before readiness with code ${code}; stderr: ${stderr}`);
      }),
    ]);

    let exclusiveBound!: () => void;
    const exclusiveIsBound = new Promise<void>((resolve) => { exclusiveBound = resolve; });
    let releaseSent = false;
    let exclusiveDrainHookFired = false;
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
        retryMs: BARRIER_RETRY_MS,
        __testAfterExclusiveSocketAcquired: async () => {
          exclusiveBound();
        },
        __testAfterExclusiveDrain: async () => {
          exclusiveDrainHookFired = true;
          expect(releaseSent).toBe(true);
          expect(sawWriterFinalWrite).toBe(true);
          await Promise.race([
            writerReleased.promise,
            sleep(CHILD_RELEASE_EVENT_TIMEOUT_MS).then(() => {
              throw new Error("writer release marker did not arrive after drain");
            }),
          ]);
          expect(sawWriterReleased).toBe(true);
        },
      },
    }).then(
      (value) => ({ status: "fulfilled", value } as const),
      (error) => ({ status: "rejected", error } as const),
    );
    rotations.push(rotation);
    await Promise.race([
      exclusiveIsBound,
      rotation.then((outcome) => {
        if (outcome.status === "rejected") throw outcome.error;
        throw new Error("rotation completed before the exclusive barrier bound");
      }),
    ]);

    // The writer was admitted before the exclusive gate. Its last write is
    // allowed to finish; no later reader can unlock until rotation finalizes.
    writer.stdin.write("WRITE\n");
    await Promise.race([
      writerWrote.promise,
      writerClosed.promise.then((code) => {
        throw new Error(`writer fixture closed before final write with code ${code}; stderr: ${stderr}`);
      }),
    ]);
    expect(stdout).toContain("WROTE\n");
    expect(eventOrder).toContain("writer-final-write");
    // Bounded-time witness: proving the drain WAITS for the live reader needs a time bound, and this
    // probe is it. A drain that does not wait is caught when it reaches __testAfterExclusiveDrain within
    // DRAIN_BLOCK_PROBE_MS; one that also stalls past that window can pass a single run. The release
    // handshake below removes the old close-window race; it does not remove this bound.
    await sleep(DRAIN_BLOCK_PROBE_MS);
    expect(exclusiveDrainHookFired).toBe(false);
    expect(writer.exitCode).toBeNull();
    releaseSent = true;
    writer.stdin.end("RELEASE\n");
    const rotationOutcome = await rotation;
    if (rotationOutcome.status === "rejected") {
      throw rotationOutcome.error;
    }
    expect(await writerClosed.promise, stderr).toBe(0);
    expect(stdout).toContain("RELEASED\n");
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
