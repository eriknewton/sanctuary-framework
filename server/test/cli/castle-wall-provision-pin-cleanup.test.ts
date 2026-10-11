import { describe, expect, it, vi } from "vitest";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Writable } from "node:stream";

import { FilesystemStorage } from "../../src/storage/filesystem.js";
import { stringToBytes, toBase64url } from "../../src/core/encoding.js";
import { hashToString } from "../../src/core/hashing.js";
import { generateRandomKey } from "../../src/core/random.js";

class CaptureStream extends Writable {
  chunks: string[] = [];
  override _write(
    chunk: unknown,
    _encoding: BufferEncoding,
    callback: (error?: Error | null) => void,
  ): void {
    this.chunks.push(String(chunk));
    callback();
  }
  text(): string {
    return this.chunks.join("");
  }
}

describe("castle-wall provision-pin cleanup", () => {
  it("retries master barrier cleanup without replacing the provision-pin failure", async () => {
    vi.resetModules();
    const tempDirs: string[] = [];
    const masterCustody =
      await vi.importActual<typeof import("../../src/core/master-custody.js")>(
        "../../src/core/master-custody.js",
      );
    let releaseCalls = 0;
    vi.doMock("../../src/core/master-custody.js", () => ({
      ...masterCustody,
      acquireFortressMasterWriteBarrier: vi.fn(async () => {
        const controller = new AbortController();
        return {
          signal: controller.signal,
          filesystemBacked: true,
          assertSessionHeld: vi.fn(),
          assertHeld: vi.fn(),
          release: vi.fn(async () => {
            releaseCalls += 1;
            if (releaseCalls === 1) {
              throw new Error("test barrier cleanup stop");
            }
          }),
        };
      }),
    }));

    try {
      const { runProvisionPin } = await import("../../src/cli/castle-wall.js");
      const fortressPath = await mkdtemp(join(tmpdir(), "sanctuary-cw-cleanup-"));
      tempDirs.push(fortressPath);
      const storage = new FilesystemStorage(join(fortressPath, "state"));
      const masterKey = generateRandomKey();
      const recoveryKey = toBase64url(masterKey);
      await storage.write(
        "_meta",
        "recovery-key-hash",
        stringToBytes(hashToString(masterKey)),
      );
      const established = await masterCustody.establishMaster({
        storage,
        recoveryKey,
        storagePathHint: fortressPath,
      });
      await established.masterWriteBarrier?.release();
      established.masterKey.fill(0);

      const err = new CaptureStream();
      const code = await runProvisionPin([], {
        out: new CaptureStream(),
        err,
        env: { SANCTUARY_STORAGE_PATH: fortressPath },
        __testResolveProvisionCustodyCredential: async () => ({
          status: "resolved" as const,
          credential: {
            source: "env-recovery-key" as const,
            kind: "recovery-key" as const,
            recoveryKey,
            location: "SANCTUARY_RECOVERY_KEY",
            displaySource: "SANCTUARY_RECOVERY_KEY",
          },
          report: {
            found: ["env-recovery-key" as const],
            rejected: [],
            indeterminate: [],
            details: {},
            integrityIndeterminate: false,
            envelopePresent: true,
            noCustodyStateAtAll: false,
            custodyKeyUnverifiable: false,
            enrolledCustodyKeyItem: "not-found" as const,
          },
        }),
        __testAfterProvisionMasterResolved: () => {
          throw new Error("test primary provision stop");
        },
      });

      expect(code).toBe(1);
      expect(releaseCalls).toBe(2);
      expect(err.text()).toContain("test primary provision stop");
    } finally {
      vi.doUnmock("../../src/core/master-custody.js");
      vi.resetModules();
      await Promise.all(tempDirs.map((dir) => rm(dir, { recursive: true, force: true })));
    }
  });
});
