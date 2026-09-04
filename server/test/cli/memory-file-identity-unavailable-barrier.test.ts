/**
 * L2 (Grok re-gate residual): a `writeIntent` memory unlock acquires the shared
 * master-rotation barrier BEFORE the unlock and transfers it to the caller ONLY
 * on the successful bootstrap return. The bootstrap's "primary identity is
 * unavailable" early return zeroed the master but did NOT release that barrier
 * (only the construction `catch` did), so a fortress with an envelope but no
 * primary identity leaked a shared reader that blocked `rotate-master` for the
 * process lifetime.
 *
 * This test drives that exact path through the real CLI command and proves the
 * barrier is released: after the command exits on identity-unavailable, an
 * exclusive rotation barrier can be acquired. It is a serialization/divergence
 * proof — the same run against the pre-fix source (no release on the early
 * return) leaves the reader held and the exclusive acquire fails closed.
 *
 * (AGENTS rule 12: a bounded lease reachable from a CLI caller, released on
 * every exit path, proven under a following rotation.)
 */

import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Writable } from "node:stream";
import { afterEach, describe, expect, it } from "vitest";

import { runMemoryEmitCommand } from "../../src/cli/memory-file.js";
import { establishMaster } from "../../src/core/master-custody.js";
import {
  withExclusiveMasterRotationBarrier,
  CrossProcessLockError,
} from "../../src/storage/cross-process-lock.js";
import { FilesystemStorage } from "../../src/storage/filesystem.js";

const supported = process.platform === "darwin" || process.platform === "linux";
const NS = "_meta";
const BARRIER = "custody-master-rotation";
const PASSPHRASE = "memory-file-identity-unavailable-barrier-passphrase";
const APPROVE_DIALOG = () => ({
  status: 0,
  signal: null,
  stdout: Buffer.from("approve\n"),
});

function makeSink(): { stream: Writable; text: () => string } {
  const chunks: string[] = [];
  const stream = new Writable({
    write(chunk, _enc, cb) {
      chunks.push(chunk.toString());
      cb();
    },
  });
  return { stream, text: () => chunks.join("") };
}

describe.skipIf(!supported)(
  "memory bootstrap releases the writeIntent barrier on identity-unavailable (L2)",
  () => {
    const cleanup: string[] = [];
    afterEach(async () => {
      await Promise.all(
        cleanup.splice(0).map((p) => rm(p, { recursive: true, force: true })),
      );
    });

    /**
     * A fortress with a custody envelope (so a passphrase unlock succeeds) but
     * NO primary identity — establishMaster first-run mints the envelope and
     * never creates an identity. Its own establishment barrier is released so the
     * only barrier the command-under-test holds is the writeIntent one.
     */
    async function envelopeOnlyFortress(): Promise<{ fortressPath: string }> {
      const fortressPath = await mkdtemp(join(tmpdir(), "l2-identity-unavailable-"));
      cleanup.push(fortressPath);
      const storage = new FilesystemStorage(join(fortressPath, "state"));
      const est = await establishMaster({
        storage,
        passphrase: PASSPHRASE,
        firstRun: { installMode: "headless", mintRecoveryKey: false },
      });
      await est.masterWriteBarrier?.release();
      est.masterKey.fill(0);
      return { fortressPath };
    }

    async function tryExclusive(
      storage: FilesystemStorage,
      timeoutMs: number,
    ): Promise<"ran" | CrossProcessLockError> {
      try {
        let ran = false;
        await withExclusiveMasterRotationBarrier(
          storage,
          NS,
          BARRIER,
          async () => {
            ran = true;
          },
          { timeoutMs, retryMs: 20 },
        );
        return ran ? "ran" : ("ran" as const);
      } catch (error) {
        if (error instanceof CrossProcessLockError) return error;
        throw error;
      }
    }

    it("returns identity-unavailable and leaves NO barrier holder, so a rotate proceeds", async () => {
      const { fortressPath } = await envelopeOnlyFortress();
      const out = makeSink();
      const err = makeSink();

      const code = await runMemoryEmitCommand({
        argv: ["--harness", "claude-code", "--dir", join(fortressPath, "out"), "--fortress", fortressPath],
        out: out.stream,
        err: err.stream,
        env: { SANCTUARY_PASSPHRASE: PASSPHRASE },
        dialogRunner: APPROVE_DIALOG,
      });

      // The command hit the identity-unavailable early return.
      expect(code).toBe(1);
      expect(err.text()).toContain("primary identity is unavailable");

      // The writeIntent barrier was released on that path (the fix). A fresh
      // exclusive rotation barrier acquires with no lingering reader. Against the
      // pre-fix source the reader is leaked and this fails closed (contention).
      const rotateStorage = new FilesystemStorage(join(fortressPath, "state"));
      const allowed = await tryExclusive(rotateStorage, 3000);
      expect(allowed).toBe("ran");
    });
  },
);
