import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { ed25519 } from "@noble/curves/ed25519";

import { toBase64url } from "../../src/core/encoding.js";
import { encrypt } from "../../src/core/encryption.js";
import { randomBytes } from "../../src/core/random.js";
import { resolveTransparencySigner } from "../../src/transparency/signer.js";
import {
  TRANSPARENCY_NEVER_ABORTED,
  TRANSPARENCY_STOP_DRAIN_DEADLINE_MS,
  TransparencySchedulerAbortedError,
  startTransparencyScheduler,
  type TransparencySchedulerAbortState,
} from "../../src/transparency/scheduler.js";

let fortressPath: string;

beforeEach(async () => {
  fortressPath = await mkdtemp(join(tmpdir(), "sanctuary-signer-"));
});

afterEach(async () => {
  await rm(fortressPath, { recursive: true, force: true });
});

async function schedulerAbortHarness(): Promise<{
  state: TransparencySchedulerAbortState;
  abort(): Promise<void>;
  release(): void;
}> {
  let state: TransparencySchedulerAbortState | undefined;
  let releaseScheduler: (() => void) | undefined;
  const scheduler = startTransparencyScheduler({
    intervalMs: 1_000,
    emit: async (abortState) => {
      state = abortState;
      await new Promise<void>((resolve) => {
        releaseScheduler = resolve;
      });
    },
    onError: () => undefined,
  });
  await vi.advanceTimersByTimeAsync(1_000);
  if (state === undefined || releaseScheduler === undefined) {
    throw new Error("scheduler did not start a transparency emission");
  }
  return {
    state,
    async abort() {
      const stopped = scheduler.stop();
      await vi.advanceTimersByTimeAsync(TRANSPARENCY_STOP_DRAIN_DEADLINE_MS);
      await stopped;
    },
    release() {
      releaseScheduler?.();
    },
  };
}

it("passes a scheduler abort through unchanged before local signer decrypt", async () => {
  vi.useFakeTimers();
  const abort = await schedulerAbortHarness();
  try {
    const masterKey = randomBytes(32);
    const privateKey = randomBytes(32);
    const publicKey = ed25519.getPublicKey(privateKey);
    await mkdir(fortressPath, { recursive: true });
    await writeFile(join(fortressPath, "castle-pinned-pubkey.bin"), publicKey);
    await writeFile(
      join(fortressPath, "castle-pinned-privkey.enc"),
      JSON.stringify(encrypt(privateKey, masterKey))
    );

    const signer = resolveTransparencySigner({
      fortressPath,
      masterKey,
      env: {},
      mode: "local",
      abortState: abort.state,
    });
    await abort.abort();

    await expect(signer).rejects.toThrow(/local transparency signer decrypt/);
    await expect(signer).rejects.toBeInstanceOf(TransparencySchedulerAbortedError);
    await expect(
      resolveTransparencySigner({
        fortressPath,
        masterKey,
        env: {},
        mode: "local",
        abortState: TRANSPARENCY_NEVER_ABORTED,
      })
    ).resolves.toMatchObject({
      signer_kid: `castle-wall:${toBase64url(publicKey)}`,
    });
  } finally {
    abort.release();
    vi.useRealTimers();
  }
});
