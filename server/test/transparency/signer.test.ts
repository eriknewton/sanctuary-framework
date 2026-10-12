import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, expect, it } from "vitest";
import { ed25519 } from "@noble/curves/ed25519";

import { toBase64url } from "../../src/core/encoding.js";
import { encrypt } from "../../src/core/encryption.js";
import { randomBytes } from "../../src/core/random.js";
import { resolveTransparencySigner } from "../../src/transparency/signer.js";
import {
  TransparencySchedulerAbortedError,
  type TransparencySchedulerAbortState,
} from "../../src/transparency/scheduler.js";

let fortressPath: string;

beforeEach(async () => {
  fortressPath = await mkdtemp(join(tmpdir(), "sanctuary-signer-"));
});

afterEach(async () => {
  await rm(fortressPath, { recursive: true, force: true });
});

function mutableAbortState(): {
  state: TransparencySchedulerAbortState;
  abort(): void;
} {
  let aborted = false;
  return {
    state: {
      get aborted() {
        return aborted;
      },
      assertNotAborted(phase: string): void {
        if (aborted) throw new TransparencySchedulerAbortedError(phase);
      },
    },
    abort() {
      aborted = true;
    },
  };
}

it("passes a scheduler abort through unchanged before local signer decrypt", async () => {
  const masterKey = randomBytes(32);
  const privateKey = randomBytes(32);
  const publicKey = ed25519.getPublicKey(privateKey);
  await mkdir(fortressPath, { recursive: true });
  await writeFile(join(fortressPath, "castle-pinned-pubkey.bin"), publicKey);
  await writeFile(
    join(fortressPath, "castle-pinned-privkey.enc"),
    JSON.stringify(encrypt(privateKey, masterKey))
  );
  const abort = mutableAbortState();

  const signer = resolveTransparencySigner({
    fortressPath,
    masterKey,
    env: {},
    mode: "local",
    abortState: abort.state,
  });
  abort.abort();

  await expect(signer).rejects.toBeInstanceOf(TransparencySchedulerAbortedError);
  await expect(
    resolveTransparencySigner({
      fortressPath,
      masterKey,
      env: {},
      mode: "local",
      abortState: {
        aborted: false,
        assertNotAborted: () => undefined,
      },
    })
  ).resolves.toMatchObject({
    signer_kid: `castle-wall:${toBase64url(publicKey)}`,
  });
});
