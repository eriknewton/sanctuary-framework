/**
 * S3: a caller that mints a passphrase the operator NEVER sees (the recovery-key
 * rekey) must not let it silently land in the machine-local encrypted fallback
 * file when no OS keyring is available — that collapses vault confidentiality to
 * "possession of the fortress dir + four public host facts" with no operator-held
 * copy. `persistAndConfirmUserProvidedPassphrase` honors `refuseFallbackFile`:
 * it fails closed instead of writing the fallback. The default (no flag) still
 * writes the fallback (compat), so the refusal is a deliberate opt-in guard.
 */

import { mkdtemp, rm, access } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";

import {
  persistAndConfirmUserProvidedPassphrase,
  PassphrasePersistenceError,
} from "../../src/wrap/passphrase.js";

// freebsd has no OS keyring branch, so persistence has only the fallback file.
const NO_KEYRING_PLATFORM = "freebsd" as NodeJS.Platform;

describe("persist refuses the machine-local fallback when asked (S3)", () => {
  const cleanup: string[] = [];
  afterEach(async () => {
    await Promise.all(
      cleanup.splice(0).map((p) => rm(p, { recursive: true, force: true })),
    );
  });

  async function tempHome(): Promise<{ home: string; storagePath: string }> {
    const home = await mkdtemp(join(tmpdir(), "persist-refuse-"));
    cleanup.push(home);
    const storagePath = join(home, ".sanctuary");
    return { home, storagePath };
  }

  it("fails closed and writes NO fallback file when refuseFallbackFile is set and no keyring exists", async () => {
    const { home, storagePath } = await tempHome();
    await expect(
      persistAndConfirmUserProvidedPassphrase("generated-secret-never-shown", {
        home,
        storagePath,
        platformOverride: NO_KEYRING_PLATFORM,
        refuseFallbackFile: true,
      }),
    ).rejects.toBeInstanceOf(PassphrasePersistenceError);

    // No fallback credential was written.
    await expect(access(join(storagePath, "passphrase.enc"))).rejects.toMatchObject({
      code: "ENOENT",
    });
  });

  it("PLANTED DIVERGENCE: without the flag the same call DOES persist to the fallback file", async () => {
    const { home, storagePath } = await tempHome();
    const result = await persistAndConfirmUserProvidedPassphrase(
      "operator-known-passphrase",
      {
        home,
        storagePath,
        platformOverride: NO_KEYRING_PLATFORM,
      },
    );
    expect(result.source).toBe("fallback-file");
    // The fallback credential exists.
    await access(join(storagePath, "passphrase.enc"));
  });
});
