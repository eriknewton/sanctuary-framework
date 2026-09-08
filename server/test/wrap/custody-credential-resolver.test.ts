/**
 * The ONE fortress custody-credential resolver (`wrap/custody-credential.ts`).
 *
 * Capability under test: every verb that needs the fortress credential
 * resolves it in one place, in one order, never returns a factor it has not
 * verified against THIS fortress, and mints a new passphrase only for a
 * fortress that has no custody at all. Register: defect.a73-install-emitted-
 * protect-fails-custody-establishment.
 *
 * WHAT EACH TEST ACTUALLY IS, so the file's claim matches its contents: the
 * first and the host-local-restriction tests are CONSTANT PINS over two
 * exported arrays (no fortress is involved); every other test is a DIRECT call
 * to the resolver against a real temporary fortress. None of them runs a CLI
 * verb; the end-to-end journey (including one run of a planner-emitted argv
 * verbatim through the CLI's own dispatcher) is
 * `test/wrap/protect-uses-enrolled-custody.test.ts`.
 *
 * Every keyring read here goes through the wrap keychain chokepoint, which the
 * suite serves from the in-memory store (test/setup/keychain-fake.ts). No
 * `security` / `secret-tool` subprocess runs and the operator's login keychain
 * is never touched.
 */

import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { mkdir, mkdtemp, readdir, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import {
  CUSTODY_CREDENTIAL_SOURCE_ORDER,
  HOST_LOCAL_CUSTODY_SOURCES,
  custodyCredentialRefusal,
  custodyCredentialSourceLabel,
  resolveFortressCustodyCredential,
} from "../../src/wrap/custody-credential.js";
import {
  ACCEPTED_CUSTODY_CREDENTIAL_SOURCES,
  CUSTODY_ENVELOPE_KEY,
  establishMaster,
} from "../../src/core/master-custody.js";
import {
  getOrCreateKeychainCustodyKey,
  readKeychainCustodyKey,
} from "../../src/wrap/keychain-custody.js";
import { persistUserProvidedPassphrase } from "../../src/wrap/passphrase.js";
import { FilesystemStorage } from "../../src/storage/filesystem.js";
import { stringToBytes, toBase64url } from "../../src/core/encoding.js";

const PASSPHRASE = "resolver-test-passphrase-not-a-real-secret";

/**
 * A fortress in the shape `sanctuary init` leaves behind on an interactive
 * install: a recovery-key wrap plus an OS-keyring custody wrap, and NO
 * passphrase wrap. This is the shape `protect` could not open.
 */
async function seedInitShapedFortress(dir: string): Promise<{
  recoveryKey: string;
  custodyKey: Uint8Array;
}> {
  await mkdir(join(dir, "state"), { recursive: true, mode: 0o700 });
  const storage = new FilesystemStorage(join(dir, "state"));
  const custodyKey = await getOrCreateKeychainCustodyKey(dir);
  if (!custodyKey) throw new Error("test keyring did not yield a custody key");
  const established = await establishMaster({
    storage,
    keychainKey: custodyKey,
    firstRun: { installMode: "interactive", mintRecoveryKey: true },
    storagePathHint: dir,
  });
  try {
    return {
      recoveryKey: established.mintedRecoveryKey!,
      custodyKey,
    };
  } finally {
    established.masterKey.fill(0);
  }
}

describe("custody credential resolver", () => {
  let dir: string;

  beforeEach(async () => {
    dir = await mkdtemp(join(tmpdir(), "custody-resolver-"));
    delete process.env.SANCTUARY_PASSPHRASE;
    delete process.env.SANCTUARY_RECOVERY_KEY;
  });

  afterEach(async () => {
    delete process.env.SANCTUARY_PASSPHRASE;
    delete process.env.SANCTUARY_RECOVERY_KEY;
    await rm(dir, { recursive: true, force: true });
  });

  it("names the same sources, in the same order, as the unlock refusal", () => {
    // Cross-file pin. The refusal text is what an operator acts on; if it lists
    // credentials in a different order than the resolver tries them, or names
    // one the resolver never reads (the A73 defect), the text is a lie.
    expect(ACCEPTED_CUSTODY_CREDENTIAL_SOURCES).toHaveLength(
      CUSTODY_CREDENTIAL_SOURCE_ORDER.length,
    );
    expect(
      CUSTODY_CREDENTIAL_SOURCE_ORDER.map(custodyCredentialSourceLabel),
    ).toEqual([...ACCEPTED_CUSTODY_CREDENTIAL_SOURCES]);
  });

  it("resolves the enrolled custody factor on an init-shaped fortress", async () => {
    const { custodyKey } = await seedInitShapedFortress(dir);
    const resolution = await resolveFortressCustodyCredential({
      storagePath: dir,
      allowMint: true,
    });
    expect(resolution.status).toBe("resolved");
    if (resolution.status !== "resolved") return;
    expect(resolution.credential.source).toBe("enrolled-custody-key");
    expect(resolution.credential.kind).toBe("keychain-key");
    if (resolution.credential.kind !== "keychain-key") return;
    expect(toBase64url(resolution.credential.keychainKey)).toBe(
      toBase64url(custodyKey),
    );
  });

  it("SANCTUARY_RECOVERY_KEY outranks the host-local factors and resolves", async () => {
    const { recoveryKey } = await seedInitShapedFortress(dir);
    process.env.SANCTUARY_RECOVERY_KEY = recoveryKey;
    const resolution = await resolveFortressCustodyCredential({
      storagePath: dir,
      allowMint: true,
    });
    expect(resolution.status).toBe("resolved");
    if (resolution.status !== "resolved") return;
    expect(resolution.credential.source).toBe("env-recovery-key");
    expect(resolution.credential.kind).toBe("recovery-key");
  });

  it("mints only for a fortress with no custody state at all", async () => {
    await mkdir(join(dir, "state"), { recursive: true, mode: 0o700 });
    const resolution = await resolveFortressCustodyCredential({
      storagePath: dir,
      allowMint: true,
    });
    expect(resolution.status).toBe("mint-required");
    expect(resolution.report.envelopePresent).toBe(false);
  });

  it("a leftover keyring item does not suppress mint-required on a directory with no custody", async () => {
    // The keyring holds this path's custody item while the directory holds no
    // envelope and no legacy marker. That is not a contrived state: `init`
    // enrols the factor before it writes custody, and the item outlives a
    // fortress directory the operator removed. Before the fix the resolver had
    // nothing to verify the item against and therefore returned it AS-IS, so
    // `protect` never reached `mint-required`; `establishWrapCustody` refuses
    // `firstRun` for a keychain credential and `establishMaster` refuses to
    // create custody without a passphrase, so `protect` after a failed `init`
    // could not start at all. A key is not a wrap of a fortress that does not
    // exist.
    await mkdir(join(dir, "state"), { recursive: true, mode: 0o700 });
    const leftover = await getOrCreateKeychainCustodyKey(dir);
    // The item really is on this host and the default reader really would find
    // it, so the assertion below is about the verdict and not about an empty
    // keyring.
    expect(leftover).not.toBeNull();
    expect(await readKeychainCustodyKey(dir)).not.toBeNull();
    leftover!.fill(0);

    const resolution = await resolveFortressCustodyCredential({
      storagePath: dir,
      allowMint: true,
    });
    expect(resolution.status).toBe("mint-required");
    expect(resolution.report.envelopePresent).toBe(false);
    // The host-local sources are not consulted at all on a directory with no
    // custody: there is nothing for them to be verified against, and reporting
    // them as "present on this host" in an answer about a fortress that does
    // not exist would point an operator at a credential for nothing.
    expect(resolution.report.found).toEqual([]);
    expect(resolution.report.rejected).toEqual([]);
    expect(resolution.report.indeterminate).toEqual([]);
    expect(resolution.report.integrityIndeterminate).toBe(false);
  });

  it("an operator-supplied credential still creates custody on a virgin fortress", async () => {
    // The no-custody verdict is checked AFTER the operator-supplied sources, so
    // a passphrase the operator handed this run is what the first run is
    // created with rather than a minted one. Returning `mint-required` here
    // would silently discard the operator's own credential.
    await mkdir(join(dir, "state"), { recursive: true, mode: 0o700 });
    process.env.SANCTUARY_PASSPHRASE = PASSPHRASE;
    const resolution = await resolveFortressCustodyCredential({
      storagePath: dir,
      allowMint: true,
    });
    expect(resolution.status).toBe("resolved");
    if (resolution.status !== "resolved") return;
    expect(resolution.credential.source).toBe("env-passphrase");
  });

  it("boot and protect agree about a directory with no custody and a leftover item", async () => {
    // The two verbs differ only in `allowMint`. `protect` mints (above); the
    // hands-free server boot passes allowMint:false and reads
    // `noCustodyStateAtAll` to decide, so the same state must come back as
    // "nothing here has ever been locked" — which `resolveHandsFreeBootCredential`
    // turns into its `virgin` verdict and the audited first run. Before the fix
    // `protect` was told the fortress was resolved while boot was told it was
    // virgin: the disagreement this resolver exists to make impossible.
    await mkdir(join(dir, "state"), { recursive: true, mode: 0o700 });
    const leftover = await getOrCreateKeychainCustodyKey(dir);
    leftover!.fill(0);

    const boot = await resolveFortressCustodyCredential({
      storagePath: dir,
      allow: HOST_LOCAL_CUSTODY_SOURCES,
      allowMint: false,
    });
    expect(boot.status).toBe("unresolved");
    expect(boot.report.envelopePresent).toBe(false);
    // The fact the boot adapter actually branches on. Envelope absence alone
    // would also be true of a LEGACY fortress, which must NOT read as virgin.
    expect(boot.report.noCustodyStateAtAll).toBe(true);
  });

  it("takes the STORED PASSPHRASE as-is on a LEGACY fortress, and never mints over one", async () => {
    // The other no-envelope state, and the reason the mint verdict is gated on
    // legacy markers rather than on the envelope alone: a pre-envelope fortress
    // has custody, has nothing to verify a candidate against, and must migrate
    // in place. Minting here would derive a parallel master over live data.
    //
    // The rule is PER SOURCE, not "any host-local factor": a pre-envelope
    // master is Argon2id(passphrase, `_meta/key-params`), so the stored
    // passphrase is the only host-local source such a fortress can be opened
    // with and is taken as-is, while a keyring custody item is never selected
    // without an envelope to authenticate it against (that half is
    // `test/wrap/legacy-fortress-stray-custody-item.test.ts`; this test stubs
    // the item ABSENT so it is only about the passphrase).
    await mkdir(join(dir, "state"), { recursive: true, mode: 0o700 });
    const storage = new FilesystemStorage(join(dir, "state"));
    await storage.write("_meta", "key-params", stringToBytes("legacy-marker"));

    const resolution = await resolveFortressCustodyCredential({
      storagePath: dir,
      allowMint: true,
      readCustodyKey: async () => ({
        status: "not-found" as const,
        service: "sanctuary-custody",
      }),
      observePassphrase: async () => ({
        status: "found" as const,
        result: {
          value: PASSPHRASE,
          source: "keychain" as const,
          location: "test-keyring",
        },
        keyringUnreachable: false,
      }),
    });
    expect(resolution.status).toBe("resolved");
    if (resolution.status !== "resolved") return;
    expect(resolution.credential.source).toBe("stored-passphrase");
    // A legacy marker is custody state even though there is no envelope, so
    // `allowMint: true` must not have produced `mint-required` above and the
    // boot adapter must not read this fortress as virgin.
    expect(resolution.report.envelopePresent).toBe(false);
    expect(resolution.report.noCustodyStateAtAll).toBe(false);
  });

  it("keeps the legacy mode UNKNOWN when the higher-priority marker is unreadable", async () => {
    // `_meta/recovery-key-hash` outranks `_meta/key-params` (the legacy branch
    // order in establishMaster). If the higher-priority marker cannot be read,
    // a readable key-params must NOT decide passphrase mode: the fortress may
    // be a recovery-key one whose marker is merely unreadable, and the
    // passphrase remedy would then name a credential that cannot open it. The
    // mode stays unknown, custody still "may exist" (no mint), and the refusal
    // carries neither legacy remedy. An unreadable marker is modelled as a
    // directory at the marker path, which every storage read rejects.
    await mkdir(join(dir, "state"), { recursive: true, mode: 0o700 });
    const storage = new FilesystemStorage(join(dir, "state"));
    await storage.write("_meta", "key-params", stringToBytes("legacy-marker"));
    // Write the higher-priority marker, then swap its on-disk entry for a
    // directory of the same name: the no-follow regular-file read refuses a
    // directory with an error that is not ENOENT, which is "unreadable", not
    // "absent". The path is discovered rather than spelled so the test cannot
    // drift from the storage layer's own key encoding.
    await storage.write("_meta", "recovery-key-hash", stringToBytes("legacy-marker"));
    const metaDir = storage.namespacePath("_meta");
    const entry = (await readdir(metaDir)).find((name) => name.includes("recovery-key-hash"));
    if (!entry) throw new Error("test could not find the recovery-key-hash entry on disk");
    await rm(join(metaDir, entry), { force: true });
    await mkdir(join(metaDir, entry), { mode: 0o700 });

    const resolution = await resolveFortressCustodyCredential({
      storagePath: dir,
      allowMint: true,
      readCustodyKey: async () => ({
        status: "not-found" as const,
        service: "sanctuary-custody",
      }),
      observePassphrase: async () => ({
        status: "absent" as const,
        keyringUnreachable: false,
      }),
    });
    expect(resolution.status).toBe("unresolved");
    if (resolution.status !== "unresolved") return;
    expect(resolution.report.noCustodyStateAtAll).toBe(false);
    expect(resolution.report.legacyCustodyMode).toBeUndefined();
    const message = custodyCredentialRefusal(resolution.report, dir).message;
    expect(message).toContain("Accepted credentials, in the order they are tried:");
    expect(message).not.toMatch(/passphrase required/i);
    expect(message).not.toMatch(/no credentials provided/i);
  });

  it("never reports mint-required over an existing envelope", async () => {
    // The A73 blocker in one assertion: the old chain minted a passphrase on a
    // fortress whose envelope it had no wrap in, then failed to unlock with it.
    // Plant that exact condition (an envelope this host holds no credential
    // for) and prove the guard refuses instead of minting.
    await seedInitShapedFortress(dir);
    const resolution = await resolveFortressCustodyCredential({
      storagePath: dir,
      allowMint: true,
      // Model a host that cannot reach the enrolled factor, so no host-local
      // credential resolves and the mint branch is the only thing left.
      readCustodyKey: async () => ({
        status: "not-found" as const,
        service: "sanctuary-custody",
      }),
      observePassphrase: async () => ({
        status: "absent" as const,
        keyringUnreachable: false,
      }),
    });
    expect(resolution.status).toBe("unresolved");
    expect(resolution.report.envelopePresent).toBe(true);
  });

  it("refusal names only the accepted sources, plus what was found and rejected", async () => {
    const { custodyKey } = await seedInitShapedFortress(dir);
    // A stale stored passphrase that does not open this fortress, alongside the
    // enrolled factor that does: the resolver must reject the stale one by name.
    await persistUserProvidedPassphrase("a-stale-passphrase-for-a-different-fortress", {
      storagePath: dir,
    });
    custodyKey.fill(0);
    const resolution = await resolveFortressCustodyCredential({
      storagePath: dir,
      allow: ["stored-passphrase"],
      allowMint: false,
    });
    expect(resolution.status).toBe("unresolved");
    expect(resolution.report.found).toContain("stored-passphrase");
    expect(resolution.report.rejected).toContain("stored-passphrase");

    const refusal = custodyCredentialRefusal(resolution.report, dir);
    for (const accepted of ACCEPTED_CUSTODY_CREDENTIAL_SOURCES) {
      expect(refusal.message).toContain(accepted);
    }
    // Nothing outside the accepted list is offered as a remedy: the old text
    // pointed the operator at a credential the code never read.
    const namedEnvVars = refusal.message.match(/SANCTUARY_[A-Z_]+/g) ?? [];
    expect([...new Set(namedEnvVars)].sort()).toEqual([
      "SANCTUARY_PASSPHRASE",
      "SANCTUARY_RECOVERY_KEY",
    ]);
    expect(refusal.message).toContain("Tried and did not unlock");
    // Never a value.
    expect(refusal.message).not.toContain("a-stale-passphrase-for-a-different-fortress");
  });

  it("never returns a factor it could not verify against an unreadable envelope", async () => {
    // The envelope is PRESENT (custody exists) but unparseable, so nothing on
    // this host can be checked against it. Before the fix the enrolled factor
    // came back `resolved` here purely because it was present: an unverified
    // credential that `export-passphrase` would have printed and the install
    // planner would have called this fortress openable on.
    const { custodyKey } = await seedInitShapedFortress(dir);
    custodyKey.fill(0);
    const storage = new FilesystemStorage(join(dir, "state"));
    await storage.write("_meta", CUSTODY_ENVELOPE_KEY, stringToBytes("{ not json"));

    const resolution = await resolveFortressCustodyCredential({
      storagePath: dir,
      allowMint: true,
    });

    expect(resolution.status).toBe("unresolved");
    expect(resolution.report.envelopePresent).toBe(true);
    expect(resolution.report.integrityIndeterminate).toBe(true);
    // Present, and neither proven nor disproven: the third answer.
    expect(resolution.report.found).toContain("enrolled-custody-key");
    expect(resolution.report.indeterminate).toContain("enrolled-custody-key");
    expect(resolution.report.rejected).not.toContain("enrolled-custody-key");

    // The refusal says the fortress could not be EVALUATED, and sends the
    // operator at the envelope rather than at a credential they already have.
    const refusal = custodyCredentialRefusal(resolution.report, dir);
    expect(refusal.message).toContain("could not be evaluated");
    expect(refusal.message).not.toContain("Unlock the OS keyring and retry");
  });

  it("host-local restriction is what makes an answer describe the emitted argv", () => {
    // The install planner's contract forbids adding a credential to the argv it
    // emits, so its resolver run must not be able to consult one.
    expect([...HOST_LOCAL_CUSTODY_SOURCES]).toEqual([
      "enrolled-custody-key",
      "stored-passphrase",
    ]);
  });

  it("ignores ambient operator credentials when restricted to host-local sources", async () => {
    const { recoveryKey } = await seedInitShapedFortress(dir);
    process.env.SANCTUARY_RECOVERY_KEY = recoveryKey;
    const resolution = await resolveFortressCustodyCredential({
      storagePath: dir,
      allow: HOST_LOCAL_CUSTODY_SOURCES,
      allowMint: false,
    });
    expect(resolution.status).toBe("resolved");
    if (resolution.status !== "resolved") return;
    expect(resolution.credential.source).toBe("enrolled-custody-key");
    expect(resolution.report.found).not.toContain("env-recovery-key");
  });
});
