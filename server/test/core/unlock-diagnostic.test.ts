/**
 * Actionable unlock-failure UX tests (element 2) + NO-disk-fallback +
 * backward-compat.
 *
 * Regression target: the boot path's cryptic "no credentials provided /
 * Refusing to start" told the operator nothing actionable. The diagnostic now
 * states which factors are enrolled, whether the OS keyring is locked vs the
 * item absent, the GUI unlock step, and the literal SANCTUARY_RECOVERY_KEY
 * recovery command — never an on-disk key location.
 */

import { describe, it, expect } from "vitest";

import { MemoryStorage } from "../../src/storage/memory.js";
import {
  establishMaster,
  buildActionableUnlockMessage,
  readEnrolledFactors,
  unwrapMaster,
  readCustodyEnvelope,
  CustodyCredentialMissingError,
} from "../../src/core/master-custody.js";
import { fromBase64url } from "../../src/core/encoding.js";

describe("buildActionableUnlockMessage — element 2", () => {
  it("lists enrolled factors, the keychain-locked guidance, and the literal SANCTUARY_RECOVERY_KEY hint", () => {
    const msg = buildActionableUnlockMessage({
      enrolledFactors: ["passphrase", "keychain", "recovery-key"],
      hasPassphraseFactor: true,
      hasKeychainFactor: true,
      keychainReachability: "unreachable",
      storagePathHint: "/tmp/fortress",
    });
    // Factor inventory.
    expect(msg).toContain("Enrolled recovery factors");
    expect(msg).toContain("passphrase");
    expect(msg).toContain("recovery key");
    expect(msg).toContain("OS keyring");
    // Keychain-locked guidance + GUI step.
    expect(msg).toContain("LOCKED or unreachable");
    expect(msg.toLowerCase()).toContain("unlock the keyring");
    // The literal recovery command.
    expect(msg).toContain("SANCTUARY_RECOVERY_KEY=");
    expect(msg).toContain("SANCTUARY_PASSPHRASE=");
  });

  it("does NOT print any on-disk key location (no co-located secret pointer)", () => {
    const msg = buildActionableUnlockMessage({
      enrolledFactors: ["recovery-key"],
      hasPassphraseFactor: false,
      hasKeychainFactor: false,
      storagePathHint: "/tmp/fortress",
    });
    expect(msg.toLowerCase()).not.toContain("recovery-key.txt");
    expect(msg).toContain("SANCTUARY_RECOVERY_KEY=");
  });

  it("distinguishes keychain item-missing from keychain-locked", () => {
    const missing = buildActionableUnlockMessage({
      enrolledFactors: ["keychain", "recovery-key"],
      hasPassphraseFactor: false,
      hasKeychainFactor: true,
      keychainReachability: "not-found",
    });
    expect(missing).toContain("MISSING from the keyring");
    expect(missing).not.toContain("LOCKED or unreachable");
  });
});

describe("readEnrolledFactors", () => {
  it("reports the distinct factor types from a fortress envelope", async () => {
    const storage = new MemoryStorage();
    await establishMaster({
      storage,
      passphrase: "correct horse battery staple",
      firstRun: { installMode: "interactive", mintRecoveryKey: true },
    });
    const factors = await readEnrolledFactors(storage);
    expect(factors.hasPassphraseFactor).toBe(true);
    expect(factors.enrolledFactors).toContain("passphrase");
    expect(factors.enrolledFactors).toContain("recovery-key");
  });

  it("returns empty for a fortress with no envelope", async () => {
    const storage = new MemoryStorage();
    const factors = await readEnrolledFactors(storage);
    expect(factors.enrolledFactors).toEqual([]);
    expect(factors.hasKeychainFactor).toBe(false);
  });
});

describe("NO disk-fallback + backward-compat", () => {
  it("a fortress with a stray on-disk recovery-key.txt is NOT auto-unlocked without the env factor", async () => {
    const storage = new MemoryStorage();
    // Provision a passphrase fortress with a minted recovery key.
    await establishMaster({
      storage,
      passphrase: "the-fortress-passphrase",
      firstRun: { installMode: "interactive", mintRecoveryKey: true },
    });
    // Even with a stray recovery-key.txt sitting somewhere, the unlock path
    // takes NO credential from disk: establishMaster with no credential throws.
    await expect(
      establishMaster({ storage }),
    ).rejects.toBeInstanceOf(CustodyCredentialMissingError);
  });

  it("backward compat: an existing fortress still unlocks with its existing passphrase factor", async () => {
    const storage = new MemoryStorage();
    const created = await establishMaster({
      storage,
      passphrase: "an-existing-passphrase",
      firstRun: { installMode: "interactive", mintRecoveryKey: true },
    });
    const reopened = await establishMaster({
      storage,
      passphrase: "an-existing-passphrase",
    });
    expect(Buffer.from(reopened.masterKey)).toEqual(
      Buffer.from(created.masterKey),
    );
  });

  it("backward compat: an existing fortress still unlocks with its minted recovery key", async () => {
    const storage = new MemoryStorage();
    const created = await establishMaster({
      storage,
      passphrase: "p",
      firstRun: { installMode: "interactive", mintRecoveryKey: true },
    });
    const minted = created.mintedRecoveryKey!;
    expect(minted).toBeTruthy();
    const envelope = await readCustodyEnvelope(storage);
    const master = await unwrapMaster(envelope!, {
      recoveryKey: fromBase64url(minted),
    });
    expect(Buffer.from(master)).toEqual(Buffer.from(created.masterKey));
  });
});
