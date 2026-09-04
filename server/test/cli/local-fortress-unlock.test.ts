/**
 * `unlockLocalFortress` — the shared local-fortress credential chokepoint for
 * the ordinary memory verbs.
 *
 * Covers: the six-source precedence, both exact-fortress OS-keyring factors
 * (injected, never the real keyring), the no-generation / fail-closed refusals
 * (absent / locked / mismatch), and the secret-free remediation contract. Each
 * test seeds a REAL custody envelope with `establishMaster` in a temp fortress,
 * so the unlock exercises the production unwrap path, not a stub.
 */

import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtemp, rm, mkdir } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { unlockLocalFortress } from "../../src/cli/local-fortress-unlock.js";
import { FilesystemStorage } from "../../src/storage/filesystem.js";
import { MemoryStorage } from "../../src/storage/memory.js";
import { establishMaster } from "../../src/core/master-custody.js";
import {
  PassphraseKeyringUnreachableError,
  type PassphraseResult,
  type PassphraseOptions,
} from "../../src/wrap/passphrase.js";

const PASSPHRASE = "unlock-correct-horse-battery-staple-not-a-real-secret";
const WRONG_PASSPHRASE = "unlock-WRONG-passphrase-not-a-real-secret";

interface Seeded {
  storagePath: string;
  statePath: string;
  storage: FilesystemStorage;
  master: Uint8Array;
  recoveryKey: string;
  cleanup: () => Promise<void>;
}

async function seedFortress(): Promise<Seeded> {
  const dir = await mkdtemp(join(tmpdir(), "local-unlock-"));
  const storagePath = join(dir, ".sanctuary");
  const statePath = join(storagePath, "state");
  await mkdir(statePath, { recursive: true, mode: 0o700 });
  const storage = new FilesystemStorage(statePath);
  const custody = await establishMaster({
    storage,
    passphrase: PASSPHRASE,
    firstRun: { installMode: "headless", mintRecoveryKey: true },
    storagePathHint: storagePath,
  });
  return {
    storagePath,
    statePath,
    storage,
    master: custody.masterKey,
    recoveryKey: custody.mintedRecoveryKey!,
    cleanup: () => rm(dir, { recursive: true, force: true }),
  };
}

/** A stored-passphrase reader stub that never touches the real OS keyring. */
function storedReturning(
  value: string | null,
): (opts?: PassphraseOptions) => Promise<PassphraseResult | null> {
  return async () =>
    value === null
      ? null
      : { value, source: "keychain", location: "test-keyring" };
}

const custodyAbsent = async () => ({ status: "not-found" as const });

describe("unlockLocalFortress", () => {
  let f: Seeded;
  beforeEach(async () => {
    f = await seedFortress();
  });
  afterEach(async () => {
    await f.cleanup();
  });

  function envelopeBytes(): Promise<Uint8Array | null> {
    return f.storage.read("_meta", "custody-envelope");
  }

  it("uses SANCTUARY_PASSPHRASE and returns only the master key", async () => {
    const r = await unlockLocalFortress({
      storage: f.storage,
      storagePath: f.storagePath,
      env: { SANCTUARY_PASSPHRASE: PASSPHRASE },
      // readStored must never be consulted when a credential is present.
      readStored: async () => {
        throw new Error("keyring must not be read when a credential is present");
      },
    });
    expect(r.ok).toBe(true);
    if (r.ok) {
      expect(r.source).toBe("env-passphrase");
      expect(Buffer.from(r.masterKey).equals(Buffer.from(f.master))).toBe(true);
    }
  });

  it("stdin passphrase takes precedence over a wrong env passphrase", async () => {
    const r = await unlockLocalFortress({
      storage: f.storage,
      storagePath: f.storagePath,
      passphraseFromStdin: PASSPHRASE,
      env: { SANCTUARY_PASSPHRASE: WRONG_PASSPHRASE },
    });
    expect(r.ok).toBe(true);
    if (r.ok) expect(r.source).toBe("passphrase-stdin");
  });

  it("argv passphrase takes precedence over a wrong env passphrase", async () => {
    const r = await unlockLocalFortress({
      storage: f.storage,
      storagePath: f.storagePath,
      passphraseFromArgv: PASSPHRASE,
      env: { SANCTUARY_PASSPHRASE: WRONG_PASSPHRASE },
    });
    expect(r.ok).toBe(true);
    if (r.ok) expect(r.source).toBe("passphrase-argv");
  });

  it("env passphrase takes precedence over env recovery key", async () => {
    const r = await unlockLocalFortress({
      storage: f.storage,
      storagePath: f.storagePath,
      env: {
        SANCTUARY_PASSPHRASE: PASSPHRASE,
        SANCTUARY_RECOVERY_KEY: "not-even-valid-base64url-****",
      },
    });
    expect(r.ok).toBe(true);
    if (r.ok) expect(r.source).toBe("env-passphrase");
  });

  it("unlocks from SANCTUARY_RECOVERY_KEY when no passphrase is present", async () => {
    const r = await unlockLocalFortress({
      storage: f.storage,
      storagePath: f.storagePath,
      env: { SANCTUARY_RECOVERY_KEY: f.recoveryKey },
    });
    expect(r.ok).toBe(true);
    if (r.ok) {
      expect(r.source).toBe("env-recovery-key");
      expect(Buffer.from(r.masterKey).equals(Buffer.from(f.master))).toBe(true);
    }
  });

  it("falls back to the exact-fortress stored passphrase when nothing else is present", async () => {
    const r = await unlockLocalFortress({
      storage: f.storage,
      storagePath: f.storagePath,
      env: {},
      readStored: storedReturning(PASSPHRASE),
      readCustody: custodyAbsent,
    });
    expect(r.ok).toBe(true);
    if (r.ok) expect(r.source).toBe("stored-passphrase");
  });

  it("refuses (absent) and never generates when no credential exists anywhere", async () => {
    const before = await envelopeBytes();
    const r = await unlockLocalFortress({
      storage: f.storage,
      storagePath: f.storagePath,
      env: {},
      readStored: storedReturning(null),
      readCustody: custodyAbsent,
    });
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.failure).toBe("absent");
    // No generation: the custody envelope on disk is byte-identical.
    const after = await envelopeBytes();
    expect(after && before && Buffer.from(after).equals(Buffer.from(before))).toBe(
      true,
    );
  });

  it("reports a locked keyring without leaking a secret", async () => {
    const r = await unlockLocalFortress({
      storage: f.storage,
      storagePath: f.storagePath,
      env: {},
      readStored: async () => {
        throw new PassphraseKeyringUnreachableError(
          "macOS Keychain",
          "locked (error 36)",
        );
      },
      readCustody: async () => ({ status: "unreachable" }),
    });
    expect(r.ok).toBe(false);
    if (!r.ok) {
      expect(r.failure).toBe("locked");
      expect(r.message).not.toContain(PASSPHRASE);
    }
  });

  it("reports a mismatch for a wrong credential without leaking it", async () => {
    const r = await unlockLocalFortress({
      storage: f.storage,
      storagePath: f.storagePath,
      env: { SANCTUARY_PASSPHRASE: WRONG_PASSPHRASE },
    });
    expect(r.ok).toBe(false);
    if (!r.ok) {
      expect(r.failure).toBe("mismatch");
      expect(r.message).not.toContain(WRONG_PASSPHRASE);
    }
  });

  it("does not bootstrap a virgin fortress from a stray stored credential", async () => {
    const virgin = new MemoryStorage();
    const r = await unlockLocalFortress({
      storage: virgin,
      storagePath: "/tmp/virgin-fortress",
      env: {},
      platformOverride: "darwin",
      readStored: storedReturning(PASSPHRASE),
      readCustody: custodyAbsent,
    });
    expect(r).toMatchObject({ ok: false, failure: "absent" });
    expect(await virgin.read("_meta", "custody-envelope")).toBeNull();
  });

  it("maps unexpected stored-credential errors without leaking their message", async () => {
    const leak = "raw-secret-from-driver";
    const r = await unlockLocalFortress({
      storage: f.storage,
      storagePath: f.storagePath,
      env: {},
      readStored: async () => { throw new Error(leak); },
      readCustody: custodyAbsent,
    });
    expect(r.ok).toBe(false);
    if (!r.ok) {
      expect(r.failure).toBe("other");
      expect(r.message).not.toContain(leak);
    }
  });

  it("opens and scrubs the custody-key factor enrolled by interactive init", async () => {
    const dir = await mkdtemp(join(tmpdir(), "local-unlock-keychain-"));
    try {
      const storagePath = join(dir, ".sanctuary");
      const storage = new FilesystemStorage(join(storagePath, "state"));
      await mkdir(join(storagePath, "state"), { recursive: true, mode: 0o700 });
      const keychainKey = new Uint8Array(32).fill(0x42);
      const established = await establishMaster({
        storage,
        keychainKey,
        firstRun: { installMode: "interactive", mintRecoveryKey: true },
        storagePathHint: storagePath,
      });
      const observed = keychainKey.slice();
      const r = await unlockLocalFortress({
        storage,
        storagePath,
        env: {},
        readStored: storedReturning(null),
        readCustody: async () => ({ status: "found", key: observed }),
      });
      expect(r.ok).toBe(true);
      if (r.ok) {
        expect(r.source).toBe("stored-custody-key");
        expect(Buffer.from(r.masterKey).equals(Buffer.from(established.masterKey))).toBe(true);
        r.masterKey.fill(0);
      }
      expect([...observed]).toEqual(new Array(32).fill(0));
      established.masterKey.fill(0);
      keychainKey.fill(0);
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });

  it("falls back from a stale stored passphrase to the interactive-init custody key", async () => {
    const dir = await mkdtemp(join(tmpdir(), "local-unlock-keychain-fallback-"));
    try {
      const storagePath = join(dir, ".sanctuary");
      const storage = new FilesystemStorage(join(storagePath, "state"));
      await mkdir(join(storagePath, "state"), { recursive: true, mode: 0o700 });
      const keychainKey = new Uint8Array(32).fill(0x43);
      const established = await establishMaster({
        storage,
        keychainKey,
        firstRun: { installMode: "interactive", mintRecoveryKey: true },
        storagePathHint: storagePath,
      });
      const observed = keychainKey.slice();
      const r = await unlockLocalFortress({
        storage,
        storagePath,
        env: {},
        readStored: storedReturning(WRONG_PASSPHRASE),
        readCustody: async () => ({ status: "found", key: observed }),
      });
      expect(r.ok).toBe(true);
      if (r.ok) {
        expect(r.source).toBe("stored-custody-key");
        expect(Buffer.from(r.masterKey).equals(Buffer.from(established.masterKey))).toBe(true);
        r.masterKey.fill(0);
      }
      expect([...observed]).toEqual(new Array(32).fill(0));
      established.masterKey.fill(0);
      keychainKey.fill(0);
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });

  it("preserves locked alternate-factor evidence when the stored passphrase is stale", async () => {
    const r = await unlockLocalFortress({
      storage: f.storage,
      storagePath: f.storagePath,
      env: {},
      readStored: storedReturning(WRONG_PASSPHRASE),
      readCustody: async () => ({
        status: "unreachable",
        detail: "test custody keyring is locked",
      }),
    });
    expect(r.ok).toBe(false);
    if (!r.ok) {
      expect(r.failure).toBe("locked");
      expect(r.message).toContain("locked");
    }
  });
});
