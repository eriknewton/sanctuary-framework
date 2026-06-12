/**
 * Master-custody envelope tests (sovereign-custody build, 2026-06-12).
 *
 * The incident class under regression here: a fortress whose printed
 * recovery key was a PARALLEL master that unlocked nothing live (two
 * disjoint master-establishment paths, F1/F2 of the adversarial review).
 * The envelope stores ONE master per fortress, only as wraps; every test
 * here closes one leg of that incident.
 */

import { describe, it, expect } from "vitest";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { MemoryStorage } from "../../src/storage/memory.js";
import {
  establishMaster,
  unwrapMaster,
  wrapMasterWithPassphrase,
  wrapMasterWithRecoveryKey,
  wrapMasterWithKeychainKey,
  writeCustodyEnvelope,
  readCustodyEnvelope,
  mintRecoveryWrap,
  verifyRecoveryWrapByReentry,
  enforceCustodyFloor,
  countVerifiedWraps,
  checkCastlePinCustody,
  CustodyUnlockError,
  CustodyCredentialMissingError,
  CustodyMigrationRefusedError,
  CustodyFloorError,
  CUSTODY_ENVELOPE_KEY,
  type CustodyEnvelope,
} from "../../src/core/master-custody.js";
import {
  deriveMasterKey,
  derivePurposeKey,
} from "../../src/core/key-derivation.js";
import { generateRandomKey } from "../../src/core/random.js";
import { hashToString } from "../../src/core/hashing.js";
import { encrypt, decrypt } from "../../src/core/encryption.js";
import {
  toBase64url,
  stringToBytes,
  bytesToString,
} from "../../src/core/encoding.js";

function b64(bytes: Uint8Array): string {
  return toBase64url(bytes);
}

describe("custody wraps", () => {
  it("passphrase wrap round-trips the master and fails closed on a wrong passphrase", async () => {
    const master = generateRandomKey();
    const wrap = await wrapMasterWithPassphrase(master, "correct horse");
    const envelope: CustodyEnvelope = {
      v: 1,
      install_mode: "interactive",
      wraps: [wrap],
      created_at: new Date().toISOString(),
    };

    const unwrapped = await unwrapMaster(envelope, { passphrase: "correct horse" });
    expect(b64(unwrapped)).toBe(b64(master));

    await expect(
      unwrapMaster(envelope, { passphrase: "wrong horse" })
    ).rejects.toThrow(CustodyUnlockError);
  });

  it("recovery-key wrap round-trips and is NOT the master itself", async () => {
    const master = generateRandomKey();
    const recoveryKey = generateRandomKey();
    const wrap = wrapMasterWithRecoveryKey(master, recoveryKey);
    const envelope: CustodyEnvelope = {
      v: 1,
      install_mode: "interactive",
      wraps: [wrap],
      created_at: new Date().toISOString(),
    };

    const unwrapped = await unwrapMaster(envelope, { recoveryKey });
    expect(b64(unwrapped)).toBe(b64(master));
    // The recovery key is a wrap of the master, never a parallel master.
    expect(b64(recoveryKey)).not.toBe(b64(master));

    await expect(
      unwrapMaster(envelope, { recoveryKey: generateRandomKey() })
    ).rejects.toThrow(CustodyUnlockError);
  });

  it("keychain wrap round-trips", async () => {
    const master = generateRandomKey();
    const custodyKey = generateRandomKey();
    const wrap = wrapMasterWithKeychainKey(master, custodyKey);
    const envelope: CustodyEnvelope = {
      v: 1,
      install_mode: "interactive",
      wraps: [wrap],
      created_at: new Date().toISOString(),
    };
    const unwrapped = await unwrapMaster(envelope, { keychainKey: custodyKey });
    expect(b64(unwrapped)).toBe(b64(master));
  });

  it("error messages never contain key material", async () => {
    const master = generateRandomKey();
    const recoveryKey = generateRandomKey();
    const wrap = wrapMasterWithRecoveryKey(master, recoveryKey);
    const envelope: CustodyEnvelope = {
      v: 1,
      install_mode: "interactive",
      wraps: [wrap],
      created_at: new Date().toISOString(),
    };
    const wrongKey = generateRandomKey();
    try {
      await unwrapMaster(envelope, { recoveryKey: wrongKey });
      expect.unreachable();
    } catch (err) {
      const msg = (err as Error).message;
      expect(msg).not.toContain(b64(master));
      expect(msg).not.toContain(b64(recoveryKey));
      expect(msg).not.toContain(b64(wrongKey));
    }
  });
});

describe("establishMaster — first run", () => {
  it("passphrase first run mints a recovery key that unlocks the SAME master (incident regression)", async () => {
    const storage = new MemoryStorage();
    const first = await establishMaster({
      storage,
      passphrase: "fortress-passphrase",
      firstRun: { installMode: "stdio-server", mintRecoveryKey: true },
    });
    expect(first.origin).toBe("first-run");
    expect(first.mintedRecoveryKey).toBeDefined();

    // The printed recovery key reconstructs the one true master — exactly
    // what failed in the 2026-06-12 drill.
    const viaRecovery = await establishMaster({
      storage,
      recoveryKey: first.mintedRecoveryKey!,
    });
    expect(b64(viaRecovery.masterKey)).toBe(b64(first.masterKey));

    // And the passphrase unlocks the same master too.
    const viaPassphrase = await establishMaster({
      storage,
      passphrase: "fortress-passphrase",
    });
    expect(b64(viaPassphrase.masterKey)).toBe(b64(first.masterKey));
    expect(viaPassphrase.origin).toBe("envelope");
  });

  it("the master is never stored bare and key-params is not written for new fortresses", async () => {
    const storage = new MemoryStorage();
    const result = await establishMaster({
      storage,
      passphrase: "fortress-passphrase",
      firstRun: { installMode: "headless", mintRecoveryKey: false },
    });
    const envelopeRaw = await storage.read("_meta", CUSTODY_ENVELOPE_KEY);
    expect(envelopeRaw).not.toBeNull();
    expect(bytesToString(envelopeRaw!)).not.toContain(b64(result.masterKey));
    expect(await storage.read("_meta", "key-params")).toBeNull();
    expect(await storage.read("_meta", "recovery-key-hash")).toBeNull();
  });

  it("refuses a first run when nothing enrollable exists (no silent custody)", async () => {
    const storage = new MemoryStorage();
    await expect(
      establishMaster({
        storage,
        firstRun: { installMode: "headless", mintRecoveryKey: false },
      })
    ).rejects.toThrow(/refusing to invent a custody secret/i);
  });

  it("refuses first runs entirely when the caller did not opt in", async () => {
    const storage = new MemoryStorage();
    await expect(
      establishMaster({ storage, passphrase: "anything" })
    ).rejects.toThrow(CustodyCredentialMissingError);
  });
});

describe("establishMaster — legacy migration", () => {
  async function seedLegacyPassphraseFortress(
    storage: MemoryStorage,
    passphrase: string
  ): Promise<Uint8Array> {
    const { key: master, params } = await deriveMasterKey(passphrase);
    await storage.write(
      "_meta",
      "key-params",
      stringToBytes(JSON.stringify(params))
    );
    // One encrypted identity = the migration evidence.
    const idKey = derivePurposeKey(master, "identity-encryption");
    const payload = encrypt(stringToBytes('{"identity_id":"seed"}'), idKey);
    await storage.write(
      "_identities",
      "seed",
      stringToBytes(JSON.stringify(payload))
    );
    return master;
  }

  it("migrates a legacy passphrase fortress in place: same master, zero data loss, idempotent", async () => {
    const storage = new MemoryStorage();
    const legacyMaster = await seedLegacyPassphraseFortress(storage, "legacy-pass");

    const migrated = await establishMaster({ storage, passphrase: "legacy-pass" });
    expect(migrated.origin).toBe("migrated-passphrase");
    // Same master — no data was re-encrypted, nothing is lost.
    expect(b64(migrated.masterKey)).toBe(b64(legacyMaster));

    // The seeded identity still decrypts under the migrated master.
    const idKey = derivePurposeKey(migrated.masterKey, "identity-encryption");
    const raw = await storage.read("_identities", "seed");
    const decrypted = decrypt(JSON.parse(bytesToString(raw!)), idKey);
    expect(bytesToString(decrypted)).toContain("seed");

    // Legacy markers are KEPT (no un-unlockable window) and the envelope
    // now short-circuits: second unlock comes from the envelope.
    expect(await storage.read("_meta", "key-params")).not.toBeNull();
    const second = await establishMaster({ storage, passphrase: "legacy-pass" });
    expect(second.origin).toBe("envelope");
    expect(b64(second.masterKey)).toBe(b64(legacyMaster));
    expect(second.envelope.install_mode).toBe("legacy-migrated");
  });

  it("REFUSES migration when the supplied passphrase contradicts existing data (never locks in a wrong master)", async () => {
    const storage = new MemoryStorage();
    await seedLegacyPassphraseFortress(storage, "right-pass");

    await expect(
      establishMaster({ storage, passphrase: "wrong-pass" })
    ).rejects.toThrow(CustodyMigrationRefusedError);

    // The fortress stays pure-legacy: no envelope captured a wrong master,
    // so the right passphrase still works.
    expect(await readCustodyEnvelope(storage)).toBeNull();
    const recovered = await establishMaster({ storage, passphrase: "right-pass" });
    expect(recovered.origin).toBe("migrated-passphrase");
  });

  it("migrates a legacy recovery-key fortress (key IS the master) after hash verification", async () => {
    const storage = new MemoryStorage();
    const legacyMaster = generateRandomKey();
    await storage.write(
      "_meta",
      "recovery-key-hash",
      stringToBytes(hashToString(legacyMaster))
    );

    const migrated = await establishMaster({
      storage,
      recoveryKey: b64(legacyMaster),
    });
    expect(migrated.origin).toBe("migrated-recovery-key");
    expect(b64(migrated.masterKey)).toBe(b64(legacyMaster));

    const second = await establishMaster({
      storage,
      recoveryKey: b64(legacyMaster),
    });
    expect(second.origin).toBe("envelope");
  });

  it("rejects a wrong legacy recovery key (hash mismatch, constant-time)", async () => {
    const storage = new MemoryStorage();
    await storage.write(
      "_meta",
      "recovery-key-hash",
      stringToBytes(hashToString(generateRandomKey()))
    );
    await expect(
      establishMaster({ storage, recoveryKey: b64(generateRandomKey()) })
    ).rejects.toThrow(/does not match|incorrect/i);
  });

  it("fails closed when a passphrase is supplied against a recovery-key-custody fortress", async () => {
    const storage = new MemoryStorage();
    await storage.write(
      "_meta",
      "recovery-key-hash",
      stringToBytes(hashToString(generateRandomKey()))
    );
    await expect(
      establishMaster({
        storage,
        passphrase: "any",
        firstRun: { installMode: "headless", mintRecoveryKey: false },
      })
    ).rejects.toThrow(/recovery-key custody/i);
    // Crucially: no new master was derived over the existing data.
    expect(await readCustodyEnvelope(storage)).toBeNull();
  });

  it("dual-path fortress (both legacy markers): the passphrase branch wins when data lives under it", async () => {
    const storage = new MemoryStorage();
    const passphraseMaster = await seedLegacyPassphraseFortress(storage, "live-pass");
    // The stale init-time marker from the OTHER path (the incident shape).
    const orphanMaster = generateRandomKey();
    await storage.write(
      "_meta",
      "recovery-key-hash",
      stringToBytes(hashToString(orphanMaster))
    );

    const migrated = await establishMaster({ storage, passphrase: "live-pass" });
    expect(b64(migrated.masterKey)).toBe(b64(passphraseMaster));

    // The orphaned init-time recovery key cannot capture the fortress: its
    // hash verifies but the data evidence contradicts it.
    const fresh = new MemoryStorage();
    for (const ns of ["_meta", "_identities"]) {
      for (const entry of await storage.list(ns)) {
        const v = await storage.read(ns, entry.key);
        if (v) await fresh.write(ns, entry.key, v);
      }
    }
    await fresh.delete("_meta", CUSTODY_ENVELOPE_KEY, false);
    await expect(
      establishMaster({ storage: fresh, recoveryKey: b64(orphanMaster) })
    ).rejects.toThrow(CustodyMigrationRefusedError);
  });
});

describe("two-factor custody floor", () => {
  async function envelopeWith(
    storage: MemoryStorage,
    installMode: CustodyEnvelope["install_mode"],
    verifiedCount: number
  ): Promise<void> {
    const master = generateRandomKey();
    const wraps = [];
    for (let i = 0; i < Math.max(verifiedCount, 1); i++) {
      wraps.push(
        wrapMasterWithRecoveryKey(master, generateRandomKey(), {
          verified: i < verifiedCount,
        })
      );
    }
    await writeCustodyEnvelope(storage, {
      v: 1,
      install_mode: installMode,
      wraps,
      created_at: new Date().toISOString(),
    });
  }

  it("passes for pre-envelope legacy fortresses (compat)", async () => {
    const storage = new MemoryStorage();
    await expect(enforceCustodyFloor(storage, "test")).resolves.toBeUndefined();
  });

  it("REFUSES an interactive install below 2 verified wraps", async () => {
    const storage = new MemoryStorage();
    await envelopeWith(storage, "interactive", 1);
    await expect(enforceCustodyFloor(storage, "identity_create")).rejects.toThrow(
      CustodyFloorError
    );
  });

  it("passes an interactive install at 2 verified wraps", async () => {
    const storage = new MemoryStorage();
    await envelopeWith(storage, "interactive", 2);
    await expect(enforceCustodyFloor(storage, "test")).resolves.toBeUndefined();
  });

  it("unverified wraps do not count toward the floor", async () => {
    const storage = new MemoryStorage();
    const master = generateRandomKey();
    await writeCustodyEnvelope(storage, {
      v: 1,
      install_mode: "interactive",
      wraps: [
        wrapMasterWithRecoveryKey(master, generateRandomKey(), { verified: false }),
        wrapMasterWithRecoveryKey(master, generateRandomKey(), { verified: false }),
      ],
      created_at: new Date().toISOString(),
    });
    await expect(enforceCustodyFloor(storage, "test")).rejects.toThrow(
      CustodyFloorError
    );
  });

  it("passes audited degraded install modes (headless / stdio-server / legacy-migrated)", async () => {
    for (const mode of ["headless", "stdio-server", "legacy-migrated"] as const) {
      const storage = new MemoryStorage();
      await envelopeWith(storage, mode, 0);
      await expect(enforceCustodyFloor(storage, "test")).resolves.toBeUndefined();
    }
  });

  it("IdentityManager.saveNew enforces the floor in the core (F6: not bypassable by SDK paths)", async () => {
    const storage = new MemoryStorage();
    await envelopeWith(storage, "interactive", 1);

    const { IdentityManager } = await import("../../src/l1-cognitive/tools.js");
    const { createIdentity } = await import("../../src/core/identity.js");
    const master = generateRandomKey();
    const mgr = new IdentityManager(storage, master);
    const { storedIdentity } = createIdentity(
      "blocked",
      derivePurposeKey(master, "identity-encryption"),
      "passphrase"
    );
    await expect(mgr.saveNew(storedIdentity)).rejects.toThrow(CustodyFloorError);
  });

  it("ReputationStore.importBundle enforces the floor in the core", async () => {
    const storage = new MemoryStorage();
    await envelopeWith(storage, "interactive", 1);

    const { ReputationStore } = await import(
      "../../src/l4-reputation/reputation-store.js"
    );
    const store = new ReputationStore(storage, generateRandomKey());
    await expect(
      store.importBundle(
        { version: "1.0", exported_at: "", subject_did: "did:x", attestations: [] } as never,
        false,
        new Map()
      )
    ).rejects.toThrow(CustodyFloorError);
  });
});

describe("recovery wrap lifecycle", () => {
  it("mintRecoveryWrap adds a wrap of the live master; re-entry verification proves end-to-end unlock", async () => {
    const storage = new MemoryStorage();
    const established = await establishMaster({
      storage,
      passphrase: "pass",
      firstRun: { installMode: "interactive", mintRecoveryKey: false },
    });

    const minted = await mintRecoveryWrap(
      storage,
      established.envelope,
      established.masterKey
    );
    expect(
      minted.envelope.wraps.find((w) => w.type === "recovery-key")?.verified
    ).toBe(false);

    // Wrong re-entry fails and does NOT mark verified.
    await expect(
      verifyRecoveryWrapByReentry(storage, minted.envelope, b64(generateRandomKey()))
    ).rejects.toThrow(CustodyUnlockError);

    // Correct re-entry unwraps the master and marks the wrap verified.
    const verified = await verifyRecoveryWrapByReentry(
      storage,
      minted.envelope,
      minted.recoveryKey
    );
    expect(
      verified.wraps.find((w) => w.type === "recovery-key")?.verified
    ).toBe(true);
    expect(countVerifiedWraps(verified)).toBe(2);

    // The minted key unlocks the same master.
    const viaRecovery = await establishMaster({
      storage,
      recoveryKey: minted.recoveryKey,
    });
    expect(b64(viaRecovery.masterKey)).toBe(b64(established.masterKey));
  });
});

describe("envelope persistence safety", () => {
  it("a malformed envelope fails closed (never regenerates custody state)", async () => {
    const storage = new MemoryStorage();
    await storage.write("_meta", CUSTODY_ENVELOPE_KEY, stringToBytes("{not json"));
    await expect(readCustodyEnvelope(storage)).rejects.toThrow(/unreadable/i);
    await expect(
      establishMaster({
        storage,
        passphrase: "x",
        firstRun: { installMode: "headless", mintRecoveryKey: false },
      })
    ).rejects.toThrow(/unreadable/i);
  });

  it("an unsupported envelope version fails closed", async () => {
    const storage = new MemoryStorage();
    await storage.write(
      "_meta",
      CUSTODY_ENVELOPE_KEY,
      stringToBytes(JSON.stringify({ v: 99, wraps: [] }))
    );
    await expect(readCustodyEnvelope(storage)).rejects.toThrow(/unsupported/i);
  });
});

describe("checkCastlePinCustody", () => {
  it("reports ok / mismatch / absent", async () => {
    const dir = await mkdtemp(join(tmpdir(), "sanctuary-pin-custody-"));
    try {
      const master = generateRandomKey();
      expect(await checkCastlePinCustody(dir, master)).toBe("absent");

      const seed = generateRandomKey();
      await writeFile(
        join(dir, "castle-pinned-privkey.enc"),
        JSON.stringify(encrypt(seed, master)),
        { mode: 0o600 }
      );
      expect(await checkCastlePinCustody(dir, master)).toBe("ok");
      expect(await checkCastlePinCustody(dir, generateRandomKey())).toBe(
        "mismatch"
      );
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });
});
