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
  verifyEnvelopeMac,
  enforceCustodyFloor,
  countVerifiedWraps,
  checkCastlePinCustody,
  CustodyUnlockError,
  CustodyCredentialMissingError,
  CustodyMigrationRefusedError,
  CustodyEnvelopeIntegrityError,
  OrphanedFortressStateError,
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
      mac: "", // unwrap tests bypass establishMaster; MAC checked there
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
      mac: "", // unwrap tests bypass establishMaster; MAC checked there
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
      mac: "", // unwrap tests bypass establishMaster; MAC checked there
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
      mac: "", // unwrap tests bypass establishMaster; MAC checked there
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

  it("refuses a first run over orphaned existing data (codex H1: no split-state)", async () => {
    const storage = new MemoryStorage();
    // A fortress with data but no envelope and no legacy markers — e.g.
    // someone deleted _meta/custody-envelope.
    await storage.write(
      "_identities",
      "orphan",
      stringToBytes(JSON.stringify({ some: "ciphertext" }))
    );
    await expect(
      establishMaster({
        storage,
        passphrase: "any",
        firstRun: { installMode: "stdio-server", mintRecoveryKey: true },
      })
    ).rejects.toThrow(OrphanedFortressStateError);
    // Nothing was created over the orphaned state.
    expect(await storage.read("_meta", CUSTODY_ENVELOPE_KEY)).toBeNull();
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

  it("DEFERS migration when data exists that the evidence probe cannot verify (codex H3)", async () => {
    const storage = new MemoryStorage();
    // Legacy fortress: key-params + data in a namespace the probe cannot
    // evidence-check (no identities/reputation/audit/sentinel).
    const { params } = await deriveMasterKey("any-pass");
    await storage.write(
      "_meta",
      "key-params",
      stringToBytes(JSON.stringify(params))
    );
    await storage.write(
      "user-data",
      "entry",
      stringToBytes(JSON.stringify({ opaque: "blob" }))
    );

    // Even a wrong passphrase must NOT get captured into an envelope here.
    const result = await establishMaster({ storage, passphrase: "any-pass" });
    expect(result.origin).toBe("legacy-deferred");
    expect(result.envelope).toBeNull();
    expect(await storage.read("_meta", CUSTODY_ENVELOPE_KEY)).toBeNull();
  });

  it("migrates a legacy passphrase fortress with ONLY markers (empty, nothing to lose)", async () => {
    const storage = new MemoryStorage();
    const { params } = await deriveMasterKey("fresh-pass");
    await storage.write(
      "_meta",
      "key-params",
      stringToBytes(JSON.stringify(params))
    );
    const result = await establishMaster({ storage, passphrase: "fresh-pass" });
    expect(result.origin).toBe("migrated-passphrase");
    expect(result.envelope).not.toBeNull();
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
    // hash verifies but the data evidence contradicts it. Model the
    // PRE-migration dual fortress (copy legacy markers + data only — no
    // envelope, no sentinel).
    const fresh = new MemoryStorage();
    for (const key of ["key-params", "recovery-key-hash"]) {
      const v = await storage.read("_meta", key);
      if (v) await fresh.write("_meta", key, v);
    }
    for (const entry of await storage.list("_identities")) {
      const v = await storage.read("_identities", entry.key);
      if (v) await fresh.write("_identities", entry.key, v);
    }
    await expect(
      establishMaster({ storage: fresh, recoveryKey: b64(orphanMaster) })
    ).rejects.toThrow(CustodyMigrationRefusedError);
  });
});

describe("two-factor custody floor", () => {
  /**
   * Build a MAC'd envelope with `verifiedTypes` distinct verified factor
   * types (recovery-key first, then keychain) plus one unverified recovery
   * wrap, under a caller-visible master.
   */
  async function envelopeWith(
    storage: MemoryStorage,
    installMode: CustodyEnvelope["install_mode"],
    verifiedTypes: number,
    master: Uint8Array = generateRandomKey()
  ): Promise<Uint8Array> {
    const wraps = [
      wrapMasterWithRecoveryKey(master, generateRandomKey(), {
        verified: verifiedTypes >= 1,
      }),
      wrapMasterWithKeychainKey(master, generateRandomKey(), {
        verified: verifiedTypes >= 2,
      }),
    ];
    await writeCustodyEnvelope(
      storage,
      {
        v: 1,
        install_mode: installMode,
        wraps,
        created_at: new Date().toISOString(),
      },
      master
    );
    return master;
  }

  it("passes for pre-envelope legacy fortresses (compat)", async () => {
    const storage = new MemoryStorage();
    await expect(
      enforceCustodyFloor(storage, "test", generateRandomKey())
    ).resolves.toBeUndefined();
  });

  it("REFUSES an interactive install below 2 verified factor types", async () => {
    const storage = new MemoryStorage();
    const master = await envelopeWith(storage, "interactive", 1);
    await expect(
      enforceCustodyFloor(storage, "identity_create", master)
    ).rejects.toThrow(CustodyFloorError);
  });

  it("passes an interactive install at 2 verified factor types", async () => {
    const storage = new MemoryStorage();
    const master = await envelopeWith(storage, "interactive", 2);
    await expect(
      enforceCustodyFloor(storage, "test", master)
    ).resolves.toBeUndefined();
  });

  it("unverified wraps do not count toward the floor", async () => {
    const storage = new MemoryStorage();
    const master = await envelopeWith(storage, "interactive", 0);
    await expect(enforceCustodyFloor(storage, "test", master)).rejects.toThrow(
      CustodyFloorError
    );
  });

  it("duplicated wraps of ONE factor type do not satisfy the floor (codex M1)", async () => {
    const storage = new MemoryStorage();
    const master = generateRandomKey();
    await writeCustodyEnvelope(
      storage,
      {
        v: 1,
        install_mode: "interactive",
        wraps: [
          wrapMasterWithRecoveryKey(master, generateRandomKey(), { verified: true }),
          wrapMasterWithRecoveryKey(master, generateRandomKey(), { verified: true }),
        ],
        created_at: new Date().toISOString(),
      },
      master
    );
    await expect(enforceCustodyFloor(storage, "test", master)).rejects.toThrow(
      CustodyFloorError
    );
  });

  it("passes audited degraded install modes (headless / stdio-server / legacy-migrated)", async () => {
    for (const mode of ["headless", "stdio-server", "legacy-migrated"] as const) {
      const storage = new MemoryStorage();
      const master = await envelopeWith(storage, mode, 0);
      await expect(
        enforceCustodyFloor(storage, "test", master)
      ).resolves.toBeUndefined();
    }
  });

  it("a TAMPERED install_mode is detected and fails closed (codex H2)", async () => {
    const storage = new MemoryStorage();
    const master = await envelopeWith(storage, "interactive", 0);

    // Attacker with bare write access flips install_mode to a degraded
    // (floor-exempt) mode without knowing the master.
    const raw = await storage.read("_meta", CUSTODY_ENVELOPE_KEY);
    const tampered = JSON.parse(bytesToString(raw!));
    tampered.install_mode = "headless";
    await storage.write(
      "_meta",
      CUSTODY_ENVELOPE_KEY,
      stringToBytes(JSON.stringify(tampered))
    );

    await expect(enforceCustodyFloor(storage, "test", master)).rejects.toThrow(
      CustodyEnvelopeIntegrityError
    );
  });

  it("a TAMPERED verified flag is detected and fails closed (codex H2)", async () => {
    const storage = new MemoryStorage();
    const master = await envelopeWith(storage, "interactive", 0);

    const raw = await storage.read("_meta", CUSTODY_ENVELOPE_KEY);
    const tampered = JSON.parse(bytesToString(raw!));
    for (const w of tampered.wraps) w.verified = true;
    await storage.write(
      "_meta",
      CUSTODY_ENVELOPE_KEY,
      stringToBytes(JSON.stringify(tampered))
    );

    await expect(enforceCustodyFloor(storage, "test", master)).rejects.toThrow(
      CustodyEnvelopeIntegrityError
    );
  });

  it("establishMaster refuses a tampered envelope at unlock (codex H2)", async () => {
    const storage = new MemoryStorage();
    const first = await establishMaster({
      storage,
      passphrase: "pass",
      firstRun: { installMode: "headless", mintRecoveryKey: false },
    });
    const raw = await storage.read("_meta", CUSTODY_ENVELOPE_KEY);
    const tampered = JSON.parse(bytesToString(raw!));
    tampered.install_mode = "interactive";
    await storage.write(
      "_meta",
      CUSTODY_ENVELOPE_KEY,
      stringToBytes(JSON.stringify(tampered))
    );
    await expect(
      establishMaster({ storage, passphrase: "pass" })
    ).rejects.toThrow(CustodyEnvelopeIntegrityError);
    expect(first.masterKey.length).toBe(32);
  });

  it("IdentityManager.saveNew enforces the floor in the core (F6: not bypassable by SDK paths)", async () => {
    const storage = new MemoryStorage();
    const master = await envelopeWith(storage, "interactive", 1);

    const { IdentityManager } = await import("../../src/cognitive/tools.js");
    const { createIdentity } = await import("../../src/core/identity.js");
    const mgr = new IdentityManager(storage, master);
    const { storedIdentity } = createIdentity(
      "blocked",
      derivePurposeKey(master, "identity-encryption"),
      "passphrase"
    );
    await expect(mgr.saveNew(storedIdentity)).rejects.toThrow(CustodyFloorError);
  });

  it("DIRECT IdentityManager.save() of a NEW identity also hits the floor (codex round-2: sanctuary_bootstrap path)", async () => {
    const storage = new MemoryStorage();
    const master = await envelopeWith(storage, "interactive", 1);

    const { IdentityManager } = await import("../../src/cognitive/tools.js");
    const { createIdentity } = await import("../../src/core/identity.js");
    const mgr = new IdentityManager(storage, master);
    const { storedIdentity } = createIdentity(
      "blocked-direct",
      derivePurposeKey(master, "identity-encryption"),
      "passphrase"
    );
    await expect(mgr.save(storedIdentity)).rejects.toThrow(CustodyFloorError);
  });

  it("UPDATING an already-loaded identity is not creation and stays un-gated", async () => {
    const storage = new MemoryStorage();
    const master = await envelopeWith(storage, "headless", 1);

    const { IdentityManager } = await import("../../src/cognitive/tools.js");
    const { createIdentity } = await import("../../src/core/identity.js");
    const mgr = new IdentityManager(storage, master);
    const { storedIdentity } = createIdentity(
      "rotatable",
      derivePurposeKey(master, "identity-encryption"),
      "passphrase"
    );
    await mgr.save(storedIdentity); // headless mode: creation allowed, audited

    // Demote the fortress to a state where CREATION would be refused…
    const raw = await storage.read("_meta", CUSTODY_ENVELOPE_KEY);
    const envelope = JSON.parse(bytesToString(raw!));
    envelope.install_mode = "interactive";
    const { writeCustodyEnvelope: rewrite } = await import(
      "../../src/core/master-custody.js"
    );
    await rewrite(storage, envelope, master);

    // …an UPDATE of the existing identity still goes through.
    await expect(mgr.save(storedIdentity)).resolves.toBeUndefined();
  });

  it("floor fails closed when the envelope is missing but the sentinel remains (codex round-2 H2)", async () => {
    const storage = new MemoryStorage();
    const master = await envelopeWith(storage, "interactive", 0);
    await storage.delete("_meta", CUSTODY_ENVELOPE_KEY, false);
    await expect(enforceCustodyFloor(storage, "test", master)).rejects.toThrow(
      CustodyEnvelopeIntegrityError
    );
  });

  it("establishMaster refuses the legacy-downgrade path when the sentinel remains (codex round-2)", async () => {
    const storage = new MemoryStorage();
    // Migrated fortress: legacy markers + envelope + sentinel.
    const { params } = await deriveMasterKey("legacy-pass");
    await storage.write(
      "_meta",
      "key-params",
      stringToBytes(JSON.stringify(params))
    );
    const migrated = await establishMaster({ storage, passphrase: "legacy-pass" });
    expect(migrated.origin).toBe("migrated-passphrase");

    // Attacker deletes the envelope; legacy markers remain. Re-migration
    // must NOT mint fresh one-wrap custody — the sentinel says no.
    await storage.delete("_meta", CUSTODY_ENVELOPE_KEY, false);
    await expect(
      establishMaster({ storage, passphrase: "legacy-pass" })
    ).rejects.toThrow(CustodyEnvelopeIntegrityError);
  });

  it("ReputationStore.importBundle enforces the floor in the core", async () => {
    const storage = new MemoryStorage();
    const master = await envelopeWith(storage, "interactive", 1);

    const { ReputationStore } = await import(
      "../../src/reputation/reputation-store.js"
    );
    const store = new ReputationStore(storage, master);
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

  it("re-entry marks ONLY the wrap the entered key decrypts (codex M1)", async () => {
    const storage = new MemoryStorage();
    const established = await establishMaster({
      storage,
      passphrase: "pass",
      firstRun: { installMode: "interactive", mintRecoveryKey: false },
    });
    expect(established.envelope).not.toBeNull();
    const firstMint = await mintRecoveryWrap(
      storage,
      established.envelope!,
      established.masterKey
    );
    const secondMint = await mintRecoveryWrap(
      storage,
      firstMint.envelope,
      established.masterKey
    );

    const verified = await verifyRecoveryWrapByReentry(
      storage,
      secondMint.envelope,
      secondMint.recoveryKey
    );
    const recoveryWraps = verified.wraps.filter((w) => w.type === "recovery-key");
    expect(recoveryWraps).toHaveLength(2);
    expect(recoveryWraps.filter((w) => w.verified)).toHaveLength(1);
    // And the envelope MAC still verifies under the master after the update.
    verifyEnvelopeMac(verified, established.masterKey);
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

  it("a wrap missing type/verified/payload still fails closed (genuinely malformed)", async () => {
    const storage = new MemoryStorage();
    await storage.write(
      "_meta",
      CUSTODY_ENVELOPE_KEY,
      stringToBytes(
        JSON.stringify({
          v: 1,
          install_mode: "interactive",
          wraps: [{ id: "x", type: "passphrase" }], // no verified, no payload
          created_at: new Date().toISOString(),
          mac: "deadbeef",
        })
      )
    );
    await expect(readCustodyEnvelope(storage)).rejects.toThrow(/unsupported/i);
  });
});

describe("pre-mac legacy envelope migration (#496 upgrade-safety)", () => {
  const LEGACY_PASSPHRASE = "legacy-passphrase-from-before-the-mac";

  /**
   * Materialize on disk a fortress provisioned BEFORE the top-level `mac` and
   * per-wrap `id` fields existed: a v:1 envelope with NO mac and a single
   * passphrase wrap WITHOUT an id, whose payload was bound with the id-less
   * legacy AEAD AAD (`sanctuary-custody-v1:passphrase`). Plus a matching
   * encrypted identity under the master so the migration evidence check
   * CONFIRMS. Returns the true master.
   */
  async function seedPreMacFortress(
    storage: MemoryStorage,
    installMode = "legacy-migrated"
  ): Promise<Uint8Array> {
    const master = generateRandomKey();
    const { key: wrapKey, params } = await deriveMasterKey(LEGACY_PASSPHRASE);
    // Pre-#496 wraps had no id, so the AAD omitted it.
    const legacyAad = stringToBytes("sanctuary-custody-v1:passphrase");
    const payload = encrypt(master, wrapKey, legacyAad);
    wrapKey.fill(0);
    const legacyEnvelope = {
      v: 1,
      install_mode: installMode,
      wraps: [
        {
          type: "passphrase",
          payload,
          kdf: params,
          verified: true,
          created_at: new Date().toISOString(),
        },
      ],
      created_at: new Date().toISOString(),
      // NO mac, NO wrap.id (the pre-#496 shape).
    };
    await storage.write(
      "_meta",
      CUSTODY_ENVELOPE_KEY,
      stringToBytes(JSON.stringify(legacyEnvelope))
    );
    // Matching encrypted state so checkMasterEvidence CONFIRMS the master.
    const idKey = derivePurposeKey(master, "identity-encryption");
    const enc = encrypt(stringToBytes('{"identity_id":"legacy-seed"}'), idKey);
    await storage.write(
      "_identities",
      "legacy-seed",
      stringToBytes(JSON.stringify(enc))
    );
    return master;
  }

  it("readCustodyEnvelope ACCEPTS a pre-mac envelope and flags it needs-migration", async () => {
    const storage = new MemoryStorage();
    await seedPreMacFortress(storage);
    const envelope = await readCustodyEnvelope(storage);
    expect(envelope).not.toBeNull();
    expect(envelope!.needsMacMigration).toBe(true);
    // It does NOT throw the old "unsupported shape" error.
  });

  it("unlocks a pre-mac fortress AND re-stamps it (mac present, every wrap has an id)", async () => {
    const storage = new MemoryStorage();
    const master = await seedPreMacFortress(storage);

    const result = await establishMaster({
      storage,
      passphrase: LEGACY_PASSPHRASE,
    });
    expect(result.origin).toBe("envelope");
    // The re-stamp is a security-relevant custody transition; origin stays
    // "envelope" so `migratedInPlace` is the ONLY signal the boot paths gate
    // the `custody_legacy_migrated` audit event on. It MUST be set here.
    expect(result.migratedInPlace).toBe(true);
    // Same master, no data lost.
    expect(b64(result.masterKey)).toBe(b64(master));
    // The seeded identity still decrypts.
    const idKey = derivePurposeKey(result.masterKey, "identity-encryption");
    const raw = await storage.read("_identities", "legacy-seed");
    expect(bytesToString(decrypt(JSON.parse(bytesToString(raw!)), idKey))).toContain(
      "legacy-seed"
    );

    // On-disk envelope is now UPGRADED: mac present, every wrap has an id.
    const onDisk = JSON.parse(
      bytesToString((await storage.read("_meta", CUSTODY_ENVELOPE_KEY))!)
    );
    expect(typeof onDisk.mac).toBe("string");
    expect(onDisk.mac.length).toBeGreaterThan(0);
    for (const w of onDisk.wraps) {
      expect(typeof w.id).toBe("string");
      expect(w.id.length).toBeGreaterThan(0);
    }

    // A SECOND unlock passes the strict MAC path cleanly (no needs-migration).
    const second = await establishMaster({
      storage,
      passphrase: LEGACY_PASSPHRASE,
    });
    expect(second.origin).toBe("envelope");
    // An ordinary strict-MAC unlock is NOT a migration: the flag must be unset
    // so the boot paths do not emit a spurious migration audit every unlock.
    expect(second.migratedInPlace).toBeUndefined();
    expect(b64(second.masterKey)).toBe(b64(master));
    const reread = await readCustodyEnvelope(storage);
    expect(reread!.needsMacMigration).toBeUndefined();
    verifyEnvelopeMac(reread!, second.masterKey);
  });

  it("wrap id assignment is stable: repeated reads yield the same synthetic ids", async () => {
    const storage = new MemoryStorage();
    await seedPreMacFortress(storage);
    const first = await readCustodyEnvelope(storage);
    const second = await readCustodyEnvelope(storage);
    expect(first!.wraps.map((w) => w.id)).toEqual(second!.wraps.map((w) => w.id));
    expect(first!.wraps[0]!.id).toBe("legacy-0");
  });

  it("FAILS CLOSED when a sentinel is present but the mac is absent (tamper / stripped mac)", async () => {
    const storage = new MemoryStorage();
    await seedPreMacFortress(storage);
    // A sentinel proves a MAC'd envelope existed; a mac-absent envelope beside
    // it means the mac was stripped. Migration must refuse (no laundering).
    await storage.write(
      "_meta",
      "custody-sentinel",
      stringToBytes(JSON.stringify({ v: 1, alg: "aes-256-gcm", iv: "x", ct: "y" }))
    );
    await expect(
      establishMaster({ storage, passphrase: LEGACY_PASSPHRASE })
    ).rejects.toThrow(CustodyEnvelopeIntegrityError);
    // The on-disk envelope is unchanged (still no mac); nothing was blessed.
    const onDisk = JSON.parse(
      bytesToString((await storage.read("_meta", CUSTODY_ENVELOPE_KEY))!)
    );
    expect(onDisk.mac).toBeUndefined();
  });

  it("REFUSES to bless a pre-mac envelope whose unlocked master contradicts existing data", async () => {
    const storage = new MemoryStorage();
    await seedPreMacFortress(storage);
    // Overwrite the seeded identity with ciphertext under a DIFFERENT master,
    // so the (correctly unwrapped) master contradicts the fortress data.
    const otherMaster = generateRandomKey();
    const otherIdKey = derivePurposeKey(otherMaster, "identity-encryption");
    const enc = encrypt(stringToBytes('{"identity_id":"other"}'), otherIdKey);
    await storage.write(
      "_identities",
      "legacy-seed",
      stringToBytes(JSON.stringify(enc))
    );
    await expect(
      establishMaster({ storage, passphrase: LEGACY_PASSPHRASE })
    ).rejects.toThrow(CustodyMigrationRefusedError);
  });

  it("re-stamps the install_mode to the most-restrictive `interactive`, never trusting the on-disk value (anti downgrade-laundering)", async () => {
    // The mac-absent envelope carries no authenticated install_mode. An attacker
    // who strips the top-level mac can equally delete the sentinel, so this
    // sentinel-absent branch can be reached with an attacker-chosen,
    // floor-exempt install_mode (here `headless`). Honoring the on-disk value
    // would silently bless that downgrade with a fresh valid MAC and disable the
    // two-factor floor. The migration must re-stamp to `interactive` instead.
    const storage = new MemoryStorage();
    await seedPreMacFortress(storage, "headless");
    await establishMaster({ storage, passphrase: LEGACY_PASSPHRASE });
    const reread = await readCustodyEnvelope(storage);
    expect(reread!.install_mode).toBe("interactive");
  });

  it("a born-#496 fortress with mac + sentinel stripped and install_mode flipped to floor-exempt cannot launder a downgrade through the migration path", async () => {
    // Reproduces the full attack: a real post-#496 fortress whose two-factor
    // custody the attacker wants to dodge. They (a) strip the top-level mac,
    // (b) DELETE the sentinel, and (c) flip install_mode to a floor-exempt
    // value. On the legit operator's next unlock the master still
    // GCM-authenticates from the wraps and the fortress ciphertext CONFIRMS, so
    // the migration runs, but it must NOT bless the attacker's floor-exempt
    // install_mode. It re-stamps `interactive`, keeping the floor in force.
    const storage = new MemoryStorage();
    const master = await seedPreMacFortress(storage, "legacy-migrated");
    const result = await establishMaster({
      storage,
      passphrase: LEGACY_PASSPHRASE,
    });
    expect(result.migratedInPlace).toBe(true);
    expect(b64(result.masterKey)).toBe(b64(master));
    const reread = await readCustodyEnvelope(storage);
    // NOT the attacker-chosen floor-exempt `legacy-migrated`.
    expect(reread!.install_mode).toBe("interactive");
    // And the floor now governs: a single verified factor type on an
    // `interactive` envelope is below CUSTODY_FLOOR_WRAPS, so a trust-bearing
    // write is refused rather than silently allowed.
    await expect(
      enforceCustodyFloor(storage, "test-action", result.masterKey)
    ).rejects.toThrow(CustodyFloorError);
  });

  it("the migrated envelope is tamper-evident: flipping install_mode now fails the MAC", async () => {
    const storage = new MemoryStorage();
    const master = await seedPreMacFortress(storage);
    await establishMaster({ storage, passphrase: LEGACY_PASSPHRASE });
    // Attacker flips install_mode on the now-MAC'd envelope. The migration
    // re-stamps to `interactive`, so flip to a DIFFERENT (floor-exempt) value
    // to exercise tamper-evidence.
    const onDisk = JSON.parse(
      bytesToString((await storage.read("_meta", CUSTODY_ENVELOPE_KEY))!)
    );
    expect(onDisk.install_mode).toBe("interactive");
    onDisk.install_mode = "headless";
    await storage.write(
      "_meta",
      CUSTODY_ENVELOPE_KEY,
      stringToBytes(JSON.stringify(onDisk))
    );
    const tampered = await readCustodyEnvelope(storage);
    expect(tampered!.needsMacMigration).toBeUndefined();
    expect(() => verifyEnvelopeMac(tampered!, master)).toThrow(
      CustodyEnvelopeIntegrityError
    );
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
