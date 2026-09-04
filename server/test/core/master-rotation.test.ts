/**
 * Master-rotation tests (F7, custody/crypto lane).
 *
 * The property under test: rotation mints a fresh master, re-encrypts
 * EVERYTHING under it (state envelopes re-signed, identities, purpose
 * stores, MAC'd records, castle pin), re-wraps custody (passphrase +
 * verified NEW recovery key), retires the old master — and a crash at ANY
 * point either leaves a fully old-keyed fortress (pre-journal) or a
 * journaled fortress that refuses to boot and resumes FORWARD to a fully
 * new-keyed one. No window exists where data sits under one master and
 * wraps only under the other.
 */

import { describe, it, expect } from "vitest";
import { mkdtemp, rm, writeFile, readFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { ed25519 } from "@noble/curves/ed25519";

import { MemoryStorage } from "../../src/storage/memory.js";
import {
  establishMaster,
  readCustodyEnvelope,
  countVerifiedWraps,
  envelopeEpochOf,
  readEnvelopeEpoch,
  CustodyUnlockError,
  CustodyRotationInProgressError,
  ROTATION_JOURNAL_KEY,
  STAGED_CUSTODY_ENVELOPE_KEY,
  STAGED_CUSTODY_SENTINEL_KEY,
} from "../../src/core/master-custody.js";
import {
  readEpochWitness,
  observeWitnessEpoch,
  evaluateRollback,
  EPOCH_WITNESS_META_KEY,
} from "../../src/core/anti-rollback.js";
import {
  readCustodyEpochCount,
  probeAuditHeadAnchor,
  deriveAuditEpochKeys,
  AUDIT_EPOCH_KEYS_KEY,
} from "../../src/operational/audit-log.js";
import {
  CUSTODY_ENVELOPE_KEY,
  CUSTODY_SENTINEL_KEY,
} from "../../src/core/master-custody.js";
import {
  rotateMaster,
  resumeRotation,
  RotationPreflightError,
  RotationResumeError,
  type RotateMasterOptions,
} from "../../src/core/master-rotation.js";
import { StateStore, type StateEntry } from "../../src/cognitive/state-store.js";
import { AuditLog } from "../../src/operational/audit-log.js";
import {
  deriveNamespaceKey,
  derivePurposeKey,
} from "../../src/core/key-derivation.js";
import { generateRandomKey } from "../../src/core/random.js";
import { encrypt, decrypt, type EncryptedPayload } from "../../src/core/encryption.js";
import {
  fromBase64url,
  toBase64url,
  stringToBytes,
  bytesToString,
} from "../../src/core/encoding.js";
import {
  FEDERATION_TRUST_ROOT_NAMESPACE,
  FEDERATION_TRUST_ROOT_KEY,
  FEDERATION_TRUST_ROOT_HKDF_INFO,
  FEDERATION_ISSUANCE_SUITE_HYBRID,
  provisionOrLoadFederationTrustRoot,
} from "../../src/mesh/federation-trust-root-store.js";
import {
  FEDERATION_JOINER_TRUST_ROOT_NAMESPACE,
  FEDERATION_JOINER_TRUST_ROOT_KEY,
  FEDERATION_JOINER_TRUST_ROOT_HKDF_INFO,
} from "../../src/mesh/federation-joiner-trust-root-store.js";
import {
  BOOTSTRAP_NONCE_STORE_NAMESPACE,
  BOOTSTRAP_NONCE_STORE_KEY,
  BOOTSTRAP_NONCE_STORE_HKDF_INFO,
} from "../../src/mesh/lifecycle/standalone-join-approver.js";
import {
  OPERATOR_CLOUD_CLAIM_STORE_NAMESPACE,
  OPERATOR_CLOUD_CLAIM_STORE_KEY,
  OPERATOR_CLOUD_CLAIM_STORE_HKDF_INFO,
} from "../../src/mesh/lifecycle/operator-cloud-join-approver.js";
import {
  FEDERATION_SYNC_STATE_STORE_NAMESPACE,
  FEDERATION_SYNC_STATE_STORE_KEY,
  FEDERATION_SYNC_STATE_STORE_HKDF_INFO,
  FederationSyncStateStore,
  FEDERATION_GUARDIAN_ANTIROLLBACK_ANCHOR_KEY,
  FEDERATION_GUARDIAN_REQUIREMENT_ESTABLISHED_KEY,
} from "../../src/v1/federation-sync-state-store.js";
import {
  OPERATOR_CLOUD_JOINED_NODE_NAMESPACE,
  OPERATOR_CLOUD_JOINED_NODE_KEY,
  OPERATOR_CLOUD_JOINED_NODE_HKDF_INFO,
} from "../../src/mesh/operator-cloud-joined-node-store.js";
import {
  FEDERATION_REISSUE_CHALLENGE_STORE_NAMESPACE,
  FEDERATION_REISSUE_CHALLENGE_STORE_KEY,
  FEDERATION_REISSUE_CHALLENGE_STORE_HKDF_INFO,
} from "../../src/v1/federation-reissue-challenge-store.js";
import { rotateKeys, type StoredIdentity } from "../../src/core/identity.js";
import {
  readSdwOwnerPin,
  writeSdwOwnerPin,
} from "../../src/sdw/write-gate.js";

const PASSPHRASE = "rotation-test-passphrase";
const KID = "agent-rotate-1";
const FORTRESS_ID = "fortress-rotation-test";

interface Fortress {
  storage: MemoryStorage;
  master: Uint8Array;
  identity: StoredIdentity;
  oldRecoveryKey: string;
}

async function buildFortress(): Promise<Fortress> {
  const storage = new MemoryStorage();
  const est = await establishMaster({
    storage,
    passphrase: PASSPHRASE,
    firstRun: { installMode: "interactive", mintRecoveryKey: true },
  });
  const master = est.masterKey;

  // A resident identity (outer record AND inner private key under the
  // identity-encryption purpose key — both must rotate).
  const seed = generateRandomKey();
  const publicKey = ed25519.getPublicKey(seed);
  const idKey = derivePurposeKey(master, "identity-encryption");
  const identity: StoredIdentity = {
    identity_id: KID,
    label: "rotation test agent",
    public_key: toBase64url(publicKey),
    did: "did:key:test",
    created_at: new Date().toISOString(),
    key_type: "ed25519",
    key_protection: "passphrase",
    encrypted_private_key: encrypt(seed, idKey),
    rotation_history: [],
  };
  await storage.write(
    "_identities",
    KID,
    stringToBytes(
      JSON.stringify(encrypt(stringToBytes(JSON.stringify(identity)), idKey))
    )
  );

  // Signed state entries in two user namespaces (ciphertext-bound writer
  // signatures: the rotation must re-sign).
  const stateStore = new StateStore(storage, master);
  await stateStore.write(
    "notes",
    "k1",
    "hello sovereign world",
    KID,
    identity.encrypted_private_key,
    idKey
  );
  await stateStore.write(
    "notes",
    "k2",
    "second entry",
    KID,
    identity.encrypted_private_key,
    idKey
  );
  await stateStore.write(
    "plans",
    "p1",
    JSON.stringify({ goal: "rotate safely" }),
    KID,
    identity.encrypted_private_key,
    idKey
  );

  // Audit chain (entries stay byte-identical across rotation; epoch-scoped
  // decryption must keep them readable).
  const audit = new AuditLog(storage, master);
  for (let i = 0; i < 3; i++) {
    await audit.appendCritical({
      layer: "l1",
      operation: `fixture_op_${i}`,
      identity_id: KID,
      result: "success",
    });
  }
  await audit.flush();

  // A purpose-keyed store without AAD (reputation)…
  await storage.write(
    "_reputation",
    "att-1",
    stringToBytes(
      JSON.stringify(
        encrypt(
          stringToBytes(JSON.stringify({ attestation: "fixture" })),
          derivePurposeKey(master, "l4-reputation")
        )
      )
    )
  );
  // …and a second purpose-keyed store without AAD (known-signer keys,
  // Exit V2 drill F2 - HIGH-2, independent gate on #1303, 2026-08-23:
  // `_known_signers` had no rotation recipe, so rotation preflight refused
  // on any fortress that had ever imported foreign reputation).
  await storage.write(
    "_known_signers",
    "signer-1",
    stringToBytes(
      JSON.stringify(
        encrypt(
          stringToBytes(JSON.stringify({ known_signer: "fixture" })),
          derivePurposeKey(master, "l4-known-signers")
        )
      )
    )
  );
  // …and one WITH a per-record AAD (sentinel findings: aad = finding id).
  await storage.write(
    "_sentinel_findings",
    "finding-1",
    stringToBytes(
      JSON.stringify(
        encrypt(
          stringToBytes(JSON.stringify({ severity: "low" })),
          derivePurposeKey(master, "l2-sentinel-finding-v1"),
          stringToBytes("finding-1")
        )
      )
    )
  );

  return {
    storage,
    master,
    identity,
    oldRecoveryKey: est.mintedRecoveryKey!,
  };
}

function rotateOpts(
  fortress: Fortress,
  overrides?: Partial<RotateMasterOptions>
): RotateMasterOptions {
  return {
    storage: fortress.storage,
    fortressId: FORTRESS_ID,
    passphrase: PASSPHRASE,
    approve: async () => true,
    // Capture rules: the disclosed key is re-entered and proven by
    // unwrapping the staged master with it.
    captureRecoveryKey: async (recoveryKey, verify) => verify(recoveryKey),
    ...overrides,
  };
}

async function readResidentIdentity(
  fortress: Fortress,
): Promise<{ identity: StoredIdentity; identityKey: Uint8Array }> {
  const identityKey = derivePurposeKey(fortress.master, "identity-encryption");
  const raw = await fortress.storage.read("_identities", KID);
  if (!raw) throw new Error(`missing test identity ${KID}`);
  const encrypted = JSON.parse(bytesToString(raw)) as EncryptedPayload;
  const identity = JSON.parse(
    bytesToString(decrypt(encrypted, identityKey))
  ) as StoredIdentity;
  return { identity, identityKey };
}

async function writeResidentIdentity(
  fortress: Fortress,
  identity: StoredIdentity,
  identityKey: Uint8Array,
): Promise<void> {
  await fortress.storage.write(
    "_identities",
    KID,
    stringToBytes(
      JSON.stringify(encrypt(stringToBytes(JSON.stringify(identity)), identityKey))
    )
  );
}

async function rotateResidentIdentity(fortress: Fortress): Promise<StoredIdentity> {
  const { identity, identityKey } = await readResidentIdentity(fortress);
  const { updatedIdentity } = rotateKeys(
    identity,
    identityKey,
    "test identity rotation"
  );
  await writeResidentIdentity(fortress, updatedIdentity, identityKey);
  return updatedIdentity;
}

/** Full post-rotation verification battery. */
async function verifyRotated(
  fortress: Fortress,
  opts?: { newRecoveryKey?: string }
): Promise<void> {
  const { storage } = fortress;

  // Custody: passphrase unlocks a DIFFERENT master; journal + staged gone.
  expect(await storage.read("_meta", ROTATION_JOURNAL_KEY)).toBeNull();
  expect(await storage.read("_meta", STAGED_CUSTODY_ENVELOPE_KEY)).toBeNull();
  expect(await storage.read("_meta", STAGED_CUSTODY_SENTINEL_KEY)).toBeNull();
  expect(await storage.read("_meta", "key-params")).toBeNull();
  expect(await storage.read("_meta", "recovery-key-hash")).toBeNull();

  const est = await establishMaster({ storage, passphrase: PASSPHRASE });
  const newMaster = est.masterKey;
  expect(toBase64url(newMaster)).not.toBe(toBase64url(fortress.master));

  // Two-factor floor preserved (passphrase + re-entry-verified recovery key).
  expect(countVerifiedWraps(est.envelope!)).toBeGreaterThanOrEqual(2);
  expect(est.envelope!.install_mode).toBe("interactive");

  // The OLD recovery key is retired.
  await expect(
    establishMaster({ storage, recoveryKey: fortress.oldRecoveryKey })
  ).rejects.toThrow(CustodyUnlockError);
  // The NEW recovery key unlocks the SAME new master.
  if (opts?.newRecoveryKey) {
    const viaRecovery = await establishMaster({
      storage,
      recoveryKey: opts.newRecoveryKey,
    });
    expect(toBase64url(viaRecovery.masterKey)).toBe(toBase64url(newMaster));
  }

  // State: decrypts, verifies signatures, survives with intact plaintext.
  const stateStore = new StateStore(storage, newMaster);
  const read1 = await stateStore.read("notes", "k1");
  expect(read1?.value).toBe("hello sovereign world");
  expect(read1?.signature_verified).toBe(true);
  const read3 = await stateStore.read("plans", "p1");
  expect(JSON.parse(read3!.value).goal).toBe("rotate safely");

  // Nothing decrypts under the OLD master anymore (user state).
  const oldNsKey = deriveNamespaceKey(fortress.master, "notes");
  const rawEntry = await storage.read("notes", "k1");
  const entry = JSON.parse(bytesToString(rawEntry!)) as StateEntry;
  expect(entry.v).toBe(3);
  expect(entry.metadata.schema_version).toBe(3);
  expect(entry.provenance_stamp?.entry_binding).toBe("notes/k1");
  expect(entry.envelope?.provenance_stamp).toEqual(entry.provenance_stamp);
  expect(() => decrypt(entry.payload, oldNsKey)).toThrow();

  // Audit: the FULL chain (pre- and post-rotation entries) loads cleanly in
  // strict mode under the new master — verifiable ACROSS the boundary.
  const audit = new AuditLog(storage, newMaster);
  const result = await audit.query({ limit: 100 });
  expect(result.integrity_findings).toEqual([]);
  const operations = result.entries.map((e) => e.operation);
  expect(operations).toContain("fixture_op_0");
  expect(operations).toContain("fixture_op_2");
  expect(operations).toContain("custody_rotation_started");
  expect(operations).toContain("custody_master_rotated");
  // The rotation audit entry records envelope/wrap ids, never key material.
  const rotated = result.entries.find(
    (e) => e.operation === "custody_master_rotated"
  )!;
  expect(rotated.details?.rotation_id).toBeTruthy();
  expect(Array.isArray(rotated.details?.old_wrap_ids)).toBe(true);
  expect(JSON.stringify(rotated.details)).not.toContain(
    toBase64url(fortress.master)
  );
  expect(JSON.stringify(rotated.details)).not.toContain(toBase64url(newMaster));

  // Purpose stores re-keyed (with and without AAD).
  const rep = JSON.parse(
    bytesToString((await storage.read("_reputation", "att-1"))!)
  ) as EncryptedPayload;
  expect(() =>
    decrypt(rep, derivePurposeKey(fortress.master, "l4-reputation"))
  ).toThrow();
  const repPlain = decrypt(rep, derivePurposeKey(newMaster, "l4-reputation"));
  expect(JSON.parse(bytesToString(repPlain)).attestation).toBe("fixture");

  const knownSigner = JSON.parse(
    bytesToString((await storage.read("_known_signers", "signer-1"))!)
  ) as EncryptedPayload;
  expect(() =>
    decrypt(knownSigner, derivePurposeKey(fortress.master, "l4-known-signers"))
  ).toThrow();
  const knownSignerPlain = decrypt(
    knownSigner,
    derivePurposeKey(newMaster, "l4-known-signers")
  );
  expect(JSON.parse(bytesToString(knownSignerPlain)).known_signer).toBe(
    "fixture"
  );

  const finding = JSON.parse(
    bytesToString((await storage.read("_sentinel_findings", "finding-1"))!)
  ) as EncryptedPayload;
  const findingPlain = decrypt(
    finding,
    derivePurposeKey(newMaster, "l2-sentinel-finding-v1"),
    stringToBytes("finding-1")
  );
  expect(JSON.parse(bytesToString(findingPlain)).severity).toBe("low");

  // Identities: outer + inner re-keyed; private key seed unchanged.
  const idKeyNew = derivePurposeKey(newMaster, "identity-encryption");
  const idRaw = JSON.parse(
    bytesToString((await storage.read("_identities", KID))!)
  ) as EncryptedPayload;
  const identity = JSON.parse(
    bytesToString(decrypt(idRaw, idKeyNew))
  ) as StoredIdentity;
  const seed = decrypt(identity.encrypted_private_key, idKeyNew);
  expect(toBase64url(ed25519.getPublicKey(seed))).toBe(identity.public_key);
}

describe("master rotation — happy path", () => {
  it("rotates the master end to end: new wraps, re-encrypted data, retired old master, audit chain verifiable across the boundary", async () => {
    const fortress = await buildFortress();
    let disclosedKey = "";
    const result = await rotateMaster(
      rotateOpts(fortress, {
        captureRecoveryKey: async (rk, verify) => {
          disclosedKey = rk;
          return verify(rk);
        },
      })
    );
    expect(result.converted_entries).toBeGreaterThan(0);
    expect(result.old_wrap_ids.length).toBeGreaterThan(0);
    await verifyRotated(fortress, { newRecoveryKey: disclosedKey });
  });

  it("rotates the master after identity rotation, preserving entries signed by old and current identity keys", async () => {
    const fortress = await buildFortress();
    const updatedIdentity = await rotateResidentIdentity(fortress);
    const { identityKey } = await readResidentIdentity(fortress);

    const stateStore = new StateStore(fortress.storage, fortress.master);
    await stateStore.write(
      "notes",
      "after-identity-rotate",
      "written after identity rotation",
      KID,
      updatedIdentity.encrypted_private_key,
      identityKey
    );

    await rotateMaster(rotateOpts(fortress));
    const est = await establishMaster({
      storage: fortress.storage,
      passphrase: PASSPHRASE,
    });
    const rotatedStore = new StateStore(fortress.storage, est.masterKey);

    const before = await rotatedStore.read("notes", "k1");
    const after = await rotatedStore.read("notes", "after-identity-rotate");
    expect(before?.value).toBe("hello sovereign world");
    expect(before?.signature_verified).toBe(true);
    expect(after?.value).toBe("written after identity rotation");
    expect(after?.signature_verified).toBe(true);
  });

  it("restamps the durable SDW owner pin under the new master", async () => {
    const fortress = await buildFortress();
    await writeSdwOwnerPin(fortress.storage, fortress.master, {
      version: 1,
      fortress_id: FORTRESS_ID,
      owner_ref: "fleet-self",
      agent_id: "claude_code:fortress-rotation-test",
      pinned_at: "2026-09-01T00:00:00.000Z",
    });
    await rotateMaster(rotateOpts(fortress));
    const established = await establishMaster({
      storage: fortress.storage,
      passphrase: PASSPHRASE,
    });
    expect((await readSdwOwnerPin(fortress.storage, fortress.master)).status).toBe(
      "invalid",
    );
    const pin = await readSdwOwnerPin(fortress.storage, established.masterKey);
    expect(pin.status).toBe("valid");
    if (pin.status === "valid") {
      expect(pin.data.agent_id).toBe("claude_code:fortress-rotation-test");
    }
  });

  it("re-encrypts the castle pin file in place", async () => {
    const fortress = await buildFortress();
    const dir = await mkdtemp(join(tmpdir(), "sanctuary-rotate-pin-"));
    try {
      const seed = generateRandomKey();
      await writeFile(
        join(dir, "castle-pinned-privkey.enc"),
        JSON.stringify(encrypt(seed, fortress.master))
      );
      const pinPath = join(dir, "castle-pinned-privkey.enc");
      await rotateMaster(rotateOpts(fortress, {
        fortressPath: dir,
        __testFortressFiles: {
          read: async () => new Uint8Array(await readFile(pinPath)),
          write: async (_name, data) => writeFile(pinPath, data, { mode: 0o600 }),
          delete: async () => false,
          restoreFreshLockScaffold: async () => undefined,
          cleanupFreshInitRecoveryResidue: async () => false,
        },
      }));
      const est = await establishMaster({
        storage: fortress.storage,
        passphrase: PASSPHRASE,
      });
      const pin = JSON.parse(
        await readFile(join(dir, "castle-pinned-privkey.enc"), "utf-8")
      ) as EncryptedPayload;
      expect(() => decrypt(pin, fortress.master)).toThrow();
      expect(toBase64url(decrypt(pin, est.masterKey))).toBe(toBase64url(seed));
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });

  it("a second rotation keeps BOTH prior audit epochs readable", async () => {
    const fortress = await buildFortress();
    await rotateMaster(rotateOpts(fortress));
    // Append an entry in epoch 1, then rotate again.
    const est1 = await establishMaster({
      storage: fortress.storage,
      passphrase: PASSPHRASE,
    });
    const audit1 = new AuditLog(fortress.storage, est1.masterKey);
    await audit1.appendCritical({
      layer: "l1",
      operation: "epoch1_op",
      identity_id: KID,
      result: "success",
    });
    await audit1.flush();

    await rotateMaster(rotateOpts(fortress));
    const est2 = await establishMaster({
      storage: fortress.storage,
      passphrase: PASSPHRASE,
    });
    const audit2 = new AuditLog(fortress.storage, est2.masterKey);
    const result = await audit2.query({ limit: 100 });
    expect(result.integrity_findings).toEqual([]);
    const ops = result.entries.map((e) => e.operation);
    expect(ops).toContain("fixture_op_0"); // epoch 0
    expect(ops).toContain("epoch1_op"); // epoch 1
    expect(ops.filter((o) => o === "custody_master_rotated")).toHaveLength(2);
  });
});

describe("master rotation — Tier-1 gate and capture rules", () => {
  it("refuses without operator approval, mutating nothing", async () => {
    const fortress = await buildFortress();
    await expect(
      rotateMaster(rotateOpts(fortress, { approve: async () => false }))
    ).rejects.toThrow(RotationPreflightError);
    // Fortress untouched: old credentials still unlock; no rotation artifacts.
    const est = await establishMaster({
      storage: fortress.storage,
      passphrase: PASSPHRASE,
    });
    expect(toBase64url(est.masterKey)).toBe(toBase64url(fortress.master));
    expect(
      await fortress.storage.read("_meta", STAGED_CUSTODY_ENVELOPE_KEY)
    ).toBeNull();
  });

  it("refuses when recovery-key capture is not completed, removing the staged envelope", async () => {
    const fortress = await buildFortress();
    await expect(
      rotateMaster(
        rotateOpts(fortress, { captureRecoveryKey: async () => false })
      )
    ).rejects.toThrow(RotationPreflightError);
    expect(
      await fortress.storage.read("_meta", STAGED_CUSTODY_ENVELOPE_KEY)
    ).toBeNull();
    expect(await fortress.storage.read("_meta", ROTATION_JOURNAL_KEY)).toBeNull();
    const est = await establishMaster({
      storage: fortress.storage,
      passphrase: PASSPHRASE,
    });
    expect(toBase64url(est.masterKey)).toBe(toBase64url(fortress.master));
  });

  it("re-entry verification is real: a wrong key does not verify the wrap", async () => {
    const fortress = await buildFortress();
    await expect(
      rotateMaster(
        rotateOpts(fortress, {
          captureRecoveryKey: async (_rk, verify) => {
            // Operator "saved" the wrong string; the unwrap proof fails and
            // capture reports failure → rotation refuses.
            return verify(toBase64url(generateRandomKey()));
          },
        })
      )
    ).rejects.toThrow(RotationPreflightError);
    const est = await establishMaster({
      storage: fortress.storage,
      passphrase: PASSPHRASE,
    });
    expect(toBase64url(est.masterKey)).toBe(toBase64url(fortress.master));
  });

  it("refuses with the wrong passphrase before touching anything", async () => {
    const fortress = await buildFortress();
    await expect(
      rotateMaster(rotateOpts(fortress, { passphrase: "wrong-passphrase" }))
    ).rejects.toThrow(CustodyUnlockError);
  });

  it("N4-ROTATE (coordinator gate, 2026-08-22): refuses while an exit-import journal exists, mutating nothing, then succeeds once it is removed", async () => {
    const fortress = await buildFortress();
    const journalRecord = {
      import_id: "planted-n4-rotate-import",
      identity_id: KID,
      started_at: new Date().toISOString(),
      snapshots: [],
    };
    await fortress.storage.write(
      "_exit_import_journal",
      "planted-n4-rotate-import",
      stringToBytes(JSON.stringify(journalRecord))
    );

    await expect(rotateMaster(rotateOpts(fortress))).rejects.toThrow(
      RotationPreflightError
    );
    // Fortress untouched: old credentials still unlock; no rotation artifacts.
    const est = await establishMaster({
      storage: fortress.storage,
      passphrase: PASSPHRASE,
    });
    expect(toBase64url(est.masterKey)).toBe(toBase64url(fortress.master));
    expect(
      await fortress.storage.read("_meta", STAGED_CUSTODY_ENVELOPE_KEY)
    ).toBeNull();

    await fortress.storage.delete(
      "_exit_import_journal",
      "planted-n4-rotate-import",
      false
    );
    const result = await rotateMaster(rotateOpts(fortress));
    expect(result.converted_entries).toBeGreaterThan(0);
  });

  it("N4-ROTATE (coordinator gate, 2026-08-22): resumeRotation also refuses while an exit-import journal exists", async () => {
    const fortress = await buildFortress();
    // Get an in-progress rotation journal on disk without finishing it, by
    // failing the run at the first conversion failpoint.
    await expect(
      rotateMaster(
        rotateOpts(fortress, {
          failpoint: (p) => {
            if (p === "journal-converting-written") {
              throw new Error("injected mid-conversion fault");
            }
          },
        })
      )
    ).rejects.toThrow(/injected mid-conversion fault/);
    expect(await fortress.storage.read("_meta", ROTATION_JOURNAL_KEY)).not.toBeNull();

    const journalRecord = {
      import_id: "planted-n4-resume-import",
      identity_id: KID,
      started_at: new Date().toISOString(),
      snapshots: [],
    };
    await fortress.storage.write(
      "_exit_import_journal",
      "planted-n4-resume-import",
      stringToBytes(JSON.stringify(journalRecord))
    );

    await expect(
      resumeRotation({
        storage: fortress.storage,
        fortressPath: undefined,
        fortressId: FORTRESS_ID,
        passphrase: PASSPHRASE,
      })
    ).rejects.toThrow(RotationResumeError);

    await fortress.storage.delete(
      "_exit_import_journal",
      "planted-n4-resume-import",
      false
    );
    const result = await resumeRotation({
      storage: fortress.storage,
      fortressPath: undefined,
      fortressId: FORTRESS_ID,
      passphrase: PASSPHRASE,
    });
    // MEDIUM-D (Codex gate, 2026-08-22): exact, not >= 0 (vacuously true) -
    // 9 is buildFortress's own fixed fixture count (identity, castle pin,
    // two state entries, audit epoch bookkeeping, the _known_signers
    // fixture added for HIGH-2 on #1303, etc.); a regression that drops a
    // namespace from the walk silently would still pass a >= 0 assertion.
    expect(result.converted_entries).toBe(9);
  });
});

describe("master rotation — fail-closed coverage", () => {
  it("aborts (nothing mutated) when an unsupported namespace holds data", async () => {
    const fortress = await buildFortress();
    await fortress.storage.write(
      "_privacy_placeholder_vault",
      "scope__record__x",
      stringToBytes("{}")
    );
    await expect(rotateMaster(rotateOpts(fortress))).rejects.toThrow(
      RotationPreflightError
    );
    const est = await establishMaster({
      storage: fortress.storage,
      passphrase: PASSPHRASE,
    });
    expect(toBase64url(est.masterKey)).toBe(toBase64url(fortress.master));
  });

  it("aborts on an unknown _meta key", async () => {
    const fortress = await buildFortress();
    await fortress.storage.write(
      "_meta",
      "mystery-record",
      stringToBytes("{}")
    );
    await expect(rotateMaster(rotateOpts(fortress))).rejects.toThrow(
      RotationPreflightError
    );
  });

  // F2 MED-1/M-1 (adversarial gate 2026-07-14): a fortress that ran the
  // writer-split migration has an `_audit-daemon` namespace. Master rotation
  // must refuse BY NAME (an intentional, greppable, actionable refusal), never
  // silently skip it, and never mutate. Locks in the fail-closed contract the
  // whole F2 design leans on (and prevents a future refactor from turning the
  // refuse into a silent skip). Also asserts the message is the F2-specific one,
  // not the generic "no registered rotation recipe" fallthrough.
  it("aborts BY NAME (nothing mutated) when the F2 _audit-daemon namespace holds data", async () => {
    const fortress = await buildFortress();
    await fortress.storage.write(
      "_audit-daemon",
      "entry-00000000000000000001-1-0",
      stringToBytes("{}")
    );
    let caught: unknown;
    try {
      await rotateMaster(rotateOpts(fortress));
    } catch (err) {
      caught = err;
    }
    expect(caught).toBeInstanceOf(RotationPreflightError);
    expect((caught as Error).message).toMatch(/_audit-daemon|writer-split|Castle Wall daemon/);
    expect((caught as Error).message).not.toMatch(/no registered rotation recipe/);
    // Nothing mutated: the master still establishes from the original passphrase.
    const est = await establishMaster({
      storage: fortress.storage,
      passphrase: PASSPHRASE,
    });
    expect(toBase64url(est.masterKey)).toBe(toBase64url(fortress.master));
  });

  it("aborts BY NAME on the sibling F2 daemon namespaces (_audit-daemon_checkpoints, _audit-daemon_meta)", async () => {
    for (const ns of ["_audit-daemon_checkpoints", "_audit-daemon_meta"]) {
      const fortress = await buildFortress();
      await fortress.storage.write(ns, "some-key", stringToBytes("{}"));
      await expect(rotateMaster(rotateOpts(fortress))).rejects.toThrow(
        RotationPreflightError
      );
    }
  });

  // F2 BLOCKER-R2 (adversarial re-gate 2026-07-14): the durable `_meta`
  // migration-established marker makes the rotation refusal robust even if the
  // `_audit-daemon*` namespaces were deleted (the raw boundary-v1.json file is
  // not a `.enc` entry and is skipped by namespace enumeration). Refuse BY NAME
  // on the `_meta` marker alone, nothing mutated.
  it("aborts BY NAME when only the F2 _meta established marker is present (daemon namespaces deleted)", async () => {
    const fortress = await buildFortress();
    await fortress.storage.write(
      "_meta",
      "audit-store-split-established-v1",
      stringToBytes(JSON.stringify({ __sanctuary_audit_store_split_established_v1: true, mac: "x" }))
    );
    let caught: unknown;
    try {
      await rotateMaster(rotateOpts(fortress));
    } catch (err) {
      caught = err;
    }
    expect(caught).toBeInstanceOf(RotationPreflightError);
    expect((caught as Error).message).toMatch(/writer-split|audit-store-split-established/);
    const est = await establishMaster({
      storage: fortress.storage,
      passphrase: PASSPHRASE,
    });
    expect(toBase64url(est.masterKey)).toBe(toBase64url(fortress.master));
  });

  it("rotates compound-AAD records (anomaly classifier: key state.<a>.<b>, AAD a|b — codex r2)", async () => {
    const fortress = await buildFortress();
    await fortress.storage.write(
      "_anomaly_classifier_state",
      "state.chi8.agent-rotate-1",
      stringToBytes(
        JSON.stringify(
          encrypt(
            stringToBytes(JSON.stringify({ weights: [1, 2, 3] })),
            derivePurposeKey(fortress.master, "l2-anomaly-classifier-state-v1"),
            stringToBytes("chi8|agent-rotate-1")
          )
        )
      )
    );
    await rotateMaster(rotateOpts(fortress));
    const est = await establishMaster({
      storage: fortress.storage,
      passphrase: PASSPHRASE,
    });
    const raw = JSON.parse(
      bytesToString(
        (await fortress.storage.read(
          "_anomaly_classifier_state",
          "state.chi8.agent-rotate-1"
        ))!
      )
    ) as EncryptedPayload;
    const plain = decrypt(
      raw,
      derivePurposeKey(est.masterKey, "l2-anomaly-classifier-state-v1"),
      stringToBytes("chi8|agent-rotate-1")
    );
    expect(JSON.parse(bytesToString(plain)).weights).toEqual([1, 2, 3]);
  });

  it("rotates the federation trust-root record (_federation/trust-root-v1, purpose-encrypted, no AAD) — re-wraps under the new master, no orphan/lockout", async () => {
    // Regression guard for the master-rotation recipe flip (_federation:
    // unsupported -> purpose-encrypted, infos ["federation-trust-root"]).
    // Without it, rotation would abort or orphan the persisted trust root,
    // locking the operator out of federation. A wrong/changed HKDF info or a
    // stray AAD would fail this decrypt under the new master.
    const fortress = await buildFortress();
    const payload = {
      fortress_id: "fed-rotate-1",
      marker: "trust-root-survives-rotation",
    };
    await fortress.storage.write(
      FEDERATION_TRUST_ROOT_NAMESPACE,
      FEDERATION_TRUST_ROOT_KEY,
      stringToBytes(
        JSON.stringify(
          encrypt(
            stringToBytes(JSON.stringify(payload)),
            derivePurposeKey(fortress.master, FEDERATION_TRUST_ROOT_HKDF_INFO)
          )
        )
      )
    );
    await rotateMaster(rotateOpts(fortress));
    const est = await establishMaster({
      storage: fortress.storage,
      passphrase: PASSPHRASE,
    });
    const raw = JSON.parse(
      bytesToString(
        (await fortress.storage.read(
          FEDERATION_TRUST_ROOT_NAMESPACE,
          FEDERATION_TRUST_ROOT_KEY
        ))!
      )
    ) as EncryptedPayload;
    const plain = decrypt(
      raw,
      derivePurposeKey(est.masterKey, FEDERATION_TRUST_ROOT_HKDF_INFO)
    );
    expect(JSON.parse(bytesToString(plain))).toEqual(payload);
  });

  it("PQC Slice 3 merge-bar 6: a HYBRID federation trust root (ML-DSA secret in the same blob) survives custody rotation (re-wraps whole, both keys intact, no new label)", async () => {
    // The hybrid ML-DSA-65 secret rides INSIDE the _federation/trust-root-v1 blob
    // (no new HKDF label, no new store). The existing _federation recipe encrypts
    // the NAMESPACE blob, not per-field, so a custody rotation re-wraps the whole
    // record including the 4032-byte ML-DSA secret. This proves the secret loads
    // back intact under the NEW master after a real rotation (no orphan/lockout).
    const fortress = await buildFortress();
    const minted = await provisionOrLoadFederationTrustRoot({
      storage: fortress.storage,
      masterKey: fortress.master,
      mint: true,
      nodeId: "home-mac",
      issuanceSuite: FEDERATION_ISSUANCE_SUITE_HYBRID,
    });
    expect(minted?.record.hybrid).toBeDefined();
    const beforeSecret = [
      ...minted!.record.hybrid!.master_private_keys.ml_dsa_65.secret_key,
    ];

    await rotateMaster(rotateOpts(fortress));

    // Re-open under the rotated custody master and LOAD the record through the
    // real primitive (validateRecord re-derives the ML-DSA public from the secret
    // and re-runs the cert-chain coherence checks, so a stranded/garbled secret
    // would throw here).
    const est = await establishMaster({
      storage: fortress.storage,
      passphrase: PASSPHRASE,
    });
    const reloaded = await provisionOrLoadFederationTrustRoot({
      storage: fortress.storage,
      masterKey: est.masterKey,
    });
    expect(reloaded?.source).toBe("persisted");
    expect(reloaded!.record.hybrid).toBeDefined();
    expect([
      ...reloaded!.record.hybrid!.master_private_keys.ml_dsa_65.secret_key,
    ]).toEqual(beforeSecret);
    expect(
      reloaded!.record.hybrid!.master_private_keys.ml_dsa_65.secret_key.length,
    ).toBe(4032);
  });

  it("rotates the federation JOINER trust-root record (_federation/joiner-trust-root-v1, anti-strand) — re-wraps under the new master, no orphan/lockout", async () => {
    // Federation Slice 3a anti-strand guard: the _federation recipe's infos
    // GREW to include "federation-joiner-trust-root". Without it, a custody
    // rotation would orphan the persisted joiner record, locking the joiner
    // out of federation. A wrong/changed HKDF info or a stray AAD would fail
    // this decrypt under the new master.
    const fortress = await buildFortress();
    const payload = {
      fortress_id: "fed-joiner-rotate-1",
      marker: "joiner-trust-root-survives-rotation",
    };
    await fortress.storage.write(
      FEDERATION_JOINER_TRUST_ROOT_NAMESPACE,
      FEDERATION_JOINER_TRUST_ROOT_KEY,
      stringToBytes(
        JSON.stringify(
          encrypt(
            stringToBytes(JSON.stringify(payload)),
            derivePurposeKey(
              fortress.master,
              FEDERATION_JOINER_TRUST_ROOT_HKDF_INFO
            )
          )
        )
      )
    );
    await rotateMaster(rotateOpts(fortress));
    const est = await establishMaster({
      storage: fortress.storage,
      passphrase: PASSPHRASE,
    });
    const raw = JSON.parse(
      bytesToString(
        (await fortress.storage.read(
          FEDERATION_JOINER_TRUST_ROOT_NAMESPACE,
          FEDERATION_JOINER_TRUST_ROOT_KEY
        ))!
      )
    ) as EncryptedPayload;
    const plain = decrypt(
      raw,
      derivePurposeKey(est.masterKey, FEDERATION_JOINER_TRUST_ROOT_HKDF_INFO)
    );
    expect(JSON.parse(bytesToString(plain))).toEqual(payload);
  });

  it("rotates BOTH _federation keys in one pass (issuer + joiner) without orphaning either", async () => {
    // The _federation namespace can in principle hold both keys; the
    // purpose-encrypted convert walker tries each info per blob. This proves
    // the grown infos list decrypts both under the new master in a single
    // rotation (the recipe-growth round-trip).
    const fortress = await buildFortress();
    const issuerPayload = { marker: "issuer-key" };
    const joinerPayload = { marker: "joiner-key" };
    await fortress.storage.write(
      FEDERATION_TRUST_ROOT_NAMESPACE,
      FEDERATION_TRUST_ROOT_KEY,
      stringToBytes(
        JSON.stringify(
          encrypt(
            stringToBytes(JSON.stringify(issuerPayload)),
            derivePurposeKey(fortress.master, FEDERATION_TRUST_ROOT_HKDF_INFO)
          )
        )
      )
    );
    await fortress.storage.write(
      FEDERATION_JOINER_TRUST_ROOT_NAMESPACE,
      FEDERATION_JOINER_TRUST_ROOT_KEY,
      stringToBytes(
        JSON.stringify(
          encrypt(
            stringToBytes(JSON.stringify(joinerPayload)),
            derivePurposeKey(
              fortress.master,
              FEDERATION_JOINER_TRUST_ROOT_HKDF_INFO
            )
          )
        )
      )
    );
    await rotateMaster(rotateOpts(fortress));
    const est = await establishMaster({
      storage: fortress.storage,
      passphrase: PASSPHRASE,
    });
    const issuerRaw = JSON.parse(
      bytesToString(
        (await fortress.storage.read(
          FEDERATION_TRUST_ROOT_NAMESPACE,
          FEDERATION_TRUST_ROOT_KEY
        ))!
      )
    ) as EncryptedPayload;
    const joinerRaw = JSON.parse(
      bytesToString(
        (await fortress.storage.read(
          FEDERATION_JOINER_TRUST_ROOT_NAMESPACE,
          FEDERATION_JOINER_TRUST_ROOT_KEY
        ))!
      )
    ) as EncryptedPayload;
    expect(
      JSON.parse(
        bytesToString(
          decrypt(
            issuerRaw,
            derivePurposeKey(est.masterKey, FEDERATION_TRUST_ROOT_HKDF_INFO)
          )
        )
      )
    ).toEqual(issuerPayload);
    expect(
      JSON.parse(
        bytesToString(
          decrypt(
            joinerRaw,
            derivePurposeKey(
              est.masterKey,
              FEDERATION_JOINER_TRUST_ROOT_HKDF_INFO
            )
          )
        )
      )
    ).toEqual(joinerPayload);
  });

  it("rotates ALL SEVEN _federation records (trust-root, joiner, spent-nonce set, provision-claim set, sync-state, operator-cloud joined-node, reissue challenge set) without strand", async () => {
    // Anti-strand for the durable single-use replay stores, the Federation 3/3b
    // P0 durable sync-state store, AND the Operator Cloud Slice 3 joined-node
    // store: each persists a blob into _federation under a NEW HKDF label.
    // Without those labels in the _federation recipe's infos, convertPurposeNamespace
    // throws RotationPreflightError and rotateMaster is DENIED on any fortress that
    // ever consumed a federation nonce/claim, persisted sync-state, OR joined as an
    // operator_cloud node, OR accepted a node-cert reissue challenge. This proves
    // the grown infos list re-wraps all seven.
    //
    // The store labels MUST equal the recipe strings; assert that explicitly so a
    // typo in either place is caught here, not only at a real operator's rotation.
    expect(BOOTSTRAP_NONCE_STORE_HKDF_INFO).toBe("federation-bootstrap-nonce-spent-set");
    expect(OPERATOR_CLOUD_CLAIM_STORE_HKDF_INFO).toBe(
      "federation-operator-cloud-provision-claim-set"
    );
    expect(FEDERATION_SYNC_STATE_STORE_HKDF_INFO).toBe("federation-sync-state");
    expect(OPERATOR_CLOUD_JOINED_NODE_HKDF_INFO).toBe("operator-cloud-joined-node");
    expect(FEDERATION_REISSUE_CHALLENGE_STORE_HKDF_INFO).toBe(
      "federation-reissue-node-cert-challenge-set"
    );
    expect(BOOTSTRAP_NONCE_STORE_NAMESPACE).toBe(FEDERATION_TRUST_ROOT_NAMESPACE);
    expect(OPERATOR_CLOUD_CLAIM_STORE_NAMESPACE).toBe(FEDERATION_TRUST_ROOT_NAMESPACE);
    expect(FEDERATION_SYNC_STATE_STORE_NAMESPACE).toBe(FEDERATION_TRUST_ROOT_NAMESPACE);
    expect(OPERATOR_CLOUD_JOINED_NODE_NAMESPACE).toBe(FEDERATION_TRUST_ROOT_NAMESPACE);
    expect(FEDERATION_REISSUE_CHALLENGE_STORE_NAMESPACE).toBe(
      FEDERATION_TRUST_ROOT_NAMESPACE
    );

    const fortress = await buildFortress();
    const records: Array<{ key: string; info: string; payload: unknown }> = [
      {
        key: FEDERATION_TRUST_ROOT_KEY,
        info: FEDERATION_TRUST_ROOT_HKDF_INFO,
        payload: { marker: "trust-root" },
      },
      {
        key: FEDERATION_JOINER_TRUST_ROOT_KEY,
        info: FEDERATION_JOINER_TRUST_ROOT_HKDF_INFO,
        payload: { marker: "joiner" },
      },
      {
        key: BOOTSTRAP_NONCE_STORE_KEY,
        info: BOOTSTRAP_NONCE_STORE_HKDF_INFO,
        payload: { v: 1, entries: [{ key: "f n nonce", expires_at_ms: Date.now() + 60_000 }] },
      },
      {
        key: OPERATOR_CLOUD_CLAIM_STORE_KEY,
        info: OPERATOR_CLOUD_CLAIM_STORE_HKDF_INFO,
        payload: { v: 1, entries: [{ key: "f n nonce", claim: { consumed: true } }] },
      },
      {
        key: FEDERATION_SYNC_STATE_STORE_KEY,
        info: FEDERATION_SYNC_STATE_STORE_HKDF_INFO,
        payload: {
          v: 1,
          accepted_high_water: [["linux-1", 7]],
          outbound_high_water: 3,
          revoked_node_ids: ["evil-node"],
          highest_eviction_serial: 2,
        },
      },
      {
        key: OPERATOR_CLOUD_JOINED_NODE_KEY,
        info: OPERATOR_CLOUD_JOINED_NODE_HKDF_INFO,
        payload: { record_version: "operator-cloud-joined-node-v1", marker: "oc-joined-node" },
      },
      {
        key: FEDERATION_REISSUE_CHALLENGE_STORE_KEY,
        info: FEDERATION_REISSUE_CHALLENGE_STORE_HKDF_INFO,
        payload: {
          v: 1,
          entries: [
            {
              key: "fortress node-1 reissue-node-cert challenge-1",
              expires_at_ms: Date.now() + 60_000,
            },
          ],
        },
      },
    ];
    // All seven live in the same _federation namespace (no-AAD, purpose-keyed).
    for (const r of records) {
      await fortress.storage.write(
        FEDERATION_TRUST_ROOT_NAMESPACE,
        r.key,
        stringToBytes(
          JSON.stringify(
            encrypt(
              stringToBytes(JSON.stringify(r.payload)),
              derivePurposeKey(fortress.master, r.info)
            )
          )
        )
      );
    }

    // Without the two new infos this throws RotationPreflightError (strand).
    await rotateMaster(rotateOpts(fortress));
    const est = await establishMaster({
      storage: fortress.storage,
      passphrase: PASSPHRASE,
    });

    // Every one decrypts + reads back under the NEW master.
    for (const r of records) {
      const raw = JSON.parse(
        bytesToString(
          (await fortress.storage.read(FEDERATION_TRUST_ROOT_NAMESPACE, r.key))!
        )
      ) as EncryptedPayload;
      const plain = decrypt(raw, derivePurposeKey(est.masterKey, r.info));
      expect(JSON.parse(bytesToString(plain))).toEqual(r.payload);
    }
  });

  // T7 (Finding #7): a fortress that ever enabled a guardian requirement carries
  // BOTH new `_meta` keys - the established sentinel (a pre-existing latent break:
  // it was unclassified, so a guarded fortress could NOT rotate) AND the new
  // anti-rollback anchor. Both must be classified so rotation SUCCEEDS, and both
  // must re-authenticate under the NEW master afterward (re-derived / restamped),
  // with the monotonic anchor floors preserved.
  it("Finding #7: master rotation composes with BOTH guardian _meta keys (established sentinel + antirollback anchor)", async () => {
    const fortress = await buildFortress();

    // Write both `_meta` markers MAC'd under the OLD master, exactly as the store
    // does (use the store itself so the bytes are byte-for-byte what production
    // writes).
    const store = new FederationSyncStateStore({
      storage: fortress.storage,
      masterKey: fortress.master,
    });
    await store.markGuardianRequirementEstablished();
    await store.writeGuardianAntiRollbackAnchor({
      loweredHighWater: 4,
      disableNonce: 6,
      requirementGeneration: 9,
    });
    // Sanity: both authenticate under the OLD master pre-rotation.
    expect((await store.guardianRequirementEstablished()).status).toBe("established");
    expect((await store.readGuardianAntiRollbackAnchor()).status).toBe("valid");

    // Without the two new classifications, convertMeta hits `default -> null ->
    // throw` and rotation is DENIED. It must now SUCCEED.
    await rotateMaster(rotateOpts(fortress));
    const est = await establishMaster({
      storage: fortress.storage,
      passphrase: PASSPHRASE,
    });

    // Both `_meta` keys are still present (not deleted by rotation).
    expect(
      await fortress.storage.read("_meta", FEDERATION_GUARDIAN_REQUIREMENT_ESTABLISHED_KEY),
    ).not.toBeNull();
    expect(
      await fortress.storage.read("_meta", FEDERATION_GUARDIAN_ANTIROLLBACK_ANCHOR_KEY),
    ).not.toBeNull();

    // Both re-authenticate under the NEW master (re-derived / restamped), with the
    // monotonic anchor floors preserved.
    const newStore = new FederationSyncStateStore({
      storage: fortress.storage,
      masterKey: est.masterKey,
    });
    expect((await newStore.guardianRequirementEstablished()).status).toBe("established");
    const anchor = await newStore.readGuardianAntiRollbackAnchor();
    expect(anchor.status).toBe("valid");
    if (anchor.status !== "valid") throw new Error("unreachable");
    expect(anchor.data.lowered_high_water).toBe(4);
    expect(anchor.data.disable_nonce).toBe(6);
    expect(anchor.data.requirement_generation).toBe(9);

    // Neither authenticates under the OLD master any more (they were re-keyed).
    expect((await store.guardianRequirementEstablished()).status).toBe("invalid");
    expect((await store.readGuardianAntiRollbackAnchor()).status).toBe("invalid");
  });

  it("aborts BY NAME on unified-inbox operator-prefs records (hash-keyed AAD — codex r2)", async () => {
    const fortress = await buildFortress();
    await fortress.storage.write(
      "_unified_inbox",
      "operator-prefs.v1.abcdef0123456789",
      stringToBytes("{}")
    );
    await expect(rotateMaster(rotateOpts(fortress))).rejects.toThrow(
      /operator-prefs/
    );
    const est = await establishMaster({
      storage: fortress.storage,
      passphrase: PASSPHRASE,
    });
    expect(toBase64url(est.masterKey)).toBe(toBase64url(fortress.master));
  });

  it("aborts on an unknown _audit_checkpoints key (codex r1 HIGH: no silent skip in an internal namespace)", async () => {
    const fortress = await buildFortress();
    await fortress.storage.write(
      "_audit_checkpoints",
      "mystery-anchor",
      stringToBytes("{}")
    );
    await expect(rotateMaster(rotateOpts(fortress))).rejects.toThrow(
      RotationPreflightError
    );
    const est = await establishMaster({
      storage: fortress.storage,
      passphrase: PASSPHRASE,
    });
    expect(toBase64url(est.masterKey)).toBe(toBase64url(fortress.master));
  });

  it("aborts BEFORE staging when the audit chain is tampered (codex r1 MEDIUM: no disclosure over a broken chain)", async () => {
    const fortress = await buildFortress();
    // Tamper one persisted audit entry's bytes.
    const entries = await fortress.storage.list("_audit");
    const target = entries[0]!;
    const raw = await fortress.storage.read("_audit", target.key);
    const record = JSON.parse(bytesToString(raw!)) as { entry_hash: string };
    record.entry_hash = record.entry_hash.replace(/^./, (c) =>
      c === "a" ? "b" : "a"
    );
    await fortress.storage.write(
      "_audit",
      target.key,
      stringToBytes(JSON.stringify(record))
    );

    let captureCalled = false;
    await expect(
      rotateMaster(
        rotateOpts(fortress, {
          captureRecoveryKey: async (rk, verify) => {
            captureCalled = true;
            return verify(rk);
          },
        })
      )
    ).rejects.toThrow(RotationPreflightError);
    // The recovery key was never disclosed and nothing was staged.
    expect(captureCalled).toBe(false);
    expect(
      await fortress.storage.read("_meta", STAGED_CUSTODY_ENVELOPE_KEY)
    ).toBeNull();
  });

  it("aborts when a state entry's writer identity is not resident (no laundering, no orphaning)", async () => {
    const fortress = await buildFortress();
    await fortress.storage.delete("_identities", KID);
    await expect(rotateMaster(rotateOpts(fortress))).rejects.toThrow(
      RotationPreflightError
    );
  });

  it("aborts when a state entry verifies under no authenticated key in the writer chain", async () => {
    const fortress = await buildFortress();
    await rotateResidentIdentity(fortress);

    const raw = await fortress.storage.read("notes", "k1");
    const entry = JSON.parse(bytesToString(raw!)) as StateEntry;
    const rogueSeed = generateRandomKey();
    entry.sig = toBase64url(
      ed25519.sign(fromBase64url(entry.payload.ct), rogueSeed)
    );
    await fortress.storage.write(
      "notes",
      "k1",
      stringToBytes(JSON.stringify(entry))
    );

    let captureCalled = false;
    await expect(
      rotateMaster(
        rotateOpts(fortress, {
          captureRecoveryKey: async (rk, verify) => {
            captureCalled = true;
            return verify(rk);
          },
        })
      )
    ).rejects.toThrow(RotationPreflightError);
    expect(captureCalled).toBe(false);
    const est = await establishMaster({
      storage: fortress.storage,
      passphrase: PASSPHRASE,
    });
    expect(toBase64url(est.masterKey)).toBe(toBase64url(fortress.master));
  });
});

describe("master rotation — crash safety (journaled two-phase, forward resume)", () => {
  const POST_JOURNAL_FAILPOINTS = [
    "journal-converting-written",
    `converted:_identities/${KID}`,
    "converted:notes/k1",
    "audit-epoch-written",
    "recovery-key-escrow-committed",
    "journal-finalizing-written",
    "envelope-promoted",
    "rotation-audited",
  ];

  it("scrubs old, new, and recovery-key buffers after an injected rotate failure", async () => {
    const fortress = await buildFortress();
    const observed = new Map<string, Uint8Array[]>();
    await expect(rotateMaster(rotateOpts(fortress, {
      __testObserveSecretBuffer: (label, buffer) => {
        const buffers = observed.get(label) ?? [];
        buffers.push(buffer);
        observed.set(label, buffers);
      },
      failpoint: (point) => {
        if (point === "staged-envelope-written") {
          throw new Error("injected rotate failure");
        }
      },
    }))).rejects.toThrow("injected rotate failure");

    expect([...observed.keys()]).toEqual(expect.arrayContaining([
      "old-master",
      "new-master",
      "recovery-key",
    ]));
    for (const buffers of observed.values()) {
      for (const buffer of buffers) {
        expect([...buffer].every((byte) => byte === 0)).toBe(true);
      }
    }
  });

  it("scrubs both decoded masters after an injected resume failure", async () => {
    const fortress = await buildFortress();
    await expect(rotateMaster(rotateOpts(fortress, {
      failpoint: (point) => {
        if (point === "journal-converting-written") {
          throw new Error("prepare interrupted resume fixture");
        }
      },
    }))).rejects.toThrow("prepare interrupted resume fixture");

    const observed = new Map<string, Uint8Array[]>();
    await expect(resumeRotation({
      storage: fortress.storage,
      fortressId: FORTRESS_ID,
      passphrase: PASSPHRASE,
      __testObserveSecretBuffer: (label, buffer) => {
        const buffers = observed.get(label) ?? [];
        buffers.push(buffer);
        observed.set(label, buffers);
      },
      failpoint: (point) => {
        if (point === `converted:_identities/${KID}`) {
          throw new Error("injected resume failure");
        }
      },
    })).rejects.toThrow("injected resume failure");

    expect([...observed.keys()]).toEqual(expect.arrayContaining([
      "old-master",
      "new-master",
    ]));
    for (const buffers of observed.values()) {
      for (const buffer of buffers) {
        expect([...buffer].every((byte) => byte === 0)).toBe(true);
      }
    }
  });

  it("promotes transactional recovery escrow only with a durable journal and then closes its handle", async () => {
    const fortress = await buildFortress();
    const events: string[] = [];
    await rotateMaster(rotateOpts(fortress, {
      captureRecoveryKey: async (rk, verify) => {
        expect(await verify(rk)).toBe(true);
        return {
          captured: true,
          commit: async () => {
            expect(await fortress.storage.read("_meta", ROTATION_JOURNAL_KEY))
              .not.toBeNull();
            events.push("commit");
          },
          rollback: async () => { events.push("rollback"); },
        };
      },
    }));
    expect(events).toEqual(["commit"]);
  });

  it("preserves staged recovery escrow when conversion fails after the journal point of no return", async () => {
    const fortress = await buildFortress();
    const events: string[] = [];
    await expect(rotateMaster(rotateOpts(fortress, {
      captureRecoveryKey: async (rk, verify) => {
        expect(await verify(rk)).toBe(true);
        return {
          captured: true,
          commit: async () => { events.push("commit"); },
          rollback: async () => { events.push("rollback"); },
        };
      },
      failpoint: (point) => {
        if (point === "journal-converting-written") {
          throw new Error("injected pre-escrow-commit failure");
        }
      },
    }))).rejects.toThrow("injected pre-escrow-commit failure");
    expect(events).toEqual([]);
  });

  it("preserves both pre-journal failure and recovery-escrow rollback failure", async () => {
    const fortress = await buildFortress();
    const error = await rotateMaster(rotateOpts(fortress, {
      captureRecoveryKey: async (rk, verify) => {
        // Deliberately do not verify the recovery wrap. The custody floor then
        // refuses before the journal is written, where rollback is still safe.
        expect(rk).toBeTruthy();
        expect(verify).toBeTypeOf("function");
        return {
          captured: true,
          commit: async () => undefined,
          rollback: async () => { throw new Error("escrow rollback failed"); },
        };
      },
    })).catch((cause) => cause as unknown);
    expect(error).toBeInstanceOf(AggregateError);
    expect((error as AggregateError).errors.map(String)).toEqual([
      expect.stringContaining("fewer than 2 verified factors"),
      "Error: escrow rollback failed",
    ]);
  });

  it("journals keyring escrow authority and re-adopts it after a hard crash", async () => {
    const fortress = await buildFortress();
    let disclosedKey = "";
    let rollbackCalls = 0;
    let promoted = false;
    let authority: {
      kind: "os-keyring";
      canonical_service: string;
      staging_service: string;
    } | undefined;

    await expect(rotateMaster(rotateOpts(fortress, {
      captureRecoveryKey: async (rk, verify, rotationId, registerPendingAuthority) => {
        disclosedKey = rk;
        expect(await verify(rk)).toBe(true);
        authority = {
          kind: "os-keyring",
          canonical_service: "sanctuary-recovery-test",
          staging_service: `sanctuary-recovery-test:rotation:${rotationId}`,
        };
        await registerPendingAuthority(authority);
        return {
          captured: true,
          authority,
          commit: async () => { promoted = true; },
          rollback: async () => { rollbackCalls++; },
        };
      },
      failpoint: (point) => {
        if (point === "journal-converting-written") {
          throw new Error("simulated hard crash after journal");
        }
      },
    }))).rejects.toThrow("simulated hard crash after journal");
    expect(rollbackCalls).toBe(0);

    await resumeRotation({
      storage: fortress.storage,
      fortressId: FORTRESS_ID,
      passphrase: PASSPHRASE,
      adoptRecoveryEscrow: async (observed, verify, rotationId) => {
        expect(observed).toEqual(authority);
        expect(rotationId).toBeTruthy();
        expect(await verify(disclosedKey)).toBe(true);
        expect(await verify(toBase64url(new Uint8Array(32).fill(0xee)))).toBe(false);
        return { commit: async () => { promoted = true; } };
      },
    });

    expect(promoted).toBe(true);
    await verifyRotated(fortress, { newRecoveryKey: disclosedKey });
  });

  for (const point of POST_JOURNAL_FAILPOINTS) {
    it(`crash at "${point}": boot refuses, resume completes, fortress fully rotated`, async () => {
      const fortress = await buildFortress();
      let disclosedKey = "";
      await expect(
        rotateMaster(
          rotateOpts(fortress, {
            captureRecoveryKey: async (rk, verify) => {
              disclosedKey = rk;
              return verify(rk);
            },
            failpoint: (p) => {
              if (p === point) throw new Error(`simulated crash at ${p}`);
            },
          })
        )
      ).rejects.toThrow(/simulated crash/);

      // The lockout-killer property: with the journal present, NO normal
      // establishment path may serve a half-keyed fortress.
      await expect(
        establishMaster({ storage: fortress.storage, passphrase: PASSPHRASE })
      ).rejects.toThrow(CustodyRotationInProgressError);

      // Forward resume with just the passphrase.
      const result = await resumeRotation({
        storage: fortress.storage,
        fortressId: FORTRESS_ID,
        passphrase: PASSPHRASE,
      });
      expect(result.rotation_id).toBeTruthy();
      await verifyRotated(fortress, { newRecoveryKey: disclosedKey });
    });
  }

  it("an ordinary exception before the journal transactionally removes staged recovery state", async () => {
    const fortress = await buildFortress();
    await expect(
      rotateMaster(
        rotateOpts(fortress, {
          failpoint: (p) => {
            if (p === "staged-envelope-written") {
              throw new Error("simulated crash at staging");
            }
          },
        })
      )
    ).rejects.toThrow(/simulated crash/);

    // No journal → normal boot works and yields the OLD master. An ordinary
    // exception runs rollback; hard-crash residue is covered separately by
    // the process-death tests.
    const est = await establishMaster({
      storage: fortress.storage,
      passphrase: PASSPHRASE,
    });
    expect(toBase64url(est.masterKey)).toBe(toBase64url(fortress.master));
    expect(
      await fortress.storage.read("_meta", STAGED_CUSTODY_ENVELOPE_KEY)
    ).toBeNull();

    // A fresh rotation cleans the orphan and completes.
    let disclosedKey = "";
    await rotateMaster(
      rotateOpts(fortress, {
        captureRecoveryKey: async (rk, verify) => {
          disclosedKey = rk;
          return verify(rk);
        },
      })
    );
    await verifyRotated(fortress, { newRecoveryKey: disclosedKey });
  });

  it("resume is idempotent: a crash DURING resume resumes again cleanly", async () => {
    const fortress = await buildFortress();
    await expect(
      rotateMaster(
        rotateOpts(fortress, {
          failpoint: (p) => {
            if (p === "converted:notes/k1") throw new Error("crash 1");
          },
        })
      )
    ).rejects.toThrow(/crash 1/);

    // First resume crashes later, mid-finalize.
    await expect(
      resumeRotation({
        storage: fortress.storage,
        fortressId: FORTRESS_ID,
        passphrase: PASSPHRASE,
        failpoint: (p) => {
          if (p === "envelope-promoted") throw new Error("crash 2");
        },
      })
    ).rejects.toThrow(/crash 2/);

    await expect(
      establishMaster({ storage: fortress.storage, passphrase: PASSPHRASE })
    ).rejects.toThrow(CustodyRotationInProgressError);

    await resumeRotation({
      storage: fortress.storage,
      fortressId: FORTRESS_ID,
      passphrase: PASSPHRASE,
    });
    await verifyRotated(fortress);
  });

  it("resume fails closed on a wrong passphrase", async () => {
    const fortress = await buildFortress();
    await expect(
      rotateMaster(
        rotateOpts(fortress, {
          failpoint: (p) => {
            if (p === "converted:notes/k1") throw new Error("crash");
          },
        })
      )
    ).rejects.toThrow(/crash/);
    await expect(
      resumeRotation({
        storage: fortress.storage,
        fortressId: FORTRESS_ID,
        passphrase: "not-the-passphrase",
      })
    ).rejects.toThrow(CustodyUnlockError);
    // Still journaled; still refuses to boot; still resumable with the truth.
    await expect(
      establishMaster({ storage: fortress.storage, passphrase: PASSPHRASE })
    ).rejects.toThrow(CustodyRotationInProgressError);
    await resumeRotation({
      storage: fortress.storage,
      fortressId: FORTRESS_ID,
      passphrase: PASSPHRASE,
    });
    await verifyRotated(fortress);
  });

  it("resume fails closed on a tampered journal", async () => {
    const fortress = await buildFortress();
    await expect(
      rotateMaster(
        rotateOpts(fortress, {
          failpoint: (p) => {
            if (p === "converted:notes/k1") throw new Error("crash");
          },
        })
      )
    ).rejects.toThrow(/crash/);

    const raw = await fortress.storage.read("_meta", ROTATION_JOURNAL_KEY);
    const journal = JSON.parse(bytesToString(raw!)) as {
      data: { phase: string };
      mac: string;
    };
    journal.data.phase = "finalizing"; // attacker tries to skip conversion
    await fortress.storage.write(
      "_meta",
      ROTATION_JOURNAL_KEY,
      stringToBytes(JSON.stringify(journal))
    );

    await expect(
      resumeRotation({
        storage: fortress.storage,
        fortressId: FORTRESS_ID,
        passphrase: PASSPHRASE,
      })
    ).rejects.toThrow(RotationResumeError);
  });

  it("a second rotation refuses while a journal exists", async () => {
    const fortress = await buildFortress();
    await expect(
      rotateMaster(
        rotateOpts(fortress, {
          failpoint: (p) => {
            if (p === "converted:notes/k1") throw new Error("crash");
          },
        })
      )
    ).rejects.toThrow(/crash/);
    await expect(rotateMaster(rotateOpts(fortress))).rejects.toThrow(
      RotationPreflightError
    );
  });

  it("resume with no journal refuses", async () => {
    const fortress = await buildFortress();
    await expect(
      resumeRotation({
        storage: fortress.storage,
        fortressId: FORTRESS_ID,
        passphrase: PASSPHRASE,
      })
    ).rejects.toThrow(RotationResumeError);
  });
});

describe("master rotation — custody floor on the rotated fortress", () => {
  it("the rotated envelope holds >= 2 verified distinct factors", async () => {
    const fortress = await buildFortress();
    await rotateMaster(rotateOpts(fortress));
    const envelope = await readCustodyEnvelope(fortress.storage);
    expect(countVerifiedWraps(envelope!)).toBeGreaterThanOrEqual(2);
    const types = envelope!.wraps.map((w) => w.type).sort();
    expect(types).toContain("passphrase");
    expect(types).toContain("recovery-key");
  });

  it("re-creates the keychain wrap when the custody key is supplied", async () => {
    const fortress = await buildFortress();
    const custodyKey = generateRandomKey();
    await rotateMaster(rotateOpts(fortress, { keychainKey: custodyKey }));
    const envelope = await readCustodyEnvelope(fortress.storage);
    expect(envelope!.wraps.some((w) => w.type === "keychain")).toBe(true);
    // And it unwraps the SAME new master.
    const viaKeychain = await establishMaster({
      storage: fortress.storage,
      keychainKey: custodyKey,
    });
    const viaPassphrase = await establishMaster({
      storage: fortress.storage,
      passphrase: PASSPHRASE,
    });
    expect(toBase64url(viaKeychain.masterKey)).toBe(
      toBase64url(viaPassphrase.masterKey)
    );
  });
});

describe("master rotation — anti-rollback epoch advance (Stage 1)", () => {
  it("a fresh fortress is epoch 0 with no witness yet", async () => {
    const fortress = await buildFortress();
    expect(await readEnvelopeEpoch(fortress.storage)).toBe(0);
    const witness = await readEpochWitness(fortress.storage, fortress.master);
    expect(witness.status).toBe("absent");
  });

  it("a single rotation advances the on-disk epoch and witness to 1", async () => {
    const fortress = await buildFortress();
    await rotateMaster(rotateOpts(fortress));

    const newEnvelope = await readCustodyEnvelope(fortress.storage);
    expect(envelopeEpochOf(newEnvelope)).toBe(1);

    const est = await establishMaster({
      storage: fortress.storage,
      passphrase: PASSPHRASE,
    });
    const witness = await readEpochWitness(fortress.storage, est.masterKey);
    expect(witness.status).toBe("valid");
    if (witness.status === "valid") {
      expect(witness.data.epoch).toBe(1);
      expect(witness.data.epoch_id).toBe(newEnvelope!.epoch_id);
    }
  });

  it("two rotations advance the epoch to 2 and the rotation count agrees", async () => {
    const fortress = await buildFortress();
    await rotateMaster(rotateOpts(fortress));
    await rotateMaster(rotateOpts(fortress));

    expect(await readEnvelopeEpoch(fortress.storage)).toBe(2);

    const est = await establishMaster({
      storage: fortress.storage,
      passphrase: PASSPHRASE,
    });
    const epochKeys = deriveAuditEpochKeys(est.masterKey);
    const count = await readCustodyEpochCount(fortress.storage, {
      epochMacKey: epochKeys.epochMacKey,
    });
    epochKeys.epochWrapKey.fill(0);
    epochKeys.epochMacKey.fill(0);
    expect(count.status).toBe("present");
    if (count.status === "present") expect(count.count).toBe(2);
  });

  it("a legitimate rotation does NOT trip the boot detector (the #501 interaction)", async () => {
    const fortress = await buildFortress();
    await rotateMaster(rotateOpts(fortress));

    const est = await establishMaster({
      storage: fortress.storage,
      passphrase: PASSPHRASE,
    });
    // Re-run the exact boot cross-check the server runs: observe the witnesses,
    // compare against the on-disk envelope epoch. The rotation advanced BOTH the
    // envelope epoch and the witness in lockstep, so the verdict is OK.
    const epochKeys = deriveAuditEpochKeys(est.masterKey);
    const epochRecord = await readCustodyEpochCount(fortress.storage, {
      epochMacKey: epochKeys.epochMacKey,
    });
    epochKeys.epochWrapKey.fill(0);
    epochKeys.epochMacKey.fill(0);
    const rotationEpochCount =
      epochRecord.status === "present" ? epochRecord.count : 0;
    const observation = await observeWitnessEpoch({
      storage: fortress.storage,
      master: est.masterKey,
      rotationEpochCount,
      rotationEpochTampered: epochRecord.status === "tampered",
    });
    const envelopeEpoch = await readEnvelopeEpoch(fortress.storage);
    const verdict = evaluateRollback({ envelopeEpoch, observation });
    expect(verdict.kind).toBe("ok");
  });

  it("DETECTS a custody-only splice that resurrects the retired credential even with both epoch witnesses deleted (codex r1 HIGH)", async () => {
    const fortress = await buildFortress();
    const { storage } = fortress;

    // Capture the PRE-rotation custody artifacts (old master). These are what an
    // attacker with disk write would restore to swap the old (leaked) master
    // back in after the operator rotated it away.
    const oldEnvelope = await storage.read("_meta", CUSTODY_ENVELOPE_KEY);
    const oldSentinel = await storage.read("_meta", CUSTODY_SENTINEL_KEY);
    expect(oldEnvelope).not.toBeNull();

    // Operator rotates (the remedy for the leak): new master, epoch advances,
    // the audit head anchor is restamped under the NEW master.
    await rotateMaster(rotateOpts(fortress));
    const newMaster = (
      await establishMaster({ storage, passphrase: PASSPHRASE })
    ).masterKey;

    // ── The attack: restore ONLY the old custody files (swap the master back),
    // and DELETE both epoch witnesses (the cheapest move to avoid the obvious
    // epoch mismatch). State + audit stay current.
    await storage.write("_meta", CUSTODY_ENVELOPE_KEY, oldEnvelope!);
    if (oldSentinel) await storage.write("_meta", CUSTODY_SENTINEL_KEY, oldSentinel);
    await storage.delete("_meta", EPOCH_WITNESS_META_KEY);
    await storage.delete("_audit_checkpoints", AUDIT_EPOCH_KEYS_KEY);

    // Boot now establishes the OLD (retired) master from the restored envelope.
    const spliced = await establishMaster({ storage, passphrase: PASSPHRASE });
    expect(toBase64url(spliced.masterKey)).toBe(toBase64url(fortress.master));
    expect(toBase64url(spliced.masterKey)).not.toBe(toBase64url(newMaster));

    // The boot cross-check, run under the spliced-in OLD master: the epoch
    // record + witness are gone (deleted), so a naive epoch comparison reads
    // epoch 0 / floor 0 = OK. But the audit head anchor — restamped under the
    // NEW master during rotation — does NOT authenticate under the old master,
    // exposing the splice.
    const headProbe = await probeAuditHeadAnchor(storage, spliced.masterKey);
    expect(headProbe.status).toBe("tampered");

    const epochKeys = deriveAuditEpochKeys(spliced.masterKey);
    const epochRecord = await readCustodyEpochCount(storage, {
      epochMacKey: epochKeys.epochMacKey,
    });
    epochKeys.epochWrapKey.fill(0);
    epochKeys.epochMacKey.fill(0);
    const observation = await observeWitnessEpoch({
      storage,
      master: spliced.masterKey,
      rotationEpochCount: epochRecord.status === "present" ? epochRecord.count : 0,
      rotationEpochTampered: epochRecord.status === "tampered",
      headAnchor: { status: headProbe.status },
    });
    expect(observation.suspect).toBe(true);

    const verdict = evaluateRollback({
      envelopeEpoch: await readEnvelopeEpoch(storage),
      observation,
    });
    expect(verdict.kind).toBe("rollback-suspected");
  });

  it("head-anchor probe treats a DELETED head anchor as tampered when it was once established (codex r2)", async () => {
    const fortress = await buildFortress();
    const { storage } = fortress;
    // buildFortress writes an audit chain → a head anchor + established marker.
    const probeBefore = await probeAuditHeadAnchor(storage, fortress.master);
    expect(probeBefore.status).toBe("valid");

    // Attacker deletes the head anchor to dodge the splice check, but the
    // plaintext `audit-head-anchor-established-v1` marker remains → tampered.
    await storage.delete("_audit_checkpoints", "__head_anchor");
    const probeAfter = await probeAuditHeadAnchor(storage, fortress.master);
    expect(probeAfter.status).toBe("tampered");
  });

  it("head-anchor probe stays tampered even after deleting the established MARKER, while audit entries survive (codex r3 HIGH)", async () => {
    const fortress = await buildFortress();
    const { storage } = fortress;
    // Attacker deletes BOTH the head anchor and its plaintext established marker
    // to erase the detector's memory — but the audit chain itself survives (the
    // splice attacker keeps the current audit). The audit entries are the second
    // independent "was established" signal, so the probe stays tampered.
    await storage.delete("_audit_checkpoints", "__head_anchor");
    await storage.delete("_meta", "audit-head-anchor-established-v1");
    expect((await storage.list("_audit")).length).toBeGreaterThan(0);
    const probe = await probeAuditHeadAnchor(storage, fortress.master);
    expect(probe.status).toBe("tampered");
  });

  it("head-anchor probe is absent (neutral) on a genuinely never-audited fortress", async () => {
    const storage = new MemoryStorage();
    const est = await establishMaster({
      storage,
      passphrase: PASSPHRASE,
      firstRun: { installMode: "interactive", mintRecoveryKey: false },
    });
    // No audit chain written → no head anchor, no established marker.
    const probe = await probeAuditHeadAnchor(storage, est.masterKey);
    expect(probe.status).toBe("absent");
  });
});
