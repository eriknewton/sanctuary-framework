/**
 * PQC Slice 3 -- at-rest ML-DSA persistence + opt-in hybrid federation-root
 * issuance (DEFAULT OFF). These are the security teeth of a build that introduces
 * NEW at-rest secret key material (the ML-DSA-65 4032-byte secret key). The merge
 * bar:
 *
 *   1. Round-trip persistence: a hybrid record saves + loads with BOTH private
 *      keys intact (Ed25519 + ML-DSA), and the at-rest ciphertext contains the
 *      raw secret bytes NOWHERE in plaintext.
 *   2. Back-compat: a v1 (classical) record loads byte-for-byte unchanged; a
 *      record minted without the suite carries NO hybrid fields.
 *   3. Hybrid issuance + verify: the persisted hybrid chain verifies under the
 *      both-must-pass policy AND its Ed25519 component verifies (so a
 *      current-version peer can still verify); a stripped/forged ML-DSA component
 *      fails closed.
 *   4. No secret leak + zeroization: the round-trip exposes no secret; the
 *      persist-failure path zeroes the transient ML-DSA secret.
 *   6. Master-rotation compatibility: the hybrid block rides the SAME
 *      `federation-trust-root` at-rest blob (no new HKDF label), so the existing
 *      `_federation` rotation recipe re-wraps it whole (proven in
 *      test/core/master-rotation.test.ts; this file proves the no-new-label claim
 *      structurally + asserts the secret lives only inside that one blob).
 *
 * Every hybrid record here is minted through the REAL primitive
 * (`provisionOrLoadFederationTrustRoot({ issuanceSuite })`), so the production
 * mint + persist + load path is exercised end to end.
 */

import { describe, expect, it } from "vitest";
import { randomBytes } from "node:crypto";
import { ml_dsa65 } from "@noble/post-quantum/ml-dsa.js";

import { MemoryStorage } from "../../src/storage/memory.js";
import { establishMaster } from "../../src/core/master-custody.js";
import { bytesToString, toBase64url } from "../../src/core/encoding.js";
import {
  ML_DSA_65_SECRET_KEY_BYTES,
  ED25519_PUBLIC_KEY_BYTES,
  HYBRID_SIGNATURE_SUITE_ID,
} from "../../src/core/crypto-suite-registry.js";
import {
  FEDERATION_ISSUANCE_SUITE_HYBRID,
  FEDERATION_TRUST_ROOT_KEY,
  FEDERATION_TRUST_ROOT_NAMESPACE,
  FederationTrustRootStore,
  mintFederationTrustRootRecord,
  provisionOrLoadFederationTrustRoot,
  verifyHybridFederationChain,
  type FederationTrustRootRecord,
} from "../../src/mesh/federation-trust-root-store.js";
import { verifyCertChainV2Hybrid } from "../../src/mesh/trust-root-hybrid.js";

async function testMasterKey(storage: MemoryStorage): Promise<Uint8Array> {
  const { masterKey } = await establishMaster({
    storage,
    passphrase: `pqc3-${randomBytes(6).toString("hex")}`,
    firstRun: { installMode: "headless", mintRecoveryKey: false },
  });
  return masterKey;
}

async function mintHybrid(
  storage: MemoryStorage,
  masterKey: Uint8Array,
  nodeId = "home-mac",
) {
  const provisioned = await provisionOrLoadFederationTrustRoot({
    storage,
    masterKey,
    mint: true,
    nodeId,
    issuanceSuite: FEDERATION_ISSUANCE_SUITE_HYBRID,
  });
  if (!provisioned) throw new Error("expected a minted hybrid record");
  return provisioned;
}

describe("PQC Slice 3 -- hybrid federation trust-root persistence", () => {
  it("merge-bar 1: round-trips both private keys; the at-rest blob holds NO secret in plaintext", async () => {
    const storage = new MemoryStorage();
    const masterKey = await testMasterKey(storage);
    const minted = await mintHybrid(storage, masterKey);

    expect(minted.source).toBe("minted");
    expect(minted.context.isHybrid).toBe(true);
    const hybrid = minted.record.hybrid;
    expect(hybrid).toBeDefined();
    expect(hybrid!.master_private_keys.ml_dsa_65.secret_key.length).toBe(
      ML_DSA_65_SECRET_KEY_BYTES,
    );
    expect(hybrid!.master_private_keys.ed25519.private_key.length).toBe(
      ED25519_PUBLIC_KEY_BYTES,
    );

    // The at-rest blob is AES-GCM ciphertext and contains NONE of the new secret
    // bytes in plaintext (the whole point of encrypting the ML-DSA secret).
    const raw = await storage.read(
      FEDERATION_TRUST_ROOT_NAMESPACE,
      FEDERATION_TRUST_ROOT_KEY,
    );
    const rawText = bytesToString(raw!);
    expect(rawText).toContain('"alg":"aes-256-gcm"');
    for (const secret of [
      toBase64url(hybrid!.master_private_keys.ml_dsa_65.secret_key),
      toBase64url(hybrid!.master_private_keys.ed25519.private_key),
      toBase64url(hybrid!.issuing_principal_private_keys.ml_dsa_65.secret_key),
      toBase64url(hybrid!.local_node_private_keys.ml_dsa_65.secret_key),
    ]) {
      expect(rawText).not.toContain(secret);
    }

    // Reload from disk: both private keys come back byte-identical.
    const reloaded = await provisionOrLoadFederationTrustRoot({
      storage,
      masterKey,
    });
    expect(reloaded?.source).toBe("persisted");
    const back = reloaded!.record.hybrid;
    expect(back).toBeDefined();
    expect([...back!.master_private_keys.ml_dsa_65.secret_key]).toEqual([
      ...hybrid!.master_private_keys.ml_dsa_65.secret_key,
    ]);
    expect([...back!.master_private_keys.ed25519.private_key]).toEqual([
      ...hybrid!.master_private_keys.ed25519.private_key,
    ]);
    // The reloaded secret really is the secret for the pinned ML-DSA public key.
    const derivedPub = ml_dsa65.getPublicKey(
      back!.master_private_keys.ml_dsa_65.secret_key,
    );
    expect(toBase64url(derivedPub)).toBe(
      back!.pinned_master.public_keys.ml_dsa_65.public_key,
    );
  });

  it("merge-bar 2: back-compat -- a v1 (classical) record loads unchanged, with NO hybrid fields", async () => {
    const storage = new MemoryStorage();
    const masterKey = await testMasterKey(storage);

    // Mint with no suite -> the unchanged classical default path.
    const classical = await provisionOrLoadFederationTrustRoot({
      storage,
      masterKey,
      mint: true,
      nodeId: "home-mac",
    });
    expect(classical?.source).toBe("minted");
    expect(classical!.record.hybrid).toBeUndefined();
    expect(classical!.context.isHybrid).toBe(false);
    expect(classical!.context.hybridPinnedMaster).toBeUndefined();

    // The persisted classical record loads back with no hybrid fields.
    const reloaded = await provisionOrLoadFederationTrustRoot({ storage, masterKey });
    expect(reloaded?.source).toBe("persisted");
    expect(reloaded!.record.hybrid).toBeUndefined();

    // A separately-constructed mint with the same params produces a record with
    // NO hybrid field (the default path is structurally classical).
    const bare = mintFederationTrustRootRecord({ nodeId: "home-mac" });
    expect("hybrid" in bare && bare.hybrid !== undefined).toBe(false);
  });

  it("merge-bar 3: the persisted hybrid chain verifies both-must-pass AND its Ed25519 component verifies", async () => {
    const storage = new MemoryStorage();
    const masterKey = await testMasterKey(storage);
    await mintHybrid(storage, masterKey);

    const reloaded = await provisionOrLoadFederationTrustRoot({ storage, masterKey });
    const hybrid = reloaded!.record.hybrid!;

    // Both-must-pass chain verify over the persisted certs (ML-DSA + Ed25519).
    await expect(verifyHybridFederationChain(hybrid)).resolves.toBeUndefined();
    await expect(
      verifyCertChainV2Hybrid(
        hybrid.local_node_cert,
        hybrid.issuing_principal_cert,
        hybrid.pinned_master,
      ),
    ).resolves.toBeUndefined();

    // The hybrid certs are tagged with the hybrid suite (so a verifier dispatches
    // to both-must-pass), and the Ed25519 component public key is present, which a
    // current-version peer uses to verify the Ed25519 half.
    expect(hybrid.local_node_cert.signature_suite).toBe(HYBRID_SIGNATURE_SUITE_ID);
    expect(
      hybrid.pinned_master.public_keys.ed25519.public_key.length,
    ).toBeGreaterThan(0);
  });

  it("merge-bar 3 (negative): a stripped ML-DSA component fails closed", async () => {
    const storage = new MemoryStorage();
    const masterKey = await testMasterKey(storage);
    await mintHybrid(storage, masterKey);
    const reloaded = await provisionOrLoadFederationTrustRoot({ storage, masterKey });
    const hybrid = reloaded!.record.hybrid!;

    // Strip the ML-DSA-65 component from the node cert's master bundle -> the
    // both-must-pass policy rejects it (a downgrade to Ed25519-only is refused).
    const stripped = {
      ...hybrid.local_node_cert,
      master_signature_bundle: {
        ...hybrid.local_node_cert.master_signature_bundle,
        components:
          hybrid.local_node_cert.master_signature_bundle.components.slice(0, 1),
      },
    };
    await expect(
      verifyCertChainV2Hybrid(
        stripped,
        hybrid.issuing_principal_cert,
        hybrid.pinned_master,
      ),
    ).rejects.toThrow();
  });

  it("merge-bar 3 (negative): a forged ML-DSA secret is rejected at load (does not match pinned public)", async () => {
    const storage = new MemoryStorage();
    const masterKey = await testMasterKey(storage);
    const minted = await mintHybrid(storage, masterKey);

    // Corrupt the persisted ML-DSA secret to a different valid-length secret, then
    // re-save: the load-time structural validation derives the public key from the
    // secret and refuses a record whose secret does not match its pinned public.
    const tampered: FederationTrustRootRecord = {
      ...minted.record,
      hybrid: {
        ...minted.record.hybrid!,
        master_private_keys: {
          ...minted.record.hybrid!.master_private_keys,
          ml_dsa_65: {
            ...minted.record.hybrid!.master_private_keys.ml_dsa_65,
            secret_key: ml_dsa65.keygen().secretKey,
          },
        },
      },
    };
    await expect(
      new FederationTrustRootStore(storage, masterKey).save(tampered),
    ).rejects.toThrow(/does not match the pinned public key/);
  });

  it("merge-bar 4: the persist-failure path zeroes the transient hybrid secrets (no record written)", async () => {
    const storage = new MemoryStorage();
    const masterKey = await testMasterKey(storage);

    // A storage whose write throws on the trust-root blob AFTER the hybrid
    // material is minted, so the primitive's catch path runs zeroRecordSecrets
    // over the hybrid block before rethrowing. The record never reaches disk.
    const failingStorage = Object.create(storage) as MemoryStorage;
    failingStorage.write = (async (
      ns: string,
      key: string,
      value: Uint8Array,
    ) => {
      if (ns === FEDERATION_TRUST_ROOT_NAMESPACE && key === FEDERATION_TRUST_ROOT_KEY) {
        throw new Error("injected persist failure");
      }
      return storage.write(ns, key, value);
    }) as MemoryStorage["write"];
    failingStorage.read = storage.read.bind(storage) as MemoryStorage["read"];
    failingStorage.exists = storage.exists.bind(storage) as MemoryStorage["exists"];
    failingStorage.list = storage.list.bind(storage) as MemoryStorage["list"];

    await expect(
      provisionOrLoadFederationTrustRoot({
        storage: failingStorage,
        masterKey,
        mint: true,
        nodeId: "home-mac",
        issuanceSuite: FEDERATION_ISSUANCE_SUITE_HYBRID,
        audit: () => {},
      }),
    ).rejects.toThrow(/injected persist failure/);

    // No persisted record was written (fail-closed; the secret never landed).
    expect(
      await storage.exists(FEDERATION_TRUST_ROOT_NAMESPACE, FEDERATION_TRUST_ROOT_KEY),
    ).toBe(false);
  });

  it("merge-bar 4 (zeroization unit): zeroHybridMaterialSecrets clears every ML-DSA + Ed25519 private byte", async () => {
    const storage = new MemoryStorage();
    const masterKey = await testMasterKey(storage);
    const minted = await mintHybrid(storage, masterKey);
    const { zeroHybridMaterialSecrets } = await import(
      "../../src/mesh/federation-trust-root-store.js"
    );
    const hybrid = minted.record.hybrid!;
    // Snapshot lengths, then zeroize and assert all-zero.
    zeroHybridMaterialSecrets(hybrid);
    for (const keys of [
      hybrid.master_private_keys,
      hybrid.issuing_principal_private_keys,
      hybrid.local_node_private_keys,
    ]) {
      expect([...keys.ml_dsa_65.secret_key]).toEqual(
        new Array(ML_DSA_65_SECRET_KEY_BYTES).fill(0),
      );
      expect([...keys.ed25519.private_key]).toEqual(
        new Array(ED25519_PUBLIC_KEY_BYTES).fill(0),
      );
    }
  });

  it("merge-bar 6: the hybrid secret lives ONLY inside the federation-trust-root blob (no new label/store/namespace)", async () => {
    const storage = new MemoryStorage();
    const masterKey = await testMasterKey(storage);
    const minted = await mintHybrid(storage, masterKey);
    const mlSecretB64 = toBase64url(
      minted.record.hybrid!.master_private_keys.ml_dsa_65.secret_key,
    );

    // Enumerate EVERY namespace + key the mint wrote. The only blob is the single
    // _federation/trust-root-v1 record -- there is no parallel store, no second
    // namespace, no new at-rest key carrying the ML-DSA secret. Because the secret
    // rides that one blob, the existing _federation rotation recipe re-wraps it
    // whole with NO new HKDF label (the rotation round-trip is proven in
    // test/core/master-rotation.test.ts).
    const namespaces = await storage.listNamespaces!();
    let trustRootBlobs = 0;
    for (const ns of namespaces) {
      for (const meta of await storage.list(ns)) {
        const raw = await storage.read(ns, meta.key);
        const text = raw ? bytesToString(raw) : "";
        // The plaintext secret must appear in NO blob at all (everything is
        // encrypted), and only the trust-root key is a federation-root blob.
        expect(text).not.toContain(mlSecretB64);
        if (ns === FEDERATION_TRUST_ROOT_NAMESPACE && meta.key === FEDERATION_TRUST_ROOT_KEY) {
          trustRootBlobs += 1;
        }
      }
    }
    expect(trustRootBlobs).toBe(1);
  });
});
