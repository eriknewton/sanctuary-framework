import { describe, expect, it } from "vitest";
import { ml_dsa65 } from "@noble/post-quantum/ml-dsa.js";
import {
  CryptoSuiteRegistry,
  ED25519_SIGNATURE_SUITE_ID,
  HYBRID_SIGNATURE_SUITE_ID,
  ML_DSA_65_COMPONENT_ALG,
  SIGNATURE_BUNDLE_VERSION,
  SIGNED_SURFACE_DOMAIN,
  canonicalSignedSurface,
  createEd25519IdentitySuiteSigner,
  createEd25519SuitePublicKeys,
  createHybridSuitePublicKeys,
  signedSurfaceBytes,
  type SignedSurfaceDescriptor,
  type SignatureBundle,
} from "../../../src/core/crypto-suite-registry.js";
import { encrypt } from "../../../src/core/encryption.js";
import { fromBase64url } from "../../../src/core/encoding.js";
import {
  generateKeypair,
  verify as verifyIdentitySignature,
} from "../../../src/core/identity.js";
import { generateRandomKey } from "../../../src/core/random.js";

function makeDescriptor(): SignedSurfaceDescriptor {
  return {
    surface_id: "test.crypto-agility.surface",
    surface_version: "sanctuary.test-surface.v1",
    signature_suite: ED25519_SIGNATURE_SUITE_ID,
    payload: {
      issuer: "issuer-1",
      message: "crypto-agility infrastructure signs descriptor-bound surfaces.",
      seq: 1,
    },
  };
}

function makeRig() {
  const keypair = generateKeypair();
  const encryptionKey = generateRandomKey();
  const encryptedPrivateKey = encrypt(keypair.privateKey, encryptionKey);
  const signer = createEd25519IdentitySuiteSigner({
    key_ref: "issuer.ed25519",
    encryptedPrivateKey,
    encryptionKey,
  });
  const publicKeys = createEd25519SuitePublicKeys({
    key_ref: "issuer.ed25519",
    publicKey: keypair.publicKey,
  });
  return { keypair, signer, publicKeys };
}

function makeHybridDescriptor(): SignedSurfaceDescriptor {
  return {
    ...makeDescriptor(),
    signature_suite: HYBRID_SIGNATURE_SUITE_ID,
  };
}

function makeHybridRig() {
  const ed25519Keypair = generateKeypair();
  const mlDsa65Keypair = ml_dsa65.keygen();
  const encryptionKey = generateRandomKey();
  const encryptedPrivateKey = encrypt(ed25519Keypair.privateKey, encryptionKey);
  const ed25519Signer = createEd25519IdentitySuiteSigner({
    key_ref: "issuer.ed25519",
    encryptedPrivateKey,
    encryptionKey,
  });
  const signer = {
    ...ed25519Signer,
    ml_dsa_65: {
      key_ref: "issuer.ml-dsa-65",
      sign: (bytes: Uint8Array) =>
        ml_dsa65.sign(bytes, mlDsa65Keypair.secretKey, {
          extraEntropy: false,
        }),
    },
  };
  const publicKeys = createHybridSuitePublicKeys({
    ed25519KeyRef: "issuer.ed25519",
    ed25519PublicKey: ed25519Keypair.publicKey,
    mlDsa65KeyRef: "issuer.ml-dsa-65",
    mlDsa65PublicKey: mlDsa65Keypair.publicKey,
  });
  return { signer, publicKeys };
}

describe("CryptoSuiteRegistry", () => {
  it("is seeded with Ed25519 and the Slice 2 hybrid suite", () => {
    const registry = new CryptoSuiteRegistry();

    expect(registry.listSuites()).toEqual([
      {
        id: ED25519_SIGNATURE_SUITE_ID,
        components: [ED25519_SIGNATURE_SUITE_ID],
        maxSignatureBytes: 64,
        maxPublicKeyBytes: 32,
      },
      {
        id: HYBRID_SIGNATURE_SUITE_ID,
        components: [ED25519_SIGNATURE_SUITE_ID, ML_DSA_65_COMPONENT_ALG],
        maxSignatureBytes: 3373,
        maxPublicKeyBytes: 1984,
      },
    ]);
  });

  it("signs and verifies a descriptor-bound surface with the existing Ed25519 identity path", async () => {
    const registry = new CryptoSuiteRegistry();
    const descriptor = makeDescriptor();
    const { keypair, signer, publicKeys } = makeRig();

    const bundle = await registry.signSurface(descriptor, signer);

    expect(bundle).toMatchObject({
      bundle_version: SIGNATURE_BUNDLE_VERSION,
      signature_suite: ED25519_SIGNATURE_SUITE_ID,
      components: [
        {
          alg: ED25519_SIGNATURE_SUITE_ID,
          key_ref: "issuer.ed25519",
        },
      ],
    });
    expect(bundle.components[0]!.sig).toEqual(expect.any(String));
    await expect(
      registry.verifySurface(descriptor, bundle, publicKeys)
    ).resolves.toBe(true);

    const signature = fromBase64url(bundle.components[0]!.sig);
    expect(
      verifyIdentitySignature(
        signedSurfaceBytes(descriptor),
        signature,
        keypair.publicKey
      )
    ).toBe(true);
  });

  it("binds surface version and signature suite into the signed bytes", () => {
    const canonical = canonicalSignedSurface(makeDescriptor());

    expect(canonical).toBe(
      `{"domain":"${SIGNED_SURFACE_DOMAIN}","payload":{"issuer":"issuer-1","message":"crypto-agility infrastructure signs descriptor-bound surfaces.","seq":1},"signature_suite":"ed25519-v1","surface_id":"test.crypto-agility.surface","surface_version":"sanctuary.test-surface.v1"}`
    );
  });

  it("rejects surface_version substitution", async () => {
    const registry = new CryptoSuiteRegistry();
    const descriptor = makeDescriptor();
    const { signer, publicKeys } = makeRig();
    const bundle = await registry.signSurface(descriptor, signer);

    await expect(
      registry.verifySurface(
        { ...descriptor, surface_version: "sanctuary.test-surface.v2" },
        bundle,
        publicKeys
      )
    ).resolves.toBe(false);
  });

  it("rejects signature_suite substitution on the descriptor or bundle", async () => {
    const registry = new CryptoSuiteRegistry();
    const descriptor = makeDescriptor();
    const { signer, publicKeys } = makeRig();
    const bundle = await registry.signSurface(descriptor, signer);

    await expect(
      registry.verifySurface(
        { ...descriptor, signature_suite: "ed25519-v2" },
        bundle,
        publicKeys
      )
    ).resolves.toBe(false);
    await expect(
      registry.verifySurface(
        descriptor,
        { ...bundle, signature_suite: "ed25519-v2" },
        publicKeys
      )
    ).resolves.toBe(false);
  });

  it("rejects stripped, extra, reordered, or relabeled components", async () => {
    const registry = new CryptoSuiteRegistry();
    const descriptor = makeDescriptor();
    const { signer, publicKeys } = makeRig();
    const bundle = await registry.signSurface(descriptor, signer);
    const component = bundle.components[0]!;

    const stripped: SignatureBundle = { ...bundle, components: [] };
    const extra: SignatureBundle = {
      ...bundle,
      components: [component, component],
    };
    const relabeled: SignatureBundle = {
      ...bundle,
      components: [{ ...component, alg: "ed25519+ml-dsa-v1" }],
    };
    const swappedKeyRef: SignatureBundle = {
      ...bundle,
      components: [{ ...component, key_ref: "attacker.ed25519" }],
    };

    await expect(
      registry.verifySurface(descriptor, stripped, publicKeys)
    ).resolves.toBe(false);
    await expect(
      registry.verifySurface(descriptor, extra, publicKeys)
    ).resolves.toBe(false);
    await expect(
      registry.verifySurface(descriptor, relabeled, publicKeys)
    ).resolves.toBe(false);
    await expect(
      registry.verifySurface(descriptor, swappedKeyRef, publicKeys)
    ).resolves.toBe(false);
  });

  it("fails closed for unknown suites", async () => {
    const registry = new CryptoSuiteRegistry();
    const { signer, publicKeys } = makeRig();
    const descriptor = {
      ...makeDescriptor(),
      signature_suite: "ed25519-v2",
    };

    await expect(registry.signSurface(descriptor, signer)).rejects.toThrow(
      /unknown signature_suite 'ed25519-v2'/
    );
    await expect(
      registry.verifySurface(
        descriptor,
        {
          bundle_version: SIGNATURE_BUNDLE_VERSION,
          signature_suite: "ed25519-v2",
          components: [],
        },
        publicKeys
      )
    ).resolves.toBe(false);
  });

  it("signs and verifies a descriptor-bound hybrid surface", async () => {
    const registry = new CryptoSuiteRegistry();
    const descriptor = makeHybridDescriptor();
    const { signer, publicKeys } = makeHybridRig();

    const bundle = await registry.signSurface(descriptor, signer);

    expect(bundle).toMatchObject({
      bundle_version: SIGNATURE_BUNDLE_VERSION,
      signature_suite: HYBRID_SIGNATURE_SUITE_ID,
      components: [
        {
          alg: ED25519_SIGNATURE_SUITE_ID,
          key_ref: "issuer.ed25519",
        },
        {
          alg: ML_DSA_65_COMPONENT_ALG,
          key_ref: "issuer.ml-dsa-65",
        },
      ],
    });
    await expect(
      registry.verifySurface(descriptor, bundle, publicKeys)
    ).resolves.toBe(true);
  });

  it("rejects hybrid component stripping, reordering, key-ref swaps, and oversized signatures", async () => {
    const registry = new CryptoSuiteRegistry();
    const descriptor = makeHybridDescriptor();
    const { signer, publicKeys } = makeHybridRig();
    const bundle = await registry.signSurface(descriptor, signer);
    const [ed25519Component, mlDsa65Component] = bundle.components;

    const stripped: SignatureBundle = {
      ...bundle,
      components: [ed25519Component!],
    };
    const reordered: SignatureBundle = {
      ...bundle,
      components: [mlDsa65Component!, ed25519Component!],
    };
    const swappedKeyRef: SignatureBundle = {
      ...bundle,
      components: [
        ed25519Component!,
        { ...mlDsa65Component!, key_ref: "attacker.ml-dsa-65" },
      ],
    };
    const oversized: SignatureBundle = {
      ...bundle,
      components: [
        ed25519Component!,
        { ...mlDsa65Component!, sig: "A".repeat(4413) },
      ],
    };

    await expect(
      registry.verifySurface(descriptor, stripped, publicKeys)
    ).resolves.toBe(false);
    await expect(
      registry.verifySurface(descriptor, reordered, publicKeys)
    ).resolves.toBe(false);
    await expect(
      registry.verifySurface(descriptor, swappedKeyRef, publicKeys)
    ).resolves.toBe(false);
    await expect(
      registry.verifySurface(descriptor, oversized, publicKeys)
    ).resolves.toBe(false);
  });

  it("rejects a valid Ed25519 half paired with a wrong-key ML-DSA-65 signature (hybrid is AND, not OR)", async () => {
    // Isolates the post-quantum half of the hybrid AND at the crypto layer: a
    // well-formed ML-DSA-65 signature (correct alg, key_ref, and byte length)
    // from a DIFFERENT ML-DSA key must NOT verify, even when the classical
    // Ed25519 half is genuinely valid. This passes the structural policy gate
    // (so it cannot be deflected by the stripping/reorder checks) and can only
    // be rejected by the real ml_dsa65.verify call.
    const registry = new CryptoSuiteRegistry();
    const descriptor = makeHybridDescriptor();
    const rig1 = makeHybridRig();
    const rig2 = makeHybridRig();
    const bundle1 = await registry.signSurface(descriptor, rig1.signer);
    const bundle2 = await registry.signSurface(descriptor, rig2.signer);

    const wrongMlDsaHalf: SignatureBundle = {
      ...bundle1,
      components: [bundle1.components[0]!, bundle2.components[1]!],
    };

    await expect(
      registry.verifySurface(descriptor, wrongMlDsaHalf, rig1.publicKeys)
    ).resolves.toBe(false);
  });
});
