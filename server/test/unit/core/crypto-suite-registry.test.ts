import { describe, expect, it } from "vitest";
import {
  CryptoSuiteRegistry,
  ED25519_SIGNATURE_SUITE_ID,
  SIGNATURE_BUNDLE_VERSION,
  SIGNED_SURFACE_DOMAIN,
  canonicalSignedSurface,
  createEd25519IdentitySuiteSigner,
  createEd25519SuitePublicKeys,
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
      message: "crypto-agility infrastructure exists; no hybrid/PQC algorithm is enabled yet.",
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

describe("CryptoSuiteRegistry slice 1", () => {
  it("is seeded with exactly the ed25519-v1 suite", () => {
    const registry = new CryptoSuiteRegistry();

    expect(registry.listSuites()).toEqual([
      {
        id: ED25519_SIGNATURE_SUITE_ID,
        components: [ED25519_SIGNATURE_SUITE_ID],
        maxSignatureBytes: 64,
        maxPublicKeyBytes: 32,
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
      `{"domain":"${SIGNED_SURFACE_DOMAIN}","payload":{"issuer":"issuer-1","message":"crypto-agility infrastructure exists; no hybrid/PQC algorithm is enabled yet.","seq":1},"signature_suite":"ed25519-v1","surface_id":"test.crypto-agility.surface","surface_version":"sanctuary.test-surface.v1"}`
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
      signature_suite: "ed25519+ml-dsa-v1",
    };

    await expect(registry.signSurface(descriptor, signer)).rejects.toThrow(
      /unknown signature_suite 'ed25519\+ml-dsa-v1'/
    );
    await expect(
      registry.verifySurface(
        descriptor,
        {
          bundle_version: SIGNATURE_BUNDLE_VERSION,
          signature_suite: "ed25519+ml-dsa-v1",
          components: [],
        },
        publicKeys
      )
    ).resolves.toBe(false);
  });
});
