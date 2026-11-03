// fail-before-exempt: deterministic replacement for a probabilistic ciphertext-absence check; behavior unchanged
import { expect } from "vitest";
import { fromBase64url, toBase64url } from "../../src/core/encoding.js";
import {
  verifySignedAttestation,
  type SignedAttestation,
} from "../../src/entitlement/compliance-attestation.js";

/** Inspect public metadata while authenticating opaque key/signature bytes against the issuer. */
export function assertAttestationPrivacy(serialized: string, publicKey: Uint8Array): void {
  const doc = JSON.parse(serialized) as SignedAttestation;
  expect(Object.keys(doc).sort()).toEqual(["attestation", "public_key", "signature"]);
  const { signature, public_key, ...metadata } = doc;
  // Only the two cryptographic fields are exempt from textual secret-field checks.
  expect(JSON.stringify({ fields: Object.keys(doc), metadata })).not.toMatch(/private/i);
  expect(public_key).toBe(toBase64url(publicKey));
  expect(verifySignedAttestation(doc, { pinnedOperatorKey: publicKey })).toMatchObject({ ok: true });
  const tampered = fromBase64url(signature);
  tampered[0] = tampered[0]! ^ 1; // Change one signed byte without changing its encoding shape.
  expect(verifySignedAttestation(
    { ...doc, signature: toBase64url(tampered) },
    { pinnedOperatorKey: publicKey },
  )).toMatchObject({ ok: false, reason: "signature_invalid" });
}
