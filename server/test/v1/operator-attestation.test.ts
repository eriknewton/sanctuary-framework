/**
 * Federation PR-A3 — durable Ed25519 operator attestation unit tests.
 *
 * The attestation is the credentialed path that REPLACED PR-A1's bearer-token
 * validator. These tests pin its security properties: it verifies only
 * against the configured operator key, binds to a specific client key (no
 * cross-session replay), is domain-separated + injective (no field splice),
 * and is bounded in time. Every malformed input verifies false — never throws.
 */

import { describe, expect, it } from "vitest";
import { ed25519 } from "@noble/curves/ed25519";
import { randomBytes } from "node:crypto";

import {
  buildOperatorAttestationMessage,
  signOperatorAttestation,
  verifyOperatorAttestation,
  V1_OPERATOR_ATTESTATION_MAX_AGE_MS,
} from "../../src/v1/operator-attestation.js";
import { toBase64url } from "../../src/core/encoding.js";

function keypair() {
  const privateKey = randomBytes(32);
  const publicKey = ed25519.getPublicKey(privateKey);
  return { privateKey, publicKey };
}

const NOW = 1_700_000_000_000;

describe("verifyOperatorAttestation", () => {
  it("accepts a fresh attestation bound to the right client key + operator key", () => {
    const op = keypair();
    const client = keypair();
    const att = signOperatorAttestation({
      operatorPublicKey: op.publicKey,
      operatorPrivateKey: op.privateKey,
      clientPubkey: client.publicKey,
      issuedAtMs: NOW,
    });
    expect(
      verifyOperatorAttestation({
        attestation: att,
        clientPubkey: client.publicKey,
        resolvedOperatorPubkey: op.publicKey,
        now: NOW,
      }),
    ).toBe(true);
  });

  it("rejects when the resolved operator key is null (fail closed)", () => {
    const op = keypair();
    const client = keypair();
    const att = signOperatorAttestation({
      operatorPublicKey: op.publicKey,
      operatorPrivateKey: op.privateKey,
      clientPubkey: client.publicKey,
      issuedAtMs: NOW,
    });
    expect(
      verifyOperatorAttestation({
        attestation: att,
        clientPubkey: client.publicKey,
        resolvedOperatorPubkey: null,
        now: NOW,
      }),
    ).toBe(false);
  });

  it("rejects when the operator key in the attestation is not the configured one", () => {
    const op = keypair();
    const other = keypair();
    const client = keypair();
    const att = signOperatorAttestation({
      operatorPublicKey: op.publicKey,
      operatorPrivateKey: op.privateKey,
      clientPubkey: client.publicKey,
      issuedAtMs: NOW,
    });
    // Attestation self-consistent but signed by a key the daemon does not trust.
    expect(
      verifyOperatorAttestation({
        attestation: att,
        clientPubkey: client.publicKey,
        resolvedOperatorPubkey: other.publicKey,
        now: NOW,
      }),
    ).toBe(false);
  });

  it("rejects an attestation bound to a different client key", () => {
    const op = keypair();
    const client = keypair();
    const otherClient = keypair();
    const att = signOperatorAttestation({
      operatorPublicKey: op.publicKey,
      operatorPrivateKey: op.privateKey,
      clientPubkey: client.publicKey,
      issuedAtMs: NOW,
    });
    expect(
      verifyOperatorAttestation({
        attestation: att,
        clientPubkey: otherClient.publicKey,
        resolvedOperatorPubkey: op.publicKey,
        now: NOW,
      }),
    ).toBe(false);
  });

  it("rejects a stale attestation and one too far in the future", () => {
    const op = keypair();
    const client = keypair();
    const mk = (issuedAtMs: number) =>
      signOperatorAttestation({
        operatorPublicKey: op.publicKey,
        operatorPrivateKey: op.privateKey,
        clientPubkey: client.publicKey,
        issuedAtMs,
      });
    const base = {
      clientPubkey: client.publicKey,
      resolvedOperatorPubkey: op.publicKey,
      now: NOW,
    };
    expect(verifyOperatorAttestation({ ...base, attestation: mk(NOW - V1_OPERATOR_ATTESTATION_MAX_AGE_MS - 1000) })).toBe(false);
    expect(verifyOperatorAttestation({ ...base, attestation: mk(NOW + 5 * 60_000) })).toBe(false);
    expect(verifyOperatorAttestation({ ...base, attestation: mk(NOW) })).toBe(true);
  });

  it("rejects a tampered signature and a tampered issued_at", () => {
    const op = keypair();
    const client = keypair();
    const att = signOperatorAttestation({
      operatorPublicKey: op.publicKey,
      operatorPrivateKey: op.privateKey,
      clientPubkey: client.publicKey,
      issuedAtMs: NOW,
    });
    const base = { clientPubkey: client.publicKey, resolvedOperatorPubkey: op.publicKey, now: NOW };
    // Flip the issued_at: the signature no longer covers it.
    expect(verifyOperatorAttestation({ ...base, attestation: { ...att, issued_at: NOW - 1 } })).toBe(false);
    // Garble the signature.
    expect(verifyOperatorAttestation({ ...base, attestation: { ...att, signature: toBase64url(randomBytes(64)) } })).toBe(false);
  });

  it("never throws on malformed inputs — all verify false", () => {
    const op = keypair();
    const client = keypair();
    const base = { clientPubkey: client.publicKey, resolvedOperatorPubkey: op.publicKey, now: NOW };
    const cases: unknown[] = [
      null,
      "string",
      42,
      {},
      { type: "operator_ed25519" },
      { type: "wrong", operator_pubkey: toBase64url(op.publicKey), issued_at: NOW, signature: "x" },
      { type: "operator_ed25519", operator_pubkey: "!!notb64!!", issued_at: NOW, signature: "x" },
      { type: "operator_ed25519", operator_pubkey: toBase64url(randomBytes(16)), issued_at: NOW, signature: toBase64url(randomBytes(64)) },
      { type: "operator_ed25519", operator_pubkey: toBase64url(op.publicKey), issued_at: "not-a-number", signature: toBase64url(randomBytes(64)) },
      { type: "operator_ed25519", operator_pubkey: toBase64url(op.publicKey), issued_at: NOW, signature: toBase64url(randomBytes(10)) },
    ];
    for (const attestation of cases) {
      expect(() => verifyOperatorAttestation({ ...base, attestation })).not.toThrow();
      expect(verifyOperatorAttestation({ ...base, attestation })).toBe(false);
    }
  });

  it("message encoding is injective across (operator, client, issued_at)", () => {
    const a = randomBytes(32);
    const b = randomBytes(32);
    const m1 = toBase64url(buildOperatorAttestationMessage(a, b, NOW));
    const m2 = toBase64url(buildOperatorAttestationMessage(b, a, NOW)); // swapped
    const m3 = toBase64url(buildOperatorAttestationMessage(a, b, NOW + 1)); // different time
    expect(m1).not.toBe(m2);
    expect(m1).not.toBe(m3);
  });
});
