/**
 * Federation PR-A1 — OPERATOR_SIGNED verification helper tests.
 *
 * The helper is built once here and consumed by every Tier 1 endpoint in
 * the later PR-A stack. These tests pin the canonical message encoding
 * (key order independence, domain separation, action binding) and the
 * never-throws denial contract.
 */

import { describe, expect, it } from "vitest";
import { ed25519 } from "@noble/curves/ed25519";
import { randomBytes } from "node:crypto";

import {
  canonicalJson,
  addOperatorAuthorizationFields,
  validateOperatorAuthorizationFreshness,
  V1_OPERATOR_AUTHORIZATION_TTL_MS,
  buildOperatorSignedMessage,
  verifyOperatorSignature,
  signOperatorPayload,
} from "../../src/v1/operator-signed.js";
import { toBase64url } from "../../src/core/encoding.js";

function makeOperator() {
  const privateKey = randomBytes(32);
  const publicKey = ed25519.getPublicKey(privateKey);
  return { privateKey, publicKey };
}

describe("canonicalJson", () => {
  it("is independent of object key insertion order at every depth", () => {
    const a = { b: 1, a: { d: [1, 2], c: "x" } };
    const b = { a: { c: "x", d: [1, 2] }, b: 1 };
    expect(canonicalJson(a)).toBe(canonicalJson(b));
    expect(canonicalJson(a)).toBe('{"a":{"c":"x","d":[1,2]},"b":1}');
  });

  it("preserves array order (arrays are not sets)", () => {
    expect(canonicalJson([2, 1])).not.toBe(canonicalJson([1, 2]));
  });

  it("drops undefined object properties and rejects unsignable values", () => {
    expect(canonicalJson({ a: 1, b: undefined })).toBe('{"a":1}');
    expect(() => canonicalJson({ a: Number.NaN })).toThrow();
    expect(() => canonicalJson({ a: 10n as unknown })).toThrow();
    const circular: Record<string, unknown> = {};
    circular.self = circular;
    expect(() => canonicalJson(circular)).toThrow();
  });
});

describe("verifyOperatorSignature", () => {
  const action = "/v1/federation/enable";
  const payload = {
    bind_address: "0.0.0.0:3501",
    idempotency_key: "11111111-2222-3333-4444-555555555555",
  };

  it("verifies a signature produced by signOperatorPayload", () => {
    const { privateKey, publicKey } = makeOperator();
    const signature = toBase64url(signOperatorPayload(action, payload, privateKey));
    expect(
      verifyOperatorSignature({ action, payload, signature, operatorPublicKey: publicKey }),
    ).toBe(true);
  });

  it("verifies regardless of payload key order", () => {
    const { privateKey, publicKey } = makeOperator();
    const signature = toBase64url(signOperatorPayload(action, payload, privateKey));
    const reordered = {
      idempotency_key: payload.idempotency_key,
      bind_address: payload.bind_address,
    };
    expect(
      verifyOperatorSignature({
        action,
        payload: reordered,
        signature,
        operatorPublicKey: publicKey,
      }),
    ).toBe(true);
  });

  it("rejects a tampered payload", () => {
    const { privateKey, publicKey } = makeOperator();
    const signature = toBase64url(signOperatorPayload(action, payload, privateKey));
    expect(
      verifyOperatorSignature({
        action,
        payload: { ...payload, bind_address: "0.0.0.0:9999" },
        signature,
        operatorPublicKey: publicKey,
      }),
    ).toBe(false);
  });

  it("rejects a signature replayed against a different action (action binding)", () => {
    const { privateKey, publicKey } = makeOperator();
    const signature = toBase64url(signOperatorPayload(action, payload, privateKey));
    expect(
      verifyOperatorSignature({
        action: "/v1/federation/disable",
        payload,
        signature,
        operatorPublicKey: publicKey,
      }),
    ).toBe(false);
  });

  it("rejects the wrong operator key", () => {
    const signer = makeOperator();
    const other = makeOperator();
    const signature = toBase64url(signOperatorPayload(action, payload, signer.privateKey));
    expect(
      verifyOperatorSignature({
        action,
        payload,
        signature,
        operatorPublicKey: other.publicKey,
      }),
    ).toBe(false);
  });

  it("never throws on malformed inputs — returns false", () => {
    const { publicKey } = makeOperator();
    expect(
      verifyOperatorSignature({
        action,
        payload,
        signature: "!!!not-base64url!!!",
        operatorPublicKey: publicKey,
      }),
    ).toBe(false);
    expect(
      verifyOperatorSignature({
        action,
        payload,
        signature: toBase64url(randomBytes(10)),
        operatorPublicKey: publicKey,
      }),
    ).toBe(false);
    const circular: Record<string, unknown> = {};
    circular.self = circular;
    expect(
      verifyOperatorSignature({
        action,
        payload: circular,
        signature: toBase64url(randomBytes(64)),
        operatorPublicKey: publicKey,
      }),
    ).toBe(false);
  });

  it("domain-separates from the session-challenge message space", () => {
    // A message built for the operator-signed domain must not be a valid
    // ceremony challenge message byte-for-byte (prefix differs).
    const message = buildOperatorSignedMessage(action, payload);
    const text = new TextDecoder().decode(message.slice(0, 40));
    expect(text).toContain("operator-signed");
    expect(text).not.toContain("session.challenge");
  });
});

describe("operator authorization freshness", () => {
  it("adds signed freshness fields with a bounded lifetime", () => {
    const nowMs = Date.parse("2026-08-08T12:00:00.000Z");
    const payload = addOperatorAuthorizationFields(
      { node_id: "edge-1" },
      { nowMs, nonce: "nonce-1" },
    );

    expect(payload).toEqual({
      node_id: "edge-1",
      authorization_nonce: "nonce-1",
      issued_at: "2026-08-08T12:00:00.000Z",
      expires_at: "2026-08-08T12:05:00.000Z",
    });
    expect(validateOperatorAuthorizationFreshness(payload, nowMs).ok).toBe(true);
  });

  it("rejects legacy payloads with no signed freshness fields", () => {
    expect(
      validateOperatorAuthorizationFreshness({ node_id: "edge-1" }),
    ).toEqual({
      ok: false,
      reason: "operator_authorization_missing_freshness",
    });
  });

  it("rejects expired, not-yet-valid, and overlong windows", () => {
    const nowMs = Date.parse("2026-08-08T12:00:00.000Z");
    expect(
      validateOperatorAuthorizationFreshness(
        addOperatorAuthorizationFields(
          { node_id: "expired" },
          { nowMs: nowMs - V1_OPERATOR_AUTHORIZATION_TTL_MS - 1, nonce: "n1" },
        ),
        nowMs,
      ),
    ).toEqual({ ok: false, reason: "operator_authorization_expired" });

    expect(
      validateOperatorAuthorizationFreshness(
        addOperatorAuthorizationFields(
          { node_id: "future" },
          { nowMs: nowMs + 61_000, nonce: "n2" },
        ),
        nowMs,
      ),
    ).toEqual({ ok: false, reason: "operator_authorization_not_yet_valid" });

    expect(
      validateOperatorAuthorizationFreshness(
        addOperatorAuthorizationFields(
          { node_id: "long" },
          {
            nowMs,
            nonce: "n3",
            ttlMs: V1_OPERATOR_AUTHORIZATION_TTL_MS + 1,
          },
        ),
        nowMs,
      ),
    ).toEqual({
      ok: false,
      reason: "operator_authorization_lifetime_too_long",
    });
  });
});
