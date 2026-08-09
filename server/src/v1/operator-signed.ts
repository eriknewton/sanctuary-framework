/**
 * OPERATOR_SIGNED verification helper (PR-A1).
 *
 * Wave 1 admin endpoints (federation enable/disable, agents
 * protect/unprotect, identity rotate, ...) carry an inline operator
 * identity signature in addition to session auth. PR-A1 ships the
 * verification primitive once so every later endpoint in the stack uses
 * the same canonical message construction; no endpoint in this PR consumes
 * it yet.
 *
 * The signed message is: domain separator, the action name (the endpoint
 * path, e.g. "/v1/federation/enable"), and the canonical-JSON encoding of
 * the request payload WITHOUT the `operator_signature` field. Canonical
 * JSON (sorted object keys, no insignificant whitespace) makes the
 * signature independent of property insertion order on either side.
 */

import { randomUUID } from "node:crypto";
import { ed25519 } from "@noble/curves/ed25519";
import { fromBase64url } from "../core/encoding.js";
import { verify } from "../core/identity.js";

/** Domain separator for operator-signed admin payloads (versioned). */
export const V1_OPERATOR_SIGNED_DOMAIN = "sanctuary.v1.operator-signed";
/** Default operator authorization lifetime: 5 minutes. */
export const V1_OPERATOR_AUTHORIZATION_TTL_MS = 5 * 60_000;
/** Bound accepted lifetimes so a signed payload cannot become a long-lived bearer. */
export const V1_OPERATOR_AUTHORIZATION_MAX_TTL_MS =
  V1_OPERATOR_AUTHORIZATION_TTL_MS;
/** Small clock skew allowance for operator and daemon clocks. */
export const V1_OPERATOR_AUTHORIZATION_CLOCK_SKEW_MS = 60_000;

export type OperatorAuthorizationFreshness =
  | {
      ok: true;
      authorizationNonce: string;
      issuedAtMs: number;
      expiresAtMs: number;
      expiresAt: string;
    }
  | {
      ok: false;
      reason:
        | "operator_authorization_missing_freshness"
        | "operator_authorization_malformed_freshness"
        | "operator_authorization_expired"
        | "operator_authorization_not_yet_valid"
        | "operator_authorization_lifetime_too_long";
    };

/**
 * Deterministic JSON encoding: object keys sorted lexicographically at
 * every nesting level, arrays preserved in order, no whitespace. Throws
 * on values JSON cannot represent faithfully (undefined, functions,
 * symbols, bigint, NaN/Infinity, circular references) — an operator
 * signature over an ambiguous payload must never be produced or accepted.
 */
export function canonicalJson(value: unknown): string {
  return encodeCanonical(value, new Set());
}

/**
 * Add the freshness fields that are covered by the operator signature. Callers
 * sign the returned object and send that same object on the wire.
 */
export function addOperatorAuthorizationFields(
  payload: Record<string, unknown>,
  opts?: { nowMs?: number; nonce?: string; ttlMs?: number },
): Record<string, unknown> {
  const nowMs = opts?.nowMs ?? Date.now();
  const ttlMs = opts?.ttlMs ?? V1_OPERATOR_AUTHORIZATION_TTL_MS;
  return {
    ...payload,
    authorization_nonce: opts?.nonce ?? randomUUID(),
    issued_at: new Date(nowMs).toISOString(),
    expires_at: new Date(nowMs + ttlMs).toISOString(),
  };
}

/**
 * Validate signed freshness fields. This is not an anti-replay primitive by
 * itself; the caller must still spend the nonce durably after signature verify.
 */
export function validateOperatorAuthorizationFreshness(
  payload: unknown,
  nowMs = Date.now(),
): OperatorAuthorizationFreshness {
  if (typeof payload !== "object" || payload === null || Array.isArray(payload)) {
    return { ok: false, reason: "operator_authorization_malformed_freshness" };
  }
  const body = payload as Record<string, unknown>;
  const nonce = body.authorization_nonce;
  const issuedAt = body.issued_at;
  const expiresAt = body.expires_at;
  if (nonce === undefined || issuedAt === undefined || expiresAt === undefined) {
    return { ok: false, reason: "operator_authorization_missing_freshness" };
  }
  if (
    typeof nonce !== "string" ||
    nonce.length === 0 ||
    nonce.length > 128 ||
    typeof issuedAt !== "string" ||
    typeof expiresAt !== "string"
  ) {
    return { ok: false, reason: "operator_authorization_malformed_freshness" };
  }
  const issuedAtMs = Date.parse(issuedAt);
  const expiresAtMs = Date.parse(expiresAt);
  if (!Number.isFinite(issuedAtMs) || !Number.isFinite(expiresAtMs)) {
    return { ok: false, reason: "operator_authorization_malformed_freshness" };
  }
  if (issuedAtMs > nowMs + V1_OPERATOR_AUTHORIZATION_CLOCK_SKEW_MS) {
    return { ok: false, reason: "operator_authorization_not_yet_valid" };
  }
  if (expiresAtMs <= nowMs) {
    return { ok: false, reason: "operator_authorization_expired" };
  }
  if (
    expiresAtMs <= issuedAtMs ||
    expiresAtMs - issuedAtMs > V1_OPERATOR_AUTHORIZATION_MAX_TTL_MS
  ) {
    return { ok: false, reason: "operator_authorization_lifetime_too_long" };
  }
  return {
    ok: true,
    authorizationNonce: nonce,
    issuedAtMs,
    expiresAtMs,
    expiresAt,
  };
}

function encodeCanonical(value: unknown, seen: Set<object>): string {
  if (value === null) return "null";
  switch (typeof value) {
    case "string":
      return JSON.stringify(value);
    case "boolean":
      return value ? "true" : "false";
    case "number":
      if (!Number.isFinite(value)) {
        throw new TypeError("canonicalJson: non-finite number");
      }
      return JSON.stringify(value);
    case "object":
      break;
    default:
      throw new TypeError(`canonicalJson: unsupported type ${typeof value}`);
  }
  const obj = value as object;
  if (seen.has(obj)) {
    throw new TypeError("canonicalJson: circular reference");
  }
  seen.add(obj);
  try {
    if (Array.isArray(obj)) {
      return `[${obj.map((item) => encodeCanonical(item, seen)).join(",")}]`;
    }
    const entries = Object.entries(obj as Record<string, unknown>)
      .filter(([, v]) => v !== undefined)
      .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0))
      .map(([k, v]) => `${JSON.stringify(k)}:${encodeCanonical(v, seen)}`);
    return `{${entries.join(",")}}`;
  } finally {
    seen.delete(obj);
  }
}

function lengthPrefixed(field: Uint8Array): Uint8Array {
  const out = new Uint8Array(4 + field.length);
  new DataView(out.buffer).setUint32(0, field.length, false);
  out.set(field, 4);
  return out;
}

/**
 * Build the byte string an operator identity signs for an OPERATOR_SIGNED
 * request. `payload` MUST already exclude the `operator_signature` field.
 */
export function buildOperatorSignedMessage(
  action: string,
  payload: unknown,
): Uint8Array {
  const encoder = new TextEncoder();
  const parts = [
    encoder.encode(V1_OPERATOR_SIGNED_DOMAIN),
    lengthPrefixed(encoder.encode(action)),
    lengthPrefixed(encoder.encode(canonicalJson(payload))),
  ];
  const total = parts.reduce((n, p) => n + p.length, 0);
  const message = new Uint8Array(total);
  let offset = 0;
  for (const part of parts) {
    message.set(part, offset);
    offset += part.length;
  }
  return message;
}

/**
 * Verify an inline operator signature. Never throws: any malformed input
 * (bad base64url, wrong key length, unencodable payload) verifies false —
 * the caller treats false as a generic denial.
 */
export function verifyOperatorSignature(input: {
  action: string;
  payload: unknown;
  signature: string;
  operatorPublicKey: Uint8Array;
}): boolean {
  try {
    const message = buildOperatorSignedMessage(input.action, input.payload);
    const signature = fromBase64url(input.signature);
    // 64 = RFC 8032 Ed25519 signature (R||S, 32 bytes each). Kept as a literal
    // on purpose: this module is a LEGACY FROZEN SERIALIZER, and
    // `test/structure/pqc-slice1-additive.test.ts` forbids it from even naming
    // the signature-suite registry. The value must equal
    // `ED25519_SIGNATURE_BYTES`;
    // `test/structure/key-length-constants.test.ts` asserts that it does.
    if (signature.length !== 64) return false;
    return verify(message, signature, input.operatorPublicKey);
  } catch {
    return false;
  }
}

/**
 * Produce an operator signature with a raw (already-decrypted, transient)
 * Ed25519 private key. The caller owns zeroing the key after use. Used by
 * tests in PR-A1 and by the client-side signing paths of later PRs in the
 * stack; never logs or returns key material.
 */
export function signOperatorPayload(
  action: string,
  payload: unknown,
  privateKey: Uint8Array,
): Uint8Array {
  const message = buildOperatorSignedMessage(action, payload);
  return ed25519.sign(message, privateKey);
}
