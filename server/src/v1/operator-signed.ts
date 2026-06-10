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

import { ed25519 } from "@noble/curves/ed25519";
import { fromBase64url } from "../core/encoding.js";
import { verify } from "../core/identity.js";

/** Domain separator for operator-signed admin payloads (versioned). */
export const V1_OPERATOR_SIGNED_DOMAIN = "sanctuary.v1.operator-signed";

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
