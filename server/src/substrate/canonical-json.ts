/**
 * Plugin substrate — canonical JSON (RFC-8785-style), self-contained.
 *
 * The signed BundleDescriptor (manifest.ts) and the governance_hash are computed over
 * these exact bytes, so the signer and every verifier MUST produce byte-identical
 * output for the same logical object (design §3.1: "Signer and verifier MUST use the
 * one shared canonicalizer"). This mirrors `mesh/canonical-json.ts` rule-for-rule but
 * is reimplemented to keep the substrate module dependency-isolated — the highest-risk
 * interop surface should not silently inherit a change made for the mesh protocol.
 *
 * Rules:
 * - Object keys sorted lexicographically (code-unit order).
 * - undefined omitted from objects; undefined at any array index is an ERROR.
 * - Non-finite numbers rejected (would serialize as null and break determinism).
 * - null preserved distinctly from undefined.
 * - No insignificant whitespace.
 *
 * CRITICAL: changing this function invalidates every signature ever produced over it.
 * Version the descriptor schema instead.
 */

import { SubstrateError } from "./errors.js";

export class CanonicalJsonError extends SubstrateError {
  constructor(message: string) {
    super("descriptor_malformed", message);
    this.name = "CanonicalJsonError";
  }
}

export function canonicalize(value: unknown): string {
  if (value === undefined) {
    throw new CanonicalJsonError("canonicalize(): top-level undefined is not serializable");
  }
  return encode(value);
}

function encode(value: unknown): string {
  if (value === null) return "null";
  if (typeof value === "boolean") return value ? "true" : "false";
  if (typeof value === "number") {
    if (!Number.isFinite(value)) {
      throw new CanonicalJsonError(
        `canonicalize(): non-finite number (${String(value)}) is not serializable`,
      );
    }
    return JSON.stringify(value);
  }
  if (typeof value === "string") return JSON.stringify(value);
  if (Array.isArray(value)) return encodeArray(value);
  if (typeof value === "object") return encodeObject(value as Record<string, unknown>);
  throw new CanonicalJsonError(`canonicalize(): unsupported type ${typeof value}`);
}

function encodeArray(arr: unknown[]): string {
  const parts: string[] = [];
  for (let i = 0; i < arr.length; i++) {
    const item = arr[i];
    if (item === undefined) {
      throw new CanonicalJsonError(
        `canonicalize(): undefined is not a valid JSON value at array index ${i}`,
      );
    }
    parts.push(encode(item));
  }
  return "[" + parts.join(",") + "]";
}

function encodeObject(obj: Record<string, unknown>): string {
  const keys = Object.keys(obj)
    .filter((k) => obj[k] !== undefined)
    .sort();
  const parts: string[] = [];
  for (const k of keys) {
    parts.push(JSON.stringify(k) + ":" + encode(obj[k]));
  }
  return "{" + parts.join(",") + "}";
}

/** UTF-8 bytes of the canonical JSON, for direct feeding to a signer or hasher. */
export function canonicalizeToBytes(value: unknown): Uint8Array {
  return new TextEncoder().encode(canonicalize(value));
}
