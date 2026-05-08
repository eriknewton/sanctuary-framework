/**
 * Sanctuary Federation Protocol v0.1 — Canonical JSON
 *
 * Byte-stable JSON serialization used as the input to every SignedEvent signature
 * and every AuditBatch signature. Two emitters producing the same logical object
 * MUST produce the same bytes so that independently-computed signatures match.
 *
 * Rules:
 * - Object keys sorted lexicographically (UTF-16 code-unit order — matches Array.prototype.sort default).
 * - Undefined values omitted from objects (they are not serialized by JSON.stringify either).
 * - Non-finite numbers (NaN, Infinity, -Infinity) rejected — would serialize as null and
 *   destroy signature determinism.
 * - `null` is preserved distinctly from `undefined`.
 * - Nested arrays and objects are canonicalized recursively.
 * - No whitespace between tokens.
 *
 * This matches the contract already implicit in `server/src/bridge/bridge.ts` stableStringify,
 * but is reimplemented here to keep the mesh module self-contained (CLAUDE.md complexity
 * risk area #1 — canonicalization is the highest-risk interop surface, and the failure
 * mode for divergence across implementations is silent signature mismatches).
 *
 * CRITICAL: if you change this function, every v0.1 signature ever produced under the
 * old rules fails verification. Version bumps instead.
 */

import { MeshError } from "./errors.js";

export class MeshCanonicalJsonError extends MeshError {
  constructor(message: string) {
    super(message);
    this.name = "MeshCanonicalJsonError";
  }
}

/**
 * Produce the canonical-JSON string for an arbitrary value.
 *
 * Accepts: null, boolean, finite number, string, array, plain object.
 * Rejects: undefined at the top level, NaN, Infinity, functions, symbols, BigInt,
 * class instances with non-JSON-representable methods.
 *
 * Objects: keys sorted, undefined values omitted (NOT serialized as null — they
 * are simply absent, matching JSON.stringify behavior but guaranteed stable).
 */
export function canonicalize(value: unknown): string {
  if (value === undefined) {
    throw new MeshCanonicalJsonError(
      "canonicalize(): top-level undefined is not serializable"
    );
  }
  return encode(value);
}

/** Encode a value to its canonical-JSON fragment. */
function encode(value: unknown): string {
  if (value === null) return "null";
  if (typeof value === "boolean") return value ? "true" : "false";
  if (typeof value === "number") {
    if (!Number.isFinite(value)) {
      throw new MeshCanonicalJsonError(
        `canonicalize(): non-finite number (${String(value)}) is not serializable`
      );
    }
    return JSON.stringify(value);
  }
  if (typeof value === "string") return JSON.stringify(value);
  if (Array.isArray(value)) return encodeArray(value);
  if (typeof value === "object") return encodeObject(value as Record<string, unknown>);
  throw new MeshCanonicalJsonError(
    `canonicalize(): unsupported type ${typeof value}`
  );
}

function encodeArray(arr: unknown[]): string {
  const parts: string[] = [];
  for (let i = 0; i < arr.length; i++) {
    const item = arr[i];
    if (item === undefined) {
      // RFC 8785 forbids undefined at any depth. Object encoding correctly
      // omits undefined values; array encoding must not silently coerce to
      // "null". A producer-side mistake would otherwise be signed and only
      // surface as a non-deterministic verification failure on the receiver.
      throw new MeshCanonicalJsonError(
        `canonicalize(): undefined is not a valid JSON value at array index ${i}`
      );
    }
    parts.push(encode(item));
  }
  return "[" + parts.join(",") + "]";
}

function encodeObject(obj: Record<string, unknown>): string {
  // Undefined values are omitted; see rule above.
  const keys = Object.keys(obj)
    .filter((k) => obj[k] !== undefined)
    .sort();
  const parts: string[] = [];
  for (const k of keys) {
    parts.push(JSON.stringify(k) + ":" + encode(obj[k]));
  }
  return "{" + parts.join(",") + "}";
}

/** UTF-8 bytes of the canonical JSON, suitable for direct feeding to a signer or hasher. */
export function canonicalizeToBytes(value: unknown): Uint8Array {
  return new TextEncoder().encode(canonicalize(value));
}
