/**
 * Sanctuary MCP Server — Encoding Utilities
 *
 * Base64url encoding/decoding per RFC 4648 §5.
 * Used throughout Sanctuary for serializing binary data in JSON.
 */

/**
 * Encode bytes to base64url string (no padding).
 */
export function toBase64url(bytes: Uint8Array): string {
  const base64 = Buffer.from(bytes).toString("base64");
  return base64.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

/**
 * Decode base64url string to bytes.
 */
export function fromBase64url(str: string): Uint8Array {
  // Restore standard base64
  let base64 = str.replace(/-/g, "+").replace(/_/g, "/");
  // Add padding
  while (base64.length % 4 !== 0) {
    base64 += "=";
  }
  const buf = Buffer.from(base64, "base64");
  return new Uint8Array(buf.buffer, buf.byteOffset, buf.byteLength);
}

/**
 * Decode a base64url string STRICTLY, rejecting any non-canonical input.
 *
 * `fromBase64url` (and Node's `Buffer.from(s, "base64")`) is lenient: it
 * silently skips characters outside the alphabet, tolerates ASCII
 * whitespace, and accepts stray `=` padding. That leniency is a fail-open
 * hazard for signature material, where a canonicalized byte string is later
 * length-checked and verified: an attacker can append `"!"`, a newline, or
 * `"=="` to a valid signature and still decode to the same bytes.
 *
 * This decoder is canonical no-padding base64url: the input must contain only
 * `[A-Za-z0-9\-_]`, must have a length that is a legal no-padding base64url
 * length (never `1 mod 4`), and must round-trip back to itself under
 * `toBase64url`. Any deviation throws. Callers verifying signatures MUST use
 * this rather than `fromBase64url`.
 */
export function fromBase64urlStrict(str: string): Uint8Array {
  if (typeof str !== "string") {
    throw new TypeError("fromBase64urlStrict: not a string");
  }
  // Charset + length gate: canonical no-padding base64url only. A length of
  // 1 mod 4 can never be produced by base64 and is rejected outright.
  if (!/^[A-Za-z0-9\-_]*$/.test(str) || str.length % 4 === 1) {
    throw new TypeError("fromBase64urlStrict: non-canonical base64url");
  }
  const decoded = fromBase64url(str);
  // Re-encode-equality: the only string that decodes to `decoded` AND encodes
  // back to `str` is the canonical one. This rejects non-canonical final-quad
  // bit patterns (e.g. trailing bits that a lenient decoder discards) that the
  // charset check alone would miss.
  if (toBase64url(decoded) !== str) {
    throw new TypeError("fromBase64urlStrict: non-canonical base64url");
  }
  return decoded;
}

/**
 * Encode a UTF-8 string to bytes.
 */
export function stringToBytes(str: string): Uint8Array {
  return new TextEncoder().encode(str);
}

/**
 * Decode bytes to a UTF-8 string.
 */
export function bytesToString(bytes: Uint8Array): string {
  return new TextDecoder().decode(bytes);
}

/**
 * Concatenate multiple Uint8Arrays.
 */
export function concatBytes(...arrays: Uint8Array[]): Uint8Array {
  const totalLength = arrays.reduce((sum, arr) => sum + arr.length, 0);
  const result = new Uint8Array(totalLength);
  let offset = 0;
  for (const arr of arrays) {
    result.set(arr, offset);
    offset += arr.length;
  }
  return result;
}

/**
 * Constant-time comparison of two byte arrays.
 * Prevents timing attacks on signature/tag verification.
 */
export function constantTimeEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) {
    diff |= a[i]! ^ b[i]!;
  }
  return diff === 0;
}
