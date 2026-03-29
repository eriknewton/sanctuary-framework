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
