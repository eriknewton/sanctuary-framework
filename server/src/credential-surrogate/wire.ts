/**
 * Credential surrogacy: what the two one-shot codecs share, and nothing more.
 *
 * WHAT IS SHARED: the protocol version, the correlation-id grammar, the
 * frame cap check, and the encode helper. WHAT IS DELIBERATELY NOT SHARED: the
 * request and response shapes. The query socket (gate to helper) and the unlock
 * socket (operator to helper) are different principals, and the helper binds
 * each socket to exactly ONE codec, so a query frame arriving on the unlock
 * socket is `malformed` and the reverse is too (design v2.1 finding B2-B2). A
 * single parser that accepted both kinds would erase that boundary: the gate uid
 * could then send an `unlock`, and the operator uid could ask for a value.
 *
 * TRANSPORT (both sockets, copied whole from `peer-resolver-protocol.ts`):
 * newline-delimited JSON, ONE request then ONE response per connection, then the
 * caller closes. No length prefix, no second frame, no multiplexing, no
 * connection reuse. A byte after the first frame is `unexpected_extra_bytes` and
 * the helper closes, as `supervisor/socket-server.ts` does.
 */

import { randomBytes } from "node:crypto";

import { SURROGATE_WIRE_MAX_FRAME_BYTES } from "./constants.js";

/** On-wire version for BOTH surrogate codecs. Bumping it is a breaking change on every end. */
export const SURROGATE_WIRE_VERSION = 1 as const;

/**
 * Correlation-id length: 32 lowercase hex characters, 128 bits from
 * `randomBytes(16)`.
 *
 * The id is REDUNDANT with the one-connection rule on purpose. Each query owns
 * its socket, so a reply cannot reach another query's reader; the id is the
 * second, independent layer, so a reply whose id does not match is denied as
 * `malformed` rather than accepted on the strength of the connection alone.
 */
export const SURROGATE_CORRELATION_ID_BYTES = 16;
const CORRELATION_ID_RE = /^[0-9a-f]{32}$/;

/** Fresh correlation id, one per request. Never reused across connections. */
export function newSurrogateCorrelationId(): string {
  return randomBytes(SURROGATE_CORRELATION_ID_BYTES).toString("hex");
}

/** True only for a correctly shaped correlation id. */
export function isSurrogateCorrelationId(value: unknown): value is string {
  return typeof value === "string" && CORRELATION_ID_RE.test(value);
}

/**
 * Encode one frame as newline-terminated JSON.
 *
 * Throws when the caller tries to encode something over the bound. That is a
 * programmer error rather than a runtime condition on the request side (callers
 * control those shapes), but on the RESPONSE side it is reachable: a value at
 * `MAX_SURROGATE_VALUE_BYTES` whose every byte needs escaping still fits by the
 * derivation of `SURROGATE_WIRE_MAX_FRAME_BYTES`, so a throw here means the
 * derivation and the validation have drifted apart and the helper must fail
 * loudly rather than emit a truncated frame.
 */
export function encodeSurrogateFrame(value: unknown): Buffer {
  const buf = Buffer.from(`${JSON.stringify(value)}\n`, "utf8");
  if (buf.length > SURROGATE_WIRE_MAX_FRAME_BYTES) {
    throw new Error(
      `surrogate wire: encoded frame (${buf.length} bytes) exceeds the ${SURROGATE_WIRE_MAX_FRAME_BYTES}-byte bound`,
    );
  }
  return buf;
}

/**
 * Parse one frame's JSON into a plain record, or `null`.
 *
 * The byte-length check runs BEFORE `JSON.parse`, so an oversized or endless
 * stream can never pin memory or block the event loop on a root process's event
 * loop. Arrays and `null` are rejected here so every caller can treat a
 * non-null return as a record.
 */
export function decodeSurrogateFrameRecord(raw: string): Record<string, unknown> | null {
  if (Buffer.byteLength(raw, "utf8") > SURROGATE_WIRE_MAX_FRAME_BYTES) return null;
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    return null;
  }
  if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) return null;
  return parsed as Record<string, unknown>;
}

/** True when `record` has exactly `keys` and nothing else. Unknown keys are refused, never ignored. */
export function hasExactKeys(record: Record<string, unknown>, keys: readonly string[]): boolean {
  const actual = Object.keys(record);
  if (actual.length !== keys.length) return false;
  for (const key of keys) {
    if (!Object.prototype.hasOwnProperty.call(record, key)) return false;
  }
  return true;
}
