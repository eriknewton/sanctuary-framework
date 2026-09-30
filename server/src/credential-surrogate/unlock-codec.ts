/**
 * Credential surrogacy: the UNLOCK codec, operator to helper, one frame each way.
 *
 * A DIFFERENT PRINCIPAL AND A DIFFERENT CODEC. The unlock socket is chowned at
 * 0600 to the uid that owns the fortress storage directory, baked into the
 * helper's argv as `--operator-uid=N` by root at arming and never taken from a
 * caller. The helper binds this socket to THIS codec only, so a query frame
 * arriving here is `malformed`, and an unlock frame on the query socket is too
 * (design v2.1 finding B2-B2). Keeping the two parsers apart is what makes the
 * gate uid unable to send an unlock and the operator uid unable to ask for a
 * value.
 *
 * ONE VALUE PER CONNECTION (finding A2-S3). An earlier shape carried
 * `values: [...]` and could not fit the frame cap. Each unlock carries exactly
 * one secret, which is what makes `SURROGATE_WIRE_MAX_FRAME_BYTES` derivable
 * from one value's escaped length.
 *
 * A STATUS ANSWER NEVER CARRIES A VALUE OR A PLACEHOLDER. It reports which
 * secrets are unlocked and when they expire, nothing more. `status` is also what
 * the operator CLI uses to decide "is this agent armed", so it has to be
 * answerable without disclosing anything.
 */

import {
  MAX_SURROGATE_VALUE_BYTES,
} from "./constants.js";
import { isLegalHttpFieldValue, validateSurrogateSecretName } from "./binding.js";
import {
  SURROGATE_WIRE_VERSION,
  decodeSurrogateFrameRecord,
  encodeSurrogateFrame,
  hasExactKeys,
  isSurrogateCorrelationId,
} from "./wire.js";

/** Load one value for one secret, for one generation, for at most `ttl_seconds`. */
export interface SurrogateUnlockRequest {
  v: typeof SURROGATE_WIRE_VERSION;
  id: string;
  kind: "unlock";
  /** The generation the caller believes the helper serves. A mismatch is refused, never adopted. */
  generation_id: number;
  /** Requested lifetime. The HELPER clamps it (AGENTS.md rule 10); this parser only bounds the shape. */
  ttl_seconds: number;
  secret: string;
  value: string;
}

/** Drop every value the helper holds, now. */
export interface SurrogateLockRequest {
  v: typeof SURROGATE_WIRE_VERSION;
  id: string;
  kind: "lock";
}

/** Ask which secrets are unlocked. The one request the operator CLI uses as an "is this agent armed" probe. */
export interface SurrogateStatusRequest {
  v: typeof SURROGATE_WIRE_VERSION;
  id: string;
  kind: "status";
}

export type SurrogateUnlockSocketRequest =
  | SurrogateUnlockRequest
  | SurrogateLockRequest
  | SurrogateStatusRequest;

export interface SurrogateOkResponse {
  v: typeof SURROGATE_WIRE_VERSION;
  id: string;
  kind: "ok";
}

/** One row of a status answer. No value, no placeholder, by construction of the type. */
export interface SurrogateStatusBinding {
  secret: string;
  unlocked: boolean;
  /** Epoch milliseconds, or `null` when the binding is locked. */
  expires_at: number | null;
}

export interface SurrogateStatusResponse {
  v: typeof SURROGATE_WIRE_VERSION;
  id: string;
  kind: "status";
  generation_id: number;
  bindings: SurrogateStatusBinding[];
}

/** Why the helper refused an unlock-socket request. Closed enum, no free-form field. */
export type SurrogateUnlockDenyReason =
  | "unknown_secret"
  | "wrong_generation"
  | "value_too_long"
  | "illegal_value_byte"
  | "malformed";

const UNLOCK_DENY_REASONS: readonly SurrogateUnlockDenyReason[] = [
  "unknown_secret",
  "wrong_generation",
  "value_too_long",
  "illegal_value_byte",
  "malformed",
];

export function isSurrogateUnlockDenyReason(value: unknown): value is SurrogateUnlockDenyReason {
  return typeof value === "string" && (UNLOCK_DENY_REASONS as readonly string[]).includes(value);
}

export interface SurrogateUnlockDenyResponse {
  v: typeof SURROGATE_WIRE_VERSION;
  id: string;
  kind: "deny";
  reason: SurrogateUnlockDenyReason;
}

export type SurrogateUnlockSocketResponse =
  | SurrogateOkResponse
  | SurrogateStatusResponse
  | SurrogateUnlockDenyResponse;

const UNLOCK_KEYS = ["v", "id", "kind", "generation_id", "ttl_seconds", "secret", "value"] as const;
const LOCK_KEYS = ["v", "id", "kind"] as const;
const STATUS_REQUEST_KEYS = LOCK_KEYS;
const OK_KEYS = ["v", "id", "kind"] as const;
const STATUS_RESPONSE_KEYS = ["v", "id", "kind", "generation_id", "bindings"] as const;
const DENY_KEYS = ["v", "id", "kind", "reason"] as const;
const STATUS_BINDING_KEYS = ["secret", "unlocked", "expires_at"] as const;

export function encodeSurrogateUnlockSocketRequest(req: SurrogateUnlockSocketRequest): Buffer {
  return encodeSurrogateFrame(req);
}

export function encodeSurrogateUnlockSocketResponse(resp: SurrogateUnlockSocketResponse): Buffer {
  return encodeSurrogateFrame(resp);
}

/** A generation id is a positive integer. Zero is the wrapper's PARKED sentinel and is never served. */
function isGenerationId(value: unknown): value is number {
  return typeof value === "number" && Number.isInteger(value) && value > 0;
}

/**
 * Strictly parse one unlock-socket request. Returns `null` on any deviation.
 *
 * The VALUE is checked here for its frame-level rules (length and legal HTTP
 * field-value bytes) because those are properties of the bytes, and refusing
 * them at the parser means no code path downstream ever holds a value that could
 * split a header. Whether the SECRET is one this helper serves, and whether the
 * generation matches, are the helper's checks against its own table: this parser
 * has no table.
 */
export function parseSurrogateUnlockSocketRequest(raw: string): SurrogateUnlockSocketRequest | null {
  const r = decodeSurrogateFrameRecord(raw);
  if (r === null) return null;
  if (r.v !== SURROGATE_WIRE_VERSION) return null;
  if (!isSurrogateCorrelationId(r.id)) return null;
  if (r.kind === "unlock") {
    if (!hasExactKeys(r, UNLOCK_KEYS)) return null;
    if (!isGenerationId(r.generation_id)) return null;
    // SHAPE ONLY, deliberately. `ttl_seconds` is CLAMPED by the helper, not
    // refused here (design 3.4.3, AGENTS.md rule 10: the relying side clamps),
    // so a generous operator request becomes a bounded unlock rather than no
    // unlock at all. What this parser refuses is a TTL that is not a positive
    // integer number of seconds, which is a different request from a generous
    // one and must not be clamped UP to something the caller never asked for.
    // The upper bound lives in `clampSurrogateUnlockSeconds`
    // (`egress-gate/surrogate-helper-daemon.ts`); must not be duplicated here.
    if (
      typeof r.ttl_seconds !== "number" ||
      !Number.isSafeInteger(r.ttl_seconds) ||
      r.ttl_seconds <= 0
    ) {
      return null;
    }
    if (validateSurrogateSecretName(r.secret) !== null) return null;
    if (typeof r.value !== "string") return null;
    if (r.value.length === 0) return null;
    // Byte length, not character count: the cap bounds what goes on the wire and
    // into a request header, and a multi-byte character would otherwise pass a
    // length check and exceed the header budget.
    if (Buffer.byteLength(r.value, "utf8") > MAX_SURROGATE_VALUE_BYTES) return null;
    if (!isLegalHttpFieldValue(r.value)) return null;
    return {
      v: SURROGATE_WIRE_VERSION,
      id: r.id,
      kind: "unlock",
      generation_id: r.generation_id,
      ttl_seconds: r.ttl_seconds,
      secret: r.secret as string,
      value: r.value,
    };
  }
  if (r.kind === "lock") {
    if (!hasExactKeys(r, LOCK_KEYS)) return null;
    return { v: SURROGATE_WIRE_VERSION, id: r.id, kind: "lock" };
  }
  if (r.kind === "status") {
    if (!hasExactKeys(r, STATUS_REQUEST_KEYS)) return null;
    return { v: SURROGATE_WIRE_VERSION, id: r.id, kind: "status" };
  }
  return null;
}

/**
 * Strictly parse one unlock-socket response. Returns `null` on any deviation; the
 * operator CLI treats that as "any other outcome" and refuses, which is what
 * makes a malformed answer a refusal rather than an assumed "unarmed".
 */
export function parseSurrogateUnlockSocketResponse(raw: string): SurrogateUnlockSocketResponse | null {
  const r = decodeSurrogateFrameRecord(raw);
  if (r === null) return null;
  if (r.v !== SURROGATE_WIRE_VERSION) return null;
  if (!isSurrogateCorrelationId(r.id)) return null;
  if (r.kind === "ok") {
    if (!hasExactKeys(r, OK_KEYS)) return null;
    return { v: SURROGATE_WIRE_VERSION, id: r.id, kind: "ok" };
  }
  if (r.kind === "status") {
    if (!hasExactKeys(r, STATUS_RESPONSE_KEYS)) return null;
    if (!isGenerationId(r.generation_id)) return null;
    if (!Array.isArray(r.bindings)) return null;
    const bindings: SurrogateStatusBinding[] = [];
    for (const entry of r.bindings) {
      if (typeof entry !== "object" || entry === null || Array.isArray(entry)) return null;
      const e = entry as Record<string, unknown>;
      if (!hasExactKeys(e, STATUS_BINDING_KEYS)) return null;
      if (validateSurrogateSecretName(e.secret) !== null) return null;
      if (typeof e.unlocked !== "boolean") return null;
      if (e.expires_at !== null && (typeof e.expires_at !== "number" || !Number.isInteger(e.expires_at))) {
        return null;
      }
      bindings.push({
        secret: e.secret as string,
        unlocked: e.unlocked,
        expires_at: e.expires_at as number | null,
      });
    }
    return {
      v: SURROGATE_WIRE_VERSION,
      id: r.id,
      kind: "status",
      generation_id: r.generation_id,
      bindings,
    };
  }
  if (r.kind === "deny") {
    if (!hasExactKeys(r, DENY_KEYS)) return null;
    if (!isSurrogateUnlockDenyReason(r.reason)) return null;
    return { v: SURROGATE_WIRE_VERSION, id: r.id, kind: "deny", reason: r.reason };
  }
  return null;
}
