/**
 * Credential surrogacy: the QUERY codec, gate to helper, one frame each way.
 *
 * This socket is reachable only by the one gate uid (the socket file is created
 * by the helper under a restrictive umask, chmod 0600, then chowned to the gate
 * uid, inside a root 0711 directory: the `peer-resolver-daemon.ts` placement,
 * copied). This module never authenticates a caller; it only shapes bytes.
 *
 * THE GATE NEVER DECIDES BINDING MEMBERSHIP. A request reports only what the
 * gate parsed out of the agent's request: which placeholder it saw, the
 * canonical host and port it reconciled, and WHERE it saw the placeholder. The
 * helper decides. That is why there is no field here a gate could use to assert
 * "this is allowed"; a compromised gate can lie about the destination, and that
 * bound is stated in design v2.1 section 1.
 */

import {
  isSurrogatePlaceholder,
} from "./placeholder.js";
import {
  MAX_SURROGATE_HEADER_NAME_LENGTH,
  MAX_SURROGATE_HOST_LENGTH,
  validateSurrogateHost,
  validateSurrogatePort,
} from "./binding.js";
import {
  SURROGATE_WIRE_VERSION,
  decodeSurrogateFrameRecord,
  encodeSurrogateFrame,
  hasExactKeys,
  isSurrogateCorrelationId,
} from "./wire.js";

/**
 * Where the gate saw the placeholder.
 *
 * `header:<lowercase name>` or the literal `target`. A placeholder in the
 * request target is reported, not swapped: the helper answers `wrong_location`,
 * which is how a misuse gets refused and logged rather than silently ignored.
 */
export type SurrogateQueryLocation = string;

const HEADER_LOCATION_PREFIX = "header:";
const TARGET_LOCATION = "target";
/** Lowercase form of the RFC 7230 token charset. The gate lowercases a header name before reporting it. */
const LOWERCASE_HEADER_NAME_RE = /^[!#$%&'*+\-.^_`|~0-9a-z]+$/;

/** True for a legal `location`. Anything else is `malformed`, never a lenient match. */
export function isSurrogateQueryLocation(value: unknown): value is SurrogateQueryLocation {
  if (typeof value !== "string") return false;
  if (value === TARGET_LOCATION) return true;
  if (!value.startsWith(HEADER_LOCATION_PREFIX)) return false;
  const name = value.slice(HEADER_LOCATION_PREFIX.length);
  if (name.length === 0 || name.length > MAX_SURROGATE_HEADER_NAME_LENGTH) return false;
  return LOWERCASE_HEADER_NAME_RE.test(name);
}

/** Build the `location` for a header the gate saw a placeholder in. */
export function surrogateHeaderLocation(headerName: string): SurrogateQueryLocation {
  return `${HEADER_LOCATION_PREFIX}${headerName.toLowerCase()}`;
}

/** The `location` for a placeholder seen in the request target. */
export const SURROGATE_TARGET_LOCATION: SurrogateQueryLocation = TARGET_LOCATION;

/** The ONLY request shape on the query socket. */
export interface SurrogateQueryRequest {
  v: typeof SURROGATE_WIRE_VERSION;
  /** Fresh correlation id, one per query. */
  id: string;
  kind: "resolve";
  placeholder: string;
  /** Canonical destination host the gate reconciled, lowercase DNS name. */
  host: string;
  port: number;
  location: SurrogateQueryLocation;
}

/** Why the helper refused. Closed enum: there is no free-form field on this wire. */
export type SurrogateDenyReason =
  | "unknown"
  | "misroute"
  | "wrong_location"
  | "locked"
  | "expired"
  | "rate_limited"
  | "malformed";

const DENY_REASONS: readonly SurrogateDenyReason[] = [
  "unknown",
  "misroute",
  "wrong_location",
  "locked",
  "expired",
  "rate_limited",
  "malformed",
];

/** True for a member of the closed deny enum. */
export function isSurrogateDenyReason(value: unknown): value is SurrogateDenyReason {
  return typeof value === "string" && (DENY_REASONS as readonly string[]).includes(value);
}

export interface SurrogateQuerySwapResponse {
  v: typeof SURROGATE_WIRE_VERSION;
  id: string;
  kind: "swap";
  value: string;
}

export interface SurrogateQueryDenyResponse {
  v: typeof SURROGATE_WIRE_VERSION;
  id: string;
  kind: "deny";
  reason: SurrogateDenyReason;
}

export type SurrogateQueryResponse = SurrogateQuerySwapResponse | SurrogateQueryDenyResponse;

const REQUEST_KEYS = ["v", "id", "kind", "placeholder", "host", "port", "location"] as const;
const SWAP_KEYS = ["v", "id", "kind", "value"] as const;
const DENY_KEYS = ["v", "id", "kind", "reason"] as const;

export function encodeSurrogateQueryRequest(req: SurrogateQueryRequest): Buffer {
  return encodeSurrogateFrame(req);
}

export function encodeSurrogateQueryResponse(resp: SurrogateQueryResponse): Buffer {
  return encodeSurrogateFrame(resp);
}

/**
 * Strictly parse one query request. Returns `null` on ANY deviation; the helper
 * turns that into a `malformed` deny rather than a throw, so a hostile frame is
 * a bounded answer and never an unhandled rejection in a root process.
 *
 * Every element is validated with the SHARED validators in `binding.ts`, the
 * same functions the policy parser and the helper's table loader use, so "a host
 * the parser accepted" and "a host the wire accepts" cannot diverge.
 */
export function parseSurrogateQueryRequest(raw: string): SurrogateQueryRequest | null {
  const r = decodeSurrogateFrameRecord(raw);
  if (r === null) return null;
  if (!hasExactKeys(r, REQUEST_KEYS)) return null;
  if (r.v !== SURROGATE_WIRE_VERSION) return null;
  if (r.kind !== "resolve") return null;
  if (!isSurrogateCorrelationId(r.id)) return null;
  if (!isSurrogatePlaceholder(r.placeholder)) return null;
  if (typeof r.host !== "string" || r.host.length > MAX_SURROGATE_HOST_LENGTH) return null;
  if (validateSurrogateHost(r.host) !== null) return null;
  if (validateSurrogatePort(r.port) !== null) return null;
  if (!isSurrogateQueryLocation(r.location)) return null;
  return {
    v: SURROGATE_WIRE_VERSION,
    id: r.id,
    kind: "resolve",
    placeholder: r.placeholder,
    host: r.host,
    port: r.port as number,
    location: r.location,
  };
}

/**
 * Strictly parse one query response. Returns `null` on any deviation, which the
 * gate client treats exactly as it treats a transport failure: a bounded
 * fail-closed denial with no upstream dial, never a silent allow.
 *
 * The value is NOT validated for length here: the helper already refused an
 * illegal value at unlock time, and re-deriving that rule on the read side would
 * be a second grammar to keep in step. What IS checked is the frame cap, before
 * the parse, in `decodeSurrogateFrameRecord`.
 */
export function parseSurrogateQueryResponse(raw: string): SurrogateQueryResponse | null {
  const r = decodeSurrogateFrameRecord(raw);
  if (r === null) return null;
  if (r.v !== SURROGATE_WIRE_VERSION) return null;
  if (!isSurrogateCorrelationId(r.id)) return null;
  if (r.kind === "swap") {
    if (!hasExactKeys(r, SWAP_KEYS)) return null;
    if (typeof r.value !== "string" || r.value.length === 0) return null;
    return { v: SURROGATE_WIRE_VERSION, id: r.id, kind: "swap", value: r.value };
  }
  if (r.kind === "deny") {
    if (!hasExactKeys(r, DENY_KEYS)) return null;
    if (!isSurrogateDenyReason(r.reason)) return null;
    return { v: SURROGATE_WIRE_VERSION, id: r.id, kind: "deny", reason: r.reason };
  }
  return null;
}
