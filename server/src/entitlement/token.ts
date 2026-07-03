/**
 * Offline entitlement-token verify and resolve (S1 scaffold).
 *
 * An entitlement token is an Ed25519-signed, OFFLINE-verifiable claim that
 * maps a subject to a tier for a validity window. It is signed by a fleet
 * issuer whose public key the verifier pins ahead of time; verification is
 * purely local (no network dependency).
 *
 * Verification is FAIL-CLOSED: any absent, invalid-signature, expired,
 * tampered, or malformed token resolves to the COMMUNITY tier. A failure
 * NEVER grants a paid tier; safe-degrade is strictly less capability. This
 * is S1 (the verify/resolve core + tier model); issuance, revocation, and
 * the rest of the control plane are out of scope.
 *
 * The signed message construction mirrors the OPERATOR_SIGNED helper: a
 * versioned domain separator followed by the length-prefixed canonical-JSON
 * encoding of the claims, so a signature is independent of property
 * insertion order and cannot be replayed under a different domain.
 */

import { fromBase64url } from "../core/encoding.js";
import { verify } from "../core/identity.js";
import {
  COMMUNITY_TIER,
  isEntitlementTier,
  type EntitlementTier,
} from "./tier.js";

/** Domain separator for entitlement tokens (versioned). */
export const ENTITLEMENT_TOKEN_DOMAIN = "sanctuary.fleet.entitlement.v1";

/** Current on-the-wire token format version. */
export const ENTITLEMENT_TOKEN_VERSION = 1 as const;

/**
 * The signed claims of an entitlement token. `subject` names the operator or
 * fleet the grant applies to. `notBefore`/`notAfter` are Unix seconds; the
 * signature covers all of these fields.
 */
export interface EntitlementClaims {
  /** Token format version; must equal ENTITLEMENT_TOKEN_VERSION. */
  version: number;
  /** Operator/fleet identifier the grant applies to. */
  subject: string;
  /** Granted tier (one of the known tiers). */
  tier: EntitlementTier;
  /** Grant validity start, Unix seconds inclusive. */
  notBefore: number;
  /** Grant validity end, Unix seconds inclusive. */
  notAfter: number;
}

/**
 * A full entitlement token: the claims plus a base64url Ed25519 signature
 * over the canonical signing message for those claims.
 */
export interface EntitlementToken {
  claims: EntitlementClaims;
  /** base64url Ed25519 signature over buildEntitlementMessage(claims). */
  signature: string;
}

/** Why a token failed to resolve to its claimed tier. */
export type EntitlementDenyReason =
  | "absent"
  | "malformed"
  | "unknown_tier"
  | "bad_signature"
  | "not_yet_valid"
  | "expired";

/**
 * The outcome of resolving a token. `tier` is ALWAYS safe to act on: it is
 * the claimed tier only when every check passed, and COMMUNITY_TIER on any
 * failure. `granted` is true only on the success path. `reason` explains a
 * denial (absent on success).
 */
export interface EntitlementResolution {
  tier: EntitlementTier;
  granted: boolean;
  reason?: EntitlementDenyReason;
}

/** Options for resolveEntitlement. */
export interface ResolveEntitlementOptions {
  /** The token to verify, or null/undefined when no token is present. */
  token: EntitlementToken | null | undefined;
  /** Pinned issuer Ed25519 public key (32 bytes). */
  issuerPublicKey: Uint8Array;
  /** Current time, Unix seconds. Injected for deterministic tests. */
  now: number;
}

/**
 * Deterministic JSON encoding: object keys sorted lexicographically at every
 * nesting level, arrays preserved in order, no whitespace. Throws on values
 * JSON cannot represent faithfully. A signature over an ambiguous payload
 * must never be produced or accepted.
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
 * Build the byte string an issuer signs for an entitlement token. Domain
 * separator followed by the length-prefixed canonical-JSON of the claims.
 */
export function buildEntitlementMessage(claims: EntitlementClaims): Uint8Array {
  const encoder = new TextEncoder();
  const domain = encoder.encode(ENTITLEMENT_TOKEN_DOMAIN);
  const body = lengthPrefixed(encoder.encode(canonicalJson(claims)));
  const message = new Uint8Array(domain.length + body.length);
  message.set(domain, 0);
  message.set(body, domain.length);
  return message;
}

/**
 * Structural validation of claims WITHOUT touching the signature. Returns a
 * deny reason for a malformed shape, or null when the shape is well-formed.
 */
function claimsShapeReason(
  claims: unknown,
): EntitlementDenyReason | null {
  if (typeof claims !== "object" || claims === null) return "malformed";
  const c = claims as Record<string, unknown>;
  if (c.version !== ENTITLEMENT_TOKEN_VERSION) return "malformed";
  if (typeof c.subject !== "string" || c.subject.length === 0) {
    return "malformed";
  }
  if (
    typeof c.notBefore !== "number" ||
    typeof c.notAfter !== "number" ||
    !Number.isFinite(c.notBefore) ||
    !Number.isFinite(c.notAfter) ||
    c.notAfter < c.notBefore
  ) {
    return "malformed";
  }
  if (!isEntitlementTier(c.tier)) return "unknown_tier";
  return null;
}

/** Build a denied resolution at the community floor. */
function deny(reason: EntitlementDenyReason): EntitlementResolution {
  return { tier: COMMUNITY_TIER, granted: false, reason };
}

/**
 * Verify a token offline against the pinned issuer key and resolve it to a
 * tier. FAIL-CLOSED: on any failure the returned tier is COMMUNITY_TIER and
 * `granted` is false. Never throws; never grants a paid tier on failure.
 *
 * Order of checks is shape first (cheap, no crypto), then signature, then
 * the validity window, so a tampered field is rejected as a bad signature
 * rather than silently altering the resolved tier.
 */
export function resolveEntitlement(
  options: ResolveEntitlementOptions,
): EntitlementResolution {
  const { token, issuerPublicKey, now } = options;

  if (token === null || token === undefined) return deny("absent");

  try {
    if (typeof token !== "object") return deny("malformed");
    if (typeof (token as EntitlementToken).signature !== "string") {
      return deny("malformed");
    }

    const shapeReason = claimsShapeReason(token.claims);
    if (shapeReason !== null) return deny(shapeReason);

    const claims = token.claims;

    const message = buildEntitlementMessage(claims);
    const signature = fromBase64url(token.signature);
    if (signature.length !== 64) return deny("bad_signature");
    if (!verify(message, signature, issuerPublicKey)) {
      return deny("bad_signature");
    }

    if (now < claims.notBefore) return deny("not_yet_valid");
    if (now > claims.notAfter) return deny("expired");

    return { tier: claims.tier, granted: true };
  } catch {
    // Any unexpected shape (bad base64url, unencodable claims) is a denial.
    return deny("malformed");
  }
}
