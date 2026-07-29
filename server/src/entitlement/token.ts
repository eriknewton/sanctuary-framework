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

import { fromBase64urlStrict } from "../core/encoding.js";
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
 * Domain separator for v2 entitlement tokens (the fleet-control-plane license
 * schema). FROZEN from now, exactly like the v1 domain: this is a signing-crypto
 * label, so the string may never change under version 2. A superset schema that
 * adds a field is fine; a *change* to this label invalidates every already-signed
 * v2 license and requires a v3.
 */
export const ENTITLEMENT_TOKEN_DOMAIN_V2 = "sanctuary.fleet.entitlement.v2";

/** The v2 token format version. FROZEN. */
export const ENTITLEMENT_TOKEN_VERSION_V2 = 2 as const;

/** The pricing axis a license is metered on. Stored explicitly so a future
 * seat/fleet pivot needs no schema migration. */
export type PricingUnit = "node" | "seat" | "fleet";

/** The billing period a license was sold under. */
export type EntitlementPeriod = "monthly" | "annual";

/** The known gated capabilities a v2 license may unlock. Sold as a SET on the
 * license (not implied by tier) so add-ons need no schema change. */
export type EntitlementFeatureFlag =
  | "roster"
  | "policy-dist"
  | "kill-safety"
  | "console";

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
 * The signed claims of a v2 (fleet-control-plane license) entitlement token.
 *
 * v2 is a SUPERSET of v1: it carries every field PR-2 will enforce a per-node
 * meter and feature gate on. EVERY field here is covered by the signature  - 
 * tampering any one of them flips verification to `bad_signature` and degrades
 * to the community floor. The single runtime field that is NOT in the token is
 * `enrolledCount` (current nodes enrolled), tracked by PR-2 against the signed
 * `entitledCount`; it deliberately has no home in these claims.
 */
export interface EntitlementClaimsV2 {
  /** Token format version; must equal ENTITLEMENT_TOKEN_VERSION_V2. */
  version: 2;
  /** Unique id binding this license (issuer-generated, e.g. 128-bit base64url). */
  licenseId: string;
  /** Operator/fleet identifier the grant applies to (non-empty). */
  subject: string;
  /** Granted tier (one of the known tiers). */
  tier: EntitlementTier;
  /** Metering axis (node/seat/fleet). Stored so a future pivot needs no migration. */
  pricingUnit: PricingUnit;
  /** Max units permitted; null = unlimited, otherwise an integer >= 0. */
  entitledCount: number | null;
  /** Billing period the license was sold under. */
  period: EntitlementPeriod;
  /** Grant validity start, Unix seconds inclusive. */
  notBefore: number;
  /** Grant validity end, Unix seconds inclusive (= expires_at; drives expiry). */
  notAfter: number;
  /**
   * Grace window end, Unix seconds, nullable. Kept SEPARATE from notAfter so
   * grace is a policy knob, not baked into expiry. If non-null must be >= notAfter.
   */
  graceUntil: number | null;
  /**
   * The set of gated capabilities this license unlocks. Stored as an explicit
   * set (NOT implied by tier). Canonicalized (sorted + deduped) before signing
   * so the signed message is order-independent.
   */
  featureFlags: string[];
  /** The issuer identity id (the public-key fingerprint verifiers pin). */
  issuer: string;
}

/**
 * A full entitlement token: the claims plus a base64url Ed25519 signature
 * over the canonical signing message for those claims. A v1 token carries
 * `EntitlementClaims`; a v2 (license) token carries `EntitlementClaimsV2`.
 * `resolveEntitlement` dispatches on `claims.version`.
 */
export interface EntitlementToken {
  claims: EntitlementClaims | EntitlementClaimsV2;
  /** base64url Ed25519 signature over the version-appropriate build message. */
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
 *
 * The enforcement fields (`entitledCount`, `featureFlags`, `pricingUnit`,
 * `period`, `graceUntil`, `licenseId`, `issuer`, `graceActive`) are present
 * ONLY on a granted v2 (license) resolution. For a v1 grant and for EVERY
 * denial they are absent (`undefined`), so a v1 resolution's key set is
 * byte-identical to what it was before v2 existed. PR-2 reads these fields to
 * enforce the per-node meter and feature gates; a verification failure strips
 * them (fail-closed), it never fabricates them.
 */
export interface EntitlementResolution {
  tier: EntitlementTier;
  granted: boolean;
  reason?: EntitlementDenyReason;
  /** v2-granted only: max units permitted (null = unlimited). */
  entitledCount?: number | null;
  /** v2-granted only: the canonicalized set of unlocked capabilities. */
  featureFlags?: string[];
  /** v2-granted only: the metering axis. */
  pricingUnit?: PricingUnit;
  /** v2-granted only: the billing period. */
  period?: EntitlementPeriod;
  /** v2-granted only: the grace-window end (null = no grace). */
  graceUntil?: number | null;
  /** v2-granted only: the license id. */
  licenseId?: string;
  /** v2-granted only: the issuer fingerprint the token was signed under. */
  issuer?: string;
  /**
   * v2-granted only: true when the grant is being honored DURING the grace
   * window (now is in `(notAfter, graceUntil]`). Paid features stay live during
   * grace; this flag is the seam PR-2/PR-3 consume to decide downgrade timing.
   * Absent (undefined) inside the normal `[notBefore, notAfter]` window.
   */
  graceActive?: boolean;
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
 * Deterministically canonicalize a feature-flag set: sort lexicographically and
 * drop duplicates. Two logically-equal sets (any order, any dupes) collapse to
 * the SAME array, so the signed message is order-independent. Reject a
 * non-array or any non-empty-string element (the caller treats a null return as
 * a malformed-claims deny). This is the single place featureFlags are ordered,
 * so the sign side and the verify side always agree byte-for-byte.
 */
function canonicalizeFeatureFlags(value: unknown): string[] | null {
  if (!Array.isArray(value)) return null;
  const seen = new Set<string>();
  for (const item of value) {
    if (typeof item !== "string" || item.length === 0) return null;
    seen.add(item);
  }
  return Array.from(seen).sort((a, b) => (a < b ? -1 : a > b ? 1 : 0));
}

/**
 * Build the byte string an issuer signs for a v2 (license) entitlement token.
 * Same construction shape as v1  -  domain separator + length-prefixed
 * canonical-JSON  -  but over the v2 domain and a v2 claims object whose
 * `featureFlags` are canonicalized (sorted + deduped) FIRST, so two logically-
 * equal claim sets produce byte-identical messages. Throws if `featureFlags` is
 * not an array of non-empty strings (a malformed set must never be signed).
 */
export function buildEntitlementMessageV2(
  claims: EntitlementClaimsV2,
): Uint8Array {
  const canonicalFlags = canonicalizeFeatureFlags(claims.featureFlags);
  if (canonicalFlags === null) {
    throw new TypeError("buildEntitlementMessageV2: malformed featureFlags");
  }
  // Canonicalize featureFlags before encoding so ordering/dupes cannot change
  // the signed bytes. Every other field is passed through; canonicalJson sorts
  // object keys, so property insertion order is already irrelevant.
  const normalized: EntitlementClaimsV2 = {
    ...claims,
    featureFlags: canonicalFlags,
  };
  const encoder = new TextEncoder();
  const domain = encoder.encode(ENTITLEMENT_TOKEN_DOMAIN_V2);
  const body = lengthPrefixed(encoder.encode(canonicalJson(normalized)));
  const message = new Uint8Array(domain.length + body.length);
  message.set(domain, 0);
  message.set(body, domain.length);
  return message;
}

/**
 * The result of normalizing claims: either a deny reason for a malformed
 * shape, or a frozen own-property snapshot of primitive claim values that is
 * safe to sign, window-check, and return. Never null on the success side.
 */
type NormalizedClaims =
  | { reason: EntitlementDenyReason; claims?: undefined }
  | { reason?: undefined; claims: EntitlementClaims };

/**
 * Validate the claim shape AND, on success, capture each field into a single
 * frozen plain-data snapshot in ONE pass.
 *
 * This is the security chokepoint for the whole "claims object is untrusted"
 * class: the caller's `token.claims` may be a proxy or a prototype/accessor
 * object whose getters return DIFFERENT values on repeated reads. If any
 * later step (signing message, window comparison, returned tier) re-read the
 * caller's object, a getter could sign a `community` payload and then hand
 * back `enterprise`, granting a paid tier after a valid signature over a
 * lower one. We read every field EXACTLY ONCE here, into own, non-accessor
 * primitives, and everything downstream uses this snapshot only. The returned
 * record is frozen so no later mutation can reintroduce the class.
 *
 * Does NOT touch the signature; that is checked against the snapshot's
 * canonical message afterward.
 */
function normalizeClaims(claims: unknown): NormalizedClaims {
  if (typeof claims !== "object" || claims === null) {
    return { reason: "malformed" };
  }
  // Read each field exactly once into a local primitive. From here on the
  // caller's object is never consulted again.
  const c = claims as Record<string, unknown>;
  const version = c.version;
  const subject = c.subject;
  const tier = c.tier;
  const notBefore = c.notBefore;
  const notAfter = c.notAfter;

  if (version !== ENTITLEMENT_TOKEN_VERSION) return { reason: "malformed" };
  if (typeof subject !== "string" || subject.length === 0) {
    return { reason: "malformed" };
  }
  if (
    typeof notBefore !== "number" ||
    typeof notAfter !== "number" ||
    !Number.isFinite(notBefore) ||
    !Number.isFinite(notAfter) ||
    notAfter < notBefore
  ) {
    return { reason: "malformed" };
  }
  if (!isEntitlementTier(tier)) return { reason: "unknown_tier" };

  // A frozen own-property plain record: no getters, no prototype surprises,
  // no shared mutable identity with the caller's object.
  const snapshot: EntitlementClaims = Object.freeze({
    version: ENTITLEMENT_TOKEN_VERSION,
    subject,
    tier,
    notBefore,
    notAfter,
  });
  return { claims: snapshot };
}

/**
 * The v2 counterpart of NormalizedClaims: either a deny reason, or a frozen
 * own-property snapshot of the v2 claims (with featureFlags already
 * canonicalized) that is safe to sign-check, window-check, and surface.
 */
type NormalizedClaimsV2 =
  | { reason: EntitlementDenyReason; claims?: undefined }
  | { reason?: undefined; claims: EntitlementClaimsV2 };

/**
 * Validate the v2 claim shape AND capture each field into ONE frozen plain-data
 * snapshot in a single pass  -  the SAME split-view chokepoint as v1's
 * `normalizeClaims`. The caller's `token.claims` is untrusted (may be a proxy
 * or accessor object returning different values on repeated reads); every field
 * is read EXACTLY ONCE here into own, non-accessor primitives, and everything
 * downstream (signing message, window checks, returned enforcement fields) uses
 * this snapshot only. A getter therefore cannot sign one entitledCount/feature
 * set and hand back another.
 *
 * `featureFlags` is canonicalized (sort + dedupe) HERE so the snapshot that
 * feeds the verify message is byte-identical to what the issuer signed.
 * Does NOT touch the signature.
 */
function normalizeClaimsV2(claims: unknown): NormalizedClaimsV2 {
  if (typeof claims !== "object" || claims === null) {
    return { reason: "malformed" };
  }
  const c = claims as Record<string, unknown>;
  // Read every field exactly once. From here on the caller's object is dead.
  const version = c.version;
  const licenseId = c.licenseId;
  const subject = c.subject;
  const tier = c.tier;
  const pricingUnit = c.pricingUnit;
  const entitledCount = c.entitledCount;
  const period = c.period;
  const notBefore = c.notBefore;
  const notAfter = c.notAfter;
  const graceUntil = c.graceUntil;
  const issuer = c.issuer;

  if (version !== ENTITLEMENT_TOKEN_VERSION_V2) return { reason: "malformed" };
  if (typeof licenseId !== "string" || licenseId.length === 0) {
    return { reason: "malformed" };
  }
  if (typeof subject !== "string" || subject.length === 0) {
    return { reason: "malformed" };
  }
  if (typeof issuer !== "string" || issuer.length === 0) {
    return { reason: "malformed" };
  }
  if (pricingUnit !== "node" && pricingUnit !== "seat" && pricingUnit !== "fleet") {
    return { reason: "malformed" };
  }
  if (period !== "monthly" && period !== "annual") {
    return { reason: "malformed" };
  }
  // entitledCount: null (unlimited) OR a finite non-negative integer.
  if (
    entitledCount !== null &&
    (typeof entitledCount !== "number" ||
      !Number.isInteger(entitledCount) ||
      entitledCount < 0)
  ) {
    return { reason: "malformed" };
  }
  if (
    typeof notBefore !== "number" ||
    typeof notAfter !== "number" ||
    !Number.isFinite(notBefore) ||
    !Number.isFinite(notAfter) ||
    notAfter < notBefore
  ) {
    return { reason: "malformed" };
  }
  // graceUntil: null OR a finite number >= notAfter (grace can only extend
  // past expiry, never precede it).
  if (
    graceUntil !== null &&
    (typeof graceUntil !== "number" ||
      !Number.isFinite(graceUntil) ||
      graceUntil < notAfter)
  ) {
    return { reason: "malformed" };
  }
  const canonicalFlags = canonicalizeFeatureFlags(c.featureFlags);
  if (canonicalFlags === null) return { reason: "malformed" };
  if (!isEntitlementTier(tier)) return { reason: "unknown_tier" };

  const snapshot: EntitlementClaimsV2 = Object.freeze({
    version: ENTITLEMENT_TOKEN_VERSION_V2,
    licenseId,
    subject,
    tier,
    pricingUnit,
    entitledCount,
    period,
    notBefore,
    notAfter,
    graceUntil,
    featureFlags: Object.freeze(canonicalFlags) as unknown as string[],
    issuer,
  });
  return { claims: snapshot };
}

/** Build a denied resolution at the community floor. */
function deny(reason: EntitlementDenyReason): EntitlementResolution {
  return { tier: COMMUNITY_TIER, granted: false, reason };
}

/**
 * Strict-decode a base64url signature to 64 bytes, or a deny reason. A lenient
 * decoder would let a malformed/non-canonical signature (trailing "!",
 * whitespace, or "==" padding) decode to the same bytes as a valid one and
 * verify fail-open, so a non-canonical signature string is a `bad_signature`,
 * not a soft malformed. Shared by both version paths.
 */
function decodeSignature(
  raw: string,
): { signature: Uint8Array; reason?: undefined } | { reason: EntitlementDenyReason } {
  let signature: Uint8Array;
  try {
    signature = fromBase64urlStrict(raw);
  } catch {
    return { reason: "bad_signature" };
  }
  if (signature.length !== 64) return { reason: "bad_signature" };
  return { signature };
}

/** Resolve a v1 token: existing verify/window path, byte-stable. */
function resolveV1(
  token: EntitlementToken,
  issuerPublicKey: Uint8Array,
  now: number,
): EntitlementResolution {
  // Normalize ONCE into a frozen own-property snapshot. Every downstream step
  // reads only `claims`, never the caller's possibly-accessor `token.claims`,
  // so a getter cannot sign a low tier and then return a higher one.
  const normalized = normalizeClaims(token.claims);
  if (normalized.reason !== undefined) return deny(normalized.reason);
  const claims = normalized.claims;

  const message = buildEntitlementMessage(claims);
  const decoded = decodeSignature(token.signature);
  if (decoded.reason !== undefined) return deny(decoded.reason);
  if (!verify(message, decoded.signature, issuerPublicKey)) {
    return deny("bad_signature");
  }

  // A non-finite clock (NaN/Infinity/undefined coerced to NaN) makes both
  // window comparisons false, which would let an out-of-window token slip
  // through. Deny before the window checks so the in-window guarantee holds.
  if (!Number.isFinite(now)) return deny("expired");
  if (now < claims.notBefore) return deny("not_yet_valid");
  if (now > claims.notAfter) return deny("expired");

  return { tier: claims.tier, granted: true };
}

/**
 * Resolve a v2 (license) token: normalize → verify → window with grace
 * semantics, then surface the enforcement fields PR-2 reads.
 *
 * Grace semantics (§5c, 14-day default set at issuance):
 *  - within [notBefore, notAfter]           → granted (no graceActive flag)
 *  - within (notAfter, graceUntil]          → granted + graceActive:true
 *  - after graceUntil (or after notAfter when graceUntil is null) → expired
 *  - non-finite clock                       → expired (as v1)
 *
 * resolve does NOT itself decide downgrade (PR-2/PR-3); it only surfaces enough
 * for them to. On ANY failure it strips every enforcement field and returns the
 * community floor  -  a verification bug can only ever REMOVE paid capability.
 */
function resolveV2(
  token: EntitlementToken,
  issuerPublicKey: Uint8Array,
  now: number,
): EntitlementResolution {
  const normalized = normalizeClaimsV2(token.claims);
  if (normalized.reason !== undefined) return deny(normalized.reason);
  const claims = normalized.claims;

  const message = buildEntitlementMessageV2(claims);
  const decoded = decodeSignature(token.signature);
  if (decoded.reason !== undefined) return deny(decoded.reason);
  if (!verify(message, decoded.signature, issuerPublicKey)) {
    return deny("bad_signature");
  }

  if (!Number.isFinite(now)) return deny("expired");
  if (now < claims.notBefore) return deny("not_yet_valid");

  // Past the hard window: honored only if inside a non-null grace window.
  let graceActive = false;
  if (now > claims.notAfter) {
    if (claims.graceUntil === null || now > claims.graceUntil) {
      return deny("expired");
    }
    graceActive = true;
  }

  // Success: surface the signed enforcement fields (all covered by the
  // signature we just verified). featureFlags is returned as a fresh mutable
  // copy of the frozen snapshot so a consumer cannot mutate module state.
  return {
    tier: claims.tier,
    granted: true,
    entitledCount: claims.entitledCount,
    featureFlags: [...claims.featureFlags],
    pricingUnit: claims.pricingUnit,
    period: claims.period,
    graceUntil: claims.graceUntil,
    licenseId: claims.licenseId,
    issuer: claims.issuer,
    ...(graceActive ? { graceActive: true } : {}),
  };
}

/**
 * Verify a token offline against the pinned issuer key and resolve it to a
 * tier. FAIL-CLOSED: on any failure the returned tier is COMMUNITY_TIER and
 * `granted` is false. Never throws; never grants a paid tier on failure.
 *
 * Dispatches on `token.claims.version`: v1 → the original verify path
 * (byte-stable), v2 → the license path with enforcement fields + grace. An
 * unknown/absent version is `malformed` → community. Order of checks within a
 * version is shape first (cheap, no crypto), then signature, then the validity
 * window, so a tampered field is rejected as a bad signature rather than
 * silently altering the resolved tier.
 */
export function resolveEntitlement(
  options: ResolveEntitlementOptions,
): EntitlementResolution {
  try {
    // Read the options bag INSIDE the guarded path. An absent or non-object
    // options argument (undefined/null/primitive) must resolve to the community
    // floor, never throw: `resolveEntitlement` is contracted to never throw and
    // to fail closed. Destructuring before the try would raise a TypeError on
    // `undefined`, escaping the fail-closed contract.
    if (typeof options !== "object" || options === null) {
      return deny("malformed");
    }
    const { token, issuerPublicKey, now } = options;

    if (token === null || token === undefined) return deny("absent");
    if (typeof token !== "object") return deny("malformed");
    if (typeof (token as EntitlementToken).signature !== "string") {
      return deny("malformed");
    }

    // Dispatch on the declared version. Reading `.version` once here only
    // selects the path; each path re-reads and validates every field itself
    // inside its own single-pass normalize (so a mutating getter cannot slip a
    // v1 claims object through the v2 path or vice versa  -  the normalize
    // re-checks `version` against the version constant it expects).
    const claimsView = (token as EntitlementToken).claims;
    const version =
      typeof claimsView === "object" && claimsView !== null
        ? (claimsView as unknown as Record<string, unknown>).version
        : undefined;

    if (version === ENTITLEMENT_TOKEN_VERSION) {
      return resolveV1(token as EntitlementToken, issuerPublicKey, now);
    }
    if (version === ENTITLEMENT_TOKEN_VERSION_V2) {
      return resolveV2(token as EntitlementToken, issuerPublicKey, now);
    }
    return deny("malformed");
  } catch {
    // Any unexpected shape (bad base64url, unencodable claims) is a denial.
    return deny("malformed");
  }
}
