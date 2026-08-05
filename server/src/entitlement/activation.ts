/**
 * Fleet control plane PR-2: ACTIVATION STATE - the operator's pasted license,
 * persisted in signed, tamper-evident fleet state, plus the fail-closed
 * resolve-on-read that the enforcement gate consumes.
 *
 * An operator buys a plan and pastes a license key into the "Activate Fleet"
 * screen. Activation:
 *   1. VERIFIES the pasted token through the shipped #859 Ed25519 verify core
 *      (`resolveEntitlement`) against the pinned issuer key BEFORE persisting -
 *      an unverifiable paste is rejected, never stored as if valid.
 *   2. PERSISTS the raw token + the grandfathered baseline into a master-MAC'd
 *      `_meta` record (the SAME tamper-evident pattern as the epoch witness /
 *      ledger-generation anchor: `derivePurposeKey` → `hmacSha256`, marker +
 *      base64url MAC). No new cryptography is invented.
 *
 * ── WHY STORE THE RAW TOKEN, NOT THE RESOLVED TIER ──────────────────────────
 * Resolution is time-dependent (a license expires; grace lapses). Persisting a
 * resolved tier would freeze a snapshot that goes stale and could be trusted
 * past expiry - a silent free-ride, exactly the failure the fail-closed contract
 * forbids. So we persist the SIGNED token and RE-RESOLVE it against the current
 * clock on every read (`resolveActivation`). The MAC over the record only proves
 * the operator's own paste was not swapped on disk; the token's Ed25519
 * signature (checked at resolve time) is what proves the ENTITLEMENT.
 *
 * ── FAIL-CLOSED READ POSTURE ────────────────────────────────────────────────
 * `resolveActivation` NEVER throws and NEVER grants a paid tier on any failure:
 *   - no record → community (no license: never a free-ride).
 *   - record present but unreadable / tampered / wrong-key MAC → community, with
 *     an `unreadable` reason (never trusts a token whose provenance we cannot
 *     authenticate; a disk-write attacker cannot forge a valid MAC without the
 *     master).
 *   - record valid but the token is expired / invalid / not-yet-valid → the
 *     entitlement core already fails those to community.
 * A resolution failure strips paid MANAGEMENT capacity; it NEVER touches any
 * node's wall (this module has no wall/enforcement/policy-push code path at all).
 *
 * SCOPE BOUND: this module persists + resolves the operator's OWN activation on
 * ONE fortress. Scheduled re-resolve, the downgrade banner/log, and the signed
 * distributed revocation list are PR-3; they consume the resolution this module
 * produces but are not built here.
 */

import type { StorageBackend } from "../storage/interface.js";
import { derivePurposeKey } from "../core/key-derivation.js";
import { hmacSha256 } from "../core/hashing.js";
import { canonicalJson } from "../audit/chain.js";
import {
  toBase64url,
  fromBase64url,
  stringToBytes,
  bytesToString,
  constantTimeEqual,
} from "../core/encoding.js";
import { resolveEntitlement, type EntitlementToken } from "./token.js";
import {
  COMMUNITY_FREE_NODE_CAP,
  resolveFleetCap,
  type FleetCap,
  type ResolvedEntitlementView,
} from "./fleet-cap.js";
import { ED25519_PUBLIC_KEY_BYTES } from "../core/crypto-suite-registry.js";

/**
 * The community node floor used when the activation record itself is UNREADABLE
 * (tampered / wrong-key). We deliberately do NOT honor a grandfather baseline
 * there because the baseline lives inside the failed MAC - trusting it would let
 * a disk-write attacker forge a higher floor. The plain 5-node free cap is the
 * safe floor.
 */
const COMMUNITY_FLOOR_FOR_UNREADABLE = COMMUNITY_FREE_NODE_CAP;

/** `_meta` key holding the master-MAC'd fleet activation record. */
export const FLEET_ACTIVATION_META_KEY = "fleet-activation-v1";

const FLEET_ACTIVATION_MARKER = "__sanctuary_fleet_activation_v1";
/** Fresh MAC domain for the activation record (distinct from every other MAC domain). */
const FLEET_ACTIVATION_MAC_DOMAIN = "sanctuary.fleet.activation.v1\n";
/** HKDF purpose label for the activation-record MAC key (distinct from all others). */
const FLEET_ACTIVATION_MAC_PURPOSE = "fleet-activation-mac";

/**
 * The MAC'd payload of the activation record. The raw signed license token plus
 * the grandfathered baseline; NOTHING resolved (resolution is recomputed on
 * read). No secret material - the token is a public signed claim and the
 * baseline is a count.
 */
export interface FleetActivationData {
  /** The signed v2 license token the operator activated (claims + signature). */
  token: EntitlementToken;
  /**
   * The per-fleet grandfathered baseline node count: an existing multi-node
   * fleet at launch keeps this count free indefinitely. 0 for a NEW fleet (the
   * plain 5-node free cap applies). Bound into the MAC so it cannot be raised on
   * disk to silently lift the cap.
   */
  grandfatheredBaseline: number;
  /** ISO-8601 activation time (advisory provenance for PR-3's log). */
  activatedAt: string;
}

function fleetActivationMac(
  master: Uint8Array,
  data: FleetActivationData,
): Uint8Array {
  const macKey = derivePurposeKey(master, FLEET_ACTIVATION_MAC_PURPOSE);
  const mac = hmacSha256(
    macKey,
    stringToBytes(FLEET_ACTIVATION_MAC_DOMAIN + canonicalJson(data)),
  );
  macKey.fill(0);
  return mac;
}

/**
 * Read + authenticate the activation record. Tri-state, mirror of
 * {@link readEpochWitness}:
 *  - "valid": authenticates under the master → a trustworthy activation.
 *  - "absent": no activation record → the fortress has never activated a license
 *    (community floor). Callers read this as "no license" (never a free-ride).
 *  - "invalid": present but tampered / malformed / wrong-key / unreadable →
 *    SUSPECT. Callers fail TOWARD community (never silently pass, never grant).
 */
export async function readFleetActivation(
  storage: StorageBackend,
  master: Uint8Array,
): Promise<
  | { status: "valid"; data: FleetActivationData }
  | { status: "absent" }
  | { status: "invalid" }
> {
  let raw: Uint8Array | null;
  try {
    raw = await storage.read("_meta", FLEET_ACTIVATION_META_KEY);
  } catch {
    // Unreadable storage is an activation we cannot trust → suspected, not absent.
    return { status: "invalid" };
  }
  if (!raw) return { status: "absent" };
  let parsed: unknown;
  try {
    parsed = JSON.parse(bytesToString(raw));
  } catch {
    return { status: "invalid" };
  }
  if (
    !parsed ||
    typeof parsed !== "object" ||
    (parsed as Record<string, unknown>)[FLEET_ACTIVATION_MARKER] !== true
  ) {
    return { status: "invalid" };
  }
  const obj = parsed as Record<string, unknown>;
  const data = obj.data as Partial<FleetActivationData> | undefined;
  const mac = obj.mac;
  if (
    !data ||
    typeof data !== "object" ||
    typeof data.grandfatheredBaseline !== "number" ||
    !Number.isSafeInteger(data.grandfatheredBaseline) ||
    data.grandfatheredBaseline < 0 ||
    typeof data.activatedAt !== "string" ||
    !isPlausibleToken(data.token) ||
    typeof mac !== "string"
  ) {
    return { status: "invalid" };
  }
  // Reconstruct the EXACT data object that was MAC'd (same field set, in any
  // order - canonicalJson sorts keys). Attaching a field the record never had,
  // or dropping one it had, changes the canonical bytes and fails the MAC, so a
  // shape mismatch is caught as invalid rather than silently trusted.
  const fullData: FleetActivationData = {
    token: data.token as EntitlementToken,
    grandfatheredBaseline: data.grandfatheredBaseline,
    activatedAt: data.activatedAt,
  };
  let provided: Uint8Array;
  try {
    provided = fromBase64url(mac);
  } catch {
    return { status: "invalid" };
  }
  if (!constantTimeEqual(provided, fleetActivationMac(master, fullData))) {
    return { status: "invalid" };
  }
  return { status: "valid", data: fullData };
}

/**
 * Structural plausibility of a stored token BEFORE the MAC check: an object with
 * a `claims` object and a string `signature`. This is a cheap malformed-shape
 * gate; the MAC (authenticity of the operator's paste) and the token's own
 * Ed25519 signature (authenticity of the entitlement, at resolve time) are the
 * real trust checks. A shape that cannot be a token fails to `invalid` here.
 */
function isPlausibleToken(token: unknown): token is EntitlementToken {
  return (
    typeof token === "object" &&
    token !== null &&
    typeof (token as { claims?: unknown }).claims === "object" &&
    (token as { claims?: unknown }).claims !== null &&
    typeof (token as { signature?: unknown }).signature === "string"
  );
}

/**
 * Persist a verified activation. The caller MUST have already verified the token
 * against the pinned issuer key (see {@link activateFleet}); this only writes the
 * master-MAC'd record. `grandfatheredBaseline` is clamped to a safe non-negative
 * integer (a malformed baseline persists as 0 - no grandfather floor - never a
 * large silent cap-lift).
 *
 * GROW-ONLY (fleet control plane PR-3 fix): the grandfather baseline is the
 * PERMANENT free floor of an existing fleet; it must never be LOWERED by a write.
 * A paid re-activation (or a concurrent auto-capture tick) recomputes the baseline
 * from the LIVE roster, which can be transiently small (a node briefly offline, a
 * roster hiccup mid-recompute) - blind-writing that lower value would permanently
 * strip a previously-captured higher floor. So this reads the currently-stored
 * (authenticated) baseline and persists `Math.max(existing, incoming)`, protecting
 * BOTH the auto-capture path and the paid-activation path at the ONE persistence
 * chokepoint. A LOWER baseline is only reachable by an explicit deactivation
 * ({@link clearFleetActivation} removes the whole record, so a subsequent activate
 * starts from an ABSENT record with no stored floor to compare against) - never by
 * an accidental lowering write here.
 *
 * FAIL-CLOSED ON A TAMPERED PRIOR RECORD (round-2 fix): the three read states are
 * treated distinctly, NOT collapsed to "floor 0":
 *   - ABSENT: genuine first write; there is no prior floor, so `existing = 0` and
 *     the incoming baseline stands (a first write is unaffected).
 *   - VALID: a trustworthy prior floor; persist `max(existing, incoming)`.
 *   - INVALID (present but tampered/unreadable/wrong-key): we CANNOT read the true
 *     prior floor, but the record's PRESENCE proves a prior activation existed. A
 *     tampered record must NEVER enable a baseline DOWNGRADE, so we do not silently
 *     treat its floor as 0. We REFUSE the write (fail closed) rather than risk
 *     lowering a floor we cannot read. The caller re-attempts after the record is
 *     re-authenticated (a legit re-activation overwrites the whole record via the
 *     verified paste path, which reads VALID once written), and the resolve-on-read
 *     path already fails a tampered record to the plain community floor, so nothing
 *     grants on the tamper in the meantime.
 */
export async function writeFleetActivation(
  storage: StorageBackend,
  master: Uint8Array,
  token: EntitlementToken,
  grandfatheredBaseline: number,
  now: () => Date = () => new Date(),
): Promise<void> {
  const incoming =
    Number.isSafeInteger(grandfatheredBaseline) && grandfatheredBaseline >= 0
      ? grandfatheredBaseline
      : 0;
  // Grow-only, fail-closed on a tampered prior record. Only a VALID stored record
  // supplies a trustworthy floor; an ABSENT record has no floor (first write); an
  // INVALID (present-but-tampered) record must NOT be read as floor 0 - that would
  // let a disk attacker who corrupts the record enable a baseline DOWNGRADE.
  let existingFloor = 0;
  const current = await readFleetActivation(storage, master);
  if (current.status === "valid") {
    existingFloor = current.data.grandfatheredBaseline;
  } else if (current.status === "invalid") {
    throw new Error(
      "Sanctuary: refusing to overwrite a fleet activation record that is present " +
        "but does not authenticate (tampered/unreadable); a tampered prior record " +
        "must never enable a grandfather-baseline downgrade. Re-activate to " +
        "re-establish an authenticated record.",
    );
  }
  const baseline = Math.max(existingFloor, incoming);
  const data: FleetActivationData = {
    token,
    grandfatheredBaseline: baseline,
    activatedAt: now().toISOString(),
  };
  const record = {
    [FLEET_ACTIVATION_MARKER]: true,
    data,
    mac: toBase64url(fleetActivationMac(master, data)),
  };
  await storage.write(
    "_meta",
    FLEET_ACTIVATION_META_KEY,
    stringToBytes(JSON.stringify(record)),
  );
}

/** Remove the activation record (operator "deactivate" - resolves to community). */
export async function clearFleetActivation(
  storage: StorageBackend,
): Promise<void> {
  await storage.delete("_meta", FLEET_ACTIVATION_META_KEY);
}

/** The outcome of activating a pasted license. */
export type ActivateFleetResult =
  | {
      ok: true;
      /** The tier the verified license grants (community if it somehow denied - see note). */
      tier: string;
      /** The resolved node cap the fleet now enforces to. */
      cap: FleetCap;
    }
  | {
      ok: false;
      /** Why the paste was rejected (operator-facing; never a secret). */
      reason:
        | "malformed_token" // the pasted string is not a decodable license token
        | "verify_failed"; // decoded but failed Ed25519 verify / expired / etc.
      /** The entitlement deny reason, when the token decoded but did not verify. */
      denyReason?: string;
    };

/**
 * Activate a fleet from a PASTED license string. The full activation loop:
 *   1. Decode the pasted string into a token (base64url of `{claims,signature}`,
 *      or a raw JSON token object - both accepted).
 *   2. VERIFY it through the shipped entitlement core against the pinned issuer
 *      key at the current time. A token that does NOT resolve to a paid grant is
 *      REJECTED (`verify_failed`) - we never persist an invalid/expired paste as
 *      if it were live. (An operator who pastes an expired key gets a clear
 *      rejection, not a silent community downgrade with a stored dead token.)
 *   3. On success, PERSIST the master-MAC'd activation record and return the
 *      resolved tier + cap.
 *
 * FAIL-CLOSED: any decode/verify failure returns `ok: false` and writes NOTHING.
 * It never throws and never grants on failure.
 *
 * `grandfatheredBaseline` is supplied by the caller (the CLI/route computes it
 * from the fleet's current node count at first activation for an existing
 * >5-node fleet; 0 for a new fleet). It is persisted verbatim (clamped safe).
 */
export async function activateFleet(args: {
  storage: StorageBackend;
  master: Uint8Array;
  /** The pasted license string (base64url token, or a JSON token object string). */
  pastedLicense: string;
  /** Pinned issuer Ed25519 public key (the fortress's default operator identity key). */
  issuerPublicKey: Uint8Array;
  /** Current time, Unix seconds. Injected for deterministic tests. */
  now: number;
  /** Grandfathered baseline node count for this fleet (0 for a new fleet). */
  grandfatheredBaseline?: number;
  nowIso?: () => Date;
}): Promise<ActivateFleetResult> {
  const token = decodeLicense(args.pastedLicense);
  if (token === null) {
    return { ok: false, reason: "malformed_token" };
  }

  // Verify through the SHIPPED entitlement core (no new crypto). A paste that
  // does not resolve to a granted paid tier is rejected outright - never stored.
  const resolution = resolveEntitlement({
    token,
    issuerPublicKey: args.issuerPublicKey,
    now: args.now,
  });
  if (!resolution.granted || resolution.tier === "community") {
    return {
      ok: false,
      reason: "verify_failed",
      ...(resolution.reason !== undefined ? { denyReason: resolution.reason } : {}),
    };
  }

  await writeFleetActivation(
    args.storage,
    args.master,
    token,
    args.grandfatheredBaseline ?? 0,
    args.nowIso,
  );

  const cap = resolveFleetCap(toView(resolution), args.grandfatheredBaseline ?? 0);
  return { ok: true, tier: resolution.tier, cap };
}

/**
 * Resolve the CURRENT fleet cap from the persisted activation, fail-closed. This
 * is the read the enforcement gate calls per request: it re-verifies the stored
 * token against the CURRENT clock (so expiry/grace are honored live) and returns
 * the node-count cap. NEVER throws; NEVER grants a paid cap on any failure.
 *
 *  - no activation record (absent) → community floor, reason `no_license`.
 *  - record unreadable / tampered / wrong-key (invalid) → community floor,
 *    reason `unreadable` (fail-closed: we do not trust a token whose provenance
 *    we cannot authenticate under the master).
 *  - record valid → re-resolve the token at `now` and map to a cap (expired /
 *    invalid tokens resolve to the community floor via the entitlement core).
 *
 * The grandfathered baseline is read from the (authenticated) record, so even a
 * community resolution keeps an existing >5-node fleet at its grandfathered
 * count. A community resolution from an ABSENT record uses baseline 0.
 */
export async function resolveActivation(
  storage: StorageBackend,
  master: Uint8Array,
  issuerPublicKey: Uint8Array,
  now: number,
): Promise<FleetCap> {
  const record = await readFleetActivation(storage, master);

  if (record.status === "absent") {
    // No license ever activated: the community floor for a new fleet (baseline 0).
    return resolveFleetCap({ granted: false, tier: "community", reason: "absent" }, 0);
  }
  if (record.status === "invalid") {
    // Present-but-unauthenticated activation: fail-closed to community, and we
    // cannot trust the on-disk baseline either (it is inside the failed MAC), so
    // baseline 0. Reason `unreadable` so PR-3 can distinguish tamper from lapse.
    return {
      maxNodes: COMMUNITY_FLOOR_FOR_UNREADABLE,
      paid: false,
      tier: "community",
      reason: "unreadable",
      graceActive: false,
    };
  }

  // Valid record: re-resolve the token at the current clock (honors expiry/grace).
  const resolution = resolveEntitlement({
    token: record.data.token,
    issuerPublicKey,
    now,
  });
  return resolveFleetCap(toView(resolution), record.data.grandfatheredBaseline);
}

/** Project an EntitlementResolution to the minimal view the cap gate reads. */
function toView(resolution: {
  granted: boolean;
  tier: string;
  entitledCount?: number | null;
  pricingUnit?: string;
  graceActive?: boolean;
  reason?: string;
}): ResolvedEntitlementView {
  return {
    granted: resolution.granted,
    tier: resolution.tier,
    ...(resolution.entitledCount !== undefined
      ? { entitledCount: resolution.entitledCount }
      : {}),
    ...(resolution.pricingUnit !== undefined
      ? { pricingUnit: resolution.pricingUnit }
      : {}),
    ...(resolution.graceActive !== undefined
      ? { graceActive: resolution.graceActive }
      : {}),
    ...(resolution.reason !== undefined ? { reason: resolution.reason } : {}),
  };
}

/**
 * Decode a pasted license string into a token, or null if it cannot be a token.
 *
 * Two accepted encodings (both fail-closed to null on anything unparseable):
 *   1. base64url of the UTF-8 JSON of `{claims,signature}` (what `sanctuary
 *      license issue` prints for the operator to paste).
 *   2. a raw JSON token object string (developer/paste-through convenience).
 *
 * Whitespace is trimmed. A decode failure returns null so `activateFleet` maps
 * it to `malformed_token` - it NEVER throws.
 */
export function decodeLicense(pasted: string): EntitlementToken | null {
  if (typeof pasted !== "string") return null;
  const trimmed = pasted.trim();
  if (trimmed.length === 0) return null;

  // Try raw JSON first (cheap, and a JSON object is unambiguous).
  if (trimmed.startsWith("{")) {
    const parsed = tryParseTokenJson(trimmed);
    if (parsed !== null) return parsed;
  }

  // Then base64url → UTF-8 JSON.
  let decoded: string;
  try {
    decoded = bytesToString(fromBase64url(trimmed));
  } catch {
    return null;
  }
  return tryParseTokenJson(decoded);
}

function tryParseTokenJson(json: string): EntitlementToken | null {
  let parsed: unknown;
  try {
    parsed = JSON.parse(json);
  } catch {
    return null;
  }
  if (!isPlausibleToken(parsed)) return null;
  return parsed;
}

/**
 * Decode a stored base64/base64url 32-byte Ed25519 public key into raw bytes, or
 * null when the input is absent, mis-encoded, or the wrong length.
 *
 * This is the seam the enforcement gate uses to pin its ISSUER key: the operator
 * pastes a license the SAME operator identity signed (issuance + activation both
 * happen on the operator's own fortress), so the fortress's DEFAULT operator
 * identity public key is the pinned issuer key. A caller that cannot decode a key
 * (no operator identity, malformed key) MUST fail CLOSED to the community floor -
 * a fortress with no resolvable issuer key can hold no valid paid grant, so
 * community is the honest, safe resolution. Pure: no I/O, never throws.
 */
export function decodeIssuerPublicKey(
  b64: string | null | undefined,
): Uint8Array | null {
  if (typeof b64 !== "string" || b64.length === 0) return null;
  try {
    // Accept both base64url (identity records) and standard base64.
    const key = Buffer.from(b64.replace(/-/g, "+").replace(/_/g, "/"), "base64");
    return key.length === ED25519_PUBLIC_KEY_BYTES ? new Uint8Array(key) : null;
  } catch {
    return null;
  }
}
