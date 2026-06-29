/**
 * Sanctuary MCP Server — Signed Release Manifest verification.
 *
 * Sanctuary's product thesis is "do not trust the vendor's update path."
 * The bare npm version notice in `update-check.ts` trusts the registry for
 * BOTH transport and authenticity — a compromised registry (or a MITM) could
 * advise an agent to fetch a malicious "update." This module closes that gap:
 * before any update is advised, an Ed25519-signed release manifest is verified
 * against a PINNED release-signing public key.
 *
 * Trust model:
 *   - The network is trusted for TRANSPORT only (it delivers bytes).
 *   - Authenticity comes from the offline signature check against the pinned
 *     key. The signed body covers the version + per-artifact SHA-256 hashes,
 *     so a verified manifest authenticates exactly what an updater would fetch.
 *   - This is offline-capable: given the manifest bytes, no network is needed
 *     to decide authenticity.
 *
 * Fail-closed (AGENTS.md invariant #5 — never silently degrade): an unsigned,
 * wrong-key, malformed, or tampered manifest yields a REFUSAL. There is no
 * code path where a manifest that does not verify against the pinned key can
 * result in an "update available" advisory.
 *
 * Crypto is NOT hand-rolled: the canonical-JSON-over-the-signed-body and the
 * Ed25519 verify primitive are reused from the same surfaces the operator-
 * signed admin path uses (`canonicalJson` + `core/identity.verify`).
 */

import { canonicalJson } from "./v1/operator-signed.js";
import { fromBase64url, stringToBytes } from "./core/encoding.js";
import { verify } from "./core/identity.js";

/** Domain separator for the release-manifest signature (versioned). */
export const RELEASE_MANIFEST_DOMAIN = "sanctuary.release-manifest.v1";

/** Ed25519 public key length in bytes. */
const ED25519_PUBLIC_KEY_LENGTH = 32;
/** Ed25519 signature length in bytes. */
const ED25519_SIGNATURE_LENGTH = 64;

/**
 * The PINNED Sanctuary release-signing public key, base64url-encoded.
 *
 * PLACEHOLDER-UNTIL-REAL-KEY: this is a build-time placeholder, NOT a
 * production key. The real release-signing key is custodied by the operator
 * (Erik) and the release workflow signs the manifest with its private half;
 * this constant must be replaced with the real public key, and the release
 * pipeline wired to publish a signed manifest, before the signed-update path
 * is enabled in production.
 *
 * SECURITY — why the placeholder is the all-zero key AND why it is explicitly
 * rejected: the all-zero 32-byte value is the Ed25519 identity point. Under
 * noble-curves (and Ed25519 generally) an all-zero signature verifies TRUE
 * against the all-zero key for ANY message (the verification equation
 * collapses to 0 == 0). So an all-zero pinned key is NOT inert — it is a
 * universal-forgery key that would accept an attacker-crafted manifest with a
 * zero signature. `loadPinnedReleaseKey` therefore REJECTS the placeholder
 * (returns null), and `verifyReleaseManifestWithKey` rejects an all-zero key
 * and an all-zero signature as defense-in-depth. Net effect: the gate truly
 * fails closed until a real key is swapped in. Tests exercise the working
 * mechanism with a generated test keypair via `verifyReleaseManifestWithKey`.
 */
export const PINNED_RELEASE_SIGNING_PUBLIC_KEY_B64URL =
  "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

/** True iff every byte of `bytes` is zero (the Ed25519 identity point / a
 * degenerate signature). Used to slam the universal-forgery door shut. */
function isAllZero(bytes: Uint8Array): boolean {
  for (let i = 0; i < bytes.length; i++) {
    if (bytes[i] !== 0) return false;
  }
  return true;
}

/**
 * The signed body of a release manifest. These fields — and ONLY these fields
 * — are covered by the signature (canonical-JSON encoded under the domain
 * separator). Adding a field here is a signed-surface change.
 */
export interface ReleaseManifestBody {
  /** The release version this manifest attests (e.g. "0.4.0"). */
  version: string;
  /**
   * Map of artifact name -> lowercase hex SHA-256 of that artifact's bytes.
   * An updater verifies fetched bytes against these hashes; this module only
   * authenticates that the map itself came from the pinned key.
   */
  artifact_hashes: Record<string, string>;
}

/** The on-the-wire signed release manifest: body plus its detached signature. */
export interface SignedReleaseManifest {
  body: ReleaseManifestBody;
  /** base64url-encoded Ed25519 signature over the canonical signed message. */
  signature: string;
}

/** Outcome of a manifest verification — explicit, never a bare boolean. */
export type ManifestVerificationResult =
  | { ok: true; body: ReleaseManifestBody }
  | { ok: false; reason: ManifestRefusalReason };

/**
 * Why a manifest was refused. Coarse-grained on purpose: callers treat any
 * non-`ok` result as a generic refusal and never advise an update.
 */
export type ManifestRefusalReason =
  | "malformed" // not a well-formed signed-manifest object / bad encoding
  | "bad_signature" // signature did not verify against the provided key
  | "bad_pinned_key"; // the pinned key itself is unusable (length/encoding)

/**
 * Build the exact byte string that is signed for a release manifest:
 *   domain separator || canonical-JSON(body)
 * Canonical JSON (sorted keys, no whitespace) makes the signature independent
 * of property insertion order on either side. Throws on an unencodable body.
 */
export function buildReleaseManifestMessage(
  body: ReleaseManifestBody,
): Uint8Array {
  const domain = stringToBytes(RELEASE_MANIFEST_DOMAIN);
  const payload = stringToBytes(canonicalJson(body));
  const message = new Uint8Array(domain.length + payload.length);
  message.set(domain, 0);
  message.set(payload, domain.length);
  return message;
}

/**
 * Narrow an untrusted value to a well-formed `SignedReleaseManifest`.
 * Returns null on any structural problem (this is the "unsigned" / malformed
 * refusal path — a value missing a signature can never be accepted).
 */
function parseSignedManifest(value: unknown): SignedReleaseManifest | null {
  if (typeof value !== "object" || value === null) return null;
  const obj = value as Record<string, unknown>;

  const signature = obj.signature;
  if (typeof signature !== "string" || signature.length === 0) return null;

  const body = obj.body;
  if (typeof body !== "object" || body === null) return null;
  const b = body as Record<string, unknown>;

  if (typeof b.version !== "string" || b.version.length === 0) return null;

  const hashes = b.artifact_hashes;
  if (typeof hashes !== "object" || hashes === null || Array.isArray(hashes)) {
    return null;
  }
  for (const v of Object.values(hashes as Record<string, unknown>)) {
    if (typeof v !== "string") return null;
  }

  return {
    body: {
      version: b.version,
      artifact_hashes: hashes as Record<string, string>,
    },
    signature,
  };
}

/**
 * Verify an untrusted signed-manifest value against an EXPLICIT public key.
 * This is the testable core: tests pass a generated test keypair's public key;
 * production passes the pinned key (via `verifyReleaseManifest`).
 *
 * Never throws. Any malformed input, bad encoding, wrong key, or tampered body
 * resolves to `{ ok: false, reason }` — fail-closed.
 */
export function verifyReleaseManifestWithKey(
  value: unknown,
  publicKey: Uint8Array,
): ManifestVerificationResult {
  if (publicKey.length !== ED25519_PUBLIC_KEY_LENGTH) {
    return { ok: false, reason: "bad_pinned_key" };
  }
  // Defense-in-depth: the all-zero public key is the curve identity point and
  // is a universal-forgery key (a zero signature verifies against it for any
  // message). Reject it outright so no caller can pass a degenerate key.
  if (isAllZero(publicKey)) {
    return { ok: false, reason: "bad_pinned_key" };
  }

  const manifest = parseSignedManifest(value);
  if (manifest === null) {
    return { ok: false, reason: "malformed" };
  }

  let signature: Uint8Array;
  try {
    signature = fromBase64url(manifest.signature);
  } catch {
    return { ok: false, reason: "malformed" };
  }
  if (signature.length !== ED25519_SIGNATURE_LENGTH) {
    return { ok: false, reason: "malformed" };
  }
  // Defense-in-depth: reject an all-zero signature. It is never a legitimate
  // Ed25519 signature and is the forgery used against an identity-point key.
  if (isAllZero(signature)) {
    return { ok: false, reason: "bad_signature" };
  }

  let message: Uint8Array;
  try {
    message = buildReleaseManifestMessage(manifest.body);
  } catch {
    // Unencodable body (should be unreachable after parse, but fail closed).
    return { ok: false, reason: "malformed" };
  }

  // `verify` (core/identity) wraps noble-curves and never throws.
  if (!verify(message, signature, publicKey)) {
    return { ok: false, reason: "bad_signature" };
  }

  return { ok: true, body: manifest.body };
}

/**
 * Decode the pinned release-signing public key. Returns null if the pinned
 * constant is malformed/unusable, which forces a fail-closed refusal upstream.
 */
export function loadPinnedReleaseKey(): Uint8Array | null {
  try {
    const key = fromBase64url(PINNED_RELEASE_SIGNING_PUBLIC_KEY_B64URL);
    if (key.length !== ED25519_PUBLIC_KEY_LENGTH) return null;
    // CRITICAL: reject the all-zero placeholder. The all-zero key is the
    // Ed25519 identity point and accepts a zero signature for ANY message —
    // a universal forgery. Returning null here makes "fails closed until the
    // real key is swapped in" actually true: the gate refuses with
    // `bad_pinned_key` rather than accepting forged manifests.
    if (isAllZero(key)) return null;
    return key;
  } catch {
    return null;
  }
}

/**
 * Verify an untrusted signed-manifest value against the PINNED production key.
 * Fail-closed: an unusable pinned key, a malformed manifest, a wrong-key or
 * tampered signature all yield `{ ok: false, ... }`.
 */
export function verifyReleaseManifest(
  value: unknown,
): ManifestVerificationResult {
  const pinned = loadPinnedReleaseKey();
  if (pinned === null) {
    return { ok: false, reason: "bad_pinned_key" };
  }
  return verifyReleaseManifestWithKey(value, pinned);
}
