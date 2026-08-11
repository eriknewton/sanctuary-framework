/**
 * Sanctuary MCP Server — SHR Verifier
 *
 * Verifies a counterparty's Sovereignty Health Report:
 * - Signature validity (Ed25519 over canonical body)
 * - Temporal validity (not expired)
 * - Schema completeness
 * - Sovereignty level assessment
 */

import type { SignedSHR, SHRVerificationResult, SHRBody, SHRRotationEvent } from "./types.js";
import { canonicalizeForSigning } from "./types.js";
import { verify, generateIdentityId } from "../core/identity.js";
import { fromBase64url, stringToBytes } from "../core/encoding.js";
import { SIGNATURE_SCHEME_V1 } from "../mesh/constants.js";

/**
 * Upper bound on rotation-chain length. A legitimate identity rotates rarely;
 * a bound keeps an attacker from forcing unbounded verification work with a
 * long crafted chain (each link costs an Ed25519 verify).
 */
const MAX_ROTATION_CHAIN = 64;

/**
 * SHR-FRESH-01 (rule-7, semantic freshness): a valid signature proves who
 * signed the report, not that the posture it describes is still current.
 * `shr_generate`'s `validity_minutes` and a hand-crafted counterparty SHR's
 * `expires_at`/`generated_at` are both signer-controlled, and the ONLY prior
 * temporal check was "has expires_at passed yet" — a signer (honest or
 * hostile) could mint a report that reads verifier-valid for years. These
 * three bounds are the relying-party floor: independent of what the signer
 * declared, a report this old, this long-lived, or this far in the future
 * is rejected here even though its signature checks out. The generator
 * (server/src/shr/generator.ts SHR_MAX_LIFETIME_MS) clamps its own output to
 * the same ceiling; this is the second, independent enforcement that also
 * covers a counterparty SHR this instance never generated.
 */

/**
 * Maximum age (now - generated_at) a relying party accepts. 24h mirrors
 * SHR_MAX_LIFETIME_MS in generator.ts: a report older than the longest
 * lifetime this instance itself would ever sign is stale by the same
 * standard, whether or not its own expires_at has technically passed.
 */
export const SHR_MAX_AGE_MS = 24 * 60 * 60 * 1000;

/**
 * Maximum total declared lifetime (expires_at - generated_at) a relying
 * party accepts, independent of the current time. Must match
 * SHR_MAX_LIFETIME_MS in generator.ts — this is the verify-side pin of the
 * same ceiling, catching an SHR from an unbounded/hostile signer whose
 * generator has no clamp of its own.
 */
export const SHR_MAX_DECLARED_LIFETIME_MS = 24 * 60 * 60 * 1000;

/**
 * Bounded tolerance for benign clock drift on `generated_at` in the future.
 * 5 minutes covers ordinary unsynchronized-clock skew between two hosts;
 * beyond it, a future generated_at is no longer "my clock is a little off"
 * but a signal the report is being back-dated or otherwise malformed, so it
 * becomes a hard failure instead of a warning.
 */
export const SHR_MAX_CLOCK_SKEW_MS = 5 * 60 * 1000;

/**
 * Verify that a key-rotation chain links the identity origin (whose key
 * derives `instanceId`) to `signedBy`. Returns an error string on any failure,
 * or null when the chain is valid.
 *
 * The chain is self-authenticating: every event must be signed by its
 * `old_public_key`, and links forward (event[i].new == event[i+1].old). An
 * attacker cannot forge a chain terminating at a key they control because the
 * first link requires the victim origin key's signature, which they do not
 * hold.
 */
function verifyRotationChain(
  proof: SHRRotationEvent[] | undefined,
  signedBy: string,
  instanceId: string
): string | null {
  if (!Array.isArray(proof) || proof.length === 0) {
    return "instance_id is not bound to signed_by — SHR identity is not self-certifying";
  }
  if (proof.length > MAX_ROTATION_CHAIN) {
    return "key_rotation_proof exceeds the maximum chain length";
  }

  // 1. The origin key must commit to instance_id.
  let originPub: Uint8Array;
  try {
    originPub = fromBase64url(proof[0]!.old_public_key);
  } catch {
    return "key_rotation_proof origin key is malformed";
  }
  if (generateIdentityId(originPub) !== instanceId) {
    return "key_rotation_proof origin key does not derive instance_id";
  }

  // 2. Walk the chain: each event signed by its old key, linking forward, and
  //    referencing the stable instance_id.
  let prevNewKey = proof[0]!.old_public_key;
  for (let i = 0; i < proof.length; i++) {
    const ev = proof[i]!;
    if (ev.old_public_key !== prevNewKey) {
      return "key_rotation_proof chain is not contiguous";
    }
    if (ev.identity_id !== instanceId) {
      return "key_rotation_proof event references a different identity";
    }
    let oldPub: Uint8Array;
    let sig: Uint8Array;
    try {
      oldPub = fromBase64url(ev.old_public_key);
      sig = fromBase64url(ev.signature);
      fromBase64url(ev.new_public_key); // validate encoding
    } catch {
      return "key_rotation_proof contains a malformed event";
    }
    // Reconstruct the signed event data — field order MUST match rotateKeys
    // (core/identity.ts): old_public_key, new_public_key, identity_id, reason,
    // rotated_at.
    const eventData = JSON.stringify({
      old_public_key: ev.old_public_key,
      new_public_key: ev.new_public_key,
      identity_id: ev.identity_id,
      reason: ev.reason,
      rotated_at: ev.rotated_at,
    });
    if (!verify(stringToBytes(eventData), sig, oldPub)) {
      return "key_rotation_proof event signature is invalid";
    }
    prevNewKey = ev.new_public_key;
  }

  // 3. The chain must terminate at the key that signed this SHR.
  if (prevNewKey !== signedBy) {
    return "key_rotation_proof does not terminate at signed_by";
  }

  return null;
}

/**
 * Verify a signed SHR.
 *
 * @param shr - The signed SHR to verify
 * @param now - Optional override for current time (for testing)
 * @returns Verification result with validity, errors, warnings, and sovereignty assessment
 */
export function verifySHR(
  shr: SignedSHR,
  now?: Date
): SHRVerificationResult {
  const errors: string[] = [];
  const warnings: string[] = [];
  const currentTime = now ?? new Date();

  // 1. Schema validation
  if (!shr.body || !shr.signed_by || !shr.signature || !shr.signature_scheme) {
    errors.push("Missing required SHR fields (body, signed_by, signature_scheme, or signature)");
    return {
      valid: false,
      errors,
      warnings,
      sovereignty_level: "minimal",
      counterparty_id: shr.body?.instance_id ?? "unknown",
      expires_at: shr.body?.expires_at ?? "unknown",
    };
  }

  if (shr.body.shr_version !== "1.0") {
    errors.push(`Unsupported SHR version: ${shr.body.shr_version}`);
  }
  if (shr.signature_scheme !== SIGNATURE_SCHEME_V1) {
    errors.push(`Unsupported SHR signature_scheme: ${String(shr.signature_scheme)}`);
  }

  // 2. Temporal validation
  const expiresAt = new Date(shr.body.expires_at);
  if (isNaN(expiresAt.getTime())) {
    errors.push("Invalid expires_at timestamp");
  } else if (currentTime > expiresAt) {
    errors.push(`SHR expired at ${shr.body.expires_at}`);
  }

  const generatedAt = new Date(shr.body.generated_at);
  if (isNaN(generatedAt.getTime())) {
    errors.push("Invalid generated_at timestamp");
  } else {
    const skewMs = generatedAt.getTime() - currentTime.getTime();
    if (skewMs > SHR_MAX_CLOCK_SKEW_MS) {
      // Fail closed (AGENTS.md #5): beyond the bounded skew tolerance, a
      // future generated_at is not benign clock drift — treat it as a
      // hard failure, not a warning, so a back-dated report cannot pass.
      errors.push(
        `SHR generated_at is ${Math.round(skewMs / 1000)}s in the future, exceeding the ${SHR_MAX_CLOCK_SKEW_MS / 1000}s clock-skew tolerance`
      );
    } else if (skewMs > 0) {
      warnings.push("SHR generated_at is in the future — clock skew detected");
    }

    // Relying-party freshness floor: reject an authentic-but-stale report
    // even though its own signature and expiry are technically fine. See
    // the SHR-FRESH-01 comment above MAX_ROTATION_CHAIN for why this check
    // exists independent of the expires_at check above.
    const ageMs = currentTime.getTime() - generatedAt.getTime();
    if (ageMs > SHR_MAX_AGE_MS) {
      errors.push(
        `SHR is ${Math.round(ageMs / (60 * 60 * 1000))}h old, exceeding the maximum relying-party age of ${SHR_MAX_AGE_MS / (60 * 60 * 1000)}h`
      );
    }

    if (!isNaN(expiresAt.getTime())) {
      const declaredLifetimeMs = expiresAt.getTime() - generatedAt.getTime();
      if (declaredLifetimeMs > SHR_MAX_DECLARED_LIFETIME_MS) {
        errors.push(
          `SHR declares a ${Math.round(declaredLifetimeMs / (60 * 60 * 1000))}h lifetime, exceeding the maximum of ${SHR_MAX_DECLARED_LIFETIME_MS / (60 * 60 * 1000)}h`
        );
      }
    }
  }

  // 3. Signature verification
  try {
    const publicKey = fromBase64url(shr.signed_by);
    const signatureBytes = fromBase64url(shr.signature);
    const canonical = canonicalizeForSigning(shr.body);
    const payload = stringToBytes(canonical);

    const signatureValid = verify(payload, signatureBytes, publicKey);
    if (!signatureValid) {
      errors.push("Invalid signature — SHR may have been tampered with");
    }

    // 3a. Identity binding (HS-1 fix): instance_id MUST be the
    // self-certifying commitment to signed_by. instance_id is defined as
    // generateIdentityId(pubkey) = SHA-256(pubkey)[:16] hex (core/identity.ts,
    // shr/generator.ts). A signed-but-self-issued SHR claiming someone
    // else's instance_id therefore fails here: an attacker would need a key
    // whose SHA-256[:16] equals the victim's id (128-bit second preimage).
    //
    // Rotation-aware (HIGH#1 fix): rotateKeys keeps instance_id STABLE while
    // changing the signing key, so a rotated identity's signed_by no longer
    // derives instance_id directly. In that case accept the SHR iff it carries
    // a valid key_rotation_proof chain from the origin key (which DOES derive
    // instance_id) to signed_by. The chain is cryptographically verified, so
    // this does not weaken the forged-peer protection.
    const expectedId = generateIdentityId(publicKey);
    if (expectedId !== shr.body.instance_id) {
      const chainError = verifyRotationChain(
        shr.body.key_rotation_proof,
        shr.signed_by,
        shr.body.instance_id
      );
      if (chainError) {
        errors.push(chainError);
      }
    }
  } catch (e) {
    errors.push(`Signature verification failed: ${(e as Error).message}`);
  }

  // 4. Layer completeness check (fail closed: a missing `layers` object is a
  // malformed SHR, not a pass — guard before dereferencing).
  const { layers } = shr.body;
  if (!layers || !layers.l1 || !layers.l2 || !layers.l3 || !layers.l4) {
    errors.push("Missing one or more layer definitions");
  }

  // 5. Assess sovereignty level
  const sovereigntyLevel = assessSovereigntyLevel(shr.body);

  // 6. Add warnings for degradations
  for (const d of shr.body.degradations ?? []) {
    if (d.severity === "critical") {
      warnings.push(`Critical degradation in ${d.layer}: ${d.description}`);
    }
  }

  return {
    valid: errors.length === 0,
    errors,
    warnings,
    sovereignty_level: sovereigntyLevel,
    counterparty_id: shr.body.instance_id,
    expires_at: shr.body.expires_at,
  };
}

/**
 * Assess the overall sovereignty level from an SHR body.
 */
function assessSovereigntyLevel(
  body: SHRBody
): "full" | "degraded" | "minimal" {
  // Fail closed: a malformed SHR missing any layer cannot assert sovereignty.
  if (
    !body.layers ||
    !body.layers.l1 ||
    !body.layers.l2 ||
    !body.layers.l3 ||
    !body.layers.l4
  ) {
    return "minimal";
  }
  const { l1, l2, l3, l4 } = body.layers;

  // All active = full
  if (
    l1.status === "active" &&
    l2.status === "active" &&
    l3.status === "active" &&
    l4.status === "active"
  ) {
    return "full";
  }

  // L1 must be active for anything above minimal
  if (l1.status !== "active") {
    return "minimal";
  }

  // L1 active but others degraded = degraded
  if (l4.status === "active" || l4.status === "degraded") {
    return "degraded";
  }

  return "minimal";
}
