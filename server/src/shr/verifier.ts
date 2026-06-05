/**
 * Sanctuary MCP Server — SHR Verifier
 *
 * Verifies a counterparty's Sovereignty Health Report:
 * - Signature validity (Ed25519 over canonical body)
 * - Temporal validity (not expired)
 * - Schema completeness
 * - Sovereignty level assessment
 */

import type { SignedSHR, SHRVerificationResult, SHRBody } from "./types.js";
import { canonicalizeForSigning } from "./types.js";
import { verify, generateIdentityId } from "../core/identity.js";
import { fromBase64url, stringToBytes } from "../core/encoding.js";
import { SIGNATURE_SCHEME_V1 } from "../mesh/constants.js";

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
  } else if (generatedAt > currentTime) {
    warnings.push("SHR generated_at is in the future — clock skew detected");
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
    // shr/generator.ts:261). A signed-but-self-issued SHR claiming someone
    // else's instance_id therefore fails here: an attacker would need a key
    // whose SHA-256[:16] equals the victim's id (128-bit second preimage).
    const expectedId = generateIdentityId(publicKey);
    if (expectedId !== shr.body.instance_id) {
      errors.push(
        "instance_id is not bound to signed_by — SHR identity is not self-certifying"
      );
    }
  } catch (e) {
    errors.push(`Signature verification failed: ${(e as Error).message}`);
  }

  // 4. Layer completeness check
  const { layers } = shr.body;
  if (!layers.l1 || !layers.l2 || !layers.l3 || !layers.l4) {
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
