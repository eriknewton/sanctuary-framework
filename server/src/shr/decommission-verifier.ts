/**
 * Sanctuary MCP Server — Decommissioning Certificate Verifier
 *
 * Verifies the validity of a decommissioning certificate:
 * - Signature verification (Ed25519)
 * - Temporal validity
 * - Zero-state check results assessment
 */

import {
  fromBase64url,
  stringToBytes,
} from "../core/encoding.js";
import { verify } from "../core/identity.js";
import { canonicalizeForSigning as canonicalizeSHR } from "./types.js";
import type {
  SignedDecommissionCertificate,
  DecommissionVerificationResult,
} from "./decommission-types.js";

/**
 * Verify a decommissioning certificate.
 *
 * @param cert - The signed decommissioning certificate to verify
 * @param atTime - Optional reference time for temporal checks (default: now)
 * @returns Verification result with validity status and detailed findings
 */
export function verifyDecommissionCertificate(
  cert: SignedDecommissionCertificate,
  atTime?: Date
): DecommissionVerificationResult {
  const errors: string[] = [];
  const warnings: string[] = [];
  const now = atTime || new Date();

  // ── Structural validation
  if (!cert.body || typeof cert.body !== "object") {
    errors.push("Invalid certificate: missing or malformed body");
    return {
      valid: false,
      errors,
      warnings,
      agent_id: "unknown",
      decommissioned_at: "",
      all_checks_passed: false,
    };
  }

  if (
    cert.body.cert_type !== "decommissioning" ||
    cert.body.cert_version !== "1.0"
  ) {
    errors.push(
      `Invalid certificate type: expected decommissioning/1.0, got ${cert.body.cert_type}/${cert.body.cert_version}`
    );
  }

  if (!cert.signed_by || !cert.signature) {
    errors.push("Invalid certificate: missing signature or signer");
  }

  if (!cert.body.agent_public_key) {
    errors.push("Invalid certificate: missing agent public key");
  }

  if (!cert.body.agent_instance_id) {
    errors.push("Invalid certificate: missing agent instance ID");
  }

  if (!cert.body.zero_state_checks || !Array.isArray(cert.body.zero_state_checks)) {
    errors.push("Invalid certificate: missing or malformed zero-state checks");
  }

  // ── Signature verification
  if (errors.length === 0) {
    try {
      // Canonicalize the body for verification
      const canonical = canonicalizeSHR(cert.body);
      const payload = stringToBytes(canonical);

      // Verify signature
      const signatureBytes = fromBase64url(cert.signature);
      const signerPublicKeyBytes = fromBase64url(cert.signed_by);

      const isValid = verify(payload, signatureBytes, signerPublicKeyBytes);

      if (!isValid) {
        errors.push("Signature verification failed: certificate has been tampered with");
      }
    } catch (err) {
      errors.push(
        `Signature verification error: ${err instanceof Error ? err.message : String(err)}`
      );
    }
  }

  // ── Temporal validation
  try {
    const issuedAt = new Date(cert.body.certificate_issued_at);
    if (isNaN(issuedAt.getTime())) {
      errors.push("Invalid certificate timestamp: malformed ISO 8601 date");
    } else if (issuedAt > now) {
      errors.push("Certificate issued in the future (clock skew or tampering)");
    }

    const decomTime = new Date(cert.body.decommissioned_at);
    if (isNaN(decomTime.getTime())) {
      errors.push("Invalid decommissioning time: malformed ISO 8601 date");
    } else if (decomTime > issuedAt) {
      warnings.push("Decommissioning time is after certificate issuance (unusual)");
    }
  } catch (err) {
    errors.push(
      `Temporal validation error: ${err instanceof Error ? err.message : String(err)}`
    );
  }

  // ── Zero-state check assessment
  let allChecksPassed = cert.body.all_checks_passed === true;
  let failedChecks = 0;

  if (cert.body.zero_state_checks && Array.isArray(cert.body.zero_state_checks)) {
    for (const check of cert.body.zero_state_checks) {
      if (check.passed === false) {
        failedChecks++;
        warnings.push(`Zero-state check failed: ${check.check_name} — ${check.details}`);
      }
    }
  }

  if (failedChecks > 0 && allChecksPassed) {
    warnings.push("Certificate claims all checks passed, but found failed checks");
  }

  if (failedChecks > 0) {
    allChecksPassed = false;
  }

  // ── Determine overall validity
  const valid = errors.length === 0;

  return {
    valid,
    errors,
    warnings,
    agent_id: cert.body.agent_instance_id,
    decommissioned_at: cert.body.decommissioned_at,
    all_checks_passed: allChecksPassed,
  };
}
