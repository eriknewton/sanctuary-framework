/**
 * Sanctuary MCP Server — Sovereignty Attestation Artifacts
 *
 * Signed, shareable artifacts proving sovereignty verification between agents.
 * Used for one-shot SHR exchanges and as portable proof of handshake completion.
 *
 * An attestation artifact contains:
 *   - Both parties' SHRs
 *   - Verification results (sovereignty level, trust tier)
 *   - Ed25519 signature over the canonical artifact body
 *   - Human-readable summary for social/public posting
 */

import type { SignedSHR } from "../shr/types.js";
import type { SovereigntyLevel, TrustTier } from "./types.js";
import type { SHRVerificationResult } from "../shr/types.js";
import { deepSortKeys } from "../shr/types.js";
import { sign } from "../core/identity.js";
import { toBase64url, stringToBytes } from "../core/encoding.js";
import { derivePurposeKey } from "../core/key-derivation.js";
import type { IdentityManager } from "../l1-cognitive/tools.js";

// ── Attestation Types ───────────────────────────────────────────────

/** Attestation artifact version */
export const ATTESTATION_VERSION = "1.0" as const;

/** The signed body of an attestation artifact */
export interface AttestationBody {
  attestation_version: typeof ATTESTATION_VERSION;
  /** Who generated this attestation */
  attester_id: string;
  /** Who was verified */
  subject_id: string;
  /** Attester's SHR at time of attestation */
  attester_shr: SignedSHR;
  /** Subject's SHR that was verified */
  subject_shr: SignedSHR;
  /** Verification results */
  verification: {
    subject_shr_valid: boolean;
    subject_sovereignty_level: SovereigntyLevel;
    subject_trust_tier: TrustTier;
    /**
     * Whether the subject's liveness was proven (nonce challenge-response).
     * The one-shot exchange path performs NO liveness check, so it is false
     * there; only the 4-step handshake can set it true. A verified trust tier
     * (verified-sovereign / verified-degraded) is only legitimate when this is
     * true — see deriveTrustTier gating below.
     */
    liveness_proven: boolean;
    /** Whether subject also verified attester (mutual exchange) */
    mutual: boolean;
    errors: string[];
    warnings: string[];
  };
  /** When this attestation was generated */
  attested_at: string;
  /** When this attestation expires (min of both SHR expiries) */
  expires_at: string;
}

/** Complete signed attestation artifact */
export interface SignedAttestation {
  body: AttestationBody;
  /** Attester's public key (base64url) */
  signed_by: string;
  /** Ed25519 signature over canonical body (base64url) */
  signature: string;
  /** Human-readable summary for social posting */
  summary: string;
}

// ── Attestation Generation ──────────────────────────────────────────

/** Derive trust tier from sovereignty level */
function deriveTrustTier(level: SovereigntyLevel): TrustTier {
  switch (level) {
    case "full":
      return "verified-sovereign";
    case "degraded":
      return "verified-degraded";
    default:
      return "unverified";
  }
}

export interface AttestationOptions {
  /** Our signed SHR */
  attesterSHR: SignedSHR;
  /** Counterparty's signed SHR */
  subjectSHR: SignedSHR;
  /** Result from verifySHR(subjectSHR) */
  verificationResult: SHRVerificationResult;
  /** Whether this is a mutual exchange (both sides verify) */
  mutual?: boolean;
  /**
   * Whether the subject's liveness was proven via a nonce challenge-response.
   * Defaults to false. When false, the attestation's trust tier is capped at
   * `unverified` regardless of the subject's structural sovereignty level — a
   * structural SHR check alone (e.g. handshake_exchange) can never confer a
   * verified tier, because a captured/forged SHR replays without liveness.
   */
  livenessProven?: boolean;
  /** Identity manager for signing */
  identityManager: IdentityManager;
  /** Master key for key derivation */
  masterKey: Uint8Array;
  /** Identity to sign with (defaults to primary) */
  identityId?: string;
}

/**
 * Generate a signed attestation artifact.
 *
 * The artifact is a portable, verifiable proof that one agent
 * verified another's sovereignty posture. It includes both SHRs,
 * the verification outcome, and a human-readable summary.
 */
export function generateAttestation(
  opts: AttestationOptions
): SignedAttestation | { error: string } {
  const {
    attesterSHR,
    subjectSHR,
    verificationResult,
    mutual = false,
    livenessProven = false,
    identityManager,
    masterKey,
    identityId,
  } = opts;

  // Resolve signing identity
  const identity = identityId
    ? identityManager.get(identityId)
    : identityManager.getDefault();

  if (!identity) {
    return { error: "No identity available for signing attestation" };
  }

  const now = new Date();
  const attesterExpiry = new Date(attesterSHR.body.expires_at);
  const subjectExpiry = new Date(subjectSHR.body.expires_at);
  const earliestExpiry = attesterExpiry < subjectExpiry ? attesterExpiry : subjectExpiry;

  const sovereigntyLevel = verificationResult.valid
    ? (verificationResult.sovereignty_level as SovereigntyLevel)
    : "unverified";

  // A verified trust tier requires proven liveness. Without it, the structural
  // sovereignty level is still reported honestly, but the tier is capped at
  // `unverified` so consumers of the attestation cannot be misled into trusting
  // a counterparty that was never liveness-checked (HIGH#2 fix).
  const trustTier: TrustTier = livenessProven
    ? deriveTrustTier(sovereigntyLevel)
    : "unverified";

  const body: AttestationBody = {
    attestation_version: ATTESTATION_VERSION,
    attester_id: attesterSHR.body.instance_id,
    subject_id: subjectSHR.body.instance_id,
    attester_shr: attesterSHR,
    subject_shr: subjectSHR,
    verification: {
      subject_shr_valid: verificationResult.valid,
      subject_sovereignty_level: sovereigntyLevel,
      subject_trust_tier: trustTier,
      liveness_proven: livenessProven,
      mutual,
      errors: verificationResult.errors,
      warnings: verificationResult.warnings,
    },
    attested_at: now.toISOString(),
    expires_at: earliestExpiry.toISOString(),
  };

  // Canonical serialization for signing
  const canonical = JSON.stringify(deepSortKeys(body));
  const payload = stringToBytes(canonical);

  // Sign with Ed25519
  const encryptionKey = derivePurposeKey(masterKey, "identity-encryption");
  const signatureBytes = sign(
    payload,
    identity.encrypted_private_key,
    encryptionKey
  );

  // Generate human-readable summary
  const summary = generateSummary(body);

  return {
    body,
    signed_by: identity.public_key,
    signature: toBase64url(signatureBytes),
    summary,
  };
}

// ── Human-Readable Summary ──────────────────────────────────────────

function layerLine(label: string, status: string): string {
  const icon = status === "active" ? "\u2713" : status === "degraded" ? "~" : "x";
  return `  ${icon} ${label}: ${status}`;
}

function generateSummary(body: AttestationBody): string {
  const v = body.verification;
  const sLayers = body.subject_shr.body.layers;
  const aLayers = body.attester_shr.body.layers;

  const tierLabel = v.subject_trust_tier === "verified-sovereign"
    ? "Verified Sovereign"
    : v.subject_trust_tier === "verified-degraded"
      ? "Verified (Degraded)"
      : "Unverified";

  const lines: string[] = [
    `--- Sovereignty Attestation ---`,
    ``,
    `Attester: ${body.attester_id.slice(0, 16)}...`,
    `Subject:  ${body.subject_id.slice(0, 16)}...`,
    `Result:   ${tierLabel}`,
    ``,
    `Subject Sovereignty Posture:`,
    layerLine("L1 Cognitive Sovereignty", sLayers.l1.status),
    layerLine("L2 Operational Isolation", sLayers.l2.status),
    layerLine("L3 Selective Disclosure", sLayers.l3.status),
    layerLine("L4 Verifiable Reputation", sLayers.l4.status),
    ``,
    `Attester Sovereignty Posture:`,
    layerLine("L1 Cognitive Sovereignty", aLayers.l1.status),
    layerLine("L2 Operational Isolation", aLayers.l2.status),
    layerLine("L3 Selective Disclosure", aLayers.l3.status),
    layerLine("L4 Verifiable Reputation", aLayers.l4.status),
    ``,
    `Mutual: ${v.mutual ? "Yes" : "One-sided"}`,
    `Attested: ${body.attested_at}`,
    `Expires:  ${body.expires_at}`,
    `Signature: ${body.attestation_version} / Ed25519`,
  ];

  if (v.warnings.length > 0) {
    lines.push(``, `Warnings: ${v.warnings.join("; ")}`);
  }

  if (v.errors.length > 0) {
    lines.push(``, `Errors: ${v.errors.join("; ")}`);
  }

  lines.push(``, `--- Verify: compare signed_by against attester's known public key ---`);

  return lines.join("\n");
}

// ── Attestation Verification ────────────────────────────────────────

import { verify } from "../core/identity.js";
import { fromBase64url } from "../core/encoding.js";

export interface AttestationVerificationResult {
  valid: boolean;
  errors: string[];
  attester_id: string;
  subject_id: string;
  trust_tier: TrustTier;
  expired: boolean;
}

/**
 * Verify a signed attestation artifact.
 *
 * Checks:
 * 1. Signature validity (Ed25519 over canonical body)
 * 2. Temporal validity (not expired)
 * 3. Structural integrity (version, required fields)
 */
export function verifyAttestation(
  attestation: SignedAttestation,
  now?: Date
): AttestationVerificationResult {
  const errors: string[] = [];
  const currentTime = now ?? new Date();

  // 1. Version check
  if (attestation.body.attestation_version !== ATTESTATION_VERSION) {
    errors.push(
      `Unsupported attestation version: ${attestation.body.attestation_version}`
    );
  }

  // 2. Required fields
  if (!attestation.body.attester_id || !attestation.body.subject_id) {
    errors.push("Missing attester_id or subject_id");
  }

  if (!attestation.body.attester_shr || !attestation.body.subject_shr) {
    errors.push("Missing attester or subject SHR");
  }

  // 3. Temporal validity
  const expired = new Date(attestation.body.expires_at) <= currentTime;
  if (expired) {
    errors.push("Attestation has expired");
  }

  // 4. Signature verification
  try {
    const publicKey = fromBase64url(attestation.signed_by);
    const canonical = JSON.stringify(deepSortKeys(attestation.body));
    const payload = stringToBytes(canonical);
    const signatureBytes = fromBase64url(attestation.signature);

    const signatureValid = verify(payload, signatureBytes, publicKey);
    if (!signatureValid) {
      errors.push("Attestation signature is invalid");
    }
  } catch (e: unknown) {
    errors.push(`Signature verification error: ${(e as Error).message}`);
  }

  // Refuse to surface a verified tier unless the signed body explicitly proves
  // liveness. This fails closed for legacy/forged artifacts that lack the field
  // (undefined !== true) and defends against a body that claims a verified tier
  // while admitting liveness_proven:false (HIGH#2 defense in depth).
  const livenessProven =
    attestation.body.verification?.liveness_proven === true;

  return {
    valid: errors.length === 0,
    errors,
    attester_id: attestation.body.attester_id ?? "unknown",
    subject_id: attestation.body.subject_id ?? "unknown",
    trust_tier: errors.length === 0 && livenessProven
      ? attestation.body.verification.subject_trust_tier
      : "unverified",
    expired,
  };
}
