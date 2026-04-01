/**
 * Sanctuary MCP Server — Decommissioning Certificate Types
 *
 * A decommissioning certificate is a special variant of the Sovereignty Health Report
 * that cryptographically proves an agent has been properly decommissioned and holds
 * zero active credentials.
 *
 * Use case: RSA 2026 gap #3 — "cannot confirm decommissioned agents hold zero credentials"
 *
 * The certificate is signed by the agent's own Ed25519 key as a final act, proving
 * that the decommissioning was performed by the agent's legitimate operator.
 */

// ── Zero-State Verification Results ──────────────────────────────────────

export interface ZeroStateCheck {
  /** Name of the check (e.g., "identities", "state", "reputation") */
  check_name: string;
  /** Whether this check passed */
  passed: boolean;
  /** Description of what was verified */
  description: string;
  /** Details about the check result */
  details: string;
}

// ── Decommissioning Certificate Body ─────────────────────────────────────

/**
 * The decommissioning certificate body — the content that gets signed.
 * Canonical form: JSON with sorted keys, no whitespace (same as SHR).
 */
export interface DecommissionCertificateBody {
  /** Certificate type identifier */
  cert_type: "decommissioning";
  /** Certificate format version */
  cert_version: "1.0";
  /** Agent's public key (identifies which agent was decommissioned) */
  agent_public_key: string;
  /** Agent's instance ID / DID (if available) */
  agent_instance_id: string;
  /** When the decommissioning was performed (ISO 8601) */
  decommissioned_at: string;
  /** When this certificate was generated (ISO 8601) */
  certificate_issued_at: string;
  /** Zero-state verification results */
  zero_state_checks: ZeroStateCheck[];
  /** Overall result: all checks passed? */
  all_checks_passed: boolean;
  /** SHA-256 hash of the key that was decommissioned (base64url) */
  decommissioned_key_hash: string;
  /** Whether private key material was confirmed zeroed */
  private_key_zeroed: boolean;
  /** Optional human-readable note about the decommissioning reason */
  decommissioning_reason?: string;
}

// ── Signed Certificate ───────────────────────────────────────────────────

/**
 * The complete signed decommissioning certificate — body + signature envelope.
 * Follows the same structure as SHR for compatibility with shared verification tooling.
 */
export interface SignedDecommissionCertificate {
  body: DecommissionCertificateBody;
  /** Public key of the signer (agent's own key as proof of authority) */
  signed_by: string;
  /** Ed25519 signature over canonical body (base64url) */
  signature: string;
}

// ── Verification Result ──────────────────────────────────────────────────

export interface DecommissionVerificationResult {
  valid: boolean;
  errors: string[];
  warnings: string[];
  agent_id: string;
  decommissioned_at: string;
  all_checks_passed: boolean;
}
