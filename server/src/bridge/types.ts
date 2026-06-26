/**
 * Sanctuary MCP Server — Concordia Bridge: Type Definitions
 *
 * Defines the interface contract between the Concordia negotiation protocol
 * and Sanctuary's sovereignty infrastructure. This is the Sanctuary side of
 * the bridge — when Concordia is present, its `accept` can trigger a
 * Sanctuary commitment for cryptographic binding. When Concordia is absent,
 * these types and tools still function independently.
 *
 * Design principle: the bridge is additive, never required. Sanctuary and
 * Concordia remain non-dependent. These types define the contract Concordia
 * implements against, not a dependency Sanctuary requires.
 */

import type { SovereigntyTier } from "../reputation/tiers.js";

// ─── Concordia Session Metadata ──────────────────────────────────────────
// These types describe the shape of data Concordia sends to Sanctuary
// when binding a negotiation outcome. Concordia is the source of truth
// for negotiation state; Sanctuary is the source of truth for sovereignty.

/**
 * Concordia negotiation outcome — the data Concordia sends when an
 * `accept` triggers a Sanctuary commitment.
 *
 * This type is defined by Sanctuary (the receiver) to specify the
 * contract Concordia must fulfill. Field names align with Concordia's
 * protocol semantics.
 */
export interface ConcordiaOutcome {
  /** Concordia session identifier */
  session_id: string;

  /** Protocol version (e.g., "concordia-v1") */
  protocol_version: string;

  /** DID of the party who proposed the accepted terms */
  proposer_did: string;

  /** DID of the party who accepted */
  acceptor_did: string;

  /** The accepted terms — opaque to Sanctuary, meaningful to Concordia */
  terms: Record<string, unknown>;

  /** SHA-256 hash of the canonical terms serialization (computed by Concordia) */
  terms_hash: string;

  /** Number of rounds in the negotiation (propose/counter cycles) */
  rounds: number;

  /** ISO 8601 timestamp when accept was issued */
  accepted_at: string;

  /** Optional: Concordia session receipt (signed transcript) */
  session_receipt?: string;
}

// ─── Bridge Commitment ───────────────────────────────────────────────────

/**
 * A Sanctuary commitment binding a Concordia negotiation outcome.
 *
 * This is the cryptographic anchor: a SHA-256 commitment over the
 * canonical serialization of the ConcordiaOutcome, plus a Pedersen
 * commitment if ZK proofs are needed (e.g., proving negotiation
 * took ≤ N rounds without revealing exact count).
 */
export interface BridgeCommitment {
  /** Unique bridge commitment identifier */
  bridge_commitment_id: string;

  /** The Concordia session this commitment binds */
  session_id: string;

  /** SHA-256 commitment: hash(canonical_outcome || blinding_factor) */
  sha256_commitment: string;

  /** Blinding factor for the SHA-256 commitment (base64url) */
  blinding_factor: string;

  /** DID of the Sanctuary identity that created this commitment */
  committer_did: string;

  /** Ed25519 signature over the commitment by the committer */
  signature: string;

  /** Optional: Pedersen commitment over the round count (for ZK range proofs) */
  pedersen_commitment?: {
    commitment: string;
    blinding_factor: string;
  };

  /** ISO 8601 timestamp */
  committed_at: string;

  /** Protocol metadata */
  bridge_version: "sanctuary-concordia-bridge-v1";
}

// ─── Bridge Verification ─────────────────────────────────────────────────

/** Result of verifying a bridge commitment against a revealed outcome */
export interface BridgeVerificationResult {
  /** Whether the commitment matches the revealed outcome */
  valid: boolean;

  /** Which checks passed/failed */
  checks: {
    sha256_match: boolean;
    signature_valid: boolean;
    session_id_match: boolean;
    terms_hash_match: boolean;
    pedersen_match?: boolean;
  };

  /** The commitment that was verified */
  bridge_commitment_id: string;

  /** ISO 8601 timestamp of verification */
  verified_at: string;
}

// ─── Bridge Attestation ──────────────────────────────────────────────────

/**
 * A bridge attestation links a Concordia negotiation to Sanctuary's
 * L4 reputation system. When a negotiation completes successfully,
 * both the commitment (L3) and the reputation attestation (L4) are
 * recorded — the commitment proves the terms were agreed, the
 * attestation feeds the sovereignty-weighted reputation score.
 */
export interface BridgeAttestationRequest {
  /** The bridge commitment ID that anchors this attestation */
  bridge_commitment_id: string;

  /** Concordia session ID */
  session_id: string;

  /** DID of the counterparty in the negotiation */
  counterparty_did: string;

  /** Negotiation outcome for reputation scoring */
  outcome_result: "completed" | "partial" | "failed" | "disputed";

  /**
   * Optional self-declared behavioral inputs. bridge_attest stores only the
   * derived negotiation_round_bucket plus bounded declared_* buckets under
   * metric_policy "concordia-bridge-behavioral-v1". Legacy exact metric names
   * and raw deal-term-like keys are rejected on new bridge attestations.
   */
  metrics?: {
    declared_offers_made?: number;
    declared_concession?: number;
    declared_reasoning_provided?: boolean;
    declared_response_time_ms?: number;
  };

  /** Identity to sign the attestation (uses default if omitted) */
  identity_id?: string;
}

/** Result of creating a bridge attestation */
export interface BridgeAttestationResult {
  /** The L4 attestation ID created */
  attestation_id: string;

  /** The bridge commitment ID that anchors it */
  bridge_commitment_id: string;

  /** Concordia session ID */
  session_id: string;

  /** Sovereignty tier applied to the attestation */
  sovereignty_tier: SovereigntyTier;

  /** Privacy-rated metric policy applied to stored bridge metric buckets */
  metric_policy?: "concordia-bridge-behavioral-v1";

  /** ISO 8601 timestamp */
  attested_at: string;
}
