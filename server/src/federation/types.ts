/**
 * Sanctuary MCP Server — Federation Types
 *
 * MCP-to-MCP federation enables two Sanctuary instances to:
 *   1. Discover each other's capabilities (SIM exchange)
 *   2. Establish mutual trust (sovereignty handshake)
 *   3. Exchange signed reputation attestations
 *   4. Evaluate trust for cross-instance interactions
 *
 * Federation operates as a protocol layer atop the handshake:
 *   Handshake establishes trust → Federation uses that trust for ongoing operations.
 *
 * Key constraint: Federation MUST respect each party's sovereignty.
 * Neither party can compel the other to share data they haven't disclosed
 * via their disclosure policy.
 */

import type { HandshakeResult } from "../handshake/types.js";
import type { SovereigntyTier } from "../reputation/tiers.js";
import type { ReputationBundle } from "../reputation/reputation-store.js";

// ── Federation Peer ─────────────────────────────────────────────────────

/** A known federation peer */
export interface FederationPeer {
  /** The peer's instance ID (from their SHR) */
  peer_id: string;
  /** The peer's DID (identity) */
  peer_did: string;
  /** When this peer was first seen */
  first_seen: string;
  /** When last handshake completed */
  last_handshake: string;
  /** Current trust tier from most recent handshake */
  trust_tier: SovereigntyTier;
  /** Handshake result (for tier resolution) */
  handshake_result: HandshakeResult;
  /** Peer's advertised capabilities (from their SIM) */
  capabilities: FederationCapabilities;
  /** Whether we have a valid (non-expired) handshake */
  active: boolean;
}

/** Capabilities a peer advertises for federation */
export interface FederationCapabilities {
  /** Whether the peer supports reputation exchange */
  reputation_exchange: boolean;
  /** Whether the peer supports mutual attestation */
  mutual_attestation: boolean;
  /** Whether the peer supports encrypted channels */
  encrypted_channel: boolean;
  /** Supported attestation formats */
  attestation_formats: string[];
}

// ── Federation Messages ─────────────────────────────────────────────────

/** Request to exchange reputation with a peer */
export interface ReputationExchangeRequest {
  /** Our instance ID */
  from_instance: string;
  /** Target peer instance ID */
  to_instance: string;
  /** Context filter (optional) */
  context?: string;
  /** Our reputation bundle (signed) */
  bundle: ReputationBundle;
  /** Timestamp */
  requested_at: string;
}

/** Response to a reputation exchange request */
export interface ReputationExchangeResponse {
  /** Whether the exchange was accepted */
  accepted: boolean;
  /** Their reputation bundle (if they chose to share) */
  bundle?: ReputationBundle;
  /** Reason for rejection (if rejected) */
  reason?: string;
  /** Timestamp */
  responded_at: string;
}

/** Mutual attestation — both parties attest to an interaction */
export interface MutualAttestationRequest {
  /** Interaction this attests to */
  interaction_id: string;
  /** Our attestation of the interaction */
  our_attestation: {
    outcome_type: string;
    outcome_result: string;
    metrics: Record<string, number>;
    context: string;
  };
  /** Our sovereignty tier at time of attestation */
  our_tier: SovereigntyTier;
  /** Timestamp */
  requested_at: string;
}

/** Response to a mutual attestation request */
export interface MutualAttestationResponse {
  /** Whether the counterparty agrees with the attestation */
  agreed: boolean;
  /** Their view of the interaction (may differ) */
  their_attestation?: {
    outcome_type: string;
    outcome_result: string;
    metrics: Record<string, number>;
    context: string;
  };
  /** Their sovereignty tier */
  their_tier?: SovereigntyTier;
  /** Dispute details if disagreed */
  dispute_reason?: string;
  /** Timestamp */
  responded_at: string;
}

// ── Trust Evaluation ────────────────────────────────────────────────────

/** Trust evaluation result for a federation peer */
export interface PeerTrustEvaluation {
  peer_id: string;
  /** Current sovereignty tier (from handshake) */
  sovereignty_tier: SovereigntyTier;
  /** Whether handshake is current (not expired) */
  handshake_current: boolean;
  /** Reputation summary (if available) */
  reputation_score?: number;
  /** How many mutual attestations we share */
  mutual_attestation_count: number;
  /** Overall trust assessment */
  trust_level: "high" | "medium" | "low" | "none";
  /** Reasoning for the assessment */
  factors: string[];
  /** Evaluated at */
  evaluated_at: string;
}
