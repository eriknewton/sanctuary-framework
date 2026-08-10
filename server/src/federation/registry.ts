/**
 * Sanctuary MCP Server — Federation Peer Registry
 *
 * Manages known federation peers. Peers are discovered through handshakes
 * and tracked for ongoing federation operations.
 *
 * The registry is the source of truth for:
 * - Who we've federated with
 * - Current trust status of each peer
 * - Peer capabilities (what operations they support)
 *
 * Security invariants:
 * - Peers are ONLY added through a completed handshake with a counterparty
 *   this fortress does not hold keys for (never self-registration; see
 *   register §Z RECHECK / LD2-02 — the shared handshakeResults map this
 *   registry reads from is kept free of self-vouched entries at the
 *   producer, handshake/tools.ts recordHandshakeResult, and the caller in
 *   federation/tools.ts re-checks identityManager.list() independently)
 * - Trust tiers degrade automatically when handshakes expire
 * - Peer data is stored encrypted under L1 sovereignty
 */

import type { HandshakeResult } from "../handshake/types.js";
import { trustTierToSovereigntyTier } from "../reputation/tiers.js";
import type {
  FederationPeer,
  FederationCapabilities,
  PeerTrustEvaluation,
} from "./types.js";

/** Default capabilities assumed for new peers */
const DEFAULT_CAPABILITIES: FederationCapabilities = {
  reputation_exchange: true,
  mutual_attestation: true,
  encrypted_channel: false,
  attestation_formats: ["sanctuary-interaction-v1"],
};

export class FederationRegistry {
  private peers = new Map<string, FederationPeer>();

  /**
   * Register or update a peer from a completed handshake.
   * This is the ONLY way peers enter the registry, and the caller
   * (federation/tools.ts) refuses a peer_did this fortress holds keys for
   * before this method is ever reached.
   */
  registerFromHandshake(
    result: HandshakeResult,
    peerDid: string,
    capabilities?: Partial<FederationCapabilities>
  ): FederationPeer {
    const existing = this.peers.get(result.counterparty_id);
    const now = new Date().toISOString();

    const peer: FederationPeer = {
      peer_id: result.counterparty_id,
      peer_did: peerDid,
      first_seen: existing?.first_seen ?? now,
      last_handshake: result.completed_at,
      trust_tier: trustTierToSovereigntyTier(result.trust_tier),
      handshake_result: result,
      capabilities: {
        ...DEFAULT_CAPABILITIES,
        ...(existing?.capabilities ?? {}),
        ...(capabilities ?? {}),
      },
      active: result.verified && new Date(result.expires_at) > new Date(),
    };

    // If already expired at registration time, degrade trust tier
    if (!peer.active) {
      peer.trust_tier = "self-attested";
    }

    this.peers.set(result.counterparty_id, peer);
    return peer;
  }

  /**
   * Get a peer by instance ID.
   * Automatically updates active status based on handshake expiry.
   */
  getPeer(peerId: string): FederationPeer | null {
    const peer = this.peers.get(peerId);
    if (!peer) return null;

    // Check if handshake has expired
    if (peer.active && new Date(peer.handshake_result.expires_at) <= new Date()) {
      peer.active = false;
      peer.trust_tier = "self-attested"; // Degrade to self-attested when expired
    }

    return peer;
  }

  /**
   * List all known peers, optionally filtered by status.
   */
  listPeers(filter?: { active_only?: boolean }): FederationPeer[] {
    const peers = Array.from(this.peers.values());

    // Update active status before filtering
    for (const peer of peers) {
      if (peer.active && new Date(peer.handshake_result.expires_at) <= new Date()) {
        peer.active = false;
        peer.trust_tier = "self-attested";
      }
    }

    if (filter?.active_only) {
      return peers.filter((p) => p.active);
    }

    return peers;
  }

  /**
   * Evaluate trust for a federation peer.
   *
   * Trust assessment considers:
   * - Handshake status (current vs expired)
   * - Sovereignty tier (verified-sovereign vs degraded vs unverified)
   * - Reputation data (if available)
   * - Mutual attestation history
   */
  evaluateTrust(
    peerId: string,
    mutualAttestationCount: number = 0,
    reputationScore?: number
  ): PeerTrustEvaluation {
    const peer = this.getPeer(peerId);
    const now = new Date().toISOString();

    if (!peer) {
      return {
        peer_id: peerId,
        sovereignty_tier: "unverified",
        handshake_current: false,
        mutual_attestation_count: 0,
        trust_level: "none",
        factors: ["Peer not found in federation registry"],
        evaluated_at: now,
      };
    }

    const factors: string[] = [];
    let score = 0;

    // Factor 1: Handshake status
    if (peer.active) {
      factors.push("Active handshake (trust current)");
      score += 3;
    } else {
      factors.push("Handshake expired (trust degraded)");
      score += 1;
    }

    // Factor 2: Sovereignty tier
    switch (peer.trust_tier) {
      case "verified-sovereign":
        factors.push("Verified sovereign — full sovereignty posture");
        score += 4;
        break;
      case "verified-degraded":
        factors.push("Verified degraded — sovereignty with known limitations");
        score += 3;
        break;
      case "self-attested":
        factors.push("Self-attested — claims not independently verified");
        score += 1;
        break;
      case "unverified":
        factors.push("Unverified — no sovereignty proof");
        score += 0;
        break;
    }

    // Factor 3: Mutual attestation history
    if (mutualAttestationCount > 10) {
      factors.push(`Strong attestation history (${mutualAttestationCount} mutual attestations)`);
      score += 3;
    } else if (mutualAttestationCount > 0) {
      factors.push(`Some attestation history (${mutualAttestationCount} mutual attestations)`);
      score += 1;
    } else {
      factors.push("No mutual attestation history");
    }

    // Factor 4: Reputation score
    if (reputationScore !== undefined) {
      if (reputationScore >= 80) {
        factors.push(`High reputation score (${reputationScore})`);
        score += 2;
      } else if (reputationScore >= 50) {
        factors.push(`Moderate reputation score (${reputationScore})`);
        score += 1;
      } else {
        factors.push(`Low reputation score (${reputationScore})`);
      }
    }

    // Map score to trust level
    let trust_level: "high" | "medium" | "low" | "none";
    if (score >= 9) trust_level = "high";
    else if (score >= 5) trust_level = "medium";
    else if (score >= 2) trust_level = "low";
    else trust_level = "none";

    return {
      peer_id: peerId,
      sovereignty_tier: peer.trust_tier,
      handshake_current: peer.active,
      reputation_score: reputationScore,
      mutual_attestation_count: mutualAttestationCount,
      trust_level,
      factors,
      evaluated_at: now,
    };
  }

  /**
   * Remove a peer from the registry.
   */
  removePeer(peerId: string): boolean {
    return this.peers.delete(peerId);
  }

  /**
   * Get the handshake results map (for tier resolution integration).
   */
  getHandshakeResults(): Map<string, HandshakeResult> {
    const results = new Map<string, HandshakeResult>();
    for (const [id, peer] of this.peers) {
      if (peer.active) {
        results.set(id, peer.handshake_result);
      }
    }
    return results;
  }
}
