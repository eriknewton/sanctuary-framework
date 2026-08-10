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

import type { AuditLog } from "../operational/audit-log.js";
import type { HandshakeResult } from "../handshake/types.js";
import { trustTierToSovereigntyTier } from "../reputation/tiers.js";
import { BoundedMap, type BoundedMapRefuseReason } from "../core/bounded-map.js";
import type {
  FederationPeer,
  FederationCapabilities,
  PeerTrustEvaluation,
} from "./types.js";

/**
 * `registerFromHandshake`'s result (MUST-FIX 2, fix-round-4 — replaces a
 * plain `FederationPeer | null`). An agent reads the federation tool
 * response to decide how to behave (MCP tool responses are product copy
 * for an agent audience, per AGENTS.md's forward-documentation rule), so
 * collapsing all three `BoundedMap` refusal reasons into a bare `null`
 * hid a real distinction the OPERATOR audit trail already had (via
 * `onRefuse` below): "this identity is flooding" (`origin_quota`), "the
 * registry is genuinely full of active peers" (`capacity`), and "the
 * audit trail itself is unavailable right now, retry" (`audit_unavailable`)
 * are three different things to tell an agent, and only the first two were
 * ever distinguishable from the return value alone. `federation/tools.ts`
 * reads `reason` directly off this result to render the accurate
 * agent-facing message.
 */
export type RegisterPeerResult =
  | { ok: true; peer: FederationPeer }
  | { ok: false; reason: BoundedMapRefuseReason };

/** Default capabilities assumed for new peers */
const DEFAULT_CAPABILITIES: FederationCapabilities = {
  reputation_exchange: true,
  mutual_attestation: true,
  encrypted_channel: false,
  attestation_formats: ["sanctuary-interaction-v1"],
};

/**
 * Hard cap on registered peers (register LD2-04): `federation_peers` register
 * is Tier-3 auto-allowed, and the only gate before a completed handshake
 * becomes a durable registry entry is the self-vouch check — an agent that
 * mints many keypairs and completes a real (attacker-reachable, if costlier
 * than a preview) 4-step handshake with each one can otherwise register
 * without limit; `getPeer`/`listPeers` only ever MUTATE an expired peer to
 * `active:false`, they never delete, so nothing ages entries out on its own.
 * 500 mirrors handshake/tools.ts's MAX_HANDSHAKE_RESULTS order of magnitude:
 * generous for a real federation topology, small enough to bound worst-case
 * memory and keep the saturation-refusal path reachable in an adversarial
 * test without an impractically long loop.
 */
export const MAX_FEDERATION_PEERS = 500;

/**
 * Per-origin quota for `peers` (AGENTS.md rule 8, MUST-FIX 1/2 RECHECK —
 * HIGH gate finding, TWICE: the first cut had no per-origin quota at all;
 * fix-round-1's quota keyed on the LOCAL identity that recorded the
 * underlying handshake result, which a caller can multiply at will via
 * `identity_create` (Tier 3 always-allow) — mint N identities, complete N
 * real 4-step handshakes, register N peers, and the "per-origin" quota
 * never engages). The ORIGIN of a peer is now the AGENT-SESSION PRINCIPAL
 * that recorded the VERIFIED handshake result CURRENTLY on file for this
 * counterparty (`handshake/tools.ts`'s `handshakeResultWriterOrigins`,
 * REQUIRED — not optional — through `federation/tools.ts`'s register
 * handler; see that parameter's doc for why optional was itself the
 * MUST-FIX 2 defect, and for why fix-round-3 reads the WRITER map rather
 * than `handshakeResults`'s own first-writer allocation origin). An
 * attacker who completes MAX_FEDERATION_PEERS real 4-step handshakes,
 * however many local identities they spread the flood across, still
 * exhausts only THEIR OWN session's quota and is REFUSED there — never
 * evicts an active peer, and never touches a DIFFERENT session's headroom.
 * 50 = 1/10th of MAX_FEDERATION_PEERS, matching
 * MAX_HANDSHAKE_SESSIONS_PER_ORIGIN / MAX_HANDSHAKE_RESULTS_PER_ORIGIN's
 * ratio: generous per-session headroom while guaranteeing at least 10
 * distinct agent sessions' worth of peers fit before any one session could
 * threaten the shared ceiling. `origin` is REQUIRED on
 * `registerFromHandshake` (MUST-FIX 2: an omitted origin must never mean
 * "skip the quota") — every production and test call site must supply one;
 * a caller with no real session context uses `AGENT_UNKNOWN_ORIGIN`
 * (handshake/tools.ts), which is itself quota-bounded, never an escape
 * hatch.
 */
export const MAX_FEDERATION_PEERS_PER_ORIGIN = 50;

/**
 * Is `peer` active RIGHT NOW, accounting for handshake expiry the lazy
 * getPeer/listPeers mutation hasn't caught up to yet? Shared by getPeer,
 * listPeers, and the eviction selector below so all three agree on what
 * "active" means at the instant they're called, rather than three
 * independently-maintained copies of the same expiry check drifting apart.
 */
function isPeerCurrentlyActive(peer: FederationPeer, now: Date): boolean {
  return peer.active && new Date(peer.handshake_result.expires_at) > now;
}

export class FederationRegistry {
  private readonly peers: BoundedMap<string, FederationPeer>;
  private readonly auditLog: AuditLog;

  constructor(auditLog: AuditLog) {
    this.auditLog = auditLog;
    this.peers = new BoundedMap<string, FederationPeer>({
      maxSize: MAX_FEDERATION_PEERS,
      maxPerOrigin: MAX_FEDERATION_PEERS_PER_ORIGIN,
      selectEviction: (entries) => {
        const now = new Date();
        let oldestInactiveKey: string | undefined;
        let oldestInactiveFirstSeen = "";
        for (const [key, peer] of entries) {
          if (isPeerCurrentlyActive(peer, now)) continue;
          if (
            oldestInactiveKey === undefined ||
            peer.first_seen < oldestInactiveFirstSeen
          ) {
            oldestInactiveKey = key;
            oldestInactiveFirstSeen = peer.first_seen;
          }
        }
        if (oldestInactiveKey === undefined) {
          // Every slot holds a currently-ACTIVE peer: refuse rather than
          // evict one to admit a new registration. An active peer is never
          // evicted to admit a new one, or registration becomes a
          // peer-flush primitive — an attacker who can complete handshakes
          // could otherwise evict a real, trusted peer just by registering
          // enough new ones.
          return { refuse: true };
        }
        return { evict: oldestInactiveKey };
      },
      onEvict: async (evictedPeerId, evictedPeer) => {
        // AWAITED + CRITICAL (MUST-FIX 6, fix-round-2 RECHECK): evicting a
        // peer drops its trust state; BoundedMap.set() awaits this and
        // ABORTS the eviction (refuses the new registration) if the durable
        // write fails, rather than deleting a peer with no audit record of
        // why. See bounded-map.ts's onEvict doc / handshake/tools.ts's
        // sessions/handshakeResults onEvict for the same pattern.
        await this.auditLog.appendCritical({
          layer: "l4",
          operation: "federation_peer_evicted",
          identity_id: "system",
          result: "success",
          details: {
            peer_id: evictedPeerId,
            peer_did: evictedPeer.peer_did,
            reason: "capacity",
          },
        });
      },
      onRefuse: (incomingPeerId, _incomingPeer, reason) => {
        // Three DISTINCT reasons (MUST-FIX 3, fix-round-3 — `capacity` and
        // `audit_unavailable` used to collapse to the same "saturated"
        // audit op, hiding "the audit trail is down" behind "the registry
        // is genuinely full of active peers" from an operator diagnosing
        // the refusal).
        const op =
          reason === "origin_quota"
            ? "federation_registry_origin_quota_exceeded"
            : reason === "audit_unavailable"
              ? "federation_registry_audit_unavailable"
              : "federation_registry_saturated";
        void this.auditLog.append(
          "l4",
          op,
          "system",
          { peer_id: incomingPeerId },
          "failure"
        );
      },
    });
  }

  /**
   * Register or update a peer from a completed handshake.
   * This is the ONLY way peers enter the registry, and the caller
   * (federation/tools.ts) refuses a peer_did this fortress holds keys for
   * before this method is ever reached.
   *
   * Returns `{ ok: false, reason }` when the registration was refused
   * (MUST-FIX 2, fix-round-4 — widened from a bare `FederationPeer | null`;
   * see `RegisterPeerResult`'s doc for why the caller needs the typed
   * reason, not just a refusal signal). `reason` is exactly
   * `BoundedMap`'s own `BoundedMapRefuseReason`: `origin_quota` (this
   * `origin`'s own quota is exhausted), `capacity` (the shared registry is
   * at capacity and every existing slot holds a currently-active peer —
   * see the eviction policy above), or `audit_unavailable` (a
   * global-capacity eviction was decided but its durable audit write did
   * not complete — rare, and distinct from a genuine capacity refusal: an
   * operator retrying the SAME registration once the audit trail recovers
   * should not be told "the registry is full"). The caller must surface
   * this as an explicit refusal, never treat it as a silent no-op success.
   *
   * `origin` is REQUIRED (MUST-FIX 2, fix-round-2 RECHECK — was optional;
   * see MAX_FEDERATION_PEERS_PER_ORIGIN's doc for why "omit it and the quota
   * is silently skipped" was itself the defect): the agent-session
   * principal that recorded the underlying handshake result. A caller with
   * no real session context passes `AGENT_UNKNOWN_ORIGIN`
   * (handshake/tools.ts) explicitly — that bucket is itself quota-bounded,
   * never an unaccounted escape hatch.
   *
   * ASYNC (MUST-FIX 6): `this.peers.set()` is async (see bounded-map.ts) so
   * a global-capacity eviction can durably audit BEFORE the delete.
   */
  async registerFromHandshake(
    result: HandshakeResult,
    peerDid: string,
    capabilities: Partial<FederationCapabilities> | undefined,
    origin: string
  ): Promise<RegisterPeerResult> {
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

    const setResult = await this.peers.set(result.counterparty_id, peer, origin);
    return setResult.ok ? { ok: true, peer } : { ok: false, reason: setResult.reason };
  }

  /**
   * Get a peer by instance ID.
   * Automatically updates active status based on handshake expiry.
   */
  getPeer(peerId: string): FederationPeer | null {
    const peer = this.peers.get(peerId);
    if (!peer) return null;

    // Check if handshake has expired
    if (!isPeerCurrentlyActive(peer, new Date())) {
      peer.active = false;
      peer.trust_tier = "self-attested"; // Degrade to self-attested when expired
    }

    return peer;
  }

  /**
   * List all known peers, optionally filtered by status.
   *
   * BOUNDED (register LD2-04, AGENTS.md rule 8(d)): `boundedList` reads at
   * most MAX_FEDERATION_PEERS entries — the registry's own hard cap — so
   * this can never do unbounded work regardless of how many peers a caller
   * has registered; it's the same bound `Array.from(this.peers.values())`
   * had implicitly (the underlying map is itself capped), made explicit via
   * the primitive built for it rather than materializing through a bare
   * Map method.
   */
  listPeers(filter?: { active_only?: boolean }): FederationPeer[] {
    const peers = this.peers.boundedList(MAX_FEDERATION_PEERS);
    const now = new Date();

    // Update active status before filtering
    for (const peer of peers) {
      if (!isPeerCurrentlyActive(peer, now)) {
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

  /** How many peers `origin` currently holds — used by federation/tools.ts
   * to pick the right refusal message (origin-quota vs global-capacity)
   * BEFORE calling registerFromHandshake, since that method only returns
   * null on refusal without saying why. */
  peerOriginSize(origin: string): number {
    return this.peers.originSize(origin);
  }

  /** The per-origin quota this registry enforces (MAX_FEDERATION_PEERS_PER_ORIGIN). */
  maxPeersPerOrigin(): number {
    return MAX_FEDERATION_PEERS_PER_ORIGIN;
  }

  /**
   * Get the handshake results map (for tier resolution integration).
   */
  getHandshakeResults(): Map<string, HandshakeResult> {
    const results = new Map<string, HandshakeResult>();
    for (const [id, peer] of this.peers.entries()) {
      if (peer.active) {
        results.set(id, peer.handshake_result);
      }
    }
    return results;
  }
}
