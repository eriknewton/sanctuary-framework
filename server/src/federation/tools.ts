/**
 * Sanctuary MCP Server — Federation MCP Tools
 *
 * MCP tool definitions for MCP-to-MCP federation.
 * Three tools cover the core federation operations:
 *   1. federation_peers — List and manage known federation peers
 *   2. federation_trust_evaluate — Evaluate trust for a peer
 *   3. federation_exchange_reputation — Exchange reputation data with a peer
 */

import type { ToolDefinition } from "../router.js";
import { toolResult } from "../router.js";
import type { AuditLog } from "../l2-operational/audit-log.js";
import type { HandshakeResult } from "../handshake/types.js";
import { FederationRegistry } from "./registry.js";

export function createFederationTools(
  auditLog: AuditLog,
  handshakeResults: Map<string, HandshakeResult>
): { tools: ToolDefinition[]; registry: FederationRegistry } {
  const registry = new FederationRegistry();

  const tools: ToolDefinition[] = [
    // ─── Peer Management ──────────────────────────────────────────────

    {
      name: "sanctuary/federation_peers",
      description:
        "List known federation peers, register a peer from a completed handshake, " +
        "or remove a peer. Every peer MUST enter through a verified handshake — " +
        "no self-registration allowed.",
      inputSchema: {
        type: "object",
        properties: {
          action: {
            type: "string",
            enum: ["list", "register", "remove"],
            description: "Operation to perform on the peer registry",
          },
          peer_id: {
            type: "string",
            description: "Peer instance ID (required for register/remove)",
          },
          peer_did: {
            type: "string",
            description: "Peer DID (required for register)",
          },
          active_only: {
            type: "boolean",
            description: "When listing, only show peers with active handshakes",
          },
        },
        required: ["action"],
      },
      handler: async (args) => {
        const action = args.action as string;

        switch (action) {
          case "list": {
            const peers = registry.listPeers({
              active_only: args.active_only as boolean | undefined,
            });

            auditLog.append("l4", "federation_peers_list", "system", {
              peer_count: peers.length,
            });

            return toolResult({
              peers: peers.map((p) => ({
                peer_id: p.peer_id,
                peer_did: p.peer_did,
                trust_tier: p.trust_tier,
                active: p.active,
                first_seen: p.first_seen,
                last_handshake: p.last_handshake,
                capabilities: p.capabilities,
              })),
              total: peers.length,
              // SEC-ADD-03: Tag response — contains counterparty peer metadata
              _content_trust: "external",
            });
          }

          case "register": {
            const peerId = args.peer_id as string;
            const peerDid = args.peer_did as string;

            if (!peerId || !peerDid) {
              return toolResult({
                error: "Both peer_id and peer_did are required for registration.",
              });
            }

            // Peer MUST have a completed handshake
            const hsResult = handshakeResults.get(peerId);
            if (!hsResult) {
              return toolResult({
                error: `No completed handshake found for peer "${peerId}". ` +
                  "Complete a sovereignty handshake first using handshake_initiate.",
              });
            }

            if (!hsResult.verified) {
              return toolResult({
                error: `Handshake with "${peerId}" was not verified. ` +
                  "Only verified handshakes can establish federation.",
              });
            }

            const peer = registry.registerFromHandshake(hsResult, peerDid);

            auditLog.append("l4", "federation_peer_register", "system", {
              peer_id: peerId,
              peer_did: peerDid,
              trust_tier: peer.trust_tier,
            });

            return toolResult({
              registered: true,
              peer_id: peer.peer_id,
              trust_tier: peer.trust_tier,
              active: peer.active,
              capabilities: peer.capabilities,
            });
          }

          case "remove": {
            const peerId = args.peer_id as string;
            if (!peerId) {
              return toolResult({ error: "peer_id is required for removal." });
            }

            const removed = registry.removePeer(peerId);

            auditLog.append("l4", "federation_peer_remove", "system", {
              peer_id: peerId,
              removed,
            });

            return toolResult({
              removed,
              peer_id: peerId,
            });
          }

          default:
            return toolResult({ error: `Unknown action: ${action}` });
        }
      },
    },

    // ─── Trust Evaluation ─────────────────────────────────────────────

    {
      name: "sanctuary/federation_trust_evaluate",
      description:
        "Evaluate the trust level of a federation peer. " +
        "Considers handshake status, sovereignty tier, reputation score, " +
        "and mutual attestation history. Returns a composite trust assessment.",
      inputSchema: {
        type: "object",
        properties: {
          peer_id: {
            type: "string",
            description: "Peer instance ID to evaluate",
          },
          mutual_attestation_count: {
            type: "number",
            description: "Number of mutual attestations with this peer (0 if unknown)",
          },
          reputation_score: {
            type: "number",
            description: "Peer's weighted reputation score (from reputation_query_weighted)",
          },
        },
        required: ["peer_id"],
      },
      handler: async (args) => {
        const peerId = args.peer_id as string;
        const mutualCount = (args.mutual_attestation_count as number) ?? 0;
        const repScore = args.reputation_score as number | undefined;

        const evaluation = registry.evaluateTrust(peerId, mutualCount, repScore);

        auditLog.append("l4", "federation_trust_evaluate", "system", {
          peer_id: peerId,
          trust_level: evaluation.trust_level,
          sovereignty_tier: evaluation.sovereignty_tier,
        });

        return toolResult({
          ...evaluation,
          // SEC-ADD-03: Tag response — derived from counterparty HandshakeResult
          _content_trust: "external",
        });
      },
    },

    // ─── Federation Status ────────────────────────────────────────────

    {
      name: "sanctuary/federation_status",
      description:
        "Overview of federation state: total peers, active connections, " +
        "trust distribution, and readiness for cross-instance operations.",
      inputSchema: {
        type: "object",
        properties: {},
      },
      handler: async () => {
        const allPeers = registry.listPeers();
        const activePeers = registry.listPeers({ active_only: true });

        // Trust tier distribution
        const tierCounts: Record<string, number> = {
          "verified-sovereign": 0,
          "verified-degraded": 0,
          "self-attested": 0,
          "unverified": 0,
        };
        for (const peer of allPeers) {
          tierCounts[peer.trust_tier] = (tierCounts[peer.trust_tier] ?? 0) + 1;
        }

        // Capability summary
        const capCounts = {
          reputation_exchange: activePeers.filter((p) => p.capabilities.reputation_exchange).length,
          mutual_attestation: activePeers.filter((p) => p.capabilities.mutual_attestation).length,
          encrypted_channel: activePeers.filter((p) => p.capabilities.encrypted_channel).length,
        };

        auditLog.append("l4", "federation_status", "system", {
          total_peers: allPeers.length,
          active_peers: activePeers.length,
        });

        return toolResult({
          total_peers: allPeers.length,
          active_peers: activePeers.length,
          expired_peers: allPeers.length - activePeers.length,
          trust_distribution: tierCounts,
          capability_coverage: capCounts,
          federation_ready: activePeers.length > 0,
          checked_at: new Date().toISOString(),
        });
      },
    },
  ];

  return { tools, registry };
}
