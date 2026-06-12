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
import { publicKeyToDid } from "../core/identity.js";
import { fromBase64url } from "../core/encoding.js";
import { FederationRegistry } from "./registry.js";

export function createFederationTools(
  auditLog: AuditLog,
  handshakeResults: Map<string, HandshakeResult>
): { tools: ToolDefinition[]; registry: FederationRegistry } {
  const registry = new FederationRegistry();

  const tools: ToolDefinition[] = [
    // ─── Peer Management ──────────────────────────────────────────────

    {
      name: "federation_peers",
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
            description:
              "Peer DID. Optional: defaults to the did:key derived from the " +
              "public key that signed the handshake SHR. If supplied, it MUST " +
              "match that derived DID — a mismatched label is rejected.",
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

            void auditLog.append("l4", "federation_peers_list", "system", {
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
            });
          }

          case "register": {
            const peerId = args.peer_id as string;
            const suppliedDid = args.peer_did as string | undefined;

            if (!peerId) {
              return toolResult({
                error: "peer_id is required for registration.",
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

            // HS-3 fix part 1: a federation peer may ONLY be bound from a
            // handshake that proved counterparty liveness via the nonce-bearing
            // 4-step protocol. A `handshake_exchange` preview result
            // (liveness_proven:false) can never be promoted to a trusted peer,
            // even if somehow marked verified.
            if (!hsResult.liveness_proven) {
              return toolResult({
                error:
                  `Handshake with "${peerId}" did not prove liveness. ` +
                  "Only a live 4-step handshake (handshake_initiate / respond / " +
                  "complete) can establish a federation peer; a one-shot " +
                  "handshake_exchange preview is not sufficient.",
              });
            }

            // HS-3 fix part 2: bind peer_did to the key that actually signed
            // the handshake SHR. Derive the DID from signed_by; if the caller
            // supplied a DID, it MUST equal the derived one — preventing an
            // arbitrary/impersonating label from being attached to a verified
            // peer.
            let derivedDid: string;
            try {
              const pubKey = fromBase64url(hsResult.counterparty_shr.signed_by);
              derivedDid = publicKeyToDid(pubKey);
            } catch (e) {
              return toolResult({
                error:
                  `Could not derive peer DID from the handshake SHR: ${(e as Error).message}`,
              });
            }

            if (suppliedDid && suppliedDid !== derivedDid) {
              return toolResult({
                error:
                  "peer_did does not match the key that signed the handshake. " +
                  "Omit peer_did to use the derived DID, or supply the correct one.",
              });
            }

            const peerDid = derivedDid;

            const peer = registry.registerFromHandshake(hsResult, peerDid);

            void auditLog.append("l4", "federation_peer_register", "system", {
              peer_id: peerId,
              peer_did: peerDid,
              trust_tier: peer.trust_tier,
            });

            return toolResult({
              registered: true,
              peer_id: peer.peer_id,
              peer_did: peer.peer_did,
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

            void auditLog.append("l4", "federation_peer_remove", "system", {
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
      name: "federation_trust_evaluate",
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

        void auditLog.append("l4", "federation_trust_evaluate", "system", {
          peer_id: peerId,
          trust_level: evaluation.trust_level,
          sovereignty_tier: evaluation.sovereignty_tier,
        });

        return toolResult(evaluation);
      },
    },

    // ─── Federation Status ────────────────────────────────────────────

    {
      name: "federation_status",
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

        void auditLog.append("l4", "federation_status", "system", {
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
