/**
 * Sanctuary Chat v1.0 — Coordination Peers Gate
 *
 * Enforces agent-initiated chat authorization via the policy engine.
 * An agent MAY initiate a chat message IF its pinned policy includes a
 * `coordination_peers` extension naming the target peer(s).
 *
 * This is a policy EXTENSION (not a new slot). The four canonical slots
 * remain locked per Key 10. The extension mechanism uses the compiled
 * policy's top-level extension surface.
 *
 * WP-MVP-7: spawn prompt §6 (agent-initiated messages).
 */

import type { CompiledPolicy } from "../policy-engine/types.js";
import {
  COORDINATION_PEERS_EXTENSION_KEY,
  CHAT_GATE_REASON_CODES,
  type ChatGateReasonCode,
} from "./constants.js";
import {
  ChatPeerNotAuthorizedError,
  ChatNoCoordinationPeersError,
} from "./errors.js";

// ═══════════════════════════════════════════════════════════════════════
// Types
// ═══════════════════════════════════════════════════════════════════════

export interface ChatGateRequest {
  /** Agent attempting to send a message. */
  agent_id: string;
  /** Target peer (agent_id or principal_id). */
  target_peer: string;
}

export interface ChatGateResult {
  decision: "allow" | "deny";
  reason_code: ChatGateReasonCode;
  explanation: string;
}

// ═══════════════════════════════════════════════════════════════════════
// Gate evaluation
// ═══════════════════════════════════════════════════════════════════════

/**
 * Evaluate whether an agent is authorized to initiate a chat message
 * to the given target peer.
 *
 * Rules:
 * 1. Null policy -> deny (hermetic).
 * 2. Sentinel agents -> deny (Key 11: inward-facing only).
 * 3. No coordination_peers extension -> deny.
 * 4. Target not in coordination_peers list -> deny.
 * 5. Target in list -> allow.
 *
 * Does NOT throw; returns a structured result. The caller decides
 * whether to throw ChatPeerNotAuthorizedError based on the result.
 */
export function evaluateChatGate(
  policy: CompiledPolicy | null,
  request: ChatGateRequest
): ChatGateResult {
  // Rule 1: null policy
  if (!policy) {
    return {
      decision: "deny",
      reason_code: CHAT_GATE_REASON_CODES.CHAT_NO_COORDINATION_PEERS,
      explanation: "no policy pinned; agent-initiated chat denied",
    };
  }

  // Rule 2: sentinel restriction (Key 11)
  if (policy.capabilities.is_sentinel) {
    return {
      decision: "deny",
      reason_code: CHAT_GATE_REASON_CODES.CHAT_SENTINEL_DENIED,
      explanation: "sentinel agents are inward-facing only; chat initiation denied",
    };
  }

  // Rule 3+4: coordination_peers check
  const peers = getCoordinationPeers(policy);
  if (!peers || peers.length === 0) {
    return {
      decision: "deny",
      reason_code: CHAT_GATE_REASON_CODES.CHAT_NO_COORDINATION_PEERS,
      explanation: `agent ${request.agent_id} has no coordination_peers in policy`,
    };
  }

  // Wildcard "*" allows messaging any peer
  if (peers.includes("*") || peers.includes(request.target_peer)) {
    return {
      decision: "allow",
      reason_code: CHAT_GATE_REASON_CODES.CHAT_PEER_AUTHORIZED,
      explanation: `agent ${request.agent_id} authorized to message ${request.target_peer}`,
    };
  }

  // Rule 4: target not in list
  return {
    decision: "deny",
    reason_code: CHAT_GATE_REASON_CODES.CHAT_PEER_NOT_AUTHORIZED,
    explanation: `agent ${request.agent_id} not authorized to message ${request.target_peer} (not in coordination_peers)`,
  };
}

/**
 * Enforce the chat gate. Throws on deny.
 * This is the entry point for the ChatService's send path.
 */
export function enforceCoordinationPeers(
  policy: CompiledPolicy | null,
  request: ChatGateRequest
): void {
  const result = evaluateChatGate(policy, request);
  if (result.decision === "deny") {
    if (result.reason_code === CHAT_GATE_REASON_CODES.CHAT_NO_COORDINATION_PEERS) {
      throw new ChatNoCoordinationPeersError(request.agent_id);
    }
    throw new ChatPeerNotAuthorizedError(request.agent_id, request.target_peer);
  }
}

// ═══════════════════════════════════════════════════════════════════════
// Policy extension extraction
// ═══════════════════════════════════════════════════════════════════════

/**
 * Extract coordination_peers from a compiled policy's extension surface.
 *
 * The compiled policy shape does not currently have a typed `extension` field.
 * This function checks for coordination_peers in the policy object, treating
 * it as a forward-compatible extension that sits alongside the four slots.
 *
 * At v1.0, the coordination_peers field is validated at compile time and
 * frozen in the signed policy blob. Changing it requires a new policy_update.
 */
export function getCoordinationPeers(
  policy: CompiledPolicy
): string[] | undefined {
  // The compiled policy may carry coordination_peers as a top-level extension
  const policyAny = policy as unknown as Record<string, unknown>;
  const peers = policyAny[COORDINATION_PEERS_EXTENSION_KEY];
  if (!peers) return undefined;
  if (!Array.isArray(peers)) return undefined;
  // Validate each entry is a string
  const valid = peers.every((p) => typeof p === "string");
  if (!valid) return undefined;
  return peers as string[];
}

/**
 * Set coordination_peers on a compiled policy (for testing and compilation).
 * Returns a new policy object with the extension added.
 */
export function withCoordinationPeers(
  policy: CompiledPolicy,
  peers: string[]
): CompiledPolicy & { coordination_peers: string[] } {
  return {
    ...policy,
    [COORDINATION_PEERS_EXTENSION_KEY]: peers,
  } as CompiledPolicy & { coordination_peers: string[] };
}
