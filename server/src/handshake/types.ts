/**
 * Sanctuary MCP Server — Sovereignty Handshake Types
 *
 * The sovereignty handshake is a mutual verification protocol between
 * two Sanctuary instances. Each party presents its SHR and proves
 * liveness via nonce challenge-response.
 *
 * Protocol:
 *   A → B: HandshakeChallenge (A's SHR + nonce)
 *   B → A: HandshakeResponse (B's SHR + B's nonce + signature over A's nonce)
 *   A → B: HandshakeCompletion (signature over B's nonce)
 *   Result: Both hold a HandshakeResult with verified counterparty status
 */

import type { SignedSHR } from "../shr/types.js";

/** Trust tier derived from sovereignty handshake */
export type TrustTier =
  | "verified-sovereign"   // Both parties fully sovereign
  | "verified-degraded"    // Verified but with degradations
  | "unverified";          // Handshake failed or not attempted

/** Sovereignty level from SHR assessment */
export type SovereigntyLevel = "full" | "degraded" | "minimal" | "unverified";

/**
 * Step 1: Initiator sends challenge
 */
export interface HandshakeChallenge {
  protocol_version: "1.0";
  shr: SignedSHR;
  nonce: string;            // base64url, 32 random bytes
  initiated_at: string;     // ISO 8601
}

/**
 * Step 2: Responder sends response
 */
export interface HandshakeResponse {
  protocol_version: "1.0";
  shr: SignedSHR;
  responder_nonce: string;            // base64url, 32 random bytes
  initiator_nonce_signature: string;  // Responder signs initiator's nonce
  responded_at: string;               // ISO 8601
}

/**
 * Step 3: Initiator sends completion
 */
export interface HandshakeCompletion {
  protocol_version: "1.0";
  responder_nonce_signature: string;  // Initiator signs responder's nonce
  completed_at: string;               // ISO 8601
}

/**
 * Final result: both parties hold this after a successful handshake
 */
export interface HandshakeResult {
  counterparty_id: string;
  counterparty_shr: SignedSHR;
  verified: boolean;
  sovereignty_level: SovereigntyLevel;
  trust_tier: TrustTier;
  completed_at: string;
  expires_at: string;         // Validity window (from SHR expiry)
  errors: string[];
}

/**
 * In-progress handshake state (stored on initiator side)
 */
export interface HandshakeSession {
  session_id: string;
  role: "initiator" | "responder";
  state: "initiated" | "responded" | "completed" | "failed";
  our_nonce: string;
  their_nonce?: string;
  our_shr: SignedSHR;
  their_shr?: SignedSHR;
  initiated_at: string;
  result?: HandshakeResult;
}
