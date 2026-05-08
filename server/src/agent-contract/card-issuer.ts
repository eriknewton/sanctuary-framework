/**
 * Sanctuary Agent Contract v0.1 — Agent Card Issuance + Verification (§3).
 *
 * At launch, the broker issues a signed Agent Card on the mesh `SignedEvent`
 * envelope. The envelope's `event_type` is `agent_card_issued`; the payload
 * is the Agent Card exactly as defined in spec §3.
 *
 * Verification walks the mesh trust chain:
 *   emitter_node (per-node cert) → signing principal → pinned fortress-master
 *
 * Additionally the card itself is structurally validated — unknown keys
 * rejected, every field type-checked, signature_scheme must equal
 * "ed25519-v1" per the crypto-agility hinge.
 *
 * Tampered cards fail either at the mesh envelope layer (signature mismatch)
 * or at the schema layer (missing/malformed field).
 */

import { sha256 } from "@noble/hashes/sha256";
import { toBase64url } from "../core/encoding.js";
import { canonicalizeToBytes } from "../mesh/canonical-json.js";
import {
  packSignedEvent,
  verifySignedEvent,
  type VerifyContext,
} from "../mesh/envelope.js";
import type { SignedEvent } from "../mesh/types.js";
import {
  AGENT_CONTRACT_VERSION,
  SIGNATURE_SCHEME_V1,
  requiredModelProviderFor,
  type AgentContractEventType,
} from "./constants.js";
import { AgentCardSchemaError, AgentCardVerificationError } from "./errors.js";
import { validateAgentCard } from "./schema.js";
import type { AgentCard, AgentCardCapability } from "./types.js";

export const AGENT_CARD_ISSUED_EVENT_TYPE: AgentContractEventType =
  "agent_card_issued";

export interface IssueAgentCardParams {
  agent_id: string;
  fortress_id: string;
  tier: "A" | "B" | "C";
  harness_id: string;
  model_provider: AgentCard["model_provider"];
  model_id: string;
  agent_pubkey: string;
  capabilities: AgentCardCapability[];
  /** Pinned policy at launch — integer version + opaque blob (same bytes the policy engine emitted). */
  policy_version: number;
  policy_blob_bytes: Uint8Array;
  attestation_endpoint: string;
  /** Broker is the emitting node. */
  emitter_node: string;
  /** Principal authoring the issuance — usually the operator's root principal. */
  emitter_principal: string;
  /** Per-node signing key for the envelope. */
  node_private_key: Uint8Array;
  /** Principal signing key for the envelope. Optional; present for v1.x crossing-fortress cards. */
  principal_private_key?: Uint8Array;
  /** Monotonic-per-emitter counter. */
  monotonic_seq: number;
  /** Optional issuance timestamp override (tests). */
  issued_at?: string;
  /** Optional expiry. */
  expires_at?: string;
}

/**
 * Build an Agent Card, validate it against the spec §3 schema, pack it into
 * a mesh SignedEvent envelope, and return both the signed event and the
 * parsed card body.
 *
 * The card itself carries `signature_scheme: "ed25519-v1"` and
 * `schema_version: "0.1"`. The envelope's Ed25519 signatures (node + optional
 * principal) are what verifiers check via `verifyAgentCard`.
 *
 * `policy_version_hash` is SHA-256(canonicalize(policy_blob_bytes)). Callers
 * pass the same bytes the policy engine canonicalized at compile time.
 */
export function issueAgentCard(
  params: IssueAgentCardParams
): { signed_event: SignedEvent<AgentCard>; card: AgentCard } {
  // Enforce per-harness provider pin at issuance, not only at adapter
  // construction. Adapters MAY validate at construction (defense in depth),
  // but the issuance gate is the structural enforcement point. Bypassing
  // an adapter does not bypass this check.
  const requiredProvider = requiredModelProviderFor(params.harness_id);
  if (requiredProvider !== null && params.model_provider !== requiredProvider) {
    throw new AgentCardSchemaError(
      `harness_id="${params.harness_id}" requires model_provider="${requiredProvider}"; got "${params.model_provider}"`
    );
  }
  const issued_at = params.issued_at ?? new Date().toISOString();
  const policy_version_hash = toBase64url(sha256(params.policy_blob_bytes));
  const card: AgentCard = {
    schema_version: AGENT_CONTRACT_VERSION,
    signature_scheme: SIGNATURE_SCHEME_V1,
    agent_id: params.agent_id,
    fortress_id: params.fortress_id,
    tier: params.tier,
    harness_id: params.harness_id,
    model_provider: params.model_provider,
    model_id: params.model_id,
    agent_pubkey: params.agent_pubkey,
    policy_version_hash,
    policy_version: params.policy_version,
    attestation_endpoint: params.attestation_endpoint,
    capabilities: params.capabilities,
    issued_at,
    ...(params.expires_at ? { expires_at: params.expires_at } : {}),
  };
  // Structural validation before we sign — prefer a schema error to a
  // signed-but-malformed card on the wire.
  validateAgentCard(card);
  const signed_event = packSignedEvent<AgentCard>({
    event_type: AGENT_CARD_ISSUED_EVENT_TYPE,
    emitter_node: params.emitter_node,
    emitter_principal: params.emitter_principal,
    fortress_id: params.fortress_id,
    payload: card,
    monotonic_seq: params.monotonic_seq,
    node_private_key: params.node_private_key,
    principal_private_key: params.principal_private_key,
  });
  return { signed_event, card };
}

export interface VerifyAgentCardResult {
  card: AgentCard;
  event: SignedEvent<AgentCard>;
  /** Unknown extension_envelope keys seen — carries forward from mesh verification. */
  unknown_extension_keys: string[];
}

/**
 * Verify an Agent Card SignedEvent. Walks the mesh trust chain (node cert →
 * principal cert → pinned fortress-master) AND validates the card body.
 *
 * Throws:
 * - MeshSignatureError if envelope verification fails (tamper, bad chain, fortress mismatch).
 * - AgentCardSchemaError if the body does not match §3.
 * - AgentCardVerificationError if the event_type is wrong for this path.
 */
export function verifyAgentCard(
  evt: SignedEvent<unknown>,
  ctx: VerifyContext
): VerifyAgentCardResult {
  if (evt.event_type !== AGENT_CARD_ISSUED_EVENT_TYPE) {
    throw new AgentCardVerificationError(
      `expected event_type "${AGENT_CARD_ISSUED_EVENT_TYPE}"; got "${evt.event_type}"`
    );
  }
  const verifyResult = verifySignedEvent(evt as SignedEvent, ctx);
  const card = validateAgentCard(verifyResult.event.payload);
  // Redundant but load-bearing: the envelope fortress_id and card fortress_id
  // MUST agree. The envelope already checks envelope fortress_id against the
  // pinned fortress; the card carries its own fortress_id and a mismatch
  // would let a misconfigured issuer ship a card into the wrong fortress.
  if (card.fortress_id !== verifyResult.event.fortress_id) {
    throw new AgentCardVerificationError(
      `card fortress_id=${card.fortress_id} does not match envelope fortress_id=${verifyResult.event.fortress_id}`
    );
  }
  return {
    card,
    event: verifyResult.event as SignedEvent<AgentCard>,
    unknown_extension_keys: verifyResult.unknown_extension_keys,
  };
}

/**
 * Convenience: compute the policy_version_hash for a given policy blob. The
 * broker and the policy engine both use this so an auditor can recompute the
 * hash from the on-disk policy blob and compare with the Agent Card.
 */
export function computePolicyVersionHash(policy_blob_bytes: Uint8Array): string {
  return toBase64url(sha256(policy_blob_bytes));
}

/**
 * Convenience: compute the canonical hash of an Agent Card for linking into
 * downstream events (usage events, lifecycle events, attestations).
 *
 * Uses mesh canonicalize so the bytes agree with the envelope's
 * payload_hash even in the presence of key-order differences.
 */
export function hashAgentCard(card: AgentCard): string {
  return toBase64url(sha256(canonicalizeToBytes(card)));
}
