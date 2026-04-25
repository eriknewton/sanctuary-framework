/**
 * Sanctuary v1.1 Coordination — Signing helpers.
 *
 * Two-layer signing per `server/src/contracts/v1.1/handoff-records.ts`:
 *
 *   Layer 1 (`LocalHandoffRecord.signature`): sender agent signs a canonical-
 *   JSON encoding of every record field except `signature` itself. The
 *   `signature_scheme` field is INCLUDED in the signed bytes so the scheme
 *   cannot be substituted independently of the signature.
 *
 *   Layer 2 (`LocalHandoffAuditPayload.actor_signature`): the actor (sender,
 *   recipient, or policy gate) signs a canonical-JSON encoding of every
 *   payload field except `actor_signature`. Same scheme-inside-signed-bytes
 *   rule.
 *
 * We delegate canonical-JSON to the mesh module's already-shipped
 * `canonicalize()` (also used by the policy-engine envelope and bridge).
 * That canonicalizer is the documented byte-stable surface for every
 * signature in Sanctuary; reusing it keeps signature determinism aligned
 * across modules.
 */

import { ed25519 } from "@noble/curves/ed25519";
import { fromBase64url, toBase64url } from "../core/encoding.js";
import { canonicalizeToBytes } from "../mesh/canonical-json.js";
import {
  SIGNATURE_SCHEME_V1,
  type SignatureScheme,
} from "../contracts/v1.1/constants.js";
import type {
  LocalHandoffAuditPayload,
  LocalHandoffRecord,
} from "../contracts/v1.1/handoff-records.js";
import { HandoffSignatureError } from "./errors.js";

/**
 * Caller-supplied signer. The coordination module never holds raw private
 * keys — it accepts a function that produces a signature byte-vector for a
 * given canonical-JSON payload. Production callers wrap their identity store
 * (encrypted-private-key + master-key + `core/identity.sign`); tests can
 * pass raw Ed25519 keys directly.
 */
export interface CoordinationSigner {
  /** Identity id of the signer. Embedded as `actor_id` for audit payloads. */
  identity_id: string;
  /** Public key for downstream verification. */
  publicKey: Uint8Array;
  /** Sign a canonical-JSON byte-vector. MUST return a 64-byte Ed25519 signature. */
  sign(payload: Uint8Array): Uint8Array;
}

/**
 * Public-key resolver. Verification needs the public key for an `actor_id`
 * (agent or operator). Coordination keeps verification decoupled from any
 * particular registry by accepting an injected resolver.
 */
export interface CoordinationKeyResolver {
  /** Resolve an agent's signing public key, or undefined if unknown. */
  lookupAgentPublicKey(agent_id: string): Uint8Array | undefined;
  /** Resolve an operator identity's signing public key, or undefined if unknown. */
  lookupOperatorPublicKey(identity_id: string): Uint8Array | undefined;
}

/** Reject any scheme other than the v1.1-supported set. */
export function assertSupportedSignatureScheme(
  scheme: SignatureScheme,
): asserts scheme is typeof SIGNATURE_SCHEME_V1 {
  if (scheme !== SIGNATURE_SCHEME_V1) {
    throw new HandoffSignatureError(
      `unsupported signature_scheme '${scheme as string}'; v1.1 accepts only '${SIGNATURE_SCHEME_V1}'`,
    );
  }
}

// ── Layer 1: LocalHandoffRecord ─────────────────────────────────────────────

/**
 * Build the canonical-JSON byte-vector that constitutes the Layer 1 signed
 * payload for a `LocalHandoffRecord`. The shape is the record minus the
 * `signature` field. `signature_scheme` is INCLUDED so the scheme cannot be
 * swapped post-signature.
 */
export function canonicalLayer1Bytes(
  record: Omit<LocalHandoffRecord, "signature">,
): Uint8Array {
  return canonicalizeToBytes(record);
}

/**
 * Produce a signed `LocalHandoffRecord` from its unsigned shape. Fills the
 * `signature` field; everything else (including `signature_scheme`) MUST be
 * present and final on the input — once signed, even cosmetic mutation
 * invalidates the signature.
 */
export function signHandoffRecord(
  unsigned: Omit<LocalHandoffRecord, "signature">,
  signer: CoordinationSigner,
): LocalHandoffRecord {
  assertSupportedSignatureScheme(unsigned.signature_scheme);
  const signature = signer.sign(canonicalLayer1Bytes(unsigned));
  return { ...unsigned, signature: toBase64url(signature) };
}

/**
 * Verify the Layer 1 signature on a `LocalHandoffRecord` against the sender
 * agent's public key. Rejects unknown schemes.
 *
 * Returns true only when scheme is v1-supported and the signature checks.
 */
export function verifyHandoffRecord(
  record: LocalHandoffRecord,
  resolver: CoordinationKeyResolver,
): boolean {
  if (record.signature_scheme !== SIGNATURE_SCHEME_V1) return false;
  const senderPubkey = resolver.lookupAgentPublicKey(record.sender_agent_id);
  if (!senderPubkey) return false;
  const { signature, ...withoutSig } = record;
  void signature;
  let sigBytes: Uint8Array;
  try {
    sigBytes = fromBase64url(record.signature);
  } catch {
    return false;
  }
  try {
    return ed25519.verify(
      sigBytes,
      canonicalLayer1Bytes(withoutSig),
      senderPubkey,
    );
  } catch {
    return false;
  }
}

// ── Layer 2: LocalHandoffAuditPayload ───────────────────────────────────────

/**
 * Build the canonical-JSON byte-vector that constitutes the Layer 2 signed
 * payload. Same rule as Layer 1: payload minus `actor_signature`; scheme
 * field is included.
 */
export function canonicalLayer2Bytes(
  payload: Omit<LocalHandoffAuditPayload, "actor_signature">,
): Uint8Array {
  return canonicalizeToBytes(payload);
}

/**
 * Sign a `LocalHandoffAuditPayload`. The actor's `identity_id` is taken from
 * the signer; callers MUST ensure it matches the per-transition signer rule
 * documented on the contract:
 *
 *   created   → sender_agent_id
 *   accepted  → recipient_agent_id
 *   denied    → recipient_agent_id OR identity_id (operator policy gate)
 *   completed → recipient_agent_id
 *   failed    → sender_agent_id OR recipient_agent_id
 */
export function signAuditPayload(
  unsigned: Omit<LocalHandoffAuditPayload, "actor_signature">,
  signer: CoordinationSigner,
): LocalHandoffAuditPayload {
  assertSupportedSignatureScheme(unsigned.signature_scheme);
  const signature = signer.sign(canonicalLayer2Bytes(unsigned));
  return { ...unsigned, actor_signature: toBase64url(signature) };
}

/**
 * Verify the actor signature on a `LocalHandoffAuditPayload`. Looks up the
 * actor's public key per `actor_role`:
 *
 *   sender / recipient → agent_id resolver
 *   policy_gate        → operator identity_id resolver
 */
export function verifyAuditPayload(
  payload: LocalHandoffAuditPayload,
  resolver: CoordinationKeyResolver,
): boolean {
  if (payload.signature_scheme !== SIGNATURE_SCHEME_V1) return false;
  let actorPubkey: Uint8Array | undefined;
  switch (payload.actor_role) {
    case "sender":
    case "recipient":
      actorPubkey = resolver.lookupAgentPublicKey(payload.actor_id);
      break;
    case "policy_gate":
      actorPubkey = resolver.lookupOperatorPublicKey(payload.actor_id);
      break;
  }
  if (!actorPubkey) return false;
  const { actor_signature, ...withoutSig } = payload;
  void actor_signature;
  let sigBytes: Uint8Array;
  try {
    sigBytes = fromBase64url(payload.actor_signature);
  } catch {
    return false;
  }
  try {
    return ed25519.verify(
      sigBytes,
      canonicalLayer2Bytes(withoutSig),
      actorPubkey,
    );
  } catch {
    return false;
  }
}
