/**
 * Recovery Cascade -- recovery event packing and verification.
 *
 * `packRecoveryEvent` is a sibling to `packSignedEvent` from WP-MVP-3.
 * It produces the same envelope shape for recovery-specific event types.
 *
 * Acceptance criterion 5: recovery events use signed envelope with
 * `signature_scheme = 'ed25519-v1'` mandatory.
 */

import { ed25519 } from "@noble/curves/ed25519";
import { sha256 } from "@noble/hashes/sha256";
import { fromBase64url, toBase64url } from "../core/encoding.js";
import { randomBytes } from "../core/random.js";
import { canonicalizeToBytes } from "../mesh/canonical-json.js";
import { SIGNATURE_SCHEME_V1 } from "../mesh/constants.js";
import { RECOVERY_EVENT_TYPES, RECOVERY_SIGNATURE_SCHEME } from "./constants.js";
import type { RecoveryEventType } from "./constants.js";
import type { RecoveryEvent } from "./types.js";

function generateEventId(): string {
  const bytes = randomBytes(16);
  let hex = "";
  for (const b of bytes) hex += b.toString(16).padStart(2, "0");
  return hex;
}

export interface PackRecoveryEventParams {
  event_type: RecoveryEventType;
  fortress_id: string;
  emitter_node: string;
  emitter_principal: string;
  payload: Record<string, unknown>;
  signing_key: Uint8Array;
}

/**
 * Pack and sign a recovery event. Sibling to `packSignedEvent` from
 * the federation mesh module.
 *
 * The envelope shape mirrors SignedEvent but uses the recovery-specific
 * RecoveryEvent type. The `signature_scheme` field is mandatory (PQ
 * migration hinge).
 *
 * Validates that event_type starts with `recovery_` (our namespace).
 */
export function packRecoveryEvent(
  params: PackRecoveryEventParams
): RecoveryEvent {
  // Validate event type is in recovery namespace.
  const validTypes = Object.values(RECOVERY_EVENT_TYPES);
  if (!validTypes.includes(params.event_type as typeof validTypes[number])) {
    throw new Error(
      `invalid recovery event type "${params.event_type}"; must be one of: ${validTypes.join(", ")}`
    );
  }

  const event_id = generateEventId();
  const created_at = new Date().toISOString();
  const payloadBytes = canonicalizeToBytes(params.payload);
  const payload_hash = toBase64url(sha256(payloadBytes));

  const body = {
    event_id,
    event_type: params.event_type,
    created_at,
    fortress_id: params.fortress_id,
    emitter_node: params.emitter_node,
    emitter_principal: params.emitter_principal,
    payload: params.payload,
    payload_hash,
    signature_scheme: RECOVERY_SIGNATURE_SCHEME,
  };

  const sig = ed25519.sign(canonicalizeToBytes(body), params.signing_key);

  return {
    ...body,
    signature: toBase64url(sig),
  };
}

/**
 * Verify a recovery event's signature and payload integrity.
 *
 * Checks:
 *   1. `signature_scheme` is `ed25519-v1` (v1.0 only).
 *   2. `payload_hash` matches re-computed SHA-256 of canonical payload.
 *   3. Ed25519 signature verifies over the canonical event body.
 *
 * Returns true on success, false on any verification failure. Does NOT
 * throw (same pattern as verifyGateReceipt).
 */
export function verifyRecoveryEvent(
  event: RecoveryEvent,
  nodePublicKey: Uint8Array
): boolean {
  // Scheme check.
  if (event.signature_scheme !== SIGNATURE_SCHEME_V1) {
    return false;
  }

  // Payload hash coherence.
  const freshPayloadHash = toBase64url(
    sha256(canonicalizeToBytes(event.payload))
  );
  if (freshPayloadHash !== event.payload_hash) {
    return false;
  }

  // Signature check.
  const { signature, ...body } = event;
  try {
    return ed25519.verify(
      fromBase64url(signature),
      canonicalizeToBytes(body),
      nodePublicKey
    );
  } catch {
    return false;
  }
}
