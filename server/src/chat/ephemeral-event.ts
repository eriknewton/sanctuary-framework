/**
 * Sanctuary Chat v1.0 — Ephemeral Event Helper
 *
 * Sibling to packSignedEvent (mesh/envelope.ts). Produces signed events
 * that are NOT persisted to the audit log and NOT dispatched through the
 * MeshRouter. Used for presence heartbeats and other low-sensitivity
 * transient signals.
 *
 * The wire shape is identical to SignedEvent; the difference is purely
 * in how the caller handles the output (publish to gossipsub topic,
 * do not feed to audit buffer).
 *
 * Spawn prompt: "Add a sibling packEphemeralEvent helper or a flag on the
 * existing path; do not invent a new envelope."
 */

import { ed25519 } from "@noble/curves/ed25519";
import { sha256 } from "@noble/hashes/sha256";
import { toBase64url } from "../core/encoding.js";
import { randomBytes } from "../core/random.js";
import { canonicalizeToBytes } from "../mesh/canonical-json.js";
import { PROTOCOL_VERSION } from "../mesh/constants.js";
import type { SignedEvent } from "../mesh/types.js";

export interface EphemeralPackParams<Payload> {
  /** Event type (must not be a reserved v1.x prefix). */
  event_type: string;
  /** Emitting node ID. */
  emitter_node: string;
  /** Emitting principal ID. */
  emitter_principal: string;
  /** Fortress scope. */
  fortress_id: string;
  /** Event payload. */
  payload: Payload;
  /** Per-emitter monotonic sequence counter. */
  monotonic_seq: number;
  /** Node's Ed25519 private key for signing. */
  node_private_key: Uint8Array;
}

/**
 * Pack and sign an ephemeral event. Same wire shape as packSignedEvent
 * but intentionally skips:
 * - Reserved event_type validation (chat event types are not reserved)
 * - Extension envelope (always empty for ephemeral)
 * - Principal signature (ephemeral events are node-signed only)
 *
 * The caller is responsible for NOT feeding this event to the audit buffer.
 */
export function packEphemeralEvent<Payload>(
  params: EphemeralPackParams<Payload>
): SignedEvent<Payload> {
  const payloadBytes = canonicalizeToBytes(params.payload);
  const payload_hash = toBase64url(sha256(payloadBytes));

  const body: Omit<SignedEvent<Payload>, "node_signature" | "principal_signature"> = {
    protocol_version: PROTOCOL_VERSION,
    event_type: params.event_type,
    event_id: generateEphemeralId(),
    emitter_node: params.emitter_node,
    emitter_principal: params.emitter_principal,
    fortress_id: params.fortress_id,
    causal_parents: [],
    payload: params.payload,
    payload_hash,
    emitted_at: new Date().toISOString(),
    monotonic_seq: params.monotonic_seq,
    extension_envelope: {},
  };

  const bytesToSign = canonicalizeToBytes(body);
  const nodeSig = ed25519.sign(bytesToSign, params.node_private_key);

  return {
    ...body,
    node_signature: toBase64url(nodeSig),
  };
}

function generateEphemeralId(): string {
  const bytes = randomBytes(16);
  let hex = "";
  for (const b of bytes) hex += b.toString(16).padStart(2, "0");
  return hex;
}
