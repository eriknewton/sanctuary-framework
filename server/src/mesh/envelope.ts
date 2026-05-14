/**
 * Sanctuary Federation Protocol v0.1 — Signed-Event Envelope
 *
 * Every federation message rides this envelope. Every message is signed by the
 * emitting node's per-node key and optionally by the authoring principal's key.
 *
 * Hard-gate invariants enforced here:
 * - Reserved extension_envelope keys (§10.1) rejected at pack time.
 * - Reserved event_type namespaces (§10.3) rejected at pack time.
 * - Reserved extension_envelope keys (§10.1) rejected at verify time.
 * - Reserved event_type namespaces (§10.3) rejected at verify time.
 * - Reserved capability bits (§10.2) rejected at verify time.
 * - Unknown extension_envelope keys IGNORED at verify time (forward-compat).
 * - Signatures cover extension_envelope bit-for-bit so v1.x-authored events
 *   with extension content verify on v0.1 receivers.
 *
 * Spec: §4.2, §10.1, §10.3.
 */

import { ed25519 } from "@noble/curves/ed25519";
import { sha256 } from "@noble/hashes/sha256";
import { fromBase64url, toBase64url } from "../core/encoding.js";
import { randomBytes } from "../core/random.js";
import { canonicalizeToBytes } from "./canonical-json.js";
import {
  isReservedEventType,
  isReservedExtensionKey,
  hasReservedCapabilityBits,
  PROTOCOL_VERSION,
} from "./constants.js";
import {
  MeshReservedCapabilityBitError,
  MeshReservedEventTypeError,
  MeshReservedExtensionKeyError,
  MeshSignatureError,
} from "./errors.js";
import type {
  ExtensionEnvelope,
  FortressMasterPublicKey,
  NodeIdentityCertificate,
  PrincipalCertificate,
  SignedEvent,
} from "./types.js";
import { verifyCertChain } from "./trust-root.js";

// ═══════════════════════════════════════════════════════════════════════
// Packing (emitter side)
// ═══════════════════════════════════════════════════════════════════════

export interface PackParams<Payload> {
  event_type: string;
  emitter_node: string;
  emitter_principal: string;
  fortress_id: string;
  causal_parents?: string[];
  payload: Payload;
  monotonic_seq: number;
  extension_envelope?: ExtensionEnvelope;
  node_private_key: Uint8Array;
  principal_private_key?: Uint8Array;
}

/**
 * Pack and sign a v0.1 SignedEvent.
 *
 * Throws MeshReservedEventTypeError if event_type is in a reserved v1.x namespace.
 * Throws MeshReservedExtensionKeyError if extension_envelope populates a reserved key.
 *
 * Both throws are load-bearing for acceptance criterion 10 (the hard gate).
 */
export function packSignedEvent<Payload>(
  params: PackParams<Payload>
): SignedEvent<Payload> {
  if (isReservedEventType(params.event_type)) {
    throw new MeshReservedEventTypeError(params.event_type);
  }
  const ext = params.extension_envelope ?? {};
  for (const key of Object.keys(ext)) {
    if (isReservedExtensionKey(key)) {
      throw new MeshReservedExtensionKeyError(key);
    }
  }

  const payloadBytes = canonicalizeToBytes(params.payload);
  const payload_hash = toBase64url(sha256(payloadBytes));
  const body: Omit<SignedEvent<Payload>, "node_signature" | "principal_signature"> = {
    protocol_version: PROTOCOL_VERSION,
    event_type: params.event_type,
    event_id: generateEventId(),
    emitter_node: params.emitter_node,
    emitter_principal: params.emitter_principal,
    fortress_id: params.fortress_id,
    causal_parents: params.causal_parents ?? [],
    payload: params.payload,
    payload_hash,
    emitted_at: new Date().toISOString(),
    monotonic_seq: params.monotonic_seq,
    extension_envelope: ext,
  };
  const bytesToSign = canonicalizeToBytes(body);
  const nodeSig = ed25519.sign(bytesToSign, params.node_private_key);
  const evt: SignedEvent<Payload> = {
    ...body,
    node_signature: toBase64url(nodeSig),
  };
  if (params.principal_private_key) {
    const principalSig = ed25519.sign(bytesToSign, params.principal_private_key);
    evt.principal_signature = toBase64url(principalSig);
  }
  return evt;
}

function generateEventId(): string {
  const bytes = randomBytes(16);
  let hex = "";
  for (const b of bytes) hex += b.toString(16).padStart(2, "0");
  return hex;
}

// ═══════════════════════════════════════════════════════════════════════
// Verifying (receiver side)
// ═══════════════════════════════════════════════════════════════════════

export interface VerifyContext {
  /** Pinned fortress-master public key for THIS receiver's fortress. */
  pinnedMasterPubkey: FortressMasterPublicKey;
  /** Lookup: emitter_node → that node's NodeIdentityCertificate (must be in local roster). */
  lookupNodeCert: (nodeId: string) => NodeIdentityCertificate | undefined;
  /** Lookup: emitter_principal → that principal's cert. */
  lookupPrincipalCert: (
    principalId: string
  ) => PrincipalCertificate | undefined;
  /**
   * If true (default), reject envelopes whose fortress_id does not match the
   * pinned fortress. This is the cross-operator isolation invariant (§10.5).
   *
   * v1.x MSP extension handlers set this to false (they expect cross-fortress
   * events, and they validate trust via grant-based logic at a higher layer).
   */
  requireMatchingFortress?: boolean;
}

export interface VerifyResult {
  ok: boolean;
  /**
   * Reserved extension_envelope keys encountered during verification.
   * These are keys present on the envelope that ARE in the v1.x reserved set
   * (per Federation Protocol v0.1 spec §10.1). The v0.1 verifier records but
   * does not reject them, so a v1.x consumer can detect that a forward-compat
   * extension payload rode the envelope. Keys not in the reserved set pass
   * through silently per spec §10.1.
   * Empty when no reserved keys ride the envelope.
   */
  recognized_reserved_extension_keys: string[];
  /** Verified event. Same shape as the input; convenience return. */
  event: SignedEvent;
}

/**
 * Verify a v0.1 SignedEvent against the pinned trust root.
 *
 * Throws a named MeshEnvelopeError / MeshCertificateError subclass on failure.
 * Unknown extension_envelope keys that are not in the reserved set pass through
 * silently; reserved namespaces and capability bits are receive-side hard gates.
 */
export function verifySignedEvent(
  evt: SignedEvent,
  ctx: VerifyContext
): VerifyResult {
  if (evt.protocol_version !== PROTOCOL_VERSION) {
    throw new MeshSignatureError(
      `unknown protocol_version ${evt.protocol_version}; v0.1 verifier accepts only ${PROTOCOL_VERSION}`
    );
  }
  const requireMatchingFortress = ctx.requireMatchingFortress ?? true;
  if (
    requireMatchingFortress &&
    evt.fortress_id !== ctx.pinnedMasterPubkey.fortress_id
  ) {
    throw new MeshSignatureError(
      `envelope fortress_id=${evt.fortress_id} does not match pinned fortress ${ctx.pinnedMasterPubkey.fortress_id} — cross-operator isolation invariant`
    );
  }

  // payload_hash coherence check — prevents an attacker swapping payload after signing.
  const freshPayloadHash = toBase64url(
    sha256(canonicalizeToBytes(evt.payload))
  );
  if (freshPayloadHash !== evt.payload_hash) {
    throw new MeshSignatureError(
      `payload_hash mismatch — envelope payload does not match its declared hash`
    );
  }

  // Node signature — cert must be in local roster and chain to pinned master.
  const nodeCert = ctx.lookupNodeCert(evt.emitter_node);
  if (!nodeCert) {
    throw new MeshSignatureError(
      `emitter_node ${evt.emitter_node} is not in local roster`
    );
  }
  if (hasReservedCapabilityBits(nodeCert.capabilities)) {
    throw new MeshReservedCapabilityBitError(nodeCert.capabilities);
  }
  const principalCert = ctx.lookupPrincipalCert(evt.emitter_principal);
  if (evt.principal_signature && !principalCert) {
    throw new MeshSignatureError(
      `emitter_principal ${evt.emitter_principal} is not in local roster but a principal_signature is present`
    );
  }
  // Chain-validate every node cert, including system-principal events. The
  // certificate's issuer is authoritative for the node → principal hop.
  const issuerPrincipalCert = ctx.lookupPrincipalCert(
    nodeCert.parent_chain.principal_id
  );
  if (!issuerPrincipalCert) {
    throw new MeshSignatureError(
      `node cert issuer principal ${nodeCert.parent_chain.principal_id} is not in local roster`
    );
  }
  verifyCertChain(nodeCert, issuerPrincipalCert, ctx.pinnedMasterPubkey);

  // Rebuild the canonical body that was signed.
  const body: Omit<SignedEvent, "node_signature" | "principal_signature"> = {
    protocol_version: evt.protocol_version,
    event_type: evt.event_type,
    event_id: evt.event_id,
    emitter_node: evt.emitter_node,
    emitter_principal: evt.emitter_principal,
    fortress_id: evt.fortress_id,
    causal_parents: evt.causal_parents,
    payload: evt.payload,
    payload_hash: evt.payload_hash,
    emitted_at: evt.emitted_at,
    monotonic_seq: evt.monotonic_seq,
    extension_envelope: evt.extension_envelope,
  };
  const bytesToVerify = canonicalizeToBytes(body);

  const nodeOk = ed25519.verify(
    fromBase64url(evt.node_signature),
    bytesToVerify,
    fromBase64url(nodeCert.node_pubkey)
  );
  if (!nodeOk) {
    throw new MeshSignatureError(
      `node_signature does not verify against ${evt.emitter_node}`
    );
  }

  if (evt.principal_signature && principalCert) {
    const principalOk = ed25519.verify(
      fromBase64url(evt.principal_signature),
      bytesToVerify,
      fromBase64url(principalCert.principal_pubkey)
    );
    if (!principalOk) {
      throw new MeshSignatureError(
        `principal_signature does not verify against ${evt.emitter_principal}`
      );
    }
  }

  if (isReservedEventType(evt.event_type)) {
    throw new MeshReservedEventTypeError(evt.event_type);
  }

  // Forward-compat: keys not in the reserved set are silently passed through.
  // Reserved keys are hard-gated on receive so future semantics never enter
  // verified v0.1 state.
  const recognized_reserved_extension_keys: string[] = [];
  for (const key of Object.keys(evt.extension_envelope ?? {})) {
    if (isReservedExtensionKey(key)) {
      throw new MeshReservedExtensionKeyError(key);
    }
  }

  return { ok: true, recognized_reserved_extension_keys, event: evt };
}
