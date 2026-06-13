/**
 * Cross-node federation sync envelope (PR-A5 — the federation marquee).
 *
 * A4 shipped `/v1/federation/sync` as a "loopback position-only" exchange: the
 * receiving fortress verified ITS OWN operator signature over the request body
 * and appended the hash-chained events. That works when both ends are the same
 * operator process talking to itself, but it does NOT let one of an operator's
 * machines accept a sync from ANOTHER of the operator's machines: node B has no
 * way to verify, cryptographically, that the events it is being handed actually
 * originate from a node that belongs to the same fortress. Trusting the request
 * because it "looks like" a sync would violate CLAUDE.md constraint 4 (never
 * assume trust across the boundary — verification is cryptographic, never shape
 * based).
 *
 * This module adds the missing primitive: a SYNC ENVELOPE the SENDING node
 * wraps around its event-log slice. The envelope carries the sender's
 * NodeIdentityCertificate (+ the issuing principal cert) and an Ed25519
 * signature, by the sender's node key, over a domain-separated, length-prefixed
 * binding of (fortress_id, sender node_id, recipient node_id, a monotonic
 * sync_high_water, and the canonical event slice). The recipient verifies, in
 * order:
 *
 *   1. The node + principal certificate chain terminates at the recipient's
 *      OWN pinned fortress-master pubkey (`verifyCertChain`). A node whose cert
 *      chains to a DIFFERENT master — i.e. a different operator's fortress — is
 *      rejected outright. This is the cross-machine trust anchor: an operator's
 *      machines share one pinned master, so "same operator, many machines" is
 *      exactly "chains to my pinned master." No global allow-list, no implicit
 *      trust: the shared master IS the recognition root.
 *   2. The envelope signature verifies against the node_pubkey INSIDE that
 *      now-verified certificate (not a pubkey supplied alongside it). So the
 *      events are bound to a node the operator actually admitted to the
 *      fortress; a forged envelope with a swapped pubkey fails here.
 *   3. The recipient binding (fortress_id + recipient node_id) matches THIS
 *      fortress. An envelope minted for fortress X or node Y cannot be replayed
 *      against fortress Z / node W.
 *   4. The sync_high_water is strictly greater than the highest the recipient
 *      has previously accepted FROM THIS SENDER NODE. This defeats replay /
 *      rollback of a whole envelope: re-presenting an old (validly-signed)
 *      envelope, or splicing in a stale event slice, is rejected because its
 *      high-water no longer advances. The per-event hash chain already defeats
 *      tampering and per-event replay; the high-water defeats whole-envelope
 *      rollback that the per-event chain alone would re-accept after a log
 *      reset.
 *
 * No private key material is in the envelope (constraint 6): only public
 * certificates and a detached signature ride the wire. The recipient's own
 * master/principal private keys never participate in VERIFY.
 *
 * The cert-chain check reuses `verifyCertChain` field-for-field — the same code
 * that gates a join — so a node that can sync is provably a node that could
 * join, and vice versa. No second, weaker trust path is introduced.
 */

import { ed25519 } from "@noble/curves/ed25519";
import { fromBase64url, toBase64url } from "../core/encoding.js";
import { verify } from "../core/identity.js";
import { verifyCertChain } from "../mesh/trust-root.js";
import type {
  FortressMasterPublicKey,
  NodeIdentityCertificate,
  PrincipalCertificate,
} from "../mesh/types.js";
import { canonicalJson } from "./operator-signed.js";
import type { FederationEvent } from "./federation.js";
import { validateFederationEventHash } from "./federation.js";

/** Domain separator for the cross-node sync envelope signature (versioned). */
export const V1_FEDERATION_SYNC_ENVELOPE_DOMAIN = "sanctuary.v1.federation-sync-envelope";

/**
 * The wire shape a sending node wraps around its event-log slice. The
 * `sender_node_cert` + `issuing_principal_cert` carry the sender's identity and
 * its chain to the shared fortress-master; `envelope_signature` is the sender's
 * node-key signature over {@link buildSyncEnvelopeMessage}.
 */
export interface FederationSyncEnvelope {
  /** Fortress both nodes belong to (must equal the recipient's). */
  fortress_id: string;
  /** The sending node's id (must equal `sender_node_cert.node_id`). */
  sender_node_id: string;
  /** The intended recipient node's id (must equal the recipient's own id). */
  recipient_node_id: string;
  /**
   * Strictly-monotonic-per-(sender,recipient) replay/rollback guard. The
   * sender advances this on every envelope it mints; the recipient rejects any
   * envelope whose high-water does not exceed the highest it has accepted from
   * this sender. A reasonable sender uses its own outbound event count, but the
   * recipient does not depend on that — only on strict monotonicity.
   */
  sync_high_water: number;
  /** The sender's hash-chained event slice. */
  events: FederationEvent[];
  /** Optional cursor the recipient should answer outbound events against. */
  cursor?: { node_id?: string; after_sequence?: number };
  /** The sender's node identity certificate (chains to the shared master). */
  sender_node_cert: NodeIdentityCertificate;
  /** The principal cert the sender's node cert chains through. */
  issuing_principal_cert: PrincipalCertificate;
  /** base64url Ed25519, by the sender node key, over the binding message. */
  envelope_signature: string;
}

function lengthPrefixed(field: Uint8Array): Uint8Array {
  const out = new Uint8Array(4 + field.length);
  new DataView(out.buffer).setUint32(0, field.length, false);
  out.set(field, 4);
  return out;
}

function u64BE(value: number): Uint8Array {
  const out = new Uint8Array(8);
  new DataView(out.buffer).setUint32(0, Math.floor(value / 0x100000000), false);
  new DataView(out.buffer).setUint32(4, value >>> 0, false);
  return out;
}

/**
 * Build the exact bytes a sending node signs (and a recipient verifies) for a
 * sync envelope. Injective length-prefixed encoding under a domain separator
 * over (fortress_id, sender_node_id, recipient_node_id, sync_high_water,
 * canonical events). The events are canonicalized WITH their hashes so the
 * signature commits to the precise slice; the recipient re-validates each
 * per-event hash independently, so the signature need not (and does not)
 * re-derive them.
 */
export function buildSyncEnvelopeMessage(input: {
  fortressId: string;
  senderNodeId: string;
  recipientNodeId: string;
  syncHighWater: number;
  events: FederationEvent[];
  cursor?: { node_id?: string; after_sequence?: number };
}): Uint8Array {
  const encoder = new TextEncoder();
  const parts = [
    encoder.encode(V1_FEDERATION_SYNC_ENVELOPE_DOMAIN),
    lengthPrefixed(encoder.encode(input.fortressId)),
    lengthPrefixed(encoder.encode(input.senderNodeId)),
    lengthPrefixed(encoder.encode(input.recipientNodeId)),
    u64BE(input.syncHighWater),
    lengthPrefixed(encoder.encode(canonicalJson(input.events))),
    lengthPrefixed(encoder.encode(canonicalJson(input.cursor ?? null))),
  ];
  const total = parts.reduce((n, p) => n + p.length, 0);
  const message = new Uint8Array(total);
  let offset = 0;
  for (const part of parts) {
    message.set(part, offset);
    offset += part.length;
  }
  return message;
}

/**
 * Sign a sync envelope with a sending node's transient Ed25519 private key.
 * The caller owns zeroing `nodePrivateKey` after use; this function never logs
 * or returns private key material. Used by the client-side sync driver and by
 * tests; the receiving side never calls this.
 */
export function signSyncEnvelope(params: {
  fortressId: string;
  senderNodeId: string;
  recipientNodeId: string;
  syncHighWater: number;
  events: FederationEvent[];
  cursor?: { node_id?: string; after_sequence?: number };
  senderNodeCert: NodeIdentityCertificate;
  issuingPrincipalCert: PrincipalCertificate;
  nodePrivateKey: Uint8Array;
}): FederationSyncEnvelope {
  const message = buildSyncEnvelopeMessage({
    fortressId: params.fortressId,
    senderNodeId: params.senderNodeId,
    recipientNodeId: params.recipientNodeId,
    syncHighWater: params.syncHighWater,
    events: params.events,
    cursor: params.cursor,
  });
  const signature = ed25519.sign(message, params.nodePrivateKey);
  return {
    fortress_id: params.fortressId,
    sender_node_id: params.senderNodeId,
    recipient_node_id: params.recipientNodeId,
    sync_high_water: params.syncHighWater,
    events: params.events,
    ...(params.cursor ? { cursor: params.cursor } : {}),
    sender_node_cert: params.senderNodeCert,
    issuing_principal_cert: params.issuingPrincipalCert,
    envelope_signature: toBase64url(signature),
  };
}

/** Outcome of verifying a peer's sync envelope against this fortress. */
export type SyncEnvelopeVerification =
  | {
      ok: true;
      senderNodeId: string;
      senderNodePubkey: string;
      syncHighWater: number;
      events: FederationEvent[];
      cursor?: { node_id?: string; after_sequence?: number };
    }
  | { ok: false; reason: SyncEnvelopeDenialReason };

export type SyncEnvelopeDenialReason =
  | "malformed_envelope"
  | "fortress_mismatch"
  | "recipient_mismatch"
  | "cert_node_id_mismatch"
  | "cert_chain_invalid"
  | "envelope_signature_invalid"
  | "event_hash_invalid"
  | "origin_node_mismatch"
  | "rollback_detected";

/**
 * Verify a peer's sync envelope. NEVER throws: any structural or cryptographic
 * defect returns `{ ok: false }` with an operator-facing reason; the HTTP layer
 * collapses every denial to one generic status so a probing peer learns nothing
 * about which check failed.
 *
 * `pinnedMaster` is the RECIPIENT's pinned fortress-master public key — the
 * trust anchor the sender's certificate chain must terminate at. `recipientNodeId`
 * is this fortress node's own id. `acceptedHighWaterFor(senderNodeId)` returns
 * the highest high-water this recipient has already accepted from that sender
 * (or null if never), which gates rollback.
 */
export function verifySyncEnvelope(input: {
  envelope: unknown;
  pinnedMaster: FortressMasterPublicKey;
  recipientNodeId: string;
  acceptedHighWaterFor(senderNodeId: string): number | null;
}): SyncEnvelopeVerification {
  const env = parseEnvelope(input.envelope);
  if (env === null) return { ok: false, reason: "malformed_envelope" };

  // 1. Fortress + recipient binding: this envelope must be addressed to THIS
  //    fortress and THIS node. (Pinned-master fortress_id is the source of
  //    truth; an envelope claiming a different fortress cannot be replayed in.)
  if (env.fortress_id !== input.pinnedMaster.fortress_id) {
    return { ok: false, reason: "fortress_mismatch" };
  }
  if (env.recipient_node_id !== input.recipientNodeId) {
    return { ok: false, reason: "recipient_mismatch" };
  }

  // 2. The sender_node_id MUST equal the id inside the presented certificate —
  //    no claiming to be one node while presenting another's cert.
  if (env.sender_node_id !== env.sender_node_cert.node_id) {
    return { ok: false, reason: "cert_node_id_mismatch" };
  }

  // 3. Certificate chain MUST terminate at the recipient's pinned master. This
  //    is the cross-machine recognition root: only a node the operator admitted
  //    to THIS fortress (same pinned master) passes. A different operator's
  //    node — chaining to a different master — is rejected here. Reuses the
  //    exact join-time verifier (no weaker second path).
  try {
    verifyCertChain(env.sender_node_cert, env.issuing_principal_cert, input.pinnedMaster);
  } catch {
    return { ok: false, reason: "cert_chain_invalid" };
  }

  // 4. Envelope signature MUST verify against the pubkey INSIDE the verified
  //    cert (not any pubkey supplied alongside). Binds the event slice to a
  //    node the operator actually admitted.
  let nodePubkey: Uint8Array;
  let signature: Uint8Array;
  try {
    nodePubkey = fromBase64url(env.sender_node_cert.node_pubkey);
    signature = fromBase64url(env.envelope_signature);
  } catch {
    return { ok: false, reason: "malformed_envelope" };
  }
  if (nodePubkey.length !== 32 || signature.length !== 64) {
    return { ok: false, reason: "malformed_envelope" };
  }
  const message = buildSyncEnvelopeMessage({
    fortressId: env.fortress_id,
    senderNodeId: env.sender_node_id,
    recipientNodeId: env.recipient_node_id,
    syncHighWater: env.sync_high_water,
    events: env.events,
    cursor: env.cursor,
  });
  if (!verify(message, signature, nodePubkey)) {
    return { ok: false, reason: "envelope_signature_invalid" };
  }

  // 5. Every per-event hash must be self-consistent. (The signature commits to
  //    the slice; this rejects a slice whose events were tampered before the
  //    sender signed, OR an honest sender that shipped a corrupt event.)
  for (const event of env.events) {
    if (!validateFederationEventHash(event)) {
      return { ok: false, reason: "event_hash_invalid" };
    }
    // Origin binding: every event MUST originate from the verified sender node.
    // Without this, a legitimately-attested node could ship events stamped with
    // ANOTHER node's origin_node_id — impersonating that node and (because the
    // recipient verifies nodes by appended origins) minting a phantom "verified"
    // node it never admitted. A node may only speak for ITSELF on the peer-sync
    // path; cross-node forwarding, if ever added, needs its own delegation proof.
    if (event.origin_node_id !== env.sender_node_id) {
      return { ok: false, reason: "origin_node_mismatch" };
    }
  }

  // 6. Rollback guard: the high-water MUST strictly advance past the highest
  //    this recipient has accepted from this sender. Re-presenting a stale
  //    (validly-signed) envelope is rejected because its high-water no longer
  //    advances.
  const prior = input.acceptedHighWaterFor(env.sender_node_id);
  if (prior !== null && env.sync_high_water <= prior) {
    return { ok: false, reason: "rollback_detected" };
  }

  return {
    ok: true,
    senderNodeId: env.sender_node_id,
    senderNodePubkey: env.sender_node_cert.node_pubkey,
    syncHighWater: env.sync_high_water,
    events: env.events,
    ...(env.cursor ? { cursor: env.cursor } : {}),
  };
}

/** Structural parse. Returns null on ANY shape error (no partial trust). */
function parseEnvelope(body: unknown): FederationSyncEnvelope | null {
  if (typeof body !== "object" || body === null) return null;
  const e = body as Record<string, unknown>;
  if (typeof e.fortress_id !== "string" || e.fortress_id.length === 0) return null;
  if (typeof e.sender_node_id !== "string" || e.sender_node_id.length === 0) return null;
  if (typeof e.recipient_node_id !== "string" || e.recipient_node_id.length === 0) return null;
  if (
    typeof e.sync_high_water !== "number" ||
    !Number.isSafeInteger(e.sync_high_water) ||
    e.sync_high_water < 0
  ) {
    return null;
  }
  if (!Array.isArray(e.events)) return null;
  if (typeof e.envelope_signature !== "string" || e.envelope_signature.length === 0) return null;
  if (typeof e.sender_node_cert !== "object" || e.sender_node_cert === null) return null;
  if (typeof e.issuing_principal_cert !== "object" || e.issuing_principal_cert === null) return null;

  const cert = e.sender_node_cert as Record<string, unknown>;
  if (typeof cert.node_id !== "string" || typeof cert.node_pubkey !== "string") return null;
  const principal = e.issuing_principal_cert as Record<string, unknown>;
  if (typeof principal.principal_id !== "string") return null;

  const events = parseEvents(e.events);
  if (events === null) return null;

  let cursor: FederationSyncEnvelope["cursor"];
  if (e.cursor !== undefined && e.cursor !== null) {
    if (typeof e.cursor !== "object" || Array.isArray(e.cursor)) return null;
    const c = e.cursor as Record<string, unknown>;
    cursor = {};
    if (c.node_id !== undefined) {
      if (typeof c.node_id !== "string" || c.node_id.length === 0) return null;
      cursor.node_id = c.node_id;
    }
    if (c.after_sequence !== undefined) {
      if (
        typeof c.after_sequence !== "number" ||
        !Number.isSafeInteger(c.after_sequence) ||
        c.after_sequence < 0
      ) {
        return null;
      }
      cursor.after_sequence = c.after_sequence;
    }
  }

  return {
    fortress_id: e.fortress_id,
    sender_node_id: e.sender_node_id,
    recipient_node_id: e.recipient_node_id,
    sync_high_water: e.sync_high_water,
    events,
    ...(cursor ? { cursor } : {}),
    sender_node_cert: e.sender_node_cert as unknown as NodeIdentityCertificate,
    issuing_principal_cert: e.issuing_principal_cert as unknown as PrincipalCertificate,
    envelope_signature: e.envelope_signature,
  };
}

function parseEvents(events: unknown[]): FederationEvent[] | null {
  const out: FederationEvent[] = [];
  for (const event of events) {
    if (typeof event !== "object" || event === null) return null;
    const e = event as Record<string, unknown>;
    if (typeof e.event_id !== "string" || e.event_id.length === 0) return null;
    if (typeof e.origin_node_id !== "string" || e.origin_node_id.length === 0) return null;
    if (typeof e.sequence !== "number" || !Number.isSafeInteger(e.sequence) || e.sequence < 1) {
      return null;
    }
    if (typeof e.occurred_at !== "string" || e.occurred_at.length === 0) return null;
    if (typeof e.kind !== "string" || e.kind.length === 0) return null;
    if (typeof e.payload !== "object" || e.payload === null || Array.isArray(e.payload)) return null;
    if (
      e.previous_hash !== null &&
      e.previous_hash !== undefined &&
      typeof e.previous_hash !== "string"
    ) {
      return null;
    }
    if (typeof e.event_hash !== "string" || e.event_hash.length === 0) return null;
    out.push({
      event_id: e.event_id,
      origin_node_id: e.origin_node_id,
      sequence: e.sequence,
      occurred_at: e.occurred_at,
      kind: e.kind,
      payload: e.payload as Record<string, unknown>,
      previous_hash: e.previous_hash === undefined ? null : e.previous_hash,
      event_hash: e.event_hash,
    });
  }
  return out;
}
