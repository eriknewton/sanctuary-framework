/**
 * Client-side cross-machine sync driver (PR-A5 — the federation marquee).
 *
 * A4's `/v1/federation/sync` was "loopback position-only": a process POSTed a
 * hand-built body to ITSELF and read events back. There was no driver for one
 * of an operator's machines to actually reach across the network to ANOTHER of
 * its machines, present a cryptographically-attributable event slice, and
 * reconcile the reply. This module is that driver.
 *
 * `pushSyncToPeer` runs on the SENDING node. It:
 *   1. Wraps this node's outbound event slice in a {@link FederationSyncEnvelope}
 *      signed by this node's identity key (`signSyncEnvelope`).
 *   2. POSTs it to the peer's `/v1/federation/sync/peer` over HTTP. Federation
 *      P1: this route is pre-session and node-cert-authenticated, so NO session
 *      token is required (the optional `sessionToken` is retained only for the
 *      A4 loopback/transitional rigs). NEVER any private key material crosses the
 *      wire (constraint 6); the node certificate in the envelope is the sole
 *      credential.
 *   3. Verifies the peer's RECIPROCAL envelope the same way the peer verified
 *      ours: the response envelope's node certificate must chain to the SHARED
 *      pinned fortress-master (`verifySyncEnvelope`). A reply that does not
 *      chain — a man-in-the-middle, or a different operator's daemon answering —
 *      is rejected; we do not reconcile unverified events.
 *   4. Returns the verified reciprocal events for the caller to append to its
 *      own hash-chained log.
 *
 * The trust anchor on BOTH directions is the shared pinned master: the operator
 * pins one master across all their machines, so "recognize my other machine" is
 * "its node cert chains to my pinned master." No implicit trust, no global
 * allow-list (CLAUDE.md constraint 4).
 */

import { fromBase64url } from "../core/encoding.js";
import type {
  FortressMasterPublicKey,
  NodeIdentityCertificate,
  PrincipalCertificate,
} from "../mesh/types.js";
import type {
  FederationAppendOptions,
  FederationAppendResult,
  FederationEvent,
} from "./federation.js";
import {
  signSyncEnvelope,
  verifySyncEnvelope,
  type FederationSyncEnvelope,
} from "./federation-sync-envelope.js";
import {
  acceptFederationEventsFailClosed,
  isFederationOperatorAuthorityEvent,
} from "./federation-revocation.js";
import {
  dashboardRequest,
  DashboardRequestError,
} from "../cli/dashboard-request.js";

/** Materials the sending node holds to mint + verify peer envelopes. */
export interface PeerSyncIdentity {
  fortressId: string;
  /** This node's id (must equal `nodeCert.node_id`). */
  nodeId: string;
  /** This node's identity certificate, chaining to the shared master. */
  nodeCert: NodeIdentityCertificate;
  /** The principal cert this node's cert chains through. */
  issuingPrincipalCert: PrincipalCertificate;
  /** Transient node Ed25519 private key — caller owns zeroing after use. */
  nodePrivateKey: Uint8Array;
  /** The SHARED pinned fortress-master pubkey (verifies the peer's reply). */
  pinnedMaster: FortressMasterPublicKey;
}

export interface PushSyncParams {
  /** The peer daemon's base URL (e.g. https://linux-1.local:3502). */
  peerUrl: string;
  /** The recipient peer's node id (binds the envelope to that machine). */
  recipientNodeId: string;
  /**
   * Federation P1: OPTIONAL. `/v1/federation/sync/peer` is now pre-session and
   * node-cert-authenticated, so no session token is required. When omitted (or
   * empty), the request carries NO `Authorization` header: the node certificate
   * in the envelope is the sole credential. Retained for the A4 loopback /
   * transitional rigs that still mint a session.
   */
  sessionToken?: string;
  /** This node's slice to push (its outbound hash-chained events). */
  events: FederationEvent[];
  /** Monotonic-per-(sender,recipient) high-water this push stamps. */
  syncHighWater: number;
  /** Optional cursor the peer answers its reciprocal slice against. */
  cursor?: { node_id?: string; after_sequence?: number };
  /**
   * Highest reciprocal high-water this caller has already accepted FROM this
   * peer (or null if none). Gates whole-envelope rollback of the peer's REPLY:
   * a replayed older reciprocal envelope is rejected because its high-water no
   * longer advances — the same guard the inbound /sync/peer path applies, now
   * applied to the response. The caller persists this per-peer and advances it
   * with `result.reciprocalHighWater` on success.
   */
  acceptedReciprocalHighWater?: number | null;
  /**
   * Local grow-only revocation projection for the reciprocal sender. Required:
   * if the caller cannot evaluate revocation, reciprocal verification fails
   * closed instead of trusting a valid-but-revoked peer certificate.
   */
  isNodeRevoked(peerNodeId: string): boolean;
  /**
   * Local event-acceptance surface for the reciprocal envelope. When supplied,
   * this must be the same fail-closed append gate used by the local federation
   * log; it lets reciprocal operator-authority evictions update the revoked set
   * before ordinary reciprocal events are accepted. If a reciprocal envelope
   * carries an eviction and this callback is absent, the client fails closed.
   */
  acceptReciprocalEvents?(
    events: FederationEvent[],
    options?: FederationAppendOptions,
  ): FederationAppendResult;
  /** Injection seam for tests; defaults to the real HTTP client. */
  request?: typeof dashboardRequest;
}

/** Outcome of a peer push: the verified reciprocal slice or a classified error. */
export type PushSyncResult =
  | {
      ok: true;
      /** Event ids the peer accepted from our slice. */
      acceptedByPeer: string[];
      /** Per-event rejections the peer reported. */
      rejectedByPeer: Array<{ event_id: string; reason: string }>;
      /** The peer's reciprocal events, AFTER local envelope verification. */
      reciprocalEvents: FederationEvent[];
      /** The peer's node id, as proven by its reciprocal cert chain. */
      peerNodeId: string;
      /** The verified reciprocal high-water; the caller persists this per-peer. */
      reciprocalHighWater: number;
    }
  | { ok: false; reason: "unreachable" | "rejected" | "reciprocal_unverified" | "malformed_response" };

/**
 * Push this node's slice to a peer and reconcile the reciprocal reply. Verifies
 * the peer's response envelope against the SHARED pinned master before trusting
 * any reciprocal event. The node private key is zeroed by the caller, not here
 * (it may be reused across peers in a fan-out).
 */
export async function pushSyncToPeer(
  identity: PeerSyncIdentity,
  params: PushSyncParams,
): Promise<PushSyncResult> {
  const request = params.request ?? dashboardRequest;

  const envelope: FederationSyncEnvelope = signSyncEnvelope({
    fortressId: identity.fortressId,
    senderNodeId: identity.nodeId,
    recipientNodeId: params.recipientNodeId,
    syncHighWater: params.syncHighWater,
    events: params.events,
    cursor: params.cursor,
    senderNodeCert: identity.nodeCert,
    issuingPrincipalCert: identity.issuingPrincipalCert,
    nodePrivateKey: identity.nodePrivateKey,
  });

  let response: PeerSyncResponse;
  try {
    response = (await request(
      "/v1/federation/sync/peer",
      { method: "POST", body: JSON.stringify(envelope) },
      // Federation P1: pre-session route. Pass the explicit empty string when no
      // session token is supplied so dashboardRequest sends NO `Authorization`
      // header (an empty authToken wins over the env fallback); the node cert in
      // the envelope is the sole credential. A supplied token is still forwarded
      // for the transitional loopback rigs.
      { dashboardUrl: params.peerUrl, authToken: params.sessionToken ?? "" },
    )) as PeerSyncResponse;
  } catch (cause) {
    if (cause instanceof DashboardRequestError) {
      // 403 = the peer rejected our envelope (cert chain / signature / rollback).
      if (cause.kind === "auth") return { ok: false, reason: "rejected" };
      return { ok: false, reason: "unreachable" };
    }
    return { ok: false, reason: "unreachable" };
  }

  if (typeof response !== "object" || response === null) {
    return { ok: false, reason: "malformed_response" };
  }
  const acceptedByPeer = Array.isArray(response.accepted)
    ? response.accepted.filter((id): id is string => typeof id === "string")
    : [];
  const rejectedByPeer = Array.isArray(response.rejected)
    ? (response.rejected as Array<{ event_id: string; reason: string }>)
    : [];

  // Fail closed: a cross-machine sync REQUIRES a peer-verifiable reciprocal
  // envelope. A reply without one (a misprovisioned peer, or an attacker
  // returning bare events) is NOT trusted — we never reconcile unattributable
  // reciprocal events. This is the symmetric form of the inbound cert-chain
  // gate; there is no weaker bare-events path on the cross-machine driver.
  if (response.envelope === undefined) {
    return { ok: false, reason: "reciprocal_unverified" };
  }

  // Verify the reciprocal envelope against the SHARED pinned master. We are the
  // recipient of the peer's reply; bind it to OUR node id. The reciprocal
  // high-water MUST advance past the last one we accepted from this peer, so a
  // replayed older reply (e.g. after a local log reset) is rejected — the same
  // whole-envelope rollback guard the inbound path applies.
  const priorReciprocal = params.acceptedReciprocalHighWater ?? null;
  const verification = verifySyncEnvelope({
    envelope: response.envelope,
    pinnedMaster: identity.pinnedMaster,
    recipientNodeId: identity.nodeId,
    acceptedHighWaterFor: () => priorReciprocal,
    isNodeRevoked: (senderNodeId) => params.isNodeRevoked(senderNodeId),
  });
  if (!verification.ok) {
    return { ok: false, reason: "reciprocal_unverified" };
  }

  const reciprocalAcceptance = acceptReciprocalEventsFailClosed(
    identity,
    params,
    verification.senderNodeId,
    verification.wireVersion,
    verification.events,
  );
  if (reciprocalAcceptance === null) {
    return { ok: false, reason: "reciprocal_unverified" };
  }

  return {
    ok: true,
    acceptedByPeer,
    rejectedByPeer,
    reciprocalEvents: reciprocalAcceptance.accepted,
    peerNodeId: verification.senderNodeId,
    reciprocalHighWater: verification.syncHighWater,
  };
}

function acceptReciprocalEventsFailClosed(
  identity: PeerSyncIdentity,
  params: PushSyncParams,
  senderNodeId: string,
  wireVersion: string,
  events: FederationEvent[],
): FederationAppendResult | null {
  if (params.acceptReciprocalEvents) {
    const accepted = params.acceptReciprocalEvents(events, {
      senderNodeId,
      wireVersion,
    });
    return isBatchRejected(accepted) ? null : accepted;
  }
  if (
    events.some((event) =>
      isFederationOperatorAuthorityEvent(event, identity.fortressId),
    )
  ) {
    return null;
  }
  const accepted = acceptFederationEventsFailClosed({
    events,
    fortressId: identity.fortressId,
    senderNodeId,
    wireVersion,
    isNodeRevoked: params.isNodeRevoked,
    appendEvents: (batch) => ({ accepted: batch, rejected: [] }),
  });
  return accepted.revocationStateAvailable && !accepted.batchRejected ? accepted : null;
}

function isBatchRejected(result: FederationAppendResult): boolean {
  return (result as FederationAppendResult & { batchRejected?: boolean }).batchRejected === true;
}

interface PeerSyncResponse {
  accepted?: unknown;
  rejected?: unknown;
  events?: unknown;
  envelope?: unknown;
  nodes?: unknown;
}

/**
 * Recognize a portable agent identity across a substrate move (PR-A5). When an
 * operator moves an agent from node A to node B, B RECOGNIZES the agent via the
 * operator-attested `agent.identity` event that arrived in A's synced log — NOT
 * a fresh re-mint. This helper extracts the portable agent ids a node knows
 * about from its (already hash-chain-validated, envelope-cert-chain-verified)
 * federation event log.
 *
 * ONLY `agent.identity` events count as a portable-identity attestation. A mere
 * `agent.seen` sighting is activity telemetry, not an admission of identity, and
 * must NOT confer recognition — otherwise a synced sighting could "recognize" an
 * agent the operator never admitted. Because the origin-binding gate on the
 * peer-sync path forces every synced event's origin_node_id to equal the
 * verified sender, an `agent.identity` event in the log is one a fortress node
 * actually emitted for itself, never an attacker-stamped foreign origin.
 *
 * This is the "identity survives substrate move" property: recognition does not
 * depend on WHICH node currently runs the agent, only on the operator-rooted
 * attestation that the agent belongs to the fortress. Returns a map of
 * agent_id → the set of node ids that have attested it.
 */
export function recognizedPortableAgents(
  events: FederationEvent[],
): Map<string, Set<string>> {
  const recognized = new Map<string, Set<string>>();
  for (const event of events) {
    if (event.kind !== "agent.identity") continue;
    const agentId = event.payload.agent_id;
    if (typeof agentId !== "string" || agentId.length === 0) continue;
    const nodes = recognized.get(agentId) ?? new Set<string>();
    nodes.add(event.origin_node_id);
    recognized.set(agentId, nodes);
  }
  return recognized;
}

/** Decode a base64url node pubkey for callers that need it; throws on malformed. */
export function decodeNodePubkey(cert: NodeIdentityCertificate): Uint8Array {
  return fromBase64url(cert.node_pubkey);
}
