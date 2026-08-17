/**
 * Sanctuary Federation Protocol v0.1 — envelope-rejection attribution
 * vocabulary (UEK-02, UEK-03, QI-02-F12).
 *
 * THE ONE shared boundary between two things that are both `string` at
 * runtime and must never be interchangeable at the type level:
 *
 *   1. `AuthenticatedPeer` — a node id THIS node has itself cryptographically
 *      authenticated (envelope verification succeeded, or the id came off a
 *      certificate this node validated) BEFORE the value was minted. This is
 *      the only identity that may KEY per-origin state or ATTRIBUTE an
 *      operator-facing alert.
 *   2. A CLAIMED emitter — the `emitter_node` field carried inside an event
 *      whose verification FAILED. It is wire text authored by whoever sent
 *      the bytes, about whoever they wanted to blame. It is display-only
 *      forensic data and carries no credibility whatsoever.
 *
 * WHY A BRAND AND NOT TWO `string` PARAMETERS (AGENTS.md rule 7). A
 * trust-bearing field must name its subject, its evidence source, its
 * verifier, and what consuming it means. Two same-typed `string` parameters
 * satisfy none of that: they are silently swappable at every call site, and a
 * reviewer reading one site cannot tell which one was verified. The brand
 * makes the distinction a compile error rather than a convention, and
 * `authenticatedPeer()` is the single, greppable place where "this string has
 * been verified" is asserted — so an auditor can enumerate every mint site
 * and check each one sits downstream of a real verification.
 *
 * WHY NO `?? "<unknown>"` FALLBACK (AGENTS.md rule 3). An optional
 * security-relevant argument that every test supplies and some production
 * call site omits is the inert-capability shape this repo documented on
 * 2026-08-08. `RejectionOrigin` is REQUIRED on every consumer, and a call
 * site with genuinely no authenticated peer must say so explicitly by passing
 * {@link NO_AUTHENTICATED_PEER} — a stated, reviewable fact about that
 * transport, not a fallback that papers over a missing value.
 */

import { QuorumFreshnessError } from "../guardian/revoke-quorum-input.js";

/**
 * Brand carrier. `unique symbol` in a `declare const` produces a nominal tag
 * that exists only in the type system: there is no runtime property, so an
 * `AuthenticatedPeer` is byte-identical to the `string` it wraps on the wire,
 * in an audit payload, and as a `Map` key.
 */
declare const AUTHENTICATED_PEER_BRAND: unique symbol;

/**
 * A node id this node has itself authenticated.
 *
 * SUBJECT: the peer that signed the bytes this node verified.
 * EVIDENCE SOURCE: the signed envelope (or validated certificate chain).
 * VERIFIER: `MeshNode.verifyOrThrow` / `verifyNodeJoinBeforeRosterMutation`,
 *   both of which check the signature against a roster-resident, non-revoked
 *   certificate chained to the pinned fortress master key.
 * CONSUMING IT MEANS: "this exact peer is responsible for the traffic this
 *   value is attached to." It does NOT mean the peer is honest, only that the
 *   attribution cannot be forged by a third party.
 */
export type AuthenticatedPeer = string & {
  readonly [AUTHENTICATED_PEER_BRAND]: "mesh-envelope-verified";
};

/**
 * The origin key for a transport that carries NO authenticated peer at all.
 *
 * Three production paths are genuinely in this state, and each is a stated
 * property of the transport rather than a missing value:
 *   - broadcast receive (`MeshNode.handleIncomingBroadcast`): the transport
 *     hands over an event and nothing else, so when envelope verification is
 *     what FAILED there is no authenticated identity anywhere in the frame;
 *   - unicast audit-batch ingestion: same shape, the batch's own
 *     `emitter_node` is the thing being verified;
 *   - an `applySync` call outside the `sync_response` receive path (initial
 *     sync, or a direct/test call).
 *
 * A FIXED sentinel — never a per-claim key — is what bounds the state these
 * refusals feed (AGENTS.md rule 8). Every un-attributable refusal collapses
 * into ONE bucket, so an attacker rotating the claimed `emitter_node` per
 * event mints exactly one entry, not one per claim.
 *
 * VALUE PINNED, NOT CHOSEN: this is the exact string
 * `SYNC_TABLE_AUDIT_UNKNOWN_RELAYING_PEER` already writes into sealed
 * `sync_table_event_denied` audit entries (C12-SYNC-ORDER-01). That constant
 * is now defined as an alias of this one — must match the pin comment in
 * `constants.ts` — so there is ONE sentinel value in the codebase rather than
 * two hand-mirrored ones that can drift (AGENTS.md rule 5), and no already-
 * sealed audit entry's `relaying_peer` value changes meaning.
 */
export const NO_AUTHENTICATED_PEER = "unknown-relaying-peer" as const;

/**
 * What a per-origin bucket, an audit governor, or an operator alert may key
 * and attribute on. Deliberately a UNION of the brand and the sentinel's
 * LITERAL type, so:
 *   - a bare `string` is assignable to neither arm and cannot reach a
 *     consumer at all;
 *   - `NO_AUTHENTICATED_PEER` is not an `AuthenticatedPeer`, so a reader can
 *     never mistake the un-attributable bucket for a real peer;
 *   - narrowing with `=== NO_AUTHENTICATED_PEER` leaves `AuthenticatedPeer`
 *     in the else-branch, so "did we actually authenticate anyone" is a
 *     type-level question, not a string comparison a site can forget.
 */
export type RejectionOrigin = AuthenticatedPeer | typeof NO_AUTHENTICATED_PEER;

/**
 * Is `nodeId` structurally unusable as a peer identity?
 *
 * TWO CASES, both structural rather than cryptographic:
 *   - the EMPTY string, which would render an alert with no subject and merge
 *     every empty-id peer into one bucket;
 *   - the {@link NO_AUTHENTICATED_PEER} sentinel's literal value, because the
 *     sentinel and a real node id share one string space, so a peer admitted
 *     under that literal name would merge its own per-origin bucket with the
 *     shared un-attributable one — able to spend that bucket's budget, or to
 *     read another origin's refusals as its own.
 *
 * THE ONE predicate (rule 5). It is asserted at the two ADMISSION chokepoints
 * — `issueNodeIdentityCertificate` (mint side) and `NodeRoster.add` (relying
 * side) — and re-asserted inside {@link authenticatedPeer} as the last line of
 * defence. Sharing one predicate is what keeps the chokepoints and the mint
 * from drifting into disagreeing about which ids are reserved; a second
 * hand-mirrored copy is the shape that lets one of them start accepting an id
 * the other refuses.
 *
 * CROSS-FILE PIN: the throwing call sites are
 * `mesh/trust-root.ts::issueNodeIdentityCertificate`,
 * `mesh/trust-root-hybrid.ts::issueNodeIdentityCertificateV2Hybrid` and
 * `mesh/lifecycle/node-roster.ts::NodeRoster.add` — must match those three
 * guards. A new certificate-issuing or roster-admitting path must call this
 * in the same change that introduces it.
 */
export function isReservedNodeId(nodeId: string): boolean {
  return nodeId.length === 0 || nodeId === NO_AUTHENTICATED_PEER;
}

/**
 * Mint an {@link AuthenticatedPeer}. THE ONLY constructor.
 *
 * INVARIANT AT THE ENFORCEMENT SITE: call this ONLY with a node id that the
 * calling frame has already verified — the `emitter_node` of an event that
 * came back from `verifyOrThrow`, or a `node_id` off a certificate whose
 * chain was validated against the pinned master key. Calling it on an
 * unverified event's self-declared `emitter_node` re-opens exactly the defect
 * this type exists to close, and no runtime check can detect that, because a
 * forged claim and a genuine id are the same bytes. The brand's value is that
 * every such call is greppable and reviewable in one query.
 *
 * WHY THE GUARD BELOW IS NOT THE ENFORCEMENT POINT. A reserved id is refused
 * UPSTREAM, at certificate issuance and at roster admission (see
 * {@link isReservedNodeId}), so no verified event can carry one and this
 * branch is unreachable from the network. It stays as a last line of defence
 * for a future mint site added upstream of those chokepoints. It must NOT be
 * relied on as the only guard: every mint site sits on a receive path whose
 * caller invokes it as `void`, so a throw here surfaces as an unhandled
 * rejection rather than a refusal — the hazard `master-rotation.ts`'s
 * `handleIncomingMasterRotationBroadcast` doc already warns about. Establish
 * the precondition upstream; do not move the check here.
 */
export function authenticatedPeer(verifiedNodeId: string): AuthenticatedPeer {
  if (isReservedNodeId(verifiedNodeId)) {
    throw new Error(
      `authenticatedPeer: refusing to mint an authenticated peer from a reserved node id (empty, or the ${NO_AUTHENTICATED_PEER} sentinel)`
    );
  }
  return verifiedNodeId as AuthenticatedPeer;
}

/**
 * WHY an envelope/event was refused. QI-02-F12: the boundary carries this so
 * a consumer can tell a CRYPTOGRAPHIC failure apart from a LOCAL policy
 * refusal. INVARIANT: a refusal produced by the RECEIVER's own state — its
 * clock, its correlation table, its local ceilings — is never reported to an
 * operator as evidence about the peer. Without a reason class a consumer
 * cannot tell the two apart, so it must either accuse every refused peer or
 * accuse none.
 */
export const REJECTION_REASON_CLASS = {
  /**
   * Envelope verification itself failed: signature mismatch, unknown or
   * revoked emitter certificate, cross-operator isolation violation,
   * non-monotonic envelope sequence. NOTHING in the event is trustworthy,
   * including its `emitter_node`. This is the only class in which the
   * accompanying claimed emitter is unverified.
   */
  ENVELOPE_UNVERIFIED: "envelope_unverified",
  /**
   * The envelope verified, and the AUTHENTICATED emitter then failed an
   * authority check (a revoke with no valid guardian quorum or principal
   * signature, a v1-shape event refused under the clean break, an
   * authorization that does not survive re-admission of its target). An
   * in-roster peer emitting an event it has no authority for is a protocol
   * violation and remains a compromise-class signal.
   */
  PEER_AUTHORIZATION_REFUSED: "peer_authorization_refused",
  /**
   * The envelope verified and the emitter had authority, but the event fell
   * outside THIS node's freshness window (a lapsed quorum context, a replayed
   * ceremony, clock skew between emitter and receiver). Relying-side
   * freshness enforcement is correct and must stay a hard fail (rule 10) —
   * but the refusal describes a TIMING relationship between two nodes, not
   * evidence that the peer is compromised, so it must never be rendered as
   * one.
   */
  FRESHNESS_REFUSED: "freshness_refused",
  /**
   * The envelope verified, and a LOCAL bound refused it: no correlating
   * outstanding request, a quota or capacity ceiling, a store that declined
   * admission. This says something about this node's own state, so
   * attributing compromise to the peer is a category error.
   */
  CAPACITY_REFUSED: "capacity_refused",
} as const;

export type RejectionReasonClass =
  (typeof REJECTION_REASON_CLASS)[keyof typeof REJECTION_REASON_CLASS];

/**
 * Does this refusal class justify telling an operator a peer may be
 * COMPROMISED? THE ONE place that mapping is made (rule 5): the detector
 * consumes this rather than re-deriving the set, so a new reason class cannot
 * be classified one way at one consumer and another way elsewhere.
 *
 * Deliberately written as an explicit membership test over the two
 * compromise-class values rather than "not freshness and not capacity": a
 * reason class added later defaults to NOT-compromise, so the failure mode of
 * forgetting to update this function is an under-loud alert, never a false
 * accusation against a named peer.
 */
export function isCompromiseSignal(reason: RejectionReasonClass): boolean {
  return (
    reason === REJECTION_REASON_CLASS.ENVELOPE_UNVERIFIED ||
    reason === REJECTION_REASON_CLASS.PEER_AUTHORIZATION_REFUSED
  );
}

/**
 * Classify an error thrown by the POST-VERIFICATION admission path (revoke
 * admission, master-rotation receipt) into a reason class. THE ONE classifier
 * (rule 5): every admission site in the mesh calls this rather than testing
 * the error type inline, because a per-site copy is the hand-mirror shape that
 * drifts — and a drift here means one refusal path tells an operator a peer is
 * compromised for a clock skew while its sibling does not.
 *
 * Only ever called where envelope verification has ALREADY succeeded, so
 * `ENVELOPE_UNVERIFIED` is deliberately not reachable from here — a site that
 * refuses AT verification passes that class as a literal, because it knows
 * statically that verification is what failed, and inferring it from an error
 * type would be a weaker statement than the call site can already make.
 *
 * CROSS-FILE PIN: `QuorumFreshnessError` is thrown ONLY by
 * `assertQuorumContextFresh` in `mesh/guardian/revoke-quorum-input.ts`, the
 * single relying-side freshness gate (rule 10) that every mesh admission path
 * routes through — must match that function's throw sites. A future freshness
 * gate throwing a DIFFERENT error type would fall silently into the
 * authority-violation arm and reintroduce the false compromise report, so it
 * must be added here in the same change that introduces it.
 *
 * The default arm is deliberately the compromise-class one: an unrecognized
 * admission failure is treated as an authority violation and stays loud. Only
 * a positively-identified freshness failure is de-escalated, so the failure
 * mode of an unclassified error is an over-loud alert, never a missed one.
 */
export function classifyAdmissionRefusal(error: Error): RejectionReasonClass {
  return error instanceof QuorumFreshnessError
    ? REJECTION_REASON_CLASS.FRESHNESS_REFUSED
    : REJECTION_REASON_CLASS.PEER_AUTHORIZATION_REFUSED;
}
