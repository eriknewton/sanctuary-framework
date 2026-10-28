import { parseBlockedEgressMetadata, type BlockedEgressMetadata } from "../../contracts/v1.1/blocked-egress.js";

declare const blockedEgressMintBrand: unique symbol;
/** Opaque handoff accepted only when minted by the audit consumer after durable persistence. */
export interface ConsumerMintedBlockedEgress {
  readonly [blockedEgressMintBrand]: true;
}

/** Display fields read by bridge admission from the consumer-owned handoff. */
export interface BlockedEgressProjection {
  metadata: BlockedEgressMetadata;
  signedFields?: { agent_id: string; observed_at: string; source_event_id: string };
}

// Weak keys retain no event history: each bounded mint dies with its handoff token.
const blockedEgressMints = new WeakMap<ConsumerMintedBlockedEgress, BlockedEgressProjection>();

/** Bridge admission consumes a token once and reads a detached snapshot; shape alone cannot mint credibility. */
export function readConsumerMintedBlockedEgress(token: ConsumerMintedBlockedEgress | undefined): BlockedEgressProjection | undefined {
  // Must match ingestBlockedEgress in principal-policy/unified-inbox-bridge.ts: only this private registry confers authority.
  if (!token || !blockedEgressMints.has(token)) return undefined;
  const minted = blockedEgressMints.get(token)!;
  // Consume before parsing so neither successful nor failed admission can replay this authority.
  blockedEgressMints.delete(token);
  const parsed = parseBlockedEgressMetadata(minted.metadata);
  if (!parsed.ok) throw new Error("Invalid consumer blocked-egress mint");
  return { metadata: parsed.value, ...(minted.signedFields ? { signedFields: { ...minted.signedFields } } : {}) };
}

/**
 * Register a single-use consumer projection. Verified covers signed host/IP,
 * string agent_id, timestamp, signature-bound seq, and the consumer subject from
 * signed agent_id with local fortress scope or signed identity_id. Reason, reason
 * class, severity and other envelope fields remain unsigned.
 */
export function mintConsumerBlockedEgress(projection: BlockedEgressProjection): ConsumerMintedBlockedEgress {
  // Only the audit consumer mints after signature verification and durable persistence: verified metadata carries
  // the pinned Castle Wall producer's credibility for signed display facts and its bound subject, never unsigned reasons.
  // Accepted unsigned or downgraded projections retain unverified attribution; must match blockedEgressMetadataFor
  // in castle-wall/runtime/audit-consumer.ts and the full-set guard in test/structure/blocked-egress-mint-single-caller.test.ts.
  // Accepted residual: callers are in-process code inside the server trust domain; no untrusted input reaches this mint directly.
  const token = Object.freeze({}) as ConsumerMintedBlockedEgress;
  blockedEgressMints.set(token, projection);
  return token;
}
