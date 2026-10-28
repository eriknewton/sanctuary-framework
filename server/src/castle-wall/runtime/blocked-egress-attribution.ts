import { parseBlockedEgressMetadata, type BlockedEgressMetadata } from "../../contracts/v1.1/blocked-egress.js";

declare const blockedEgressMintBrand: unique symbol;
/** Opaque handoff accepted only when minted by the audit consumer after durable persistence. */
export interface ConsumerMintedBlockedEgress {
  readonly [blockedEgressMintBrand]: true;
}

/** Display fields read by bridge admission from the consumer-owned handoff. */
export interface BlockedEgressProjection {
  metadata: BlockedEgressMetadata;
  signedFields?: { agent_id?: string; observed_at: string; source_event_id: string };
}

// Weak keys retain no event history: each bounded mint dies with its handoff token.
const blockedEgressMints = new WeakMap<ConsumerMintedBlockedEgress, BlockedEgressProjection>();

/** Bridge admission reads a detached snapshot; a shape-compatible object cannot mint credibility. */
export function readConsumerMintedBlockedEgress(token: ConsumerMintedBlockedEgress | undefined): BlockedEgressProjection | undefined {
  // Must match ingestBlockedEgress in principal-policy/unified-inbox-bridge.ts: only this private registry confers authority.
  if (!token || !blockedEgressMints.has(token)) return undefined;
  const minted = blockedEgressMints.get(token)!;
  const parsed = parseBlockedEgressMetadata(minted.metadata);
  if (!parsed.ok) throw new Error("Invalid consumer blocked-egress mint");
  return { metadata: parsed.value, ...(minted.signedFields ? { signedFields: { ...minted.signedFields } } : {}) };
}

/** Register the audit consumer's accepted projection for later bridge admission. */
export function mintConsumerBlockedEgress(projection: BlockedEgressProjection): ConsumerMintedBlockedEgress {
  // Only the audit consumer mints after signature verification and durable persistence: verified metadata carries
  // the pinned Castle Wall producer's credibility for signed display facts and its bound subject, never unsigned reasons.
  // Accepted unsigned or downgraded projections retain unverified attribution; must match blockedEgressMetadataFor
  // in castle-wall/runtime/audit-consumer.ts and the full-set guard in test/structure/blocked-egress-mint-single-caller.test.ts.
  const token = Object.freeze({}) as ConsumerMintedBlockedEgress;
  blockedEgressMints.set(token, projection);
  return token;
}
