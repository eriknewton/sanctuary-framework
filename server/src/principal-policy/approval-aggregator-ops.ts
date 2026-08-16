/**
 * Wire operation names emitted by the cross-harness approval aggregator.
 *
 * Kept in a side-effect-free module so readers such as the evidence-pack
 * aggregator can share the wire strings without importing the aggregator
 * implementation.
 */
export const APPROVAL_AGGREGATOR_AUDIT_OPS = {
  AGGREGATED: "cross_harness_approval_aggregated",
  RESOLVED: "cross_harness_approval_resolved",
  DEDUPED: "cross_harness_approval_deduped",
  PAYLOAD_DECRYPTED: "cross_harness_approval_payload_decrypted",
  AUDIT_TRAIL_VIEWED: "cross_harness_approval_audit_trail_viewed",
  REPLAYED: "cross_harness_approval_replayed",
} as const;
