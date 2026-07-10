/**
 * DISTINCT local audit operation strings for the enforcement-export lifecycle.
 *
 * These are NEW at-rest audit `operation` values, documented per the
 * frozen-surface rule. They are LOCAL strings only: none of them widens a
 * shared/global enum (widening a shared enum fans out to every audit consumer,
 * so a new state is always a distinct value in a local field). They are also
 * NOT wire messages and NOT tiers dispatched through the approval gate; they are
 * `AuditLog` entry `operation` values that record what the operator-side
 * exporter did.
 *
 * `refused` is deliberately distinct from `emitted` so an operator can tell a
 * fail-closed refusal (no opt-in, no pinned destination, denied Tier-1 gate, or
 * an unreachable pinned collector) from a normal successful emission.
 */

/** The exporter enabled an OUTBOUND push sink (Tier-1 approved, pinned destination). */
export const ENFORCEMENT_EXPORT_ENABLED = "enforcement_export_enabled" as const;

/** The exporter delivered a batch of mapped events to its configured sink. */
export const ENFORCEMENT_EXPORT_EMITTED = "enforcement_export_emitted" as const;

/**
 * The exporter REFUSED to deliver (fail-closed): missing opt-in, missing/invalid
 * pinned destination, denied Tier-1 approval, or an unreachable/failed pinned
 * collector. Never a silent drop; never a fallback to a different lane.
 */
export const ENFORCEMENT_EXPORT_REFUSED = "enforcement_export_refused" as const;
