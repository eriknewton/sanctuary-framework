/**
 * Sanctuary — Workload Lifecycle audit schema: constants & vocabulary.
 *
 * Public name: "workload lifecycle audit" / "workload lifecycle events".
 * Internal substrate for the workload-attestation position paper's rung (a):
 * first-class, signed, chain-bound lifecycle events for declared stateful
 * ("mind-class") workloads.
 *
 * This module is ADDITIVE on top of the existing audit chain. Lifecycle events
 * are ordinary `AUDIT_CHAIN_SCHEMA_VERSION = 2` entries whose `operation` is one
 * of `WORKLOAD_LIFECYCLE_OPS` and whose `details` carries the versioned payload
 * defined in `./payload.ts`. Nothing here touches chaining, anchors, or
 * checkpoint verification (envelope hashing is over
 * `sequence/prev_hash/timestamp/encrypted_payload_bytes/schema_version` only).
 *
 * What this schema does NOT claim — stated here so it travels with the code:
 *   - No consciousness detection. `workload_class` is a declared classification
 *     against a published behavioral threshold, never a sentience verdict in
 *     either direction.
 *   - No welfare verdict, and no completeness against a host that simply never
 *     declares a workload (that gap belongs to registry attestation, a later
 *     build item — see `prev_lifecycle_seq` honesty note in `./payload.ts`).
 *
 * Design: Review/Sanctuary/Mind_Hosting_Audit_Schema_Design_2026-06-12.md
 * Review:  Review/Sanctuary/Mind_Hosting_Audit_Schema_Design_Review_2026-06-12.md
 */

import { SANCTUARY_DISTRESS_OPERATION } from "../distress/tools.js";

/** Domain-string version for the lifecycle `details` payload. */
export const WORKLOAD_LIFECYCLE_SCHEMA = "sanctuary.workload-lifecycle.v1" as const;
export type WorkloadLifecycleSchema = typeof WORKLOAD_LIFECYCLE_SCHEMA;

/** Domain-string version for the consent-record payload (reserved; consent
 * records are a separate later build item — referenced by `consent_ref` only
 * in v1, never embedded). Declared here so the vocabulary is single-sourced. */
export const WORKLOAD_CONSENT_SCHEMA = "sanctuary.workload-consent.v1" as const;

/** Domain-string version for the published mind-class threshold definition.
 * Versioned separately because it moves on a science timescale; the registry
 * attestation (later) names which definition version it was made under. */
export const WORKLOAD_CLASS_DEFINITION = "sanctuary.workload-class.v1" as const;

/**
 * Operation constants on the free-form `AuditEntry.operation` field, following
 * the `BROKER_OPS` additive-only pattern. Every value is a distinct
 * `operation` string an auditor can filter the chain on.
 *
 * `DISTRESS_SIGNALED` deliberately reuses the CANONICAL `sanctuary_distress`
 * operation already shipped (the habeas port, #497) rather than minting a
 * second distress vocabulary. The chain record of a distress signal IS its
 * lifecycle event; there is no separate `workload_distress_signaled` string.
 * Egress ordering for that lane is owned by the distress emitter
 * (signal egress first, audit record after — see `distress/tools.ts`).
 */
export const WORKLOAD_LIFECYCLE_OPS = {
  INSTANTIATED: "workload_instantiated",
  PAUSED: "workload_paused",
  RESUMED: "workload_resumed",
  FORKED: "workload_forked",
  MERGED: "workload_merged",
  /** Default termination: execution stops, full state preserved, revival-capable. */
  SLEPT: "workload_slept",
  /** Exceptional, gated termination: state destroyed. ALWAYS recordable
   * (H1 inversion) — prevention is the Tier-1 policy gate's job, never schema
   * validity. An unconsented delete is recorded LOUD, not suppressed. */
  DELETED: "workload_deleted",
  /** Registry entry created/updated without a run-state change. */
  REGISTERED: "workload_registered",
  /**
   * Host-level workload attestation emitted (rung b). A signed statement over
   * the DECLARED/recorded workload set and its consent disposition, sealed as a
   * chain-bound critical entry. Scope is declared-workloads-only — it does NOT
   * assert host-wide process completeness (that is the separate registry-
   * attestation / undeclared-workload frontier, a later item). Additive: the
   * attestation event records THAT an attestation was made; it never gates or
   * suppresses a lifecycle event.
   */
  HOST_ATTESTED: "workload_host_attestation",
  /** Distress channel exercised — reuses the canonical distress operation. */
  DISTRESS_SIGNALED: SANCTUARY_DISTRESS_OPERATION,
} as const;

export type WorkloadLifecycleOp =
  (typeof WORKLOAD_LIFECYCLE_OPS)[keyof typeof WORKLOAD_LIFECYCLE_OPS];

/** All lifecycle operation strings, for membership checks. */
export const WORKLOAD_LIFECYCLE_OP_VALUES: readonly string[] = Object.freeze(
  Object.values(WORKLOAD_LIFECYCLE_OPS)
);

/** True iff `op` is a workload-lifecycle operation string. */
export function isWorkloadLifecycleOp(op: string): op is WorkloadLifecycleOp {
  return WORKLOAD_LIFECYCLE_OP_VALUES.includes(op);
}

/**
 * Normative op ↔ agent-contract `to_state` mapping (design §1.2, review M5).
 *
 * Published as part of `sanctuary.workload-lifecycle.v1` so a second reader
 * cross-checking an audit entry's `signed_event_hash` against the bound mesh
 * `SignedEvent` knows which mesh `to_state` legally binds to which audit
 * `operation`. The mapping is intentionally many-to-one on the audit side:
 * `revoked` is who-decided, not what-happened-to-state, so a guardian-initiated
 * termination records as `workload_slept` (the state was preserved) while its
 * bound mesh event still says `to_state: "revoked"`. This is not a mismatch —
 * it is the documented mapping a verifier consults.
 *
 * `checkpointed` maps to no distinct op: a checkpoint is a property
 * (`checkpoint_hash`) carried on another transition, not a treatment-relevant
 * transition of its own. A `checkpointed` mesh transition therefore has no
 * 1:1 audit counterpart by design (review M5(a)).
 *
 * The dual-channel invariant is precise (and intentionally NOT "every audit
 * entry has a mesh event"): an audit entry that DOES originate from a mesh
 * transition MUST carry `signed_event_hash`, binding it to exactly one mesh
 * `SignedEvent`; an audit entry with NO mesh counterpart (an operator-CLI-origin
 * registration, or a mesh-less delete) carries no `signed_event_hash` and is a
 * recordable, marked, mesh-less event. Binding is required for mesh-origin
 * events and absent-by-honesty for the rest — `signed_event_hash` is therefore
 * optional at the schema layer ON PURPOSE: forcing it would make a mesh-less act
 * (e.g. an unconsented CLI delete) unrecordable, which is exactly the omission
 * pattern H1 forbids. The agent-contract SEAL, which always holds a SignedEvent,
 * always populates it.
 */
export const STATE_TO_LIFECYCLE_OP: Readonly<
  Record<string, WorkloadLifecycleOp | null>
> = Object.freeze({
  launched: WORKLOAD_LIFECYCLE_OPS.INSTANTIATED,
  paused: WORKLOAD_LIFECYCLE_OPS.PAUSED,
  resumed: WORKLOAD_LIFECYCLE_OPS.RESUMED,
  // Default termination is sleep; delete is the exceptional gated path and is
  // NOT auto-derived from a `retired` state — a caller asking to destroy state
  // must say so explicitly, so `retired` maps to the safe default.
  retired: WORKLOAD_LIFECYCLE_OPS.SLEPT,
  revoked: WORKLOAD_LIFECYCLE_OPS.SLEPT,
  // No audit op — checkpoint is a payload property, not a treatment transition.
  checkpointed: null,
});

/**
 * Resolve the audit operation for an agent-contract `to_state`. Returns `null`
 * for `checkpointed` (no audit counterpart) and `undefined` for an unknown
 * state (caller fails closed).
 */
export function lifecycleOpForState(
  toState: string
): WorkloadLifecycleOp | null | undefined {
  if (!(toState in STATE_TO_LIFECYCLE_OP)) return undefined;
  return STATE_TO_LIFECYCLE_OP[toState];
}
