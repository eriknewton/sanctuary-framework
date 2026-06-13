/**
 * Sanctuary — Agent-contract audit-log SEAL.
 *
 * This closes the deferred TODO in `agent-contract/lifecycle.ts`:
 *
 *   "The audit-log seal on `retired` is NOT implemented here — it is a
 *    downstream consumer concern (the audit log subsystem watches for the
 *    event). This module only emits."
 *
 * The seal is that downstream consumer. Given a freshly emitted agent-contract
 * `LifecycleEvent` and its packed mesh `SignedEvent`, it writes the matching
 * CRITICAL workload-lifecycle audit-chain entry, binding the two channels by
 * `signed_event_hash`. The mesh `SignedEvent` proves WHO authorized the
 * transition (portable, identity-signed); the audit-chain entry proves
 * COMPLETENESS AND ORDER (chained, tamper-evident). Neither alone has both.
 *
 * Why a seal rather than baking the audit write into `emitLifecycleEvent`:
 * `emitLifecycleEvent` is a pure builder that runs in contexts with no
 * `AuditLog` instance (and is unit-tested as such). Sealing is the job of the
 * fortress-side caller that holds BOTH the mesh stream and the `AuditLog` —
 * today the Tier-B adapter (`agent-contract/adapters/tier-b-sdk.ts`), the only
 * production caller of `emitLifecycleEvent`. The seal is injected there as an
 * optional sink so wiring it is additive and non-breaking.
 *
 * Dual-channel invariant (review M5): a MESH-ORIGIN lifecycle audit entry binds
 * to exactly one mesh event via `signed_event_hash`. Because the seal always
 * holds a `SignedEvent`, every entry it writes IS bound. (Entries written
 * through the generic writer with no mesh counterpart — e.g. an operator-CLI
 * registration — are honestly unbound; see `constants.ts`.) `checkpointed`
 * transitions map to NO audit op (a checkpoint is a payload property, not a
 * treatment transition) and are the one deliberately-unmirrored transition; the
 * seal returns `null` for them rather than inventing an op.
 */

import type { LifecycleEvent } from "../agent-contract/types.js";
import type { SignedEvent } from "../mesh/types.js";
import type { AuditLog } from "../l2-operational/audit-log.js";
import { lifecycleOpForState } from "./constants.js";
import {
  WORKLOAD_LIFECYCLE_SCHEMA,
  WORKLOAD_CLASS_DEFINITION,
} from "./constants.js";
import {
  emitWorkloadLifecycle,
  signedEventHash,
  type LifecycleInitiator,
  type WorkloadLifecyclePayload,
} from "./payload.js";

/** Standing context the seal needs that does not vary per transition. */
export interface LifecycleSealContext {
  auditLog: AuditLog;
  /**
   * Declared workload class for this agent (public string, e.g.
   * "stateful-agent"). Honest by default — a wrapped harness session is the
   * operator's workload, not a claimed mind-class; the caller passes the
   * truthful classification rather than the schema asserting one.
   */
  workload_class: string;
  /** Published threshold-definition id; defaults to the v1 definition. */
  class_definition?: string;
  /** How to read the acting initiator for the audit payload. */
  initiator: LifecycleInitiator;
  /**
   * Audit `identity_id` field (the fortress/identity recording the entry).
   * Distinct from `initiator.identity_id`, which records who authorized the
   * transition.
   */
  recording_identity_id: string;
}

export interface LifecycleSealInput {
  event: LifecycleEvent;
  signed_event: SignedEvent<LifecycleEvent>;
  /** Stable registry id for the workload (assigned at first registration). */
  workload_id: string;
  /** Running instance id (forks get a new one). */
  instance_id: string;
  /**
   * Per-instance ordinal of this instance's previous RECORDED lifecycle event,
   * if any. Detects a dropped RECORD only (H2) — never an unrecorded
   * transition. This is the caller's own ordinal, NOT the global audit-chain
   * sequence (the `appendCritical` contract returns no sequence to bind to).
   */
  prev_lifecycle_seq?: number;
  /** Optional fork/merge lineage. */
  lineage?: WorkloadLifecyclePayload["lineage"];
  /** Optional preserved-state-bundle hash (self-reported; not verified). */
  state_commitment?: string;
  /** Consent reference + status. Defaults to absent/null — loud, never omitted. */
  consent_ref?: string | null;
  consent_status?: WorkloadLifecyclePayload["consent_status"];
}

/**
 * Seal an agent-contract lifecycle transition into the audit chain.
 *
 * Returns the written payload, or `null` when the transition maps to no audit
 * op (`checkpointed`). Throws on an unknown `to_state` (fail closed) or on a
 * payload/persistence failure (the underlying `appendCritical` contract).
 */
export async function sealLifecycleEmission(
  ctx: LifecycleSealContext,
  input: LifecycleSealInput
): Promise<WorkloadLifecyclePayload | null> {
  const op = lifecycleOpForState(input.event.to_state);
  if (op === undefined) {
    // Unknown contract state — never invent an op; fail closed.
    throw new Error(
      `cannot seal lifecycle event: unknown to_state "${input.event.to_state}"`
    );
  }
  if (op === null) {
    // `checkpointed`: the one deliberately-unmirrored transition (review M5).
    return null;
  }

  const state_disposition =
    op === "workload_deleted"
      ? "destroyed"
      : op === "workload_slept" ||
          op === "workload_paused" ||
          op === "workload_forked" ||
          op === "workload_merged"
        ? "preserved"
        : "running";

  const payload: WorkloadLifecyclePayload = {
    lifecycle_schema: WORKLOAD_LIFECYCLE_SCHEMA,
    workload_id: input.workload_id,
    instance_id: input.instance_id,
    workload_class: ctx.workload_class,
    class_definition: ctx.class_definition ?? WORKLOAD_CLASS_DEFINITION,
    initiator: ctx.initiator,
    consent_ref: input.consent_ref ?? null,
    // Never omitted; defaults to the loud "absent" so a missing consent surfaces
    // rather than disappearing (design §2.4).
    consent_status: input.consent_status ?? "absent",
    state_disposition,
    signed_event_hash: signedEventHash(input.signed_event),
    manufactured_preference_caveat: true,
    ...(input.lineage ? { lineage: input.lineage } : {}),
    ...(input.state_commitment
      ? { state_commitment: input.state_commitment }
      : {}),
    ...(input.event.checkpoint_hash
      ? { checkpoint_hash: input.event.checkpoint_hash }
      : {}),
    ...(input.prev_lifecycle_seq !== undefined
      ? { prev_lifecycle_seq: input.prev_lifecycle_seq }
      : {}),
  };

  return emitWorkloadLifecycle({
    auditLog: ctx.auditLog,
    operation: op,
    identity_id: ctx.recording_identity_id,
    payload,
  });
}
