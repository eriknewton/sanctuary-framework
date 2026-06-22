/**
 * Sanctuary — Workload Lifecycle audit schema: payload type, validation, and
 * the single sanctioned emission API.
 *
 * `AuditEntry.details` is free-form (`Record<string, unknown>`) at the chain
 * layer. Lifecycle events give it a versioned, validated shape. Validation is
 * fail-closed on an unknown `lifecycle_schema` version (constraint 5: never
 * silently degrade), matching the codebase's domain-string versioning
 * discipline (`sanctuary.audit-checkpoint.v1`, etc.).
 *
 * REVIEW INVERSIONS folded in (see the design review, 2026-06-12):
 *
 *   H1 — A `workload_deleted` event is ALWAYS valid and ALWAYS recordable,
 *   including when `consent_status: "absent"` and no override block is present.
 *   Refusing to record an unconsented destruction would be the exact omission
 *   pattern this schema exists to kill: the worst act would be the one
 *   guaranteed to leave no chain record. Prevention of unconsented deletes is
 *   the Tier-1 POLICY GATE's job, not schema validity. The schema's role here
 *   is to make the act loud and permanently marked, never to suppress it.
 *
 *   H2 — `prev_lifecycle_seq` detects a dropped RECORD (the per-instance linked
 *   list of recorded events), NOT an unrecorded real-world transition. A host
 *   that kills a declared instance and emits nothing leaves a perfectly closed
 *   linked list ending in "still running"; this layer cannot detect that.
 *   Likewise lineage claims (`lineage.parents`) are bound at recording time and
 *   cannot be rewritten afterward, but a host that mis-declares a fork's origin
 *   at emission is NOT caught here — that is the registry-attestation /
 *   undeclared-workload frontier, a separate later build item. The comments and
 *   docs state this limit precisely and never claim lineage-laundering is
 *   prevented.
 *
 *   Per-entry external verification (Merkle inclusion proofs that let a single
 *   disclosed entry be checked against an off-host root without the full
 *   entry-hash list) is its OWN later build item. `computeAuditRoot` is a flat
 *   hash today, not a Merkle tree; this module does NOT claim inclusion proofs.
 *
 * Design: Review/Sanctuary/Mind_Hosting_Audit_Schema_Design_2026-06-12.md
 */

import { canonicalJson, sha256Hex } from "../audit/chain.js";
import type { AuditEntryInput } from "../operational/audit-log.js";
import type { AuditLog } from "../operational/audit-log.js";
import {
  WORKLOAD_LIFECYCLE_OPS,
  WORKLOAD_LIFECYCLE_SCHEMA,
  isWorkloadLifecycleOp,
  type WorkloadLifecycleOp,
  type WorkloadLifecycleSchema,
} from "./constants.js";

/** Thrown when a lifecycle payload fails validation. Fail-closed. */
export class WorkloadLifecycleSchemaError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "WorkloadLifecycleSchemaError";
  }
}

export type InitiatorKind = "operator" | "agent" | "guardian" | "policy";

export interface LifecycleInitiator {
  kind: InitiatorKind;
  identity_id: string;
  /** Signer key id for the bound mesh SignedEvent, when available. */
  signer_kid?: string;
}

export interface LifecycleLineage {
  /** Parent instance ids. `>= 2` on merge; exactly 1 on fork. */
  parents: string[];
  /** Anchor for future persona keying (reserved; later identity build item). */
  lineage_root?: string;
}

/** Consent coverage status. NEVER omitted — absence is a loud, legal value. */
export type ConsentStatus = "present" | "absent" | "inherited";

/** State disposition after the transition. */
export type StateDisposition = "running" | "preserved" | "destroyed";

/**
 * Override block for an exceptional `workload_deleted` without a `consent_ref`.
 * Records who authorized destruction, why, and which approval record backs it.
 * Its presence does NOT make an unconsented delete "valid vs invalid" — every
 * delete is valid (H1); the override block is the operator's on-chain account
 * of an exceptional act, hash-pinned at the time of the act.
 */
export interface DeleteOverride {
  approved_by: string;
  reason: string;
  /** Id of the Tier-1 approval record this delete was authorized under. */
  approval_record_id: string;
}

/**
 * The versioned `details` payload for a workload-lifecycle audit entry.
 *
 * No workload CONTENT ever enters this payload — names, prompts, memories, and
 * outputs are excluded by schema. `state_commitment` is a hash, not state.
 */
export interface WorkloadLifecyclePayload {
  lifecycle_schema: WorkloadLifecycleSchema;
  /** Stable registry id, assigned at first registration. */
  workload_id: string;
  /** This running instance (forks get new instance ids). */
  instance_id: string;
  /** Declared classification (public string: "stateful-agent"). */
  workload_class: string;
  /** Published, versioned threshold-definition id this class was declared under. */
  class_definition: string;
  initiator: LifecycleInitiator;
  /** Present on fork/merge/instantiate-from-state. */
  lineage?: LifecycleLineage;
  /** Reference to a consent record (separate namespace); never the body. */
  consent_ref: string | null;
  /** Required enum — "absent" is a legal, loud value (design §2.4). */
  consent_status: ConsentStatus;
  state_disposition: StateDisposition;
  /** Hash of the preserved state bundle on pause/sleep/fork/merge.
   * Self-reported: presence here attests the operator's claim of preservation;
   * it is NOT a verification that the bundle exists or survives (review M4). */
  state_commitment?: string;
  /** Optional agent-contract compatibility field. */
  checkpoint_hash?: string;
  /**
   * Binds this audit entry to exactly one mesh `SignedEvent` for the transition.
   * REQUIRED for a mesh-origin event (the seal always sets it); ABSENT for a
   * mesh-less event (operator-CLI registration, mesh-less delete). Optional at
   * the schema layer on purpose — forcing it would make a mesh-less act
   * unrecordable, the omission pattern H1 forbids. See `constants.ts` for the
   * precise dual-channel invariant.
   */
  signed_event_hash?: string;
  /**
   * Per-instance ordinal of this instance's PREVIOUS recorded lifecycle event,
   * forming an intra-stream linked list. This is an emitter-supplied ordinal,
   * NOT necessarily the global audit-chain sequence number: an emitter that can
   * read back the chain sequence (e.g. a future fold-aware writer) may set it to
   * the true chain sequence, but the Tier-B adapter seal writes its own
   * monotonic per-instance count because `appendCritical` returns no sequence.
   *
   * What it proves (H2): a dropped RECORD in this instance's recorded stream is
   * detectable (the linked list breaks). What it does NOT prove: that an event
   * was recorded for every real-world transition — a host that simply never
   * emits leaves a perfectly closed list. Lineage laundering is likewise not
   * prevented here; that is the registry-attestation / undeclared-workload
   * frontier (a separate later build item).
   */
  prev_lifecycle_seq?: number;
  /** Exceptional-delete account (H1). Optional; never gates emittability. */
  override?: DeleteOverride;
  /** Reserved revival-policy commitment (design open question; policy later). */
  revival_review_at?: string;
  /** revival_class on sleep: how the preserved state is held. */
  revival_class?: "operator_on_demand" | "escrowed" | "embargoed";
  /** Honest insufficiency flag: v1 consent is operator/spawner authorization on
   * the workload's behalf, not agent-side consent. Always true in v1. */
  manufactured_preference_caveat?: boolean;
}

const INITIATOR_KINDS: readonly InitiatorKind[] = [
  "operator",
  "agent",
  "guardian",
  "policy",
];
const CONSENT_STATUSES: readonly ConsentStatus[] = [
  "present",
  "absent",
  "inherited",
];
const STATE_DISPOSITIONS: readonly StateDisposition[] = [
  "running",
  "preserved",
  "destroyed",
];

const REVIVAL_CLASSES: readonly NonNullable<
  WorkloadLifecyclePayload["revival_class"]
>[] = ["operator_on_demand", "escrowed", "embargoed"];

/** Closed set of top-level keys. Any other key is rejected (no content smuggling). */
const ALLOWED_TOP_LEVEL_KEYS: ReadonlySet<string> = new Set([
  "lifecycle_schema",
  "workload_id",
  "instance_id",
  "workload_class",
  "class_definition",
  "initiator",
  "lineage",
  "consent_ref",
  "consent_status",
  "state_disposition",
  "state_commitment",
  "checkpoint_hash",
  "signed_event_hash",
  "prev_lifecycle_seq",
  "override",
  "revival_review_at",
  "revival_class",
  "manufactured_preference_caveat",
]);
const ALLOWED_INITIATOR_KEYS: ReadonlySet<string> = new Set([
  "kind",
  "identity_id",
  "signer_kid",
]);
const ALLOWED_LINEAGE_KEYS: ReadonlySet<string> = new Set([
  "parents",
  "lineage_root",
]);
const ALLOWED_OVERRIDE_KEYS: ReadonlySet<string> = new Set([
  "approved_by",
  "reason",
  "approval_record_id",
]);

function isPlainObject(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

function isNonEmptyString(v: unknown): v is string {
  return typeof v === "string" && v.length > 0;
}

/** Reject any key outside `allowed`. The whole point is that NO field outside
 * the published schema (a prompt, a memory, a secret) can ride in the payload
 * — the "lifecycle, not contents" privacy invariant, enforced not just
 * asserted. */
function rejectUnknownKeys(
  obj: Record<string, unknown>,
  allowed: ReadonlySet<string>,
  where: string
): void {
  for (const key of Object.keys(obj)) {
    if (!allowed.has(key)) {
      throw new WorkloadLifecycleSchemaError(
        `unknown key "${key}" in ${where} — lifecycle payloads carry no free-form content`
      );
    }
  }
}

/**
 * Validate (and fail closed on) a lifecycle payload.
 *
 * Returns the typed payload on success. Throws `WorkloadLifecycleSchemaError`
 * on any structural violation OR on an unknown `lifecycle_schema` version
 * (constraint 5: fail closed for attestation-relevant reads, never "silently
 * degrade"). A plain operator query that merely renders entries may catch this
 * and show the entry as opaque-but-present; an attestation/verification read
 * must let it throw.
 *
 * NOTE (H1): this validator NEVER rejects a `workload_deleted` payload for
 * lacking consent or an override. `consent_status: "absent"` with no override
 * is a fully valid, recordable payload — loud and marked, by design.
 */
export function validateWorkloadLifecyclePayload(
  v: unknown
): WorkloadLifecyclePayload {
  if (!isPlainObject(v)) {
    throw new WorkloadLifecycleSchemaError(
      `lifecycle payload must be an object; got ${typeof v}`
    );
  }
  // Closed schema: reject any field outside the published vocabulary BEFORE
  // anything else, so a smuggled `prompt`/`memory`/secret never reaches the
  // chain even via a cast caller (the no workload-content invariant, enforced).
  rejectUnknownKeys(v, ALLOWED_TOP_LEVEL_KEYS, "lifecycle payload");

  if (v.lifecycle_schema !== WORKLOAD_LIFECYCLE_SCHEMA) {
    // Fail closed on unknown / missing version — do not guess a shape.
    throw new WorkloadLifecycleSchemaError(
      `unknown lifecycle_schema ${JSON.stringify(
        v.lifecycle_schema
      )}; expected "${WORKLOAD_LIFECYCLE_SCHEMA}" (fail closed)`
    );
  }
  if (!isNonEmptyString(v.workload_id)) {
    throw new WorkloadLifecycleSchemaError("workload_id required");
  }
  if (!isNonEmptyString(v.instance_id)) {
    throw new WorkloadLifecycleSchemaError("instance_id required");
  }
  if (!isNonEmptyString(v.workload_class)) {
    throw new WorkloadLifecycleSchemaError("workload_class required");
  }
  if (!isNonEmptyString(v.class_definition)) {
    throw new WorkloadLifecycleSchemaError("class_definition required");
  }
  if (!isPlainObject(v.initiator)) {
    throw new WorkloadLifecycleSchemaError("initiator required");
  }
  rejectUnknownKeys(v.initiator, ALLOWED_INITIATOR_KEYS, "initiator");
  if (!INITIATOR_KINDS.includes(v.initiator.kind as InitiatorKind)) {
    throw new WorkloadLifecycleSchemaError(
      `initiator.kind must be one of ${INITIATOR_KINDS.join("|")}`
    );
  }
  if (!isNonEmptyString(v.initiator.identity_id)) {
    throw new WorkloadLifecycleSchemaError("initiator.identity_id required");
  }
  if (
    v.initiator.signer_kid !== undefined &&
    !isNonEmptyString(v.initiator.signer_kid)
  ) {
    throw new WorkloadLifecycleSchemaError(
      "initiator.signer_kid must be a non-empty string if present"
    );
  }
  const initiator: LifecycleInitiator = {
    kind: v.initiator.kind as InitiatorKind,
    identity_id: v.initiator.identity_id,
    ...(v.initiator.signer_kid !== undefined
      ? { signer_kid: v.initiator.signer_kid as string }
      : {}),
  };
  // consent_status is REQUIRED — silence is the failure mode the design kills.
  if (!CONSENT_STATUSES.includes(v.consent_status as ConsentStatus)) {
    throw new WorkloadLifecycleSchemaError(
      `consent_status required, one of ${CONSENT_STATUSES.join("|")} (never omitted)`
    );
  }
  if (v.consent_ref !== null && !isNonEmptyString(v.consent_ref)) {
    throw new WorkloadLifecycleSchemaError(
      "consent_ref must be a non-empty string or null"
    );
  }
  if (!STATE_DISPOSITIONS.includes(v.state_disposition as StateDisposition)) {
    throw new WorkloadLifecycleSchemaError(
      `state_disposition must be one of ${STATE_DISPOSITIONS.join("|")}`
    );
  }
  let lineage: LifecycleLineage | undefined;
  if (v.lineage !== undefined) {
    if (!isPlainObject(v.lineage) || !Array.isArray(v.lineage.parents)) {
      throw new WorkloadLifecycleSchemaError(
        "lineage.parents must be an array if lineage present"
      );
    }
    rejectUnknownKeys(v.lineage, ALLOWED_LINEAGE_KEYS, "lineage");
    if (!v.lineage.parents.every((p) => isNonEmptyString(p))) {
      throw new WorkloadLifecycleSchemaError(
        "lineage.parents must be non-empty strings"
      );
    }
    if (
      v.lineage.lineage_root !== undefined &&
      !isNonEmptyString(v.lineage.lineage_root)
    ) {
      throw new WorkloadLifecycleSchemaError(
        "lineage.lineage_root must be a non-empty string if present"
      );
    }
    lineage = {
      parents: [...(v.lineage.parents as string[])],
      ...(v.lineage.lineage_root !== undefined
        ? { lineage_root: v.lineage.lineage_root as string }
        : {}),
    };
  }
  if (v.prev_lifecycle_seq !== undefined) {
    if (
      typeof v.prev_lifecycle_seq !== "number" ||
      !Number.isInteger(v.prev_lifecycle_seq) ||
      v.prev_lifecycle_seq < 0
    ) {
      throw new WorkloadLifecycleSchemaError(
        "prev_lifecycle_seq must be a non-negative integer if present"
      );
    }
  }
  let override: DeleteOverride | undefined;
  if (v.override !== undefined) {
    if (
      !isPlainObject(v.override) ||
      !isNonEmptyString(v.override.approved_by) ||
      !isNonEmptyString(v.override.reason) ||
      !isNonEmptyString(v.override.approval_record_id)
    ) {
      throw new WorkloadLifecycleSchemaError(
        "override must carry approved_by, reason, approval_record_id"
      );
    }
    rejectUnknownKeys(v.override, ALLOWED_OVERRIDE_KEYS, "override");
    override = {
      approved_by: v.override.approved_by,
      reason: v.override.reason,
      approval_record_id: v.override.approval_record_id,
    };
  }
  // Validate optional binding/string fields so the sanctioned writer cannot
  // emit a malformed binding (review M2 round 2).
  if (v.state_commitment !== undefined && !isNonEmptyString(v.state_commitment)) {
    throw new WorkloadLifecycleSchemaError(
      "state_commitment must be a non-empty string if present"
    );
  }
  if (v.checkpoint_hash !== undefined && !isNonEmptyString(v.checkpoint_hash)) {
    throw new WorkloadLifecycleSchemaError(
      "checkpoint_hash must be a non-empty string if present"
    );
  }
  if (
    v.signed_event_hash !== undefined &&
    !isNonEmptyString(v.signed_event_hash)
  ) {
    throw new WorkloadLifecycleSchemaError(
      "signed_event_hash must be a non-empty string if present"
    );
  }
  if (
    v.revival_review_at !== undefined &&
    !isNonEmptyString(v.revival_review_at)
  ) {
    throw new WorkloadLifecycleSchemaError(
      "revival_review_at must be a non-empty string if present"
    );
  }
  if (
    v.revival_class !== undefined &&
    !REVIVAL_CLASSES.includes(
      v.revival_class as NonNullable<WorkloadLifecyclePayload["revival_class"]>
    )
  ) {
    throw new WorkloadLifecycleSchemaError(
      `revival_class must be one of ${REVIVAL_CLASSES.join("|")} if present`
    );
  }
  if (
    v.manufactured_preference_caveat !== undefined &&
    typeof v.manufactured_preference_caveat !== "boolean"
  ) {
    throw new WorkloadLifecycleSchemaError(
      "manufactured_preference_caveat must be a boolean if present"
    );
  }

  // Construct a FRESH object from validated fields only. Even if some future
  // edit slipped an unchecked key past the guard above, what gets written to
  // the chain is built here from the known vocabulary — never the raw input.
  const out: WorkloadLifecyclePayload = {
    lifecycle_schema: WORKLOAD_LIFECYCLE_SCHEMA,
    workload_id: v.workload_id,
    instance_id: v.instance_id,
    workload_class: v.workload_class,
    class_definition: v.class_definition,
    initiator,
    consent_ref: v.consent_ref as string | null,
    consent_status: v.consent_status as ConsentStatus,
    state_disposition: v.state_disposition as StateDisposition,
    ...(lineage ? { lineage } : {}),
    ...(v.state_commitment !== undefined
      ? { state_commitment: v.state_commitment as string }
      : {}),
    ...(v.checkpoint_hash !== undefined
      ? { checkpoint_hash: v.checkpoint_hash as string }
      : {}),
    ...(v.signed_event_hash !== undefined
      ? { signed_event_hash: v.signed_event_hash as string }
      : {}),
    ...(v.prev_lifecycle_seq !== undefined
      ? { prev_lifecycle_seq: v.prev_lifecycle_seq as number }
      : {}),
    ...(override ? { override } : {}),
    ...(v.revival_review_at !== undefined
      ? { revival_review_at: v.revival_review_at as string }
      : {}),
    ...(v.revival_class !== undefined
      ? {
          revival_class: v.revival_class as NonNullable<
            WorkloadLifecyclePayload["revival_class"]
          >,
        }
      : {}),
    ...(v.manufactured_preference_caveat !== undefined
      ? { manufactured_preference_caveat: v.manufactured_preference_caveat }
      : {}),
  };
  return out;
}

/** Compute the canonical `signed_event_hash` for a packed mesh SignedEvent.
 * sha256 over canonical JSON of the packed event, matching chain hash
 * discipline (hash a canonical form, never a lossy re-encode). */
export function signedEventHash(packedSignedEvent: unknown): string {
  return sha256Hex(canonicalJson(packedSignedEvent));
}

/**
 * Parameters for {@link emitWorkloadLifecycle}. The `operation` is constrained
 * to the lifecycle vocabulary; the `payload` is validated before any write.
 */
export interface EmitWorkloadLifecycleParams {
  auditLog: AuditLog;
  operation: WorkloadLifecycleOp;
  identity_id: string;
  payload: WorkloadLifecyclePayload;
  /** "success" by default; an unconsented/forced delete is still "success" as a
   * RECORD of what happened — the gap is surfaced via consent_status/override,
   * not via result:"failure". */
  result?: "success" | "failure";
  timestamp?: string;
}

/**
 * THE single sanctioned writer of `workload_*` lifecycle audit entries
 * (review M3). It validates the payload (fail-closed) and appends a CRITICAL,
 * durability-verified, hash-chained audit entry. No other call site should
 * write a `WORKLOAD_LIFECYCLE_OPS` operation directly; a test asserts this.
 *
 * H1: a `workload_deleted` with `consent_status:"absent"` and no override is
 * accepted and recorded here, loud and marked. This function does NOT enforce
 * the Tier-1 approval that SHOULD precede a real delete — that gate runs
 * upstream (policy gate / operator CLI). This function guarantees only that
 * whatever happened is recorded tamper-evidently.
 */
export async function emitWorkloadLifecycle(
  params: EmitWorkloadLifecycleParams
): Promise<WorkloadLifecyclePayload> {
  // Defense in depth: TypeScript constrains `operation` to the lifecycle
  // vocabulary, but a JS or cast caller could pass an off-vocabulary string.
  // Fail closed so a lifecycle PAYLOAD can never be written under an operation
  // outside this module's vocabulary.
  if (!isWorkloadLifecycleOp(params.operation)) {
    throw new WorkloadLifecycleSchemaError(
      `operation ${JSON.stringify(
        params.operation
      )} is not a workload-lifecycle op`
    );
  }
  // The distress op is reused as a VOCABULARY MARKER for chain completeness
  // (an auditor folding lifecycle ops sees distress signals in the same set),
  // but the canonical distress emitter (`distress/tools.ts`) is the ONLY
  // sanctioned writer of `sanctuary_distress` — it owns the bounded envelope,
  // rate limit, signature, local notification, and signal-egress-before-audit
  // ordering. This generic lifecycle writer must NOT short-circuit any of that,
  // so it refuses to write the distress op directly.
  if (params.operation === WORKLOAD_LIFECYCLE_OPS.DISTRESS_SIGNALED) {
    throw new WorkloadLifecycleSchemaError(
      "sanctuary_distress must be emitted only through the canonical distress " +
        "emitter (distress/tools.ts), never the generic lifecycle writer"
    );
  }
  const payload = validateWorkloadLifecyclePayload(params.payload);
  assertOpPayloadConsistency(params.operation, payload);
  const entry: AuditEntryInput = {
    layer: "l2",
    operation: params.operation,
    identity_id: params.identity_id,
    result: params.result ?? "success",
    details: payload as unknown as Record<string, unknown>,
    ...(params.timestamp ? { timestamp: params.timestamp } : {}),
  };
  await params.auditLog.appendCritical(entry);
  return payload;
}

/**
 * Op ↔ payload INTERNAL-CONSISTENCY check (review M2 round 3).
 *
 * This validates that a recorded claim is internally coherent — it does NOT
 * gate on consent or approval, and it never makes an act unrecordable for
 * lacking authorization (that would re-create the omission pattern H1 forbids).
 * It only rejects a self-contradictory RECORD: a delete that claims its state
 * still runs, a fork with the wrong parent cardinality, a sleep that claims
 * destruction. The honest, gated path (delete + absent consent + override) is
 * fully permitted.
 */
function assertOpPayloadConsistency(
  operation: WorkloadLifecycleOp,
  payload: WorkloadLifecyclePayload
): void {
  switch (operation) {
    case WORKLOAD_LIFECYCLE_OPS.DELETED:
      if (payload.state_disposition !== "destroyed") {
        throw new WorkloadLifecycleSchemaError(
          `workload_deleted must record state_disposition "destroyed", got "${payload.state_disposition}"`
        );
      }
      break;
    case WORKLOAD_LIFECYCLE_OPS.SLEPT:
    case WORKLOAD_LIFECYCLE_OPS.PAUSED:
      if (payload.state_disposition === "destroyed") {
        throw new WorkloadLifecycleSchemaError(
          `${operation} preserves state; state_disposition must not be "destroyed"`
        );
      }
      break;
    case WORKLOAD_LIFECYCLE_OPS.FORKED:
      if (!payload.lineage || payload.lineage.parents.length !== 1) {
        throw new WorkloadLifecycleSchemaError(
          "workload_forked must carry lineage with exactly one parent"
        );
      }
      break;
    case WORKLOAD_LIFECYCLE_OPS.MERGED:
      if (!payload.lineage || payload.lineage.parents.length < 2) {
        throw new WorkloadLifecycleSchemaError(
          "workload_merged must carry lineage with at least two parents"
        );
      }
      break;
    default:
      // instantiate/resume/register carry no extra cross-field constraints here.
      break;
  }
}

export { WORKLOAD_LIFECYCLE_OPS };
