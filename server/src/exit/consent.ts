/**
 * Sanctuary exit machinery — Slice 1: first-class consent + exit tombstone.
 *
 * Two first-class, audited surfaces, both anchored into the existing
 * hash-linked audit chain (`l2-operational/audit-log.ts`) so neither can be
 * silently removed after the fact:
 *
 *   1. CONSENT RELEASE — the mutual-agreement lever. An operator may deem a
 *      `shared_entangled` record benign and release it so it travels with the
 *      agent on exit (or affirm that an `agent_owned` write the operator
 *      reviewed is benign). This is a FIRST-CLASS surface, not a stub: it is
 *      the explicit "an operator may allow it to go" path the design ratified.
 *      It writes a critical audit entry recording the two-party disposition.
 *
 *   2. EXIT TOMBSTONE — an auditable receipt of INTENT TO REMOVE, NOT erasure.
 *      The tombstone proves *that* a datum existed and *that* a removal was
 *      recorded (content-hash bound), without retaining the content. It does
 *      NOT prove the bytes are gone: a full-disk snapshot restore resurrects
 *      "removed" data and is locally undetectable, exactly as
 *      `core/anti-rollback.ts` documents. This module states that limitation in
 *      parity with anti-rollback and never claims erasure.
 *
 * Both surfaces are operator-gated (Tier-1-style): the caller passes the
 * approving operator's identity id, and the audit entry is `appendCritical`
 * (durable, round-trip-verified) because exit dispositions are irreversible-
 * adjacent.
 */

import type { AuditLog } from "../l2-operational/audit-log.js";
import { hashToString } from "../core/hashing.js";
import { stringToBytes } from "../core/encoding.js";
import type { MemoryClass } from "./memory-class.js";

/** Audit operations emitted by the exit consent / tombstone surfaces. */
export const EXIT_CONSENT_AUDIT_OPS = {
  CONSENT_RELEASE: "exit_consent_release",
  TOMBSTONE: "exit_tombstone",
} as const;

export type ExitConsentAuditOp =
  (typeof EXIT_CONSENT_AUDIT_OPS)[keyof typeof EXIT_CONSENT_AUDIT_OPS];

export type ConsentDisposition =
  | "released_to_agent"
  | "affirmed_agent_owned_benign";

export interface ConsentReleaseInput {
  readonly auditLog: AuditLog;
  /** The approving operator's identity id (Tier-1-style gate). */
  readonly operatorIdentityId: string;
  /** The lineage id of the record whose disposition is being agreed. */
  readonly lineageId: string;
  /** The class of the record at the time of the agreement. */
  readonly memoryClass: MemoryClass;
  /** The agent the record is released to (the counterparty to the agreement). */
  readonly agentRef: string;
  readonly disposition: ConsentDisposition;
  /** Optional free-text justification recorded in the audit entry. */
  readonly justification?: string;
}

export interface ConsentReleaseReceipt {
  readonly op: typeof EXIT_CONSENT_AUDIT_OPS.CONSENT_RELEASE;
  readonly lineage_id: string;
  readonly memory_class: MemoryClass;
  readonly disposition: ConsentDisposition;
  readonly operator_identity_id: string;
  readonly agent_ref: string;
  readonly released_at: string;
}

/**
 * Record an audited two-party consent release. Writes a critical audit entry
 * into the hash-linked chain and returns a receipt. The returned
 * `lineage_id` is what the partition step consumes via
 * `consentReleasedLineageIds` to flip a `shared_entangled` record to
 * includable.
 *
 * Honest scoping: this delivers the cooperating-host case. On a hostile host
 * that refuses to run the ceremony, no software lever forces a release — that
 * needs the covenant layer's destination/registry component (deferred). This
 * function does not claim to compel an unwilling operator.
 */
export async function recordConsentRelease(
  input: ConsentReleaseInput,
): Promise<ConsentReleaseReceipt> {
  if (!input.operatorIdentityId) {
    throw new Error("recordConsentRelease: operatorIdentityId is required (Tier-1 gate)");
  }
  if (!input.lineageId) {
    throw new Error("recordConsentRelease: lineageId is required");
  }
  const released_at = new Date().toISOString();
  await input.auditLog.appendCritical({
    layer: "l1",
    operation: EXIT_CONSENT_AUDIT_OPS.CONSENT_RELEASE,
    identity_id: input.operatorIdentityId,
    result: "success",
    details: {
      lineage_id: input.lineageId,
      memory_class: input.memoryClass,
      disposition: input.disposition,
      agent_ref: input.agentRef,
      ...(input.justification !== undefined ? { justification: input.justification } : {}),
    },
  });
  await input.auditLog.flush();
  return {
    op: EXIT_CONSENT_AUDIT_OPS.CONSENT_RELEASE,
    lineage_id: input.lineageId,
    memory_class: input.memoryClass,
    disposition: input.disposition,
    operator_identity_id: input.operatorIdentityId,
    agent_ref: input.agentRef,
    released_at,
  };
}

/** Reasons an exit scrub writes a tombstone. */
export type ExitTombstoneReason =
  | "exit_scrub_operator_owned"
  | "exit_scrub_agent_owned"
  | "operator_request";

export interface ExitTombstoneInput {
  readonly auditLog: AuditLog;
  /** The operator authorizing the removal (Tier-1-style gate). */
  readonly operatorIdentityId: string;
  readonly lineageId: string;
  /** The class at the time of removal. */
  readonly memoryClass: MemoryClass;
  readonly reason: ExitTombstoneReason;
  /**
   * The content being removed. Hashed (never retained) so the tombstone proves
   * WHAT was removed without keeping it. The hash is content-derived; for low-
   * entropy operator data it is a confirmation oracle, accepted for the audit
   * benefit (design §7.4 — a keyed/salted hash is the staged hardening).
   */
  readonly content: string;
}

/**
 * An exit tombstone: an auditable receipt of INTENT TO REMOVE.
 *
 * IMPORTANT — this is NOT a cryptographic guarantee of erasure. The bytes are
 * not provably gone: a full-disk snapshot restore (Time Machine, backup, clone)
 * to a self-consistent earlier state resurrects the tombstoned data with a
 * fully valid audit chain, and is LOCALLY UNDETECTABLE on an unanchored
 * fortress — identical to the residual `core/anti-rollback.ts` documents for
 * the credential case. The honest characterization is "auditable intent to
 * remove," never "erased."
 */
export interface ExitTombstone {
  readonly format: "SANCTUARY_EXIT_TOMBSTONE_V1";
  /**
   * The semantics, spelled out so no downstream reader can mistake this for
   * erasure. Carried in the record, not just the docs.
   */
  readonly semantics: "intent_to_remove_not_erasure";
  readonly lineage_id: string;
  readonly memory_class: MemoryClass;
  readonly reason: ExitTombstoneReason;
  /** sha256 of the removed content (proves WHAT, without retaining it). */
  readonly content_hash: string;
  readonly content_hash_alg: "sha256";
  readonly removed_at: string;
  /**
   * The snapshot-resurrection limitation, carried in-record (parity with
   * anti-rollback's honest-residual posture). A consumer that reads this
   * tombstone cannot accidentally treat it as proof of erasure.
   */
  readonly erasure_limitation: "snapshot_restore_resurrects_locally_undetectable";
}

/**
 * Write an exit tombstone into the audit chain and return the tombstone record.
 * The content is hashed and discarded; only the hash is recorded.
 */
export async function writeExitTombstone(
  input: ExitTombstoneInput,
): Promise<ExitTombstone> {
  if (!input.operatorIdentityId) {
    throw new Error("writeExitTombstone: operatorIdentityId is required (Tier-1 gate)");
  }
  if (!input.lineageId) {
    throw new Error("writeExitTombstone: lineageId is required");
  }
  const content_hash = hashToString(stringToBytes(input.content));
  const removed_at = new Date().toISOString();
  const tombstone: ExitTombstone = {
    format: "SANCTUARY_EXIT_TOMBSTONE_V1",
    semantics: "intent_to_remove_not_erasure",
    lineage_id: input.lineageId,
    memory_class: input.memoryClass,
    reason: input.reason,
    content_hash,
    content_hash_alg: "sha256",
    removed_at,
    erasure_limitation: "snapshot_restore_resurrects_locally_undetectable",
  };
  await input.auditLog.appendCritical({
    layer: "l1",
    operation: EXIT_CONSENT_AUDIT_OPS.TOMBSTONE,
    identity_id: input.operatorIdentityId,
    result: "success",
    details: {
      lineage_id: tombstone.lineage_id,
      memory_class: tombstone.memory_class,
      reason: tombstone.reason,
      content_hash: tombstone.content_hash,
      semantics: tombstone.semantics,
      erasure_limitation: tombstone.erasure_limitation,
    },
  });
  await input.auditLog.flush();
  return tombstone;
}

/**
 * Characterization helper used by tests and callers to assert, in code, that a
 * tombstone is NOT erasure. Returns false for any object that claims erasure
 * semantics or omits the limitation marker — so a future refactor that tried to
 * relabel a tombstone as "erased" would fail this guard.
 */
export function isIntentToRemoveNotErasure(value: unknown): boolean {
  return (
    value !== null &&
    typeof value === "object" &&
    (value as ExitTombstone).semantics === "intent_to_remove_not_erasure" &&
    (value as ExitTombstone).erasure_limitation ===
      "snapshot_restore_resurrects_locally_undetectable"
  );
}
