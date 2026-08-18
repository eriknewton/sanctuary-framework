/**
 * Operator unattributed-disclosure surface: the ONE place that performs an
 * unattributed state disclosure, shared by the MCP tool and the CLI verb.
 *
 * WHY THIS IS A SHARED FUNCTION AND NOT TWO CALL SITES. This operation is a
 * deliberate hole in a guard, so its obligations are the operation, not
 * decoration on it: an audit record naming the namespace and the key, a
 * structurally distinct result, and no durable side effect. Two transports
 * hand-implementing that list is the hand-mirrored-registry shape AGENTS.md
 * assurance rule 5 names; the second copy is where the audit write goes missing
 * and nothing reds. One function, two thin callers, and a parity test that pins
 * both callers to it.
 *
 * WHAT THIS FUNCTION DOES NOT DO: the Tier-1 approval. That is applied at each
 * transport, because that is where an operator actually is - the MCP router
 * classifies `state_disclose_unattributed` Tier 1 from
 * `NON_RELAXABLE_STATE_DISCLOSURE_TIER1_OPERATIONS`, and the CLI evaluates the
 * same operation name through an `ApprovalGate` built on the same policy. Both
 * resolve the tier from that one non-relaxable set, so neither can be relaxed
 * by a hand-authored policy and the two cannot drift apart.
 */

import type { AuditLog } from "../operational/audit-log.js";
import type {
  StateStore,
  UnattributedStateDisclosure,
} from "./state-store.js";

/**
 * Wire operation name. Must match the sole entry of
 * `NON_RELAXABLE_STATE_DISCLOSURE_TIER1_OPERATIONS` in
 * `src/principal-policy/loader.ts`, the MCP tool `name` in
 * `src/cognitive/tools.ts`, and the CLI subcommand in
 * `src/cli/subcommands.ts`. A drift guard test pins all four to this constant;
 * the tier is resolved from the operation NAME, so a mismatch here would
 * silently classify the operation as unknown rather than as non-relaxable
 * Tier 1.
 */
export const UNATTRIBUTED_DISCLOSURE_OPERATION = "state_disclose_unattributed";

/** Audit operation recorded for a disclosure that was refused, not performed. */
export const UNATTRIBUTED_DISCLOSURE_REFUSED_OPERATION =
  "state_disclose_unattributed_refused";

export interface UnattributedDisclosureRequest {
  /**
   * REQUIRED, not optional, and that is the point (AGENTS.md assurance rule 3).
   * The audit record is the only trace this hole was ever used, so a caller
   * that cannot produce an audit log must not be able to perform the operation
   * at all. An optional dependency here would make "every invocation is
   * audited" true of the tests that pass one and false of any production wiring
   * that forgot, which is the exact inert-security-property shape that rule
   * exists to prevent. The type system refuses the call instead.
   */
  readonly auditLog: AuditLog;
  readonly stateStore: StateStore;
  readonly namespace: string;
  readonly key: string;
  /** Operator/principal recorded on the audit event. */
  readonly identityId: string;
  /**
   * Provenance of the Tier-1 decision that permitted this call, when the
   * transport has one to bind. Absent means the transport did not mint one, not
   * that approval was skipped; the gate itself is what enforced it.
   */
  readonly approvalAuditId?: string;
}

export type UnattributedDisclosureOutcome =
  | { readonly status: "disclosed"; readonly disclosure: UnattributedStateDisclosure }
  | { readonly status: "not_found" }
  /**
   * The ordinary verified read would have returned this entry, so the surface
   * declined rather than bypassing a control that did not need bypassing.
   */
  | { readonly status: "refused_writer_is_establishable" }
  /** Any other verification outcome (rollback, corruption, schema). */
  | { readonly status: "refused_verification"; readonly classification: string };

/**
 * Disclose the content of an entry whose writer cannot be established.
 *
 * ORDERING IS PART OF THE CONTRACT: the audit record is appended with
 * `appendCritical` and AWAITED BEFORE the read is attempted, so a disclosure
 * cannot complete without a durable trace of the attempt. Auditing afterwards
 * would leave a crash, a kill, or a throw mid-read as an untraced use of the
 * hole, and the failure mode is invisible from the outside: the operator sees
 * nothing missing, and only the absence of a record later shows it. The refusal
 * paths append their own outcome record too, so an operator reading the log can
 * tell a disclosure that happened from one that was declined.
 */
export async function discloseUnattributedState(
  request: UnattributedDisclosureRequest,
): Promise<UnattributedDisclosureOutcome> {
  const details = {
    namespace: request.namespace,
    key: request.key,
    ...(request.approvalAuditId
      ? { approval_audit_id: request.approvalAuditId }
      : {}),
  };

  await request.auditLog.appendCritical({
    layer: "l1",
    operation: UNATTRIBUTED_DISCLOSURE_OPERATION,
    identity_id: request.identityId,
    result: "success",
    details,
  });

  let disclosure: UnattributedStateDisclosure | null;
  try {
    disclosure = await request.stateStore.readUnattributed(
      request.namespace,
      request.key,
    );
  } catch (error) {
    const classification = (error as { classification?: string }).classification;
    if (classification === undefined) throw error;
    await request.auditLog.appendCritical({
      layer: "l1",
      operation: UNATTRIBUTED_DISCLOSURE_REFUSED_OPERATION,
      identity_id: request.identityId,
      result: "failure",
      details: { ...details, classification },
    });
    return classification === "writer_is_establishable"
      ? { status: "refused_writer_is_establishable" }
      : { status: "refused_verification", classification };
  }

  if (!disclosure) return { status: "not_found" };
  return { status: "disclosed", disclosure };
}
