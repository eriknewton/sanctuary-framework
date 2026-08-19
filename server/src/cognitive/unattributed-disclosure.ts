/**
 * Operator unattributed-disclosure surface: the ONE place that performs an
 * unattributed state disclosure, shared by the MCP tool and the CLI verb.
 *
 * WHY THIS IS A SHARED FUNCTION AND NOT TWO CALL SITES. This operation is a
 * deliberate hole in a guard, so its obligations are the operation, not
 * decoration on it: the namespace firewall, an audit record naming the
 * namespace and the key, a structurally distinct result, and no mutation of the
 * state store (this function's only writes are its own audit records; a
 * transport may create its own deliberate artifact, as the CLI does). Two transports hand-implementing that list is the
 * hand-mirrored-registry shape AGENTS.md assurance rule 5 names; the second
 * copy is where the audit write goes missing and nothing reds. One function,
 * two thin callers, and a parity test that pins both callers to it.
 *
 * THE NAMESPACE FIREWALL LIVES HERE, AND IT DID NOT ALWAYS. An adversarial gate
 * on this change found the two transports implementing different obligation
 * lists: the MCP tool applied the reserved-namespace refusal and the
 * opaque-handle ownership assertion, the CLI verb applied NEITHER, so the CLI
 * disclosed content out of a reserved namespace with exit 0. That is exactly
 * the shape this module exists to prevent, present in the module's own change.
 * Both checks are transport-INDEPENDENT - one is a pure function of the
 * namespace string, the other of the registry and the session binding the
 * caller hands in - so both now run before the audit record and before the
 * read, for every caller, and a transport cannot skip one by forgetting it.
 * The transports render the refusal; they no longer decide it.
 *
 * WHAT THIS FUNCTION DOES NOT DO: the Tier-1 approval. That is applied at each
 * transport, because that is where an operator actually is - the MCP router
 * classifies `state_disclose_unattributed` Tier 1 from
 * `NON_RELAXABLE_STATE_DISCLOSURE_TIER1_OPERATIONS`, and the CLI evaluates the
 * same operation name through an `ApprovalGate` built on the same policy. Both
 * resolve the tier from that one non-relaxable set, so neither can be relaxed
 * by a hand-authored policy and the two cannot drift apart.
 */

import type {
  OpaqueNamespaceRegistry,
  SessionBinding,
} from "../agent-native/safety-base.js";
import type { AuditLog } from "../operational/audit-log.js";
import { getReservedNamespaceViolation } from "./state-store.js";
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

/**
 * Audit operation for the PRE-READ marker: this call was authorized and is
 * about to read. Distinct from the terminal operation on purpose. A `success`
 * row written before the read asserts a disclosure happened at a moment when
 * nothing has been read yet, which is a claim the code cannot support; the
 * marker and the answer are two facts and get two rows.
 */
export const UNATTRIBUTED_DISCLOSURE_ATTEMPT_OPERATION =
  "state_disclose_unattributed_attempt";

/**
 * Audit operation for whether the disclosed content actually REACHED the
 * operator. Written by the transport, not by this function: the disclosure can
 * succeed here and still fail to be delivered (a file that cannot be written, a
 * receipt that never reaches the terminal), and without a terminal delivery row
 * the durable history reads success while the operator was told it failed.
 *
 * Must match the constant consumed in `src/cli/state-disclose.ts`.
 */
export const UNATTRIBUTED_DISCLOSURE_DELIVERY_OPERATION =
  "state_disclose_unattributed_delivery";

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
  /**
   * REQUIRED for the same reason `auditLog` is. The opaque-handle ownership
   * assertion is one of this operation's obligations, and an optional registry
   * would make "a `mem_*` namespace is only disclosed to its owner" true of the
   * transport that remembered to pass one and silently false of the transport
   * that did not. An operator process with no agent session (the CLI) passes a
   * fresh empty registry and no binding, which is not a bypass: an empty
   * registry owns no handle, so every `mem_*` namespace refuses. That is the
   * fail-closed direction.
   */
  readonly namespaceRegistry: OpaqueNamespaceRegistry;
  /**
   * The acting agent session, when the transport has one. Absent means there is
   * no agent session to check against, which REFUSES every opaque handle rather
   * than permitting it.
   */
  readonly sessionBinding?: SessionBinding;
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
   * The namespace is reserved for internal subsystem use. `reservedPrefix` is
   * the curated prefix that matched, or the namespace itself for an uncurated
   * `_`-namespace, so a transport can name it without re-deriving it.
   */
  | { readonly status: "refused_namespace_reserved"; readonly reservedPrefix: string }
  /**
   * The namespace is an opaque memory handle this caller does not own, or there
   * is no live session to own it with. Rendered as the generic namespace
   * denial: which of those two it was is not something the caller is told.
   */
  | { readonly status: "refused_namespace_unavailable" }
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
 * nothing missing, and only the absence of a record later shows it.
 *
 * TWO ROWS, NOT ONE, AND THE SPLIT IS THE POINT. The pre-read row is an
 * ATTEMPT marker under its own operation name; the row under the operation
 * name itself is TERMINAL and is written only once the outcome is known. A
 * single `success` row committed before the read asserted that a disclosure
 * happened at a moment when nothing had been read, so a call that then threw
 * left durable history reading "disclosed".
 *
 * EVERY TERMINAL OUTCOME APPENDS ITS OWN RECORD, so the attempt marker is
 * never the last word on a call that disclosed nothing. That covers the
 * classified refusals, `not_found` (which used to append nothing, leaving a
 * miss byte-identical in the log to a disclosure that happened), and an
 * ORDINARY unclassified error, which is rethrown to the caller but no longer
 * before its own failure row is durable.
 *
 * WHAT THIS FUNCTION CANNOT AUDIT is whether the content reached the
 * operator: the transport does the delivering, so it owns the
 * `..._delivery` row.
 *
 * It is also true of BOTH halves of the namespace firewall below (each naming
 * the namespace AND the key, so the audited claim holds on a refusal too),
 * which is a
 * correction: the reserved-namespace refusal used to return silently while its
 * sibling audited, so an operator greping this operation saw opaque-handle
 * denials and did NOT see an approved attempt to disclose `_identities`. The
 * asymmetry made the sentence above false against a shipped test in the same
 * commit that wrote it. Both now audit; if you add a third refusal, it audits
 * too, or this paragraph becomes false again.
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

  // NAMESPACE FIREWALL, BEFORE ANYTHING ELSE. Both checks run for every
  // transport. They sit above the audit append deliberately: a request for a
  // namespace this surface will never serve is rejected on its arguments, and
  // no `state_disclose_unattributed` success record is written for a call that
  // was never a disclosure attempt against a servable namespace.
  const reservedPrefix = getReservedNamespaceViolation(request.namespace);
  if (reservedPrefix !== null) {
    // Audited, in the same shape as its sibling refusal below. This is the
    // MORE security-interesting of the two attempts, not the less: reaching
    // here means a human already granted the Tier-1 approval (the gate runs
    // before this function, in both transports) and the target was the
    // reserved internal set - `_identities`, `_principal`, `_file_grants`.
    // An operator grepping this operation must see that attempt. It used to
    // write nothing, so it was invisible.
    //
    // No write amplification: the human approval upstream bounds the rate, so
    // an untrusted caller cannot drive this append in a loop.
    await request.auditLog.appendCritical({
      layer: "l1",
      operation: UNATTRIBUTED_DISCLOSURE_OPERATION,
      identity_id: "system",
      result: "failure",
      details: {
        namespace: request.namespace,
        // The KEY is named here too. The audited claim this surface makes is
        // "namespace and key", and a firewall row that carries only the
        // namespace makes that claim false on the two refusals an operator
        // most wants to reconstruct.
        key: request.key,
        denial_class: "namespace_reserved",
      },
    });
    return { status: "refused_namespace_reserved", reservedPrefix };
  }

  try {
    request.namespaceRegistry.assertOwned(
      request.namespace,
      request.sessionBinding,
    );
  } catch {
    // Recorded under the operation name with the repo-wide namespace denial
    // shape, and under `system` rather than the requesting principal, so it
    // sorts with every other `namespace_unavailable` denial an operator greps
    // for rather than reading as a principal's disclosure.
    await request.auditLog.appendCritical({
      layer: "l1",
      operation: UNATTRIBUTED_DISCLOSURE_OPERATION,
      identity_id: "system",
      result: "failure",
      details: {
        namespace: request.namespace,
        // Named for the same reason as its sibling above.
        key: request.key,
        denial_class: "namespace_unavailable",
      },
    });
    return { status: "refused_namespace_unavailable" };
  }

  // THE PRE-READ MARKER, under its own operation name. Awaited before the read
  // so a crash, a kill, or a throw mid-read still leaves a durable trace that
  // the hole was entered. It deliberately does NOT claim an outcome: an
  // outcome-claiming row written here would say a disclosure happened at a
  // moment when nothing has been read.
  await request.auditLog.appendCritical({
    layer: "l1",
    operation: UNATTRIBUTED_DISCLOSURE_ATTEMPT_OPERATION,
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
    if (classification === undefined) {
      // AN ORDINARY ERROR IS A TERMINAL OUTCOME TOO. A malformed encrypted
      // payload or a storage fault carries no classification and used to be
      // rethrown with no row of its own, leaving the pre-read marker as the
      // log's last word on a call that disclosed nothing. The row is written
      // before the rethrow so the caller's own error handling cannot suppress
      // it; the error itself still propagates unchanged.
      await request.auditLog.appendCritical({
        layer: "l1",
        operation: UNATTRIBUTED_DISCLOSURE_OPERATION,
        identity_id: request.identityId,
        result: "failure",
        details: { ...details, classification: "unclassified_error" },
      });
      throw error;
    }
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

  if (!disclosure) {
    // A MISS IS NOT A DISCLOSURE. Without this record the only trace of a
    // missing key is the pre-read `success` entry, which is indistinguishable
    // from a call that handed content to an operator.
    await request.auditLog.appendCritical({
      layer: "l1",
      operation: UNATTRIBUTED_DISCLOSURE_REFUSED_OPERATION,
      identity_id: request.identityId,
      result: "failure",
      details: { ...details, classification: "not_found" },
    });
    return { status: "not_found" };
  }

  // THE TERMINAL ROW, written only once the read actually produced content.
  // This is the row that means "an entry was disclosed"; everything before it
  // means "a disclosure was attempted".
  await request.auditLog.appendCritical({
    layer: "l1",
    operation: UNATTRIBUTED_DISCLOSURE_OPERATION,
    identity_id: request.identityId,
    result: "success",
    details,
  });
  return { status: "disclosed", disclosure };
}
