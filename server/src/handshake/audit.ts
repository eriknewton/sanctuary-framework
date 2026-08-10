/**
 * Sanctuary MCP Server, Sovereignty Handshake: Session-Lifecycle Audit Hooks
 *
 * Hardening wave 6 finding #90.
 *
 * The four MCP tool entry points (handshake_initiate / handshake_respond /
 * handshake_complete / handshake_status) already audit each tool action in
 * server/src/handshake/tools.ts. Those entries answer "which tool was
 * invoked." This module adds session-lifecycle entries that answer "which
 * state the session reached, regardless of which tool drove the transition":
 *
 *   handshake_initiated , session is created, awaiting counterparty
 *   handshake_completed , both nonces signed and verified, sovereignty established
 *   handshake_failed    , verification step rejected the session (signature, SHR, version)
 *   handshake_aborted   , session was discarded without ever reaching completed (timeout, operator cancel, transport drop)
 *
 * The hooks reuse the existing AuditLog class, no new logger, no new
 * transport. Operations are appended at layer "l4" so they sort with the
 * existing handshake_* entries.
 */

import type { AuditLog } from "../operational/audit-log.js";

/**
 * Session-lifecycle audit operation names. Distinct from the tool-action
 * names (handshake_initiate, handshake_respond, etc.) so audit consumers
 * can filter on lifecycle state without parsing tool semantics.
 */
export const HANDSHAKE_LIFECYCLE_OPS = {
  INITIATED: "handshake_initiated",
  COMPLETED: "handshake_completed",
  FAILED: "handshake_failed",
  ABORTED: "handshake_aborted",
} as const;

export type HandshakeLifecycleOp =
  (typeof HANDSHAKE_LIFECYCLE_OPS)[keyof typeof HANDSHAKE_LIFECYCLE_OPS];

/** Reasons a handshake may transition to the failed state. */
export type HandshakeFailureReason =
  | "shr_invalid"
  | "nonce_signature_invalid"
  | "protocol_version_unsupported"
  | "no_signing_identity"
  | "session_unknown"
  | "session_state_mismatch"
  | "session_expired"
  // Class-level self-vouch guard (register §Z RECHECK / LD2-02): the
  // counterparty's signing DID is one this fortress currently holds
  // (identityManager.list()), so the "verification" would be self-referential
  // rather than independent. Distinct from sameSigningKey's identical-key
  // rejection in protocol.ts — this catches two DISTINCT locally-held keys.
  | "self_vouch_local_did"
  | "other";

/** Reasons a handshake may be aborted (operator or transport). */
export type HandshakeAbortReason =
  | "operator_cancelled"
  | "session_timeout"
  | "transport_dropped"
  | "shutdown"
  | "other";

export interface HandshakeLifecycleContext {
  /** Local session identifier. */
  session_id: string;
  /** Role this side played in the session. */
  role: "initiator" | "responder";
  /** Identity id of the local principal. Used as the audit subject. */
  identity_id: string;
  /** Counterparty identity id, when known. */
  counterparty_id?: string;
}

/**
 * Append a handshake_initiated audit entry. Fires when a fresh session
 * record is created and stored.
 */
export function auditHandshakeInitiated(
  auditLog: AuditLog,
  ctx: HandshakeLifecycleContext
): void {
  void auditLog.append(
    "l4",
    HANDSHAKE_LIFECYCLE_OPS.INITIATED,
    ctx.identity_id,
    detailsFromContext(ctx),
    "success"
  );
}

/**
 * Append a handshake_completed audit entry. Fires when both nonces have
 * been signed and verified, i.e., the session has reached the completed
 * state on this side.
 */
export function auditHandshakeCompleted(
  auditLog: AuditLog,
  ctx: HandshakeLifecycleContext & {
    /** Trust tier surfaced by the completion result. */
    trust_tier?: string;
  }
): void {
  const details = detailsFromContext(ctx);
  if (ctx.trust_tier !== undefined) {
    details.trust_tier = ctx.trust_tier;
  }
  void auditLog.append(
    "l4",
    HANDSHAKE_LIFECYCLE_OPS.COMPLETED,
    ctx.identity_id,
    details,
    "success"
  );
}

/**
 * Append a handshake_failed audit entry. Fires when verification rejects
 * the session, signature mismatch, SHR invalid, protocol-version drift,
 * or any other fatal error during a state transition.
 */
export function auditHandshakeFailed(
  auditLog: AuditLog,
  ctx: HandshakeLifecycleContext & {
    reason: HandshakeFailureReason;
    error?: string;
  }
): void {
  const details = detailsFromContext(ctx);
  details.reason = ctx.reason;
  if (ctx.error !== undefined) {
    details.error = ctx.error;
  }
  void auditLog.append(
    "l4",
    HANDSHAKE_LIFECYCLE_OPS.FAILED,
    ctx.identity_id,
    details,
    "failure"
  );
}

/**
 * Append a handshake_aborted audit entry. Fires when a session is
 * discarded without ever reaching the completed state, operator cancel,
 * timeout, transport drop, or shutdown.
 */
export function auditHandshakeAborted(
  auditLog: AuditLog,
  ctx: HandshakeLifecycleContext & {
    reason: HandshakeAbortReason;
  }
): void {
  const details = detailsFromContext(ctx);
  details.reason = ctx.reason;
  void auditLog.append(
    "l4",
    HANDSHAKE_LIFECYCLE_OPS.ABORTED,
    ctx.identity_id,
    details,
    "failure"
  );
}

function detailsFromContext(
  ctx: HandshakeLifecycleContext
): Record<string, unknown> {
  const details: Record<string, unknown> = {
    session_id: ctx.session_id,
    role: ctx.role,
  };
  if (ctx.counterparty_id !== undefined) {
    details.counterparty_id = ctx.counterparty_id;
  }
  return details;
}
