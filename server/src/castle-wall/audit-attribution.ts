/**
 * Read-side Castle Wall audit attribution.
 *
 * Castle Wall audit rows are tamper-evident, not attribution-authoritative:
 * an in-process writer can append a fresh valid row with arbitrary
 * `details.agent_id` / `details.agent_template`. Readers that attribute an
 * agent from Castle Wall evidence must therefore re-verify the persisted
 * producer signature and derive the subject from the signed canonical body.
 */

import type { AuditEntry } from "../operational/audit-log.js";
import {
  CASTLE_WALL_AUDIT_LAYER,
  CASTLE_WALL_AUDIT_PROVENANCE_KEY,
  CASTLE_WALL_ARM_LEASE_REVOKED_OPERATION,
  CASTLE_WALL_EVIDENCE_BASIS_DETAIL_KEY,
  CASTLE_WALL_EVIDENCE_BASIS_PRODUCER_SIGNED,
  CASTLE_WALL_HEARTBEAT_OPERATION,
  CASTLE_WALL_PRODUCER_CAPTURED_AT_MS_DETAIL_KEY,
  CASTLE_WALL_PRODUCER_KID_DETAIL_KEY,
  CASTLE_WALL_PRODUCER_SIG_DETAIL_KEY,
  CASTLE_WALL_PRODUCER_SIGNED_CANONICAL_DETAIL_KEY,
} from "./constants.js";
import {
  isLegacyMacOSAuditTokenHex,
  protectionSubjectFromMacOSAuditToken,
} from "./subject-binding.js";
import {
  verifyProducerSignature,
  type ProducerSignatureInput,
  type ProducerSignatureVerdict,
} from "./runtime/producer-signature.js";

const CASTLE_WALL_ATTRIBUTION_SENSITIVE_OPERATIONS: ReadonlySet<string> =
  Object.freeze(
    new Set<string>([
      "egress_blocked",
      "egress_allowed",
      "operator_decision",
      "policy_loaded",
      "policy_validation_failed",
      "filter_started",
      "filter_stopped",
      "filter_crashed",
      "provider_unbound",
      "queue_saturated",
      "no_wall_engaged",
      "no_wall_expired",
      "wal_overflow",
      "external_firewall_clobber",
      "egress_metric_batch",
      "flow_decision_rejected",
      "audit_event_rejected",
      "producer_signature_rejected",
      CASTLE_WALL_HEARTBEAT_OPERATION,
      CASTLE_WALL_ARM_LEASE_REVOKED_OPERATION,
    ]),
  );

export interface AuditAttributionOptions {
  /**
   * Pinned producer public key used to re-verify persisted Castle Wall producer
   * signatures. No key means no verified read-side attribution.
   */
  pinnedProducerKeyB64url?: string | null;
  /**
   * Local fortress id needed to resolve macOS signed audit-token subjects.
   */
  subjectFortressId?: string | null;
  /**
   * Injectable verifier for unit tests. Production uses `verifyProducerSignature`.
   */
  verifyProducerSignature?: VerifyProducerSignatureFn;
}

export type VerifyProducerSignatureFn = (
  input: ProducerSignatureInput,
  pinnedProducerKeyB64url: string,
) => ProducerSignatureVerdict;

export interface VerifiedCastleWallAuditAttribution {
  status: "verified";
  agentId: string;
  agentTemplate: string | null;
  signedBody: Record<string, unknown>;
  signedDetails: Record<string, unknown>;
}

type ParsedSignedBody =
  | { kind: "ok"; body: Record<string, unknown> }
  | { kind: "error" };

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

export function parseCastleWallSignedCanonicalBody(
  details: Record<string, unknown>,
): Record<string, unknown> | null {
  const canonical = details[CASTLE_WALL_PRODUCER_SIGNED_CANONICAL_DETAIL_KEY];
  if (typeof canonical !== "string") return null;
  let parsed: unknown;
  try {
    parsed = JSON.parse(canonical);
  } catch {
    return null;
  }
  return isRecord(parsed) ? parsed : null;
}

function signedCanonicalDetails(
  body: Record<string, unknown>,
): Record<string, unknown> {
  return isRecord(body.details) ? body.details : {};
}

function subjectFromSignedCanonicalValue(value: unknown): string | null {
  if (typeof value !== "string" || value.length === 0) return null;
  return value;
}

type MacOSSignedSubjectResolution =
  | { status: "absent" }
  | { status: "resolved"; subject: string }
  | { status: "unresolvable" };

function macOSSubjectFromSignedCanonicalDetails(
  parsed: Record<string, unknown>,
  subjectFortressId?: string | null,
): MacOSSignedSubjectResolution {
  const details = signedCanonicalDetails(parsed);
  if (!Object.prototype.hasOwnProperty.call(details, "agent_id")) {
    return { status: "absent" };
  }
  const agentId = details.agent_id;
  if (!isLegacyMacOSAuditTokenHex(agentId)) {
    return { status: "absent" };
  }
  if (subjectFortressId === null || subjectFortressId === undefined) {
    return { status: "unresolvable" };
  }
  const subject = protectionSubjectFromMacOSAuditToken(subjectFortressId, agentId);
  return subject === null
    ? { status: "unresolvable" }
    : { status: "resolved", subject };
}

/**
 * The subject from the persisted SIGNED canonical body.
 *
 * This is the subject authority for a re-verified producer-signed Castle Wall
 * entry. The top-level audit row's `identity_id` is chosen by the in-process
 * writer that appended the row, and an arbitrary signed `details.agent_id`
 * string is only an agent metadata field unless it is a macOS audit token that
 * can be resolved with the local fortress id.
 */
export function signedCanonicalIdentityId(
  details: Record<string, unknown>,
  subjectFortressId?: string | null,
): string | null {
  const parsed = parseCastleWallSignedCanonicalBody(details);
  if (parsed === null) return null;
  const macOSSubject = macOSSubjectFromSignedCanonicalDetails(
    parsed,
    subjectFortressId,
  );
  if (macOSSubject.status === "resolved") return macOSSubject.subject;
  if (macOSSubject.status === "unresolvable") return null;
  return subjectFromSignedCanonicalValue(parsed.identity_id);
}

export function isCastleWallAttributionSensitiveEntry(
  entry: Pick<AuditEntry, "layer" | "operation" | "details">,
): boolean {
  if (entry.layer !== CASTLE_WALL_AUDIT_LAYER) return false;
  if (CASTLE_WALL_ATTRIBUTION_SENSITIVE_OPERATIONS.has(entry.operation)) {
    return true;
  }
  return (
    entry.details?.[CASTLE_WALL_EVIDENCE_BASIS_DETAIL_KEY] !== undefined ||
    entry.details?.[CASTLE_WALL_AUDIT_PROVENANCE_KEY] !== undefined
  );
}

function parseSignedBodyFromDetails(
  details: Record<string, unknown>,
): ParsedSignedBody {
  const body = parseCastleWallSignedCanonicalBody(details);
  return body === null ? { kind: "error" } : { kind: "ok", body };
}

/**
 * Re-verify one Castle Wall audit row and return signature-derived
 * attribution. Any missing field, absent key, rejected signature, or missing
 * signed subject returns null.
 */
export function verifiedCastleWallAuditAttribution(
  entry: AuditEntry,
  options: AuditAttributionOptions = {},
): VerifiedCastleWallAuditAttribution | null {
  if (!isCastleWallAttributionSensitiveEntry(entry)) return null;
  const details = entry.details;
  if (!details) return null;
  if (
    details[CASTLE_WALL_EVIDENCE_BASIS_DETAIL_KEY] !==
    CASTLE_WALL_EVIDENCE_BASIS_PRODUCER_SIGNED
  ) {
    return null;
  }
  const pinnedProducerKeyB64url = options.pinnedProducerKeyB64url ?? null;
  if (pinnedProducerKeyB64url === null) return null;

  const signatureB64url = details[CASTLE_WALL_PRODUCER_SIG_DETAIL_KEY];
  const keyId = details[CASTLE_WALL_PRODUCER_KID_DETAIL_KEY];
  const eventCanonicalJson =
    details[CASTLE_WALL_PRODUCER_SIGNED_CANONICAL_DETAIL_KEY];
  const capturedAtUnixMs =
    details[CASTLE_WALL_PRODUCER_CAPTURED_AT_MS_DETAIL_KEY];
  const seq = details.seq;
  if (
    typeof signatureB64url !== "string" ||
    typeof keyId !== "string" ||
    typeof eventCanonicalJson !== "string" ||
    typeof capturedAtUnixMs !== "number" ||
    typeof seq !== "number"
  ) {
    return null;
  }

  const input: ProducerSignatureInput = {
    eventCanonicalJson,
    capturedAtUnixMs,
    seq,
    signatureB64url,
    keyId,
  };
  const verifier = options.verifyProducerSignature ?? verifyProducerSignature;
  const verdict = verifier(input, pinnedProducerKeyB64url);
  if (!verdict.ok) return null;

  const parsed = parseSignedBodyFromDetails(details);
  if (parsed.kind !== "ok") return null;
  const agentId = signedCanonicalIdentityId(details, options.subjectFortressId);
  if (agentId === null) return null;
  const signedDetails = signedCanonicalDetails(parsed.body);
  const nestedAgent = isRecord(signedDetails.agent) ? signedDetails.agent : null;
  const agentTemplate =
    typeof signedDetails.agent_template === "string" &&
    signedDetails.agent_template.length > 0
      ? signedDetails.agent_template
      : typeof nestedAgent?.template === "string" &&
          nestedAgent.template.length > 0
        ? nestedAgent.template
        : null;

  return {
    status: "verified",
    agentId,
    agentTemplate,
    signedBody: parsed.body,
    signedDetails,
  };
}

function rawAgentIdFromDetails(details: Record<string, unknown> | undefined): string | null {
  if (!details) return null;
  const nested = isRecord(details.agent) ? details.agent.id : undefined;
  if (typeof nested === "string" && nested.length > 0) return nested;
  const flat = details.agent_id;
  return typeof flat === "string" && flat.length > 0 ? flat : null;
}

function rawAgentTemplateFromDetails(
  details: Record<string, unknown> | undefined,
): string | null {
  if (!details) return null;
  const nested = isRecord(details.agent) ? details.agent.template : undefined;
  if (typeof nested === "string" && nested.length > 0) return nested;
  const flat = details.agent_template;
  return typeof flat === "string" && flat.length > 0 ? flat : null;
}

/**
 * Agent id for general audit readers. Castle Wall attribution-sensitive rows
 * use only signature-verified attribution; non-Castle-Wall rows retain the
 * legacy metadata hint behavior.
 */
export function auditEntryAgentId(
  entry: AuditEntry,
  options: AuditAttributionOptions = {},
): string | null {
  if (isCastleWallAttributionSensitiveEntry(entry)) {
    return verifiedCastleWallAuditAttribution(entry, options)?.agentId ?? null;
  }
  return rawAgentIdFromDetails(entry.details);
}

/**
 * Agent template for general audit readers. Castle Wall attribution-sensitive
 * rows use only signature-verified signed-body details; non-Castle-Wall rows
 * retain the legacy metadata hint behavior.
 */
export function auditEntryAgentTemplate(
  entry: AuditEntry,
  options: AuditAttributionOptions = {},
): string | null {
  if (isCastleWallAttributionSensitiveEntry(entry)) {
    return (
      verifiedCastleWallAuditAttribution(entry, options)?.agentTemplate ?? null
    );
  }
  return rawAgentTemplateFromDetails(entry.details);
}
