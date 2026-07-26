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
import { canonicalize } from "../mesh/canonical-json.js";
import {
  CASTLE_WALL_EVIDENCE_BASIS_DETAIL_KEY,
  CASTLE_WALL_EVIDENCE_BASIS_PRODUCER_SIGNED,
  CASTLE_WALL_PRODUCER_CAPTURED_AT_MS_DETAIL_KEY,
  CASTLE_WALL_PRODUCER_KID_DETAIL_KEY,
  CASTLE_WALL_PRODUCER_SIG_DETAIL_KEY,
  CASTLE_WALL_PRODUCER_SIGNED_CANONICAL_DETAIL_KEY,
  CASTLE_WALL_SIGNED_ROW_BINDING_IGNORED_DETAIL_KEYS,
  CASTLE_WALL_WAL_SEQUENCE_DETAIL_KEY,
} from "./constants.js";
import {
  fortressIdFromProtectionSubject,
  isLegacyMacOSAuditTokenHex,
  protectionSubjectFromMacOSAuditToken,
} from "./subject-binding.js";
import {
  verifyProducerSignature,
  type ProducerSignatureInput,
  type ProducerSignatureVerdict,
} from "./runtime/producer-signature.js";

const CASTLE_WALL_SIGNED_OPERATION_TO_AUDIT_OPERATION: ReadonlyMap<string, string> =
  new Map([
    ["egress_blocked", "egress_blocked"],
    ["egress_allowed", "egress_allowed"],
    ["egress_approved", "egress_allowed"],
    ["egress_pending", "operator_decision"],
  ]);

const ROW_BINDING_IGNORED_DETAIL_KEYS: ReadonlySet<string> = new Set(
  CASTLE_WALL_SIGNED_ROW_BINDING_IGNORED_DETAIL_KEYS,
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

export type AuditAttributionOptionsResolver = () =>
  | AuditAttributionOptions
  | Promise<AuditAttributionOptions>;

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

function normalizedEvidenceDetails(
  details: Record<string, unknown> | undefined,
): Record<string, unknown> {
  if (!details) return {};
  const out: Record<string, unknown> = {};
  for (const [key, value] of Object.entries(details)) {
    if (!ROW_BINDING_IGNORED_DETAIL_KEYS.has(key)) out[key] = value;
  }
  return out;
}

function canonicalJsonEquals(left: unknown, right: unknown): boolean {
  try {
    return canonicalize(left) === canonicalize(right);
  } catch {
    return false;
  }
}

function subjectFromSignedCanonicalValue(
  value: unknown,
  subjectFortressId?: string | null,
): string | null {
  if (typeof value !== "string" || value.length === 0) return null;
  if (subjectFortressId === null || subjectFortressId === undefined) return null;
  if (fortressIdFromProtectionSubject(value) !== subjectFortressId) return null;
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
  const identitySubject = subjectFromSignedCanonicalValue(
    parsed.identity_id,
    subjectFortressId,
  );
  if (identitySubject !== null) return identitySubject;
  const macOSSubject = macOSSubjectFromSignedCanonicalDetails(
    parsed,
    subjectFortressId,
  );
  if (macOSSubject.status === "resolved") return macOSSubject.subject;
  return null;
}

function signedCanonicalBodyIdentityId(
  body: Record<string, unknown>,
  subjectFortressId?: string | null,
): string | null {
  const identitySubject = subjectFromSignedCanonicalValue(
    body.identity_id,
    subjectFortressId,
  );
  if (identitySubject !== null) return identitySubject;
  const macOSSubject = macOSSubjectFromSignedCanonicalDetails(
    body,
    subjectFortressId,
  );
  if (macOSSubject.status === "resolved") return macOSSubject.subject;
  return null;
}

export function isCastleWallAttributionSensitiveEntry(
  _entry: Pick<AuditEntry, "layer" | "operation" | "details">,
): boolean {
  // Compatibility export: attribution is sensitive by default for every audit
  // row. Do not narrow this back to a layer/operation allowlist.
  return true;
}

function parseSignedBodyFromDetails(
  details: Record<string, unknown>,
): ParsedSignedBody {
  const body = parseCastleWallSignedCanonicalBody(details);
  return body === null ? { kind: "error" } : { kind: "ok", body };
}

function signedOperationMatchesPersistedEntry(
  signedOperation: unknown,
  persistedOperation: string,
): boolean {
  if (typeof signedOperation !== "string" || signedOperation.length === 0) {
    return false;
  }
  const mapped =
    CASTLE_WALL_SIGNED_OPERATION_TO_AUDIT_OPERATION.get(signedOperation) ??
    signedOperation;
  return mapped === persistedOperation;
}

function normalizedSignedOperation(operation: unknown): unknown {
  if (typeof operation !== "string" || operation.length === 0) {
    return operation;
  }
  return (
    CASTLE_WALL_SIGNED_OPERATION_TO_AUDIT_OPERATION.get(operation) ??
    operation
  );
}

function normalizedSignedResult(result: unknown): unknown {
  if (result === "blocked") return "failure";
  if (result === "pending") return "success";
  return result;
}

function normalizedPersistedRowForSignedComparison(
  entry: AuditEntry,
): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  for (const [key, value] of Object.entries(
    entry as AuditEntry & Record<string, unknown>,
  )) {
    out[key] =
      key === "details" && isRecord(value)
        ? normalizedEvidenceDetails(value)
        : value;
  }
  return out;
}

function normalizedSignedBodyForPersistedComparison(
  body: Record<string, unknown>,
  subjectFortressId?: string | null,
): Record<string, unknown> | null {
  const signedSubject = signedCanonicalBodyIdentityId(body, subjectFortressId);
  if (signedSubject === null) return null;

  const out: Record<string, unknown> = {};
  for (const [key, value] of Object.entries(body)) {
    if (key === "operation") {
      out.operation = normalizedSignedOperation(value);
    } else if (key === "result") {
      out.result = normalizedSignedResult(value);
    } else if (key === "identity_id") {
      out.identity_id = signedSubject;
    } else if (key === "details" && isRecord(value)) {
      out.details = normalizedEvidenceDetails(value);
    } else {
      out[key] = value;
    }
  }
  out.identity_id = signedSubject;
  return out;
}

function signedBodyMatchesPersistedEntry(
  entry: AuditEntry,
  body: Record<string, unknown>,
  subjectFortressId?: string | null,
): boolean {
  if (!signedOperationMatchesPersistedEntry(body.operation, entry.operation)) {
    return false;
  }
  const signedComparable = normalizedSignedBodyForPersistedComparison(
    body,
    subjectFortressId,
  );
  if (signedComparable === null) return false;
  return canonicalJsonEquals(
    normalizedPersistedRowForSignedComparison(entry),
    signedComparable,
  );
}

/**
 * Re-verify one Castle Wall audit row and return signature-derived
 * attribution. Any missing field, absent key, rejected signature, or missing
 * signed subject returns null. A valid detached signature is not enough: the
 * signed canonical body must also bind to the persisted row being projected.
 */
export function verifiedCastleWallAuditAttribution(
  entry: AuditEntry,
  options: AuditAttributionOptions = {},
): VerifiedCastleWallAuditAttribution | null {
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
  const seq = details[CASTLE_WALL_WAL_SEQUENCE_DETAIL_KEY];
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
  if (
    !signedBodyMatchesPersistedEntry(
      entry,
      parsed.body,
      options.subjectFortressId,
    )
  ) {
    return null;
  }
  const agentId = signedCanonicalBodyIdentityId(
    parsed.body,
    options.subjectFortressId,
  );
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

/**
 * Agent id for general audit readers. Attribution is default-deny: only a
 * re-verified producer-signed row projects an agent. Forgeable details metadata
 * never projects attribution.
 */
export function auditEntryAgentId(
  entry: AuditEntry,
  options: AuditAttributionOptions = {},
): string | null {
  return verifiedCastleWallAuditAttribution(entry, options)?.agentId ?? null;
}

/**
 * Agent template for general audit readers. Attribution is default-deny: only a
 * re-verified producer-signed row projects a template. Forgeable details
 * metadata never projects attribution.
 */
export function auditEntryAgentTemplate(
  entry: AuditEntry,
  options: AuditAttributionOptions = {},
): string | null {
  return verifiedCastleWallAuditAttribution(entry, options)?.agentTemplate ?? null;
}
