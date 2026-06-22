/**
 * Sanctuary Composition v1.0 -- Concordia Adapter
 *
 * High-level API for packing and verifying Concordia receipts via the
 * Python sidecar. Maps Sanctuary signed-event envelope shapes to
 * Concordia envelope shapes. No direct Concordia SDK imports.
 *
 * signature_scheme is MANDATORY on every composition-emitted envelope.
 */

import { SIDECAR_RPC_METHODS, SIDECAR_SIGNATURE_SCHEME, CONCORDIA_RECEIPT_SCHEMA_URN } from "./constants.js";
import type { SidecarRpcClient } from "./sidecar-rpc.js";
import type {
  CommitmentEvent,
  ConcordiaAttestationMetadata,
  ConcordiaReceipt,
  ConcordiaReference,
  MandateVerificationResult,
} from "./types.js";
import { MandateVerificationError, SidecarResponseShapeError } from "./errors.js";
import { COMPOSITION_DEFAULTS, CONCORDIA_MANDATE_SCHEMA_URN } from "./constants.js";
import {
  assertBoolean,
  assertChecksRecord,
  assertNonEmptyString,
  assertOptionalPlainObject,
  assertOptionalString,
  assertPlainObject,
} from "./assert-shape.js";

const MANDATE_CHECK_FLAGS = [
  "signature_valid",
  "chain_valid",
  "not_expired",
  "not_revoked",
  "constraints_valid",
] as const;

const MANDATE_VALID_STATUSES = ["active", "expired", "revoked", "suspended"] as const;
type MandateStatus = (typeof MANDATE_VALID_STATUSES)[number];

type AttestationMetadataField =
  | "commitment_class"
  | "references_count"
  | "counterparty_count"
  | "offers_made"
  | "concession_magnitude"
  | "reasoning_provided";

const ATTESTATION_METADATA_FIELDS: readonly AttestationMetadataField[] = [
  "commitment_class",
  "references_count",
  "counterparty_count",
  "offers_made",
  "concession_magnitude",
  "reasoning_provided",
] as const;

const ATTESTATION_METADATA_FIELD_SET = new Set<string>(
  ATTESTATION_METADATA_FIELDS
);

const DISALLOWED_ATTESTATION_METADATA_FIELD_MESSAGE =
  "Concordia sidecar attestation_metadata contains a disallowed field";

const RAW_TERM_VALUE_PATTERNS = [
  /\$/,
  /\b(?:price|amount|quantity|qty|total|terms?|currency|cost|fee|budget|deliverable|deadline|invoice)\b/i,
  /\b\d+(?:\.\d{1,2})?\s*(?:usd|dollars?|units?|items?|hours?)\b/i,
] as const;

function isMandateStatus(v: unknown): v is MandateStatus {
  return (
    typeof v === "string" &&
    (MANDATE_VALID_STATUSES as readonly string[]).includes(v)
  );
}

function stringLooksLikeRawTerms(value: string): boolean {
  return RAW_TERM_VALUE_PATTERNS.some((pattern) => pattern.test(value));
}

function assertSafeMetadataLabel(
  method: string,
  field: AttestationMetadataField,
  value: unknown
): string {
  if (typeof value !== "string" || value.length === 0 || value.length > 128) {
    throw new SidecarResponseShapeError(
      method,
      `field "attestation_metadata.${field}" must be a non-empty string up to 128 characters`
    );
  }
  if (stringLooksLikeRawTerms(value)) {
    throw new SidecarResponseShapeError(
      method,
      `field "attestation_metadata.${field}" contains raw-term-like text`
    );
  }
  return value;
}

function assertNonNegativeIntegerMetadata(
  method: string,
  field: AttestationMetadataField,
  value: unknown
): number {
  if (typeof value !== "number" || !Number.isInteger(value) || value < 0) {
    throw new SidecarResponseShapeError(
      method,
      `field "attestation_metadata.${field}" must be a non-negative integer`
    );
  }
  return value;
}

function assertConcessionMagnitude(
  method: string,
  value: unknown
): number {
  if (typeof value !== "number" || !Number.isFinite(value) || value < 0 || value > 1) {
    throw new SidecarResponseShapeError(
      method,
      `field "attestation_metadata.concession_magnitude" must be a number from 0 to 1`
    );
  }
  return value;
}

function assertBooleanMetadata(
  method: string,
  field: AttestationMetadataField,
  value: unknown
): boolean {
  if (typeof value !== "boolean") {
    throw new SidecarResponseShapeError(
      method,
      `field "attestation_metadata.${field}" must be a boolean`
    );
  }
  return value;
}

function assertConcordiaAttestationMetadata(
  method: string,
  metadata: Record<string, unknown> | undefined
): ConcordiaAttestationMetadata | undefined {
  if (metadata === undefined) return undefined;

  const out: ConcordiaAttestationMetadata = {};
  for (const [key, value] of Object.entries(metadata)) {
    if (!ATTESTATION_METADATA_FIELD_SET.has(key)) {
      throw new SidecarResponseShapeError(
        method,
        DISALLOWED_ATTESTATION_METADATA_FIELD_MESSAGE
      );
    }

    const field = key as AttestationMetadataField;
    switch (field) {
      case "commitment_class":
        out.commitment_class = assertSafeMetadataLabel(method, field, value);
        break;
      case "references_count":
        out.references_count = assertNonNegativeIntegerMetadata(method, field, value);
        break;
      case "counterparty_count":
        out.counterparty_count = assertNonNegativeIntegerMetadata(method, field, value);
        break;
      case "offers_made":
        out.offers_made = assertNonNegativeIntegerMetadata(method, field, value);
        break;
      case "concession_magnitude":
        out.concession_magnitude = assertConcessionMagnitude(method, value);
        break;
      case "reasoning_provided":
        out.reasoning_provided = assertBooleanMetadata(method, field, value);
        break;
    }
  }
  return out;
}

/**
 * Pack a Concordia receipt from a Sanctuary commitment event.
 * Calls the sidecar's pack_receipt RPC method.
 *
 * @param rpc Active RPC client to the running sidecar
 * @param event Commitment event from chat gate or policy engine
 * @returns ConcordiaReceipt
 */
export async function packConcordiaReceipt(
  rpc: SidecarRpcClient,
  event: CommitmentEvent
): Promise<ConcordiaReceipt> {
  // Build references array from mesh peer refs (intra-mesh graph, acceptance criterion 9)
  const references: ConcordiaReference[] = [];

  // Add reference to the source Sanctuary event
  references.push({
    ref_type: "receipt",
    ref_id: event.event_id,
    relationship: "references",
    metadata: {
      source: "sanctuary_commitment",
      event_type: event.event_type,
    },
  });

  // Add mesh quorum peer references (intra-mesh references graph)
  if (event.mesh_peer_refs && event.mesh_peer_refs.length > 0) {
    for (const peerId of event.mesh_peer_refs) {
      references.push({
        ref_type: "receipt",
        ref_id: peerId,
        relationship: "references",
        metadata: { source: "mesh_quorum_peer" },
      });
    }
  }

  const response = await rpc.call(SIDECAR_RPC_METHODS.PACK_RECEIPT, {
    source_event_id: event.event_id,
    source_event_type: event.event_type,
    agent_id: event.agent_id,
    counterparty_id: event.counterparty_id,
    commitment_class: event.commitment_class,
    fortress_id: event.fortress_id,
    emitter_node: event.emitter_node,
    references: references.map((r) => ({
      ref_type: r.ref_type,
      ref_id: r.ref_id,
      relationship: r.relationship,
      metadata: r.metadata,
    })),
    bounded_scope: event.bounded_scope,
    signature_scheme: SIDECAR_SIGNATURE_SCHEME,
    emitted_at: event.emitted_at,
  });

  if (response.error) {
    throw new Error(`Sidecar pack_receipt failed: ${response.error.message}`);
  }

  const result = assertPlainObject(SIDECAR_RPC_METHODS.PACK_RECEIPT, response.result);
  const receiptId = assertNonEmptyString(SIDECAR_RPC_METHODS.PACK_RECEIPT, result, "receipt_id");
  const signature = assertNonEmptyString(SIDECAR_RPC_METHODS.PACK_RECEIPT, result, "signature");
  const packedAt =
    assertOptionalString(SIDECAR_RPC_METHODS.PACK_RECEIPT, result, "packed_at") ??
    new Date().toISOString();
  const attestationMetadata = assertConcordiaAttestationMetadata(
    SIDECAR_RPC_METHODS.PACK_RECEIPT,
    assertOptionalPlainObject(
      SIDECAR_RPC_METHODS.PACK_RECEIPT,
      result,
      "attestation_metadata"
    )
  );

  return {
    receipt_id: receiptId,
    schema_urn: CONCORDIA_RECEIPT_SCHEMA_URN,
    source_event_id: event.event_id,
    source_event_type: event.event_type,
    agent_id: event.agent_id,
    counterparty_id: event.counterparty_id,
    commitment_class: event.commitment_class,
    references,
    signature,
    signature_scheme: SIDECAR_SIGNATURE_SCHEME,
    packed_at: packedAt,
    bounded_scope: event.bounded_scope,
    attestation_metadata: attestationMetadata,
  };
}

/**
 * Verify a Concordia receipt via the sidecar.
 *
 * @param rpc Active RPC client
 * @param receipt The receipt to verify
 * @returns true if valid, false otherwise
 */
export async function verifyConcordiaReceipt(
  rpc: SidecarRpcClient,
  receipt: ConcordiaReceipt
): Promise<boolean> {
  const response = await rpc.call(SIDECAR_RPC_METHODS.VERIFY_RECEIPT, {
    receipt_id: receipt.receipt_id,
    signature: receipt.signature,
    agent_id: receipt.agent_id,
    counterparty_id: receipt.counterparty_id,
    commitment_class: receipt.commitment_class,
    references: receipt.references,
    packed_at: receipt.packed_at,
    source_event_id: receipt.source_event_id,
    source_event_type: receipt.source_event_type,
    signature_scheme: receipt.signature_scheme,
    bounded_scope: receipt.bounded_scope,
  });

  if (response.error) {
    return false;
  }

  const result = assertPlainObject(SIDECAR_RPC_METHODS.VERIFY_RECEIPT, response.result);
  return assertBoolean(SIDECAR_RPC_METHODS.VERIFY_RECEIPT, result, "valid");
}

/**
 * Verify a Concordia mandate (delegation chain) via the sidecar.
 *
 * @param rpc Active RPC client
 * @param mandateData Mandate dict from Concordia v0.4.0 shape
 * @returns MandateVerificationResult
 * @throws MandateVerificationError on verification failure
 */
export async function verifyMandate(
  rpc: SidecarRpcClient,
  mandateData: Record<string, unknown>
): Promise<MandateVerificationResult> {
  const mandateId = (mandateData.mandate_id as string) ?? "unknown";

  // Enforce delegation depth limit
  const chain = mandateData.delegation_chain as unknown[];
  if (chain && chain.length > COMPOSITION_DEFAULTS.MAX_MANDATE_DELEGATION_DEPTH) {
    throw new MandateVerificationError(
      mandateId,
      `Delegation chain depth ${chain.length} exceeds maximum ${COMPOSITION_DEFAULTS.MAX_MANDATE_DELEGATION_DEPTH}`
    );
  }

  const response = await rpc.call(SIDECAR_RPC_METHODS.VERIFY_MANDATE, {
    mandate: mandateData,
    max_depth: COMPOSITION_DEFAULTS.MAX_MANDATE_DELEGATION_DEPTH,
  });

  if (response.error) {
    throw new MandateVerificationError(
      mandateId,
      response.error.message
    );
  }

  const result = assertPlainObject(SIDECAR_RPC_METHODS.VERIFY_MANDATE, response.result);
  const valid = assertBoolean(SIDECAR_RPC_METHODS.VERIFY_MANDATE, result, "valid");
  const checks = assertChecksRecord(
    SIDECAR_RPC_METHODS.VERIFY_MANDATE,
    result,
    "checks",
    MANDATE_CHECK_FLAGS
  );
  const status: MandateStatus = isMandateStatus(result.status) ? result.status : "active";

  return {
    valid,
    mandate_id: mandateId,
    schema_urn: CONCORDIA_MANDATE_SCHEMA_URN,
    issuer: (mandateData.issuer as string) ?? "",
    subject: (mandateData.subject as string) ?? "",
    delegation_depth: chain ? chain.length : 0,
    status,
    checks: {
      signature_valid: checks.signature_valid,
      chain_valid: checks.chain_valid,
      not_expired: checks.not_expired,
      not_revoked: checks.not_revoked,
      constraints_valid: checks.constraints_valid,
    },
    verified_at: new Date().toISOString(),
    signature_scheme: SIDECAR_SIGNATURE_SCHEME,
  };
}
