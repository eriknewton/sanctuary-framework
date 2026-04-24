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
  ConcordiaReceipt,
  ConcordiaReference,
  MandateVerificationResult,
} from "./types.js";
import { MandateVerificationError } from "./errors.js";
import { COMPOSITION_DEFAULTS, CONCORDIA_MANDATE_SCHEMA_URN } from "./constants.js";

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

  const result = response.result as Record<string, unknown>;

  return {
    receipt_id: result.receipt_id as string,
    schema_urn: CONCORDIA_RECEIPT_SCHEMA_URN,
    source_event_id: event.event_id,
    source_event_type: event.event_type,
    agent_id: event.agent_id,
    counterparty_id: event.counterparty_id,
    commitment_class: event.commitment_class,
    references,
    signature: result.signature as string,
    signature_scheme: SIDECAR_SIGNATURE_SCHEME,
    packed_at: result.packed_at as string ?? new Date().toISOString(),
    attestation_metadata: result.attestation_metadata as Record<string, unknown> | undefined,
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
  });

  if (response.error) {
    return false;
  }

  const result = response.result as Record<string, unknown>;
  return result.valid === true;
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

  const result = response.result as Record<string, unknown>;
  const checks = result.checks as Record<string, boolean>;

  return {
    valid: result.valid === true,
    mandate_id: mandateId,
    schema_urn: CONCORDIA_MANDATE_SCHEMA_URN,
    issuer: (mandateData.issuer as string) ?? "",
    subject: (mandateData.subject as string) ?? "",
    delegation_depth: chain ? chain.length : 0,
    status: (result.status as "active" | "expired" | "revoked" | "suspended") ?? "active",
    checks: {
      signature_valid: checks?.signature_valid ?? false,
      chain_valid: checks?.chain_valid ?? false,
      not_expired: checks?.not_expired ?? false,
      not_revoked: checks?.not_revoked ?? false,
      constraints_valid: checks?.constraints_valid ?? false,
    },
    verified_at: new Date().toISOString(),
    signature_scheme: SIDECAR_SIGNATURE_SCHEME,
  };
}
