/**
 * JoinApprover implementations.
 *
 * The lifecycle orchestrator delegates the operator-decision step of the join
 * flow (§3.1 step 4) to a JoinApprover. The production implementation wraps
 * the existing principal-policy ApprovalGate (see `JoinApprover` jsdoc in
 * types.ts for wiring notes — wiring is owned by the console thread,
 * WP-MVP-2). Tests use the auto-approve / auto-deny implementations here.
 *
 * Critical: the lifecycle orchestrator MUST NOT bypass the gate in production.
 * The auto-approve implementation exists for tests of the orchestrator itself
 * and MUST NOT be used in production code paths.
 */

import { generateKeypair } from "../../core/identity.js";
import { fromBase64url } from "../../core/encoding.js";
import { CAP_STANDARD_FORTRESS_NODE } from "../constants.js";
import { issueNodeIdentityCertificate } from "../trust-root.js";
import type {
  FortressMasterPublicKey,
  PrincipalCertificate,
} from "../types.js";
import type { JoinApprovalResult, JoinApprover, JoinRequest } from "./types.js";

/**
 * Build the standard NodeIdentityCertificate for an approved join. Pulled out
 * so production approver implementations can reuse the same cert shape.
 */
export function issueCertificateForApprovedJoin(params: {
  request: JoinRequest;
  pinned_master_pubkey: FortressMasterPublicKey;
  issuing_principal_cert: PrincipalCertificate;
  issuing_principal_private_key: Uint8Array;
  master_private_key?: Uint8Array;
  expires_at?: string;
}) {
  return issueNodeIdentityCertificate({
    node_id: params.request.bootstrap_token.intended_node_id,
    node_pubkey: fromBase64url(params.request.node_pubkey),
    node_mode: params.request.node_mode,
    fortress_id: params.request.bootstrap_token.fortress_id,
    capabilities: CAP_STANDARD_FORTRESS_NODE,
    parent_chain: {
      fortress_master_pubkey: params.pinned_master_pubkey.public_key,
      principal_id: params.issuing_principal_cert.principal_id,
      principal_pubkey: params.issuing_principal_cert.principal_pubkey,
    },
    principal_private_key: params.issuing_principal_private_key,
    expires_at: params.expires_at,
    tee_attestation_hash:
      params.request.node_mode === "sovereign_tee"
        ? params.request.attestation
        : undefined,
    master_private_key: params.master_private_key,
  });
}

/**
 * AUTO-APPROVE — TESTS ONLY.
 *
 * Approves every join request and issues a certificate using the supplied
 * issuer principal. Never use in production. The orchestrator's join flow
 * itself is what's under test; the approval surface is exercised by
 * orchestrator-driven tests and end-to-end through the principal-policy gate
 * in the console thread (WP-MVP-2).
 */
export function createAutoApproveJoinApprover(params: {
  pinned_master_pubkey: FortressMasterPublicKey;
  issuing_principal_cert: PrincipalCertificate;
  issuing_principal_private_key: Uint8Array;
  master_private_key?: Uint8Array;
}): JoinApprover {
  return {
    async requestApproval(request: JoinRequest): Promise<JoinApprovalResult> {
      const certificate = issueCertificateForApprovedJoin({
        request,
        pinned_master_pubkey: params.pinned_master_pubkey,
        issuing_principal_cert: params.issuing_principal_cert,
        issuing_principal_private_key: params.issuing_principal_private_key,
        master_private_key: params.master_private_key,
      });
      return { approved: true, certificate };
    },
  };
}

/** AUTO-DENY — TESTS ONLY. Used to assert orchestrator behavior on denial. */
export function createAutoDenyJoinApprover(reason: string): JoinApprover {
  return {
    async requestApproval(_request: JoinRequest): Promise<JoinApprovalResult> {
      return { approved: false, denial_reason: reason };
    },
  };
}

/**
 * Convenience: generate a new per-node Ed25519 keypair on the joining node.
 * Re-exports `generateKeypair` for symmetric naming with mesh primitives.
 */
export function generateNodeKeypair() {
  return generateKeypair();
}
