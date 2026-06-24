/**
 * Operator Cloud Slice 2, pending-provision-claim store + production JoinApprover.
 *
 * The home/issuer node, after the Tier-1 `operator_cloud_provision` approval
 * returns approve, records a PENDING APPROVED PROVISION CLAIM. The production
 * JoinApprover for an `operator_cloud` join consumes a matching, unexpired,
 * unconsumed claim before issuing the certificate. Absent / expired / mismatched
 * / already-consumed -> denial.
 *
 * This is the structural enforcement behind two BLOCKING criteria:
 *  - HIGH-1 / HIGH-4 anti-substitution: the claim binds node_pubkey_hash,
 *    bootstrap nonce, manifest digest, scoped-secret ciphertext digest, and
 *    decrypt-scope digest. A leaked bundle consumed by a substituted keypair, or
 *    a substituted bundle, fails the digest/pubkey match and is denied.
 *  - The cloud join is NEVER auto-approved: certificate issuance for an
 *    operator-cloud node is impossible without a live Tier-1 decision recorded
 *    as this exact claim. There is no default approver (Slice 1 already denies
 *    when no approver is bound).
 */

import { fromBase64url } from "../../core/encoding.js";
import {
  computeNodePubkeyHash,
  verifyOperatorCloudJoinProof,
} from "../operator-cloud-provision.js";
import { issueCertificateForApprovedJoin } from "./join-approver.js";
import type {
  FortressMasterPublicKey,
  PrincipalCertificate,
} from "../types.js";
import type { JoinApprovalResult, JoinApprover, JoinRequest } from "./types.js";

/** A Tier-1-approved provision claim, recorded by the home node before delivery. */
export interface OperatorCloudProvisionClaim {
  fortress_id: string;
  node_id: string;
  node_mode: "operator_cloud";
  node_pubkey_hash: string;
  bootstrap_nonce: string;
  manifest_digest: string;
  scoped_secret_ciphertext_digest: string;
  scope_digest: string;
  bundle_digest: string;
  expires_at: string;
  consumed: boolean;
}

export interface RecordProvisionClaimParams {
  fortress_id: string;
  node_id: string;
  node_pubkey_hash: string;
  bootstrap_nonce: string;
  manifest_digest: string;
  scoped_secret_ciphertext_digest: string;
  scope_digest: string;
  bundle_digest: string;
  expires_at: string;
}

/**
 * In-memory pending-claim store. Production wires this to the encrypted state
 * store; the in-memory implementation is the Slice 2 mechanism + the test
 * substrate. A claim is single-use: `consume` flips `consumed` and never returns
 * it again.
 */
export class OperatorCloudProvisionClaimStore {
  private readonly claims = new Map<string, OperatorCloudProvisionClaim>();

  private key(fortressId: string, nodeId: string, nonce: string): string {
    return `${fortressId} ${nodeId} ${nonce}`;
  }

  record(params: RecordProvisionClaimParams): OperatorCloudProvisionClaim {
    const claim: OperatorCloudProvisionClaim = {
      fortress_id: params.fortress_id,
      node_id: params.node_id,
      node_mode: "operator_cloud",
      node_pubkey_hash: params.node_pubkey_hash,
      bootstrap_nonce: params.bootstrap_nonce,
      manifest_digest: params.manifest_digest,
      scoped_secret_ciphertext_digest: params.scoped_secret_ciphertext_digest,
      scope_digest: params.scope_digest,
      bundle_digest: params.bundle_digest,
      expires_at: params.expires_at,
      consumed: false,
    };
    this.claims.set(
      this.key(params.fortress_id, params.node_id, params.bootstrap_nonce),
      claim,
    );
    return claim;
  }

  /** Peek a claim without consuming it (status surfaces). */
  peek(
    fortressId: string,
    nodeId: string,
    nonce: string,
  ): OperatorCloudProvisionClaim | null {
    return this.claims.get(this.key(fortressId, nodeId, nonce)) ?? null;
  }

  /**
   * Atomically consume the matching claim if it is present, unconsumed, and
   * unexpired. Returns the claim on success; null otherwise. The caller is
   * responsible for verifying digest/pubkey bindings BEFORE acting on it, 
   * `consume` only enforces single-use + expiry.
   */
  consume(
    fortressId: string,
    nodeId: string,
    nonce: string,
    nowMs = Date.now(),
  ): OperatorCloudProvisionClaim | null {
    const claim = this.claims.get(this.key(fortressId, nodeId, nonce));
    if (!claim) return null;
    if (claim.consumed) return null;
    if (Date.parse(claim.expires_at) < nowMs) return null;
    claim.consumed = true;
    return claim;
  }
}

export interface OperatorCloudJoinApproverParams {
  pinned_master_pubkey: FortressMasterPublicKey;
  issuing_principal_cert: PrincipalCertificate;
  issuing_principal_private_key: Uint8Array;
  master_private_key?: Uint8Array;
  claimStore: OperatorCloudProvisionClaimStore;
  /**
   * The node-scoped proof key for the node being provisioned, supplied by the
   * home node when it recorded the claim (the same derived transport key that
   * rode in the bundle's scoped-secret section). Used to verify the
   * operator-cloud join proof binding.
   */
  nodeJoinProofKey: Uint8Array;
  nowMs?: () => number;
  expiresAt?: string;
}

/**
 * Build the PRODUCTION operator-cloud join approver. It only issues a cert when
 * a Tier-1-approved provision claim matches the request EXACTLY:
 *   - bootstrap nonce + node id + fortress id locate the claim,
 *   - node_pubkey_hash binds the cert to the keypair the operator approved,
 *   - the operator-cloud join proof binds nonce + pubkey + bundle digest under
 *     the node-scoped proof key.
 * Any mismatch denies; the HTTP layer collapses denials to a uniform 401.
 */
export function createOperatorCloudJoinApprover(
  params: OperatorCloudJoinApproverParams,
): JoinApprover {
  return {
    async requestApproval(request: JoinRequest): Promise<JoinApprovalResult> {
      if (request.node_mode !== "operator_cloud") {
        return {
          approved: false,
          denial_reason: "operator-cloud approver only issues operator_cloud nodes",
        };
      }
      const nowMs = params.nowMs?.() ?? Date.now();
      const token = request.bootstrap_token;
      const claim = params.claimStore.consume(
        token.fortress_id,
        token.intended_node_id,
        token.nonce,
        nowMs,
      );
      if (!claim) {
        return {
          approved: false,
          denial_reason: "no matching unconsumed approved provision claim",
        };
      }
      // Bind the cert to the keypair the operator approved (HIGH-1).
      const nodePubkeyHash = computeNodePubkeyHash(request.node_pubkey);
      if (nodePubkeyHash !== claim.node_pubkey_hash) {
        return {
          approved: false,
          denial_reason: "node_pubkey does not match approved provision claim",
        };
      }
      // Verify the operator-cloud join proof binds nonce + pubkey + bundle.
      const proofOk = verifyOperatorCloudJoinProof({
        nodeJoinProofKey: params.nodeJoinProofKey,
        fortressId: token.fortress_id,
        nodeId: token.intended_node_id,
        bootstrapNonce: token.nonce,
        nodePubkeyB64: request.node_pubkey,
        bundleDigest: claim.bundle_digest,
        proof: request.hkdf_salt_proof,
      });
      if (!proofOk) {
        return {
          approved: false,
          denial_reason: "operator-cloud join proof does not bind the approved bundle",
        };
      }
      // Defense-in-depth: reject a malformed node pubkey before issuance.
      try {
        if (fromBase64url(request.node_pubkey).length !== 32) {
          return { approved: false, denial_reason: "node_pubkey is not a 32-byte key" };
        }
      } catch {
        return { approved: false, denial_reason: "node_pubkey is malformed" };
      }
      const certificate = issueCertificateForApprovedJoin({
        request,
        pinned_master_pubkey: params.pinned_master_pubkey,
        issuing_principal_cert: params.issuing_principal_cert,
        issuing_principal_private_key: params.issuing_principal_private_key,
        master_private_key: params.master_private_key,
        expires_at: params.expiresAt,
      });
      return { approved: true, certificate };
    },
  };
}
