/**
 * Master rotation event flow + cascade.
 *
 * Spec §9.3 (guardian quorum reconstitution), §9.4 (cascade implications),
 * §9.5 (audit continuity).
 *
 * Flow:
 *   1. Guardian quorum signs a `MasterRotationQuorumInput` over the new
 *      fortress-master public key.
 *   2. The quorum proof is packaged into a `MasterRotationPayload` (§4.2-shaped
 *      `quorum_signatures`) and emitted as a SignedEvent on the wire.
 *   3. Receiving nodes verify guardian quorum against the pinned `GuardianRoster`,
 *      accept the new master pubkey, re-derive HKDF subkeys, and re-issue per-
 *      node certificates under the rotated master.
 *
 * Audit continuity (§9.5): every node inserts a `master_rotation` boundary
 * entry in its audit batch immediately after acceptance. Pre-rotation audit
 * entries continue to verify under the OLD master via the audit log's
 * `historical_master` chaining; post-rotation entries verify under the NEW
 * master.
 */

import { canonicalizeToBytes } from "../canonical-json.js";
import { SIGNATURE_SCHEME_V1 } from "../constants.js";
import {
  deriveNodeAuditChainKey,
  deriveNodeTransportKey,
  issueNodeIdentityCertificate,
  issuePrincipalCertificate,
} from "../trust-root.js";
import type {
  FortressMasterPublicKey,
  MasterRotationPayload,
  NodeIdentityCertificate,
  PrincipalCertificate,
} from "../types.js";
import {
  MasterRotationError,
} from "./errors.js";
import {
  verifyGuardianQuorum,
  signMasterRotationAsGuardian,
} from "./guardian-roster.js";
import type {
  GuardianQuorumProof,
  GuardianRoster,
  MasterRotationQuorumInput,
} from "./types.js";
import { fromBase64url } from "../../core/encoding.js";
import { ed25519 } from "@noble/curves/ed25519";

// ═══════════════════════════════════════════════════════════════════════
// Building a master-rotation payload (ceremony side)
// ═══════════════════════════════════════════════════════════════════════

/**
 * Assemble a `MasterRotationPayload` from a quorum-input + per-guardian
 * signatures. The reconstitution ceremony collects M signatures (each produced
 * via `signMasterRotationAsGuardian`), then calls this to package them.
 *
 * Validates the assembled proof against the pinned roster before returning.
 */
export function buildMasterRotationPayload(params: {
  input: MasterRotationQuorumInput;
  guardian_signatures: Array<{ guardian_id: string; signature: string }>;
  pinned_roster: GuardianRoster;
}): MasterRotationPayload {
  const proof: GuardianQuorumProof = {
    roster_version: params.pinned_roster.version,
    signatures: params.guardian_signatures,
  };
  // Validate before emitting — an invalid quorum is operator error, not a
  // wire-side concern.
  verifyGuardianQuorum({
    input: params.input,
    proof,
    pinned_roster: params.pinned_roster,
  });
  // Producer mapping invariant: the ceremony collects signatures by guardian_id,
  // but the wire payload carries guardian_pubkey so receivers bind the proof to
  // their own pinned roster, not to producer-supplied ids. The non-null lookup
  // below is safe only because verifyGuardianQuorum already proved every id is
  // in the pinned roster and that each signature covers this canonical input.
  return {
    old_master_pubkey: params.input.old_master_pubkey,
    new_master_pubkey: params.input.new_master_pubkey,
    quorum_signatures: params.guardian_signatures.map((s) => ({
      guardian_pubkey: params.pinned_roster.guardians.find(
        (g) => g.guardian_id === s.guardian_id
      )!.public_key,
      signature: s.signature,
    })),
    rotated_at: params.input.rotated_at,
  };
}

// ═══════════════════════════════════════════════════════════════════════
// Acceptance (receiver side)
// ═══════════════════════════════════════════════════════════════════════

export interface AcceptMasterRotationParams {
  payload: MasterRotationPayload;
  pinned_master: FortressMasterPublicKey;
  pinned_roster: GuardianRoster;
}

export interface AcceptMasterRotationResult {
  accepted_new_master: FortressMasterPublicKey;
  rotated_at: string;
}

/**
 * Verify and accept a master-rotation event payload.
 *
 * Steps:
 *   1. Confirm `payload.old_master_pubkey === pinned_master.public_key`.
 *   2. Reconstruct the canonical `MasterRotationQuorumInput`.
 *   3. Verify guardian quorum against the pinned roster (verifyGuardianQuorum).
 *   4. Return the new master pubkey for the cascade orchestrator to install.
 *
 * The signature in `payload.quorum_signatures[i].signature` is verified by
 * locating the guardian in the pinned roster by `guardian_pubkey` and running
 * Ed25519 verification.
 *
 * Throws MasterRotationError on any mismatch.
 */
export function acceptMasterRotation(
  params: AcceptMasterRotationParams
): AcceptMasterRotationResult {
  const { payload, pinned_master, pinned_roster } = params;
  if (payload.old_master_pubkey !== pinned_master.public_key) {
    throw new MasterRotationError(
      `old_master_pubkey in event=${payload.old_master_pubkey} does not match pinned master ${pinned_master.public_key}`
    );
  }
  if (
    payload.new_master_pubkey.fortress_id !== pinned_master.fortress_id
  ) {
    throw new MasterRotationError(
      `new_master fortress_id=${payload.new_master_pubkey.fortress_id} does not match current fortress ${pinned_master.fortress_id} — fortress identity is preserved across rotation`
    );
  }
  const input: MasterRotationQuorumInput = {
    old_master_pubkey: payload.old_master_pubkey,
    new_master_pubkey: payload.new_master_pubkey,
    rotated_at: payload.rotated_at,
    fortress_id: pinned_master.fortress_id,
  };
  // Re-key payload.quorum_signatures into a GuardianQuorumProof shape by
  // looking up guardian_id from guardian_pubkey.
  const sigsAsProof = payload.quorum_signatures.map((s) => {
    const guardian = pinned_roster.guardians.find(
      (g) => g.public_key === s.guardian_pubkey
    );
    if (!guardian) {
      throw new MasterRotationError(
        `quorum signature from unknown guardian pubkey ${s.guardian_pubkey} (not in pinned roster v${pinned_roster.version})`
      );
    }
    // Receiver identity-reducer invariant: the event carries public keys, but
    // quorum counting happens on pinned guardian_id entries. A pubkey that does
    // not resolve in the receiver's roster contributes nothing; the sender's
    // roster version or claimed ids are never trusted across the wire.
    return { guardian_id: guardian.guardian_id, signature: s.signature };
  });
  // Receiver canonical-input invariant: rebuild the exact input from accepted
  // event fields plus the receiver's pinned fortress_id, then let
  // verifyGuardianQuorum enforce roster_version, distinct ids, threshold, and
  // Ed25519 signatures. The payload cannot smuggle an alternate fortress_id.
  verifyGuardianQuorum({
    input,
    proof: {
      roster_version: pinned_roster.version,
      signatures: sigsAsProof,
    },
    pinned_roster,
  });
  return {
    accepted_new_master: payload.new_master_pubkey,
    rotated_at: payload.rotated_at,
  };
}

// ═══════════════════════════════════════════════════════════════════════
// Cascade — re-derive HKDF + re-issue certs (§9.4)
// ═══════════════════════════════════════════════════════════════════════

export interface CascadeReKeyParams {
  /** Plaintext NEW fortress-master secret (zeroed by caller after use). */
  new_master_secret: Uint8Array;
  /** Public form of the NEW master. */
  new_master_public: FortressMasterPublicKey;
  /** Old node certificates that must be re-issued under the new master. */
  old_node_certificates: NodeIdentityCertificate[];
  /** Old principal certificate that must be re-issued under the new master. */
  old_root_principal: PrincipalCertificate;
  /** Plaintext NEW root-principal private key for re-signing per-node certs. */
  new_root_principal_private_key: Uint8Array;
  /** Plaintext NEW root-principal public key. */
  new_root_principal_public_key: Uint8Array;
}

export interface CascadeReKeyResult {
  new_root_principal_certificate: PrincipalCertificate;
  re_issued_node_certificates: NodeIdentityCertificate[];
  /** Per-node re-derived audit-chain HMAC keys keyed by node_id. */
  re_derived_audit_chain_keys: Map<string, Uint8Array>;
  /** Per-node re-derived transport keys keyed by node_id. */
  re_derived_transport_keys: Map<string, Uint8Array>;
}

/**
 * Re-issue every per-node certificate + re-derive every per-node HKDF subkey
 * under the rotated master. Locator + policy re-sign decisions are operator
 * policy and live one layer up; this function ships the federation-protocol
 * cryptographic substrate.
 *
 * Default policy per spec §9.4 last bullet: policy versions are PRESERVED
 * with `historical_master` so verifiers chain-verify against the old master.
 * Operator can opt into re-sign separately. This function does NOT touch
 * policies — `runRotationCascadeAtNode` calls into this for the cert + HKDF
 * scope only.
 */
export function rekeyOnMasterRotation(
  params: CascadeReKeyParams
): CascadeReKeyResult {
  // Re-issue Root principal cert under the new master.
  const newRootPrincipalCert = issuePrincipalCertificate({
    principal_id: params.old_root_principal.principal_id,
    principal_pubkey: params.new_root_principal_public_key,
    role: params.old_root_principal.role,
    fortress_id: params.new_master_public.fortress_id,
    master_private_key: params.new_master_secret,
    expires_at: params.old_root_principal.expires_at,
  });
  // Re-issue each per-node cert under the new principal + master, preserving
  // node_id, node_pubkey, node_mode, capabilities, attestation hash. Wallet
  // of HKDF subkeys re-derived in the same pass.
  const reissued: NodeIdentityCertificate[] = [];
  const auditKeys = new Map<string, Uint8Array>();
  const transportKeys = new Map<string, Uint8Array>();
  for (const oldCert of params.old_node_certificates) {
    const reissue = issueNodeIdentityCertificate({
      node_id: oldCert.node_id,
      node_pubkey: fromBase64url(oldCert.node_pubkey),
      node_mode: oldCert.node_mode,
      fortress_id: params.new_master_public.fortress_id,
      capabilities: oldCert.capabilities,
      parent_chain: {
        fortress_master_pubkey: params.new_master_public.public_key,
        principal_id: newRootPrincipalCert.principal_id,
        principal_pubkey: newRootPrincipalCert.principal_pubkey,
      },
      principal_private_key: params.new_root_principal_private_key,
      master_private_key: params.new_master_secret,
      tee_attestation_hash: oldCert.tee_attestation_hash,
    });
    reissued.push(reissue);
    auditKeys.set(
      oldCert.node_id,
      deriveNodeAuditChainKey({
        fortress_master_secret: params.new_master_secret,
        node_id: oldCert.node_id,
      })
    );
    transportKeys.set(
      oldCert.node_id,
      deriveNodeTransportKey({
        fortress_master_secret: params.new_master_secret,
        node_id: oldCert.node_id,
        node_mode: oldCert.node_mode,
      })
    );
  }
  return {
    new_root_principal_certificate: newRootPrincipalCert,
    re_issued_node_certificates: reissued,
    re_derived_audit_chain_keys: auditKeys,
    re_derived_transport_keys: transportKeys,
  };
}

// ═══════════════════════════════════════════════════════════════════════
// Audit-continuity boundary entry (§9.5)
// ═══════════════════════════════════════════════════════════════════════

/**
 * Build the boundary-entry payload that every node inserts into its audit
 * batch immediately after accepting a master rotation. The boundary entry is
 * what enables a verifier walking the audit log to encounter the rotation,
 * verify the guardian quorum, and continue verifying under the new chain.
 *
 * Returned object is the `payload` field for `pushAuditEntry`. The caller
 * sets `attestation_state` and per-batch wrapping.
 */
export function buildMasterRotationAuditPayload(params: {
  old_master_pubkey: string;
  new_master_pubkey: string;
  guardian_quorum_signatures: Array<{
    guardian_pubkey: string;
    signature: string;
  }>;
  rotated_at: string;
}): {
  kind: "master_rotation_boundary";
  old_master_pubkey: string;
  new_master_pubkey: string;
  guardian_quorum_signatures: Array<{
    guardian_pubkey: string;
    signature: string;
  }>;
  rotated_at: string;
  signature_scheme: typeof SIGNATURE_SCHEME_V1;
} {
  return {
    kind: "master_rotation_boundary",
    old_master_pubkey: params.old_master_pubkey,
    new_master_pubkey: params.new_master_pubkey,
    guardian_quorum_signatures: params.guardian_quorum_signatures,
    rotated_at: params.rotated_at,
    signature_scheme: SIGNATURE_SCHEME_V1,
  };
}

/**
 * Walk an audit-log slice that may span a master rotation, verifying every
 * signature against the appropriate master.
 *
 * The verifier MUST receive the in-order sequence of audit entries plus the
 * pre-rotation master pubkey and (after encountering a `master_rotation_boundary`)
 * verify subsequent entries against the post-rotation master. The boundary
 * entry itself is the operator-visible record of the rotation.
 *
 * This function returns the verification trace; throws on any signature failure.
 */
export interface AuditContinuityWalkInput {
  /**
   * Pre-rotation node pubkey lookup — used for entries before the boundary.
   * Returns undefined if the node is not in the pre-rotation roster.
   */
  preRotationNodePubkey: (nodeId: string) => string | undefined;
  /**
   * Post-rotation node pubkey lookup — used for entries after the boundary.
   * Returns undefined if the node is not in the post-rotation roster.
   */
  postRotationNodePubkey: (nodeId: string) => string | undefined;
  /** Body-canonicalized signatures over each entry. */
  entries: Array<{
    body: Record<string, unknown>;
    signature: string;
    emitter_node: string;
    is_boundary?: boolean;
  }>;
}

export interface AuditContinuityWalkResult {
  pre_rotation_verified: number;
  post_rotation_verified: number;
  boundary_seen: boolean;
}

export function walkAuditContinuity(
  input: AuditContinuityWalkInput
): AuditContinuityWalkResult {
  let pre = 0;
  let post = 0;
  let crossed = false;
  for (const entry of input.entries) {
    const lookup = crossed
      ? input.postRotationNodePubkey
      : input.preRotationNodePubkey;
    const pubkey = lookup(entry.emitter_node);
    if (!pubkey) {
      throw new MasterRotationError(
        `audit-continuity walk: no pubkey available for emitter_node=${entry.emitter_node} on ${crossed ? "post" : "pre"}-rotation side`
      );
    }
    const ok = ed25519.verify(
      fromBase64url(entry.signature),
      canonicalizeToBytes(entry.body),
      fromBase64url(pubkey)
    );
    if (!ok) {
      throw new MasterRotationError(
        `audit-continuity walk: signature failed for emitter_node=${entry.emitter_node} on ${crossed ? "post" : "pre"}-rotation side`
      );
    }
    if (entry.is_boundary) {
      crossed = true;
    } else if (crossed) {
      post += 1;
    } else {
      pre += 1;
    }
  }
  return {
    pre_rotation_verified: pre,
    post_rotation_verified: post,
    boundary_seen: crossed,
  };
}

// Re-export for convenience.
export { signMasterRotationAsGuardian };
