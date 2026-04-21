/**
 * Sanctuary Federation Protocol v0.1 — Audit Batch
 *
 * Per-node audit entries accumulate in a local buffer, are sealed every 5 seconds
 * or every 256 entries into an AuditBatch, and stream over direct libp2p streams
 * to the canonical audit node (§5.2).
 *
 * Two rollback canaries enforced here:
 * 1. Per-emitter monotonic batch_seq. Non-monotonic = rollback (§8.3).
 * 2. prev_batch_hash chain. Discontinuity = rollback or replay (§8.3).
 *
 * HKDF chain proof: an HMAC over (batch_id, batch_seq, prev_batch_hash) using the
 * node_audit_chain_key (HKDF-derived from the fortress-master per §2.2). A stolen
 * per-node signing key alone cannot forge this proof — the attacker also needs
 * access to the master-derived chain key, which is only re-derivable under
 * guardian quorum recovery.
 */

import { ed25519 } from "@noble/curves/ed25519";
import { hmac } from "@noble/hashes/hmac";
import { sha256 } from "@noble/hashes/sha256";
import { fromBase64url, toBase64url } from "../core/encoding.js";
import { randomBytes } from "../core/random.js";
import { canonicalizeToBytes } from "./canonical-json.js";
import { SIGNATURE_SCHEME_V1 } from "./constants.js";
import {
  MeshAuditBatchError,
  MeshChainDiscontinuityError,
  MeshRollbackDetectedError,
  MeshSignatureError,
} from "./errors.js";
import type {
  AuditBatch,
  AuditEntry,
  FortressMasterPublicKey,
  NodeIdentityCertificate,
} from "./types.js";
import { verifyCertChain } from "./trust-root.js";
import type { PrincipalCertificate } from "./types.js";

// ═══════════════════════════════════════════════════════════════════════
// Sealing (emitter side)
// ═══════════════════════════════════════════════════════════════════════

/**
 * Seal an audit batch: compute prev_batch_hash chain link, HKDF chain proof, and
 * the per-node Ed25519 signature over the whole batch.
 *
 * The caller owns the per-emitter monotonic batch_seq counter and MUST advance it
 * by exactly 1 for each successive seal call on this emitter. A gap or rollback
 * in the emitter's batch_seq will cause the canonical audit node to reject the
 * batch (MeshRollbackDetectedError).
 */
export interface SealParams {
  emitter_node: string;
  /** Must be previousBatchSeq + 1, or 0 if this is the first batch on this emitter. */
  batch_seq: number;
  entries: AuditEntry[];
  /**
   * The immediately-preceding batch from this emitter, if any. Used to compute
   * prev_batch_hash. Pass null for the first batch.
   */
  previous_batch: AuditBatch | null;
  node_audit_chain_key: Uint8Array;
  node_private_key: Uint8Array;
}

export function sealAuditBatch(params: SealParams): AuditBatch {
  if (!Number.isInteger(params.batch_seq) || params.batch_seq < 0) {
    throw new MeshAuditBatchError(
      `invalid batch_seq ${params.batch_seq} — must be non-negative integer`
    );
  }
  if (params.previous_batch) {
    if (params.previous_batch.emitter_node !== params.emitter_node) {
      throw new MeshAuditBatchError(
        `previous_batch emitter_node=${params.previous_batch.emitter_node} does not match current emitter=${params.emitter_node}`
      );
    }
    if (params.previous_batch.batch_seq + 1 !== params.batch_seq) {
      throw new MeshAuditBatchError(
        `batch_seq gap: previous=${params.previous_batch.batch_seq} current=${params.batch_seq} — expected strict +1 monotonicity`
      );
    }
  } else if (params.batch_seq !== 0) {
    throw new MeshAuditBatchError(
      `first batch must have batch_seq=0; got ${params.batch_seq}`
    );
  }

  const prev_batch_hash = params.previous_batch
    ? hashBatch(params.previous_batch)
    : "";

  const batch_id = generateBatchId();
  const chainProofInput = canonicalizeToBytes({
    batch_id,
    batch_seq: params.batch_seq,
    prev_batch_hash,
  });
  const hkdf_chain_proof = toBase64url(
    hmac(sha256, params.node_audit_chain_key, chainProofInput)
  );

  const body: Omit<AuditBatch, "signature"> = {
    batch_id,
    emitter_node: params.emitter_node,
    batch_seq: params.batch_seq,
    prev_batch_hash,
    entries: params.entries,
    hkdf_chain_proof,
    sealed_at: new Date().toISOString(),
  };
  const sig = ed25519.sign(canonicalizeToBytes(body), params.node_private_key);
  return { ...body, signature: toBase64url(sig) };
}

function generateBatchId(): string {
  const bytes = randomBytes(16);
  let hex = "";
  for (const b of bytes) hex += b.toString(16).padStart(2, "0");
  return hex;
}

function hashBatch(batch: AuditBatch): string {
  return toBase64url(sha256(canonicalizeToBytes(batch)));
}

// ═══════════════════════════════════════════════════════════════════════
// Entry sealing
// ═══════════════════════════════════════════════════════════════════════

/** Seal an individual audit entry with the per-node key. */
export function sealAuditEntry(params: {
  emitter_node: string;
  emitter_agent: string;
  emitter_principal: string;
  policy_version: number;
  attestation_state: string;
  payload: unknown;
  node_private_key: Uint8Array;
}): AuditEntry {
  const entry_id = generateBatchId();
  const body = {
    entry_id,
    emitter_node: params.emitter_node,
    emitter_agent: params.emitter_agent,
    emitter_principal: params.emitter_principal,
    policy_version: params.policy_version,
    attestation_state: params.attestation_state,
    signature_scheme: SIGNATURE_SCHEME_V1,
    payload: params.payload,
    emitted_at: new Date().toISOString(),
  };
  const sig = ed25519.sign(canonicalizeToBytes(body), params.node_private_key);
  return { ...body, signature: toBase64url(sig) };
}

// ═══════════════════════════════════════════════════════════════════════
// Verification (canonical audit node side)
// ═══════════════════════════════════════════════════════════════════════

export interface VerifyBatchContext {
  pinnedMasterPubkey: FortressMasterPublicKey;
  lookupNodeCert: (nodeId: string) => NodeIdentityCertificate | undefined;
  lookupPrincipalCert: (
    principalId: string
  ) => PrincipalCertificate | undefined;
  lookupAuditChainKey: (nodeId: string) => Uint8Array | undefined;
  /**
   * Canonical audit log's view of this emitter's most-recent batch, for rollback
   * and chain-discontinuity detection. null means no prior batch — current must
   * be batch_seq=0.
   */
  lookupPreviousBatch: (nodeId: string) => AuditBatch | null;
}

/**
 * Verify an incoming AuditBatch: per-node signature, HKDF chain proof, batch_seq
 * monotonicity, prev_batch_hash continuity, per-entry signatures.
 *
 * Throws:
 * - MeshSignatureError  — bad Ed25519 signature.
 * - MeshRollbackDetectedError — non-monotonic batch_seq (§8.3 canary #1).
 * - MeshChainDiscontinuityError — prev_batch_hash does not match prior batch (§8.3 canary #2).
 * - MeshAuditBatchError — HKDF chain proof fails (stolen signing key without master).
 */
export function verifyAuditBatch(
  batch: AuditBatch,
  ctx: VerifyBatchContext
): void {
  const cert = ctx.lookupNodeCert(batch.emitter_node);
  if (!cert) {
    throw new MeshSignatureError(
      `audit batch emitter_node=${batch.emitter_node} is not in local roster`
    );
  }

  // Verify the node's own Ed25519 signature over the batch body.
  const body: Omit<AuditBatch, "signature"> = {
    batch_id: batch.batch_id,
    emitter_node: batch.emitter_node,
    batch_seq: batch.batch_seq,
    prev_batch_hash: batch.prev_batch_hash,
    entries: batch.entries,
    hkdf_chain_proof: batch.hkdf_chain_proof,
    sealed_at: batch.sealed_at,
  };
  const bytesToVerify = canonicalizeToBytes(body);
  const sigOk = ed25519.verify(
    fromBase64url(batch.signature),
    bytesToVerify,
    fromBase64url(cert.node_pubkey)
  );
  if (!sigOk) {
    throw new MeshSignatureError(
      `audit batch signature does not verify against ${batch.emitter_node}`
    );
  }

  // Verify the HKDF chain proof — requires the auditor to also hold the
  // node_audit_chain_key (HKDF-derived from the fortress-master). A stolen
  // per-node signing key alone does not let an attacker forge this HMAC.
  const auditChainKey = ctx.lookupAuditChainKey(batch.emitter_node);
  if (!auditChainKey) {
    throw new MeshAuditBatchError(
      `no node_audit_chain_key available for emitter_node=${batch.emitter_node}`
    );
  }
  const chainProofInput = canonicalizeToBytes({
    batch_id: batch.batch_id,
    batch_seq: batch.batch_seq,
    prev_batch_hash: batch.prev_batch_hash,
  });
  const expected = toBase64url(hmac(sha256, auditChainKey, chainProofInput));
  if (expected !== batch.hkdf_chain_proof) {
    throw new MeshAuditBatchError(
      `hkdf_chain_proof mismatch for ${batch.emitter_node} batch_seq=${batch.batch_seq} — possible stolen signing key without master-derived chain key`
    );
  }

  // Monotonicity + chain continuity against the canonical audit log's prior record.
  const previous = ctx.lookupPreviousBatch(batch.emitter_node);
  if (!previous) {
    if (batch.batch_seq !== 0) {
      throw new MeshRollbackDetectedError(
        batch.emitter_node,
        `first-seen batch from this emitter but batch_seq=${batch.batch_seq} != 0`
      );
    }
    if (batch.prev_batch_hash !== "") {
      throw new MeshChainDiscontinuityError(
        batch.emitter_node,
        batch.batch_seq,
        `first-seen batch must have empty prev_batch_hash`
      );
    }
  } else {
    if (batch.batch_seq <= previous.batch_seq) {
      throw new MeshRollbackDetectedError(
        batch.emitter_node,
        `incoming batch_seq=${batch.batch_seq} <= previous batch_seq=${previous.batch_seq}`
      );
    }
    if (batch.batch_seq !== previous.batch_seq + 1) {
      throw new MeshChainDiscontinuityError(
        batch.emitter_node,
        batch.batch_seq,
        `expected batch_seq=${previous.batch_seq + 1} got ${batch.batch_seq}`
      );
    }
    const expectedPrevHash = hashBatch(previous);
    if (batch.prev_batch_hash !== expectedPrevHash) {
      throw new MeshChainDiscontinuityError(
        batch.emitter_node,
        batch.batch_seq,
        `prev_batch_hash does not match canonical audit log's prior batch hash`
      );
    }
  }

  // Optional per-entry signature verification.
  for (const entry of batch.entries) {
    verifyAuditEntry(entry, cert, ctx);
  }
}

function verifyAuditEntry(
  entry: AuditEntry,
  emitterNodeCert: NodeIdentityCertificate,
  ctx: VerifyBatchContext
): void {
  if (entry.signature_scheme !== SIGNATURE_SCHEME_V1) {
    throw new MeshSignatureError(
      `unknown signature_scheme=${entry.signature_scheme} on audit entry ${entry.entry_id}; v1.0 verifier accepts only ${SIGNATURE_SCHEME_V1}`
    );
  }
  const body = {
    entry_id: entry.entry_id,
    emitter_node: entry.emitter_node,
    emitter_agent: entry.emitter_agent,
    emitter_principal: entry.emitter_principal,
    policy_version: entry.policy_version,
    attestation_state: entry.attestation_state,
    signature_scheme: entry.signature_scheme,
    payload: entry.payload,
    emitted_at: entry.emitted_at,
  };
  const ok = ed25519.verify(
    fromBase64url(entry.signature),
    canonicalizeToBytes(body),
    fromBase64url(emitterNodeCert.node_pubkey)
  );
  if (!ok) {
    throw new MeshSignatureError(
      `audit entry ${entry.entry_id} signature does not verify against ${emitterNodeCert.node_id}`
    );
  }
  // Principal attribution: if emitter_principal != "system" and principal cert
  // is in the roster, walk the chain to confirm the principal is a valid member
  // of this fortress. (The entry itself is signed only by the node; the
  // principal-attribution check protects against a node manufacturing entries
  // claiming to be authored by a foreign principal.)
  if (entry.emitter_principal !== "system") {
    const principalCert = ctx.lookupPrincipalCert(entry.emitter_principal);
    if (!principalCert) {
      throw new MeshSignatureError(
        `audit entry ${entry.entry_id} claims emitter_principal=${entry.emitter_principal} not in roster`
      );
    }
    verifyCertChain(emitterNodeCert, principalCert, ctx.pinnedMasterPubkey);
  }
}
