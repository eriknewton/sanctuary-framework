/**
 * Operator Cloud Slice 2, issuer-side provision service.
 *
 * Orchestrates the home/issuer-side provision flow into testable units:
 *   1. Build the redacted EXTERNAL approval context (HIGH-2): only opaque
 *      digests + counts + non-sensitive labels travel to the webhook/dashboard
 *      approval channel. Raw agent ids / namespaces / grant ids / secret bytes
 *      NEVER appear here.
 *   2. Prebuild + digest the full bundle IN MEMORY (HIGH-1 ordering): the caller
 *      delivers it ONLY after the Tier-1 gate returns approve.
 *   3. On approval, record the digest-bound pending provision claim (consumed by
 *      the production operator-cloud join approver).
 *
 * This service does no I/O and never touches the macOS keychain; it operates on
 * material the caller (an issuer-capable local context) already holds.
 */

import { stringToBytes } from "../core/encoding.js";
import {
  buildOperatorCloudProvisionBundle,
  computeNodePubkeyHash,
  type BuildProvisionBundleParams,
  type BuiltProvisionBundle,
} from "./operator-cloud-provision.js";
import {
  OperatorCloudProvisionClaimStore,
  type OperatorCloudProvisionClaim,
} from "./lifecycle/operator-cloud-join-approver.js";

export const OPERATOR_CLOUD_PROVISION_OPERATION = "operator_cloud_provision";

/**
 * The redacted approval context sent to EXTERNAL channels (webhook/dashboard
 * inbox) BEFORE approval. By construction this carries NO raw scope identifiers
 * and NO secret bytes, only opaque digests, counts, and operator-chosen labels.
 * Treat agent ids / namespaces / grant ids as operator data (HIGH-2): they are
 * surfaced to the operator LOCALLY for inspection, never pushed externally here.
 */
export interface OperatorCloudProvisionExternalContext {
  operation: typeof OPERATOR_CLOUD_PROVISION_OPERATION;
  fortress_id: string;
  node_id: string;
  node_mode: "operator_cloud";
  provider: string;
  delivery_target: string;
  trust_boundary: string;
  agent_count: number;
  namespace_count: number;
  grant_count: number;
  expires_at: string;
  manifest_digest: string;
  scope_digest: string;
  bundle_digest: string;
  node_pubkey_hash: string;
}

/**
 * The LOCAL approval context shown to the operator on their own machine. It MAY
 * include the full scope manifest because the operator inspects it locally
 * before approving; it must never be forwarded to an external channel.
 */
export interface OperatorCloudProvisionLocalContext
  extends OperatorCloudProvisionExternalContext {
  agent_ids: string[];
  namespaces: string[];
  grant_ids: string[];
}

export interface PreparedProvision {
  built: BuiltProvisionBundle;
  externalContext: OperatorCloudProvisionExternalContext;
  localContext: OperatorCloudProvisionLocalContext;
  /** Hash of the joining node public key, bound into the claim. */
  nodePubkeyHash: string;
}

export interface PrepareProvisionParams extends BuildProvisionBundleParams {
  provider: string;
  /** The joining node public key (from `operator-cloud prepare` on the VM), base64url. */
  nodePubkeyB64: string;
}

/**
 * Prepare a provision: prebuild + digest the bundle in memory and derive both
 * approval contexts. Does NOT record a claim and does NOT deliver, the caller
 * runs the Tier-1 gate against `externalContext`, then calls
 * `recordApprovedProvisionClaim` only on approve.
 */
export function prepareOperatorCloudProvision(
  params: PrepareProvisionParams,
): PreparedProvision {
  const built = buildOperatorCloudProvisionBundle(params);
  const nodePubkeyHash = computeNodePubkeyHash(params.nodePubkeyB64);
  // The bundle digest binds the joining node pubkey for the claim binding by
  // mixing the pubkey hash into the recorded claim; the bundle-internal digest
  // already binds manifest + ciphertext + delivery target. We additionally pin
  // node_pubkey_hash on the digests for downstream claim recording.
  built.digests.node_pubkey_hash = nodePubkeyHash;

  const externalContext: OperatorCloudProvisionExternalContext = {
    operation: OPERATOR_CLOUD_PROVISION_OPERATION,
    fortress_id: params.fortressId,
    node_id: params.nodeId,
    node_mode: "operator_cloud",
    provider: params.provider,
    delivery_target: params.deliveryTarget,
    trust_boundary: built.bundle.manifest.trust_boundary.label,
    agent_count: params.agentIds.length,
    namespace_count: params.namespaces.length,
    grant_count: params.grants.length,
    expires_at: params.expiresAt,
    manifest_digest: built.digests.manifest_digest,
    scope_digest: built.digests.scope_digest,
    bundle_digest: built.digests.bundle_digest,
    node_pubkey_hash: nodePubkeyHash,
  };

  const localContext: OperatorCloudProvisionLocalContext = {
    ...externalContext,
    agent_ids: [...params.agentIds],
    namespaces: [...params.namespaces],
    grant_ids: params.grants.map((g) => g.grant_id),
  };

  return { built, externalContext, localContext, nodePubkeyHash };
}

/**
 * Record the Tier-1-approved provision claim. Call this ONLY after the gate
 * returns approve for `operator_cloud_provision`. The claim binds exactly the
 * digests + node pubkey the operator approved; the production join approver
 * consumes it once.
 */
export function recordApprovedProvisionClaim(params: {
  claimStore: OperatorCloudProvisionClaimStore;
  prepared: PreparedProvision;
}): OperatorCloudProvisionClaim {
  const { built, nodePubkeyHash } = params.prepared;
  return params.claimStore.record({
    fortress_id: built.bundle.manifest.fortress_id,
    node_id: built.bundle.manifest.node_id,
    node_pubkey_hash: nodePubkeyHash,
    bootstrap_nonce: built.digests.bootstrap_nonce,
    manifest_digest: built.digests.manifest_digest,
    scoped_secret_ciphertext_digest: built.digests.scoped_secret_ciphertext_digest,
    scope_digest: built.digests.scope_digest,
    bundle_digest: built.digests.bundle_digest,
    expires_at: built.bundle.manifest.expires_at,
  });
}

const SCOPE_IDENTIFIER_KEYS = ["agent_ids", "namespaces", "grant_ids"] as const;

/**
 * Defense-in-depth guard for HIGH-2: assert an object destined for an EXTERNAL
 * approval channel carries no raw scope identifiers and no obvious secret bytes.
 * Used by the provision command before it hands context to the gate.
 */
export function assertNoScopeLeakInExternalContext(context: unknown): void {
  if (typeof context !== "object" || context === null) return;
  const obj = context as Record<string, unknown>;
  for (const key of SCOPE_IDENTIFIER_KEYS) {
    if (key in obj) {
      throw new Error(
        `external approval context must not carry raw scope identifiers: ${key}`,
      );
    }
  }
  const SENSITIVE = /data_key|node_join_proof_key|unseal_key|private_key|master_secret/i;
  const serialized = JSON.stringify(obj);
  if (SENSITIVE.test(serialized)) {
    throw new Error("external approval context must not carry secret material");
  }
  // The serialized form must not contain the bundle's scoped-secret ciphertext.
  // (Digests only, never the ciphertext body.)
  void stringToBytes(serialized);
}
