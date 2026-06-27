/**
 * Operator Cloud Slice 2, scoped provision bundle + per-grant key schedule.
 *
 * The home/issuer node builds a SCOPED provision bundle for an `operator_cloud`
 * node. The bundle carries ONLY:
 *   - the cleartext manifest (public trust root, certs, bootstrap token, scope),
 *   - an encrypted scoped-secret section (node-scoped proof key, the cloud-node
 *     unseal key, and explicitly assigned per-grant data keys + ciphertexts).
 *
 * It NEVER carries the fortress master secret, the fortress master private key,
 * the issuing-principal private key, recovery/guardian material, other nodes'
 * keys, or whole-home state. Slice 1's `FederationNonIssuerOperatorCloudContext`
 * type boundary continues to hold for the resulting cloud context.
 *
 * The CORE SECURITY PROPERTY (HIGH-3 of the design review): out-of-scope state
 * is encrypted under per-grant data keys (DEKs) that the cloud node DOES NOT
 * hold. A compromised cloud node running attacker code therefore still lacks the
 * key bytes to decrypt unassigned namespaces or whole-home state, the boundary
 * is "this node literally lacks the key," not "home chose not to send it."
 *
 * Key schedule (no reuse of the at-rest unseal key as a data key):
 *   - Each assigned grant gets a fresh random 32-byte DEK.
 *   - The grant ciphertext is AES-256-GCM under that DEK, with AEAD AAD bound to
 *     {fortress_id, node_id, grant_id, agent_id, namespace, grant_version,
 *      scope_digest} (HIGH-3 / the review's AAD list). A
 *     ciphertext for one node/scope/grant fails to decrypt under any other.
 *   - The DEKs ride ONLY inside the encrypted scoped-secret section, wrapped to
 *     the cloud node. Unassigned home state is encrypted under home-only keys
 *     whose DEKs are never placed in any bundle.
 *
 * Anti-substitution binding (HIGH-1 / HIGH-4): the full bundle is prebuilt and
 * digested BEFORE approval. The approval-bound claim pins the joining node
 * public-key hash, the bootstrap-token nonce, the manifest digest, the
 * scoped-secret ciphertext digest, and the decrypt-scope digest. The
 * operator-cloud join proof is bound to {fortress_id, node_id, node_mode,
 * bootstrap_nonce, node_pubkey, bundle_digest}, a leaked bundle consumed by a
 * substituted keypair is rejected.
 */

import { hmac } from "@noble/hashes/hmac";
import { sha256 } from "@noble/hashes/sha256";
import {
  fromBase64url,
  stringToBytes,
  toBase64url,
} from "../core/encoding.js";
import { randomBytes } from "../core/random.js";
import { encrypt, decrypt, type EncryptedPayload } from "../core/encryption.js";
import { canonicalize, canonicalizeToBytes } from "./canonical-json.js";
import {
  NODE_TRUST_BOUNDARY_VERSION,
  OPERATOR_CLOUD_TRUST_BOUNDARY_LABEL,
} from "./node-posture.js";
import type {
  BootstrapToken,
} from "./lifecycle/types.js";
import type {
  FortressMasterPublicKey,
  NodeIdentityCertificate,
  PrincipalCertificate,
} from "./types.js";

export const OPERATOR_CLOUD_BUNDLE_VERSION = "operator-cloud-provision-v1" as const;
export const OPERATOR_CLOUD_SCOPE_VERSION = "operator-cloud-scope-v1" as const;
export const OPERATOR_CLOUD_GRANT_VERSION = "operator-cloud-grant-v1" as const;
export const OPERATOR_CLOUD_JOINED_NODE_RECORD_VERSION =
  "operator-cloud-joined-node-v1" as const;

/**
 * Domain separators for the digests. Specifying these now (LOW-1 of the review)
 * removes the "implementers chose incompatible digest domains" ambiguity:
 *   manifest_digest = sha256("<MANIFEST_DOMAIN>" || canonical(manifest_without_digest))
 *   scoped_ciphertext_digest = sha256("<SCOPED_DOMAIN>" || canonical(EncryptedPayload))
 *   scope_digest = sha256("<SCOPE_DOMAIN>" || canonical(scope_manifest))
 *   bundle_digest = sha256("<BUNDLE_DOMAIN>" || manifest_digest || scoped_ciphertext_digest || node_pubkey || delivery_target)
 */
const MANIFEST_DIGEST_DOMAIN = "sanctuary-oc-provision-manifest-v1";
const SCOPED_CIPHERTEXT_DIGEST_DOMAIN = "sanctuary-oc-provision-scoped-ct-v1";
const SCOPE_DIGEST_DOMAIN = "sanctuary-oc-provision-scope-v1";
const BUNDLE_DIGEST_DOMAIN = "sanctuary-oc-provision-bundle-v1";
/** Operator-cloud join-proof domain (distinct from the local-mode proof). */
const OC_JOIN_PROOF_DOMAIN = "sanctuary-oc-join-proof-v1";

// ── Scope manifest ──────────────────────────────────────────────────────────

export interface OperatorCloudScopeManifest {
  scope_version: typeof OPERATOR_CLOUD_SCOPE_VERSION;
  node_id: string;
  agent_ids: string[];
  namespaces: string[];
  /** Per-grant digests; the wrapped DEKs live in the encrypted section, not here. */
  state_grant_ids: string[];
  expires_at?: string;
}

/** One explicitly-assigned state grant, as authored by the home issuer. */
export interface OperatorCloudGrantInput {
  grant_id: string;
  agent_id: string;
  namespace: string;
  /** Cleartext state bytes the home node already unwrapped locally. */
  plaintext: Uint8Array;
}

// ── Bundle shapes ─────────────────────────────────────────────────────────────

export interface OperatorCloudTrustBoundaryManifest {
  version: typeof NODE_TRUST_BOUNDARY_VERSION;
  posture: "provider_in_trust_boundary_not_tee";
  label: string;
  provider_in_trust_boundary: true;
  tee_attested: false;
}

/**
 * Cleartext (non-root) manifest. Public trust root + certs + scope + bootstrap
 * token. The bootstrap_token is a non-root JOIN CREDENTIAL (MED-2): it is not
 * fortress-root material, but it is sensitive operational credential, keep it
 * out of approval logs and webhook context (only its nonce/expiry travel there).
 */
export interface OperatorCloudBundleManifest {
  bundle_version: typeof OPERATOR_CLOUD_BUNDLE_VERSION;
  fortress_id: string;
  node_id: string;
  node_mode: "operator_cloud";
  home_federation_url: string;
  bootstrap_token: BootstrapToken;
  pinned_master_pubkey: FortressMasterPublicKey;
  issuing_principal_cert: PrincipalCertificate;
  trust_boundary: OperatorCloudTrustBoundaryManifest;
  scope_manifest: OperatorCloudScopeManifest;
  expires_at: string;
}

/** Per-grant entry in the encrypted scoped-secret section. */
export interface OperatorCloudWrappedGrant {
  grant_id: string;
  agent_id: string;
  namespace: string;
  grant_version: typeof OPERATOR_CLOUD_GRANT_VERSION;
  /** Fresh random per-grant DEK (32 bytes, base64url). Cloud node holds this ONLY for assigned grants. */
  data_key: string;
  /** AES-256-GCM ciphertext of the grant plaintext under data_key, with grant AAD. */
  ciphertext: EncryptedPayload;
}

/** The decrypted scoped-secret section. NEVER serialized to the public manifest. */
export interface OperatorCloudScopedSecret {
  /** Per-node join/proof key (derived node transport key). NOT the master secret. */
  node_join_proof_key: string;
  /** Random per-node key wrapping the cloud joined-node record at rest. */
  cloud_node_unseal_key: string;
  assigned_grants: OperatorCloudWrappedGrant[];
}

/**
 * The full provision bundle as delivered. The scoped secret is encrypted under a
 * one-time delivery key (the cloud node proves possession of the matching
 * delivery secret out of band). The manifest is cleartext (non-root).
 */
export interface OperatorCloudProvisionBundle {
  manifest: OperatorCloudBundleManifest;
  /** AES-256-GCM ciphertext of canonical(OperatorCloudScopedSecret) under the delivery key. */
  scoped_secret: EncryptedPayload;
}

/** Digests computed over a prebuilt bundle, used by the approval claim binding. */
export interface OperatorCloudBundleDigests {
  manifest_digest: string;
  scoped_secret_ciphertext_digest: string;
  scope_digest: string;
  bundle_digest: string;
  node_pubkey_hash: string;
  bootstrap_nonce: string;
}

// ── Digest helpers (domain-separated) ────────────────────────────────────────

function sha256Domain(domain: string, ...parts: Uint8Array[]): string {
  const h = sha256.create();
  h.update(stringToBytes(domain));
  for (const p of parts) h.update(p);
  return toBase64url(h.digest());
}

export function computeManifestDigest(manifest: OperatorCloudBundleManifest): string {
  return sha256Domain(MANIFEST_DIGEST_DOMAIN, canonicalizeToBytes(manifest));
}

export function computeScopedSecretCiphertextDigest(
  scopedSecret: EncryptedPayload,
): string {
  return sha256Domain(
    SCOPED_CIPHERTEXT_DIGEST_DOMAIN,
    canonicalizeToBytes(scopedSecret),
  );
}

export function computeScopeDigest(scope: OperatorCloudScopeManifest): string {
  return sha256Domain(SCOPE_DIGEST_DOMAIN, canonicalizeToBytes(scope));
}

export function computeNodePubkeyHash(nodePubkeyB64: string): string {
  return sha256Domain(
    "sanctuary-oc-node-pubkey-v1",
    fromBase64url(nodePubkeyB64),
  );
}

/**
 * The bundle digest binds the manifest, the scoped-secret ciphertext, and the
 * delivery target. It deliberately does NOT include the joining node public key:
 * the home node digests the bundle at BUILD time, before the cloud node has
 * generated its keypair. The keypair is bound separately, via `node_pubkey_hash`
 * on the approval claim AND inside the operator-cloud join proof input. This is
 * the single canonical bundle-digest domain used by both the home builder and
 * the cloud-side assembler so the proof binds the same bytes the approver checks.
 */
export function computeBundleDigest(params: {
  manifestDigest: string;
  scopedSecretCiphertextDigest: string;
  deliveryTarget: string;
}): string {
  return sha256Domain(
    BUNDLE_DIGEST_DOMAIN,
    stringToBytes(params.manifestDigest),
    stringToBytes("|"),
    stringToBytes(params.scopedSecretCiphertextDigest),
    stringToBytes("|"),
    stringToBytes(params.deliveryTarget),
  );
}

// ── Per-grant AEAD AAD ────────────────────────────────────────────────────────

/**
 * Build the AEAD additional-authenticated-data for one grant. Binding every one
 * of these fields means a ciphertext authored for (nodeA, scopeX, grantG) cannot
 * be replayed/decrypted as belonging to (nodeB, scopeY, grantH) even under the
 * correct DEK, the GCM tag check fails. This is the substitution defense; the
 * confidentiality defense is the per-grant DEK itself.
 */
function grantAad(params: {
  fortressId: string;
  nodeId: string;
  grantId: string;
  agentId: string;
  namespace: string;
  scopeDigest: string;
}): Uint8Array {
  return canonicalizeToBytes({
    aad_version: "operator-cloud-grant-aad-v1",
    fortress_id: params.fortressId,
    node_id: params.nodeId,
    grant_id: params.grantId,
    agent_id: params.agentId,
    namespace: params.namespace,
    grant_version: OPERATOR_CLOUD_GRANT_VERSION,
    scope_digest: params.scopeDigest,
  });
}

// ── Operator-cloud join proof (HIGH-1) ────────────────────────────────────────

/**
 * Compute the operator-cloud join proof. Unlike the local-mode
 * `computeJoinHkdfSaltProof` (which HMACs only {node_id, node_mode} and is
 * therefore replayable for the same node), this binds the bootstrap nonce, the
 * exact node public key that will receive the certificate, and the bundle
 * digest. A leaked bundle consumed by a DIFFERENT keypair, or with a different
 * nonce/bundle, produces a different proof and is rejected.
 *
 * Keyed by the node-scoped proof key (the derived node transport key), so a
 * holder of only a bootstrap token (without the scoped proof key) cannot forge
 * it, the same property the local-mode proof gives, extended with substitution
 * binding.
 */
export function computeOperatorCloudJoinProof(params: {
  nodeJoinProofKey: Uint8Array;
  fortressId: string;
  nodeId: string;
  bootstrapNonce: string;
  nodePubkeyB64: string;
  bundleDigest: string;
}): string {
  const input = canonicalizeToBytes({
    domain: OC_JOIN_PROOF_DOMAIN,
    fortress_id: params.fortressId,
    node_id: params.nodeId,
    node_mode: "operator_cloud",
    bootstrap_nonce: params.bootstrapNonce,
    node_pubkey: params.nodePubkeyB64,
    bundle_digest: params.bundleDigest,
  });
  return toBase64url(hmac(sha256, params.nodeJoinProofKey, input));
}

export function verifyOperatorCloudJoinProof(params: {
  nodeJoinProofKey: Uint8Array;
  fortressId: string;
  nodeId: string;
  bootstrapNonce: string;
  nodePubkeyB64: string;
  bundleDigest: string;
  proof: string;
}): boolean {
  const expected = computeOperatorCloudJoinProof(params);
  // Length-safe constant-ish compare on equal-length base64url strings.
  if (expected.length !== params.proof.length) return false;
  let diff = 0;
  for (let i = 0; i < expected.length; i++) {
    diff |= expected.charCodeAt(i) ^ params.proof.charCodeAt(i);
  }
  return diff === 0;
}

// ── Bundle build ──────────────────────────────────────────────────────────────

export interface BuildProvisionBundleParams {
  fortressId: string;
  nodeId: string;
  homeFederationUrl: string;
  bootstrapToken: BootstrapToken;
  pinnedMasterPubkey: FortressMasterPublicKey;
  issuingPrincipalCert: PrincipalCertificate;
  /** The derived node transport/proof key for (node_id, operator_cloud). NOT the master secret. */
  nodeJoinProofKey: Uint8Array;
  agentIds: string[];
  namespaces: string[];
  grants: OperatorCloudGrantInput[];
  /** Where the encrypted bundle is delivered (bound into the bundle digest). */
  deliveryTarget: string;
  /** One-time delivery key the cloud node proves possession of out of band. */
  deliveryKey: Uint8Array;
  expiresAt: string;
}

export interface BuiltProvisionBundle {
  bundle: OperatorCloudProvisionBundle;
  digests: OperatorCloudBundleDigests;
  /** The cloud-node unseal key, returned so the home node can audit/discard it. */
  cloudNodeUnsealKey: Uint8Array;
}

/**
 * Prebuild + digest the full bundle IN MEMORY. The caller MUST NOT deliver or
 * persist the returned bundle until the Tier-1 approval gate returns approve
 * (HIGH-1 ordering rule). The digests are what the approval claim binds.
 *
 * REFUSES any grant whose (agent_id, namespace) is not declared in agentIds /
 * namespaces, a grant cannot smuggle scope past the manifest the operator sees.
 */
export function buildOperatorCloudProvisionBundle(
  params: BuildProvisionBundleParams,
): BuiltProvisionBundle {
  if (params.nodeJoinProofKey.length !== 32) {
    throw new Error("node_join_proof_key must be 32 bytes");
  }
  if (params.deliveryKey.length !== 32) {
    throw new Error("delivery key must be 32 bytes");
  }
  const agentSet = new Set(params.agentIds);
  const namespaceSet = new Set(params.namespaces);
  const grantIds = new Set<string>();
  for (const grant of params.grants) {
    if (!agentSet.has(grant.agent_id)) {
      throw new Error(
        `grant ${grant.grant_id} agent_id ${grant.agent_id} not in declared scope`,
      );
    }
    if (!namespaceSet.has(grant.namespace)) {
      throw new Error(
        `grant ${grant.grant_id} namespace ${grant.namespace} not in declared scope`,
      );
    }
    if (grantIds.has(grant.grant_id)) {
      throw new Error(`duplicate grant_id ${grant.grant_id}`);
    }
    grantIds.add(grant.grant_id);
  }

  const scopeManifest: OperatorCloudScopeManifest = {
    scope_version: OPERATOR_CLOUD_SCOPE_VERSION,
    node_id: params.nodeId,
    agent_ids: [...params.agentIds],
    namespaces: [...params.namespaces],
    state_grant_ids: params.grants.map((g) => g.grant_id),
    ...(params.expiresAt ? { expires_at: params.expiresAt } : {}),
  };
  const scopeDigest = computeScopeDigest(scopeManifest);

  // Wrap each grant under a FRESH random per-grant DEK with grant-bound AAD.
  const cloudNodeUnsealKey = randomBytes(32);
  const assignedGrants: OperatorCloudWrappedGrant[] = params.grants.map(
    (grant) => {
      const dek = randomBytes(32);
      try {
        const ciphertext = encrypt(
          grant.plaintext,
          dek,
          grantAad({
            fortressId: params.fortressId,
            nodeId: params.nodeId,
            grantId: grant.grant_id,
            agentId: grant.agent_id,
            namespace: grant.namespace,
            scopeDigest,
          }),
        );
        return {
          grant_id: grant.grant_id,
          agent_id: grant.agent_id,
          namespace: grant.namespace,
          grant_version: OPERATOR_CLOUD_GRANT_VERSION,
          data_key: toBase64url(dek),
          ciphertext,
        };
      } finally {
        dek.fill(0);
      }
    },
  );

  const scopedSecret: OperatorCloudScopedSecret = {
    node_join_proof_key: toBase64url(params.nodeJoinProofKey),
    cloud_node_unseal_key: toBase64url(cloudNodeUnsealKey),
    assigned_grants: assignedGrants,
  };

  const scopedPlaintext = stringToBytes(canonicalize(scopedSecret));
  let scopedSecretCiphertext: EncryptedPayload;
  try {
    scopedSecretCiphertext = encrypt(scopedPlaintext, params.deliveryKey);
  } finally {
    scopedPlaintext.fill(0);
  }

  const manifest: OperatorCloudBundleManifest = {
    bundle_version: OPERATOR_CLOUD_BUNDLE_VERSION,
    fortress_id: params.fortressId,
    node_id: params.nodeId,
    node_mode: "operator_cloud",
    home_federation_url: params.homeFederationUrl,
    bootstrap_token: params.bootstrapToken,
    pinned_master_pubkey: params.pinnedMasterPubkey,
    issuing_principal_cert: params.issuingPrincipalCert,
    trust_boundary: {
      version: NODE_TRUST_BOUNDARY_VERSION,
      posture: "provider_in_trust_boundary_not_tee",
      label: OPERATOR_CLOUD_TRUST_BOUNDARY_LABEL,
      provider_in_trust_boundary: true,
      tee_attested: false,
    },
    scope_manifest: scopeManifest,
    expires_at: params.expiresAt,
  };

  const manifestDigest = computeManifestDigest(manifest);
  const scopedSecretCiphertextDigest =
    computeScopedSecretCiphertextDigest(scopedSecretCiphertext);
  // The bundle digest binds manifest + scoped ciphertext + delivery target. The
  // joining node's actual pubkey is bound separately at claim time via
  // node_pubkey_hash and inside the operator-cloud join proof input.
  const bundleDigest = computeBundleDigest({
    manifestDigest,
    scopedSecretCiphertextDigest,
    deliveryTarget: params.deliveryTarget,
  });

  const digests: OperatorCloudBundleDigests = {
    manifest_digest: manifestDigest,
    scoped_secret_ciphertext_digest: scopedSecretCiphertextDigest,
    scope_digest: scopeDigest,
    bundle_digest: bundleDigest,
    node_pubkey_hash: "",
    bootstrap_nonce: params.bootstrapToken.nonce,
  };

  return {
    bundle: { manifest, scoped_secret: scopedSecretCiphertext },
    digests,
    cloudNodeUnsealKey,
  };
}

// ── Cloud-side bundle consumption ────────────────────────────────────────────

/** Decrypt the scoped-secret section with the one-time delivery key. */
export function openScopedSecret(
  bundle: OperatorCloudProvisionBundle,
  deliveryKey: Uint8Array,
): OperatorCloudScopedSecret {
  const plaintext = decrypt(bundle.scoped_secret, deliveryKey);
  try {
    const parsed = JSON.parse(new TextDecoder().decode(plaintext)) as unknown;
    return parseScopedSecret(parsed);
  } finally {
    plaintext.fill(0);
  }
}

/**
 * Decrypt one assigned grant. The cloud node can only do this for grants whose
 * DEK rode in its scoped-secret section AND whose AAD matches this node/scope.
 * A grant ciphertext from another node/scope, or under a DEK this node was not
 * given, throws (GCM auth failure / missing key), the negative-decrypt property.
 */
export function decryptAssignedGrant(params: {
  grant: OperatorCloudWrappedGrant;
  fortressId: string;
  nodeId: string;
  scopeDigest: string;
}): Uint8Array {
  const dek = fromBase64url(params.grant.data_key);
  try {
    return decrypt(
      params.grant.ciphertext,
      dek,
      grantAad({
        fortressId: params.fortressId,
        nodeId: params.nodeId,
        grantId: params.grant.grant_id,
        agentId: params.grant.agent_id,
        namespace: params.grant.namespace,
        scopeDigest: params.scopeDigest,
      }),
    );
  } finally {
    dek.fill(0);
  }
}

function parseScopedSecret(value: unknown): OperatorCloudScopedSecret {
  if (typeof value !== "object" || value === null) {
    throw new Error("scoped secret is not an object");
  }
  const v = value as Record<string, unknown>;
  if (typeof v.node_join_proof_key !== "string") {
    throw new Error("scoped secret missing node_join_proof_key");
  }
  if (typeof v.cloud_node_unseal_key !== "string") {
    throw new Error("scoped secret missing cloud_node_unseal_key");
  }
  if (!Array.isArray(v.assigned_grants)) {
    throw new Error("scoped secret missing assigned_grants");
  }
  const grants: OperatorCloudWrappedGrant[] = v.assigned_grants.map((g) => {
    if (typeof g !== "object" || g === null) {
      throw new Error("grant is not an object");
    }
    const gr = g as Record<string, unknown>;
    if (
      typeof gr.grant_id !== "string" ||
      typeof gr.agent_id !== "string" ||
      typeof gr.namespace !== "string" ||
      gr.grant_version !== OPERATOR_CLOUD_GRANT_VERSION ||
      typeof gr.data_key !== "string" ||
      typeof gr.ciphertext !== "object" ||
      gr.ciphertext === null
    ) {
      throw new Error("grant is malformed");
    }
    return {
      grant_id: gr.grant_id,
      agent_id: gr.agent_id,
      namespace: gr.namespace,
      grant_version: OPERATOR_CLOUD_GRANT_VERSION,
      data_key: gr.data_key,
      ciphertext: gr.ciphertext as EncryptedPayload,
    };
  });
  return {
    node_join_proof_key: v.node_join_proof_key,
    cloud_node_unseal_key: v.cloud_node_unseal_key,
    assigned_grants: grants,
  };
}

// ── Root/issuer no-leak assertion (serialized-bundle denylist) ────────────────

const ROOT_MATERIAL_DENYLIST = [
  "master_secret",
  "master_private_key",
  "issuing_principal_private_key",
  "recovery_key",
  "guardian_share",
  "passphrase",
  "seed_phrase",
  "mnemonic",
] as const;

/**
 * Assert the SERIALIZED bundle (manifest + ciphertext) carries no root/issuer
 * material by key name. This is a defense-in-depth byte scan; the structural
 * defense is that the bundle types simply have no field for those secrets.
 * Note: the scoped-secret section is ciphertext here, so its plaintext keys are
 * not visible, by design, the cloud node only ever holds scoped keys.
 */
export function assertBundleHasNoRootMaterial(
  bundle: OperatorCloudProvisionBundle,
): void {
  const serialized = JSON.stringify(bundle).toLowerCase();
  for (const banned of ROOT_MATERIAL_DENYLIST) {
    if (serialized.includes(banned)) {
      throw new Error(
        `provision bundle must not contain root/issuer material: ${banned}`,
      );
    }
  }
}

// ── Joined-node record (operator-cloud runtime shape) ────────────────────────

/**
 * The cloud node's at-rest runtime record. Distinct from Federation Slice 1's
 * home `FederationTrustRootRecord` (which holds master_secret + issuer private
 * key). This record holds ONLY scoped material and yields a non-issuer context.
 */
export interface OperatorCloudJoinedNodeRecord {
  record_version: typeof OPERATOR_CLOUD_JOINED_NODE_RECORD_VERSION;
  fortress_id: string;
  node_id: string;
  node_mode: "operator_cloud";
  pinned_master_pubkey: FortressMasterPublicKey;
  issuing_principal_cert: PrincipalCertificate;
  local_node_cert: NodeIdentityCertificate;
  /** Node Ed25519 private key wrapped under the cloud_node_unseal_key. */
  wrapped_local_node_private_key: EncryptedPayload;
  scope_manifest: OperatorCloudScopeManifest;
  trust_boundary: OperatorCloudTrustBoundaryManifest;
  disclosure_acknowledged_at: string;
}

export function isOperatorCloudJoinedNodeRecord(
  value: unknown,
): value is OperatorCloudJoinedNodeRecord {
  if (typeof value !== "object" || value === null) return false;
  const v = value as Record<string, unknown>;
  return (
    v.record_version === OPERATOR_CLOUD_JOINED_NODE_RECORD_VERSION &&
    v.node_mode === "operator_cloud" &&
    typeof v.fortress_id === "string" &&
    typeof v.node_id === "string"
  );
}

/**
 * Wrap the node private key under the cloud-node unseal key for at-rest storage.
 * The unseal key is itself scoped (per-node, delivered in the scoped secret);
 * it is NOT a fortress root key.
 */
export function wrapNodePrivateKeyForCloud(params: {
  nodePrivateKey: Uint8Array;
  cloudNodeUnsealKey: Uint8Array;
}): EncryptedPayload {
  return encrypt(params.nodePrivateKey, params.cloudNodeUnsealKey);
}
