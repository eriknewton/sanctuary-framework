/**
 * Additive v2 hybrid trust-root certificate chain.
 *
 * This module owns the Ed25519+ML-DSA-65 certificate-chain surface. Legacy v0.1
 * trust-root serializers stay in trust-root.ts and do not import the suite
 * registry, so frozen v1 signatures remain byte-stable.
 */

import { ed25519 } from "@noble/curves/ed25519";
import { ml_dsa65 } from "@noble/post-quantum/ml-dsa.js";
import {
  ED25519_PRIVATE_KEY_BYTES,
  ED25519_PUBLIC_KEY_BYTES,
  ED25519_SIGNATURE_SUITE_ID,
  HYBRID_SIGNATURE_SUITE_ID,
  ML_DSA_65_PUBLIC_KEY_BYTES,
  ML_DSA_65_SECRET_KEY_BYTES,
  createHybridSuitePublicKeys,
  cryptoSuiteRegistry,
  type CanonicalJsonValue,
  type SignatureBundle,
  type SuitePublicKeys,
  type SuiteSigner,
} from "../core/crypto-suite-registry.js";
import { fromBase64url, toBase64url } from "../core/encoding.js";
import { generateKeypair } from "../core/identity.js";
import { hasReservedCapabilityBits, type NodeMode } from "./constants.js";
import {
  MeshChainError,
  MeshReservedCapabilityBitError,
} from "./errors.js";
import { generateFortressId, verifyCertChain } from "./trust-root.js";
import type {
  FortressMasterPublicKey,
  FortressMasterPublicKeysV2Hybrid,
  HybridCertificatePublicKeys,
  NodeIdentityCertificate,
  NodeIdentityCertificateV2Hybrid,
  PrincipalCertificate,
  PrincipalCertificateV2Hybrid,
} from "./types.js";

/**
 * CROSS-FILE CONTRACT. These three at-rest version strings are ALSO spelled as
 * literal types in `mesh/types.ts` -- `FortressMasterPublicKeysV2Hybrid
 * .key_version`, `PrincipalCertificateV2Hybrid.certificate_version`,
 * `NodeIdentityCertificateV2Hybrid.certificate_version`, and again inside
 * `NodeIdentityCertificateV2Hybrid.parent_chain` as
 * `fortress_master_key_version` / `principal_certificate_version`.
 *
 * The literals there are NOT written as `typeof <const>` on purpose: this file
 * imports `./types.js`, so a `typeof` reference would make types.ts import
 * back. TypeScript itself would tolerate that (an `import type` is erased and
 * creates no runtime cycle), but `scripts/check-import-cycles.ts` is a regex
 * scanner that does not distinguish type-only specifiers, so the repo's own
 * cycle gate would count it. The duplication is the price of the acyclic
 * direction as this repo measures it.
 *
 * Failure mode of a drift: TypeScript catches an assignment mismatch at
 * compile time IF both sides are in the same assignment, but a hand-parsed
 * certificate read off disk is checked against whichever copy that code path
 * happens to reference, so a partially-updated pair rejects genuine stored
 * certificates as the wrong version. Change all copies in the SAME PR.
 * Enforced by `test/structure/cross-file-contract-pins.test.ts`.
 */
export const FORTRESS_MASTER_KEY_VERSION_V2_HYBRID =
  "sanctuary.fortress-master.v2.hybrid-ed25519-ml-dsa-65" as const;
export const PRINCIPAL_CERTIFICATE_VERSION_V2_HYBRID =
  "sanctuary.principal-cert.v2.hybrid-ed25519-ml-dsa-65" as const;
export const NODE_IDENTITY_CERTIFICATE_VERSION_V2_HYBRID =
  "sanctuary.node-cert.v2.hybrid-ed25519-ml-dsa-65" as const;
export const TRUST_ROOT_PRINCIPAL_CERT_SURFACE_ID =
  "sanctuary.mesh.trust-root.principal-certificate" as const;
export const TRUST_ROOT_NODE_CERT_SURFACE_ID =
  "sanctuary.mesh.trust-root.node-identity-certificate" as const;
export const TRUST_ROOT_ROOT_ROTATION_SURFACE_ID =
  "sanctuary.mesh.trust-root.root-rotation-certificate" as const;
/** Surface version for the hybrid root-rotation binding (rotate-root --renew). */
export const ROOT_ROTATION_HYBRID_BINDING_VERSION =
  "sanctuary.root-rotation.v2.hybrid-ed25519-ml-dsa-65" as const;

export const MAX_HYBRID_SIGNATURE_BUNDLE_JSON_BYTES = 6 * 1024;
export const MAX_HYBRID_PRINCIPAL_CERT_JSON_BYTES = 14 * 1024;
export const MAX_HYBRID_NODE_CERT_JSON_BYTES = 28 * 1024;

export type TrustRootCertificateChainPolicy =
  | typeof ED25519_SIGNATURE_SUITE_ID
  | typeof HYBRID_SIGNATURE_SUITE_ID;

export interface HybridPrivateKeyMaterial {
  readonly ed25519: {
    readonly key_ref: string;
    readonly private_key: Uint8Array;
  };
  readonly ml_dsa_65: {
    readonly key_ref: string;
    readonly secret_key: Uint8Array;
  };
}

/**
 * Generate a v2 hybrid fortress-master key set at bootstrap.
 *
 * This is the only v2 helper that returns ML-DSA-65 secret material. Callers
 * must immediately store both private keys in the encrypted state store and
 * clear the returned buffers once encrypted. Verifiers never return or log
 * these bytes, and v2 certificates carry only public keys plus signature
 * bundles.
 */
export function generateFortressMasterV2Hybrid(): {
  public: FortressMasterPublicKeysV2Hybrid;
  private_keys: HybridPrivateKeyMaterial;
} {
  const { publicKey: ed25519PublicKey, privateKey: ed25519PrivateKey } =
    generateKeypair();
  const { publicKey: mlDsa65PublicKey, secretKey: mlDsa65SecretKey } =
    ml_dsa65.keygen();
  const fortressId = generateFortressId();
  const createdAt = new Date().toISOString();
  const keyRefs = hybridKeyRefs("fortress-master", fortressId);
  return {
    public: {
      key_version: FORTRESS_MASTER_KEY_VERSION_V2_HYBRID,
      signature_suite: HYBRID_SIGNATURE_SUITE_ID,
      fortress_id: fortressId,
      created_at: createdAt,
      public_keys: {
        signature_suite: HYBRID_SIGNATURE_SUITE_ID,
        ed25519: {
          key_ref: keyRefs.ed25519,
          public_key: toBase64url(ed25519PublicKey),
        },
        ml_dsa_65: {
          key_ref: keyRefs.ml_dsa_65,
          public_key: toBase64url(mlDsa65PublicKey),
        },
      },
    },
    private_keys: {
      ed25519: {
        key_ref: keyRefs.ed25519,
        private_key: ed25519PrivateKey,
      },
      ml_dsa_65: {
        key_ref: keyRefs.ml_dsa_65,
        secret_key: mlDsa65SecretKey,
      },
    },
  };
}

/** Create a standalone v2 hybrid key set for principals or nodes. */
export function generateHybridCertificateKeypair(params: {
  readonly owner_kind: "principal" | "node";
  readonly owner_id: string;
}): {
  public_keys: HybridCertificatePublicKeys;
  private_keys: HybridPrivateKeyMaterial;
} {
  const { publicKey: ed25519PublicKey, privateKey: ed25519PrivateKey } =
    generateKeypair();
  const { publicKey: mlDsa65PublicKey, secretKey: mlDsa65SecretKey } =
    ml_dsa65.keygen();
  const keyRefs = hybridKeyRefs(params.owner_kind, params.owner_id);
  return {
    public_keys: {
      signature_suite: HYBRID_SIGNATURE_SUITE_ID,
      ed25519: {
        key_ref: keyRefs.ed25519,
        public_key: toBase64url(ed25519PublicKey),
      },
      ml_dsa_65: {
        key_ref: keyRefs.ml_dsa_65,
        public_key: toBase64url(mlDsa65PublicKey),
      },
    },
    private_keys: {
      ed25519: {
        key_ref: keyRefs.ed25519,
        private_key: ed25519PrivateKey,
      },
      ml_dsa_65: {
        key_ref: keyRefs.ml_dsa_65,
        secret_key: mlDsa65SecretKey,
      },
    },
  };
}

/** Issue a v2 hybrid principal certificate signed by the fortress-master suite. */
export async function issuePrincipalCertificateV2Hybrid(params: {
  readonly principal_id: string;
  readonly principal_public_keys: HybridCertificatePublicKeys;
  readonly role: PrincipalCertificateV2Hybrid["role"];
  readonly master_public_keys: FortressMasterPublicKeysV2Hybrid;
  readonly master_private_keys: HybridPrivateKeyMaterial;
  readonly issued_at?: string;
  readonly expires_at?: string;
}): Promise<PrincipalCertificateV2Hybrid> {
  const body = {
    certificate_version: PRINCIPAL_CERTIFICATE_VERSION_V2_HYBRID,
    signature_suite: HYBRID_SIGNATURE_SUITE_ID,
    principal_id: params.principal_id,
    principal_public_keys: params.principal_public_keys,
    role: params.role,
    fortress_id: params.master_public_keys.fortress_id,
    issued_at: params.issued_at ?? new Date().toISOString(),
    expires_at: params.expires_at,
  } satisfies Omit<PrincipalCertificateV2Hybrid, "master_signature_bundle">;
  assertHybridPublicKeys("principal_public_keys", body.principal_public_keys);
  assertHybridPublicKeys(
    "master_public_keys",
    params.master_public_keys.public_keys
  );
  assertHybridPrivateKeyRefs(
    params.master_private_keys,
    params.master_public_keys.public_keys
  );
  const masterSignatureBundle = await cryptoSuiteRegistry.signSurface(
    principalV2Descriptor(body),
    hybridSignerFromPrivateKeys(params.master_private_keys)
  );
  const cert: PrincipalCertificateV2Hybrid = {
    ...body,
    master_signature_bundle: masterSignatureBundle,
  };
  assertJsonByteLimit(
    "v2 hybrid principal certificate",
    cert,
    MAX_HYBRID_PRINCIPAL_CERT_JSON_BYTES
  );
  return cert;
}

/**
 * Issue a v2 hybrid per-node certificate.
 *
 * The node certificate always includes both a principal signature bundle and a
 * fortress-master signature bundle. Omitting the master bundle is a downgrade
 * and is rejected by verifyCertChainV2Hybrid.
 */
export async function issueNodeIdentityCertificateV2Hybrid(params: {
  readonly node_id: string;
  readonly node_public_keys: HybridCertificatePublicKeys;
  readonly node_mode: NodeMode;
  readonly capabilities: number;
  readonly principal_certificate: PrincipalCertificateV2Hybrid;
  readonly principal_private_keys: HybridPrivateKeyMaterial;
  readonly master_public_keys: FortressMasterPublicKeysV2Hybrid;
  readonly master_private_keys: HybridPrivateKeyMaterial;
  readonly joined_at?: string;
  readonly expires_at?: string;
  readonly tee_attestation_hash?: string;
}): Promise<NodeIdentityCertificateV2Hybrid> {
  if (hasReservedCapabilityBits(params.capabilities)) {
    throw new MeshReservedCapabilityBitError(params.capabilities);
  }
  if (params.capabilities === 0) {
    throw new MeshChainError(
      "v2 hybrid node cert MUST set at least CAP_STANDARD_FORTRESS_NODE (bit 0)"
    );
  }
  assertHybridPublicKeys("node_public_keys", params.node_public_keys);
  assertHybridPublicKeys(
    "principal_public_keys",
    params.principal_certificate.principal_public_keys
  );
  assertHybridPublicKeys(
    "master_public_keys",
    params.master_public_keys.public_keys
  );
  assertHybridPrivateKeyRefs(
    params.principal_private_keys,
    params.principal_certificate.principal_public_keys
  );
  assertHybridPrivateKeyRefs(
    params.master_private_keys,
    params.master_public_keys.public_keys
  );

  const body = {
    certificate_version: NODE_IDENTITY_CERTIFICATE_VERSION_V2_HYBRID,
    signature_suite: HYBRID_SIGNATURE_SUITE_ID,
    node_id: params.node_id,
    node_public_keys: params.node_public_keys,
    node_mode: params.node_mode,
    fortress_id: params.master_public_keys.fortress_id,
    joined_at: params.joined_at ?? new Date().toISOString(),
    expires_at: params.expires_at,
    capabilities: params.capabilities,
    parent_chain: {
      fortress_master_key_version: FORTRESS_MASTER_KEY_VERSION_V2_HYBRID,
      fortress_master_key_refs: {
        ed25519: params.master_public_keys.public_keys.ed25519.key_ref,
        ml_dsa_65: params.master_public_keys.public_keys.ml_dsa_65.key_ref,
      },
      principal_certificate_version: PRINCIPAL_CERTIFICATE_VERSION_V2_HYBRID,
      principal_id: params.principal_certificate.principal_id,
      principal_key_refs: {
        ed25519:
          params.principal_certificate.principal_public_keys.ed25519.key_ref,
        ml_dsa_65:
          params.principal_certificate.principal_public_keys.ml_dsa_65.key_ref,
      },
    },
    tee_attestation_hash: params.tee_attestation_hash,
    delegated_grants: [] as unknown[],
    attestation_lineage_chain: [] as unknown[],
  } satisfies Omit<
    NodeIdentityCertificateV2Hybrid,
    "principal_signature_bundle" | "master_signature_bundle"
  >;
  if (body.fortress_id !== params.principal_certificate.fortress_id) {
    throw new MeshChainError(
      "v2 hybrid node cert principal certificate belongs to a different fortress"
    );
  }
  const descriptor = nodeV2Descriptor(body);
  const [principalSignatureBundle, masterSignatureBundle] = await Promise.all([
    cryptoSuiteRegistry.signSurface(
      descriptor,
      hybridSignerFromPrivateKeys(params.principal_private_keys)
    ),
    cryptoSuiteRegistry.signSurface(
      descriptor,
      hybridSignerFromPrivateKeys(params.master_private_keys)
    ),
  ]);
  const cert: NodeIdentityCertificateV2Hybrid = {
    ...body,
    principal_signature_bundle: principalSignatureBundle,
    master_signature_bundle: masterSignatureBundle,
  };
  assertJsonByteLimit(
    "v2 hybrid node certificate",
    cert,
    MAX_HYBRID_NODE_CERT_JSON_BYTES
  );
  return cert;
}

/** Verify a v2 hybrid principal certificate against the pinned hybrid master. */
export async function verifyPrincipalCertificateV2Hybrid(
  cert: PrincipalCertificateV2Hybrid,
  pinnedMasterPubkey: FortressMasterPublicKeysV2Hybrid,
  nowMs = Date.now()
): Promise<void> {
  assertV2HybridPrincipalCertificate(cert);
  assertV2HybridFortressMaster(pinnedMasterPubkey);
  assertJsonByteLimit(
    "v2 hybrid principal certificate",
    cert,
    MAX_HYBRID_PRINCIPAL_CERT_JSON_BYTES
  );
  assertSignatureBundleSize(
    "principal master_signature_bundle",
    cert.master_signature_bundle
  );
  assertHybridPublicKeys("principal_public_keys", cert.principal_public_keys);
  assertHybridPublicKeys("master_public_keys", pinnedMasterPubkey.public_keys);

  if (cert.fortress_id !== pinnedMasterPubkey.fortress_id) {
    throw new MeshChainError(
      `v2 principal cert fortress_id=${cert.fortress_id} does not match pinned master fortress_id=${pinnedMasterPubkey.fortress_id}`
    );
  }
  assertNotExpired("principal cert", cert.principal_id, cert.expires_at, nowMs);

  const ok = await cryptoSuiteRegistry.verifySurface(
    principalV2Descriptor(principalV2Body(cert)),
    cert.master_signature_bundle,
    hybridPublicKeysFromCertificate(pinnedMasterPubkey.public_keys)
  );
  if (!ok) {
    throw new MeshChainError(
      `v2 principal cert ${cert.principal_id} hybrid signature does not verify against pinned fortress-master`
    );
  }
}

/** Verify a v2 hybrid node certificate chain against the pinned hybrid master. */
export async function verifyCertChainV2Hybrid(
  cert: NodeIdentityCertificateV2Hybrid,
  principalCert: PrincipalCertificateV2Hybrid,
  pinnedMasterPubkey: FortressMasterPublicKeysV2Hybrid,
  nowMs = Date.now()
): Promise<void> {
  assertV2HybridNodeCertificate(cert);
  assertV2HybridPrincipalCertificate(principalCert);
  assertV2HybridFortressMaster(pinnedMasterPubkey);
  assertJsonByteLimit(
    "v2 hybrid node certificate",
    cert,
    MAX_HYBRID_NODE_CERT_JSON_BYTES
  );
  assertSignatureBundleSize(
    "node principal_signature_bundle",
    cert.principal_signature_bundle
  );
  assertSignatureBundleSize(
    "node master_signature_bundle",
    cert.master_signature_bundle
  );
  assertHybridPublicKeys("node_public_keys", cert.node_public_keys);

  if (cert.fortress_id !== pinnedMasterPubkey.fortress_id) {
    throw new MeshChainError(
      `v2 node cert fortress_id=${cert.fortress_id} does not match pinned master fortress_id=${pinnedMasterPubkey.fortress_id}`
    );
  }
  if (principalCert.fortress_id !== pinnedMasterPubkey.fortress_id) {
    throw new MeshChainError(
      "v2 principal cert fortress_id mismatch during node-chain validation"
    );
  }
  if (
    cert.parent_chain.fortress_master_key_version !==
      FORTRESS_MASTER_KEY_VERSION_V2_HYBRID ||
    cert.parent_chain.fortress_master_key_refs.ed25519 !==
      pinnedMasterPubkey.public_keys.ed25519.key_ref ||
    cert.parent_chain.fortress_master_key_refs.ml_dsa_65 !==
      pinnedMasterPubkey.public_keys.ml_dsa_65.key_ref
  ) {
    throw new MeshChainError(
      "v2 node cert parent_chain fortress-master key refs do not match pinned master"
    );
  }
  if (
    cert.parent_chain.principal_certificate_version !==
      PRINCIPAL_CERTIFICATE_VERSION_V2_HYBRID ||
    cert.parent_chain.principal_id !== principalCert.principal_id ||
    cert.parent_chain.principal_key_refs.ed25519 !==
      principalCert.principal_public_keys.ed25519.key_ref ||
    cert.parent_chain.principal_key_refs.ml_dsa_65 !==
      principalCert.principal_public_keys.ml_dsa_65.key_ref
  ) {
    throw new MeshChainError(
      `v2 node cert parent_chain principal does not match given principal cert ${principalCert.principal_id}`
    );
  }

  await verifyPrincipalCertificateV2Hybrid(
    principalCert,
    pinnedMasterPubkey,
    nowMs
  );
  assertNotExpired("node cert", cert.node_id, cert.expires_at, nowMs);

  const descriptor = nodeV2Descriptor(nodeV2Body(cert));
  const principalOk = await cryptoSuiteRegistry.verifySurface(
    descriptor,
    cert.principal_signature_bundle,
    hybridPublicKeysFromCertificate(principalCert.principal_public_keys)
  );
  if (!principalOk) {
    throw new MeshChainError(
      `v2 node cert ${cert.node_id} principal hybrid signature does not verify against principal ${principalCert.principal_id}`
    );
  }
  const masterOk = await cryptoSuiteRegistry.verifySurface(
    descriptor,
    cert.master_signature_bundle,
    hybridPublicKeysFromCertificate(pinnedMasterPubkey.public_keys)
  );
  if (!masterOk) {
    throw new MeshChainError(
      `v2 node cert ${cert.node_id} master hybrid signature does not verify against pinned fortress-master`
    );
  }
}

/**
 * Policy-dispatch chain verifier for downgrade-sensitive callers.
 *
 * minimum_suite "ed25519+ml-dsa-v1" rejects every v0.1/v1 Ed25519-only chain
 * before crypto verification. Callers that still accept legacy chains must
 * explicitly request minimum_suite "ed25519-v1".
 */
export async function verifyCertChainWithPolicy(
  cert: NodeIdentityCertificate | NodeIdentityCertificateV2Hybrid,
  principalCert: PrincipalCertificate | PrincipalCertificateV2Hybrid,
  pinnedMasterPubkey:
    | FortressMasterPublicKey
    | FortressMasterPublicKeysV2Hybrid,
  options: {
    readonly minimum_suite: TrustRootCertificateChainPolicy;
    readonly nowMs?: number;
  }
): Promise<void> {
  const nowMs = options.nowMs ?? Date.now();
  if (options.minimum_suite === HYBRID_SIGNATURE_SUITE_ID) {
    if (
      !isV2HybridNodeCertificate(cert) ||
      !isV2HybridPrincipalCertificate(principalCert) ||
      !isV2HybridFortressMaster(pinnedMasterPubkey)
    ) {
      throw new MeshChainError(
        "hybrid-required chain policy rejects non-hybrid trust-root certificate chain"
      );
    }
    await verifyCertChainV2Hybrid(cert, principalCert, pinnedMasterPubkey, nowMs);
    return;
  }

  if (
    isV2HybridNodeCertificate(cert) ||
    isV2HybridPrincipalCertificate(principalCert) ||
    isV2HybridFortressMaster(pinnedMasterPubkey)
  ) {
    if (
      isV2HybridNodeCertificate(cert) &&
      isV2HybridPrincipalCertificate(principalCert) &&
      isV2HybridFortressMaster(pinnedMasterPubkey)
    ) {
      await verifyCertChainV2Hybrid(
        cert,
        principalCert,
        pinnedMasterPubkey,
        nowMs
      );
      return;
    }
    throw new MeshChainError("mixed v1/v2 trust-root certificate chain rejected");
  }

  verifyCertChain(
    cert as NodeIdentityCertificate,
    principalCert as PrincipalCertificate,
    pinnedMasterPubkey as FortressMasterPublicKey,
    nowMs
  );
}

// ═══════════════════════════════════════════════════════════════════════
// Hybrid root-rotation binding (rotate-root --renew on a HYBRID fortress)
// ═══════════════════════════════════════════════════════════════════════

/**
 * The exact canonical body the OLD hybrid master signs (both components) and a
 * verifier reconstructs for a hybrid root-rotation binding. Binds the full
 * classical rotation body (stable fortress_id, old_master_pubkey, new_master,
 * strictly-monotonic rotation_serial, rotated_at) and BOTH the old and new
 * hybrid master public-key sets (both Ed25519 + ML-DSA-65 components).
 * Signature-bearing fields are excluded. FROZEN wire surface.
 */
function hybridRotationBindingBody(params: {
  readonly fortress_id: string;
  readonly old_master_pubkey: string;
  readonly new_master: FortressMasterPublicKey;
  readonly rotation_serial: number;
  readonly rotated_at: string;
  readonly old_hybrid_master: FortressMasterPublicKeysV2Hybrid;
  readonly new_hybrid_master: FortressMasterPublicKeysV2Hybrid;
}): CanonicalJsonValue {
  return {
    kind: ROOT_ROTATION_HYBRID_BINDING_VERSION,
    fortress_id: params.fortress_id,
    old_master_pubkey: params.old_master_pubkey,
    new_master: {
      public_key: params.new_master.public_key,
      fortress_id: params.new_master.fortress_id,
      created_at: params.new_master.created_at,
    },
    rotation_serial: params.rotation_serial,
    rotated_at: params.rotated_at,
    old_hybrid_master: params.old_hybrid_master as unknown as CanonicalJsonValue,
    new_hybrid_master: params.new_hybrid_master as unknown as CanonicalJsonValue,
  };
}

function hybridRotationDescriptor(body: CanonicalJsonValue) {
  return {
    surface_id: TRUST_ROOT_ROOT_ROTATION_SURFACE_ID,
    surface_version: ROOT_ROTATION_HYBRID_BINDING_VERSION,
    signature_suite: HYBRID_SIGNATURE_SUITE_ID,
    payload: body,
  };
}

/**
 * Sign the hybrid half of a root-rotation certificate with the OLD hybrid
 * master's two private keys (Ed25519 + ML-DSA-65). Produces a both-must-pass
 * hybrid signature bundle binding the OLD hybrid master to the NEW hybrid master
 * AND binding the outer classical K1->K2 rotation body. The caller MUST zero the
 * old master private material after return (constraint 6). The returned binding
 * is PUBLIC (an old-key signature over public keys).
 */
export async function signFederationRootRotationHybridBinding(params: {
  readonly fortress_id: string;
  readonly old_master_pubkey: string;
  readonly new_master: FortressMasterPublicKey;
  readonly rotation_serial: number;
  readonly old_hybrid_master: FortressMasterPublicKeysV2Hybrid;
  readonly new_hybrid_master: FortressMasterPublicKeysV2Hybrid;
  readonly old_hybrid_master_private_keys: HybridPrivateKeyMaterial;
  readonly rotated_at?: string;
}): Promise<{
  hybrid_rotation: {
    old_hybrid_master: FortressMasterPublicKeysV2Hybrid;
    new_hybrid_master: FortressMasterPublicKeysV2Hybrid;
    old_hybrid_master_signature_bundle: SignatureBundle;
  };
  rotated_at: string;
}> {
  if (!Number.isInteger(params.rotation_serial) || params.rotation_serial < 1) {
    throw new MeshChainError(
      "hybrid rotation_serial must be a positive integer (a renewal always advances the serial)"
    );
  }
  if (params.old_hybrid_master.fortress_id !== params.fortress_id) {
    throw new MeshChainError(
      "hybrid rotation old_hybrid_master.fortress_id must equal the stable fortress_id"
    );
  }
  if (params.old_master_pubkey.length === 0) {
    throw new MeshChainError("hybrid rotation old_master_pubkey must be present");
  }
  if (params.new_master.fortress_id !== params.fortress_id) {
    throw new MeshChainError(
      "hybrid rotation new_master.fortress_id must equal the stable fortress_id"
    );
  }
  if (params.new_master.public_key.length === 0) {
    throw new MeshChainError("hybrid rotation new_master.public_key must be present");
  }
  if (params.new_hybrid_master.fortress_id !== params.fortress_id) {
    throw new MeshChainError(
      "hybrid rotation new_hybrid_master.fortress_id must equal the stable fortress_id (renewal preserves identity)"
    );
  }
  assertHybridPublicKeys(
    "old_hybrid_master",
    params.old_hybrid_master.public_keys
  );
  assertHybridPublicKeys(
    "new_hybrid_master",
    params.new_hybrid_master.public_keys
  );
  assertHybridPrivateKeyRefs(
    params.old_hybrid_master_private_keys,
    params.old_hybrid_master.public_keys
  );
  const rotatedAt = params.rotated_at ?? new Date().toISOString();
  const body = hybridRotationBindingBody({
    fortress_id: params.fortress_id,
    old_master_pubkey: params.old_master_pubkey,
    new_master: params.new_master,
    rotation_serial: params.rotation_serial,
    rotated_at: rotatedAt,
    old_hybrid_master: params.old_hybrid_master,
    new_hybrid_master: params.new_hybrid_master,
  });
  const bundle = await cryptoSuiteRegistry.signSurface(
    hybridRotationDescriptor(body),
    hybridSignerFromPrivateKeys(params.old_hybrid_master_private_keys)
  );
  return {
    hybrid_rotation: {
      old_hybrid_master: params.old_hybrid_master,
      new_hybrid_master: params.new_hybrid_master,
      old_hybrid_master_signature_bundle: bundle,
    },
    rotated_at: rotatedAt,
  };
}

/**
 * Verify the hybrid half of a root-rotation certificate against the master the
 * verifier CURRENTLY pins (the OLD hybrid master, both components). BOTH-MUST-PASS:
 * the hybrid bundle's Ed25519 AND ML-DSA-65 components must both verify under the
 * pinned old hybrid master, or the binding is rejected. This is the fail-closed
 * gate against a silent PQ-downgrade of the rotation link. Throws MeshChainError
 * on any failure.
 *
 *   - the binding names the pinned OLD hybrid master (both key refs) and the
 *     SAME fortress_id;
 *   - the new hybrid master carries that same fortress_id;
 *   - if `minSerial` is supplied, the serial MUST strictly advance it;
 *   - the bundle verifies (both components) under the pinned old hybrid master.
 */
export async function verifyFederationRootRotationHybridBinding(
  binding: {
    old_hybrid_master: FortressMasterPublicKeysV2Hybrid;
    new_hybrid_master: FortressMasterPublicKeysV2Hybrid;
    old_hybrid_master_signature_bundle: SignatureBundle;
  },
  pinnedOldHybridMaster: FortressMasterPublicKeysV2Hybrid,
  opts: {
    fortress_id?: string;
    old_master_pubkey?: string;
    new_master?: FortressMasterPublicKey;
    rotation_serial?: number;
    rotated_at?: string;
    minSerial?: number;
  } = {}
): Promise<void> {
  assertV2HybridFortressMaster(pinnedOldHybridMaster);
  assertV2HybridFortressMaster(binding.old_hybrid_master);
  assertV2HybridFortressMaster(binding.new_hybrid_master);
  assertHybridPublicKeys(
    "binding.old_hybrid_master",
    binding.old_hybrid_master.public_keys
  );
  assertHybridPublicKeys(
    "binding.new_hybrid_master",
    binding.new_hybrid_master.public_keys
  );
  assertHybridPublicKeys(
    "pinned old hybrid master",
    pinnedOldHybridMaster.public_keys
  );
  assertSignatureBundleSize(
    "hybrid rotation signature bundle",
    binding.old_hybrid_master_signature_bundle
  );

  // The binding's declared old hybrid master MUST be the master this verifier
  // currently pins (both key refs + both public keys), and the same fortress_id.
  if (
    binding.old_hybrid_master.fortress_id !== pinnedOldHybridMaster.fortress_id ||
    binding.old_hybrid_master.public_keys.ed25519.key_ref !==
      pinnedOldHybridMaster.public_keys.ed25519.key_ref ||
    binding.old_hybrid_master.public_keys.ed25519.public_key !==
      pinnedOldHybridMaster.public_keys.ed25519.public_key ||
    binding.old_hybrid_master.public_keys.ml_dsa_65.key_ref !==
      pinnedOldHybridMaster.public_keys.ml_dsa_65.key_ref ||
    binding.old_hybrid_master.public_keys.ml_dsa_65.public_key !==
      pinnedOldHybridMaster.public_keys.ml_dsa_65.public_key
  ) {
    throw new MeshChainError(
      "hybrid rotation binding old_hybrid_master does not match the hybrid master this verifier currently pins"
    );
  }
  if (
    opts.fortress_id !== undefined &&
    binding.new_hybrid_master.fortress_id !== opts.fortress_id
  ) {
    throw new MeshChainError(
      "hybrid rotation binding new_hybrid_master.fortress_id does not match the stable fortress_id"
    );
  }
  if (
    binding.new_hybrid_master.fortress_id !== pinnedOldHybridMaster.fortress_id
  ) {
    throw new MeshChainError(
      "hybrid rotation binding new_hybrid_master.fortress_id does not match the stable fortress_id"
    );
  }
  if (opts.rotation_serial !== undefined) {
    if (!Number.isInteger(opts.rotation_serial) || opts.rotation_serial < 1) {
      throw new MeshChainError(
        "hybrid rotation rotation_serial must be a positive integer"
      );
    }
    if (opts.minSerial !== undefined && opts.rotation_serial <= opts.minSerial) {
      throw new MeshChainError(
        `hybrid rotation rotation_serial=${opts.rotation_serial} does not advance the adopted serial ${opts.minSerial} (stale / replayed rotation rejected)`
      );
    }
  }

  if (opts.old_master_pubkey !== undefined && opts.old_master_pubkey.length === 0) {
    throw new MeshChainError("hybrid rotation old_master_pubkey must be present");
  }
  if (opts.new_master !== undefined) {
    if (opts.new_master.public_key.length === 0) {
      throw new MeshChainError("hybrid rotation new_master.public_key must be present");
    }
    if (
      opts.fortress_id !== undefined &&
      opts.new_master.fortress_id !== opts.fortress_id
    ) {
      throw new MeshChainError(
        "hybrid rotation new_master.fortress_id does not match the stable fortress_id"
      );
    }
  }

  // Reconstruct the body exactly: the caller supplies the classical rotation
  // cert fields so the hybrid signed preimage is bound to the outer Ed25519 link.
  if (
    opts.fortress_id === undefined ||
    opts.old_master_pubkey === undefined ||
    opts.new_master === undefined ||
    opts.rotation_serial === undefined ||
    opts.rotated_at === undefined
  ) {
    throw new MeshChainError(
      "hybrid rotation verify requires the full classical rotation body to reconstruct the signed body"
    );
  }
  const body = hybridRotationBindingBody({
    fortress_id: opts.fortress_id,
    old_master_pubkey: opts.old_master_pubkey,
    new_master: opts.new_master,
    rotation_serial: opts.rotation_serial,
    rotated_at: opts.rotated_at,
    old_hybrid_master: binding.old_hybrid_master,
    new_hybrid_master: binding.new_hybrid_master,
  });
  const ok = await cryptoSuiteRegistry.verifySurface(
    hybridRotationDescriptor(body),
    binding.old_hybrid_master_signature_bundle,
    hybridPublicKeysFromCertificate(pinnedOldHybridMaster.public_keys)
  );
  if (!ok) {
    throw new MeshChainError(
      "hybrid rotation binding signature does not verify (both-must-pass) under the pinned old hybrid master"
    );
  }
}

function hybridKeyRefs(
  ownerKind: "fortress-master" | "principal" | "node",
  ownerId: string
): { readonly ed25519: string; readonly ml_dsa_65: string } {
  return {
    ed25519: `${ownerKind}.${ownerId}.ed25519-v1`,
    ml_dsa_65: `${ownerKind}.${ownerId}.ml-dsa-65-v1`,
  };
}

function hybridSignerFromPrivateKeys(
  keys: HybridPrivateKeyMaterial
): SuiteSigner {
  if (keys.ed25519.private_key.length !== ED25519_PRIVATE_KEY_BYTES) {
    throw new MeshChainError("hybrid Ed25519 private key must be 32 bytes");
  }
  if (keys.ml_dsa_65.secret_key.length !== ML_DSA_65_SECRET_KEY_BYTES) {
    throw new MeshChainError("hybrid ML-DSA-65 secret key must be 4032 bytes");
  }
  return {
    ed25519: {
      key_ref: keys.ed25519.key_ref,
      sign: (bytes) => ed25519.sign(bytes, keys.ed25519.private_key),
    },
    ml_dsa_65: {
      key_ref: keys.ml_dsa_65.key_ref,
      sign: (bytes) => ml_dsa65.sign(bytes, keys.ml_dsa_65.secret_key),
    },
  };
}

function hybridPublicKeysFromCertificate(
  keys: HybridCertificatePublicKeys
): SuitePublicKeys {
  assertHybridPublicKeys("hybrid_public_keys", keys);
  return createHybridSuitePublicKeys({
    ed25519KeyRef: keys.ed25519.key_ref,
    ed25519PublicKey: decodeExactPublicKey(
      "ed25519 public key",
      keys.ed25519.public_key,
      ED25519_PUBLIC_KEY_BYTES
    ),
    mlDsa65KeyRef: keys.ml_dsa_65.key_ref,
    mlDsa65PublicKey: decodeExactPublicKey(
      "ML-DSA-65 public key",
      keys.ml_dsa_65.public_key,
      ML_DSA_65_PUBLIC_KEY_BYTES
    ),
  });
}

function assertHybridPrivateKeyRefs(
  privateKeys: HybridPrivateKeyMaterial,
  publicKeys: HybridCertificatePublicKeys
): void {
  if (privateKeys.ed25519.key_ref !== publicKeys.ed25519.key_ref) {
    throw new MeshChainError(
      "hybrid Ed25519 private key_ref does not match public key_ref"
    );
  }
  if (privateKeys.ml_dsa_65.key_ref !== publicKeys.ml_dsa_65.key_ref) {
    throw new MeshChainError(
      "hybrid ML-DSA-65 private key_ref does not match public key_ref"
    );
  }
}

function assertHybridPublicKeys(
  label: string,
  keys: HybridCertificatePublicKeys
): void {
  if (typeof keys !== "object" || keys === null) {
    throw new MeshChainError(`${label} must be an object`);
  }
  if (keys.signature_suite !== HYBRID_SIGNATURE_SUITE_ID) {
    throw new MeshChainError(
      `${label} signature_suite must be ${HYBRID_SIGNATURE_SUITE_ID}`
    );
  }
  if (!keys.ed25519?.key_ref || !keys.ml_dsa_65?.key_ref) {
    throw new MeshChainError(`${label} must include non-empty hybrid key refs`);
  }
  decodeExactPublicKey(
    `${label}.ed25519.public_key`,
    keys.ed25519.public_key,
    ED25519_PUBLIC_KEY_BYTES
  );
  decodeExactPublicKey(
    `${label}.ml_dsa_65.public_key`,
    keys.ml_dsa_65.public_key,
    ML_DSA_65_PUBLIC_KEY_BYTES
  );
}

function decodeExactPublicKey(
  label: string,
  encoded: string,
  expectedBytes: number
): Uint8Array {
  try {
    const decoded = fromBase64url(encoded);
    if (toBase64url(decoded) !== encoded || decoded.length !== expectedBytes) {
      throw new Error("bad public key encoding");
    }
    return decoded;
  } catch {
    throw new MeshChainError(
      `${label} is not a canonical ${expectedBytes}-byte base64url value`
    );
  }
}

function principalV2Body(
  cert: PrincipalCertificateV2Hybrid
): Omit<PrincipalCertificateV2Hybrid, "master_signature_bundle"> {
  return {
    certificate_version: cert.certificate_version,
    signature_suite: cert.signature_suite,
    principal_id: cert.principal_id,
    principal_public_keys: cert.principal_public_keys,
    role: cert.role,
    fortress_id: cert.fortress_id,
    issued_at: cert.issued_at,
    expires_at: cert.expires_at,
  };
}

function nodeV2Body(
  cert: NodeIdentityCertificateV2Hybrid
): Omit<
  NodeIdentityCertificateV2Hybrid,
  "principal_signature_bundle" | "master_signature_bundle"
> {
  return {
    certificate_version: cert.certificate_version,
    signature_suite: cert.signature_suite,
    node_id: cert.node_id,
    node_public_keys: cert.node_public_keys,
    node_mode: cert.node_mode,
    fortress_id: cert.fortress_id,
    joined_at: cert.joined_at,
    expires_at: cert.expires_at,
    capabilities: cert.capabilities,
    parent_chain: cert.parent_chain,
    tee_attestation_hash: cert.tee_attestation_hash,
    delegated_grants: cert.delegated_grants ?? [],
    attestation_lineage_chain: cert.attestation_lineage_chain ?? [],
  };
}

function principalV2Descriptor(
  body: Omit<PrincipalCertificateV2Hybrid, "master_signature_bundle">
) {
  return {
    surface_id: TRUST_ROOT_PRINCIPAL_CERT_SURFACE_ID,
    surface_version: PRINCIPAL_CERTIFICATE_VERSION_V2_HYBRID,
    signature_suite: HYBRID_SIGNATURE_SUITE_ID,
    payload: body as unknown as CanonicalJsonValue,
  };
}

function nodeV2Descriptor(
  body: Omit<
    NodeIdentityCertificateV2Hybrid,
    "principal_signature_bundle" | "master_signature_bundle"
  >
) {
  return {
    surface_id: TRUST_ROOT_NODE_CERT_SURFACE_ID,
    surface_version: NODE_IDENTITY_CERTIFICATE_VERSION_V2_HYBRID,
    signature_suite: HYBRID_SIGNATURE_SUITE_ID,
    payload: body as unknown as CanonicalJsonValue,
  };
}

function assertSignatureBundleSize(label: string, bundle: unknown): void {
  if (bundle === undefined || bundle === null) {
    throw new MeshChainError(`${label} is required`);
  }
  assertJsonByteLimit(label, bundle, MAX_HYBRID_SIGNATURE_BUNDLE_JSON_BYTES);
}

function assertJsonByteLimit(
  label: string,
  value: unknown,
  maxBytes: number
): void {
  const size = Buffer.byteLength(JSON.stringify(value), "utf8");
  if (size > maxBytes) {
    throw new MeshChainError(`${label} exceeds ${maxBytes} byte parse cap`);
  }
}

function assertNotExpired(
  label: string,
  id: string,
  expiresAt: string | undefined,
  nowMs: number
): void {
  if (!expiresAt) return;
  const expiresMs = Date.parse(expiresAt);
  if (Number.isNaN(expiresMs) || expiresMs < nowMs) {
    throw new MeshChainError(`${label} ${id} expired at ${expiresAt}`);
  }
}

function assertV2HybridFortressMaster(
  master: FortressMasterPublicKeysV2Hybrid
): void {
  if (
    master.key_version !== FORTRESS_MASTER_KEY_VERSION_V2_HYBRID ||
    master.signature_suite !== HYBRID_SIGNATURE_SUITE_ID
  ) {
    throw new MeshChainError("unsupported v2 hybrid fortress-master descriptor");
  }
}

function assertV2HybridPrincipalCertificate(
  cert: PrincipalCertificateV2Hybrid
): void {
  if (
    cert.certificate_version !== PRINCIPAL_CERTIFICATE_VERSION_V2_HYBRID ||
    cert.signature_suite !== HYBRID_SIGNATURE_SUITE_ID
  ) {
    throw new MeshChainError("unsupported v2 hybrid principal certificate");
  }
}

function assertV2HybridNodeCertificate(
  cert: NodeIdentityCertificateV2Hybrid
): void {
  if (
    cert.certificate_version !== NODE_IDENTITY_CERTIFICATE_VERSION_V2_HYBRID ||
    cert.signature_suite !== HYBRID_SIGNATURE_SUITE_ID
  ) {
    throw new MeshChainError("unsupported v2 hybrid node certificate");
  }
  if (!cert.master_signature_bundle) {
    throw new MeshChainError(
      "v2 hybrid node cert requires master_signature_bundle"
    );
  }
}

function isV2HybridFortressMaster(
  value: unknown
): value is FortressMasterPublicKeysV2Hybrid {
  return (
    typeof value === "object" &&
    value !== null &&
    (value as { key_version?: unknown }).key_version ===
      FORTRESS_MASTER_KEY_VERSION_V2_HYBRID &&
    (value as { signature_suite?: unknown }).signature_suite ===
      HYBRID_SIGNATURE_SUITE_ID
  );
}

function isV2HybridPrincipalCertificate(
  value: unknown
): value is PrincipalCertificateV2Hybrid {
  return (
    typeof value === "object" &&
    value !== null &&
    (value as { certificate_version?: unknown }).certificate_version ===
      PRINCIPAL_CERTIFICATE_VERSION_V2_HYBRID &&
    (value as { signature_suite?: unknown }).signature_suite ===
      HYBRID_SIGNATURE_SUITE_ID
  );
}

function isV2HybridNodeCertificate(
  value: unknown
): value is NodeIdentityCertificateV2Hybrid {
  return (
    typeof value === "object" &&
    value !== null &&
    (value as { certificate_version?: unknown }).certificate_version ===
      NODE_IDENTITY_CERTIFICATE_VERSION_V2_HYBRID &&
    (value as { signature_suite?: unknown }).signature_suite ===
      HYBRID_SIGNATURE_SUITE_ID
  );
}
