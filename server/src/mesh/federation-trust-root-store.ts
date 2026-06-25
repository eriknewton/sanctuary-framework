/**
 * Encrypted persistence for the v1 HTTP federation trust root.
 *
 * The `_federation/trust-root-v1` record is the root of cross-machine trust:
 * fortress master public/private material, the distinct transport HKDF secret,
 * the issuing principal keypair, and this daemon's local node identity. It is
 * always stored as AES-GCM ciphertext under a purpose-derived custody key.
 *
 * PQC Slice 3 (opt-in, default OFF): a fortress provisioned with the hybrid
 * suite ALSO carries, additively in this SAME at-rest blob (same custody key,
 * same `federation-trust-root` HKDF label, no new label, no new store), the
 * Ed25519+ML-DSA-65 hybrid pinned master, the hybrid master private key material
 * (Ed25519 32-byte private key plus the ML-DSA-65 4032-byte secret key), and the
 * hybrid principal + local node certificates. Classical-only (v1) records carry
 * none of those fields and load byte-for-byte unchanged. This makes only the
 * federation SIGNING MASTER hybrid-capable when opted in; it does NOT make audit,
 * transparency, reputation, custody at-rest, or transport post-quantum.
 */

import { ed25519 } from "@noble/curves/ed25519";
import { ml_dsa65 } from "@noble/post-quantum/ml-dsa.js";
import type { StorageBackend } from "../storage/interface.js";
import { encrypt, decrypt, type EncryptedPayload } from "../core/encryption.js";
import { derivePurposeKey } from "../core/key-derivation.js";
import {
  bytesToString,
  fromBase64url,
  stringToBytes,
  toBase64url,
} from "../core/encoding.js";
import { generateKeypair } from "../core/identity.js";
import { randomBytes } from "../core/random.js";
import {
  ED25519_PUBLIC_KEY_BYTES,
  ML_DSA_65_SECRET_KEY_BYTES,
} from "../core/crypto-suite-registry.js";
import { CAP_STANDARD_FORTRESS_NODE, type NodeMode } from "./constants.js";
import {
  generateFortressMaster,
  issueNodeIdentityCertificate,
  issuePrincipalCertificate,
  verifyCertChain,
  verifyPrincipalCertificate,
} from "./trust-root.js";
import { FEDERATION_ROOT_ROTATION_KIND } from "./trust-root.js";
import {
  generateFortressMasterV2Hybrid,
  generateHybridCertificateKeypair,
  issueNodeIdentityCertificateV2Hybrid,
  issuePrincipalCertificateV2Hybrid,
  verifyCertChainV2Hybrid,
  type HybridPrivateKeyMaterial,
} from "./trust-root-hybrid.js";
import type {
  FederationRootRotationCertificate,
  FortressMasterPublicKey,
  FortressMasterPublicKeysV2Hybrid,
  HybridCertificatePublicKeys,
  NodeIdentityCertificate,
  NodeIdentityCertificateV2Hybrid,
  PrincipalCertificate,
  PrincipalCertificateV2Hybrid,
} from "./types.js";

/** Federation issuance suite selector (opt-in; classical is the default). */
export const FEDERATION_ISSUANCE_SUITE_CLASSICAL = "ed25519-v1" as const;
export const FEDERATION_ISSUANCE_SUITE_HYBRID = "ed25519+ml-dsa-v1" as const;
export type FederationIssuanceSuite =
  | typeof FEDERATION_ISSUANCE_SUITE_CLASSICAL
  | typeof FEDERATION_ISSUANCE_SUITE_HYBRID;

/**
 * The hybrid signing material a hybrid fortress holds in the encrypted blob,
 * additively alongside the classical master. The ML-DSA-65 secret (4032 bytes)
 * and the hybrid Ed25519 private key (32 bytes) are decrypted transiently for
 * signing and zeroed after every use; they are NEVER printed, logged, returned
 * by any verifier surface, or persisted in plaintext (constraint 6).
 */
export interface FederationHybridMasterMaterial {
  pinned_master: FortressMasterPublicKeysV2Hybrid;
  master_private_keys: HybridPrivateKeyMaterial;
  issuing_principal_cert: PrincipalCertificateV2Hybrid;
  issuing_principal_private_keys: HybridPrivateKeyMaterial;
  local_node_cert: NodeIdentityCertificateV2Hybrid;
  local_node_private_keys: HybridPrivateKeyMaterial;
}

export const FEDERATION_TRUST_ROOT_NAMESPACE = "_federation";
export const FEDERATION_TRUST_ROOT_KEY = "trust-root-v1";
export const FEDERATION_TRUST_ROOT_HKDF_INFO = "federation-trust-root";

export interface FederationTrustRootRecord {
  fortress_id: string;
  node_id: string;
  pinned_master_pubkey: FortressMasterPublicKey;
  /** Distinct 32-byte symmetric HKDF source; not the Ed25519 master key. */
  master_secret: Uint8Array;
  /** Present only on the home/issuing node. Joined nodes omit it. */
  master_private_key?: Uint8Array;
  issuing_principal_cert: PrincipalCertificate;
  issuing_principal_private_key: Uint8Array;
  local_node_cert: NodeIdentityCertificate;
  local_node_private_key: Uint8Array;
  /**
   * Slice 3a (rotate-root --renew): the monotonic rotation serial of the CURRENT
   * master. Absent on a freshly-provisioned root (serial 0 implicitly); set to a
   * strictly-advancing integer by each renewal so a replayed/stale rotation cert
   * is rejected. Additive + optional: pre-rotation records omit it.
   */
  rotation_serial?: number;
  /**
   * Slice 3a: the rotation certificate signed by the PREVIOUS master attesting
   * THIS master. Present once the root has been rotated at least once; a joiner
   * that still pins the previous master adopts the new key by verifying this cert
   * (Slice 3b). PUBLIC (an old-key signature over the new PUBLIC key); safe at
   * rest and exportable. Absent on a freshly-provisioned root.
   */
  rotation_cert?: FederationRootRotationCertificate;
  /**
   * PQC Slice 3 (opt-in, default OFF): the Ed25519+ML-DSA-65 hybrid signing
   * material for a fortress provisioned with the hybrid suite. Present ONLY on a
   * hybrid issuer record; absent (undefined) on a classical (default) record,
   * which therefore loads byte-for-byte unchanged. The contained ML-DSA-65 secret
   * key (4032 bytes) and hybrid Ed25519 private key are encrypted in the SAME blob
   * as `master_private_key`/`master_secret` and zeroed after every transient use.
   * The classical fields above remain populated on a hybrid record (transport-key
   * derivation + current-version peer compatibility ride the Ed25519 chain).
   */
  hybrid?: FederationHybridMasterMaterial;
}

/** Persisted form of one hybrid key pair (key_ref plus base64url private bytes). */
interface PersistedHybridPrivateKeyMaterial {
  ed25519: { key_ref: string; private_key: string };
  ml_dsa_65: { key_ref: string; secret_key: string };
}

/** Persisted (base64url) form of the optional hybrid signing material. */
interface PersistedFederationHybridMasterMaterial {
  pinned_master: FortressMasterPublicKeysV2Hybrid;
  master_private_keys: PersistedHybridPrivateKeyMaterial;
  issuing_principal_cert: PrincipalCertificateV2Hybrid;
  issuing_principal_private_keys: PersistedHybridPrivateKeyMaterial;
  local_node_cert: NodeIdentityCertificateV2Hybrid;
  local_node_private_keys: PersistedHybridPrivateKeyMaterial;
}

interface PersistedFederationTrustRootRecord {
  fortress_id: string;
  node_id: string;
  pinned_master_pubkey: FortressMasterPublicKey;
  master_secret: string;
  master_private_key?: string;
  issuing_principal_cert: PrincipalCertificate;
  issuing_principal_private_key: string;
  local_node_cert: NodeIdentityCertificate;
  local_node_private_key: string;
  rotation_serial?: number;
  rotation_cert?: FederationRootRotationCertificate;
  hybrid?: PersistedFederationHybridMasterMaterial;
}

export class FederationTrustRootStoreError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "FederationTrustRootStoreError";
  }
}

export class FederationTrustRootStore {
  private readonly storage: StorageBackend;
  private readonly encryptionKey: Uint8Array;

  constructor(storage: StorageBackend, masterKey: Uint8Array) {
    this.storage = storage;
    this.encryptionKey = derivePurposeKey(
      masterKey,
      FEDERATION_TRUST_ROOT_HKDF_INFO,
    );
  }

  async load(): Promise<FederationTrustRootRecord | null> {
    const raw = await this.storage.read(
      FEDERATION_TRUST_ROOT_NAMESPACE,
      FEDERATION_TRUST_ROOT_KEY,
    );
    if (raw === null) return null;

    let plaintext: Uint8Array | null = null;
    try {
      const encrypted = JSON.parse(bytesToString(raw)) as EncryptedPayload;
      plaintext = decrypt(encrypted, this.encryptionKey);
      const parsed = JSON.parse(bytesToString(plaintext)) as unknown;
      return decodePersistedRecord(parsed);
    } catch (err) {
      throw new FederationTrustRootStoreError(
        `federation trust root failed to load: ${publicErrorReason(err)}`,
      );
    } finally {
      plaintext?.fill(0);
    }
  }

  async save(record: FederationTrustRootRecord): Promise<void> {
    validateRecord(record);
    const serialized = stringToBytes(
      JSON.stringify(encodePersistedRecord(record)),
    );
    try {
      const encrypted = encrypt(serialized, this.encryptionKey);
      await this.storage.write(
        FEDERATION_TRUST_ROOT_NAMESPACE,
        FEDERATION_TRUST_ROOT_KEY,
        stringToBytes(JSON.stringify(encrypted)),
      );
    } finally {
      serialized.fill(0);
    }
  }
}

export interface ProvisionOrLoadFederationTrustRootOptions {
  storage: StorageBackend;
  masterKey: Uint8Array;
  /** Explicit-only mint gate. Production boot leaves this false. */
  mint?: boolean;
  /** Required when minting a first/home node. */
  nodeId?: string;
  nodeMode?: NodeMode;
  principalId?: string;
  /**
   * PQC Slice 3: issuance suite for a fresh mint. DEFAULT = classical
   * (`ed25519-v1`), the unchanged behavior. `ed25519+ml-dsa-v1` additionally
   * mints + persists the hybrid signing material. Ignored when a record already
   * exists (load is suite-agnostic). Opt-in only; never flipped by default.
   */
  issuanceSuite?: FederationIssuanceSuite;
  audit?: (event: FederationTrustRootAuditEvent) => Promise<void> | void;
}

export interface FederationTrustRootAuditEvent {
  operation: "federation_trust_root_load" | "federation_trust_root_mint";
  result: "success" | "failure";
  details: Record<string, unknown>;
}

export interface ProvisionedFederationTrustRoot {
  record: FederationTrustRootRecord;
  context: ReturnType<typeof federationContextFromTrustRootRecord>;
  source: "persisted" | "minted";
}

export async function provisionOrLoadFederationTrustRoot(
  opts: ProvisionOrLoadFederationTrustRootOptions,
): Promise<ProvisionedFederationTrustRoot | null> {
  const store = new FederationTrustRootStore(opts.storage, opts.masterKey);
  let record: FederationTrustRootRecord | null;
  try {
    record = await store.load();
  } catch (err) {
    await auditTrustRoot(opts.audit, {
      operation: "federation_trust_root_load",
      result: "failure",
      details: { reason: "load_failed", error_class: errorName(err) },
    });
    return null;
  }

  if (record !== null) {
    await auditTrustRoot(opts.audit, {
      operation: "federation_trust_root_load",
      result: "success",
      details: {
        fortress_id: record.pinned_master_pubkey.fortress_id,
        node_id: record.node_id,
      },
    });
    return {
      record,
      context: federationContextFromTrustRootRecord(record),
      source: "persisted",
    };
  }

  if (opts.mint !== true) return null;

  const nodeId = opts.nodeId;
  if (typeof nodeId !== "string" || nodeId.length === 0) {
    throw new FederationTrustRootStoreError(
      "nodeId is required to mint a federation trust root",
    );
  }
  const minted = mintFederationTrustRootRecord({
    nodeId,
    nodeMode: opts.nodeMode ?? "local",
    principalId: opts.principalId ?? "principal-root",
  });
  const hybridRequested =
    opts.issuanceSuite === FEDERATION_ISSUANCE_SUITE_HYBRID;
  try {
    if (hybridRequested) {
      // Opt-in hybrid: additively mint the Ed25519+ML-DSA-65 signing material
      // under the SAME fortress_id, verify the both-must-pass chain before
      // persisting, and store it in the same encrypted blob.
      const hybrid = await mintHybridFederationMaterial({
        fortressId: minted.fortress_id,
        nodeId,
        nodeMode: opts.nodeMode ?? "local",
        principalId: opts.principalId ?? "principal-root",
      });
      await verifyHybridFederationChain(hybrid);
      minted.hybrid = hybrid;
    }
    await store.save(minted);
    await auditTrustRoot(opts.audit, {
      operation: "federation_trust_root_mint",
      result: "success",
      details: {
        fortress_id: minted.pinned_master_pubkey.fortress_id,
        node_id: minted.node_id,
        // Attribution-only metadata (PUBLIC, no secret material): which suite
        // this fortress was provisioned with.
        issuance_suite: hybridRequested
          ? FEDERATION_ISSUANCE_SUITE_HYBRID
          : FEDERATION_ISSUANCE_SUITE_CLASSICAL,
      },
    });
    return {
      record: minted,
      context: federationContextFromTrustRootRecord(minted),
      source: "minted",
    };
  } catch (err) {
    await auditTrustRoot(opts.audit, {
      operation: "federation_trust_root_mint",
      result: "failure",
      details: { reason: "persist_failed", error_class: errorName(err) },
    });
    zeroRecordSecrets(minted);
    throw err;
  }
}

export function federationContextFromTrustRootRecord(
  record: FederationTrustRootRecord,
) {
  validateRecord(record);
  return {
    fortressId: record.pinned_master_pubkey.fortress_id,
    nodeId: record.node_id,
    pinnedMasterPubkey: { ...record.pinned_master_pubkey },
    issuingPrincipalCert: clonePrincipalCert(record.issuing_principal_cert),
    getIssuingPrincipalPrivateKey: () =>
      Uint8Array.from(record.issuing_principal_private_key),
    getFortressMasterSecret: () => Uint8Array.from(record.master_secret),
    getMasterPrivateKey: () =>
      record.master_private_key
        ? Uint8Array.from(record.master_private_key)
        : undefined,
    localNodeCert: cloneNodeCert(record.local_node_cert),
    getLocalNodePrivateKey: () => Uint8Array.from(record.local_node_private_key),
    isNodeRevoked: () => false,
    // PQC Slice 3: present (true) when this fortress was provisioned hybrid. The
    // hybrid PINNED MASTER is PUBLIC (the out-of-band anchor a hybrid-capable
    // joiner would pin); the secret material is NOT exposed here (constraint 6).
    isHybrid: record.hybrid !== undefined,
    hybridPinnedMaster: record.hybrid
      ? structuredClone(record.hybrid.pinned_master)
      : undefined,
  };
}

/**
 * PQC Slice 3 (opt-in): mint the Ed25519+ML-DSA-65 hybrid signing material for a
 * fortress under an EXISTING classical record's fortress_id. The hybrid master is
 * a SEPARATE hybrid keypair set (not the classical Ed25519 master), carrying both
 * an Ed25519 component a current-version peer can still verify AND an ML-DSA-65
 * component for post-quantum resistance. Issues the v2 hybrid principal + local
 * node certs via the Slice-2 helpers (both-must-pass at verify). The returned
 * material's ML-DSA-65 secret (4032 bytes) + Ed25519 private keys are owned by the
 * caller (the mint path stores them encrypted then zeroes the transient copies).
 */
export async function mintHybridFederationMaterial(params: {
  fortressId: string;
  nodeId: string;
  nodeMode?: NodeMode;
  principalId?: string;
}): Promise<FederationHybridMasterMaterial> {
  // The hybrid master's fortress_id is generated independently by the helper; we
  // re-bind it to the classical record's fortress_id so the hybrid and classical
  // chains name the SAME fortress (a hybrid fortress is one identity, two suites).
  const masterGen = generateFortressMasterV2Hybrid();
  const pinnedMaster: FortressMasterPublicKeysV2Hybrid = {
    ...masterGen.public,
    fortress_id: params.fortressId,
  };
  const principalKeys = generateHybridCertificateKeypair({
    owner_kind: "principal",
    owner_id: params.principalId ?? "principal-root",
  });
  const nodeKeys = generateHybridCertificateKeypair({
    owner_kind: "node",
    owner_id: params.nodeId,
  });
  const issuingPrincipalCert = await issuePrincipalCertificateV2Hybrid({
    principal_id: params.principalId ?? "principal-root",
    principal_public_keys: principalKeys.public_keys,
    role: "root",
    master_public_keys: pinnedMaster,
    master_private_keys: masterGen.private_keys,
  });
  const localNodeCert = await issueNodeIdentityCertificateV2Hybrid({
    node_id: params.nodeId,
    node_public_keys: nodeKeys.public_keys,
    node_mode: params.nodeMode ?? "local",
    capabilities: CAP_STANDARD_FORTRESS_NODE,
    principal_certificate: issuingPrincipalCert,
    principal_private_keys: principalKeys.private_keys,
    master_public_keys: pinnedMaster,
    master_private_keys: masterGen.private_keys,
  });
  return {
    pinned_master: pinnedMaster,
    master_private_keys: masterGen.private_keys,
    issuing_principal_cert: issuingPrincipalCert,
    issuing_principal_private_keys: principalKeys.private_keys,
    local_node_cert: localNodeCert,
    local_node_private_keys: nodeKeys.private_keys,
  };
}

/**
 * Re-run the v2 hybrid both-must-pass cert-chain verification over a record's
 * hybrid block: the principal + node certs MUST verify against the pinned hybrid
 * master, which proves the persisted certs round-tripped intact. The mint path
 * calls this before persisting; tests assert it directly. Async (ML-DSA verify).
 */
export async function verifyHybridFederationChain(
  hybrid: FederationHybridMasterMaterial,
  nowMs = Date.now(),
): Promise<void> {
  await verifyCertChainV2Hybrid(
    hybrid.local_node_cert,
    hybrid.issuing_principal_cert,
    hybrid.pinned_master,
    nowMs,
  );
}

export function mintFederationTrustRootRecord(params: {
  nodeId: string;
  nodeMode?: NodeMode;
  principalId?: string;
}): FederationTrustRootRecord {
  const master = generateFortressMaster();
  const principal = generateKeypair();
  const node = generateKeypair();
  const masterSecret = randomBytes(32);
  try {
    const fortressId = master.public.fortress_id;
    const principalId = params.principalId ?? "principal-root";
    const principalCert = issuePrincipalCertificate({
      principal_id: principalId,
      principal_pubkey: principal.publicKey,
      role: "root",
      fortress_id: fortressId,
      master_private_key: master.private_key,
    });
    const nodeCert = issueNodeIdentityCertificate({
      node_id: params.nodeId,
      node_pubkey: node.publicKey,
      node_mode: params.nodeMode ?? "local",
      fortress_id: fortressId,
      capabilities: CAP_STANDARD_FORTRESS_NODE,
      parent_chain: {
        fortress_master_pubkey: master.public.public_key,
        principal_id: principalId,
        principal_pubkey: principalCert.principal_pubkey,
      },
      principal_private_key: principal.privateKey,
      master_private_key: master.private_key,
    });
    return {
      fortress_id: fortressId,
      node_id: params.nodeId,
      pinned_master_pubkey: { ...master.public },
      master_secret: Uint8Array.from(masterSecret),
      master_private_key: Uint8Array.from(master.private_key),
      issuing_principal_cert: clonePrincipalCert(principalCert),
      issuing_principal_private_key: Uint8Array.from(principal.privateKey),
      local_node_cert: cloneNodeCert(nodeCert),
      local_node_private_key: Uint8Array.from(node.privateKey),
    };
  } finally {
    master.private_key.fill(0);
    principal.privateKey.fill(0);
    node.privateKey.fill(0);
    masterSecret.fill(0);
  }
}

function encodePersistedRecord(
  record: FederationTrustRootRecord,
): PersistedFederationTrustRootRecord {
  return {
    fortress_id: record.fortress_id,
    node_id: record.node_id,
    pinned_master_pubkey: { ...record.pinned_master_pubkey },
    master_secret: encodeKey(record.master_secret, "master_secret"),
    ...(record.master_private_key
      ? {
          master_private_key: encodeKey(
            record.master_private_key,
            "master_private_key",
          ),
        }
      : {}),
    issuing_principal_cert: clonePrincipalCert(record.issuing_principal_cert),
    issuing_principal_private_key: encodeKey(
      record.issuing_principal_private_key,
      "issuing_principal_private_key",
    ),
    local_node_cert: cloneNodeCert(record.local_node_cert),
    local_node_private_key: encodeKey(
      record.local_node_private_key,
      "local_node_private_key",
    ),
    ...(typeof record.rotation_serial === "number"
      ? { rotation_serial: record.rotation_serial }
      : {}),
    ...(record.rotation_cert
      ? { rotation_cert: { ...record.rotation_cert } }
      : {}),
    ...(record.hybrid ? { hybrid: encodeHybridMaterial(record.hybrid) } : {}),
  };
}

function encodeHybridPrivateKeys(
  keys: HybridPrivateKeyMaterial,
): PersistedHybridPrivateKeyMaterial {
  assertExactLength(
    keys.ed25519.private_key,
    ED25519_PUBLIC_KEY_BYTES,
    "hybrid ed25519 private_key",
  );
  assertExactLength(
    keys.ml_dsa_65.secret_key,
    ML_DSA_65_SECRET_KEY_BYTES,
    "hybrid ml_dsa_65 secret_key",
  );
  return {
    ed25519: {
      key_ref: keys.ed25519.key_ref,
      private_key: toBase64url(keys.ed25519.private_key),
    },
    ml_dsa_65: {
      key_ref: keys.ml_dsa_65.key_ref,
      secret_key: toBase64url(keys.ml_dsa_65.secret_key),
    },
  };
}

function encodeHybridMaterial(
  hybrid: FederationHybridMasterMaterial,
): PersistedFederationHybridMasterMaterial {
  return {
    pinned_master: hybrid.pinned_master,
    master_private_keys: encodeHybridPrivateKeys(hybrid.master_private_keys),
    issuing_principal_cert: hybrid.issuing_principal_cert,
    issuing_principal_private_keys: encodeHybridPrivateKeys(
      hybrid.issuing_principal_private_keys,
    ),
    local_node_cert: hybrid.local_node_cert,
    local_node_private_keys: encodeHybridPrivateKeys(
      hybrid.local_node_private_keys,
    ),
  };
}

function decodePersistedRecord(value: unknown): FederationTrustRootRecord {
  if (!isObject(value)) {
    throw new FederationTrustRootStoreError("record is not an object");
  }
  const record = {
    fortress_id: readString(value, "fortress_id"),
    node_id: readString(value, "node_id"),
    pinned_master_pubkey: readObject(
      value,
      "pinned_master_pubkey",
    ) as unknown as FortressMasterPublicKey,
    master_secret: decodeKey(readString(value, "master_secret"), "master_secret"),
    ...(typeof value.master_private_key === "string"
      ? {
          master_private_key: decodeKey(
            value.master_private_key,
            "master_private_key",
          ),
        }
      : {}),
    issuing_principal_cert: readObject(
      value,
      "issuing_principal_cert",
    ) as unknown as PrincipalCertificate,
    issuing_principal_private_key: decodeKey(
      readString(value, "issuing_principal_private_key"),
      "issuing_principal_private_key",
    ),
    local_node_cert: readObject(
      value,
      "local_node_cert",
    ) as unknown as NodeIdentityCertificate,
    local_node_private_key: decodeKey(
      readString(value, "local_node_private_key"),
      "local_node_private_key",
    ),
    ...(typeof value.rotation_serial === "number"
      ? { rotation_serial: value.rotation_serial }
      : {}),
    ...(isObject(value.rotation_cert)
      ? {
          rotation_cert:
            value.rotation_cert as unknown as FederationRootRotationCertificate,
        }
      : {}),
    ...(isObject(value.hybrid)
      ? { hybrid: decodeHybridMaterial(value.hybrid) }
      : {}),
  };
  validateRecord(record);
  return record;
}

function decodeHybridPrivateKeys(
  value: unknown,
  where: string,
): HybridPrivateKeyMaterial {
  if (!isObject(value) || !isObject(value.ed25519) || !isObject(value.ml_dsa_65)) {
    throw new FederationTrustRootStoreError(`${where} is malformed`);
  }
  const ed = value.ed25519 as Record<string, unknown>;
  const ml = value.ml_dsa_65 as Record<string, unknown>;
  if (typeof ed.key_ref !== "string" || typeof ml.key_ref !== "string") {
    throw new FederationTrustRootStoreError(`${where} is missing a key_ref`);
  }
  return {
    ed25519: {
      key_ref: ed.key_ref,
      private_key: decodeKeyExact(
        readString(ed, "private_key"),
        ED25519_PUBLIC_KEY_BYTES,
        `${where}.ed25519.private_key`,
      ),
    },
    ml_dsa_65: {
      key_ref: ml.key_ref,
      secret_key: decodeKeyExact(
        readString(ml, "secret_key"),
        ML_DSA_65_SECRET_KEY_BYTES,
        `${where}.ml_dsa_65.secret_key`,
      ),
    },
  };
}

function decodeHybridMaterial(
  value: Record<string, unknown>,
): FederationHybridMasterMaterial {
  return {
    pinned_master: readObject(
      value,
      "pinned_master",
    ) as unknown as FortressMasterPublicKeysV2Hybrid,
    master_private_keys: decodeHybridPrivateKeys(
      value.master_private_keys,
      "hybrid.master_private_keys",
    ),
    issuing_principal_cert: readObject(
      value,
      "issuing_principal_cert",
    ) as unknown as PrincipalCertificateV2Hybrid,
    issuing_principal_private_keys: decodeHybridPrivateKeys(
      value.issuing_principal_private_keys,
      "hybrid.issuing_principal_private_keys",
    ),
    local_node_cert: readObject(
      value,
      "local_node_cert",
    ) as unknown as NodeIdentityCertificateV2Hybrid,
    local_node_private_keys: decodeHybridPrivateKeys(
      value.local_node_private_keys,
      "hybrid.local_node_private_keys",
    ),
  };
}

function validateRecord(record: FederationTrustRootRecord): void {
  if (record.fortress_id !== record.pinned_master_pubkey.fortress_id) {
    throw new FederationTrustRootStoreError(
      "record fortress_id does not match pinned master fortress_id",
    );
  }
  if (record.issuing_principal_cert.fortress_id !== record.fortress_id) {
    throw new FederationTrustRootStoreError(
      "issuing principal cert fortress_id mismatch",
    );
  }
  if (record.local_node_cert.fortress_id !== record.fortress_id) {
    throw new FederationTrustRootStoreError(
      "local node cert fortress_id mismatch",
    );
  }
  if (record.local_node_cert.node_id !== record.node_id) {
    throw new FederationTrustRootStoreError(
      "local node cert node_id mismatch",
    );
  }
  assertKeyLength(record.master_secret, "master_secret");
  if (record.master_private_key) {
    assertKeyLength(record.master_private_key, "master_private_key");
    assertPrivateKeyMatchesPublic(
      record.master_private_key,
      record.pinned_master_pubkey.public_key,
      "master_private_key",
    );
  }
  assertKeyLength(
    record.issuing_principal_private_key,
    "issuing_principal_private_key",
  );
  assertPrivateKeyMatchesPublic(
    record.issuing_principal_private_key,
    record.issuing_principal_cert.principal_pubkey,
    "issuing_principal_private_key",
  );
  assertKeyLength(record.local_node_private_key, "local_node_private_key");
  assertPrivateKeyMatchesPublic(
    record.local_node_private_key,
    record.local_node_cert.node_pubkey,
    "local_node_private_key",
  );
  verifyPrincipalCertificate(
    record.issuing_principal_cert,
    record.pinned_master_pubkey,
  );
  verifyCertChain(
    record.local_node_cert,
    record.issuing_principal_cert,
    record.pinned_master_pubkey,
  );
  // Slice 3a: when a rotation cert / serial is present they must cohere with the
  // record's CURRENT master (the cert attests the new master K2 == this record's
  // pinned master, names this record's fortress_id and serial). A record carrying
  // a rotation cert that does not match its own master is rejected: a renewal
  // record must be self-consistent before it can serve laggard joiners (3b).
  if (record.rotation_cert !== undefined || record.rotation_serial !== undefined) {
    if (
      typeof record.rotation_serial !== "number" ||
      !Number.isInteger(record.rotation_serial) ||
      record.rotation_serial < 1
    ) {
      throw new FederationTrustRootStoreError(
        "rotation_serial must be a positive integer when a rotation has occurred",
      );
    }
    if (record.rotation_cert === undefined) {
      throw new FederationTrustRootStoreError(
        "rotation_serial present without a rotation_cert",
      );
    }
    const cert = record.rotation_cert;
    if (cert.kind !== FEDERATION_ROOT_ROTATION_KIND) {
      throw new FederationTrustRootStoreError("rotation_cert kind is not the rotation tag");
    }
    if (cert.fortress_id !== record.fortress_id) {
      throw new FederationTrustRootStoreError("rotation_cert fortress_id mismatch");
    }
    if (cert.new_master.public_key !== record.pinned_master_pubkey.public_key) {
      throw new FederationTrustRootStoreError(
        "rotation_cert new_master does not match the record's current pinned master",
      );
    }
    if (cert.rotation_serial !== record.rotation_serial) {
      throw new FederationTrustRootStoreError(
        "rotation_cert rotation_serial does not match the record rotation_serial",
      );
    }
    if (cert.old_master_pubkey === record.pinned_master_pubkey.public_key) {
      throw new FederationTrustRootStoreError(
        "rotation_cert old_master_pubkey must differ from the new (current) master",
      );
    }
  }
  // PQC Slice 3: structural integrity of the optional hybrid block. The async
  // cryptographic chain-verify (verifyHybridFederationChain) is run at mint and
  // asserted in tests; here we enforce the cheap, sync invariants that keep the
  // private material coherent with the pinned hybrid master and fortress_id. The
  // Ed25519 component derives its public key (must match the pinned hybrid
  // master), the ML-DSA secret derives its public key (must match), and every
  // key_ref must agree between private material and the public certificate it
  // signs for.
  if (record.hybrid !== undefined) {
    validateHybridMaterial(record.fortress_id, record.hybrid);
  }
}

function validateHybridMaterial(
  fortressId: string,
  hybrid: FederationHybridMasterMaterial,
): void {
  if (hybrid.pinned_master.fortress_id !== fortressId) {
    throw new FederationTrustRootStoreError(
      "hybrid pinned_master fortress_id does not match the record fortress_id",
    );
  }
  if (hybrid.issuing_principal_cert.fortress_id !== fortressId) {
    throw new FederationTrustRootStoreError(
      "hybrid issuing principal cert fortress_id mismatch",
    );
  }
  if (hybrid.local_node_cert.fortress_id !== fortressId) {
    throw new FederationTrustRootStoreError(
      "hybrid local node cert fortress_id mismatch",
    );
  }
  // Master private material must derive the pinned hybrid master public keys.
  assertHybridPrivateDerivesPublic(
    hybrid.master_private_keys,
    hybrid.pinned_master.public_keys,
    "hybrid master",
  );
  // Issuing-principal private material must derive the principal cert's keys.
  assertHybridPrivateDerivesPublic(
    hybrid.issuing_principal_private_keys,
    hybrid.issuing_principal_cert.principal_public_keys,
    "hybrid issuing principal",
  );
  // Local-node private material must derive the node cert's keys.
  assertHybridPrivateDerivesPublic(
    hybrid.local_node_private_keys,
    hybrid.local_node_cert.node_public_keys,
    "hybrid local node",
  );
}

function assertHybridPrivateDerivesPublic(
  privateKeys: HybridPrivateKeyMaterial,
  publicKeys: HybridCertificatePublicKeys,
  label: string,
): void {
  if (
    privateKeys.ed25519.key_ref !== publicKeys.ed25519.key_ref ||
    privateKeys.ml_dsa_65.key_ref !== publicKeys.ml_dsa_65.key_ref
  ) {
    throw new FederationTrustRootStoreError(`${label} key_ref mismatch`);
  }
  assertExactLength(
    privateKeys.ed25519.private_key,
    ED25519_PUBLIC_KEY_BYTES,
    `${label} ed25519 private_key`,
  );
  assertExactLength(
    privateKeys.ml_dsa_65.secret_key,
    ML_DSA_65_SECRET_KEY_BYTES,
    `${label} ml_dsa_65 secret_key`,
  );
  // Ed25519 public derivation: getPublicKey(private) must equal the pinned key.
  const derivedEd = ed25519.getPublicKey(privateKeys.ed25519.private_key);
  const expectedEd = fromBase64url(publicKeys.ed25519.public_key);
  try {
    if (!bytesEqual(derivedEd, expectedEd)) {
      throw new FederationTrustRootStoreError(
        `${label} ed25519 private key does not match the pinned public key`,
      );
    }
  } finally {
    derivedEd.fill(0);
    expectedEd.fill(0);
  }
  // ML-DSA-65 public derivation: getPublicKey(secret) must equal the pinned key.
  const derivedMl = ml_dsa65.getPublicKey(privateKeys.ml_dsa_65.secret_key);
  const expectedMl = fromBase64url(publicKeys.ml_dsa_65.public_key);
  try {
    if (!bytesEqual(derivedMl, expectedMl)) {
      throw new FederationTrustRootStoreError(
        `${label} ml_dsa_65 secret key does not match the pinned public key`,
      );
    }
  } finally {
    derivedMl.fill(0);
    expectedMl.fill(0);
  }
}

function assertKeyLength(value: Uint8Array, label: string): void {
  if (value.length !== 32) {
    throw new FederationTrustRootStoreError(`${label} must be 32 bytes`);
  }
}

function assertExactLength(
  value: Uint8Array,
  expected: number,
  label: string,
): void {
  if (value.length !== expected) {
    throw new FederationTrustRootStoreError(
      `${label} must be ${expected} bytes`,
    );
  }
}

function decodeKeyExact(
  value: string,
  expected: number,
  label: string,
): Uint8Array {
  let decoded: Uint8Array;
  try {
    decoded = fromBase64url(value);
  } catch {
    throw new FederationTrustRootStoreError(`${label} is not base64url`);
  }
  assertExactLength(decoded, expected, label);
  return decoded;
}

function assertPrivateKeyMatchesPublic(
  privateKey: Uint8Array,
  publicKey: string,
  label: string,
): void {
  const derived = ed25519.getPublicKey(privateKey);
  const expected = fromBase64url(publicKey);
  try {
    if (!bytesEqual(derived, expected)) {
      throw new FederationTrustRootStoreError(`${label} does not match cert`);
    }
  } finally {
    derived.fill(0);
    expected.fill(0);
  }
}

function encodeKey(value: Uint8Array, label: string): string {
  assertKeyLength(value, label);
  return toBase64url(value);
}

function decodeKey(value: string, label: string): Uint8Array {
  let decoded: Uint8Array;
  try {
    decoded = fromBase64url(value);
  } catch {
    throw new FederationTrustRootStoreError(`${label} is not base64url`);
  }
  assertKeyLength(decoded, label);
  return decoded;
}

function readString(value: Record<string, unknown>, key: string): string {
  const field = value[key];
  if (typeof field !== "string" || field.length === 0) {
    throw new FederationTrustRootStoreError(`${key} is required`);
  }
  return field;
}

function readObject(value: Record<string, unknown>, key: string): Record<string, unknown> {
  const field = value[key];
  if (!isObject(field)) {
    throw new FederationTrustRootStoreError(`${key} is required`);
  }
  return field;
}

function isObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i]! ^ b[i]!;
  return diff === 0;
}

function clonePrincipalCert(cert: PrincipalCertificate): PrincipalCertificate {
  return { ...cert };
}

function cloneNodeCert(cert: NodeIdentityCertificate): NodeIdentityCertificate {
  return {
    ...cert,
    parent_chain: { ...cert.parent_chain },
    ...(cert.delegated_grants
      ? { delegated_grants: [...cert.delegated_grants] }
      : {}),
    ...(cert.attestation_lineage_chain
      ? { attestation_lineage_chain: [...cert.attestation_lineage_chain] }
      : {}),
  };
}

function zeroRecordSecrets(record: FederationTrustRootRecord): void {
  record.master_secret.fill(0);
  record.master_private_key?.fill(0);
  record.issuing_principal_private_key.fill(0);
  record.local_node_private_key.fill(0);
  // PQC Slice 3: zero the hybrid private material too (the ML-DSA-65 4032-byte
  // secret keys + the hybrid Ed25519 private keys) on every persist-failure path.
  if (record.hybrid) zeroHybridMaterialSecrets(record.hybrid);
}

/** Zero every private byte in a hybrid block (Ed25519 private + ML-DSA secret). */
export function zeroHybridMaterialSecrets(
  hybrid: FederationHybridMasterMaterial,
): void {
  for (const keys of [
    hybrid.master_private_keys,
    hybrid.issuing_principal_private_keys,
    hybrid.local_node_private_keys,
  ]) {
    keys.ed25519.private_key.fill(0);
    keys.ml_dsa_65.secret_key.fill(0);
  }
}

async function auditTrustRoot(
  audit: ProvisionOrLoadFederationTrustRootOptions["audit"],
  event: FederationTrustRootAuditEvent,
): Promise<void> {
  if (!audit) return;
  await audit(event);
}

function publicErrorReason(err: unknown): string {
  if (err instanceof FederationTrustRootStoreError) return err.message;
  if (err instanceof SyntaxError) return "malformed JSON";
  return "decrypt_or_parse_failed";
}

function errorName(err: unknown): string {
  return err instanceof Error ? err.name : "Error";
}
