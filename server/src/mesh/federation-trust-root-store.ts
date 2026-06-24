/**
 * Encrypted persistence for the v1 HTTP federation trust root.
 *
 * The `_federation/trust-root-v1` record is the root of cross-machine trust:
 * fortress master public/private material, the distinct transport HKDF secret,
 * the issuing principal keypair, and this daemon's local node identity. It is
 * always stored as AES-GCM ciphertext under a purpose-derived custody key.
 */

import { ed25519 } from "@noble/curves/ed25519";
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
import { CAP_STANDARD_FORTRESS_NODE, type NodeMode } from "./constants.js";
import {
  generateFortressMaster,
  issueNodeIdentityCertificate,
  issuePrincipalCertificate,
  verifyCertChain,
  verifyPrincipalCertificate,
} from "./trust-root.js";
import { FEDERATION_ROOT_ROTATION_KIND } from "./trust-root.js";
import type {
  FederationRootRotationCertificate,
  FortressMasterPublicKey,
  NodeIdentityCertificate,
  PrincipalCertificate,
} from "./types.js";

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
  try {
    await store.save(minted);
    await auditTrustRoot(opts.audit, {
      operation: "federation_trust_root_mint",
      result: "success",
      details: {
        fortress_id: minted.pinned_master_pubkey.fortress_id,
        node_id: minted.node_id,
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
  };
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
  };
  validateRecord(record);
  return record;
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
}

function assertKeyLength(value: Uint8Array, label: string): void {
  if (value.length !== 32) {
    throw new FederationTrustRootStoreError(`${label} must be 32 bytes`);
  }
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
