/**
 * Encrypted persistence for the v1 HTTP federation JOINER trust root.
 *
 * A JOINER is the second machine in a federation: it ran a real join ceremony
 * against an issuer fortress and holds ONLY what that ceremony legitimately
 * yields. Unlike the issuer store (`federation-trust-root-store.ts`), a joiner
 * record is a strict NON-ISSUER record: it carries the pinned master PUBLIC
 * key it must trust, the issuing principal cert (public), and this joiner's OWN
 * node cert + node private key. It NEVER carries the fortress master secret,
 * the master private key, or the issuing principal private key. Peer sync is
 * cert-chain-verified (`/v1/federation/sync/peer`), so a joiner derives no
 * issuer transport proofs and needs none of the issuing material.
 *
 * The `_federation/joiner-trust-root-v1` record is always stored as AES-GCM
 * ciphertext under a purpose-derived custody key (HKDF label
 * `federation-joiner-trust-root`, additive and distinct from the issuer
 * store's `federation-trust-root`). Cross-operator isolation and AEAD
 * tamper-evidence come for free from the master-derived purpose key.
 *
 * The pinned master is an OUT-OF-BAND trust anchor: it is supplied by the
 * caller, never inferred from a server response (CLAUDE.md constraint 4). The
 * store refuses to persist or load a joiner cert that does not chain to the
 * pinned master.
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
import { verifyCertChain, verifyPrincipalCertificate } from "./trust-root.js";
import type {
  FortressMasterPublicKey,
  NodeIdentityCertificate,
  PrincipalCertificate,
} from "./types.js";

export const FEDERATION_JOINER_TRUST_ROOT_NAMESPACE = "_federation";
export const FEDERATION_JOINER_TRUST_ROOT_KEY = "joiner-trust-root-v1";
export const FEDERATION_JOINER_TRUST_ROOT_HKDF_INFO =
  "federation-joiner-trust-root";

/**
 * Field names that MUST NEVER appear in a joiner record. Their presence in a
 * decoded blob is a load-time failure, not a silent drop: a joiner that holds
 * any of these is a latent issuer-authority escalation. This is the defense-in
 * -depth check that makes "a joiner accidentally minted with issuer material"
 * a hard refusal.
 */
const FORBIDDEN_ISSUER_FIELDS: readonly string[] = [
  "master_secret",
  "master_private_key",
  "issuing_principal_private_key",
];

/**
 * The NON-ISSUER joiner record. By construction it holds NONE of the issuing
 * material (no `master_secret`, no `master_private_key`, no
 * `issuing_principal_private_key`). Even a build bug that tried to construct an
 * issuer context from this record would find the issuer accessors empty.
 */
export interface FederationJoinerTrustRootRecord {
  /** The JOINED fortress id (from the issued cert + pinned master). */
  fortress_id: string;
  /** This joiner's node id (from the issued cert). */
  node_id: string;
  /** The out-of-band trust anchor this joiner pins (PUBLIC key only). */
  pinned_master_pubkey: FortressMasterPublicKey;
  /** The issuing principal cert received from the join (PUBLIC). */
  issuing_principal_cert: PrincipalCertificate;
  /** The cert issued TO this joiner. */
  local_node_cert: NodeIdentityCertificate;
  /** This joiner's OWN node private key (generated locally at join). */
  local_node_private_key: Uint8Array;
}

interface PersistedFederationJoinerTrustRootRecord {
  fortress_id: string;
  node_id: string;
  pinned_master_pubkey: FortressMasterPublicKey;
  issuing_principal_cert: PrincipalCertificate;
  local_node_cert: NodeIdentityCertificate;
  local_node_private_key: string;
}

export class FederationJoinerTrustRootStoreError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "FederationJoinerTrustRootStoreError";
  }
}

export class FederationJoinerTrustRootStore {
  private readonly storage: StorageBackend;
  private readonly encryptionKey: Uint8Array;

  constructor(storage: StorageBackend, masterKey: Uint8Array) {
    this.storage = storage;
    this.encryptionKey = derivePurposeKey(
      masterKey,
      FEDERATION_JOINER_TRUST_ROOT_HKDF_INFO,
    );
  }

  async load(): Promise<FederationJoinerTrustRootRecord | null> {
    const raw = await this.storage.read(
      FEDERATION_JOINER_TRUST_ROOT_NAMESPACE,
      FEDERATION_JOINER_TRUST_ROOT_KEY,
    );
    if (raw === null) return null;

    let plaintext: Uint8Array | null = null;
    try {
      const encrypted = JSON.parse(bytesToString(raw)) as EncryptedPayload;
      plaintext = decrypt(encrypted, this.encryptionKey);
      const parsed = JSON.parse(bytesToString(plaintext)) as unknown;
      return decodePersistedRecord(parsed);
    } catch (err) {
      throw new FederationJoinerTrustRootStoreError(
        `federation joiner trust root failed to load: ${publicErrorReason(err)}`,
      );
    } finally {
      plaintext?.fill(0);
    }
  }

  async save(record: FederationJoinerTrustRootRecord): Promise<void> {
    validateJoinerRecord(record);
    const serialized = stringToBytes(
      JSON.stringify(encodePersistedRecord(record)),
    );
    try {
      const encrypted = encrypt(serialized, this.encryptionKey);
      await this.storage.write(
        FEDERATION_JOINER_TRUST_ROOT_NAMESPACE,
        FEDERATION_JOINER_TRUST_ROOT_KEY,
        stringToBytes(JSON.stringify(encrypted)),
      );
    } finally {
      serialized.fill(0);
    }
  }
}

export interface FederationJoinerTrustRootAuditEvent {
  operation:
    | "federation_joiner_trust_root_load"
    | "federation_joiner_trust_root_save";
  result: "success" | "failure";
  details: Record<string, unknown>;
}

export interface ProvisionOrLoadFederationJoinerTrustRootOptions {
  storage: StorageBackend;
  masterKey: Uint8Array;
  audit?: (
    event: FederationJoinerTrustRootAuditEvent,
  ) => Promise<void> | void;
}

export interface ProvisionedFederationJoinerTrustRoot {
  record: FederationJoinerTrustRootRecord;
  context: ReturnType<typeof joinerContextFromRecord>;
  source: "persisted";
}

/**
 * Load a persisted joiner trust root, if present, into a NON-ISSUER context.
 *
 * There is NO mint path. A joiner record can only be created from a real join
 * ceremony result (a joiner has no master to mint from). Absence -> null
 * (federation honestly off). A malformed / tampered / cross-operator blob ->
 * fail-closed null (audited), never a crash, never a minted replacement.
 */
export async function loadFederationJoinerTrustRoot(
  opts: ProvisionOrLoadFederationJoinerTrustRootOptions,
): Promise<ProvisionedFederationJoinerTrustRoot | null> {
  const store = new FederationJoinerTrustRootStore(opts.storage, opts.masterKey);
  let record: FederationJoinerTrustRootRecord | null;
  try {
    record = await store.load();
  } catch (err) {
    await auditJoinerTrustRoot(opts.audit, {
      operation: "federation_joiner_trust_root_load",
      result: "failure",
      details: { reason: "load_failed", error_class: errorName(err) },
    });
    return null;
  }

  if (record === null) return null;

  await auditJoinerTrustRoot(opts.audit, {
    operation: "federation_joiner_trust_root_load",
    result: "success",
    details: {
      fortress_id: record.pinned_master_pubkey.fortress_id,
      node_id: record.node_id,
    },
  });
  return {
    record,
    context: joinerContextFromRecord(record),
    source: "persisted",
  };
}

/**
 * Persist a joiner record obtained from a real join ceremony.
 *
 * The `pinnedMasterPubkey` is the out-of-band trust anchor: the issued cert
 * MUST chain to it or this refuses to persist (CLAUDE.md constraint 4: no
 * implicit trust across the boundary; the server's response is never the trust
 * source). `validateJoinerRecord` re-runs the full cert-chain verification
 * before any ciphertext is written.
 */
export async function persistFederationJoinerTrustRoot(opts: {
  storage: StorageBackend;
  masterKey: Uint8Array;
  pinnedMasterPubkey: FortressMasterPublicKey;
  issuingPrincipalCert: PrincipalCertificate;
  localNodeCert: NodeIdentityCertificate;
  localNodePrivateKey: Uint8Array;
  audit?: ProvisionOrLoadFederationJoinerTrustRootOptions["audit"];
}): Promise<ProvisionedFederationJoinerTrustRoot> {
  const record: FederationJoinerTrustRootRecord = {
    fortress_id: opts.pinnedMasterPubkey.fortress_id,
    node_id: opts.localNodeCert.node_id,
    pinned_master_pubkey: { ...opts.pinnedMasterPubkey },
    issuing_principal_cert: clonePrincipalCert(opts.issuingPrincipalCert),
    local_node_cert: cloneNodeCert(opts.localNodeCert),
    local_node_private_key: Uint8Array.from(opts.localNodePrivateKey),
  };
  const store = new FederationJoinerTrustRootStore(opts.storage, opts.masterKey);
  try {
    await store.save(record);
  } catch (err) {
    await auditJoinerTrustRoot(opts.audit, {
      operation: "federation_joiner_trust_root_save",
      result: "failure",
      details: { reason: "persist_failed", error_class: errorName(err) },
    });
    record.local_node_private_key.fill(0);
    throw err;
  }
  await auditJoinerTrustRoot(opts.audit, {
    operation: "federation_joiner_trust_root_save",
    result: "success",
    details: {
      fortress_id: record.pinned_master_pubkey.fortress_id,
      node_id: record.node_id,
    },
  });
  return {
    record,
    context: joinerContextFromRecord(record),
    source: "persisted",
  };
}

/**
 * Build a NON-ISSUER federation context from a joiner record.
 *
 * The returned context exposes NO `getIssuingPrincipalPrivateKey`, NO
 * `getFortressMasterSecret`, NO `getMasterPrivateKey`, and NO `approver`. It is
 * a `nodeMode` context (the node mode of this joiner) that can present its cert
 * on `/sync/peer` but structurally cannot mint bootstrap tokens or issue certs.
 */
export function joinerContextFromRecord(
  record: FederationJoinerTrustRootRecord,
) {
  validateJoinerRecord(record);
  return {
    fortressId: record.pinned_master_pubkey.fortress_id,
    nodeId: record.node_id,
    nodeMode: record.local_node_cert.node_mode,
    pinnedMasterPubkey: { ...record.pinned_master_pubkey },
    issuingPrincipalCert: clonePrincipalCert(record.issuing_principal_cert),
    localNodeCert: cloneNodeCert(record.local_node_cert),
    getLocalNodePrivateKey: () => Uint8Array.from(record.local_node_private_key),
    isNodeRevoked: () => false,
  };
}

function encodePersistedRecord(
  record: FederationJoinerTrustRootRecord,
): PersistedFederationJoinerTrustRootRecord {
  return {
    fortress_id: record.fortress_id,
    node_id: record.node_id,
    pinned_master_pubkey: { ...record.pinned_master_pubkey },
    issuing_principal_cert: clonePrincipalCert(record.issuing_principal_cert),
    local_node_cert: cloneNodeCert(record.local_node_cert),
    local_node_private_key: encodeKey(
      record.local_node_private_key,
      "local_node_private_key",
    ),
  };
}

function decodePersistedRecord(
  value: unknown,
): FederationJoinerTrustRootRecord {
  if (!isObject(value)) {
    throw new FederationJoinerTrustRootStoreError("record is not an object");
  }
  // Defense in depth: a blob carrying ANY issuer field is REFUSED, not
  // silently dropped. A joiner holding issuer material is an escalation.
  for (const forbidden of FORBIDDEN_ISSUER_FIELDS) {
    if (forbidden in value) {
      throw new FederationJoinerTrustRootStoreError(
        `joiner record must not contain issuer material (${forbidden})`,
      );
    }
  }
  const record: FederationJoinerTrustRootRecord = {
    fortress_id: readString(value, "fortress_id"),
    node_id: readString(value, "node_id"),
    pinned_master_pubkey: readObject(
      value,
      "pinned_master_pubkey",
    ) as unknown as FortressMasterPublicKey,
    issuing_principal_cert: readObject(
      value,
      "issuing_principal_cert",
    ) as unknown as PrincipalCertificate,
    local_node_cert: readObject(
      value,
      "local_node_cert",
    ) as unknown as NodeIdentityCertificate,
    local_node_private_key: decodeKey(
      readString(value, "local_node_private_key"),
      "local_node_private_key",
    ),
  };
  validateJoinerRecord(record);
  return record;
}

/**
 * Validate a joiner record. Runs the same cert-chain checks the issuer store
 * runs, MINUS the issuer-key checks (a joiner has none). Plus a HARD assertion
 * that no issuer material is present at the runtime-object level.
 */
export function validateJoinerRecord(
  record: FederationJoinerTrustRootRecord,
): void {
  // Defense in depth: a runtime record object carrying any issuer field is
  // refused. This catches a build bug that constructs a joiner record from an
  // issuer record before it can be persisted or turned into a context.
  const candidate = record as unknown as Record<string, unknown>;
  for (const forbidden of FORBIDDEN_ISSUER_FIELDS) {
    if (forbidden in candidate) {
      throw new FederationJoinerTrustRootStoreError(
        `joiner record must not contain issuer material (${forbidden})`,
      );
    }
  }

  if (record.fortress_id !== record.pinned_master_pubkey.fortress_id) {
    throw new FederationJoinerTrustRootStoreError(
      "record fortress_id does not match pinned master fortress_id",
    );
  }
  if (record.issuing_principal_cert.fortress_id !== record.fortress_id) {
    throw new FederationJoinerTrustRootStoreError(
      "issuing principal cert fortress_id mismatch",
    );
  }
  if (record.local_node_cert.fortress_id !== record.fortress_id) {
    throw new FederationJoinerTrustRootStoreError(
      "local node cert fortress_id mismatch",
    );
  }
  if (record.local_node_cert.node_id !== record.node_id) {
    throw new FederationJoinerTrustRootStoreError(
      "local node cert node_id mismatch",
    );
  }
  assertKeyLength(record.local_node_private_key, "local_node_private_key");
  assertPrivateKeyMatchesPublic(
    record.local_node_private_key,
    record.local_node_cert.node_pubkey,
    "local_node_private_key",
  );
  // The whole point of the pinned master: the chain MUST terminate at it.
  verifyPrincipalCertificate(
    record.issuing_principal_cert,
    record.pinned_master_pubkey,
  );
  verifyCertChain(
    record.local_node_cert,
    record.issuing_principal_cert,
    record.pinned_master_pubkey,
  );
}

function assertKeyLength(value: Uint8Array, label: string): void {
  if (value.length !== 32) {
    throw new FederationJoinerTrustRootStoreError(`${label} must be 32 bytes`);
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
      throw new FederationJoinerTrustRootStoreError(
        `${label} does not match cert`,
      );
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
    throw new FederationJoinerTrustRootStoreError(`${label} is not base64url`);
  }
  assertKeyLength(decoded, label);
  return decoded;
}

function readString(value: Record<string, unknown>, key: string): string {
  const field = value[key];
  if (typeof field !== "string" || field.length === 0) {
    throw new FederationJoinerTrustRootStoreError(`${key} is required`);
  }
  return field;
}

function readObject(
  value: Record<string, unknown>,
  key: string,
): Record<string, unknown> {
  const field = value[key];
  if (!isObject(field)) {
    throw new FederationJoinerTrustRootStoreError(`${key} is required`);
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

async function auditJoinerTrustRoot(
  audit: ProvisionOrLoadFederationJoinerTrustRootOptions["audit"],
  event: FederationJoinerTrustRootAuditEvent,
): Promise<void> {
  if (!audit) return;
  await audit(event);
}

function publicErrorReason(err: unknown): string {
  if (err instanceof FederationJoinerTrustRootStoreError) return err.message;
  if (err instanceof SyntaxError) return "malformed JSON";
  return "decrypt_or_parse_failed";
}

function errorName(err: unknown): string {
  return err instanceof Error ? err.name : "Error";
}
