/**
 * Encrypted persistence for an operator_cloud JOINED-NODE runtime record.
 *
 * Operator Cloud (Slice 3, boot-wire). A cloud node that completed the Slice-2
 * operator_cloud join holds an `OperatorCloudJoinedNodeRecord`: a strict
 * NON-ISSUER record carrying the pinned master PUBLIC key it must trust, the
 * issuing principal cert (public), this node's own node cert, the node private
 * key already wrapped under the per-node cloud unseal key, and the scope
 * manifest + trust-boundary manifest. It NEVER carries the fortress master
 * secret, the master private key, or the issuing principal private key, exactly
 * like the federation joiner store, and yields a non-issuer operator_cloud
 * federation context on boot.
 *
 * The `_federation/operator-cloud-joined-node-v1` record is always stored as
 * AES-GCM ciphertext under a purpose-derived custody key (HKDF label
 * `operator-cloud-joined-node`, additive and distinct from the issuer store's
 * `federation-trust-root` and the local joiner store's
 * `federation-joiner-trust-root`). Cross-operator isolation and AEAD
 * tamper-evidence come for free from the master-derived purpose key.
 *
 * There is NO mint path here. A joined-node record is created only from a real
 * operator_cloud join ceremony result (Slice 2's issuer-built provision bundle,
 * consumed on the cloud VM); this store load-only on boot. The pinned master is
 * an OUT-OF-BAND trust anchor: supplied by the join, never inferred from a
 * server response (constraint 4). The store refuses to persist or load a node
 * cert that does not chain to the pinned master.
 *
 * Honest trust boundary (Option A). An operator_cloud node runs with SCOPED
 * custody on a cloud node; the provider is IN the trust boundary (it can read
 * this node's RAM while the node runs) until a TEE exists. This is NOT a
 * zero-trust or "provider sees nothing" claim, and the "runs in your cloud,
 * custody-preserved" product claim stays gated on the deferred real-VM drill.
 * The record carries the trust-boundary manifest verbatim so the disclosure
 * survives at rest and travels with the node.
 */

import type { StorageBackend } from "../storage/interface.js";
import { encrypt, decrypt, type EncryptedPayload } from "../core/encryption.js";
import { derivePurposeKey } from "../core/key-derivation.js";
import {
  bytesToString,
  fromBase64url,
  stringToBytes,
} from "../core/encoding.js";
import { verifyCertChain, verifyPrincipalCertificate } from "./trust-root.js";
import {
  OPERATOR_CLOUD_JOINED_NODE_RECORD_VERSION,
  type OperatorCloudJoinedNodeRecord,
} from "./operator-cloud-provision.js";

export const OPERATOR_CLOUD_JOINED_NODE_NAMESPACE = "_federation";
export const OPERATOR_CLOUD_JOINED_NODE_KEY = "operator-cloud-joined-node-v1";
export const OPERATOR_CLOUD_JOINED_NODE_HKDF_INFO =
  "operator-cloud-joined-node";

/**
 * Field names that MUST NEVER appear in a joined-node record. Their presence in
 * a decoded blob is a load-time failure, not a silent drop: a cloud node that
 * holds any of these is a latent issuer-authority escalation. This is the
 * defense-in-depth check that makes "a cloud node accidentally minted with
 * issuer material" a hard refusal.
 */
const FORBIDDEN_ISSUER_FIELDS: readonly string[] = [
  "master_secret",
  "master_private_key",
  "issuing_principal_private_key",
];

export class OperatorCloudJoinedNodeStoreError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "OperatorCloudJoinedNodeStoreError";
  }
}

export class OperatorCloudJoinedNodeStore {
  private readonly storage: StorageBackend;
  private readonly encryptionKey: Uint8Array;

  constructor(storage: StorageBackend, masterKey: Uint8Array) {
    this.storage = storage;
    this.encryptionKey = derivePurposeKey(
      masterKey,
      OPERATOR_CLOUD_JOINED_NODE_HKDF_INFO,
    );
  }

  async load(): Promise<OperatorCloudJoinedNodeRecord | null> {
    const raw = await this.storage.read(
      OPERATOR_CLOUD_JOINED_NODE_NAMESPACE,
      OPERATOR_CLOUD_JOINED_NODE_KEY,
    );
    if (raw === null) return null;

    let plaintext: Uint8Array | null = null;
    try {
      const encrypted = JSON.parse(bytesToString(raw)) as EncryptedPayload;
      plaintext = decrypt(encrypted, this.encryptionKey);
      const parsed = JSON.parse(bytesToString(plaintext)) as unknown;
      return decodePersistedRecord(parsed);
    } catch (err) {
      throw new OperatorCloudJoinedNodeStoreError(
        `operator-cloud joined node failed to load: ${publicErrorReason(err)}`,
      );
    } finally {
      plaintext?.fill(0);
    }
  }

  async save(record: OperatorCloudJoinedNodeRecord): Promise<void> {
    validateJoinedNodeRecord(record);
    const serialized = stringToBytes(JSON.stringify(record));
    try {
      const encrypted = encrypt(serialized, this.encryptionKey);
      await this.storage.write(
        OPERATOR_CLOUD_JOINED_NODE_NAMESPACE,
        OPERATOR_CLOUD_JOINED_NODE_KEY,
        stringToBytes(JSON.stringify(encrypted)),
      );
    } finally {
      serialized.fill(0);
    }
  }
}

export interface OperatorCloudJoinedNodeAuditEvent {
  operation:
    | "operator_cloud_joined_node_load"
    | "operator_cloud_joined_node_save";
  result: "success" | "failure";
  details: Record<string, unknown>;
}

export interface ProvisionOrLoadOperatorCloudJoinedNodeOptions {
  storage: StorageBackend;
  masterKey: Uint8Array;
  audit?: (event: OperatorCloudJoinedNodeAuditEvent) => Promise<void> | void;
}

export interface ProvisionedOperatorCloudJoinedNode {
  record: OperatorCloudJoinedNodeRecord;
  context: ReturnType<typeof operatorCloudContextFromRecord>;
  source: "persisted";
}

/**
 * Load a persisted operator_cloud joined-node record, if present, into a
 * NON-ISSUER operator_cloud context (boot path is LOAD-ONLY).
 *
 * There is NO mint path. A joined-node record can only be created from a real
 * operator_cloud join ceremony result (a cloud node has no master to mint
 * from). Absence -> null (federation honestly off). A malformed / tampered /
 * cross-operator blob -> fail-closed null (audited), never a crash, never a
 * minted replacement.
 */
export async function provisionOrLoadOperatorCloudJoinedNode(
  opts: ProvisionOrLoadOperatorCloudJoinedNodeOptions,
): Promise<ProvisionedOperatorCloudJoinedNode | null> {
  const store = new OperatorCloudJoinedNodeStore(opts.storage, opts.masterKey);
  let record: OperatorCloudJoinedNodeRecord | null;
  try {
    record = await store.load();
  } catch (err) {
    await auditJoinedNode(opts.audit, {
      operation: "operator_cloud_joined_node_load",
      result: "failure",
      details: { reason: "load_failed", error_class: errorName(err) },
    });
    return null;
  }

  if (record === null) return null;

  await auditJoinedNode(opts.audit, {
    operation: "operator_cloud_joined_node_load",
    result: "success",
    details: {
      fortress_id: record.fortress_id,
      node_id: record.node_id,
    },
  });
  return {
    record,
    context: operatorCloudContextFromRecord(record),
    source: "persisted",
  };
}

/**
 * Persist a joined-node record obtained from a real operator_cloud join.
 *
 * The pinned master is the out-of-band trust anchor: the node cert MUST chain to
 * it or this refuses to persist (constraint 4: no implicit trust across the
 * boundary; the server's response is never the trust source).
 * `validateJoinedNodeRecord` re-runs the full cert-chain verification before
 * any ciphertext is written.
 */
export async function persistOperatorCloudJoinedNode(opts: {
  storage: StorageBackend;
  masterKey: Uint8Array;
  record: OperatorCloudJoinedNodeRecord;
  audit?: ProvisionOrLoadOperatorCloudJoinedNodeOptions["audit"];
}): Promise<ProvisionedOperatorCloudJoinedNode> {
  const store = new OperatorCloudJoinedNodeStore(opts.storage, opts.masterKey);
  try {
    await store.save(opts.record);
  } catch (err) {
    await auditJoinedNode(opts.audit, {
      operation: "operator_cloud_joined_node_save",
      result: "failure",
      details: { reason: "persist_failed", error_class: errorName(err) },
    });
    throw err;
  }
  await auditJoinedNode(opts.audit, {
    operation: "operator_cloud_joined_node_save",
    result: "success",
    details: {
      fortress_id: opts.record.fortress_id,
      node_id: opts.record.node_id,
    },
  });
  return {
    record: opts.record,
    context: operatorCloudContextFromRecord(opts.record),
    source: "persisted",
  };
}

/**
 * Build a NON-ISSUER operator_cloud federation context from a joined-node
 * record.
 *
 * The returned context exposes NO `getIssuingPrincipalPrivateKey`, NO
 * `getFortressMasterSecret`, NO `getMasterPrivateKey`, and NO `approver`. It is
 * pinned to `nodeMode: "operator_cloud"`, which is STRUCTURALLY non-issuer: it
 * can present its cert on `/sync/peer` but cannot mint bootstrap tokens or issue
 * certs.
 *
 * The node private key is held at rest WRAPPED under the per-node cloud unseal
 * key (delivered in the Slice-2 scoped secret, not held by this store), so this
 * context does not expose a raw node private key. Unwrapping it for `/sync/peer`
 * signing is the cloud node's runtime concern, gated on the unseal key.
 */
export function operatorCloudContextFromRecord(
  record: OperatorCloudJoinedNodeRecord,
) {
  validateJoinedNodeRecord(record);
  return {
    fortressId: record.fortress_id,
    nodeId: record.node_id,
    nodeMode: "operator_cloud" as const,
    pinnedMasterPubkey: { ...record.pinned_master_pubkey },
    issuingPrincipalCert: clonePrincipalCert(record.issuing_principal_cert),
    localNodeCert: cloneNodeCert(record.local_node_cert),
    isNodeRevoked: () => false,
  };
}

function decodePersistedRecord(value: unknown): OperatorCloudJoinedNodeRecord {
  if (!isObject(value)) {
    throw new OperatorCloudJoinedNodeStoreError("record is not an object");
  }
  // Defense in depth: a blob carrying ANY issuer field is REFUSED, not silently
  // dropped. A cloud node holding issuer material is an escalation.
  for (const forbidden of FORBIDDEN_ISSUER_FIELDS) {
    if (forbidden in value) {
      throw new OperatorCloudJoinedNodeStoreError(
        `operator-cloud joined node record must not contain issuer material (${forbidden})`,
      );
    }
  }
  if (value.record_version !== OPERATOR_CLOUD_JOINED_NODE_RECORD_VERSION) {
    throw new OperatorCloudJoinedNodeStoreError(
      "operator-cloud joined node record_version mismatch",
    );
  }
  if (value.node_mode !== "operator_cloud") {
    throw new OperatorCloudJoinedNodeStoreError(
      "operator-cloud joined node record node_mode must be operator_cloud",
    );
  }
  const record: OperatorCloudJoinedNodeRecord = {
    record_version: OPERATOR_CLOUD_JOINED_NODE_RECORD_VERSION,
    fortress_id: readString(value, "fortress_id"),
    node_id: readString(value, "node_id"),
    node_mode: "operator_cloud",
    pinned_master_pubkey: readObject(
      value,
      "pinned_master_pubkey",
    ) as unknown as OperatorCloudJoinedNodeRecord["pinned_master_pubkey"],
    issuing_principal_cert: readObject(
      value,
      "issuing_principal_cert",
    ) as unknown as OperatorCloudJoinedNodeRecord["issuing_principal_cert"],
    local_node_cert: readObject(
      value,
      "local_node_cert",
    ) as unknown as OperatorCloudJoinedNodeRecord["local_node_cert"],
    wrapped_local_node_private_key: readObject(
      value,
      "wrapped_local_node_private_key",
    ) as unknown as EncryptedPayload,
    scope_manifest: readObject(
      value,
      "scope_manifest",
    ) as unknown as OperatorCloudJoinedNodeRecord["scope_manifest"],
    trust_boundary: readObject(
      value,
      "trust_boundary",
    ) as unknown as OperatorCloudJoinedNodeRecord["trust_boundary"],
    disclosure_acknowledged_at: readString(value, "disclosure_acknowledged_at"),
  };
  validateJoinedNodeRecord(record);
  return record;
}

/**
 * Validate a joined-node record. Runs the same cert-chain checks the issuer
 * store runs, MINUS the issuer-key checks (a cloud node has none). Plus a HARD
 * assertion that no issuer material is present at the runtime-object level and
 * that the node cert is itself an operator_cloud cert.
 */
export function validateJoinedNodeRecord(
  record: OperatorCloudJoinedNodeRecord,
): void {
  // Defense in depth: a runtime record object carrying any issuer field is
  // refused. This catches a build bug that constructs a joined-node record from
  // an issuer record before it can be persisted or turned into a context.
  const candidate = record as unknown as Record<string, unknown>;
  for (const forbidden of FORBIDDEN_ISSUER_FIELDS) {
    if (forbidden in candidate) {
      throw new OperatorCloudJoinedNodeStoreError(
        `operator-cloud joined node record must not contain issuer material (${forbidden})`,
      );
    }
  }

  if (record.node_mode !== "operator_cloud") {
    throw new OperatorCloudJoinedNodeStoreError(
      "operator-cloud joined node record node_mode must be operator_cloud",
    );
  }
  if (record.fortress_id !== record.pinned_master_pubkey.fortress_id) {
    throw new OperatorCloudJoinedNodeStoreError(
      "record fortress_id does not match pinned master fortress_id",
    );
  }
  if (record.issuing_principal_cert.fortress_id !== record.fortress_id) {
    throw new OperatorCloudJoinedNodeStoreError(
      "issuing principal cert fortress_id mismatch",
    );
  }
  if (record.local_node_cert.fortress_id !== record.fortress_id) {
    throw new OperatorCloudJoinedNodeStoreError(
      "local node cert fortress_id mismatch",
    );
  }
  if (record.local_node_cert.node_id !== record.node_id) {
    throw new OperatorCloudJoinedNodeStoreError(
      "local node cert node_id mismatch",
    );
  }
  // The node cert MUST itself be an operator_cloud cert: a non-issuer
  // operator_cloud context can only be built from an operator_cloud node cert.
  if (record.local_node_cert.node_mode !== "operator_cloud") {
    throw new OperatorCloudJoinedNodeStoreError(
      "local node cert node_mode must be operator_cloud",
    );
  }
  assertWrappedKey(record.wrapped_local_node_private_key);
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

function assertWrappedKey(value: EncryptedPayload): void {
  if (
    !isObject(value) ||
    value.v !== 1 ||
    value.alg !== "aes-256-gcm" ||
    typeof value.iv !== "string" ||
    typeof value.ct !== "string"
  ) {
    throw new OperatorCloudJoinedNodeStoreError(
      "wrapped_local_node_private_key is not a well-formed AES-GCM payload",
    );
  }
  // The node private key is held WRAPPED (ciphertext under the per-node unseal
  // key), so the raw key never appears in this record. A well-formed AES-GCM
  // ciphertext of a 32-byte key carries a 16-byte tag plus the body; a ct
  // shorter than the GCM tag itself is a malformed / cleartext-smuggled wrap.
  let bytes: Uint8Array;
  try {
    bytes = fromBase64url(value.ct);
  } catch {
    throw new OperatorCloudJoinedNodeStoreError(
      "wrapped_local_node_private_key ciphertext is not base64url",
    );
  }
  if (bytes.length < 16) {
    throw new OperatorCloudJoinedNodeStoreError(
      "wrapped_local_node_private_key ciphertext is implausibly short",
    );
  }
}

function readString(value: Record<string, unknown>, key: string): string {
  const field = value[key];
  if (typeof field !== "string" || field.length === 0) {
    throw new OperatorCloudJoinedNodeStoreError(`${key} is required`);
  }
  return field;
}

function readObject(
  value: Record<string, unknown>,
  key: string,
): Record<string, unknown> {
  const field = value[key];
  if (!isObject(field)) {
    throw new OperatorCloudJoinedNodeStoreError(`${key} is required`);
  }
  return field;
}

function isObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function clonePrincipalCert(
  cert: OperatorCloudJoinedNodeRecord["issuing_principal_cert"],
): OperatorCloudJoinedNodeRecord["issuing_principal_cert"] {
  return { ...cert };
}

function cloneNodeCert(
  cert: OperatorCloudJoinedNodeRecord["local_node_cert"],
): OperatorCloudJoinedNodeRecord["local_node_cert"] {
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

async function auditJoinedNode(
  audit: ProvisionOrLoadOperatorCloudJoinedNodeOptions["audit"],
  event: OperatorCloudJoinedNodeAuditEvent,
): Promise<void> {
  if (!audit) return;
  await audit(event);
}

function publicErrorReason(err: unknown): string {
  if (err instanceof OperatorCloudJoinedNodeStoreError) return err.message;
  if (err instanceof SyntaxError) return "malformed JSON";
  return "decrypt_or_parse_failed";
}

function errorName(err: unknown): string {
  return err instanceof Error ? err.name : "Error";
}
