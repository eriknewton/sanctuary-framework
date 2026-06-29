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

import { createHash } from "node:crypto";
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
import { canonicalJson } from "../v1/operator-signed.js";
import {
  FEDERATION_ROOT_REVOCATION_EVENT_KIND,
  federationOperatorAuthorityOrigin,
  verifyFederationRootRevocationEvent,
  type FederationRootRevocationPayload,
  type FederationRootRevocationRejectionReason,
} from "../v1/federation-revocation.js";
import type {
  FortressMasterPublicKey,
  NodeIdentityCertificate,
  PrincipalCertificate,
} from "./types.js";

export const FEDERATION_JOINER_TRUST_ROOT_NAMESPACE = "_federation";
export const FEDERATION_JOINER_TRUST_ROOT_KEY = "joiner-trust-root-v1";
export const FEDERATION_JOINER_TRUST_ROOT_HKDF_INFO =
  "federation-joiner-trust-root";
export const FEDERATION_JOINER_COMPROMISE_ROOT_ADOPTION_EVENT_VERSION =
  "sanctuary.v1.federation-joiner-compromise-root-adoption.v1";

const FEDERATION_JOINER_COMPROMISE_ROOT_ADOPTION_DOMAIN =
  "sanctuary.v1.federation-joiner-compromise-root-adoption";

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
  /**
   * Grow-only roots this joiner has cryptographically accepted as revoked.
   * Additive 3c-2 state: pre-3c-2 records omit it and decode to an empty set.
   */
  revoked_root_pubkeys?: Set<string>;
  /**
   * Highest accepted compromise root-revocation serial. Additive anti-rollback
   * floor; absent on a never-compromise-adopted joiner (zero implicitly).
   */
  highest_revocation_serial?: number;
}

interface PersistedFederationJoinerTrustRootRecord {
  fortress_id: string;
  node_id: string;
  pinned_master_pubkey: FortressMasterPublicKey;
  issuing_principal_cert: PrincipalCertificate;
  local_node_cert: NodeIdentityCertificate;
  local_node_private_key: string;
  revoked_root_pubkeys?: string[];
  highest_revocation_serial?: number;
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
    | "federation_joiner_trust_root_save"
    | "federation_joiner_compromise_root_adopt";
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
  const revokedRootPubkeys = normalizeRevokedRootPubkeys(
    record.revoked_root_pubkeys,
  );
  return {
    fortressId: record.pinned_master_pubkey.fortress_id,
    nodeId: record.node_id,
    nodeMode: record.local_node_cert.node_mode,
    pinnedMasterPubkey: { ...record.pinned_master_pubkey },
    issuingPrincipalCert: clonePrincipalCert(record.issuing_principal_cert),
    localNodeCert: cloneNodeCert(record.local_node_cert),
    getLocalNodePrivateKey: () => Uint8Array.from(record.local_node_private_key),
    isNodeRevoked: () => false,
    revokedRootPubkeys,
    highestRevocationSerial: normalizeHighestRevocationSerial(
      record.highest_revocation_serial,
    ),
  };
}

export type FederationJoinerCompromiseRootAdoptionRejectionReason =
  | "joiner_trust_root_missing"
  | "joiner_trust_root_unavailable"
  | "fortress_mismatch"
  | "new_root_matches_current_root"
  | "old_principal_attestation_invalid"
  | "revoked_root_not_current_anchor"
  | "revocation_serial_replay"
  | "new_principal_chain_invalid"
  | "reissued_node_cert_invalid"
  | "reissued_node_identity_mismatch"
  | "root_revocation_invalid"
  | "persist_failed";

export type FederationJoinerCompromiseRootAdoptionResult =
  | {
      adopted: true;
      state: "adopted";
      previousPinnedMaster: FortressMasterPublicKey;
      pinnedMaster: FortressMasterPublicKey;
      revocationSerial: number;
      record: FederationJoinerTrustRootRecord;
      context: ReturnType<typeof joinerContextFromRecord>;
    }
  | {
      adopted: false;
      state: "held_old_trust";
      reason: FederationJoinerCompromiseRootAdoptionRejectionReason;
      currentPinnedMaster: FortressMasterPublicKey | null;
      revocationSerial?: number;
      detail?: FederationRootRevocationRejectionReason;
    };

interface FederationJoinerCompromiseRootAdoptionAttestationBody {
  event_version: typeof FEDERATION_JOINER_COMPROMISE_ROOT_ADOPTION_EVENT_VERSION;
  fortress_id: string;
  current_master_pubkey: string;
  current_issuing_principal_id: string;
  current_issuing_principal_pubkey: string;
  new_master_pubkey: string;
  new_issuing_principal_id: string;
  new_issuing_principal_pubkey: string;
  new_issuing_principal_cert_hash: string;
  reissued_node_id: string;
  reissued_node_pubkey: string;
  reissued_node_cert_hash: string;
  revocation_serial: number;
  root_revocation_hash: string;
}

export interface FederationJoinerCompromiseRootAdoptionAttestation
  extends FederationJoinerCompromiseRootAdoptionAttestationBody {
  attesting_principal_signature: string;
}

export function signFederationJoinerCompromiseRootAdoptionAttestation(params: {
  current: FederationJoinerTrustRootRecord;
  newPinnedMasterPubkey: FortressMasterPublicKey;
  newIssuingPrincipalCert: PrincipalCertificate;
  reissuedLocalNodeCert: NodeIdentityCertificate;
  rootRevocation: FederationRootRevocationPayload;
  currentIssuingPrincipalPrivateKey: Uint8Array;
}): FederationJoinerCompromiseRootAdoptionAttestation {
  validateJoinerRecord(params.current);
  const body = buildJoinerCompromiseRootAdoptionAttestationBody({
    current: params.current,
    newPinnedMasterPubkey: params.newPinnedMasterPubkey,
    newIssuingPrincipalCert: params.newIssuingPrincipalCert,
    reissuedLocalNodeCert: params.reissuedLocalNodeCert,
    rootRevocation: params.rootRevocation,
  });
  const signature = ed25519.sign(
    buildJoinerCompromiseRootAdoptionAttestationMessage(body),
    params.currentIssuingPrincipalPrivateKey,
  );
  return {
    ...body,
    attesting_principal_signature: toBase64url(signature),
  };
}

/**
 * Verify and adopt a compromise-rotated issuer root on a JOINER.
 *
 * This is the custody-core half of rotate-root --compromised (3c-2): it replaces
 * the joiner's pinned master ONLY after cryptographically proving all of:
 *   - the joiner's already-pinned K1 issuing principal attests this exact K2
 *     adoption bundle (so a self-minted attacker root is not enough);
 *   - the presented root-revocation is signed by the NEW K2 principal;
 *   - that K2 principal chains to the presented K2 pinned master;
 *   - the revocation names the joiner's CURRENT K1 anchor as revoked;
 *   - the revocation serial strictly advances the local anti-rollback floor;
 *   - this same node has a K2-issued replacement cert for its existing node key.
 *
 * If any check fails, the old record is left untouched and the result surfaces
 * `state:"held_old_trust"` so a live node is not silently evicted or stranded.
 */
export async function adoptFederationJoinerCompromiseRoot(opts: {
  storage: StorageBackend;
  masterKey: Uint8Array;
  newPinnedMasterPubkey: FortressMasterPublicKey;
  newIssuingPrincipalCert: PrincipalCertificate;
  reissuedLocalNodeCert: NodeIdentityCertificate;
  rootRevocation: FederationRootRevocationPayload;
  adoptionAttestation: FederationJoinerCompromiseRootAdoptionAttestation;
  audit?: ProvisionOrLoadFederationJoinerTrustRootOptions["audit"];
}): Promise<FederationJoinerCompromiseRootAdoptionResult> {
  const store = new FederationJoinerTrustRootStore(opts.storage, opts.masterKey);
  let current: FederationJoinerTrustRootRecord | null;
  try {
    current = await store.load();
  } catch (err) {
    await auditJoinerTrustRoot(opts.audit, {
      operation: "federation_joiner_compromise_root_adopt",
      result: "failure",
      details: { reason: "joiner_trust_root_unavailable", error_class: errorName(err) },
    });
    return {
      adopted: false,
      state: "held_old_trust",
      reason: "joiner_trust_root_unavailable",
      currentPinnedMaster: null,
    };
  }
  if (current === null) {
    await auditJoinerTrustRoot(opts.audit, {
      operation: "federation_joiner_compromise_root_adopt",
      result: "failure",
      details: { reason: "joiner_trust_root_missing" },
    });
    return {
      adopted: false,
      state: "held_old_trust",
      reason: "joiner_trust_root_missing",
      currentPinnedMaster: null,
    };
  }

  const verified = await verifyJoinerCompromiseRootAdoption({
    current,
    newPinnedMasterPubkey: opts.newPinnedMasterPubkey,
    newIssuingPrincipalCert: opts.newIssuingPrincipalCert,
    reissuedLocalNodeCert: opts.reissuedLocalNodeCert,
    rootRevocation: opts.rootRevocation,
    adoptionAttestation: opts.adoptionAttestation,
  });
  if (!verified.ok) {
    await auditJoinerTrustRoot(opts.audit, {
      operation: "federation_joiner_compromise_root_adopt",
      result: "failure",
      details: {
        reason: verified.reason,
        ...(verified.detail ? { detail: verified.detail } : {}),
        fortress_id: current.fortress_id,
        node_id: current.node_id,
      },
    });
    return {
      adopted: false,
      state: "held_old_trust",
      reason: verified.reason,
      currentPinnedMaster: { ...current.pinned_master_pubkey },
      ...(verified.revocationSerial !== undefined
        ? { revocationSerial: verified.revocationSerial }
        : {}),
      ...(verified.detail ? { detail: verified.detail } : {}),
    };
  }

  const revokedRootPubkeys = normalizeRevokedRootPubkeys(
    current.revoked_root_pubkeys,
  );
  revokedRootPubkeys.add(current.pinned_master_pubkey.public_key);
  if (opts.rootRevocation.revoked_hybrid !== undefined) {
    revokedRootPubkeys.add(opts.rootRevocation.revoked_hybrid.ed25519.public_key);
    revokedRootPubkeys.add(opts.rootRevocation.revoked_hybrid.ml_dsa_65.public_key);
  }
  const next: FederationJoinerTrustRootRecord = {
    fortress_id: current.fortress_id,
    node_id: current.node_id,
    pinned_master_pubkey: { ...opts.newPinnedMasterPubkey },
    issuing_principal_cert: clonePrincipalCert(opts.newIssuingPrincipalCert),
    local_node_cert: cloneNodeCert(opts.reissuedLocalNodeCert),
    local_node_private_key: Uint8Array.from(current.local_node_private_key),
    revoked_root_pubkeys: revokedRootPubkeys,
    highest_revocation_serial: opts.rootRevocation.revocation_serial,
  };

  try {
    await store.save(next);
  } catch (err) {
    next.local_node_private_key.fill(0);
    await auditJoinerTrustRoot(opts.audit, {
      operation: "federation_joiner_compromise_root_adopt",
      result: "failure",
      details: {
        reason: "persist_failed",
        error_class: errorName(err),
        fortress_id: current.fortress_id,
        node_id: current.node_id,
      },
    });
    return {
      adopted: false,
      state: "held_old_trust",
      reason: "persist_failed",
      currentPinnedMaster: { ...current.pinned_master_pubkey },
      revocationSerial: opts.rootRevocation.revocation_serial,
    };
  }

  await auditJoinerTrustRoot(opts.audit, {
    operation: "federation_joiner_compromise_root_adopt",
    result: "success",
    details: {
      fortress_id: next.fortress_id,
      node_id: next.node_id,
      revoked_master_pubkey: current.pinned_master_pubkey.public_key,
      new_master_pubkey: next.pinned_master_pubkey.public_key,
      revocation_serial: next.highest_revocation_serial,
    },
  });

  return {
    adopted: true,
    state: "adopted",
    previousPinnedMaster: { ...current.pinned_master_pubkey },
    pinnedMaster: { ...next.pinned_master_pubkey },
    revocationSerial: opts.rootRevocation.revocation_serial,
    record: next,
    context: joinerContextFromRecord(next),
  };
}

async function verifyJoinerCompromiseRootAdoption(input: {
  current: FederationJoinerTrustRootRecord;
  newPinnedMasterPubkey: FortressMasterPublicKey;
  newIssuingPrincipalCert: PrincipalCertificate;
  reissuedLocalNodeCert: NodeIdentityCertificate;
  rootRevocation: FederationRootRevocationPayload;
  adoptionAttestation: FederationJoinerCompromiseRootAdoptionAttestation;
}): Promise<
  | { ok: true }
  | {
      ok: false;
      reason: FederationJoinerCompromiseRootAdoptionRejectionReason;
      revocationSerial?: number;
      detail?: FederationRootRevocationRejectionReason;
    }
> {
  const {
    current,
    newPinnedMasterPubkey,
    newIssuingPrincipalCert,
    reissuedLocalNodeCert,
    rootRevocation,
    adoptionAttestation,
  } = input;
  if (
    newPinnedMasterPubkey.fortress_id !== current.fortress_id ||
    rootRevocation.fortress_id !== current.fortress_id ||
    newIssuingPrincipalCert.fortress_id !== current.fortress_id ||
    reissuedLocalNodeCert.fortress_id !== current.fortress_id
  ) {
    return { ok: false, reason: "fortress_mismatch" };
  }
  if (newPinnedMasterPubkey.public_key === current.pinned_master_pubkey.public_key) {
    return { ok: false, reason: "new_root_matches_current_root" };
  }
  if (rootRevocation.revoked_master_pubkey !== current.pinned_master_pubkey.public_key) {
    return {
      ok: false,
      reason: "revoked_root_not_current_anchor",
      revocationSerial: rootRevocation.revocation_serial,
    };
  }
  const serialFloor = normalizeHighestRevocationSerial(
    current.highest_revocation_serial,
  );
  if (rootRevocation.revocation_serial <= serialFloor) {
    return {
      ok: false,
      reason: "revocation_serial_replay",
      revocationSerial: rootRevocation.revocation_serial,
    };
  }

  if (
    !verifyJoinerCompromiseRootAdoptionAttestation({
      current,
      newPinnedMasterPubkey,
      newIssuingPrincipalCert,
      reissuedLocalNodeCert,
      rootRevocation,
      adoptionAttestation,
    })
  ) {
    return {
      ok: false,
      reason: "old_principal_attestation_invalid",
      revocationSerial: rootRevocation.revocation_serial,
    };
  }

  try {
    verifyPrincipalCertificate(newIssuingPrincipalCert, newPinnedMasterPubkey);
  } catch {
    return {
      ok: false,
      reason: "new_principal_chain_invalid",
      revocationSerial: rootRevocation.revocation_serial,
    };
  }

  const event = {
    event_id: `${federationOperatorAuthorityOrigin(current.fortress_id)}:${rootRevocation.revocation_serial}`,
    origin_node_id: federationOperatorAuthorityOrigin(current.fortress_id),
    sequence: rootRevocation.revocation_serial,
    occurred_at: rootRevocation.effective_at,
    kind: FEDERATION_ROOT_REVOCATION_EVENT_KIND,
    payload: rootRevocation as unknown as Record<string, unknown>,
    previous_hash: null,
    event_hash: "adoption-verify-only",
  };
  // DEBT (#802 review follow-up): HYBRID (PQC, ML-DSA) compromise-root adoption is
  // NOT yet supported on this joiner path. We do NOT pass
  // operatorHybridPrincipalPublicKeys, so a revocation carrying a revoked_hybrid /
  // ML-DSA bundle hits the hybrid-bundle gate in verifyFederationRootRevocationEvent
  // (federation-revocation.ts ~line 1034: revoked_hybrid present but no operator
  // hybrid pubkeys => "operator_signature_bundle_invalid") and is REJECTED here as
  // reason "root_revocation_invalid". This is FAIL-CLOSED and intentional: a hybrid
  // fleet cannot yet re-secure a joiner via this path, but it can NEVER adopt an
  // unverified hybrid root. Pinned by the "rejects a HYBRID-root adoption FAIL-CLOSED"
  // test in federation-joiner-trust-root-store.test.ts. Follow-on slice to add real
  // hybrid support: (1) thread the new K2 hybrid principal public keys into this
  // verify call, (2) bind them in the adoption attestation body so the old principal
  // co-signs the hybrid anchor too, (3) add accept + tamper-reject hybrid tests.
  const verified = await verifyFederationRootRevocationEvent({
    event,
    fortressId: current.fortress_id,
    pinnedMaster: newPinnedMasterPubkey,
    operatorPrincipalCert: newIssuingPrincipalCert,
    highestRevocationSerial: serialFloor,
  });
  if (!verified.ok) {
    return {
      ok: false,
      reason: "root_revocation_invalid",
      revocationSerial: rootRevocation.revocation_serial,
      detail: verified.reason,
    };
  }

  if (
    reissuedLocalNodeCert.node_id !== current.node_id ||
    reissuedLocalNodeCert.node_pubkey !== current.local_node_cert.node_pubkey ||
    reissuedLocalNodeCert.node_mode !== current.local_node_cert.node_mode
  ) {
    return {
      ok: false,
      reason: "reissued_node_identity_mismatch",
      revocationSerial: rootRevocation.revocation_serial,
    };
  }
  try {
    verifyCertChain(
      reissuedLocalNodeCert,
      newIssuingPrincipalCert,
      newPinnedMasterPubkey,
    );
  } catch {
    return {
      ok: false,
      reason: "reissued_node_cert_invalid",
      revocationSerial: rootRevocation.revocation_serial,
    };
  }
  return { ok: true };
}

function verifyJoinerCompromiseRootAdoptionAttestation(input: {
  current: FederationJoinerTrustRootRecord;
  newPinnedMasterPubkey: FortressMasterPublicKey;
  newIssuingPrincipalCert: PrincipalCertificate;
  reissuedLocalNodeCert: NodeIdentityCertificate;
  rootRevocation: FederationRootRevocationPayload;
  adoptionAttestation: FederationJoinerCompromiseRootAdoptionAttestation;
}): boolean {
  const expected = buildJoinerCompromiseRootAdoptionAttestationBody(input);
  const { attesting_principal_signature: signature, ...body } =
    input.adoptionAttestation;
  if (canonicalJson(body) !== canonicalJson(expected)) return false;

  let sig: Uint8Array;
  let pubkey: Uint8Array;
  try {
    sig = fromBase64url(signature);
    pubkey = fromBase64url(input.current.issuing_principal_cert.principal_pubkey);
  } catch {
    return false;
  }
  try {
    if (sig.length !== 64) return false;
    return ed25519.verify(
      sig,
      buildJoinerCompromiseRootAdoptionAttestationMessage(expected),
      pubkey,
    );
  } finally {
    sig.fill(0);
    pubkey.fill(0);
  }
}

function buildJoinerCompromiseRootAdoptionAttestationBody(input: {
  current: FederationJoinerTrustRootRecord;
  newPinnedMasterPubkey: FortressMasterPublicKey;
  newIssuingPrincipalCert: PrincipalCertificate;
  reissuedLocalNodeCert: NodeIdentityCertificate;
  rootRevocation: FederationRootRevocationPayload;
}): FederationJoinerCompromiseRootAdoptionAttestationBody {
  return {
    event_version: FEDERATION_JOINER_COMPROMISE_ROOT_ADOPTION_EVENT_VERSION,
    fortress_id: input.current.fortress_id,
    current_master_pubkey: input.current.pinned_master_pubkey.public_key,
    current_issuing_principal_id:
      input.current.issuing_principal_cert.principal_id,
    current_issuing_principal_pubkey:
      input.current.issuing_principal_cert.principal_pubkey,
    new_master_pubkey: input.newPinnedMasterPubkey.public_key,
    new_issuing_principal_id: input.newIssuingPrincipalCert.principal_id,
    new_issuing_principal_pubkey: input.newIssuingPrincipalCert.principal_pubkey,
    new_issuing_principal_cert_hash: hashPublicArtifact(
      input.newIssuingPrincipalCert,
    ),
    reissued_node_id: input.reissuedLocalNodeCert.node_id,
    reissued_node_pubkey: input.reissuedLocalNodeCert.node_pubkey,
    reissued_node_cert_hash: hashPublicArtifact(input.reissuedLocalNodeCert),
    revocation_serial: input.rootRevocation.revocation_serial,
    root_revocation_hash: hashPublicArtifact(input.rootRevocation),
  };
}

function buildJoinerCompromiseRootAdoptionAttestationMessage(
  body: FederationJoinerCompromiseRootAdoptionAttestationBody,
): Uint8Array {
  const domain = stringToBytes(FEDERATION_JOINER_COMPROMISE_ROOT_ADOPTION_DOMAIN);
  const payload = stringToBytes(canonicalJson(body));
  const length = new Uint8Array(4);
  new DataView(length.buffer).setUint32(0, payload.length, false);
  const message = new Uint8Array(domain.length + length.length + payload.length);
  message.set(domain, 0);
  message.set(length, domain.length);
  message.set(payload, domain.length + length.length);
  return message;
}

function hashPublicArtifact(value: unknown): string {
  return createHash("sha256").update(canonicalJson(value)).digest("base64url");
}

function encodePersistedRecord(
  record: FederationJoinerTrustRootRecord,
): PersistedFederationJoinerTrustRootRecord {
  const revokedRootPubkeys = normalizeRevokedRootPubkeys(
    record.revoked_root_pubkeys,
  );
  const highestRevocationSerial = normalizeHighestRevocationSerial(
    record.highest_revocation_serial,
  );
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
    ...(revokedRootPubkeys.size > 0
      ? { revoked_root_pubkeys: [...revokedRootPubkeys].sort() }
      : {}),
    ...(highestRevocationSerial > 0
      ? { highest_revocation_serial: highestRevocationSerial }
      : {}),
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
    revoked_root_pubkeys: decodeRevokedRootPubkeys(value.revoked_root_pubkeys),
    highest_revocation_serial:
      value.highest_revocation_serial === undefined
        ? 0
        : decodeHighestRevocationSerial(value.highest_revocation_serial),
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
  const revokedRootPubkeys = normalizeRevokedRootPubkeys(
    record.revoked_root_pubkeys,
  );
  const highestRevocationSerial = normalizeHighestRevocationSerial(
    record.highest_revocation_serial,
  );
  if (revokedRootPubkeys.has(record.pinned_master_pubkey.public_key)) {
    throw new FederationJoinerTrustRootStoreError(
      "current pinned master is marked revoked",
    );
  }
  if (highestRevocationSerial === 0 && revokedRootPubkeys.size > 0) {
    throw new FederationJoinerTrustRootStoreError(
      "revoked roots require a positive revocation serial floor",
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

function decodeRevokedRootPubkeys(value: unknown): Set<string> {
  if (value === undefined) return new Set();
  if (!Array.isArray(value)) {
    throw new FederationJoinerTrustRootStoreError(
      "revoked_root_pubkeys is not an array",
    );
  }
  const out = new Set<string>();
  for (const pubkey of value) {
    if (typeof pubkey !== "string" || pubkey.length === 0) {
      throw new FederationJoinerTrustRootStoreError(
        "revoked root pubkey is invalid",
      );
    }
    out.add(pubkey);
  }
  return out;
}

function decodeHighestRevocationSerial(value: unknown): number {
  if (
    typeof value !== "number" ||
    !Number.isSafeInteger(value) ||
    value < 0
  ) {
    throw new FederationJoinerTrustRootStoreError(
      "highest_revocation_serial is invalid",
    );
  }
  return value;
}

function normalizeRevokedRootPubkeys(value: unknown): Set<string> {
  if (value === undefined) return new Set();
  if (!(value instanceof Set)) {
    throw new FederationJoinerTrustRootStoreError(
      "revoked_root_pubkeys must be a Set",
    );
  }
  const out = new Set<string>();
  for (const pubkey of value) {
    if (typeof pubkey !== "string" || pubkey.length === 0) {
      throw new FederationJoinerTrustRootStoreError(
        "revoked root pubkey is invalid",
      );
    }
    out.add(pubkey);
  }
  return out;
}

function normalizeHighestRevocationSerial(value: unknown): number {
  if (value === undefined) return 0;
  return decodeHighestRevocationSerial(value);
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
