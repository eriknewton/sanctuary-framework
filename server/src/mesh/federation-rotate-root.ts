/**
 * Federation root-of-trust rotation: issuer-side renewal (rotate-root --renew),
 * Slice 3a.
 *
 * Rotates the FEDERATION FORTRESS SIGNING MASTER: the Ed25519 keypair whose
 * private half signs the issuing principal cert + every node cert and whose
 * public half every joiner pins out of band. This is DISTINCT from the custody
 * master (`core/master-rotation.ts`), the symmetric at-rest key. rotate-root
 * re-keys the federation payload INSIDE the custody-encrypted record; it does
 * NOT touch the custody envelope.
 *
 * SCOPE (Slice 3a, renewal only):
 *   - mint a NEW master keypair K2; KEEP the existing 32-byte symmetric
 *     `master_secret` UNCHANGED (rotating it is compromise-only, a later slice:
 *     it would churn every derived transport/audit key + the out-of-band join
 *     secret);
 *   - KEEP the existing `fortress_id` STABLE (Q1a). Only the keypair rotates, so
 *     the fortress is a durable identity with a rotatable signing credential;
 *   - re-issue the issuing principal cert + the local node cert under K2 (reusing
 *     `rekeyOnMasterRotation`, the at-rest cert-re-issuance cascade);
 *   - sign a ROTATION CERTIFICATE with the OLD master K1 attesting K2 + the
 *     stable fortress_id + a strictly-monotonic `rotation_serial`;
 *   - persist the new record (master=K2, fortress_id + master_secret unchanged,
 *     rotation_serial advanced, rotation_cert retained for laggard joiners).
 *
 * ATOMICITY: staged-then-promote, journaled, resumable. A crash mid-rotation
 * leaves the OLD root intact and bootable; `--resume` completes (or, before the
 * staged record is written, rolls back to) a clean state. The fortress always
 * boots to a valid issuer root (old OR new, never a corrupt hybrid). This mirrors
 * the custody-rotation journal pattern in `core/master-rotation.ts`.
 *
 * MUTUAL EXCLUSION: rotate-root refuses to start while a custody master-rotation
 * journal exists, and boot / custody rotation must refuse while a federation
 * rotation journal exists. Two half-rotations must never overlap. Fail closed.
 *
 * NEVER prints/logs the old or new master private key or master_secret
 * (constraint 6). The rotation cert + the new master PUBLIC key are safe to
 * surface (the new pinned master is printed for out-of-band redistribution).
 *
 * NOT in this slice (3b/3c/3d): the joiner adopt verb, the home re-issue
 * endpoint, the compromise path, root revocation, wire distribution.
 */

import type { StorageBackend } from "../storage/interface.js";
import { encrypt, decrypt, type EncryptedPayload } from "../core/encryption.js";
import { derivePurposeKey } from "../core/key-derivation.js";
import { generateKeypair } from "../core/identity.js";
import { hmacSha256 } from "../core/hashing.js";
import { randomBytes } from "../core/random.js";
import { ROTATION_JOURNAL_KEY as CUSTODY_ROTATION_JOURNAL_KEY } from "../core/master-custody.js";
import {
  FederationSyncStateStore,
  type FederationSyncStateSnapshot,
} from "../v1/federation-sync-state-store.js";
import {
  signFederationRootRevocationPayload,
  signFederationRootRevocationPayloadHybrid,
  type FederationRootRevocationHybridBinding,
  type FederationRootRevocationPayload,
} from "../v1/federation-revocation.js";
import { signFederationRootRotationHybridBinding } from "./trust-root-hybrid.js";
import {
  bytesToString,
  constantTimeEqual,
  fromBase64url,
  stringToBytes,
  toBase64url,
} from "../core/encoding.js";
import { canonicalize } from "./canonical-json.js";
import {
  generateFortressMaster,
  signFederationRootRotationCertificate,
} from "./trust-root.js";
import { rekeyOnMasterRotation } from "./guardian/master-rotation.js";
import {
  FederationTrustRootStore,
  FEDERATION_TRUST_ROOT_NAMESPACE,
  encodeHybridMaterial,
  decodeHybridMaterial,
  mintHybridFederationMaterial,
  zeroHybridMaterialSecrets,
  type FederationHybridMasterMaterial,
  type FederationTrustRootRecord,
} from "./federation-trust-root-store.js";
import type { FederationRootRotationCertificate } from "./types.js";

/**
 * Staged record (the minted-but-not-yet-promoted new root). A crash with this
 * present but the journal absent means the rotation never reached the point of
 * no return; it is cleaned (loudly) on the next attempt.
 */
export const FEDERATION_ROTATE_ROOT_STAGED_KEY = "trust-root-v1-next";
/**
 * The federation rotate-root journal. While it exists the boot path REFUSES (a
 * half-rotated root must never serve) and a custody rotation REFUSES. Resume
 * forward (promote the staged record) to clear it.
 */
export const FEDERATION_ROTATE_ROOT_JOURNAL_KEY = "rotate-root-journal";
/**
 * MAC domain-separation purpose for the rotate-root journal. The journal records
 * serials / fortress_id only (NEVER key material) and is MAC'd under the custody
 * master so a tampered journal is rejected (mirrors the custody journal).
 */
export const FEDERATION_ROTATE_ROOT_JOURNAL_MAC_PURPOSE =
  "federation-rotate-root-journal-mac";

const JOURNAL_MAC_DOMAIN = "sanctuary.federation-rotate-root-journal.v1\n";

/**
 * PQC Slice 3 fail-closed guard (constraint 5: never silently degrade).
 *
 * A hybrid live record MUST be structurally complete before any hybrid rotation
 * mints over it. If a component is missing or a private key length is wrong, we
 * REFUSE rather than fall through to a classical-only rotation that would
 * silently drop the post-quantum half. The cheap structural checks here are a
 * defense-in-depth layer on top of the store's own `validateRecord` (which a
 * loaded record already passed); they make the "never downgrade on a malformed
 * hybrid" invariant explicit at the rotate boundary.
 */
export function assertHybridRecordWellFormedForRotation(
  hybrid: FederationHybridMasterMaterial,
): void {
  const pinned = hybrid.pinned_master?.public_keys;
  if (
    !pinned ||
    !pinned.ed25519?.public_key ||
    !pinned.ml_dsa_65?.public_key ||
    !hybrid.master_private_keys?.ed25519?.private_key ||
    !hybrid.master_private_keys?.ml_dsa_65?.secret_key
  ) {
    throw new HybridRotateDowngradeError(
      "this fortress has a hybrid federation root but its hybrid material is incomplete; refusing to rotate (a rotation must never silently drop the ML-DSA component and downgrade to a classical-only root)",
    );
  }
  if (hybrid.master_private_keys.ed25519.private_key.length !== 32) {
    throw new HybridRotateDowngradeError(
      "hybrid master Ed25519 private key is malformed (not 32 bytes); refusing to rotate fail-closed",
    );
  }
  if (hybrid.master_private_keys.ml_dsa_65.secret_key.length !== 4032) {
    throw new HybridRotateDowngradeError(
      "hybrid master ML-DSA-65 secret key is malformed (not 4032 bytes); refusing to rotate fail-closed",
    );
  }
}

export class FederationRotateRootError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "FederationRotateRootError";
  }
}

export class FederationRotateRootResumeError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "FederationRotateRootResumeError";
  }
}

/**
 * A hybrid record that cannot be rotated without dropping its post-quantum half
 * (malformed/incomplete hybrid material). A subtype of FederationRotateRootError
 * so the CLI maps it to exit 3 with a clear refusal (constraint 5, fail-closed).
 */
class HybridRotateDowngradeError extends FederationRotateRootError {
  constructor(message: string) {
    super(message);
    this.name = "HybridRotateDowngradeError";
  }
}

export type FederationRotationPhase = "staged" | "promoting";

interface FederationRotationJournalData {
  v: 1;
  /** The stable fortress id (unchanged across the rotation). */
  fortress_id: string;
  phase: FederationRotationPhase;
  /** Serial of the master being RETIRED (the live record before this rotation). */
  old_rotation_serial: number;
  /** Serial of the NEW master this rotation installs (old + 1). */
  new_rotation_serial: number;
  /** Base64url public key of the retiring master K1 (PUBLIC, never the secret). */
  old_master_pubkey: string;
  /** Base64url public key of the incoming master K2 (PUBLIC, never the secret). */
  new_master_pubkey: string;
  started_at: string;
  updated_at: string;
  /**
   * Slice 3c-1: a COMPROMISE rotate (vs renewal). When set, the promoted record
   * carries NO rotation_cert and the resume path re-persists the durable root
   * revocation of `old_master_pubkey` at `revocation_serial` instead of
   * requiring a rotation cert. Optional for back-compat: an absent flag is a
   * renewal journal (the only kind 3a wrote).
   */
  compromise?: true;
  /** Slice 3c-1: the revocation serial to (re-)persist on a compromise resume. */
  revocation_serial?: number;
  /**
   * PQC Slice 3: on a HYBRID compromise, the OLD hybrid master's two component
   * public keys (base64url) being revoked. Recorded so a compromise resume can
   * re-add BOTH to the durable revoked-root set without the old hybrid private
   * material (which is gone after promote). Absent on a classical compromise.
   */
  old_hybrid_ed25519_pubkey?: string;
  old_hybrid_ml_dsa_pubkey?: string;
  /**
   * True when the live root being rotated was hybrid. Resume uses this durable bit
   * to refuse a staged record that lacks a valid hybrid block instead of
   * classically promoting over a hybrid root.
   */
  hybrid_expected?: boolean;
}

export interface FederationRotateRootAuditEvent {
  operation: "federation_root_rotated" | "federation_root_compromise_revoked";
  result: "success" | "failure";
  details: Record<string, unknown>;
}

export interface RotateFederationRootOptions {
  storage: StorageBackend;
  /** The unlocked custody master key (encrypts the trust-root payload). */
  masterKey: Uint8Array;
  audit?: (event: FederationRotateRootAuditEvent) => Promise<void> | void;
  /** Test seam: crash injection. Throw inside to simulate a hard kill. */
  failpoint?: (point: string) => void;
  /** Operator-facing progress lines. */
  log?: (line: string) => void;
}

export interface RotateFederationRootResult {
  fortress_id: string;
  /** The new pinned master (PUBLIC) to redistribute out of band. */
  new_pinned_master: FederationTrustRootRecord["pinned_master_pubkey"];
  /** The rotation cert (PUBLIC) signed by the OLD master, for joiner adoption. */
  rotation_cert: FederationRootRotationCertificate;
  rotation_serial: number;
  previous_master_pubkey: string;
  /** Whether this run resumed a crashed rotation rather than starting fresh. */
  resumed: boolean;
  /**
   * PQC Slice 3: the NEW hybrid pinned master (PUBLIC, both components) to
   * redistribute out of band when the rotated fortress is hybrid. Undefined on a
   * classical rotation.
   */
  new_hybrid_pinned_master?: FederationHybridMasterMaterial["pinned_master"];
}

export interface RotateFederationRootCompromisedResult {
  fortress_id: string;
  /** The new pinned master (PUBLIC, K2) to redistribute via OUT-OF-BAND re-pin. */
  new_pinned_master: FederationTrustRootRecord["pinned_master_pubkey"];
  /** The revoked old master (PUBLIC, K1) that is now permanently distrusted. */
  revoked_master_pubkey: string;
  /**
   * The signed, durably-persisted root-revocation event (PUBLIC; signed under
   * K2). On a RESUMED run the original K2 signature is not reconstructable, so
   * `operator_signature` is empty and `signature_note` explains why (the durable
   * projection is the enforcement source of truth and has been re-persisted).
   */
  root_revocation: FederationRootRevocationPayload & { signature_note?: string };
  /** The strictly-monotonic revocation serial this compromise rotate installed. */
  revocation_serial: number;
  /**
   * PQC Slice 3: the NEW hybrid pinned master (PUBLIC, both components) to
   * re-pin out of band when the compromised fortress was hybrid. Undefined on a
   * classical compromise.
   */
  new_hybrid_pinned_master?: FederationHybridMasterMaterial["pinned_master"];
}

// ── Journal helpers (MAC'd under the custody master; no key material) ─────

function journalMac(
  data: FederationRotationJournalData,
  masterKey: Uint8Array,
): string {
  const macKey = derivePurposeKey(masterKey, FEDERATION_ROTATE_ROOT_JOURNAL_MAC_PURPOSE);
  try {
    const mac = hmacSha256(
      macKey,
      stringToBytes(JOURNAL_MAC_DOMAIN + canonicalize(data)),
    );
    return toBase64url(mac);
  } finally {
    macKey.fill(0);
  }
}

async function writeJournal(
  storage: StorageBackend,
  data: FederationRotationJournalData,
  masterKey: Uint8Array,
): Promise<void> {
  const record = { data, mac: journalMac(data, masterKey) };
  await storage.write(
    FEDERATION_TRUST_ROOT_NAMESPACE,
    FEDERATION_ROTATE_ROOT_JOURNAL_KEY,
    stringToBytes(JSON.stringify(record)),
  );
}

async function readJournal(
  storage: StorageBackend,
  masterKey: Uint8Array,
): Promise<FederationRotationJournalData | null> {
  const raw = await storage.read(
    FEDERATION_TRUST_ROOT_NAMESPACE,
    FEDERATION_ROTATE_ROOT_JOURNAL_KEY,
  );
  if (!raw) return null;
  let parsed: { data?: FederationRotationJournalData; mac?: string };
  try {
    parsed = JSON.parse(bytesToString(raw));
  } catch {
    throw new FederationRotateRootResumeError(
      "the rotate-root journal is unreadable (malformed JSON); restore _federation from backup before resuming",
    );
  }
  if (
    !parsed?.data ||
    typeof parsed.mac !== "string" ||
    !constantTimeEqual(
      stringToBytes(parsed.mac),
      stringToBytes(journalMac(parsed.data, masterKey)),
    )
  ) {
    throw new FederationRotateRootResumeError(
      "the rotate-root journal failed authentication (tampered, or the supplied credential does not match); refusing to resume",
    );
  }
  return parsed.data;
}

/**
 * Whether a federation rotate-root journal exists on this fortress. The boot
 * path and the custody-rotation engine both consult this so a half-rotated
 * federation root never serves and the two rotations never overlap.
 */
export async function federationRotateRootInProgress(
  storage: StorageBackend,
): Promise<boolean> {
  return storage.exists(
    FEDERATION_TRUST_ROOT_NAMESPACE,
    FEDERATION_ROTATE_ROOT_JOURNAL_KEY,
  );
}

// ── Staged-record helpers ────────────────────────────────────────────────

/**
 * The staged (minted-but-not-yet-promoted) rotated root, encrypted under the
 * SAME custody purpose key the live store uses, at a DISTINCT storage key. The
 * promoted record is byte-identical to a freshly-written live record because
 * promote() routes through the live store's own save() (which re-validates).
 *
 * The staged store deliberately does NOT validate on save: the live store
 * validates on promote. This keeps the staged blob a pure transient that the
 * point-of-no-return promote step authenticates before it ever serves.
 */
class StagedRecordStore {
  private readonly storage: StorageBackend;
  private readonly encryptionKey: Uint8Array;

  constructor(storage: StorageBackend, masterKey: Uint8Array) {
    this.storage = storage;
    this.encryptionKey = derivePurposeKey(masterKey, "federation-trust-root");
  }

  async load(): Promise<FederationTrustRootRecord | null> {
    const raw = await this.storage.read(
      FEDERATION_TRUST_ROOT_NAMESPACE,
      FEDERATION_ROTATE_ROOT_STAGED_KEY,
    );
    if (raw === null) return null;
    let plaintext: Uint8Array | null = null;
    try {
      const encrypted = JSON.parse(bytesToString(raw)) as EncryptedPayload;
      plaintext = decrypt(encrypted, this.encryptionKey);
      return parseStagedRecord(bytesToString(plaintext));
    } catch (err) {
      throw new FederationRotateRootResumeError(
        `the staged rotated root failed to load: ${err instanceof Error ? err.message : "decrypt/parse failed"}`,
      );
    } finally {
      plaintext?.fill(0);
    }
  }

  async save(record: FederationTrustRootRecord): Promise<void> {
    const serialized = stringToBytes(JSON.stringify(encodeRecordForStaging(record)));
    try {
      const encrypted = encrypt(serialized, this.encryptionKey);
      await this.storage.write(
        FEDERATION_TRUST_ROOT_NAMESPACE,
        FEDERATION_ROTATE_ROOT_STAGED_KEY,
        stringToBytes(JSON.stringify(encrypted)),
      );
    } finally {
      serialized.fill(0);
    }
  }
}

function encodeRecordForStaging(record: FederationTrustRootRecord): unknown {
  // PQC Slice 3: the `hybrid` block IS carried through staging now (a hybrid
  // rotation stages a hybrid record and promotes it as hybrid; dropping the
  // block would silently downgrade to classical-only on promote -- constraint 5).
  // We reuse the live store's exact persisted-hybrid encoder so the staged blob
  // round-trips byte-for-byte through the same validateRecord on promote.
  return {
    fortress_id: record.fortress_id,
    node_id: record.node_id,
    pinned_master_pubkey: { ...record.pinned_master_pubkey },
    master_secret: toBase64url(record.master_secret),
    ...(record.master_private_key
      ? { master_private_key: toBase64url(record.master_private_key) }
      : {}),
    issuing_principal_cert: { ...record.issuing_principal_cert },
    issuing_principal_private_key: toBase64url(record.issuing_principal_private_key),
    local_node_cert: {
      ...record.local_node_cert,
      parent_chain: { ...record.local_node_cert.parent_chain },
    },
    local_node_private_key: toBase64url(record.local_node_private_key),
    ...(typeof record.rotation_serial === "number"
      ? { rotation_serial: record.rotation_serial }
      : {}),
    ...(record.rotation_cert ? { rotation_cert: { ...record.rotation_cert } } : {}),
    ...(record.hybrid ? { hybrid: encodeHybridMaterial(record.hybrid) } : {}),
  };
}

function isStagedObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function parseStagedRecord(json: string): FederationTrustRootRecord {
  // Structural decode only; the promote step's liveStore.save() runs the full
  // cert-chain + rotation-cert + hybrid-coherence validation before the record
  // can serve. PQC Slice 3: the `hybrid` block IS decoded here (via the live
  // store's exact persisted-hybrid decoder) so a staged hybrid rotation promotes
  // as hybrid; if a hybrid block is present it MUST decode (a malformed staged
  // hybrid throws, never silently drops to classical -- constraint 5).
  const value = JSON.parse(json) as Record<string, unknown>;
  if (value.hybrid !== undefined && !isStagedObject(value.hybrid)) {
    throw new FederationRotateRootResumeError(
      "hybrid block in staged record is present but malformed; refusing to resume fail-closed",
    );
  }
  const decode32 = (b64: unknown, label: string): Uint8Array => {
    if (typeof b64 !== "string") {
      throw new FederationRotateRootResumeError(`${label} missing in staged record`);
    }
    const bytes = fromBase64url(b64);
    if (bytes.length !== 32) {
      throw new FederationRotateRootResumeError(`${label} must be 32 bytes`);
    }
    return bytes;
  };
  const record: FederationTrustRootRecord = {
    fortress_id: String(value.fortress_id),
    node_id: String(value.node_id),
    pinned_master_pubkey:
      value.pinned_master_pubkey as FederationTrustRootRecord["pinned_master_pubkey"],
    master_secret: decode32(value.master_secret, "master_secret"),
    ...(typeof value.master_private_key === "string"
      ? { master_private_key: decode32(value.master_private_key, "master_private_key") }
      : {}),
    issuing_principal_cert:
      value.issuing_principal_cert as FederationTrustRootRecord["issuing_principal_cert"],
    issuing_principal_private_key: decode32(
      value.issuing_principal_private_key,
      "issuing_principal_private_key",
    ),
    local_node_cert:
      value.local_node_cert as FederationTrustRootRecord["local_node_cert"],
    local_node_private_key: decode32(
      value.local_node_private_key,
      "local_node_private_key",
    ),
    ...(typeof value.rotation_serial === "number"
      ? { rotation_serial: value.rotation_serial }
      : {}),
    ...(value.rotation_cert
      ? { rotation_cert: value.rotation_cert as FederationRootRotationCertificate }
      : {}),
    ...(isStagedObject(value.hybrid)
      ? { hybrid: decodeHybridMaterial(value.hybrid) }
      : {}),
  };
  return record;
}

function zeroRecordSecrets(record: FederationTrustRootRecord): void {
  record.master_secret.fill(0);
  record.master_private_key?.fill(0);
  record.issuing_principal_private_key.fill(0);
  record.local_node_private_key.fill(0);
  // PQC Slice 3: zero the hybrid private material on every exit path too (the
  // ML-DSA-65 4032-byte secrets + the hybrid Ed25519 private keys; constraint 6).
  if (record.hybrid) zeroHybridMaterialSecrets(record.hybrid);
}

/** Zero the live-record secrets (classical + any hybrid) in one place. */
function zeroLiveSecrets(record: FederationTrustRootRecord): void {
  if (record.master_private_key) record.master_private_key.fill(0);
  record.master_secret.fill(0);
  record.issuing_principal_private_key.fill(0);
  record.local_node_private_key.fill(0);
  if (record.hybrid) zeroHybridMaterialSecrets(record.hybrid);
}

// ── Mint the new (K2) record from the live (K1) record ───────────────────

/**
 * Build the rotated record: new master keypair K2 (stable fortress_id, stable
 * master_secret), principal + local node certs re-issued under K2 via the
 * `rekeyOnMasterRotation` cascade, and the K1-signed rotation cert. All transient
 * private material is zeroed before return EXCEPT what rides in the returned
 * record (the caller owns zeroing that).
 */
async function mintRotatedRecord(
  live: FederationTrustRootRecord,
  newRotationSerial: number,
): Promise<FederationTrustRootRecord> {
  const oldMasterPrivate = live.master_private_key;
  if (!oldMasterPrivate) {
    throw new FederationRotateRootError(
      "this fortress holds a NON-ISSUER (joiner) federation root; only an issuer can rotate-root",
    );
  }
  // PQC Slice 3: a hybrid live root MUST be well-formed before we rotate it; a
  // malformed hybrid block fails closed (never falls through to classical-only).
  if (live.hybrid !== undefined) {
    assertHybridRecordWellFormedForRotation(live.hybrid);
  }
  const k2 = generateFortressMaster();
  // Keep the stable fortress_id; only the keypair rotates.
  const newMasterPublic = {
    public_key: k2.public.public_key,
    fortress_id: live.fortress_id,
    created_at: k2.public.created_at,
  };
  const newPrincipal = generateKeypair();
  // One rotated_at shared by the classical cert and the hybrid binding so a
  // hybrid cert's two halves attest the same instant.
  const rotatedAt = new Date().toISOString();
  let newHybrid: FederationHybridMasterMaterial | undefined;
  try {
    // Re-issue the principal cert + the local node cert under K2. The cascade
    // also derives transport/audit subkeys (off the Ed25519 key it is handed),
    // but we DISCARD those: renewal keeps master_secret stable, and the record
    // never persists derived subkeys (they are derived on demand from
    // master_secret). We pass K2's PRIVATE key as `new_master_secret` purely for
    // the SIGNING role; the discarded HKDF maps are zeroed below.
    const cascade = rekeyOnMasterRotation({
      new_master_secret: k2.private_key,
      new_master_public: newMasterPublic,
      old_node_certificates: [live.local_node_cert],
      old_root_principal: live.issuing_principal_cert,
      new_root_principal_private_key: newPrincipal.privateKey,
      new_root_principal_public_key: newPrincipal.publicKey,
    });
    for (const k of cascade.re_derived_audit_chain_keys.values()) k.fill(0);
    for (const k of cascade.re_derived_transport_keys.values()) k.fill(0);
    const reissuedNodeCert = cascade.re_issued_node_certificates[0];
    if (!reissuedNodeCert) {
      throw new FederationRotateRootError("cascade did not re-issue the local node cert");
    }

    const rotationCert = signFederationRootRotationCertificate({
      fortress_id: live.fortress_id,
      old_master_pubkey: live.pinned_master_pubkey.public_key,
      new_master: newMasterPublic,
      old_master_private_key: oldMasterPrivate,
      rotation_serial: newRotationSerial,
      rotated_at: rotatedAt,
    });

    // PQC Slice 3: a hybrid live root rotates the HYBRID master in lockstep with
    // the classical Ed25519 master. Mint a fresh hybrid master + re-issue hybrid
    // principal + node certs under the SAME stable fortress_id, then sign the
    // hybrid half of the rotation cert with the OLD hybrid master keys (both
    // components, both-must-pass). The result carries BOTH the classical fields
    // (so a current-version classical joiner adopts the Ed25519 chain) AND the
    // new hybrid block (so a hybrid joiner adopts the post-quantum chain).
    if (live.hybrid !== undefined) {
      newHybrid = await mintHybridFederationMaterial({
        fortressId: live.fortress_id,
        nodeId: live.node_id,
        nodeMode: live.local_node_cert.node_mode,
        principalId: live.issuing_principal_cert.principal_id,
      });
      const hybridSigned = await signFederationRootRotationHybridBinding({
        fortress_id: live.fortress_id,
        old_master_pubkey: live.pinned_master_pubkey.public_key,
        new_master: newMasterPublic,
        rotation_serial: newRotationSerial,
        old_hybrid_master: live.hybrid.pinned_master,
        new_hybrid_master: newHybrid.pinned_master,
        old_hybrid_master_private_keys: live.hybrid.master_private_keys,
        rotated_at: rotatedAt,
      });
      rotationCert.hybrid_rotation = hybridSigned.hybrid_rotation;
    }

    return {
      fortress_id: live.fortress_id,
      node_id: live.node_id,
      pinned_master_pubkey: { ...newMasterPublic },
      master_secret: Uint8Array.from(live.master_secret),
      master_private_key: Uint8Array.from(k2.private_key),
      issuing_principal_cert: { ...cascade.new_root_principal_certificate },
      issuing_principal_private_key: Uint8Array.from(newPrincipal.privateKey),
      local_node_cert: {
        ...reissuedNodeCert,
        parent_chain: { ...reissuedNodeCert.parent_chain },
      },
      local_node_private_key: Uint8Array.from(live.local_node_private_key),
      rotation_serial: newRotationSerial,
      rotation_cert: rotationCert,
      ...(newHybrid ? { hybrid: newHybrid } : {}),
    };
  } catch (err) {
    // On any failure after the new hybrid material was minted, zero it (it never
    // reached the returned record).
    if (newHybrid) zeroHybridMaterialSecrets(newHybrid);
    throw err;
  } finally {
    k2.private_key.fill(0);
    newPrincipal.privateKey.fill(0);
  }
}

/**
 * Build the COMPROMISE-rotated record (rotate-root --compromised, Slice 3c-1).
 *
 * Differs from {@link mintRotatedRecord} (renewal) in exactly three ways
 * (design Q2-compromise, Q4-note, Q6):
 *   1. Rotates the symmetric `master_secret` to a FRESH 32-byte value (renewal
 *      keeps it stable). The fresh secret flows through `rekeyOnMasterRotation`
 *      so every transport/audit HKDF subkey re-derives off the new secret; a
 *      thief who captured the old derived keys cannot use them post-rotation.
 *   2. Produces NO K1-signed rotation cert and sets NO `rotation_serial` on the
 *      record. The compromise adoption mechanism is an out-of-band re-pin
 *      (Slice 3c-2), NEVER an old-key-signed artifact (an attacker holding K1
 *      could forge a rotation cert). This is the structural downgrade-resistance
 *      property: the record validates cleanly with neither field
 *      (FederationTrustRootStore.validateRecord only couples them when present).
 *   3. The old root K1 is REVOKED via a net-new root-revocation event signed
 *      under K2 (built by the caller from the returned `newPrincipalForSigning`),
 *      not retired by an old->new attestation.
 *
 * Returns the rotated record PLUS the new principal private key (transient) the
 * caller needs to sign the root-revocation event under K2. The caller owns
 * zeroing `newPrincipalPrivateKey`; this function zeros all OTHER transient
 * material before return.
 */
async function mintCompromiseRotatedRecord(live: FederationTrustRootRecord): Promise<{
  record: FederationTrustRootRecord;
  newPrincipalPrivateKey: Uint8Array;
  /**
   * PQC Slice 3: on a hybrid compromise, the NEW K2 hybrid principal's two
   * private keys, transient, for signing the hybrid revocation bundle. The
   * caller owns zeroing these; undefined on a classical compromise.
   */
  newHybridPrincipalPrivateKeys?: {
    ed25519: { key_ref: string; private_key: Uint8Array };
    ml_dsa_65: { key_ref: string; secret_key: Uint8Array };
  };
}> {
  const oldMasterPrivate = live.master_private_key;
  if (!oldMasterPrivate) {
    throw new FederationRotateRootError(
      "this fortress holds a NON-ISSUER (joiner) federation root; only an issuer can rotate-root",
    );
  }
  // PQC Slice 3: a hybrid live root MUST be well-formed before we rotate it.
  if (live.hybrid !== undefined) {
    assertHybridRecordWellFormedForRotation(live.hybrid);
  }
  const k2 = generateFortressMaster();
  // Keep the stable fortress_id; only the keypair (and, on compromise, the
  // symmetric secret) rotate.
  const newMasterPublic = {
    public_key: k2.public.public_key,
    fortress_id: live.fortress_id,
    created_at: k2.public.created_at,
  };
  const newPrincipal = generateKeypair();
  // Fresh symmetric master_secret (compromise-only). The OLD secret is assumed
  // captured, so every key derived from it must change.
  const newMasterSecret = randomBytes(32);
  let newHybrid: FederationHybridMasterMaterial | undefined;
  let newHybridPrincipalPrivateKeys:
    | {
        ed25519: { key_ref: string; private_key: Uint8Array };
        ml_dsa_65: { key_ref: string; secret_key: Uint8Array };
      }
    | undefined;
  try {
    const cascade = rekeyOnMasterRotation({
      new_master_secret: k2.private_key,
      new_master_public: newMasterPublic,
      old_node_certificates: [live.local_node_cert],
      old_root_principal: live.issuing_principal_cert,
      new_root_principal_private_key: newPrincipal.privateKey,
      new_root_principal_public_key: newPrincipal.publicKey,
    });
    for (const k of cascade.re_derived_audit_chain_keys.values()) k.fill(0);
    for (const k of cascade.re_derived_transport_keys.values()) k.fill(0);
    const reissuedNodeCert = cascade.re_issued_node_certificates[0];
    if (!reissuedNodeCert) {
      throw new FederationRotateRootError("cascade did not re-issue the local node cert");
    }

    // PQC Slice 3: a hybrid compromise rotates the HYBRID master in lockstep with
    // the classical one. Mint a FRESH hybrid master + hybrid principal/node certs
    // under the stable fortress_id (NO rotation cert, downgrade-resistant). The
    // OLD hybrid master is revoked by the caller via a hybrid revocation signed
    // under the NEW hybrid principal.
    if (live.hybrid !== undefined) {
      newHybrid = await mintHybridFederationMaterial({
        fortressId: live.fortress_id,
        nodeId: live.node_id,
        nodeMode: live.local_node_cert.node_mode,
        principalId: live.issuing_principal_cert.principal_id,
      });
      // Copy the new hybrid PRINCIPAL keys out for the caller's revocation
      // signing (the record's own copy is zeroed with the record when done).
      newHybridPrincipalPrivateKeys = {
        ed25519: {
          key_ref: newHybrid.issuing_principal_private_keys.ed25519.key_ref,
          private_key: Uint8Array.from(
            newHybrid.issuing_principal_private_keys.ed25519.private_key,
          ),
        },
        ml_dsa_65: {
          key_ref: newHybrid.issuing_principal_private_keys.ml_dsa_65.key_ref,
          secret_key: Uint8Array.from(
            newHybrid.issuing_principal_private_keys.ml_dsa_65.secret_key,
          ),
        },
      };
    }

    const record: FederationTrustRootRecord = {
      fortress_id: live.fortress_id,
      node_id: live.node_id,
      pinned_master_pubkey: { ...newMasterPublic },
      master_secret: Uint8Array.from(newMasterSecret),
      master_private_key: Uint8Array.from(k2.private_key),
      issuing_principal_cert: { ...cascade.new_root_principal_certificate },
      issuing_principal_private_key: Uint8Array.from(newPrincipal.privateKey),
      local_node_cert: {
        ...reissuedNodeCert,
        parent_chain: { ...reissuedNodeCert.parent_chain },
      },
      local_node_private_key: Uint8Array.from(live.local_node_private_key),
      // NO rotation_serial, NO rotation_cert: downgrade-resistance invariant.
      ...(newHybrid ? { hybrid: newHybrid } : {}),
    };
    return {
      record,
      newPrincipalPrivateKey: Uint8Array.from(newPrincipal.privateKey),
      ...(newHybridPrincipalPrivateKeys ? { newHybridPrincipalPrivateKeys } : {}),
    };
  } catch (err) {
    if (newHybrid) zeroHybridMaterialSecrets(newHybrid);
    if (newHybridPrincipalPrivateKeys) {
      newHybridPrincipalPrivateKeys.ed25519.private_key.fill(0);
      newHybridPrincipalPrivateKeys.ml_dsa_65.secret_key.fill(0);
    }
    throw err;
  } finally {
    k2.private_key.fill(0);
    newPrincipal.privateKey.fill(0);
    newMasterSecret.fill(0);
  }
}

// ── Promote (atomic point of no return) ──────────────────────────────────

/**
 * Promote the staged record to the live key, then delete the staged record.
 * Idempotent: a re-run with the staged record already gone leaves the live
 * record as-is and lets the caller finish any remaining durable safety work
 * before clearing the journal. The live store's save() re-validates the full
 * record (cert chain + rotation-cert coherence) before the write, so a corrupt
 * staged record can never be promoted.
 */
async function promote(
  storage: StorageBackend,
  masterKey: Uint8Array,
  journal: FederationRotationJournalData,
  failpoint: (p: string) => void,
): Promise<void> {
  if (journal.phase !== "promoting") {
    await writeJournal(
      storage,
      { ...journal, phase: "promoting", updated_at: new Date().toISOString() },
      masterKey,
    );
    failpoint("journal-promoting-written");
  }

  const stagedStore = new StagedRecordStore(storage, masterKey);
  const staged = await stagedStore.load();
  const liveStore = new FederationTrustRootStore(storage, masterKey);
  if (staged) {
    try {
      if (journal.hybrid_expected === true && staged.hybrid === undefined) {
        throw new FederationRotateRootResumeError(
          "rotate-root journal expected a hybrid staged root, but the staged record has no valid hybrid block; refusing to promote fail-closed",
        );
      }
      // save() validates (cert chain + rotation-cert coherence) then writes.
      await liveStore.save(staged);
      failpoint("live-record-promoted");
    } finally {
      zeroRecordSecrets(staged);
    }
    await storage.delete(
      FEDERATION_TRUST_ROOT_NAMESPACE,
      FEDERATION_ROTATE_ROOT_STAGED_KEY,
    );
    failpoint("staged-deleted");
  }
  // else: a prior resume already promoted + deleted the staged record; the live
  // record is already K2. The caller still owns any remaining idempotent work
  // (for compromise: durable revocation persistence) before it clears the journal.
}

async function clearRotationJournal(
  storage: StorageBackend,
  failpoint: (p: string) => void,
): Promise<void> {
  await storage.delete(
    FEDERATION_TRUST_ROOT_NAMESPACE,
    FEDERATION_ROTATE_ROOT_JOURNAL_KEY,
  );
  failpoint("journal-deleted");
}

// ── Public entry points ──────────────────────────────────────────────────

/**
 * rotate-root --renew (issuer-side, pure-local). Mints K2, re-issues certs,
 * signs the K1 rotation cert, and atomically promotes the new root.
 *
 * Refuses if: a federation rotation is already in progress (use --resume); a
 * custody rotation is in progress (mutual exclusion); or this fortress is not a
 * provisioned issuer (no issuer record to rotate).
 */
export async function rotateFederationRootRenew(
  opts: RotateFederationRootOptions,
): Promise<RotateFederationRootResult> {
  const { storage, masterKey } = opts;
  const log = opts.log ?? (() => {});
  const failpoint = opts.failpoint ?? (() => {});

  // Mutual exclusion: never start while EITHER rotation is mid-flight.
  if (await storage.read("_meta", CUSTODY_ROTATION_JOURNAL_KEY)) {
    throw new FederationRotateRootError(
      "a custody master rotation is in progress on this fortress; finish it (`sanctuary rotate-master --resume`) before rotating the federation root",
    );
  }
  if (await federationRotateRootInProgress(storage)) {
    throw new FederationRotateRootError(
      "a federation rotate-root is already in progress on this fortress; resume it with `sanctuary federation rotate-root --resume`",
    );
  }

  // Clean an orphaned staged record from a pre-journal crash (the rotation never
  // reached the point of no return; the fortress is fully on the OLD master).
  if (
    await storage.exists(
      FEDERATION_TRUST_ROOT_NAMESPACE,
      FEDERATION_ROTATE_ROOT_STAGED_KEY,
    )
  ) {
    log(
      "Note: removing a stale staged rotated root from an earlier attempt that " +
        "never began promoting. The current root is unchanged; this run mints a fresh one.",
    );
    await storage.delete(
      FEDERATION_TRUST_ROOT_NAMESPACE,
      FEDERATION_ROTATE_ROOT_STAGED_KEY,
    );
  }

  const liveStore = new FederationTrustRootStore(storage, masterKey);
  const live = await liveStore.load();
  if (live === null) {
    throw new FederationRotateRootError(
      "this fortress is not a provisioned federation issuer (no _federation/trust-root-v1 to rotate); run `sanctuary federation provision` first",
    );
  }
  let rotated: FederationTrustRootRecord | undefined;
  try {
    if (!live.master_private_key) {
      throw new FederationRotateRootError(
        "this fortress holds a NON-ISSUER (joiner) federation root; only an issuer can rotate-root",
      );
    }
    // PQC Slice 3: a hybrid root rotates the HYBRID master in lockstep (constraint
    // 5: never silently drop the ML-DSA block). A malformed hybrid block fails
    // closed inside mintRotatedRecord (HybridRotateDowngradeError) BEFORE staging.

    const oldSerial = typeof live.rotation_serial === "number" ? live.rotation_serial : 0;
    const newSerial = oldSerial + 1;

    log(
      live.hybrid !== undefined
        ? "Minting the new HYBRID federation signing master (K2, Ed25519+ML-DSA-65)..."
        : "Minting the new federation signing master (K2)...",
    );
    rotated = await mintRotatedRecord(live, newSerial);
    const journal: FederationRotationJournalData = {
      v: 1,
      fortress_id: live.fortress_id,
      phase: "staged",
      old_rotation_serial: oldSerial,
      new_rotation_serial: newSerial,
      old_master_pubkey: live.pinned_master_pubkey.public_key,
      new_master_pubkey: rotated.pinned_master_pubkey.public_key,
      started_at: new Date().toISOString(),
      updated_at: new Date().toISOString(),
      hybrid_expected: live.hybrid !== undefined,
    };

    // Stage the new record FIRST, then the journal. A crash after the staged
    // record but before the journal still leaves the OLD root live (boot reads
    // the live key); the orphaned staged record is cleaned on the next attempt.
    const stagedStore = new StagedRecordStore(storage, masterKey);
    await stagedStore.save(rotated);
    failpoint("staged-record-written");

    // Point of no return: journal on. From here boot REFUSES until resumed.
    await writeJournal(storage, journal, masterKey);
    failpoint("journal-staged-written");

    log("Promoting the new federation root...");
    await promote(storage, masterKey, journal, failpoint);

    const result: RotateFederationRootResult = {
      fortress_id: rotated.fortress_id,
      new_pinned_master: { ...rotated.pinned_master_pubkey },
      rotation_cert: structuredClone(rotated.rotation_cert!),
      rotation_serial: newSerial,
      previous_master_pubkey: live.pinned_master_pubkey.public_key,
      resumed: false,
      ...(rotated.hybrid
        ? { new_hybrid_pinned_master: structuredClone(rotated.hybrid.pinned_master) }
        : {}),
    };
    await emitAudit(opts.audit, {
      operation: "federation_root_rotated",
      result: "success",
      details: {
        fortress_id: rotated.fortress_id,
        node_id: rotated.node_id,
        rotation_serial: newSerial,
        old_master_pubkey: live.pinned_master_pubkey.public_key,
        new_master_pubkey: rotated.pinned_master_pubkey.public_key,
        hybrid: rotated.hybrid !== undefined,
        resumed: false,
      },
    });
    await clearRotationJournal(storage, failpoint);
    return result;
  } catch (err) {
    await emitAudit(opts.audit, {
      operation: "federation_root_rotated",
      result: "failure",
      details: {
        fortress_id: live.fortress_id,
        reason: "rotation_failed",
        error_class: err instanceof Error ? err.name : "Error",
      },
    });
    throw err;
  } finally {
    if (rotated) zeroRecordSecrets(rotated);
    zeroLiveSecrets(live);
  }
}

/**
 * rotate-root --compromised (issuer-side, pure-local). Slice 3c-1.
 *
 * Mints K2 with a FRESH symmetric master_secret, re-issues the principal + local
 * node cert under K2 (reusing the 3a mint/cascade/journal), atomically promotes
 * the new root, then REVOKES the old root K1 via a net-new root-revocation event
 * SIGNED UNDER K2 and DURABLY persisted into the federation sync-state store
 * (the same blob the daemon rehydrates on boot, so the revocation survives a
 * restart). Produces NO K1-signed rotation cert: the only adoption path is an
 * out-of-band re-pin of K2 (Slice 3c-2). This is the structural separation that
 * keeps a thief who holds K1 from forging an adoption artifact.
 *
 * Mutual exclusion + provisioning + staged-orphan-clean guards mirror renewal.
 * Refuses if: a federation rotation is already in progress (use --resume); a
 * custody rotation is in progress; or this fortress is not a provisioned issuer.
 *
 * NEVER prints/logs a private key or master_secret (constraint 6). The new
 * pinned master (K2) public key + the revocation event are PUBLIC.
 */
export async function rotateFederationRootCompromised(
  opts: RotateFederationRootOptions,
): Promise<RotateFederationRootCompromisedResult> {
  const { storage, masterKey } = opts;
  const log = opts.log ?? (() => {});
  const failpoint = opts.failpoint ?? (() => {});

  // Mutual exclusion: never start while EITHER rotation is mid-flight.
  if (await storage.read("_meta", CUSTODY_ROTATION_JOURNAL_KEY)) {
    throw new FederationRotateRootError(
      "a custody master rotation is in progress on this fortress; finish it (`sanctuary rotate-master --resume`) before rotating the federation root",
    );
  }
  if (await federationRotateRootInProgress(storage)) {
    throw new FederationRotateRootError(
      "a federation rotate-root is already in progress on this fortress; resume it with `sanctuary federation rotate-root --resume`",
    );
  }

  // Clean an orphaned staged record from a pre-journal crash (the rotation never
  // reached the point of no return; the fortress is fully on the OLD master).
  if (
    await storage.exists(
      FEDERATION_TRUST_ROOT_NAMESPACE,
      FEDERATION_ROTATE_ROOT_STAGED_KEY,
    )
  ) {
    log(
      "Note: removing a stale staged rotated root from an earlier attempt that " +
        "never began promoting. The current root is unchanged; this run mints a fresh one.",
    );
    await storage.delete(
      FEDERATION_TRUST_ROOT_NAMESPACE,
      FEDERATION_ROTATE_ROOT_STAGED_KEY,
    );
  }

  const liveStore = new FederationTrustRootStore(storage, masterKey);
  const live = await liveStore.load();
  if (live === null) {
    throw new FederationRotateRootError(
      "this fortress is not a provisioned federation issuer (no _federation/trust-root-v1 to rotate); run `sanctuary federation provision` first",
    );
  }
  let oldRevokedHybrid: FederationRootRevocationHybridBinding | undefined;
  let oldMasterPubkey = "";
  let newRevocationSerial = 1;
  let rotated: FederationTrustRootRecord | undefined;
  let newPrincipalPrivateKey: Uint8Array | undefined;
  let newHybridPrincipalPrivateKeys:
    | {
        ed25519: { key_ref: string; private_key: Uint8Array };
        ml_dsa_65: { key_ref: string; secret_key: Uint8Array };
      }
    | undefined;
  try {
    if (!live.master_private_key) {
      throw new FederationRotateRootError(
        "this fortress holds a NON-ISSUER (joiner) federation root; only an issuer can rotate-root",
      );
    }
    // PQC Slice 3: a hybrid root rotates the HYBRID master in lockstep. A malformed
    // hybrid block fails closed inside mintCompromiseRotatedRecord BEFORE staging
    // (constraint 5). Capture the OLD hybrid component public keys NOW (the live
    // hybrid private material is zeroed once minting reads it).
    if (live.hybrid !== undefined) {
      assertHybridRecordWellFormedForRotation(live.hybrid);
      const oldHybridPub = live.hybrid.pinned_master.public_keys;
      oldRevokedHybrid = {
        ed25519: {
          key_ref: oldHybridPub.ed25519.key_ref,
          public_key: oldHybridPub.ed25519.public_key,
        },
        ml_dsa_65: {
          key_ref: oldHybridPub.ml_dsa_65.key_ref,
          public_key: oldHybridPub.ml_dsa_65.public_key,
        },
      };
    }

    oldMasterPubkey = live.pinned_master_pubkey.public_key;
    // The compromise rotate advances a SEPARATE revocation_serial (parallel to the
    // node eviction_serial), sourced from the durable sync-state floor so a re-run
    // never replays an earlier serial.
    const syncStateStore = new FederationSyncStateStore({ storage, masterKey });
    let priorSnapshot: FederationSyncStateSnapshot;
    try {
      priorSnapshot = await syncStateStore.load();
    } catch (err) {
      // Present-but-corrupt durable state -> fail closed (do NOT rotate onto an
      // unevaluable revocation floor that could replay an old serial).
      throw new FederationRotateRootError(
        `the durable federation sync-state is present but unreadable; restore _federation from backup before a compromise rotate (${err instanceof Error ? err.message : "load failed"})`,
      );
    }
    newRevocationSerial = priorSnapshot.highestRevocationSerial + 1;

    log(
      live.hybrid !== undefined
        ? "Minting the new HYBRID federation signing master (K2, Ed25519+ML-DSA-65) + fresh master_secret..."
        : "Minting the new federation signing master (K2) + fresh master_secret...",
    );
    const minted = await mintCompromiseRotatedRecord(live);
    rotated = minted.record;
    newPrincipalPrivateKey = minted.newPrincipalPrivateKey;
    newHybridPrincipalPrivateKeys = minted.newHybridPrincipalPrivateKeys;
    const journal: FederationRotationJournalData = {
      v: 1,
      fortress_id: live.fortress_id,
      phase: "staged",
      // Compromise does not use the renewal rotation_serial lineage; record the
      // current serial as both old/new so the journal stays well-formed.
      old_rotation_serial:
        typeof live.rotation_serial === "number" ? live.rotation_serial : 0,
      new_rotation_serial:
        typeof live.rotation_serial === "number" ? live.rotation_serial : 0,
      old_master_pubkey: oldMasterPubkey,
      new_master_pubkey: rotated.pinned_master_pubkey.public_key,
      started_at: new Date().toISOString(),
      updated_at: new Date().toISOString(),
      compromise: true,
      revocation_serial: newRevocationSerial,
      hybrid_expected: live.hybrid !== undefined,
      ...(oldRevokedHybrid !== undefined
        ? {
            old_hybrid_ed25519_pubkey: oldRevokedHybrid.ed25519.public_key,
            old_hybrid_ml_dsa_pubkey: oldRevokedHybrid.ml_dsa_65.public_key,
          }
        : {}),
    };

    // Stage the new record FIRST, then the journal (same ordering as renewal).
    const stagedStore = new StagedRecordStore(storage, masterKey);
    await stagedStore.save(rotated);
    failpoint("staged-record-written");

    await writeJournal(storage, journal, masterKey);
    failpoint("journal-staged-written");

    log("Promoting the new federation root (K2)...");
    await promote(storage, masterKey, journal, failpoint);
    failpoint("compromise-root-promoted");

    // Sign the root-revocation event under the NEW principal/K2 (NEVER K1). On a
    // HYBRID compromise, sign a HYBRID bundle (both components) under the new K2
    // hybrid principal AND bind BOTH old hybrid component public keys, so the
    // revocation's authenticity is PQ-protected and any chain pinning EITHER old
    // component is rejectable.
    const effectiveAt = new Date().toISOString();
    let rootRevocation: FederationRootRevocationPayload;
    if (oldRevokedHybrid !== undefined && newHybridPrincipalPrivateKeys !== undefined) {
      rootRevocation = await signFederationRootRevocationPayloadHybrid({
        fortressId: rotated.fortress_id,
        revokedMasterPubkey: oldMasterPubkey,
        revokedHybrid: oldRevokedHybrid,
        effectiveAt,
        revocationSerial: newRevocationSerial,
        operatorPrincipalId: rotated.issuing_principal_cert.principal_id,
        newClassicalPrincipalPrivateKey: newPrincipalPrivateKey,
        newHybridPrincipalPrivateKeys,
      });
    } else {
      rootRevocation = signFederationRootRevocationPayload({
        fortressId: rotated.fortress_id,
        revokedMasterPubkey: oldMasterPubkey,
        effectiveAt,
        revocationSerial: newRevocationSerial,
        operatorPrincipalId: rotated.issuing_principal_cert.principal_id,
        operatorPrincipalPrivateKey: newPrincipalPrivateKey,
      });
    }

    // Durably persist the revoked root into the SAME sync-state blob the daemon
    // rehydrates on boot. Re-load fresh (the promote above did not touch it) and
    // fold the revoked root in, advancing the serial floor. A persist failure
    // AFTER promote leaves the live root on K2 (correct) but with the revocation
    // not yet durable -> THROW so the operator re-runs the persist; the old root
    // is still distrusted in this process and the next persist carries it.
    log("Persisting the durable root revocation of the old master (K1)...");
    const snapshot = await syncStateStore.load();
    snapshot.revokedRootPubkeys.add(oldMasterPubkey);
    // PQC Slice 3: also revoke BOTH old hybrid component public keys, so a chain
    // pinning EITHER the old Ed25519 OR the old ML-DSA hybrid component is denied.
    if (oldRevokedHybrid !== undefined) {
      snapshot.revokedRootPubkeys.add(oldRevokedHybrid.ed25519.public_key);
      snapshot.revokedRootPubkeys.add(oldRevokedHybrid.ml_dsa_65.public_key);
    }
    snapshot.highestRevocationSerial = Math.max(
      snapshot.highestRevocationSerial,
      newRevocationSerial,
    );
    await syncStateStore.persist(snapshot);
    failpoint("root-revocation-persisted");

    await emitAudit(opts.audit, {
      operation: "federation_root_compromise_revoked",
      result: "success",
      details: {
        fortress_id: rotated.fortress_id,
        node_id: rotated.node_id,
        revoked_master_pubkey: oldMasterPubkey,
        new_master_pubkey: rotated.pinned_master_pubkey.public_key,
        revocation_serial: newRevocationSerial,
        master_secret_rotated: true,
        rotation_cert_emitted: false,
        hybrid: oldRevokedHybrid !== undefined,
      },
    });
    await clearRotationJournal(storage, failpoint);

    return {
      fortress_id: rotated.fortress_id,
      new_pinned_master: { ...rotated.pinned_master_pubkey },
      revoked_master_pubkey: oldMasterPubkey,
      root_revocation: structuredClone(rootRevocation),
      revocation_serial: newRevocationSerial,
      ...(rotated.hybrid
        ? { new_hybrid_pinned_master: structuredClone(rotated.hybrid.pinned_master) }
        : {}),
    };
  } catch (err) {
    await emitAudit(opts.audit, {
      operation: "federation_root_compromise_revoked",
      result: "failure",
      details: {
        fortress_id: live.fortress_id,
        reason: "compromise_rotation_failed",
        error_class: err instanceof Error ? err.name : "Error",
      },
    });
    throw err;
  } finally {
    newPrincipalPrivateKey?.fill(0);
    if (newHybridPrincipalPrivateKeys) {
      newHybridPrincipalPrivateKeys.ed25519.private_key.fill(0);
      newHybridPrincipalPrivateKeys.ml_dsa_65.secret_key.fill(0);
    }
    if (rotated) zeroRecordSecrets(rotated);
    zeroLiveSecrets(live);
  }
}

/**
 * Resume a crashed federation rotate-root forward to completion. Requires only
 * the custody master key. Idempotent: re-runs the promote step (which is itself
 * idempotent). If no journal exists, there is nothing to resume.
 */
export async function resumeFederationRootRotation(
  opts: RotateFederationRootOptions,
): Promise<RotateFederationRootResult> {
  const { storage, masterKey } = opts;
  const log = opts.log ?? (() => {});
  const failpoint = opts.failpoint ?? (() => {});

  const journal = await readJournal(storage, masterKey);
  if (journal === null) {
    throw new FederationRotateRootResumeError(
      "no federation rotate-root is in progress on this fortress (no journal)",
    );
  }
  if (journal.compromise === true) {
    // A compromise rotate journal: the promoted record carries NO rotation cert
    // (downgrade-resistance) and needs its durable root revocation re-persisted.
    // The CLI dispatches a compromise journal to resumeFederationRootCompromised
    // (via federationRotateRootJournalIsCompromise); reaching here means a
    // renewal-shaped caller hit a compromise journal -> fail closed.
    throw new FederationRotateRootResumeError(
      "this fortress has a COMPROMISE rotate-root in progress; resume it with `sanctuary federation rotate-root --compromised --resume`",
    );
  }
  // PQC Slice 3: the staged record carries its `hybrid` block through, so a
  // hybrid rotation promotes as hybrid (no classical-over-hybrid downgrade). The
  // live store's validateRecord on promote rejects a malformed hybrid staged
  // record fail-closed (the old root stays live).

  log("Resuming: promoting the staged federation root...");
  await promote(storage, masterKey, journal, failpoint);

  // After promote the live record is K2. Load it (validated) for the result.
  const liveStore = new FederationTrustRootStore(storage, masterKey);
  const live = await liveStore.load();
  try {
    if (live === null || !live.rotation_cert || typeof live.rotation_serial !== "number") {
      throw new FederationRotateRootResumeError(
        "rotate-root resumed but the promoted root is missing its rotation cert; restore _federation from backup",
      );
    }
    const result: RotateFederationRootResult = {
      fortress_id: live.fortress_id,
      new_pinned_master: { ...live.pinned_master_pubkey },
      rotation_cert: structuredClone(live.rotation_cert),
      rotation_serial: live.rotation_serial,
      previous_master_pubkey: journal.old_master_pubkey,
      resumed: true,
      ...(live.hybrid
        ? { new_hybrid_pinned_master: structuredClone(live.hybrid.pinned_master) }
        : {}),
    };
    await emitAudit(opts.audit, {
      operation: "federation_root_rotated",
      result: "success",
      details: {
        fortress_id: live.fortress_id,
        node_id: live.node_id,
        rotation_serial: live.rotation_serial,
        old_master_pubkey: journal.old_master_pubkey,
        new_master_pubkey: live.pinned_master_pubkey.public_key,
        hybrid: live.hybrid !== undefined,
        resumed: true,
      },
    });
    await clearRotationJournal(storage, failpoint);
    return result;
  } finally {
    if (live) zeroLiveSecrets(live);
  }
}

/**
 * Whether the in-progress rotate-root journal is a COMPROMISE rotate (vs a
 * renewal). The CLI peeks this to dispatch `--resume` to the correct resume
 * function. Returns false when there is no journal or it is a renewal journal.
 * Throws only if the journal is present-but-unauthenticated (tampered).
 */
export async function federationRotateRootJournalIsCompromise(
  storage: StorageBackend,
  masterKey: Uint8Array,
): Promise<boolean> {
  const journal = await readJournal(storage, masterKey);
  return journal?.compromise === true;
}

/**
 * Resume a crashed COMPROMISE rotate-root forward to completion. Promotes the
 * staged K2 record (idempotent), then re-persists the durable root revocation of
 * the old master recorded in the journal (idempotent: re-adding an
 * already-revoked root is a no-op; the serial floor only ever rises). Requires
 * only the custody master key.
 */
export async function resumeFederationRootCompromised(
  opts: RotateFederationRootOptions,
): Promise<RotateFederationRootCompromisedResult> {
  const { storage, masterKey } = opts;
  const log = opts.log ?? (() => {});
  const failpoint = opts.failpoint ?? (() => {});

  const journal = await readJournal(storage, masterKey);
  if (journal === null) {
    throw new FederationRotateRootResumeError(
      "no federation rotate-root is in progress on this fortress (no journal)",
    );
  }
  if (journal.compromise !== true) {
    throw new FederationRotateRootResumeError(
      "the in-progress rotate-root is a RENEWAL, not a compromise; resume it with `sanctuary federation rotate-root --renew --resume`",
    );
  }
  // PQC Slice 3: the staged compromise record carries its `hybrid` block through,
  // so a hybrid compromise promotes as hybrid (no downgrade). validateRecord on
  // promote rejects a malformed staged hybrid record fail-closed.

  log("Resuming: promoting the staged federation root (K2)...");
  await promote(storage, masterKey, journal, failpoint);

  // After promote the live record is K2 (no rotation cert, by design).
  const liveStore = new FederationTrustRootStore(storage, masterKey);
  const live = await liveStore.load();
  try {
    if (live === null) {
      throw new FederationRotateRootResumeError(
        "compromise rotate-root resumed but the promoted root failed to load; restore _federation from backup",
      );
    }

    // Re-persist the durable root revocation (idempotent). The journal carries the
    // revoked old master + serial so a crash between promote and the original
    // persist is recoverable without re-minting.
    const revocationSerial =
      typeof journal.revocation_serial === "number" ? journal.revocation_serial : 1;
    const syncStateStore = new FederationSyncStateStore({ storage, masterKey });
    let snapshot: FederationSyncStateSnapshot;
    try {
      snapshot = await syncStateStore.load();
    } catch (err) {
      throw new FederationRotateRootResumeError(
        `the durable federation sync-state is present but unreadable; restore _federation from backup before resuming the compromise rotate (${err instanceof Error ? err.message : "load failed"})`,
      );
    }
    snapshot.revokedRootPubkeys.add(journal.old_master_pubkey);
    // PQC Slice 3: re-add BOTH old hybrid component pubkeys from the journal so a
    // resumed hybrid compromise still denies any chain pinning either old component.
    if (typeof journal.old_hybrid_ed25519_pubkey === "string") {
      snapshot.revokedRootPubkeys.add(journal.old_hybrid_ed25519_pubkey);
    }
    if (typeof journal.old_hybrid_ml_dsa_pubkey === "string") {
      snapshot.revokedRootPubkeys.add(journal.old_hybrid_ml_dsa_pubkey);
    }
    snapshot.highestRevocationSerial = Math.max(
      snapshot.highestRevocationSerial,
      revocationSerial,
    );
    await syncStateStore.persist(snapshot);
    failpoint("root-revocation-persisted");

    await emitAudit(opts.audit, {
      operation: "federation_root_compromise_revoked",
      result: "success",
      details: {
        fortress_id: live.fortress_id,
        node_id: live.node_id,
        revoked_master_pubkey: journal.old_master_pubkey,
        new_master_pubkey: live.pinned_master_pubkey.public_key,
        revocation_serial: revocationSerial,
        resumed: true,
      },
    });
    await clearRotationJournal(storage, failpoint);
    // DEBT: the signed revocation event from the original run is not
    // reconstructable here (the K2 principal key is at rest, not in the journal);
    // the durable projection is the enforcement source of truth and is now
    // re-persisted. We therefore emit an empty `operator_signature` with an
    // honest `signature_note` rather than a fabricated signature. A future slice
    // could re-derive + re-sign on resume if the K2 principal key were unlocked.
    return {
      fortress_id: live.fortress_id,
      new_pinned_master: { ...live.pinned_master_pubkey },
      revoked_master_pubkey: journal.old_master_pubkey,
      root_revocation: {
        event_version: "sanctuary.v1.federation-root-revocation",
        fortress_id: live.fortress_id,
        revoked_master_pubkey: journal.old_master_pubkey,
        effective_at: journal.started_at,
        revocation_serial: revocationSerial,
        operator_principal_id: live.issuing_principal_cert.principal_id,
        operator_signature: "",
        ...(typeof journal.old_hybrid_ed25519_pubkey === "string" &&
        typeof journal.old_hybrid_ml_dsa_pubkey === "string"
          ? {
              revoked_hybrid: {
                ed25519: {
                  key_ref: live.hybrid?.pinned_master.public_keys.ed25519.key_ref ?? "",
                  public_key: journal.old_hybrid_ed25519_pubkey,
                },
                ml_dsa_65: {
                  key_ref: live.hybrid?.pinned_master.public_keys.ml_dsa_65.key_ref ?? "",
                  public_key: journal.old_hybrid_ml_dsa_pubkey,
                },
              },
            }
          : {}),
        signature_note:
          "resumed run: enforcement is the durable revocation projection (already re-persisted); the original K2 signature is not reconstructable here",
      },
      revocation_serial: revocationSerial,
      ...(live.hybrid
        ? { new_hybrid_pinned_master: structuredClone(live.hybrid.pinned_master) }
        : {}),
    };
  } finally {
    if (live) zeroLiveSecrets(live);
  }
}

async function emitAudit(
  audit: RotateFederationRootOptions["audit"],
  event: FederationRotateRootAuditEvent,
): Promise<void> {
  if (!audit) return;
  await audit(event);
}

// Re-export the rotation-cert verifier so consumers (3b joiner adopt, tests)
// import the renewal surface from one module.
export {
  signFederationRootRotationCertificate,
  verifyFederationRootRotationCertificate,
} from "./trust-root.js";
