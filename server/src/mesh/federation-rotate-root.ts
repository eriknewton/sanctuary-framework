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
  type FederationRootRevocationPayload,
} from "../v1/federation-revocation.js";
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
}

export interface RotateFederationRootCompromisedResult {
  fortress_id: string;
  /** The new pinned master (PUBLIC, K2) to redistribute via OUT-OF-BAND re-pin. */
  new_pinned_master: FederationTrustRootRecord["pinned_master_pubkey"];
  /** The revoked old master (PUBLIC, K1) that is now permanently distrusted. */
  revoked_master_pubkey: string;
  /** The signed, durably-persisted root-revocation event (PUBLIC; signed under K2). */
  root_revocation: FederationRootRevocationPayload;
  /** The strictly-monotonic revocation serial this compromise rotate installed. */
  revocation_serial: number;
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
  };
}

function parseStagedRecord(json: string): FederationTrustRootRecord {
  // Structural decode only; the promote step's liveStore.save() runs the full
  // cert-chain + rotation-cert validation before the record can serve.
  const value = JSON.parse(json) as Record<string, unknown>;
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
  };
  return record;
}

function zeroRecordSecrets(record: FederationTrustRootRecord): void {
  record.master_secret.fill(0);
  record.master_private_key?.fill(0);
  record.issuing_principal_private_key.fill(0);
  record.local_node_private_key.fill(0);
}

// ── Mint the new (K2) record from the live (K1) record ───────────────────

/**
 * Build the rotated record: new master keypair K2 (stable fortress_id, stable
 * master_secret), principal + local node certs re-issued under K2 via the
 * `rekeyOnMasterRotation` cascade, and the K1-signed rotation cert. All transient
 * private material is zeroed before return EXCEPT what rides in the returned
 * record (the caller owns zeroing that).
 */
function mintRotatedRecord(
  live: FederationTrustRootRecord,
  newRotationSerial: number,
): FederationTrustRootRecord {
  const oldMasterPrivate = live.master_private_key;
  if (!oldMasterPrivate) {
    throw new FederationRotateRootError(
      "this fortress holds a NON-ISSUER (joiner) federation root; only an issuer can rotate-root",
    );
  }
  const k2 = generateFortressMaster();
  // Keep the stable fortress_id; only the keypair rotates.
  const newMasterPublic = {
    public_key: k2.public.public_key,
    fortress_id: live.fortress_id,
    created_at: k2.public.created_at,
  };
  const newPrincipal = generateKeypair();
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
    });

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
    };
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
function mintCompromiseRotatedRecord(live: FederationTrustRootRecord): {
  record: FederationTrustRootRecord;
  newPrincipalPrivateKey: Uint8Array;
} {
  const oldMasterPrivate = live.master_private_key;
  if (!oldMasterPrivate) {
    throw new FederationRotateRootError(
      "this fortress holds a NON-ISSUER (joiner) federation root; only an issuer can rotate-root",
    );
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
    };
    return {
      record,
      newPrincipalPrivateKey: Uint8Array.from(newPrincipal.privateKey),
    };
  } finally {
    k2.private_key.fill(0);
    newPrincipal.privateKey.fill(0);
    newMasterSecret.fill(0);
  }
}

// ── Promote (atomic point of no return) ──────────────────────────────────

/**
 * Promote the staged record to the live key, then delete the staged record and
 * the journal LAST. Idempotent: a re-run with the staged record already gone
 * just clears the journal. The live store's save() re-validates the full record
 * (cert chain + rotation-cert coherence) before the write, so a corrupt staged
 * record can never be promoted.
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
  // record is already K2. Just clear the journal.

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
  if (!live.master_private_key) {
    throw new FederationRotateRootError(
      "this fortress holds a NON-ISSUER (joiner) federation root; only an issuer can rotate-root",
    );
  }

  const oldSerial = typeof live.rotation_serial === "number" ? live.rotation_serial : 0;
  const newSerial = oldSerial + 1;

  log("Minting the new federation signing master (K2)...");
  const rotated = mintRotatedRecord(live, newSerial);
  try {
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
      rotation_cert: { ...rotated.rotation_cert! },
      rotation_serial: newSerial,
      previous_master_pubkey: live.pinned_master_pubkey.public_key,
      resumed: false,
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
        resumed: false,
      },
    });
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
    zeroRecordSecrets(rotated);
    if (live.master_private_key) live.master_private_key.fill(0);
    live.master_secret.fill(0);
    live.issuing_principal_private_key.fill(0);
    live.local_node_private_key.fill(0);
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
  if (!live.master_private_key) {
    throw new FederationRotateRootError(
      "this fortress holds a NON-ISSUER (joiner) federation root; only an issuer can rotate-root",
    );
  }

  const oldMasterPubkey = live.pinned_master_pubkey.public_key;
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
  const newRevocationSerial = priorSnapshot.highestRevocationSerial + 1;

  log("Minting the new federation signing master (K2) + fresh master_secret...");
  const minted = mintCompromiseRotatedRecord(live);
  const rotated = minted.record;
  const newPrincipalPrivateKey = minted.newPrincipalPrivateKey;
  try {
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

    // Sign the root-revocation event under the NEW principal/K2 (NEVER K1).
    const rootRevocation = signFederationRootRevocationPayload({
      fortressId: rotated.fortress_id,
      revokedMasterPubkey: oldMasterPubkey,
      effectiveAt: new Date().toISOString(),
      revocationSerial: newRevocationSerial,
      operatorPrincipalId: rotated.issuing_principal_cert.principal_id,
      operatorPrincipalPrivateKey: newPrincipalPrivateKey,
    });

    // Durably persist the revoked root into the SAME sync-state blob the daemon
    // rehydrates on boot. Re-load fresh (the promote above did not touch it) and
    // fold the revoked root in, advancing the serial floor. A persist failure
    // AFTER promote leaves the live root on K2 (correct) but with the revocation
    // not yet durable -> THROW so the operator re-runs the persist; the old root
    // is still distrusted in this process and the next persist carries it.
    log("Persisting the durable root revocation of the old master (K1)...");
    const snapshot = await syncStateStore.load();
    snapshot.revokedRootPubkeys.add(oldMasterPubkey);
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
      },
    });

    return {
      fortress_id: rotated.fortress_id,
      new_pinned_master: { ...rotated.pinned_master_pubkey },
      revoked_master_pubkey: oldMasterPubkey,
      root_revocation: { ...rootRevocation },
      revocation_serial: newRevocationSerial,
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
    newPrincipalPrivateKey.fill(0);
    zeroRecordSecrets(rotated);
    if (live.master_private_key) live.master_private_key.fill(0);
    live.master_secret.fill(0);
    live.issuing_principal_private_key.fill(0);
    live.local_node_private_key.fill(0);
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

  log("Resuming: promoting the staged federation root...");
  await promote(storage, masterKey, journal, failpoint);

  // After promote the live record is K2. Load it (validated) for the result.
  const liveStore = new FederationTrustRootStore(storage, masterKey);
  const live = await liveStore.load();
  if (live === null || !live.rotation_cert || typeof live.rotation_serial !== "number") {
    throw new FederationRotateRootResumeError(
      "rotate-root resumed but the promoted root is missing its rotation cert; restore _federation from backup",
    );
  }
  try {
    const result: RotateFederationRootResult = {
      fortress_id: live.fortress_id,
      new_pinned_master: { ...live.pinned_master_pubkey },
      rotation_cert: { ...live.rotation_cert },
      rotation_serial: live.rotation_serial,
      previous_master_pubkey: journal.old_master_pubkey,
      resumed: true,
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
        resumed: true,
      },
    });
    return result;
  } finally {
    if (live.master_private_key) live.master_private_key.fill(0);
    live.master_secret.fill(0);
    live.issuing_principal_private_key.fill(0);
    live.local_node_private_key.fill(0);
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

  log("Resuming: promoting the staged federation root (K2)...");
  await promote(storage, masterKey, journal, failpoint);

  // After promote the live record is K2 (no rotation cert, by design).
  const liveStore = new FederationTrustRootStore(storage, masterKey);
  const live = await liveStore.load();
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
  snapshot.highestRevocationSerial = Math.max(
    snapshot.highestRevocationSerial,
    revocationSerial,
  );
  await syncStateStore.persist(snapshot);
  failpoint("root-revocation-persisted");

  try {
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
    // The signed revocation event from the original run is not reconstructable
    // here (the K2 principal key is at rest, not the journal); the durable
    // projection is the enforcement source of truth and is now re-persisted.
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
      },
      revocation_serial: revocationSerial,
    };
  } finally {
    if (live.master_private_key) live.master_private_key.fill(0);
    live.master_secret.fill(0);
    live.issuing_principal_private_key.fill(0);
    live.local_node_private_key.fill(0);
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
