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
import { ROTATION_JOURNAL_KEY as CUSTODY_ROTATION_JOURNAL_KEY } from "../core/master-custody.js";
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
}

export interface FederationRotateRootAuditEvent {
  operation: "federation_root_rotated";
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
