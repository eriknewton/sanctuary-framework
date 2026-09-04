/**
 * Sanctuary MCP Server — Master-Key Rotation (F7)
 *
 * Rotates the fortress master: mints a fresh random 32-byte master,
 * re-encrypts everything encrypted under the old master, re-wraps custody
 * (passphrase wrap from the operator passphrase, a NEW recovery key minted +
 * disclosed + re-entry-verified, keychain wrap where resolvable), and
 * retires the old master.
 *
 * What derives from the master (the trace, from origin/main @ 33154ec8):
 *
 *  1. HKDF purpose keys (`derivePurposeKey`) encrypting per-namespace blobs
 *     — identities, reputation, commitments, policies, privacy policies,
 *     context-gate, sovereignty profile, principal baseline, intelligence,
 *     handoffs, chat, inbox, sentinel findings, honeypot traps, anomaly
 *     classifier state, query-anonymity, DID-web registry, auto-trigger
 *     rules, bridge commitments → re-encrypted blob-by-blob.
 *  2. HKDF namespace keys (`deriveNamespaceKey`) encrypting user state
 *     entries — whose ciphertext is SIGNED by the writer identity, so each
 *     entry is re-encrypted AND re-signed with the writer's resident key
 *     (cognitive/state-store.ts `rotateStateEntryBytes`).
 *  3. Master-keyed MACs over plaintext policy records — state version
 *     anchors, audit rotation/head anchors, transparency anchor config +
 *     counter floor → verified under the old master, restamped under the new.
 *  4. The audit entry encryption key ("audit-log") — NOT re-encrypted:
 *     every chain entry_hash (and every externally anchorable checkpoint
 *     root) covers the CIPHERTEXT, so rewriting it would invalidate the
 *     entire tamper-evidence history. Instead the retiring epoch's audit
 *     key is wrapped under the NEW master in an authenticated epoch record
 *     (key-id-scoped verification — see audit-log.ts). The chain verifies
 *     unchanged ACROSS the rotation boundary.
 *  5. Direct encryption under the raw master — the Castle Wall pinned
 *     private key file → re-encrypted in place.
 *  6. Custody artifacts — envelope wraps, envelope MAC, sentinel → replaced
 *     wholesale by the staged envelope at finalize; legacy markers
 *     (`key-params`, `recovery-key-hash`) would re-derive the OLD master,
 *     so they are deleted (audited).
 *
 * Crash safety — journaled two-phase with idempotent forward resume:
 *
 *   stage      staged envelope written at `_meta/custody-envelope-next`;
 *              recovery key disclosed + re-entry verified. NO journal yet
 *              and NO data mutated: a crash here leaves a fully old-keyed
 *              fortress that boots normally (orphaned staged keys are
 *              cleaned, audibly, on the next rotate).
 *   converting journal present; the walker re-encrypts in place. Decryption
 *              under the NEW key marks an entry done (GCM authenticates),
 *              so the walk is idempotent and resumable at any granularity.
 *              `establishMaster` REFUSES to boot while the journal exists —
 *              a half-keyed fortress must never serve.
 *   finalizing all data is under the new master; the staged envelope is
 *              promoted, legacy markers deleted, the rotation audited, and
 *              the journal removed LAST. Every step is idempotent.
 *
 * Resume requires only the fortress passphrase: it unwraps the OLD master
 * from the live envelope and the NEW master from the staged envelope —
 * key material never touches the journal (which records envelope/wrap ids
 * only, and is MAC'd under the new master).
 *
 * Fail-closed coverage rule: the preflight enumerates EVERY namespace
 * (storage backends must implement `listNamespaces`) and verifies every
 * blob decrypts/authenticates under its registered recipe BEFORE anything
 * is written. A namespace this engine does not have a recipe for — or any
 * blob that does not verify — ABORTS the rotation with nothing mutated.
 * Coverage can only grow by registering recipes; drift can never corrupt.
 */

import { access } from "node:fs/promises";
import { join, resolve } from "node:path";

import type { StorageBackend } from "../storage/interface.js";
import {
  withExclusiveMasterRotationBarrier,
  type CrossProcessLockLease,
  type MasterWriteBarrierOptions,
} from "../storage/cross-process-lock.js";
import {
  hasInterruptedExitImport,
  EXIT_IMPORT_JOURNAL_POSTIMAGE_NAMESPACE,
  EXIT_RECOVERY_VERB,
  withExitAdmissionLock,
} from "../storage/exit-import-journal.js";
import {
  encrypt,
  decrypt,
  type EncryptedPayload,
} from "./encryption.js";
import { deriveNamespaceKey, derivePurposeKey } from "./key-derivation.js";
import { generateRandomKey } from "./random.js";
import { hashToString, hmacSha256 } from "./hashing.js";
import {
  toBase64url,
  fromBase64url,
  stringToBytes,
  bytesToString,
  constantTimeEqual,
} from "./encoding.js";
import {
  readCustodyEnvelope,
  writeCustodyEnvelope,
  unwrapMaster,
  verifyEnvelopeMac,
  wrapMasterWithPassphrase,
  wrapMasterWithRecoveryKey,
  wrapMasterWithKeychainKey,
  verifyRecoveryWrapByReentry,
  countVerifiedWraps,
  CUSTODY_ENVELOPE_KEY,
  CUSTODY_SENTINEL_KEY,
  ROTATION_JOURNAL_KEY,
  STAGED_CUSTODY_ENVELOPE_KEY,
  STAGED_CUSTODY_SENTINEL_KEY,
  CUSTODY_FLOOR_WRAPS,
  CUSTODY_WRITE_LOCK_NAMESPACE,
  MASTER_ROTATION_BARRIER_NAME,
  envelopeEpochOf,
  withCustodyWriteLock,
} from "./master-custody.js";
import { canonicalJson } from "../audit/chain.js";
import {
  SDW_OWNER_PIN_KEY,
  restampSdwOwnerPinForRotation,
} from "../sdw/write-gate.js";
import {
  AuditLog,
  deriveAuditEpochKeys,
  readAuditEpochEntries,
  writeAuditEpochRecord,
  AUDIT_EPOCH_KEYS_KEY,
} from "../operational/audit-log.js";
import { writeEpochWitness } from "./anti-rollback.js";
import {
  resolveAuthenticatedIdentityWriterPublicKeys,
  rotateStateEntryBytes,
  rotateStateMetaRecordBytes,
  STATE_META_PUBLIC_KEYS_KEY,
  STATE_META_VERSION_ANCHORS_KEY,
  type RotationWriterMaterial,
} from "../cognitive/state-store.js";
import type { StoredIdentity } from "./identity.js";

// ── Errors ──────────────────────────────────────────────────────────

/** Preflight refused: rotation would not be able to convert this fortress
 * completely. NOTHING has been mutated. */
export class RotationPreflightError extends Error {
  constructor(message: string) {
    super(
      `Sanctuary: refusing to rotate the master key.\n${message}\n` +
        "Nothing was changed; the fortress remains fully under its current master."
    );
    this.name = "RotationPreflightError";
  }
}

async function runtimeMarkerExists(fortressPath: string | undefined): Promise<boolean> {
  if (fortressPath === undefined) return false;
  try {
    await access(join(fortressPath, "runtime.json"));
    return true;
  } catch (error) {
    if (
      error instanceof Error &&
      "code" in error &&
      (error as NodeJS.ErrnoException).code === "ENOENT"
    ) {
      return false;
    }
    throw error;
  }
}

export class RotationResumeError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "RotationResumeError";
  }
}

// ── Journal ─────────────────────────────────────────────────────────

const JOURNAL_MAC_DOMAIN = "sanctuary.custody-rotation-journal.v1\n";
const JOURNAL_MAC_PURPOSE = "custody-rotation-journal-mac";
export const PENDING_RECOVERY_KEY = "rotation-recovery-pending";
const PENDING_RECOVERY_MAC_DOMAIN = "sanctuary.custody-rotation-recovery-pending.v1\n";
const PENDING_RECOVERY_MAC_PURPOSE = "custody-rotation-recovery-pending-mac";

export type RotationPhase = "converting" | "finalizing";

/**
 * Non-secret durable authority needed to recover a recovery-key escrow after
 * the rotation journal's point of no return. The identifiers are authenticated
 * by the journal MAC; the platform adapter must still prove they are the
 * deterministic services for this fortress and rotation before adopting them.
 */
export interface RotationRecoveryEscrowAuthority {
  kind: "os-keyring";
  canonical_service: string;
  staging_service: string;
}

export interface RotationRecoveryEscrowMutation {
  captured: true;
  authority: RotationRecoveryEscrowAuthority;
  commit(): Promise<void>;
  rollback(): Promise<void>;
}

export interface RotationRecoveryFileAuthority {
  kind: "recovery-file";
  path: string;
  parent_dev: string;
  parent_ino: string;
  file_dev: string | null;
  file_ino: string | null;
}

export type RotationPendingRecoveryAuthority =
  | RotationRecoveryEscrowAuthority
  | RotationRecoveryFileAuthority;

export interface RotationPendingRecoveryData {
  v: 1;
  rotation_id: string;
  created_at: string;
  staged_envelope_sha256: string;
  authorities: RotationPendingRecoveryAuthority[];
}

function pendingRecoveryMac(
  data: RotationPendingRecoveryData,
  oldMaster: Uint8Array,
): string {
  const macKey = derivePurposeKey(oldMaster, PENDING_RECOVERY_MAC_PURPOSE);
  const mac = hmacSha256(
    macKey,
    stringToBytes(PENDING_RECOVERY_MAC_DOMAIN + canonicalJson(data)),
  );
  macKey.fill(0);
  return toBase64url(mac);
}

async function writePendingRecovery(
  storage: StorageBackend,
  data: RotationPendingRecoveryData,
  oldMaster: Uint8Array,
): Promise<void> {
  await storage.write(
    "_meta",
    PENDING_RECOVERY_KEY,
    stringToBytes(JSON.stringify({ data, mac: pendingRecoveryMac(data, oldMaster) })),
  );
}

function validPendingAuthority(value: unknown): value is RotationPendingRecoveryAuthority {
  if (value === null || typeof value !== "object") return false;
  const candidate = value as Record<string, unknown>;
  if (candidate.kind === "os-keyring") {
    return typeof candidate.canonical_service === "string"
      && candidate.canonical_service.length > 0
      && typeof candidate.staging_service === "string"
      && candidate.staging_service.length > 0;
  }
  return candidate.kind === "recovery-file"
    && typeof candidate.path === "string" && candidate.path.startsWith("/")
    && typeof candidate.parent_dev === "string" && /^\d+$/.test(candidate.parent_dev)
    && typeof candidate.parent_ino === "string" && /^\d+$/.test(candidate.parent_ino)
    && (candidate.file_dev === null || typeof candidate.file_dev === "string")
    && (candidate.file_ino === null || typeof candidate.file_ino === "string")
    && ((candidate.file_dev === null) === (candidate.file_ino === null))
    && (candidate.file_dev === null || /^\d+$/.test(candidate.file_dev))
    && (candidate.file_ino === null || /^\d+$/.test(candidate.file_ino));
}

async function readPendingRecovery(
  storage: StorageBackend,
  oldMaster: Uint8Array,
): Promise<RotationPendingRecoveryData | null> {
  const raw = await storage.read("_meta", PENDING_RECOVERY_KEY);
  if (!raw) return null;
  let parsed: { data?: RotationPendingRecoveryData; mac?: string };
  try {
    parsed = JSON.parse(bytesToString(raw));
  } catch {
    throw new RotationPreflightError(
      "the pending recovery-escrow record is malformed; restore _meta from backup",
    );
  }
  const data = parsed.data;
  if (
    !data || data.v !== 1 || !/^[A-Za-z0-9_-]{16}$/.test(data.rotation_id)
    || typeof data.created_at !== "string"
    || !/^[A-Za-z0-9_-]{43}$/.test(data.staged_envelope_sha256)
    || !Array.isArray(data.authorities) || data.authorities.length > 2
    || !data.authorities.every(validPendingAuthority)
    || new Set(data.authorities.map((authority) =>
      authority.kind === "os-keyring"
        ? `keyring:${authority.staging_service}`
        : `file:${authority.path}`,
    )).size !== data.authorities.length
    || typeof parsed.mac !== "string"
    || !constantTimeEqual(
      stringToBytes(parsed.mac),
      stringToBytes(pendingRecoveryMac(data, oldMaster)),
    )
  ) {
    throw new RotationPreflightError(
      "the pending recovery-escrow record failed authentication or shape validation",
    );
  }
  return data;
}

interface RotationJournalData {
  v: 1;
  rotation_id: string;
  phase: RotationPhase;
  started_at: string;
  updated_at: string;
  /** Envelope/wrap identifiers only — NEVER key material. */
  old_wrap_ids: string[];
  new_wrap_ids: string[];
  /** Non-secret authority for a staged, crash-adoptable recovery escrow. */
  recovery_escrow?: RotationRecoveryEscrowAuthority;
}

function journalMac(data: RotationJournalData, newMaster: Uint8Array): string {
  const macKey = derivePurposeKey(newMaster, JOURNAL_MAC_PURPOSE);
  const mac = hmacSha256(
    macKey,
    stringToBytes(JOURNAL_MAC_DOMAIN + canonicalJson(data))
  );
  macKey.fill(0);
  return toBase64url(mac);
}

async function writeJournal(
  storage: StorageBackend,
  data: RotationJournalData,
  newMaster: Uint8Array
): Promise<void> {
  const record = { data, mac: journalMac(data, newMaster) };
  await storage.write(
    "_meta",
    ROTATION_JOURNAL_KEY,
    stringToBytes(JSON.stringify(record))
  );
}

async function readJournal(
  storage: StorageBackend,
  newMaster: Uint8Array
): Promise<RotationJournalData | null> {
  const raw = await storage.read("_meta", ROTATION_JOURNAL_KEY);
  if (!raw) return null;
  let parsed: { data?: RotationJournalData; mac?: string };
  try {
    parsed = JSON.parse(bytesToString(raw));
  } catch {
    throw new RotationResumeError(
      "Sanctuary: the rotation journal is unreadable (malformed JSON). " +
        "Restore _meta from backup before resuming."
    );
  }
  if (
    !parsed?.data ||
    typeof parsed.mac !== "string" ||
    !constantTimeEqual(
      stringToBytes(parsed.mac),
      stringToBytes(journalMac(parsed.data, newMaster))
    )
  ) {
    throw new RotationResumeError(
      "Sanctuary: the rotation journal failed authentication (tampered, or the " +
        "supplied credential does not unlock the staged custody envelope). " +
        "Refusing to resume."
    );
  }
  return parsed.data;
}

// ── Namespace recipes ───────────────────────────────────────────────

type NamespaceRecipe =
  | {
      kind: "purpose-encrypted";
      infos: string[];
      /**
       * Key prefixes within an otherwise-supported namespace whose AAD
       * cannot be reconstructed (e.g. it binds material that only survives
       * as a hash in the storage key). Their presence aborts rotation BY
       * NAME with remediation text — never a silent skip (codex r2).
       */
      unsupportedKeyPrefixes?: Array<{ prefix: string; reason: string }>;
    }
  | { kind: "namespace-info-encrypted"; infos: string[] }
  | { kind: "identities" }
  | { kind: "state" }
  | { kind: "meta" }
  | { kind: "audit" }
  | { kind: "audit-checkpoints" }
  | { kind: "sdw-meta" }
  | { kind: "plaintext"; reason: string }
  | { kind: "unsupported"; reason: string };

const UNSUPPORTED_DEFERRAL =
  "master rotation does not support this subsystem yet (named deferral; " +
  "see the F7 PR). Export or clear the namespace, rotate, then restore.";

/**
 * Every namespace this engine knows how to rotate (or refuses, by name).
 * HKDF info strings are duplicated from their owning stores — safely:
 * the preflight DECRYPT-VERIFIES every blob before any write, so a drifted
 * info string can only make rotation refuse, never corrupt.
 */
const NAMESPACE_RECIPES: Record<string, NamespaceRecipe> = {
  _identities: { kind: "identities" },
  _meta: { kind: "meta" },
  _audit: { kind: "audit" },
  _audit_checkpoints: { kind: "audit-checkpoints" },
  _audit_integrity_alert: {
    kind: "plaintext",
    reason: "operator-facing alert log (no key material, no ciphertext)",
  },
  // F2 Option A (adversarial gate MED-1/M-1, 2026-07-14): the root Castle Wall
  // daemon's own audit chain and its siblings. Master rotation does NOT yet
  // support them (the daemon chain is encrypted under the SAME `audit-log`
  // purpose key derivation as `_audit`, but the rotation engine has no
  // adapter-aware pass to re-wrap a REMAPPED namespace, and the writer-split
  // BOUNDARY MAC is keyed off the rotating master and is not re-stamped by any
  // recipe). Refuse BY NAME with an actionable message rather than hitting the
  // generic "no registered rotation recipe" fallthrough, so an operator on a
  // migrated (armed) box gets a clear reason instead of an opaque internal
  // error. LANDMINE (do not remove without reading): implementing rotation for
  // these namespaces REQUIRES also re-stamping the split-boundary record under
  // the new master (`deriveAuditStoreSplitBoundaryMacKey` + rewrite via
  // `writeAuditStoreSplitBoundary`) IN THE SAME rotation, or the boundary reads
  // `invalid` post-rotation and F2 regresses (the operator load stops filtering
  // and re-throws on unreadable root-owned entries). See the `// F2 rekey`
  // comment on `deriveAuditStoreSplitBoundaryMacKey` in
  // `operational/audit-log.ts`.
  "_audit-daemon": {
    kind: "unsupported",
    reason:
      "the root Castle Wall daemon's own audit chain (F2 writer-split). Master " +
      "rotation does not support it yet, and it is a persistent tamper-evident " +
      "audit chain that must NOT be cleared. Rotation is deliberately refused on " +
      "a migrated fortress until daemon-audit re-wrap + boundary-MAC re-stamp " +
      "land. " + UNSUPPORTED_DEFERRAL,
  },
  "_audit-daemon_checkpoints": {
    kind: "unsupported",
    reason:
      "the root Castle Wall daemon audit chain's checkpoints/anchors (F2 " +
      "writer-split). Refused with `_audit-daemon`. " + UNSUPPORTED_DEFERRAL,
  },
  "_audit-daemon_meta": {
    kind: "unsupported",
    reason:
      "the root Castle Wall daemon audit chain's established marker (F2 " +
      "writer-split). Refused with `_audit-daemon`. " + UNSUPPORTED_DEFERRAL,
  },

  _reputation: { kind: "purpose-encrypted", infos: ["l4-reputation"] },
  // HIGH-2 (independent gate on #1303, 2026-08-23): Exit V2 drill F2 added
  // `_known_signers` (reputation/known-signers-store.ts) with no rotation
  // recipe, so rotation preflight refused ("unsupported") on any fortress
  // that had ever imported foreign reputation - a namespace-recipe registry
  // gap, not a security defect, but a fortress-bricking one.
  _known_signers: { kind: "purpose-encrypted", infos: ["l4-known-signers"] },
  _escrows: { kind: "purpose-encrypted", infos: ["l4-reputation"] },
  _guarantees: { kind: "purpose-encrypted", infos: ["l4-reputation"] },
  _commitments: { kind: "purpose-encrypted", infos: ["l3-commitments"] },
  _policies: { kind: "purpose-encrypted", infos: ["l3-policies"] },
  _context_gate_policies: {
    kind: "purpose-encrypted",
    infos: ["l2-context-gate"],
  },
  _privacy_policies: {
    kind: "purpose-encrypted",
    infos: ["l2-privacy-policies-v1"],
  },
  _sovereignty_profile: {
    kind: "purpose-encrypted",
    infos: ["sovereignty-profile"],
  },
  _principal: { kind: "purpose-encrypted", infos: ["principal-baseline"] },
  _intelligence: {
    kind: "purpose-encrypted",
    infos: ["intelligence-substrate-config"],
  },
  _handoffs: {
    kind: "purpose-encrypted",
    infos: ["sanctuary-v1.1-coordination-handoffs"],
  },
  _chat: {
    kind: "purpose-encrypted",
    infos: ["operator-chat-store-v1", "concierge-memory-store-v1"],
  },
  _english_policy_activation: {
    kind: "purpose-encrypted",
    infos: ["l2-english-policy-activation-v1"],
  },
  _approval_aggregator: {
    kind: "purpose-encrypted",
    infos: ["l2-approval-aggregator-v1"],
  },
  _approval_aggregator_payloads: {
    kind: "purpose-encrypted",
    infos: ["l2-approval-aggregator-payload-v1"],
  },
  _unified_inbox: {
    kind: "purpose-encrypted",
    infos: [
      "principal-policy-unified-inbox-v1",
      "principal-policy-unified-inbox-operator-prefs-v1",
      "principal-policy-unified-inbox-retention-policy-v1",
    ],
    unsupportedKeyPrefixes: [
      {
        prefix: "operator-prefs.",
        reason:
          "dashboard operator-prefs records bind the raw operator id into " +
          "their AAD while the storage key holds only its hash, so rotation " +
          "cannot reconstruct the AAD. These records are non-precious UI " +
          "filter preferences: delete them (they regenerate on next " +
          "dashboard use) and re-run the rotation.",
      },
    ],
  },
  _honeypot_traps: { kind: "purpose-encrypted", infos: ["l2-honeypot-trap-v1"] },
  _sentinel_findings: {
    kind: "purpose-encrypted",
    infos: ["l2-sentinel-finding-v1"],
  },
  _query_anonymity_tier_b: {
    kind: "purpose-encrypted",
    infos: ["l2-query-anonymity-tier-b-v1"],
  },
  _query_anonymity_reverse_map: {
    kind: "purpose-encrypted",
    infos: ["query-anonymity-reverse-mapping-v1"],
  },
  _recognition_hosted_did_web: {
    kind: "purpose-encrypted",
    infos: ["l2-recognition-hosted-did-web-v1"],
  },
  _auto_trigger_rules: {
    kind: "purpose-encrypted",
    infos: ["l2-auto-trigger-rules-v1"],
  },
  _anomaly_classifier_state: {
    kind: "purpose-encrypted",
    infos: ["l2-anomaly-classifier-state-v1"],
  },
  _bridge: { kind: "purpose-encrypted", infos: ["bridge-commitments"] },
  _federation: {
    kind: "purpose-encrypted",
    infos: [
      "federation-trust-root",
      "federation-joiner-trust-root",
      // Durable single-use replay sets persisted under _federation by the
      // standalone nonce store and the operator-cloud claim store. Both blobs
      // are derivePurposeKey(master, <label>) with NO AAD (like the trust-root
      // store), so the no-AAD candidate re-wraps them. Without these labels a
      // fortress that consumed a federation nonce/claim would strand its replay
      // set and rotateMaster would abort (RotationPreflightError). The strings
      // MUST equal BOOTSTRAP_NONCE_STORE_HKDF_INFO and
      // OPERATOR_CLOUD_CLAIM_STORE_HKDF_INFO (asserted in master-rotation.test).
      "federation-bootstrap-nonce-spent-set",
      "federation-operator-cloud-provision-claim-set",
      // Durable peer-sync security state (Federation 3/3b P0): per-sender
      // accepted high-water + outbound high-water + folded revocation
      // projection + (PR-A durable fleet membership) the grow-only node roster
      // (the paid node-count source), persisted under _federation by the
      // sync-state store. Same no-AAD derivePurposeKey blob, re-wrapped by the
      // no-AAD candidate; the roster is an additive field inside the SAME blob
      // (no new label), so rotation coverage is unchanged.
      // Without this label a fortress that ever persisted sync-state would
      // strand it and rotateMaster would abort. MUST equal
      // FEDERATION_SYNC_STATE_STORE_HKDF_INFO (asserted in master-rotation.test).
      "federation-sync-state",
      // Operator Cloud (Slice 3 boot-wire): the cloud node's at-rest joined-node
      // record (non-issuer scoped-custody runtime state), persisted under
      // _federation by the operator-cloud joined-node store. Same no-AAD
      // derivePurposeKey blob, so the no-AAD candidate re-wraps it. Without this
      // label a fortress that ever joined as an operator_cloud node would strand
      // its joined-node record and rotateMaster would abort. MUST equal
      // OPERATOR_CLOUD_JOINED_NODE_HKDF_INFO (asserted in master-rotation.test).
      "operator-cloud-joined-node",
      // Durable server-issued challenge spent-set for the pre-session
      // federation node-cert reissue endpoint (Slice 3c-2). Same no-AAD
      // derivePurposeKey blob; without this label a fortress that accepted a
      // reissue proof would strand the replay set on custody master rotation.
      // MUST equal FEDERATION_REISSUE_CHALLENGE_STORE_HKDF_INFO (asserted in
      // master-rotation.test).
      "federation-reissue-node-cert-challenge-set",
    ],
  },
  _fortress_mode: {
    kind: "namespace-info-encrypted",
    infos: ["sanctuary-fortress-mode-v1"],
  },

  // Named deferrals — fail closed by NAME, never silently skipped.
  _privacy_placeholder_vault: {
    kind: "unsupported",
    reason:
      "privacy placeholder vault storage keys are themselves derived from a " +
      "master-keyed HMAC; rotation must re-key (rename) every entry, which " +
      "needs the vault's own re-key flow. " + UNSUPPORTED_DEFERRAL,
  },
  _transparency_anchors: {
    kind: "unsupported",
    reason:
      "transparency anchor receipts are signed by a master-derived anchor " +
      "key; rotation needs the anchor-key cascade. " + UNSUPPORTED_DEFERRAL,
  },
  _transparency_checkpoints: {
    kind: "unsupported",
    reason:
      "transparency checkpoints are signed by a master-derived anchor key; " +
      "rotation needs the anchor-key cascade. " + UNSUPPORTED_DEFERRAL,
  },
  _sdw_catalog: { kind: "unsupported", reason: UNSUPPORTED_DEFERRAL },
  // Closed set: the owner pin is a MAC'd marker that can be safely restamped.
  // Any other SDW metadata key still aborts by name below.
  _sdw_meta: { kind: "sdw-meta" },
  _sdw_working_state: { kind: "unsupported", reason: UNSUPPORTED_DEFERRAL },
  _sdw_query_history: { kind: "unsupported", reason: UNSUPPORTED_DEFERRAL },
  _sdw_document_corpus: { kind: "unsupported", reason: UNSUPPORTED_DEFERRAL },
  _sdw_vector_memory: { kind: "unsupported", reason: UNSUPPORTED_DEFERRAL },
  _exit_public_identities: { kind: "unsupported", reason: UNSUPPORTED_DEFERRAL },
  _exit_audit_receipts: { kind: "unsupported", reason: UNSUPPORTED_DEFERRAL },
  _exit_policy_sets: { kind: "unsupported", reason: UNSUPPORTED_DEFERRAL },
  _exit_commitments: { kind: "unsupported", reason: UNSUPPORTED_DEFERRAL },
  _exit_placeholder_metadata: {
    kind: "unsupported",
    reason: UNSUPPORTED_DEFERRAL,
  },
  _handshake: { kind: "unsupported", reason: UNSUPPORTED_DEFERRAL },
  _shr: { kind: "unsupported", reason: UNSUPPORTED_DEFERRAL },
  _composition: { kind: "unsupported", reason: UNSUPPORTED_DEFERRAL },
  "_facade/hidden": { kind: "unsupported", reason: UNSUPPORTED_DEFERRAL },
  "castle-wall": {
    kind: "unsupported",
    reason:
      "castle-wall IPC frames are runtime artifacts; stop the daemon and " +
      "clear the namespace before rotating. " + UNSUPPORTED_DEFERRAL,
  },
  // N4-ROTATE (coordinator gate, 2026-08-22): explicit, not the underscore
  // fallback below - this namespace holds the exit-import writer guard's
  // own rollback records. The preflight refusal above
  // (hasInterruptedExitImport) is what stops rotation while it exists;
  // this entry keeps rotation from treating the journal's own bytes as
  // ordinary state independently of that check.
  _exit_import_journal: {
    kind: "unsupported",
    reason:
      "holds the exit-import writer guard's own rollback journal; rotation " +
      "is refused outright while one exists (see the preflight check), " +
      "never partially applied to it. " + UNSUPPORTED_DEFERRAL,
  },
  // MEDIUM-C (Codex gate, 2026-08-22): the writer guard's per-location
  // post-image records; same reasoning and same preflight refusal as the
  // main journal namespace above.
  [EXIT_IMPORT_JOURNAL_POSTIMAGE_NAMESPACE]: {
    kind: "unsupported",
    reason:
      "holds the exit-import writer guard's per-location post-image " +
      "records; rotation is refused outright while an import journal " +
      "exists (see the preflight check). " + UNSUPPORTED_DEFERRAL,
  },
};

function recipeFor(namespace: string): NamespaceRecipe {
  const known = NAMESPACE_RECIPES[namespace];
  if (known) return known;
  if (namespace.startsWith("_")) {
    return {
      kind: "unsupported",
      reason: `internal namespace "${namespace}" has no registered rotation recipe`,
    };
  }
  // Anything else is user state written through the StateStore.
  return { kind: "state" };
}

// ── `_meta` key classification ──────────────────────────────────────

type MetaKeyClass =
  | "legacy-marker" // deleted at finalize
  | "custody" // replaced by the staged envelope at finalize
  | "rotation" // this engine's own artifacts
  | "plaintext-keep" // positively identified non-secret record
  | "state-meta-mac" // master-MAC'd record → restamp
  | "transparency-anchor-config" // master-MAC'd record → restamp
  | "transparency-counter-floor" // master-MAC'd record → restamp
  | "epoch-witness" // anti-rollback witness → finalize re-stamps (advanced)
  | "rollback-freeze" // anti-rollback freeze marker → restamp under new master
  | "federation-guardian-antirollback" // {marker,data,mac} anchor → restamp
  | "federation-guardian-established" // dataless MAC sentinel → inline re-derive
  | "rekey-journal-pending"; // interrupted recovery-key rekey → refuse with a remedy

// Duplicated marker/MAC constants (see the recipe-table drift note above —
// the verify-before-write rule makes drift refuse, never corrupt).
const TRANSPARENCY_ANCHOR_CONFIG_META_KEY = "transparency-anchor-config-v1";
const TRANSPARENCY_ANCHOR_CONFIG_MARKER =
  "__sanctuary_transparency_anchor_config_v1";
const TRANSPARENCY_ANCHOR_CONFIG_MAC_PURPOSE =
  "transparency-anchor-config-mac-v1";
const TRANSPARENCY_ANCHOR_CONFIG_MAC_DOMAIN =
  "sanctuary.transparency.anchor-config.v1\n";
const TRANSPARENCY_FLOOR_META_KEY = "transparency-counter-floor-v1";
const TRANSPARENCY_FLOOR_MARKER = "__sanctuary_transparency_counter_floor_v1";
const TRANSPARENCY_FLOOR_MAC_PURPOSE = "transparency-counter-floor";
const TRANSPARENCY_FLOOR_MAC_DOMAIN = "sanctuary.transparency-counter-floor.v1\n";

const AUDIT_HEAD_ANCHOR_ESTABLISHED_KEY = "audit-head-anchor-established-v1";
const PRIMARY_IDENTITY_META_KEY = "primary_identity_id";
// F2 BLOCKER-R2 (adversarial re-gate 2026-07-14): the writer-split
// migration-established marker (byte-matches audit-log.ts's
// AUDIT_STORE_SPLIT_ESTABLISHED_META_KEY). Its presence proves the fortress ran
// the F2 store-split migration, so master rotation MUST refuse (the split-
// boundary MAC is keyed off the rotating master and is not re-stamped — see the
// `_audit-daemon*` namespace recipes + the deriveAuditStoreSplitBoundaryMacKey
// landmine comment). This `_meta` marker makes the refusal robust even if the
// `_audit-daemon*` namespaces were deleted (the raw boundary-v1.json file is not
// a `.enc` entry and is skipped by namespace enumeration, so it cannot carry the
// refusal on its own).
const AUDIT_STORE_SPLIT_ESTABLISHED_META_KEY = "audit-store-split-established-v1";

// Anti-rollback Stage 1 (duplicated from core/anti-rollback.ts; the
// verify-before-write rule makes drift refuse, never corrupt). The witness is
// re-stamped (with the ADVANCED epoch) by finalize, so convertMeta only needs
// to recognize the key and leave it alone during the convert pass. The freeze
// marker is restamped under the new master like the transparency floor.
const EPOCH_WITNESS_META_KEY = "custody-epoch-witness-v1";
const ROLLBACK_FREEZE_META_KEY = "custody-rollback-freeze-v1";
const ROLLBACK_FREEZE_MARKER = "__sanctuary_custody_rollback_freeze_v1";
const ROLLBACK_FREEZE_MAC_PURPOSE = "custody-rollback-freeze-mac";
const ROLLBACK_FREEZE_MAC_DOMAIN = "sanctuary.custody-rollback-freeze.v1\n";

// Finding #7 (duplicated from v1/federation-sync-state-store.ts; the
// verify-before-write rule makes drift refuse, never corrupt). BOTH guardian
// `_meta` keys MAC under the STORE purpose key ("federation-sync-state"), not a
// bespoke *-mac purpose, so no new HKDF label is minted (§7 reuse). Two shapes:
//  - the anti-rollback ANCHOR is a {marker,data,mac} record whose MAC is over
//    canonicalJson(data), so it FITS restampMacRecord (via macPurpose =
//    FEDERATION_SYNC_STATE_STORE_HKDF_INFO).
//  - the established SENTINEL is a DATALESS {v,mac} record whose MAC is over a
//    FIXED domain string (not `data`), so it does NOT fit restampMacRecord and
//    is re-derived inline in convertMeta.
// The established-sentinel classification ALSO fixes a PRE-EXISTING latent break
// independent of this fix: before this, a fortress that ever enabled a guardian
// requirement wrote that `_meta` key and then could NOT rotate its custody
// master (convertMeta hit default -> null -> throw).
const FEDERATION_SYNC_STATE_STORE_HKDF_INFO = "federation-sync-state";
const FEDERATION_GUARDIAN_ANTIROLLBACK_ANCHOR_META_KEY =
  "federation-guardian-antirollback-anchor-v1";
const FEDERATION_GUARDIAN_ANTIROLLBACK_ANCHOR_MARKER =
  "__sanctuary_federation_guardian_antirollback_anchor_v1";
const FEDERATION_GUARDIAN_ANTIROLLBACK_ANCHOR_MAC_DOMAIN =
  "sanctuary.federation.guardian-antirollback-anchor.v1\n";
const FEDERATION_GUARDIAN_REQUIREMENT_ESTABLISHED_META_KEY =
  "federation-guardian-requirement-established-v1";
const FEDERATION_GUARDIAN_REQUIREMENT_ESTABLISHED_MAC_DOMAIN =
  "sanctuary.federation.guardian-requirement.established.v1";

function classifyMetaKey(key: string): MetaKeyClass | null {
  switch (key) {
    case "key-params":
    case "recovery-key-hash":
      return "legacy-marker";
    case CUSTODY_ENVELOPE_KEY:
    case CUSTODY_SENTINEL_KEY:
      return "custody";
    case ROTATION_JOURNAL_KEY:
    case PENDING_RECOVERY_KEY:
    case STAGED_CUSTODY_ENVELOPE_KEY:
    case STAGED_CUSTODY_SENTINEL_KEY:
      return "rotation";
    case STATE_META_PUBLIC_KEYS_KEY: // public keys only
    case AUDIT_HEAD_ANCHOR_ESTABLISHED_KEY: // literal "1"
    case PRIMARY_IDENTITY_META_KEY: // identity id string
      return "plaintext-keep";
    case STATE_META_VERSION_ANCHORS_KEY:
      return "state-meta-mac";
    case TRANSPARENCY_ANCHOR_CONFIG_META_KEY:
      return "transparency-anchor-config";
    case TRANSPARENCY_FLOOR_META_KEY:
      return "transparency-counter-floor";
    case EPOCH_WITNESS_META_KEY:
      return "epoch-witness";
    case ROLLBACK_FREEZE_META_KEY:
      return "rollback-freeze";
    case FEDERATION_GUARDIAN_ANTIROLLBACK_ANCHOR_META_KEY:
      return "federation-guardian-antirollback";
    case FEDERATION_GUARDIAN_REQUIREMENT_ESTABLISHED_META_KEY:
      return "federation-guardian-established";
    // Must match REKEY_JOURNAL_KEY in server/src/cli/reset-passphrase.ts: the
    // authenticated journal a `reset-passphrase --mode recovery-key` writes and
    // deletes on completion. Its presence means an interrupted rekey left custody
    // mid-transition; rotation must refuse with a heal remedy, not the opaque
    // "unrecognized record" abort (S7).
    case "custody-rekey-journal":
      return "rekey-journal-pending";
    default:
      return null; // Unknown → preflight aborts (fail closed).
  }
}

// ── Generic MAC'd-record restamp ────────────────────────────────────

function restampMacRecord(args: {
  raw: Uint8Array;
  where: string;
  marker: string;
  macPurpose: string;
  macDomain: string;
  oldMaster: Uint8Array;
  newMaster: Uint8Array;
}): Uint8Array | "already-new" | "leave" {
  let parsed: unknown;
  try {
    parsed = JSON.parse(bytesToString(args.raw));
  } catch {
    throw new RotationPreflightError(`${args.where} is not valid JSON`);
  }
  const obj = parsed as Record<string, unknown>;
  if (!obj || typeof obj !== "object" || obj[args.marker] !== true) {
    // Bare / marker-stripped records are untrusted today; leave them so the
    // owning subsystem's own fail-closed handling applies unchanged.
    return "leave";
  }
  const data = obj.data;
  const mac = obj.mac;
  if (!data || typeof data !== "object" || typeof mac !== "string") {
    throw new RotationPreflightError(`${args.where} is malformed`);
  }
  const macFor = (master: Uint8Array): Uint8Array => {
    const macKey = derivePurposeKey(master, args.macPurpose);
    const out = hmacSha256(
      macKey,
      stringToBytes(args.macDomain + canonicalJson(data))
    );
    macKey.fill(0);
    return out;
  };
  let provided: Uint8Array;
  try {
    provided = fromBase64url(mac);
  } catch {
    throw new RotationPreflightError(`${args.where} MAC is malformed`);
  }
  if (constantTimeEqual(provided, macFor(args.newMaster))) return "already-new";
  if (!constantTimeEqual(provided, macFor(args.oldMaster))) {
    throw new RotationPreflightError(
      `${args.where} failed authentication under both the old and the new ` +
        "master (tampered); rotation must not restamp it"
    );
  }
  return stringToBytes(
    JSON.stringify({
      [args.marker]: true,
      data,
      mac: toBase64url(macFor(args.newMaster)),
    })
  );
}

/**
 * Finding #7 (4b): re-derive the DATALESS federation-guardian established
 * sentinel under the new master. Unlike restampMacRecord, this record's MAC is
 * over a FIXED domain string (not `data`), so we recompute it directly. The
 * record shape is `{ v: 1, mac }` where
 * `mac = HMAC(derivePurposeKey(master, "federation-sync-state"), DOMAIN)`.
 *
 * Verify-before-write (mirror restampMacRecord's dual-master check): a marker
 * that already authenticates under the NEW master is "already-new"; one that
 * authenticates under the OLD master is re-stamped; one that authenticates under
 * NEITHER is tampered -> abort (never restamp a forged marker). A structurally
 * malformed record aborts.
 */
function restampFederationGuardianEstablishedSentinel(args: {
  raw: Uint8Array;
  where: string;
  oldMaster: Uint8Array;
  newMaster: Uint8Array;
}): Uint8Array | "already-new" {
  let parsed: unknown;
  try {
    parsed = JSON.parse(bytesToString(args.raw));
  } catch {
    throw new RotationPreflightError(`${args.where} is not valid JSON`);
  }
  const obj = parsed as Record<string, unknown>;
  if (!obj || typeof obj !== "object" || typeof obj.mac !== "string") {
    throw new RotationPreflightError(`${args.where} is malformed`);
  }
  const macFor = (master: Uint8Array): string => {
    const macKey = derivePurposeKey(master, FEDERATION_SYNC_STATE_STORE_HKDF_INFO);
    const out = hmacSha256(
      macKey,
      stringToBytes(FEDERATION_GUARDIAN_REQUIREMENT_ESTABLISHED_MAC_DOMAIN)
    );
    macKey.fill(0);
    return toBase64url(out);
  };
  const newMac = macFor(args.newMaster);
  let provided: Uint8Array;
  let newMacBytes: Uint8Array;
  try {
    provided = fromBase64url(obj.mac);
    newMacBytes = fromBase64url(newMac);
  } catch {
    throw new RotationPreflightError(`${args.where} MAC is malformed`);
  }
  if (constantTimeEqual(provided, newMacBytes)) return "already-new";
  if (!constantTimeEqual(provided, fromBase64url(macFor(args.oldMaster)))) {
    throw new RotationPreflightError(
      `${args.where} failed authentication under both the old and the new ` +
        "master (tampered); rotation must not restamp it"
    );
  }
  return stringToBytes(JSON.stringify({ v: 1, mac: newMac }));
}

// ── AAD candidates ──────────────────────────────────────────────────

/**
 * Candidate AADs for purpose-encrypted stores, reconstructed from the
 * storage key + the fortress identifiers (hashed fortress id, resolved
 * fortress paths — different stores bind different ones). Every store's
 * AAD is a deterministic function of those; the preflight decrypt proves
 * the right candidate (GCM authentication picks it), and a store whose AAD
 * cannot be reconstructed makes rotation refuse, never guess.
 */
function aadCandidates(
  key: string,
  identifiers: string[]
): Array<Uint8Array | undefined> {
  // Key variants: the full key plus the id-ish suffixes stores commonly
  // bind (key after a `prefix.`/`prefix-` style namespace prefix), each
  // also offered with its remaining separators normalized to the `|` the
  // stores join compound AADs with (e.g. key `state.<a>.<b>` whose AAD is
  // `<a>|<b>` — the anomaly classifier shape, codex r2).
  const baseVariants = new Set<string>([key]);
  const firstDot = key.indexOf(".");
  if (firstDot > 0) baseVariants.add(key.slice(firstDot + 1));
  const lastDash = key.lastIndexOf("-");
  if (lastDash > 0) baseVariants.add(key.slice(lastDash + 1));
  const firstDash = key.indexOf("-");
  if (firstDash > 0) baseVariants.add(key.slice(firstDash + 1));
  const keyVariants = new Set<string>();
  for (const variant of baseVariants) {
    keyVariants.add(variant);
    for (const sep of ["__", "/", ":", "."]) {
      if (variant.includes(sep)) keyVariants.add(variant.split(sep).join("|"));
    }
  }

  const candidates: Array<string | undefined> = [undefined, ...keyVariants];
  for (const id of identifiers) {
    candidates.push(id);
    for (const variant of keyVariants) {
      for (const sep of ["|", ":"]) {
        candidates.push(`${id}${sep}${variant}`);
        candidates.push(`${variant}${sep}${id}`);
      }
    }
  }
  const unique = [...new Set(candidates)];
  return unique.map((c) => (c === undefined ? undefined : stringToBytes(c)));
}

function parseEncryptedPayload(raw: Uint8Array): EncryptedPayload | null {
  try {
    const parsed = JSON.parse(bytesToString(raw)) as EncryptedPayload;
    if (
      parsed &&
      typeof parsed === "object" &&
      parsed.v === 1 &&
      parsed.alg === "aes-256-gcm" &&
      typeof parsed.iv === "string" &&
      typeof parsed.ct === "string"
    ) {
      return parsed;
    }
  } catch {
    // not an EncryptedPayload
  }
  return null;
}

// ── Options & context ───────────────────────────────────────────────

export interface RotateMasterOptions {
  storage: StorageBackend;
  /** Fortress root (holds castle-pinned-privkey.enc). Omit in unit tests
   * that exercise storage-only fortresses. */
  fortressPath?: string;
  fortressId: string;
  /** The operator's fortress passphrase: unlocks the old master AND becomes
   * the new envelope's passphrase wrap. */
  passphrase: string;
  /** OS-keyring custody key, when the caller resolved one (re-creates the
   * keychain wrap on the new envelope). */
  keychainKey?: Uint8Array;
  /**
   * Tier-1 human approval gate (CLAUDE.md #3: key rotation is irreversible
   * and requires confirmation BEFORE execution). Called with the preflight
   * summary; rotation proceeds only on `true`. The CLI implements this as
   * an interactive typed confirmation; there is no headless bypass in this
   * engine (a headless `--no-confirm` rotation is Erik's D3 territory).
   */
  approve: (summary: RotationPlanSummary) => Promise<boolean>;
  /**
   * Recovery-key capture: disclose `recoveryKey` to the operator, then
   * verify re-entry by calling `verify` with what the operator typed
   * (the engine proves the re-entered key by unwrapping the staged master
   * with it — #496 capture rules). Return false to abort (nothing mutated).
   */
  captureRecoveryKey: (
    recoveryKey: string,
    verify: (entered: string) => Promise<boolean>,
    rotationId: string,
    registerPendingAuthority: (
      authority: RotationPendingRecoveryAuthority,
    ) => Promise<void>,
  ) => Promise<
    | boolean
    | RotationRecoveryEscrowMutation
    | {
        captured: true;
        commit(): Promise<void>;
        rollback(): Promise<void>;
      }
  >;
  /**
   * Crash reconciliation for authenticated pre-journal escrow authorities.
   * The adapter must verify each candidate against the staged envelope before
   * deleting the exact keyring item or inode it owns.
   */
  reconcilePendingRecoveryEscrow?: (
    pending: Readonly<RotationPendingRecoveryData>,
    verify: (candidate: string) => Promise<boolean>,
  ) => Promise<void>;
  /** Test seam: crash injection. Throw inside to simulate a hard kill. */
  failpoint?: (point: string) => void;
  /** Operator-facing progress lines (CLI: stderr). */
  log?: (line: string) => void;
  /** Test only: observe the real kernel holder and kill it to prove fencing. */
  __testAfterKernelHolderAcquired?: (pid: number) => void;
  /** Test only: observe the process-owned lock socket for loss fencing. */
  __testAfterKernelSocketAcquired?: (path: string) => void;
  /** Test only: pause after durable Castle-pin publish but before the lease fence. */
  __testAfterCastlePinPublished?: () => void | Promise<void>;
  /** Test only: storage-only fixtures may inject an isolated file capability. */
  __testFortressFiles?: NonNullable<CrossProcessLockLease["stableFortressFiles"]>;
  /** Test only: observe owned secret buffers for exception-path zeroization. */
  __testObserveSecretBuffer?: (
    label: "old-master" | "new-master" | "recovery-key",
    buffer: Uint8Array,
  ) => void;
  /** Test only: observe/control the shared/exclusive rotation barrier. */
  __testMasterRotationBarrierOptions?: MasterWriteBarrierOptions;
}

export interface RotationPlanSummary {
  rotation_id: string;
  namespaces: Array<{ namespace: string; entries: number; kind: string }>;
  total_entries: number;
  audit_entries_epoch_scoped: number;
  castle_pin: "present" | "absent" | "mismatch";
  keychain_wrap: "re-created" | "dropped-unresolvable" | "not-present";
  warnings: string[];
}

export interface RotateMasterResult {
  rotation_id: string;
  /** Wrap ids on the retired envelope (audit detail — never key material). */
  old_wrap_ids: string[];
  new_wrap_ids: string[];
  converted_entries: number;
}

interface Ctx {
  storage: StorageBackend;
  fortressPath?: string;
  fortressId: string;
  /** Identifier candidates stores bind into AADs (hashed fortress id,
   * resolved fortress/state paths). */
  aadIdentifiers: string[];
  oldMaster: Uint8Array;
  newMaster: Uint8Array;
  rotationId: string;
  failpoint: (point: string) => void;
  log: (line: string) => void;
  writerCache: Map<string, RotationWriterMaterial | null>;
  lease: CrossProcessLockLease;
  __testAfterCastlePinPublished?: () => void | Promise<void>;
  __testFortressFiles?: NonNullable<CrossProcessLockLease["stableFortressFiles"]>;
}

const PIN_FILE = "castle-pinned-privkey.enc";

function buildAadIdentifiers(fortressId: string, fortressPath?: string): string[] {
  const ids = new Set<string>([fortressId]);
  if (fortressPath) {
    ids.add(resolve(fortressPath));
    ids.add(resolve(join(fortressPath, "state")));
  }
  return [...ids];
}

/** Zero the derived identity-encryption keys cached for state re-signing. */
function zeroizeWriterCache(ctx: Ctx): void {
  for (const material of ctx.writerCache.values()) {
    material?.identityEncryptionKey.fill(0);
  }
  ctx.writerCache.clear();
}

/** Fence every durable rotation helper/mutation on both sides of its await. */
async function fenced<T>(ctx: Ctx, mutation: () => Promise<T>): Promise<T> {
  ctx.lease.assertHeld();
  const result = await mutation();
  ctx.lease.assertHeld();
  return result;
}

// ── Conversion walkers (all idempotent: new key first, then old) ────

async function listKeys(
  storage: StorageBackend,
  namespace: string
): Promise<string[]> {
  return (await storage.list(namespace)).map((m) => m.key);
}

/** Resolve a state writer's signing material from `_identities`, under
 * whichever master currently encrypts the record (resume-safe). */
async function resolveWriter(
  ctx: Ctx,
  kid: string
): Promise<RotationWriterMaterial | null> {
  if (ctx.writerCache.has(kid)) return ctx.writerCache.get(kid) ?? null;
  let material: RotationWriterMaterial | null = null;
  const raw = await ctx.storage.read("_identities", kid);
  if (raw) {
    const payload = parseEncryptedPayload(raw);
    if (payload) {
      for (const master of [ctx.newMaster, ctx.oldMaster]) {
        const idKey = derivePurposeKey(master, "identity-encryption");
        try {
          const identity = JSON.parse(
            bytesToString(decrypt(payload, idKey))
          ) as StoredIdentity;
          material = {
            encryptedPrivateKey: identity.encrypted_private_key,
            identityEncryptionKey: idKey,
            publicKey: fromBase64url(identity.public_key),
            verificationPublicKeys:
              resolveAuthenticatedIdentityWriterPublicKeys(identity),
          };
          break;
        } catch {
          idKey.fill(0);
        }
      }
    }
  }
  ctx.writerCache.set(kid, material);
  return material;
}

/** `_identities`: re-encrypt the outer record AND the inner private key. */
async function convertIdentities(ctx: Ctx, verifyOnly: boolean): Promise<number> {
  const oldKey = derivePurposeKey(ctx.oldMaster, "identity-encryption");
  const newKey = derivePurposeKey(ctx.newMaster, "identity-encryption");
  let converted = 0;
  try {
    for (const key of await listKeys(ctx.storage, "_identities")) {
      const raw = await ctx.storage.read("_identities", key);
      if (!raw) continue;
      const payload = parseEncryptedPayload(raw);
      if (!payload) {
        throw new RotationPreflightError(
          `_identities/${key} is not an encrypted payload`
        );
      }
      try {
        decrypt(payload, newKey).fill(0);
        continue; // already converted
      } catch {
        // fall through to the old key
      }
      let identity: StoredIdentity;
      try {
        identity = JSON.parse(
          bytesToString(decrypt(payload, oldKey))
        ) as StoredIdentity;
      } catch {
        throw new RotationPreflightError(
          `_identities/${key} does not decrypt under either master`
        );
      }
      const innerSeed = decrypt(identity.encrypted_private_key, oldKey);
      if (verifyOnly) {
        innerSeed.fill(0);
        continue;
      }
      const rotated: StoredIdentity = {
        ...identity,
        encrypted_private_key: encrypt(innerSeed, newKey),
      };
      innerSeed.fill(0);
      await fenced(ctx, () =>
        ctx.storage.write(
          "_identities",
          key,
          stringToBytes(encryptToJson(rotated, newKey)),
        ),
      );
      converted++;
      ctx.failpoint(`converted:_identities/${key}`);
    }
  } finally {
    oldKey.fill(0);
    newKey.fill(0); // resolveWriter derives its own copy; safe to zero.
  }
  return converted;
}

function encryptToJson(value: unknown, key: Uint8Array): string {
  return JSON.stringify(encrypt(stringToBytes(JSON.stringify(value)), key));
}

/** User state namespaces: re-encrypt + re-sign each entry. */
async function convertStateNamespace(
  ctx: Ctx,
  namespace: string,
  verifyOnly: boolean
): Promise<number> {
  const oldNsKey = deriveNamespaceKey(ctx.oldMaster, namespace);
  const newNsKey = deriveNamespaceKey(ctx.newMaster, namespace);
  let converted = 0;
  try {
    for (const key of await listKeys(ctx.storage, namespace)) {
      const raw = await ctx.storage.read(namespace, key);
      if (!raw) continue;
      let result;
      try {
        result = await rotateStateEntryBytes({
          raw,
          namespace,
          key,
          oldNamespaceKey: oldNsKey,
          newNamespaceKey: newNsKey,
          resolveWriter: (kid) => resolveWriter(ctx, kid),
          verifyOnly,
        });
      } catch (err) {
        throw new RotationPreflightError(
          err instanceof Error ? err.message : String(err)
        );
      }
      if (result.status === "converted") {
        await fenced(ctx, () => ctx.storage.write(namespace, key, result.bytes));
        converted++;
        ctx.failpoint(`converted:${namespace}/${key}`);
      }
    }
  } finally {
    oldNsKey.fill(0);
    newNsKey.fill(0);
  }
  return converted;
}

/** Purpose-keyed stores: re-encrypt under the matching (info, AAD) pair. */
async function convertPurposeNamespace(
  ctx: Ctx,
  namespace: string,
  infos: string[],
  deriveFn: (master: Uint8Array, info: string) => Uint8Array,
  verifyOnly: boolean,
  unsupportedKeyPrefixes?: Array<{ prefix: string; reason: string }>
): Promise<number> {
  const oldKeys = infos.map((info) => deriveFn(ctx.oldMaster, info));
  const newKeys = infos.map((info) => deriveFn(ctx.newMaster, info));
  let converted = 0;
  try {
    for (const key of await listKeys(ctx.storage, namespace)) {
      const blocked = unsupportedKeyPrefixes?.find((u) =>
        key.startsWith(u.prefix)
      );
      if (blocked) {
        throw new RotationPreflightError(
          `${namespace}/${key}: ${blocked.reason}`
        );
      }
      const raw = await ctx.storage.read(namespace, key);
      if (!raw) continue;
      const payload = parseEncryptedPayload(raw);
      if (!payload) {
        throw new RotationPreflightError(
          `${namespace}/${key} is not an encrypted payload (no rotation recipe for its format)`
        );
      }
      const aads = aadCandidates(key, ctx.aadIdentifiers);
      let done = false;
      // Already under the new master?
      outer: for (const newKey of newKeys) {
        for (const aad of aads) {
          try {
            decrypt(payload, newKey, aad).fill(0);
            done = true;
            break outer;
          } catch {
            // try next candidate
          }
        }
      }
      if (done) continue;
      let plaintext: Uint8Array | null = null;
      let matched: { index: number; aad: Uint8Array | undefined } | null = null;
      outer2: for (let i = 0; i < oldKeys.length; i++) {
        for (const aad of aads) {
          try {
            plaintext = decrypt(payload, oldKeys[i]!, aad);
            matched = { index: i, aad };
            break outer2;
          } catch {
            // try next candidate
          }
        }
      }
      if (!plaintext || !matched) {
        throw new RotationPreflightError(
          `${namespace}/${key} does not decrypt under any registered key/AAD ` +
            "recipe for this namespace"
        );
      }
      try {
        if (verifyOnly) continue;
        const next = encrypt(plaintext, newKeys[matched.index]!, matched.aad);
        await fenced(ctx, () =>
          ctx.storage.write(
            namespace,
            key,
            stringToBytes(JSON.stringify(next)),
          ),
        );
        converted++;
        ctx.failpoint(`converted:${namespace}/${key}`);
      } finally {
        plaintext.fill(0);
      }
    }
  } finally {
    for (const k of [...oldKeys, ...newKeys]) k.fill(0);
  }
  return converted;
}

/** `_meta`: restamp MAC'd records; verify every key is classified. */
async function convertMeta(ctx: Ctx, verifyOnly: boolean): Promise<number> {
  let converted = 0;
  for (const key of await listKeys(ctx.storage, "_meta")) {
    // F2 BLOCKER-R2: refuse BY NAME on a fortress that ran the writer-split
    // migration. This covers the case where the `_audit-daemon*` namespaces were
    // deleted (so their named recipes never fire) but the durable `_meta`
    // established marker survives. The boundary MAC would silently regress F2 if
    // rotated without re-stamping; do not rotate until that lands.
    if (key === AUDIT_STORE_SPLIT_ESTABLISHED_META_KEY) {
      throw new RotationPreflightError(
        `_meta/${key}: this fortress ran the F2 audit store writer-split ` +
          "migration. Master rotation does not support it yet (the split-boundary " +
          "MAC is keyed off the rotating master and is not re-stamped), so rotation " +
          "is deliberately refused until daemon-audit re-wrap + boundary-MAC " +
          "re-stamp land."
      );
    }
    const cls = classifyMetaKey(key);
    if (cls === null) {
      throw new RotationPreflightError(
        `_meta/${key} is not a record this rotation engine recognizes; ` +
          "refusing to rotate around it"
      );
    }
    if (cls === "rekey-journal-pending") {
      // S7: an interrupted `reset-passphrase --mode recovery-key` left its
      // authenticated journal, so custody is mid-transition. Rotating around it
      // is unsafe; name the exact heal step (re-running the rekey completes and
      // deletes the journal) instead of the generic unrecognized-record abort.
      throw new RotationPreflightError(
        `_meta/${key}: an interrupted recovery-key passphrase rekey left its ` +
          "custody journal in place, so master rotation is refused until it heals. " +
          "Re-run `sanctuary reset-passphrase --mode recovery-key --fortress <path>`; " +
          "it resumes and clears the journal without changing anything else, then " +
          "rotation can proceed."
      );
    }
    if (
      cls === "legacy-marker" ||
      cls === "custody" ||
      cls === "rotation" ||
      cls === "plaintext-keep" ||
      // The epoch witness is re-stamped with the ADVANCED epoch by finalize
      // (writeEpochWitness force), so the convert pass leaves it alone — like
      // the custody envelope. Re-stamping the OLD epoch here would just be
      // overwritten, and could briefly under-report the epoch mid-rotation;
      // boot is blocked while the journal exists anyway.
      cls === "epoch-witness"
    ) {
      continue;
    }
    const raw = await ctx.storage.read("_meta", key);
    if (!raw) continue;
    let next: Uint8Array | "already-new" | "leave" | null;
    if (cls === "state-meta-mac") {
      const result = rotateStateMetaRecordBytes({
        raw,
        metaKey: key,
        oldMasterKey: ctx.oldMaster,
        newMasterKey: ctx.newMaster,
      });
      next = result === null ? "leave" : result;
    } else if (cls === "federation-guardian-established") {
      // Finding #7 (4b): the established sentinel is a DATALESS {v,mac} record
      // whose MAC is over a FIXED domain string (not `data`), so restampMacRecord
      // (which re-MACs canonicalJson(data)) does NOT fit it. Re-derive inline:
      // verify under the old master first (refuse a tampered marker), then
      // recompute the MAC under the new master's purpose key over the same fixed
      // domain and rewrite {v:1, mac}.
      next = restampFederationGuardianEstablishedSentinel({
        raw,
        where: `_meta/${key}`,
        oldMaster: ctx.oldMaster,
        newMaster: ctx.newMaster,
      });
    } else {
      const restampParams =
        cls === "transparency-anchor-config"
          ? {
              marker: TRANSPARENCY_ANCHOR_CONFIG_MARKER,
              macPurpose: TRANSPARENCY_ANCHOR_CONFIG_MAC_PURPOSE,
              macDomain: TRANSPARENCY_ANCHOR_CONFIG_MAC_DOMAIN,
            }
          : cls === "rollback-freeze"
            ? {
                marker: ROLLBACK_FREEZE_MARKER,
                macPurpose: ROLLBACK_FREEZE_MAC_PURPOSE,
                macDomain: ROLLBACK_FREEZE_MAC_DOMAIN,
              }
            : cls === "federation-guardian-antirollback"
              ? {
                  // Finding #7 (4a): the anchor is a {marker,data,mac} record with
                  // the MAC over canonicalJson(data), so it fits restampMacRecord
                  // exactly. macPurpose is the STORE purpose key label (no new
                  // HKDF label; §7 reuse), so restampMacRecord re-derives the
                  // identical key the store used.
                  marker: FEDERATION_GUARDIAN_ANTIROLLBACK_ANCHOR_MARKER,
                  macPurpose: FEDERATION_SYNC_STATE_STORE_HKDF_INFO,
                  macDomain: FEDERATION_GUARDIAN_ANTIROLLBACK_ANCHOR_MAC_DOMAIN,
                }
              : {
                  marker: TRANSPARENCY_FLOOR_MARKER,
                  macPurpose: TRANSPARENCY_FLOOR_MAC_PURPOSE,
                  macDomain: TRANSPARENCY_FLOOR_MAC_DOMAIN,
                };
      next = restampMacRecord({
        raw,
        where: `_meta/${key}`,
        ...restampParams,
        oldMaster: ctx.oldMaster,
        newMaster: ctx.newMaster,
      });
    }
    if (next === "leave" || next === "already-new") continue;
    if (!verifyOnly && next instanceof Uint8Array) {
      await fenced(ctx, () => ctx.storage.write("_meta", key, next));
      converted++;
      ctx.failpoint(`converted:_meta/${key}`);
    }
  }
  return converted;
}

/** `_audit_checkpoints`: every key is positively classified (codex r1 HIGH —
 * an unrecognized record in an internal namespace must abort, never be
 * silently skipped past a master rotation):
 *  - the two master-MAC'd anchors → verified under the old master, restamped;
 *  - the custody-epoch record → must authenticate under one of the masters
 *    (rewrapped by convertAuditEpochs);
 *  - `audit-checkpoint-*` / `legacy-anchor-*` records → hash/signature based
 *    (no master-keyed material), positively shape-checked, kept as-is;
 *  - anything else → abort. */
/**
 * `_sdw_meta` is a closed set for rotation. The durable owner pin can be
 * authenticated under the old master and restamped under the new one; replay
 * anchors and any future key remain unsupported and abort by exact name.
 */
async function convertSdwMeta(ctx: Ctx, verifyOnly: boolean): Promise<number> {
  let converted = 0;
  for (const key of await listKeys(ctx.storage, "_sdw_meta")) {
    if (key !== SDW_OWNER_PIN_KEY) {
      throw new RotationPreflightError(
        `namespace "_sdw_meta" key "${key}": ${UNSUPPORTED_DEFERRAL}`,
      );
    }
    let outcome: "absent" | "already-new" | "converted";
    try {
      const restamp = () => restampSdwOwnerPinForRotation({
        storage: ctx.storage,
        oldMaster: ctx.oldMaster,
        newMaster: ctx.newMaster,
        verifyOnly,
      });
      outcome = verifyOnly ? await restamp() : await fenced(ctx, restamp);
    } catch (err) {
      throw new RotationPreflightError(
        `_sdw_meta/${SDW_OWNER_PIN_KEY}: ${err instanceof Error ? err.message : String(err)}`,
      );
    }
    if (outcome === "converted" && !verifyOnly) {
      converted += 1;
      ctx.failpoint(`converted:_sdw_meta/${SDW_OWNER_PIN_KEY}`);
    }
  }
  return converted;
}

async function convertAuditAnchors(ctx: Ctx, verifyOnly: boolean): Promise<number> {
  let converted = 0;
  const MAC_ANCHORS: Record<
    string,
    { marker: string; purpose: string; domain: string }
  > = {
    __rotation_anchor: {
      marker: "__sanctuary_audit_rotation_anchor_v1",
      purpose: "audit-rotation-anchor",
      domain: "sanctuary.audit-rotation-anchor.v1\n",
    },
    __head_anchor: {
      marker: "__sanctuary_audit_head_anchor_v1",
      purpose: "audit-head-anchor",
      domain: "sanctuary.audit-head-anchor.v1\n",
    },
    // IC-05-DG signing control records. Marker/purpose/domain must match
    // AUDIT_SIGNING_LATCH_V2_MARKER / AUDIT_SIGNING_LATCH_V2_MAC_PURPOSE /
    // AUDIT_SIGNING_LATCH_V2_MAC_DOMAIN and AUDIT_SIGNING_HEAD_MARKER /
    // AUDIT_SIGNING_HEAD_MAC_PURPOSE / AUDIT_SIGNING_HEAD_MAC_DOMAIN in
    // operational/audit-log.ts; the key literals are
    // AUDIT_SIGNING_LATCH_V2_KEY / AUDIT_SIGNING_HEAD_KEY in
    // audit/checkpoint-shape.ts. Omitting either entry would make rotation
    // ABORT on every fortress that ever signed a checkpoint (closed-set
    // classifier below). `restampMacRecord` gives these the required
    // dual-master transitional verification: already-new is tolerated on
    // resume, a marker-bearing record failing BOTH masters aborts loudly
    // (tamper is never restamped into validity), and a marker-stripped
    // record is left for the audit log's own fail-closed reader.
    __signing_latch_v2: {
      marker: "__sanctuary_audit_signing_latch_v2",
      purpose: "audit-signing-latch-v2",
      domain: "sanctuary.audit-signing-latch.v2\n",
    },
    __signing_head: {
      marker: "__sanctuary_audit_signing_head_v1",
      purpose: "audit-signing-head",
      domain: "sanctuary.audit-signing-head.v1\n",
    },
  };
  for (const key of await listKeys(ctx.storage, "_audit_checkpoints")) {
    const anchor = MAC_ANCHORS[key];
    if (anchor) {
      const raw = await ctx.storage.read("_audit_checkpoints", key);
      if (!raw) continue;
      const next = restampMacRecord({
        raw,
        where: `_audit_checkpoints/${key}`,
        marker: anchor.marker,
        macPurpose: anchor.purpose,
        macDomain: anchor.domain,
        oldMaster: ctx.oldMaster,
        newMaster: ctx.newMaster,
      });
      if (next === "leave" || next === "already-new") continue;
      if (!verifyOnly) {
        await fenced(ctx, () =>
          ctx.storage.write("_audit_checkpoints", key, next),
        );
        converted++;
        ctx.failpoint(`converted:_audit_checkpoints/${key}`);
      }
      continue;
    }
    if (key === AUDIT_EPOCH_KEYS_KEY) {
      // Must authenticate under the new master (resume) or the old one
      // (about to be rewrapped by convertAuditEpochs). Anything else is
      // tamper — abort.
      const newKeys = deriveAuditEpochKeys(ctx.newMaster);
      const oldKeys = deriveAuditEpochKeys(ctx.oldMaster);
      try {
        let entries;
        try {
          entries = await readAuditEpochEntries(ctx.storage, newKeys);
        } catch {
          entries = await readAuditEpochEntries(ctx.storage, oldKeys);
        }
        for (const e of entries) e.key.fill(0);
      } catch {
        throw new RotationPreflightError(
          `_audit_checkpoints/${key} (the custody-epoch record) does not ` +
            "authenticate under either master (tampered); rotating over it " +
            "would orphan prior audit epochs"
        );
      } finally {
        newKeys.epochWrapKey.fill(0);
        newKeys.epochMacKey.fill(0);
        oldKeys.epochWrapKey.fill(0);
        oldKeys.epochMacKey.fill(0);
      }
      continue;
    }
    if (key.startsWith("audit-checkpoint-") || key.startsWith("legacy-anchor-")) {
      // Hash-chain/Ed25519 records: no master-keyed material; positively
      // verify the shape so a foreign blob hiding under the prefix aborts.
      const raw = await ctx.storage.read("_audit_checkpoints", key);
      if (!raw) continue;
      let kind: unknown;
      try {
        kind = (JSON.parse(bytesToString(raw)) as Record<string, unknown>)
          .checkpoint_kind;
      } catch {
        kind = undefined;
      }
      if (kind !== "audit-checkpoint" && kind !== "legacy-anchor") {
        throw new RotationPreflightError(
          `_audit_checkpoints/${key} is not a recognized checkpoint record; ` +
            "refusing to rotate around it"
        );
      }
      continue;
    }
    throw new RotationPreflightError(
      `_audit_checkpoints/${key} is not a record this rotation engine ` +
        "recognizes; refusing to rotate around it"
    );
  }
  return converted;
}

/**
 * Audit custody epochs: wrap the retiring epoch's audit key (and re-wrap
 * every prior epoch key) under the NEW master. Idempotent: if the record
 * already authenticates under the new master and names this rotation_id,
 * the work is done.
 */
async function convertAuditEpochs(ctx: Ctx): Promise<void> {
  const oldEpochKeys = deriveAuditEpochKeys(ctx.oldMaster);
  const newEpochKeys = deriveAuditEpochKeys(ctx.newMaster);
  try {
    // Resume check: already rewritten under the new master?
    try {
      const existing = await readAuditEpochEntries(ctx.storage, newEpochKeys);
      if (existing.some((e) => e.entry.rotation_id === ctx.rotationId)) {
        for (const e of existing) e.key.fill(0);
        return;
      }
      for (const e of existing) e.key.fill(0);
    } catch {
      // Not under the new master yet — read under the old.
    }
    const prior = await readAuditEpochEntries(ctx.storage, oldEpochKeys);
    const retiringAuditKey = derivePurposeKey(ctx.oldMaster, "audit-log");
    const rotatedAt = new Date().toISOString();
    try {
      await fenced(ctx, () => writeAuditEpochRecord(ctx.storage, newEpochKeys, [
        ...prior.map((e) => ({
          rotation_id: e.entry.rotation_id,
          rotated_at: e.entry.rotated_at,
          key: e.key,
        })),
        {
          rotation_id: ctx.rotationId,
          rotated_at: rotatedAt,
          key: retiringAuditKey,
        },
      ]));
    } finally {
      retiringAuditKey.fill(0);
      for (const e of prior) e.key.fill(0);
    }
    ctx.failpoint("audit-epoch-written");
  } finally {
    oldEpochKeys.epochWrapKey.fill(0);
    oldEpochKeys.epochMacKey.fill(0);
    newEpochKeys.epochWrapKey.fill(0);
    newEpochKeys.epochMacKey.fill(0);
  }
}

/** Castle Wall pinned private key (encrypted DIRECTLY under the master). */
async function convertCastlePin(
  ctx: Ctx,
  verifyOnly: boolean
): Promise<"ok" | "absent" | "mismatch"> {
  if (!ctx.fortressPath) return "absent";
  const files = ctx.lease.stableFortressFiles ?? ctx.__testFortressFiles;
  if (!files) {
    throw new RotationPreflightError(
      "Castle pin rotation requires an inode-bound fortress file capability",
    );
  }
  const raw = await files.read(PIN_FILE);
  if (raw === null) return "absent";
  const payload = parseEncryptedPayload(raw);
  if (!payload) return "mismatch";
  try {
    decrypt(payload, ctx.newMaster).fill(0);
    return "ok"; // already converted
  } catch {
    // fall through
  }
  let seed: Uint8Array;
  try {
    seed = decrypt(payload, ctx.oldMaster);
  } catch {
    // Dual-path damage predating this rotation (the #496 diagnostic case):
    // the pin is already orphaned; rotation neither fixes nor worsens it.
    // Surfaced in the plan summary + audited; the cure is a re-pin.
    return "mismatch";
  }
  try {
    if (verifyOnly) return "ok";
    await fenced(ctx, async () => {
      await files.write(
        PIN_FILE,
        stringToBytes(JSON.stringify(encrypt(seed, ctx.newMaster))),
        0o600,
      );
      // Atomic publish is already durable here. A crash or holder loss at this
      // boundary leaves either the old valid pin or the new valid pin; resume
      // authenticates both possibilities and converges forward.
      ctx.failpoint("castle-pin-published");
      await ctx.__testAfterCastlePinPublished?.();
    });
    ctx.failpoint("converted:castle-pin");
    return "ok";
  } finally {
    seed.fill(0);
  }
}

// ── The walk (verify pass and convert pass share one driver) ────────

async function walkFortress(
  ctx: Ctx,
  verifyOnly: boolean
): Promise<{ converted: number; plan: RotationPlanSummary["namespaces"] }> {
  if (typeof ctx.storage.listNamespaces !== "function") {
    throw new RotationPreflightError(
      "this storage backend cannot enumerate namespaces; rotation cannot " +
        "prove complete coverage and refuses to guess"
    );
  }
  const namespaces = await ctx.storage.listNamespaces();
  const plan: RotationPlanSummary["namespaces"] = [];
  let converted = 0;

  // Convert identities FIRST: state-entry re-signing resolves writer keys
  // through `_identities` and the resolver prefers the new master.
  const ordered = [...namespaces].sort((a, b) =>
    a === "_identities" ? -1 : b === "_identities" ? 1 : a.localeCompare(b)
  );

  for (const namespace of ordered) {
    const recipe = recipeFor(namespace);
    const entries = (await ctx.storage.list(namespace)).length;
    if (entries === 0) continue;
    plan.push({ namespace, entries, kind: recipe.kind });
    switch (recipe.kind) {
      case "unsupported":
        throw new RotationPreflightError(
          `namespace "${namespace}" (${entries} entries): ${recipe.reason}`
        );
      case "plaintext":
      case "audit":
        break; // audit entries are epoch-scoped, not rewritten
      case "identities":
        converted += await convertIdentities(ctx, verifyOnly);
        break;
      case "state":
        converted += await convertStateNamespace(ctx, namespace, verifyOnly);
        break;
      case "purpose-encrypted":
        converted += await convertPurposeNamespace(
          ctx,
          namespace,
          recipe.infos,
          derivePurposeKey,
          verifyOnly,
          recipe.unsupportedKeyPrefixes
        );
        break;
      case "namespace-info-encrypted":
        converted += await convertPurposeNamespace(
          ctx,
          namespace,
          recipe.infos,
          deriveNamespaceKey,
          verifyOnly
        );
        break;
      case "meta":
        converted += await convertMeta(ctx, verifyOnly);
        break;
      case "audit-checkpoints":
        converted += await convertAuditAnchors(ctx, verifyOnly);
        break;
      case "sdw-meta":
        converted += await convertSdwMeta(ctx, verifyOnly);
        break;
    }
  }
  return { converted, plan };
}

// ── Finalize ────────────────────────────────────────────────────────

/**
 * Anti-rollback Stage 1: the new custody epoch after this rotation = the number
 * of entries in the post-conversion custody-epoch record (convertAuditEpochs
 * has appended this rotation's epoch entry under the new master). Read under the
 * new master; defaults to 1 if the record is unexpectedly unreadable here (a
 * rotation has, by definition, advanced the epoch to at least 1). Reads only the
 * count — every unwrapped key is zeroed.
 */
async function readNewEpochCount(ctx: Ctx): Promise<number> {
  const newEpochKeys = deriveAuditEpochKeys(ctx.newMaster);
  try {
    const entries = await readAuditEpochEntries(ctx.storage, newEpochKeys);
    for (const e of entries) e.key.fill(0);
    return Math.max(1, entries.length);
  } catch {
    // The record must authenticate under the new master at finalize (it was
    // just written by convertAuditEpochs); if it does not, a rotation still
    // advanced the epoch — never report 0 (that would falsely read as "no
    // rotation" and let the boot detector treat the rotated fortress as the
    // pre-rotation one). Minimum advanced epoch is 1.
    return 1;
  } finally {
    newEpochKeys.epochWrapKey.fill(0);
    newEpochKeys.epochMacKey.fill(0);
  }
}

async function finalize(ctx: Ctx, journal: RotationJournalData): Promise<void> {
  if (journal.phase !== "finalizing") {
    await fenced(ctx, () => writeJournal(
      ctx.storage,
      { ...journal, phase: "finalizing", updated_at: new Date().toISOString() },
      ctx.newMaster,
    ));
    ctx.failpoint("journal-finalizing-written");
  }

  // Anti-rollback Stage 1: this rotation ADVANCES the epoch. The new epoch =
  // the count of entries in the post-conversion custody-epoch record
  // (convertAuditEpochs has already appended this rotation's entry, so the
  // count includes it). Computed here (not at staging) so it is correct after
  // a resume and idempotent: re-running finalize recomputes the same count and
  // re-stamps the same epoch. A monotonic rotation can never LOWER the epoch,
  // so the boot detector sees the rotated fortress as fresher, never rolled
  // back. (epoch_id = this rotation's id.)
  const newEpoch = await readNewEpochCount(ctx);

  // Promote the staged envelope (idempotent: if the staged copy is gone, a
  // prior resume already promoted it), stamping the advanced epoch into it so
  // the on-disk custody epoch matches the witness.
  const staged = await readCustodyEnvelope(ctx.storage, {
    envelopeKey: STAGED_CUSTODY_ENVELOPE_KEY,
  });
  if (staged) {
    verifyEnvelopeMac(staged, ctx.newMaster);
    await fenced(ctx, () => writeCustodyEnvelope(
      ctx.storage,
      { ...staged, epoch: newEpoch, epoch_id: ctx.rotationId },
      ctx.newMaster,
    ));
    ctx.failpoint("envelope-promoted");
    await fenced(ctx, () =>
      ctx.storage.delete("_meta", STAGED_CUSTODY_ENVELOPE_KEY),
    );
    await fenced(ctx, () =>
      ctx.storage.delete("_meta", STAGED_CUSTODY_SENTINEL_KEY),
    );
    ctx.failpoint("staged-deleted");
  } else {
    // Late-finalize resume: the live envelope is already promoted but may
    // predate this epoch stamp. Re-stamp it idempotently so a crash between
    // promotion and witness-write still lands a consistent epoch.
    const live = await readCustodyEnvelope(ctx.storage);
    if (live && envelopeEpochOf(live) < newEpoch) {
      await fenced(ctx, () => writeCustodyEnvelope(
        ctx.storage,
        { ...live, epoch: newEpoch, epoch_id: ctx.rotationId },
        ctx.newMaster,
      ));
    }
  }

  // Advance the monotonic epoch witness to the new epoch (force: the rotation
  // is the authority on its own epoch; a concurrent stale witness must not
  // block a legitimate rotation from raising the floor).
  await fenced(ctx, () => writeEpochWitness(
    ctx.storage,
    ctx.newMaster,
    {
      epoch: newEpoch,
      epoch_id: ctx.rotationId,
      witnessed_at: new Date().toISOString(),
    },
    { force: true },
  ));
  ctx.failpoint("epoch-witness-advanced");

  // Legacy markers would re-derive the OLD master — the dual-path divergence
  // generator this lane exists to kill. Delete them (audited below).
  await fenced(ctx, () => ctx.storage.delete("_meta", "key-params"));
  await fenced(ctx, () => ctx.storage.delete("_meta", "recovery-key-hash"));
  ctx.failpoint("legacy-markers-deleted");

  // Audit the rotation under the NEW master (old entries decrypt via the
  // epoch record; the chain verifies across the boundary). Envelope ids
  // only — never key material (CLAUDE.md #6).
  // IC-05-DG: transitional rotation reader (the #1249 fail-soft roster) —
  // mid-rotation the signing control records may authenticate under either
  // epoch, so downgrade detection is declared off AT CONSTRUCTION rather
  // than minting false TAMPERED verdicts; the next steady-state fortress
  // load runs it. Never derived from storage (DELTA-4).
  const auditLog = new AuditLog(ctx.storage, ctx.newMaster, {
    signingDetectionMode: "non-fortress",
  });
  await fenced(ctx, () => auditLog.appendCritical({
    layer: "l1",
    operation: "custody_master_rotated",
    identity_id: ctx.fortressId,
    result: "success",
    details: {
      rotation_id: ctx.rotationId,
      old_wrap_ids: journal.old_wrap_ids,
      new_wrap_ids: journal.new_wrap_ids,
      legacy_markers_deleted: true,
    },
  }));
  await fenced(ctx, () => auditLog.flush());
  ctx.failpoint("rotation-audited");

  await fenced(ctx, () => ctx.storage.delete("_meta", PENDING_RECOVERY_KEY));
  await fenced(ctx, () => ctx.storage.delete("_meta", ROTATION_JOURNAL_KEY));
}

// ── Public entry points ─────────────────────────────────────────────

/**
 * Federation rotate-root mutual exclusion (Slice 3a). A federation
 * signing-master rotation re-keys the `_federation/trust-root-v1` payload;
 * running a custody rotation concurrently could re-encrypt a half-rotated
 * payload, so custody rotation refuses while the federation rotate-root journal
 * exists. The namespace/key are the literal mesh constants (core must not import
 * mesh -- the wrong layering direction): FEDERATION_TRUST_ROOT_NAMESPACE +
 * FEDERATION_ROTATE_ROOT_JOURNAL_KEY in mesh/federation-rotate-root.ts. This is
 * the single source for the check and its message; both the early diagnostic in
 * `rotateMaster` and the authoritative in-lock preflight call it, so the two
 * can never drift.
 */
async function assertNoFederationRotateRootInProgress(
  storage: StorageBackend,
): Promise<void> {
  if (await storage.read("_federation", "rotate-root-journal")) {
    throw new RotationPreflightError(
      "a federation rotate-root is in progress on this fortress; finish it " +
        "(`sanctuary federation rotate-root --resume`) before rotating the custody master"
    );
  }
}

export async function rotateMaster(
  opts: RotateMasterOptions
): Promise<RotateMasterResult> {
  // Ordering invariant: surface the federation rotate-root refusal BEFORE the
  // exclusive master-rotation barrier drains. The barrier waits for live writer
  // sessions to close and, under a lingering or slow-to-reap reader socket,
  // times out with a GENERIC "master rotation waited Nms for active writer
  // session(s) to close" error that masks the real cause. The specific reason a
  // custody rotate must give the operator (a federation rotate-root is mid-flight)
  // would otherwise be non-deterministic, decided by barrier-reader timing that
  // differs between a fast dev host and a slower CI runner. This is a diagnostic
  // fast-path only; the authoritative check in rotateMasterLocked still runs
  // under the barrier + custody lock and closes the process-start race, so the
  // mutual-exclusion guarantee does not depend on this early read.
  await assertNoFederationRotateRootInProgress(opts.storage);
  return withExclusiveMasterRotationBarrier(
    opts.storage,
    CUSTODY_WRITE_LOCK_NAMESPACE,
    MASTER_ROTATION_BARRIER_NAME,
    () => withCustodyWriteLock(
      opts.storage,
      (lease) => rotateMasterLocked(opts, lease),
      {
        metadata: { owner: "rotate-master" },
        ...(opts.__testAfterKernelHolderAcquired !== undefined
          ? {
              __testAfterKernelHolderAcquired:
                opts.__testAfterKernelHolderAcquired,
            }
          : {}),
        ...(opts.__testAfterKernelSocketAcquired !== undefined
          ? { __testAfterKernelSocketAcquired: opts.__testAfterKernelSocketAcquired }
          : {}),
      },
    ),
    opts.__testMasterRotationBarrierOptions,
  );
}

async function rotateMasterLocked(
  opts: RotateMasterOptions,
  lease: CrossProcessLockLease,
): Promise<RotateMasterResult> {
  const storage = opts.storage;
  const log = opts.log ?? (() => {});
  const failpoint = opts.failpoint ?? (() => {});

  // Final runtime recheck under BOTH the exclusive master-session barrier and
  // the custody mutation lock. The CLI's earlier diagnostic check is only an
  // optimization; this is the authority that closes a process-start race.
  if (await runtimeMarkerExists(opts.fortressPath)) {
    throw new RotationPreflightError(
      "runtime.json exists, indicating a Sanctuary writer may still be running; " +
        "stop the dashboard and wrapped agents before rotating",
    );
  }

  if (await storage.read("_meta", ROTATION_JOURNAL_KEY)) {
    throw new RotationPreflightError(
      "a rotation is already in progress on this fortress; resume it with " +
        "`sanctuary rotate-master --resume`"
    );
  }

  // N4-ROTATE (coordinator gate, 2026-08-22): rotation re-encrypts every
  // "state"-classified namespace and re-stamps `_meta` MAC records by
  // writing directly to storage (the writer guard's chokepoints - the state
  // and reputation stores' write paths - are not on this path at all).
  // Those are exactly the journal-set locations a pending exit-import
  // journal can later restore, so run this the same way the two mutual-
  // exclusion checks above do: refuse before any conversion begins.
  if (await hasInterruptedExitImport(storage)) {
    throw new RotationPreflightError(
      // F1/round-3: must match EXIT_RECOVERY_VERB, imported above from
      // storage/exit-import-journal.ts, AND the exact
      // "--fortress <fortress path>" form - recover takes no ambient path
      // (exit/cli.ts's ExitRecoverFortressPathRequiredError).
      "an exit-import rollback journal exists for this fortress, meaning an " +
        `import is in progress or pending recovery; run \`sanctuary exit ` +
        `${EXIT_RECOVERY_VERB} --fortress <fortress path>\` to recover, ` +
        "then retry"
    );
  }

  // Mutual exclusion with the federation rotate-root journal (Slice 3a). This
  // is the AUTHORITATIVE check: it runs under the exclusive master-rotation
  // barrier + custody mutation lock, so it closes the process-start race that
  // the early diagnostic in `rotateMaster` cannot. Shares the one source
  // (`assertNoFederationRotateRootInProgress`) with that diagnostic so the
  // refusal message cannot drift between the two sites.
  await assertNoFederationRotateRootInProgress(storage);

  // Unlock the OLD master. Envelope-format custody is required: rotation of
  // a pure-legacy fortress goes through `sanctuary wrap` migration first.
  const oldEnvelope = await readCustodyEnvelope(storage);
  if (!oldEnvelope) {
    throw new RotationPreflightError(
      "this fortress does not have envelope-format custody yet; run " +
        "`sanctuary wrap` once (it migrates in place) and retry"
    );
  }
  const oldMaster = await unwrapMaster(oldEnvelope, {
    passphrase: opts.passphrase,
  });
  try {
    opts.__testObserveSecretBuffer?.("old-master", oldMaster);
    verifyEnvelopeMac(oldEnvelope, oldMaster);

    // Reconcile an interrupted PRE-journal recovery handoff before minting a
    // new rotation identity. The pending record is authenticated by the still-
    // live old master and binds every external authority to the exact staged
    // envelope bytes. External cleanup is delegated to the platform adapter,
    // which must verify the candidate and delete only its recorded inode/item.
    const pendingRecovery = await readPendingRecovery(storage, oldMaster);
    const abandonedStagedEnvelope = await readCustodyEnvelope(storage, {
      envelopeKey: STAGED_CUSTODY_ENVELOPE_KEY,
    });
    if (pendingRecovery) {
      if (!abandonedStagedEnvelope) {
        throw new RotationPreflightError(
          "an authenticated pending recovery handoff exists but its staged custody envelope is missing; refusing to guess which external recovery material is safe to remove",
        );
      }
      const stagedBytes = await storage.read("_meta", STAGED_CUSTODY_ENVELOPE_KEY);
      const stagedDigestMatches = stagedBytes !== null
        && hashToString(stagedBytes) === pendingRecovery.staged_envelope_sha256;
      if (!stagedDigestMatches && pendingRecovery.authorities.length > 0) {
        throw new RotationPreflightError(
          "the pending recovery handoff does not bind the current staged custody envelope",
        );
      }
      if (pendingRecovery.authorities.length > 0) {
        if (!opts.reconcilePendingRecoveryEscrow) {
          throw new RotationPreflightError(
            "a prior pre-journal recovery handoff needs platform reconciliation; retry through the rotate-master CLI with the same fortress and --recovery-out path",
          );
        }
        await opts.reconcilePendingRecoveryEscrow(
          pendingRecovery,
          (candidate) => recoveryCandidateAuthenticatesEnvelope(
            abandonedStagedEnvelope,
            candidate,
          ),
        );
      }
      lease.assertHeld();
      await storage.delete("_meta", PENDING_RECOVERY_KEY);
      lease.assertHeld();
      await storage.delete("_meta", STAGED_CUSTODY_ENVELOPE_KEY);
      lease.assertHeld();
      await storage.delete("_meta", STAGED_CUSTODY_SENTINEL_KEY);
      lease.assertHeld();
      log(
        `Reconciled interrupted pre-journal recovery handoff ${pendingRecovery.rotation_id}; ` +
          "its new recovery key never became active.",
      );
    } else if (abandonedStagedEnvelope) {
      // Compatibility cleanup for v4 and for a crash after staging but before
      // the first pending-record write: no external handoff was authorized.
      log(
        "Note: removing a staged custody envelope from an attempt that ended " +
          "before recovery escrow was authorized; its recovery key is inactive.",
      );
      lease.assertHeld();
      await storage.delete("_meta", STAGED_CUSTODY_ENVELOPE_KEY);
      lease.assertHeld();
      await storage.delete("_meta", STAGED_CUSTODY_SENTINEL_KEY);
      lease.assertHeld();
    }

  const newMaster = generateRandomKey();
  try {
  opts.__testObserveSecretBuffer?.("new-master", newMaster);
  // 12 = 96 random bits taken from the 32-byte CSPRNG draw, chosen because 12
  // bytes is exactly 16 base64url characters with no padding. A rotation id is
  // an opaque log/journal label, not key material.
  const rotationId = toBase64url(generateRandomKey().subarray(0, 12));
  const ctx: Ctx = {
    storage,
    ...(opts.fortressPath !== undefined ? { fortressPath: opts.fortressPath } : {}),
    fortressId: opts.fortressId,
    aadIdentifiers: buildAadIdentifiers(opts.fortressId, opts.fortressPath),
    oldMaster,
    newMaster,
    rotationId,
    failpoint,
    log,
    writerCache: new Map(),
    lease,
    ...(opts.__testAfterCastlePinPublished
      ? { __testAfterCastlePinPublished: opts.__testAfterCastlePinPublished }
      : {}),
    ...(opts.__testFortressFiles ? { __testFortressFiles: opts.__testFortressFiles } : {}),
  };

  let recoveryCapture:
    | {
        commit(): Promise<void>;
        rollback(): Promise<void>;
        authority?: RotationRecoveryEscrowAuthority;
      }
    | undefined;
  let journalDurable = false;
  let rotationFailure: unknown;
  const recoveryCleanupFailures: unknown[] = [];
  let rotationResult: RotateMasterResult | undefined;
  try {
    // ── Preflight: verify EVERYTHING before mutating ANYTHING. ──
    log("Preflight: verifying every namespace converts cleanly...");
    const verify = await walkFortress(ctx, true);
    const pinStatus = await convertCastlePin(ctx, true);
    const auditEntries = (await storage.list("_audit")).length;

    // The audit chain must verify (strict mode) under the OLD master BEFORE
    // anything is staged or disclosed (codex r1 MEDIUM): pre-existing audit
    // tamper aborts here with nothing mutated, not after a recovery key has
    // already been shown to the operator.
    try {
      // IC-05-DG: transitional rotation reader; see the rotation-audit
      // instance's note. Never derived from storage (DELTA-4).
      const auditPreflight = new AuditLog(storage, oldMaster, {
        signingDetectionMode: "non-fortress",
      });
      await auditPreflight.query({ limit: 1 });
    } catch (err) {
      throw new RotationPreflightError(
        "the audit chain does not verify under the current master:\n  " +
          (err instanceof Error ? err.message : String(err))
      );
    }
    const oldHasKeychain = oldEnvelope.wraps.some((w) => w.type === "keychain");
    const warnings: string[] = [];
    if (pinStatus === "mismatch") {
      warnings.push(
        "the Castle Wall pinned key does not decrypt under this master " +
          "(pre-existing dual-path damage); rotation will leave it untouched — " +
          "re-pin afterwards"
      );
    }
    if (oldHasKeychain && !opts.keychainKey) {
      warnings.push(
        "the current envelope has an OS-keyring wrap but no keyring custody " +
          "key was resolvable; the rotated envelope will NOT have a keychain " +
          "wrap until you re-enroll it"
      );
    }
    const summary: RotationPlanSummary = {
      rotation_id: rotationId,
      namespaces: verify.plan,
      total_entries: verify.plan.reduce((sum, p) => sum + p.entries, 0),
      audit_entries_epoch_scoped: auditEntries,
      castle_pin: pinStatus === "ok" ? "present" : pinStatus,
      keychain_wrap: oldHasKeychain
        ? opts.keychainKey
          ? "re-created"
          : "dropped-unresolvable"
        : opts.keychainKey
          ? "re-created"
          : "not-present",
      warnings,
    };

    // ── Tier-1 approval gate (human confirmation BEFORE execution). ──
    if (!(await opts.approve(summary))) {
      throw new RotationPreflightError("operator declined the confirmation gate");
    }

    // ── Stage the new custody envelope (no data mutated yet). ──
    const wraps = [
      await fenced(ctx, () =>
        wrapMasterWithPassphrase(newMaster, opts.passphrase, {
          verified: true,
        }),
      ),
    ];
    const recoveryKeyBytes = generateRandomKey();
    let recoveryKey: string;
    try {
      opts.__testObserveSecretBuffer?.("recovery-key", recoveryKeyBytes);
      recoveryKey = toBase64url(recoveryKeyBytes);
      ctx.lease.assertHeld();
      wraps.push(
        wrapMasterWithRecoveryKey(newMaster, recoveryKeyBytes, { verified: false })
      );
      ctx.lease.assertHeld();
    } finally {
      recoveryKeyBytes.fill(0);
    }
    if (opts.keychainKey) {
      ctx.lease.assertHeld();
      wraps.push(
        wrapMasterWithKeychainKey(newMaster, opts.keychainKey, { verified: true })
      );
      ctx.lease.assertHeld();
    }
    let stagedEnvelope = await fenced(ctx, () => writeCustodyEnvelope(
      storage,
      {
        v: 1,
        install_mode: "interactive",
        wraps,
        created_at: new Date().toISOString(),
      },
      newMaster,
      {
        envelopeKey: STAGED_CUSTODY_ENVELOPE_KEY,
        sentinelKey: STAGED_CUSTODY_SENTINEL_KEY,
      },
    ));
    failpoint("staged-envelope-written");

    let pendingRecovery: RotationPendingRecoveryData = {
      v: 1,
      rotation_id: rotationId,
      created_at: new Date().toISOString(),
      staged_envelope_sha256: hashToString(
        stringToBytes(JSON.stringify(stagedEnvelope)),
      ),
      authorities: [],
    };
    await fenced(ctx, () => writePendingRecovery(storage, pendingRecovery, oldMaster));
    failpoint("pending-recovery-written");
    let recoveryReentryVerified = false;

    const registerPendingAuthority = async (
      authority: RotationPendingRecoveryAuthority,
    ): Promise<void> => {
      if (!recoveryReentryVerified) {
        throw new RotationPreflightError(
          "recovery escrow attempted publication before the staged recovery key was re-entry verified",
        );
      }
      if (!validPendingAuthority(authority)) {
        throw new RotationPreflightError("recovery escrow supplied an invalid pending authority");
      }
      if (
        authority.kind === "os-keyring"
          ? !authority.staging_service.endsWith(`:rotation:${rotationId}`)
          : !authority.path.startsWith("/")
            || !/^\d+$/.test(authority.parent_dev)
            || !/^\d+$/.test(authority.parent_ino)
            || (authority.file_dev !== null && !/^\d+$/.test(authority.file_dev))
            || (authority.file_ino !== null && !/^\d+$/.test(authority.file_ino))
      ) {
        throw new RotationPreflightError(
          "recovery escrow authority is not bound to this rotation and output parent",
        );
      }
      const existingIndex = pendingRecovery.authorities.findIndex((existing) => (
        (existing.kind === "os-keyring" && authority.kind === "os-keyring"
          && existing.staging_service === authority.staging_service)
        || (existing.kind === "recovery-file" && authority.kind === "recovery-file"
          && existing.path === authority.path)
      ));
      const authorities = [...pendingRecovery.authorities];
      if (existingIndex >= 0) {
        const existing = authorities[existingIndex]!;
        if (
          existing.kind !== "recovery-file" || authority.kind !== "recovery-file"
          || existing.parent_dev !== authority.parent_dev
          || existing.parent_ino !== authority.parent_ino
          || existing.file_dev !== null || existing.file_ino !== null
          || authority.file_dev === null || authority.file_ino === null
        ) {
          throw new RotationPreflightError("recovery escrow authority was registered twice");
        }
        authorities[existingIndex] = authority;
      } else {
        authorities.push(authority);
      }
      const next: RotationPendingRecoveryData = {
        ...pendingRecovery,
        authorities,
      };
      await fenced(ctx, () => writePendingRecovery(storage, next, oldMaster));
      pendingRecovery = next;
    };

    // ── NEW recovery key: disclose + re-entry verify (#496 rules). ──
    const captureResult = await fenced(ctx, () =>
      opts.captureRecoveryKey(recoveryKey, async (entered) => {
      try {
        if (recoveryReentryVerified) {
          return recoveryCandidateAuthenticatesEnvelope(stagedEnvelope, entered);
        }
        stagedEnvelope = await fenced(ctx, () => verifyRecoveryWrapByReentry(
          storage,
          stagedEnvelope,
          entered,
          {
            envelopeKey: STAGED_CUSTODY_ENVELOPE_KEY,
            sentinelKey: STAGED_CUSTODY_SENTINEL_KEY,
          },
        ));
        const reboundBytes = await fenced(ctx, () =>
          storage.read("_meta", STAGED_CUSTODY_ENVELOPE_KEY),
        );
        if (!reboundBytes) {
          throw new Error("verified staged custody envelope disappeared before recovery binding");
        }
        pendingRecovery = {
          ...pendingRecovery,
          staged_envelope_sha256: hashToString(reboundBytes),
        };
        await fenced(ctx, () => writePendingRecovery(storage, pendingRecovery, oldMaster));
        recoveryReentryVerified = true;
        return true;
      } catch {
        return false;
      }
      }, rotationId, registerPendingAuthority),
    );
    const captured = typeof captureResult === "boolean"
      ? captureResult
      : captureResult.captured;
    if (typeof captureResult !== "boolean") recoveryCapture = captureResult;
    if (!captured) {
      await fenced(ctx, () =>
        storage.delete("_meta", STAGED_CUSTODY_ENVELOPE_KEY),
      );
      await fenced(ctx, () =>
        storage.delete("_meta", STAGED_CUSTODY_SENTINEL_KEY),
      );
      throw new RotationPreflightError(
        "recovery-key capture was not completed; rotation requires a " +
          "verified recovery wrap before any data is touched"
      );
    }

    // Two-factor floor on the ROTATED fortress, enforced before conversion.
    if (countVerifiedWraps(stagedEnvelope) < CUSTODY_FLOOR_WRAPS) {
      await fenced(ctx, () =>
        storage.delete("_meta", STAGED_CUSTODY_ENVELOPE_KEY),
      );
      await fenced(ctx, () =>
        storage.delete("_meta", STAGED_CUSTODY_SENTINEL_KEY),
      );
      throw new RotationPreflightError(
        `the rotated envelope would hold fewer than ${CUSTODY_FLOOR_WRAPS} verified ` +
          "factors; rotation must never weaken custody below the floor"
      );
    }

    // Audit the start under the OLD master (this entry stays readable after
    // rotation via the audit epoch record).
    // IC-05-DG: transitional rotation reader; see the rotation-audit
    // instance's note. Never derived from storage (DELTA-4).
    const oldAudit = new AuditLog(storage, oldMaster, {
      signingDetectionMode: "non-fortress",
    });
    await fenced(ctx, () => oldAudit.appendCritical({
      layer: "l1",
      operation: "custody_rotation_started",
      identity_id: opts.fortressId,
      result: "success",
      details: {
        rotation_id: rotationId,
        old_wrap_ids: oldEnvelope.wraps.map((w) => w.id),
        new_wrap_ids: stagedEnvelope.wraps.map((w) => w.id),
        ...(warnings.length > 0 ? { warnings } : {}),
      },
    }));
    await fenced(ctx, () => oldAudit.flush());
    // Deterministic process-death boundary: pending recovery authority and its
    // exact staged envelope are durable, while the conversion journal is not.
    // A real SIGKILL here must be reconciled on the next rotation attempt.
    failpoint("recovery-escrow-captured-pre-journal");

    // ── Point of no return: journal on, boots blocked, convert. ──
    const recoveryEscrowAuthority = pendingRecovery.authorities.find(
      (authority): authority is RotationRecoveryEscrowAuthority =>
        authority.kind === "os-keyring",
    );
    const journal: RotationJournalData = {
      v: 1,
      rotation_id: rotationId,
      phase: "converting",
      started_at: new Date().toISOString(),
      updated_at: new Date().toISOString(),
      old_wrap_ids: oldEnvelope.wraps.map((w) => w.id),
      new_wrap_ids: stagedEnvelope.wraps.map((w) => w.id),
      ...(recoveryEscrowAuthority
        ? { recovery_escrow: recoveryEscrowAuthority }
        : {}),
    };
    // HIGH-1 (Codex gate, 2026-08-22): the admission lock now spans the
    // re-check, the journal publish, AND the whole conversion/finalize
    // that follows - not just the publish step. A short lock left the
    // conversion writes reachable by a concurrent exit-import's own
    // recovery-lock-holding pass in the SAME way a short import-side lock
    // did (see importExitBundle's matching comment, exit/bundle.ts): a
    // concurrent open must wait this lock's bound and refuse, never
    // observe or act on a rotation that is still in progress.
    ctx.lease.assertHeld();
    rotationResult = await withExitAdmissionLock(storage, "rotate", async () => {
      if (await hasInterruptedExitImport(storage)) {
        throw new RotationPreflightError(
          // F1/round-3: must match EXIT_RECOVERY_VERB, imported above,
          // AND the exact "--fortress <fortress path>" form - recover
          // takes no ambient path (exit/cli.ts's
          // ExitRecoverFortressPathRequiredError).
          "an exit-import rollback journal exists for this fortress, meaning " +
            `an import started after this rotation's preflight passed; run ` +
            `\`sanctuary exit ${EXIT_RECOVERY_VERB} --fortress <fortress ` +
            "path>` to recover, then retry the rotation"
        );
      }
      await fenced(ctx, () => writeJournal(storage, journal, newMaster));
      // From this point every failure must preserve durable escrow authority:
      // the fortress can only resume forward and the new recovery key may be
      // the operator's sole durable off-host factor.
      journalDurable = true;
      failpoint("journal-converting-written");

      log("Converting: re-encrypting fortress data under the new master...");
      const convertResult = await fenced(ctx, () => walkFortress(ctx, false));
      await fenced(ctx, () => convertAuditEpochs(ctx));
      await fenced(ctx, () => convertCastlePin(ctx, false));
      failpoint("convert-complete");

      // Promote machine escrow only after conversion has durably reached its
      // commit boundary while the rotation journal still forces every reader to
      // resume forward. A failure here leaves the journal and old canonical
      // escrow intact; a hard crash cannot expose the staged key as canonical
      // before the fortress has committed to the new master.
      await fenced(ctx, async () => {
        await recoveryCapture?.commit();
      });
      failpoint("recovery-key-escrow-committed");

      log("Finalizing: promoting the new custody envelope...");
      await fenced(ctx, () => finalize(ctx, journal));

      return {
        rotation_id: rotationId,
        old_wrap_ids: journal.old_wrap_ids,
        new_wrap_ids: journal.new_wrap_ids,
        converted_entries: convertResult.converted,
      };
    });
    ctx.lease.assertHeld();
  } catch (error) {
    rotationFailure = error;
  } finally {
    if (!journalDurable) {
      const cleanup = async (operation: () => Promise<unknown>): Promise<void> => {
        try {
          await operation();
        } catch (error) {
          recoveryCleanupFailures.push(error);
        }
      };
      await cleanup(async () => recoveryCapture?.rollback());
      await cleanup(() => fenced(ctx, () => storage.delete("_meta", PENDING_RECOVERY_KEY)));
      await cleanup(() => fenced(ctx, () => storage.delete("_meta", STAGED_CUSTODY_ENVELOPE_KEY)));
      await cleanup(() => fenced(ctx, () => storage.delete("_meta", STAGED_CUSTODY_SENTINEL_KEY)));
    }
    zeroizeWriterCache(ctx);
  }
  if (recoveryCleanupFailures.length > 0) {
    throw new AggregateError(
      [
        ...(rotationFailure === undefined ? [] : [rotationFailure]),
        ...recoveryCleanupFailures,
      ],
      "master rotation failed and pre-journal recovery state did not roll back cleanly",
      { cause: rotationFailure ?? recoveryCleanupFailures[0] },
    );
  }
  if (rotationFailure !== undefined) throw rotationFailure;
  return rotationResult!;
  } finally {
    newMaster.fill(0);
  }
  } finally {
    oldMaster.fill(0);
  }
}

export interface ResumeRotationOptions {
  storage: StorageBackend;
  fortressPath?: string;
  fortressId: string;
  passphrase: string;
  failpoint?: (point: string) => void;
  log?: (line: string) => void;
  /**
   * Re-adopt a durable recovery escrow named by the authenticated journal.
   * Required only when the interrupted rotation staged an OS-keyring escrow.
   * The adapter must read the candidate back and call `verify` before it may
   * return a mutation that promotes the candidate idempotently.
   */
  adoptRecoveryEscrow?: (
    authority: RotationRecoveryEscrowAuthority,
    verify: (candidate: string) => Promise<boolean>,
    rotationId: string,
  ) => Promise<{ commit(): Promise<void> }>;
  /** Test only: observe the real kernel holder and kill it to prove fencing. */
  __testAfterKernelHolderAcquired?: (pid: number) => void;
  /** Test only: pause after durable Castle-pin publish but before the lease fence. */
  __testAfterCastlePinPublished?: () => void | Promise<void>;
  /** Test only: storage-only fixtures may inject an isolated file capability. */
  __testFortressFiles?: NonNullable<CrossProcessLockLease["stableFortressFiles"]>;
  /** Test only: observe owned secret buffers for exception-path zeroization. */
  __testObserveSecretBuffer?: (
    label: "old-master" | "new-master",
    buffer: Uint8Array,
  ) => void;
  /** Test only: observe/control the shared/exclusive rotation barrier. */
  __testMasterRotationBarrierOptions?: MasterWriteBarrierOptions;
}

/**
 * Resume a crashed rotation FORWARD to completion. Requires only the
 * fortress passphrase. Idempotent at every granularity: converted blobs
 * authenticate under the new key and are skipped; everything else converts.
 */
export async function resumeRotation(
  opts: ResumeRotationOptions
): Promise<RotateMasterResult> {
  return withExclusiveMasterRotationBarrier(
    opts.storage,
    CUSTODY_WRITE_LOCK_NAMESPACE,
    MASTER_ROTATION_BARRIER_NAME,
    () => withCustodyWriteLock(
      opts.storage,
      (lease) => resumeRotationLocked(opts, lease),
      {
        metadata: { owner: "resume-master-rotation" },
        ...(opts.__testAfterKernelHolderAcquired !== undefined
          ? {
              __testAfterKernelHolderAcquired:
                opts.__testAfterKernelHolderAcquired,
            }
          : {}),
      },
    ),
    opts.__testMasterRotationBarrierOptions,
  );
}

async function recoveryCandidateAuthenticatesEnvelope(
  envelope: NonNullable<Awaited<ReturnType<typeof readCustodyEnvelope>>>,
  candidate: string,
  expectedMaster?: Uint8Array,
): Promise<boolean> {
  let recoveryKeyBytes: Uint8Array | undefined;
  let candidateMaster: Uint8Array | undefined;
  try {
    recoveryKeyBytes = fromBase64url(candidate);
    if (recoveryKeyBytes.length !== 32) return false;
    candidateMaster = await unwrapMaster(envelope, {
      recoveryKey: recoveryKeyBytes,
    });
    verifyEnvelopeMac(envelope, candidateMaster);
    return expectedMaster === undefined
      ? true
      : constantTimeEqual(candidateMaster, expectedMaster);
  } catch {
    return false;
  } finally {
    candidateMaster?.fill(0);
    recoveryKeyBytes?.fill(0);
  }
}

async function recoveryCandidateUnlocksRotationEnvelope(
  envelope: NonNullable<Awaited<ReturnType<typeof readCustodyEnvelope>>>,
  newMaster: Uint8Array,
  candidate: string,
): Promise<boolean> {
  return recoveryCandidateAuthenticatesEnvelope(
    envelope,
    candidate,
    newMaster,
  );
}

async function resumeRotationLocked(
  opts: ResumeRotationOptions,
  lease: CrossProcessLockLease,
): Promise<RotateMasterResult> {
  const storage = opts.storage;
  const log = opts.log ?? (() => {});

  if (await runtimeMarkerExists(opts.fortressPath)) {
    throw new RotationResumeError(
      "runtime.json exists, indicating a Sanctuary writer may still be running; " +
        "stop the dashboard and wrapped agents before resuming rotation",
    );
  }

  // N4-ROTATE (coordinator gate, 2026-08-22): same refusal as rotateMaster's
  // preflight - a resume also converts and writes journal-set locations
  // directly, outside the writer guard's chokepoints.
  if (await hasInterruptedExitImport(storage)) {
    throw new RotationResumeError(
      // F1/round-3: must match EXIT_RECOVERY_VERB, imported above, AND
      // the exact "--fortress <fortress path>" form - recover takes no
      // ambient path (exit/cli.ts's ExitRecoverFortressPathRequiredError).
      "an exit-import rollback journal exists for this fortress, meaning an " +
        `import is in progress or pending recovery; run \`sanctuary exit ` +
        `${EXIT_RECOVERY_VERB} --fortress <fortress path>\` to recover, ` +
        "then retry"
    );
  }

  const rawJournal = await storage.read("_meta", ROTATION_JOURNAL_KEY);
  if (!rawJournal) {
    throw new RotationResumeError(
      "Sanctuary: no rotation is in progress on this fortress (no journal)."
    );
  }

  // The NEW master comes from the staged envelope while it exists; after
  // promotion (late finalize crash) it comes from the live envelope.
  const staged = await readCustodyEnvelope(storage, {
    envelopeKey: STAGED_CUSTODY_ENVELOPE_KEY,
  });
  const live = await readCustodyEnvelope(storage);
  if (!live) {
    throw new RotationResumeError(
      "Sanctuary: the live custody envelope is missing mid-rotation. " +
        "Restore _meta from backup before resuming."
    );
  }
  const newMaster = await unwrapMaster(staged ?? live, {
    passphrase: opts.passphrase,
  });
  try {
    opts.__testObserveSecretBuffer?.("new-master", newMaster);
    verifyEnvelopeMac(staged ?? live, newMaster);
    const journal = await readJournal(storage, newMaster);
    if (!journal) {
      throw new RotationResumeError("Sanctuary: rotation journal vanished mid-read.");
    }

    let recoveryEscrow: { commit(): Promise<void> } | undefined;
    if (journal.recovery_escrow) {
      if (!opts.adoptRecoveryEscrow) {
        throw new RotationResumeError(
          "Sanctuary: this interrupted rotation has a staged OS-keyring " +
            "recovery escrow, but this caller cannot adopt it. Resume from the " +
            "Sanctuary CLI on the original host with its OS keyring unlocked.",
        );
      }
      const recoveryEnvelope = staged ?? live;
      try {
        recoveryEscrow = await opts.adoptRecoveryEscrow(
          journal.recovery_escrow,
          (candidate) => recoveryCandidateUnlocksRotationEnvelope(
            recoveryEnvelope,
            newMaster,
            candidate,
          ),
          journal.rotation_id,
        );
      } catch (error) {
        throw new RotationResumeError(
          "Sanctuary: the staged OS-keyring recovery escrow could not be " +
            "authenticated and adopted; refusing to resume without a durable " +
            `new recovery factor (${error instanceof Error ? error.message : String(error)}).`,
        );
      }
    }

    // The OLD master is needed only while converting; the live envelope is
    // still the old one until finalize promotes the staged copy.
    let oldMaster: Uint8Array | undefined;
    try {
      if (journal.phase === "converting") {
        if (!staged) {
          throw new RotationResumeError(
            "Sanctuary: rotation journal says 'converting' but the staged envelope " +
              "is missing. Restore _meta from backup before resuming."
          );
        }
        oldMaster = await unwrapMaster(live, { passphrase: opts.passphrase });
        opts.__testObserveSecretBuffer?.("old-master", oldMaster);
        verifyEnvelopeMac(live, oldMaster);
      } else {
        // finalizing: all data is already under the new master.
        oldMaster = new Uint8Array(newMaster); // placeholder; never matches old data
        opts.__testObserveSecretBuffer?.("old-master", oldMaster);
      }

      const ctx: Ctx = {
    storage,
    ...(opts.fortressPath !== undefined ? { fortressPath: opts.fortressPath } : {}),
    fortressId: opts.fortressId,
    aadIdentifiers: buildAadIdentifiers(opts.fortressId, opts.fortressPath),
    oldMaster,
    newMaster,
    rotationId: journal.rotation_id,
    failpoint: opts.failpoint ?? (() => {}),
    log,
    writerCache: new Map(),
    lease,
    ...(opts.__testAfterCastlePinPublished
      ? { __testAfterCastlePinPublished: opts.__testAfterCastlePinPublished }
      : {}),
    ...(opts.__testFortressFiles ? { __testFortressFiles: opts.__testFortressFiles } : {}),
      };
      try {
    // F1 (coordinator gate, 2026-08-22): re-check immediately before
    // resuming conversion, not only the top-of-function preflight above -
    // an exit-import can start and journal between resumeRotation being
    // invoked and reaching this point. HIGH-1 (Codex gate, 2026-08-22):
    // the admission lock now spans the re-check AND the whole remaining
    // conversion/finalize, not only the check - same reason as
    // rotateMaster's matching widened lock (a short lock left the
    // conversion writes reachable by a concurrent exit-import's own
    // recovery pass).
    ctx.lease.assertHeld();
    const result = await withExitAdmissionLock(storage, "resume", async () => {
      if (await hasInterruptedExitImport(storage)) {
        throw new RotationResumeError(
          // F1/round-3: must match EXIT_RECOVERY_VERB, imported above,
          // AND the exact "--fortress <fortress path>" form - recover
          // takes no ambient path (exit/cli.ts's
          // ExitRecoverFortressPathRequiredError).
          "an exit-import rollback journal exists for this fortress, " +
            `meaning an import started after this resume began; run ` +
            `\`sanctuary exit ${EXIT_RECOVERY_VERB} --fortress <fortress ` +
            "path>` to recover, then retry the resume"
        );
      }
      let converted = 0;
      if (journal.phase === "converting") {
        log("Resuming: converting remaining fortress data...");
        converted = (await fenced(ctx, () => walkFortress(ctx, false))).converted;
        await fenced(ctx, () => convertAuditEpochs(ctx));
        await fenced(ctx, () => convertCastlePin(ctx, false));
      }
      // The authenticated journal keeps the staging authority durable across
      // crashes. Promote it only after conversion is complete, and before the
      // live envelope can become authoritative. The adapter handles both a
      // still-present staging item and a prior crash after canonical promotion.
      await fenced(ctx, async () => {
        await recoveryEscrow?.commit();
      });
      log("Resuming: finalizing...");
      await fenced(ctx, () => finalize(ctx, journal));
      return {
        rotation_id: journal.rotation_id,
        old_wrap_ids: journal.old_wrap_ids,
        new_wrap_ids: journal.new_wrap_ids,
        converted_entries: converted,
      };
    });
    ctx.lease.assertHeld();
    return result;
      } finally {
        zeroizeWriterCache(ctx);
      }
    } finally {
      oldMaster?.fill(0);
    }
  } finally {
    newMaster.fill(0);
  }
}
