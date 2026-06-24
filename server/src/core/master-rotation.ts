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

import { readFile, writeFile } from "node:fs/promises";
import { join, resolve } from "node:path";

import type { StorageBackend } from "../storage/interface.js";
import {
  encrypt,
  decrypt,
  type EncryptedPayload,
} from "./encryption.js";
import { deriveNamespaceKey, derivePurposeKey } from "./key-derivation.js";
import { generateRandomKey } from "./random.js";
import { hmacSha256 } from "./hashing.js";
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
  envelopeEpochOf,
} from "./master-custody.js";
import { canonicalJson } from "../audit/chain.js";
import {
  AuditLog,
  deriveAuditEpochKeys,
  readAuditEpochEntries,
  writeAuditEpochRecord,
  AUDIT_EPOCH_KEYS_KEY,
} from "../operational/audit-log.js";
import { writeEpochWitness } from "./anti-rollback.js";
import {
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

export class RotationResumeError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "RotationResumeError";
  }
}

// ── Journal ─────────────────────────────────────────────────────────

const JOURNAL_MAC_DOMAIN = "sanctuary.custody-rotation-journal.v1\n";
const JOURNAL_MAC_PURPOSE = "custody-rotation-journal-mac";

export type RotationPhase = "converting" | "finalizing";

interface RotationJournalData {
  v: 1;
  rotation_id: string;
  phase: RotationPhase;
  started_at: string;
  updated_at: string;
  /** Envelope/wrap identifiers only — NEVER key material. */
  old_wrap_ids: string[];
  new_wrap_ids: string[];
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

  _reputation: { kind: "purpose-encrypted", infos: ["l4-reputation"] },
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
    infos: ["federation-trust-root"],
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
  _sdw_meta: { kind: "unsupported", reason: UNSUPPORTED_DEFERRAL },
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
  | "rollback-freeze"; // anti-rollback freeze marker → restamp under new master

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

function classifyMetaKey(key: string): MetaKeyClass | null {
  switch (key) {
    case "key-params":
    case "recovery-key-hash":
      return "legacy-marker";
    case CUSTODY_ENVELOPE_KEY:
    case CUSTODY_SENTINEL_KEY:
      return "custody";
    case ROTATION_JOURNAL_KEY:
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
    verify: (entered: string) => Promise<boolean>
  ) => Promise<boolean>;
  /** Test seam: crash injection. Throw inside to simulate a hard kill. */
  failpoint?: (point: string) => void;
  /** Operator-facing progress lines (CLI: stderr). */
  log?: (line: string) => void;
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
      await ctx.storage.write(
        "_identities",
        key,
        stringToBytes(encryptToJson(rotated, newKey))
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
        await ctx.storage.write(namespace, key, result.bytes);
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
        await ctx.storage.write(
          namespace,
          key,
          stringToBytes(JSON.stringify(next))
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
    const cls = classifyMetaKey(key);
    if (cls === null) {
      throw new RotationPreflightError(
        `_meta/${key} is not a record this rotation engine recognizes; ` +
          "refusing to rotate around it"
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
      await ctx.storage.write("_meta", key, next);
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
        await ctx.storage.write("_audit_checkpoints", key, next);
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
      await writeAuditEpochRecord(ctx.storage, newEpochKeys, [
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
      ]);
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
  const pinPath = join(ctx.fortressPath, PIN_FILE);
  let raw: string;
  try {
    raw = await readFile(pinPath, "utf-8");
  } catch {
    return "absent";
  }
  const payload = parseEncryptedPayload(stringToBytes(raw));
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
    await writeFile(pinPath, JSON.stringify(encrypt(seed, ctx.newMaster)), {
      mode: 0o600,
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
    await writeJournal(
      ctx.storage,
      { ...journal, phase: "finalizing", updated_at: new Date().toISOString() },
      ctx.newMaster
    );
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
    await writeCustodyEnvelope(
      ctx.storage,
      { ...staged, epoch: newEpoch, epoch_id: ctx.rotationId },
      ctx.newMaster
    );
    ctx.failpoint("envelope-promoted");
    await ctx.storage.delete("_meta", STAGED_CUSTODY_ENVELOPE_KEY);
    await ctx.storage.delete("_meta", STAGED_CUSTODY_SENTINEL_KEY);
    ctx.failpoint("staged-deleted");
  } else {
    // Late-finalize resume: the live envelope is already promoted but may
    // predate this epoch stamp. Re-stamp it idempotently so a crash between
    // promotion and witness-write still lands a consistent epoch.
    const live = await readCustodyEnvelope(ctx.storage);
    if (live && envelopeEpochOf(live) < newEpoch) {
      await writeCustodyEnvelope(
        ctx.storage,
        { ...live, epoch: newEpoch, epoch_id: ctx.rotationId },
        ctx.newMaster
      );
    }
  }

  // Advance the monotonic epoch witness to the new epoch (force: the rotation
  // is the authority on its own epoch; a concurrent stale witness must not
  // block a legitimate rotation from raising the floor).
  await writeEpochWitness(
    ctx.storage,
    ctx.newMaster,
    {
      epoch: newEpoch,
      epoch_id: ctx.rotationId,
      witnessed_at: new Date().toISOString(),
    },
    { force: true }
  );
  ctx.failpoint("epoch-witness-advanced");

  // Legacy markers would re-derive the OLD master — the dual-path divergence
  // generator this lane exists to kill. Delete them (audited below).
  await ctx.storage.delete("_meta", "key-params");
  await ctx.storage.delete("_meta", "recovery-key-hash");
  ctx.failpoint("legacy-markers-deleted");

  // Audit the rotation under the NEW master (old entries decrypt via the
  // epoch record; the chain verifies across the boundary). Envelope ids
  // only — never key material (CLAUDE.md #6).
  const auditLog = new AuditLog(ctx.storage, ctx.newMaster);
  await auditLog.appendCritical({
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
  });
  await auditLog.flush();
  ctx.failpoint("rotation-audited");

  await ctx.storage.delete("_meta", ROTATION_JOURNAL_KEY);
}

// ── Public entry points ─────────────────────────────────────────────

export async function rotateMaster(
  opts: RotateMasterOptions
): Promise<RotateMasterResult> {
  const storage = opts.storage;
  const log = opts.log ?? (() => {});
  const failpoint = opts.failpoint ?? (() => {});

  if (await storage.read("_meta", ROTATION_JOURNAL_KEY)) {
    throw new RotationPreflightError(
      "a rotation is already in progress on this fortress; resume it with " +
        "`sanctuary rotate-master --resume`"
    );
  }

  // Clean orphaned staged artifacts from a pre-journal crash (the fortress
  // is fully old-keyed; the previously disclosed recovery key never became
  // active). Loud, so a stale disclosure is never silently trusted.
  if (await storage.read("_meta", STAGED_CUSTODY_ENVELOPE_KEY)) {
    log(
      "Note: removing a stale staged custody envelope from an earlier rotation\n" +
        "attempt that never began converting. Any recovery key disclosed during\n" +
        "that attempt is DEAD and unlocks nothing — discard it; this run will\n" +
        "mint and verify a fresh one."
    );
    await storage.delete("_meta", STAGED_CUSTODY_ENVELOPE_KEY);
    await storage.delete("_meta", STAGED_CUSTODY_SENTINEL_KEY);
  }

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
  verifyEnvelopeMac(oldEnvelope, oldMaster);

  const newMaster = generateRandomKey();
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
  };

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
      const auditPreflight = new AuditLog(storage, oldMaster);
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
      await wrapMasterWithPassphrase(newMaster, opts.passphrase, {
        verified: true,
      }),
    ];
    const recoveryKeyBytes = generateRandomKey();
    const recoveryKey = toBase64url(recoveryKeyBytes);
    wraps.push(
      wrapMasterWithRecoveryKey(newMaster, recoveryKeyBytes, { verified: false })
    );
    recoveryKeyBytes.fill(0);
    if (opts.keychainKey) {
      wraps.push(
        wrapMasterWithKeychainKey(newMaster, opts.keychainKey, { verified: true })
      );
    }
    let stagedEnvelope = await writeCustodyEnvelope(
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
      }
    );
    failpoint("staged-envelope-written");

    // ── NEW recovery key: disclose + re-entry verify (#496 rules). ──
    const captured = await opts.captureRecoveryKey(recoveryKey, async (entered) => {
      try {
        stagedEnvelope = await verifyRecoveryWrapByReentry(
          storage,
          stagedEnvelope,
          entered,
          {
            envelopeKey: STAGED_CUSTODY_ENVELOPE_KEY,
            sentinelKey: STAGED_CUSTODY_SENTINEL_KEY,
          }
        );
        return true;
      } catch {
        return false;
      }
    });
    if (!captured) {
      await storage.delete("_meta", STAGED_CUSTODY_ENVELOPE_KEY);
      await storage.delete("_meta", STAGED_CUSTODY_SENTINEL_KEY);
      throw new RotationPreflightError(
        "recovery-key capture was not completed; rotation requires a " +
          "verified recovery wrap before any data is touched"
      );
    }

    // Two-factor floor on the ROTATED fortress, enforced before conversion.
    if (countVerifiedWraps(stagedEnvelope) < CUSTODY_FLOOR_WRAPS) {
      await storage.delete("_meta", STAGED_CUSTODY_ENVELOPE_KEY);
      await storage.delete("_meta", STAGED_CUSTODY_SENTINEL_KEY);
      throw new RotationPreflightError(
        `the rotated envelope would hold fewer than ${CUSTODY_FLOOR_WRAPS} verified ` +
          "factors; rotation must never weaken custody below the floor"
      );
    }

    // Audit the start under the OLD master (this entry stays readable after
    // rotation via the audit epoch record).
    const oldAudit = new AuditLog(storage, oldMaster);
    await oldAudit.appendCritical({
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
    });
    await oldAudit.flush();

    // ── Point of no return: journal on, boots blocked, convert. ──
    const journal: RotationJournalData = {
      v: 1,
      rotation_id: rotationId,
      phase: "converting",
      started_at: new Date().toISOString(),
      updated_at: new Date().toISOString(),
      old_wrap_ids: oldEnvelope.wraps.map((w) => w.id),
      new_wrap_ids: stagedEnvelope.wraps.map((w) => w.id),
    };
    await writeJournal(storage, journal, newMaster);
    failpoint("journal-converting-written");

    log("Converting: re-encrypting fortress data under the new master...");
    const convertResult = await walkFortress(ctx, false);
    await convertAuditEpochs(ctx);
    await convertCastlePin(ctx, false);
    failpoint("convert-complete");

    log("Finalizing: promoting the new custody envelope...");
    await finalize(ctx, journal);

    return {
      rotation_id: rotationId,
      old_wrap_ids: journal.old_wrap_ids,
      new_wrap_ids: journal.new_wrap_ids,
      converted_entries: convertResult.converted,
    };
  } finally {
    zeroizeWriterCache(ctx);
    oldMaster.fill(0);
    newMaster.fill(0);
  }
}

export interface ResumeRotationOptions {
  storage: StorageBackend;
  fortressPath?: string;
  fortressId: string;
  passphrase: string;
  failpoint?: (point: string) => void;
  log?: (line: string) => void;
}

/**
 * Resume a crashed rotation FORWARD to completion. Requires only the
 * fortress passphrase. Idempotent at every granularity: converted blobs
 * authenticate under the new key and are skipped; everything else converts.
 */
export async function resumeRotation(
  opts: ResumeRotationOptions
): Promise<RotateMasterResult> {
  const storage = opts.storage;
  const log = opts.log ?? (() => {});
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
  verifyEnvelopeMac(staged ?? live, newMaster);
  const journal = await readJournal(storage, newMaster);
  if (!journal) {
    throw new RotationResumeError("Sanctuary: rotation journal vanished mid-read.");
  }

  // The OLD master is needed only while converting; the live envelope is
  // still the old one until finalize promotes the staged copy.
  let oldMaster: Uint8Array;
  if (journal.phase === "converting") {
    if (!staged) {
      throw new RotationResumeError(
        "Sanctuary: rotation journal says 'converting' but the staged envelope " +
          "is missing. Restore _meta from backup before resuming."
      );
    }
    oldMaster = await unwrapMaster(live, { passphrase: opts.passphrase });
    verifyEnvelopeMac(live, oldMaster);
  } else {
    // finalizing: all data is already under the new master.
    oldMaster = new Uint8Array(newMaster); // placeholder; never matches old data
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
  };
  try {
    let converted = 0;
    if (journal.phase === "converting") {
      log("Resuming: converting remaining fortress data...");
      converted = (await walkFortress(ctx, false)).converted;
      await convertAuditEpochs(ctx);
      await convertCastlePin(ctx, false);
    }
    log("Resuming: finalizing...");
    await finalize(ctx, journal);
    return {
      rotation_id: journal.rotation_id,
      old_wrap_ids: journal.old_wrap_ids,
      new_wrap_ids: journal.new_wrap_ids,
      converted_entries: converted,
    };
  } finally {
    zeroizeWriterCache(ctx);
    oldMaster.fill(0);
    newMaster.fill(0);
  }
}
