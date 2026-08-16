/**
 * Sanctuary MCP Server — L2 Operational Isolation: Audit Log
 *
 * Append-only log of all sovereignty-relevant operations.
 * Stored encrypted under L1 sovereignty.
 *
 * Every tool invocation that modifies state, generates proofs,
 * or records reputation produces an audit entry. The human principal
 * can inspect what their agent has done.
 */

import { lstat, mkdir, open, readFile, readdir, rm, link, stat, unlink } from "node:fs/promises";
import { readFileSync, type Stats } from "node:fs";
import { execFileSync } from "node:child_process";
import { randomBytes } from "node:crypto";
import { dirname, join } from "node:path";
import { uptime as osUptime } from "node:os";
import { AsyncLocalStorage } from "node:async_hooks";
import type {
  FilesystemStorageCapabilities,
  StorageBackend,
} from "../storage/interface.js";
import { chownCreatedDirChain, writeFileCustody } from "../storage/custody-fs.js";
import { encrypt, decrypt, type EncryptedPayload } from "../core/encryption.js";
import { derivePurposeKey } from "../core/key-derivation.js";
import { hmacSha256 } from "../core/hashing.js";
import { stringToBytes, bytesToString, toBase64url, fromBase64url } from "../core/encoding.js";
import {
  AUDIT_CHAIN_GENESIS,
  AUDIT_CHAIN_SCHEMA_VERSION,
  AUDIT_CHECKPOINT_SCHEMA_VERSION,
  AUDIT_EPOCH_KEYS_KEY,
  AUDIT_HEAD_ANCHOR_KEY,
  AUDIT_ROTATION_ANCHOR_MARKER,
  isAuditRotationAnchorEnvelope,
  type AuditCheckpointRecord,
  type AuditCheckpointSignature,
  type AuditCheckpointSigningPayload,
  canonicalJson,
  computeAuditEntryHash,
  computeAuditRoot,
  isAuditCheckpointRecord,
  sha256Hex,
  verifyCheckpointSignature,
} from "../audit/chain.js";
import { createFortressCheckpointIdentityBinding } from "../audit/checkpoint-identity.js";
import type { PluginContribution } from "../substrate/attribution.js";

export interface AuditEntry {
  timestamp: string;
  layer: "l1" | "l2" | "l3" | "l4";
  operation: string;
  identity_id: string;
  result: "success" | "failure";
  details?: Record<string, unknown>;
  contributors?: PluginContribution[];
}

/** One chained, decrypted, verified entry handed to a streaming consumer. */
export interface VerifiedChainItem {
  sequence: number;
  entry_hash: string;
  entry: AuditEntry;
}

/**
 * Streaming consumer of the verified hash chain (the daemon-OOM-on-a-large-log
 * bound). The full decrypted chain is NEVER simultaneously resident: each
 * chained entry is decrypted + hash-checked, handed to `onEntry`, and then
 * released. The contiguous chain walk + anchor/checkpoint verification complete
 * AFTER the stream, before `streamVerifiedChain` resolves; in strict mode it
 * throws on any failure, so a consumer that commits its fold only after the
 * await returns clean never commits over an unverified chain (see
 * {@link AuditLog.streamVerifiedChain}). Consumers fold their result
 * incrementally (Merkle leaves, per-rule counters, workload replay) instead of
 * materializing the whole `AuditEntry[]`.
 *
 * `reset` is the read-consistency contract: the verified pass runs under a
 * torn-read retry loop, so a pass that observed a transient mid-mutation state
 * is discarded and re-run. `reset()` fires before such a re-run so the consumer
 * drops everything it accumulated from the abandoned pass and starts clean; the
 * entries delivered between the LAST `reset()` (or the start) and a clean return
 * are exactly the entries of the single accepted verified pass. A consumer that
 * does not implement `reset` MUST be commutative-and-idempotent over re-delivery
 * (none of the three production consumers are, so they all implement it).
 */
export interface VerifiedChainConsumer {
  onEntry: (item: VerifiedChainItem) => void;
  reset?: () => void;
}

export type AuditEntryInput = Omit<AuditEntry, "timestamp"> & {
  timestamp?: string;
};

export interface PersistedAuditEnvelopeV2 {
  schema_version: typeof AUDIT_CHAIN_SCHEMA_VERSION;
  sequence: number;
  prev_hash: string;
  entry_hash: string;
  timestamp: string;
  encrypted_payload_bytes: string;
}

export type AuditIntegrityFindingKind =
  | "storage_unavailable"
  | "entry_unreadable"
  | "entry_malformed"
  | "entry_hash_mismatch"
  | "entry_decrypt_failed"
  | "sequence_gap_or_reorder"
  | "prev_hash_mismatch"
  | "legacy_anchor_missing"
  | "legacy_anchor_mismatch"
  | "rotation_anchor_missing"
  | "rotation_anchor_invalid"
  | "tail_anchor_missing"
  | "tail_anchor_invalid"
  | "checkpoint_malformed"
  | "checkpoint_root_mismatch"
  | "checkpoint_signature_mismatch"
  | "checkpoint_signature_unverifiable"
  | "checkpoint_signature_embedded_key_untrusted"
  // F2 Option A (writer-split) boundary findings. See the module doc comment
  // near AUDIT_SPLIT_BOUNDARY_DIRNAME.
  //  - split_boundary_invalid: a boundary record is PRESENT but fails MAC
  //    authentication (tampered/forged/wrong-key). Fail closed: the load does
  //    NOT filter the sealed region and does NOT let a truncated suffix be
  //    TOFU-blessed as a rotation cut.
  //  - split_boundary_missing: no boundary record, but a durable migration
  //    marker (a `_audit-daemon*` namespace) proves the split migration ran.
  //    An absent boundary in that state is a deletion, not a never-migrated
  //    fortress, so it is a finding (fail closed), not a silent full walk.
  //  - sealed_prefix_incomplete: with a VALID boundary, the sealed legacy
  //    region's V2 entry files (seq <= sealed_tip) are not a gap-free run
  //    ending exactly at sealed_tip. Detected from the directory LISTING
  //    (no decrypt), so it catches deletion of sealed entries even when their
  //    contents are unreadable at operator privilege (the F2 cross-uid case).
  | "split_boundary_invalid"
  | "split_boundary_missing"
  | "sealed_prefix_incomplete";

export interface AuditIntegrityFinding {
  kind: AuditIntegrityFindingKind;
  message: string;
  key?: string;
  sequence?: number;
  expected?: string | number;
  actual?: string | number;
}

export interface AuditCreateOwner {
  uid: number;
  gid: number;
}

type AuditLockFileHandle = Awaited<ReturnType<typeof open>>;

/**
 * What a checkpoint public-key resolver may hand back for one `signer_kid`:
 * a single key, the signer's full authenticated key set (current key plus
 * verified rotation-chain predecessors, so pre-rotation checkpoints keep
 * verifying after a rotation), or `undefined`/an empty set for "this signer
 * is unknown", which the verify path reports as an integrity finding.
 */
export type AuditCheckpointKeyResolution =
  | string
  | Uint8Array
  | ReadonlyArray<string | Uint8Array>
  | undefined;

export interface AuditLogConfig {
  /** Maximum total size of stored audit entries in bytes. Default: 100 MB. */
  maxTotalSizeBytes?: number;
  /** Maximum number of stored audit entry files to retain. Default: 100_000. */
  maxEntries?: number;
  /**
   * Upper bound on the number of decrypted entries the instance holds in memory
   * (the recent-entry window in `this.entries` / `this.chainEntries`). This is
   * DECOUPLED from `maxEntries` (the on-disk retention cap): the persisted log
   * and every full re-read stay complete regardless of this value, which only
   * bounds RAM growth on a long-running process. Defaults to `maxEntries` (never
   * below {@link MIN_IN_MEMORY_ENTRY_FLOOR}) so behavior is unchanged unless set.
   * Exposed primarily so the daemon can cap steady-state RAM below the (large)
   * disk cap, and so tests can drive the in-memory trim independently of on-disk
   * rotation.
   */
  maxInMemoryEntries?: number;
  /** Verify chain failures by throwing (strict) or surfacing findings (lenient). */
  integrityMode?: "strict" | "lenient";
  /**
   * F2 Option A (fortress audit store split by writer): whether this
   * instance's load path should consult the on-disk "split boundary" record
   * (see the module doc comment near {@link AUDIT_SPLIT_BOUNDARY_DIRNAME})
   * written by {@link migrateFortressAuditStoreSplit} et al.
   *
   * Defaults to `true` so every EXISTING call site gets the fix for free:
   * on a fortress that never had a boundary written (the overwhelming
   * majority, meaning anything that never ran a root Castle Wall daemon),
   * the check is a single cheap file read that comes back "absent" and
   * changes NOTHING about today's behavior.
   *
   * Set to `false` for an `AuditLog` instance that is itself the boundary's
   * *target* namespace re-mapped onto a DIFFERENT physical store (the
   * daemon's own `_audit-daemon` chain via `createDaemonAuditLog`): that
   * instance's local sequence numbers start fresh at 1 and must never be
   * compared against the legacy `_audit` chain's sealed tip sequence.
   */
  consultSplitBoundary?: boolean;
  /** Write a checkpoint after this many critical appends. Default: 100. */
  checkpointInterval?: number;
  /**
   * Typed identity signing bridge for checkpoint records. Optional in the
   * CONFIG only as an injection seam (tests, embedders with their own key
   * custody): when omitted, the constructor derives the production fortress
   * signer from its own required arguments (IC-05), so no call site can
   * silently opt out of checkpoint signing by forgetting a config field.
   */
  checkpointSigner?: (
    payload: AuditCheckpointSigningPayload
  ) => Promise<AuditCheckpointSignature | null>;
  /**
   * Resolve known checkpoint signing keys by signer_kid. May return a single
   * key or the signer's full authenticated key set (current key plus
   * rotation-chain predecessors), synchronously or as a promise. Same
   * injection-seam contract as `checkpointSigner`: omitted means the
   * constructor-derived fortress resolver, not "no resolution".
   */
  checkpointPublicKeyResolver?: (
    signerKid: string
  ) =>
    | AuditCheckpointKeyResolution
    | Promise<AuditCheckpointKeyResolution>;
  /**
   * Explicit self-check opt-in for checkpoint-embedded public keys.
   * Embedded keys prove record self-consistency only, not signer identity.
   */
  trustEmbeddedCheckpointPublicKeys?: boolean;
  /** Optional in-process subscribers notified when audit-chain integrity fails. */
  integrityAnomalySubscribers?: AuditIntegrityAnomalySubscriber[];
  /**
   * Create-with-fchown owner for filesystem artifacts this AuditLog creates
   * outside the StorageBackend contract. Today that is the cross-process
   * `.audit-write.lock` file: when set, the owner is applied on the open temp
   * descriptor before the lock is linked into visibility, mirroring
   * `writeFileCustody`'s descriptor-first owner discipline.
   */
  createOwner?: AuditCreateOwner;
  /**
   * Test seam for the descriptor owner operation. Production defaults to
   * `FileHandle.chown`; callers should set only `createOwner`.
   */
  createOwnerChown?: (
    handle: AuditLockFileHandle,
    owner: AuditCreateOwner,
  ) => Promise<void>;
  /**
   * Test seam ONLY for the namespace-directory create-with-fchown chain;
   * production uses `chownCreatedDirChain` (storage/custody-fs.ts); callers
   * should set only `createOwner`.
   */
  createOwnerChownDirChain?: (
    firstCreated: string,
    leafDir: string,
    owner: { uid: number; gid: number },
  ) => Promise<void>;
  /**
   * Test seam ONLY for the pre-existing-namespace-chain ownership check
   * (PR #1084 gate F2); production uses `fs.lstat`. Lets tests simulate a
   * root-owned or foreign-owned chain without privileges; callers should set
   * only `createOwner`.
   */
  namespaceDirLstat?: (path: string) => Promise<{
    uid: number;
    gid: number;
    isSymbolicLink(): boolean;
    isDirectory(): boolean;
  }>;
  /**
   * Backstop interval (ms) between full on-disk re-verifications on the eager
   * read path. Defaults to {@link DEFAULT_AUDIT_EAGER_REVERIFY_INTERVAL_MS}
   * (30s); also overridable via the `AUDIT_EAGER_REVERIFY_INTERVAL_MS` env var.
   * Exposed primarily so tests can drive the backstop deterministically. The
   * sentinel fingerprint check (event-driven out-of-band detection) is NOT
   * gated by this interval; this is only the residual same-length+mtime backstop.
   */
  eagerReverifyIntervalMs?: number;
  /**
   * Age bound (ms) past which an id-less (0-byte) stale audit-write lock, and an
   * orphaned `.acquire.*.tmp` acquire-temp, are considered crash litter and
   * swept. Defaults to {@link AUDIT_WRITE_LOCK_IDLESS_STALE_MS} (10 min); also
   * overridable via the `AUDIT_WRITE_LOCK_IDLESS_STALE_MS` env var. Exposed so
   * tests can drive the 0-byte-age and orphan-temp-GC branches deterministically
   * on a freshly-booted host (where a real 10-minute mtime cannot be assumed to
   * post-date boot). Never breaks a content-bearing lock; only the id-less
   * fallback and the acquire-temp sweep consult it.
   */
  idlessStaleLockMs?: number;
  /**
   * Maximum time (ms) this process may hold the cross-process audit-write lock
   * around one critical section. Defaults to 30s. Must be a positive finite
   * number; invalid values fail construction rather than silently weakening the
   * recovery bound.
   */
  writeLockHoldDeadlineMs?: number;
  /**
   * Same-process, same-boot lock age (ms) after which a later acquire may force
   * release of its own stale lock. Defaults to 60s and must be strictly greater
   * than the resolved write-lock hold deadline, so a legitimate holder has a
   * chance to abandon and release before this recovery edge fires.
   */
  selfHeldStaleLockMs?: number;
}

export interface AuditIntegrityAnomalyEvent {
  type: "audit_integrity_finding";
  severity: "P1";
  finding_count: number;
  findings: AuditIntegrityFinding[];
  observed_at: string;
}

export type AuditIntegrityAnomalySubscriber = (
  event: AuditIntegrityAnomalyEvent
) => void | Promise<void>;

export type AuditWriteLockRecoveryReason =
  | "write_lock_hold_deadline_exceeded"
  | "self_held_stale_forced_release";

export interface AuditWriteLockRecoveryEvent {
  reason: AuditWriteLockRecoveryReason;
  lockPath: string;
}

export type AuditWriteLockRecoveryListener = (
  event: AuditWriteLockRecoveryEvent
) => void;

interface AuditWriteLockAbortSignal {
  aborted: boolean;
}

const DEFAULT_MAX_TOTAL_SIZE_BYTES = 100 * 1024 * 1024; // 100 MB
const DEFAULT_MAX_ENTRIES = 100_000;
const DEFAULT_CHECKPOINT_INTERVAL = 100;
// In-memory retention bound for the decrypted recent-entry window the instance
// holds in `this.entries` / `this.chainEntries`. On-disk rotation prunes the
// PERSISTED log (authoritative), but the in-memory arrays were never trimmed:
// every `append()` pushed one more decrypted entry forever, so a long-running
// daemon's heap grew without bound (the full-mode `castle-wall daemon` OOM,
// ~4GB after a few minutes of heartbeat appends). These arrays only ever serve
// recent-entry reads (`query` returns `slice(-limit)`, default 50) and the
// chained-tail view (which re-reads the full chain from disk first), so there is
// no correctness need to hold more than the recent window in RAM. We cap the
// in-memory window at the on-disk entry cap (so any log within its disk budget
// is byte-for-byte unchanged) but never below a small floor (so a tiny
// `maxEntries` test/config still keeps a usable recent window in memory while
// still bounding growth). The disk remains the source of truth for full reads.
const MIN_IN_MEMORY_ENTRY_FLOOR = 256;
const AUDIT_NAMESPACE = "_audit";
const AUDIT_CHECKPOINT_NAMESPACE = "_audit_checkpoints";
const AUDIT_META_NAMESPACE = "_meta";
// F3: reserved storage key for the single MAC-authenticated rotation checkpoint.
// Stored alongside the (optionally-signed) checkpoint records but addressed by a
// fixed key that does NOT match the `audit-checkpoint-`/`legacy-anchor-` prefixes
// the checkpoint readers list on, so it never collides with those scans.
const AUDIT_ROTATION_ANCHOR_KEY = "__rotation_anchor";
// AUDIT_HEAD_ANCHOR_KEY ("__head_anchor") is imported from the pure shared
// `audit/checkpoint-shape.ts` (G1/G5) so this runtime and the raw CLI
// exporter's control-key allowlist cannot drift.
const AUDIT_HEAD_ANCHOR_ESTABLISHED_KEY = "audit-head-anchor-established-v1";
// F2 Option A (Finding 1, adversarial gate 2026-07-15): an OPERATOR-provenance
// marker that records "the operator has written at least one POST-SPLIT suffix
// head anchor (an entry above the sealed tip)". It is a NEW key that no pre-#929
// daemon ever wrote, and the post-#929 daemon's `_meta` is remapped to
// `_audit-daemon_meta`, so its presence is UNSPOOFABLY operator-established. It
// discriminates the two states that otherwise look identical from surviving
// disk (chain == sealed region only + an unreadable `__head_anchor`): a genuine
// just-migrated armed box (marker ABSENT, benign, suppress) versus a fortress
// whose post-split suffix was ERASED and whose anchor was made unreadable to
// launder it (marker PRESENT, tamper, fail closed). Without it, the unreadable
// legacy-anchor suppression could hide a full-suffix truncation.
//
// RESIDUAL (documented, irreducible at the filesystem-durability tier): a
// directory-write attacker who ALSO deletes this operator-owned marker returns
// `read` -> null -> "not established" -> suppression, re-opening the full-suffix
// laundering. This is (a) strictly narrower than the pre-fix single-chmod heal
// (the marker raises the attack from "hide the anchor" to "hide the anchor AND
// erase the whole suffix AND delete this marker"), and (b) the SAME co-deletable-
// witness class the module already accepts for the whole-log case
// (`AUDIT_HEAD_ANCHOR_ESTABLISHED_KEY` + `isEstablishedAuditStore`: delete every
// entry + that marker + all checkpoints and a truncation-to-empty likewise reads
// as a legitimate first boot). No non-co-deletable on-disk witness of a suffix
// can exist once the entries, checkpoints, anchor, and marker all live in the
// operator-writable store; closing it requires boot-anchored / externally-
// attested state (Secure Enclave / TPM / remote attestation), which is a
// separate build and out of scope for the mint unblock.
const AUDIT_POST_SPLIT_SUFFIX_ESTABLISHED_KEY =
  "audit-post-split-suffix-established-v1";
// AUDIT_ROTATION_ANCHOR_MARKER ("__sanctuary_audit_rotation_anchor_v1") is
// imported from the pure shared `audit/checkpoint-shape.ts` (re-gate round 3)
// so this runtime's anchor shape and the raw CLI exporter's cannot drift.
const AUDIT_HEAD_ANCHOR_MARKER = "__sanctuary_audit_head_anchor_v1";
// Domain-separated MAC over the rotation-anchor record. The anchor records the
// authenticated lowest-surviving sequence + its prev_hash after a prune, so a
// post-cut deletion is still detectable while a legitimate rotation verifies
// cleanly. The MAC ALWAYS authenticates (master-key derived) — unlike the
// optional Ed25519 checkpoint signer, which may be null.
const AUDIT_ROTATION_ANCHOR_MAC_DOMAIN = "sanctuary.audit-rotation-anchor.v1\n";
const AUDIT_HEAD_ANCHOR_MAC_DOMAIN = "sanctuary.audit-head-anchor.v1\n";

// ── F2 Option A: fortress audit store split by writer ──────────────────────
//
// On an armed box the root Castle Wall daemon and the operator CLI both wrote
// into this SAME `_audit` store; the daemon's root-owned entries are
// unreadable by the (non-root) operator uid, so `ensureLoaded()` threw
// `AuditIntegrityError` on every armed box with any daemon history, and
// file-grant mint (which requires a durable audit write) failed closed
// (drill-verified 2026-07-14, finding F2). The fix is NOT to weaken this
// check (that was the rejected Option C: it would blind the operator's own
// integrity check to half of its own store); it is store separation: going
// forward the daemon writes its own SEPARATE chain under `_audit-daemon`
// (see operational/audit-store-split.ts) while the operator keeps writing
// this `_audit` chain, completely untouched. (Historical note: the daemon
// chain's files were originally root-owned; since the fortress-ownership
// create-with-fchown work (spec 2026-07-30, #1056) a root daemon hands its
// chain's files to the fortress owner at creation via `createOwner`, so the
// separation is by NAMESPACE and writer, not by file ownership.)
//
// The one remaining problem is HISTORY: an already-armed fortress has root
// entries interleaved THROUGHOUT its existing single hash chain (the chain
// links sequentially across every writer: `entry_hash` covers `prev_hash`,
// so a daemon entry cannot be surgically extracted without invalidating
// every operator entry's hash link on either side of it). The migration
// therefore never touches a single existing byte of `_audit`: it freezes
// the ENTIRE existing chain as a sealed legacy segment by writing a
// MAC-authenticated "split boundary" record (a root-run migration can read
// the whole legacy chain, since root bypasses ordinary file-permission
// checks) that captures the chain's tip (sequence + entry_hash) at the
// moment of the split. From then on, THIS instance's load path:
//
//   (a) never attempts to read/verify any `entry-*` key at or below the
//       sealed tip sequence, since the key's sequence is parsed from its
//       own unencrypted filename, so no permission-denied read is ever
//       attempted for a legacy entry, and no `entry_unreadable` finding is
//       ever raised for one; and
//   (b) seeds the chain walk from (tip_sequence + 1, tip_entry_hash)
//       instead of GENESIS, so the FIRST new post-split entry must
//       cryptographically chain from the sealed tip.
//
// Nothing before the boundary is deleted, repaired, or rewritten: the full
// legacy chain remains on disk. Honest scope of what re-verifies it (M-2,
// adversarial gate 2026-07-14): the ROUTINE operator load does NOT re-walk the
// sealed region's content: it pins the tip POSITION + HASH (via the MAC'd
// boundary) and, from the directory LISTING only, checks the sealed V2 files
// form a gap-free run ending at the tip (`checkSealedPrefixCompleteness`,
// surfaced as a `sealed_prefix_incomplete` finding). The sealed entries'
// CONTENT is re-verified only by the shipped crypto walk
// `verifySealedLegacyPrefix` (operational/audit-store-split.ts), which
// `audit-store-status` / `verifyFortressAuditFullPicture` run whenever the
// caller can READ the sealed files (root, or an operator on a fortress whose
// sealed entries predate root ownership). So: routine loads detect DELETION of
// sealed files; a readable crypto re-walk additionally detects in-place CONTENT
// tampering; an unreadable sealed region is reported honestly as unverified,
// never as "verified". Only this instance's routine load stops re-walking the
// content. On a fortress that never had a daemon write into `_audit` (the
// overwhelming majority of installs, meaning anything that never armed Castle
// Wall as root against this fortress), no boundary record is ever written, so
// the whole mechanism is a silent no-op: the boundary file simply does not
// exist, `loadSplitBoundary()` returns "absent", and behavior is byte-for-byte
// identical to before this PR.
//
// The boundary record is intentionally NOT stored via the encrypted
// StorageBackend contract (which, when the writer is root, always produces a
// 0600 root-owned file): it holds no secret (two integers, a hex hash, and a
// timestamp), it MUST be readable by the operator uid so the operator's own
// load path can consult it, and its integrity comes entirely from the MAC
// (keyed from the master key both root and the operator possess) rather than
// from file-permission confidentiality. It lives as a plain file under its
// own directory, matching `FilesystemStorageCapabilities.namespacePath`'s
// documented exception for "callers' own files ... outside the normal
// encrypted key/value contract."
const AUDIT_SPLIT_BOUNDARY_DIRNAME = "_audit_migration";
const AUDIT_SPLIT_BOUNDARY_FILENAME = "boundary-v1.json";
const AUDIT_SPLIT_BOUNDARY_MARKER = "__sanctuary_audit_store_split_boundary_v1";
const AUDIT_SPLIT_BOUNDARY_MAC_DOMAIN =
  "sanctuary.audit-store-split-boundary.v1\n";
// BLOCKER-2 (adversarial gate 2026-07-14): the durable "the writer-split
// migration ran" markers, used to distinguish a DELETED boundary from a
// never-migrated fortress. These literals MUST byte-match
// `operational/audit-store-split.ts`'s `AUDIT_DAEMON_NAMESPACE` /
// `AUDIT_DAEMON_CHECKPOINT_NAMESPACE` / `AUDIT_DAEMON_META_NAMESPACE`; they are
// duplicated (not imported) because audit-store-split.ts imports FROM this
// module, so importing back would create a dependency cycle. A structural test
// (`audit-store-split-marker-namespaces-match`) asserts they stay in lockstep.
const AUDIT_DAEMON_MIGRATION_MARKER_NAMESPACES = [
  "_audit-daemon",
  "_audit-daemon_checkpoints",
  "_audit-daemon_meta",
] as const;
// BLOCKER-R2 (adversarial re-gate 2026-07-14): a durable, MAC-authenticated
// "the writer-split migration ran" marker in `_meta`, deliberately NOT
// co-deletable with the daemon namespace set. The prior boundary-loss
// fail-closed depended ONLY on the `_audit-daemon*` namespaces; deleting those
// alongside the boundary restored the pre-fix absent-boundary TOFU path. This
// marker lives beside the fortress's own custody records in `_meta`, so an
// attacker who strips every daemon namespace + the boundary still leaves it
// behind, and an absent boundary with this marker present fails closed
// (`split_boundary_missing` + TOFU suppressed). MAC'd (same derived key as the
// boundary, distinct domain) so it cannot be forged; deletion is the residual
// the F1/F3 "single deletable file" note already documents (closing it fully
// needs boot-anchored/externally-attested storage, out of scope).
const AUDIT_STORE_SPLIT_ESTABLISHED_META_KEY = "audit-store-split-established-v1";
const AUDIT_STORE_SPLIT_ESTABLISHED_MARKER =
  "__sanctuary_audit_store_split_established_v1";
const AUDIT_STORE_SPLIT_ESTABLISHED_MAC_DOMAIN =
  "sanctuary.audit-store-split-established.v1\n";

// ── Master-rotation custody epochs (F7) ─────────────────────────────
//
// A MASTER rotation (core/master-rotation.ts) deliberately does NOT
// re-encrypt audit entry ciphertext: every entry_hash in the tamper-evident
// chain — and every externally anchorable checkpoint root built from those
// hashes — covers `encrypted_payload_bytes`, so rewriting the ciphertext
// would invalidate the entire verification history and turn rotation into an
// undetectable history-rewrite window. Instead the rotation engine stores
// the retiring epoch's audit purpose key, wrapped under the NEW master, in a
// MAC-authenticated record; decryption is key-id-scoped (try the current
// epoch key, then prior epochs), while chain verification is untouched and
// verifies seamlessly ACROSS the rotation boundary.
//
// Residual (documented): pre-rotation audit payloads remain encrypted under
// the old-master-derived audit key, so an adversary who holds BOTH the old
// master AND the ciphertext can still read pre-rotation audit metadata
// (operation names/results — never key material, per CLAUDE.md #6). That is
// the price of keeping the chain externally verifiable across rotation.
// G1/G5 (post-#969 sweep re-gate): the key literal now lives in the pure
// shared `audit/checkpoint-shape.ts` (one definition for this runtime AND the
// raw CLI exporter's control-key allowlist); re-exported here so existing
// importers (master rotation, tests) are unchanged.
export { AUDIT_EPOCH_KEYS_KEY };
const AUDIT_EPOCH_KEYS_MARKER = "__sanctuary_audit_epoch_keys_v1";
const AUDIT_EPOCH_MAC_DOMAIN = "sanctuary.audit-epoch-keys.v1\n";
const AUDIT_EPOCH_WRAP_PURPOSE = "audit-epoch-wrap";
const AUDIT_EPOCH_MAC_PURPOSE = "audit-epoch-record-mac";

export interface AuditEpochEntry {
  rotation_id: string;
  rotated_at: string;
  /** The retiring epoch's audit purpose key, AES-256-GCM wrapped under
   * HKDF(current master, "audit-epoch-wrap"). Never plaintext at rest. */
  wrapped_key: EncryptedPayload;
}

function epochRecordMacBytes(
  macKey: Uint8Array,
  data: { epochs: AuditEpochEntry[] }
): Uint8Array {
  return hmacSha256(
    macKey,
    stringToBytes(AUDIT_EPOCH_MAC_DOMAIN + canonicalJson(data))
  );
}

/**
 * Read + authenticate the custody-epoch record and unwrap the prior epoch
 * audit keys. Returns [] when the record is absent. A present-but-invalid
 * record (malformed, marker stripped, MAC mismatch, unwrap failure) returns
 * [] as well: the prior-epoch entries then fail decryption and surface as
 * `entry_decrypt_failed` integrity findings — fail closed, never a silent
 * downgrade to "those entries don't exist".
 */
export async function readAuditEpochKeys(
  storage: StorageBackend,
  keys: { epochWrapKey: Uint8Array; epochMacKey: Uint8Array }
): Promise<Uint8Array[]> {
  let raw: Uint8Array | null;
  try {
    raw = await storage.read(AUDIT_CHECKPOINT_NAMESPACE, AUDIT_EPOCH_KEYS_KEY);
  } catch {
    return [];
  }
  if (!raw) return [];
  try {
    const parsed = JSON.parse(bytesToString(raw)) as Record<string, unknown>;
    if (parsed?.[AUDIT_EPOCH_KEYS_MARKER] !== true) return [];
    const data = parsed.data as { epochs: AuditEpochEntry[] };
    const mac = parsed.mac;
    if (typeof mac !== "string" || !Array.isArray(data?.epochs)) return [];
    const provided = fromBase64url(mac);
    if (
      !constantTimeEqual(provided, epochRecordMacBytes(keys.epochMacKey, data))
    ) {
      return [];
    }
    const out: Uint8Array[] = [];
    for (const epoch of data.epochs) {
      out.push(decrypt(epoch.wrapped_key, keys.epochWrapKey));
    }
    return out;
  } catch {
    return [];
  }
}

/**
 * Anti-rollback Stage 1 witness: how many master rotations this fortress has
 * recorded (the #501 custody-epoch count), distinguishing the three states the
 * rollback detector must treat differently:
 *  - "absent": no epoch record → 0 rotations (epoch 0). Not suspicious.
 *  - "present": record authenticates → `count` rotations have happened. The
 *    epoch floor is `count`.
 *  - "tampered": record is PRESENT but malformed / marker-stripped / MAC
 *    mismatch → fail closed toward the freeze direction (the caller treats this
 *    as suspected rollback, never as absent).
 *
 * Unlike {@link readAuditEpochKeys} (which collapses tampered→[] because the
 * downstream entry decryption surfaces the tamper as integrity findings), this
 * reader makes "tampered" explicit so the rollback detector can freeze on it.
 * It does NOT unwrap any epoch key (no key material touched).
 */
export async function readCustodyEpochCount(
  storage: StorageBackend,
  keys: { epochMacKey: Uint8Array }
): Promise<
  | { status: "absent" }
  | { status: "present"; count: number }
  | { status: "tampered" }
> {
  let raw: Uint8Array | null;
  try {
    raw = await storage.read(AUDIT_CHECKPOINT_NAMESPACE, AUDIT_EPOCH_KEYS_KEY);
  } catch {
    // Cannot read the record → cannot prove it is absent → suspected.
    return { status: "tampered" };
  }
  if (!raw) return { status: "absent" };
  let parsed: Record<string, unknown>;
  try {
    parsed = JSON.parse(bytesToString(raw)) as Record<string, unknown>;
  } catch {
    return { status: "tampered" };
  }
  if (parsed?.[AUDIT_EPOCH_KEYS_MARKER] !== true) return { status: "tampered" };
  const data = parsed.data as { epochs?: AuditEpochEntry[] } | undefined;
  const mac = parsed.mac;
  if (typeof mac !== "string" || !Array.isArray(data?.epochs)) {
    return { status: "tampered" };
  }
  let provided: Uint8Array;
  try {
    provided = fromBase64url(mac);
  } catch {
    return { status: "tampered" };
  }
  if (
    !constantTimeEqual(
      provided,
      epochRecordMacBytes(keys.epochMacKey, { epochs: data.epochs })
    )
  ) {
    return { status: "tampered" };
  }
  return { status: "present", count: data.epochs.length };
}

/**
 * Anti-rollback Stage 1 SPLICE witness: probe the audit head anchor under a
 * candidate master. The head anchor is master-MAC'd over the highest chained
 * sequence; it survives a CUSTODY-FILES-ONLY rollback (an attacker who restores
 * only `_meta/custody-*` to resurrect a retired credential leaves the current
 * audit head in place). The signatures:
 *  - "absent": no head anchor AND no established marker → a genuinely brand-new
 *    or never-audited fortress. Neutral (no false positive on first boot).
 *  - "valid": authenticates under THIS master → the audit head belongs to this
 *    master; `highest_sequence` is real work this master did.
 *  - "tampered": PRESENT but does NOT authenticate under this master (the splice
 *    signature — old custody envelope grafted onto a newer audit head), OR
 *    DELETED/marker-stripped while the `audit-head-anchor-established-v1` marker
 *    in `_meta` proves the fortress once had a head anchor. Deleting the head
 *    anchor to dodge the splice check (codex r2 HIGH) now reads as tampered, not
 *    absent — the attacker would also have to delete the established marker, and
 *    that marker's own disappearance is itself the established→gone signature.
 *
 * Read-only; touches no key material beyond the head-anchor MAC key (zeroed).
 */
export async function probeAuditHeadAnchor(
  storage: StorageBackend,
  masterKey: Uint8Array
): Promise<
  | { status: "absent" }
  | { status: "valid"; highest_sequence: number }
  | { status: "tampered" }
> {
  // Was a head anchor EVER established? Two independent signals, OR'd so that
  // deleting either does NOT erase the detector's memory (codex r3 HIGH):
  //  (1) the plaintext `audit-head-anchor-established-v1` marker in _meta, and
  //  (2) the presence of ANY audit entries / checkpoint records — a head anchor
  //      is written once the chain reaches its checkpoint interval, so surviving
  //      `_audit` or `_audit_checkpoints` content is itself evidence the
  //      fortress did audited work and SHOULD have a head anchor.
  // To make a deleted/stripped head anchor read as "absent" (neutral), an
  // attacker must delete the marker AND wipe the entire audit chain + all
  // checkpoint records — i.e. destroy the audit trail wholesale, which is the
  // glaring, separately-detectable full-wipe residual, not a quiet splice.
  let established = false;
  try {
    if ((await storage.read(AUDIT_META_NAMESPACE, AUDIT_HEAD_ANCHOR_ESTABLISHED_KEY)) !== null) {
      established = true;
    }
  } catch {
    // Cannot read the marker → cannot prove it absent → lean suspect.
    established = true;
  }
  if (!established) {
    try {
      if ((await storage.list(AUDIT_NAMESPACE)).length > 0) established = true;
    } catch {
      established = true; // cannot enumerate → lean suspect
    }
  }
  if (!established) {
    try {
      // Any checkpoint/anchor/epoch record beyond a clean empty store.
      if ((await storage.list(AUDIT_CHECKPOINT_NAMESPACE)).length > 0) {
        established = true;
      }
    } catch {
      established = true;
    }
  }

  let raw: Uint8Array | null;
  try {
    raw = await storage.read(AUDIT_CHECKPOINT_NAMESPACE, AUDIT_HEAD_ANCHOR_KEY);
  } catch {
    // Cannot read it → cannot prove absence → treat as suspect (tampered).
    return { status: "tampered" };
  }
  // Absent head anchor: suspect IFF it was once established (deletion), else a
  // genuine never-audited fortress (neutral — no first-boot false positive).
  if (!raw) return established ? { status: "tampered" } : { status: "absent" };
  let parsed: unknown;
  try {
    parsed = JSON.parse(bytesToString(raw));
  } catch {
    return { status: "tampered" };
  }
  if (!isRecord(parsed) || parsed[AUDIT_HEAD_ANCHOR_MARKER] !== true) {
    // Marker-stripped record: suspect IFF a head anchor was once established
    // (an attacker stripping the marker to look "absent"), else neutral.
    return established ? { status: "tampered" } : { status: "absent" };
  }
  const data = parsed.data;
  const mac = parsed.mac;
  if (
    !isRecord(data) ||
    typeof mac !== "string" ||
    typeof data.highest_sequence !== "number" ||
    !Number.isSafeInteger(data.highest_sequence) ||
    data.highest_sequence <= 0 ||
    typeof data.head_hash !== "string" ||
    !/^[0-9a-f]{64}$/.test(data.head_hash)
  ) {
    return { status: "tampered" };
  }
  const macKey = derivePurposeKey(masterKey, "audit-head-anchor");
  try {
    const expected = hmacSha256(
      macKey,
      stringToBytes(
        AUDIT_HEAD_ANCHOR_MAC_DOMAIN +
          canonicalJson({
            highest_sequence: data.highest_sequence,
            head_hash: data.head_hash,
          })
      )
    );
    let provided: Uint8Array;
    try {
      provided = fromBase64url(mac);
    } catch {
      return { status: "tampered" };
    }
    if (!constantTimeEqual(provided, expected)) {
      return { status: "tampered" };
    }
    return { status: "valid", highest_sequence: data.highest_sequence };
  } finally {
    macKey.fill(0);
  }
}

/**
 * Read the epoch record's raw entries (authenticated) for the rotation
 * engine, which must re-wrap every prior epoch key under the next master.
 */
export async function readAuditEpochEntries(
  storage: StorageBackend,
  keys: { epochWrapKey: Uint8Array; epochMacKey: Uint8Array }
): Promise<Array<{ entry: AuditEpochEntry; key: Uint8Array }>> {
  const raw = await storage.read(
    AUDIT_CHECKPOINT_NAMESPACE,
    AUDIT_EPOCH_KEYS_KEY
  );
  if (!raw) return [];
  const parsed = JSON.parse(bytesToString(raw)) as Record<string, unknown>;
  if (parsed?.[AUDIT_EPOCH_KEYS_MARKER] !== true) {
    throw new Error(
      "Sanctuary: audit custody-epoch record is malformed (marker missing)."
    );
  }
  const data = parsed.data as { epochs: AuditEpochEntry[] };
  const mac = parsed.mac;
  if (
    typeof mac !== "string" ||
    !Array.isArray(data?.epochs) ||
    !constantTimeEqual(
      fromBase64url(mac),
      epochRecordMacBytes(keys.epochMacKey, data)
    )
  ) {
    throw new Error(
      "Sanctuary: audit custody-epoch record failed authentication " +
        "(tampered, forged, or wrong key). Refusing to rotate over it."
    );
  }
  return data.epochs.map((entry) => ({
    entry,
    key: decrypt(entry.wrapped_key, keys.epochWrapKey),
  }));
}

/** Write the authenticated custody-epoch record (rotation engine only). */
export async function writeAuditEpochRecord(
  storage: StorageBackend,
  keys: { epochWrapKey: Uint8Array; epochMacKey: Uint8Array },
  epochs: Array<{ rotation_id: string; rotated_at: string; key: Uint8Array }>
): Promise<void> {
  const data = {
    epochs: epochs.map((e) => ({
      rotation_id: e.rotation_id,
      rotated_at: e.rotated_at,
      wrapped_key: encrypt(e.key, keys.epochWrapKey),
    })),
  };
  const record = {
    [AUDIT_EPOCH_KEYS_MARKER]: true,
    data,
    mac: toBase64url(epochRecordMacBytes(keys.epochMacKey, data)),
  };
  await storage.write(
    AUDIT_CHECKPOINT_NAMESPACE,
    AUDIT_EPOCH_KEYS_KEY,
    stringToBytes(JSON.stringify(record))
  );
}

/** Derive the epoch wrap + MAC keys for a given master (rotation engine). */
export function deriveAuditEpochKeys(masterKey: Uint8Array): {
  epochWrapKey: Uint8Array;
  epochMacKey: Uint8Array;
} {
  return {
    epochWrapKey: derivePurposeKey(masterKey, AUDIT_EPOCH_WRAP_PURPOSE),
    epochMacKey: derivePurposeKey(masterKey, AUDIT_EPOCH_MAC_PURPOSE),
  };
}
const AUDIT_INTEGRITY_ALERT_NAMESPACE = "_audit_integrity_alert";
const AUDIT_INTEGRITY_ALERT_KEY = "audit-integrity-alert.log";
const AUDIT_WRITE_LOCK_FILE = ".audit-write.lock";
// EXPORTED (fix-round-4, MUST-FIX 1 cross-file pin): core/bounded-map.ts's
// `ON_EVICT_AUDIT_TIMEOUT_MS` derives from this and
// `DEFAULT_AUDIT_WRITE_LOCK_HOLD_DEADLINE_MS` below — a caller-supplied
// `onEvict` critical audit is (almost always, see that constant's own doc)
// a `this.appendCritical(...)` call, and its worst-case settle time is
// bounded by these same two numbers (lock ACQUISITION timeout, then the
// held-write's own deadline). If either of these values changes, that
// derivation must be re-checked — see bounded-map.ts's
// `ON_EVICT_AUDIT_TIMEOUT_MS` doc for the full reasoning.
export const AUDIT_WRITE_LOCK_TIMEOUT_MS = 5_000;
const AUDIT_WRITE_LOCK_RETRY_MS = 100;
export const DEFAULT_AUDIT_WRITE_LOCK_HOLD_DEADLINE_MS = 30_000;
const DEFAULT_AUDIT_SELF_HELD_STALE_LOCK_MS = 60_000;
// Drill-found (Leg 5, MBA, 2026-07-15): a 0-byte / unparseable audit lock that
// carries neither `pid` nor `acquired_at` cannot be proven stale by the two
// content-based proofs in `breakStaleAuditLock`, so a torn acquire (crash
// between file-create and stamp under the old open-then-write path) stranded a
// permanently unbreakable lock. A lock with NO usable id content whose mtime
// exceeds this generous age bound is provably not a live holder: a legitimate
// holder ALWAYS writes its stamp before doing any work (and, since the
// atomic-acquire fix below, the lock file never exists without its full stamp),
// and no legitimate hold ever approaches this bound (holds are sub-second; the
// contention timeout above is 5s). The bound only ever clears an id-less lock,
// never a content-bearing one, so it cannot break a live lock a real holder
// stamped. Ten minutes is far beyond any conceivable hold yet far below
// "survived a reboot" (already covered by the boot-time proof).
const AUDIT_WRITE_LOCK_IDLESS_STALE_MS = 10 * 60 * 1_000;
// Slack (ms) absorbed when comparing a lock's monotonic `uptime_ms` stamp
// against the current `os.uptime()`: the holder read its uptime a few syscalls
// before the reader reads theirs, so a lock legitimately stamped "just now" can
// carry an uptime a hair ABOVE the reader's current uptime purely from that
// ordering. One second is far beyond that gap yet far below any interval that
// could let a genuinely stale lock masquerade as same-boot-live.
const AUDIT_LOCK_MONO_UPTIME_TOLERANCE_MS = 1_000;
// Process-local monotonic counter for unique audit-lock temp-file names during
// the atomic acquire (paired with pid + a wall-clock component). Never
// persisted; collision-free within a process and across concurrent processes.
let auditLockTempCounter = 0;
// Suffix marking an audit-lock acquire-temp: `<lockfile>.acquire.<pid>.<n>.<hex>.tmp`.
// A crash / kill -9 between `link()` and the `finally` unlink in
// `atomicAcquireAuditLock` strands one of these; the startup sweep GCs any older
// than the id-less stale bound (invisible to `list()`, litter only).
const AUDIT_LOCK_ACQUIRE_TEMP_INFIX = ".acquire.";
const AUDIT_LOCK_ACQUIRE_TEMP_SUFFIX = ".tmp";

/** Parse the id-less-stale-lock / orphan-acquire-temp age bound from config /
 * env, defaulting to {@link AUDIT_WRITE_LOCK_IDLESS_STALE_MS}. A positive finite
 * override wins (config first, then env); anything else falls back to the
 * default. Mirrors {@link resolveEagerReverifyIntervalMs}. */
function resolveIdlessStaleLockMs(configured?: number): number {
  if (typeof configured === "number" && Number.isFinite(configured) && configured >= 0) {
    return configured;
  }
  const env = Number(process.env.AUDIT_WRITE_LOCK_IDLESS_STALE_MS);
  if (Number.isFinite(env) && env >= 0 && process.env.AUDIT_WRITE_LOCK_IDLESS_STALE_MS) {
    return env;
  }
  return AUDIT_WRITE_LOCK_IDLESS_STALE_MS;
}

function resolveWriteLockHoldDeadlineMs(configured?: number): number {
  const resolved =
    configured === undefined ? DEFAULT_AUDIT_WRITE_LOCK_HOLD_DEADLINE_MS : configured;
  if (typeof resolved !== "number" || !Number.isFinite(resolved) || resolved <= 0) {
    throw new Error(
      `AuditLogConfig.writeLockHoldDeadlineMs must be a positive finite number (got ${String(
        configured,
      )})`,
    );
  }
  return resolved;
}

function resolveSelfHeldStaleLockMs(
  configured: number | undefined,
  writeLockHoldDeadlineMs: number,
): number {
  const resolved =
    configured === undefined ? DEFAULT_AUDIT_SELF_HELD_STALE_LOCK_MS : configured;
  if (typeof resolved !== "number" || !Number.isFinite(resolved) || resolved <= 0) {
    throw new Error(
      `AuditLogConfig.selfHeldStaleLockMs must be a positive finite number (got ${String(
        configured,
      )})`,
    );
  }
  if (resolved <= writeLockHoldDeadlineMs) {
    throw new Error(
      `AuditLogConfig.selfHeldStaleLockMs must be strictly greater than writeLockHoldDeadlineMs ` +
        `(got ${resolved} <= ${writeLockHoldDeadlineMs})`,
    );
  }
  return resolved;
}
// Read-consistency backstop. A reader does NOT take the write lock (audit reads
// must work even if a crashed writer stranded a lock, and must never be blockable
// by a planted lock file), so it can observe a torn cut while a rotation is
// mid-flight. We retry through such transients, but the budget is a bounded
// wall-clock DEADLINE rather than a fixed tick count: a legitimately slow
// rotation on a loaded CI host can outrun any small fixed ceiling (the original
// false-fail), while an attacker who keeps the store permanently mid-update still
// fails closed once the deadline passes.
// `AUDIT_READ_CONSISTENCY_MAX_MS` must stay below the stall in
// `ONE_PASS_OUTLIVES_THE_BUDGET_MS` in
// `test/operational/audit-log-concurrent-append-anchor.test.ts`, which pins the
// mandatory-retry behavior by making one pass spend the entire budget.
const AUDIT_READ_CONSISTENCY_MAX_MS = 2_000;
const AUDIT_READ_CONSISTENCY_RETRY_MS = 10;

/**
 * Outcome of reading the MAC'd head anchor. `unreadable_sealed` is the
 * operator-uid-cannot-read-the-root-owned-legacy-anchor case (F2 Option A), NOT
 * a tamper verdict; see {@link AuditLog.verifyHeadAnchor} for how each status is
 * adjudicated.
 */
type HeadAnchorReadResult =
  | { status: "valid"; highest_sequence: number; head_hash: string }
  | { status: "absent" }
  | { status: "invalid" }
  | { status: "unreadable_sealed" };
// Eager-read backstop throttle. The posture dashboard composes several full-chain
// reads per board paint and pushes the same payload on an SSE cadence; re-reading
// + re-decrypting + re-verifying a 10k-entry / 40MB chain from disk on EVERY such
// read pegs the event loop (the #714 drill: 11-30s/paint, Node at 203% CPU). The
// in-memory view is maintained EAGERLY on every append (the server is the sole
// appender; `persistChainedEntry` records + chains each new entry under the write
// lock), so an eager read is already current for everything this process wrote,
// with NO lag for a just-appended entry. A full on-disk re-scan is therefore
// needed ONLY to catch OUT-OF-BAND tampering (a direct file edit that bypasses
// the server). Out-of-band edits that change the cheap listing fingerprint (entry
// count / newest key / per-entry size+mtime aggregate) are caught EVENT-DRIVEN on
// the NEXT eager read by the sentinel below; this full re-scan is the BACKSTOP for
// the residual case the sentinel cannot see (a same-length, mtime-preserved byte
// edit). The load-time full verify is unconditional (it ignores this throttle), so
// an out-of-band edit present at boot still fails loud immediately. Injectable via
// AuditLogConfig.eagerReverifyIntervalMs / AUDIT_EAGER_REVERIFY_INTERVAL_MS env so
// tests can drive the backstop timing deterministically.
const DEFAULT_AUDIT_EAGER_REVERIFY_INTERVAL_MS = 30_000;
// Sentinel self-throttle. The fingerprint sentinel runs a metadata-only
// `storage.list()` (no decrypt, no full hash) to catch out-of-band edits on the
// hot SSE path event-driven, but a full per-read `list()` over 10k entries on a
// ~5s SSE cadence would itself start to load the event loop, so we cap the
// sentinel's OWN cadence to this short interval. It stays far below the backstop
// interval, so an out-of-band fingerprint change is still caught within seconds.
const AUDIT_EAGER_SENTINEL_INTERVAL_MS = 2_000;

/** Parse the eager-reverify backstop interval from config / env, defaulting to
 * {@link DEFAULT_AUDIT_EAGER_REVERIFY_INTERVAL_MS}. A positive finite override
 * wins (config first, then env); anything else falls back to the default. */
function resolveEagerReverifyIntervalMs(configured?: number): number {
  if (typeof configured === "number" && Number.isFinite(configured) && configured >= 0) {
    return configured;
  }
  const env = Number(process.env.AUDIT_EAGER_REVERIFY_INTERVAL_MS);
  if (Number.isFinite(env) && env >= 0) {
    return env;
  }
  return DEFAULT_AUDIT_EAGER_REVERIFY_INTERVAL_MS;
}

/** True iff `pid` names a live process this user could signal. Used to detect a
 * stale audit-write lock left by a crashed/killed holder. */
function isProcessAlive(pid: number): boolean {
  if (!Number.isInteger(pid) || pid <= 0) return false;
  try {
    process.kill(pid, 0);
    return true;
  } catch (err) {
    const code =
      err instanceof Error && "code" in err
        ? (err as NodeJS.ErrnoException).code
        : undefined;
    // EPERM: the process exists but belongs to another user — still alive.
    return code === "EPERM";
  }
}

/**
 * Operation-name constants for the v0.10.0 Secret Broker (L3 Selective
 * Disclosure layer). Kept here as a single source of truth so the broker
 * and audit-query callers agree on string values. Additive only — the
 * AuditEntry.operation field remains a free-form string.
 */
export const BROKER_OPS = {
  SECRET_ADDED: "broker_secret_added",
  SECRET_ROTATED: "broker_secret_rotated",
  SECRET_DELETED: "broker_secret_deleted",
  SECRET_GRANTED: "broker_secret_granted",
  SECRET_REVOKED: "broker_secret_revoked",
  SECRET_READ: "broker_secret_read",
  TOKEN_ISSUED: "broker_token_issued",
  TOKEN_DENIED: "broker_token_denied",
  BACKEND_UNLOCKED: "broker_backend_unlocked",
} as const;

export type BrokerOp = (typeof BROKER_OPS)[keyof typeof BROKER_OPS];

export type AuditPersistenceFailureClassification =
  | "storage_full"
  | "disk_failure"
  | "permission_denied"
  | "partial_write"
  | "unknown"
  | "multiple";

export class AuditPersistenceError extends Error {
  readonly classification: AuditPersistenceFailureClassification;
  override readonly cause?: unknown;

  constructor(
    message: string,
    classification: AuditPersistenceFailureClassification = "unknown",
    cause?: unknown
  ) {
    super(message);
    this.name = "AuditPersistenceError";
    this.classification = classification;
    this.cause = cause;
  }
}

export class AuditLockContentionError extends Error {
  constructor(readonly lockPath: string) {
    super(
      `audit write blocked: the audit write lock at '${lockPath}' was held for >5s. ` +
        `The lock file records the holder's pid and acquired_at; inspect it to see who ` +
        `holds it. If a Sanctuary process is genuinely running, wait for it to finish. ` +
        `If none is, the lock is a stale/torn leftover from a crashed writer: stop all ` +
        `Sanctuary processes for this fortress, then delete the lock file at that path ` +
        `and retry. (This lock is not held open by a file descriptor during the write, ` +
        `so lsof may show no holder even for a legitimately held lock; trust the ` +
        `recorded pid + a process check, not lsof.)`
    );
    this.name = "AuditLockContentionError";
  }
}

export class AuditLockHoldDeadlineError extends Error {
  constructor(
    readonly lockPath: string,
    readonly deadlineMs: number
  ) {
    super(
      `audit write lock at '${lockPath}' exceeded its ${deadlineMs}ms hold deadline; ` +
        `the in-flight append was abandoned and the lock was released so later audit ` +
        `writes can continue.`
    );
    this.name = "AuditLockHoldDeadlineError";
  }
}

export class AuditLogPersistenceError extends AuditPersistenceError {
  constructor(readonly failures: readonly unknown[]) {
    const message =
      failures.length === 1
        ? failureMessage(failures[0])
        : `${failures.length} audit persistence writes failed`;
    super(message, failures.length === 1 ? classifyFailure(failures[0]) : "multiple");
    this.name = "AuditLogPersistenceError";
  }
}

export class AuditIntegrityError extends Error {
  constructor(readonly findings: readonly AuditIntegrityFinding[]) {
    super(
      findings.length === 1
        ? findings[0]!.message
        : `${findings.length} audit integrity findings detected`
    );
    this.name = "AuditIntegrityError";
  }
}

/**
 * Internal marker wrapping an error thrown by a {@link VerifiedChainConsumer}'s
 * `onEntry` during a streaming reload pass. The decrypt loop runs inside
 * `loadPersistedEntries`' outer try (it iterates a live `storage.list`), so a
 * raw consumer throw would otherwise be caught there and relabeled
 * `storage_unavailable`. Tagging it lets the outer catch re-throw the consumer's
 * ORIGINAL error verbatim: a consumer rejection (e.g. a malformed workload
 * lifecycle payload) is neither a storage failure nor a decrypt failure and must
 * surface as itself, never be absorbed into the integrity findings (#504). Never
 * escapes the module: it is always unwrapped before it leaves `loadPersistedEntries`.
 */
class ConsumerRejectedEntryError extends Error {
  constructor(readonly cause: unknown) {
    super("audit-chain consumer rejected a decrypted entry");
    this.name = "ConsumerRejectedEntryError";
  }
}

const auditIntegrityContext = new AsyncLocalStorage<{
  allowIntegrityFindings: boolean;
}>();

/**
 * When set, `query` serves from the eagerly-maintained in-memory verified view
 * and throttles the OUT-OF-BAND on-disk re-verification (see {@link
 * AuditLog.queryEager}). The always-on posture surface (home board + per-panel
 * endpoints + SSE push) opens this scope via {@link AuditLog.runEagerReads} so
 * every read it composes is bounded-cost, WITHOUT touching the agent-facing
 * `query` callers (who keep per-request on-disk re-verification). The flag never
 * weakens honesty: the eager view is current for every server-written entry and
 * the strict-mode findings contract is unchanged.
 */
const auditEagerReadContext = new AsyncLocalStorage<{ eager: boolean }>();

// ── F2 Option A: split-boundary record (shared read/write logic) ───────────
//
// These are module-level (not `AuditLog` methods) because BOTH the class's
// own load path (read-only, keyed from its own derived MAC key) and the
// migration orchestration in `operational/audit-store-split.ts` (which
// WRITES the record, from a different call site entirely) need the exact
// same envelope shape and MAC computation. Keeping one definition avoids the
// two ever drifting apart.

/** The split-boundary record: where the operator's `_audit` chain was sealed
 * and the daemon namespace new writes continue in. */
export interface AuditStoreSplitBoundary {
  /** Highest sequence number in the sealed legacy (pre-split) `_audit` chain.
   * 0 if the chain was empty at migration time. */
  sealed_tip_sequence: number;
  /** BLOCKER-R1 (adversarial re-gate 2026-07-14): the LOWEST V2 `entry-*`
   * sequence present in the sealed region at migration time (the pre-split
   * rotation floor, or 1 if never rotated; 0 when the chain was empty). Recorded
   * so a reader can detect deletion of the LOWEST sealed entry (the residual
   * the first fix round documented but did not close). Without a known base, a
   * deleted bottom entry leaves a still-contiguous-ending-at-tip run that reads
   * as a legitimate rotation floor; with the base pinned, lowest-present must
   * equal it. */
  sealed_base_sequence: number;
  /** `entry_hash` of the sequence-`sealed_tip_sequence` entry, or
   * {@link AUDIT_CHAIN_GENESIS} if `sealed_tip_sequence` is 0. */
  sealed_tip_entry_hash: string;
  /** ISO timestamp the boundary was sealed. */
  sealed_at: string;
  /** The namespace the root daemon's own chain continues in
   * (`operational/audit-store-split.ts`'s `AUDIT_DAEMON_NAMESPACE`). Recorded
   * here so a future reader never has to hardcode it a second place. */
  daemon_namespace: string;
}

export type AuditStoreSplitBoundaryLoadResult =
  | { status: "valid"; boundary: AuditStoreSplitBoundary }
  | { status: "absent" }
  | { status: "invalid" };

/** Absolute path to the split-boundary record, given the fortress's `state`
 * directory (i.e. `dirname(namespacePath(AUDIT_NAMESPACE))`). */
export function auditStoreSplitBoundaryPath(fortressStatePath: string): string {
  return join(
    fortressStatePath,
    AUDIT_SPLIT_BOUNDARY_DIRNAME,
    AUDIT_SPLIT_BOUNDARY_FILENAME
  );
}

/** Derive the MAC key for the split-boundary record from the fortress master
 * key. A dedicated purpose string, domain-separated from every other derived
 * key in this file.
 *
 * F2 REKEY LANDMINE (adversarial gate M-1, 2026-07-14): this MAC key is derived
 * from the ROTATING master (same as the audit head-anchor). The boundary record
 * is NOT re-stamped by any master-rotation recipe today; instead rotation is
 * REFUSED by name on any fortress that ran the writer-split migration (see the
 * `_audit-daemon*` `unsupported` recipes in `core/master-rotation.ts`). If a
 * future change adds a rotation recipe to RE-ENABLE rotation for those
 * namespaces, it MUST also re-stamp this boundary record under the NEW master
 * (re-derive this key + `writeAuditStoreSplitBoundary`) inside the same
 * rotation. Otherwise the boundary reads `invalid` post-rotation, the operator
 * load stops filtering the sealed region, and F2 regresses (re-throws on the
 * unreadable root-owned entries on an armed box). Do not silently lift the
 * rotation refusal without closing this. */
export function deriveAuditStoreSplitBoundaryMacKey(
  masterKey: Uint8Array
): Uint8Array {
  return derivePurposeKey(masterKey, "audit-store-split-boundary");
}

// LOW-1 (adversarial gate 2026-07-14): `sealed_at` is inside the MAC input, so
// a file-writer without the master key cannot falsify WHEN the split happened
// while preserving a valid MAC. Every authenticated field the record carries is
// covered here; nothing about the boundary record is trusted display-only.
function auditStoreSplitBoundaryMacBytes(
  macKey: Uint8Array,
  data: {
    sealed_tip_sequence: number;
    sealed_base_sequence: number;
    sealed_tip_entry_hash: string;
    daemon_namespace: string;
    sealed_at: string;
  }
): Uint8Array {
  return hmacSha256(
    macKey,
    stringToBytes(AUDIT_SPLIT_BOUNDARY_MAC_DOMAIN + canonicalJson(data))
  );
}

/**
 * Write the split-boundary record. Operator-readable by design (mode 0o644 /
 * parent 0o755): see the module doc comment above for why that is safe. The
 * record carries no secret, and its integrity comes from the MAC, not from
 * file-permission confidentiality. Uses the same O_EXCL-temp + fsync +
 * atomic-rename + fsync-dir discipline as every other durable write in this
 * codebase (`writeFileCustody`), so a crash mid-write leaves either the OLD
 * state (no boundary) or the fully-written NEW one, never a torn file.
 *
 * This is the COMMIT point of the store-split migration: callers must write
 * everything else (the daemon chain's genesis marker entry) BEFORE calling
 * this, so that a crash before this call is safely retryable (idempotent,
 * see `migrateFortressAuditStoreSplit`) and a crash after it never leaves the
 * daemon chain without its marker.
 */
export async function writeAuditStoreSplitBoundary(
  fortressStatePath: string,
  macKey: Uint8Array,
  boundary: {
    sealed_tip_sequence: number;
    sealed_base_sequence: number;
    sealed_tip_entry_hash: string;
    daemon_namespace: string;
    sealed_at?: string;
  }
): Promise<void> {
  const sealedAt = boundary.sealed_at ?? new Date().toISOString();
  // `data` holds the structural fields; `sealed_at` lives at the envelope top
  // level (as it always has) but is folded into the MAC input below, so it is
  // authenticated without being duplicated into the persisted `data`.
  const data = {
    sealed_tip_sequence: boundary.sealed_tip_sequence,
    sealed_base_sequence: boundary.sealed_base_sequence,
    sealed_tip_entry_hash: boundary.sealed_tip_entry_hash,
    daemon_namespace: boundary.daemon_namespace,
  };
  const envelope = {
    [AUDIT_SPLIT_BOUNDARY_MARKER]: true,
    data,
    sealed_at: sealedAt,
    mac: toBase64url(
      auditStoreSplitBoundaryMacBytes(macKey, { ...data, sealed_at: sealedAt })
    ),
  };
  await writeFileCustody(
    auditStoreSplitBoundaryPath(fortressStatePath),
    JSON.stringify(envelope),
    { mode: 0o644, parentMode: 0o755 }
  );
}

/**
 * Read + MAC-verify the split-boundary record.
 *   - `valid`   : present, well-formed, MAC matches → authenticated boundary.
 *   - `invalid` : present but malformed / MAC mismatch → tampered or forged;
 *     the caller MUST fail closed (never silently treat as absent).
 *   - `absent`  : no record, including "not readable at this privilege",
 *     which degrades to "act as if no migration ran" (today's behavior).
 *     This is safe as a NON-fatal default because the record is a pure
 *     optimization for the class's own load path: an unreadable/absent
 *     record simply means `ensureLoaded` walks the full legacy chain again,
 *     exactly as it did before this PR (correct, if F2-affected). A caller
 *     that needs to distinguish "genuinely never migrated" from "migrated
 *     but I can't read the marker" for reporting purposes (the full-picture
 *     verifier) does its own presence probe separately.
 */
export async function readAuditStoreSplitBoundary(
  fortressStatePath: string,
  macKey: Uint8Array
): Promise<AuditStoreSplitBoundaryLoadResult> {
  let raw: Buffer;
  try {
    raw = await readFile(auditStoreSplitBoundaryPath(fortressStatePath));
  } catch {
    return { status: "absent" };
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw.toString("utf8"));
  } catch {
    return { status: "invalid" };
  }
  if (!isRecord(parsed) || parsed[AUDIT_SPLIT_BOUNDARY_MARKER] !== true) {
    return { status: "absent" };
  }
  const data = parsed.data;
  const mac = parsed.mac;
  const sealedAt = parsed.sealed_at;
  if (
    !isRecord(data) ||
    typeof mac !== "string" ||
    typeof sealedAt !== "string" ||
    typeof data.sealed_tip_sequence !== "number" ||
    !Number.isSafeInteger(data.sealed_tip_sequence) ||
    data.sealed_tip_sequence < 0 ||
    typeof data.sealed_base_sequence !== "number" ||
    !Number.isSafeInteger(data.sealed_base_sequence) ||
    data.sealed_base_sequence < 0 ||
    data.sealed_base_sequence > data.sealed_tip_sequence ||
    // base is 0 iff the sealed chain was empty (tip 0); otherwise base >= 1.
    (data.sealed_tip_sequence === 0
      ? data.sealed_base_sequence !== 0
      : data.sealed_base_sequence < 1) ||
    typeof data.sealed_tip_entry_hash !== "string" ||
    typeof data.daemon_namespace !== "string" ||
    data.daemon_namespace.length === 0 ||
    (data.sealed_tip_sequence === 0
      ? data.sealed_tip_entry_hash !== AUDIT_CHAIN_GENESIS
      : !/^[0-9a-f]{64}$/.test(data.sealed_tip_entry_hash))
  ) {
    return { status: "invalid" };
  }
  let providedMac: Uint8Array;
  try {
    providedMac = fromBase64url(mac);
  } catch {
    return { status: "invalid" };
  }
  const expected = auditStoreSplitBoundaryMacBytes(macKey, {
    sealed_tip_sequence: data.sealed_tip_sequence,
    sealed_base_sequence: data.sealed_base_sequence,
    sealed_tip_entry_hash: data.sealed_tip_entry_hash,
    daemon_namespace: data.daemon_namespace,
    sealed_at: sealedAt,
  });
  if (!constantTimeEqual(providedMac, expected)) {
    return { status: "invalid" };
  }
  return {
    status: "valid",
    boundary: {
      sealed_tip_sequence: data.sealed_tip_sequence,
      sealed_base_sequence: data.sealed_base_sequence,
      sealed_tip_entry_hash: data.sealed_tip_entry_hash,
      sealed_at: sealedAt,
      daemon_namespace: data.daemon_namespace,
    },
  };
}

// BLOCKER-R2: MAC over the (data-less) established marker. Domain-separated
// from the boundary MAC but reuses the same derived key. Authenticates "a
// party with the master key wrote this marker", so a planted fake cannot force
// a spurious split_boundary_missing DoS.
function auditStoreSplitEstablishedMacBytes(macKey: Uint8Array): Uint8Array {
  return hmacSha256(
    macKey,
    stringToBytes(AUDIT_STORE_SPLIT_ESTABLISHED_MAC_DOMAIN)
  );
}

/**
 * BLOCKER-R2 (adversarial re-gate 2026-07-14): write the durable
 * migration-established marker to `_meta` (via the normal StorageBackend, so it
 * lands beside the fortress's custody records, NOT co-deletable with the
 * `_audit-daemon*` namespaces). Written by `migrateFortressAuditStoreSplit`
 * BEFORE the boundary commit, so a crash mid-migration still leaves the marker
 * (a retry is idempotent). Its presence + an absent boundary = boundary was
 * deleted (fail closed), regardless of whether the daemon namespaces survive.
 */
export async function writeAuditStoreSplitEstablishedMarker(
  storage: StorageBackend,
  macKey: Uint8Array
): Promise<void> {
  const envelope = {
    [AUDIT_STORE_SPLIT_ESTABLISHED_MARKER]: true,
    mac: toBase64url(auditStoreSplitEstablishedMacBytes(macKey)),
  };
  await storage.write(
    AUDIT_META_NAMESPACE,
    AUDIT_STORE_SPLIT_ESTABLISHED_META_KEY,
    stringToBytes(JSON.stringify(envelope))
  );
}

/**
 * BLOCKER-R2 + HIGH-1 (round 3): read + MAC-verify the migration-established
 * marker, TRI-STATE so a corrupted/unreadable marker is NOT laundered into
 * "never migrated":
 *   - `present`: authentic marker → the writer-split migration ran. An absent
 *     boundary in this state is a deletion (fail closed).
 *   - `invalid_or_unreadable`: the marker RECORD exists but does not
 *     authenticate (bad JSON, missing/wrong marker key, missing/malformed/wrong
 *     MAC) OR the read threw (EACCES/IO). This is evidence of a migration whose
 *     witness was tampered/corrupted, so callers MUST treat it as migration
 *     evidence and fail closed; the round-2 fix collapsed all of these to
 *     "absent", which let an attacker CORRUPT the marker to re-open the TOFU
 *     fail-open (HIGH-1).
 *   - `absent`: NO record at all (`storage.read` returned null) → genuinely
 *     never migrated (the common case). Absence never fabricates a migration.
 */
export async function readAuditStoreSplitEstablishedMarker(
  storage: StorageBackend,
  macKey: Uint8Array
): Promise<"present" | "absent" | "invalid_or_unreadable"> {
  let raw: Uint8Array | null;
  try {
    raw = await storage.read(AUDIT_META_NAMESPACE, AUDIT_STORE_SPLIT_ESTABLISHED_META_KEY);
  } catch {
    // A read error cannot prove absence; a present-but-unreadable marker is
    // exactly the tamper case. Fail closed.
    return "invalid_or_unreadable";
  }
  if (!raw) return "absent"; // no record: genuinely never migrated
  let parsed: unknown;
  try {
    parsed = JSON.parse(bytesToString(raw));
  } catch {
    return "invalid_or_unreadable";
  }
  if (!isRecord(parsed) || parsed[AUDIT_STORE_SPLIT_ESTABLISHED_MARKER] !== true) {
    return "invalid_or_unreadable";
  }
  const mac = parsed.mac;
  if (typeof mac !== "string") return "invalid_or_unreadable";
  let providedMac: Uint8Array;
  try {
    providedMac = fromBase64url(mac);
  } catch {
    return "invalid_or_unreadable";
  }
  return constantTimeEqual(providedMac, auditStoreSplitEstablishedMacBytes(macKey))
    ? "present"
    : "invalid_or_unreadable";
}

/** Parse the zero-padded sequence number embedded in a V2 `entry-*` storage
 * key (`entry-${20-digit-sequence}-${epochMs}-${counter}`). Returns null for
 * any key that does not match this shape (e.g. a pre-V2 legacy key), which
 * callers must treat as "not filterable by sequence", never as sequence 0. */
function parseEntryKeySequence(key: string): number | null {
  const match = /^entry-(\d{20})-/.exec(key);
  if (!match) return null;
  const seq = Number(match[1]);
  return Number.isSafeInteger(seq) ? seq : null;
}

/** Parse the zero-padded checkpoint sequence embedded in an `audit-checkpoint-`
 * / `legacy-anchor-` storage key (`${kind}-${20-digit-sequence}`, built by
 * `writeCheckpointRecord`). Returns null for any key that does not match, which
 * callers treat as "not classifiable by sequence" (never sequence 0). Lets the
 * operator decide a checkpoint sits in the sealed legacy region from the
 * UNENCRYPTED key alone, without reading the (possibly root-owned, unreadable)
 * file. */
function parseCheckpointKeySequence(key: string): number | null {
  const match = /-(\d{20})$/.exec(key);
  if (!match) return null;
  const seq = Number(match[1]);
  return Number.isSafeInteger(seq) ? seq : null;
}

/** True iff a filesystem error is a privilege denial (EACCES/EPERM), i.e. "this
 * process cannot open the file at its current privilege", as opposed to a
 * corruption / IO / not-found condition. F2: on an armed box the legacy audit
 * checkpoint/anchor files a pre-split ROOT daemon wrote are root-owned 0600, so
 * the operator uid's read throws EACCES; that is the contamination case the
 * split boundary re-routes, distinct from a genuine tamper/IO fault which must
 * still fail closed. */
function isPermissionError(err: unknown): boolean {
  const code =
    err instanceof Error && "code" in err
      ? String((err as NodeJS.ErrnoException).code)
      : "";
  return code === "EACCES" || code === "EPERM";
}

// ── F2 sealed-region verifier (chokepoint core) ────────────────────────────
//
// BLOCKER-1 (adversarial re-gate round 3, 2026-07-14): the routine load SKIPS
// the sealed legacy region by design, so `getIntegrityFindings()` never
// reflects sealed CONTENT integrity. This crypto walk is the one place that
// re-verifies the sealed region's content (reading envelope bytes, recomputing
// entry hashes, chaining base->tip, matching the MAC'd tip hash; NO decrypt,
// so it works whenever the caller can READ the files). It lives here (not in
// audit-store-split.ts) so `AuditLog` can call it directly with its own stored
// `splitBoundaryMacKey` + `storage`, WITHOUT the raw master key; which is what
// makes the single `AuditLog.getAuditChainVerdict()` chokepoint reachable from
// every clean-claiming surface (they all hold only an `AuditLog` handle).
// `verifySealedLegacyPrefix(storage, masterKey)` in audit-store-split.ts is a
// thin wrapper over this that derives the MAC key from the master.
export type SealedRegionVerdict =
  /** No VALID boundary present: nothing was sealed by a committed migration. */
  | { status: "not_present" }
  /** The migration sealed an empty chain (`sealed_tip_sequence === 0`). */
  | { status: "empty" }
  /** Every sealed V2 entry re-hashed, chained, and the tip matched the MAC'd
   * `sealed_tip_entry_hash`. */
  | { status: "verified"; entries_verified: number; sealed_tip_sequence: number }
  /** At least one sealed entry could not be read at this privilege (the F2
   * cross-uid case). Honest: NOT verified. Re-run as root. */
  | { status: "unreadable"; note: string }
  /** The sealed V2 entry files are not a gap-free run from the MAC'd base to the
   * MAC'd tip (a sealed entry was deleted / disappeared). */
  | { status: "incomplete"; expected_tip: number; highest_present: number }
  /** A sealed entry's content was tampered: a recomputed entry hash, a chain
   * link, or the tip hash did not match. */
  | { status: "hash_mismatch"; sequence: number; expected: string; actual: string };

interface SealedEnvelopeV2 {
  sequence: number;
  prev_hash: string;
  entry_hash: string;
  timestamp: string;
  encrypted_payload_bytes: string;
  schema_version: number;
}

function isSealedEnvelopeV2(value: unknown): value is SealedEnvelopeV2 {
  if (!isRecord(value)) return false;
  return (
    value.schema_version === AUDIT_CHAIN_SCHEMA_VERSION &&
    typeof value.sequence === "number" &&
    Number.isSafeInteger(value.sequence) &&
    value.sequence > 0 &&
    typeof value.prev_hash === "string" &&
    typeof value.entry_hash === "string" &&
    /^[0-9a-f]{64}$/.test(value.entry_hash) &&
    typeof value.timestamp === "string" &&
    typeof value.encrypted_payload_bytes === "string"
  );
}

/**
 * The sealed-region crypto walk. `storage` needs only `list`/`read` on the
 * `_audit` namespace; `statePath` is the fortress `state` dir (for the boundary
 * file); `macKey` is the split-boundary MAC key (from the master key, or an
 * `AuditLog`'s pre-derived `splitBoundaryMacKey`). Never decrypts.
 *
 * Deletion of the LOWEST sealed entry IS now caught (via the MAC'd
 * `sealed_base_sequence`). Pre-V2 (null-sequence) sealed keys are not walked
 * here; a chain mixing pre-V2 sealed entries gets `verified` over its V2 sealed
 * region only.
 */
export async function verifySealedRegionAt(opts: {
  storage: Pick<StorageBackend, "list" | "read">;
  statePath: string;
  macKey: Uint8Array;
}): Promise<SealedRegionVerdict> {
  const { storage, statePath, macKey } = opts;
  const boundary = await readAuditStoreSplitBoundary(statePath, macKey);
  if (boundary.status !== "valid") return { status: "not_present" };
  const tip = boundary.boundary.sealed_tip_sequence;
  const base = boundary.boundary.sealed_base_sequence;
  if (tip <= 0) return { status: "empty" };

  let metas;
  try {
    metas = await storage.list(AUDIT_NAMESPACE);
  } catch {
    return { status: "unreadable", note: "could not list the _audit namespace" };
  }

  const bySeq = new Map<number, SealedEnvelopeV2>();
  for (const meta of metas) {
    const seq = parseEntryKeySequence(meta.key);
    if (seq === null || seq > tip) continue;
    let raw: Uint8Array | null;
    try {
      raw = await storage.read(AUDIT_NAMESPACE, meta.key);
    } catch (err) {
      const code = (err as NodeJS.ErrnoException).code;
      if (code === "EACCES" || code === "EPERM") {
        return {
          status: "unreadable",
          note: `sealed entry ${meta.key} is not readable at this privilege (re-run as root)`,
        };
      }
      return {
        status: "unreadable",
        note: `sealed entry ${meta.key} could not be read: ${failureMessage(err)}`,
      };
    }
    if (!raw) continue;
    let parsed: unknown;
    try {
      parsed = JSON.parse(bytesToString(raw));
    } catch {
      return { status: "hash_mismatch", sequence: seq, expected: "<valid V2 envelope>", actual: "<unparseable>" };
    }
    if (!isSealedEnvelopeV2(parsed)) {
      return { status: "hash_mismatch", sequence: seq, expected: "<valid V2 envelope>", actual: "<malformed envelope>" };
    }
    bySeq.set(parsed.sequence, parsed);
  }

  const presentSeqs = [...bySeq.keys()].sort((a, b) => a - b);
  const highest = presentSeqs.length > 0 ? presentSeqs[presentSeqs.length - 1]! : 0;
  const lowest = presentSeqs.length > 0 ? presentSeqs[0]! : 0;
  // Completeness: a gap-free run from the MAC'd base to the MAC'd tip. Checking
  // `lowest === base` closes the lowest-entry-deletion residual.
  if (presentSeqs.length === 0 || highest !== tip || (base > 0 && lowest !== base)) {
    return { status: "incomplete", expected_tip: tip, highest_present: highest };
  }
  for (let i = 1; i < presentSeqs.length; i++) {
    if (presentSeqs[i]! !== presentSeqs[i - 1]! + 1) {
      return { status: "incomplete", expected_tip: tip, highest_present: highest };
    }
  }

  // Crypto walk: recompute each entry hash, verify chain links among present
  // entries, and match the tip to the MAC'd sealed_tip_entry_hash.
  let prevHash: string | null = null;
  for (const seq of presentSeqs) {
    const env = bySeq.get(seq)!;
    const recomputed = computeAuditEntryHash({
      sequence: env.sequence,
      prev_hash: env.prev_hash,
      timestamp: env.timestamp,
      encrypted_payload_bytes: env.encrypted_payload_bytes,
      schema_version: env.schema_version,
    });
    if (recomputed !== env.entry_hash) {
      return { status: "hash_mismatch", sequence: seq, expected: env.entry_hash, actual: recomputed };
    }
    if (prevHash !== null && env.prev_hash !== prevHash) {
      return { status: "hash_mismatch", sequence: seq, expected: prevHash, actual: env.prev_hash };
    }
    prevHash = env.entry_hash;
  }

  const tipEnv = bySeq.get(tip)!;
  if (tipEnv.entry_hash !== boundary.boundary.sealed_tip_entry_hash) {
    return {
      status: "hash_mismatch",
      sequence: tip,
      expected: boundary.boundary.sealed_tip_entry_hash,
      actual: tipEnv.entry_hash,
    };
  }
  return { status: "verified", entries_verified: presentSeqs.length, sealed_tip_sequence: tip };
}

/**
 * BLOCKER-1 (round 3): the SINGLE audit-chain verdict every clean-claiming
 * surface must consume. `verified` ONLY when routine suffix findings are empty
 * AND the sealed region is `verified`/`empty`/`not_present`. `verified_suffix_only`
 * when the suffix is clean but the sealed region is `unreadable` (e.g. an armed
 * box's operator uid). `findings` for any routine finding OR a sealed
 * `hash_mismatch`/`incomplete`. `key_unavailable` is for callers that have no
 * verifier at all (never produced by `AuditLog.getAuditChainVerdict`, which
 * always has its keys).
 */
export type AuditChainVerdictStatus =
  | "verified"
  | "verified_suffix_only"
  | "findings"
  | "key_unavailable";

export interface AuditChainVerdict {
  status: AuditChainVerdictStatus;
  routine_finding_count: number;
  sealed_region: SealedRegionVerdict;
}

/** Fold a routine-finding count + a sealed-region verdict into the single
 * clean-claim verdict. Shared so the derivation lives in exactly one place. */
export function foldAuditChainVerdict(
  routineFindingCount: number,
  sealed: SealedRegionVerdict
): AuditChainVerdict {
  const sealedIsProblem =
    sealed.status === "hash_mismatch" || sealed.status === "incomplete";
  let status: AuditChainVerdictStatus;
  if (routineFindingCount > 0 || sealedIsProblem) {
    status = "findings";
  } else if (sealed.status === "unreadable") {
    status = "verified_suffix_only";
  } else {
    status = "verified"; // sealed verified / empty / not_present
  }
  return { status, routine_finding_count: routineFindingCount, sealed_region: sealed };
}

/**
 * Collapse the verdict for a surface that makes an explicit "verified clean /
 * no tampering / verified_against_audit_chain" CLAIM. True ONLY for a fully
 * `verified` chain (routine clean AND sealed verified/empty/not_present). A
 * `verified_suffix_only` (sealed unreadable at this privilege) is NOT a clean
 * claim and returns false; the surface should render "suffix verified, sealed
 * region unverified at this privilege", never bare "verified".
 */
export function auditChainVerdictClaimsClean(v: AuditChainVerdict): boolean {
  return v.status === "verified";
}

/**
 * Collapse the verdict for a gate whose only job is "is the audit read TAINTED
 * (active tamper); must I fail closed?"; e.g. the Castle Wall arm-state gate
 * and the custody/recognition integrity gates. Untampered = anything that is
 * NOT `findings` (which covers routine findings AND sealed hash_mismatch /
 * incomplete). A `verified_suffix_only` (sealed unreadable) is UNTAMPERED: the
 * live/suffix evidence verified, and an armed box's operator-uid simply cannot
 * read the root-owned sealed history — that must NOT flip every armed box's
 * arm-state to "unknown". Root re-verification (audit-store-status) is where a
 * root-owned sealed tamper is caught.
 */
export function auditChainVerdictUntampered(v: AuditChainVerdict): boolean {
  return v.status !== "findings";
}

/**
 * F2 round-4 HIGH-1 (2026-07-15): the AMBER caveat companion to
 * {@link auditChainVerdictUntampered}. True when the chain is untampered at
 * this privilege BUT the sealed history could not be re-verified here
 * (`verified_suffix_only`, i.e. an armed box's operator uid cannot read the
 * root-owned sealed region). An operational/arm gate may treat this as non-red
 * (untampered), but an EVIDENCE surface must NOT render it as a fully-`verified`
 * green: it renders amber ("sealed history not re-verifiable at this privilege;
 * run as root for a full verify"). Distinct from `findings` (active tamper) and
 * from `verified` (fully clean). Callers pair this with `untampered` so the
 * green claim stays reserved for `auditChainVerdictClaimsClean`.
 */
export function auditChainVerdictSealedUnverifiedAtPrivilege(
  v: AuditChainVerdict
): boolean {
  return v.status === "verified_suffix_only";
}

export class AuditLog {
  private storage: StorageBackend;
  private encryptionKey: Uint8Array;
  private rotationAnchorMacKey: Uint8Array;
  private headAnchorMacKey: Uint8Array;
  private epochWrapKey: Uint8Array;
  private epochMacKey: Uint8Array;
  /** Lazily-loaded prior-epoch audit keys (master rotations); null = not yet loaded. */
  private epochKeysCache: Uint8Array[] | null = null;
  private entries: AuditEntry[] = [];
  private chainEntries: Array<{ sequence: number; entry_hash: string }> = [];
  private counter = 0;
  /**
   * Per-instance random suffix mixed into every persisted entry key. Two
   * DISTINCT writers (two processes, or two `AuditLog` instances in one process)
   * that momentarily both believe they hold the write lock could otherwise
   * persist the SAME `entry-<seq>-<ms>-<counter>` key in the same millisecond
   * with both counters at 0, and the atomic rename would silently OVERWRITE one
   * of the two forked writes at the same path, leaving no second file for the
   * chain verifier to flag as a fork (Codex re-gate, 2026-07-15). A per-instance
   * nonce makes their keys distinct, so a double-acquire always leaves TWO files
   * at the same sequence, which the contiguous-sequence walk detects as
   * `sequence_gap_or_reorder`/`prev_hash_mismatch` (fail closed, never a silent
   * fork). The key's `^entry-<20-digit-seq>-` prefix (the only part any reader
   * parses via `parseEntryKeySequence`) is unchanged, so this is parse- and
   * sort-compatible with existing fortresses. */
  private readonly instanceKeyNonce = randomBytes(6).toString("hex");
  /** F2 Finding 1: the sealed split-boundary tip observed on the last load (0
   * when no valid boundary). Cached so the append path can tell a post-split
   * SUFFIX entry (`sequence > cachedSealedTip`) from a sealed-region one without
   * re-reading the boundary per append. */
  private cachedSealedTip = 0;
  /** F2 Finding 1: in-memory guard so the post-split-suffix-established marker is
   * written at most once per instance (it is idempotent, but this avoids a
   * `_meta` write on every suffix append). */
  private postSplitSuffixMarkerEnsured = false;
  private readonly maxTotalSizeBytes: number;
  private readonly maxEntries: number;
  /**
   * Upper bound on how many entries the instance keeps decrypted in memory
   * (`this.entries` / `this.chainEntries`). Mirrors the on-disk entry cap but
   * never drops below {@link MIN_IN_MEMORY_ENTRY_FLOOR}. Prevents the
   * append-only in-memory arrays from growing without bound on a long-running
   * daemon (the full-mode daemon OOM). The persisted log is unaffected; full
   * reads re-load from disk.
   */
  private readonly maxInMemoryEntries: number;
  private readonly integrityMode: "strict" | "lenient";
  private readonly checkpointInterval: number;
  private readonly checkpointSigner: (
    payload: AuditCheckpointSigningPayload
  ) => Promise<AuditCheckpointSignature | null>;
  private readonly checkpointPublicKeyResolver: (
    signerKid: string
  ) =>
    | AuditCheckpointKeyResolution
    | Promise<AuditCheckpointKeyResolution>;
  private readonly trustEmbeddedCheckpointPublicKeys: boolean;
  private readonly integrityAnomalySubscribers: AuditIntegrityAnomalySubscriber[];
  private readonly filesystemCapabilities?: FilesystemStorageCapabilities;
  private readonly auditWriteLockPath?: string;
  private lastIntegrityAlertSignature: string | null = null;
  private rotationInFlight = false;
  private readonly pendingWrites = new Set<Promise<void>>();
  private pendingVisibleEntries = 0;
  private appendQueue: Promise<void> = Promise.resolve();
  private loaded = false;
  private integrityFindings: AuditIntegrityFinding[] = [];
  private nextSequence = 1;
  private lastEntryHash = AUDIT_CHAIN_GENESIS;
  private hashesSinceCheckpoint: string[] = [];
  private lastCheckpointSequence = 0;
  private criticalAppendsSinceCheckpoint = 0;
  private checkpointInFlight = false;
  /**
   * Wall-clock of the most recent FULL on-disk re-verification (a complete
   * `loadPersistedEntries` pass that re-read, re-decrypted, re-hashed and
   * chain-walked every surviving entry). Drives the throttle on the eager read
   * path (`queryEager`): the in-memory verified view is maintained on EVERY
   * append (the server is the sole appender), so reads do not need a full disk
   * re-scan to be current for this-process writes; the periodic full re-scan
   * exists ONLY to catch OUT-OF-BAND on-disk tampering (a direct file edit that
   * bypasses the server). Initialized to 0 so the first eager read always pays a
   * full verify. See {@link queryEager}.
   */
  private lastFullVerifyAtMs = 0;
  /**
   * Single-flight guard for the eager-read full re-verify. A board paint fires
   * several eager reads concurrently (the `buildHome` `Promise.all`); without
   * this they could all trip the throttle and launch redundant full chain scans
   * at once (a thundering herd that mutates shared in-memory chain state in
   * parallel). They instead share ONE in-flight scan. Null when no eager full
   * verify is running.
   */
  private eagerReverifyInFlight: Promise<void> | null = null;
  /**
   * Cheap metadata fingerprint of the audit store (entry count + newest key +
   * per-entry size/mtime aggregate; see {@link auditStoreFingerprint}) as it
   * stood at the last point this process KNOWS the store was consistent: refreshed
   * after every completed full re-verify AND after each of THIS process's own
   * appends. On each eager read the sentinel recomputes the live fingerprint and
   * compares it to this expected value; a mismatch means an on-disk change NOT
   * attributable to this process (out-of-band tamper) and forces an IMMEDIATE full
   * re-verify regardless of the backstop throttle. Null until first computed.
   */
  private expectedStoreFingerprint: string | null = null;
  /** Wall-clock of the last sentinel fingerprint check, to self-throttle the
   * sentinel's own `storage.list()` to {@link AUDIT_EAGER_SENTINEL_INTERVAL_MS}
   * so the hot SSE path does not list the whole store on every read. */
  private lastSentinelCheckAtMs = 0;
  /** Backstop interval (ms) between full on-disk re-verifies on the eager path;
   * resolved once from config/env. See {@link resolveEagerReverifyIntervalMs}. */
  private readonly eagerReverifyIntervalMs: number;
  private readonly createOwner: AuditCreateOwner | undefined;
  private readonly createOwnerChown: (
    handle: AuditLockFileHandle,
    owner: AuditCreateOwner,
  ) => Promise<void>;
  private readonly createOwnerChownDirChain: (
    firstCreated: string,
    leafDir: string,
    owner: AuditCreateOwner,
  ) => Promise<void>;
  private readonly namespaceDirLstat: NonNullable<
    AuditLogConfig["namespaceDirLstat"]
  >;
  /** Age bound (ms) for the id-less 0-byte stale-lock fallback and the orphan
   * acquire-temp sweep; resolved once from config/env. See
   * {@link resolveIdlessStaleLockMs}. */
  private readonly idlessStaleLockMs: number;
  /** Deadline-bounds a single acquired lock hold; see {@link withAuditWriteLock}. */
  private readonly writeLockHoldDeadlineMs: number;
  /** Same-pid stale-lock breaker bound; must exceed {@link writeLockHoldDeadlineMs}. */
  private readonly selfHeldStaleLockMs: number;
  /** Process-local count of forced audit-write-lock recovery events. */
  private writeLockRecoveryCount = 0;
  /**
   * Process-local subscribers notified when the lock layer performs a forced
   * recovery. Listeners are observability hooks only: they are fire-and-forget
   * and can never veto or fail the append path.
   */
  private readonly writeLockRecoveryListeners: AuditWriteLockRecoveryListener[] = [];
  /** One-shot guard: the orphan `.acquire.*.tmp` sweep runs once per process on
   * the first write-lock acquire (crash-orphan temps can only predate this
   * process, so a single lazy startup sweep suffices to keep them from
   * accumulating across restarts). */
  private staleAcquireTempsSwept = false;
  /** F2 Option A: whether to consult the split-boundary record. See
   * {@link AuditLogConfig.consultSplitBoundary}. */
  private readonly consultSplitBoundary: boolean;
  /** F2 Option A: MAC key for the split-boundary record, derived up front
   * (mirrors every other purpose key on this class: the raw master is never
   * retained). */
  private readonly splitBoundaryMacKey: Uint8Array;
  /** BLOCKER-1 (round 3): memoized sealed-region verdict, keyed on the cheap
   * sealed-region fingerprint (see {@link verifySealedRegion}). The sealed
   * region is immutable post-migration, so a stable fingerprint means the
   * verdict is reusable; any tamper flips the fingerprint and forces a re-walk. */
  private cachedSealedVerdict: { fingerprint: string; verdict: SealedRegionVerdict } | null = null;

  constructor(storage: StorageBackend, masterKey: Uint8Array, config?: AuditLogConfig) {
    this.storage = storage;
    this.encryptionKey = derivePurposeKey(masterKey, "audit-log");
    // F3: derive the rotation-anchor MAC key up front and never retain the raw
    // master key (mirrors how encryptionKey is derived here, per F1's pattern).
    this.rotationAnchorMacKey = derivePurposeKey(masterKey, "audit-rotation-anchor");
    this.headAnchorMacKey = derivePurposeKey(masterKey, "audit-head-anchor");
    // F7: keys for the custody-epoch record (pre-rotation entry decryption).
    // Derived up front so the raw master is never retained on the instance.
    const epochKeys = deriveAuditEpochKeys(masterKey);
    this.epochWrapKey = epochKeys.epochWrapKey;
    this.epochMacKey = epochKeys.epochMacKey;
    this.maxTotalSizeBytes = config?.maxTotalSizeBytes ?? DEFAULT_MAX_TOTAL_SIZE_BYTES;
    this.maxEntries = config?.maxEntries ?? DEFAULT_MAX_ENTRIES;
    // In-memory window cap, decoupled from the on-disk cap: defaults to
    // `maxEntries` so behavior is unchanged unless a caller sets it explicitly,
    // but is independently configurable so the daemon can keep less in RAM than
    // it retains on disk (and so trim behavior can be exercised in isolation
    // from on-disk rotation). Never below the floor, so a usable recent window
    // survives even under a tiny cap.
    this.maxInMemoryEntries = Math.max(
      config?.maxInMemoryEntries ?? this.maxEntries,
      MIN_IN_MEMORY_ENTRY_FLOOR
    );
    this.integrityMode = config?.integrityMode ?? "strict";
    this.checkpointInterval =
      config?.checkpointInterval ?? DEFAULT_CHECKPOINT_INTERVAL;
    // IC-05 enforcement site (AGENTS.md assurance rule 3): the checkpoint
    // signer/resolver pair used to be an optional dependency that every test
    // supplied and every production call site omitted, so shipped fortresses
    // wrote unsigned checkpoints and distrusted signed ones. Rule 3 offers
    // "make it required" or "fail closed on absence"; this site takes the
    // stronger third form: the production pair is DERIVED from the
    // constructor's own required arguments (storage + master key), so no call
    // site can omit it. Explicit config remains the injection seam and wins
    // per field. Fail-closed-on-absence was rejected one level down instead
    // of here: a fortress legitimately has zero identities until bootstrap,
    // and refusing audit appends then would make audit availability depend on
    // identity existence; that case degrades to the honest `unsigned`
    // checkpoint record, never to a silently trusted fallback key.
    const fortressCheckpointIdentity = createFortressCheckpointIdentityBinding(
      storage,
      derivePurposeKey(masterKey, "identity-encryption")
    );
    this.checkpointSigner =
      config?.checkpointSigner ?? fortressCheckpointIdentity.checkpointSigner;
    this.checkpointPublicKeyResolver =
      config?.checkpointPublicKeyResolver ??
      fortressCheckpointIdentity.checkpointPublicKeyResolver;
    this.trustEmbeddedCheckpointPublicKeys =
      config?.trustEmbeddedCheckpointPublicKeys ?? false;
    this.integrityAnomalySubscribers = config?.integrityAnomalySubscribers ?? [];
    this.eagerReverifyIntervalMs = resolveEagerReverifyIntervalMs(
      config?.eagerReverifyIntervalMs
    );
    this.createOwner = config?.createOwner;
    this.createOwnerChown =
      config?.createOwnerChown ??
      ((handle, owner) => handle.chown(owner.uid, owner.gid));
    this.createOwnerChownDirChain =
      config?.createOwnerChownDirChain ?? chownCreatedDirChain;
    this.namespaceDirLstat = config?.namespaceDirLstat ?? ((path) => lstat(path));
    this.idlessStaleLockMs = resolveIdlessStaleLockMs(config?.idlessStaleLockMs);
    this.writeLockHoldDeadlineMs = resolveWriteLockHoldDeadlineMs(
      config?.writeLockHoldDeadlineMs
    );
    this.selfHeldStaleLockMs = resolveSelfHeldStaleLockMs(
      config?.selfHeldStaleLockMs,
      this.writeLockHoldDeadlineMs
    );
    this.consultSplitBoundary = config?.consultSplitBoundary ?? true;
    this.splitBoundaryMacKey = deriveAuditStoreSplitBoundaryMacKey(masterKey);
    this.filesystemCapabilities = asFilesystemCapabilities(storage);
    if (this.filesystemCapabilities) {
      this.auditWriteLockPath = join(
        this.filesystemCapabilities.namespacePath(AUDIT_NAMESPACE),
        AUDIT_WRITE_LOCK_FILE
      );
      // SAFETY: one-time startup announcement of the audit-write coordination
      // mechanism, routed to STDERR via console.error. Operators need to see
      // this so they can locate the lock file and inspect lsof on it if writes
      // appear stuck. It must NEVER touch stdout: on an MCP stdio boot stdout
      // is the JSON-RPC channel, and console.info writes to stdout in Node
      // (this line was empirically the first stdout byte, ahead of the
      // initialize response).
      console.error(
        `[audit-log] cross-process file locking enabled: ${this.auditWriteLockPath}`
      );
    }
  }

  /**
   * Subscribe to audit-write-lock recovery events. The hook is intentionally
   * process-local and observability-only: callbacks run fire-and-forget, and any
   * thrown/rejected listener failure is swallowed so recovery cannot become a new
   * audit append failure mode.
   */
  onWriteLockRecovery(listener: AuditWriteLockRecoveryListener): void {
    this.writeLockRecoveryListeners.push(listener);
  }

  /** Process-local count of forced audit-write-lock recovery events. */
  getWriteLockRecoveryCount(): number {
    return this.writeLockRecoveryCount;
  }

  private recordWriteLockRecoveryEvent(event: AuditWriteLockRecoveryEvent): void {
    this.writeLockRecoveryCount++;
    for (const listener of this.writeLockRecoveryListeners) {
      try {
        const maybePromise = listener(event) as unknown;
        if (
          maybePromise &&
          typeof (maybePromise as { then?: unknown }).then === "function"
        ) {
          void Promise.resolve(maybePromise).catch(() => undefined);
        }
      } catch {
        // Listener hooks must never throw into the append path.
      }
    }
  }

  /**
   * Append a best-effort audit entry for low-risk telemetry.
   *
   * The on-disk persist is async and tracked via `pendingWrites`, but callers
   * are allowed to proceed without awaiting it. Use this only for read-path
   * observations, health/heartbeat events, low-resolution metrics, and other
   * telemetry where losing the entry must not change the trust decision.
   *
   * Failure contract (both boundaries fail loud, neither silently degrades):
   *   - awaited: the returned promise rejects with `AuditPersistenceError`
   *     at the call site;
   *   - un-awaited (`void`): the failure stays tracked in `pendingWrites`
   *     and is rethrown by `flush()` as `AuditLogPersistenceError`.
   * An un-awaited call never produces an unhandled rejection (the tracking
   * handler below consumes it).
   *
   * Critical state changes, approval decisions, identity/key operations,
   * policy changes, egress denials, and export/exit operations MUST use
   * `appendCritical()` instead.
   */
  append(
    layer: AuditEntry["layer"],
    operation: string,
    identityId: string,
    details?: Record<string, unknown>,
    result: "success" | "failure" = "success"
  ): Promise<void> {
    this.pendingVisibleEntries++;
    const writePromise = this.enqueueAppend({
      layer,
      operation,
      identity_id: identityId,
      result,
      details,
    }, { verifyDurability: false, critical: false });
    this.trackPendingWrite(writePromise);
    return writePromise;
  }

  /**
   * Append a critical audit entry and resolve only after the storage backend
   * has accepted and round-trip verified the exact encrypted bytes.
   *
   * Filesystem durability depends on the configured StorageBackend. The
   * current backend contract exposes `write()` but not a portable fsync hook,
   * so this method treats a completed write plus exact read-after-write
   * verification as the backend-equivalent durability barrier. Storage
   * failures, disk-full conditions, permission failures, and partial/torn
   * writes throw `AuditPersistenceError` with a classification. Like
   * `append()`, the returned promise is tracked until it settles: an awaited
   * caller gets the rejection at the call site, and a fire-and-forget caller's
   * failure is rethrown by `flush()`.
   */
  appendCritical(entry: AuditEntryInput): Promise<void> {
    const writePromise = this.enqueueAppend(entry, {
      verifyDurability: true,
      critical: true,
    });
    this.trackPendingWrite(writePromise);
    return writePromise;
  }

  async runAllowingIntegrityFindings<T>(fn: () => Promise<T>): Promise<T> {
    return auditIntegrityContext.run({ allowIntegrityFindings: true }, fn);
  }

  async getIntegrityFindings(): Promise<AuditIntegrityFinding[]> {
    await this.appendQueue;
    await this.ensureLoaded({ allowIntegrityFindings: true });
    return [...this.integrityFindings];
  }

  private trackPendingWrite(writePromise: Promise<void>): void {
    this.pendingWrites.add(writePromise);
    void writePromise.then(
      () => this.pendingWrites.delete(writePromise),
      () => this.pendingWrites.delete(writePromise)
    );
  }

  /**
   * F2 Option A: the current chain tip (sequence 0 / `AUDIT_CHAIN_GENESIS`
   * for an empty chain). Used by `migrateFortressAuditStoreSplit` to compute
   * the split-boundary record's sealed tip, and by any other caller that
   * needs the verified head without appending. Loads (and integrity-checks,
   * in whatever `integrityMode` this instance was constructed with) first.
   */
  async getChainHead(): Promise<{ sequence: number; entry_hash: string }> {
    await this.appendQueue;
    await this.ensureLoaded({ allowIntegrityFindings: true });
    return { sequence: this.nextSequence - 1, entry_hash: this.lastEntryHash };
  }

  /**
   * BLOCKER-1 (adversarial re-gate round 3, 2026-07-14; hardened round 5,
   * 2026-07-15): crypto-re-verify the sealed legacy region's CONTENT using this
   * instance's own `storage` + `splitBoundaryMacKey` (no master key needed; the
   * walk reads envelope bytes and recomputes hashes). Memoized on a
   * CONTENT-authenticated sealed-region fingerprint (see
   * {@link sealedRegionFingerprint}): the fingerprint reads the same stored
   * envelope bytes the verifier reads and folds them into a SHA-256, so any
   * in-place edit or deletion of a sealed entry flips it and forces a full
   * re-walk. A cache hit skips only the more expensive decrypt-free chain
   * recompute + tip-MAC match, not the tamper check itself. Returns
   * `not_present` for a non-filesystem backend or a daemon instance
   * (`consultSplitBoundary: false`).
   *
   * Round-5 note: the prior fingerprint keyed on count + size/mtime metadata,
   * which the exact in-place sealed-tamper adversary can forge (a same-length
   * ciphertext-byte flip preserves size; `utimes`/`touch -r` restores mtime),
   * so a long-lived process served a STALE `verified` over a real sealed tamper.
   * Metadata is NOT a tamper-detection guarantee; only reading the bytes is.
   */
  async verifySealedRegion(): Promise<SealedRegionVerdict> {
    if (!this.consultSplitBoundary || !this.filesystemCapabilities) {
      return { status: "not_present" };
    }
    const statePath = dirname(
      this.filesystemCapabilities.namespacePath(AUDIT_NAMESPACE)
    );
    // A fingerprint read failure yields NULL, never a shared sentinel string: a
    // sentinel key could collide with itself across calls (throw -> cache under
    // sentinel -> later throw -> stale hit on a non-content key). Null always
    // misses the cache AND is never cached, so every failed-fingerprint call
    // does a fresh walk (round-5 gate hardening).
    let fingerprint: string | null;
    try {
      fingerprint = await this.sealedRegionFingerprint();
    } catch {
      fingerprint = null; // force a fresh walk; result not cacheable
    }
    if (
      this.cachedSealedVerdict &&
      this.cachedSealedVerdict.fingerprint === fingerprint
    ) {
      return this.cachedSealedVerdict.verdict;
    }
    const verdict = await verifySealedRegionAt({
      storage: this.storage,
      statePath,
      macKey: this.splitBoundaryMacKey,
    });
    // Only cache a stable/terminal verdict under a REAL content fingerprint; an
    // `unreadable` may be transient (a race with a chmod), and a null
    // fingerprint (fingerprint read failed) must never be a cache key (null
    // would match null on the next failed read and serve a stale verdict).
    if (verdict.status !== "unreadable" && fingerprint !== null) {
      this.cachedSealedVerdict = { fingerprint, verdict };
    }
    return verdict;
  }

  /** CONTENT-authenticated fingerprint of ONLY the sealed region (entries at or
   * below the boundary tip). Reads the SAME stored envelope bytes the verifier
   * ({@link verifySealedRegionAt}) reads and folds each entry's key + raw bytes
   * into a SHA-256, so any in-place byte edit or deletion of a sealed entry
   * changes the digest and forces a re-walk. It deliberately does NOT use file
   * size/mtime: both are attacker-forgeable (a same-length ciphertext-byte flip
   * preserves size; mtime can be restored via `utimes`), so metadata can never
   * be the trust basis for reusing a cached `verified`. Returns "no-boundary"
   * when there is no valid boundary (nothing sealed) so the memo key is stable
   * for the common case; "empty" when the boundary sealed an empty chain.
   * Propagates a read error (e.g. EACCES on an armed box) to the caller, which
   * forces a walk that reports `unreadable` (and is not cached). */
  private async sealedRegionFingerprint(): Promise<string> {
    const boundary = await this.loadSplitBoundary();
    if (boundary.status !== "valid") return "no-boundary";
    const tip = boundary.boundary.sealed_tip_sequence;
    if (tip <= 0) return "empty";
    const metas = await this.storage.list(AUDIT_NAMESPACE, "entry-");
    const sealed = metas.filter((m) => {
      const seq = parseEntryKeySequence(m.key);
      return seq !== null && seq <= tip;
    });
    sealed.sort((a, b) => a.key.localeCompare(b.key));
    // Fold the actual stored bytes of every sealed entry into the digest. Any
    // in-place tamper flips a per-entry hash; a deletion drops a key from the
    // run (marked "<absent>" if it vanishes between list and read). A read
    // failure throws out of here so the caller falls through to a fresh walk.
    const parts: string[] = [`tip=${tip}`, `count=${sealed.length}`];
    for (const m of sealed) {
      const raw = await this.storage.read(AUDIT_NAMESPACE, m.key);
      parts.push(`${m.key}:${raw ? sha256Hex(raw) : "<absent>"}`);
    }
    return sha256Hex(parts.join("\n"));
  }

  /**
   * BLOCKER-1 (round 3): the SINGLE audit-chain verdict every clean-claiming
   * surface must consume instead of deriving "clean" from
   * `query().integrity_findings.length === 0` (which skips the sealed region
   * and lies over in-place sealed tamper). Folds the routine suffix findings
   * with the sealed-region crypto verdict. `verified` ONLY when routine findings
   * are empty AND sealed is verified/empty/not_present.
   */
  async getAuditChainVerdict(): Promise<AuditChainVerdict> {
    const routine = await this.getIntegrityFindings();
    const sealed = await this.verifySealedRegion();
    return foldAuditChainVerdict(routine.length, sealed);
  }

  /**
   * Wait for every in-flight `append()` persist (and its rotation pass) to
   * settle. Rejects with `AuditLogPersistenceError` if any tracked persist
   * failed. Safe to call multiple times — newly-appended entries during a
   * flush are also awaited. Re-entrant only at the granularity of "drain
   * everything queued so far". Short-lived CLIs MUST call this before
   * `process.exit()` to keep audit writes durable.
   */
  async flush(): Promise<void> {
    const failures: unknown[] = [];
    while (this.pendingWrites.size > 0) {
      const results = await Promise.allSettled([...this.pendingWrites]);
      for (const result of results) {
        if (result.status === "rejected") failures.push(result.reason);
      }
    }
    if (failures.length > 0) {
      throw new AuditLogPersistenceError(failures);
    }
    await this.appendQueue;
    await this.writeCheckpointIfNeeded("graceful-shutdown");
  }

  private enqueueAppend(
    entry: AuditEntryInput,
    options: { verifyDurability: boolean; critical: boolean }
  ): Promise<void> {
    const task = this.appendQueue
      .catch(() => {
        // Keep later appends from inheriting a prior append failure.
      })
      .then(() => this.persistChainedEntry(entry, options));
    this.appendQueue = task.then(
      () => undefined,
      () => undefined
    );
    return task;
  }

  private async persistChainedEntry(
    entry: AuditEntryInput,
    options: { verifyDurability: boolean; critical: boolean }
  ): Promise<void> {
    try {
      const normalized = this.normalizeEntry(entry);
      await this.reverifyCachedIntegrityFindingsBeforeAppend();
      const serialized = stringToBytes(JSON.stringify(normalized));
      const encrypted = encrypt(serialized, this.encryptionKey);
      const encryptedBytes = stringToBytes(JSON.stringify(encrypted));
      const encryptedPayloadBytes = toBase64url(encryptedBytes);
      await this.withAuditWriteLock(async (signal) => {
        this.assertAuditWriteLockActive(signal);
        // LOCK-HOLD COST: on this process's FIRST append this is a full
        // load-and-verify pass held inside the cross-process write lock, and the
        // read-consistency retry can make it two. See the KNOWN LATENCY EXPOSURE
        // note in `loadPersistedEntriesWithReadConsistency` for the measured
        // bound and why it is accepted rather than mitigated here.
        await this.ensureLoaded();
        this.assertAuditWriteLockActive(signal);
        await this.freshenChainStateFromDisk();
        this.assertAuditWriteLockActive(signal);
        const sequence = this.nextSequence;
        const prevHash = this.lastEntryHash;
        // Hash-chain invariant: the entry hash covers the previous hash and the
        // encrypted payload bytes, so changing either content or position in the
        // append-only chain changes the digest checked on every reload.
        const entryHash = computeAuditEntryHash({
          sequence,
          prev_hash: prevHash,
          timestamp: normalized.timestamp,
          encrypted_payload_bytes: encryptedPayloadBytes,
          schema_version: AUDIT_CHAIN_SCHEMA_VERSION,
        });
        const envelope: PersistedAuditEnvelopeV2 = {
          schema_version: AUDIT_CHAIN_SCHEMA_VERSION,
          sequence,
          prev_hash: prevHash,
          entry_hash: entryHash,
          timestamp: normalized.timestamp,
          encrypted_payload_bytes: encryptedPayloadBytes,
        };
        const key = `entry-${String(sequence).padStart(20, "0")}-${Date.now()}-${this.counter++}-${this.instanceKeyNonce}`;
        const persistedBytes = stringToBytes(JSON.stringify(envelope));
        try {
          this.assertAuditWriteLockActive(signal);
          await this.writeAuditEntryBytes(key, persistedBytes);
          this.assertAuditWriteLockActive(signal);

          if (options.verifyDurability) {
            this.assertAuditWriteLockActive(signal);
            await this.verifyPersistedBytes(key, persistedBytes);
            this.assertAuditWriteLockActive(signal);
          }
          this.assertAuditWriteLockActive(signal);
          // ORDERING INVARIANT (must match the anchor-before-listing read order
          // in `loadPersistedEntries`): the entry file is durably on disk BEFORE
          // the anchor claims its sequence, so a floor of N is only ever
          // published after entry N was written. A reader that samples the
          // anchor AFTER listing the entries loses that ordering (an append can
          // land in between) and reports a live append as tail truncation.
          // The converse is deliberately NOT claimed: a floor of N does not
          // prove entry N still exists at read time, and an N that has since
          // been deleted is precisely the truncation `verifyHeadAnchor` catches.
          await this.writeHeadAnchor(sequence, entryHash);
          this.assertAuditWriteLockActive(signal);
          // F2 Finding 1: the FIRST time this operator instance persists a
          // post-split SUFFIX entry (above the sealed tip) under boundary
          // consultation, record the operator-provenance "suffix established"
          // marker. Thereafter an unreadable/erased head anchor with the suffix
          // gone is proven tamper (fail closed), not a benign just-migrated box.
          // Best-effort + off the durability-critical path: a failure to stamp
          // it must never brick an append (worst case the next append retries);
          // the marker only tightens Finding 1's full-suffix-erasure case, which
          // the `sequence > tip` gate already covers for surviving suffixes.
          if (
            this.consultSplitBoundary &&
            !this.postSplitSuffixMarkerEnsured &&
            sequence > this.cachedSealedTip &&
            this.cachedSealedTip > 0
          ) {
            try {
              this.assertAuditWriteLockActive(signal);
              await this.storage.write(
                AUDIT_META_NAMESPACE,
                AUDIT_POST_SPLIT_SUFFIX_ESTABLISHED_KEY,
                stringToBytes("1")
              );
              this.assertAuditWriteLockActive(signal);
              this.postSplitSuffixMarkerEnsured = true;
            } catch {
              // Non-fatal; retried on the next suffix append.
            }
          }
        } catch (err) {
          throw toAuditPersistenceError(err);
        }

        this.entries.push(normalized);
        this.chainEntries.push({ sequence, entry_hash: entryHash });
        this.nextSequence = sequence + 1;
        this.lastEntryHash = entryHash;
        this.hashesSinceCheckpoint.push(entryHash);
        // Bound the in-memory recent-entry window. Without this the arrays grow
        // one element per append forever (the long-running-daemon OOM); disk
        // rotation never touched them. Trimming here keeps the heap flat while
        // the persisted log (and every full re-read) stays complete.
        this.trimInMemoryRetention();
        if (options.critical) {
          this.criticalAppendsSinceCheckpoint++;
        }
      });

      if (
        options.critical &&
        this.checkpointInterval > 0 &&
        this.criticalAppendsSinceCheckpoint >= this.checkpointInterval
      ) {
        await this.writeCheckpointIfNeeded("critical-interval");
      }

      // Rotation runs as part of the same tracked promise so flush() also
      // covers any prune-driven deletes.
      await this.maybeRotate().catch(() => {
        // Rotation failure is non-fatal
      });

      // Re-baseline the eager-read sentinel fingerprint to the post-append (and
      // post-rotation) on-disk state. This is what keeps the server's OWN appends
      // from tripping the sentinel into a redundant full re-verify (which would
      // kill the perf win); only out-of-band edits (NOT attributable to this
      // process) change the fingerprint away from this baseline. Cheap metadata
      // list, no decrypt. Best-effort: a list failure leaves the prior baseline.
      await this.refreshExpectedStoreFingerprint();
    } finally {
      if (!options.critical && this.pendingVisibleEntries > 0) {
        this.pendingVisibleEntries--;
      }
    }
  }

  /**
   * Cap the decrypted recent-entry window held in memory.
   *
   * `this.entries` is `[legacy..., chained...]`; the chained suffix aligns 1:1
   * with `this.chainEntries`. We trim the OLDEST entries from the front of both
   * arrays in lockstep so the alignment invariant
   * (`entries.length - chainEntries.length` === surviving legacy count) is
   * preserved: dropping `n` from the front of `entries` while dropping the same
   * count of the oldest aligned `chainEntries` removes legacy entries first (no
   * chained counterpart) and only then chained entries (each with its
   * `chainEntries` twin). `this.hashesSinceCheckpoint` is bounded the same way.
   *
   * SAFETY: this only drops the in-memory cache of OLD entries. The persisted
   * log is untouched, the verified chain HEAD is tracked by `nextSequence` /
   * `lastEntryHash` (not the array tail), checkpoint roots are computed from
   * disk (`collectPersistedEntryHashes`), and `verifiedChainView()` / `query()`
   * re-read the full chain from disk before serving. So trimming the in-memory
   * window changes no on-the-wire, on-disk, or verification behavior; it only
   * stops the heap from growing without bound on a long-running daemon.
   */
  private trimInMemoryRetention(): void {
    const cap = this.maxInMemoryEntries;
    const overflow = this.entries.length - cap;
    if (overflow > 0) {
      // Drop the oldest `overflow` entries from the front. The chained suffix
      // shrinks by however many of those dropped entries were chained, which is
      // exactly `overflow` once the legacy prefix has been consumed; before
      // that, dropped entries are legacy-only and `chainEntries` is left intact.
      const legacyCount = this.entries.length - this.chainEntries.length;
      this.entries.splice(0, overflow);
      const chainedDropped = Math.max(0, overflow - legacyCount);
      if (chainedDropped > 0) {
        this.chainEntries.splice(0, chainedDropped);
      }
    }
    if (this.hashesSinceCheckpoint.length > cap) {
      this.hashesSinceCheckpoint.splice(
        0,
        this.hashesSinceCheckpoint.length - cap
      );
    }
  }

  private normalizeEntry(entry: AuditEntryInput): AuditEntry {
    return {
      timestamp: entry.timestamp ?? new Date().toISOString(),
      layer: entry.layer,
      operation: entry.operation,
      identity_id: entry.identity_id,
      result: entry.result,
      details: entry.details,
      ...(entry.contributors !== undefined ? { contributors: entry.contributors } : {}),
    };
  }

  private async verifyPersistedBytes(
    key: string,
    expected: Uint8Array
  ): Promise<void> {
    let stored: Uint8Array | null;
    try {
      stored = await this.storage.read(AUDIT_NAMESPACE, key);
    } catch (err) {
      throw new AuditPersistenceError(
        failureMessage(err),
        classifyFailure(err),
        err
      );
    }
    if (!stored || !bytesEqual(stored, expected)) {
      throw new AuditPersistenceError(
        "audit persistence write failed: persisted bytes did not round-trip",
        "partial_write"
      );
    }
  }

  /** Number of oldest entries to prune to bring `metas` (key-sorted ascending)
   * back under the count and size limits. 0 when within budget. */
  private rotationDeleteCount(metas: readonly { size_bytes: number }[]): number {
    const totalSize = metas.reduce((sum, m) => sum + m.size_bytes, 0);
    let toDelete = 0;
    if (metas.length > this.maxEntries) {
      toDelete = metas.length - this.maxEntries;
    }
    if (totalSize > this.maxTotalSizeBytes) {
      let runningSize = totalSize;
      for (
        let i = toDelete;
        i < metas.length && runningSize > this.maxTotalSizeBytes;
        i++
      ) {
        runningSize -= metas[i]!.size_bytes;
        toDelete = i + 1;
      }
    }
    return toDelete;
  }

  /**
   * Prune oldest audit entries when storage exceeds configured limits.
   * Entries are sorted by key (timestamp-based) so oldest are pruned first.
   */
  private async maybeRotate(): Promise<void> {
    if (this.rotationInFlight) return;
    this.rotationInFlight = true;
    try {
      // F2 Option A: a valid split boundary is an UNPRUNABLE floor. Rotation
      // sorts oldest-first and deletes from the bottom, so without this an
      // over-cap chain would eventually select sealed (possibly root-owned,
      // possibly unreadable) legacy entries as prune candidates, silently
      // destroying exactly the history the boundary promises to preserve
      // ("nothing before the boundary is deleted, repaired, or rewritten";
      // see the module doc comment). `storage.delete()` on most POSIX
      // filesystems only needs write permission on the DIRECTORY, not the
      // target file, so an unreadable sealed entry would otherwise still be
      // deletable: this filter is the actual enforcement of that promise,
      // not just a permission accident to route around.
      const splitBoundary = await this.loadSplitBoundary();
      const sealedTipSequence =
        splitBoundary.status === "valid" ? splitBoundary.boundary.sealed_tip_sequence : 0;
      // L-1 (adversarial gate 2026-07-14): when a valid boundary seals a region,
      // a pre-V2 (null-sequence) `entry` key CANNOT be proven to sit above the
      // sealed tip, and it may well belong to the sealed legacy region (a
      // fortress old enough to hold pre-V2 entries that later armed a root
      // daemon). Treat null-sequence keys as AT/BELOW the floor (protected,
      // unprunable) whenever a boundary is in force, matching the "nothing
      // before the boundary is deleted" promise. When there is no boundary
      // (sealedTipSequence === 0), preserve the pre-F2 behavior exactly: legacy
      // keys are prunable oldest-first as they always were.
      const boundaryInForce = sealedTipSequence > 0;
      const abovesSealedFloor = (meta: { key: string }): boolean => {
        const seq = parseEntryKeySequence(meta.key);
        if (seq === null) return !boundaryInForce;
        return seq > sealedTipSequence;
      };

      // Cheap lock-free pre-check: only pay the cross-process lock cost when a
      // prune is actually due. storage.list() returns key-sorted entries.
      const preMetas = (await this.storage.list(AUDIT_NAMESPACE)).filter(
        abovesSealedFloor
      );
      if (this.rotationDeleteCount(preMetas) <= 0) return;

      // F3: serialize the anchor write + prune under the SAME cross-process lock
      // the append path uses. Without this, two AuditLog instances rotating the
      // same namespace race their cut points: a late finisher could write a
      // stale (lower) base_sequence after another process already pruned farther,
      // leaving a MAC-valid anchor pointing at a non-surviving entry — strict
      // readers would then throw on a legitimate concurrent rotation. The lock is
      // a no-op for non-filesystem backends. maybeRotate is called from
      // persistChainedEntry AFTER its own lock has been released, so this
      // re-acquisition cannot deadlock (mirrors writeCheckpointIfNeeded).
      await this.withAuditWriteLock(async (signal) => {
        // Re-list INSIDE the lock: another rotator may have pruned since the
        // pre-check, so recompute the cut against the authoritative state.
        this.assertAuditWriteLockActive(signal);
        const metas = (await this.storage.list(AUDIT_NAMESPACE)).filter(
          abovesSealedFloor
        );
        this.assertAuditWriteLockActive(signal);
        metas.sort((a, b) => a.key.localeCompare(b.key));
        // Always keep at least one entry as the surviving anchor base — even
        // under degenerate caps (maxEntries: 0, or maxTotalSizeBytes smaller than
        // a single entry, where rotationDeleteCount would otherwise return
        // metas.length). Capping rather than aborting lets rotation still make
        // progress (prune as much as possible) instead of growing without bound.
        const toDelete = Math.min(
          this.rotationDeleteCount(metas),
          metas.length - 1
        );
        if (toDelete <= 0) return;

        // Authenticate the cut BEFORE pruning. The new lowest-surviving entry is
        // metas[toDelete] (v2 keys are zero-padded by sequence; legacy v1 keys —
        // `${epochMs}-${n}` — are digit-prefixed and sort BEFORE `entry-`, so
        // they prune first and never interleave). Only prune once we have either
        // (a) written a MAC anchor for a v2 cut, or (b) confirmed the cut lands on
        // a legacy/non-v2 entry (the legacy-anchor path covers that prefix). If we
        // cannot read/parse the new base, or the anchor write fails, ABORT the
        // prune: deleting without an authenticated anchor would let the next load
        // silently TOFU-re-anchor an unauthenticated cut, defeating the
        // fail-closed guarantee. Rotation retries on the next append.
        let safeToPrune = false;
        try {
          this.assertAuditWriteLockActive(signal);
          const newBaseRaw = await this.storage.read(
            AUDIT_NAMESPACE,
            metas[toDelete]!.key
          );
          this.assertAuditWriteLockActive(signal);
          if (newBaseRaw) {
            const parsed = JSON.parse(bytesToString(newBaseRaw));
            if (isPersistedAuditEnvelopeV2(parsed)) {
              this.assertAuditWriteLockActive(signal);
              await this.writeRotationAnchor(parsed.sequence, parsed.prev_hash);
              this.assertAuditWriteLockActive(signal);
            }
            // Reached only if the v2 anchor was written, or the cut is legacy/
            // non-v2 (no chained anchor needed) — both are safe to prune.
            safeToPrune = true;
          }
        } catch {
          safeToPrune = false;
        }
        if (!safeToPrune) return;

        for (let i = 0; i < toDelete; i++) {
          this.assertAuditWriteLockActive(signal);
          await this.storage.delete(AUDIT_NAMESPACE, metas[i]!.key);
          this.assertAuditWriteLockActive(signal);
        }
      });
    } finally {
      this.rotationInFlight = false;
    }
  }

  /**
   * F3: persist the single MAC-authenticated rotation anchor, overwriting any
   * prior one as the cut moves forward. The MAC is keyed from the master key
   * (always available) — NOT the optional Ed25519 checkpoint signer — so the
   * cut is always authenticated.
   *
   * Uses the durable (fsync) write barrier on filesystem backends, mirroring
   * audit-entry persistence. The caller (maybeRotate) prunes entries immediately
   * after this resolves; without the fsync, a power loss after the deletes reach
   * disk but before the anchor flushes would leave a post-F3 rotation with no
   * authenticated cut, reloading through the anchor-absent TOFU path.
   */
  private async writeRotationAnchor(
    baseSequence: number,
    basePrevHash: string
  ): Promise<void> {
    const data = { base_sequence: baseSequence, base_prev_hash: basePrevHash };
    const envelope = {
      [AUDIT_ROTATION_ANCHOR_MARKER]: true,
      data,
      mac: toBase64url(this.rotationAnchorMacBytes(data)),
    };
    const bytes = stringToBytes(JSON.stringify(envelope));
    if (this.filesystemCapabilities) {
      await this.filesystemCapabilities.writeDurable(
        AUDIT_CHECKPOINT_NAMESPACE,
        AUDIT_ROTATION_ANCHOR_KEY,
        bytes
      );
      return;
    }
    await this.storage.write(
      AUDIT_CHECKPOINT_NAMESPACE,
      AUDIT_ROTATION_ANCHOR_KEY,
      bytes
    );
  }

  /** Domain-separated master-key MAC over the rotation-anchor `data` record. */
  private rotationAnchorMacBytes(data: {
    base_sequence: number;
    base_prev_hash: string;
  }): Uint8Array {
    return hmacSha256(
      this.rotationAnchorMacKey,
      stringToBytes(AUDIT_ROTATION_ANCHOR_MAC_DOMAIN + canonicalJson(data))
    );
  }

  /**
   * F2 Option A: resolve this instance's own `_audit`-directory-adjacent
   * split-boundary path and load + MAC-verify the record there. Returns
   * `absent` (a pure no-op default, see the module doc comment) when
   * `consultSplitBoundary` is false, when there is no filesystem capability
   * (non-filesystem backend, mirroring the rotation anchor's own gating), or
   * when the record does not exist / cannot be read at this privilege.
   */
  private async loadSplitBoundary(): Promise<AuditStoreSplitBoundaryLoadResult> {
    if (!this.consultSplitBoundary || !this.filesystemCapabilities) {
      return { status: "absent" };
    }
    const auditDir = this.filesystemCapabilities.namespacePath(AUDIT_NAMESPACE);
    return readAuditStoreSplitBoundary(dirname(auditDir), this.splitBoundaryMacKey);
  }

  /**
   * F2 Option A + BLOCKER-2 (adversarial gate 2026-07-14): probe whether the
   * split migration has EVER run on this fortress, independent of the boundary
   * record itself. The daemon's own `_audit-daemon` namespace (its genesis
   * marker entry) is the durable proof the migration committed; its siblings
   * (`_audit-daemon_checkpoints`/`_audit-daemon_meta`) are secondary markers.
   * If any of them holds an entry, a MISSING boundary is a DELETION of the
   * boundary, not a never-migrated fortress, and must fail closed rather than
   * silently fall back to a full walk that a truncated-suffix attacker could
   * ride via rotation-anchor TOFU. Metadata-only (`list`), never decrypts, so
   * it is safe cross-uid.
   */
  private async daemonMigrationMarkerExists(): Promise<boolean> {
    // BLOCKER-R2 + HIGH-1 (round 3): the durable `_meta` established marker is
    // checked FIRST because it is NOT co-deletable with the daemon namespace
    // set. Both `present` (authentic) AND `invalid_or_unreadable` (corrupted /
    // unreadable record) count as migration evidence and fail closed; the
    // round-2 code only checked `=== "present"`, which let an attacker CORRUPT
    // the marker to collapse it to "absent" and re-open the TOFU fail-open.
    // Only a genuinely-`absent` marker (no record at all) is not evidence.
    if (
      (await readAuditStoreSplitEstablishedMarker(
        this.storage,
        this.splitBoundaryMacKey
      )) !== "absent"
    ) {
      return true;
    }
    for (const ns of AUDIT_DAEMON_MIGRATION_MARKER_NAMESPACES) {
      try {
        if ((await this.storage.list(ns)).length > 0) return true;
      } catch {
        // A listing error is itself suspicious (a marker dir we cannot
        // enumerate). Treat it as "marker may exist" so an absent boundary
        // fails closed rather than fails open.
        return true;
      }
    }
    return false;
  }

  /**
   * F2 Option A + BLOCKER-1/BLOCKER-2 (adversarial gate 2026-07-14): resolve
   * the split boundary for a LOAD, deriving integrity findings and the TOFU
   * suppression flag. This is the single chokepoint that decides how the load
   * treats the boundary:
   *
   *   - `valid`  : filter the sealed region (effectiveSealedTip = the MAC'd
   *     tip); no boundary-level finding; TOFU not suppressed (a later rotation
   *     of the POST-split chain is still a legitimate F3 cut). The sealed
   *     region's completeness is checked separately by
   *     {@link checkSealedPrefixCompleteness}.
   *   - `invalid`: a PRESENT boundary that fails MAC authentication. Surface a
   *     `split_boundary_invalid` finding (fail closed) and DO NOT filter
   *     (effectiveSealedTip = 0 → full walk, which re-throws F2 on an armed box
   *     = fail closed). Suppress TOFU so a boundary-loss + prefix-deletion
   *     cannot be laundered into an authenticated rotation cut.
   *   - `absent` + a durable migration marker exists: the boundary was DELETED
   *     after a real migration. Surface `split_boundary_missing`, do not filter,
   *     suppress TOFU. Same fail-closed posture as `invalid`.
   *   - `absent` + no marker: genuinely never migrated (the overwhelming
   *     majority). No finding, no filter, TOFU allowed exactly as pre-F2.
   */
  private async resolveSplitBoundaryForLoad(
    findings: AuditIntegrityFinding[]
  ): Promise<{
    boundary: AuditStoreSplitBoundaryLoadResult;
    effectiveSealedTip: number;
    suppressTofu: boolean;
  }> {
    // When boundary consultation is disabled (the DAEMON chain's own AuditLog,
    // constructed with `consultSplitBoundary: false`, i.e. it IS the daemon
    // store, not the operator store), do NOTHING: no boundary read, no marker probe
    // (its remap adapter does not even expose the marker namespaces), no
    // finding. Same for a non-filesystem backend. This mirrors
    // `loadSplitBoundary`'s own early return.
    if (!this.consultSplitBoundary || !this.filesystemCapabilities) {
      return { boundary: { status: "absent" }, effectiveSealedTip: 0, suppressTofu: false };
    }
    const boundary = await this.loadSplitBoundary();
    if (boundary.status === "valid") {
      return {
        boundary,
        effectiveSealedTip: boundary.boundary.sealed_tip_sequence,
        suppressTofu: false,
      };
    }
    if (boundary.status === "invalid") {
      findings.push({
        kind: "split_boundary_invalid",
        message:
          "audit store split-boundary record is present but failed authentication " +
          "(tampered, forged, or wrong key); refusing to trust the sealed tip and " +
          "not treating the surviving suffix as an authenticated rotation cut",
      });
      return { boundary, effectiveSealedTip: 0, suppressTofu: true };
    }
    // absent
    if (await this.daemonMigrationMarkerExists()) {
      findings.push({
        kind: "split_boundary_missing",
        message:
          "a daemon audit store exists (the writer-split migration ran) but the " +
          "split-boundary record is absent; it was deleted after migration, so the " +
          "sealed tip cannot be trusted and the surviving suffix is not an " +
          "authenticated rotation cut",
      });
      return { boundary, effectiveSealedTip: 0, suppressTofu: true };
    }
    return { boundary, effectiveSealedTip: 0, suppressTofu: false };
  }

  /**
   * F2 Option A + BLOCKER-1 (adversarial gate 2026-07-14): with a VALID
   * boundary, verify from the directory LISTING (no decrypt, so it works even
   * when the sealed entries are root-owned and unreadable at operator
   * privilege) that the sealed region's V2 `entry-*` files form a gap-free run
   * ending EXACTLY at `sealed_tip_sequence`. This catches deletion or
   * disappearance of a sealed entry (the evidence-suppression vector the gate
   * flagged: an attacker with directory write permission unlinking sealed
   * files), which the content-level chain walk cannot see because it never
   * reads those files.
   *
   * BLOCKER-R1 (adversarial re-gate 2026-07-14): the run must ALSO start
   * exactly at the MAC'd `sealed_base_sequence`, so deletion of the LOWEST
   * sealed entry (which the first fix round left as a documented residual) is
   * now caught here too, not just by the root crypto walk. Pre-V2 (null-seq)
   * legacy keys below the V2 base are not sequence-checkable here; they are
   * covered by the root crypto verifier, not this listing check.
   */
  private checkSealedPrefixCompleteness(
    storedEntriesRaw: readonly { key: string }[],
    sealedTipSequence: number,
    sealedBaseSequence: number,
    findings: AuditIntegrityFinding[]
  ): void {
    if (sealedTipSequence <= 0) return; // nothing was sealed (empty at migration)
    const sealedSeqs: number[] = [];
    for (const meta of storedEntriesRaw) {
      const seq = parseEntryKeySequence(meta.key);
      if (seq !== null && seq <= sealedTipSequence) sealedSeqs.push(seq);
    }
    sealedSeqs.sort((a, b) => a - b);
    const highest = sealedSeqs.length > 0 ? sealedSeqs[sealedSeqs.length - 1]! : 0;
    const lowest = sealedSeqs.length > 0 ? sealedSeqs[0]! : 0;
    let contiguous = true;
    for (let i = 1; i < sealedSeqs.length; i++) {
      if (sealedSeqs[i]! !== sealedSeqs[i - 1]! + 1) {
        contiguous = false;
        break;
      }
    }
    const baseOk = sealedBaseSequence <= 0 || lowest === sealedBaseSequence;
    if (
      sealedSeqs.length === 0 ||
      highest !== sealedTipSequence ||
      !baseOk ||
      !contiguous
    ) {
      findings.push({
        kind: "sealed_prefix_incomplete",
        sequence: sealedTipSequence,
        expected: sealedTipSequence,
        actual: highest,
        message:
          sealedSeqs.length === 0
            ? `the entire sealed legacy audit prefix (sequences <= ${sealedTipSequence}) is missing from disk (deletion or corruption)`
            : highest !== sealedTipSequence
              ? `the sealed legacy audit prefix's top entry (sequence ${sealedTipSequence}) is missing; highest surviving sealed sequence is ${highest} (truncation)`
              : !baseOk
                ? `the sealed legacy audit prefix's bottom entry (sequence ${sealedBaseSequence}) is missing; lowest surviving sealed sequence is ${lowest} (a sealed entry was deleted)`
                : `the sealed legacy audit prefix has a gap below sequence ${sealedTipSequence} (a sealed entry was deleted)`,
      });
    }
  }

  /**
   * F3: load + MAC-verify the rotation anchor.
   *   - `valid`   : marker present, well-formed, MAC matches → authenticated cut.
   *   - `invalid` : marker present but malformed / MAC mismatch / unreadable →
   *     tampered or forged; the caller fails closed with a finding.
   *   - `absent`  : no record, or a bare/marker-stripped record (untrusted, like
   *     F1) → the caller's trust-on-first-use migration path applies.
   */
  private async loadRotationAnchor(
    findings: AuditIntegrityFinding[]
  ): Promise<
    | { status: "valid"; base_sequence: number; base_prev_hash: string }
    | { status: "absent" }
    | { status: "invalid" }
  > {
    let raw: Uint8Array | null;
    try {
      raw = await this.storage.read(
        AUDIT_CHECKPOINT_NAMESPACE,
        AUDIT_ROTATION_ANCHOR_KEY
      );
    } catch (err) {
      findings.push({
        kind: "storage_unavailable",
        message: `audit rotation anchor could not be read: ${failureMessage(err)}`,
      });
      // Cannot read it → cannot prove the cut → fail closed (not "absent").
      return { status: "invalid" };
    }
    if (!raw) return { status: "absent" };

    let parsed: unknown;
    try {
      parsed = JSON.parse(bytesToString(raw));
    } catch {
      return { status: "invalid" };
    }
    if (!isRecord(parsed) || parsed[AUDIT_ROTATION_ANCHOR_MARKER] !== true) {
      // Bare / marker-stripped / legacy: untrusted, treated as no anchor. An
      // absent anchor is NOT self-healed: for a genesis-rooted chain the default
      // seed applies, and for an above-genesis suffix `resolveChainSeed` fails
      // closed (`rotation_anchor_missing`). Only a legitimate future rotation
      // re-establishes an authenticated anchor (via `maybeRotate`).
      return { status: "absent" };
    }

    // Re-gate round 3: the structural arm is the SHARED shape predicate
    // (marker + data + canonical 43-char base64url mac), so this runtime and the raw
    // CLI exporter cannot drift apart on what a rotation anchor looks like.
    // The MAC VERIFICATION below stays here: only this runtime holds the
    // custody-derived MAC key.
    if (!isAuditRotationAnchorEnvelope(parsed)) {
      return { status: "invalid" };
    }
    const data = parsed.data;
    let providedMac: Uint8Array;
    try {
      providedMac = fromBase64url(parsed.mac);
    } catch {
      return { status: "invalid" };
    }
    if (
      !constantTimeEqual(
        providedMac,
        this.rotationAnchorMacBytes({
          base_sequence: data.base_sequence,
          base_prev_hash: data.base_prev_hash,
        })
      )
    ) {
      return { status: "invalid" };
    }
    return {
      status: "valid",
      base_sequence: data.base_sequence,
      base_prev_hash: data.base_prev_hash,
    };
  }

  private async writeHeadAnchor(
    highestSequence: number,
    headHash: string
  ): Promise<void> {
    const data = { highest_sequence: highestSequence, head_hash: headHash };
    const envelope = {
      [AUDIT_HEAD_ANCHOR_MARKER]: true,
      data,
      mac: toBase64url(this.headAnchorMacBytes(data)),
    };
    const bytes = stringToBytes(JSON.stringify(envelope));
    if (this.filesystemCapabilities) {
      await this.filesystemCapabilities.writeDurable(
        AUDIT_CHECKPOINT_NAMESPACE,
        AUDIT_HEAD_ANCHOR_KEY,
        bytes
      );
    } else {
      await this.storage.write(
        AUDIT_CHECKPOINT_NAMESPACE,
        AUDIT_HEAD_ANCHOR_KEY,
        bytes
      );
    }
    await this.storage.write(
      AUDIT_META_NAMESPACE,
      AUDIT_HEAD_ANCHOR_ESTABLISHED_KEY,
      stringToBytes("1")
    );
  }

  private headAnchorMacBytes(data: {
    highest_sequence: number;
    head_hash: string;
  }): Uint8Array {
    return hmacSha256(
      this.headAnchorMacKey,
      stringToBytes(AUDIT_HEAD_ANCHOR_MAC_DOMAIN + canonicalJson(data))
    );
  }

  /**
   * Outcome of one head-anchor read. Named so the load path can sample the
   * anchor early (before the entry listing) and hand the SAME result to
   * {@link verifyHeadAnchor} later in the pass; see the ordering invariant in
   * {@link loadPersistedEntries}.
   */
  private async loadHeadAnchor(
    findings: AuditIntegrityFinding[],
    // F2 Option A: whether a VALID split boundary seals a legacy region. On an
    // armed box the legacy `__head_anchor` was written by a pre-split ROOT
    // daemon and is root-owned 0600, so the operator uid's read throws EACCES.
    // With a valid boundary that legacy anchor only ever recorded the sealed
    // region's head (<= sealed tip; the migration captured the tip), so it is
    // superseded by the boundary. Reporting `unreadable_sealed` lets the caller
    // treat it as "no usable anchor for the post-split suffix" and re-establish
    // the operator's OWN anchor, instead of failing the whole load closed.
    boundaryIsValid = false
  ): Promise<HeadAnchorReadResult> {
    let raw: Uint8Array | null;
    try {
      raw = await this.storage.read(
        AUDIT_CHECKPOINT_NAMESPACE,
        AUDIT_HEAD_ANCHOR_KEY
      );
    } catch (err) {
      if (boundaryIsValid && isPermissionError(err)) {
        // Root-owned legacy anchor, unreadable at the operator uid, superseded
        // by the MAC'd boundary. Not a finding; the caller re-establishes the
        // suffix anchor. A non-permission fault still fails closed below.
        return { status: "unreadable_sealed" };
      }
      findings.push({
        kind: "storage_unavailable",
        message: `audit head anchor could not be read: ${failureMessage(err)}`,
      });
      return { status: "invalid" };
    }
    if (!raw) return { status: "absent" };

    let parsed: unknown;
    try {
      parsed = JSON.parse(bytesToString(raw));
    } catch {
      return { status: "invalid" };
    }
    if (!isRecord(parsed) || parsed[AUDIT_HEAD_ANCHOR_MARKER] !== true) {
      return { status: "absent" };
    }

    const data = parsed.data;
    const mac = parsed.mac;
    if (
      !isRecord(data) ||
      typeof mac !== "string" ||
      typeof data.highest_sequence !== "number" ||
      !Number.isSafeInteger(data.highest_sequence) ||
      data.highest_sequence <= 0 ||
      typeof data.head_hash !== "string" ||
      !/^[0-9a-f]{64}$/.test(data.head_hash)
    ) {
      return { status: "invalid" };
    }
    let providedMac: Uint8Array;
    try {
      providedMac = fromBase64url(mac);
    } catch {
      return { status: "invalid" };
    }
    if (
      !constantTimeEqual(
        providedMac,
        this.headAnchorMacBytes({
          highest_sequence: data.highest_sequence,
          head_hash: data.head_hash,
        })
      )
    ) {
      return { status: "invalid" };
    }
    return {
      status: "valid",
      highest_sequence: data.highest_sequence,
      head_hash: data.head_hash,
    };
  }

  /**
   * Adjudicate the head anchor against the surviving chain.
   *
   * `anchor` is read by the CALLER, before it lists the entries, and handed in
   * here (it is never re-read at this point in the pass). State the property
   * that ordering buys exactly, because it is narrower than "the listing also
   * sees it": on the LEGITIMATE append path the entry file is written before the
   * anchor that names it (see `persistChainedEntry`), so an anchor sampled
   * before the listing can only name an entry that was already on disk. It does
   * NOT guarantee the later listing still contains that entry — an adversarial
   * delete or rollback between the two reads removes it — and that case must
   * fail, not be excused: an entry the anchor names but the listing lacks leaves
   * `highestChainedSeq < anchor.highest_sequence`, which is reported as
   * `tail_anchor_invalid` below and fails the load closed.
   *
   * So the early sample removes only the FALSE verdict. Sampling AFTER the
   * listing instead admits an append that landed mid-pass, raising a floor the
   * already-taken listing could not have reached, and turns a live, healthy
   * writer into that same tamper verdict.
   */
  private async verifyHeadAnchor(
    anchor: HeadAnchorReadResult,
    highestChainedSeq: number,
    highestChainedHash: string,
    hasLegacyEntries: boolean,
    hasChainedEntries: boolean,
    findings: AuditIntegrityFinding[],
    sealedTipSequence = 0
  ): Promise<void> {
    if (anchor.status === "valid") {
      if (highestChainedSeq < anchor.highest_sequence) {
        findings.push({
          kind: "tail_anchor_invalid",
          sequence: highestChainedSeq,
          expected: anchor.highest_sequence,
          actual: highestChainedSeq,
          message: `audit head anchor floor ${anchor.highest_sequence} exceeds highest surviving sequence ${highestChainedSeq} (tail truncation or replay detected)`,
        });
        return;
      }
      if (
        highestChainedSeq === anchor.highest_sequence &&
        highestChainedHash !== anchor.head_hash
      ) {
        findings.push({
          kind: "tail_anchor_invalid",
          sequence: highestChainedSeq,
          expected: anchor.head_hash,
          actual: highestChainedHash,
          message: `audit head anchor hash does not match the surviving head at sequence ${highestChainedSeq}`,
        });
      }
      return;
    }

    if (anchor.status === "invalid") {
      findings.push({
        kind: "tail_anchor_invalid",
        message:
          "audit head anchor is present but failed authentication (tampered, forged, or wrong key)",
      });
      return;
    }

    if (anchor.status === "unreadable_sealed") {
      // F2 Option A: `__head_anchor` is unreadable at the operator uid while a
      // VALID MAC'd boundary exists. On a just-migrated armed box this is the
      // benign legacy state (a pre-split root daemon wrote a root-owned anchor
      // that only ever recorded the sealed region's head, <= the sealed tip,
      // which the boundary now anchors). But a bare "suppress" here would launder
      // a post-split tail truncation, so it is gated on TWO proofs (Finding 1,
      // adversarial gate 2026-07-15):
      //
      //   (a) No surviving post-split SUFFIX. If `highestChainedSeq >
      //       sealedTipSequence`, a suffix survives; the operator necessarily
      //       already wrote its OWN operator-owned, readable anchor at that
      //       higher floor, so an unreadable anchor now is tamper (someone made
      //       it unreadable to force a lower-floor heal). Fail closed.
      //   (b) The operator never established a suffix that has since been erased.
      //       Even with no surviving suffix, a fortress that ONCE had one (and
      //       whose suffix + suffix checkpoints were all deleted) is
      //       indistinguishable from a fresh box by surviving entries alone. The
      //       operator-provenance "suffix established" marker
      //       (AUDIT_POST_SPLIT_SUFFIX_ESTABLISHED_KEY) closes that: if it is
      //       present the suffix was erased -> fail closed.
      //
      // When both proofs pass (no surviving suffix AND never established one),
      // this is the genuine just-migrated state: suppress the finding. NO write
      // is done here (unlike the prior heal) -- the operator's next append
      // establishes its own readable anchor via the normal append path, so a
      // pure read never mutates the store.
      if (highestChainedSeq > sealedTipSequence) {
        findings.push({
          kind: "tail_anchor_invalid",
          sequence: highestChainedSeq,
          message:
            "audit head anchor is unreadable at this privilege but a post-split " +
            "suffix survives (the operator's own anchor must be readable); " +
            "refusing to heal to a lower floor (possible tail truncation)",
        });
        return;
      }
      if (await this.postSplitSuffixWasEstablished()) {
        findings.push({
          kind: "tail_anchor_invalid",
          message:
            "audit head anchor is unreadable and no post-split suffix survives, " +
            "but the operator previously established a post-split suffix " +
            "(possible full-suffix truncation with the anchor hidden)",
        });
        return;
      }
      return;
    }

    if (hasLegacyEntries && !hasChainedEntries && highestChainedSeq > 0) {
      await this.writeHeadAnchor(highestChainedSeq, highestChainedHash);
      return;
    }

    if (await this.isEstablishedAuditStore(hasLegacyEntries || hasChainedEntries)) {
      // First boot is legitimately anchorless. Once audit bytes or the
      // audit-established marker exist, stripping the tail floor makes rollback
      // indistinguishable from an empty log and must fail closed.
      findings.push({
        kind: "tail_anchor_missing",
        message:
          "audit head anchor missing for established audit store (tail truncation or whole-log deletion may have occurred)",
      });
    }
  }

  /**
   * F2 Finding 1: has this operator ever established a POST-SPLIT suffix (an
   * entry above the sealed tip)? Reads the operator-provenance marker
   * {@link AUDIT_POST_SPLIT_SUFFIX_ESTABLISHED_KEY}. Fail-safe: a present OR
   * unreadable/errored marker is treated as "established" (so an attacker cannot
   * clear the tamper signal by making the marker unreadable); only a definitely-
   * absent marker (`read` returns null) is "not established". `exists` is
   * stat-based and would report a root-owned marker present without proving we
   * can read its provenance, so this uses `read` and treats a permission error
   * conservatively as established.
   */
  private async postSplitSuffixWasEstablished(): Promise<boolean> {
    try {
      const raw = await this.storage.read(
        AUDIT_META_NAMESPACE,
        AUDIT_POST_SPLIT_SUFFIX_ESTABLISHED_KEY
      );
      return raw !== null;
    } catch {
      // Unreadable/errored: cannot prove absence, so assume established (fail
      // closed) rather than let an unreadable marker suppress the tamper check.
      return true;
    }
  }

  private async isEstablishedAuditStore(hasAuditEntries: boolean): Promise<boolean> {
    if (hasAuditEntries) return true;
    if (
      await this.storage
        .exists(AUDIT_META_NAMESPACE, AUDIT_HEAD_ANCHOR_ESTABLISHED_KEY)
        .catch(() => false)
    ) {
      return true;
    }
    const checkpointMetas = await this.storage
      .list(AUDIT_CHECKPOINT_NAMESPACE)
      .catch(() => []);
    return checkpointMetas.length > 0;
  }

  /**
   * F3: resolve the seed (expected first sequence + prev_hash) for the chained
   * walk, accounting for rotation. Three regimes:
   *   - lowest chained == legacyCount+1 → no rotation in the chained region; seed
   *     genesis / legacy anchor as before (a stale anchor, if any, is ignored).
   *   - lowest chained  > legacyCount+1 → the head was pruned; REQUIRE a MAC-valid
   *     rotation anchor whose base_sequence == the lowest survivor. Absent /
   *     invalid / mismatched → finding (fail closed), unconditionally.
   *   - no chained entries → if an anchor still exists, the whole post-cut chain
   *     was truncated → finding.
   *
   * NO trust-on-first-use for an above-genesis suffix (F2 round 3, 2026-07-14):
   * the old pre-F3 accommodation, "an anchor-absent but internally-contiguous
   * surviving chain is accepted once and a fresh anchor is written", was removed
   * because an attacker who deletes the prefix AND every witness leaves exactly
   * that shape. An above-genesis suffix with no authenticated cut now ALWAYS
   * surfaces `rotation_anchor_missing` and writes NO anchor, regardless of
   * marker/boundary state. Only a legitimate future rotation writes an anchor
   * (via `maybeRotate`). A pre-F3 log that genuinely rotated before anchors
   * existed therefore reports the finding until re-anchored by a real rotation:
   * honest, fail-closed, and the accepted cost of closing the launder.
   *
   * F2 Option A: when a valid split-boundary record exists (`splitBoundary`),
   * it REPLACES `legacyCount+1`/genesis as the default seed. The sealed
   * legacy chain (V1-legacy region + everything chained up to the boundary)
   * is treated exactly like a rotation cut that already happened, except no
   * anchor file for it is required (the boundary record IS the anchor for
   * this purpose) and `chainedEntries.length === 0` at the boundary is the
   * EXPECTED steady state immediately after migration, not a truncation.
   * Everything below (rotation-anchor validation / mismatch / truncation handling)
   * is otherwise unchanged and layers on top of this new default correctly:
   * a LATER rotation of the post-split chain is still detected and
   * authenticated exactly as before.
   *
   * BLOCKER-2 (adversarial gate 2026-07-14): `suppressTofu` is set when the
   * split boundary is present-but-invalid or deleted-after-migration. In that
   * state the sealed tip is untrusted, so a surviving suffix that begins ABOVE
   * sequence 1 could be a boundary-loss + prefix-deletion truncation. TOFU must
   * NOT bless it as a rotation cut: with `suppressTofu`, the anchor-absent
   * contiguous-suffix branch surfaces a finding and writes NO fresh rotation
   * anchor (fail closed) instead of self-healing.
   */
  private async resolveChainSeed(
    chainedEntries: Array<{
      key: string;
      envelope: PersistedAuditEnvelopeV2;
    }>,
    legacyCount: number,
    legacyAnchorHash: string,
    splitBoundary: AuditStoreSplitBoundaryLoadResult,
    suppressTofu: boolean,
    findings: AuditIntegrityFinding[]
  ): Promise<{ expectedSequence: number; expectedPrevHash: string }> {
    const defaultSeedSequence =
      splitBoundary.status === "valid"
        ? splitBoundary.boundary.sealed_tip_sequence + 1
        : legacyCount + 1;
    const defaultSeedPrevHash =
      splitBoundary.status === "valid"
        ? splitBoundary.boundary.sealed_tip_entry_hash
        : legacyCount > 0
          ? legacyAnchorHash
          : AUDIT_CHAIN_GENESIS;
    const defaultSeed = {
      expectedSequence: defaultSeedSequence,
      expectedPrevHash: defaultSeedPrevHash,
    };

    if (chainedEntries.length === 0) {
      // No chained entries to walk. If a rotation anchor is present it references
      // a base entry that no longer survives — i.e. the entire post-cut chain was
      // removed. That is a truncation, not a legitimate empty/legacy-only log.
      const anchor = await this.loadRotationAnchor(findings);
      if (anchor.status !== "absent") {
        findings.push({
          kind: "rotation_anchor_invalid",
          message:
            "audit rotation anchor is present but no chained entries survive (the post-cut chain may have been truncated)",
        });
      }
      return defaultSeed;
    }

    const head = chainedEntries[0]!.envelope;
    const lowestChainedSeq = head.sequence;

    // No rotation in the chained region: the head sits exactly where the legacy
    // prefix (or genesis) leaves off. (lowestChainedSeq can only be < the default
    // when a legacy entry was pruned — a pre-existing, out-of-F3-scope edge; the
    // legacy-anchor path reports that separately. Seed as before either way.)
    if (lowestChainedSeq <= defaultSeedSequence) {
      return defaultSeed;
    }

    const anchor = await this.loadRotationAnchor(findings);

    if (anchor.status === "valid") {
      if (anchor.base_sequence === lowestChainedSeq) {
        // Seed from the AUTHENTICATED anchor; the forward walk verifies cleanly.
        return {
          expectedSequence: anchor.base_sequence,
          expectedPrevHash: anchor.base_prev_hash,
        };
      }
      // The authenticated base does not match the lowest survivor — the head was
      // truncated (deleted) or a lower entry was reintroduced. Fail closed with a
      // single clear finding; seed from the head so the walk does not pile on a
      // cascade of gap findings down to base_sequence.
      findings.push({
        kind: "rotation_anchor_invalid",
        sequence: lowestChainedSeq,
        expected: anchor.base_sequence,
        actual: lowestChainedSeq,
        message: `audit rotation anchor base_sequence ${anchor.base_sequence} does not match the lowest surviving sequence ${lowestChainedSeq} (entries may have been truncated)`,
      });
      return {
        expectedSequence: lowestChainedSeq,
        expectedPrevHash: head.prev_hash,
      };
    }

    if (anchor.status === "invalid") {
      findings.push({
        kind: "rotation_anchor_invalid",
        sequence: lowestChainedSeq,
        message:
          "audit rotation anchor is present but failed authentication (tampered, forged, or wrong key)",
      });
      return {
        expectedSequence: lowestChainedSeq,
        expectedPrevHash: head.prev_hash,
      };
    }

    // BLOCKER-2 (adversarial gate 2026-07-14): a missing/invalid split boundary
    // could explain this above-floor suffix as a boundary-loss + prefix-deletion
    // truncation. Refuse to TOFU-bless it (that would launder the truncation
    // into an authenticated rotation cut); surface a finding and write no
    // anchor. The `split_boundary_invalid` / `split_boundary_missing` finding is
    // already recorded by the resolver; this adds the localized sequence
    // context and keeps the walk from re-anchoring.
    if (suppressTofu) {
      findings.push({
        kind: "rotation_anchor_missing",
        sequence: lowestChainedSeq,
        message: `audit chain starts at sequence ${lowestChainedSeq} (above ${defaultSeedSequence}) with an untrusted (invalid/missing) split boundary and no rotation anchor; refusing to self-heal a possibly-truncated suffix`,
      });
      return {
        expectedSequence: lowestChainedSeq,
        expectedPrevHash: head.prev_hash,
      };
    }

    // HIGH-1 (adversarial re-gate round 3, 2026-07-14): the ROBUST,
    // key-independent invariant. We are here only when the surviving chained
    // region starts ABOVE the floor (`lowestChainedSeq > defaultSeedSequence`,
    // so always > genesis) with NO authenticated rotation anchor. Such a suffix
    // is itself evidence of a deleted prefix, and it must NEVER be TOFU-blessed
    // (self-healed into a fresh rotation anchor) regardless of marker state.
    // The round-2 code self-healed here whenever the suffix was internally
    // contiguous, which is exactly the fail-open an attacker who deletes every
    // migration witness (boundary + daemon namespaces + `_meta` marker + sealed
    // prefix) rides: the contiguous above-genesis suffix got re-anchored and
    // read clean. Now we fail closed unconditionally: surface a
    // `rotation_anchor_missing` finding and write NO anchor.
    //
    // Compatibility note (accepted): a genuinely legitimate PRE-F3
    // already-rotated log (rotated before F3 shipped 2026-06-06, no anchor, and
    // never loaded since) no longer silently self-heals; it now surfaces this
    // finding once and the operator re-establishes via `--accept-broken-chain`.
    // Any F3+ rotation writes an authenticated anchor (handled above), so only
    // that vanishing never-loaded-since population is affected, and for it the
    // outcome is fail-closed (a finding), never corruption.
    //
    // IRREDUCIBLE RESIDUAL (documented, NOT claimed closed): this invariant
    // relies on the SURVIVING entries. It cannot distinguish this from a
    // legitimate history on evidence alone; a floor that does not live in a
    // single deletable file (boot-anchored / externally attested) is required
    // to close the "delete every witness" case fully, same class as F1/F3's
    // documented boot-anchor residual (CLAUDE.md "Known Complexity" #6).
    findings.push({
      kind: "rotation_anchor_missing",
      sequence: lowestChainedSeq,
      message: `audit chain starts at sequence ${lowestChainedSeq} (above ${defaultSeedSequence}) with no authenticated rotation anchor; an above-genesis suffix without an authenticated cut is evidence of a deleted prefix and is NOT self-healed`,
    });
    return {
      expectedSequence: lowestChainedSeq,
      expectedPrevHash: head.prev_hash,
    };
  }

  // (`isChainInternallyContiguous` was removed in round 3: the anchor-absent
  // above-genesis suffix is now unconditionally fail-closed per HIGH-1, so the
  // contiguous-vs-not distinction no longer gates a TOFU self-heal. The forward
  // chain walk still localizes any internal break.)

  /**
   * Read-only verified view of the surviving hash chain, pairing each chained
   * envelope's (sequence, entry_hash) with its decrypted entry. Used by the
   * transparency emitter to compute the checkpoint Merkle root and the
   * per-rule enforcement counters over the SAME entry set.
   *
   * Strict-mode integrity applies: if the chain fails verification this
   * throws `AuditIntegrityError` — a transparency checkpoint must never be
   * minted over a log that does not verify (fail closed, never degrade).
   */
  async verifiedChainView(): Promise<Array<VerifiedChainItem>> {
    // Backward-compatible array view: materializes the full chain (so it is as
    // memory-heavy as a caller that genuinely needs the whole array), but is now
    // backed by the streaming verifier so it shares ONE verification path with
    // {@link streamVerifiedChain}. Long-running daemon hot paths (transparency
    // emit, against-log recount, workload replay) call streamVerifiedChain
    // directly so the whole decrypted chain is never resident at once; that is
    // the daemon-OOM-on-a-large-log fix. This array variant is retained for
    // tests and any caller that legitimately wants the materialized view.
    const view: Array<VerifiedChainItem> = [];
    await this.streamVerifiedChain({
      onEntry: (item) => view.push(item),
      // A torn-read retry restarts the pass: drop the partially-built array so
      // the returned view is exactly the single accepted verified pass.
      reset: () => {
        view.length = 0;
      },
    });
    return view;
  }

  /**
   * Streaming verified view of the surviving hash chain. Runs the SAME strict
   * chain verification as {@link verifiedChainView} (it throws
   * `AuditIntegrityError` in strict mode on a chain that does not verify, so a
   * transparency checkpoint is never minted over a tampered log), but hands each
   * chained entry to `consumer.onEntry` in ascending chain-sequence order and
   * then RELEASES it. The full decrypted chain is never simultaneously resident,
   * so a large on-disk log no longer allocates its whole multi-GB decrypted
   * payload set per call.
   *
   * Ordering / tamper-evidence (read carefully, the safety is in the await, not
   * a pre-stream gate): `onEntry` fires DURING the decrypt loop, so each entry is
   * decrypted + hash-checked before the consumer sees it, but the FULL-CHAIN
   * checks (the contiguous sequence/prev-hash walk, the legacy / rotation / head
   * anchors, the checkpoint roots) run AFTER the loop, on cheap envelope metadata.
   * The guarantee a consumer relies on is therefore the AWAIT boundary, not a
   * pre-stream verification: this method does not resolve until those full-chain
   * checks have run, and in strict mode it THROWS `AuditIntegrityError` if any
   * failed. So a consumer that commits its incremental fold only AFTER
   * `await streamVerifiedChain(...)` returns clean never commits a result over an
   * unverified or tampered chain (a mid-stream tamper makes the await reject, the
   * fold is discarded). The full-chain invariants are derived from envelope
   * metadata and on-disk reads, never from a materialized decrypted array, so
   * streaming changes WHEN payloads are released, not WHAT is verified. See
   * {@link VerifiedChainConsumer} for the `reset` (read-consistency) contract.
   */
  async streamVerifiedChain(consumer: VerifiedChainConsumer): Promise<void> {
    await this.appendQueue;
    await this.reloadPersistedEntries(consumer);
  }

  /**
   * Read-only, MAC-authenticated rotation floor (the #437 machinery), exposed
   * for host-mode transparency verification (`--against-log`).
   *
   * A legitimate rotation prunes a contiguous PREFIX and records a single
   * master-key-MAC'd anchor naming the lowest sequence that still survives.
   * The transparency host verifier uses this to distinguish "prefix pruned by
   * authentic rotation" from "prefix DELETED to dodge Merkle recomputation":
   * only an anchor whose `base_sequence` matches the live floor authenticates
   * the cut. Without the master key the anchor's MAC cannot be checked at all,
   * so the floor is unauthenticatable and the host check must fail closed.
   *
   *   - "valid"   : anchor present, MAC verifies → `base_sequence` is the
   *     authenticated lowest surviving sequence.
   *   - "absent"  : no anchor (a never-rotated log legitimately has none; the
   *     caller treats prefix loss as unauthenticated and fails closed).
   *   - "invalid" : anchor present but malformed / MAC mismatch / unreadable
   *     (tampered or wrong key) → fail closed.
   */
  async authenticatedRotationFloor(): Promise<
    | { status: "valid"; base_sequence: number; base_prev_hash: string }
    | { status: "absent" }
    | { status: "invalid" }
  > {
    // loadRotationAnchor only pushes findings on a storage read error, which it
    // already maps to status "invalid"; a throwaway sink keeps this read-only.
    return this.loadRotationAnchor([]);
  }

  /**
   * Query the audit log with filtering.
   *
   * `identity_id`, when supplied, is applied BEFORE the `limit` slice, so an
   * own-identity read gets up to `limit` of the CALLER'S OWN in-window entries
   * rather than a global page that may contain few/none of theirs. Without this
   * the agent-facing own-identity reads (monitor_audit_log, audit_export_siem,
   * the cooperative search/events surfaces, broker/audit_query) had to query a
   * fixed wider window and post-filter — a caller with many other-identity
   * entries ahead of theirs in that window saw an undercount (CISO LOW,
   * 2026-06-16; fail-closed — never a leak, but `count` was incomplete).
   * `total` reflects the post-filter population so callers can detect truncation.
   */
  async query(options: {
    since?: string;
    layer?: AuditEntry["layer"];
    operation_type?: string;
    identity_id?: string;
    limit?: number;
  }): Promise<{
    entries: AuditEntry[];
    total: number;
    integrity_findings: AuditIntegrityFinding[];
  }> {
    // EAGER SCOPE (posture surface): serve from the eagerly-maintained verified
    // view with the throttled on-disk re-verify, so the high-frequency board
    // composition does not re-scan the whole chain per request (the #714 wedge).
    // OUTSIDE the scope (the agent-facing default): re-scan on EVERY call so
    // read-class operations fail loud as soon as corruption appears. Reads do NOT
    // take the cross-process write lock: stale reads are tolerable, and acquiring
    // the write lock here would create the audit namespace dir as a side effect
    // for fortresses that have never written, breaking non-recursive cleanup in
    // tests that only construct an AuditLog.
    if (auditEagerReadContext.getStore()?.eager === true) {
      await this.ensureFreshEagerView();
    } else {
      await this.appendQueue;
      await this.reloadPersistedEntries();
    }

    let filtered = this.entries;

    if (options.since) {
      const sinceDate = new Date(options.since);
      filtered = filtered.filter(
        (e) => new Date(e.timestamp) >= sinceDate
      );
    }
    if (options.layer) {
      filtered = filtered.filter((e) => e.layer === options.layer);
    }
    if (options.operation_type) {
      filtered = filtered.filter(
        (e) => e.operation === options.operation_type
      );
    }
    // Identity filter BEFORE the limit slice (own-identity-read paging fix): the
    // limit must bound the caller's OWN entries, not a global page.
    if (options.identity_id !== undefined) {
      filtered = filtered.filter((e) => e.identity_id === options.identity_id);
    }

    const total = filtered.length;
    const limit = options.limit ?? 50;
    const entries = filtered.slice(-limit); // Most recent entries

    return { entries, total, integrity_findings: [...this.integrityFindings] };
  }

  /**
   * Read-only view of the configured FIFO retention caps. Exposed for
   * calendar-period reporters (the law-firm evidence pack) that must disclose
   * a covered-window shortfall when size-based retention may have pruned
   * early-period entries. Returns configuration only; no entries, no keys.
   */
  getRetentionConfig(): { maxEntries: number; maxTotalSizeBytes: number } {
    return {
      maxEntries: this.maxEntries,
      maxTotalSizeBytes: this.maxTotalSizeBytes,
    };
  }

  /**
   * Read-only view of the CURRENT on-disk retention usage: the retained entry
   * count, the total on-disk size in bytes, and whether the log has ever pruned
   * (a rotation anchor exists). Exposed for calendar-period reporters (the
   * law-firm evidence pack) so a covered-window shortfall can distinguish
   * size-cap pruning from genuine inactivity (retention prunes on EITHER the
   * entry cap OR the size cap). Returns metadata sums only; no entries decrypted,
   * no keys touched. `everPruned` is best-effort: an unreadable anchor namespace
   * yields `null` so the caller does not over-claim "never pruned".
   */
  async getRetentionUsage(): Promise<{
    entryCount: number;
    totalSizeBytes: number;
    everPruned: boolean | null;
  }> {
    const metas = await this.storage.list(AUDIT_NAMESPACE);
    const totalSizeBytes = metas.reduce((sum, m) => sum + m.size_bytes, 0);
    let everPruned: boolean | null;
    try {
      const anchor = await this.storage.read(
        AUDIT_CHECKPOINT_NAMESPACE,
        AUDIT_ROTATION_ANCHOR_KEY
      );
      everPruned = anchor !== null;
    } catch {
      everPruned = null;
    }
    return { entryCount: metas.length, totalSizeBytes, everPruned };
  }

  /**
   * Eager, bounded-cost read for the always-on posture surface (the home board,
   * its per-panel endpoints, and the SSE live-refresh push).
   *
   * Identical filtering + result shape to {@link query}, but the per-request cost
   * does NOT scale with chain length. `query` re-reads, re-decrypts, re-hashes and
   * chain-walks every surviving entry from disk on EVERY call; at a real 10k-entry
   * / 40MB chain that is 11-30s and pegs the event loop (the #714 drill), and the
   * SSE cadence makes an open board recompute it continuously, wedging the server.
   *
   * This path serves from the EAGERLY-MAINTAINED in-memory verified view instead:
   *   - {@link persistChainedEntry} appends to `this.entries` / `this.chainEntries`
   *     and advances the verified head (`nextSequence` / `lastEntryHash`) on EVERY
   *     append, under the write lock, after chaining the new entry from the
   *     freshened-from-disk head (so an append is valid by construction). It does
   *     NOT touch `this.integrityFindings`: that array is the OUT-OF-BAND verdict
   *     and is (re)computed only by a full rescan: at load (`loadPersistedEntries`,
   *     which assigns `this.integrityFindings`), by the sentinel-forced rescan
   *     below, or by the throttled backstop rescan. So the in-memory ENTRY view is
   *     always current for everything THIS process wrote, with NO lag, and a
   *     just-appended entry is visible to the very next eager read.
   *   - We `await this.appendQueue` first, so all queued appends are reflected
   *     before we read (never-stale: an in-flight append is drained, not skipped).
   *   - SENTINEL (event-driven out-of-band detection): each eager read recomputes a
   *     CHEAP listing fingerprint of the store (count + newest key + per-entry
   *     size/mtime aggregate; metadata only, NO decrypt, NO full hash; see
   *     {@link auditStoreFingerprint}) and compares it to the expected fingerprint
   *     refreshed after each completed rescan AND after each of this process's own
   *     appends. A mismatch is an on-disk change NOT attributable to this process,
   *     so it forces an IMMEDIATE full re-scan regardless of the backstop throttle.
   *     The sentinel's own `list()` is self-throttled to
   *     `AUDIT_EAGER_SENTINEL_INTERVAL_MS` so the hot SSE path stays bounded at 10k.
   *   - BACKSTOP: a FULL on-disk re-scan (the expensive `loadPersistedEntries`) also
   *     runs when the view was never loaded OR more than the configured
   *     `eagerReverifyIntervalMs` has elapsed since the last full verify. This is
   *     the residual safety net for the ONE out-of-band shape the sentinel cannot
   *     see (a same-length, mtime-preserved byte edit), and the boot floor.
   *
   * NEVER-STALE-GREEN GUARANTEE: `integrity_findings` returned here is the EAGER
   * verdict. There is no window where a just-appended-but-unverified entry reads
   * green (appends chain from the verified head by construction), and a load-time /
   * sentinel-forced / backstop re-scan that detects a problem assigns the finding
   * to `this.integrityFindings`, which every subsequent eager read inherits. The
   * strict-mode contract is preserved: when integrity findings are present, this
   * throws `AuditIntegrityError` (unless the caller opted into
   * `runAllowingIntegrityFindings`), exactly as `query` does.
   *
   * OUT-OF-BAND TAMPER DETECTION BOUNDARY (documented, intentional): an on-disk
   * edit made by a non-server process is caught (a) unconditionally at load, (b)
   * on the NEXT eager read by the sentinel whenever it changes the listing
   * fingerprint (count / newest key / per-entry size or mtime), event-driven, not
   * up to the backstop interval, and (c) within at most `eagerReverifyIntervalMs`
   * by the backstop for the residual cases below. The
   * agent-facing audit query (`query`) is UNCHANGED and still re-verifies on every
   * call, so the inspectable audit surface keeps per-request on-disk tamper
   * detection; only the high-frequency posture composition is throttled. The
   * remaining stale-green windows on the eager path both fall to the backstop
   * (never beyond `eagerReverifyIntervalMs`, because a server append never advances
   * the backstop clock): (1) a fingerprint-PRESERVING out-of-band content edit
   * between backstop re-scans, and (2) a fingerprint-CHANGING out-of-band edit that
   * a subsequent legitimate server append re-baselines over before the next
   * sentinel check. Neither can EVER serve stale-green for anything the server
   * itself did, and the boundary is bounded + documented, never silent.
   */
  async queryEager(options: {
    since?: string;
    layer?: AuditEntry["layer"];
    operation_type?: string;
    identity_id?: string;
    limit?: number;
  }): Promise<{
    entries: AuditEntry[];
    total: number;
    integrity_findings: AuditIntegrityFinding[];
  }> {
    return this.runEagerReads(() => this.query(options));
  }

  /**
   * Run `fn` with the audit eager-read mode active: every `query` call inside it
   * serves from the eagerly-maintained verified view with the throttled on-disk
   * re-verify (see {@link queryEager}). Used by the posture route layer to wrap
   * the whole home-board composition (the digest, feature-health, castle-wall,
   * custody-exit, recognition and query-privacy reads, plus the SSE push) in ONE
   * bounded-cost scope WITHOUT plumbing a flag through every builder. Honesty is
   * unchanged: the eager view is current for every server-written entry and the
   * strict-mode integrity contract still applies inside the scope.
   */
  async runEagerReads<T>(fn: () => Promise<T>): Promise<T> {
    return auditEagerReadContext.run({ eager: true }, fn);
  }

  /**
   * Bring the in-memory verified view up to date for an eager read. Drains the
   * append queue (so every queued append is reflected, never-stale), then decides
   * whether a full on-disk re-scan is needed:
   *   - the backstop throttle (never loaded, or `eagerReverifyIntervalMs` elapsed
   *     since the last full verify), AND
   *   - the SENTINEL: a cheap metadata fingerprint of the store compared to the
   *     expected fingerprint (refreshed after each rescan and after this process's
   *     own appends). A mismatch is an out-of-band change and forces an IMMEDIATE
   *     full re-scan even if the backstop has not elapsed.
   * It then enforces the SAME strict-mode integrity contract as `query` (findings
   * → throw unless the caller opted in). See {@link queryEager}.
   */
  private async ensureFreshEagerView(): Promise<void> {
    await this.appendQueue;
    const backstopDue =
      !this.loaded ||
      Date.now() - this.lastFullVerifyAtMs >= this.eagerReverifyIntervalMs;
    // SENTINEL: only worth the metadata `list()` when we are NOT already going to
    // rescan, and at most once per the sentinel self-throttle so the hot SSE path
    // does not list the whole store on every read.
    const sentinelTripped = backstopDue ? false : await this.sentinelDetectsDrift();
    if (backstopDue || sentinelTripped) {
      // Full disk re-scan (also stamps lastFullVerifyAtMs + refreshes findings +
      // the expected fingerprint), single-flighted so concurrent board reads share
      // ONE scan instead of racing redundant scans over the same shared chain state.
      if (this.eagerReverifyInFlight === null) {
        this.eagerReverifyInFlight = (async () => {
          try {
            await this.loadPersistedEntriesWithReadConsistency();
            this.loaded = true;
          } finally {
            this.eagerReverifyInFlight = null;
          }
        })();
      }
      await this.eagerReverifyInFlight;
    }
    await this.reportIntegrityFindingsIfAny();
    const contextAllowsIntegrityFindings =
      auditIntegrityContext.getStore()?.allowIntegrityFindings === true;
    if (
      this.integrityMode === "strict" &&
      this.integrityFindings.length > 0 &&
      !contextAllowsIntegrityFindings
    ) {
      throw new AuditIntegrityError(this.integrityFindings);
    }
  }

  /**
   * Cheap, self-throttled out-of-band drift check for the eager read path.
   * Returns true iff the live store fingerprint differs from the expected one
   * (an on-disk change NOT attributable to this process's own appends), which
   * forces an immediate full re-verify in {@link ensureFreshEagerView}.
   *
   * Self-throttled to {@link AUDIT_EAGER_SENTINEL_INTERVAL_MS}: between checks it
   * returns false so the hot SSE path does not run `storage.list()` on every read
   * at 10k entries. Drift is therefore caught on the first eager read after the
   * sentinel interval has elapsed: within seconds, far below the backstop. If no
   * expected fingerprint has been established yet (no rescan/append since boot),
   * it returns false: the backstop / load-time verify owns that first pass.
   */
  private async sentinelDetectsDrift(): Promise<boolean> {
    const now = Date.now();
    if (now - this.lastSentinelCheckAtMs < AUDIT_EAGER_SENTINEL_INTERVAL_MS) {
      return false;
    }
    this.lastSentinelCheckAtMs = now;
    if (this.expectedStoreFingerprint === null) return false;
    const actual = await this.auditStoreFingerprint();
    return actual !== this.expectedStoreFingerprint;
  }

  /**
   * Cheap metadata fingerprint of the audit namespace: entry count, newest key,
   * and a per-entry size+mtime aggregate. Built from ONE `storage.list()` (no
   * read, NO decrypt, NO full hash), so it is safe to run on the hot eager path.
   * Any out-of-band change that adds/removes an entry (count / newest key) or
   * rewrites one in place (its `size_bytes` and/or `modified_at` change) flips
   * this value. The ONLY out-of-band edit it cannot see is a same-length,
   * mtime-preserved byte rewrite, caught by the throttled backstop full re-scan.
   */
  private async auditStoreFingerprint(): Promise<string> {
    let metas;
    try {
      metas = await this.storage.list(AUDIT_NAMESPACE);
    } catch {
      // A listing error is itself a drift signal: returning a sentinel distinct
      // from any real fingerprint makes the comparison unequal and forces a rescan.
      return "list-error";
    }
    if (metas.length === 0) return "0";
    metas.sort((a, b) => a.key.localeCompare(b.key));
    const newestKey = metas[metas.length - 1]!.key;
    // Order-independent aggregate of per-entry size+mtime: catches an in-place
    // rewrite (size or mtime changes) without paying a per-read full sort/hash
    // beyond the cheap list above.
    let sizeSum = 0;
    let mtimeAgg = 0;
    for (const m of metas) {
      sizeSum += m.size_bytes;
      // Fold the mtime string into a small rolling integer; collisions only cost
      // a missed event-driven catch (the backstop still covers it), never a false
      // green for a server-written entry.
      for (let i = 0; i < m.modified_at.length; i++) {
        mtimeAgg = (mtimeAgg * 31 + m.modified_at.charCodeAt(i)) >>> 0;
      }
    }
    return `${metas.length}:${newestKey}:${sizeSum}:${mtimeAgg}`;
  }

  /** Recompute + cache the expected store fingerprint as the current on-disk
   * state. Called after a completed full re-verify and after each of this
   * process's own appends, so the sentinel treats only OUT-OF-BAND changes as
   * drift. A failure to list leaves the prior expected value untouched rather
   * than poisoning it (the next sentinel/ backstop pass re-establishes it). */
  private async refreshExpectedStoreFingerprint(): Promise<void> {
    try {
      this.expectedStoreFingerprint = await this.auditStoreFingerprint();
    } catch {
      // Leave the prior fingerprint in place; do not mask drift with a stale-clear.
    }
  }

  private async reverifyCachedIntegrityFindingsBeforeAppend(): Promise<void> {
    if (
      this.integrityMode !== "strict" ||
      !this.loaded ||
      this.integrityFindings.length === 0
    ) {
      return;
    }
    // C7: this instance already failed closed once. Before refusing the next
    // append with that cached verdict, take one fresh look WITHOUT holding the
    // append write lock. If the store is still dirty, strict reload throws here;
    // if a transient healed, the normal locked append path can proceed.
    await this.reloadPersistedEntries();
  }

  private async ensureLoaded(options?: { allowIntegrityFindings?: boolean }): Promise<void> {
    if (!this.loaded) {
      await this.loadPersistedEntriesWithReadConsistency();
      this.loaded = true;
    }
    await this.reportIntegrityFindingsIfAny();
    const contextAllowsIntegrityFindings =
      auditIntegrityContext.getStore()?.allowIntegrityFindings === true;
    if (
      this.integrityMode === "strict" &&
      this.integrityFindings.length > 0 &&
      options?.allowIntegrityFindings !== true &&
      !contextAllowsIntegrityFindings
    ) {
      throw new AuditIntegrityError(this.integrityFindings);
    }
  }

  private async reloadPersistedEntries(
    consumer?: VerifiedChainConsumer
  ): Promise<void> {
    await this.loadPersistedEntriesWithReadConsistency(consumer);
    this.loaded = true;
    await this.reportIntegrityFindingsIfAny();
    const contextAllowsIntegrityFindings =
      auditIntegrityContext.getStore()?.allowIntegrityFindings === true;
    if (
      this.integrityMode === "strict" &&
      this.integrityFindings.length > 0 &&
      !contextAllowsIntegrityFindings
    ) {
      throw new AuditIntegrityError(this.integrityFindings);
    }
  }

  private async loadPersistedEntriesWithReadConsistency(
    consumer?: VerifiedChainConsumer
  ): Promise<void> {
    const deadline = Date.now() + AUDIT_READ_CONSISTENCY_MAX_MS;
    let lastSignature: string | null = null;
    let streamedThisLoop = false;
    for (;;) {
      // A retry means the prior pass observed a transient mid-mutation state and
      // is being discarded. Tell the streaming consumer to drop everything it
      // accumulated from that abandoned pass BEFORE we re-decrypt, so the entries
      // it keeps are exactly those of the single accepted pass (the one we return
      // from). The first pass needs no reset (nothing accumulated yet).
      if (consumer && streamedThisLoop) consumer.reset?.();
      await this.loadPersistedEntries(consumer);
      streamedThisLoop = consumer !== undefined;
      if (this.integrityFindings.length === 0) {
        return; // clean read
      }
      // Give-up discriminator (attacker safety) is STORE STABILITY, not the
      // finding kind. Retry only while the store is DEMONSTRABLY mid-mutation:
      // a writer marker is currently held, OR the entry listing changed since the
      // previous attempt. The listing-changed signal is essential — a bursty
      // writer releases the cross-process marker between appends, so an
      // instantaneous marker check alone gives up mid-burst and surfaces a
      // legitimate rotation tear (the CI false-fail). A STATIC store with findings
      // is real tamper (truncation, byte edit, forged anchor) and falls through to
      // fail closed within a single retry — discriminating on stability rather
      // than on finding-kind means ALL torn-read shapes (anchor floor ahead of a
      // pruned listing, entries pruned out from under a scan, a half-updated
      // checkpoint root) are tolerated WITHOUT ever classifying a genuine tamper
      // signal as "transient". The first attempt with findings always retries once
      // to establish the listing baseline. The wall-clock deadline below bounds an
      // attacker who keeps the store permanently churning.
      const signature = await this.auditEntryListingSignature();
      const hadBaseline = lastSignature !== null;
      const listingChanged = hadBaseline && signature !== lastSignature;
      lastSignature = signature;
      const storeIsMutating =
        listingChanged || (await this.isAuditWriterInProgress());
      if (hadBaseline && !storeIsMutating) {
        return; // static store with findings → fail closed (no masking)
      }
      // The deadline is checked only AFTER a baseline exists, so the one
      // mandatory retry above is real work rather than a claim. Checking it
      // first (the pre-2026-08-05 order) silently deleted that retry on any
      // store where a SINGLE pass outlives the whole budget, which is the
      // normal case at scale: one full decrypt+verify pass costs 11-30s
      // on a 10k-entry chain (see the #714 note on the eager-read backstop) and
      // the budget is 2s. Every transient tear on a large log therefore became
      // a hard tamper verdict on the first look, with no second look at all.
      //
      // KNOWN LATENCY EXPOSURE (availability, not tamper weakening; accepted
      // 2026-08-05, unmitigated on purpose). In the case this change is about —
      // one pass outliving the 2s budget — making the retry mandatory costs
      // exactly ONE extra full pass: the second pass establishes the baseline
      // with the deadline already blown, so this check ends the loop. (Further
      // passes remain possible in general, but only while the store is
      // demonstrably mutating AND the whole loop is still inside the budget,
      // i.e. only when passes are cheap.) But `persistChainedEntry`
      // calls `ensureLoaded()` INSIDE `withAuditWriteLock`, so on an appending
      // process's FIRST load that extra pass is paid while the cross-process
      // write lock is held.
      //
      // The size of that extra pass, measured rather than assumed. A cold full
      // pass is LINEAR in entry count, not quadratic: timed on this branch
      // (macOS, ~250-byte entries) at 250/500/1000/2000 entries the pass took
      // 28/50/95/193ms, a flat ~0.1ms per entry. The per-entry constant, though,
      // tracks PAYLOAD size, so it is not one number: the #714 profile (10k
      // entries at ~40MB, so ~4KB each) measured 11-30s per pass, i.e. ~1.1-3ms
      // per entry, ~10-30x the small-entry constant above. At the ~166k entries
      // the register-C6 production host carries, the extra pass is therefore
      // ~16s of decrypt+verify with small entries and ~180-500s with #714-sized
      // ones. The upper half of that range blows
      // `DEFAULT_AUDIT_WRITE_LOCK_HOLD_DEADLINE_MS` (30s), which aborts the hold
      // via the `signal` and runs lock recovery, while concurrent appenders
      // waiting to acquire give up after `AUDIT_WRITE_LOCK_TIMEOUT_MS` (5s) with
      // `AuditLockContentionError`. The
      // trigger is narrow (a first load that both finds a transient tear and
      // outruns the budget), and every cheap mitigation is worse than the
      // exposure: skipping the retry when the caller holds the write lock
      // reinstates exactly the first-look-is-final tamper verdict this change
      // exists to remove, and scaling the budget by chain size only permits MORE
      // passes. A real fix is an incremental/cheap re-verify so a second look is
      // not a second full pass; that is its own design, tracked as follow-up, and
      // deliberately NOT attempted here.
      if (hadBaseline && Date.now() >= deadline) {
        return; // bounded backstop; surfaced in strict mode by the caller
      }
      await sleep(AUDIT_READ_CONSISTENCY_RETRY_MS);
    }
  }

  /**
   * Cheap mutation fingerprint of the audit entry namespace: count + lowest +
   * highest key. A concurrent append (new highest key / higher count) or a prune
   * (new lowest key / lower count) changes it; a static store does not. Used only
   * on the read-consistency retry path to decide whether a present integrity
   * finding is worth retrying (active mutation) or should fail closed (static).
   */
  private async auditEntryListingSignature(): Promise<string> {
    try {
      const metas = await this.storage.list(AUDIT_NAMESPACE);
      if (metas.length === 0) return "0";
      metas.sort((a, b) => a.key.localeCompare(b.key));
      return `${metas.length}:${metas[0]!.key}:${metas[metas.length - 1]!.key}`;
    } catch {
      // A listing error is itself a sign of concurrent mutation; return a
      // sentinel distinct from any real signature so the next attempt compares
      // unequal and retries (bounded by the deadline).
      return "list-error";
    }
  }

  private async isAuditWriterInProgress(): Promise<boolean> {
    if (!this.auditWriteLockPath) return false;
    try {
      await readFile(this.auditWriteLockPath, "utf8");
    } catch (err) {
      const code =
        err instanceof Error && "code" in err
          ? String((err as NodeJS.ErrnoException).code)
          : "";
      return code !== "ENOENT" && code !== "ENOTDIR";
    }
    if (await this.breakStaleAuditLock(this.auditWriteLockPath)) {
      return false;
    }
    return true;
  }

  private auditLockHoldDeadlineError(): AuditLockHoldDeadlineError {
    return new AuditLockHoldDeadlineError(
      this.auditWriteLockPath ?? AUDIT_WRITE_LOCK_FILE,
      this.writeLockHoldDeadlineMs
    );
  }

  private assertAuditWriteLockActive(signal: AuditWriteLockAbortSignal): void {
    if (signal.aborted) {
      throw this.auditLockHoldDeadlineError();
    }
  }

  /**
   * Acquire the cross-process audit write lock for one deadline-bounded
   * operation.
   *
   * Mini2 freeze, 2026-08-02 (finding documented 2026-08-03): the previous
   * `try/finally` released the lock only after the awaited operation settled, so
   * a hung filesystem/storage write kept a live same-boot lock on disk forever
   * and every later append failed with contention. The operation now races a
   * hold deadline: on expiry the append fails loudly, listeners are notified,
   * and the existing inode-verified release path runs.
   *
   * Residual, documented by design: a hang INSIDE the storage write can still
   * land bytes after abandonment. Entry keys are unique, so nothing is
   * overwritten; the cooperative abort checks keep the abandoned operation from
   * writing later steps or mutating in-memory head state, and full-chain
   * verification surfaces any duplicate sequence as an integrity finding. Loud
   * and chain-visible degradation beats frozen-forever.
   */
  /**
   * PR #1084 gate F2: retry must not launder a failed ownership handback. If
   * the created-chain chown failed (or the process crashed between mkdir and
   * chown), the namespace directories exist ROOT-OWNED; the next append's
   * recursive mkdir then returns undefined, and without this check the write
   * would proceed silently, permanently reinstating the root-owned-chain
   * defect for the segment. When the chain already exists and `createOwner`
   * is set, this walks the FULL created-chain depth (re-gate F2-deep): a deep
   * first-ever namespace such as `boot-audit/<fp>/_audit` creates three levels
   * at once, so a crash mid-handback can leave `boot-audit` root-owned while a
   * two-level recheck repaired only the lower pair, leaving the operator
   * locked out one level up. The walk ascends the CONTIGUOUS run of
   * deviating directories (root-owned, or operator-owned with a drifted gid)
   * from the namespace dir upward and:
   *   - repairs that run through the SAME descriptor-verified
   *     `chownCreatedDirChain` path (#1051 safety contract: `O_NOFOLLOW |
   *     O_DIRECTORY` opens, chown through handles, created-only, symlinked
   *     component refused) — repair is correct here because these are the
   *     daemon's own audit-store directories, not arbitrary pre-existing dirs;
   *   - STOPS at the first healthy operator-owned ancestor, which under the
   *     intended ownership model is the fortress root itself: that is the
   *     ceiling, so the walk never ascends above the fortress/storage root
   *     (same non-ancestor-stop safety as `chownCreatedDirChain`);
   *   - REFUSES loudly on a symlinked/non-directory entry, a directory owned
   *     by any OTHER uid (never seize a third party's directory), or a
   *     deviating run that reaches the filesystem root or the runaway cap
   *     without a healthy boundary (never chase ownership toward `/`); the
   *     append fails with a diagnosable reason (hard constraint 5: no silent
   *     proceed on wrong ownership).
   * Cost: a handful of lstats per locked write in the healthy case (the walk
   * stops at the first healthy ancestor, i.e. after one lstat once the tree is
   * clean). Deliberately no caching, so an external ownership change mid-run
   * stays detected.
   */
  private async verifyOrRepairNamespaceDirOwnership(
    leafDir: string,
    owner: AuditCreateOwner,
  ): Promise<void> {
    // Runaway guard doubling as the fortress-root ceiling: the deepest known
    // audit-store namespace (`<fortress>/boot-audit/<fp>/_audit`) is three
    // created levels below the fortress, so a healthy boundary is always found
    // within a few hops. A deviating run that never reaches one is pathological
    // (e.g. a root-owned fortress, which is `repair-custody`'s job, not this
    // append path's) and is refused rather than chased toward `/`.
    const MAX_NAMESPACE_ANCESTOR_WALK = 16;
    let topmostRepair: string | undefined;
    let dir = leafDir;
    for (let depth = 0; ; depth++) {
      if (depth >= MAX_NAMESPACE_ANCESTOR_WALK) {
        throw new Error(
          `audit namespace directory ${leafDir} sits under an unbroken run of ${depth} non-operator-owned directories with no healthy ancestor; refusing to write audit entries (never chase ownership toward the filesystem root). Run 'sudo sanctuary castle-wall repair-custody' to repair operator custody.`
        );
      }
      const stats = await this.namespaceDirLstat(dir);
      if (stats.isSymbolicLink() || !stats.isDirectory()) {
        throw new Error(
          `audit namespace directory ${dir} is not a plain directory; refusing to write audit entries through it`
        );
      }
      if (stats.uid !== 0 && stats.uid !== owner.uid) {
        throw new Error(
          `audit namespace directory ${dir} is owned by uid ${stats.uid} (neither root nor the fortress owner uid ${owner.uid}); refusing to write audit entries through it. Run 'sudo sanctuary castle-wall repair-custody' to repair operator custody.`
        );
      }
      const needsRepair = stats.uid === 0 || stats.gid !== owner.gid;
      if (!needsRepair) {
        // First healthy operator-owned ancestor: the pre-existing tree (the
        // fortress root under the intended model). Stop here; never ascend
        // into or above it.
        break;
      }
      topmostRepair = dir;
      const parent = dirname(dir);
      if (parent === dir) {
        // Reached the filesystem root while still inside the deviating run:
        // no healthy boundary exists. Refuse rather than seize up to `/`.
        throw new Error(
          `audit namespace directory ${leafDir} has no operator-owned ancestor before the filesystem root; refusing to write audit entries. Run 'sudo sanctuary castle-wall repair-custody' to repair operator custody.`
        );
      }
      dir = parent;
    }
    if (topmostRepair !== undefined) {
      // Fail-closed: a repair failure propagates and fails the append. The
      // topmost deviating directory is an ancestor of (or equal to) leafDir,
      // so `chownCreatedDirChain` repairs the whole contiguous run in one pass.
      await this.createOwnerChownDirChain(topmostRepair, leafDir, owner);
    }
  }

  private async withAuditWriteLock<T>(
    operation: (signal: AuditWriteLockAbortSignal) => Promise<T>
  ): Promise<T> {
    const signal: AuditWriteLockAbortSignal = { aborted: false };
    if (!this.auditWriteLockPath) return operation(signal);

    // A single append writes one chained entry, its durable head anchor, and
    // the durable "anchor established" marker. Owner-mode FilesystemStorage
    // deliberately refuses to create a missing parent as root, so ALL three
    // namespace directories must exist (and be handed back to the fortress
    // owner) before the append starts. Initializing only `_audit` made the
    // first safe-mode boot append fail successively on `_audit_checkpoints`
    // and `_meta` in a genuinely fresh fortress.
    for (const namespace of [
      AUDIT_NAMESPACE,
      AUDIT_CHECKPOINT_NAMESPACE,
      AUDIT_META_NAMESPACE,
    ]) {
      const namespaceDir =
        this.filesystemCapabilities!.namespacePath(namespace);
      const firstCreated = await mkdir(namespaceDir, {
        recursive: true,
        mode: 0o700,
      });
      if (this.createOwner !== undefined) {
        if (firstCreated !== undefined) {
          /**
           * Fortress-ownership spec 2026-07-30: recursive mkdir as root creates
           * the missing namespace chain root-owned 0700; files inside are
           * operator-owned but the operator cannot traverse the directories.
           */
          await this.createOwnerChownDirChain(
            firstCreated,
            namespaceDir,
            this.createOwner,
          );
        } else {
          // PR #1084 gate F2: retry must not launder a failed handback. See
          // {@link verifyOrRepairNamespaceDirOwnership}.
          await this.verifyOrRepairNamespaceDirOwnership(
            namespaceDir,
            this.createOwner,
          );
        }
      }
    }
    // Once-per-process: GC any `.acquire.*.tmp` a prior process's crash/kill-9
    // stranded between `link()` and its cleanup (invisible to `list()`, litter
    // only). Bounded and best-effort so it can never block or fail an acquire.
    await this.sweepStaleAcquireTempsOnce(this.auditWriteLockPath);
    const started = Date.now();
    // Identity (dev+ino) of the lock file THIS acquire published, captured at
    // acquire time. The graceful release below unlinks ONLY if the path still
    // resolves to this exact inode, symmetric with the stale-break path: if the
    // lock was ever broken-and-republished under us (a fresh inode at the same
    // path), a bare `rm(path)` would delete the NEW holder's lock and let two
    // writers proceed. `unlinkIfSameInode` rejects that. See atomicAcquireAuditLock.
    let heldLockStats: Stats | undefined;
    let acquired = false;
    while (!acquired) {
      try {
        // Atomic acquire (drill-found fix, Leg 5, MBA 2026-07-15): stamp a fully
        // populated lock into a temp file (with `pid` + `acquired_at`), fsync it,
        // then `link()` it into place. `link` fails with EEXIST if the lock is
        // already held, giving the same mutual-exclusion guarantee as `open(wx)`,
        // but the visible lock file NEVER exists in a content-less state; there
        // is no create-then-stamp window in which a crash can strand a 0-byte
        // lock its own staleness-prover cannot clear. A crash before the `link`
        // leaves only the temp file (cleaned up below / ignored by the prover).
        heldLockStats = await this.atomicAcquireAuditLock(this.auditWriteLockPath);
        acquired = true;
      } catch (err) {
        const code =
          err instanceof Error && "code" in err
            ? String((err as NodeJS.ErrnoException).code)
            : "";
        if (code !== "EEXIST") throw err;
        // The lock file exists. A non-graceful exit (crash / kill -9 / reboot)
        // strands it with a dead holder — the graceful `rm` below never ran — so
        // the next daemon would block the full timeout and fail to (re)start.
        // Break a PROVABLY-stale lock and retry immediately; never break a lock
        // a live process holds.
        if (await this.breakStaleAuditLock(this.auditWriteLockPath)) {
          continue;
        }
        if (Date.now() - started >= AUDIT_WRITE_LOCK_TIMEOUT_MS) {
          throw new AuditLockContentionError(this.auditWriteLockPath);
        }
        await sleep(AUDIT_WRITE_LOCK_RETRY_MS);
      }
    }

    try {
      let timer: ReturnType<typeof setTimeout> | undefined;
      const operationPromise = Promise.resolve().then(() => operation(signal));
      void operationPromise.catch(() => undefined);
      try {
        const deadlinePromise = new Promise<never>((_resolve, reject) => {
          timer = setTimeout(() => {
            signal.aborted = true;
            // SAFETY: forced lock recovery must be loud on operator-facing
            // stderr BEFORE any other handling (AGENTS.md constraint 5).
            console.error(
              `[audit-log] AUDIT-WRITE-LOCK-RECOVERY reason=write_lock_hold_deadline_exceeded ` +
                `lock=${this.auditWriteLockPath} deadline_ms=${this.writeLockHoldDeadlineMs} ` +
                `- abandoning the in-flight append and releasing the lock; ` +
                `the underlying operation may still be running`,
            );
            this.recordWriteLockRecoveryEvent({
              reason: "write_lock_hold_deadline_exceeded",
              lockPath: this.auditWriteLockPath!,
            });
            reject(this.auditLockHoldDeadlineError());
          }, this.writeLockHoldDeadlineMs);
          timer.unref?.();
        });
        return await Promise.race([operationPromise, deadlinePromise]);
      } finally {
        signal.aborted = true;
        if (timer) clearTimeout(timer);
      }
    } finally {
      // Inode-verified release (symmetric with the stale-break path). Delete the
      // lock only if it is still the file WE published; if a broken-and-republished
      // lock now occupies the path with a different inode, leave it (never clobber
      // the new holder). Fall back to a bare `rm` only if we somehow hold no
      // captured identity, so a release never silently leaks the lock.
      //
      // A REAL unlink failure (EIO/EPERM/EROFS) now PROPAGATES rather than being
      // swallowed: `unlinkIfSameInode` returns for the benign outcomes (the file
      // was ours and removed, was already gone, or a different inode now occupies
      // the path → not ours) and THROWS only on a genuine fs error. Swallowing
      // that error would leave our lock on disk still carrying our live same-boot
      // pid, which the next acquirer cannot prove stale → permanent self-brick.
      // Surfacing it is invariant 5 (never silently degrade to a leaked lock).
      if (heldLockStats) {
        await this.unlinkIfSameInode(this.auditWriteLockPath, heldLockStats);
      } else {
        await rm(this.auditWriteLockPath, { force: true });
      }
    }
  }

  /**
   * Once per process, sweep orphaned audit-lock acquire-temps
   * (`<lockfile>.acquire.*.tmp`) whose mtime is older than
   * {@link idlessStaleLockMs}. A crash / kill -9 between `link()` and the
   * `finally` unlink in {@link atomicAcquireAuditLock} strands one of these
   * permanently: it is invisible to `list()` (which filters to `.enc`) and never
   * consulted by the staleness prover, so it is pure litter that accumulates
   * across restarts. Age-gating past the generous id-less bound guarantees a
   * temp a CONCURRENT acquirer is mid-flight with (sub-second) is never reaped.
   * Best-effort and bounded: any error is swallowed so the sweep can never block
   * or fail a write-lock acquire.
   */
  private async sweepStaleAcquireTempsOnce(lockPath: string): Promise<void> {
    if (this.staleAcquireTempsSwept) return;
    this.staleAcquireTempsSwept = true;
    try {
      const dir = dirname(lockPath);
      const lockBase = lockPath.slice(dir.length + 1);
      const tempPrefix = lockBase + AUDIT_LOCK_ACQUIRE_TEMP_INFIX;
      const entries = await readdir(dir);
      const now = Date.now();
      for (const name of entries) {
        if (!name.startsWith(tempPrefix) || !name.endsWith(AUDIT_LOCK_ACQUIRE_TEMP_SUFFIX)) {
          continue;
        }
        const tempPath = join(dir, name);
        try {
          const st = await stat(tempPath);
          if (now - st.mtimeMs > this.idlessStaleLockMs) {
            await unlink(tempPath).catch(() => undefined);
          }
        } catch {
          // Vanished or unstattable between readdir and stat: nothing to reap.
        }
      }
    } catch {
      // Listing the audit dir failed (e.g. not yet created): no temps to sweep.
    }
  }

  /**
   * Atomically create the audit write lock already carrying its `{pid,
   * acquired_at, uptime_ms, boot_id}` stamp, or throw `EEXIST` if it is already
   * held. Returns the `Stats` (dev+ino) of the published lock so the caller's
   * graceful release can be inode-verified (symmetric with the stale-break path).
   *
   * Drill-found fix (Leg 5, MBA 2026-07-15): the prior acquire did
   * `open(path,"wx")` (which creates the file EMPTY) and only THEN wrote the
   * stamp. A crash / kill -9 / power-loss in that window stranded a 0-byte lock,
   * and `breakStaleAuditLock` (which proves staleness from `pid`/`acquired_at`)
   * cannot clear a content-less file, so the fortress was permanently bricked
   * with a misleading "another writer holds the lock". This closes the window:
   * the fully-stamped payload is written + fsync'd to a temp file first, then
   * `link()`-ed into place. `link` is atomic and fails with EEXIST when the lock
   * already exists (same mutual exclusion as `open(wx)`), so the visible lock
   * file only ever exists WITH its stamp. A crash before the `link` leaves at
   * most an orphan temp file, which is cleaned up here and never consulted by
   * the staleness prover.
   *
   * `boot_id` (a per-boot IDENTITY UUID; see {@link currentBootId}) is the
   * PRIMARY same-boot proof: `breakStaleAuditLock` protects a live same-boot lock
   * only when the lock's `boot_id` equals the current boot's, and treats any
   * mismatch as definitive reboot evidence. `uptime_ms` (system `os.uptime()` at
   * acquire) is a MONOTONIC magnitude used WITHIN a proven-same boot to tell our
   * own live lock from a reused-self-pid orphan without trusting the wall clock;
   * unlike `boot_id`, a bare uptime magnitude aliases across reboots, so it is
   * never consulted unless `boot_id` has already proven the same boot.
   */
  private async atomicAcquireAuditLock(lockPath: string): Promise<Stats> {
    // The temp name uses a CRYPTO-RANDOM component (not just pid + time +
    // counter) so it is unpredictable: combined with the O_EXCL (`"wx"`) create
    // below and the operator-owned 0700 audit dir it lives in, an attacker
    // cannot pre-create a symlink at a guessable temp path to redirect the write
    // (CodeQL js/insecure-temporary-file). The pid + counter are retained only
    // for human-readable provenance in a crash-orphan.
    const tempPath =
      `${lockPath}${AUDIT_LOCK_ACQUIRE_TEMP_INFIX}${process.pid}.` +
      `${(auditLockTempCounter++).toString(36)}.` +
      `${randomBytes(12).toString("hex")}${AUDIT_LOCK_ACQUIRE_TEMP_SUFFIX}`;
    let tempCreated = false;
    // Inode identity of the file we publish. `link` is a hard link, so `lockPath`
    // shares the temp's inode: capturing it from the OPEN handle (before close,
    // hence before the link) is race-free: it is exactly the inode `lockPath`
    // will resolve to, with no window for another actor to swap it.
    let publishedStats: Stats | undefined;
    try {
      const handle = await open(tempPath, "wx", 0o600);
      tempCreated = true;
      try {
        await this.applyAuditWriteLockCreateOwner(handle);
        const uptimeMs = currentUptimeMs();
        const bootId = currentBootId();
        await handle.writeFile(
          JSON.stringify({
            pid: process.pid,
            acquired_at: new Date().toISOString(),
            ...(uptimeMs !== undefined ? { uptime_ms: Math.round(uptimeMs) } : {}),
            ...(bootId !== undefined ? { boot_id: bootId } : {}),
          })
        );
        await handle.sync();
        publishedStats = await handle.stat();
      } finally {
        await handle.close();
      }
      // Atomic publish: EEXIST here means the lock is already held; propagate it
      // so the caller's contention/break loop handles it exactly as before.
      await link(tempPath, lockPath);
    } finally {
      if (tempCreated) {
        // The temp name is no longer needed whether the link succeeded, the link
        // threw, or the write/sync/close between them threw: `link` created a
        // second name for the same inode (so `lockPath` keeps it), and every
        // other path leaves only the orphan temp to reclaim. Cleaning up on the
        // whole post-create range (not just after a successful stamp) prevents
        // orphan-temp litter accumulating in the audit dir on partial failures.
        await unlink(tempPath).catch(() => undefined);
      }
    }
    // Reached only when the link succeeded (any failure above threw); the handle
    // stat always populated publishedStats before the link, so this is defined.
    return publishedStats!;
  }

  private async applyAuditWriteLockCreateOwner(
    handle: AuditLockFileHandle
  ): Promise<void> {
    if (this.createOwner === undefined) return;
    await this.createOwnerChown(handle, this.createOwner);
  }

  /**
   * Remove `lockPath` ONLY if it still resolves to the SAME inode
   * (`dev`+`ino`) that {@link breakStaleAuditLock} just proved stale, returning
   * true iff the proven-stale file was removed (or had already vanished).
   *
   * Pathname-TOCTOU guard (Codex re-gate, 2026-07-15): break-by-path can, under
   * concurrent acquirers, delete a DIFFERENT file than the one proven stale: a
   * racing acquirer may have already broken the stale lock and published a fresh
   * live lock at the same path, which a delayed `rm(lockPath)` would then
   * clobber, letting two writers believe they hold the lock. Re-checking inode
   * identity immediately before removal rejects exactly that case (a fresh lock
   * has a new inode). The residual window between this re-`stat` and the `rm` is
   * a couple of syscalls; any double-acquire it could still permit is caught by
   * the hash-chain's contiguous-sequence verification on the next load (fail
   * closed as a detected integrity finding, never a silent fork).
   */
  private async unlinkIfSameInode(
    lockPath: string,
    proven: Stats
  ): Promise<boolean> {
    let current: Stats;
    try {
      current = await stat(lockPath);
    } catch (err) {
      const code =
        err instanceof Error && "code" in err
          ? String((err as NodeJS.ErrnoException).code)
          : "";
      // Already gone: another writer removed the proven-stale lock; effectively
      // broken from our perspective. A REAL fs error (EACCES/EIO/…) is NOT
      // "already gone" and must NOT be laundered into a benign `false`: surface
      // it so a caller (esp. the graceful release) never silently treats a lock
      // it could not verify as released (invariant 5: never silently degrade).
      if (code === "ENOENT") return true;
      throw err;
    }
    if (current.dev !== proven.dev || current.ino !== proven.ino) {
      // A different file object now occupies the path (a racing acquirer already
      // broke the stale lock and published a fresh one). Do NOT remove it. This
      // is the one benign `false`: not an error, just "not ours to remove".
      return false;
    }
    // `rm(force)` swallows ENOENT (someone else removed it first → gone, fine)
    // but PROPAGATES a real removal error (EIO/EPERM/EROFS). That propagation is
    // intentional and must reach the caller: a swallowed release failure leaves
    // our lock on disk still carrying our live same-boot pid, which the next
    // acquirer cannot prove stale → permanent self-brick.
    await rm(lockPath, { force: true });
    return true;
  }

  /**
   * Break the audit-write lock iff it is PROVABLY stale, returning true when a
   * stale lock was removed. Staleness is proven several ways, all robust:
   *
   *   - BOOT-IDENTITY (primary; a per-boot UUID stamp, see {@link
   *     currentBootId}). When the lock's `boot_id` proves a DIFFERENT boot than
   *     the current one, the lock survived a reboot and is definitionally
   *     orphaned REGARDLESS of pid liveness (a reboot can reuse the dead holder's
   *     pid for a live process, foreign OR our own reclaimed pid), so it is
   *     broken, and this check runs BEFORE any pid-liveness "protect" path.
   *     When `boot_id` proves the SAME boot, the monotonic `uptime_ms` / pid
   *     reasoning is valid and immune to a wall-clock step, so a live same-boot
   *     holder is protected (legitimate contention) and a same-boot crash orphan
   *     (dead pid, or our own reused pid stamped before our start) is broken.
   *     This is what a bare `uptime_ms` MAGNITUDE cannot do alone: uptime resets
   *     on reboot, so a previous boot's value ALIASES into this boot's range and
   *     a reboot orphan with a reused-alive pid would masquerade as live (the
   *     #944 permanent-brick regression this gating closes).
   *   - WALL-CLOCK FALLBACK (locks with NO `boot_id`, i.e. old format, or when the
   *     boot-identity source is unavailable in a confined sandbox): the lock's
   *     `acquired_at` predates the current system boot. A lock that survived a
   *     reboot is definitionally orphaned, and this is immune to PID reuse (the
   *     recorded PID may now belong to an unrelated process, INCLUDING this very
   *     process: after a reboot the OS can hand us the dead holder's old pid, so
   *     this proof is checked BEFORE the self-pid guard). This restores the
   *     pre-PR behavior for old-format locks: strong reboot evidence WINS.
   *   - The recorded pid is OURS but `acquired_at` predates THIS process's start
   *     (a reused-self-pid orphan): we had not started when it was stamped, so it
   *     cannot be a lock we hold. Uses `process.uptime()` (no `uv_uptime`
   *     syscall), so it breaks the orphan even when boot time is unavailable in a
   *     confined-uid sandbox (Opus re-gate NEW-1, 2026-07-15).
   *   - The recorded holder PID is not alive. Covers a same-boot crash / kill
   *     before the PID has been reused.
   *   - Drill-found (Leg 5, MBA 2026-07-15): the lock is a genuinely EMPTY
   *     (0-byte) file (the exact torn-acquire artifact) AND its file mtime
   *     predates boot OR exceeds the id-less stale bound ({@link
   *     AuditLogConfig.idlessStaleLockMs}, default {@link
   *     AUDIT_WRITE_LOCK_IDLESS_STALE_MS}). A legitimate holder always stamps
   *     `{pid, acquired_at, uptime_ms, boot_id}` (and, since the atomic-acquire
   *     fix, the lock file never exists content-less), so a 0-byte lock can only
   *     be a torn acquire from an old binary or an out-of-band tool. Gated on
   *     `size === 0` (not merely "no id parsed"): a NON-empty but unparseable
   *     lock stays fail-closed, since it could be a live holder writing a format
   *     this build does not understand.
   *
   * Documented residual: for an OLD-format lock (no `boot_id`), or in a sandbox
   * with no boot-identity source, a large forward wall-clock step can still make
   * a live same-boot lock's `acquired_at` look pre-boot and break it (the
   * original clock-skew case). Every lock THIS build writes carries a `boot_id`
   * and is immune (the same-boot identity match protects it). A false-break is
   * detected fail-closed by the hash-chain's contiguous-sequence check on the
   * next load (a detected integrity finding, never a silent fork). The lock is a
   * LOCAL-ONLY, single-host, single-boot coordination primitive; the boot-
   * identity / monotonic reasoning is not valid across a shared network
   * filesystem.
   *
   * A lock held by a live process acquired during this boot is left untouched
   * (legitimate contention). A lock that carries an id but cannot be proven
   * stale, or a non-empty lock this build cannot parse, is left untouched
   * (fail-safe: never break a lock we cannot prove is dead). Every removal goes
   * through {@link unlinkIfSameInode} so a racing acquirer's fresh lock is never
   * clobbered by a delayed break. Fixes the daemon-cannot-restart-after-reboot
   * defect (A1 drill 2026-06-04, reboot 2) and the permanently-bricking 0-byte
   * lock (MBA custody drill 2026-07-15).
   *
   * Availability limitation (documented, not a proof): a 0-byte lock with a
   * FUTURE mtime is deliberately NOT broken here (it neither predates boot nor
   * exceeds the age bound). Planting such a file requires fortress-uid write
   * access, i.e. prior full compromise, at which point the attacker could
   * destroy the audit log directly; this fallback is an availability aid for
   * honest torn acquires, not a defense against a uid-level adversary.
   */
  private async breakStaleAuditLock(lockPath: string): Promise<boolean> {
    // Capture the identity + metadata AND the content of the EXACT file we are
    // about to reason about from a SINGLE open file descriptor: `fstat` + read
    // on one fd is a consistent snapshot, so the metadata (inode, size, mtime)
    // and the parsed `{pid, acquired_at}` always describe the same file object.
    // This closes the stat->read TOCTOU a separate path-based `stat()` then
    // `readFile()` would open (CodeQL js/file-system-race), and the captured
    // inode is re-verified by `unlinkIfSameInode` before the eventual removal so
    // a racing acquirer's fresh lock is never clobbered.
    let proven: Stats;
    let rawContent: string;
    let handle: Awaited<ReturnType<typeof open>>;
    try {
      handle = await open(lockPath, "r");
    } catch (err) {
      const code =
        err instanceof Error && "code" in err
          ? String((err as NodeJS.ErrnoException).code)
          : "";
      // Vanished: another writer released it; retry. Otherwise (e.g. EACCES):
      // cannot inspect, cannot prove stale.
      if (code === "ENOENT") return true;
      return false;
    }
    try {
      proven = await handle.stat();
      rawContent = await handle.readFile("utf8");
    } catch (err) {
      const code =
        err instanceof Error && "code" in err
          ? String((err as NodeJS.ErrnoException).code)
          : "";
      if (code === "ENOENT") return true;
      return false;
    } finally {
      await handle.close().catch(() => undefined);
    }

    let holderPid: number | undefined;
    let acquiredAtMs: number | undefined;
    let lockUptimeMs: number | undefined;
    let lockBootId: string | undefined;
    try {
      const parsed = JSON.parse(rawContent) as {
        pid?: unknown;
        acquired_at?: unknown;
        uptime_ms?: unknown;
        boot_id?: unknown;
      };
      if (typeof parsed.pid === "number" && Number.isInteger(parsed.pid)) {
        holderPid = parsed.pid;
      }
      if (typeof parsed.acquired_at === "string") {
        const t = Date.parse(parsed.acquired_at);
        if (!Number.isNaN(t)) acquiredAtMs = t;
      }
      if (typeof parsed.uptime_ms === "number" && Number.isFinite(parsed.uptime_ms)) {
        lockUptimeMs = parsed.uptime_ms;
      }
      if (typeof parsed.boot_id === "string" && parsed.boot_id.length > 0) {
        lockBootId = parsed.boot_id;
      }
    } catch {
      // Empty or non-JSON content: no id to parse. Handled by the 0-byte
      // fallback below (only when genuinely empty); non-empty stays fail-closed.
    }

    // ── Boot-identity-gated staleness reasoning ─────────────────────────────
    // A per-boot IDENTITY token (`boot_id`; a UUID minted fresh each boot, see
    // currentBootId) answers "was this lock stamped during the CURRENT boot?"
    // PROVABLY. This is what a raw uptime MAGNITUDE cannot do: `os.uptime()`
    // resets to 0 on reboot, so a PREVIOUS boot's `uptime_ms` falls in the same
    // numeric range as this boot's and ALIASES: a reboot orphan (whose recorded
    // pid a reboot then reused for a live process) looks exactly like a live
    // same-boot lock. Gating the "this is a live lock, protect it" decision on
    // boot-identity EQUALITY lets us protect a genuine live same-boot lock
    // WITHOUT ever shadowing the reboot-orphan proof (the #944 permanent-brick
    // regression this closes).
    //
    // Local-only invariant (documented): this lock coordinates writers on ONE
    // host's local filesystem. `boot_id` / `os.uptime()` are comparable only
    // within a single machine; this must NOT be pointed at a shared network
    // filesystem where they would come from a different host.
    const currentBoot = currentBootId();
    const bootIdentityKnown = lockBootId !== undefined && currentBoot !== undefined;
    const bootIdentitySameBoot = bootIdentityKnown && lockBootId === currentBoot;
    const bootIdentityDifferentBoot = bootIdentityKnown && lockBootId !== currentBoot;

    // TIE-BREAK (mandatory): a boot-identity that proves a DIFFERENT boot is the
    // STRONGEST reboot proof there is: the lock survived a reboot, so it is
    // definitionally orphaned REGARDLESS of pid liveness (a reboot can hand the
    // dead holder's pid to a live process, foreign OR our own reclaimed pid).
    // Checked BEFORE any pid-liveness "protect" path so a reused-alive pid can
    // never keep a reboot orphan intact. Rows A/B of the acceptance table.
    if (bootIdentityDifferentBoot) {
      return this.unlinkIfSameInode(lockPath, proven);
    }

    const currentUptime = currentUptimeMs();
    const ourStartUptime =
      currentUptime !== undefined ? currentUptime - process.uptime() * 1000 : undefined;

    // SAME boot PROVEN → the monotonic uptime / pid-liveness reasoning is valid
    // and immune to a wall-clock step, so we can safely protect a live same-boot
    // lock (rows D/E) and break a same-boot crash orphan, with no risk of
    // shadowing the reboot proof, since a reboot would have failed the identity
    // match above. Only reached when boot-identity is KNOWN and equal.
    if (bootIdentitySameBoot && holderPid !== undefined) {
      if (holderPid === process.pid) {
        // Our own pid, PROVEN same boot. If a monotonic `uptime_ms` stamp is
        // present and predates THIS process's start, a dead predecessor reclaimed
        // our pid this boot → reused-self orphan → break (clock-step-immune).
        // If it is at/after our start, the lock is genuinely ours → never break.
        // If no uptime stamp is present we cannot decide here; fall through to
        // the wall-clock reused-self proof below (process.uptime()-based).
        // Documented residual (mirrors the id-less note below): a same-boot
        // OWN-PID lock LACKING `uptime_ms` reaches the wall-clock reused-self
        // proof, so a large forward clock step can make our own live lock's
        // `acquired_at` appear to predate our process start and false-break it.
        // A false-break is detected fail-closed by the hash-chain
        // contiguous-sequence check on the next load (never a silent fork).
        // atomicAcquireAuditLock stamps `uptime_ms`/`boot_id` CONDITIONALLY
        // (their platform sources can be unavailable), so the residual covers
        // locks written by older binaries AND current builds on hosts where
        // those sources return undefined.
        if (lockUptimeMs !== undefined && ourStartUptime !== undefined) {
          if (lockUptimeMs < ourStartUptime - AUDIT_LOCK_MONO_UPTIME_TOLERANCE_MS) {
            return this.unlinkIfSameInode(lockPath, proven);
          }
          // Mini2 2026-08-02 freeze recovery edge (finding 2026-08-03): with
          // the hold deadline above, this process should never leave its own
          // same-boot lock older than `selfHeldStaleLockMs`. If it does, the
          // holder is a wedged/abandoned append or a failed graceful release,
          // not legitimate contention. Use monotonic uptime age only after
          // `boot_id` proved same boot; wall time is deliberately irrelevant.
          if (currentUptime !== undefined) {
            const heldForMs = currentUptime - lockUptimeMs;
            if (
              heldForMs >
              this.selfHeldStaleLockMs + AUDIT_LOCK_MONO_UPTIME_TOLERANCE_MS
            ) {
              const roundedHeldForMs = Math.max(0, Math.round(heldForMs));
              // SAFETY: forced lock recovery must be loud on operator-facing
              // stderr BEFORE any other handling (AGENTS.md constraint 5).
              console.error(
                `[audit-log] AUDIT-WRITE-LOCK-RECOVERY reason=self_held_stale_forced_release ` +
                  `lock=${lockPath} held_for_ms=${roundedHeldForMs} pid=${holderPid}`,
              );
              this.recordWriteLockRecoveryEvent({
                reason: "self_held_stale_forced_release",
                lockPath,
              });
              return this.unlinkIfSameInode(lockPath, proven);
            }
          }
          return false;
        }
      } else if (isProcessAlive(holderPid)) {
        // A live FOREIGN holder that PROVABLY stamped this boot → legitimate
        // contention. Protect it from the wall-clock `predatesBoot` proof below,
        // which a forward clock step could otherwise use to break this live lock.
        return false;
      } else {
        // Foreign holder, proven same boot, NOT alive → same-boot crash orphan.
        return this.unlinkIfSameInode(lockPath, proven);
      }
    }

    // UNKNOWN boot-identity (old-format lock with no `boot_id`, or boot-identity
    // unavailable in a confined sandbox): we CANNOT prove same-boot, so we must
    // NOT protect on pid-liveness alone: that is exactly what would let a reboot
    // orphan with a reused-alive pid survive → brick. Fall through to the
    // wall-clock reboot proofs below (`predatesBoot`-unconditional, the pre-PR
    // fail-safe behavior), which break a reboot orphan. Documented residual: an
    // OLD-format live same-boot lock under a large forward clock step can still
    // be false-broken here (predatesBoot); every lock THIS build writes carries a
    // `boot_id` and is immune. A false-break is detected fail-closed by the
    // hash-chain contiguous-sequence check on the next load (never a silent
    // fork), the same residual the id-less path documents.
    const bootTimeMs = currentBootTimeMs();
    const predatesBoot =
      acquiredAtMs !== undefined &&
      bootTimeMs !== undefined &&
      acquiredAtMs < bootTimeMs;
    // A lock whose recorded pid is OURS but whose acquired_at predates our own
    // process start cannot be a lock this process holds (we had not started when
    // it was stamped), so it is a reused-pid orphan. `process.uptime()` needs no
    // `uv_uptime` syscall, so this proof holds even in the confined-uid sandbox
    // that can leave `currentBootTimeMs()` undefined; without it, a restarted
    // fixed-role daemon that reclaims its old pid across a reboot would re-brick
    // exactly the way the boot proof is meant to prevent (Opus re-gate NEW-1,
    // 2026-07-15). Sound because a pid is unique among LIVE processes: a lock
    // carrying our pid is either ours (stamped at/after our start) or a dead
    // predecessor's (stamped before), never a concurrent foreign live holder.
    const processStartMs = currentProcessStartMs();
    const reusedSelfPidOrphan =
      holderPid === process.pid &&
      acquiredAtMs !== undefined &&
      processStartMs !== undefined &&
      acquiredAtMs < processStartMs;

    // A lock whose OWN acquired_at predates this boot cannot belong to any live
    // process, INCLUDING this one (we started after boot). Break it regardless
    // of the recorded pid, and BEFORE the self-pid guard: after a reboot the OS
    // can reuse the dead holder's pid as ours, and a self-pid short-circuit here
    // would otherwise refuse to break a genuinely orphaned lock (Codex re-gate,
    // 2026-07-15).
    if (predatesBoot || reusedSelfPidOrphan) {
      return this.unlinkIfSameInode(lockPath, proven);
    }

    // Our OWN live lock (our pid, stamped at/after our start): never break it.
    if (holderPid === process.pid) return false;

    if (holderPid !== undefined && !isProcessAlive(holderPid)) {
      return this.unlinkIfSameInode(lockPath, proven);
    }

    // 0-byte fallback: a genuinely EMPTY lock carries no id to prove liveness
    // from, so the pid/boot proofs above can never clear it (the exact
    // 0-byte-lock brick). It is provably NOT a live holder when its file mtime
    // predates boot (survived a reboot) or exceeds a generous age bound no
    // legitimate sub-second hold approaches. Gated on `size === 0` so a
    // content-bearing lock (parseable or not) is NEVER cleared this way.
    if (proven.size === 0) {
      const mtimeMs = proven.mtimeMs;
      const mtimePredatesBoot = bootTimeMs !== undefined && mtimeMs < bootTimeMs;
      const exceedsIdlessAgeBound =
        Date.now() - mtimeMs > this.idlessStaleLockMs;
      if (mtimePredatesBoot || exceedsIdlessAgeBound) {
        return this.unlinkIfSameInode(lockPath, proven);
      }
    }

    return false;
  }

  private async freshenChainStateFromDisk(): Promise<void> {
    const latest = await this.readLatestPersistedChainState();
    if (!latest) return;
    if (latest.nextSequence > this.nextSequence) {
      this.nextSequence = latest.nextSequence;
      this.lastEntryHash = latest.lastEntryHash;
    } else if (
      latest.nextSequence === this.nextSequence &&
      this.lastEntryHash !== latest.lastEntryHash
    ) {
      this.lastEntryHash = latest.lastEntryHash;
    }
  }

  /**
   * Drill-found lock-hold fix (Mini1 fortress drill, 2026-07-12): this used to
   * read-and-parse EVERY persisted entry to find the max sequence, on every
   * single append, HELD INSIDE the cross-process `withAuditWriteLock`. On a
   * non-trivial log that made each append's lock hold time O(n), and under
   * concurrent writers (egress-probe timer, heartbeats, reload, flow
   * decisions) the queue backed up past `AUDIT_WRITE_LOCK_TIMEOUT_MS` (5s),
   * exactly the contention window the drill observed, starving flow-decision
   * writes with `AuditLockContentionError`.
   *
   * `storage.list()` returns keys sorted ascending, and the `entry-` key
   * embeds the sequence zero-padded to a fixed width (see the `key` built in
   * `persistChainedEntry`), so the highest-sequence entry is ALWAYS the tail
   * of `metas`. Walking backward from the tail and stopping at the first
   * entry that parses as a valid envelope makes the common case O(1) instead
   * of O(n); a run of malformed/torn trailing entries costs more, but never
   * more than the prior full scan (fail-safe: this can never see fewer
   * candidates than necessary to find a valid one, matching the previous
   * "scan until you find a real entry" behavior exactly).
   */
  private async readLatestPersistedChainState(): Promise<{
    nextSequence: number;
    lastEntryHash: string;
  } | null> {
    // F2 Option A: exactly like `loadPersistedEntries`, never attempt a read
    // on an entry at or below a valid split boundary's sealed tip: those are
    // the legacy, possibly-permission-denied entries this instance's routine
    // paths must never touch. Without this, the O(1) backward tail-scan below
    // would walk straight into a sealed (potentially unreadable) entry on
    // EVERY `appendCritical` for a fortress with zero post-split entries so
    // far, throwing on the very read this file's own fix exists to avoid.
    // Exhausting the walk without finding anything ABOVE the boundary
    // correctly returns `null` ("nothing new to freshen from"): the
    // in-memory state was already seeded from the boundary by `ensureLoaded`.
    const splitBoundary = await this.loadSplitBoundary();
    const sealedTipSequence =
      splitBoundary.status === "valid" ? splitBoundary.boundary.sealed_tip_sequence : 0;
    // F2 Finding 1 (Codex re-gate MED): refresh the cached sealed tip from this
    // fresh boundary read. `freshenChainStateFromDisk` runs on every append, so
    // this keeps `cachedSealedTip` current even for a long-lived instance that
    // first loaded BEFORE the boundary was created (which would otherwise leave
    // it 0 and make the post-split-suffix marker write miss). Only advance it
    // (never zero it) so a transient boundary-read failure cannot lose the tip.
    if (sealedTipSequence > this.cachedSealedTip) {
      this.cachedSealedTip = sealedTipSequence;
    }
    const metas = await this.storage.list(AUDIT_NAMESPACE, "entry-");
    for (let i = metas.length - 1; i >= 0; i--) {
      const seq = parseEntryKeySequence(metas[i]!.key);
      if (seq !== null && seq <= sealedTipSequence) break;
      const raw = await this.storage.read(AUDIT_NAMESPACE, metas[i]!.key);
      if (!raw) continue;
      try {
        const parsed = JSON.parse(bytesToString(raw));
        if (!isPersistedAuditEnvelopeV2(parsed)) continue;
        return {
          nextSequence: parsed.sequence + 1,
          lastEntryHash: parsed.entry_hash,
        };
      } catch {
        // Full integrity verification reports malformed entries separately.
      }
    }
    return null;
  }

  private async writeAuditEntryBytes(
    key: string,
    persistedBytes: Uint8Array
  ): Promise<void> {
    if (this.filesystemCapabilities) {
      await this.filesystemCapabilities.writeDurable(
        AUDIT_NAMESPACE,
        key,
        persistedBytes
      );
      return;
    }
    await this.storage.write(AUDIT_NAMESPACE, key, persistedBytes);
  }

  /**
   * Decrypt an audit entry payload: current epoch key first, then prior
   * custody-epoch keys (master rotations, F7). GCM authentication decides;
   * the original failure propagates when nothing matches — never a weaker
   * path (#5). The epoch list is loaded at most once per instance; a
   * missing/invalid epoch record yields no keys, so prior-epoch entries
   * surface as `entry_decrypt_failed` findings (fail closed).
   */
  private async decryptEntryPayload(
    encrypted: EncryptedPayload
  ): Promise<Uint8Array> {
    try {
      return decrypt(encrypted, this.encryptionKey);
    } catch (primaryErr) {
      if (this.epochKeysCache === null) {
        this.epochKeysCache = await readAuditEpochKeys(this.storage, {
          epochWrapKey: this.epochWrapKey,
          epochMacKey: this.epochMacKey,
        });
      }
      for (const epochKey of this.epochKeysCache) {
        try {
          return decrypt(encrypted, epochKey);
        } catch {
          // Try the next epoch; GCM authentication decides.
        }
      }
      throw primaryErr;
    }
  }

  /**
   * Decrypt + strict-verify the full surviving chain.
   *
   * Memory contract (the daemon-OOM-on-a-large-log fix): the full decrypted
   * chain is NEVER simultaneously resident. Each chained entry is decrypted to
   * (a) prove it decrypts (the `entry_decrypt_failed` integrity check) and
   * (b) be handed to the streaming `consumer` when one drives this pass, OR slid
   * into the bounded recent-entry window otherwise; either way the decrypted
   * payload is then released. The full-chain structures we retain
   * (`chainedEntries`, `legacyRawEntries`, `this.chainEntries`) carry only cheap
   * envelope / raw-byte metadata (sequence, entry_hash, prev_hash, key), so a
   * large on-disk log no longer allocates its whole multi-GB decrypted payload
   * set per reload. Verification coverage is unchanged: every entry is still
   * decrypted, hash-checked, chain-walked, and anchor/checkpoint-covered.
   *
   * When a `consumer` is supplied (transparency emitter / against-log recount /
   * workload replay) each decrypted chained entry streams to it in ascending
   * chain-sequence order (listing order is sequence order because keys carry a
   * zero-padded sequence, the same invariant the chain walk already relies on)
   * and the non-streaming window is left untouched for the other callers. The
   * chain is still verified AFTER the decrypt loop; in strict mode any tamper
   * finding makes the caller throw `AuditIntegrityError`, discarding whatever the
   * consumer accumulated (it folds incrementally, never persisting until the
   * verified pass returns clean), so a tampered log never yields a usable result.
   */
  private async loadPersistedEntries(
    consumer?: VerifiedChainConsumer
  ): Promise<void> {
    const findings: AuditIntegrityFinding[] = [];
    // Cheap full-chain metadata only; no decrypted payloads retained here.
    const legacyRawEntries: Array<{ key: string; raw: Uint8Array }> = [];
    const chainedEntries: Array<{
      key: string;
      envelope: PersistedAuditEnvelopeV2;
    }> = [];
    // Bounded recent-entry window built during the streaming decrypt for the
    // non-streaming callers (query / posture / append). Only the newest
    // `maxInMemoryEntries` decrypted entries are kept; older payloads are dropped
    // as the window slides, so a large chain never materializes its full
    // decrypted set. A streaming `consumer` keeps NO window; it already received
    // every chained entry in order.
    const windowCap = this.maxInMemoryEntries;
    const recentEntries: AuditEntry[] = [];
    const recentChained: Array<{ sequence: number; entry_hash: string }> = [];
    const pushWindow = (
      entry: AuditEntry,
      chained: { sequence: number; entry_hash: string } | null
    ): void => {
      if (consumer) return; // streaming consumer keeps no window
      recentEntries.push(entry);
      if (chained) recentChained.push(chained);
      // Trim the OLDEST entries from the front in lockstep with their aligned
      // chained twins (legacy entries, which have no chained twin, are dropped
      // first) so `recentEntries.length - recentChained.length` stays equal to
      // the surviving legacy count (the same alignment invariant the append
      // path's trimInMemoryRetention preserves).
      const overflow = recentEntries.length - windowCap;
      if (overflow > 0) {
        const legacyResident = recentEntries.length - recentChained.length;
        recentEntries.splice(0, overflow);
        const chainedDropped = Math.max(0, overflow - legacyResident);
        if (chainedDropped > 0) recentChained.splice(0, chainedDropped);
      }
    };

    try {
      // F2 Option A: resolve the split-boundary FIRST, before any read. The
      // resolver (BLOCKER-1/2 hardening, 2026-07-14) surfaces a
      // `split_boundary_invalid` / `split_boundary_missing` finding and sets
      // `suppressTofu` for a present-but-invalid or deleted-after-migration
      // boundary (fail closed), and yields the effective sealed tip (the MAC'd
      // tip only when the boundary is VALID; 0 otherwise, so an untrusted
      // boundary never filters the region). When valid, filter out every
      // `entry-*` key at or below the sealed tip (parsed from the unencrypted
      // key itself) so this never reads a legacy entry an armed box's operator
      // uid cannot open; a key with no parseable sequence (pre-V2 legacy) is
      // left to the existing legacy-entry path below.
      const {
        boundary: splitBoundary,
        effectiveSealedTip,
        suppressTofu,
      } = await this.resolveSplitBoundaryForLoad(findings);
      // F2 Finding 1: remember the trusted sealed tip so the append path can
      // classify a post-split suffix entry without re-reading the boundary.
      this.cachedSealedTip = effectiveSealedTip;
      // ORDERING INVARIANT (must match the entry-then-anchor write order in
      // `persistChainedEntry`): sample the MAC'd head anchor BEFORE listing the
      // entries. The property this buys is narrow, so claim it precisely: a
      // LEGITIMATE append writes its entry file first and its anchor second, so
      // an anchor read here can only name an entry that was already on disk. It
      // does NOT promise the listing taken below still contains that entry — a
      // delete or rollback landing between the two reads removes it — and that
      // must fail closed, which it does: `verifyHeadAnchor` then sees
      // `highestChainedSeq < anchor.highest_sequence` and raises
      // `tail_anchor_invalid`.
      // What the early sample removes is only the FALSE verdict: reading the
      // anchor after the listing (the pre-2026-08-05 order) let an append that
      // landed mid-pass raise a floor the just-taken listing could not reach,
      // reporting a healthy concurrent writer as tail truncation. Sampling
      // EARLIER never weakens the guard, because an append after the sample only
      // makes the anchor a lower floor, and an older floor is still a floor.
      const headAnchor = await this.loadHeadAnchor(
        findings,
        splitBoundary.status === "valid"
      );
      const storedEntriesRaw = await this.storage.list(AUDIT_NAMESPACE);
      // BLOCKER-1: with a valid boundary, prove from the LISTING that the sealed
      // region is complete (gap-free run ending at the tip). This catches
      // deletion of sealed entries even when their contents are unreadable, so
      // `getIntegrityFindings()` (hence `audit-findings`) no longer reports a
      // deleted/truncated sealed prefix as clean.
      if (splitBoundary.status === "valid") {
        this.checkSealedPrefixCompleteness(
          storedEntriesRaw,
          effectiveSealedTip,
          splitBoundary.boundary.sealed_base_sequence,
          findings
        );
      }
      const storedEntries =
        effectiveSealedTip > 0
          ? storedEntriesRaw.filter((meta) => {
              const seq = parseEntryKeySequence(meta.key);
              return seq === null || seq > effectiveSealedTip;
            })
          : storedEntriesRaw;
      for (const meta of storedEntries) {
        let raw: Uint8Array | null;
        try {
          raw = await this.storage.read(AUDIT_NAMESPACE, meta.key);
        } catch (err) {
          findings.push({
            kind: "entry_unreadable",
            key: meta.key,
            message: `audit entry ${meta.key} could not be read: ${failureMessage(err)}`,
          });
          continue;
        }
        if (!raw) {
          findings.push({
            kind: "entry_unreadable",
            key: meta.key,
            message: `audit entry ${meta.key} disappeared during load`,
          });
          continue;
        }

        let parsed: unknown;
        try {
          parsed = JSON.parse(bytesToString(raw));
        } catch {
          findings.push({
            kind: "entry_malformed",
            key: meta.key,
            message: `audit entry ${meta.key} is not valid JSON`,
          });
          continue;
        }

        if (isPersistedAuditEnvelopeV2(parsed)) {
          const expectedHash = computeAuditEntryHash({
            sequence: parsed.sequence,
            prev_hash: parsed.prev_hash,
            timestamp: parsed.timestamp,
            encrypted_payload_bytes: parsed.encrypted_payload_bytes,
            schema_version: parsed.schema_version,
          });
          if (expectedHash !== parsed.entry_hash) {
            findings.push({
              kind: "entry_hash_mismatch",
              key: meta.key,
              sequence: parsed.sequence,
              expected: expectedHash,
              actual: parsed.entry_hash,
              message: `audit entry ${meta.key} hash mismatch at sequence ${parsed.sequence}`,
            });
          }

          let entry: AuditEntry;
          try {
            const encryptedBytes = fromBase64url(parsed.encrypted_payload_bytes);
            const encrypted: EncryptedPayload = JSON.parse(bytesToString(encryptedBytes));
            const decrypted = await this.decryptEntryPayload(encrypted);
            entry = JSON.parse(bytesToString(decrypted));
          } catch {
            findings.push({
              kind: "entry_decrypt_failed",
              key: meta.key,
              sequence: parsed.sequence,
              message: `audit entry ${meta.key} could not be decrypted at sequence ${parsed.sequence}`,
            });
            continue;
          }
          // Retain only cheap envelope metadata for the full-chain verify.
          chainedEntries.push({ key: meta.key, envelope: parsed });
          // Stream the decrypted entry to the consumer (Merkle/recount/replay) or
          // slide it into the bounded window; release it either way so a large
          // chain is never fully resident. Listing order is ascending sequence
          // order (zero-padded sequence in the key), so the consumer sees entries
          // in chain-sequence order. This is DELIBERATELY outside the decrypt
          // try/catch above: a consumer that throws (e.g. workload replay's
          // validateWorkloadLifecyclePayload rejecting a malformed lifecycle
          // entry) must propagate as ITSELF, not be miscategorized as
          // `entry_decrypt_failed` (decrypt already succeeded). Mislabeling it
          // would, under a future lenient pass, silently SKIP the entry: exactly
          // the #504 under-report the consumers forbid.
          if (consumer) {
            try {
              consumer.onEntry({
                sequence: parsed.sequence,
                entry_hash: parsed.entry_hash,
                entry,
              });
            } catch (consumerErr) {
              // The consumer rejected this (decrypted, hash-checked) entry, e.g.
              // workload replay's validateWorkloadLifecyclePayload on a malformed
              // lifecycle record. Propagate it AS ITSELF: tag it so the outer
              // catch re-throws verbatim instead of relabeling it
              // `storage_unavailable`. It is neither a decrypt failure nor a
              // storage failure, and must never be silently absorbed into the
              // findings list (the #504 under-report the consumers forbid).
              throw new ConsumerRejectedEntryError(consumerErr);
            }
          } else {
            pushWindow(entry, {
              sequence: parsed.sequence,
              entry_hash: parsed.entry_hash,
            });
          }
          continue;
        }

        let legacyEntry: AuditEntry;
        try {
          const encrypted = parsed as EncryptedPayload;
          const decrypted = await this.decryptEntryPayload(encrypted);
          legacyEntry = JSON.parse(bytesToString(decrypted));
        } catch {
          findings.push({
            kind: "entry_decrypt_failed",
            key: meta.key,
            message: `legacy audit entry ${meta.key} could not be decrypted`,
          });
          continue;
        }
        // Keep the raw bytes (needed for the legacy-anchor hash below); the
        // decrypted entry only slides into the bounded window. Legacy entries
        // carry no chained (sequence, entry_hash) pair and the streaming
        // consumers operate on the chained region only, so a legacy entry is
        // never streamed; the legacy region's coverage is attested by the legacy
        // anchor, not by these decrypted payloads. The window push is outside the
        // decrypt try/catch above for the same reason as the chained path: a
        // post-decrypt throw must not be miscategorized as a decrypt failure.
        legacyRawEntries.push({ key: meta.key, raw });
        pushWindow(legacyEntry, null);
      }

      const legacyHashes = legacyRawEntries.map((legacy, index) =>
        sha256Hex(
          JSON.stringify({
            schema_version: 1,
            sequence: index + 1,
            key: legacy.key,
            encrypted_payload_bytes: toBase64url(legacy.raw),
          })
        )
      );
      const legacyAnchorHash =
        legacyHashes.length > 0 ? computeAuditRoot(legacyHashes) : AUDIT_CHAIN_GENESIS;

      await this.verifyAndMaybeWriteLegacyAnchor(
        legacyRawEntries.length,
        legacyAnchorHash,
        findings,
        effectiveSealedTip
      );

      // F3: derive the chain-walk seed, honoring an authenticated rotation cut
      // (async: it reads + MAC-verifies the rotation anchor). It no longer
      // self-heals an above-genesis suffix: an absent/invalid anchor there fails
      // closed (`rotation_anchor_missing`) rather than TOFU-writing a fresh one.
      const chainSeed = await this.resolveChainSeed(
        chainedEntries,
        legacyRawEntries.length,
        legacyAnchorHash,
        splitBoundary,
        suppressTofu,
        findings
      );
      this.verifyChainedEntries(
        chainedEntries,
        chainSeed.expectedSequence,
        chainSeed.expectedPrevHash,
        findings
      );

      await this.verifyCheckpoints(
        legacyRawEntries.length,
        legacyAnchorHash,
        chainedEntries.map((item) => item.envelope),
        splitBoundary,
        findings
      );

      // Serve the bounded recent-entry window built during the streaming decrypt
      // above (NOT the full decrypted chain). When a streaming consumer drove
      // this pass, both window arrays are empty by design: the consumer already
      // received every chained entry in order, and the non-streaming window is
      // left to the query / posture / append callers. The full-chain integrity
      // invariants are unaffected: the chain head (`nextSequence` /
      // `lastEntryHash`), the legacy / rotation / head anchors, and the
      // checkpoint roots are all derived from the cheap envelope metadata and the
      // on-disk reads below, never from this window.
      if (!consumer) {
        this.entries = recentEntries;
        this.chainEntries = recentChained;
      }
      // F3: continue from the HIGHEST surviving sequence, not the entry count.
      // After rotation prunes a contiguous prefix, count != highest sequence, and
      // a count-based nextSequence would re-issue an already-used sequence and
      // break the chain. (Identical to count+1 when nothing was pruned.)
      // F2 Option A: when no chained entry survives (either genuinely nothing
      // was ever written, or everything at/below a valid split boundary was
      // filtered out above), the boundary's sealed tip is the correct floor,
      // not `legacyRawEntries.length`/`legacyAnchorHash`, which describe the
      // V1-legacy region and are 0/GENESIS on any fortress that never had one.
      // Getting this wrong would corrupt `nextSequence`/`lastEntryHash` below
      // (the state the NEXT append seeds from), not just the head-anchor check.
      const highestChainedSeq =
        chainedEntries.at(-1)?.envelope.sequence ??
        (splitBoundary.status === "valid"
          ? splitBoundary.boundary.sealed_tip_sequence
          : legacyRawEntries.length);
      const highestChainedHash =
        chainedEntries.at(-1)?.envelope.entry_hash ??
        (splitBoundary.status === "valid"
          ? splitBoundary.boundary.sealed_tip_entry_hash
          : legacyAnchorHash);
      await this.verifyHeadAnchor(
        headAnchor,
        highestChainedSeq,
        highestChainedHash,
        legacyRawEntries.length > 0,
        chainedEntries.length > 0,
        findings,
        effectiveSealedTip
      );
      this.nextSequence = highestChainedSeq + 1;
      this.lastEntryHash = highestChainedHash;
      this.hashesSinceCheckpoint = this.collectHashesSinceLastCheckpoint();
      this.integrityFindings = findings;
      // The reload now keeps only the bounded recent-entry WINDOW resident (the
      // splice in pushWindow slid it during the streaming decrypt), so a large
      // on-disk log no longer materializes its full multi-GB decrypted payload
      // set per reload; that was the daemon-OOM-on-a-large-log amplification.
      // `verifiedChainView()` / `streamVerifiedChain()` STREAM the full surviving
      // chain from disk one decrypted entry at a time, so the transparency Merkle
      // root, the against-log recount, and workload replay still cover the
      // complete chain without it ever being fully resident. #821's APPEND-path
      // bound (trimInMemoryRetention) and this RELOAD-path bound together keep the
      // heap flat on a long-running daemon.
      // A complete on-disk re-scan just ran: reset the eager-read backstop throttle
      // so the next eager read serves from this freshly-verified view without
      // re-paying, and re-baseline the sentinel fingerprint to this verified state
      // so subsequent out-of-band edits read as drift.
      this.lastFullVerifyAtMs = Date.now();
      await this.refreshExpectedStoreFingerprint();
    } catch (err) {
      // A consumer that rejected a (successfully decrypted, hash-checked) entry
      // is NOT a storage failure: propagate its original error verbatim rather
      // than mislabeling it `storage_unavailable` and swallowing it into the
      // findings list. (The streaming consumers run in strict mode, where any
      // finding throws anyway, but a future lenient pass must surface the
      // consumer's real rejection, not a generic storage finding.)
      if (err instanceof ConsumerRejectedEntryError) {
        throw err.cause;
      }
      findings.push({
        kind: "storage_unavailable",
        message: `audit storage could not be listed: ${failureMessage(err)}`,
      });
      this.integrityFindings = findings;
      // Even a failed listing is a completed (failed) full pass; stamp it so the
      // throttle does not hot-loop full scans, but the findings above keep the
      // read honest (an eager read inherits these findings → never green). Re-baseline
      // the fingerprint best-effort; on a list failure it stays a sentinel value.
      this.lastFullVerifyAtMs = Date.now();
      await this.refreshExpectedStoreFingerprint();
    }
  }

  private async verifyAndMaybeWriteLegacyAnchor(
    legacyCount: number,
    legacyAnchorHash: string,
    findings: AuditIntegrityFinding[],
    sealedTipSequence = 0
  ): Promise<void> {
    if (legacyCount === 0) return;
    const existing = await this.readCheckpoints(
      "legacy-anchor",
      findings,
      sealedTipSequence
    );
    if (existing.length === 0) {
      await this.writeCheckpointRecord({
        checkpoint_kind: "legacy-anchor",
        checkpoint_sequence: legacyCount,
        from_sequence: 1,
        root_hash: legacyAnchorHash,
        previous_checkpoint_sequence: 0,
        signed_at: new Date().toISOString(),
      });
      return;
    }

    const anchor = existing.at(-1)!;
    await this.verifyCheckpointRecordSignature(anchor, findings);
    if (
      anchor.checkpoint_sequence !== legacyCount ||
      anchor.root_hash !== legacyAnchorHash
    ) {
      findings.push({
        kind: "legacy_anchor_mismatch",
        expected: anchor.root_hash,
        actual: legacyAnchorHash,
        message: "legacy audit anchor does not match the current legacy entries",
      });
    }
  }

  private verifyChainedEntries(
    entries: Array<{
      key: string;
      envelope: PersistedAuditEnvelopeV2;
    }>,
    expectedSequenceSeed: number,
    expectedPrevHashSeed: string,
    findings: AuditIntegrityFinding[]
  ): void {
    // Seed is resolved by resolveChainSeed (genesis, legacy anchor, or an
    // authenticated rotation anchor). The contiguous forward walk is unchanged.
    let expectedSequence = expectedSequenceSeed;
    let expectedPrevHash = expectedPrevHashSeed;

    for (const item of entries) {
      const envelope = item.envelope;
      if (envelope.sequence !== expectedSequence) {
        findings.push({
          kind: "sequence_gap_or_reorder",
          key: item.key,
          sequence: envelope.sequence,
          expected: expectedSequence,
          actual: envelope.sequence,
          message: `audit sequence break at ${item.key}: expected ${expectedSequence}, found ${envelope.sequence}`,
        });
      }
      if (envelope.prev_hash !== expectedPrevHash) {
        findings.push({
          kind: "prev_hash_mismatch",
          key: item.key,
          sequence: envelope.sequence,
          expected: expectedPrevHash,
          actual: envelope.prev_hash,
          message: `audit prev_hash mismatch at sequence ${envelope.sequence}`,
        });
      }
      expectedSequence++;
      expectedPrevHash = envelope.entry_hash;
    }
  }

  private async verifyCheckpoints(
    legacyCount: number,
    legacyAnchorHash: string,
    entries: PersistedAuditEnvelopeV2[],
    splitBoundary: AuditStoreSplitBoundaryLoadResult,
    findings: AuditIntegrityFinding[]
  ): Promise<void> {
    // F2 Option A: a checkpoint entirely within the SEALED legacy region (see
    // the module doc comment near AUDIT_SPLIT_BOUNDARY_DIRNAME) can never be
    // root-recomputed from the current in-memory entry set, since this
    // instance never even attempted to read those entries. Every checkpoint
    // that predates the split has `checkpoint_sequence <= sealedTipSequence`
    // by construction (the migration captures the CURRENT tip, so nothing
    // sealed can reference a not-yet-written future entry). Resolve it BEFORE
    // the read so `readCheckpoints` can also SKIP a sealed-region checkpoint
    // file that is unreadable at this privilege (a root-owned legacy file on an
    // armed box) instead of failing the whole load closed.
    const sealedTipSequence =
      splitBoundary.status === "valid" ? splitBoundary.boundary.sealed_tip_sequence : 0;
    const checkpoints = await this.readCheckpoints(
      "audit-checkpoint",
      findings,
      sealedTipSequence
    );
    const entryBySequence = new Map(entries.map((entry) => [entry.sequence, entry]));
    let highestCheckpoint = 0;

    // F3: the lowest surviving chained sequence. Entries below this floor (but
    // above the legacy region) were legitimately pruned by rotation. A checkpoint
    // written before that rotation still references those now-gone sequences; its
    // root cannot be re-derived from entries that no longer exist. (When legacy
    // entries survive, no chained rotation has occurred — legacy keys prune first
    // — so the floor is legacyCount+1 and nothing is skipped.)
    const rotationFloor =
      entries[0]?.sequence ?? Math.max(sealedTipSequence, legacyCount) + 1;

    for (const checkpoint of checkpoints) {
      if (checkpoint.checkpoint_sequence > highestCheckpoint) {
        highestCheckpoint = checkpoint.checkpoint_sequence;
      }

      // A checkpoint whose range dips below the surviving floor spans
      // rotated-out entries, OR sits entirely within the sealed split-boundary
      // region. Skip the root re-derivation (it would always mismatch, since
      // the leaves are gone or were never loaded), but still verify its signature
      // below. The CURRENT chain's integrity is anchored by the MAC'd rotation
      // anchor (or the MAC'd split-boundary record) + the forward walk, not by
      // these historical checkpoints, so skipping the root recomputation here
      // is not a fail-open for the protected property.
      const spansRotatedEntries =
        checkpoint.checkpoint_sequence <= sealedTipSequence ||
        (checkpoint.from_sequence > legacyCount &&
          checkpoint.from_sequence < rotationFloor);

      if (!spansRotatedEntries) {
        const hashes: string[] = [];
        for (
          let sequence = checkpoint.from_sequence;
          sequence <= checkpoint.checkpoint_sequence;
          sequence++
        ) {
          if (sequence <= legacyCount) {
            if (
              checkpoint.from_sequence === 1 &&
              checkpoint.checkpoint_sequence === legacyCount
            ) {
              hashes.push(legacyAnchorHash);
              break;
            }
            findings.push({
              kind: "checkpoint_root_mismatch",
              sequence,
              message: `checkpoint includes legacy sequence ${sequence} outside the legacy anchor`,
            });
            continue;
          }
          const entry = entryBySequence.get(sequence);
          if (!entry) {
            findings.push({
              kind: "checkpoint_root_mismatch",
              sequence,
              message: `checkpoint references missing audit sequence ${sequence}`,
            });
            continue;
          }
          hashes.push(entry.entry_hash);
        }

        // Checkpoint root invariant: the persisted root is recomputed from the
        // verified entry hashes on load, so a checkpoint cannot bless a changed
        // span by carrying its own root_hash.
        const expectedRoot = computeAuditRoot(hashes);
        if (checkpoint.root_hash !== expectedRoot) {
          findings.push({
            kind: "checkpoint_root_mismatch",
            sequence: checkpoint.checkpoint_sequence,
            expected: expectedRoot,
            actual: checkpoint.root_hash,
            message: `checkpoint root mismatch at sequence ${checkpoint.checkpoint_sequence}`,
          });
        }
      }

      await this.verifyCheckpointRecordSignature(checkpoint, findings);
    }

    this.lastCheckpointSequence = highestCheckpoint;
  }

  private async verifyCheckpointRecordSignature(
    checkpoint: AuditCheckpointRecord,
    findings: AuditIntegrityFinding[]
  ): Promise<void> {
    if (checkpoint.unsigned) return;
    if (!checkpoint.signer_kid || !checkpoint.signature) {
      findings.push({
        kind: "checkpoint_signature_mismatch",
        sequence: checkpoint.checkpoint_sequence,
        message: `checkpoint ${checkpoint.checkpoint_sequence} is marked signed but lacks signer data`,
      });
      return;
    }

    let resolution: AuditCheckpointKeyResolution;
    try {
      resolution = await this.checkpointPublicKeyResolver(checkpoint.signer_kid);
    } catch {
      // A resolver failure reads as "signer unknown" and surfaces as a
      // finding below; it must never read as verified, and must never crash
      // the load pass that the rest of the chain verification rides on.
      resolution = undefined;
    }
    const resolvedPublicKeys = (
      Array.isArray(resolution) ? resolution : [resolution]
    ).filter((key): key is string | Uint8Array => key !== undefined);
    // Checkpoint trust-basis invariant: an embedded public key is part of the
    // checkpoint being verified, so it is attacker-controlled unless the caller
    // explicitly asks for an internal-consistency check instead of signer trust.
    // When the resolver DID return authenticated keys, they are authoritative
    // for this signer_kid: a signature that fails against them is a mismatch,
    // never a reason to retry against the embedded copy.
    if (resolvedPublicKeys.length === 0) {
      const embeddedPublicKey = this.trustEmbeddedCheckpointPublicKeys
        ? checkpoint.public_key
        : undefined;
      if (!embeddedPublicKey) {
        if (checkpoint.public_key) {
          findings.push({
            kind: "checkpoint_signature_embedded_key_untrusted",
            sequence: checkpoint.checkpoint_sequence,
            message:
              `checkpoint signer ${checkpoint.signer_kid} has only an embedded public key; ` +
              "configure checkpointPublicKeyResolver with an authenticated key, or explicitly opt in to embedded-key self-checks",
          });
          return;
        }
        findings.push({
          kind: "checkpoint_signature_unverifiable",
          sequence: checkpoint.checkpoint_sequence,
          message: `checkpoint signer ${checkpoint.signer_kid} has no known public key`,
        });
        return;
      }
      resolvedPublicKeys.push(embeddedPublicKey);
    }

    const valid = resolvedPublicKeys.some((publicKey) =>
      verifyCheckpointSignature(
        checkpointPayload(checkpoint),
        checkpoint.signature!,
        publicKey
      )
    );
    if (!valid) {
      findings.push({
        kind: "checkpoint_signature_mismatch",
        sequence: checkpoint.checkpoint_sequence,
        message: `checkpoint signature mismatch at sequence ${checkpoint.checkpoint_sequence}`,
      });
    }
  }

  private async readCheckpoints(
    kind: "audit-checkpoint" | "legacy-anchor",
    findings: AuditIntegrityFinding[],
    // F2 Option A: the sealed split-boundary tip (0 when there is no VALID
    // boundary). A checkpoint whose key-sequence sits at or below this tip
    // anchors ONLY the sealed legacy region, whose integrity is carried by the
    // MAC'd boundary + the root-only sealed-region crypto walk, NOT by these
    // legacy checkpoints. On an armed box those files were written by a
    // pre-split ROOT daemon (root-owned 0600) and are unreadable at the operator
    // uid, so their read throws EACCES. Below, such a read is SKIPPED (never a
    // finding) exactly as the routine load already skips sealed ENTRIES; a
    // genuine tamper/IO fault, or any unreadable checkpoint ABOVE the tip, still
    // fails closed. This is the READ-side analogue of the sealed-region skip that
    // `verifyCheckpoints` already applies to the root RE-DERIVATION.
    sealedTipSequence = 0
  ): Promise<AuditCheckpointRecord[]> {
    const records: AuditCheckpointRecord[] = [];
    let metas;
    try {
      metas = await this.storage.list(AUDIT_CHECKPOINT_NAMESPACE, `${kind}-`);
    } catch (err) {
      findings.push({
        kind: "storage_unavailable",
        message: `audit checkpoints could not be listed: ${failureMessage(err)}`,
      });
      return records;
    }

    for (const meta of metas) {
      const keySeq = parseCheckpointKeySequence(meta.key);
      const inSealedRegion =
        sealedTipSequence > 0 && keySeq !== null && keySeq <= sealedTipSequence;
      let raw: Uint8Array | null;
      try {
        raw = await this.storage.read(AUDIT_CHECKPOINT_NAMESPACE, meta.key);
      } catch (err) {
        // F2: a sealed-region checkpoint the operator uid cannot open on an
        // armed box (root-owned legacy file). The boundary MAC covers the
        // sealed region, so skip it silently: the same soundness argument that
        // lets the routine load skip unreadable sealed entries. Anything else
        // (a non-permission error, or an unreadable checkpoint ABOVE the sealed
        // tip) is a real problem and fails closed.
        if (inSealedRegion && isPermissionError(err)) {
          continue;
        }
        findings.push({
          kind: "storage_unavailable",
          message: `audit checkpoint ${meta.key} could not be read: ${failureMessage(err)}`,
        });
        continue;
      }
      if (!raw) {
        findings.push({
          kind: "checkpoint_malformed",
          key: meta.key,
          message: `audit checkpoint ${meta.key} disappeared during load`,
        });
        continue;
      }
      try {
        const parsed = JSON.parse(bytesToString(raw));
        if (!isAuditCheckpointRecord(parsed) || parsed.checkpoint_kind !== kind) {
          throw new Error("invalid checkpoint shape");
        }
        records.push(parsed);
      } catch {
        findings.push({
          kind: "checkpoint_malformed",
          key: meta.key,
          message: `audit checkpoint ${meta.key} is malformed`,
        });
      }
    }

    return records.sort(
      (a, b) => a.checkpoint_sequence - b.checkpoint_sequence
    );
  }

  private collectHashesSinceLastCheckpoint(): string[] {
    if (this.lastCheckpointSequence <= 0) {
      return this.chainEntries.map((entry) => entry.entry_hash);
    }
    return this.chainEntries
      .filter((entry) => entry.sequence > this.lastCheckpointSequence)
      .map((entry) => entry.entry_hash);
  }

  private async writeCheckpointIfNeeded(_reason: string): Promise<void> {
    if (this.checkpointInFlight || this.hashesSinceCheckpoint.length === 0) return;
    this.checkpointInFlight = true;
    try {
      await this.withAuditWriteLock(async (signal) => {
        this.assertAuditWriteLockActive(signal);
        await this.freshenChainStateFromDisk();
        this.assertAuditWriteLockActive(signal);
        // F2 Option A: never ask for hashes at or below a valid split
        // boundary's sealed tip, since those entries are the legacy region
        // this instance's routine paths must never attempt to read. A checkpoint
        // whose natural `from_sequence` would dip into the sealed region
        // instead starts right after it, mirroring how `verifyCheckpoints`
        // already tolerates a checkpoint not covering a rotated/sealed
        // prefix on the READ side. Resolve it BEFORE scanning existing
        // checkpoints so the scan can also skip a sealed-region checkpoint file
        // that is unreadable at this privilege (a root-owned legacy file on an
        // armed box) instead of throwing EACCES out of the append/checkpoint path.
        const splitBoundary = await this.loadSplitBoundary();
        this.assertAuditWriteLockActive(signal);
        const sealedTipSequence =
          splitBoundary.status === "valid"
            ? splitBoundary.boundary.sealed_tip_sequence
            : 0;
        const previousCheckpointSequence =
          await this.readHighestAuditCheckpointSequence(sealedTipSequence);
        this.assertAuditWriteLockActive(signal);
        const checkpointSequence = this.nextSequence - 1;
        const fromSequence = Math.max(
          previousCheckpointSequence + 1,
          sealedTipSequence + 1
        );
        const hashes = await this.collectPersistedEntryHashes(
          fromSequence,
          checkpointSequence,
          sealedTipSequence
        );
        this.assertAuditWriteLockActive(signal);
        if (hashes.length === 0) return;
        await this.writeCheckpointRecord({
          checkpoint_kind: "audit-checkpoint",
          checkpoint_sequence: checkpointSequence,
          from_sequence: fromSequence,
          // Checkpoint write invariant: the root is derived from persisted entry
          // hashes collected while the write lock is held, not from mutable
          // in-memory payloads or caller-provided checkpoint material.
          root_hash: computeAuditRoot(hashes),
          previous_checkpoint_sequence: previousCheckpointSequence,
          signed_at: new Date().toISOString(),
        });
        this.assertAuditWriteLockActive(signal);
        this.lastCheckpointSequence = checkpointSequence;
        this.hashesSinceCheckpoint = [];
        this.criticalAppendsSinceCheckpoint = 0;
      });
    } finally {
      this.checkpointInFlight = false;
    }
  }

  private async readHighestAuditCheckpointSequence(
    sealedTipSequence = 0
  ): Promise<number> {
    const metas = await this.storage.list(
      AUDIT_CHECKPOINT_NAMESPACE,
      "audit-checkpoint-"
    );
    let highest = 0;
    for (const meta of metas) {
      // F2 Option A: the operator's own checkpoints are always ABOVE the sealed
      // tip, so a sealed-region checkpoint the operator uid cannot open on an
      // armed box (root-owned legacy file) is never the highest and can be
      // skipped silently. A non-permission fault, or an unreadable checkpoint
      // above the tip, still surfaces (rethrown to the append/checkpoint caller,
      // which fails closed rather than under-counting the checkpoint floor).
      const keySeq = parseCheckpointKeySequence(meta.key);
      const inSealedRegion =
        sealedTipSequence > 0 && keySeq !== null && keySeq <= sealedTipSequence;
      let raw: Uint8Array | null;
      try {
        raw = await this.storage.read(AUDIT_CHECKPOINT_NAMESPACE, meta.key);
      } catch (err) {
        if (inSealedRegion && isPermissionError(err)) continue;
        throw err;
      }
      if (!raw) continue;
      try {
        const parsed = JSON.parse(bytesToString(raw));
        if (
          isAuditCheckpointRecord(parsed) &&
          parsed.checkpoint_kind === "audit-checkpoint" &&
          parsed.checkpoint_sequence > highest
        ) {
          highest = parsed.checkpoint_sequence;
        }
      } catch {
        // Full verification reports malformed checkpoints.
      }
    }
    return highest;
  }

  private async collectPersistedEntryHashes(
    fromSequence: number,
    toSequence: number,
    sealedTipSequence = 0
  ): Promise<string[]> {
    const metas = await this.storage.list(AUDIT_NAMESPACE, "entry-");
    const bySequence = new Map<number, string>();
    for (const meta of metas) {
      // F2 Option A: same guard as `readLatestPersistedChainState`; never
      // attempt a read at or below the sealed tip.
      const seq = parseEntryKeySequence(meta.key);
      if (seq !== null && seq <= sealedTipSequence) continue;
      const raw = await this.storage.read(AUDIT_NAMESPACE, meta.key);
      if (!raw) continue;
      try {
        const parsed = JSON.parse(bytesToString(raw));
        if (isPersistedAuditEnvelopeV2(parsed)) {
          bySequence.set(parsed.sequence, parsed.entry_hash);
        }
      } catch {
        // Full verification reports malformed entries.
      }
    }

    const hashes: string[] = [];
    for (let sequence = fromSequence; sequence <= toSequence; sequence++) {
      const hash = bySequence.get(sequence);
      if (!hash) break;
      hashes.push(hash);
    }
    return hashes;
  }

  private async writeCheckpointRecord(
    payload: AuditCheckpointSigningPayload
  ): Promise<void> {
    let signed: AuditCheckpointSignature | null;
    try {
      signed = (await this.checkpointSigner(payload)) ?? null;
    } catch {
      signed = null;
    }

    // Production checkpoints are signed by the constructor-derived fortress
    // identity binding (IC-05); a checkpoint may still be unsigned when the
    // store holds no signable identity (fresh fortress before bootstrap, a
    // store whose adapter cannot reach identity records). That honest bound
    // is serialized as `unsigned` instead of fabricating signer evidence or
    // silently trusting a fallback key.
    const record: AuditCheckpointRecord = {
      schema_version: AUDIT_CHECKPOINT_SCHEMA_VERSION,
      ...payload,
      signer_kid: signed?.signer_kid ?? null,
      signature: signed?.signature ?? null,
      signature_algorithm: signed ? "Ed25519" : null,
      payload_encoding: "domain-separated-canonical-json-v1",
      unsigned: !signed,
      ...(signed?.public_key ? { public_key: signed.public_key } : {}),
      ...(!signed
        ? { unsigned_reason: "no signing identity available at checkpoint time" }
        : {}),
    };
    const key = `${payload.checkpoint_kind}-${String(payload.checkpoint_sequence).padStart(20, "0")}`;
    await this.storage.write(
      AUDIT_CHECKPOINT_NAMESPACE,
      key,
      stringToBytes(JSON.stringify(record))
    );
  }

  private async reportIntegrityFindingsIfAny(): Promise<void> {
    if (this.integrityFindings.length === 0) return;
    const signature = JSON.stringify(
      this.integrityFindings.map((finding) => ({
        kind: finding.kind,
        key: finding.key,
        sequence: finding.sequence,
        expected: finding.expected,
        actual: finding.actual,
      }))
    );
    if (signature === this.lastIntegrityAlertSignature) return;
    this.lastIntegrityAlertSignature = signature;

    const event: AuditIntegrityAnomalyEvent = {
      type: "audit_integrity_finding",
      severity: "P1",
      finding_count: this.integrityFindings.length,
      findings: [...this.integrityFindings],
      observed_at: new Date().toISOString(),
    };

    for (const subscriber of this.integrityAnomalySubscribers) {
      try {
        await subscriber(event);
      } catch {
        // Alert subscribers must not mask the integrity failure itself.
      }
    }

    await this.writeIntegrityAlertLog(event).catch(() => {
      // The caller still gets AuditIntegrityError in strict mode.
    });
  }

  private async writeIntegrityAlertLog(
    event: AuditIntegrityAnomalyEvent
  ): Promise<void> {
    const line = `${JSON.stringify({
      observed_at: event.observed_at,
      severity: event.severity,
      finding_count: event.finding_count,
      findings: event.findings.map((finding) => ({
        kind: finding.kind,
        key: finding.key,
        sequence: finding.sequence,
      })),
    })}\n`;
    const existing = await this.storage.read(
      AUDIT_INTEGRITY_ALERT_NAMESPACE,
      AUDIT_INTEGRITY_ALERT_KEY
    );
    const next =
      (existing ? bytesToString(existing) : "") + line;
    if (this.filesystemCapabilities) {
      await this.filesystemCapabilities.writeDurable(
        AUDIT_INTEGRITY_ALERT_NAMESPACE,
        AUDIT_INTEGRITY_ALERT_KEY,
        stringToBytes(next)
      );
      return;
    }
    await this.storage.write(
      AUDIT_INTEGRITY_ALERT_NAMESPACE,
      AUDIT_INTEGRITY_ALERT_KEY,
      stringToBytes(next)
    );
  }

  /**
   * Get total number of entries.
   */
  get size(): number {
    return this.entries.length + this.pendingVisibleEntries;
  }
}

function failureMessage(failure: unknown): string {
  if (failure instanceof Error && failure.message.length > 0) {
    return `audit persistence write failed: ${failure.message}`;
  }
  return `audit persistence write failed: ${String(failure)}`;
}

function toAuditPersistenceError(err: unknown): AuditPersistenceError {
  if (err instanceof AuditPersistenceError) return err;
  return new AuditPersistenceError(failureMessage(err), classifyFailure(err), err);
}

function classifyFailure(err: unknown): AuditPersistenceFailureClassification {
  if (err instanceof AuditPersistenceError) return err.classification;
  const code =
    err instanceof Error && "code" in err
      ? String((err as NodeJS.ErrnoException).code)
      : "";
  if (code === "ENOSPC" || code === "EDQUOT") return "storage_full";
  if (code === "EACCES" || code === "EPERM") return "permission_denied";
  if (code === "EIO" || code === "EROFS" || code === "ENODEV") {
    return "disk_failure";
  }
  return "unknown";
}

function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.byteLength !== b.byteLength) return false;
  for (let i = 0; i < a.byteLength; i++) {
    if (a[i] !== b[i]) return false;
  }
  return true;
}

/** Constant-time byte comparison for MAC verification (avoids timing leaks). */
function constantTimeEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) {
    diff |= a[i]! ^ b[i]!;
  }
  return diff === 0;
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function currentBootTimeMs(): number | undefined {
  try {
    return Date.now() - osUptime() * 1000;
  } catch {
    // Some sandboxed child processes cannot call uv_uptime. In that case the
    // lock is not proven stale by boot time; PID liveness (and the
    // process-start proof below) can still prove it.
    return undefined;
  }
}

/**
 * System uptime in ms (`os.uptime()`), or undefined if the syscall is
 * unavailable (the same confined-uid sandbox that can block {@link
 * currentBootTimeMs}). Unlike a wall-clock-derived boot/start time, this is a
 * MONOTONIC signal: it advances at real-time rate and is unaffected by a wall-
 * clock step, so it is the trustworthy basis for deciding whether an audit-write
 * lock stamped `uptime_ms` belongs to the current boot / a live holder even when
 * the wall clock has jumped forward (VM resume, NTP correction).
 */
function currentUptimeMs(): number | undefined {
  try {
    return osUptime() * 1000;
  } catch {
    return undefined;
  }
}

// Cache for {@link currentBootId}: `undefined` = not yet read, `null` = read but
// no source available. The boot-identity token is constant for the life of a
// boot, so one read suffices and keeps the sysctl exec / /proc read off the
// per-acquire hot path.
let cachedBootId: string | null | undefined;

/**
 * A per-boot IDENTITY token that is STABLE within a boot, DIFFERENT across
 * reboots, and (unlike a boot TIME) INVARIANT to a wall-clock step:
 *   - Linux: `/proc/sys/kernel/random/boot_id`, a random UUID minted each boot.
 *   - macOS: `kern.bootsessionuuid`, a random UUID minted each boot; falls back
 *     to the `kern.boottime` string on the rare build without it.
 * Returns `undefined` when no source is available (an unknown platform, or a
 * confined sandbox that blocks both the /proc read and the sysctl exec).
 *
 * This is the trustworthy answer to "was this lock stamped during the CURRENT
 * boot?". A boot TIME derived from `Date.now() - uptime` shifts under an NTP /
 * VM-resume clock step, and a raw `uptime` MAGNITUDE ALIASES across reboots (a
 * previous boot's uptime falls in the same numeric range as this boot's), so
 * neither can distinguish a live same-boot lock from a reboot orphan whose pid
 * was reused by a live process. A per-boot UUID cannot be confused between two
 * boots, so {@link AuditLog.breakStaleAuditLock} uses it to protect a genuine
 * live same-boot lock WITHOUT shadowing the reboot-orphan proof.
 *
 * Result is cached (see {@link cachedBootId}). A read failure caches "no source"
 * so a broken/blocked source is not retried on every acquire; this fails safe:
 * with no identity the caller falls back to the wall-clock reboot proofs.
 */
function currentBootId(): string | undefined {
  if (cachedBootId !== undefined) return cachedBootId ?? undefined;
  cachedBootId = readBootIdUncached() ?? null;
  return cachedBootId ?? undefined;
}

/** One-shot platform read behind {@link currentBootId}'s cache. */
function readBootIdUncached(): string | undefined {
  try {
    if (process.platform === "linux") {
      const id = readFileSync("/proc/sys/kernel/random/boot_id", "utf8").trim();
      return id.length > 0 ? id : undefined;
    }
    if (process.platform === "darwin") {
      const readSysctl = (name: string): string => {
        try {
          return execFileSync("sysctl", ["-n", name], {
            encoding: "utf8",
            stdio: ["ignore", "pipe", "ignore"],
            timeout: 2_000,
          }).trim();
        } catch {
          return "";
        }
      };
      const sessionUuid = readSysctl("kern.bootsessionuuid");
      if (sessionUuid.length > 0) return sessionUuid;
      // Last-resort fallback for a macOS build without kern.bootsessionuuid: the
      // boot TIME string. Less ideal (a large clock step can shift it), but still
      // a per-boot discriminator; the tie-break treats any mismatch as reboot
      // evidence, never as license to protect an orphan.
      const boottime = readSysctl("kern.boottime");
      return boottime.length > 0 ? boottime : undefined;
    }
    return undefined;
  } catch {
    return undefined;
  }
}

/**
 * Wall-clock time this Node PROCESS started, in ms. Unlike
 * {@link currentBootTimeMs}, `process.uptime()` is process-local and needs no
 * `uv_uptime` syscall, so it survives the confined-uid sandbox that can block
 * `os.uptime()`. Used ONLY as the reused-self-pid discriminator: a lock whose
 * recorded pid equals ours but whose `acquired_at` predates our own start
 * cannot be a lock this process holds (we had not started when it was stamped),
 * so it is a reused-pid orphan and must be breakable even when boot time is
 * unavailable (drill-follow-up, Opus re-gate NEW-1, 2026-07-15).
 */
function currentProcessStartMs(): number | undefined {
  try {
    return Date.now() - process.uptime() * 1000;
  } catch {
    return undefined;
  }
}

function asFilesystemCapabilities(
  storage: StorageBackend
): FilesystemStorageCapabilities | undefined {
  const candidate = storage as Partial<FilesystemStorageCapabilities>;
  if (
    typeof candidate.namespacePath === "function" &&
    typeof candidate.writeDurable === "function"
  ) {
    return candidate as FilesystemStorageCapabilities;
  }
  return undefined;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return !!value && typeof value === "object" && !Array.isArray(value);
}

function isPersistedAuditEnvelopeV2(
  value: unknown
): value is PersistedAuditEnvelopeV2 {
  return (
    isRecord(value) &&
    value.schema_version === AUDIT_CHAIN_SCHEMA_VERSION &&
    typeof value.sequence === "number" &&
    Number.isSafeInteger(value.sequence) &&
    value.sequence > 0 &&
    typeof value.prev_hash === "string" &&
    typeof value.entry_hash === "string" &&
    /^[0-9a-f]{64}$/.test(value.entry_hash) &&
    typeof value.timestamp === "string" &&
    typeof value.encrypted_payload_bytes === "string"
  );
}

// isAuditCheckpointRecord moved to the pure shared `audit/checkpoint-shape.ts`
// (G1, post-#969 sweep re-gate) and is imported above: the raw CLI exporter's
// hand-duplicated copy had drifted WEAKER than this runtime's (no
// schema_version / signature_algorithm / payload_encoding / root_hash-hex
// checks), so a malformed checkpoint could export uncounted. One shared
// definition makes that drift structurally impossible.

function checkpointPayload(
  checkpoint: AuditCheckpointRecord
): AuditCheckpointSigningPayload {
  return {
    checkpoint_kind: checkpoint.checkpoint_kind,
    checkpoint_sequence: checkpoint.checkpoint_sequence,
    from_sequence: checkpoint.from_sequence,
    root_hash: checkpoint.root_hash,
    previous_checkpoint_sequence: checkpoint.previous_checkpoint_sequence,
    signed_at: checkpoint.signed_at,
  };
}
