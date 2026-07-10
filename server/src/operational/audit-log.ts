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

import { mkdir, open, readFile, rm } from "node:fs/promises";
import { join } from "node:path";
import { uptime as osUptime } from "node:os";
import { AsyncLocalStorage } from "node:async_hooks";
import type {
  FilesystemStorageCapabilities,
  StorageBackend,
} from "../storage/interface.js";
import { encrypt, decrypt, type EncryptedPayload } from "../core/encryption.js";
import { derivePurposeKey } from "../core/key-derivation.js";
import { hmacSha256 } from "../core/hashing.js";
import { stringToBytes, bytesToString, toBase64url, fromBase64url } from "../core/encoding.js";
import {
  AUDIT_CHAIN_GENESIS,
  AUDIT_CHAIN_SCHEMA_VERSION,
  AUDIT_CHECKPOINT_SCHEMA_VERSION,
  type AuditCheckpointRecord,
  type AuditCheckpointSignature,
  type AuditCheckpointSigningPayload,
  canonicalJson,
  computeAuditEntryHash,
  computeAuditRoot,
  sha256Hex,
  verifyCheckpointSignature,
} from "../audit/chain.js";
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
  | "checkpoint_signature_unverifiable";

export interface AuditIntegrityFinding {
  kind: AuditIntegrityFindingKind;
  message: string;
  key?: string;
  sequence?: number;
  expected?: string | number;
  actual?: string | number;
}

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
  /** Write a checkpoint after this many critical appends. Default: 100. */
  checkpointInterval?: number;
  /** Optional typed identity signing bridge for checkpoint records. */
  checkpointSigner?: (
    payload: AuditCheckpointSigningPayload
  ) => Promise<AuditCheckpointSignature | null>;
  /** Resolve a known checkpoint signing key by signer_kid. */
  checkpointPublicKeyResolver?: (signerKid: string) => string | Uint8Array | undefined;
  /** Optional in-process subscribers notified when audit-chain integrity fails. */
  integrityAnomalySubscribers?: AuditIntegrityAnomalySubscriber[];
  /**
   * Backstop interval (ms) between full on-disk re-verifications on the eager
   * read path. Defaults to {@link DEFAULT_AUDIT_EAGER_REVERIFY_INTERVAL_MS}
   * (30s); also overridable via the `AUDIT_EAGER_REVERIFY_INTERVAL_MS` env var.
   * Exposed primarily so tests can drive the backstop deterministically. The
   * sentinel fingerprint check (event-driven out-of-band detection) is NOT
   * gated by this interval; this is only the residual same-length+mtime backstop.
   */
  eagerReverifyIntervalMs?: number;
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
// F3: reserved storage key for the single MAC-authenticated rotation checkpoint.
// Stored alongside the (optionally-signed) checkpoint records but addressed by a
// fixed key that does NOT match the `audit-checkpoint-`/`legacy-anchor-` prefixes
// the checkpoint readers list on, so it never collides with those scans.
const AUDIT_ROTATION_ANCHOR_KEY = "__rotation_anchor";
const AUDIT_HEAD_ANCHOR_KEY = "__head_anchor";
const AUDIT_HEAD_ANCHOR_ESTABLISHED_KEY = "audit-head-anchor-established-v1";
// Distinctive envelope marker so a MAC'd rotation anchor is unambiguously
// distinguished from a bare/marker-stripped record (mirrors F1's state-meta MAC).
const AUDIT_ROTATION_ANCHOR_MARKER = "__sanctuary_audit_rotation_anchor_v1";
const AUDIT_HEAD_ANCHOR_MARKER = "__sanctuary_audit_head_anchor_v1";
// Domain-separated MAC over the rotation-anchor record. The anchor records the
// authenticated lowest-surviving sequence + its prev_hash after a prune, so a
// post-cut deletion is still detectable while a legitimate rotation verifies
// cleanly. The MAC ALWAYS authenticates (master-key derived) — unlike the
// optional Ed25519 checkpoint signer, which may be null.
const AUDIT_ROTATION_ANCHOR_MAC_DOMAIN = "sanctuary.audit-rotation-anchor.v1\n";
const AUDIT_HEAD_ANCHOR_MAC_DOMAIN = "sanctuary.audit-head-anchor.v1\n";

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
export const AUDIT_EPOCH_KEYS_KEY = "__custody_epoch_keys";
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
    if ((await storage.read("_meta", AUDIT_HEAD_ANCHOR_ESTABLISHED_KEY)) !== null) {
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
const AUDIT_WRITE_LOCK_TIMEOUT_MS = 5_000;
const AUDIT_WRITE_LOCK_RETRY_MS = 100;
// Read-consistency backstop. A reader does NOT take the write lock (audit reads
// must work even if a crashed writer stranded a lock, and must never be blockable
// by a planted lock file), so it can observe a torn cut while a rotation is
// mid-flight. We retry through such transients, but the budget is a bounded
// wall-clock DEADLINE rather than a fixed tick count: a legitimately slow
// rotation on a loaded CI host can outrun any small fixed ceiling (the original
// false-fail), while an attacker who keeps the store permanently mid-update still
// fails closed once the deadline passes.
const AUDIT_READ_CONSISTENCY_MAX_MS = 2_000;
const AUDIT_READ_CONSISTENCY_RETRY_MS = 10;
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
      `audit write blocked: another writer held the lock for >5s; check for stuck processes; inspect with: lsof ${lockPath}`
    );
    this.name = "AuditLockContentionError";
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
  private readonly checkpointSigner?: (
    payload: AuditCheckpointSigningPayload
  ) => Promise<AuditCheckpointSignature | null>;
  private readonly checkpointPublicKeyResolver?: (
    signerKid: string
  ) => string | Uint8Array | undefined;
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
    this.checkpointSigner = config?.checkpointSigner;
    this.checkpointPublicKeyResolver = config?.checkpointPublicKeyResolver;
    this.integrityAnomalySubscribers = config?.integrityAnomalySubscribers ?? [];
    this.eagerReverifyIntervalMs = resolveEagerReverifyIntervalMs(
      config?.eagerReverifyIntervalMs
    );
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
    this.pendingWrites.add(writePromise);
    void writePromise.then(
      () => this.pendingWrites.delete(writePromise),
      () => this.pendingWrites.delete(writePromise)
    );
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
   * writes throw `AuditPersistenceError` with a classification.
   */
  async appendCritical(entry: AuditEntryInput): Promise<void> {
    await this.enqueueAppend(entry, { verifyDurability: true, critical: true });
  }

  async runAllowingIntegrityFindings<T>(fn: () => Promise<T>): Promise<T> {
    return auditIntegrityContext.run({ allowIntegrityFindings: true }, fn);
  }

  async getIntegrityFindings(): Promise<AuditIntegrityFinding[]> {
    await this.appendQueue;
    await this.ensureLoaded({ allowIntegrityFindings: true });
    return [...this.integrityFindings];
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
      const serialized = stringToBytes(JSON.stringify(normalized));
      const encrypted = encrypt(serialized, this.encryptionKey);
      const encryptedBytes = stringToBytes(JSON.stringify(encrypted));
      const encryptedPayloadBytes = toBase64url(encryptedBytes);
      await this.withAuditWriteLock(async () => {
        await this.ensureLoaded();
        await this.freshenChainStateFromDisk();
        const sequence = this.nextSequence;
        const prevHash = this.lastEntryHash;
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
        const key = `entry-${String(sequence).padStart(20, "0")}-${Date.now()}-${this.counter++}`;
        const persistedBytes = stringToBytes(JSON.stringify(envelope));
        try {
          await this.writeAuditEntryBytes(key, persistedBytes);

          if (options.verifyDurability) {
            await this.verifyPersistedBytes(key, persistedBytes);
          }
          await this.writeHeadAnchor(sequence, entryHash);
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
      // Cheap lock-free pre-check: only pay the cross-process lock cost when a
      // prune is actually due. storage.list() returns key-sorted entries.
      const preMetas = await this.storage.list(AUDIT_NAMESPACE);
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
      await this.withAuditWriteLock(async () => {
        // Re-list INSIDE the lock: another rotator may have pruned since the
        // pre-check, so recompute the cut against the authoritative state.
        const metas = await this.storage.list(AUDIT_NAMESPACE);
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
          const newBaseRaw = await this.storage.read(
            AUDIT_NAMESPACE,
            metas[toDelete]!.key
          );
          if (newBaseRaw) {
            const parsed = JSON.parse(bytesToString(newBaseRaw));
            if (isPersistedAuditEnvelopeV2(parsed)) {
              await this.writeRotationAnchor(parsed.sequence, parsed.prev_hash);
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
          await this.storage.delete(AUDIT_NAMESPACE, metas[i]!.key);
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
      // Bare / marker-stripped / legacy: untrusted, treated as no anchor so the
      // TOFU migration path re-establishes it from the surviving chain.
      return { status: "absent" };
    }

    const data = parsed.data;
    const mac = parsed.mac;
    if (
      !isRecord(data) ||
      typeof mac !== "string" ||
      typeof data.base_sequence !== "number" ||
      !Number.isSafeInteger(data.base_sequence) ||
      data.base_sequence <= 0 ||
      typeof data.base_prev_hash !== "string"
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
      "_meta",
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

  private async loadHeadAnchor(
    findings: AuditIntegrityFinding[]
  ): Promise<
    | { status: "valid"; highest_sequence: number; head_hash: string }
    | { status: "absent" }
    | { status: "invalid" }
  > {
    let raw: Uint8Array | null;
    try {
      raw = await this.storage.read(
        AUDIT_CHECKPOINT_NAMESPACE,
        AUDIT_HEAD_ANCHOR_KEY
      );
    } catch (err) {
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

  private async verifyHeadAnchor(
    highestChainedSeq: number,
    highestChainedHash: string,
    hasLegacyEntries: boolean,
    hasChainedEntries: boolean,
    findings: AuditIntegrityFinding[]
  ): Promise<void> {
    const anchor = await this.loadHeadAnchor(findings);
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

  private async isEstablishedAuditStore(hasAuditEntries: boolean): Promise<boolean> {
    if (hasAuditEntries) return true;
    if (
      await this.storage
        .exists("_meta", AUDIT_HEAD_ANCHOR_ESTABLISHED_KEY)
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
   *     invalid / mismatched → finding (fail closed), except the TOFU case below.
   *   - no chained entries → if an anchor still exists, the whole post-cut chain
   *     was truncated → finding.
   *
   * Trust-on-first-use migration: a pre-F3 log that rotated before this change
   * has lowest > legacyCount+1 and NO anchor. If its surviving chain is internally
   * contiguous, accept it once and write the authenticated anchor; thereafter it
   * is MAC-protected. A non-contiguous (genuinely truncated) chain still flags via
   * the forward walk. This mirrors F1's one-time self-heal residual.
   */
  private async resolveChainSeed(
    chainedEntries: Array<{
      key: string;
      envelope: PersistedAuditEnvelopeV2;
    }>,
    legacyCount: number,
    legacyAnchorHash: string,
    findings: AuditIntegrityFinding[]
  ): Promise<{ expectedSequence: number; expectedPrevHash: string }> {
    const defaultSeedSequence = legacyCount + 1;
    const defaultSeedPrevHash =
      legacyCount > 0 ? legacyAnchorHash : AUDIT_CHAIN_GENESIS;
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

    // anchor.status === "absent": pre-F3 already-rotated log OR truncation.
    if (this.isChainInternallyContiguous(chainedEntries)) {
      // TOFU: accept the current surviving chain once and authenticate it.
      //
      // RESIDUAL (documented, not closed here — F3 design ratified 2026-06-06,
      // consistent with F1 #394): a filesystem-level adversary who deletes BOTH
      // this anchor file AND the current lowest-surviving (head) entry leaves a
      // still-contiguous suffix that is indistinguishable from a legitimate
      // pre-F3 rotation, so this branch re-accepts it and re-anchors at the new
      // head — a head truncation hidden as migration. This is the same class as
      // F1's "delete the MAC'd floor file + one more op" replay residual, and the
      // filesystem-adversary threat model is explicitly not fully specified
      // (see CLAUDE.md "Known Complexity" #6). Closing it requires a floor that
      // does not live in a single deletable file (boot-anchored / externally
      // attested), which is out of scope for F3.
      await this.writeRotationAnchor(lowestChainedSeq, head.prev_hash);
      return {
        expectedSequence: lowestChainedSeq,
        expectedPrevHash: head.prev_hash,
      };
    }
    // Non-contiguous: a genuine internal truncation. Flag it; the forward walk
    // also localizes the exact break.
    findings.push({
      kind: "rotation_anchor_missing",
      sequence: lowestChainedSeq,
      message: `audit chain starts at sequence ${lowestChainedSeq} (above ${defaultSeedSequence}) with no rotation anchor and is not internally contiguous (entries may have been truncated)`,
    });
    return {
      expectedSequence: lowestChainedSeq,
      expectedPrevHash: head.prev_hash,
    };
  }

  /**
   * True iff the chained entries form an unbroken run: each sequence is exactly
   * one above its predecessor and each prev_hash equals the predecessor's
   * entry_hash. Used to decide whether an anchor-less rotated log is a legitimate
   * pre-F3 prune (TOFU-acceptable) versus a truncated chain.
   */
  private isChainInternallyContiguous(
    chainedEntries: Array<{ envelope: PersistedAuditEnvelopeV2 }>
  ): boolean {
    for (let i = 1; i < chainedEntries.length; i++) {
      const prev = chainedEntries[i - 1]!.envelope;
      const curr = chainedEntries[i]!.envelope;
      if (curr.sequence !== prev.sequence + 1) return false;
      if (curr.prev_hash !== prev.entry_hash) return false;
    }
    return true;
  }

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
      if (Date.now() >= deadline) {
        return; // bounded backstop; surfaced in strict mode by the caller
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
      // to establish the listing baseline. The wall-clock deadline above bounds an
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

  private async withAuditWriteLock<T>(operation: () => Promise<T>): Promise<T> {
    if (!this.auditWriteLockPath) return operation();

    await mkdir(this.filesystemCapabilities!.namespacePath(AUDIT_NAMESPACE), {
      recursive: true,
      mode: 0o700,
    });
    const started = Date.now();
    let acquired = false;
    while (!acquired) {
      try {
        const handle = await open(this.auditWriteLockPath, "wx", 0o600);
        try {
          await handle.writeFile(
            JSON.stringify({
              pid: process.pid,
              acquired_at: new Date().toISOString(),
            })
          );
          await handle.sync();
        } finally {
          await handle.close();
        }
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
      return await operation();
    } finally {
      await rm(this.auditWriteLockPath, { force: true });
    }
  }

  /**
   * Break the audit-write lock iff it is PROVABLY stale, returning true when a
   * stale lock was removed. Staleness is proven two ways, both robust:
   *
   *   - The lock's `acquired_at` predates the current system boot. A lock that
   *     survived a reboot is definitionally orphaned, and this is immune to PID
   *     reuse (the recorded PID may now belong to an unrelated process).
   *   - The recorded holder PID is not alive. Covers a same-boot crash / kill
   *     before the PID has been reused.
   *
   * A lock held by a live process acquired during this boot is left untouched
   * (legitimate contention). An unreadable / corrupt / pid-less lock cannot be
   * proven stale, so it is also left untouched (fail-safe: never break a lock we
   * cannot prove is dead). Fixes the daemon-cannot-restart-after-reboot defect
   * surfaced by the A1 acceptance drill (2026-06-04, reboot 2).
   */
  private async breakStaleAuditLock(lockPath: string): Promise<boolean> {
    let holderPid: number | undefined;
    let acquiredAtMs: number | undefined;
    try {
      const raw = await readFile(lockPath, "utf8");
      const parsed = JSON.parse(raw) as { pid?: unknown; acquired_at?: unknown };
      if (typeof parsed.pid === "number" && Number.isInteger(parsed.pid)) {
        holderPid = parsed.pid;
      }
      if (typeof parsed.acquired_at === "string") {
        const t = Date.parse(parsed.acquired_at);
        if (!Number.isNaN(t)) acquiredAtMs = t;
      }
    } catch (err) {
      const code =
        err instanceof Error && "code" in err
          ? String((err as NodeJS.ErrnoException).code)
          : "";
      // Vanished between open() and read(): another writer released it; retry.
      if (code === "ENOENT") return true;
      // Unreadable / corrupt content: cannot prove staleness — do not break.
      return false;
    }

    if (holderPid === process.pid) return false;

    const bootTimeMs = currentBootTimeMs();
    const predatesBoot =
      acquiredAtMs !== undefined &&
      bootTimeMs !== undefined &&
      acquiredAtMs < bootTimeMs;
    const holderDead = holderPid !== undefined && !isProcessAlive(holderPid);
    if (!predatesBoot && !holderDead) return false;

    // Best-effort removal; ignore a race where another writer already cleared it.
    await rm(lockPath, { force: true });
    return true;
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

  private async readLatestPersistedChainState(): Promise<{
    nextSequence: number;
    lastEntryHash: string;
  } | null> {
    const metas = await this.storage.list(AUDIT_NAMESPACE, "entry-");
    let latest: PersistedAuditEnvelopeV2 | null = null;
    for (const meta of metas) {
      const raw = await this.storage.read(AUDIT_NAMESPACE, meta.key);
      if (!raw) continue;
      try {
        const parsed = JSON.parse(bytesToString(raw));
        if (!isPersistedAuditEnvelopeV2(parsed)) continue;
        if (
          latest === null ||
          parsed.sequence > latest.sequence ||
          (parsed.sequence === latest.sequence &&
            parsed.timestamp.localeCompare(latest.timestamp) > 0)
        ) {
          latest = parsed;
        }
      } catch {
        // Full integrity verification reports malformed entries separately.
      }
    }
    if (!latest) return null;
    return {
      nextSequence: latest.sequence + 1,
      lastEntryHash: latest.entry_hash,
    };
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
      const storedEntries = await this.storage.list(AUDIT_NAMESPACE);
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
        findings
      );

      // F3: derive the chain-walk seed, honoring an authenticated rotation cut
      // (async: it reads + MAC-verifies the rotation anchor and may TOFU-write).
      const chainSeed = await this.resolveChainSeed(
        chainedEntries,
        legacyRawEntries.length,
        legacyAnchorHash,
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
      const highestChainedSeq =
        chainedEntries.at(-1)?.envelope.sequence ?? legacyRawEntries.length;
      const highestChainedHash =
        chainedEntries.at(-1)?.envelope.entry_hash ?? legacyAnchorHash;
      await this.verifyHeadAnchor(
        highestChainedSeq,
        highestChainedHash,
        legacyRawEntries.length > 0,
        chainedEntries.length > 0,
        findings
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
    findings: AuditIntegrityFinding[]
  ): Promise<void> {
    if (legacyCount === 0) return;
    const existing = await this.readCheckpoints("legacy-anchor", findings);
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
    this.verifyCheckpointRecordSignature(anchor, findings);
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
    findings: AuditIntegrityFinding[]
  ): Promise<void> {
    const checkpoints = await this.readCheckpoints("audit-checkpoint", findings);
    const entryBySequence = new Map(entries.map((entry) => [entry.sequence, entry]));
    let highestCheckpoint = 0;

    // F3: the lowest surviving chained sequence. Entries below this floor (but
    // above the legacy region) were legitimately pruned by rotation. A checkpoint
    // written before that rotation still references those now-gone sequences; its
    // root cannot be re-derived from entries that no longer exist. (When legacy
    // entries survive, no chained rotation has occurred — legacy keys prune first
    // — so the floor is legacyCount+1 and nothing is skipped.)
    const rotationFloor = entries[0]?.sequence ?? legacyCount + 1;

    for (const checkpoint of checkpoints) {
      if (checkpoint.checkpoint_sequence > highestCheckpoint) {
        highestCheckpoint = checkpoint.checkpoint_sequence;
      }

      // A checkpoint whose range dips below the surviving floor spans
      // rotated-out entries. Skip the root re-derivation (it would always
      // mismatch — the leaves are gone), but still verify its signature below.
      // The CURRENT chain's integrity is anchored by the MAC'd rotation anchor +
      // the forward walk, not by these historical checkpoints, so skipping the
      // root recomputation here is not a fail-open for the protected property.
      const spansRotatedEntries =
        checkpoint.from_sequence > legacyCount &&
        checkpoint.from_sequence < rotationFloor;

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

      this.verifyCheckpointRecordSignature(checkpoint, findings);
    }

    this.lastCheckpointSequence = highestCheckpoint;
  }

  private verifyCheckpointRecordSignature(
    checkpoint: AuditCheckpointRecord,
    findings: AuditIntegrityFinding[]
  ): void {
    if (checkpoint.unsigned) return;
    if (!checkpoint.signer_kid || !checkpoint.signature) {
      findings.push({
        kind: "checkpoint_signature_mismatch",
        sequence: checkpoint.checkpoint_sequence,
        message: `checkpoint ${checkpoint.checkpoint_sequence} is marked signed but lacks signer data`,
      });
      return;
    }

    const publicKey =
      this.checkpointPublicKeyResolver?.(checkpoint.signer_kid) ??
      checkpoint.public_key;
    if (!publicKey) {
      findings.push({
        kind: "checkpoint_signature_unverifiable",
        sequence: checkpoint.checkpoint_sequence,
        message: `checkpoint signer ${checkpoint.signer_kid} has no known public key`,
      });
      return;
    }

    const valid = verifyCheckpointSignature(
      checkpointPayload(checkpoint),
      checkpoint.signature,
      publicKey
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
    findings: AuditIntegrityFinding[]
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
      const raw = await this.storage.read(AUDIT_CHECKPOINT_NAMESPACE, meta.key);
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
      await this.withAuditWriteLock(async () => {
        await this.freshenChainStateFromDisk();
        const previousCheckpointSequence =
          await this.readHighestAuditCheckpointSequence();
        const checkpointSequence = this.nextSequence - 1;
        const fromSequence = previousCheckpointSequence + 1;
        const hashes = await this.collectPersistedEntryHashes(
          fromSequence,
          checkpointSequence
        );
        if (hashes.length === 0) return;
        await this.writeCheckpointRecord({
          checkpoint_kind: "audit-checkpoint",
          checkpoint_sequence: checkpointSequence,
          from_sequence: fromSequence,
          root_hash: computeAuditRoot(hashes),
          previous_checkpoint_sequence: previousCheckpointSequence,
          signed_at: new Date().toISOString(),
        });
        this.lastCheckpointSequence = checkpointSequence;
        this.hashesSinceCheckpoint = [];
        this.criticalAppendsSinceCheckpoint = 0;
      });
    } finally {
      this.checkpointInFlight = false;
    }
  }

  private async readHighestAuditCheckpointSequence(): Promise<number> {
    const metas = await this.storage.list(
      AUDIT_CHECKPOINT_NAMESPACE,
      "audit-checkpoint-"
    );
    let highest = 0;
    for (const meta of metas) {
      const raw = await this.storage.read(AUDIT_CHECKPOINT_NAMESPACE, meta.key);
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
    toSequence: number
  ): Promise<string[]> {
    const metas = await this.storage.list(AUDIT_NAMESPACE, "entry-");
    const bySequence = new Map<number, string>();
    for (const meta of metas) {
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
      signed = (await this.checkpointSigner?.(payload)) ?? null;
    } catch {
      signed = null;
    }

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
    // lock is not proven stale by boot time; PID liveness can still prove it.
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

function isAuditCheckpointRecord(value: unknown): value is AuditCheckpointRecord {
  return (
    isRecord(value) &&
    value.schema_version === AUDIT_CHECKPOINT_SCHEMA_VERSION &&
    (value.checkpoint_kind === "audit-checkpoint" ||
      value.checkpoint_kind === "legacy-anchor") &&
    typeof value.checkpoint_sequence === "number" &&
    Number.isSafeInteger(value.checkpoint_sequence) &&
    typeof value.from_sequence === "number" &&
    Number.isSafeInteger(value.from_sequence) &&
    typeof value.root_hash === "string" &&
    /^[0-9a-f]{64}$/.test(value.root_hash) &&
    typeof value.previous_checkpoint_sequence === "number" &&
    Number.isSafeInteger(value.previous_checkpoint_sequence) &&
    typeof value.signed_at === "string" &&
    (typeof value.signer_kid === "string" || value.signer_kid === null) &&
    (typeof value.signature === "string" || value.signature === null) &&
    (value.signature_algorithm === "Ed25519" ||
      value.signature_algorithm === null) &&
    value.payload_encoding === "domain-separated-canonical-json-v1" &&
    typeof value.unsigned === "boolean"
  );
}

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
