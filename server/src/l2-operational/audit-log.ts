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

export interface AuditEntry {
  timestamp: string;
  layer: "l1" | "l2" | "l3" | "l4";
  operation: string;
  identity_id: string;
  result: "success" | "failure";
  details?: Record<string, unknown>;
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

const auditIntegrityContext = new AsyncLocalStorage<{
  allowIntegrityFindings: boolean;
}>();

export class AuditLog {
  private storage: StorageBackend;
  private encryptionKey: Uint8Array;
  private rotationAnchorMacKey: Uint8Array;
  private headAnchorMacKey: Uint8Array;
  private entries: AuditEntry[] = [];
  private chainEntries: Array<{ sequence: number; entry_hash: string }> = [];
  private counter = 0;
  private readonly maxTotalSizeBytes: number;
  private readonly maxEntries: number;
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

  constructor(storage: StorageBackend, masterKey: Uint8Array, config?: AuditLogConfig) {
    this.storage = storage;
    this.encryptionKey = derivePurposeKey(masterKey, "audit-log");
    // F3: derive the rotation-anchor MAC key up front and never retain the raw
    // master key (mirrors how encryptionKey is derived here, per F1's pattern).
    this.rotationAnchorMacKey = derivePurposeKey(masterKey, "audit-rotation-anchor");
    this.headAnchorMacKey = derivePurposeKey(masterKey, "audit-head-anchor");
    this.maxTotalSizeBytes = config?.maxTotalSizeBytes ?? DEFAULT_MAX_TOTAL_SIZE_BYTES;
    this.maxEntries = config?.maxEntries ?? DEFAULT_MAX_ENTRIES;
    this.integrityMode = config?.integrityMode ?? "strict";
    this.checkpointInterval =
      config?.checkpointInterval ?? DEFAULT_CHECKPOINT_INTERVAL;
    this.checkpointSigner = config?.checkpointSigner;
    this.checkpointPublicKeyResolver = config?.checkpointPublicKeyResolver;
    this.integrityAnomalySubscribers = config?.integrityAnomalySubscribers ?? [];
    this.filesystemCapabilities = asFilesystemCapabilities(storage);
    if (this.filesystemCapabilities) {
      this.auditWriteLockPath = join(
        this.filesystemCapabilities.namespacePath(AUDIT_NAMESPACE),
        AUDIT_WRITE_LOCK_FILE
      );
      // SAFETY: one-time startup announcement of the audit-write coordination
      // mechanism. Operators need to see this so they can locate the lock file
      // and inspect lsof on it if writes appear stuck. Goes to stderr-equivalent
      // console.info, which is operator-facing diagnostic surface, not telemetry.
      console.info(
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
    } finally {
      if (!options.critical && this.pendingVisibleEntries > 0) {
        this.pendingVisibleEntries--;
      }
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
      entry: AuditEntry;
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
  async verifiedChainView(): Promise<
    Array<{ sequence: number; entry_hash: string; entry: AuditEntry }>
  > {
    await this.appendQueue;
    await this.reloadPersistedEntries();
    // this.entries is [legacy..., chained...] in order; the chained suffix
    // aligns 1:1 with this.chainEntries (both built from the same load pass).
    const chainedEntries = this.entries.slice(
      this.entries.length - this.chainEntries.length
    );
    return this.chainEntries.map((chained, index) => ({
      sequence: chained.sequence,
      entry_hash: chained.entry_hash,
      entry: chainedEntries[index]!,
    }));
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
   */
  async query(options: {
    since?: string;
    layer?: AuditEntry["layer"];
    operation_type?: string;
    limit?: number;
  }): Promise<{
    entries: AuditEntry[];
    total: number;
    integrity_findings: AuditIntegrityFinding[];
  }> {
    await this.appendQueue;
    // Re-scan so read-class operations fail loud as soon as corruption appears.
    // Reads do NOT take the cross-process write lock: stale reads are tolerable,
    // and acquiring the write lock here would create the audit namespace dir as
    // a side effect for fortresses that have never written, breaking
    // non-recursive cleanup in tests that only construct an AuditLog.
    await this.reloadPersistedEntries();

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

    const total = filtered.length;
    const limit = options.limit ?? 50;
    const entries = filtered.slice(-limit); // Most recent entries

    return { entries, total, integrity_findings: [...this.integrityFindings] };
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

  private async reloadPersistedEntries(): Promise<void> {
    await this.loadPersistedEntriesWithReadConsistency();
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

  private async loadPersistedEntriesWithReadConsistency(): Promise<void> {
    const deadline = Date.now() + AUDIT_READ_CONSISTENCY_MAX_MS;
    let lastSignature: string | null = null;
    for (;;) {
      await this.loadPersistedEntries();
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

  private async loadPersistedEntries(): Promise<void> {
    const findings: AuditIntegrityFinding[] = [];
    const legacyRawEntries: Array<{ key: string; raw: Uint8Array; entry: AuditEntry }> = [];
    const chainedEntries: Array<{
      key: string;
      envelope: PersistedAuditEnvelopeV2;
      entry: AuditEntry;
    }> = [];

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

          try {
            const encryptedBytes = fromBase64url(parsed.encrypted_payload_bytes);
            const encrypted: EncryptedPayload = JSON.parse(bytesToString(encryptedBytes));
            const decrypted = decrypt(encrypted, this.encryptionKey);
            const entry: AuditEntry = JSON.parse(bytesToString(decrypted));
            chainedEntries.push({ key: meta.key, envelope: parsed, entry });
          } catch {
            findings.push({
              kind: "entry_decrypt_failed",
              key: meta.key,
              sequence: parsed.sequence,
              message: `audit entry ${meta.key} could not be decrypted at sequence ${parsed.sequence}`,
            });
          }
          continue;
        }

        try {
          const encrypted = parsed as EncryptedPayload;
          const decrypted = decrypt(encrypted, this.encryptionKey);
          const entry: AuditEntry = JSON.parse(bytesToString(decrypted));
          legacyRawEntries.push({ key: meta.key, raw, entry });
        } catch {
          findings.push({
            kind: "entry_decrypt_failed",
            key: meta.key,
            message: `legacy audit entry ${meta.key} could not be decrypted`,
          });
        }
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

      this.entries = [
        ...legacyRawEntries.map((item) => item.entry),
        ...chainedEntries.map((item) => item.entry),
      ];
      this.chainEntries = chainedEntries.map((item) => ({
        sequence: item.envelope.sequence,
        entry_hash: item.envelope.entry_hash,
      }));
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
    } catch (err) {
      findings.push({
        kind: "storage_unavailable",
        message: `audit storage could not be listed: ${failureMessage(err)}`,
      });
      this.integrityFindings = findings;
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
      entry: AuditEntry;
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
    let signed: AuditCheckpointSignature | null = null;
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
