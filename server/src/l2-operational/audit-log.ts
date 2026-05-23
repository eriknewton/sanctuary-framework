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

import { mkdir, open, rm } from "node:fs/promises";
import { join } from "node:path";
import type {
  FilesystemStorageCapabilities,
  StorageBackend,
} from "../storage/interface.js";
import { encrypt, decrypt, type EncryptedPayload } from "../core/encryption.js";
import { derivePurposeKey } from "../core/key-derivation.js";
import { stringToBytes, bytesToString, toBase64url, fromBase64url } from "../core/encoding.js";
import {
  AUDIT_CHAIN_GENESIS,
  AUDIT_CHAIN_SCHEMA_VERSION,
  AUDIT_CHECKPOINT_SCHEMA_VERSION,
  type AuditCheckpointRecord,
  type AuditCheckpointSignature,
  type AuditCheckpointSigningPayload,
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
const AUDIT_INTEGRITY_ALERT_NAMESPACE = "_audit_integrity_alert";
const AUDIT_INTEGRITY_ALERT_KEY = "audit-integrity-alert.log";
const AUDIT_WRITE_LOCK_FILE = ".audit-write.lock";
const AUDIT_WRITE_LOCK_TIMEOUT_MS = 5_000;
const AUDIT_WRITE_LOCK_RETRY_MS = 100;

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

export class AuditLog {
  private storage: StorageBackend;
  private encryptionKey: Uint8Array;
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

  /**
   * Prune oldest audit entries when storage exceeds configured limits.
   * Entries are sorted by key (timestamp-based) so oldest are pruned first.
   */
  private async maybeRotate(): Promise<void> {
    if (this.rotationInFlight) return;
    this.rotationInFlight = true;
    try {
      const metas = await this.storage.list(AUDIT_NAMESPACE);
      if (metas.length === 0) return;

      // Sort by key ascending (oldest first — keys are timestamp-prefixed)
      metas.sort((a, b) => a.key.localeCompare(b.key));

      const totalSize = metas.reduce((sum, m) => sum + m.size_bytes, 0);
      let toDelete = 0;

      // Check entry count limit
      if (metas.length > this.maxEntries) {
        toDelete = metas.length - this.maxEntries;
      }

      // Check total size limit — prune until under budget
      if (totalSize > this.maxTotalSizeBytes) {
        let runningSize = totalSize;
        for (let i = toDelete; i < metas.length && runningSize > this.maxTotalSizeBytes; i++) {
          runningSize -= metas[i]!.size_bytes;
          toDelete = i + 1;
        }
      }

      // Delete oldest entries
      for (let i = 0; i < toDelete; i++) {
        await this.storage.delete(AUDIT_NAMESPACE, metas[i]!.key);
      }
    } finally {
      this.rotationInFlight = false;
    }
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

  private async ensureLoaded(): Promise<void> {
    if (this.loaded) return;
    await this.loadPersistedEntries();
    this.loaded = true;
    await this.reportIntegrityFindingsIfAny();
    if (this.integrityMode === "strict" && this.integrityFindings.length > 0) {
      throw new AuditIntegrityError(this.integrityFindings);
    }
  }

  private async reloadPersistedEntries(): Promise<void> {
    await this.loadPersistedEntries();
    this.loaded = true;
    await this.reportIntegrityFindingsIfAny();
    if (this.integrityMode === "strict" && this.integrityFindings.length > 0) {
      throw new AuditIntegrityError(this.integrityFindings);
    }
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

      this.verifyChainedEntries(
        chainedEntries,
        legacyRawEntries.length,
        legacyAnchorHash,
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
      this.nextSequence = legacyRawEntries.length + chainedEntries.length + 1;
      this.lastEntryHash =
        chainedEntries.at(-1)?.envelope.entry_hash ?? legacyAnchorHash;
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
    legacyCount: number,
    legacyAnchorHash: string,
    findings: AuditIntegrityFinding[]
  ): void {
    let expectedSequence = legacyCount + 1;
    let expectedPrevHash =
      legacyCount > 0 ? legacyAnchorHash : AUDIT_CHAIN_GENESIS;

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

    for (const checkpoint of checkpoints) {
      if (checkpoint.checkpoint_sequence > highestCheckpoint) {
        highestCheckpoint = checkpoint.checkpoint_sequence;
      }

      const hashes: string[] = [];
      for (
        let sequence = checkpoint.from_sequence;
        sequence <= checkpoint.checkpoint_sequence;
        sequence++
      ) {
        if (sequence <= legacyCount) {
          if (checkpoint.from_sequence === 1 && checkpoint.checkpoint_sequence === legacyCount) {
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

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
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
