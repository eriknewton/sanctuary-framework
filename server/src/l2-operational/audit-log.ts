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

import type { StorageBackend } from "../storage/interface.js";
import { encrypt, decrypt, type EncryptedPayload } from "../core/encryption.js";
import { derivePurposeKey } from "../core/key-derivation.js";
import { stringToBytes, bytesToString } from "../core/encoding.js";

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

export interface AuditLogConfig {
  /** Maximum total size of stored audit entries in bytes. Default: 100 MB. */
  maxTotalSizeBytes?: number;
  /** Maximum number of stored audit entry files to retain. Default: 100_000. */
  maxEntries?: number;
}

const DEFAULT_MAX_TOTAL_SIZE_BYTES = 100 * 1024 * 1024; // 100 MB
const DEFAULT_MAX_ENTRIES = 100_000;

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

export class AuditLog {
  private storage: StorageBackend;
  private encryptionKey: Uint8Array;
  private entries: AuditEntry[] = [];
  private counter = 0;
  private readonly maxTotalSizeBytes: number;
  private readonly maxEntries: number;
  private rotationInFlight = false;
  private readonly pendingWrites = new Set<Promise<void>>();

  constructor(storage: StorageBackend, masterKey: Uint8Array, config?: AuditLogConfig) {
    this.storage = storage;
    this.encryptionKey = derivePurposeKey(masterKey, "audit-log");
    this.maxTotalSizeBytes = config?.maxTotalSizeBytes ?? DEFAULT_MAX_TOTAL_SIZE_BYTES;
    this.maxEntries = config?.maxEntries ?? DEFAULT_MAX_ENTRIES;
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
    const entry = this.normalizeEntry({
      layer,
      operation,
      identity_id: identityId,
      result,
      details,
    });

    this.entries.push(entry);

    const writePromise = this.persistEntry(entry, { verifyDurability: false });
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
    const normalized = this.normalizeEntry(entry);
    await this.persistEntry(normalized, { verifyDurability: true });
    this.entries.push(normalized);
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
  }

  private async persistEntry(
    entry: AuditEntry,
    options: { verifyDurability: boolean }
  ): Promise<void> {
    const key = `${Date.now()}-${this.counter++}`;
    const serialized = stringToBytes(JSON.stringify(entry));
    const encrypted = encrypt(serialized, this.encryptionKey);
    const encryptedBytes = stringToBytes(JSON.stringify(encrypted));
    try {
      await this.storage.write("_audit", key, encryptedBytes);

      if (options.verifyDurability) {
        await this.verifyPersistedBytes(key, encryptedBytes);
      }
    } catch (err) {
      throw toAuditPersistenceError(err);
    }

    // Rotation runs as part of the same tracked promise so flush() also
    // covers any prune-driven deletes.
    await this.maybeRotate().catch(() => {
      // Rotation failure is non-fatal
    });
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
      stored = await this.storage.read("_audit", key);
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
      const metas = await this.storage.list("_audit");
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
        await this.storage.delete("_audit", metas[i]!.key);
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
  }): Promise<{ entries: AuditEntry[]; total: number }> {
    // First, try to load persisted entries we don't have in memory
    await this.loadPersistedEntries();

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

    return { entries, total };
  }

  private async loadPersistedEntries(): Promise<void> {
    try {
      const storedEntries = await this.storage.list("_audit");
      for (const meta of storedEntries) {
        const raw = await this.storage.read("_audit", meta.key);
        if (!raw) continue;
        try {
          const encrypted: EncryptedPayload = JSON.parse(bytesToString(raw));
          const decrypted = decrypt(encrypted, this.encryptionKey);
          const entry: AuditEntry = JSON.parse(bytesToString(decrypted));

          // Deduplicate (check if we already have this timestamp+operation)
          const isDuplicate = this.entries.some(
            (e) =>
              e.timestamp === entry.timestamp &&
              e.operation === entry.operation &&
              e.identity_id === entry.identity_id
          );
          if (!isDuplicate) {
            this.entries.push(entry);
          }
        } catch {
          // Skip corrupted entries
        }
      }

      // Sort by timestamp
      this.entries.sort(
        (a, b) =>
          new Date(a.timestamp).getTime() - new Date(b.timestamp).getTime()
      );
    } catch {
      // Storage not available yet — that's fine
    }
  }

  /**
   * Get total number of entries.
   */
  get size(): number {
    return this.entries.length;
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
