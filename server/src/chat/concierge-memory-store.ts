/**
 * Sanctuary MCP Server — Concierge Memory Store (WP-V1.3-9 Tau-1)
 *
 * Per-fortress, encrypted-at-rest, cocoon-bound persistence for
 * concierge conversation turns. Distinct from the v1.2 OperatorChatStore
 * (single fortress-scoped thread, capped FIFO, no retention) — this
 * store is the foundation for v1.3 conversational sovereignty depth:
 * multi-thread enumeration, per-turn retention, scrollable history.
 *
 * Storage layout:
 *   namespace: `_chat`                       (existing reserved L1 namespace)
 *   key:       `concierge_memory.{thread_id}` (one record per thread)
 *   payload:   AES-256-GCM ciphertext of the JSON-serialised turns bundle.
 *   key:       `concierge-memory-store-v1` HKDF subkey of fortress master.
 *   AAD:       UTF-8 bytes of `thread_id` — swapping records across
 *              threads breaks the auth tag. Castle-walking discipline:
 *              the encryption boundary holds even against on-disk shuffle.
 *
 * Concurrency:
 * Per-thread async lock serializes appendTurn calls within the same
 * store instance. Cross-process locking is out of scope (single-process
 * Sanctuary server).
 *
 * Retention:
 * Each turn carries an ISO-8601 `retention_until`. `pruneExpired()`
 * iterates threads and drops turns whose retention_until is in the
 * past. Empty bundles are deleted entirely. Caller wires this into
 * the cocoon-unlock initialization path (the wiring layer fires it
 * once the store is constructed).
 *
 * Multi-fortress isolation:
 * The HKDF subkey is derived from the fortress master key. Two
 * fortresses never produce identical encryption keys for identical
 * thread_ids. The `fortress_id` field on each turn is metadata for
 * audit clarity; isolation is enforced cryptographically.
 */

import type { StorageBackend } from "../storage/interface.js";
import {
  encrypt,
  decrypt,
  type EncryptedPayload,
} from "../core/encryption.js";
import { derivePurposeKey } from "../core/key-derivation.js";
import { stringToBytes, bytesToString } from "../core/encoding.js";

export const CONCIERGE_MEMORY_NAMESPACE = "_chat";
export const CONCIERGE_MEMORY_KEY_PREFIX = "concierge_memory.";
const HKDF_INFO = "concierge-memory-store-v1";

/** Default retention window when the operator has not tuned a custom value. */
export const DEFAULT_CONCIERGE_RETENTION_DAYS = 30;

/** Hard upper bound on per-bundle decode size to keep degenerate threads
 * from monopolising the read path. Single concierge bundle past 4 MiB
 * means the operator should rotate the thread, not crash the server. */
const MAX_BUNDLE_BYTES = 4 * 1024 * 1024;

/** One turn in a concierge thread. */
export interface ConciergeTurn {
  /** UUID of the thread this turn belongs to. */
  thread_id: string;
  /** Stable fortress id (audit metadata; isolation is keyed). */
  fortress_id: string;
  /** Monotonic turn number within thread, starting at 1. */
  turn_id: number;
  /** Sender role. */
  role: "user" | "assistant";
  /** Cleartext at runtime; AES-256-GCM at rest. */
  content: string;
  /** ISO-8601 timestamp of turn creation. */
  created_at: string;
  /** ISO-8601 timestamp after which prune drops this turn. */
  retention_until: string;
}

/** Operator-facing summary surfaced by `listThreads`. */
export interface ConciergeThreadSummary {
  thread_id: string;
  created_at: string;
  last_turn_at: string;
  turn_count: number;
}

/** Persisted bundle. Read-modify-write per appendTurn. */
interface ConciergeThreadBundle {
  /** Forward-compat field; bump on schema change. */
  version: 1;
  thread_id: string;
  fortress_id: string;
  created_at: string;
  turns: ConciergeTurn[];
}

export interface ConciergeMemoryStoreOptions {
  /** Storage backend that persists the encrypted bundles. */
  storage: StorageBackend;
  /** 32-byte fortress master key. */
  masterKey: Uint8Array;
  /** Stable fortress id stamped on every turn for audit clarity. */
  fortressId: string;
  /** Operator-tunable retention window. Default 30 days. */
  retentionDays?: number;
}

export interface ReadThreadOptions {
  /** Return only turns with turn_id strictly greater than this. */
  sinceTurnId?: number;
  /** Cap the number of turns returned (oldest-first within the bundle). */
  limit?: number;
}

/**
 * Stable failure-reason enum for `readThreadStrict` (WP-V1.3-9 Tau-2).
 * Mirrors the shape carried by `operator_concierge_memory_read_failed`
 * audit payloads so the service emits the cause verbatim.
 */
export type ConciergeMemoryReadFailure =
  | "decrypt_failed"
  | "schema_mismatch"
  | "oversize_bundle"
  | "io_failed"
  | "unknown";

/**
 * Discriminated result for `readThreadStrict`. The fold-read path uses
 * this so an empty thread (no bundle) does not look the same as a
 * corrupted bundle (which must trigger graceful degradation).
 */
export type ReadThreadStrictResult =
  | { ok: true; turns: ConciergeTurn[] }
  | { ok: false; reason: ConciergeMemoryReadFailure };

export interface ListThreadsOptions {
  /** Cap the number of summaries returned. */
  limit?: number;
}

/**
 * Encrypted, AAD-bound, retention-aware concierge memory persistence.
 */
export class ConciergeMemoryStore {
  private storage: StorageBackend;
  private encryptionKey: Uint8Array;
  private fortressId: string;
  private retentionDays: number;
  private locks: Map<string, Promise<void>>;

  constructor(opts: ConciergeMemoryStoreOptions) {
    this.storage = opts.storage;
    this.encryptionKey = derivePurposeKey(opts.masterKey, HKDF_INFO);
    this.fortressId = opts.fortressId;
    this.retentionDays =
      opts.retentionDays !== undefined && opts.retentionDays > 0
        ? opts.retentionDays
        : DEFAULT_CONCIERGE_RETENTION_DAYS;
    this.locks = new Map();
  }

  /**
   * Append a turn to the named thread, creating the bundle if no record
   * exists. Returns the persisted turn (with assigned turn_id +
   * retention_until). Per-thread serialisation guarantees turn_id
   * monotonicity even under concurrent callers.
   */
  async appendTurn(
    threadId: string,
    role: "user" | "assistant",
    content: string,
  ): Promise<ConciergeTurn> {
    return this.withLock(threadId, async () => {
      const bundle = (await this.loadBundle(threadId)) ?? null;
      const now = new Date();
      const retentionMs = this.retentionDays * 24 * 60 * 60 * 1000;
      const retentionUntil = new Date(now.getTime() + retentionMs);
      const nextTurnId = bundle ? lastTurnId(bundle) + 1 : 1;

      const turn: ConciergeTurn = {
        thread_id: threadId,
        fortress_id: this.fortressId,
        turn_id: nextTurnId,
        role,
        content,
        created_at: now.toISOString(),
        retention_until: retentionUntil.toISOString(),
      };

      const next: ConciergeThreadBundle = bundle
        ? { ...bundle, turns: [...bundle.turns, turn] }
        : {
            version: 1,
            thread_id: threadId,
            fortress_id: this.fortressId,
            created_at: now.toISOString(),
            turns: [turn],
          };

      await this.saveBundle(next);
      return turn;
    });
  }

  /**
   * Read turns from a thread, oldest-first. Returns an empty array if
   * the thread does not exist or its bundle is corrupt. Does not emit
   * audit events; the caller (HTTP route handler) owns audit semantics.
   */
  async readThread(
    threadId: string,
    opts?: ReadThreadOptions,
  ): Promise<ConciergeTurn[]> {
    const bundle = await this.loadBundle(threadId);
    if (!bundle) return [];

    let turns = bundle.turns;
    if (opts?.sinceTurnId !== undefined) {
      const cutoff = opts.sinceTurnId;
      turns = turns.filter((t) => t.turn_id > cutoff);
    }
    if (opts?.limit !== undefined) {
      turns = turns.slice(0, opts.limit);
    }
    return turns;
  }

  /**
   * Read turns with explicit failure surfacing (WP-V1.3-9 Tau-2). Where
   * `readThread` collapses every failure mode to an empty array, this
   * variant returns a discriminated result so the multi-turn fold path
   * can degrade cleanly + emit `operator_concierge_memory_read_failed`
   * with a concrete cause.
   *
   * - No bundle on disk → `{ ok: true, turns: [] }` (a fresh thread).
   * - Bundle present, decode + decrypt + schema check pass → ok with turns.
   * - Bundle present, oversize → `{ ok: false, reason: "oversize_bundle" }`.
   * - Bundle present, decryption fails → `{ ok: false, reason: "decrypt_failed" }`.
   * - Bundle present, schema mismatch (version / thread_id) → `schema_mismatch`.
   * - Storage IO error → `io_failed`.
   */
  async readThreadStrict(
    threadId: string,
    opts?: ReadThreadOptions,
  ): Promise<ReadThreadStrictResult> {
    const key = bundleKey(threadId);
    let raw: Uint8Array | null;
    try {
      raw = await this.storage.read(CONCIERGE_MEMORY_NAMESPACE, key);
    } catch {
      return { ok: false, reason: "io_failed" };
    }
    if (!raw) return { ok: true, turns: [] };
    if (raw.length > MAX_BUNDLE_BYTES) {
      return { ok: false, reason: "oversize_bundle" };
    }

    let envelope: EncryptedPayload;
    try {
      envelope = JSON.parse(bytesToString(raw));
    } catch {
      return { ok: false, reason: "schema_mismatch" };
    }

    let plaintext: Uint8Array;
    try {
      const aad = stringToBytes(threadId);
      plaintext = decrypt(envelope, this.encryptionKey, aad);
    } catch {
      return { ok: false, reason: "decrypt_failed" };
    }

    let parsed: ConciergeThreadBundle;
    try {
      parsed = JSON.parse(bytesToString(plaintext)) as ConciergeThreadBundle;
    } catch {
      return { ok: false, reason: "schema_mismatch" };
    }
    if (parsed.version !== 1) return { ok: false, reason: "schema_mismatch" };
    if (parsed.thread_id !== threadId) {
      return { ok: false, reason: "schema_mismatch" };
    }

    let turns = parsed.turns;
    if (opts?.sinceTurnId !== undefined) {
      const cutoff = opts.sinceTurnId;
      turns = turns.filter((t) => t.turn_id > cutoff);
    }
    if (opts?.limit !== undefined) {
      turns = turns.slice(0, opts.limit);
    }
    return { ok: true, turns };
  }

  /**
   * Enumerate concierge threads in this fortress with summary metadata.
   * Sorted newest-first by last_turn_at.
   */
  async listThreads(
    opts?: ListThreadsOptions,
  ): Promise<ConciergeThreadSummary[]> {
    const entries = await this.storage.list(
      CONCIERGE_MEMORY_NAMESPACE,
      CONCIERGE_MEMORY_KEY_PREFIX,
    );
    const summaries: ConciergeThreadSummary[] = [];
    for (const meta of entries) {
      const threadId = stripKeyPrefix(meta.key);
      if (threadId === null) continue;
      const bundle = await this.loadBundle(threadId);
      if (!bundle || bundle.turns.length === 0) continue;
      const last = bundle.turns[bundle.turns.length - 1];
      summaries.push({
        thread_id: bundle.thread_id,
        created_at: bundle.created_at,
        last_turn_at: last ? last.created_at : bundle.created_at,
        turn_count: bundle.turns.length,
      });
    }
    summaries.sort((a, b) =>
      a.last_turn_at < b.last_turn_at ? 1 : a.last_turn_at > b.last_turn_at ? -1 : 0,
    );
    if (opts?.limit !== undefined) {
      return summaries.slice(0, opts.limit);
    }
    return summaries;
  }

  /**
   * Delete a thread's bundle. Returns true if the bundle existed and
   * was removed; false if no bundle was present. Audit emission is the
   * caller's responsibility.
   */
  async deleteThread(threadId: string): Promise<boolean> {
    const key = bundleKey(threadId);
    return this.withLock(threadId, async () => {
      const existed = await this.storage.exists(
        CONCIERGE_MEMORY_NAMESPACE,
        key,
      );
      if (!existed) return false;
      try {
        await this.storage.delete(CONCIERGE_MEMORY_NAMESPACE, key);
      } catch {
        return false;
      }
      return true;
    });
  }

  /**
   * Drop expired turns across all threads. Threads emptied by pruning
   * are removed entirely. Returns the count of turns pruned.
   */
  async pruneExpired(now?: Date): Promise<{ pruned: number }> {
    const cutoff = (now ?? new Date()).toISOString();
    const entries = await this.storage.list(
      CONCIERGE_MEMORY_NAMESPACE,
      CONCIERGE_MEMORY_KEY_PREFIX,
    );
    let pruned = 0;
    for (const meta of entries) {
      const threadId = stripKeyPrefix(meta.key);
      if (threadId === null) continue;
      pruned += await this.withLock(threadId, async () => {
        const bundle = await this.loadBundle(threadId);
        if (!bundle) return 0;
        const kept = bundle.turns.filter((t) => t.retention_until > cutoff);
        const dropped = bundle.turns.length - kept.length;
        if (dropped === 0) return 0;
        if (kept.length === 0) {
          await this.storage.delete(
            CONCIERGE_MEMORY_NAMESPACE,
            bundleKey(threadId),
          );
        } else {
          await this.saveBundle({ ...bundle, turns: kept });
        }
        return dropped;
      });
    }
    return { pruned };
  }

  // ── internals ────────────────────────────────────────────────────────

  private async loadBundle(
    threadId: string,
  ): Promise<ConciergeThreadBundle | null> {
    const key = bundleKey(threadId);
    let raw: Uint8Array | null;
    try {
      raw = await this.storage.read(CONCIERGE_MEMORY_NAMESPACE, key);
    } catch {
      return null;
    }
    if (!raw) return null;
    if (raw.length > MAX_BUNDLE_BYTES) return null;

    try {
      const envelope: EncryptedPayload = JSON.parse(bytesToString(raw));
      const aad = stringToBytes(threadId);
      const plaintext = decrypt(envelope, this.encryptionKey, aad);
      const parsed = JSON.parse(
        bytesToString(plaintext),
      ) as ConciergeThreadBundle;
      if (parsed.version !== 1) return null;
      if (parsed.thread_id !== threadId) return null;
      return parsed;
    } catch {
      return null;
    }
  }

  private async saveBundle(bundle: ConciergeThreadBundle): Promise<void> {
    const key = bundleKey(bundle.thread_id);
    const aad = stringToBytes(bundle.thread_id);
    const plaintext = stringToBytes(JSON.stringify(bundle));
    const envelope = encrypt(plaintext, this.encryptionKey, aad);
    await this.storage.write(
      CONCIERGE_MEMORY_NAMESPACE,
      key,
      stringToBytes(JSON.stringify(envelope)),
    );
  }

  /**
   * Run `task` while holding the per-thread async lock. Lock is released
   * once the task settles (success or failure). Generic helper so
   * appendTurn / deleteThread / pruneExpired share serialisation.
   */
  private async withLock<T>(
    threadId: string,
    task: () => Promise<T>,
  ): Promise<T> {
    const previous = this.locks.get(threadId) ?? Promise.resolve();
    let release!: () => void;
    const next = new Promise<void>((resolve) => {
      release = resolve;
    });
    const chained = previous.then(() => next);
    this.locks.set(threadId, chained);
    try {
      await previous;
      return await task();
    } finally {
      release();
      if (this.locks.get(threadId) === chained) {
        this.locks.delete(threadId);
      }
    }
  }
}

function bundleKey(threadId: string): string {
  return `${CONCIERGE_MEMORY_KEY_PREFIX}${threadId}`;
}

function stripKeyPrefix(key: string): string | null {
  if (!key.startsWith(CONCIERGE_MEMORY_KEY_PREFIX)) return null;
  return key.slice(CONCIERGE_MEMORY_KEY_PREFIX.length);
}

function lastTurnId(bundle: ConciergeThreadBundle): number {
  let max = 0;
  for (const t of bundle.turns) {
    if (t.turn_id > max) max = t.turn_id;
  }
  return max;
}
