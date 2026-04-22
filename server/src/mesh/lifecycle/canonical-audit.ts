/**
 * Canonical-audit buffer + designation.
 *
 * Per-node audit-buffer management: every node accumulates locally-produced
 * audit entries; every interval-or-size threshold (5s / 256 entries default
 * per §5.2), the buffer is sealed via `sealAuditBatch` and shipped to the
 * canonical audit node over a unicast direct stream.
 *
 * Canonical-audit-node designation: v0.1 default = first local-mode node
 * (per spec §5.2 + §13 outstanding-for-Erik). The canonical audit node also
 * keeps the authoritative audit log per emitter — `previousBatch` lookups
 * for verifyAuditBatch read from this store.
 *
 * Sovereign-TEE alternative: an operator running a regulated-industry pilot
 * may want to designate their sovereign-TEE node as canonical from
 * fortress-bootstrap (better tamper-evidence). v0.1 supports this by passing
 * `is_canonical_audit_node: true` in the orchestrator config; v1.x will
 * surface this as a console-driven choice. NOT implemented in this thread.
 */

import { sealAuditBatch } from "../audit-batch.js";
import { DEFAULTS } from "../constants.js";
import type { AuditBatch, AuditEntry } from "../types.js";
import type { CounterStore, FlushedBatch } from "./types.js";

export interface AuditBufferOptions {
  audit_batch_interval_ms?: number;
  audit_batch_max_entries?: number;
}

/**
 * Per-emitter local buffer. The emitting node holds entries here until a
 * flush condition triggers a seal. The `previous_batch` reference is held
 * by the buffer so that strict-+1 monotonicity is preserved across seals.
 */
export class AuditBuffer {
  private pending: AuditEntry[] = [];
  private previousBatch: AuditBatch | null = null;
  private readonly intervalMs: number;
  private readonly maxEntries: number;

  constructor(opts: AuditBufferOptions = {}) {
    this.intervalMs =
      opts.audit_batch_interval_ms ?? DEFAULTS.AUDIT_BATCH_INTERVAL_MS;
    this.maxEntries =
      opts.audit_batch_max_entries ?? DEFAULTS.AUDIT_BATCH_MAX_ENTRIES;
  }

  push(entry: AuditEntry): void {
    this.pending.push(entry);
  }

  size(): number {
    return this.pending.length;
  }

  /**
   * Decide whether the buffer should be flushed now based on size or age.
   * Time-based flush is driven by the orchestrator's tick — pass the time of
   * the OLDEST pending entry as `oldestEntryTimeMs`.
   */
  shouldFlush(nowMs: number, oldestEntryTimeMs: number | null): boolean {
    if (this.pending.length >= this.maxEntries) return true;
    if (this.pending.length > 0 && oldestEntryTimeMs !== null) {
      return nowMs - oldestEntryTimeMs >= this.intervalMs;
    }
    return false;
  }

  /**
   * Seal the pending entries into a batch and clear the buffer. Caller advances
   * the per-node audit_batch_seq counter in the supplied CounterStore.
   *
   * Returns null if there are no pending entries.
   */
  flush(params: {
    emitter_node: string;
    counters: CounterStore;
    node_audit_chain_key: Uint8Array;
    node_private_key: Uint8Array;
  }): { batch: AuditBatch; flushed: FlushedBatch } | null {
    if (this.pending.length === 0) return null;
    const batch_seq = params.counters.next("audit_batch_seq");
    const entries = this.pending;
    const batch = sealAuditBatch({
      emitter_node: params.emitter_node,
      batch_seq,
      entries,
      previous_batch: this.previousBatch,
      node_audit_chain_key: params.node_audit_chain_key,
      node_private_key: params.node_private_key,
    });
    this.pending = [];
    this.previousBatch = batch;
    return {
      batch,
      flushed: {
        batch_seq,
        entry_count: entries.length,
        sealed_at: batch.sealed_at,
      },
    };
  }
}

/**
 * Canonical-audit-node side store: authoritative per-emitter previous-batch
 * lookup for verifyAuditBatch + a flat append-only log of every accepted batch.
 *
 * Operator-configured replicas (§5.4) and N-way audit replication (§10.1
 * `audit_replication_full_n_way`, v1.x) extend off this store; v0.1 surfaces
 * the simple in-memory shape that the lifecycle orchestrator wires.
 */
export class CanonicalAuditLog {
  private previousByEmitter = new Map<string, AuditBatch>();
  private appendOrder: AuditBatch[] = [];

  /**
   * Record a verified batch. Caller MUST have run verifyAuditBatch first.
   */
  append(batch: AuditBatch): void {
    this.previousByEmitter.set(batch.emitter_node, batch);
    this.appendOrder.push(batch);
  }

  lookupPreviousBatch(nodeId: string): AuditBatch | null {
    return this.previousByEmitter.get(nodeId) ?? null;
  }

  size(): number {
    return this.appendOrder.length;
  }

  /** Flat snapshot in append order — used by sync replies and tests. */
  snapshot(): AuditBatch[] {
    return [...this.appendOrder];
  }

  /**
   * Per-emitter range pull for sync delta (§3.5 step 4 — "missed audit
   * batches"). Returns batches strictly greater than `since_seq`.
   */
  rangeFor(nodeId: string, sinceSeq: number): AuditBatch[] {
    return this.appendOrder.filter(
      (b) => b.emitter_node === nodeId && b.batch_seq > sinceSeq
    );
  }
}
