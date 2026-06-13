/**
 * Sanctuary — Workload registry projection (thin prototype, rung b).
 *
 * A DERIVED, in-memory view of the workload-lifecycle audit chain. The audit
 * chain is the durable source of truth; this is a read-only projection built by
 * REPLAYING the chain's workload-lifecycle entries. It adds NO new persistent
 * store — nothing here writes. Rebuild it by replaying the chain again.
 *
 * COMPOSES with the shipped #504 schema (`./payload.ts`, `./constants.ts`):
 *   - It reads the SAME validated `WorkloadLifecyclePayload` shape the sanctioned
 *     writer emits, via `validateWorkloadLifecyclePayload` (fail-closed: a
 *     malformed/unknown-version lifecycle entry throws rather than being guessed
 *     at — constraint #5, never silently degrade).
 *   - It does NOT re-implement or relax any of #504's schema/consent semantics.
 *     `consent_status`, `consent_ref`, `override`, and `manufactured_preference_
 *     caveat` are carried through verbatim from the recorded payload.
 *
 * HONESTY (the #504 frontier, restated so it travels with the code):
 *   This enumerates the DECLARED set — workloads the chain has a RECORD of. It
 *   does NOT and must NOT claim knowledge of undeclared / never-recorded
 *   workloads, nor host-wide process completeness. Detecting workloads that were
 *   never declared is the separate registry-attestation / undeclared-workload
 *   frontier, an explicitly LATER build item. A terminated workload
 *   (`deleted`/`slept`) stays listed with its terminal disposition — the
 *   projection reports disposition honestly, it never silently drops a
 *   terminated workload.
 */

import type { AuditEntry, AuditLog } from "../l2-operational/audit-log.js";
import {
  WORKLOAD_LIFECYCLE_OPS,
  isWorkloadLifecycleOp,
  type WorkloadLifecycleOp,
} from "./constants.js";
import {
  validateWorkloadLifecyclePayload,
  type ConsentStatus,
  type DeleteOverride,
  type WorkloadLifecyclePayload,
} from "./payload.js";

/**
 * Terminal/intermediate lifecycle state a workload is in per its LAST recorded
 * transition. Mirrors the run-state ops; an attestation reads `consent_status`
 * (carried separately) for the consent question, not this.
 */
export type WorkloadLifecycleState =
  | "registered"
  | "instantiated"
  | "paused"
  | "resumed"
  | "forked"
  | "merged"
  | "slept"
  | "deleted";

/** The audit ops that are RUN-STATE transitions the registry folds over. The
 * host-attestation op (`HOST_ATTESTED`) and the distress op are lifecycle-
 * vocabulary members but are NOT per-workload state transitions, so they are
 * deliberately excluded from the state fold below. */
const OP_TO_STATE: Readonly<Record<string, WorkloadLifecycleState>> =
  Object.freeze({
    [WORKLOAD_LIFECYCLE_OPS.REGISTERED]: "registered",
    [WORKLOAD_LIFECYCLE_OPS.INSTANTIATED]: "instantiated",
    [WORKLOAD_LIFECYCLE_OPS.PAUSED]: "paused",
    [WORKLOAD_LIFECYCLE_OPS.RESUMED]: "resumed",
    [WORKLOAD_LIFECYCLE_OPS.FORKED]: "forked",
    [WORKLOAD_LIFECYCLE_OPS.MERGED]: "merged",
    [WORKLOAD_LIFECYCLE_OPS.SLEPT]: "slept",
    [WORKLOAD_LIFECYCLE_OPS.DELETED]: "deleted",
  });

/** The latest disposition of one declared workload, folded from its records. */
export interface WorkloadRecord {
  workload_id: string;
  /** State per the LAST recorded run-state transition for this workload. */
  state: WorkloadLifecycleState;
  /** Distinct instance ids seen across this workload's recorded events. */
  instance_ids: string[];
  /** Latest recorded consent disposition. `absent` is loud and never omitted. */
  consent_status: ConsentStatus;
  /** Latest recorded consent reference (never the body), or null. */
  consent_ref: string | null;
  /** Exceptional-delete account from the latest record carrying one, if any. */
  override?: DeleteOverride;
  /** Honest-insufficiency flag carried verbatim from the latest record:
   * v1 consent is operator authorization as proxy, NOT agent-side preference. */
  manufactured_preference_caveat: boolean;
  /** Per-instance ordinal of the last record seen (H2: detects a dropped
   * RECORD, never an unrecorded transition). Undefined if none carried one. */
  last_prev_lifecycle_seq?: number;
}

/**
 * In-memory projection of declared workloads. Built once from a chain replay;
 * call {@link WorkloadRegistry.fromAuditLog} to (re)build from current chain
 * state. Holds no key material and writes nothing.
 */
export class WorkloadRegistry {
  private readonly byId = new Map<string, WorkloadRecord>();

  private constructor() {}

  /**
   * Build the projection by replaying the audit chain's workload-lifecycle
   * entries in chain order.
   *
   * Fail-closed: each lifecycle entry's `details` is run through
   * `validateWorkloadLifecyclePayload`; a malformed/unknown-version entry throws
   * (it is NOT skipped silently). An attestation built on a registry that
   * skipped unreadable records would under-report — exactly the omission the
   * #504 discipline forbids.
   */
  static async fromAuditLog(auditLog: AuditLog): Promise<WorkloadRegistry> {
    const registry = new WorkloadRegistry();
    // Replay every workload-lifecycle op. `query` filters by a single operation
    // type, so fold each run-state op in turn, then sort the union by chain
    // timestamp to apply transitions in recorded order. We pull a generous
    // limit so the projection sees the whole declared history, not a tail.
    const REPLAY_LIMIT = 1_000_000;
    const collected: AuditEntry[] = [];
    for (const opString of Object.keys(OP_TO_STATE)) {
      const { entries } = await auditLog.query({
        operation_type: opString,
        limit: REPLAY_LIMIT,
      });
      for (const e of entries) collected.push(e);
    }
    // Apply in recorded order. Timestamps are ISO-8601 (lexicographically
    // ordered); ties keep query order, which is chain order within an op.
    collected.sort((a, b) => a.timestamp.localeCompare(b.timestamp));
    for (const entry of collected) registry.apply(entry);
    return registry;
  }

  /** Fold one workload-lifecycle audit entry into the projection. */
  private apply(entry: AuditEntry): void {
    if (!isWorkloadLifecycleOp(entry.operation)) return;
    const op = entry.operation as WorkloadLifecycleOp;
    const state = OP_TO_STATE[op];
    // Non-state ops (host attestation, distress) carry no per-workload payload
    // shape and never advance a workload's disposition. Skip them.
    if (state === undefined) return;
    if (!entry.details) return;

    // Fail closed on a malformed/unknown-version lifecycle payload (#504
    // constraint #5). validateWorkloadLifecyclePayload throws on violation.
    const payload: WorkloadLifecyclePayload =
      validateWorkloadLifecyclePayload(entry.details);

    const existing = this.byId.get(payload.workload_id);
    const instanceIds = existing ? [...existing.instance_ids] : [];
    if (!instanceIds.includes(payload.instance_id)) {
      instanceIds.push(payload.instance_id);
    }

    const record: WorkloadRecord = {
      workload_id: payload.workload_id,
      // The latest applied transition wins (collected is in recorded order).
      state,
      instance_ids: instanceIds,
      consent_status: payload.consent_status,
      consent_ref: payload.consent_ref,
      manufactured_preference_caveat:
        payload.manufactured_preference_caveat ?? false,
      ...(payload.override ? { override: payload.override } : {}),
      ...(payload.prev_lifecycle_seq !== undefined
        ? { last_prev_lifecycle_seq: payload.prev_lifecycle_seq }
        : {}),
    };
    this.byId.set(payload.workload_id, record);
  }

  /**
   * All workloads the chain has a RECORD of, with their latest disposition.
   * A terminated (`deleted`/`slept`) workload remains listed with that terminal
   * state — terminated workloads are reported honestly, never dropped.
   *
   * Sorted by workload_id for deterministic output (the attestation canonical
   * form must be stable across rebuilds).
   */
  listDeclared(): WorkloadRecord[] {
    return [...this.byId.values()]
      .map((r) => ({ ...r, instance_ids: [...r.instance_ids] }))
      .sort((a, b) => a.workload_id.localeCompare(b.workload_id));
  }

  /** Latest disposition of one declared workload, or undefined if no record. */
  get(workloadId: string): WorkloadRecord | undefined {
    const r = this.byId.get(workloadId);
    return r ? { ...r, instance_ids: [...r.instance_ids] } : undefined;
  }

  /** Count of distinct declared workloads. */
  get size(): number {
    return this.byId.size;
  }
}
