/**
 * Sanctuary — Undeclared-workload detection (thin prototype, rung c).
 *
 * Cross-checks the host's LIVE supervised workloads (the supervisor's
 * `status()` snapshot) against the DECLARED, audit-chain-recorded set (the
 * {@link WorkloadRegistry} projection of the #504 lifecycle chain), and flags
 * any live supervised workload that has NO matching declared lifecycle record.
 *
 * This closes the biggest honest gap #513 disclaimed: the host attestation
 * (#513) covers DECLARED workloads only — it cannot say whether a workload is
 * running that was NEVER declared. This module answers exactly that question for
 * the workloads the supervisor sees, and is just as careful about NOT
 * over-claiming.
 *
 * COMPOSES with #509 (supervisor) + #504/#513 (registry/attestation), additive:
 *   - It consumes the supervisor's `SupervisedAgentStatus[]` and a built
 *     `WorkloadRegistry`; both are INJECTED so the detector unit-tests without a
 *     real supervisor process, daemon, or socket.
 *   - It changes NO #504/#513 schema semantics, the consent enum, the attestation
 *     signed-body shape, or the seal binding. It only READS `listDeclared()`.
 *   - It introduces no crypto and no persistent store. The SIGNED + SEALED
 *     finding lives in `undeclared-finding.ts` / `undeclared-finding-seal.ts`,
 *     reusing the #513 Ed25519 + canonical-JSON + chain-bound-critical pattern.
 *
 * THE IDENTIFIER SEAM — handled honestly, NO false alarms (the hard part):
 *   The supervisor keys live workloads by `agent_id`; the registry keys declared
 *   workloads by `workload_id`, each carrying `instance_ids`. By default the
 *   Tier-B adapter sets `workload_id === agent_id` AND `instance_id ===
 *   agent_id`, but a custom adapter CAN override `workload_id` (and/or carry the
 *   `agent_id` only as an `instance_id`). A naive "agent_id not in declared
 *   workload_ids" diff would FALSE-FLAG a custom-mapped, fully-declared workload
 *   as "undeclared" — a false security alarm, which is WORSE than no detection.
 *
 *   Therefore a live `agent_id` counts as DECLARED (cleared) iff SOME ACTIVE
 *   declared record has `workload_id === agent_id` OR `agent_id ∈ that record's
 *   instance_ids`. This resolves the default wiring AND the
 *   instance-id-carries-agent-id case. UNDECLARED = live `agent_id`s with no such
 *   ACTIVE match.
 *
 *   ONLY ACTIVE RECORDS CLEAR (codex follow-up — the worse error direction): a
 *   `deleted` (destroyed) or `slept` (dormant, not running) declared record does
 *   NOT clear a live workload. A live workload that matches ONLY such a terminal/
 *   dormant record is itself flagged with a DISTINCT reason
 *   (`UNDECLARED_REASON_TERMINAL_DECLARATION`) — it is running without a current
 *   declaration. This closes the missed detection where a `workload_deleted`
 *   record's (possibly reused) id silently cleared a genuinely-undeclared new
 *   live workload.
 *
 *   HONEST LIMITATION (rung-c.1): a workload whose adapter overrode BOTH
 *   `workload_id` AND `instance_id` away from its `agent_id` cannot be resolved
 *   here without an explicit external mapping table; it could appear in the
 *   undeclared list even though it WAS declared under different ids. The finding's
 *   `scope` text states this boundary so a reader never treats the undeclared list
 *   as definitive beyond it. Scope is ALSO bounded to the supervisor's view: a
 *   workload running entirely OUTSIDE the supervisor (host-wide process
 *   enumeration, rung d) is out of scope here.
 *
 * No consciousness / sentience / welfare claim appears anywhere. Neutral
 * "workload" language only (CISO-safe).
 */

import type { SupervisedAgentState } from "../supervisor/protocol.js";
import type {
  WorkloadLifecycleState,
  WorkloadRegistry,
} from "./registry.js";

/**
 * The declared lifecycle states whose record is currently EXTANT (the workload
 * is, per its last recorded transition, either standing or runnable) and may
 * therefore CLEAR a matching live workload. `deleted` (destroyed) and `slept`
 * (dormant — not running; a live one that resumed without recording it) are
 * deliberately EXCLUDED: a live workload that matches only such a record is
 * running without a current declaration, so it must still be flagged rather than
 * silently cleared by a stale terminal/dormant record (which could also be a
 * REUSED id, since the schema does not guarantee ids are unique or non-reused).
 */
const ACTIVE_CLEARING_STATES: ReadonlySet<WorkloadLifecycleState> = new Set([
  "registered",
  "instantiated",
  "paused",
  "resumed",
  "forked",
  "merged",
]);

/** Minimal live-status shape the detector needs. Structurally a subset of the
 * supervisor's `SupervisedAgentStatus`, named locally so the detector does not
 * couple to the full supervisor status surface (and so a test can construct one
 * without the supervisor's other fields). */
export interface LiveSupervisedWorkload {
  agent_id: string;
  harness: string;
  state: SupervisedAgentState;
}

/** Reason: the live workload matched NO declared record at all (by either
 * `workload_id` or `instance_id`). Bound into the finding so a reader sees WHY a
 * workload was flagged and on what match rule. */
export const UNDECLARED_REASON =
  "no matching declared lifecycle record (by workload_id or instance_id)" as const;

/** Reason: the live workload matched ONLY a `deleted`/`slept` declared record —
 * a terminated or dormant declaration. The workload is observed running, but its
 * last recorded declaration says it should be destroyed (`deleted`) or not
 * running (`slept`), so it is running without a current declaration. (This also
 * covers a REUSED id: a new live workload colliding with a stale terminal
 * record's id.) Distinguished from {@link UNDECLARED_REASON} so the finding is
 * precise. */
export const UNDECLARED_REASON_TERMINAL_DECLARATION =
  "live workload matches only a terminated or dormant (deleted/slept) declared record; it is running without a current declaration" as const;

/** The reason a live workload was flagged. */
export type UndeclaredReason =
  | typeof UNDECLARED_REASON
  | typeof UNDECLARED_REASON_TERMINAL_DECLARATION;

/** One flagged live workload with no matching ACTIVE declared lifecycle record. */
export interface UndeclaredWorkload {
  agent_id: string;
  harness: string;
  /** The supervisor's lifecycle state for this live workload (verbatim). */
  supervisor_state: SupervisedAgentState;
  reason: UndeclaredReason;
}

/** Result of a detection pass. Counts let a reader see the comparison size
 * without re-deriving it (live vs declared sets). */
export interface UndeclaredDetection {
  /** Live supervised workloads with NO matching declared record, sorted by
   * `agent_id` for deterministic output (the signed finding must be stable). */
  undeclared: UndeclaredWorkload[];
  /** Count of live supervised workloads compared. */
  live_count: number;
  /** Count of distinct declared workloads compared against. */
  declared_count: number;
}

export interface DetectUndeclaredWorkloadsParams {
  /** The supervisor's `status()` snapshot (the LIVE supervised set). */
  liveStatuses: ReadonlyArray<LiveSupervisedWorkload>;
  /** The declared-workload projection of the audit chain (READ-only here). */
  registry: WorkloadRegistry;
}

/**
 * Cross-check the live supervised set against the declared set and return the
 * undeclared workloads.
 *
 * A live `agent_id` is DECLARED (cleared) iff some ACTIVE declared record (state
 * in {@link ACTIVE_CLEARING_STATES}) matches it by `workload_id === agent_id` OR
 * `agent_id ∈ instance_ids` (THE SEAM RULE — this is what prevents the false
 * alarm on custom-mapped / instance-id-carried declared workloads). A `deleted`
 * or `slept` record does NOT clear: a live workload matching only such a
 * terminal/dormant record is flagged with
 * {@link UNDECLARED_REASON_TERMINAL_DECLARATION}; one matching no declared record
 * at all is flagged with {@link UNDECLARED_REASON}.
 *
 * Deterministic: the undeclared list is sorted by `agent_id`. Pure + injectable:
 * no supervisor/daemon/socket and no chain access beyond `registry.listDeclared()`.
 */
export function detectUndeclaredWorkloads(
  params: DetectUndeclaredWorkloadsParams,
): UndeclaredDetection {
  const declared = params.registry.listDeclared();

  // Build TWO identifier sets for the seam match, split by record state:
  //   - activeIdentifiers: ids of ACTIVE/extant records — these CLEAR a live
  //     workload (resolves the default wiring and the instance-id-carries-
  //     agent-id case).
  //   - terminalIdentifiers: ids of `deleted`/`slept` records — these do NOT
  //     clear, but let us flag a live match with the precise terminal reason
  //     rather than the no-record-at-all reason. (A live id present in BOTH —
  //     e.g. a reused id active again elsewhere — is cleared: an active record
  //     wins, so activeIdentifiers is checked first.)
  const activeIdentifiers = new Set<string>();
  const terminalIdentifiers = new Set<string>();
  for (const record of declared) {
    const target = ACTIVE_CLEARING_STATES.has(record.state)
      ? activeIdentifiers
      : terminalIdentifiers;
    target.add(record.workload_id);
    for (const instanceId of record.instance_ids) {
      target.add(instanceId);
    }
  }

  const undeclared: UndeclaredWorkload[] = [];
  for (const live of params.liveStatuses) {
    // An ACTIVE declared record clears the live workload — no alarm.
    if (activeIdentifiers.has(live.agent_id)) continue;
    // No active match. If it matches ONLY a terminal/dormant record, flag it
    // with the distinct terminal reason; otherwise it matches nothing declared.
    const reason: UndeclaredReason = terminalIdentifiers.has(live.agent_id)
      ? UNDECLARED_REASON_TERMINAL_DECLARATION
      : UNDECLARED_REASON;
    undeclared.push({
      agent_id: live.agent_id,
      harness: live.harness,
      supervisor_state: live.state,
      reason,
    });
  }

  undeclared.sort((a, b) => a.agent_id.localeCompare(b.agent_id));

  return {
    undeclared,
    live_count: params.liveStatuses.length,
    declared_count: declared.length,
  };
}
