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
 *   Therefore a live `agent_id` counts as DECLARED iff SOME declared record has
 *   `workload_id === agent_id` OR `agent_id ∈ that record's instance_ids`. This
 *   resolves the default wiring AND the instance-id-carries-agent-id case.
 *   UNDECLARED = live `agent_id`s with no such match.
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
import type { WorkloadRegistry } from "./registry.js";

/** Minimal live-status shape the detector needs. Structurally a subset of the
 * supervisor's `SupervisedAgentStatus`, named locally so the detector does not
 * couple to the full supervisor status surface (and so a test can construct one
 * without the supervisor's other fields). */
export interface LiveSupervisedWorkload {
  agent_id: string;
  harness: string;
  state: SupervisedAgentState;
}

/** The single canonical reason string for an undeclared flag. Bound into the
 * finding so a reader sees WHY a workload was flagged and on what match rule. */
export const UNDECLARED_REASON =
  "no matching declared lifecycle record (by workload_id or instance_id)" as const;

/** One flagged live workload with no matching declared lifecycle record. */
export interface UndeclaredWorkload {
  agent_id: string;
  harness: string;
  /** The supervisor's lifecycle state for this live workload (verbatim). */
  supervisor_state: SupervisedAgentState;
  reason: typeof UNDECLARED_REASON;
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
 * A live `agent_id` is DECLARED iff some declared record matches it by
 * `workload_id === agent_id` OR `agent_id ∈ instance_ids` (THE SEAM RULE — this
 * is what prevents the false alarm on custom-mapped / instance-id-carried
 * declared workloads). Everything else live is UNDECLARED.
 *
 * Deterministic: the undeclared list is sorted by `agent_id`. Pure + injectable:
 * no supervisor/daemon/socket and no chain access beyond `registry.listDeclared()`.
 */
export function detectUndeclaredWorkloads(
  params: DetectUndeclaredWorkloadsParams,
): UndeclaredDetection {
  const declared = params.registry.listDeclared();

  // Build the set of identifiers that count as "declared" for the seam match:
  // every declared workload_id AND every declared instance_id. A live agent_id
  // matching ANY of these is declared (resolves both the default wiring and the
  // instance-id-carries-agent-id case).
  const declaredIdentifiers = new Set<string>();
  for (const record of declared) {
    declaredIdentifiers.add(record.workload_id);
    for (const instanceId of record.instance_ids) {
      declaredIdentifiers.add(instanceId);
    }
  }

  const undeclared: UndeclaredWorkload[] = [];
  for (const live of params.liveStatuses) {
    if (declaredIdentifiers.has(live.agent_id)) continue; // declared — no alarm.
    undeclared.push({
      agent_id: live.agent_id,
      harness: live.harness,
      supervisor_state: live.state,
      reason: UNDECLARED_REASON,
    });
  }

  undeclared.sort((a, b) => a.agent_id.localeCompare(b.agent_id));

  return {
    undeclared,
    live_count: params.liveStatuses.length,
    declared_count: declared.length,
  };
}
