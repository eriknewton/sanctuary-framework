/**
 * Promote orchestration: selected candidates -> live, signed allow rules.
 *
 * THE RED-LINE INVARIANT (this function exists to uphold it): no manifest
 * mutation, no `publish()` call, and no rule addition happens unless
 * `deps.approve()` returns `allowed: true`. Approval is the SAME Tier-1
 * gate class as `state_export` / key rotation (registered as a
 * non-relaxable Tier-1 operation in `principal-policy/loader.ts` +
 * `gate.ts`, mirroring the Governed File-Grant v1 precedent). If the
 * approval channel is unreachable or denies, this function returns without
 * ever calling `deps.publish` -- the live ruleset is byte-unchanged and
 * every selected destination stays denied (adversarial review finding H1
 * and H2; CI DoD tests 3 and 5).
 *
 * A candidate that cannot synthesize a valid rule (fails `validateRule`) is
 * dropped BEFORE the approval gate is even asked -- it is never offered,
 * and a bad row never blocks promoting the rest of a clean selection
 * (CI DoD test 2).
 */

import type { AllowlistRule } from "../allowlist/schema.js";
import { synthesizeCandidateRule } from "./synthesize.js";
import {
  DEFAULT_OBSERVE_GRANULARITY,
  type CandidateObservation,
  type ObserveGranularity,
} from "./types.js";

/** One row the operator selected to promote, with an optional per-row granularity override (D-Q2). */
export interface PromoteSelectionRow {
  key: string;
  granularity?: ObserveGranularity;
}

export interface PromotePublishResult {
  written_rule_filenames: string[];
  removed_rule_filenames: string[];
}

/** Narrow approval-gate surface `promoteCandidates` needs; `ApprovalGate.evaluate` satisfies it. */
export interface PromoteApprover {
  (operation: string, context: Record<string, unknown>): Promise<{ allowed: boolean; reason?: string }>;
}

export interface PromoteDeps {
  /** The full live ruleset BEFORE promote, read fresh (never a stale cache). */
  currentRules: readonly AllowlistRule[];
  /** Tier-1 approval call. Never invoked when there is nothing valid to promote. */
  approve: PromoteApprover;
  /**
   * Re-signs + atomically publishes the FULL merged ruleset. Invoked ONLY
   * after `approve()` returns `allowed: true` -- never before, never on a
   * denial. Wraps `runtime/manifest-publisher.ts`'s `publishSignedManifest`
   * in production; a test double in unit tests.
   */
  publish: (rules: AllowlistRule[]) => Promise<PromotePublishResult>;
  /**
   * Best-effort per-candidate audit append, one call per promoted
   * candidate. A throw here must NEVER be reported as "promote failed" --
   * by the time this runs the manifest has already been re-signed and
   * published (mirrors `file-grant/mint.ts`'s post-place confirmation
   * audit: a throw after the access-conferring step never rolls back a
   * live grant).
   */
  auditPromotedCandidate?: (row: {
    key: string;
    rule_id: string;
    candidate: CandidateObservation;
  }) => Promise<void>;
  now: Date;
}

export type PromoteDroppedReason = "not_found" | "failed_validation";

export type PromoteOutcome =
  | {
      status: "no_candidates";
      dropped: Array<{ key: string; reason: PromoteDroppedReason }>;
    }
  | {
      status: "denied";
      reason: string;
      dropped: Array<{ key: string; reason: PromoteDroppedReason }>;
    }
  | {
      status: "promoted";
      promotedKeys: string[];
      addedRules: AllowlistRule[];
      dropped: Array<{ key: string; reason: PromoteDroppedReason }>;
      publish: PromotePublishResult;
    };

export async function promoteCandidates(
  selection: readonly PromoteSelectionRow[],
  candidatesByKey: ReadonlyMap<string, CandidateObservation>,
  deps: PromoteDeps,
): Promise<PromoteOutcome> {
  const dropped: Array<{ key: string; reason: PromoteDroppedReason }> = [];
  const createdAt = deps.now.toISOString();

  const promotable: Array<{ key: string; observation: CandidateObservation; rule: AllowlistRule }> = [];
  for (const row of selection) {
    const observation = candidatesByKey.get(row.key);
    if (!observation) {
      dropped.push({ key: row.key, reason: "not_found" });
      continue;
    }
    const rule = synthesizeCandidateRule(observation, createdAt, row.granularity ?? DEFAULT_OBSERVE_GRANULARITY);
    if (!rule) {
      dropped.push({ key: row.key, reason: "failed_validation" });
      continue;
    }
    promotable.push({ key: row.key, observation, rule });
  }

  if (promotable.length === 0) {
    // Nothing to approve, nothing to publish. Deliberately does NOT call
    // `deps.approve` -- there is nothing valid for a human to approve.
    return { status: "no_candidates", dropped };
  }

  const approval = await deps.approve("castle_wall_observe_promote", {
    candidate_count: promotable.length,
    destinations: promotable.map(
      (row) => `${row.observation.host ?? row.observation.ip}:${row.observation.port}/${row.observation.protocol}`,
    ),
  });

  if (!approval.allowed) {
    // THE RED-LINE INVARIANT: no publish() call below this line on the
    // denied path. The live manifest is byte-unchanged; every selected
    // destination stays blocked.
    return { status: "denied", reason: approval.reason ?? "not approved", dropped };
  }

  const existingIds = new Set(deps.currentRules.map((rule) => rule.id));
  const addedRules = promotable.filter((row) => !existingIds.has(row.rule.id)).map((row) => row.rule);
  const mergedRules = [...deps.currentRules, ...addedRules];
  const publishResult = await deps.publish(mergedRules);

  for (const row of promotable) {
    if (!deps.auditPromotedCandidate) continue;
    try {
      await deps.auditPromotedCandidate({ key: row.key, rule_id: row.rule.id, candidate: row.observation });
    } catch {
      // Best-effort: the manifest is already published. A throw here must
      // never surface as "promote failed" once the access-widening step
      // (publish) has already succeeded.
    }
  }

  return {
    status: "promoted",
    promotedKeys: promotable.map((row) => row.key),
    addedRules,
    dropped,
    publish: publishResult,
  };
}
