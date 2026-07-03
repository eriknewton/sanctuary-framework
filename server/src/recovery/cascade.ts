/**
 * Recovery Cascade -- orchestrator.
 *
 * DMswitch trigger -> guardian notify -> threshold evaluate -> action execute.
 *
 * Acceptance criterion 4: deterministic. Given the same inputs (guardian
 * roster, threshold, recent activity, pending recovery events), the cascade
 * evaluates the same way on any honest node.
 *
 * Acceptance criterion 10: four failure modes tested.
 */

import { randomBytes } from "../core/random.js";
import type { GuardianRoster } from "../mesh/guardian/types.js";
import {
  RECOVERY_EVENT_TYPES,
  type CascadeStateCode,
  type RecoveryAction,
} from "./constants.js";
import { evaluateDmswitch, validateDmswitchConfig } from "./dmswitch.js";
import {
  CascadeStateError,
  ThresholdNotMetError,
  WindowNotExpiredError,
} from "./errors.js";
import { packRecoveryEvent } from "./recovery-event.js";
import {
  buildApprovalSigningInput,
  evaluateThreshold,
} from "./threshold-evaluator.js";
import type {
  ActivityRecord,
  CascadeState,
  DmswitchConfig,
  GuardianApproval,
} from "./types.js";

function generateCascadeId(): string {
  const bytes = randomBytes(16);
  let hex = "";
  for (const b of bytes) hex += b.toString(16).padStart(2, "0");
  return hex;
}

/**
 * Valid state transitions for the cascade state machine.
 */
const VALID_TRANSITIONS: Record<CascadeStateCode, CascadeStateCode[]> = {
  idle: ["triggered"],
  triggered: ["awaiting_threshold"],
  awaiting_threshold: ["threshold_met", "failed"],
  threshold_met: ["executing"],
  executing: ["completed", "failed"],
  completed: [],
  failed: [],
};

function assertTransition(
  current: CascadeStateCode,
  next: CascadeStateCode
): void {
  const allowed = VALID_TRANSITIONS[current];
  if (!allowed || !allowed.includes(next)) {
    throw new CascadeStateError(
      `invalid cascade state transition: ${current} -> ${next}`
    );
  }
}

/**
 * Initiate a recovery cascade. Creates the cascade state in `triggered` state.
 *
 * The cascade can be initiated either by DMswitch (automatic, after operator
 * absence threshold) or manually (guardian-initiated recovery request).
 *
 * Fail-closed invariant: when a `dmswitch_trigger` is supplied, the operator
 * absence window MUST have expired. If it has not, this throws
 * WindowNotExpiredError and no cascade is created. This blocks the path where
 * a DMswitch-attributed cascade reaches `awaiting_threshold` on non-expired
 * input, letting guardians satisfy the M-of-N threshold and execute before the
 * absence window elapses. Manual (guardian-requested) recovery does not supply
 * `dmswitch_trigger` and is unaffected.
 */
export function initiateCascade(params: {
  action: RecoveryAction;
  fortress_id: string;
  roster: GuardianRoster;
  dmswitch_trigger?: {
    last_activity: ActivityRecord;
    config: DmswitchConfig;
    now_ms?: number;
  };
}): CascadeState {
  const cascade_id = generateCascadeId();
  const now = new Date().toISOString();

  let dmswitch_trigger: CascadeState["dmswitch_trigger"];
  if (params.dmswitch_trigger) {
    // Fail-closed config gate: the DMswitch window feeds the trigger arithmetic
    // (elapsed_ms >= window_ms). A below-minimum, zero, or non-finite window
    // would make the switch fire immediately, letting a DMswitch-attributed
    // cascade reach awaiting_threshold and execute before the mandatory absence
    // window elapses. Validate the config at this gate BEFORE evaluateDmswitch,
    // so an out-of-range window throws RecoveryConfigError and no cascade is
    // created or stored. This is the same shape contract emitCascadeEntry's
    // callers must honor; running it here closes the class at the cascade-
    // creation boundary.
    validateDmswitchConfig(params.dmswitch_trigger.config);
    const evaluation = evaluateDmswitch({
      last_activity: params.dmswitch_trigger.last_activity,
      config: params.dmswitch_trigger.config,
      now_ms: params.dmswitch_trigger.now_ms,
    });
    if (!evaluation.triggered) {
      throw new WindowNotExpiredError({
        remaining_ms: evaluation.remaining_ms,
        expires_at: evaluation.expires_at,
      });
    }
    dmswitch_trigger = {
      last_activity_at: params.dmswitch_trigger.last_activity.last_activity_at,
      triggered_at: now,
      window_ms: evaluation.window_ms,
    };
  }

  return {
    cascade_id,
    state: "triggered",
    action: params.action,
    fortress_id: params.fortress_id,
    roster_version: params.roster.version,
    threshold_m: params.roster.m,
    threshold_n: params.roster.n,
    approvals: [],
    initiated_at: now,
    dmswitch_trigger,
    events: [],
  };
}

/**
 * Transition cascade to awaiting_threshold state.
 */
export function beginAwaitingThreshold(cascade: CascadeState): CascadeState {
  assertTransition(cascade.state, "awaiting_threshold");
  return {
    ...cascade,
    state: "awaiting_threshold",
  };
}

/**
 * Register a guardian approval on the cascade.
 *
 * Does NOT verify the signature (that is the threshold evaluator's job).
 * This function only adds the approval to the cascade state if the cascade
 * is in the correct state.
 */
export function registerApproval(
  cascade: CascadeState,
  approval: GuardianApproval
): CascadeState {
  if (cascade.state !== "awaiting_threshold") {
    throw new CascadeStateError(
      `cannot register approval in state "${cascade.state}"; cascade must be in "awaiting_threshold"`
    );
  }
  if (approval.cascade_id !== cascade.cascade_id) {
    throw new CascadeStateError(
      `approval cascade_id "${approval.cascade_id}" does not match cascade "${cascade.cascade_id}"`
    );
  }
  // Reject an approval whose declared recovery_action does not match this
  // cascade's action. The declared action is unauthenticated envelope metadata;
  // binding it here keeps a guardian's approval for one action from being
  // parked on a cascade for a different action (fail closed).
  if (approval.recovery_action !== cascade.action) {
    throw new CascadeStateError(
      `approval recovery_action "${approval.recovery_action}" does not match cascade action "${cascade.action}"`
    );
  }
  // Reject duplicate guardian.
  if (cascade.approvals.some((a) => a.guardian_id === approval.guardian_id)) {
    throw new CascadeStateError(
      `duplicate approval from guardian ${approval.guardian_id}`
    );
  }

  return {
    ...cascade,
    approvals: [...cascade.approvals, approval],
  };
}

/**
 * Evaluate the current cascade state against the guardian roster.
 * If threshold is met, transitions to `threshold_met`.
 *
 * Pure function. Deterministic given the same inputs.
 */
export function evaluateCascade(
  cascade: CascadeState,
  roster: GuardianRoster
): CascadeState {
  if (cascade.state !== "awaiting_threshold") {
    return cascade;
  }

  const signingInput = buildApprovalSigningInput({
    cascade_id: cascade.cascade_id,
    recovery_action: cascade.action,
    fortress_id: cascade.fortress_id,
    roster_version: cascade.roster_version,
  });

  const result = evaluateThreshold({
    approvals: cascade.approvals,
    roster,
    signing_input: signingInput,
  });

  if (result.threshold_met) {
    return {
      ...cascade,
      state: "threshold_met",
      threshold_met_at: new Date().toISOString(),
    };
  }

  return cascade;
}

/**
 * Execute the recovery action. Transitions from `threshold_met` to
 * `executing`, then to `completed` or `failed`.
 *
 * The actual action implementation is delegated to the caller via the
 * `executor` callback. This function handles state transitions and
 * event emission.
 */
export async function executeCascade(params: {
  cascade: CascadeState;
  roster: GuardianRoster;
  executor: (cascade: CascadeState) => Promise<void>;
  emitter_node: string;
  emitter_principal: string;
  signing_key: Uint8Array;
}): Promise<CascadeState> {
  let cascade = params.cascade;

  // Verify threshold is met before executing.
  assertTransition(cascade.state, "executing");

  const signingInput = buildApprovalSigningInput({
    cascade_id: cascade.cascade_id,
    recovery_action: cascade.action,
    fortress_id: cascade.fortress_id,
    roster_version: cascade.roster_version,
  });

  const thresholdResult = evaluateThreshold({
    approvals: cascade.approvals,
    roster: params.roster,
    signing_input: signingInput,
  });

  if (!thresholdResult.threshold_met) {
    throw new ThresholdNotMetError({
      valid_count: thresholdResult.valid_count,
      threshold_m: thresholdResult.threshold_m,
    });
  }

  cascade = { ...cascade, state: "executing" };

  try {
    await params.executor(cascade);

    const completedEvent = packRecoveryEvent({
      event_type: RECOVERY_EVENT_TYPES.RECOVERY_EXECUTED,
      fortress_id: cascade.fortress_id,
      emitter_node: params.emitter_node,
      emitter_principal: params.emitter_principal,
      payload: {
        cascade_id: cascade.cascade_id,
        action: cascade.action,
        valid_approvals: thresholdResult.valid_count,
        threshold_m: thresholdResult.threshold_m,
      },
      signing_key: params.signing_key,
    });

    return {
      ...cascade,
      state: "completed",
      completed_at: new Date().toISOString(),
      events: [...cascade.events, completedEvent],
    };
  } catch (err) {
    const failedEvent = packRecoveryEvent({
      event_type: RECOVERY_EVENT_TYPES.RECOVERY_FAILED,
      fortress_id: cascade.fortress_id,
      emitter_node: params.emitter_node,
      emitter_principal: params.emitter_principal,
      payload: {
        cascade_id: cascade.cascade_id,
        action: cascade.action,
        error: err instanceof Error ? err.message : String(err),
      },
      signing_key: params.signing_key,
    });

    return {
      ...cascade,
      state: "failed",
      failed_at: new Date().toISOString(),
      failure_reason: err instanceof Error ? err.message : String(err),
      events: [...cascade.events, failedEvent],
    };
  }
}

/**
 * Fail a cascade manually (e.g., on timeout or operator cancellation).
 */
export function failCascade(
  cascade: CascadeState,
  reason: string
): CascadeState {
  if (cascade.state === "completed" || cascade.state === "failed") {
    throw new CascadeStateError(
      `cannot fail cascade in terminal state "${cascade.state}"`
    );
  }
  return {
    ...cascade,
    state: "failed",
    failed_at: new Date().toISOString(),
    failure_reason: reason,
  };
}
