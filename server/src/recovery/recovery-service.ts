/**
 * Recovery Cascade -- public API surface.
 *
 * Ties the recovery primitives (guardian roster, DMswitch, threshold
 * evaluator, cascade orchestrator, multi-principal boundary) into three
 * operator-facing operations:
 *
 *   1. `initRecovery` -- start a recovery cascade.
 *   2. `registerGuardianApproval` -- register a guardian's signed approval.
 *   3. `queryCascadeState` -- query the current state of a cascade.
 *
 * Non-dependency invariant: this module imports only from recovery/*,
 * mesh/guardian/, mesh/canonical-json, mesh/constants, and core/.
 * No Concordia, no Verascore.
 */

import type { GuardianRoster } from "../mesh/guardian/types.js";
import type { RecoveryAction } from "./constants.js";
import {
  beginAwaitingThreshold,
  evaluateCascade,
  executeCascade,
  initiateCascade,
  registerApproval,
} from "./cascade.js";
import {
  evaluateDmswitch,
  emitCascadeEntry,
} from "./dmswitch.js";
import { CascadeStateError } from "./errors.js";
import { evaluateMultiPrincipalBoundary } from "./multi-principal.js";
import type {
  ActivityRecord,
  CascadeState,
  GuardianApproval,
  RecoveryConfig,
  RecoveryEvent,
} from "./types.js";

/**
 * In-memory store for active cascades. Production deployments swap this
 * for an encrypted persistent store (same pattern as Concordia's
 * in-memory session store).
 */
export class RecoveryStore {
  private cascades = new Map<string, CascadeState>();

  get(cascade_id: string): CascadeState | undefined {
    return this.cascades.get(cascade_id);
  }

  set(cascade: CascadeState): void {
    this.cascades.set(cascade.cascade_id, cascade);
  }

  list(): CascadeState[] {
    return Array.from(this.cascades.values());
  }

  listActive(): CascadeState[] {
    return this.list().filter(
      (c) => c.state !== "completed" && c.state !== "failed"
    );
  }
}

/**
 * Recovery service context.
 */
export interface RecoveryServiceContext {
  fortress_id: string;
  emitter_node: string;
  emitter_principal: string;
  node_signing_key: Uint8Array;
  roster: GuardianRoster;
  config: RecoveryConfig;
  store: RecoveryStore;
}

/**
 * Initialize a recovery cascade.
 *
 * If `dmswitch_trigger` is provided, validates that the operator absence
 * window has expired before initiating. Otherwise, initiates a manual
 * (guardian-requested) recovery.
 */
export function initRecovery(params: {
  ctx: RecoveryServiceContext;
  action: RecoveryAction;
  last_activity?: ActivityRecord;
}): { cascade: CascadeState; entry_event?: RecoveryEvent } {
  let entry_event: RecoveryEvent | undefined;

  const dmswitchTrigger = params.last_activity
    ? {
        last_activity: params.last_activity,
        config: params.ctx.config.dmswitch,
      }
    : undefined;

  // If DMswitch-initiated, emit cascade entry event.
  if (params.last_activity) {
    const evaluation = evaluateDmswitch({
      last_activity: params.last_activity,
      config: params.ctx.config.dmswitch,
    });
    if (evaluation.triggered) {
      entry_event = emitCascadeEntry({
        last_activity: params.last_activity,
        config: params.ctx.config.dmswitch,
        fortress_id: params.ctx.fortress_id,
        emitter_node: params.ctx.emitter_node,
        emitter_principal: params.ctx.emitter_principal,
        signing_key: params.ctx.node_signing_key,
      });
    }
  }

  let cascade = initiateCascade({
    action: params.action,
    fortress_id: params.ctx.fortress_id,
    roster: params.ctx.roster,
    dmswitch_trigger: dmswitchTrigger,
  });

  cascade = beginAwaitingThreshold(cascade);

  if (entry_event) {
    cascade = { ...cascade, events: [...cascade.events, entry_event] };
  }

  params.ctx.store.set(cascade);
  return { cascade, entry_event };
}

/**
 * Register a guardian's signed approval toward the M-of-N threshold.
 *
 * After registration, re-evaluates the cascade. If threshold is met,
 * also runs the multi-principal boundary check.
 */
export function registerGuardianApproval(params: {
  ctx: RecoveryServiceContext;
  cascade_id: string;
  approval: GuardianApproval;
}): {
  cascade: CascadeState;
  threshold_met: boolean;
  boundary_result?: ReturnType<typeof evaluateMultiPrincipalBoundary>;
} {
  let cascade = params.ctx.store.get(params.cascade_id);
  if (!cascade) {
    throw new CascadeStateError(
      `cascade ${params.cascade_id} not found`
    );
  }

  cascade = registerApproval(cascade, params.approval);
  cascade = evaluateCascade(cascade, params.ctx.roster);

  let boundary_result: ReturnType<typeof evaluateMultiPrincipalBoundary> | undefined;

  if (cascade.state === "threshold_met") {
    boundary_result = evaluateMultiPrincipalBoundary({
      agent_id: `recovery:${cascade.cascade_id}`,
      recovery_action: cascade.action,
      cascade_state: cascade,
      guardian_roster: params.ctx.roster,
    });
  }

  params.ctx.store.set(cascade);

  return {
    cascade,
    threshold_met: cascade.state === "threshold_met",
    boundary_result,
  };
}

/**
 * Query the current state of a cascade.
 */
export function queryCascadeState(params: {
  ctx: RecoveryServiceContext;
  cascade_id: string;
}): CascadeState | undefined {
  return params.ctx.store.get(params.cascade_id);
}

/**
 * Execute a cascade whose threshold has been met.
 */
export async function executeRecovery(params: {
  ctx: RecoveryServiceContext;
  cascade_id: string;
  executor: (cascade: CascadeState) => Promise<void>;
}): Promise<CascadeState> {
  const cascade = params.ctx.store.get(params.cascade_id);
  if (!cascade) {
    throw new CascadeStateError(
      `cascade ${params.cascade_id} not found`
    );
  }

  const result = await executeCascade({
    cascade,
    roster: params.ctx.roster,
    executor: params.executor,
    emitter_node: params.ctx.emitter_node,
    emitter_principal: params.ctx.emitter_principal,
    signing_key: params.ctx.node_signing_key,
  });

  params.ctx.store.set(result);
  return result;
}
