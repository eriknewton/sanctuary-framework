/**
 * Recovery Cascade -- Dead-man-switch evaluator.
 *
 * Acceptance criterion 3: DMswitch fires at window. Default 30 days of
 * operator inactivity triggers cascade entry. 90-day estate-planning toggle
 * configurable.
 *
 * Acceptance criterion 9: `max_offline_window` read from fortress config;
 * 30d default, 90d max for estate-planning mode.
 *
 * Acceptance criterion 4 (partial): given the same inputs, any honest
 * node computes the same result (pure functions, no side effects).
 *
 * Key 13 LOCKED: DMswitch only triggers a cascade entry; actual recovery
 * still requires guardian threshold met.
 */

import {
  DEFAULT_DMSWITCH_WINDOW_MS,
  MAX_ESTATE_PLANNING_WINDOW_MS,
  MIN_DMSWITCH_WINDOW_MS,
  RECOVERY_EVENT_TYPES,
} from "./constants.js";
import { RecoveryConfigError, WindowNotExpiredError } from "./errors.js";
import { packRecoveryEvent } from "./recovery-event.js";
import type { ActivityRecord, DmswitchConfig, RecoveryEvent } from "./types.js";

/**
 * Validate a DMswitch configuration.
 */
export function validateDmswitchConfig(config: DmswitchConfig): void {
  // Fail-closed finiteness gate: the window feeds directly into the DMswitch
  // arithmetic (elapsed_ms >= window_ms). A non-finite window (NaN/Infinity) or
  // a below-minimum/zero window would let the switch fire immediately or behave
  // undefined, so reject it here BEFORE any comparison rather than assuming the
  // config was screened upstream. This runs first so the minimum/maximum checks
  // below operate only on finite numbers.
  if (!Number.isFinite(config.max_offline_window_ms)) {
    throw new RecoveryConfigError(
      `max_offline_window_ms must be a finite number; got ${config.max_offline_window_ms}`
    );
  }
  if (config.max_offline_window_ms < MIN_DMSWITCH_WINDOW_MS) {
    throw new RecoveryConfigError(
      `max_offline_window_ms (${config.max_offline_window_ms}) is below the minimum ${MIN_DMSWITCH_WINDOW_MS}ms (7 days)`
    );
  }
  if (
    config.estate_planning_enabled &&
    config.max_offline_window_ms > MAX_ESTATE_PLANNING_WINDOW_MS
  ) {
    throw new RecoveryConfigError(
      `max_offline_window_ms (${config.max_offline_window_ms}) exceeds the estate-planning maximum ${MAX_ESTATE_PLANNING_WINDOW_MS}ms (90 days)`
    );
  }
  if (
    !config.estate_planning_enabled &&
    config.max_offline_window_ms > DEFAULT_DMSWITCH_WINDOW_MS
  ) {
    throw new RecoveryConfigError(
      `max_offline_window_ms (${config.max_offline_window_ms}) exceeds the non-estate default ${DEFAULT_DMSWITCH_WINDOW_MS}ms (30 days); enable estate_planning to use longer windows`
    );
  }
}

/**
 * Record an operator activity tick. Returns a new ActivityRecord.
 * Pure function; caller persists.
 */
export function recordActivity(source: string, now_ms?: number): ActivityRecord {
  const ms = now_ms ?? Date.now();
  return {
    last_activity_at: new Date(ms).toISOString(),
    last_activity_ms: ms,
    source,
  };
}

/**
 * Evaluation result for DMswitch window check.
 */
export interface DmswitchEvaluation {
  /** Whether the window has expired. */
  triggered: boolean;
  /** ms elapsed since last activity. */
  elapsed_ms: number;
  /** Configured window in ms. */
  window_ms: number;
  /** ms remaining until trigger (0 if already triggered). */
  remaining_ms: number;
  /** ISO8601 of when the window expires. */
  expires_at: string;
}

/**
 * Evaluate whether the DMswitch should fire.
 *
 * Pure function. Deterministic given the same inputs (acceptance criterion 4).
 *
 * Activity ticks reset the window; window elapses without ticks,
 * cascade entry emitted.
 */
export function evaluateDmswitch(params: {
  last_activity: ActivityRecord;
  config: DmswitchConfig;
  now_ms?: number;
}): DmswitchEvaluation {
  const now = params.now_ms ?? Date.now();
  const window_ms = params.config.max_offline_window_ms;
  const elapsed_ms = now - params.last_activity.last_activity_ms;
  const remaining_ms = Math.max(0, window_ms - elapsed_ms);
  const expires_at = new Date(
    params.last_activity.last_activity_ms + window_ms
  ).toISOString();

  return {
    triggered: elapsed_ms >= window_ms,
    elapsed_ms,
    window_ms,
    remaining_ms,
    expires_at,
  };
}

/**
 * Enforce that the DMswitch window has expired. Throws WindowNotExpiredError
 * if the window has not elapsed.
 */
export function enforceDmswitchExpired(params: {
  last_activity: ActivityRecord;
  config: DmswitchConfig;
  now_ms?: number;
}): DmswitchEvaluation {
  // Fail-closed shape gate at the enforcement boundary. This is the single
  // chokepoint through which cascade-entry enforcement flows: emitCascadeEntry
  // calls this, and any direct caller of enforceDmswitchExpired also passes
  // here. Validating the config BEFORE evaluateDmswitch closes the malformed-
  // window class (zero/below-minimum/non-finite) on the public event-emission
  // path, so a degenerate window can never make elapsed_ms >= window_ms fire a
  // signed DMSWITCH_CASCADE_ENTRY before the mandatory minimum absence window.
  validateDmswitchConfig(params.config);
  const evaluation = evaluateDmswitch(params);
  if (!evaluation.triggered) {
    throw new WindowNotExpiredError({
      remaining_ms: evaluation.remaining_ms,
      expires_at: evaluation.expires_at,
    });
  }
  return evaluation;
}

/**
 * Emit a cascade-entry recovery event when the DMswitch fires.
 *
 * Caller (the canonical audit node or recovery service) calls this once
 * when `evaluateDmswitch` returns `triggered: true`, then initiates the
 * cascade flow.
 */
export function emitCascadeEntry(params: {
  last_activity: ActivityRecord;
  config: DmswitchConfig;
  fortress_id: string;
  emitter_node: string;
  emitter_principal: string;
  signing_key: Uint8Array;
  now_ms?: number;
}): RecoveryEvent {
  const evaluation = enforceDmswitchExpired({
    last_activity: params.last_activity,
    config: params.config,
    now_ms: params.now_ms,
  });

  return packRecoveryEvent({
    event_type: RECOVERY_EVENT_TYPES.DMSWITCH_CASCADE_ENTRY,
    fortress_id: params.fortress_id,
    emitter_node: params.emitter_node,
    emitter_principal: params.emitter_principal,
    payload: {
      last_activity_at: params.last_activity.last_activity_at,
      triggered_at: new Date(params.now_ms ?? Date.now()).toISOString(),
      window_ms: evaluation.window_ms,
      elapsed_ms: evaluation.elapsed_ms,
      estate_planning_enabled: params.config.estate_planning_enabled,
    },
    signing_key: params.signing_key,
  });
}
