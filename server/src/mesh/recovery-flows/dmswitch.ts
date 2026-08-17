/**
 * DMswitch grace-window helper for the device-recovery ceremony.
 *
 * Spec §9.2 (DMswitch), Architecture Walk Key 13 (recovery cascade), Drew
 * pilot: the 90-day default applies to retail/SMB operators; the 30-day
 * operator-configurable variant exists for MSP client defaults. The Drew
 * client conversation may widen this to 180 days — that surface is explicitly
 * carried as a spawn-time decision in the handoff.
 *
 * The helper decides whether a device-recovery ceremony attempted RIGHT NOW
 * against a known-last-operator-activity timestamp is still inside the grace
 * window. If so, the ceremony returns a `DMswitchGraceWindowActive` error
 * carrying the available_at timestamp + remaining_ms. Outside the window,
 * the ceremony proceeds.
 */

import { parseIsoInstantWithOffset } from "../../core/time.js";
import {
  DEFAULT_DMSWITCH_ABSENCE_MS,
  DEFAULT_DMSWITCH_GRACE_MS,
} from "../guardian/constants.js";
import { DMswitchGraceWindowActive } from "./errors.js";

export interface DMswitchGraceWindowInput {
  /**
   * Strict ISO-8601 timestamp of last operator activity, carrying a MANDATORY
   * `Z` designator or numeric offset (TZ-SIB-01). The offset is required
   * because this stamp is the base of the absence + grace window arithmetic
   * that gates the guardian-revocation path; it must denote ONE absolute
   * instant on every node that evaluates it.
   */
  last_operator_activity_at: string;
  /** Current time — defaults to Date.now(). */
  now_ms?: number;
  /** Absence threshold (default: 90 days). */
  absence_ms?: number;
  /** Grace window (default: 30 days). */
  grace_ms?: number;
  /**
   * If true, the device-recovery ceremony is being driven specifically
   * because the DMswitch has FIRED (via failure-mode detector + operator
   * confirmation); this bypasses the grace check per §3.6.1 (guardian-
   * revocation path is unlocked once the dmswitch fires). Default false
   * so day-one operator recovery hits the grace check.
   */
  dmswitch_already_fired?: boolean;
}

export interface DMswitchGraceWindowEvaluation {
  blocked: boolean;
  available_at?: string;
  remaining_ms?: number;
}

/**
 * Compute whether a ceremony is blocked by the DMswitch grace window.
 */
export function evaluateDMswitchGraceWindow(
  params: DMswitchGraceWindowInput
): DMswitchGraceWindowEvaluation {
  if (params.dmswitch_already_fired === true) {
    return { blocked: false };
  }
  const nowMs = params.now_ms ?? Date.now();
  const absenceMs = params.absence_ms ?? DEFAULT_DMSWITCH_ABSENCE_MS;
  const graceMs = params.grace_ms ?? DEFAULT_DMSWITCH_GRACE_MS;
  // TZ-SIB-01: timestamps entering trust arithmetic carry a mandatory offset;
  // an offset-less stamp is refused (throw, fail-closed — MUST-NEVER #5),
  // never resolved against the reading node's local zone. This window gates
  // the guardian-revocation path, so the stamp must mean one absolute instant
  // fleet-wide.
  const lastActivityMs = parseIsoInstantWithOffset(
    params.last_operator_activity_at
  );
  if (lastActivityMs === undefined) {
    throw new Error(
      `evaluateDMswitchGraceWindow: last_operator_activity_at is not a strict ISO-8601 timestamp with a Z designator or numeric offset: ${params.last_operator_activity_at}`
    );
  }
  const available = lastActivityMs + absenceMs + graceMs;
  if (nowMs >= available) {
    return { blocked: false };
  }
  return {
    blocked: true,
    available_at: new Date(available).toISOString(),
    remaining_ms: available - nowMs,
  };
}

/**
 * Convenience: evaluate + throw if blocked. Used by device-recovery.ts.
 */
export function enforceDMswitchGraceWindow(
  params: DMswitchGraceWindowInput
): void {
  const r = evaluateDMswitchGraceWindow(params);
  if (!r.blocked) return;
  throw new DMswitchGraceWindowActive({
    available_at: r.available_at!,
    remaining_ms: r.remaining_ms!,
  });
}
