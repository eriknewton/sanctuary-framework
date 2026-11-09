/**
 * The one record-clock rule every liveness reader applies to a stored time
 * pair (UTC and uptime) from the current boot: the envelope records in the
 * evaluator and each census sample nested inside the observer record. It is
 * pure and imports no filesystem, network or process module, so it ships in the
 * contract bundle.
 */
import { parseIsoInstantWithOffset } from "../../core/time.js";
import { LOCAL_JITTER } from "./constants.js";

export type Timing = { ok: true; ageMs: number } | { ok: false };

/**
 * Age of a current-boot record from both clocks. A UTC time more than
 * LOCAL_JITTER in the future, a negative uptime age, or a UTC age and uptime age
 * that diverge by more than LOCAL_JITTER is untrusted: within one boot the two
 * clocks progress together, so a larger gap means one of them moved, and a
 * fresh wrapper never makes an inconsistent nested time trustworthy.
 */
export function recordTiming(observedAt: string, observedUptimeMs: number, nowMs: number, uptimeMs: number): Timing {
  // Timestamps entering freshness arithmetic go through the one strict instant predicate; an unparsable time is untrusted.
  const utcAge = nowMs - (parseIsoInstantWithOffset(observedAt) ?? Number.NaN);
  const uptimeAge = uptimeMs - observedUptimeMs;
  if (!Number.isFinite(utcAge) || utcAge < -LOCAL_JITTER || uptimeAge < 0) return { ok: false };
  if (Math.abs(utcAge - uptimeAge) > LOCAL_JITTER) return { ok: false };
  return { ok: true, ageMs: Math.max(0, utcAge, uptimeAge) };
}
