/**
 * Credential surrogacy: sink-level placeholder redaction.
 *
 * WHAT THIS CLOSES (design v2.1 finding B2-N9). A placeholder is a live bearer
 * surrogate for its generation: anything that can read one can ask the gate to
 * spend the real credential on the bound destination. The agent controls
 * several strings that reach an event sink verbatim, the CONNECT authority
 * (`request.url`) most directly, so an agent can put a placeholder into a log
 * line the operator or root later reads. Redacting at the SINK rather than at
 * each emission site is deliberate: a new event kind added later is covered
 * without its author remembering, and there is one place to test.
 *
 * This is redaction, not validation. It never rejects an event and never
 * throws; a sink that threw would drop the event that was worth keeping.
 */

import { surrogatePlaceholderScanRe } from "./placeholder.js";

/** What a redacted placeholder reads as in a log. Fixed token: a drill greps for it. */
export const SURROGATE_PLACEHOLDER_REDACTION = "<surrogate-placeholder>";

/** Replace every placeholder-shaped substring in one string. */
export function redactSurrogatePlaceholdersInString(value: string): string {
  return value.replace(surrogatePlaceholderScanRe(), SURROGATE_PLACEHOLDER_REDACTION);
}

/**
 * Redact every string reachable from `event`, at any depth, in place-free form.
 *
 * Depth and breadth are bounded by the event shapes themselves (the event types
 * are closed enums of flat records with fixed fields), so this does not need a
 * cap of its own; it does need cycle safety, because a future sink might pass
 * an object that references itself and a log write must not hang.
 */
export function redactSurrogatePlaceholders<T>(event: T): T {
  return redactValue(event, new WeakMap()) as T;
}

function redactValue(value: unknown, seen: WeakMap<object, unknown>): unknown {
  if (typeof value === "string") return redactSurrogatePlaceholdersInString(value);
  if (value === null || typeof value !== "object") return value;
  const existing = seen.get(value as object);
  if (existing !== undefined) return existing;
  if (Array.isArray(value)) {
    const out: unknown[] = [];
    seen.set(value as object, out);
    for (const element of value) out.push(redactValue(element, seen));
    return out;
  }
  const out: Record<string, unknown> = {};
  seen.set(value as object, out);
  for (const [key, element] of Object.entries(value as Record<string, unknown>)) {
    out[key] = redactValue(element, seen);
  }
  return out;
}
