/**
 * Sanctuary Agent Contract v0.1 — Capability Runtime Enforcement (§2.4).
 *
 * Every harness-initiated action is checked against the Agent Card's declared
 * capabilities BEFORE execution. Undeclared capabilities fail closed at the
 * broker with `CapabilityUndeclaredError`.
 *
 * Matching rules:
 * - `kind` must match exactly.
 * - `target` supports exact match and prefix wildcard (`prefix*`) per spec
 *   §3. Prefix-match is the only wildcard form at v0.1; infix / regex are
 *   deferred to v1.x so an auditor can enumerate reachable targets
 *   statically.
 * - If a capability has `constraints.per_day_max` (integer), the enforcer
 *   tracks per-day usage in a caller-provided counter and rejects once the
 *   cap is reached. No counter ⇒ no cap.
 *
 * Capability extensions (Agent Card amendment mid-launch) are themselves
 * gated by the policy engine — see spec §2.4. This module intentionally does
 * NOT implement extension; a new card must be issued to change the
 * capability set.
 */

import {
  CAPABILITY_KINDS,
  type CapabilityKind,
} from "./constants.js";
import { CapabilityUndeclaredError } from "./errors.js";
import type { AgentCard, AgentCardCapability } from "./types.js";

export interface CapabilityCounter {
  /** Read the current count of uses today (UTC day) for an agent+capability. */
  read(agent_id: string, capability_index: number, utc_day: string): number;
  /** Increment and return the new count. */
  increment(
    agent_id: string,
    capability_index: number,
    utc_day: string
  ): number;
}

/**
 * Default in-memory counter — process-local. Production wires a persistent
 * store keyed on (agent_id, card_hash, utc_day). The counter must survive
 * restarts to honor per-day caps; in-memory is a testing default only.
 */
export class InMemoryCapabilityCounter implements CapabilityCounter {
  private counts = new Map<string, number>();

  private key(agent_id: string, i: number, utc_day: string): string {
    return `${agent_id}|${i}|${utc_day}`;
  }

  read(agent_id: string, capability_index: number, utc_day: string): number {
    return this.counts.get(this.key(agent_id, capability_index, utc_day)) ?? 0;
  }

  increment(
    agent_id: string,
    capability_index: number,
    utc_day: string
  ): number {
    const k = this.key(agent_id, capability_index, utc_day);
    const next = (this.counts.get(k) ?? 0) + 1;
    this.counts.set(k, next);
    return next;
  }
}

export interface CapabilityCheckParams {
  card: AgentCard;
  attempted_kind: CapabilityKind;
  attempted_target: string;
  counter?: CapabilityCounter;
  now?: () => Date;
}

export interface CapabilityCheckResult {
  capability_index: number;
  matched: AgentCardCapability;
  /** The UTC-day key used for rate-limit bookkeeping. */
  utc_day: string;
  /** New count after this check — undefined if no counter. */
  new_count?: number;
}

/** UTC day in `YYYY-MM-DD` form, per-agent rate limit bucket. */
function utcDay(now: Date): string {
  return now.toISOString().slice(0, 10);
}

function matchesTarget(cap_target: string, attempted: string): boolean {
  if (cap_target === attempted) return true;
  if (cap_target.endsWith("*")) {
    const prefix = cap_target.slice(0, -1);
    return attempted.startsWith(prefix);
  }
  return false;
}

/**
 * Check that `attempted_kind` + `attempted_target` are declared on the card.
 * Throws CapabilityUndeclaredError on mismatch. Returns the matched
 * capability index for audit linking.
 *
 * If a counter is supplied and the matched capability has a
 * `constraints.per_day_max` integer, the check increments the counter and
 * rejects once the cap is reached. The counter is read-then-increment; the
 * cap check uses the NEW count (post-increment) so "max 5" means you can do
 * it 5 times per day.
 */
export function enforceCapability(
  params: CapabilityCheckParams
): CapabilityCheckResult {
  if (!(CAPABILITY_KINDS as readonly string[]).includes(params.attempted_kind)) {
    throw new CapabilityUndeclaredError(
      params.card.agent_id,
      params.attempted_kind,
      params.attempted_target
    );
  }
  const now = (params.now ?? (() => new Date()))();
  const day = utcDay(now);

  let matchedIndex = -1;
  for (let i = 0; i < params.card.capabilities.length; i++) {
    const c = params.card.capabilities[i];
    if (
      c.kind === params.attempted_kind &&
      matchesTarget(c.target, params.attempted_target)
    ) {
      matchedIndex = i;
      break;
    }
  }

  if (matchedIndex === -1) {
    throw new CapabilityUndeclaredError(
      params.card.agent_id,
      params.attempted_kind,
      params.attempted_target
    );
  }

  const matched = params.card.capabilities[matchedIndex];
  let new_count: number | undefined;
  if (params.counter) {
    const cap = matched.constraints?.per_day_max;
    if (typeof cap === "number" && Number.isInteger(cap) && cap >= 0) {
      const candidate = params.counter.increment(
        params.card.agent_id,
        matchedIndex,
        day
      );
      if (candidate > cap) {
        throw new CapabilityUndeclaredError(
          params.card.agent_id,
          params.attempted_kind,
          `${params.attempted_target} (per_day_max=${cap} exhausted)`
        );
      }
      new_count = candidate;
    }
  }

  return {
    capability_index: matchedIndex,
    matched,
    utc_day: day,
    ...(new_count !== undefined ? { new_count } : {}),
  };
}

/**
 * Dry-run capability check — returns boolean rather than throwing. Useful
 * in adapter layers that want to discover undeclared capabilities before
 * forwarding to the broker.
 */
export function hasCapability(
  card: AgentCard,
  attempted_kind: CapabilityKind,
  attempted_target: string
): boolean {
  if (!(CAPABILITY_KINDS as readonly string[]).includes(attempted_kind)) {
    return false;
  }
  return card.capabilities.some(
    (c) =>
      c.kind === attempted_kind && matchesTarget(c.target, attempted_target)
  );
}
