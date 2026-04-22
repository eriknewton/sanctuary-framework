/**
 * Sanctuary Attestation UX v1.0 -- Degrade-Not-Destroy Logic
 *
 * Cached-badge logic, offline indicator, verification-retry backoff.
 * Design brief section 2, rule 4: "Attestation failure pauses affected
 * agents, marks badges yellow or red, and surfaces remediation options.
 * It never throws a modal, never blocks the rest of the workflow."
 *
 * Structural invariant: no code path in this module throws or halts on
 * a verification failure. Errors are caught and mapped to degraded states.
 */

import { DEGRADE_DEFAULTS, type BadgeStateColor } from "./constants.js";
import type { StoredBadgeState } from "./types.js";

// -----------------------------------------------------------------------
// Retry state tracking
// -----------------------------------------------------------------------

interface RetryState {
  scope_id: string;
  attempt_count: number;
  next_retry_at: number; // epoch ms
  last_failure_reason: string;
}

const retryStates = new Map<string, RetryState>();

// -----------------------------------------------------------------------
// Cached badge logic
// -----------------------------------------------------------------------

/**
 * Mark a stored badge as cached (offline/degraded mode).
 * The cached badge continues to display the last-known-good state.
 */
export function markBadgeCached(stored: StoredBadgeState): StoredBadgeState {
  return {
    ...stored,
    is_cached: true,
    cached_at: new Date().toISOString(),
  };
}

/**
 * Check if a cached badge has expired.
 * Expired cached badges should show "offline" instead of stale data.
 */
export function isCachedBadgeExpired(stored: StoredBadgeState): boolean {
  if (!stored.is_cached || !stored.cached_at) {
    return false;
  }
  const cachedTime = new Date(stored.cached_at).getTime();
  return Date.now() - cachedTime > DEGRADE_DEFAULTS.CACHED_BADGE_TTL_MS;
}

/**
 * Get the display state for a badge, accounting for cache expiry.
 * If cached and expired, returns "offline". Otherwise returns the badge state.
 */
export function getDisplayState(stored: StoredBadgeState): BadgeStateColor {
  if (stored.is_cached && isCachedBadgeExpired(stored)) {
    return "offline";
  }
  return stored.badge.state;
}

// -----------------------------------------------------------------------
// Verification retry with exponential backoff
// -----------------------------------------------------------------------

/**
 * Record a verification failure and compute the next retry time.
 * Returns the retry state so the caller can schedule a retry.
 */
export function recordVerificationFailure(
  scope_id: string,
  reason: string
): RetryState {
  const existing = retryStates.get(scope_id);
  const attempt_count = existing ? existing.attempt_count + 1 : 1;

  const delay = Math.min(
    DEGRADE_DEFAULTS.INITIAL_RETRY_DELAY_MS *
      Math.pow(DEGRADE_DEFAULTS.BACKOFF_MULTIPLIER, attempt_count - 1),
    DEGRADE_DEFAULTS.MAX_RETRY_DELAY_MS
  );

  const state: RetryState = {
    scope_id,
    attempt_count,
    next_retry_at: Date.now() + delay,
    last_failure_reason: reason,
  };

  retryStates.set(scope_id, state);
  return state;
}

/**
 * Check if a scope is ready for retry.
 */
export function isReadyForRetry(scope_id: string): boolean {
  const state = retryStates.get(scope_id);
  if (!state) return true; // No failure recorded, can try
  return Date.now() >= state.next_retry_at;
}

/**
 * Check if maximum retries have been exhausted.
 * After max retries, the badge settles into a steady degraded state.
 */
export function isRetryExhausted(scope_id: string): boolean {
  const state = retryStates.get(scope_id);
  if (!state) return false;
  return state.attempt_count >= DEGRADE_DEFAULTS.MAX_RETRIES;
}

/**
 * Clear retry state for a scope (called on successful verification).
 */
export function clearRetryState(scope_id: string): void {
  retryStates.delete(scope_id);
}

/**
 * Get retry state for a scope.
 */
export function getRetryState(scope_id: string): RetryState | undefined {
  return retryStates.get(scope_id);
}

// -----------------------------------------------------------------------
// Safe execution wrapper (degrade-not-destroy structural enforcement)
// -----------------------------------------------------------------------

/**
 * Execute a verification function with degrade-not-destroy semantics.
 * If the function throws, catch the error and return a degraded badge state.
 * Never re-throws. Never halts.
 *
 * This is the structural enforcement of the degrade-not-destroy invariant.
 */
export function safeVerify<T>(
  scope_id: string,
  fn: () => T,
  fallbackState: BadgeStateColor = "yellow"
): { ok: true; result: T } | { ok: false; state: BadgeStateColor; reason: string } {
  try {
    const result = fn();
    clearRetryState(scope_id);
    return { ok: true, result };
  } catch (err: unknown) {
    const reason =
      err instanceof Error ? err.message : "Unknown verification failure";
    recordVerificationFailure(scope_id, reason);

    // If retries exhausted, settle into degraded steady state
    const state = isRetryExhausted(scope_id) ? "red" : fallbackState;
    return { ok: false, state, reason };
  }
}

// -----------------------------------------------------------------------
// Store management
// -----------------------------------------------------------------------

/** Clear all retry states. Test-only. */
export function clearAllRetryStates(): void {
  retryStates.clear();
}
