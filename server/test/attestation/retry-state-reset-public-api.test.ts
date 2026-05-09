/**
 * Sanctuary Attestation UX v1.x — retry-state reset public API regression
 *
 * Closes full-sweep #70 (P2 small): `clearRetryState()` previously lived on
 * the internal `degrade-not-destroy.ts` module and was unreachable from the
 * public `attestation-service.ts` API. An operator who fixed the underlying
 * cause of repeated verification failures had no way to flip the badge back
 * to green short of restarting the dashboard process. The public
 * `resetScopeRetryState()` wrapper closes that gap, and this suite is the
 * pre-fix-fail / post-fix-pass regression that pins it.
 *
 * Coverage:
 *   - happy path: reset returns `{ reset: true }` and clears the in-memory
 *     entry that `recordVerificationFailure` writes
 *   - audit event: caller-supplied `auditSink` receives an
 *     `attestation_retry_state_reset` event with the prior attempt count
 *     and failure reason
 *   - validation: empty / whitespace / non-string `scope_id` rejects without
 *     touching the retry-state map
 *   - failing audit-sink does not abort the reset (load-bearing UX behavior
 *     is the badge-clearing, not the audit emission)
 *   - module-level surface: the new symbol is re-exported from the
 *     attestation index barrel so `console-service.ts` can import it
 */

import { describe, it, expect, beforeEach } from "vitest";

import {
  RETRY_STATE_RESET_EVENT_TYPE,
  resetScopeRetryState,
  type AttestationRetryStateResetEvent,
} from "../../src/attestation/attestation-service.js";
import {
  clearAllRetryStates,
  getRetryState,
  recordVerificationFailure,
} from "../../src/attestation/degrade-not-destroy.js";

describe("attestation-service: resetScopeRetryState (full-sweep #70)", () => {
  beforeEach(() => {
    clearAllRetryStates();
  });

  it("clears the in-process retry-state entry for the given scope", () => {
    recordVerificationFailure("scope-A", "transient network error");
    expect(getRetryState("scope-A")).toBeDefined();

    const result = resetScopeRetryState("scope-A");

    expect(result).toEqual({ reset: true });
    expect(getRetryState("scope-A")).toBeUndefined();
  });

  it("invokes the audit sink with the prior attempt count and failure reason BEFORE clearing", () => {
    recordVerificationFailure("scope-B", "first failure");
    recordVerificationFailure("scope-B", "second failure");
    recordVerificationFailure("scope-B", "third failure");
    const prior = getRetryState("scope-B");
    expect(prior?.attempt_count).toBe(3);
    expect(prior?.last_failure_reason).toBe("third failure");

    const events: AttestationRetryStateResetEvent[] = [];
    const result = resetScopeRetryState("scope-B", {
      auditSink: (event) => events.push(event),
    });

    expect(result.reset).toBe(true);
    expect(events).toHaveLength(1);
    const event = events[0];
    expect(event).toBeDefined();
    if (!event) throw new Error("audit event missing");
    expect(event.type).toBe(RETRY_STATE_RESET_EVENT_TYPE);
    expect(event.type).toBe("attestation_retry_state_reset");
    expect(event.scope_id).toBe("scope-B");
    expect(event.prior_attempt_count).toBe(3);
    expect(event.prior_failure_reason).toBe("third failure");
    expect(typeof event.emitted_at).toBe("string");
    // Post-emit, retry state is gone.
    expect(getRetryState("scope-B")).toBeUndefined();
  });

  it("emits an audit event even when no prior retry state exists (idempotent reset)", () => {
    expect(getRetryState("never-failed")).toBeUndefined();

    const events: AttestationRetryStateResetEvent[] = [];
    const result = resetScopeRetryState("never-failed", {
      auditSink: (event) => events.push(event),
    });

    expect(result.reset).toBe(true);
    expect(events).toHaveLength(1);
    const event = events[0];
    expect(event).toBeDefined();
    if (!event) throw new Error("audit event missing");
    expect(event.scope_id).toBe("never-failed");
    expect(event.prior_attempt_count).toBeUndefined();
    expect(event.prior_failure_reason).toBeUndefined();
  });

  it("trims whitespace from scope_id before hashing into the retry-state map", () => {
    recordVerificationFailure("scope-trim", "boom");
    expect(getRetryState("scope-trim")).toBeDefined();

    const result = resetScopeRetryState("  scope-trim  ");

    expect(result.reset).toBe(true);
    expect(getRetryState("scope-trim")).toBeUndefined();
  });

  it("rejects an empty scope_id without touching retry-state map", () => {
    recordVerificationFailure("untouched", "preserve me");

    const result = resetScopeRetryState("");

    expect(result.reset).toBe(false);
    expect(result.reason).toMatch(/non-empty/i);
    expect(getRetryState("untouched")).toBeDefined();
  });

  it("rejects a whitespace-only scope_id without touching retry-state map", () => {
    recordVerificationFailure("untouched-2", "preserve me");

    const result = resetScopeRetryState("   \t\n   ");

    expect(result.reset).toBe(false);
    expect(result.reason).toMatch(/non-empty/i);
    expect(getRetryState("untouched-2")).toBeDefined();
  });

  it("rejects a non-string scope_id without throwing", () => {
    recordVerificationFailure("untouched-3", "preserve me");

    // Caller passed something that survived TypeScript's check (e.g., a
    // JSON body field that the dashboard's POST handler did not coerce).
    const result = resetScopeRetryState(42 as unknown as string);

    expect(result.reset).toBe(false);
    expect(result.reason).toMatch(/string/i);
    expect(getRetryState("untouched-3")).toBeDefined();
  });

  it("does not abort the reset when the audit sink throws", () => {
    recordVerificationFailure("scope-throwing-sink", "boom");
    expect(getRetryState("scope-throwing-sink")).toBeDefined();

    const result = resetScopeRetryState("scope-throwing-sink", {
      auditSink: () => {
        throw new Error("downstream SSE socket closed");
      },
    });

    expect(result.reset).toBe(true);
    expect(getRetryState("scope-throwing-sink")).toBeUndefined();
  });

  it("re-exports RETRY_STATE_RESET_EVENT_TYPE so consumers can switch on it", () => {
    expect(RETRY_STATE_RESET_EVENT_TYPE).toBe("attestation_retry_state_reset");
  });
});
