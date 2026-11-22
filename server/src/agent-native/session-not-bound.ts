/** This module owns the error brand; it is never registered globally. */
export const SESSION_NOT_BOUND_BRAND: unique symbol = Symbol("session-not-bound");

/** The producer must match SessionNotBoundError in safety-base.ts. */
export function isSessionNotBoundError(error: unknown): boolean {
  // A type brand chooses the cause, never message text; it affects only the operator ledger label, never what the agent sees.
  return typeof error === "object" && error !== null
    && (error as { [SESSION_NOT_BOUND_BRAND]?: unknown })[SESSION_NOT_BOUND_BRAND] === true;
}
