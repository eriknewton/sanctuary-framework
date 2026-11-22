/** This module owns the error brand; it is never registered globally. */
export const ORIGIN_UNRESOLVED_BRAND: unique symbol = Symbol("origin-unresolved");

/**
 * A state write whose origin cannot be determined fails, and stores nothing.
 * The producer must match resolveStateWriteOrigin in cognitive/tools.ts.
 */
export class OriginUnresolvedError extends Error {
  constructor(options?: { cause?: unknown }) {
    // The message is fixed and operator-side; the agent sees only the router's one refusal.
    super("write origin could not be determined", options);
    this.name = "OriginUnresolvedError";
    // The type brand must match isOriginUnresolvedError below.
    Object.defineProperty(this, ORIGIN_UNRESOLVED_BRAND, { value: true });
  }
}

/** The producer must match OriginUnresolvedError above. */
export function isOriginUnresolvedError(error: unknown): boolean {
  // A type brand identifies the error, never message text.
  return typeof error === "object" && error !== null
    && (error as { [ORIGIN_UNRESOLVED_BRAND]?: unknown })[ORIGIN_UNRESOLVED_BRAND] === true;
}
