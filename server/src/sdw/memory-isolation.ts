/**
 * Multi-agent isolation guard for the shared SDW memory owner scope.
 *
 * The SDW memory adapter wired in index.ts is bound to ONE `fleet-self` owner
 * scope reused for every caller, so SDW memory has no per-agent custody
 * isolation yet. This guard pins the single wrapped-agent identity the shared
 * scope is bound to and REFUSES any second, distinct identity, until real
 * per-agent isolation (deriving owner_ref from the caller) lands.
 *
 * It lives in its own file because EVERY tool family that reaches the shared
 * scope has to share ONE guard instance. Two guards over the same scope each
 * pin their own first caller, so a second agent refused by one family would
 * still be the first caller of the other and get through it. Read paths and
 * bulk plaintext export paths are the same custody question.
 */

/**
 * Strictly additive and fail closed:
 * - No `ownerIdentity` resolver -> no second identity can ever be observed ->
 *   the guard is a strict NO-OP (existing single-agent behavior unchanged).
 * - A single coordinator resolves a stable value (or a stable `undefined`);
 *   the bound identity is pinned once and every call matches it -> NO-OP.
 * - Any call whose resolved identity differs from the pinned one is REFUSED.
 *   The pin is NOT advanced to the new identity, so the guard cannot be walked
 *   forward by alternating callers; the shared scope stays bound to whoever
 *   touched it first.
 *
 * `undefined` is treated as a concrete identity value (the "no wrapped-agent
 * id configured" caller). Mixing a concrete id with `undefined` is therefore
 * two distinct identities and is refused: a configured agent must not share
 * the unconfigured coordinator's scope.
 */
export type MultiAgentIsolationGuard = (
  operation: string,
) => { allowed: true } | { allowed: false };

export function createMultiAgentIsolationGuard(
  ownerIdentity: (() => string | undefined) | undefined,
): MultiAgentIsolationGuard {
  // Sentinel so we can distinguish "never observed an identity" from "observed
  // `undefined`" without conflating the two.
  let bound: { value: string | undefined } | null = null;
  return (_operation: string) => {
    if (ownerIdentity === undefined) {
      // No resolver wired: a second identity can never be observed. NO-OP.
      return { allowed: true };
    }
    const observed = ownerIdentity();
    if (bound === null) {
      bound = { value: observed };
      return { allowed: true };
    }
    return bound.value === observed ? { allowed: true } : { allowed: false };
  };
}
