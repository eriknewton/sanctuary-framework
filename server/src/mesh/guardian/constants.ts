/**
 * Sanctuary Federation Protocol v0.1 — Guardian + Recovery Cascade Constants
 *
 * Per Architecture Walk Key 13 LOCKED + spec §9: M-of-N guardian quorum with
 * default 3-of-5. Configurable; v1.0 ships defaults only.
 *
 * `kind` enumerations are deliberately small: `human` and `sanctuary_operated`
 * at v1.0. Institutional crypto-custody (Casa / Coinbase Custody / Anchorage /
 * BitGo / Fireblocks) is reserved for v1.x partnership work and intentionally
 * NOT named in any committed v1.0 artifact (naming-discipline rule).
 *
 * HKDF info strings here intentionally differ from those in mesh/constants.ts
 * and lifecycle/constants.ts so guardian-derived material is independent of
 * transport / audit-chain / node-key-wrap material.
 */

/** v1.0 default M (signatures required for quorum). */
export const DEFAULT_GUARDIAN_M = 3;
/** v1.0 default N (total guardians on the roster). */
export const DEFAULT_GUARDIAN_N = 5;

/**
 * Guardian-roster version is monotonic per fortress. Receivers pin the highest
 * version seen and reject older versions on receipt (replay-of-old-roster
 * protection).
 */
export const GUARDIAN_ROSTER_INITIAL_VERSION = 1;

/**
 * Allowed `kind` values at v1.0. Reserved slot for v1.x institutional-custody
 * adapter exists in the type but is not enumerated as a string literal here so
 * that v1.0 emitters cannot accidentally ship a v1.x-only kind.
 */
export const GUARDIAN_KINDS_V1_0 = ["human", "sanctuary_operated"] as const;
export type GuardianKindV1 = (typeof GUARDIAN_KINDS_V1_0)[number];

/**
 * v1.0 emitter check — returns true if the kind is permitted at v1.0.
 * v1.0 verifiers tolerate unknown kinds (forward-compat for v1.x); only the
 * issuance path enforces this.
 */
export function isV10GuardianKind(s: string): s is GuardianKindV1 {
  return (GUARDIAN_KINDS_V1_0 as readonly string[]).includes(s);
}

/**
 * Default canonical-audit-loss grace window before the operator is asked to
 * promote a replica. Spec §8.5: 24 hours past the heartbeat-miss threshold.
 */
export const DEFAULT_CANONICAL_AUDIT_LOSS_GRACE_MS = 24 * 60 * 60 * 1000;

/**
 * Default DMswitch operator-absence threshold + grace window per Key 13 lock.
 * Operator absent for 90 days, then a 30-day grace window before the canonical
 * audit node generates `dmswitch_triggered`.
 *
 * v1.x adds a multi-condition power-user grammar (research ticket carried
 * separately); v1.0 ships defaults only.
 */
export const DEFAULT_DMSWITCH_ABSENCE_MS = 90 * 24 * 60 * 60 * 1000;
export const DEFAULT_DMSWITCH_GRACE_MS = 30 * 24 * 60 * 60 * 1000;
