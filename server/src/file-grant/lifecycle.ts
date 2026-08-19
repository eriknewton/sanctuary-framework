/**
 * Governed File-Grant v1 -- pure lifecycle transitions (build spec section 6).
 *
 * Every transition here is a pure function of `(grant, now)` (or a duration).
 * Expiry is COMPUTED, never a wall-clock timer: nothing in this module
 * schedules a callback or sleeps. This satisfies the "soaks-are-fake-without-
 * users" discipline -- there is no wall-clock gate to fake in the first
 * place, so deterministic tests just pass different `now` values.
 */

import { parseIsoInstantWithOffset } from "../core/time.js";
import type { FileGrant, FileGrantEnforcement, FileGrantStatus } from "./types.js";

/**
 * Pure honesty verdict for a grant's enforcement, given the resolved uids and
 * whether an agent-uid readability probe has actually confirmed a read through
 * the grant tree. This is the single place the `met`/`unverified`/`unmet`
 * decision is made, so the "never overclaim from a uid-split alone" rule
 * (Invariant #5, build spec section 10) is enforced in ONE testable function
 * rather than scattered comparisons. POSIX ACL read is inode-scoped, not
 * grant-tree-only; in the confined model the grant tree is the reachable path.
 *
 * - `agentUid === null`                    -> `unmet` (no dedicated agent
 *   account on this host, nothing to enforce with).
 * - `sourceOwnerUid === null`              -> `unmet` (cannot establish a
 *   boundary without knowing who owns the source).
 * - `agentUid === sourceOwnerUid`          -> `unmet` (the agent uid already
 *   owns / can read the source; the grant confers nothing new, so there is no
 *   boundary to enforce). This is the case a `sudo` mint would otherwise
 *   falsely report as enforced if the comparison used `process.getuid()`.
 * - a real, distinct boundary but NOT `readVerified` -> `unverified`
 *   (configured, but a read through the grant tree was not confirmed in this
 *   operation).
 * - a real, distinct boundary AND `readVerified` -> `met` (confirmed read
 *   through the grant tree).
 */
export function determineEnforcement(params: {
  agentUid: number | null;
  sourceOwnerUid: number | null;
  readVerified: boolean;
}): FileGrantEnforcement {
  const { agentUid, sourceOwnerUid, readVerified } = params;
  if (agentUid === null || sourceOwnerUid === null) return "unmet";
  if (agentUid === sourceOwnerUid) return "unmet";
  return readVerified ? "met" : "unverified";
}

const DURATION_RE = /^(\d+)([smhd])$/;

/**
 * Parse a duration string like "30s", "5m", "24h", "7d" into seconds.
 * Mirrors the shape of `parseLeaseTtlSeconds` in cli/castle-wall.ts (the
 * dead-man TTL precedent cited by the build spec) with a "d" unit added,
 * since a box-local file grant's natural TTL horizon is days, not seconds.
 */
export function parseFileGrantTtlDuration(value: string): number {
  const match = DURATION_RE.exec(value);
  if (!match) {
    throw new Error(
      `Invalid TTL duration "${value}". Use a form like 30s, 5m, 24h, or 7d.`
    );
  }
  const amount = Number(match[1]);
  const unit = match[2]!;
  const multiplier =
    unit === "s" ? 1 : unit === "m" ? 60 : unit === "h" ? 3600 : 86400;
  return amount * multiplier;
}

/**
 * Compute `expires_at` from a TTL in seconds (or `null` for a standing
 * grant) relative to `now`. Pure: no `Date.now()` call inside.
 */
export function computeExpiresAt(
  ttlSeconds: number | null,
  now: Date
): string | null {
  if (ttlSeconds === null) return null;
  return new Date(now.getTime() + ttlSeconds * 1000).toISOString();
}

/**
 * Whether a grant's expiry has passed at `now`. A `null` `expires_at`
 * (standing grant) never expires. A grant already marked `revoked` is not
 * additionally "expired" -- revoked is a distinct terminal state.
 *
 * AN UNPARSEABLE `expires_at` COUNTS AS EXPIRED, and that direction is the
 * whole point. `expires_at` is typed `string | null`, but the record is read
 * back from stored JSON, so the field holds whatever was written there. A
 * value that is not a date yields `NaN` from `Date.getTime()`, and every
 * comparison against `NaN` is false -- so the obvious spelling,
 * `new Date(...).getTime() <= now.getTime()`, answers "not expired" for a
 * grant whose expiry cannot be read at all.
 *
 * That answer is silent and it fails OPEN. The reconcile pass scrubs on this
 * verdict, so a grant with a garbled expiry keeps its tree entry, and on a
 * uid-split box the agent keeps filesystem read access, indefinitely. The pass
 * reports `{expired: [], scrubbed: []}` and exits zero, because from its point
 * of view nothing was due. Nothing is logged, because nothing failed.
 *
 * Treating it as expired inverts that: the entry is scrubbed and the record is
 * flipped, which is an access REDUCTION and the safe direction for a value
 * nobody can interpret. A standing grant is spelled `null` and is unaffected;
 * only a present-but-unreadable value takes this path.
 *
 * A NaN CHECK IS NOT ENOUGH, and this is the part that matters. `new Date(x)`
 * does not merely fail on garbage, it COERCES: a bare number becomes an epoch
 * offset, an array becomes its `toString`, `"2999"` becomes a year, and
 * `"2026-08-18T00:00:00"` with no offset is interpreted in the HOST's local
 * zone, so the same stored record expires in one timezone and not in another.
 * Every one of those yields a valid FUTURE date, sails past a NaN test, and
 * preserves access exactly as before. Fail-closed on NaN alone closes the
 * loudest case and leaves the class open.
 *
 * So the value is parsed rather than coerced, through the repository's shared
 * canonical parser, which requires a full ISO 8601 instant WITH an explicit
 * offset and a finite result. Anything else, including a non-string, is
 * unreadable and therefore expired.
 *
 * THE THREAT MODEL, because it decides how strict this has to be: the danger is
 * CORRUPTION, not an adversarial choice of date. Anyone able to write
 * `expires_at` can write a well-formed far-future value and keep access that
 * way, so refusing non-canonical spellings buys nothing against a writer. What
 * this defends is that a value nobody can READ must not silently mean "never
 * expires". An impossible calendar date (`2999-02-30`, which the engine would
 * normalise to March 2) is in that class and is REFUSED by the shared parser
 * (FG-EXPIRY-CALENDAR-01): the shipping mint path only ever writes
 * `toISOString` output, so no legitimate grant carries February 30, and a
 * record that does is detectable corruption whose normalisation preserved
 * access past the date actually written. Refusal routes through the same
 * fail-closed branch as any other unreadable expiry: the grant expires.
 *
 * Deliberately NOT solved by refusing the record at the store's decode. On this
 * branch a `JSON.parse` failure is not caught per record, so the listing aborts
 * and EVERY entry is left untouched, which is the fail-open outcome again and
 * at a wider blast radius than one record.
 */
export function isGrantExpired(grant: FileGrant, now: Date): boolean {
  if (grant.status === "revoked") return false;
  if (grant.expires_at === null) return false;
  const expiresAt =
    typeof grant.expires_at === "string"
      ? parseIsoInstantWithOffset(grant.expires_at)
      : undefined;
  if (expiresAt === undefined) return true;
  return expiresAt <= now.getTime();
}

/**
 * Project the EFFECTIVE status of a grant at `now`, without mutating the
 * grant or the store. A persisted "active" grant whose TTL has passed
 * projects as "expired" even before any sweep updates the persisted record;
 * a persisted "revoked" grant stays "revoked" regardless of `now`.
 */
export function projectGrantStatus(
  grant: FileGrant,
  now: Date
): FileGrantStatus {
  if (grant.status === "revoked") return "revoked";
  if (isGrantExpired(grant, now)) return "expired";
  return grant.status;
}

/**
 * Pure transition: mark a grant revoked at `now`. Idempotent -- revoking an
 * already-revoked grant returns an equivalent object (the original
 * `revoked_at` is preserved, never overwritten by a later revoke call), so a
 * caller can safely re-apply this to a grant already in the `revoked` state.
 */
export function reviseGrantForRevoke(grant: FileGrant, now: Date): FileGrant {
  if (grant.status === "revoked") {
    return grant;
  }
  return {
    ...grant,
    status: "revoked",
    revoked_at: now.toISOString(),
  };
}

/**
 * Pure transition: mark a grant expired at `now`. A no-op if the grant is
 * not actually past its TTL, or already revoked (revoked is terminal and
 * takes priority over expiry).
 */
export function reviseGrantForExpiry(grant: FileGrant, now: Date): FileGrant {
  if (grant.status === "revoked") return grant;
  if (!isGrantExpired(grant, now)) return grant;
  if (grant.status === "expired") return grant;
  return {
    ...grant,
    status: "expired",
  };
}
