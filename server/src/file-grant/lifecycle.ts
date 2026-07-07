/**
 * Governed File-Grant v1 -- pure lifecycle transitions (build spec section 6).
 *
 * Every transition here is a pure function of `(grant, now)` (or a duration).
 * Expiry is COMPUTED, never a wall-clock timer: nothing in this module
 * schedules a callback or sleeps. This satisfies the "soaks-are-fake-without-
 * users" discipline -- there is no wall-clock gate to fake in the first
 * place, so deterministic tests just pass different `now` values.
 */

import type { FileGrant, FileGrantEnforcement, FileGrantStatus } from "./types.js";

/**
 * Pure honesty verdict for a grant's enforcement, given the resolved uids and
 * whether an agent-uid readability probe has actually confirmed access. This
 * is the single place the `met`/`unverified`/`unmet` decision is made, so the
 * "never overclaim from a uid-split alone" rule (Invariant #5, build spec
 * section 10) is enforced in ONE testable function rather than scattered
 * comparisons.
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
 *   (configured; on-hardware read-scope not yet verified -- the deferred
 *   drill). v1's autonomous path always lands here for a uid split.
 * - a real, distinct boundary AND `readVerified` -> `met`.
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
 */
export function isGrantExpired(grant: FileGrant, now: Date): boolean {
  if (grant.status === "revoked") return false;
  if (grant.expires_at === null) return false;
  return new Date(grant.expires_at).getTime() <= now.getTime();
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
