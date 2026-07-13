/**
 * Governed File-Grant v1 -- grant-tree reconcile (build spec sections 6-7).
 *
 * This is the step that makes the pure `planGrantTree` planner LOAD-BEARING at
 * runtime and gives the TTL real teeth: without it, an expired grant's tree
 * entry lingers on disk (on a uid-split box, agent read access would outlive
 * the stated TTL) and `list` would only PROJECT "expired" for display while
 * the persisted record still said "active".
 *
 * `reconcileFileGrantTree`:
 *   1. loads the live grant set,
 *   2. computes the desired tree contents with `planGrantTree` (the same pure
 *      planner unit-tested with fixtures),
 *   3. flips every persisted `active` grant whose TTL has passed to `expired`
 *      via the pure `reviseGrantForExpiry` transition, and
 *   4. scrubs every tree entry the plan says must not be present (revoked +
 *      expired grants), idempotently (a revoke already scrubbed its own entry;
 *      re-scrubbing an absent entry is a no-op).
 *
 * It is wired into the mutating CLI touches (mint / revoke), so ordinary use
 * keeps the tree converged; it is also exported standalone for a future
 * `file-grant sweep` / cron. It never PLACES entries (v1 only places at mint),
 * so it can only ever REDUCE access -- safe to run on any touch.
 */

import type { AuditLog } from "../operational/audit-log.js";
import { isGrantExpired, reviseGrantForExpiry } from "./lifecycle.js";
import { planGrantTree } from "./planner.js";
import type { FileGrant, FileGrantAclRemovalResult, FsOps } from "./types.js";

export interface ReconcileFileGrantStore {
  list(): Promise<FileGrant[]>;
  put(grant: FileGrant): Promise<void>;
}

export interface ReconcileFileGrantDeps {
  store: ReconcileFileGrantStore;
  fsOps: Pick<FsOps, "removeEntry">;
  /** Injected clock reading. Never `new Date()` inside this module. */
  now: Date;
  auditLog?: AuditLog;
  /** Identity recorded on the expiry audit entries. Defaults to "system". */
  reconciledBy?: string;
}

export interface ReconcileFileGrantResult {
  /** grant ids whose persisted status was flipped active -> expired. */
  expired: string[];
  /** relative tree entries that were scrubbed (revoked or expired grants). */
  scrubbed: string[];
}

export async function reconcileFileGrantTree(
  deps: ReconcileFileGrantDeps
): Promise<ReconcileFileGrantResult> {
  const grants = await deps.store.list();
  const plan = planGrantTree(grants, deps.now);
  const grantsById = new Map(grants.map((grant) => [grant.grant_id, grant]));

  // SAFETY-CRITICAL, FIRST: scrub every tree entry the plan says must not be
  // present (revoked + expired grants). Removing access is the safety-critical
  // action; the persisted-status flip below is only bookkeeping. So the scrub
  // runs FIRST and INDEPENDENTLY of the status write -- a status-write throw
  // must never skip an access scrub (the fail-open R2-2 closes). It is also
  // best-effort PER ENTRY: one entry's scrub failure must not prevent removing
  // another's. `removeEntry` is idempotent (re-scrubbing an absent entry is a
  // no-op). Any scrub error is remembered and surfaced only AFTER best-effort
  // removal of every entry AND the bookkeeping flip below.
  const scrubbed: string[] = [];
  let firstScrubError: unknown = null;
  const aclFailureByGrantId = new Map<string, FileGrantAclRemovalResult>();
  const confirmedScrubbedGrantIds = new Set<string>();
  for (const entry of plan.toScrub) {
    try {
      const grant = grantsById.get(entry.grant_id);
      const removeResult = await deps.fsOps.removeEntry(
        entry.relative_tree_entry,
        grant ? { grantedReadAce: grant.granted_read_ace ?? null } : undefined
      );
      if (removeResult.scrubbed) {
        scrubbed.push(entry.relative_tree_entry);
        confirmedScrubbedGrantIds.add(entry.grant_id);
      } else {
        aclFailureByGrantId.set(entry.grant_id, removeResult.aclRemoval);
        await appendScrubFailureAudit(deps, entry, grant, removeResult.aclRemoval);
        if (firstScrubError === null) {
          firstScrubError = new Error(
            `Governed File-Grant: failed to remove ACL for ` +
              `${entry.relative_tree_entry}: ${removeResult.aclRemoval.reason ?? "unknown"}`
          );
        }
      }
    } catch (err) {
      if (firstScrubError === null) firstScrubError = err;
    }
  }

  // BOOKKEEPING, SECOND: flip persisted status for grants that have aged past
  // their TTL but whose record still says "active". This runs AFTER access has
  // already been removed, so a status-write failure here can no longer leave
  // expired access live; the throw is still surfaced to the caller (the record
  // may lag at "active"), but the tree entry is already gone.
  // `reviseGrantForExpiry` is a no-op for revoked or not-yet-expired grants.
  const expired: string[] = [];
  for (const grant of grants) {
    const shouldExpire = grant.status === "active" && isGrantExpired(grant, deps.now);
    const shouldClearAce =
      confirmedScrubbedGrantIds.has(grant.grant_id) && grant.granted_read_ace != null;
    if (shouldExpire || shouldClearAce) {
      let revised = shouldExpire ? reviseGrantForExpiry(grant, deps.now) : grant;
      if (shouldClearAce) {
        revised = { ...revised, granted_read_ace: null };
      }
      await deps.store.put(revised);
    }
    if (shouldExpire) {
      expired.push(grant.grant_id);
      await appendExpiryAudit(deps, grant, aclFailureByGrantId.get(grant.grant_id));
    }
  }

  // Surface a scrub failure now -- only after best-effort access removal AND the
  // status flip, so neither the remaining scrubs nor the bookkeeping are skipped
  // by an early throw.
  if (firstScrubError !== null) throw firstScrubError;

  return { expired, scrubbed };
}

async function appendScrubFailureAudit(
  deps: ReconcileFileGrantDeps,
  entry: { grant_id: string; relative_tree_entry: string },
  grant: FileGrant | undefined,
  aclFailure: FileGrantAclRemovalResult
): Promise<void> {
  try {
    await deps.auditLog?.appendCritical({
      layer: "l1",
      operation: "file_grant_revoke",
      identity_id: deps.reconciledBy ?? "system",
      result: "failure",
      details: {
        grant_id: entry.grant_id,
        subject_agent_id: grant?.subject_agent_id,
        reason: "reconcile_acl_removal_failed",
        tree_entry: entry.relative_tree_entry,
        acl_removal: aclFailure,
      },
    });
  } catch {
    // Best-effort: reconcile still reports the scrub failure to its caller.
  }
}

async function appendExpiryAudit(
  deps: ReconcileFileGrantDeps,
  grant: FileGrant,
  aclFailure?: FileGrantAclRemovalResult
): Promise<void> {
  try {
    // Auto-expiry reuses the `file_grant_revoke` audit operation (not a new
    // op string): TTL expiry, like revoke, is a safe-direction access
    // REDUCTION, and reusing the op keeps the CLI audit-write inventory small.
    // The distinct `reason: "expired_ttl_scrub"` (vs revoke's absence of it)
    // disambiguates an auto-expiry from an operator revoke in the trail.
    await deps.auditLog?.appendCritical({
      layer: "l1",
      operation: "file_grant_revoke",
      identity_id: deps.reconciledBy ?? "system",
      result: aclFailure ? "failure" : "success",
      details: {
        grant_id: grant.grant_id,
        subject_agent_id: grant.subject_agent_id,
        reason: aclFailure ? "expired_ttl_acl_removal_failed" : "expired_ttl_scrub",
        ...(aclFailure ? { acl_removal: aclFailure } : {}),
      },
    });
  } catch {
    // Best-effort: an audit failure must not abort a reconcile that is
    // reducing (never expanding) access.
  }
}
