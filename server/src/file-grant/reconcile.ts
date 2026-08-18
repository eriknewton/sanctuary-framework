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
 *
 * THROW CONTRACT (round 4, opus LOW-2; widened to the READ fan-out under
 * FG-RECONCILE-ORDER-01; the two losses separated under
 * FG-RECONCILE-REPORT-01): every per-entry failure is caught and deferred, so
 * no single entry can skip another entry's scrub or the status bookkeeping.
 * There are TWO KINDS and they are tracked separately on purpose:
 *
 *   - A RECORD THAT DID NOT READ BACK (step 1). One grant is unconverged. Its
 *     tree entry is untouched, which is where the run found it.
 *   - A READABLE GRANT THAT DID NOT RECONCILE (`readableGrantFailure`): a
 *     `removeEntry` throw or a reported ACL-removal failure in step 4, or a
 *     status write that rejected in step 3. This is the one that means a grant
 *     which SHOULD have lost access still has it.
 *
 * A single slot holding whichever came first would let the read failure swallow
 * every instance of the second in the same pass, so the report at the end
 * carries BOTH, and claims a reconciliation of the readable grants only when
 * that is what happened. Each scrubbed entry's access is removed BEFORE any
 * throw, so a surfaced throw is fail-closed. Being idempotent and
 * safe-direction, a subsequent `reconcileFileGrantTree` run re-converges the
 * shared fortress ACE.
 *
 * WHAT AN UNREADABLE RECORD DOES AND DOES NOT MEAN. A grant whose record cannot
 * be read -- a read that rejects, or a record that comes back carrying none of
 * a grant's shape -- is left entirely alone: its tree entry is not scrubbed,
 * because its state is unknown and reconcile never acts on a record it has not
 * read. That is the same position the run started in, so the honest bound is
 * "one grant unconverged", not "access silently widened" -- and every OTHER
 * grant is reconciled normally, which is the property the read fan-out used to
 * lose. The second half of that definition lives in the store's decode, and it
 * has to: a record admitted by a cast fails HERE instead, outside the per-entry
 * isolation, where it takes every other grant's reconcile down with it.
 */

import type { AuditLog } from "../operational/audit-log.js";
import { isGrantExpired, reviseGrantForExpiry } from "./lifecycle.js";
import { planGrantTree } from "./planner.js";
import {
  FileGrantUnreadableEntriesError,
  type FileGrant,
  type FileGrantAclRemovalResult,
  type FileGrantListing,
  type FileGrantUnreadableEntry,
  type FsOps,
} from "./types.js";

export interface ReconcileFileGrantStore {
  /**
   * REQUIRED, and deliberately not the strict `list()`. Reconcile must be given
   * the per-entry-tolerant listing, because a listing that throws on one
   * unreadable record keeps the safety-critical scrub below from running at
   * all. Making this the only listing method reconcile accepts is what stops a
   * production call site from quietly wiring the strict one back in; must match
   * `FileGrantStore.listEntries` in `store.ts`.
   */
  listEntries(): Promise<FileGrantListing>;
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
  // READ FAN-OUT, TOLERANT PER ENTRY: `listEntries` returns the grants that
  // read back alongside the ids of the ones that did not, instead of rejecting
  // on the first unreadable record. The invariant this enforces is ORDERING,
  // not merely resilience: the scrub below is the only thing that takes an
  // expired grant's access away, so a read that can reject before the scrub
  // starts makes the scrub's own per-entry tolerance unreachable and lets one
  // unreadable record hold every other grant's access open past its TTL. The
  // read failure is not discarded -- it is deferred and reported after the
  // scrub and the bookkeeping flip, alongside any failure the readable grants
  // hit, never in place of one.
  const listing = await deps.store.listEntries();
  const grants = listing.grants;
  const plan = planGrantTree(grants, deps.now);
  const grantsById = new Map(grants.map((grant) => [grant.grant_id, grant]));

  const scrubbed: string[] = [];
  // The deferred-failure slot for the grants that DID read back: the scrub loop
  // and the bookkeeping loop below both fill it. It is deliberately NOT seeded
  // from the read fan-out. A record that did not read and a removal that did
  // not complete are different losses -- the first means one grant is
  // unconverged, the second means a grant that SHOULD have lost access still
  // has it -- and seeding here would let the first silently swallow every
  // instance of the second in the same pass. The read failure is reported
  // ALONGSIDE this one at the end, never instead of it.
  let readableGrantFailure: unknown = null;

  // SAFETY-CRITICAL, FIRST AMONG THE MUTATIONS, and deliberately the first
  // AWAIT of any kind after the listing -- a delay ahead of it is the same
  // shape as a block, which is why the unreadable-record audit appends were
  // moved below. Scrub every tree entry the plan
  // says must not be present (revoked + expired grants). Removing access is the
  // safety-critical action; the persisted-status flip below is only
  // bookkeeping. So the scrub runs BEFORE and INDEPENDENTLY of the status write
  // -- a status-write throw must never skip an access scrub (the fail-open R2-2
  // closes). It is also best-effort PER ENTRY: one entry's scrub failure must
  // not prevent removing another's. `removeEntry` is idempotent (re-scrubbing
  // an absent entry is a no-op). Any scrub error is remembered and surfaced
  // only AFTER best-effort removal of every entry AND the bookkeeping flip
  // below.
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
        if (readableGrantFailure === null) {
          readableGrantFailure = new Error(
            `Governed File-Grant: failed to remove ACL for ` +
              `${entry.relative_tree_entry}: ${removeResult.aclRemoval.reason ?? "unknown"}`
          );
        }
      }
    } catch (err) {
      if (readableGrantFailure === null) readableGrantFailure = err;
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
    let flipped = true;
    if (shouldExpire || shouldClearAce) {
      let revised = shouldExpire ? reviseGrantForExpiry(grant, deps.now) : grant;
      if (shouldClearAce) {
        revised = { ...revised, granted_read_ace: null };
      }
      // BEST-EFFORT PER ENTRY, LIKE THE SCRUB ABOVE. This used to be the one
      // mutation loop in the function without a per-entry catch, which made it
      // the one loop that could both skip the remaining grants' flips and erase
      // a failure already deferred from the scrub -- the caller then saw the
      // write error alone and was told nothing about the access still live or
      // the record that never read. The stated principle ("no single entry can
      // skip another entry's scrub or the status bookkeeping") is this loop's
      // too. Access is already removed by the time this runs, so a rejection
      // here is a record lagging at "active", reported and not fatal.
      try {
        await deps.store.put(revised);
      } catch (err) {
        flipped = false;
        if (readableGrantFailure === null) readableGrantFailure = err;
      }
    }
    if (shouldExpire) {
      // Only a flip that actually landed is reported as one; `expired` names
      // the records whose PERSISTED status changed.
      if (flipped) expired.push(grant.grant_id);
      await appendExpiryAudit(deps, grant, aclFailureByGrantId.get(grant.grant_id));
    }
  }

  // THE UNREADABLE-RECORD TRAIL RUNS HERE, AFTER BOTH MUTATION LOOPS. It is a
  // durable audit append, one per unreadable record, and nothing bounds how
  // long an append can take -- there is no timeout on `appendCritical`. The
  // ordering rationale this whole function is built on is that nothing which
  // can delay or prevent the scrub may precede it, and an unbounded await is
  // exactly that shape. Nothing downstream reads these rows, so the position
  // costs nothing, and the "first among the mutations" claim above is then
  // literally true rather than nearly true.
  for (const entry of listing.unreadable) {
    await appendUnreadableGrantAudit(deps, entry);
  }

  // Report the pass that actually ran, after best-effort access removal AND the
  // status flip, so neither the remaining scrubs nor the bookkeeping are skipped
  // by an early throw. Swallowing either failure would trade one silent failure
  // for another: the caller would be told a partial reconcile converged.
  //
  // BOTH LOSSES TRAVEL TOGETHER. When records did not read AND a readable
  // grant did not reconcile, one error carries both: the ids that were not
  // read, and the failure that left a readable grant unconverged. Whichever
  // happened first, neither is dropped, and the message states only what this
  // pass observed -- it can no longer claim a reconciliation of the readable
  // grants in a run where one of them was not reconciled.
  if (listing.unreadable.length > 0) {
    throw new FileGrantUnreadableEntriesError(
      listing.unreadable.map((entry) => entry.grant_id),
      listing.unreadable[0]!.cause,
      { failure: readableGrantFailure }
    );
  }
  if (readableGrantFailure !== null) throw readableGrantFailure;

  return { expired, scrubbed };
}

/**
 * Record that a persisted grant record could not be read back, so the loss is
 * durable rather than living only in a thrown message the CLI may summarize.
 * The reconcile still reports the failure to its caller; this is the operator's
 * trail, and it names the grant id only (an unreadable record's scope path is
 * exactly what could not be read).
 */
async function appendUnreadableGrantAudit(
  deps: ReconcileFileGrantDeps,
  entry: FileGrantUnreadableEntry
): Promise<void> {
  try {
    // ITS OWN OPERATION, NOT `file_grant_revoke`. The expiry append below
    // reuses the revoke op with a stated justification -- a TTL expiry, like a
    // revoke, is an access REDUCTION that really happened. Nothing here was
    // revoked and no access changed, so that justification does not reach this
    // row, and an auditor filtering the revoke operation would otherwise be
    // handed rows where nothing was revoked. `operation` is a free-form string
    // (see `operational/audit-log.ts`), so a distinct name costs nothing; this
    // follows mint's `file_grant_recorded` precedent, and like it, the string
    // is an AuditLog value only and is never dispatched to the approval gate,
    // so it carries no tier of its own.
    await deps.auditLog?.appendCritical({
      layer: "l1",
      operation: "file_grant_reconcile_failed",
      identity_id: deps.reconciledBy ?? "system",
      result: "failure",
      details: {
        grant_id: entry.grant_id,
        reason: "reconcile_grant_unreadable",
      },
    });
  } catch {
    // Best-effort: reconcile still reports the read failure to its caller.
  }
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
