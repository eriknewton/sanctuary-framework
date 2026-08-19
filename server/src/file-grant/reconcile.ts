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
 *
 * THE BOUND, STATED AT ITS OWN POSITION (FG-RECONCILE-ENUM-01). The tolerance
 * above is PER RECORD. It is not tolerance of an ENUMERATION failure: if the
 * listing's own scan rejects - a page of the underlying store failing rather
 * than one record failing to decode - `listEntries` rejects, and this function
 * throws before `plan.toScrub` exists. Zero entries are scrubbed, including for
 * every grant that read back perfectly on an earlier page.
 *
 * That is the SAME class this module was hardened against, surviving one
 * position earlier: one fault holding every other grant's access open past its
 * TTL. It is narrowed, not closed. What closes it is a listing that is tolerant
 * at the page boundary as well as the record boundary, which is a change to the
 * store's listing contract rather than a catch added here - so it is a design,
 * and it is tracked rather than patched. Do not read the per-record tolerance
 * below as covering it.
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
  // Every grant the plan says must lose its tree entry. Needed separately from
  // the confirmed set so the expiry audit can distinguish "was not due a scrub"
  // from "was due one and it did not complete".
  const scrubDueGrantIds = new Set(plan.toScrub.map((e) => e.grant_id));
  // Collected during the scrub loop, appended after it. See the deferral note
  // at the push site: an awaited append between two grants' scrubs delays the
  // second grant's access removal. BOTH failure shapes of the scrub loop land
  // here -- a removal that RETURNED a structured failure and a removal that
  // THREW -- because the throw path used to leave no deferred record at all,
  // and for a grant already persisted `expired` or `revoked` (no expiry flip
  // due, so no expiry row runs for it) that meant access stayed live with
  // zero durable rows in any channel (FG-RECONCILE-THROW-SILENT-01).
  const deferredScrubFailureAudits: Array<{
    entry: (typeof plan.toScrub)[number];
    grant: FileGrant | undefined;
    failure:
      | { kind: "acl_removal_reported"; aclRemoval: FileGrantAclRemovalResult }
      | { kind: "removal_threw"; error: unknown };
  }> = [];
  for (const entry of plan.toScrub) {
    // Resolved OUTSIDE the try so the catch below can name the grant on the
    // deferred failure record; a Map lookup cannot throw.
    const grant = grantsById.get(entry.grant_id);
    try {
      const removeResult = await deps.fsOps.removeEntry(
        entry.relative_tree_entry,
        grant ? { grantedReadAce: grant.granted_read_ace ?? null } : undefined
      );
      if (removeResult.scrubbed) {
        scrubbed.push(entry.relative_tree_entry);
        confirmedScrubbedGrantIds.add(entry.grant_id);
      } else {
        aclFailureByGrantId.set(entry.grant_id, removeResult.aclRemoval);
        // DEFERRED, NOT APPENDED HERE. This append used to be awaited inside
        // the loop, so one grant's audit write sat between that grant's failed
        // scrub and the NEXT grant's `removeEntry`. Nothing bounds how long a
        // durable append takes, and this loop is the only thing that takes
        // expired access away, so a slow or blocked audit on grant A held
        // grant B's access open past its TTL. The module header already states
        // the rule this violated, and the unreadable-record trail was moved
        // below for exactly this reason; the scrub loop's own failure append
        // was left behind.
        deferredScrubFailureAudits.push({
          entry,
          grant,
          failure: { kind: "acl_removal_reported", aclRemoval: removeResult.aclRemoval },
        });
        if (readableGrantFailure === null) {
          readableGrantFailure = new Error(
            `Governed File-Grant: failed to remove ACL for ` +
              `${entry.relative_tree_entry}: ${removeResult.aclRemoval.reason ?? "unknown"}`
          );
        }
      }
    } catch (err) {
      // A throw is deferred like the structured failure above, NOT only
      // remembered in the first-wins slot: the slot feeds the thrown error,
      // and a thrown message is not a durable trail. Without this record a
      // grant already persisted `expired` or `revoked` -- the states the
      // expiry append below never runs for -- kept live access with zero
      // audit rows (FG-RECONCILE-THROW-SILENT-01). Appended after the loop
      // for the same reason as its sibling: an awaited append here would sit
      // between this grant's failed scrub and the next grant's removal.
      deferredScrubFailureAudits.push({
        entry,
        grant,
        failure: { kind: "removal_threw", error: err },
      });
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
  // Grants whose expiry append RAN this pass. Consulted by the deferred
  // thrown-scrub trail below: for an ACTIVE expiring grant whose scrub threw,
  // the expiry row already reports the failure
  // (`expired_ttl_scrub_did_not_complete`), so a second row here would be one
  // fault described twice -- the FG-RECONCILE-ACL-DOUBLE-01 shape, and a
  // pinned test asserts exactly one row for that grant. Recording the append
  // that actually ran, rather than re-deriving the `shouldExpire` predicate at
  // the other site, is what keeps the two sites from drifting.
  const expiryAuditedGrantIds = new Set<string>();
  for (const grant of grants) {
    const shouldExpire = grant.status === "active" && isGrantExpired(grant, deps.now);
    const shouldClearAce =
      confirmedScrubbedGrantIds.has(grant.grant_id) && grant.granted_read_ace != null;
    let flipped = true;
    let writeError: unknown | undefined;
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
        // AUDITED UNCONDITIONALLY, BEFORE the deferred-slot race below.
        // `readableGrantFailure` holds ONE failure and is first-wins, so when a
        // scrub already failed earlier in this pass, this write error loses the
        // race and is never thrown. Without a durable row it would then be
        // absent from EVERY channel - not thrown, not returned, not logged -
        // while the earlier scrub failure is the only thing the caller sees.
        // The row is emitted below, exactly once; see the ordering note there.
        writeError = err;
        if (readableGrantFailure === null) readableGrantFailure = err;
      }
    }
    // ONE ROW PER FAILED STATUS WRITE, which is narrower than "one row per
    // grant per pass" and the narrower claim is the true one.
    //
    // What this branching fixes: an earlier round emitted the write failure
    // from its own helper AND from the expiry append, both carrying the same
    // reason, so one rejected `put` produced two records describing one fault,
    // 2F appends for F failures, and the retention budget consumed twice as
    // fast. `appendExpiryAudit` already runs on the expiring path and already
    // carries the durability, so it takes the error too; the separate helper is
    // reached ONLY on the path where that append does not run at all.
    //
    // What it does NOT fix, stated here because the stronger claim was made and
    // was wrong: a STRUCTURED ACL-removal failure still produces two rows for
    // one fault, `reconcile_acl_removal_failed` from the scrub trail and
    // `expired_ttl_acl_removal_failed` from this append. That pair predates the
    // duplicate above and picking a canonical row is a consumer-visible
    // decision, so it is tracked (FG-RECONCILE-ACL-DOUBLE-01) and pinned by a
    // test rather than changed here.
    if (shouldExpire) {
      // Only a flip that actually landed is reported as one; `expired` names
      // the records whose PERSISTED status changed.
      if (flipped) expired.push(grant.grant_id);
      // `scrubConfirmed` is what stops this row claiming success for access that
      // is still live. `aclFailureByGrantId` only records a STRUCTURED failure;
      // a scrub that THREW is caught above and leaves no entry there, so the
      // row saw no failure, no write error, a landed flip, and reported
      // `result: "success"` / `reason: "expired_ttl_scrub"` for a grant whose
      // tree entry was never removed. The set of confirmed scrubs already
      // exists and answers the question directly: was this grant due to be
      // scrubbed, and did that scrub actually complete.
      const dueToScrub = scrubDueGrantIds.has(grant.grant_id);
      expiryAuditedGrantIds.add(grant.grant_id);
      await appendExpiryAudit(
        deps,
        grant,
        aclFailureByGrantId.get(grant.grant_id),
        flipped,
        writeError,
        !dueToScrub || confirmedScrubbedGrantIds.has(grant.grant_id)
      );
    } else if (writeError !== undefined) {
      // The clear-the-ACE-only path: the record was rewritten to drop a stale
      // `granted_read_ace` without expiring, so no expiry row is due. The write
      // still rejected, and without this the failure would be invisible again
      // on exactly the path the expiry row does not cover.
      await appendStatusWriteFailureAudit(deps, grant, writeError);
    }
  }

  // THE DEFERRED SCRUB-FAILURE TRAIL RUNS HERE, for the same reason the
  // unreadable-record trail below does: every access removal this pass will
  // attempt has already been attempted, so an append can no longer delay one.
  for (const deferred of deferredScrubFailureAudits) {
    if (deferred.failure.kind === "acl_removal_reported") {
      await appendScrubFailureAudit(
        deps,
        deferred.entry,
        deferred.grant,
        deferred.failure.aclRemoval
      );
    } else if (!expiryAuditedGrantIds.has(deferred.entry.grant_id)) {
      // A thrown scrub gets its row ONLY when no expiry row carried it: for an
      // active expiring grant the expiry append above already reported
      // `expired_ttl_scrub_did_not_complete`, and one fault is one row. The
      // structured branch above stays unconditional on purpose -- its
      // two-rows-for-one-fault bound predates this fix, is tracked as
      // FG-RECONCILE-ACL-DOUBLE-01, and is pinned by a test; collapsing it is
      // a consumer-visible decision that is not taken here.
      await appendThrownScrubFailureAudit(
        deps,
        deferred.entry,
        deferred.grant,
        deferred.failure.error
      );
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

/**
 * The counterpart to `appendScrubFailureAudit` for the scrub loop's OTHER
 * failure shape: `removeEntry` THREW rather than returning a structured
 * ACL-removal result. It exists because the throw path used to leave only the
 * first-wins error slot, so for a grant already persisted `expired` or
 * `revoked` -- the states the expiry append never runs for -- a thrown scrub
 * left zero durable rows while access stayed live
 * (FG-RECONCILE-THROW-SILENT-01). Filed under `file_grant_revoke` with
 * `result: "failure"` like its structured sibling: both are attempted access
 * reductions that did not land. Best-effort for the same reason as every
 * append here: an audit failure must never abort a reconcile that is reducing
 * access.
 */
async function appendThrownScrubFailureAudit(
  deps: ReconcileFileGrantDeps,
  entry: { grant_id: string; relative_tree_entry: string },
  grant: FileGrant | undefined,
  err: unknown
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
        // Distinct from `reconcile_acl_removal_failed`: that reason means the
        // removal RAN and reported which ACL step failed; this one means the
        // removal threw before reporting anything, so there is no structured
        // result to attach and the error text is the whole evidence.
        reason: "reconcile_scrub_threw",
        tree_entry: entry.relative_tree_entry,
        error: err instanceof Error ? err.message : String(err),
      },
    });
  } catch {
    // Best-effort: reconcile still reports the thrown scrub to its caller.
  }
}

/**
 * The counterpart to `appendScrubFailureAudit` for the OTHER mutation in this
 * function.
 *
 * It exists because the two mutation loops share one deferred-error slot and
 * that slot is first-wins. A scrub failure earlier in the pass therefore
 * suppresses this one from the thrown error, and with no row of its own a
 * status-write failure would be invisible in every channel at once. An access
 * reduction that did not durably land is not a thing an operator may have to
 * infer from silence.
 *
 * Best-effort like its sibling: an audit failure must never abort a reconcile
 * that is reducing access.
 */
async function appendStatusWriteFailureAudit(
  deps: ReconcileFileGrantDeps,
  grant: FileGrant,
  err: unknown
): Promise<void> {
  try {
    await deps.auditLog?.appendCritical({
      layer: "l1",
      operation: "file_grant_revoke",
      identity_id: deps.reconciledBy ?? "system",
      result: "failure",
      details: {
        grant_id: grant.grant_id,
        subject_agent_id: grant.subject_agent_id,
        // NOT an expiry reason, because nothing expired on this path. This
        // helper is now reached only when a REVOKED grant's record failed to
        // persist its cleared ACE metadata: no TTL passed, no status
        // transition was attempted. Labelling it `expired_ttl_*` told an
        // operator a grant had aged out when it had been revoked, which is a
        // different event with a different cause. `revoke.ts` already had the
        // accurate word for it and this reuses it rather than minting a
        // second name for one thing.
        reason: "ace_metadata_clear_persist_failed",
        error: err instanceof Error ? err.message : String(err),
        // False by construction here: this row exists only because the write
        // rejected. Stated anyway so every row this reconcile emits for a
        // grant carries the same durability field, and an operator never has
        // to know which helper wrote which row.
        status_flipped: false,
      },
    });
  } catch {
    // Best-effort: reconcile still reports what it can to its caller.
  }
}

/**
 * `statusFlipped` is NOT optional bookkeeping detail: it is what keeps this row
 * from asserting something that did not happen.
 *
 * The expiry pass has two independent halves - taking the ACL away, and
 * persisting the record as expired - and either can fail on its own. A row that
 * reads `result: "success"` for a grant whose record is still persisted as
 * `active` tells an operator the TTL was enforced when the durable state says
 * it was not, and an audit trail that overstates an access REDUCTION is the
 * direction that gets believed.
 *
 * Before this argument existed the caller appended unconditionally, so a
 * rejected `put` produced exactly that false row.
 */
async function appendExpiryAudit(
  deps: ReconcileFileGrantDeps,
  grant: FileGrant,
  aclFailure?: FileGrantAclRemovalResult,
  statusFlipped: boolean = true,
  writeError?: unknown,
  scrubConfirmed: boolean = true
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
      result:
        aclFailure || !statusFlipped || !scrubConfirmed ? "failure" : "success",
      details: {
        grant_id: grant.grant_id,
        subject_agent_id: grant.subject_agent_id,
        reason: aclFailure
          ? "expired_ttl_acl_removal_failed"
          : !scrubConfirmed
            ? "expired_ttl_scrub_did_not_complete"
            : statusFlipped
              ? "expired_ttl_scrub"
              : "expired_ttl_status_write_failed",
        ...(aclFailure ? { acl_removal: aclFailure } : {}),
        // Stated on every row rather than only the failing one, so an operator
        // reading the trail never has to infer durability from a reason string.
        status_flipped: statusFlipped,
        // Carried HERE rather than emitted as a second row: one fault is one
        // event. See the ordering note at the call site.
        ...(writeError !== undefined
          ? {
              error:
                writeError instanceof Error
                  ? writeError.message
                  : String(writeError),
            }
          : {}),
      },
    });
  } catch {
    // Best-effort: an audit failure must not abort a reconcile that is
    // reducing (never expanding) access.
  }
}
