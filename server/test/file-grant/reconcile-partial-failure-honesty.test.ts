/**
 * Governed File-Grant -- the tree reconcile converges every grant it can decode,
 * and reports the pass it actually ran (FG-RECONCILE-DECODE-01,
 * FG-RECONCILE-REPORT-01).
 *
 * CAPABILITY ASSERTED HERE. A reconcile pass carries two obligations, and this
 * suite pins them together because satisfying either one alone is not a pass.
 * The SAFETY obligation: every grant whose record decodes has its expired tree
 * entry and read ACE taken away, whatever became of any other record in the
 * same namespace. The HONESTY obligation: what the caller is handed describes
 * the pass that actually ran. A record that did not decode is named; a removal
 * or a status write that did not complete is named alongside it rather than
 * displaced by it; and the sentence claiming the readable grants were
 * reconciled appears only in a report written after they were.
 *
 * FAULT SCHEDULE EXERCISED (AGENTS.md rule 12). Four per-entry faults, injected
 * alone and in combination, always against a namespace that also holds a grant
 * past its TTL with a live tree entry, so every assertion turns on whether that
 * unrelated grant's access survived: a stored value that returns cleanly from
 * the read but carries none of a grant's shape; a stored value that decodes to
 * nothing at all; a tree-entry removal that rejects; and a bookkeeping status
 * write that rejects. A fifth assertion pins the ORDER of the awaits, since an
 * append that precedes the removal is an append that can delay it.
 */

import { describe, expect, it } from "vitest";

import { mintFileGrant } from "../../src/file-grant/mint.js";
import { reconcileFileGrantTree } from "../../src/file-grant/reconcile.js";
import { FileGrantUnreadableEntriesError } from "../../src/file-grant/types.js";
import {
  DEFAULT_FAKE_SOURCE_IDENTITY,
  FakeFsOps,
  failReadFor,
  makeFileGrantTestStore,
  readsBackAs,
} from "./fixtures.js";

const MINTED_AT = new Date("2026-07-07T00:00:00.000Z");
const PAST_TTL = new Date("2026-07-07T02:00:00.000Z");

/** The substring, not the whole sentence, so this pins the CLAIM and not its wording. */
const RECONCILED_CLAIM = "readable grant was still reconciled";

type TestStore = Awaited<ReturnType<typeof makeFileGrantTestStore>>;

async function mintGrant(
  deps: { fsOps: FakeFsOps; store: TestStore["grantStore"]; auditLog: TestStore["auditLog"] },
  agentId: string,
  path: string,
) {
  const { grant } = await mintFileGrant(
    {
      subjectAgentId: agentId,
      scope: { kind: "file", path },
      mode: "read",
      ttlSeconds: 60,
      createdBy: "operator-1",
    },
    { fsOps: deps.fsOps, store: deps.store, now: MINTED_AT, auditLog: deps.auditLog },
  );
  return grant;
}

/**
 * One grant already past its TTL and holding a live tree entry, plus a sibling
 * whose record the caller is about to break. Every case below asserts on the
 * first grant's access, which is the only thing that distinguishes a reconcile
 * that ran from one that never reached its removal loop.
 */
async function twoGrants(
  opts: { removeThrows?: Error; removeAclThrows?: Error } = {},
) {
  const store = await makeFileGrantTestStore();
  const fsOps = new FakeFsOps({
    agentUid: 502,
    sourceOwnerUid: 501,
    ...(opts.removeThrows ? { removeThrows: opts.removeThrows } : {}),
    // Forwarded, because it was not. `removeThrows` makes `removeEntry` THROW;
    // `removeAclThrows` makes it RETURN a structured failure. They are
    // different branches of the scrub loop, and a helper that silently drops
    // the second means every test written against it exercises the first.
    ...(opts.removeAclThrows ? { removeAclThrows: opts.removeAclThrows } : {}),
  });
  const seed = { fsOps, store: store.grantStore, auditLog: store.auditLog };
  const expiring = await mintGrant(seed, "agent-expiring", "/tmp/expiring.txt");
  const sibling = await mintGrant(seed, "agent-sibling", "/tmp/sibling.txt");
  expect(fsOps.placed).toHaveLength(2);
  return { ...store, fsOps, expiring, sibling };
}

async function reconcileError(deps: Parameters<typeof reconcileFileGrantTree>[0]): Promise<unknown> {
  return reconcileFileGrantTree(deps).then(
    () => null,
    (err: unknown) => err,
  );
}

/**
 * Give a grant a darwin ACE whose inode identity matches, so `removeEntry`
 * reaches the ACL-removal branch. Combined with `removeAclThrows` this yields a
 * STRUCTURED failure (`scrubbed: false`) rather than a throw, which is a
 * different code path in the scrub loop and the one the throw-based fixtures
 * never reach.
 */
async function giveDarwinAce(
  store: TestStore["grantStore"],
  grantId: string,
  path: string,
): Promise<void> {
  const live = await store.get(grantId);
  await store.put({
    ...live!,
    granted_read_ace: {
      agent_uid: 502,
      platform: "darwin",
      source_realpath: path,
      source_dev: DEFAULT_FAKE_SOURCE_IDENTITY.source_dev,
      source_ino: DEFAULT_FAKE_SOURCE_IDENTITY.source_ino,
    },
  });
}

describe("file-grant reconcile: a record that does not decode is one record, not the whole pass", () => {
  it("still scrubs and flips every other grant when a sibling's stored value carries no grant shape", async () => {
    const { grantStore, stateStore, auditLog, fsOps, expiring, sibling } = await twoGrants();

    // The fault the read fan-out cannot see: this key resolves, decrypts, and
    // returns a value. Only the decode can tell that it is not a grant.
    readsBackAs(stateStore, sibling.grant_id, "{}");

    const error = await reconcileError({
      store: grantStore,
      fsOps,
      now: PAST_TTL,
      auditLog,
      reconciledBy: "operator-1",
    });

    // THE SAFETY PROPERTY: the expired grant's access is gone.
    expect(fsOps.scrubbed).toContain(expiring.tree_entry);
    expect((await grantStore.get(expiring.grant_id))!.status).toBe("expired");
    // THE HONESTY PROPERTY: the record that did not decode is named as such,
    // not raised as whatever type the first field access happened to produce.
    expect(error).toBeInstanceOf(FileGrantUnreadableEntriesError);
    expect((error as FileGrantUnreadableEntriesError).grantIds).toEqual([sibling.grant_id]);
    // And its own entry is left where the run found it: its state is unknown.
    expect(fsOps.scrubbed).not.toContain(sibling.tree_entry);
  });

  it("reports a stored value that decodes to nothing instead of dropping it silently", async () => {
    const { grantStore, stateStore, auditLog, fsOps, expiring, sibling } = await twoGrants();

    // A record in the reserved grant namespace is never "someone else's row",
    // so a decode that yields nothing is a loss and has to be reported as one.
    readsBackAs(stateStore, sibling.grant_id, "null");

    const error = await reconcileError({ store: grantStore, fsOps, now: PAST_TTL, auditLog });

    expect(error).toBeInstanceOf(FileGrantUnreadableEntriesError);
    expect((error as FileGrantUnreadableEntriesError).grantIds).toEqual([sibling.grant_id]);
    expect(fsOps.scrubbed).toContain(expiring.tree_entry);
  });
});

describe("file-grant reconcile: the report names every loss in the pass, and claims only what happened", () => {
  it("surfaces a removal failure to the caller even when a record in the same pass did not read", async () => {
    const denied = new Error("EACCES: permission denied, unlink grant tree entry");
    const { grantStore, stateStore, auditLog, fsOps, expiring, sibling } = await twoGrants({
      removeThrows: denied,
    });

    failReadFor(stateStore, sibling.grant_id, "writer key could not be resolved");

    const error = await reconcileError({
      store: grantStore,
      fsOps,
      now: PAST_TTL,
      auditLog,
      reconciledBy: "operator-1",
    });

    // A record that did not read and a removal that did not complete are
    // different losses. The one that happened first must not displace the one
    // that means an expired grant's access is still live.
    expect(String((error as Error).message)).toContain(denied.message);
    expect(String((error as Error).message)).toContain(sibling.grant_id);
    expect((error as FileGrantUnreadableEntriesError).readableGrants?.failure).toBe(denied);
    // The removal really was attempted and really did not take the entry away.
    expect(fsOps.events).toContain(`remove:${expiring.tree_entry}`);
    expect(fsOps.scrubbed).not.toContain(expiring.tree_entry);
  });

  it("makes the reconciliation claim only in the run where it is true", async () => {
    const clean = await twoGrants();
    failReadFor(clean.stateStore, clean.sibling.grant_id, "writer key could not be resolved");
    const cleanError = await reconcileError({
      store: clean.grantStore,
      fsOps: clean.fsOps,
      now: PAST_TTL,
      auditLog: clean.auditLog,
    });
    expect(clean.fsOps.scrubbed).toContain(clean.expiring.tree_entry);
    expect(String((cleanError as Error).message)).toContain(RECONCILED_CLAIM);

    const broken = await twoGrants({ removeThrows: new Error("EACCES: permission denied") });
    failReadFor(broken.stateStore, broken.sibling.grant_id, "writer key could not be resolved");
    const brokenError = await reconcileError({
      store: broken.grantStore,
      fsOps: broken.fsOps,
      now: PAST_TTL,
      auditLog: broken.auditLog,
    });
    // The same sentence in a run where a readable grant was NOT reconciled is
    // the failure this assertion exists to keep out of an operator's terminal.
    expect(broken.fsOps.scrubbed).not.toContain(broken.expiring.tree_entry);
    expect(String((brokenError as Error).message)).not.toContain(RECONCILED_CLAIM);
  });

  it("keeps the deferred failure when the bookkeeping write rejects", async () => {
    const { grantStore, stateStore, auditLog, fsOps, expiring, sibling } = await twoGrants();

    failReadFor(stateStore, sibling.grant_id, "writer key could not be resolved");
    const writeFailed = new Error("state write failed (disk full)");
    grantStore.put = async () => {
      throw writeFailed;
    };

    const error = await reconcileError({ store: grantStore, fsOps, now: PAST_TTL, auditLog });

    // The status flip is the one mutation loop whose failure used to leave the
    // caller with no report at all, which is the shape the whole pass exists to
    // avoid. Access removal already happened, so this is a bookkeeping lag.
    expect(fsOps.scrubbed).toContain(expiring.tree_entry);
    expect(error).toBeInstanceOf(FileGrantUnreadableEntriesError);
    expect((error as FileGrantUnreadableEntriesError).grantIds).toEqual([sibling.grant_id]);
    expect((error as FileGrantUnreadableEntriesError).readableGrants?.failure).toBe(writeFailed);
    expect(String((error as Error).message)).toContain(writeFailed.message);
  });

  it("never records an expiry as a success when the status write did not land", async () => {
    // REGRESSION introduced by this PR's own fix round. Gating `expired.push`
    // on the flip was right; leaving the audit append ungated was not. A
    // rejected `put` then produced a `result: "success"` /
    // `reason: "expired_ttl_scrub"` row for a record still persisted as
    // `active` - the trail asserting the TTL was enforced while the durable
    // state says it was not. Before the fix round the throw propagated and the
    // row did not exist at all, so this shipped strictly worse than what it
    // replaced.
    const { grantStore, auditLog, fsOps, expiring } = await twoGrants();

    const writeFailed = new Error("state write failed (disk full)");
    grantStore.put = async () => {
      throw writeFailed;
    };

    await reconcileError({ store: grantStore, fsOps, now: PAST_TTL, auditLog });

    // Access WAS removed - this is a bookkeeping lag, not a fail-open.
    expect(fsOps.scrubbed).toContain(expiring.tree_entry);

    const revokes = await auditLog.query({ operation_type: "file_grant_revoke", limit: 200 });
    const expiryRows = revokes.entries.filter(
      (entry) => (entry.details as { grant_id?: string } | undefined)?.grant_id === expiring.grant_id,
    );
    // NOT VACUOUS. Asserting only "no success rows" passes when there are no
    // rows at all, which is a different outcome and would hide the append being
    // dropped entirely. Pin that the row exists first.
    // Exactly one, not "at least one": a duplicate is the shape this whole
    // section exists to catch, and `>` cannot see one.
    expect(expiryRows).toHaveLength(1);
    const successRows = expiryRows.filter((entry) => entry.result === "success");
    // THE PROPERTY: no row may claim success for a flip that did not land.
    expect(successRows).toHaveLength(0);
    const scrubClaims = expiryRows.filter(
      (entry) => (entry.details as { reason?: string } | undefined)?.reason === "expired_ttl_scrub",
    );
    expect(scrubClaims).toHaveLength(0);
    // And the durability is stated outright rather than left to be inferred
    // from a reason string.
    for (const entry of expiryRows) {
      expect((entry.details as { status_flipped?: boolean }).status_flipped).toBe(false);
    }
  });

  it("keeps a status-write failure visible even when a scrub failure already claimed the one deferred slot", async () => {
    // REGRESSION introduced by this PR's own fix round, and the subtler of the
    // two. `readableGrantFailure` holds ONE failure, first-wins. Adding a catch
    // around the status write without giving it a row of its own meant that
    // when a scrub failed earlier in the same pass, the write error was neither
    // thrown, nor returned, nor recorded: absent from every channel at once.
    // The scrub path has had an audit row since it gained its catch. This is
    // the missing counterpart.
    const removeFailed = new Error("scrub failed first (acl backend down)");
    const { grantStore, auditLog, fsOps, expiring } = await twoGrants({
      removeThrows: removeFailed,
    });

    const writeFailed = new Error("state write failed (disk full)");
    grantStore.put = async () => {
      throw writeFailed;
    };

    const rowsForGrantBefore = (await auditLog.query({ limit: 500 })).entries.filter(
      (entry) => (entry.details as { grant_id?: string } | undefined)?.grant_id === expiring.grant_id,
    ).length;

    const error = await reconcileError({ store: grantStore, fsOps, now: PAST_TTL, auditLog });

    // First-wins is preserved deliberately: the scrub failure is the one that
    // means access is still live, so it is the right one to throw.
    expect(error).toBe(removeFailed);

    // But the write failure must still be SOMEWHERE. This is the assertion the
    // fix round was missing.
    const revokes = await auditLog.query({ operation_type: "file_grant_revoke", limit: 200 });
    // The reason names the SCRUB, not the write, and that ordering is correct:
    // this grant's tree entry was never removed, so access is still live, which
    // is the more urgent of the two facts. The write failure is not lost, it
    // travels on the same row in `error`. Asserting the old
    // `expired_ttl_status_write_failed` label here would pin the row to the
    // less important truth.
    const writeFailureRows = revokes.entries.filter(
      (entry) =>
        (entry.details as { reason?: string } | undefined)?.reason ===
          "expired_ttl_scrub_did_not_complete" &&
        (entry.details as { grant_id?: string } | undefined)?.grant_id === expiring.grant_id,
    );
    // EXACTLY ONE, not "at least one". The weaker assertion is what let a
    // duplicate ship: an earlier round emitted this failure from its own helper
    // AND from the expiry append, so one rejected write produced two records
    // with the same reason - one fault reported as two events, and 2F appends
    // for F failures against a bounded retention budget. A `>=` assertion
    // cannot see that. Any row-count assertion on an audit trail should be
    // exact for the same reason.
    expect(writeFailureRows).toHaveLength(1);
    expect(writeFailureRows[0]!.result).toBe("failure");
    expect((writeFailureRows[0]!.details as { error?: string }).error).toContain(
      writeFailed.message,
    );
    // And THIS PASS emits one row for the grant, not one per helper that had an
    // opinion about it. Measured as a delta across every audit operation rather
    // than by filtering one operation name: a duplicate written under a
    // different operation would be invisible to a scoped filter, and the
    // fixture's own mint rows carry the same grant_id so an absolute count over
    // all operations would be counting setup.
    const rowsForGrantAfter = (await auditLog.query({ limit: 500 })).entries.filter(
      (entry) => (entry.details as { grant_id?: string } | undefined)?.grant_id === expiring.grant_id,
    ).length;
    expect(rowsForGrantAfter - rowsForGrantBefore).toBe(1);
  });

  it("still records a rejected write on the clear-the-ACE path, where no expiry row is due", async () => {
    // The branch the consolidation created, tested because an untested branch
    // is how the duplicate got in. A REVOKED grant that still carries a
    // `granted_read_ace` gets its record rewritten to drop the stale ACE, and
    // `shouldExpire` is false for it, so the expiry row that carries the write
    // error on the other path never runs here. Folding both paths into that one
    // row would make this failure invisible again, on exactly the path the row
    // does not cover.
    const { grantStore, auditLog, fsOps, expiring } = await twoGrants();

    // Revoked (so it scrubs but never expires) and still holding an ACE whose
    // inode identity matches, so the removal SUCCEEDS and the grant lands in
    // the confirmed-scrubbed set. An ACE without that identity fails cleanup
    // and never reaches the branch at all.
    const live = await grantStore.get(expiring.grant_id);
    await grantStore.put({
      ...live!,
      status: "revoked",
      granted_read_ace: {
        agent_uid: 502,
        platform: "darwin",
        source_realpath: "/tmp/expiring.txt",
        source_dev: DEFAULT_FAKE_SOURCE_IDENTITY.source_dev,
        source_ino: DEFAULT_FAKE_SOURCE_IDENTITY.source_ino,
      },
    });

    const writeFailed = new Error("state write failed (disk full)");
    const realPut = grantStore.put.bind(grantStore);
    let armed = false;
    grantStore.put = async (g) => {
      if (armed) throw writeFailed;
      return realPut(g);
    };
    armed = true;

    // Delta across EVERY audit operation, like the deferred-slot test above,
    // not only the operation-and-reason filter below: a duplicate row written
    // under a different operation or reason would be invisible to a scoped
    // filter, and the fixture's own mint rows carry the same grant_id so an
    // absolute count would be counting setup (FG-RECONCILE-TEST-ORDERING-01).
    const rowsForGrantBefore = (await auditLog.query({ limit: 500 })).entries.filter(
      (entry) => (entry.details as { grant_id?: string } | undefined)?.grant_id === expiring.grant_id,
    ).length;

    await reconcileError({ store: grantStore, fsOps, now: PAST_TTL, auditLog });

    const rowsForGrantAfter = (await auditLog.query({ limit: 500 })).entries.filter(
      (entry) => (entry.details as { grant_id?: string } | undefined)?.grant_id === expiring.grant_id,
    ).length;
    expect(rowsForGrantAfter - rowsForGrantBefore).toBe(1);

    const revokes = await auditLog.query({ operation_type: "file_grant_revoke", limit: 200 });
    const rows = revokes.entries.filter(
      (entry) =>
        (entry.details as { grant_id?: string } | undefined)?.grant_id === expiring.grant_id &&
        (entry.details as { reason?: string } | undefined)?.reason ===
          "ace_metadata_clear_persist_failed",
    );
    expect(rows).toHaveLength(1);
    expect(rows[0]!.result).toBe("failure");
    // The reason must NOT claim an expiry: nothing aged out here, the grant was
    // revoked. An `expired_ttl_*` label on this path tells an operator the
    // wrong story about why access changed.
    const expiryLabelled = revokes.entries.filter(
      (entry) =>
        (entry.details as { grant_id?: string } | undefined)?.grant_id === expiring.grant_id &&
        String((entry.details as { reason?: string } | undefined)?.reason ?? "").startsWith(
          "expired_ttl",
        ),
    );
    expect(expiryLabelled).toHaveLength(0);
  });

  it("never lets one grant's failure audit sit between another grant's scrub", async () => {
    // The module's ordering rule is that the scrub loop takes access away and
    // nothing which can block may run inside it. The scrub-failure audit was
    // awaited in that loop, so grant A's durable append sat between A's failed
    // scrub and B's `removeEntry`, and nothing bounds how long an append takes.
    // A blocked audit on one grant therefore held another grant's access open
    // past its TTL. Position is the assertion, exactly as it is for the
    // unreadable-record trail.
    const { grantStore, auditLog, fsOps, expiring, sibling } = await twoGrants({
      removeAclThrows: new Error("acl backend down"),
    });
    await giveDarwinAce(grantStore, expiring.grant_id, "/tmp/expiring.txt");
    await giveDarwinAce(grantStore, sibling.grant_id, "/tmp/sibling.txt");

    const realAppend = auditLog.appendCritical.bind(auditLog);
    auditLog.appendCritical = (async (entry: Parameters<typeof realAppend>[0]) => {
      const reason = (entry.details as { reason?: string } | undefined)?.reason;
      if (reason === "reconcile_acl_removal_failed") {
        fsOps.events.push("audit:scrub-failure");
      }
      return realAppend(entry);
    }) as typeof auditLog.appendCritical;

    await reconcileError({ store: grantStore, fsOps, now: PAST_TTL, auditLog });

    const firstAudit = fsOps.events.indexOf("audit:scrub-failure");
    const removals = fsOps.events
      .map((e, i) => (e.startsWith("remove:") ? i : -1))
      .filter((i) => i >= 0);
    expect(firstAudit).toBeGreaterThanOrEqual(0);
    // THE EXACT TWO removals, tied to their grants, not a count
    // (FG-RECONCILE-TEST-ORDERING-01). "More than one removal" is satisfied by
    // two removals of the SAME grant while its sibling is skipped, which is
    // precisely the shape an append wedged into the loop could produce; a
    // count cannot see a duplicate, and an untied count cannot see whose
    // access was never taken away.
    expect(fsOps.events.filter((e) => e.startsWith("remove:")).sort()).toEqual(
      [`remove:${expiring.tree_entry}`, `remove:${sibling.tree_entry}`].sort(),
    );
    // EVERY removal precedes the first failure audit. Asserting only "the last
    // removal happened" would pass with an append wedged between the two.
    expect(Math.max(...removals)).toBeLessThan(firstAudit);
  });

  it("reports a structured ACL failure twice, which is a known bound and not the fixed duplicate", async () => {
    // PINS A BOUND RATHER THAN A FIX. When `removeEntry` reports a structured
    // failure (rather than throwing) and the status write then rejects, the
    // grant gets a `reconcile_acl_removal_failed` row from the scrub trail AND
    // an `expired_ttl_acl_removal_failed` row from the expiry append. That is
    // one fault described twice, in two vocabularies, and it predates the
    // duplicate this PR removed.
    //
    // It is pinned here so the "one row per grant per pass" claim is not made
    // where it is untrue, and so a future fix that picks a canonical row has a
    // test to flip rather than a behaviour to discover. Register:
    // FG-RECONCILE-ACL-DOUBLE-01.
    const { grantStore, auditLog, fsOps, expiring } = await twoGrants({
      removeAclThrows: new Error("acl backend down"),
    });
    await giveDarwinAce(grantStore, expiring.grant_id, "/tmp/expiring.txt");
    grantStore.put = async () => {
      throw new Error("state write failed (disk full)");
    };

    await reconcileError({ store: grantStore, fsOps, now: PAST_TTL, auditLog });

    const revokes = await auditLog.query({ operation_type: "file_grant_revoke", limit: 200 });
    const reasons = revokes.entries
      .filter((e) => (e.details as { grant_id?: string } | undefined)?.grant_id === expiring.grant_id)
      .map((e) => (e.details as { reason?: string }).reason)
      .sort();
    expect(reasons).toEqual([
      "expired_ttl_acl_removal_failed",
      "reconcile_acl_removal_failed",
    ]);
  });

  it("leaves a durable failure row when the scrub of an already-expired or already-revoked grant throws", async () => {
    // THE SILENT PAIR (FG-RECONCILE-THROW-SILENT-01). A grant whose persisted
    // status is already `expired` or `revoked` takes no expiry flip, so the
    // expiry row that carries a thrown scrub for ACTIVE expiring grants never
    // runs for it. The throw is caught by the scrub loop's per-entry catch,
    // `aclFailureByGrantId` records only STRUCTURED failures, and the deferred
    // scrub-failure trail used to carry only those, so a thrown scrub left
    // ZERO durable rows for these two states: access still live, no trace in
    // any channel but the thrown error the CLI may summarize. Round 5's fix
    // looked complete precisely because the active-expiring state happens to
    // be covered.
    const removeFailed = new Error("scrub failed (acl backend down)");
    const { grantStore, auditLog, fsOps, expiring, sibling } = await twoGrants({
      removeThrows: removeFailed,
    });

    // One grant per silent state. Neither takes the expiry path: no status
    // flip is due, so no expiry row can carry the failure for them.
    const expiredLive = await grantStore.get(expiring.grant_id);
    await grantStore.put({ ...expiredLive!, status: "expired" });
    const revokedLive = await grantStore.get(sibling.grant_id);
    await grantStore.put({ ...revokedLive!, status: "revoked" });

    // Delta shape, not an operation-scoped count: a row emitted under a
    // different operation or reason must not be invisible to the assertion.
    const rowsFor = async (grantId: string) =>
      (await auditLog.query({ limit: 500 })).entries.filter(
        (entry) => (entry.details as { grant_id?: string } | undefined)?.grant_id === grantId,
      ).length;
    const expiredRowsBefore = await rowsFor(expiring.grant_id);
    const revokedRowsBefore = await rowsFor(sibling.grant_id);

    const error = await reconcileError({ store: grantStore, fsOps, now: PAST_TTL, auditLog });

    // Access is still live for both, and the caller does hear about it...
    expect(error).toBe(removeFailed);
    expect(fsOps.scrubbed).not.toContain(expiring.tree_entry);
    expect(fsOps.scrubbed).not.toContain(sibling.tree_entry);

    // ...but a thrown message is not a durable trail. EXACTLY ONE failure row
    // per grant: zero is the silent defect, two is the duplicate class the
    // rest of this suite exists to keep out.
    const revokes = await auditLog.query({ operation_type: "file_grant_revoke", limit: 200 });
    for (const grant of [expiring, sibling]) {
      const rows = revokes.entries.filter(
        (entry) =>
          (entry.details as { grant_id?: string } | undefined)?.grant_id === grant.grant_id &&
          (entry.details as { reason?: string } | undefined)?.reason === "reconcile_scrub_threw",
      );
      expect(rows).toHaveLength(1);
      expect(rows[0]!.result).toBe("failure");
      expect((rows[0]!.details as { error?: string }).error).toContain(removeFailed.message);
      expect((rows[0]!.details as { tree_entry?: string }).tree_entry).toBe(grant.tree_entry);
    }
    expect((await rowsFor(expiring.grant_id)) - expiredRowsBefore).toBe(1);
    expect((await rowsFor(sibling.grant_id)) - revokedRowsBefore).toBe(1);
  });

  it("falls back to the thrown-scrub row when the expiry append itself rejects", async () => {
    // ROUND-7 SCHEDULE (FG-RECONCILE-THROW-SILENT-01, second reach). The
    // fallback suppression must key off a CONFIRMED durable expiry append,
    // not an attempted one: the expiry helper swallows its own append
    // failure, so a set populated before the await records intent, not a
    // row. Executed against round 6: scrub threw AND only the expiry append
    // rejected -> persisted status became `expired`, access remained live,
    // and total audit rows for the grant were ZERO -- the exact silent state
    // the round-6 fix targeted, reached via a different fault schedule.
    const removeFailed = new Error("scrub failed (acl backend down)");
    const { grantStore, auditLog, fsOps, expiring } = await twoGrants({
      removeThrows: removeFailed,
    });

    // Fail ONLY the expiry-reason append; every other append (including the
    // fallback row this test exists to demand) goes through to the real log.
    const appendFailed = new Error("audit backend rejected the append");
    const realAppend = auditLog.appendCritical.bind(auditLog);
    auditLog.appendCritical = (async (entry: Parameters<typeof realAppend>[0]) => {
      const reason = String(
        (entry.details as { reason?: string } | undefined)?.reason ?? "",
      );
      if (reason.startsWith("expired_ttl")) throw appendFailed;
      return realAppend(entry);
    }) as typeof auditLog.appendCritical;

    const rowsForGrantBefore = (await auditLog.query({ limit: 500 })).entries.filter(
      (entry) => (entry.details as { grant_id?: string } | undefined)?.grant_id === expiring.grant_id,
    ).length;

    const error = await reconcileError({ store: grantStore, fsOps, now: PAST_TTL, auditLog });

    // The gate's executed state: flip landed, access still live, caller told.
    expect(error).toBe(removeFailed);
    expect((await grantStore.get(expiring.grant_id))!.status).toBe("expired");
    expect(fsOps.scrubbed).not.toContain(expiring.tree_entry);

    // EXACTLY the fallback row: the expiry row never landed, so the grant
    // must still be eligible for the thrown-scrub trail. Zero rows here is
    // the defect; the count is a delta across every operation so a row filed
    // anywhere would be seen.
    const revokes = await auditLog.query({ operation_type: "file_grant_revoke", limit: 200 });
    const rows = revokes.entries.filter(
      (entry) => (entry.details as { grant_id?: string } | undefined)?.grant_id === expiring.grant_id,
    );
    expect(rows).toHaveLength(1);
    expect(rows[0]!.result).toBe("failure");
    expect((rows[0]!.details as { reason?: string }).reason).toBe("reconcile_scrub_threw");
    expect((rows[0]!.details as { error?: string }).error).toContain(removeFailed.message);
    const rowsForGrantAfter = (await auditLog.query({ limit: 500 })).entries.filter(
      (entry) => (entry.details as { grant_id?: string } | undefined)?.grant_id === expiring.grant_id,
    ).length;
    expect(rowsForGrantAfter - rowsForGrantBefore).toBe(1);
  });

  it("never records an expiry as a success when the scrub that should have removed access threw", async () => {
    // The false-success row. `aclFailureByGrantId` records only a STRUCTURED
    // removal failure; a scrub that THROWS is caught and leaves no entry there.
    // The expiry append therefore saw no failure, a landed status flip, and no
    // write error, and wrote `result: "success"` / `reason: "expired_ttl_scrub"`
    // for a grant whose tree entry was never removed. An audit trail that
    // over-reports an access reduction is the direction that gets believed.
    const { grantStore, auditLog, fsOps, expiring } = await twoGrants({
      removeThrows: new Error("scrub failed (acl backend down)"),
    });

    await reconcileError({ store: grantStore, fsOps, now: PAST_TTL, auditLog });

    // Access was NOT removed.
    expect(fsOps.scrubbed).not.toContain(expiring.tree_entry);

    const revokes = await auditLog.query({ operation_type: "file_grant_revoke", limit: 200 });
    const rows = revokes.entries.filter(
      (e) => (e.details as { grant_id?: string } | undefined)?.grant_id === expiring.grant_id,
    );
    expect(rows).toHaveLength(1);
    // THE PROPERTY: no row may report success for a pass that left access live.
    expect(rows[0]!.result).toBe("failure");
    expect((rows[0]!.details as { reason?: string }).reason).toBe(
      "expired_ttl_scrub_did_not_complete",
    );
  });

  it("makes no reconcile claim on the strict display listing, which never reconciles", async () => {
    const { grantStore, stateStore, sibling } = await twoGrants();

    failReadFor(stateStore, sibling.grant_id, "writer key could not be resolved");

    const error = await grantStore.list().then(
      () => null,
      (err: unknown) => err,
    );

    expect(error).toBeInstanceOf(FileGrantUnreadableEntriesError);
    expect(String((error as Error).message)).toContain(sibling.grant_id);
    expect(String((error as Error).message)).not.toContain(RECONCILED_CLAIM);
  });
});

describe("file-grant reconcile: the durable trail of an unread record", () => {
  it("never appends ahead of the safety-critical removal", async () => {
    const { grantStore, stateStore, auditLog, fsOps, expiring, sibling } = await twoGrants();

    failReadFor(stateStore, sibling.grant_id, "writer key could not be resolved");
    // Record the append against the same timeline the removals are recorded on.
    const realAppend = auditLog.appendCritical.bind(auditLog);
    auditLog.appendCritical = (async (entry: Parameters<typeof realAppend>[0]) => {
      const reason = (entry.details as { reason?: string } | undefined)?.reason;
      if (reason === "reconcile_grant_unreadable") fsOps.events.push("audit:unreadable");
      return realAppend(entry);
    }) as typeof auditLog.appendCritical;

    await reconcileError({ store: grantStore, fsOps, now: PAST_TTL, auditLog });

    const removedAt = fsOps.events.indexOf(`remove:${expiring.tree_entry}`);
    const appendedAt = fsOps.events.indexOf("audit:unreadable");
    expect(removedAt).toBeGreaterThanOrEqual(0);
    expect(appendedAt).toBeGreaterThanOrEqual(0);
    // Nothing unbounded may sit between the listing and the removal; a durable
    // append has no timeout, so its position is the assertion.
    expect(removedAt).toBeLessThan(appendedAt);
  });

  it("is filed under its own operation, since nothing was revoked and no access changed", async () => {
    const { grantStore, stateStore, auditLog, fsOps, sibling } = await twoGrants();

    failReadFor(stateStore, sibling.grant_id, "writer key could not be resolved");

    await reconcileError({
      store: grantStore,
      fsOps,
      now: PAST_TTL,
      auditLog,
      reconciledBy: "operator-1",
    });

    const own = await auditLog.query({ operation_type: "file_grant_reconcile_failed", limit: 200 });
    const recorded = own.entries.filter(
      (entry) => (entry.details as { reason?: string } | undefined)?.reason === "reconcile_grant_unreadable",
    );
    expect(recorded).toHaveLength(1);
    expect((recorded[0]!.details as { grant_id?: string }).grant_id).toBe(sibling.grant_id);
    expect(recorded[0]!.result).toBe("failure");

    // An auditor filtering the revoke operation must not be handed a row where
    // nothing was revoked.
    const revokes = await auditLog.query({ operation_type: "file_grant_revoke", limit: 200 });
    expect(
      revokes.entries.filter(
        (entry) => (entry.details as { reason?: string } | undefined)?.reason === "reconcile_grant_unreadable",
      ),
    ).toHaveLength(0);
  });
});
