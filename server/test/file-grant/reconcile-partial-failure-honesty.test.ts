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
import { FakeFsOps, failReadFor, makeFileGrantTestStore, readsBackAs } from "./fixtures.js";

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
async function twoGrants(opts: { removeThrows?: Error } = {}) {
  const store = await makeFileGrantTestStore();
  const fsOps = new FakeFsOps({
    agentUid: 502,
    sourceOwnerUid: 501,
    ...(opts.removeThrows ? { removeThrows: opts.removeThrows } : {}),
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
