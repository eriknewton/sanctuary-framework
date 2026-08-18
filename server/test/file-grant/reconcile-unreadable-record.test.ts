/**
 * Governed File-Grant -- the tree reconcile converges every grant it can read
 * (FG-RECONCILE-ORDER-01).
 *
 * CAPABILITY ASSERTED HERE. When one persisted grant record does not read back,
 * `reconcileFileGrantTree` still scrubs the tree entry and read ACE of every
 * OTHER grant whose TTL has passed, still flips those records to "expired", and
 * only then reports the unread record to its caller. Two properties have to
 * hold together: removing access is the safety property, and the report
 * reaching the caller is the honesty property. A pass that satisfies one by
 * dropping the other is not a pass.
 *
 * FAULT SCHEDULE EXERCISED (AGENTS.md rule 12). A per-entry read rejection
 * raised inside the listing fan-out that feeds a reconcile pass, with a second
 * grant already past its TTL and holding a live tree entry, so the ordering
 * between the read fan-out and the scrub is what the assertions turn on.
 */

import { describe, expect, it } from "vitest";

import { mintFileGrant } from "../../src/file-grant/mint.js";
import { reconcileFileGrantTree } from "../../src/file-grant/reconcile.js";
import { FileGrantUnreadableEntriesError } from "../../src/file-grant/types.js";
import type { StateStore } from "../../src/cognitive/state-store.js";
import { FakeFsOps, makeFileGrantTestStore } from "./fixtures.js";

const MINTED_AT = new Date("2026-07-07T00:00:00.000Z");
const PAST_TTL = new Date("2026-07-07T02:00:00.000Z");

/**
 * Make one specific grant key's StateStore read reject, the way an entry whose
 * writer key cannot be resolved does, while every other key still reads. The
 * patch goes on `read` only: `StateStore.list` enumerates through the storage
 * backend, so both keys still appear in the listing and the fan-out genuinely
 * has to survive one of them.
 */
function failReadFor(stateStore: StateStore, key: string, message: string): void {
  const realRead = stateStore.read.bind(stateStore);
  stateStore.read = (async (
    namespace: string,
    readKey: string,
    ...rest: unknown[]
  ) => {
    if (readKey === key) throw new Error(message);
    return (realRead as (...args: unknown[]) => unknown)(namespace, readKey, ...rest);
  }) as typeof stateStore.read;
}

async function mintGrant(
  deps: { fsOps: FakeFsOps; store: Awaited<ReturnType<typeof makeFileGrantTestStore>>["grantStore"]; auditLog: Awaited<ReturnType<typeof makeFileGrantTestStore>>["auditLog"] },
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

describe("file-grant reconcile: one unread record never holds another grant's access open", () => {
  it("scrubs the expired grant's tree entry and flips its status even though a sibling record does not read", async () => {
    const { grantStore, stateStore, auditLog } = await makeFileGrantTestStore();
    const fsOps = new FakeFsOps({ agentUid: 502, sourceOwnerUid: 501 });

    const expiring = await mintGrant(
      { fsOps, store: grantStore, auditLog },
      "agent-expiring",
      "/tmp/expiring.txt",
    );
    const sibling = await mintGrant(
      { fsOps, store: grantStore, auditLog },
      "agent-sibling",
      "/tmp/sibling.txt",
    );
    expect(fsOps.placed).toHaveLength(2);

    failReadFor(stateStore, sibling.grant_id, "writer key could not be resolved");

    await expect(
      reconcileFileGrantTree({
        store: grantStore,
        fsOps,
        now: PAST_TTL,
        auditLog,
        reconciledBy: "operator-1",
      }),
    ).rejects.toBeInstanceOf(FileGrantUnreadableEntriesError);

    // THE SAFETY PROPERTY: the expired grant's access is gone. This is the
    // assertion that distinguishes a reconcile that ran from one that never
    // reached its scrub loop.
    expect(fsOps.scrubbed).toContain(expiring.tree_entry);
    // THE BOOKKEEPING RAN TOO, so the throw is genuinely deferred to the end
    // rather than merely moved a few lines later.
    expect((await grantStore.get(expiring.grant_id))!.status).toBe("expired");
  });

  it("reports the unread record to the caller by grant id, after the scrub", async () => {
    const { grantStore, stateStore, auditLog } = await makeFileGrantTestStore();
    const fsOps = new FakeFsOps({ agentUid: 502, sourceOwnerUid: 501 });

    const expiring = await mintGrant(
      { fsOps, store: grantStore, auditLog },
      "agent-expiring",
      "/tmp/expiring.txt",
    );
    const sibling = await mintGrant(
      { fsOps, store: grantStore, auditLog },
      "agent-sibling",
      "/tmp/sibling.txt",
    );

    failReadFor(stateStore, sibling.grant_id, "writer key could not be resolved");

    // THE HONESTY PROPERTY: swallowing the read failure would trade one silent
    // failure for another, so the error must still reach the caller, and must
    // name which record was not read.
    const error = await reconcileFileGrantTree({
      store: grantStore,
      fsOps,
      now: PAST_TTL,
      auditLog,
    }).then(
      () => null,
      (err: unknown) => err as FileGrantUnreadableEntriesError,
    );

    expect(error).toBeInstanceOf(FileGrantUnreadableEntriesError);
    expect(error!.grantIds).toEqual([sibling.grant_id]);
    expect(String(error)).toContain(sibling.grant_id);
    // ... and the scrub that ran before it is still visible in the same run.
    expect(fsOps.scrubbed).toContain(expiring.tree_entry);
  });

  it("leaves the unread grant's own tree entry alone, since its state is unknown", async () => {
    const { grantStore, stateStore, auditLog } = await makeFileGrantTestStore();
    const fsOps = new FakeFsOps({ agentUid: 502, sourceOwnerUid: 501 });

    const expiring = await mintGrant(
      { fsOps, store: grantStore, auditLog },
      "agent-expiring",
      "/tmp/expiring.txt",
    );
    const sibling = await mintGrant(
      { fsOps, store: grantStore, auditLog },
      "agent-sibling",
      "/tmp/sibling.txt",
    );

    failReadFor(stateStore, sibling.grant_id, "writer key could not be resolved");

    await expect(
      reconcileFileGrantTree({ store: grantStore, fsOps, now: PAST_TTL, auditLog }),
    ).rejects.toBeInstanceOf(FileGrantUnreadableEntriesError);

    // The stated bound: reconcile never acts on a record it has not read, so
    // the unread grant is exactly where the run found it. That is one grant
    // unconverged, which is what the caller is told; it is not access widened.
    expect(fsOps.scrubbed).not.toContain(sibling.tree_entry);
    expect(fsOps.scrubbed).toContain(expiring.tree_entry);
  });

  it("names every unread record, not just the first", async () => {
    const { grantStore, stateStore, auditLog } = await makeFileGrantTestStore();
    const fsOps = new FakeFsOps({ agentUid: 502, sourceOwnerUid: 501 });

    const expiring = await mintGrant(
      { fsOps, store: grantStore, auditLog },
      "agent-expiring",
      "/tmp/expiring.txt",
    );
    const first = await mintGrant(
      { fsOps, store: grantStore, auditLog },
      "agent-first",
      "/tmp/first.txt",
    );
    const second = await mintGrant(
      { fsOps, store: grantStore, auditLog },
      "agent-second",
      "/tmp/second.txt",
    );

    failReadFor(stateStore, first.grant_id, "writer key could not be resolved");
    failReadFor(stateStore, second.grant_id, "writer key could not be resolved");

    const error = await reconcileFileGrantTree({
      store: grantStore,
      fsOps,
      now: PAST_TTL,
      auditLog,
    }).then(
      () => null,
      (err: unknown) => err as FileGrantUnreadableEntriesError,
    );

    expect(error).toBeInstanceOf(FileGrantUnreadableEntriesError);
    expect([...error!.grantIds].sort()).toEqual([first.grant_id, second.grant_id].sort());
    expect(fsOps.scrubbed).toContain(expiring.tree_entry);
  });

  it("records each unread record in the audit trail so the loss is durable", async () => {
    const { grantStore, stateStore, auditLog } = await makeFileGrantTestStore();
    const fsOps = new FakeFsOps({ agentUid: 502, sourceOwnerUid: 501 });

    await mintGrant({ fsOps, store: grantStore, auditLog }, "agent-expiring", "/tmp/expiring.txt");
    const sibling = await mintGrant(
      { fsOps, store: grantStore, auditLog },
      "agent-sibling",
      "/tmp/sibling.txt",
    );

    failReadFor(stateStore, sibling.grant_id, "writer key could not be resolved");

    await expect(
      reconcileFileGrantTree({
        store: grantStore,
        fsOps,
        now: PAST_TTL,
        auditLog,
        reconciledBy: "operator-1",
      }),
    ).rejects.toBeInstanceOf(FileGrantUnreadableEntriesError);

    const entries = (await auditLog.query({ limit: 200 })).entries;
    const recorded = entries.filter(
      (entry) =>
        (entry.details as { reason?: string } | undefined)?.reason ===
        "reconcile_grant_unreadable",
    );
    expect(recorded).toHaveLength(1);
    expect((recorded[0]!.details as { grant_id?: string }).grant_id).toBe(sibling.grant_id);
    expect(recorded[0]!.result).toBe("failure");
  });

  it("still converges cleanly, with no deferred error, when every record reads", async () => {
    const { grantStore, auditLog } = await makeFileGrantTestStore();
    const fsOps = new FakeFsOps({ agentUid: 502, sourceOwnerUid: 501 });

    const expiring = await mintGrant(
      { fsOps, store: grantStore, auditLog },
      "agent-expiring",
      "/tmp/expiring.txt",
    );

    const result = await reconcileFileGrantTree({
      store: grantStore,
      fsOps,
      now: PAST_TTL,
      auditLog,
    });

    expect(result.expired).toContain(expiring.grant_id);
    expect(result.scrubbed).toContain(expiring.tree_entry);
  });
});
