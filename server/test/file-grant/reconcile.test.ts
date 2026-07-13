/**
 * Governed File-Grant v1 -- real TTL scrub via reconcile (Fix 4).
 *
 * The pure `planGrantTree` planner is made LOAD-BEARING here: after a grant's
 * TTL passes (injected clock), `reconcileFileGrantTree` must ACTUALLY scrub
 * the tree entry (call `removeEntry`) and flip the persisted status to
 * "expired" via `reviseGrantForExpiry` -- not merely PROJECT "expired" for
 * display. This is what stops agent read access from outliving the stated TTL
 * on a uid-split box.
 */

import { describe, expect, it } from "vitest";

import { mintFileGrant } from "../../src/file-grant/mint.js";
import { reconcileFileGrantTree } from "../../src/file-grant/reconcile.js";
import { listFileGrants } from "../../src/file-grant/list.js";
import type { FileGrantAclResult } from "../../src/file-grant/types.js";
import { DEFAULT_FAKE_SOURCE_IDENTITY, FakeFsOps, makeFileGrantTestStore } from "./fixtures.js";

const APPLIED: FileGrantAclResult = { status: "applied", platform: process.platform };

describe("file-grant reconcile: expired grants are actually scrubbed", () => {
  it("scrubs the tree entry AND flips persisted status once a grant is past its TTL", async () => {
    const { grantStore, auditLog } = makeFileGrantTestStore();
    const fsOps = new FakeFsOps({ agentUid: 502, sourceOwnerUid: 501 });

    const { grant } = await mintFileGrant(
      {
        subjectAgentId: "agent-1",
        scope: { kind: "file", path: "/tmp/example.txt" },
        mode: "read",
        ttlSeconds: 60,
        createdBy: "operator-1",
      },
      { fsOps, store: grantStore, now: new Date("2026-07-07T00:00:00.000Z"), auditLog },
    );

    // Before expiry: reconcile is a no-op (grant still active, entry stays).
    const before = await reconcileFileGrantTree({
      store: grantStore,
      fsOps,
      now: new Date("2026-07-07T00:00:30.000Z"),
      auditLog,
    });
    expect(before.expired).toHaveLength(0);
    expect(before.scrubbed).toHaveLength(0);
    expect((await grantStore.get(grant.grant_id))!.status).toBe("active");

    // After expiry: the tree entry is REMOVED and the record is flipped.
    const after = await reconcileFileGrantTree({
      store: grantStore,
      fsOps,
      now: new Date("2026-07-07T02:00:00.000Z"),
      auditLog,
    });

    expect(after.expired).toContain(grant.grant_id);
    expect(after.scrubbed).toContain(grant.tree_entry);
    // The scrub actually happened at the fs layer.
    expect(fsOps.scrubbed).toContain(grant.tree_entry);
    // The persisted record was flipped, not merely projected.
    expect((await grantStore.get(grant.grant_id))!.status).toBe("expired");
  });

  it("removes a verified grant ACL when expiry scrub removes the tree entry", async () => {
    const { grantStore, auditLog } = makeFileGrantTestStore();
    const fsOps = new FakeFsOps({
      agentUid: 502,
      sourceOwnerUid: 501,
      grantAgentReadResult: APPLIED,
      probeAgentReadResult: true,
    });

    const { grant, enforcement } = await mintFileGrant(
      {
        subjectAgentId: "agent-1",
        scope: { kind: "file", path: "/tmp/example.txt" },
        mode: "read",
        ttlSeconds: 60,
        createdBy: "operator-1",
      },
      { fsOps, store: grantStore, now: new Date("2026-07-07T00:00:00.000Z"), auditLog },
    );
    expect(enforcement).toBe("met");

    await reconcileFileGrantTree({
      store: grantStore,
      fsOps,
      now: new Date("2026-07-07T02:00:00.000Z"),
      auditLog,
    });

    expect(fsOps.removedAcls).toContainEqual({
      entry: grant.tree_entry,
      uid: 502,
      sourceRealpath: grant.scope.path,
      sourceIdentity: DEFAULT_FAKE_SOURCE_IDENTITY,
    });
    expect(fsOps.scrubbed).toContain(grant.tree_entry);
    expect(fsOps.removeOptions).toContainEqual({
      entry: grant.tree_entry,
      options: { grantedReadAce: grant.granted_read_ace },
    });
    const persisted = await grantStore.get(grant.grant_id);
    expect(persisted!.status).toBe("expired");
    expect(persisted!.granted_read_ace).toBeNull();
  });

  it("retains verified grant ACL metadata when expiry scrub cannot confirm removal", async () => {
    const { grantStore, auditLog } = makeFileGrantTestStore();
    const fsOps = new FakeFsOps({
      agentUid: 502,
      sourceOwnerUid: 501,
      grantAgentReadResult: APPLIED,
      probeAgentReadResult: true,
      removeAclThrows: new Error("acl removal failed"),
    });

    const { grant, enforcement } = await mintFileGrant(
      {
        subjectAgentId: "agent-1",
        scope: { kind: "file", path: "/tmp/example.txt" },
        mode: "read",
        ttlSeconds: 60,
        createdBy: "operator-1",
      },
      { fsOps, store: grantStore, now: new Date("2026-07-07T00:00:00.000Z"), auditLog },
    );
    expect(enforcement).toBe("met");

    await expect(
      reconcileFileGrantTree({
        store: grantStore,
        fsOps,
        now: new Date("2026-07-07T02:00:00.000Z"),
        auditLog,
      }),
    ).rejects.toThrow(/failed to remove ACL/);

    const persisted = await grantStore.get(grant.grant_id);
    expect(persisted!.status).toBe("expired");
    expect(persisted!.granted_read_ace).toEqual(grant.granted_read_ace);
  });

  it("never scrubs or expires a standing (no-TTL) grant", async () => {
    const { grantStore } = makeFileGrantTestStore();
    const fsOps = new FakeFsOps({ agentUid: 502, sourceOwnerUid: 501 });

    const { grant } = await mintFileGrant(
      {
        subjectAgentId: "agent-1",
        scope: { kind: "file", path: "/tmp/standing.txt" },
        mode: "read",
        ttlSeconds: null,
        createdBy: "operator-1",
      },
      { fsOps, store: grantStore, now: new Date("2026-07-07T00:00:00.000Z") },
    );

    const result = await reconcileFileGrantTree({
      store: grantStore,
      fsOps,
      now: new Date("2099-01-01T00:00:00.000Z"),
    });

    expect(result.expired).toHaveLength(0);
    expect(result.scrubbed).toHaveLength(0);
    expect((await grantStore.get(grant.grant_id))!.status).toBe("active");
  });

  it("scrubs the expired tree entry even when the status persist THROWS (R2-2 fail-open close)", async () => {
    const { grantStore, auditLog } = makeFileGrantTestStore();
    const fsOps = new FakeFsOps({ agentUid: 502, sourceOwnerUid: 501 });

    const { grant } = await mintFileGrant(
      {
        subjectAgentId: "agent-1",
        scope: { kind: "file", path: "/tmp/expired.txt" },
        mode: "read",
        ttlSeconds: 60,
        createdBy: "operator-1",
      },
      { fsOps, store: grantStore, now: new Date("2026-07-07T00:00:00.000Z"), auditLog },
    );

    // A store whose list() works but whose put() (the status flip) throws. The
    // scrub is the safety-critical action and must run BEFORE / independently of
    // the status write, so a status-write throw must NOT skip the scrub. The
    // throw is still surfaced (bookkeeping lag), but access is already gone.
    const statusPutThrows = {
      list: () => grantStore.list(),
      put: async () => {
        throw new Error("status persist failed");
      },
    };

    await expect(
      reconcileFileGrantTree({
        store: statusPutThrows,
        fsOps,
        now: new Date("2026-07-07T02:00:00.000Z"), // past the 60s TTL
      }),
    ).rejects.toThrow(/status persist failed/);

    // The expired tree entry was STILL scrubbed despite the status-write throw.
    expect(fsOps.scrubbed).toContain(grant.tree_entry);
  });

  it("a list-command touch reconciles (scrubs the expired entry) before projecting -- not merely 'expired' (R2-4)", async () => {
    const { grantStore, auditLog } = makeFileGrantTestStore();
    const fsOps = new FakeFsOps({ agentUid: 502, sourceOwnerUid: 501 });

    const { grant } = await mintFileGrant(
      {
        subjectAgentId: "agent-1",
        scope: { kind: "file", path: "/tmp/list-expiry.txt" },
        mode: "read",
        ttlSeconds: 60,
        createdBy: "operator-1",
      },
      { fsOps, store: grantStore, now: new Date("2026-07-07T00:00:00.000Z"), auditLog },
    );
    expect(fsOps.placed).toHaveLength(1);

    // Replay exactly what `cmdList` now does on every list touch: reconcile at
    // the current clock, THEN project. A mint-once-then-only-list box must not
    // keep an expired symlink alive on disk.
    const listClock = new Date("2026-07-07T02:00:00.000Z"); // past the 60s TTL
    await reconcileFileGrantTree({ store: grantStore, fsOps, now: listClock, auditLog });
    const projected = await listFileGrants(grantStore, listClock);

    // The tree entry was actually SCRUBBED on the list touch (not merely projected).
    expect(fsOps.scrubbed).toContain(grant.tree_entry);
    // The persisted record was flipped, and the projection reflects expired.
    expect((await grantStore.get(grant.grant_id))!.status).toBe("expired");
    expect(
      projected.find((g) => g.grant_id === grant.grant_id)!.projected_status,
    ).toBe("expired");
  });

  it("scrubs a revoked grant's entry idempotently without re-flipping status", async () => {
    const { grantStore } = makeFileGrantTestStore();
    const fsOps = new FakeFsOps({ agentUid: 502, sourceOwnerUid: 501 });

    const { grant } = await mintFileGrant(
      {
        subjectAgentId: "agent-1",
        scope: { kind: "file", path: "/tmp/revoked.txt" },
        mode: "read",
        ttlSeconds: null,
        createdBy: "operator-1",
      },
      { fsOps, store: grantStore, now: new Date("2026-07-07T00:00:00.000Z") },
    );
    // Persist it as revoked directly.
    await grantStore.put({ ...grant, status: "revoked", revoked_at: "2026-07-07T01:00:00.000Z" });

    const result = await reconcileFileGrantTree({
      store: grantStore,
      fsOps,
      now: new Date("2026-07-07T02:00:00.000Z"),
    });

    expect(result.expired).toHaveLength(0); // revoked is not "expired"
    expect(result.scrubbed).toContain(grant.tree_entry);
    expect((await grantStore.get(grant.grant_id))!.status).toBe("revoked");
  });
});
