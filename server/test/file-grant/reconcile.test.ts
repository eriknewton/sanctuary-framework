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
import { FakeFsOps, makeFileGrantTestStore } from "./fixtures.js";

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
