/**
 * Governed File-Grant v1 -- revoke is idempotent + audited (DoD gate 8).
 *
 * Double-revoke is a no-op-success (not an error); each mint/revoke appends
 * an audit entry, asserted via the in-memory `AuditLog.query`.
 */

import { describe, expect, it } from "vitest";

import { mintFileGrant } from "../../src/file-grant/mint.js";
import { revokeFileGrant } from "../../src/file-grant/revoke.js";
import type { FileGrantAclResult } from "../../src/file-grant/types.js";
import { FakeFsOps, makeFileGrantTestStore } from "./fixtures.js";

const APPLIED: FileGrantAclResult = { status: "applied", platform: process.platform };

describe("file-grant revoke: idempotent + audited", () => {
  it("revoking an active grant marks it revoked, scrubs the tree entry, and audits", async () => {
    const { grantStore, auditLog } = makeFileGrantTestStore();
    const fsOps = new FakeFsOps({ agentUid: 502, sourceOwnerUid: 501 });

    const { grant } = await mintFileGrant(
      {
        subjectAgentId: "agent-1",
        scope: { kind: "file", path: "/tmp/example.txt" },
        mode: "read",
        ttlSeconds: 3600,
        createdBy: "operator-1",
      },
      { fsOps, store: grantStore, now: new Date("2026-07-07T00:00:00.000Z"), auditLog },
    );

    const result = await revokeFileGrant(grant.grant_id, "operator-1", {
      fsOps,
      store: grantStore,
      now: new Date("2026-07-07T01:00:00.000Z"),
      auditLog,
    });

    expect(result.found).toBe(true);
    expect(result.alreadyRevoked).toBe(false);
    expect(result.grant!.status).toBe("revoked");
    expect(fsOps.scrubbed).toContain(grant.tree_entry);

    const persisted = await grantStore.get(grant.grant_id);
    expect(persisted!.status).toBe("revoked");

    const { entries } = await auditLog.query({ operation_type: "file_grant_revoke" });
    expect(entries).toHaveLength(1);
    expect(entries[0]!.result).toBe("success");
  });

  it("revoking a verified grant removes the ACL before scrubbing the tree entry", async () => {
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
        ttlSeconds: 3600,
        createdBy: "operator-1",
      },
      { fsOps, store: grantStore, now: new Date("2026-07-07T00:00:00.000Z"), auditLog },
    );
    expect(enforcement).toBe("met");

    await revokeFileGrant(grant.grant_id, "operator-1", {
      fsOps,
      store: grantStore,
      now: new Date("2026-07-07T01:00:00.000Z"),
      auditLog,
    });

    expect(fsOps.removedAcls).toContainEqual({
      entry: grant.tree_entry,
      uid: 502,
      sourceRealpath: grant.scope.path,
    });
    expect(fsOps.scrubbed).toContain(grant.tree_entry);
    expect(fsOps.removeOptions).toContainEqual({
      entry: grant.tree_entry,
      options: { grantedReadAce: grant.granted_read_ace },
    });
    expect(fsOps.events.slice(-2)).toEqual([
      `remove:${grant.tree_entry}`,
      `acl-removed:${grant.tree_entry}:502`,
    ]);
  });

  it("double-revoke is a no-op success, not an error", async () => {
    const { grantStore, auditLog } = makeFileGrantTestStore();
    const fsOps = new FakeFsOps({ agentUid: 502, sourceOwnerUid: 501 });

    const { grant } = await mintFileGrant(
      {
        subjectAgentId: "agent-1",
        scope: { kind: "file", path: "/tmp/example.txt" },
        mode: "read",
        ttlSeconds: null,
        createdBy: "operator-1",
      },
      { fsOps, store: grantStore, now: new Date(), auditLog },
    );

    const first = await revokeFileGrant(grant.grant_id, "operator-1", {
      fsOps,
      store: grantStore,
      now: new Date(),
      auditLog,
    });
    expect(first.alreadyRevoked).toBe(false);

    const second = await revokeFileGrant(grant.grant_id, "operator-1", {
      fsOps,
      store: grantStore,
      now: new Date(),
      auditLog,
    });
    expect(second.found).toBe(true);
    expect(second.alreadyRevoked).toBe(true);

    // Each call (mint, revoke, revoke) leaves its own audit entry.
    const { entries } = await auditLog.query({ operation_type: "file_grant_revoke" });
    expect(entries).toHaveLength(2);
    expect(entries.every((e) => e.result === "success")).toBe(true);
  });

  it("revoking a nonexistent grant id returns found: false and audits a failure", async () => {
    const { grantStore, auditLog } = makeFileGrantTestStore();
    const fsOps = new FakeFsOps();

    const result = await revokeFileGrant("fg_doesnotexist000", "operator-1", {
      fsOps,
      store: grantStore,
      now: new Date(),
      auditLog,
    });

    expect(result.found).toBe(false);
    expect(result.grant).toBeNull();

    const { entries } = await auditLog.query({ operation_type: "file_grant_revoke" });
    expect(entries).toHaveLength(1);
    expect(entries[0]!.result).toBe("failure");
  });

  it("propagates a scrub failure but keeps the record revoked (never resurrected to active)", async () => {
    const { grantStore, auditLog } = makeFileGrantTestStore();
    const mintFsOps = new FakeFsOps({ agentUid: 502, sourceOwnerUid: 501 });

    const { grant } = await mintFileGrant(
      {
        subjectAgentId: "agent-1",
        scope: { kind: "file", path: "/tmp/example.txt" },
        mode: "read",
        ttlSeconds: 3600,
        createdBy: "operator-1",
      },
      { fsOps: mintFsOps, store: grantStore, now: new Date(), auditLog },
    );

    const scrubError = new Error("simulated scrub failure");
    const revokeFsOps = new FakeFsOps({ removeThrows: scrubError });

    await expect(
      revokeFileGrant(grant.grant_id, "operator-1", {
        fsOps: revokeFsOps,
        store: grantStore,
        now: new Date(),
        auditLog,
      }),
    ).rejects.toThrow(scrubError);

    // The record is still revoked even though the scrub failed.
    const persisted = await grantStore.get(grant.grant_id);
    expect(persisted!.status).toBe("revoked");
  });

  it("removes the ACE for the persisted uid even if the current descriptor drifts", async () => {
    const { grantStore, auditLog } = makeFileGrantTestStore();
    const mintFsOps = new FakeFsOps({
      agentUid: 502,
      sourceOwnerUid: 501,
      grantAgentReadResult: APPLIED,
      probeAgentReadResult: true,
    });

    const { grant } = await mintFileGrant(
      {
        subjectAgentId: "agent-1",
        scope: { kind: "file", path: "/tmp/example.txt" },
        mode: "read",
        ttlSeconds: 3600,
        createdBy: "operator-1",
      },
      { fsOps: mintFsOps, store: grantStore, now: new Date(), auditLog },
    );

    const revokeFsOps = new FakeFsOps({ agentUid: 777, sourceOwnerUid: 501 });
    const result = await revokeFileGrant(grant.grant_id, "operator-1", {
      fsOps: revokeFsOps,
      store: grantStore,
      now: new Date(),
      auditLog,
    });

    expect(result.scrubbed).toBe(true);
    expect(revokeFsOps.removedAcls).toContainEqual({
      entry: grant.tree_entry,
      uid: 502,
      sourceRealpath: "/tmp/example.txt",
    });
    expect(revokeFsOps.removedAcls).not.toContainEqual({
      entry: grant.tree_entry,
      uid: 777,
      sourceRealpath: "/tmp/example.txt",
    });
  });

  it("reports ACL removal failure honestly while still unlinking the tree entry", async () => {
    const { grantStore, auditLog } = makeFileGrantTestStore();
    const fsOps = new FakeFsOps({
      agentUid: 502,
      sourceOwnerUid: 501,
      grantAgentReadResult: APPLIED,
      probeAgentReadResult: true,
      removeAclThrows: new Error("acl removal failed"),
    });

    const { grant } = await mintFileGrant(
      {
        subjectAgentId: "agent-1",
        scope: { kind: "file", path: "/tmp/example.txt" },
        mode: "read",
        ttlSeconds: 3600,
        createdBy: "operator-1",
      },
      { fsOps, store: grantStore, now: new Date(), auditLog },
    );

    const result = await revokeFileGrant(grant.grant_id, "operator-1", {
      fsOps,
      store: grantStore,
      now: new Date(),
      auditLog,
    });

    const persisted = await grantStore.get(grant.grant_id);
    expect(persisted!.status).toBe("revoked");
    expect(persisted!.granted_read_ace).toEqual(grant.granted_read_ace);
    expect(result.scrubbed).toBe(false);
    expect(result.treeEntryRemoved).toBe(true);
    expect(result.aclRemoval?.status).toBe("failed");
    expect(fsOps.scrubbed).toContain(grant.tree_entry);

    const { entries } = await auditLog.query({ operation_type: "file_grant_revoke" });
    expect(entries.at(-1)!.result).toBe("failure");
    expect(entries.at(-1)!.details.reason).toBe("acl_removal_failed");
  });
});
