/**
 * Governed File-Grant v1 -- revoke is idempotent + audited (DoD gate 8).
 *
 * Double-revoke is a no-op-success (not an error); each mint/revoke appends
 * an audit entry, asserted via the in-memory `AuditLog.query`.
 */

import { describe, expect, it } from "vitest";

import { mintFileGrant } from "../../src/file-grant/mint.js";
import { revokeFileGrant } from "../../src/file-grant/revoke.js";
import { FakeFsOps, makeFileGrantTestStore } from "./fixtures.js";

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
});
