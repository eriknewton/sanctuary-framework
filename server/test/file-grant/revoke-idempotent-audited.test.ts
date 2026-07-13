/**
 * Governed File-Grant v1 -- revoke is idempotent + audited (DoD gate 8).
 *
 * Double-revoke is a no-op-success (not an error); each mint/revoke appends
 * an audit entry, asserted via the in-memory `AuditLog.query`.
 */

import { describe, expect, it } from "vitest";
import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { mintFileGrant } from "../../src/file-grant/mint.js";
import { revokeFileGrant } from "../../src/file-grant/revoke.js";
import {
  FILE_GRANT_SCHEMA_VERSION,
  type FileGrant,
  type FileGrantAclResult,
  type FileGrantSourceIdentity,
} from "../../src/file-grant/types.js";
import {
  PosixFileGrantFsOps,
  type FileGrantExecCommand,
  type FileGrantMacAclLinkOps,
  type FileGrantOpenedFile,
} from "../../src/file-grant/fs-ops.js";
import {
  DEFAULT_FAKE_SOURCE_IDENTITY,
  FakeFsOps,
  SWAPPED_FAKE_SOURCE_IDENTITY,
  makeFileGrantTestStore,
} from "./fixtures.js";

const APPLIED: FileGrantAclResult = { status: "applied", platform: process.platform };
const LINUX_APPLIED: FileGrantAclResult = { status: "applied", platform: "linux" };

function errnoError(code: string, message: string): NodeJS.ErrnoException {
  const err = new Error(message) as NodeJS.ErrnoException;
  err.code = code;
  return err;
}

function makeStoredMacGrant(params: {
  grantId: string;
  treeEntry: string;
  trustedPath: string;
  identity: FileGrantSourceIdentity;
}): FileGrant {
  return {
    grant_id: params.grantId,
    schema_version: FILE_GRANT_SCHEMA_VERSION,
    subject_agent_id: "agent-1",
    scope: { kind: "file", path: "/operator/source.txt" },
    mode: "read",
    created_by: "operator-1",
    created_at: "2026-07-13T00:00:00.000Z",
    expires_at: null,
    status: "active",
    revoked_at: null,
    tree_entry: params.treeEntry,
    granted_read_ace: {
      agent_uid: 502,
      platform: "darwin",
      source_realpath: "/operator/source.txt",
      source_dev: params.identity.source_dev,
      source_ino: params.identity.source_ino,
      mac_principal: "agentuser",
      mac_acl_hardlink_path: params.trustedPath,
    },
    audit_refs: [],
  };
}

function makeMacRevokeFsOps(params: {
  fortress: string;
  identity: FileGrantSourceIdentity;
  failChmod?: boolean;
  missingOnOpen?: boolean;
}): {
  commands: FileGrantExecCommand[];
  fsOps: PosixFileGrantFsOps;
} {
  const commands: FileGrantExecCommand[] = [];
  const macAclLinkOps: FileGrantMacAclLinkOps = {
    link: async () => {},
    open: async (): Promise<FileGrantOpenedFile> => {
      if (params.missingOnOpen) throw errnoError("ENOENT", "missing trusted link");
      return {
        stat: async () => ({
          dev: BigInt(params.identity.source_dev),
          ino: BigInt(params.identity.source_ino),
          uid: 501n,
        }),
        close: async () => {},
      };
    },
    rm: async () => {},
  };
  const fsOps = new PosixFileGrantFsOps(params.fortress, {
    platform: "darwin",
    macAclLinkOps,
    execRunner: {
      execFile: async (command) => {
        commands.push(command);
        if (params.failChmod && command.file === "chmod") {
          throw new Error("chmod -a failed");
        }
        return { stdout: "", stderr: "" };
      },
    },
  });
  return { commands, fsOps };
}

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
      sourceIdentity: DEFAULT_FAKE_SOURCE_IDENTITY,
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
      sourceIdentity: DEFAULT_FAKE_SOURCE_IDENTITY,
    });
    expect(revokeFsOps.removedAcls).not.toContainEqual({
      entry: grant.tree_entry,
      uid: 777,
      sourceRealpath: "/tmp/example.txt",
      sourceIdentity: DEFAULT_FAKE_SOURCE_IDENTITY,
    });
  });

  it("does not remove a persisted ACE when the source inode has changed", async () => {
    const { grantStore, auditLog } = makeFileGrantTestStore();
    const mintFsOps = new FakeFsOps({
      agentUid: 502,
      sourceOwnerUid: 501,
      grantAgentReadResult: LINUX_APPLIED,
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

    const revokeFsOps = new FakeFsOps({
      agentUid: 502,
      sourceOwnerUid: 501,
      removeSourceIdentity: SWAPPED_FAKE_SOURCE_IDENTITY,
    });
    const result = await revokeFileGrant(grant.grant_id, "operator-1", {
      fsOps: revokeFsOps,
      store: grantStore,
      now: new Date(),
      auditLog,
    });

    expect(result.scrubbed).toBe(false);
    expect(result.treeEntryRemoved).toBe(true);
    expect(result.aclRemoval?.status).toBe("failed");
    expect(result.aclRemoval?.reason).toContain("source inode mismatch");
    expect(revokeFsOps.removedAcls).toHaveLength(0);
    expect(revokeFsOps.scrubbed).toContain(grant.tree_entry);

    const persisted = await grantStore.get(grant.grant_id);
    expect(persisted!.status).toBe("revoked");
    expect(persisted!.granted_read_ace).toEqual(grant.granted_read_ace);

    const { entries } = await auditLog.query({ operation_type: "file_grant_revoke" });
    expect(entries.at(-1)!.result).toBe("failure");
    expect(entries.at(-1)!.details.reason).toBe("acl_removal_failed");
    expect(entries.at(-1)!.details.tree_entry_removed).toBe(true);
  });

  it("Linux reports ACL removal failure honestly while still unlinking the grant-tree symlink", async () => {
    const { grantStore, auditLog } = makeFileGrantTestStore();
    const fsOps = new FakeFsOps({
      agentUid: 502,
      sourceOwnerUid: 501,
      grantAgentReadResult: LINUX_APPLIED,
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
    expect(entries.at(-1)!.details.retryable).toBe(true);
  });

  it("macOS chmod failure keeps the trusted hard link and ACE metadata until retry succeeds", async () => {
    const fortress = await mkdtemp(join(tmpdir(), "sanctuary-file-grant-revoke-mac-"));
    try {
      const { grantStore, auditLog } = makeFileGrantTestStore();
      const identity = { source_dev: "11", source_ino: "22" };
      const treeEntry = "agent-1/fg_mac_retry";
      const trustedPath = join(fortress, "grants", treeEntry);
      await mkdir(join(fortress, "grants", "agent-1"), { recursive: true });
      await writeFile(trustedPath, "operator data");
      const grant = makeStoredMacGrant({
        grantId: "fg_mac_retry",
        treeEntry,
        trustedPath,
        identity,
      });
      await grantStore.put(grant);

      const failing = makeMacRevokeFsOps({ fortress, identity, failChmod: true });
      const first = await revokeFileGrant(grant.grant_id, "operator-1", {
        fsOps: failing.fsOps,
        store: grantStore,
        now: new Date("2026-07-13T01:00:00.000Z"),
        auditLog,
      });

      expect(first.scrubbed).toBe(false);
      expect(first.treeEntryRemoved).toBe(false);
      expect(first.aclRemoval?.status).toBe("failed");
      expect(first.aclRemoval?.reason).toContain("chmod -a failed");
      expect(await readFile(trustedPath, "utf8")).toBe("operator data");
      expect((await grantStore.get(grant.grant_id))!.granted_read_ace).toEqual(
        grant.granted_read_ace
      );

      const { entries: afterFailureEntries } = await auditLog.query({
        operation_type: "file_grant_revoke",
      });
      expect(afterFailureEntries.at(-1)!.result).toBe("failure");
      expect(afterFailureEntries.at(-1)!.details.reason).toBe("acl_removal_failed");
      expect(afterFailureEntries.at(-1)!.details.retryable).toBe(true);
      expect(afterFailureEntries.at(-1)!.details.tree_entry_removed).toBe(false);

      const retry = makeMacRevokeFsOps({ fortress, identity });
      const second = await revokeFileGrant(grant.grant_id, "operator-1", {
        fsOps: retry.fsOps,
        store: grantStore,
        now: new Date("2026-07-13T01:05:00.000Z"),
        auditLog,
      });

      expect(second.alreadyRevoked).toBe(true);
      expect(second.scrubbed).toBe(true);
      expect(second.treeEntryRemoved).toBe(true);
      expect(second.aclRemoval?.status).toBe("removed");
      expect(retry.commands).toEqual([
        { file: "chmod", args: ["-a", "user:agentuser allow read,execute", trustedPath] },
      ]);
      await expect(readFile(trustedPath, "utf8")).rejects.toThrow();
      expect((await grantStore.get(grant.grant_id))!.granted_read_ace).toBeNull();
    } finally {
      await rm(fortress, { recursive: true, force: true });
    }
  });

  it("macOS missing hard link at revoke keeps ACE metadata and reports failure, not removed", async () => {
    const fortress = await mkdtemp(join(tmpdir(), "sanctuary-file-grant-revoke-mac-"));
    try {
      const { grantStore, auditLog } = makeFileGrantTestStore();
      const identity = { source_dev: "11", source_ino: "22" };
      const treeEntry = "agent-1/fg_mac_missing";
      const trustedPath = join(fortress, "grants", treeEntry);
      const grant = makeStoredMacGrant({
        grantId: "fg_mac_missing",
        treeEntry,
        trustedPath,
        identity,
      });
      await grantStore.put(grant);

      const missing = makeMacRevokeFsOps({ fortress, identity, missingOnOpen: true });
      const result = await revokeFileGrant(grant.grant_id, "operator-1", {
        fsOps: missing.fsOps,
        store: grantStore,
        now: new Date("2026-07-13T01:00:00.000Z"),
        auditLog,
      });

      expect(result.scrubbed).toBe(false);
      expect(result.treeEntryRemoved).toBe(false);
      expect(result.aclRemoval?.status).toBe("failed");
      expect(result.aclRemoval?.reason).toContain("cannot confirm ACE removal");
      expect(missing.commands).toHaveLength(0);
      const persisted = await grantStore.get(grant.grant_id);
      expect(persisted!.status).toBe("revoked");
      expect(persisted!.granted_read_ace).toEqual(grant.granted_read_ace);

      const { entries } = await auditLog.query({ operation_type: "file_grant_revoke" });
      expect(entries.at(-1)!.result).toBe("failure");
      expect(entries.at(-1)!.details.reason).toBe("acl_removal_failed");
      expect(entries.at(-1)!.details.tree_entry_removed).toBe(false);
    } finally {
      await rm(fortress, { recursive: true, force: true });
    }
  });
});
