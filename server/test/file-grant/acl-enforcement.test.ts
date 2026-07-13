/**
 * Governed File-Grant source-inode ACL plus grant-tree read probe primitive.
 *
 * These tests use the injected fake FsOps only. They prove that `met` is only
 * reachable from an ACL apply result plus a same-operation agent-uid probe
 * through the grant tree returning true, and that every edge fails closed to
 * `unverified` or `unmet`.
 */

import { describe, expect, it } from "vitest";

import { mintFileGrant } from "../../src/file-grant/mint.js";
import type { FileGrantAclResult } from "../../src/file-grant/types.js";
import { FakeFsOps, makeFileGrantTestStore } from "./fixtures.js";

const NOW = new Date("2026-07-13T00:00:00.000Z");
const APPLIED: FileGrantAclResult = { status: "applied", platform: process.platform };

function baseParams() {
  return {
    subjectAgentId: "agent-1",
    scope: { kind: "file" as const, path: "/tmp/example.txt" },
    mode: "read",
    ttlSeconds: 3600,
    createdBy: "operator-1",
  };
}

describe("file-grant ACL/probe enforcement honesty", () => {
  it("returns met only when ACL application is applied and the same-operation probe confirms", async () => {
    const { grantStore } = makeFileGrantTestStore();
    const fsOps = new FakeFsOps({
      agentUid: 502,
      sourceOwnerUid: 501,
      grantAgentReadResult: APPLIED,
      probeAgentReadResult: true,
    });

    const { grant, enforcement } = await mintFileGrant(baseParams(), {
      fsOps,
      store: grantStore,
      now: NOW,
    });

    expect(enforcement).toBe("met");
    expect(grant.granted_read_ace).toEqual({
      agent_uid: 502,
      platform: process.platform,
      source_realpath: "/tmp/example.txt",
    });
    expect(fsOps.events).toEqual([
      `place:${grant.tree_entry}`,
      `grant:${grant.tree_entry}:502:/tmp/example.txt`,
      `probe:${grant.tree_entry}:502`,
    ]);
  });

  it("keeps a uid split unverified when the ACL applies but the probe returns false", async () => {
    const { grantStore } = makeFileGrantTestStore();
    const fsOps = new FakeFsOps({
      agentUid: 502,
      sourceOwnerUid: 501,
      grantAgentReadResult: APPLIED,
      probeAgentReadResult: false,
    });

    const { grant, enforcement } = await mintFileGrant(baseParams(), {
      fsOps,
      store: grantStore,
      now: NOW,
    });

    expect(enforcement).toBe("unverified");
    expect(grant.granted_read_ace).toEqual({
      agent_uid: 502,
      platform: process.platform,
      source_realpath: "/tmp/example.txt",
    });
    expect(fsOps.probedReads).toHaveLength(1);
  });

  it("keeps a uid split unverified when the probe throws", async () => {
    const { grantStore } = makeFileGrantTestStore();
    const fsOps = new FakeFsOps({
      agentUid: 502,
      sourceOwnerUid: 501,
      grantAgentReadResult: APPLIED,
      probeAgentReadThrows: new Error("probe timeout"),
    });

    const { enforcement } = await mintFileGrant(baseParams(), {
      fsOps,
      store: grantStore,
      now: NOW,
    });

    expect(enforcement).toBe("unverified");
    expect(fsOps.probedReads).toHaveLength(1);
  });

  it("keeps a uid split unverified when ACL application is not privileged", async () => {
    const { grantStore } = makeFileGrantTestStore();
    const fsOps = new FakeFsOps({
      agentUid: 502,
      sourceOwnerUid: 501,
      grantAgentReadResult: {
        status: "not_privileged",
        platform: process.platform,
        reason: "EPERM",
      },
      probeAgentReadResult: true,
    });

    const { enforcement } = await mintFileGrant(baseParams(), {
      fsOps,
      store: grantStore,
      now: NOW,
    });

    expect(enforcement).toBe("unverified");
    expect(fsOps.probedReads).toHaveLength(0);
  });

  it("keeps a uid split unverified on unsupported platforms", async () => {
    const { grantStore } = makeFileGrantTestStore();
    const fsOps = new FakeFsOps({
      agentUid: 502,
      sourceOwnerUid: 501,
      grantAgentReadResult: {
        status: "unsupported_platform",
        platform: "win32",
        reason: "unsupported platform win32",
      },
      probeAgentReadResult: true,
    });

    const { enforcement } = await mintFileGrant(baseParams(), {
      fsOps,
      store: grantStore,
      now: NOW,
    });

    expect(enforcement).toBe("unverified");
    expect(fsOps.probedReads).toHaveLength(0);
  });

  it("keeps a same-owner grant unmet even if a probe would pass", async () => {
    const { grantStore } = makeFileGrantTestStore();
    const fsOps = new FakeFsOps({
      agentUid: 502,
      sourceOwnerUid: 502,
      grantAgentReadResult: APPLIED,
      probeAgentReadResult: true,
    });

    const { enforcement } = await mintFileGrant(baseParams(), {
      fsOps,
      store: grantStore,
      now: NOW,
    });

    expect(enforcement).toBe("unmet");
    expect(fsOps.grantedReads).toHaveLength(0);
    expect(fsOps.probedReads).toHaveLength(0);
  });

  it("keeps a uid split unverified when an injected grant op throws", async () => {
    const { grantStore } = makeFileGrantTestStore();
    const fsOps = new FakeFsOps({
      agentUid: 502,
      sourceOwnerUid: 501,
      grantAgentReadThrows: new Error("setfacl failed"),
      probeAgentReadResult: true,
    });

    const { enforcement } = await mintFileGrant(baseParams(), {
      fsOps,
      store: grantStore,
      now: NOW,
    });

    expect(enforcement).toBe("unverified");
    expect(fsOps.probedReads).toHaveLength(0);
  });
});
