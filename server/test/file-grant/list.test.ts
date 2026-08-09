/**
 * Governed File-Grant v1 -- list projection.
 *
 * `listFileGrants` projects each persisted grant's EFFECTIVE status at a
 * given `now` without mutating the store.
 */

import { describe, expect, it } from "vitest";

import { listFileGrants } from "../../src/file-grant/list.js";
import { mintFileGrant } from "../../src/file-grant/mint.js";
import { FakeFsOps, makeFileGrantTestStore } from "./fixtures.js";

describe("file-grant list projection", () => {
  it("projects a past-TTL grant as expired without mutating the persisted record", async () => {
    const { grantStore } = await makeFileGrantTestStore();
    const fsOps = new FakeFsOps({ agentUid: 502, sourceOwnerUid: 501 });

    const { grant } = await mintFileGrant(
      {
        subjectAgentId: "agent-1",
        scope: { kind: "file", path: "/tmp/example.txt" },
        mode: "read",
        ttlSeconds: 60,
        createdBy: "operator-1",
      },
      { fsOps, store: grantStore, now: new Date("2026-07-07T00:00:00.000Z") },
    );

    const later = new Date("2026-07-07T01:00:00.000Z");
    const projected = await listFileGrants(grantStore, later);
    expect(projected).toHaveLength(1);
    expect(projected[0]!.projected_status).toBe("expired");

    // The persisted record itself is untouched (still "active"); listing
    // never mutates the store.
    const persisted = await grantStore.get(grant.grant_id);
    expect(persisted!.status).toBe("active");
  });

  it("filters by subjectAgentId", async () => {
    const { grantStore } = await makeFileGrantTestStore();
    const fsOps = new FakeFsOps({ agentUid: 502, sourceOwnerUid: 501 });

    await mintFileGrant(
      {
        subjectAgentId: "agent-1",
        scope: { kind: "file", path: "/tmp/a" },
        mode: "read",
        ttlSeconds: null,
        createdBy: "operator-1",
      },
      { fsOps, store: grantStore, now: new Date() },
    );
    await mintFileGrant(
      {
        subjectAgentId: "agent-2",
        scope: { kind: "file", path: "/tmp/b" },
        mode: "read",
        ttlSeconds: null,
        createdBy: "operator-1",
      },
      { fsOps, store: grantStore, now: new Date() },
    );

    const filtered = await listFileGrants(grantStore, new Date(), { subjectAgentId: "agent-2" });
    expect(filtered).toHaveLength(1);
    expect(filtered[0]!.subject_agent_id).toBe("agent-2");
  });

  it("returns an empty list when there are no grants", async () => {
    const { grantStore } = await makeFileGrantTestStore();
    expect(await listFileGrants(grantStore, new Date())).toEqual([]);
  });
});
