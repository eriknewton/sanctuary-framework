/**
 * Governed File-Grant v1 -- fail-closed mint (DoD gate 5, Invariant #5).
 *
 * Two scenarios:
 *   (a) An injected FsOps whose `place()` throws: mint leaves NO active
 *       grant object and NO tree entry (the persisted object is rolled
 *       back), and the caller sees a typed `FileGrantMintFailedError`.
 *   (b) Agent uid === operator uid (or agent uid unknown): mint SUCCEEDS
 *       (the grant is recorded) but reports `enforcement: "unmet"` --
 *       never a false "governed" claim on a same-uid box.
 */

import { describe, expect, it } from "vitest";

import { mintFileGrant } from "../../src/file-grant/mint.js";
import { FileGrantMintFailedError } from "../../src/file-grant/types.js";
import { FakeFsOps, makeFileGrantTestStore } from "./fixtures.js";

describe("file-grant fail-closed mint", () => {
  it("rolls back the persisted grant object when tree placement throws", async () => {
    const { grantStore, auditLog } = makeFileGrantTestStore();
    const placeError = new Error("simulated EPERM: cannot chown to agent uid");
    const fsOps = new FakeFsOps({ placeThrows: placeError });

    await expect(
      mintFileGrant(
        {
          subjectAgentId: "agent-1",
          scope: { kind: "file", path: "/tmp/example.txt" },
          mode: "read",
          ttlSeconds: 3600,
          createdBy: "operator-1",
        },
        { fsOps, store: grantStore, now: new Date("2026-07-07T00:00:00.000Z"), auditLog },
      ),
    ).rejects.toBeInstanceOf(FileGrantMintFailedError);

    // No phantom grant: the object was written then rolled back.
    expect(await grantStore.list()).toHaveLength(0);

    // The failure is still audited.
    const { entries } = await auditLog.query({ operation_type: "file_grant" });
    expect(entries.some((e) => e.result === "failure")).toBe(true);
  });

  it("reports enforcement: unmet when the agent uid equals the operator uid (same-uid box)", async () => {
    const { grantStore } = makeFileGrantTestStore();
    const fsOps = new FakeFsOps({ agentUid: 501, operatorUid: 501 });

    const { grant, enforcement } = await mintFileGrant(
      {
        subjectAgentId: "agent-1",
        scope: { kind: "file", path: "/tmp/example.txt" },
        mode: "read",
        ttlSeconds: 3600,
        createdBy: "operator-1",
      },
      { fsOps, store: grantStore, now: new Date("2026-07-07T00:00:00.000Z") },
    );

    expect(enforcement).toBe("unmet");
    // The grant IS recorded (mint still succeeds), just honestly labeled.
    expect(await grantStore.get(grant.grant_id)).not.toBeNull();
  });

  it("reports enforcement: unmet when no dedicated agent uid is configured at all", async () => {
    const { grantStore } = makeFileGrantTestStore();
    const fsOps = new FakeFsOps({ agentUid: null, operatorUid: 501 });

    const { enforcement } = await mintFileGrant(
      {
        subjectAgentId: "agent-1",
        scope: { kind: "file", path: "/tmp/example.txt" },
        mode: "read",
        ttlSeconds: null,
        createdBy: "operator-1",
      },
      { fsOps, store: grantStore, now: new Date() },
    );

    expect(enforcement).toBe("unmet");
  });

  it("reports enforcement: met when the agent uid is a real, distinct uid", async () => {
    const { grantStore } = makeFileGrantTestStore();
    const fsOps = new FakeFsOps({ agentUid: 502, operatorUid: 501 });

    const { enforcement } = await mintFileGrant(
      {
        subjectAgentId: "agent-1",
        scope: { kind: "file", path: "/tmp/example.txt" },
        mode: "read",
        ttlSeconds: 3600,
        createdBy: "operator-1",
      },
      { fsOps, store: grantStore, now: new Date() },
    );

    expect(enforcement).toBe("met");
  });
});
