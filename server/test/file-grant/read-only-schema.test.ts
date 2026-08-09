// fail-before-exempt: inherited supporting file-grant coverage still passes against pre-fix source; key-resolution fail-before coverage lives in state-envelope-integrity.test.ts and master-rotation.test.ts
/**
 * Governed File-Grant v1 -- read-only schema enforcement (DoD gate 4).
 *
 * `mode: "write"` (or any non-"read" value) at mint is REJECTED with a typed
 * error, proving v1 is read-only by construction. Write-mode grants are
 * explicitly out of scope (build spec section 8).
 */

import { describe, expect, it } from "vitest";

import { mintFileGrant } from "../../src/file-grant/mint.js";
import { FileGrantModeRejectedError } from "../../src/file-grant/types.js";
import { FakeFsOps, makeFileGrantTestStore } from "./fixtures.js";

describe("file-grant read-only schema enforcement", () => {
  it("rejects mode: write with a typed error", async () => {
    const { grantStore } = await makeFileGrantTestStore();
    const fsOps = new FakeFsOps();

    await expect(
      mintFileGrant(
        {
          subjectAgentId: "agent-1",
          scope: { kind: "file", path: "/tmp/example.txt" },
          mode: "write",
          ttlSeconds: 3600,
          createdBy: "operator-1",
        },
        { fsOps, store: grantStore, now: new Date("2026-07-07T00:00:00.000Z") },
      ),
    ).rejects.toBeInstanceOf(FileGrantModeRejectedError);

    // No grant object and no tree entry: the reject happens before any
    // persistence or placement is attempted.
    expect(await grantStore.list()).toHaveLength(0);
    expect(fsOps.placed).toHaveLength(0);
  });

  it("rejects an arbitrary non-read mode string", async () => {
    const { grantStore } = await makeFileGrantTestStore();
    const fsOps = new FakeFsOps();

    await expect(
      mintFileGrant(
        {
          subjectAgentId: "agent-1",
          scope: { kind: "dir", path: "/tmp/example-dir" },
          mode: "readwrite",
          ttlSeconds: null,
          createdBy: "operator-1",
        },
        { fsOps, store: grantStore, now: new Date() },
      ),
    ).rejects.toThrow(/read-only/);
  });
});
