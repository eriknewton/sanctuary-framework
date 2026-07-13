/**
 * Governed File-Grant v1 -- pure planner correctness (DoD gate 6).
 *
 * `planGrantTree` fixtures: N active grants -> N tree entries; a revoked or
 * expired grant -> a scrub entry; deterministic ordering; no duplicate
 * placements. No I/O anywhere in this file.
 */

import { describe, expect, it } from "vitest";

import { planGrantTree } from "../../src/file-grant/planner.js";
import { FILE_GRANT_SCHEMA_VERSION, type FileGrant } from "../../src/file-grant/types.js";

const NOW = new Date("2026-07-07T12:00:00.000Z");

function grant(overrides: Partial<FileGrant>): FileGrant {
  return {
    grant_id: "fg_0000000000000000",
    schema_version: FILE_GRANT_SCHEMA_VERSION,
    subject_agent_id: "agent-1",
    scope: { kind: "file", path: "/tmp/a" },
    mode: "read",
    created_by: "operator-1",
    created_at: "2026-07-01T00:00:00.000Z",
    expires_at: null,
    status: "active",
    revoked_at: null,
    tree_entry: "agent-1/fg_0000000000000000",
    audit_refs: [],
    ...overrides,
  };
}

describe("file-grant pure planner", () => {
  it("N active, unexpired grants produce N placements and zero scrubs", () => {
    const grants = [
      grant({ grant_id: "fg_a", tree_entry: "agent-1/fg_a" }),
      grant({ grant_id: "fg_b", tree_entry: "agent-1/fg_b" }),
      grant({ grant_id: "fg_c", tree_entry: "agent-1/fg_c" }),
    ];
    const plan = planGrantTree(grants, NOW);
    expect(plan.toPlace).toHaveLength(3);
    expect(plan.toScrub).toHaveLength(0);
    expect(plan.toPlace.map((e) => e.grant_id)).toEqual(["fg_a", "fg_b", "fg_c"]);
  });

  it("a revoked grant produces a scrub entry, not a placement", () => {
    const grants = [
      grant({ grant_id: "fg_a", status: "revoked", revoked_at: "2026-07-06T00:00:00.000Z" }),
    ];
    const plan = planGrantTree(grants, NOW);
    expect(plan.toPlace).toHaveLength(0);
    expect(plan.toScrub).toHaveLength(1);
    expect(plan.toScrub[0]!.grant_id).toBe("fg_a");
  });

  it("a persisted-active but past-TTL grant produces a scrub entry (expiry computed live)", () => {
    const grants = [
      grant({
        grant_id: "fg_a",
        status: "active",
        expires_at: "2026-07-01T00:00:00.000Z", // in the past relative to NOW
      }),
    ];
    const plan = planGrantTree(grants, NOW);
    expect(plan.toPlace).toHaveLength(0);
    expect(plan.toScrub).toHaveLength(1);
  });

  it("a standing (no-expiry) grant never scrubs, regardless of how far NOW advances", () => {
    const grants = [grant({ grant_id: "fg_a", expires_at: null })];
    const farFuture = new Date("2099-01-01T00:00:00.000Z");
    const plan = planGrantTree(grants, farFuture);
    expect(plan.toPlace).toHaveLength(1);
    expect(plan.toScrub).toHaveLength(0);
  });

  it("deduplicates by tree_entry: two grants sharing a tree_entry place only once", () => {
    const grants = [
      grant({ grant_id: "fg_a", tree_entry: "agent-1/shared" }),
      grant({ grant_id: "fg_b", tree_entry: "agent-1/shared" }),
    ];
    const plan = planGrantTree(grants, NOW);
    expect(plan.toPlace).toHaveLength(1);
  });

  it("orders placements deterministically by grant_id", () => {
    const grants = [
      grant({ grant_id: "fg_c", tree_entry: "agent-1/fg_c" }),
      grant({ grant_id: "fg_a", tree_entry: "agent-1/fg_a" }),
      grant({ grant_id: "fg_b", tree_entry: "agent-1/fg_b" }),
    ];
    const plan = planGrantTree(grants, NOW);
    expect(plan.toPlace.map((e) => e.grant_id)).toEqual(["fg_a", "fg_b", "fg_c"]);
  });

  it("an empty grant set produces an empty plan", () => {
    const plan = planGrantTree([], NOW);
    expect(plan.toPlace).toHaveLength(0);
    expect(plan.toScrub).toHaveLength(0);
  });
});
