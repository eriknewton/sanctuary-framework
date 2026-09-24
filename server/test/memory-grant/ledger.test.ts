import { describe, expect, it } from "vitest";
import {
  addMemoryGrant,
  isMemoryGrantUseAllowed,
  parseMemoryGrantLedger,
  parseMemoryGrantRecord,
  revokeMemoryGrant,
  type MemoryGrantRecord,
  type MemoryGrantUse,
} from "../../src/memory-grant/index.js";

const CREATED = "2026-09-23T12:00:00.000Z";
const EXPIRES = "2026-10-23T12:00:00.000Z";
const ID = "123e4567-e89b-42d3-a456-426614174000";

function record(): MemoryGrantRecord {
  return {
    schema_version: 1,
    grant_id: ID,
    fortress_id: "fortress-1",
    subject_agent_id: "coordinator",
    subject_agent_uid: 502,
    harness: "claude-code",
    source_root: { path: "/Users/operator/context", dev: "16777220", ino: "1234" },
    owner_ref: "fleet-self",
    created_at: CREATED,
    expires_at: EXPIRES,
    revoked_at: null,
    classifier_override: false,
  };
}

function use(): MemoryGrantUse {
  const grant = record();
  return {
    grant_id: grant.grant_id,
    fortress_id: grant.fortress_id,
    subject_agent_id: grant.subject_agent_id,
    subject_agent_uid: grant.subject_agent_uid,
    harness: grant.harness,
    source_root: grant.source_root,
    owner_ref: grant.owner_ref,
    classifier_override_requested: false,
  };
}

const middle = Date.parse("2026-09-24T12:00:00.000Z");

describe("memory-grant record contract", () => {
  it("accepts an exact, bounded record and rejects unknown fields and versions", () => {
    expect(parseMemoryGrantRecord(record())).not.toBeNull();
    expect(parseMemoryGrantRecord({ ...record(), extra: true })).toBeNull();
    expect(parseMemoryGrantRecord({ ...record(), schema_version: 2 })).toBeNull();
    expect(parseMemoryGrantRecord({ ...record(), classifier_override: true })).toBeNull();
    expect(parseMemoryGrantRecord({ ...record(), classifier_override: undefined })).toBeNull();
    expect(parseMemoryGrantRecord({ ...record(), harness: "other" })).toBeNull();
    expect(parseMemoryGrantRecord({ ...record(), harness: "claude_code" })).toBeNull();
    expect(parseMemoryGrantRecord({ ...record(), harness: "codex" })).not.toBeNull();
    expect(parseMemoryGrantRecord({ ...record(), expires_at: null })).toBeNull();
    expect(parseMemoryGrantRecord({ ...record(), expires_at: "2027-01-01T00:00:00.000Z" })).toBeNull();
    expect(parseMemoryGrantRecord({ ...record(), expires_at: CREATED })).toBeNull();
    expect(parseMemoryGrantRecord({ ...record(), created_at: "2026-02-30T00:00:00.000Z" })).toBeNull();
    expect(parseMemoryGrantRecord({ ...record(), revoked_at: "2026-09-22T00:00:00.000Z" })).toBeNull();
    const hidden = Object.defineProperty({ ...record() }, "hidden", { value: true });
    expect(parseMemoryGrantRecord(hidden)).toBeNull();
  });

  it("rejects noncanonical roots and invalid inode or uid identities", () => {
    for (const root of ["/", "/tmp/../context", "/tmp//context", "/tmp/context/", "relative/path", "/tmp/./context"]) {
      expect(parseMemoryGrantRecord({ ...record(), source_root: { ...record().source_root, path: root } })).toBeNull();
    }
    expect(parseMemoryGrantRecord({ ...record(), source_root: { ...record().source_root, ino: "01" } })).toBeNull();
    expect(parseMemoryGrantRecord({ ...record(), source_root: { ...record().source_root, dev: "9".repeat(21) } })).toBeNull();
    expect(parseMemoryGrantRecord({ ...record(), source_root: { ...record().source_root, ino: "9".repeat(21) } })).toBeNull();
    expect(parseMemoryGrantRecord({ ...record(), source_root: { ...record().source_root, extra: 1 } })).toBeNull();
    expect(parseMemoryGrantRecord({ ...record(), subject_agent_uid: -1 })).toBeNull();
    expect(parseMemoryGrantRecord({ ...record(), subject_agent_uid: 0 })).toBeNull();
    expect(parseMemoryGrantRecord({ ...record(), subject_agent_uid: 1.5 })).toBeNull();
    expect(parseMemoryGrantRecord({ ...record(), subject_agent_uid: 0xFFFFFFFF })).toBeNull();
  });

  it("requires every identity and scope binding at use, including inode and classifier", () => {
    const ledger = { schema_version: 1, grants: [record()] };
    expect(isMemoryGrantUseAllowed(ledger, use(), middle)).toBe(true);
    for (const [key, value] of [
      ["grant_id", "123e4567-e89b-42d3-a456-426614174001"],
      ["fortress_id", "other-fortress"],
      ["subject_agent_id", "other-agent"],
      ["subject_agent_uid", 503],
      ["harness", "openclaw"],
      ["owner_ref", "other-owner"],
      ["classifier_override_requested", true],
    ] as const) {
      expect(isMemoryGrantUseAllowed(ledger, { ...use(), [key]: value }, middle)).toBe(false);
    }
    expect(isMemoryGrantUseAllowed(ledger, { ...use(), source_root: { ...use().source_root, path: "/Users/operator" } }, middle)).toBe(false);
    expect(isMemoryGrantUseAllowed(ledger, { ...use(), source_root: { ...use().source_root, dev: "9" } }, middle)).toBe(false);
    expect(isMemoryGrantUseAllowed(ledger, { ...use(), source_root: { ...use().source_root, ino: "9" } }, middle)).toBe(false);
    expect(isMemoryGrantUseAllowed(ledger, { ...use(), source_root: null }, middle)).toBe(false);
    expect(isMemoryGrantUseAllowed(ledger, { ...use(), extra: true }, middle)).toBe(false);
  });

  it("denies missing, malformed, future, expired and revoked grants", () => {
    const ledger = { schema_version: 1, grants: [record()] };
    expect(isMemoryGrantUseAllowed(null, use(), middle)).toBe(false);
    expect(isMemoryGrantUseAllowed({ schema_version: 1, grants: [] }, use(), middle)).toBe(false);
    expect(isMemoryGrantUseAllowed(ledger, use(), Date.parse(CREATED) - 1)).toBe(false);
    expect(isMemoryGrantUseAllowed(ledger, use(), Date.parse(EXPIRES))).toBe(false);
    expect(isMemoryGrantUseAllowed({ schema_version: 1, grants: [{ ...record(), revoked_at: CREATED }] }, use(), middle)).toBe(false);
    expect(isMemoryGrantUseAllowed({ schema_version: 1, grants: [{ ...record(), unknown: 1 }] }, use(), middle)).toBe(false);
    expect(isMemoryGrantUseAllowed(ledger, use(), Number.NaN)).toBe(false);
  });

  it("inserts uniquely and revokes without mutating the old ledger", () => {
    const empty = { schema_version: 1, grants: [] };
    const added = addMemoryGrant(empty, record());
    expect(added).not.toBeNull();
    expect(empty.grants).toEqual([]);
    expect(addMemoryGrant(added, record())).toBeNull();
    const revoked = revokeMemoryGrant(added, ID, middle);
    expect(revoked?.grants[0]?.revoked_at).toBe(new Date(middle).toISOString());
    expect(added?.grants[0]?.revoked_at).toBeNull();
    expect(revokeMemoryGrant(revoked, ID, middle)).toBeNull();
    expect(revokeMemoryGrant(added, ID, Number.MAX_SAFE_INTEGER)).toBeNull();
    expect(isMemoryGrantUseAllowed(revoked, use(), middle)).toBe(false);
    expect(parseMemoryGrantLedger({ schema_version: 1, grants: [record(), record()] })).toBeNull();
  });

  it("accepts the capacity boundary and refuses another grant", () => {
    const grants = Array.from({ length: 1024 }, (_, index) => ({
      ...record(),
      grant_id: `123e4567-e89b-42d3-a456-${String(index).padStart(12, "0")}`,
    }));
    const full = { schema_version: 1, grants };
    expect(parseMemoryGrantLedger(full)).not.toBeNull();
    expect(addMemoryGrant(full, record())).toBeNull();
    expect(parseMemoryGrantLedger({ schema_version: 1, grants: [...grants, record()] })).toBeNull();
  });
});
