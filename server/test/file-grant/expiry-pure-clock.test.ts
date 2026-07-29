/**
 * Governed File-Grant v1 -- expiry is pure over an injected clock (DoD
 * gate 7).
 *
 * A grant with `expires_at` in the past classifies "expired"; a `null`
 * (standing) grant never expires. No wall-clock sleep anywhere in this
 * file -- every test injects a fixed `now` and asserts a pure function's
 * return value.
 */

import { describe, expect, it } from "vitest";

import {
  computeExpiresAt,
  isGrantExpired,
  parseFileGrantTtlDuration,
  projectGrantStatus,
  reviseGrantForExpiry,
} from "../../src/file-grant/lifecycle.js";
import { FILE_GRANT_SCHEMA_VERSION, type FileGrant } from "../../src/file-grant/types.js";

function grant(overrides: Partial<FileGrant> = {}): FileGrant {
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

describe("parseFileGrantTtlDuration", () => {
  it.each([
    ["30s", 30],
    ["5m", 300],
    ["24h", 86400],
    ["7d", 604800],
  ])("parses %s as %d seconds", (input, expected) => {
    expect(parseFileGrantTtlDuration(input)).toBe(expected);
  });

  it("rejects a malformed duration", () => {
    expect(() => parseFileGrantTtlDuration("not-a-duration")).toThrow();
    expect(() => parseFileGrantTtlDuration("5x")).toThrow();
    expect(() => parseFileGrantTtlDuration("")).toThrow();
  });
});

describe("computeExpiresAt", () => {
  it("computes a future ISO timestamp for a given TTL and now", () => {
    const now = new Date("2026-07-07T00:00:00.000Z");
    expect(computeExpiresAt(3600, now)).toBe("2026-07-07T01:00:00.000Z");
  });

  it("returns null for a null TTL (standing grant)", () => {
    expect(computeExpiresAt(null, new Date())).toBeNull();
  });
});

describe("isGrantExpired / projectGrantStatus over an injected clock", () => {
  it("a grant whose expires_at is in the past is expired at a later now", () => {
    const g = grant({ expires_at: "2026-07-07T00:00:00.000Z" });
    expect(isGrantExpired(g, new Date("2026-07-08T00:00:00.000Z"))).toBe(true);
    expect(projectGrantStatus(g, new Date("2026-07-08T00:00:00.000Z"))).toBe("expired");
  });

  it("a grant whose expires_at is in the future is not expired yet", () => {
    const g = grant({ expires_at: "2026-07-08T00:00:00.000Z" });
    expect(isGrantExpired(g, new Date("2026-07-07T00:00:00.000Z"))).toBe(false);
    expect(projectGrantStatus(g, new Date("2026-07-07T00:00:00.000Z"))).toBe("active");
  });

  it("a standing grant (expires_at: null) never expires, no matter how far now advances", () => {
    const g = grant({ expires_at: null });
    expect(isGrantExpired(g, new Date("2099-01-01T00:00:00.000Z"))).toBe(false);
    expect(projectGrantStatus(g, new Date("2099-01-01T00:00:00.000Z"))).toBe("active");
  });

  it("a revoked grant is never additionally reported as expired", () => {
    const g = grant({
      status: "revoked",
      revoked_at: "2026-07-06T00:00:00.000Z",
      expires_at: "2026-07-01T00:00:00.000Z",
    });
    expect(isGrantExpired(g, new Date("2026-07-08T00:00:00.000Z"))).toBe(false);
    expect(projectGrantStatus(g, new Date("2026-07-08T00:00:00.000Z"))).toBe("revoked");
  });

  it("expiry at the exact boundary instant counts as expired", () => {
    const g = grant({ expires_at: "2026-07-07T00:00:00.000Z" });
    expect(isGrantExpired(g, new Date("2026-07-07T00:00:00.000Z"))).toBe(true);
  });
});

describe("reviseGrantForExpiry", () => {
  it("marks a past-TTL active grant expired", () => {
    const g = grant({ expires_at: "2026-07-01T00:00:00.000Z" });
    const revised = reviseGrantForExpiry(g, new Date("2026-07-08T00:00:00.000Z"));
    expect(revised.status).toBe("expired");
  });

  it("is a no-op for a grant not yet past its TTL", () => {
    const g = grant({ expires_at: "2026-07-08T00:00:00.000Z" });
    const revised = reviseGrantForExpiry(g, new Date("2026-07-07T00:00:00.000Z"));
    expect(revised).toEqual(g);
  });

  it("never resurrects a revoked grant back to expired/active", () => {
    const g = grant({ status: "revoked", expires_at: "2026-07-01T00:00:00.000Z" });
    const revised = reviseGrantForExpiry(g, new Date("2026-07-08T00:00:00.000Z"));
    expect(revised.status).toBe("revoked");
  });
});
