/**
 * FG-RECONCILE-EXPIRY-PARSE-01: an expiry nobody can read must not mean
 * "never expires".
 *
 * `expires_at` is typed `string | null` and is read back from stored JSON, so
 * the field holds whatever was written there. `new Date(<garbage>).getTime()`
 * is `NaN`, and every comparison against `NaN` is false, so the natural
 * spelling of the check answers "not expired" for a grant whose expiry cannot
 * be interpreted at all.
 *
 * That failure is silent and it runs the wrong way: reconcile scrubs on this
 * verdict, so the tree entry survives, the agent keeps read access past any
 * intended TTL, and the pass reports nothing expired and nothing scrubbed with
 * exit code zero. Nothing is logged, because from the pass's point of view
 * nothing was due.
 *
 * These tests pin the DIRECTION, which is the part that matters: an
 * uninterpretable expiry reduces access rather than preserving it.
 */
import { describe, expect, it } from "vitest";

import { isGrantExpired, projectGrantStatus } from "../../src/file-grant/lifecycle.js";
import { mintFileGrant } from "../../src/file-grant/mint.js";
import { reconcileFileGrantTree } from "../../src/file-grant/reconcile.js";
import { FakeFsOps, makeFileGrantTestStore } from "./fixtures.js";
import {
  FILE_GRANT_SCHEMA_VERSION,
  type FileGrant,
} from "../../src/file-grant/types.js";

const NOW = new Date("2026-08-18T00:00:00.000Z");

/**
 * A fully typed, valid grant. Only `expires_at` is cast, and only at the point
 * where the test is deliberately simulating what a stored record can hold. A
 * blanket cast over the whole object would hide a genuine shape mistake in the
 * fixture, which is the opposite of what this file is for.
 */
const VALID_GRANT: FileGrant = {
  grant_id: "fg_test",
  schema_version: FILE_GRANT_SCHEMA_VERSION,
  subject_agent_id: "agent-1",
  scope: { kind: "file", path: "/tmp/x.txt" },
  mode: "read",
  created_by: "operator-1",
  created_at: "2026-08-01T00:00:00.000Z",
  expires_at: null,
  status: "active",
  revoked_at: null,
  tree_entry: "agent-1/fg_test",
  audit_refs: [],
};

function grantWithExpiry(expiresAt: unknown): FileGrant {
  // The one cast, and the reason for it: the type states what the code expects
  // of `expires_at`; a record read back from stored JSON carries whatever was
  // written there.
  return { ...VALID_GRANT, expires_at: expiresAt as FileGrant["expires_at"] };
}

describe("an expiry that cannot be parsed", () => {
  it("counts as EXPIRED rather than as never-expiring", () => {
    expect(isGrantExpired(grantWithExpiry("banana"), NOW)).toBe(true);
  });

  it("holds for every uninterpretable shape a stored record can carry", () => {
    for (const value of [
      "banana",
      "",
      "not-a-date",
      "2026-13-45T99:99:99Z",
      {},
      [],
      true,
      Number.NaN,
    ]) {
      expect(isGrantExpired(grantWithExpiry(value), NOW)).toBe(true);
    }
  });

  it("is not fooled by values JavaScript COERCES into valid future dates", () => {
    // The case a NaN check cannot see, and the reason this function parses
    // rather than coerces. `new Date(x)` turns a bare number into an epoch
    // offset, an array into its `toString`, and a bare year into a year. Each
    // yields a valid FUTURE date, so a NaN test passes it and access is
    // preserved exactly as before the fix.
    //
    // The previous version of the test above passed for `[]` and `true` only
    // because they coerce to 1970, which is in the past. It read as "every
    // uninterpretable shape" while proving nothing about the shapes that
    // coerce forwards.
    for (const value of [
      4102444800000, // epoch ms in 2100
      ["2999-01-01T00:00:00.000Z"], // array, via toString
      "2999", // a bare year
      "08/19/2999", // a locale-ish date
    ]) {
      expect(isGrantExpired(grantWithExpiry(value), NOW)).toBe(true);
    }
  });

  it("FG-EXPIRY-CALENDAR-01 (fixed): an impossible calendar date is refused, so the grant expires", () => {
    // Before the fix, `Date.parse` NORMALISED these instead of refusing them
    // (`2999-02-30` to March 2, `2026-02-29` to March 1, `2026-04-31` to
    // May 1), and the far-future one preserved access past the date actually
    // written. The stated threat is CORRUPTION, and this is DETECTABLE
    // corruption: the shipping mint path always writes `toISOString()` output,
    // so no legitimate grant carries February 30.
    //
    // The shared parser now compares the written calendar fields against the
    // parsed instant re-rendered in the written offset
    // (`parseIsoInstantWithOffset`, core/time.ts) and refuses on mismatch,
    // which routes down the same fail-closed branch as any other unreadable
    // expiry. All three reproductions now expire, INCLUDING the far-future one
    // that used to keep its access:
    expect(isGrantExpired(grantWithExpiry("2999-02-30T00:00:00.000Z"), NOW)).toBe(true);
    expect(isGrantExpired(grantWithExpiry("2026-02-29T00:00:00.000Z"), NOW)).toBe(true);
    expect(isGrantExpired(grantWithExpiry("2026-04-31T00:00:00.000Z"), NOW)).toBe(true);

    // The over-strictness guard, on THIS surface: a legitimate future expiry
    // whose written day differs from its UTC day must keep its access. The
    // parser-level must-pass corpus lives in
    // test/core/time-calendar-validity.test.ts; this one line pins that the
    // grant surface inherits it.
    expect(isGrantExpired(grantWithExpiry("2026-08-19T02:00:00+05:30"), NOW)).toBe(false);
  });

  it("leaves a standing grant standing, which is spelled null and nothing else", () => {
    expect(isGrantExpired(grantWithExpiry(null), NOW)).toBe(false);
    expect(projectGrantStatus(grantWithExpiry(null), NOW)).toBe("active");
  });

  it("does not disturb readable expiries in either direction", () => {
    expect(isGrantExpired(grantWithExpiry("2026-08-17T00:00:00.000Z"), NOW)).toBe(true);
    expect(isGrantExpired(grantWithExpiry("2026-08-19T00:00:00.000Z"), NOW)).toBe(false);
  });

  it("still treats a revoked grant as revoked, not additionally expired", () => {
    const revoked = { ...grantWithExpiry("banana"), status: "revoked" as const };
    expect(isGrantExpired(revoked, NOW)).toBe(false);
    expect(projectGrantStatus(revoked, NOW)).toBe("revoked");
  });
});

/**
 * The unit tests above pin the predicate. They would all still pass if the
 * reconcile pass scrubbed access but left the record persisted as active, which
 * is a half-converged state, so the behaviour is proven end to end here from a
 * record that has been through JSON exactly as a stored one has.
 */
describe("reconcile over a record whose expiry cannot be parsed", () => {
  it("removes the entry AND persists the status, from a JSON round-tripped record", async () => {
    const store = await makeFileGrantTestStore();
    const fsOps = new FakeFsOps({ agentUid: 502, sourceOwnerUid: 501 });
    const { grant } = await mintFileGrant(
      {
        subjectAgentId: "agent-1",
        scope: { kind: "file", path: "/tmp/x.txt" },
        mode: "read",
        ttlSeconds: 3600,
        createdBy: "operator-1",
      },
      {
        fsOps,
        store: store.grantStore,
        now: new Date("2026-08-01T00:00:00.000Z"),
        auditLog: store.auditLog,
      }
    );
    const { grant: elapsedGrant } = await mintFileGrant(
      {
        subjectAgentId: "agent-2",
        scope: { kind: "file", path: "/tmp/y.txt" },
        mode: "read",
        ttlSeconds: 3600,
        createdBy: "operator-1",
      },
      {
        fsOps,
        store: store.grantStore,
        now: new Date("2026-08-01T00:00:00.000Z"),
        auditLog: store.auditLog,
      }
    );
    expect(fsOps.placed).toHaveLength(2);

    // Round-tripped through JSON, which is the only way a stored record is ever
    // read back, so the value under test is the value a real fortress holds.
    const live = await store.grantStore.get(grant.grant_id);
    const corrupted = JSON.parse(
      JSON.stringify({ ...live!, expires_at: "not-a-date" })
    );
    await store.grantStore.put(corrupted);

    const result = await reconcileFileGrantTree({
      store: store.grantStore,
      fsOps,
      now: NOW,
      auditLog: store.auditLog,
    });

    // Access is gone.
    expect(fsOps.scrubbed).toContain(grant.tree_entry);
    // AND the record agrees, which is the half the predicate tests cannot see.
    const after = await store.grantStore.get(grant.grant_id);
    expect(after!.status).toBe("expired");
    expect(result.expired).toContain(grant.grant_id);
    expect((await store.grantStore.get(elapsedGrant.grant_id))!.status).toBe("expired");
    expect(result.expired).toContain(elapsedGrant.grant_id);
    // The pass leaves one honest durable trace for each cause. A corrupt expiry
    // must not be described as a TTL that genuinely elapsed, while the clean
    // sibling pins the existing TTL vocabulary against a broad relabel.
    const audit = await store.auditLog.query({
      operation_type: "file_grant_revoke",
      limit: 50,
    });
    const rowsFor = (grantId: string) =>
      audit.entries.filter(
        (entry) =>
          (entry.details as { grant_id?: string } | undefined)?.grant_id === grantId
      );
    const corruptRows = rowsFor(grant.grant_id);
    const elapsedRows = rowsFor(elapsedGrant.grant_id);
    expect(corruptRows).toHaveLength(1);
    expect(elapsedRows).toHaveLength(1);
    expect((corruptRows[0]!.details as { reason?: string }).reason).toBe(
      "invalid_expiry_scrub"
    );
    expect((elapsedRows[0]!.details as { reason?: string }).reason).toBe(
      "expired_ttl_scrub"
    );
  });
});
