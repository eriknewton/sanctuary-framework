/**
 * Tests for the arm-time uid-existence gate (fix H1): refuses to arm unless
 * the account exists AND its uid exactly matches the uid about to be armed.
 */

import { describe, it, expect } from "vitest";

import { checkUidExistenceBeforeArm, type UidExistenceOps } from "../../../src/castle-wall/provision/uid-gate.js";

function mockOps(uid: number | undefined): UidExistenceOps {
  return { lookupAccountUid: async () => uid };
}

describe("castle-wall/provision/uid-gate", () => {
  it("H1: passes when the account exists at exactly the expected uid", async () => {
    const result = await checkUidExistenceBeforeArm("sanctuary-hermes", 502, mockOps(502));
    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.uid).toBe(502);
    }
  });

  it("H1: refuses when the account does not exist", async () => {
    const result = await checkUidExistenceBeforeArm("sanctuary-hermes", 502, mockOps(undefined));
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.reason).toMatch(/does not exist/);
    }
  });

  it("H1: refuses when the account exists but at a DIFFERENT uid (closes the half-provision fail-open)", async () => {
    const result = await checkUidExistenceBeforeArm("sanctuary-hermes", 502, mockOps(999));
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.reason).toMatch(/not the expected uid/);
    }
  });

  it("propagates a probe exception (fail-closed: caller must treat a throw as refuse-to-arm)", async () => {
    const throwingOps: UidExistenceOps = {
      lookupAccountUid: async () => {
        throw new Error("directory service unreachable");
      },
    };
    await expect(checkUidExistenceBeforeArm("sanctuary-hermes", 502, throwingOps)).rejects.toThrow(
      /directory service unreachable/,
    );
  });
});
