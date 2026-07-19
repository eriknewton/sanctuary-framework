/**
 * Tests for the dedicated agent service-account plan/create plumbing:
 * idempotency (skip-if-matches), conflict refusal (never silently
 * reassign), safe-name validation, uid selection (lowest free >=
 * ceiling, never colliding with an existing uid), and (fix F7) that the
 * create plan/execution binds the account's home to the re-home target.
 */

import { describe, it, expect } from "vitest";

import {
  deriveAgentAccountName,
  AccountProvisionVerificationError,
  parseServiceAccountIsHidden,
  planAccountCreate,
  executeAccountProvisionPlan,
  planAndCreateAccount,
  serviceAccountRecordProblems,
  type AccountProvisionOps,
  type ServiceAccountRecord,
} from "../../../src/castle-wall/provision/account.js";

const CEILING = 500;
const HOME_DIR = "/var/sanctuary-agents/sanctuary-hermes";

function completeRecord(uid: number, homeDirectory: string = HOME_DIR): ServiceAccountRecord {
  return { uid, homeDirectory, isHidden: true, userShell: "/usr/bin/false" };
}

function canonicalHome(path: string): string {
  return path.replace(/^\/var(?=\/|$)/, "/private/var").replace(/\/+$/, "");
}

function mockOps(
  overrides: Partial<AccountProvisionOps> & {
    initialRecord?: ServiceAccountRecord;
    createRecord?: (accountName: string, uid: number, homeDirectory: string) => ServiceAccountRecord;
    createThrowsAfterRecord?: Error;
  } = {},
): AccountProvisionOps & {
  created: Array<{ accountName: string; uid: number; comment: string | undefined; homeDirectory: string }>;
  hardened: string[];
  deleted: string[];
  record: ServiceAccountRecord | undefined;
} {
  const created: Array<{ accountName: string; uid: number; comment: string | undefined; homeDirectory: string }> = [];
  const hardened: string[] = [];
  const deleted: string[] = [];
  const { initialRecord, createRecord, createThrowsAfterRecord, ...opsOverrides } = overrides;
  let record = initialRecord;
  return {
    created,
    hardened,
    deleted,
    get record() {
      return record;
    },
    lookupAccountUid: async () => record?.uid,
    lookupAccountRecord: async () => record,
    canonicalizeHomeDirectory: async (path) => canonicalHome(path),
    highestAssignedUid: async () => 499,
    createUser: async (accountName, uid, comment, homeDirectory) => {
      created.push({ accountName, uid, comment, homeDirectory });
      record =
        createRecord?.(accountName, uid, homeDirectory) ?? {
          uid,
          homeDirectory,
          userShell: "/usr/bin/false",
        };
      if (createThrowsAfterRecord !== undefined) {
        throw createThrowsAfterRecord;
      }
    },
    hardenCreatedUser: async (accountName) => {
      hardened.push(accountName);
      if (record !== undefined) record = { ...record, isHidden: true };
    },
    deleteCreatedUser: async (accountName) => {
      deleted.push(accountName);
      record = undefined;
    },
    ...opsOverrides,
  };
}

describe("castle-wall/provision/account", () => {
  it("derives the canonical account name from an agent id", () => {
    expect(deriveAgentAccountName("hermes")).toBe("sanctuary-hermes");
  });

  describe("parseServiceAccountIsHidden", () => {
    it.each(["1", "YES", "yes", "TRUE", "true"])("accepts hidden spelling %s", (value) => {
      expect(parseServiceAccountIsHidden(value)).toBe(true);
    });

    it.each(["0", "NO", "false", "maybe"])("does not accept non-hidden spelling %s", (value) => {
      expect(parseServiceAccountIsHidden(value)).toBe(false);
    });

    it("preserves an absent attribute as absent", () => {
      expect(parseServiceAccountIsHidden(undefined)).toBeUndefined();
    });
  });

  describe("planAccountCreate", () => {
    it("plans create with the lowest free uid >= ceiling when no account exists", () => {
      const plan = planAccountCreate(
        { accountName: "sanctuary-hermes", ceiling: CEILING, homeDirectory: HOME_DIR },
        { existingUid: undefined, highestAssignedUid: 499 },
      );
      expect(plan).toEqual({ action: "create", accountName: "sanctuary-hermes", uid: 500 });
    });

    it("plans create ABOVE the ceiling when the highest assigned uid already exceeds it", () => {
      const plan = planAccountCreate(
        { accountName: "sanctuary-hermes", ceiling: CEILING, homeDirectory: HOME_DIR },
        { existingUid: undefined, highestAssignedUid: 510 },
      );
      expect(plan).toEqual({ action: "create", accountName: "sanctuary-hermes", uid: 511 });
    });

    it("plans skip (idempotent) when the account already exists at a uid >= ceiling", () => {
      const plan = planAccountCreate(
        { accountName: "sanctuary-hermes", ceiling: CEILING, homeDirectory: HOME_DIR },
        { existingUid: 502, highestAssignedUid: 510 },
      );
      expect(plan.action).toBe("skip");
      if (plan.action === "skip") {
        expect(plan.uid).toBe(502);
      }
    });

    it("plans skip when the account uid exactly equals the ceiling (boundary)", () => {
      const plan = planAccountCreate(
        { accountName: "sanctuary-hermes", ceiling: CEILING, homeDirectory: HOME_DIR },
        { existingUid: CEILING, highestAssignedUid: CEILING },
      );
      expect(plan.action).toBe("skip");
    });

    it("plans conflict (refuses) when the account exists at a uid BELOW the ceiling", () => {
      const plan = planAccountCreate(
        { accountName: "sanctuary-hermes", ceiling: CEILING, homeDirectory: HOME_DIR },
        { existingUid: 42, highestAssignedUid: 510 },
      );
      expect(plan.action).toBe("conflict");
      if (plan.action === "conflict") {
        expect(plan.existingUid).toBe(42);
      }
    });

    it("rejects an unsafe account name", () => {
      expect(() =>
        planAccountCreate(
          { accountName: "sanctuary agent", ceiling: CEILING, homeDirectory: HOME_DIR },
          { existingUid: undefined, highestAssignedUid: 499 },
        ),
      ).toThrow(/not a safe service-account name/);
    });

    it.each(["root", "_root", "daemon", "wheel", "admin"])(
      "refuses a reserved/privileged account name %s",
      (accountName) => {
        expect(() =>
          planAccountCreate(
            { accountName, ceiling: CEILING, homeDirectory: HOME_DIR },
            { existingUid: undefined, highestAssignedUid: 499 },
          ),
        ).toThrow(/privileged\/reserved name/);
      },
    );

    it("rejects a non-positive ceiling", () => {
      expect(() =>
        planAccountCreate(
          { accountName: "sanctuary-hermes", ceiling: 0, homeDirectory: HOME_DIR },
          { existingUid: undefined, highestAssignedUid: 499 },
        ),
      ).toThrow(/positive integer/);
    });

    it("fix F7: rejects a non-absolute home directory", () => {
      expect(() =>
        planAccountCreate(
          { accountName: "sanctuary-hermes", ceiling: CEILING, homeDirectory: "relative/path" },
          { existingUid: undefined, highestAssignedUid: 499 },
        ),
      ).toThrow(/absolute path/);
    });

    it("fix F7: rejects a home directory containing '..' segments", () => {
      expect(() =>
        planAccountCreate(
          { accountName: "sanctuary-hermes", ceiling: CEILING, homeDirectory: "/var/sanctuary-agents/../etc" },
          { existingUid: undefined, highestAssignedUid: 499 },
        ),
      ).toThrow(/no "\.\." segments/);
    });
  });

  describe("executeAccountProvisionPlan", () => {
    it("calls createUser only for a create plan, WITH the home directory bound (fix F7)", async () => {
      const ops = mockOps();
      const plan = planAccountCreate(
        { accountName: "sanctuary-hermes", ceiling: CEILING, homeDirectory: HOME_DIR },
        { existingUid: undefined, highestAssignedUid: 499 },
      );
      const result = await executeAccountProvisionPlan(
        plan,
        { accountName: "sanctuary-hermes", ceiling: CEILING, homeDirectory: HOME_DIR },
        ops,
      );
      expect(result.uid).toBe(500);
      expect(ops.created).toEqual([
        { accountName: "sanctuary-hermes", uid: 500, comment: undefined, homeDirectory: HOME_DIR },
      ]);
      expect(ops.hardened).toEqual(["sanctuary-hermes"]);
    });

    it("does not call createUser for a skip plan (idempotent no-op)", async () => {
      const ops = mockOps({ initialRecord: completeRecord(502) });
      const plan = planAccountCreate(
        { accountName: "sanctuary-hermes", ceiling: CEILING, homeDirectory: HOME_DIR },
        { existingUid: 502, highestAssignedUid: 510 },
      );
      const result = await executeAccountProvisionPlan(
        plan,
        { accountName: "sanctuary-hermes", ceiling: CEILING, homeDirectory: HOME_DIR },
        ops,
      );
      expect(result.uid).toBe(502);
      expect(ops.created).toEqual([]);
      expect(ops.hardened).toEqual([]);
    });

    it("throws (never mutates) for a conflict plan", async () => {
      const ops = mockOps();
      const plan = planAccountCreate(
        { accountName: "sanctuary-hermes", ceiling: CEILING, homeDirectory: HOME_DIR },
        { existingUid: 42, highestAssignedUid: 510 },
      );
      await expect(
        executeAccountProvisionPlan(
          plan,
          { accountName: "sanctuary-hermes", ceiling: CEILING, homeDirectory: HOME_DIR },
          ops,
        ),
      ).rejects.toThrow(/below the ceiling/);
      expect(ops.created).toEqual([]);
      expect(ops.hardened).toEqual([]);
    });
  });

  describe("planAndCreateAccount (probe + plan + execute)", () => {
    it("probes, plans create, and executes end to end, binding the home directory (fix F7)", async () => {
      const ops = mockOps();
      const { plan, uid } = await planAndCreateAccount(
        { accountName: "sanctuary-hermes", ceiling: CEILING, homeDirectory: HOME_DIR },
        ops,
      );
      expect(plan.action).toBe("create");
      expect(uid).toBe(500);
      expect(ops.created).toEqual([
        { accountName: "sanctuary-hermes", uid: 500, comment: undefined, homeDirectory: HOME_DIR },
      ]);
      expect(ops.hardened).toEqual(["sanctuary-hermes"]);
    });

    it("is idempotent: a second run against an ops that now reports the account existing plans skip", async () => {
      const ops = mockOps({ initialRecord: completeRecord(500), highestAssignedUid: async () => 510 });
      const { plan, uid } = await planAndCreateAccount(
        { accountName: "sanctuary-hermes", ceiling: CEILING, homeDirectory: HOME_DIR },
        ops,
      );
      expect(plan.action).toBe("skip");
      expect(uid).toBe(500);
      expect(ops.created).toEqual([]);
      expect(ops.hardened).toEqual([]);
    });

    it("B1: rolls back an observed fresh shared account when primary create mutates then throws", async () => {
      const ops = mockOps({
        createThrowsAfterRecord: new Error("dscl IsHidden write failed after sysadminctl created account"),
      });
      await expect(
        planAndCreateAccount(
          { accountName: "sanctuary-hermes", ceiling: CEILING, homeDirectory: HOME_DIR },
          ops,
        ),
      ).rejects.toThrow(/rollback observed: sanctuary-hermes account record is absent/);
      expect(ops.created).toHaveLength(1);
      expect(ops.hardened).toEqual([]);
      expect(ops.deleted).toEqual(["sanctuary-hermes"]);
      expect(ops.record).toBeUndefined();
    });

    it("B2: rolls back an observed fresh shared account when post-create hardening fails", async () => {
      const ops = mockOps({
        hardenCreatedUser: async () => {
          throw new Error("dscl IsHidden write failed");
        },
      });
      await expect(
        planAndCreateAccount(
          { accountName: "sanctuary-hermes", ceiling: CEILING, homeDirectory: HOME_DIR },
          ops,
        ),
      ).rejects.toThrow(/Creating service account .*dscl IsHidden write failed.*rollback observed/s);
      expect(ops.created).toHaveLength(1);
      expect(ops.deleted).toEqual(["sanctuary-hermes"]);
      expect(ops.record).toBeUndefined();
    });

    it("H1: does not roll back a record whose observed uid differs from this run's planned uid", async () => {
      const ops = mockOps({
        createThrowsAfterRecord: new Error("user already exists"),
        createRecord: () => completeRecord(777),
      });
      await expect(
        planAndCreateAccount(
          { accountName: "sanctuary-hermes", ceiling: CEILING, homeDirectory: HOME_DIR },
          ops,
        ),
      ).rejects.toThrow(/rollback NOT attempted.*uid 777 does not match this run's planned uid 500/s);
      expect(ops.deleted).toEqual([]);
      expect(ops.record).toEqual(completeRecord(777));
    });

    it("H1: refuses before arming when the created agent account has no home read-back, then rolls it back", async () => {
      const ops = mockOps({
        createRecord: (_name, uid) => ({ uid, isHidden: true, userShell: "/usr/bin/false" }),
      });
      await expect(
        planAndCreateAccount(
          { accountName: "sanctuary-hermes", ceiling: CEILING, homeDirectory: HOME_DIR },
          ops,
        ),
      ).rejects.toThrow(AccountProvisionVerificationError);
      expect(ops.created).toHaveLength(1);
      expect(ops.deleted).toEqual(["sanctuary-hermes"]);
    });

    it("B1/H1: accepts a symlink-resolved NFSHomeDirectory form after canonical comparison", async () => {
      const ops = mockOps({
        createRecord: (_name, uid) => completeRecord(uid, "/private/var/sanctuary-agents/sanctuary-hermes/"),
      });
      const result = await planAndCreateAccount(
        { accountName: "sanctuary-hermes", ceiling: CEILING, homeDirectory: HOME_DIR },
        ops,
      );
      expect(result.uid).toBe(500);
      expect(result.observed).toContain("/private/var/sanctuary-agents/sanctuary-hermes/");
    });

    it("B2/H1: refuses a same uid/home service account missing hidden/no-login hardening", async () => {
      const ops = mockOps({
        initialRecord: { uid: 500, homeDirectory: HOME_DIR, userShell: "/bin/zsh" },
        highestAssignedUid: async () => 510,
      });
      await expect(
        planAndCreateAccount(
          { accountName: "sanctuary-hermes", ceiling: CEILING, homeDirectory: HOME_DIR },
          ops,
        ),
      ).rejects.toThrow(/IsHidden.*UserShell/);
      expect(ops.created).toEqual([]);
      expect(ops.deleted).toEqual([]);
    });

    it("M4: rejects an observed relative NFSHomeDirectory before canonicalization can make it look valid", async () => {
      let canonicalizeCalls = 0;
      const problems = await serviceAccountRecordProblems(
        {
          uid: 500,
          homeDirectory: "private/var/sanctuary-agents/sanctuary-hermes",
          isHidden: true,
          userShell: "/usr/bin/false",
        },
        { uid: 500, homeDirectory: HOME_DIR },
        {
          canonicalizeHomeDirectory: async (path) => {
            canonicalizeCalls += 1;
            return canonicalHome(path);
          },
        },
      );
      expect(problems).toEqual([
        "NFSHomeDirectory is private/var/sanctuary-agents/sanctuary-hermes, expected an absolute path, expected /var/sanctuary-agents/sanctuary-hermes",
      ]);
      expect(canonicalizeCalls).toBe(0);
    });

    it("M4: rejects an observed NFSHomeDirectory with a '..' segment before canonicalization", async () => {
      let canonicalizeCalls = 0;
      const problems = await serviceAccountRecordProblems(
        {
          uid: 500,
          homeDirectory: "/var/sanctuary-agents/../sanctuary-hermes",
          isHidden: true,
          userShell: "/usr/bin/false",
        },
        { uid: 500, homeDirectory: HOME_DIR },
        {
          canonicalizeHomeDirectory: async (path) => {
            canonicalizeCalls += 1;
            return canonicalHome(path);
          },
        },
      );
      expect(problems.join("\n")).toContain('expected a path with no ".." segments');
      expect(canonicalizeCalls).toBe(0);
    });
  });
});
