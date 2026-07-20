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
  AccountUidEnumerationError,
  AccountProvisionVerificationError,
  lookupAccountRecordAfterCreate,
  parseHighestAssignedUidFromDsclList,
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
    uidNames?: readonly string[];
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
  const { initialRecord, uidNames = [], createRecord, createThrowsAfterRecord, ...opsOverrides } = overrides;
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
    lookupAccountNamesByUid: async () => uidNames,
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

  describe("parseHighestAssignedUidFromDsclList", () => {
    it("parses negative macOS uids instead of dropping their lines", () => {
      const stdout = "nobody -2\nagentmac 501\nroot 0\nsanctuary-hermes 502\n";
      expect(parseHighestAssignedUidFromDsclList(stdout, CEILING - 1)).toBe(502);
    });

    it("fails closed on any unparseable non-empty uid enumeration line", () => {
      expect(() => parseHighestAssignedUidFromDsclList("agentmac 501\nmalformed-line\n", CEILING - 1)).toThrow(
        AccountUidEnumerationError,
      );
      expect(() => parseHighestAssignedUidFromDsclList("agentmac 501\nmalformed-line\n", CEILING - 1)).toThrow(
        /only 1 parsed.*line 2/s,
      );
    });

    it.each([
      ["empty", ""],
      ["whitespace-only", "\n  \n\t"],
      ["CRLF-only", "\r\n\r\n"],
      ["truncated-without-root", "daemon 1\nnobody -2\nagentmac 501\n"],
    ])("refuses %s uid enumeration output because the complete local census must include root uid 0", (_name, stdout) => {
      expect(() => parseHighestAssignedUidFromDsclList(stdout, CEILING - 1)).toThrow(AccountUidEnumerationError);
      expect(() => parseHighestAssignedUidFromDsclList(stdout, CEILING - 1)).toThrow(/root uid record \(root 0\)/);
    });

    it("parses a realistic complete census and returns the highest uid", () => {
      const stdout = "daemon 1\nnobody -2\nroot 0\nagentmac 501\n";
      expect(parseHighestAssignedUidFromDsclList(stdout, CEILING - 1)).toBe(501);
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

    it("throws with recovery guidance (never mutates) for a conflict plan", async () => {
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
      ).rejects.toThrow(/below the ceiling.*Recovery:.*UniqueID.*NFSHomeDirectory.*IsHidden.*UserShell/s);
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

    it("refuses the truncated-census case when the computed uid is directly observed as assigned", async () => {
      const ops = mockOps({ highestAssignedUid: async () => 502, uidNames: ["sanctuary-agent"] });
      await expect(
        planAndCreateAccount(
          { accountName: "sanctuary-hermes-two", ceiling: CEILING, homeDirectory: "/var/sanctuary-agents/two" },
          ops,
        ),
      ).rejects.toThrow(/uid 503.*"sanctuary-agent".*UID census is only a candidate-selection input/s);
      expect(ops.created).toEqual([]);
      expect(ops.hardened).toEqual([]);
    });

    it("refuses an agent-account create whose computed uid collides with a known-live excluded uid", async () => {
      const ops = mockOps({ highestAssignedUid: async () => 502 });
      await expect(
        planAndCreateAccount(
          {
            accountName: "sanctuary-hermes-two",
            ceiling: CEILING,
            homeDirectory: "/var/sanctuary-agents/two",
            excludedUids: [503],
          },
          ops,
        ),
      ).rejects.toThrow(/known-live excluded uid \(503\)/);
      expect(ops.created).toEqual([]);
      expect(ops.hardened).toEqual([]);
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

    it("B1/B2: leaves an observed fresh shared account in place when primary create mutates then throws", async () => {
      const ops = mockOps({
        createThrowsAfterRecord: new Error("dscl IsHidden write failed after sysadminctl created account"),
      });
      await expect(
        planAndCreateAccount(
          { accountName: "sanctuary-hermes", ceiling: CEILING, homeDirectory: HOME_DIR },
          ops,
        ),
      ).rejects.toThrow(/rollback deletion NOT attempted.*UniqueID=500/s);
      expect(ops.created).toHaveLength(1);
      expect(ops.hardened).toEqual([]);
      expect(ops.deleted).toEqual([]);
      expect(ops.record).toEqual({
        uid: 500,
        homeDirectory: HOME_DIR,
        userShell: "/usr/bin/false",
      });
    });

    it("B2/H2: leaves an observed fresh shared account in place when post-create hardening fails", async () => {
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
      ).rejects.toThrow(/Creating service account .*dscl IsHidden write failed.*rollback deletion NOT attempted/s);
      expect(ops.created).toHaveLength(1);
      expect(ops.deleted).toEqual([]);
      expect(ops.record).toEqual({
        uid: 500,
        homeDirectory: HOME_DIR,
        userShell: "/usr/bin/false",
      });
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
      ).rejects.toThrow(/rollback deletion NOT attempted.*uid=777/s);
      expect(ops.deleted).toEqual([]);
      expect(ops.record).toEqual(completeRecord(777));
    });

    it("B2: does not delete a concurrent shared account created at the same deterministic uid", async () => {
      let lookupCalls = 0;
      let record: ServiceAccountRecord | undefined;
      const ops: AccountProvisionOps = {
        lookupAccountUid: async () => record?.uid,
        lookupAccountRecord: async () => {
          lookupCalls += 1;
          if (lookupCalls === 1) return undefined;
          record = completeRecord(500);
          return record;
        },
        canonicalizeHomeDirectory: async (path) => canonicalHome(path),
        highestAssignedUid: async () => 499,
        lookupAccountNamesByUid: async () => (record === undefined ? [] : ["sanctuary-hermes"]),
        createUser: async () => {
          throw new Error("user already exists");
        },
        hardenCreatedUser: async () => undefined,
      };
      await expect(
        planAndCreateAccount(
          { accountName: "sanctuary-hermes", ceiling: CEILING, homeDirectory: HOME_DIR },
          ops,
        ),
      ).rejects.toThrow(/rollback deletion NOT attempted.*uid=500/s);
      expect(record).toEqual(completeRecord(500));
    });

    it("H1: refuses before arming when the created agent account has no home read-back, leaving it for repair", async () => {
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
      expect(ops.deleted).toEqual([]);
      expect(ops.record).toEqual({ uid: 500, isHidden: true, userShell: "/usr/bin/false" });
    });

    it("H2: retries transient post-create record reads before treating the create as failed", async () => {
      let lookupCalls = 0;
      let record: ServiceAccountRecord | undefined;
      const ops: AccountProvisionOps = {
        lookupAccountUid: async () => record?.uid,
        lookupAccountRecord: async () => {
          lookupCalls += 1;
          if (lookupCalls === 1) return undefined;
          if (lookupCalls === 2 || lookupCalls === 3) throw new Error("transient DirectoryService read failed");
          return record;
        },
        canonicalizeHomeDirectory: async (path) => canonicalHome(path),
        highestAssignedUid: async () => 499,
        lookupAccountNamesByUid: async () => [],
        createUser: async (_accountName, uid, _comment, homeDirectory) => {
          record = { uid, homeDirectory, userShell: "/usr/bin/false" };
        },
        hardenCreatedUser: async () => {
          if (record !== undefined) record = { ...record, isHidden: true };
        },
      };
      const result = await planAndCreateAccount(
        { accountName: "sanctuary-hermes", ceiling: CEILING, homeDirectory: HOME_DIR },
        ops,
      );
      expect(result.uid).toBe(500);
      expect(lookupCalls).toBe(4);
    });

    it("H2: retries a transient absent post-create readback before treating the create as failed", async () => {
      let lookupCalls = 0;
      let record: ServiceAccountRecord | undefined;
      const ops: AccountProvisionOps = {
        lookupAccountUid: async () => record?.uid,
        lookupAccountRecord: async () => {
          lookupCalls += 1;
          if (lookupCalls === 1) return undefined;
          if (lookupCalls === 2) return undefined;
          return record;
        },
        canonicalizeHomeDirectory: async (path) => canonicalHome(path),
        highestAssignedUid: async () => 499,
        lookupAccountNamesByUid: async () => [],
        createUser: async (_accountName, uid, _comment, homeDirectory) => {
          record = { uid, homeDirectory, userShell: "/usr/bin/false" };
        },
        hardenCreatedUser: async () => {
          if (record !== undefined) record = { ...record, isHidden: true };
        },
      };
      const result = await planAndCreateAccount(
        { accountName: "sanctuary-hermes", ceiling: CEILING, homeDirectory: HOME_DIR },
        ops,
      );
      expect(result.uid).toBe(500);
      expect(lookupCalls).toBe(3);
    });

    it("M-1: a clean absent post-create observation clears any stale read error", async () => {
      let lookupCalls = 0;
      const observed = await lookupAccountRecordAfterCreate(
        {
          lookupAccountRecord: async () => {
            lookupCalls += 1;
            if (lookupCalls === 1) throw new Error("transient first read failed");
            return undefined;
          },
        },
        "sanctuary-hermes",
      );
      expect(observed).toBeUndefined();
      expect(lookupCalls).toBe(3);
    });

    it("B1: an existing malformed record that cannot expose UniqueID stops planning and names full repair", async () => {
      let highestCalls = 0;
      let created = false;
      const ops: AccountProvisionOps = {
        lookupAccountUid: async () => undefined,
        lookupAccountRecord: async () => {
          throw new Error(
            'directory-service record "sanctuary-hermes" exists but UniqueID is missing; refusing to treat it as absent',
          );
        },
        canonicalizeHomeDirectory: async (path) => canonicalHome(path),
        highestAssignedUid: async () => {
          highestCalls += 1;
          return 499;
        },
        lookupAccountNamesByUid: async () => [],
        createUser: async () => {
          created = true;
        },
        hardenCreatedUser: async () => undefined,
      };
      await expect(
        planAndCreateAccount(
          { accountName: "sanctuary-hermes", ceiling: CEILING, homeDirectory: HOME_DIR },
          ops,
        ),
      ).rejects.toThrow(/UniqueID.*NFSHomeDirectory.*IsHidden.*UserShell/s);
      expect(highestCalls).toBe(0);
      expect(created).toBe(false);
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
