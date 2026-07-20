/**
 * Unit tests for the dedicated gate service-account provisioning (Slice 5
 * S5-3). Pure planning + injected ops; no host, no real dscl/sysadminctl.
 */

import { describe, it, expect } from "vitest";

import {
  deriveGateAccountName,
  gateAccountProvisionOptions,
  planGateAccountProvision,
  planAndCreateGateAccount,
  GateUidCollisionError,
  GATE_ACCOUNT_NAME_PREFIX,
  type GateAccountProvisionOps,
  type GateAccountRecord,
} from "../../src/egress-gate/gate-account.js";
import { parseDsclSearchAccountNames } from "../../src/wrap/auto-provision.js";

const AGENT_UID = 502;

const GATE_HOME = "/var/sanctuary-agents/sanctuary-gate-hermes";

function completeGateRecord(uid: number, homeDirectory = GATE_HOME): GateAccountRecord {
  return { uid, homeDirectory, isHidden: true, userShell: "/usr/bin/false" };
}

function canonicalHome(path: string): string {
  return path.replace(/^\/var(?=\/|$)/, "/private/var").replace(/\/+$/, "");
}

function gateOps(input: {
  existing?: GateAccountRecord;
  highest?: number;
  uidNames?: readonly string[];
  create?: (name: string, uid: number, home: string) => GateAccountRecord | Promise<GateAccountRecord>;
} = {}): GateAccountProvisionOps & {
  created: Array<{ name: string; uid: number; home: string }>;
  hardened: string[];
  deleted: string[];
  record: GateAccountRecord | undefined;
} {
  const state = {
    record: input.existing,
    recordName: input.existing === undefined ? undefined as string | undefined : "sanctuary-gate-hermes",
    created: [] as Array<{ name: string; uid: number; home: string }>,
    hardened: [] as string[],
    deleted: [] as string[],
  };
  return {
    created: state.created,
    hardened: state.hardened,
    deleted: state.deleted,
    get record() {
      return state.record;
    },
    lookupAccountUid: async () => state.record?.uid,
    lookupAccountRecord: async () => state.record,
    canonicalizeHomeDirectory: async (path) => canonicalHome(path),
    highestAssignedUid: async () => input.highest ?? 504,
    lookupAccountNamesByUid: async (uid) =>
      input.uidNames ?? (state.record !== undefined && state.record.uid === uid && state.recordName !== undefined ? [state.recordName] : []),
    createUser: async (name, uid, _comment, home) => {
      state.created.push({ name, uid, home });
      state.recordName = name;
      state.record =
        input.create !== undefined
          ? await input.create(name, uid, home)
          : { uid, homeDirectory: home, userShell: "/usr/bin/false" };
    },
    hardenCreatedUser: async (name) => {
      state.hardened.push(name);
      if (state.record !== undefined) state.record = { ...state.record, isHidden: true };
    },
  };
}

describe("egress-gate/gate-account", () => {
  it("derives a per-agent gate account name under the canonical prefix", () => {
    expect(deriveGateAccountName("hermes")).toBe(`${GATE_ACCOUNT_NAME_PREFIX}hermes`);
    expect(deriveGateAccountName("hermes")).toBe("sanctuary-gate-hermes");
  });

  it("rejects an agent id that would produce an unsafe service-account name", () => {
    expect(() => deriveGateAccountName("bad name")).toThrow(/safe service-account name/);
    expect(() => deriveGateAccountName("a/b")).toThrow(/safe service-account name/);
    expect(() => deriveGateAccountName("Up$er")).toThrow(/safe service-account name/);
  });

  it("builds shared provision options with a gate-specific comment and derived name", () => {
    const opts = gateAccountProvisionOptions({
      agentId: "hermes",
      agentUid: AGENT_UID,
      ceiling: 500,
      homeDirectory: "/var/sanctuary-agents/sanctuary-gate-hermes",
    });
    expect(opts.accountName).toBe("sanctuary-gate-hermes");
    expect(opts.ceiling).toBe(500);
    expect(opts.homeDirectory).toBe("/var/sanctuary-agents/sanctuary-gate-hermes");
    expect(opts.comment).toContain("hermes");
  });

  it("plans a create above the ceiling AND every assigned uid when no account exists", () => {
    const plan = planGateAccountProvision(
      { agentId: "hermes", agentUid: AGENT_UID, ceiling: 500, homeDirectory: "/var/sanctuary-agents/sanctuary-gate-hermes" },
      { existingUid: undefined, highestAssignedUid: 507 },
    );
    expect(plan.action).toBe("create");
    if (plan.action === "create") {
      expect(plan.accountName).toBe("sanctuary-gate-hermes");
      expect(plan.uid).toBe(508); // max(ceiling, highest+1)
    }
  });

  it("plans a skip (idempotent) when the gate account already exists at/above the ceiling", () => {
    const plan = planGateAccountProvision(
      { agentId: "hermes", agentUid: AGENT_UID, ceiling: 500, homeDirectory: "/var/sanctuary-agents/sanctuary-gate-hermes" },
      { existingUid: 511, highestAssignedUid: 511 },
    );
    expect(plan.action).toBe("skip");
    if (plan.action === "skip") {
      expect(plan.uid).toBe(511);
    }
  });

  it("refuses (conflict) a same-name account below the ceiling rather than reassigning", () => {
    const plan = planGateAccountProvision(
      { agentId: "hermes", agentUid: AGENT_UID, ceiling: 500, homeDirectory: "/var/sanctuary-agents/sanctuary-gate-hermes" },
      { existingUid: 42, highestAssignedUid: 600 },
    );
    expect(plan.action).toBe("conflict");
  });

  it("planAndCreateGateAccount refuses a sub-ceiling conflict with actionable recovery guidance", async () => {
    const ops = gateOps({ existing: completeGateRecord(42), highest: 600 });
    await expect(
      planAndCreateGateAccount({ agentId: "hermes", agentUid: AGENT_UID, ceiling: 500, homeDirectory: GATE_HOME }, ops),
    ).rejects.toThrow(/below the ceiling.*Recovery:.*UniqueID.*NFSHomeDirectory.*IsHidden.*UserShell/s);
    expect(ops.created).toEqual([]);
    expect(ops.hardened).toEqual([]);
  });

  it("planAndCreateGateAccount executes a create through injected ops and returns uid + name", async () => {
    const ops = gateOps();
    const result = await planAndCreateGateAccount(
      { agentId: "hermes", agentUid: AGENT_UID, ceiling: 500, homeDirectory: "/var/sanctuary-agents/sanctuary-gate-hermes" },
      ops,
    );
    expect(result.accountName).toBe("sanctuary-gate-hermes");
    expect(result.uid).toBe(505);
    expect(result.observed).toContain("NFSHomeDirectory=/var/sanctuary-agents/sanctuary-gate-hermes");
    expect(ops.created).toEqual([
      { name: "sanctuary-gate-hermes", uid: 505, home: "/var/sanctuary-agents/sanctuary-gate-hermes" },
    ]);
    expect(ops.hardened).toEqual(["sanctuary-gate-hermes"]);
  });

  it("ALWAYS refuses a skip whose existing uid collides with the agent uid, even with NO excludeUids (Codex round-3)", () => {
    // The confined agent uid is structurally excluded; omitting excludeUids
    // must NOT let a pre-existing sanctuary-gate account at the agent uid pass.
    expect(() =>
      planGateAccountProvision(
        { agentId: "hermes", agentUid: AGENT_UID, ceiling: 500, homeDirectory: "/var/sanctuary-agents/sanctuary-gate-hermes" },
        { existingUid: AGENT_UID, highestAssignedUid: AGENT_UID },
      ),
    ).toThrow(/excluded agent-or-operator uid.*UniqueID.*NFSHomeDirectory/s);
  });

  it("refuses a create plan whose computed uid lands on an excluded agent/operator uid before any side effect", () => {
    // ceiling 500, highest 500 -> computed uid 501; since 501 is excluded, the
    // UID census is stale and no alternate UID can be guessed safely.
    expect(() =>
      planGateAccountProvision(
        {
          agentId: "hermes",
          agentUid: AGENT_UID,
          ceiling: 500,
          homeDirectory: "/var/sanctuary-agents/sanctuary-gate-hermes",
          excludeUids: [501],
        },
        { existingUid: undefined, highestAssignedUid: 500 },
      ),
    ).toThrow(GateUidCollisionError);
    expect(() =>
      planGateAccountProvision(
        {
          agentId: "hermes",
          agentUid: AGENT_UID,
          ceiling: 500,
          homeDirectory: "/var/sanctuary-agents/sanctuary-gate-hermes",
          excludeUids: [501],
        },
        { existingUid: undefined, highestAssignedUid: 500 },
      ),
    ).toThrow(/allow-all open relay/);
  });

  for (const { highestAssignedUid, excludedUid } of [
    { highestAssignedUid: 502, excludedUid: 503 },
    { highestAssignedUid: 500, excludedUid: 501 },
  ]) {
    it(`refuses stale enumeration proof case highest=${highestAssignedUid} excluded=${excludedUid} before create`, async () => {
      const ops = gateOps({ highest: highestAssignedUid });
      await expect(
        planAndCreateGateAccount(
          {
            agentId: "hermes",
            agentUid: AGENT_UID,
            ceiling: 500,
            homeDirectory: "/var/sanctuary-agents/sanctuary-gate-hermes",
            excludeUids: [excludedUid],
          },
          ops,
        ),
      ).rejects.toThrow(GateUidCollisionError);
      expect(ops.created).toEqual([]);
      expect(ops.hardened).toEqual([]);
    });
  }

  it("refuses a gate create when direct uid lookup finds a live non-excluded account dropped by the census", async () => {
    const ops = gateOps({ highest: 502, uidNames: ["sanctuary-agent"] });
    await expect(
      planAndCreateGateAccount(
        {
          agentId: "hermes",
          agentUid: AGENT_UID,
          ceiling: 500,
          homeDirectory: "/var/sanctuary-agents/sanctuary-gate-hermes",
          excludeUids: [501],
        },
        ops,
      ),
    ).rejects.toThrow(/uid 503.*"sanctuary-agent".*UID census is only a candidate-selection input/s);
    expect(ops.created).toEqual([]);
    expect(ops.hardened).toEqual([]);
  });

  it.each([
    ["space-named holder", "Legacy Admin\t\tUniqueID = (\n    503\n)\n", /"Legacy Admin"/],
    ["localized attribute residue", "eriknewton\t\tIdentifiantUnique = (\n    503\n)\n", /could not be directly observed as unassigned/],
  ])("refuses a gate create when dscl search output contains %s", async (_name, searchOut, refusal) => {
    const ops = gateOps({
      highest: 502,
      create: (name, uid, home) => completeGateRecord(uid, home),
    });
    const guardedOps: GateAccountProvisionOps = {
      ...ops,
      lookupAccountNamesByUid: async () => parseDsclSearchAccountNames(searchOut),
    };
    await expect(
      planAndCreateGateAccount(
        {
          agentId: "hermes",
          agentUid: AGENT_UID,
          ceiling: 500,
          homeDirectory: "/var/sanctuary-agents/sanctuary-gate-hermes",
          excludeUids: [501],
        },
        guardedOps,
      ),
    ).rejects.toThrow(refusal);
    expect(ops.created).toEqual([]);
    expect(ops.hardened).toEqual([]);
  });

  it("requires a positive agentUid (fail-closed: the exclusion cannot be skipped)", () => {
    expect(() =>
      planGateAccountProvision(
        { agentId: "hermes", agentUid: 0, ceiling: 500, homeDirectory: "/var/sanctuary-agents/sanctuary-gate-hermes" },
        { existingUid: undefined, highestAssignedUid: 507 },
      ),
    ).toThrow(/agentUid must be a positive integer/);
  });

  it("allows a plan whose uid avoids the agent uid and every excluded operator uid", () => {
    const plan = planGateAccountProvision(
      {
        agentId: "hermes",
        agentUid: AGENT_UID,
        ceiling: 500,
        homeDirectory: "/var/sanctuary-agents/sanctuary-gate-hermes",
        excludeUids: [501],
      },
      { existingUid: undefined, highestAssignedUid: 507 },
    );
    expect(plan.action).toBe("create");
    if (plan.action === "create") {
      expect(plan.uid).toBe(508);
    }
  });

  it("planAndCreateGateAccount does not create when the plan is a skip (idempotent no-op)", async () => {
    const ops = gateOps({ existing: completeGateRecord(511), highest: 511 });
    const result = await planAndCreateGateAccount(
      { agentId: "hermes", agentUid: AGENT_UID, ceiling: 500, homeDirectory: "/var/sanctuary-agents/sanctuary-gate-hermes" },
      ops,
    );
    expect(result.plan.action).toBe("skip");
    expect(result.uid).toBe(511);
    expect(ops.created).toEqual([]);
    expect(ops.hardened).toEqual([]);
  });

  it("leaves a fresh partial gate account in place for repair when the home attribute is missing", async () => {
    const ops = gateOps({ create: (_name, uid) => ({ uid, isHidden: true, userShell: "/usr/bin/false" }) });
    await expect(
      planAndCreateGateAccount(
        { agentId: "hermes", agentUid: AGENT_UID, ceiling: 500, homeDirectory: "/var/sanctuary-agents/sanctuary-gate-hermes" },
        ops,
      ),
    ).rejects.toThrow(/rollback deletion NOT attempted.*UniqueID=505/s);
    expect(ops.created).toEqual([
      { name: "sanctuary-gate-hermes", uid: 505, home: "/var/sanctuary-agents/sanctuary-gate-hermes" },
    ]);
    expect(ops.deleted).toEqual([]);
    expect(ops.record).toEqual({ uid: 505, isHidden: true, userShell: "/usr/bin/false" });
  });

  it("B2: leaves a fresh gate account in place when post-create hardening fails", async () => {
    const ops = gateOps({
      create: (_name, uid, home) => ({ uid, homeDirectory: home, userShell: "/usr/bin/false" }),
    });
    await expect(
      planAndCreateGateAccount(
        { agentId: "hermes", agentUid: AGENT_UID, ceiling: 500, homeDirectory: "/var/sanctuary-agents/sanctuary-gate-hermes" },
        {
          ...ops,
          hardenCreatedUser: async () => {
            throw new Error("dscl IsHidden write failed");
          },
        },
      ),
    ).rejects.toThrow(/dscl IsHidden write failed.*rollback deletion NOT attempted/s);
    expect(ops.deleted).toEqual([]);
    expect(ops.record).toEqual({
      uid: 505,
      homeDirectory: "/var/sanctuary-agents/sanctuary-gate-hermes",
      userShell: "/usr/bin/false",
    });
  });

  it("H1: does NOT delete a concurrent gate account whose observed uid differs from this run's planned uid", async () => {
    let lookupCalls = 0;
    let record: GateAccountRecord | undefined;
    const ops: GateAccountProvisionOps = {
      lookupAccountUid: async () => undefined,
      canonicalizeHomeDirectory: async (path) => canonicalHome(path),
      highestAssignedUid: async () => 504,
      lookupAccountRecord: async () => {
        lookupCalls += 1;
        if (lookupCalls === 1) return undefined;
        record = completeGateRecord(777);
        return record;
      },
      lookupAccountNamesByUid: async () => [],
      createUser: async () => {
        throw new Error("user already exists");
      },
      hardenCreatedUser: async () => undefined,
    };
    await expect(
      planAndCreateGateAccount(
        { agentId: "hermes", agentUid: AGENT_UID, ceiling: 500, homeDirectory: "/var/sanctuary-agents/sanctuary-gate-hermes" },
        ops,
      ),
    ).rejects.toThrow(/rollback deletion NOT attempted.*uid=777/s);
    expect(record).toEqual(completeGateRecord(777));
  });

  it("B2: does NOT delete a concurrent gate account created at the same deterministic uid", async () => {
    let lookupCalls = 0;
    let record: GateAccountRecord | undefined;
    const ops: GateAccountProvisionOps = {
      lookupAccountUid: async () => record?.uid,
      canonicalizeHomeDirectory: async (path) => canonicalHome(path),
      highestAssignedUid: async () => 504,
      lookupAccountRecord: async () => {
        lookupCalls += 1;
        if (lookupCalls === 1) return undefined;
        record = completeGateRecord(505);
        return record;
      },
      lookupAccountNamesByUid: async () => (record === undefined ? [] : ["sanctuary-gate-hermes"]),
      createUser: async () => {
        throw new Error("user already exists");
      },
      hardenCreatedUser: async () => undefined,
    };
    await expect(
      planAndCreateGateAccount(
        { agentId: "hermes", agentUid: AGENT_UID, ceiling: 500, homeDirectory: "/var/sanctuary-agents/sanctuary-gate-hermes" },
        ops,
      ),
    ).rejects.toThrow(/rollback deletion NOT attempted.*uid=505/s);
    expect(record).toEqual(completeGateRecord(505));
  });

  it("B1/M2: refuses an existing same-name partial gate account without deleting it", async () => {
    const ops = gateOps({ existing: { uid: 505 }, highest: 505 });
    await expect(
      planAndCreateGateAccount(
        { agentId: "hermes", agentUid: AGENT_UID, ceiling: 500, homeDirectory: "/var/sanctuary-agents/sanctuary-gate-hermes" },
        ops,
      ),
    ).rejects.toThrow(/Existing service account .* incomplete/);
    expect(ops.created).toEqual([]);
    expect(ops.deleted).toEqual([]);
    expect(ops.record).toEqual({ uid: 505 });
  });

  it("B1: an existing malformed gate record that cannot expose UniqueID stops planning and names full repair", async () => {
    let highestCalls = 0;
    let created = false;
    const ops: GateAccountProvisionOps = {
      lookupAccountUid: async () => undefined,
      lookupAccountRecord: async () => {
        throw new Error(
          'directory-service record "sanctuary-gate-hermes" exists but UniqueID is missing; refusing to treat it as absent',
        );
      },
      canonicalizeHomeDirectory: async (path) => canonicalHome(path),
      highestAssignedUid: async () => {
        highestCalls += 1;
        return 504;
      },
      lookupAccountNamesByUid: async () => [],
      createUser: async () => {
        created = true;
      },
      hardenCreatedUser: async () => undefined,
    };
    await expect(
      planAndCreateGateAccount({ agentId: "hermes", agentUid: AGENT_UID, ceiling: 500, homeDirectory: GATE_HOME }, ops),
    ).rejects.toThrow(/UniqueID.*NFSHomeDirectory.*IsHidden.*UserShell/s);
    expect(highestCalls).toBe(0);
    expect(created).toBe(false);
  });

  it("B1: accepts /var and /private/var home forms as the same canonical path", async () => {
    const ops = gateOps({
      create: (_name, uid) => completeGateRecord(uid, "/private/var/sanctuary-agents/sanctuary-gate-hermes/"),
    });
    const result = await planAndCreateGateAccount(
      { agentId: "hermes", agentUid: AGENT_UID, ceiling: 500, homeDirectory: "/var/sanctuary-agents/sanctuary-gate-hermes" },
      ops,
    );
    expect(result.uid).toBe(505);
    expect(ops.deleted).toEqual([]);
  });

  it("B2: rejects a same uid/home gate account with missing IsHidden and a login shell", async () => {
    const ops = gateOps({
      existing: { uid: 505, homeDirectory: "/var/sanctuary-agents/sanctuary-gate-hermes", userShell: "/bin/zsh" },
      highest: 505,
    });
    await expect(
      planAndCreateGateAccount(
        { agentId: "hermes", agentUid: AGENT_UID, ceiling: 500, homeDirectory: "/var/sanctuary-agents/sanctuary-gate-hermes" },
        ops,
      ),
    ).rejects.toThrow(/IsHidden.*UserShell/);
    expect(ops.deleted).toEqual([]);
    expect(ops.record).toEqual({ uid: 505, homeDirectory: "/var/sanctuary-agents/sanctuary-gate-hermes", userShell: "/bin/zsh" });
  });

  it("B2: leaves a fresh gate account in place when post-create hardening is missing", async () => {
    const ops = gateOps({
      create: (_name, uid, home) => ({ uid, homeDirectory: home, userShell: "/bin/zsh" }),
    });
    await expect(
      planAndCreateGateAccount(
        { agentId: "hermes", agentUid: AGENT_UID, ceiling: 500, homeDirectory: "/var/sanctuary-agents/sanctuary-gate-hermes" },
        ops,
      ),
    ).rejects.toThrow(/IsHidden.*UserShell/);
    expect(ops.deleted).toEqual([]);
    expect(ops.record).toEqual({
      uid: 505,
      homeDirectory: "/var/sanctuary-agents/sanctuary-gate-hermes",
      isHidden: true,
      userShell: "/bin/zsh",
    });
  });

  it("H2: retries transient post-create record reads before treating the gate create as failed", async () => {
    let lookupCalls = 0;
    let uidLookupCalls = 0;
    let record: GateAccountRecord | undefined;
    const ops: GateAccountProvisionOps = {
      lookupAccountUid: async () => record?.uid,
      lookupAccountRecord: async () => {
        lookupCalls += 1;
        if (lookupCalls === 1) return undefined;
        if (lookupCalls === 2 || lookupCalls === 3) throw new Error("transient DirectoryService read failed");
        return record;
      },
      canonicalizeHomeDirectory: async (path) => canonicalHome(path),
      highestAssignedUid: async () => 504,
      lookupAccountNamesByUid: async () => {
        uidLookupCalls += 1;
        return uidLookupCalls === 1 ? [] : ["sanctuary-gate-hermes"];
      },
      createUser: async (_name, uid, _comment, home) => {
        record = { uid, homeDirectory: home, userShell: "/usr/bin/false" };
      },
      hardenCreatedUser: async () => {
        if (record !== undefined) record = { ...record, isHidden: true };
      },
    };
    const result = await planAndCreateGateAccount(
      { agentId: "hermes", agentUid: AGENT_UID, ceiling: 500, homeDirectory: GATE_HOME },
      ops,
    );
    expect(result.uid).toBe(505);
    expect(lookupCalls).toBe(4);
    expect(uidLookupCalls).toBe(2);
  });

  it("H2: retries a transient absent post-create gate readback before treating the create as failed", async () => {
    let lookupCalls = 0;
    let uidLookupCalls = 0;
    let record: GateAccountRecord | undefined;
    const ops: GateAccountProvisionOps = {
      lookupAccountUid: async () => record?.uid,
      lookupAccountRecord: async () => {
        lookupCalls += 1;
        if (lookupCalls === 1) return undefined;
        if (lookupCalls === 2) return undefined;
        return record;
      },
      canonicalizeHomeDirectory: async (path) => canonicalHome(path),
      highestAssignedUid: async () => 504,
      lookupAccountNamesByUid: async () => {
        uidLookupCalls += 1;
        return uidLookupCalls === 1 ? [] : ["sanctuary-gate-hermes"];
      },
      createUser: async (_name, uid, _comment, home) => {
        record = { uid, homeDirectory: home, userShell: "/usr/bin/false" };
      },
      hardenCreatedUser: async () => {
        if (record !== undefined) record = { ...record, isHidden: true };
      },
    };
    const result = await planAndCreateGateAccount(
      { agentId: "hermes", agentUid: AGENT_UID, ceiling: 500, homeDirectory: GATE_HOME },
      ops,
    );
    expect(result.uid).toBe(505);
    expect(lookupCalls).toBe(3);
    expect(uidLookupCalls).toBe(2);
  });

  it("H1: does NOT delete when rollback cannot observe the record before deletion", async () => {
    let record: GateAccountRecord | undefined;
    let lookupCalls = 0;
    const ops: GateAccountProvisionOps = {
      lookupAccountUid: async () => undefined,
      canonicalizeHomeDirectory: async (path) => canonicalHome(path),
      highestAssignedUid: async () => 504,
      lookupAccountRecord: async () => {
        lookupCalls += 1;
        if (lookupCalls === 1) return undefined;
        if (lookupCalls === 2) throw new Error("DirectoryService read failed");
        return record;
      },
      lookupAccountNamesByUid: async () => [],
      createUser: async (_name, uid, _comment, home) => {
        record = completeGateRecord(uid, home);
        throw new Error("sysadminctl failed after create");
      },
      hardenCreatedUser: async () => undefined,
    };
    await expect(
      planAndCreateGateAccount(
        { agentId: "hermes", agentUid: AGENT_UID, ceiling: 500, homeDirectory: "/var/sanctuary-agents/sanctuary-gate-hermes" },
        ops,
      ),
    ).rejects.toThrow(/rollback NOT attempted: pre-delete read failed/s);
    expect(record).toEqual(completeGateRecord(505));
  });
});
