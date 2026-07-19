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
  GateAccountVerificationError,
  GATE_ACCOUNT_NAME_PREFIX,
  type GateAccountProvisionOps,
  type GateAccountRecord,
} from "../../src/egress-gate/gate-account.js";

const AGENT_UID = 502;

function gateOps(input: {
  existing?: GateAccountRecord;
  highest?: number;
  create?: (name: string, uid: number, home: string) => GateAccountRecord | Promise<GateAccountRecord>;
} = {}): GateAccountProvisionOps & {
  created: Array<{ name: string; uid: number; home: string }>;
  deleted: string[];
  record: GateAccountRecord | undefined;
} {
  const state = {
    record: input.existing,
    created: [] as Array<{ name: string; uid: number; home: string }>,
    deleted: [] as string[],
  };
  return {
    created: state.created,
    deleted: state.deleted,
    get record() {
      return state.record;
    },
    lookupAccountUid: async () => state.record?.uid,
    lookupAccountRecord: async () => state.record,
    highestAssignedUid: async () => input.highest ?? 504,
    createUser: async (name, uid, _comment, home) => {
      state.created.push({ name, uid, home });
      state.record = input.create !== undefined ? await input.create(name, uid, home) : { uid, homeDirectory: home };
    },
    deleteCreatedUser: async (name) => {
      state.deleted.push(name);
      state.record = undefined;
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
      homeDirectory: "/var/sanctuary-gate/hermes",
    });
    expect(opts.accountName).toBe("sanctuary-gate-hermes");
    expect(opts.ceiling).toBe(500);
    expect(opts.homeDirectory).toBe("/var/sanctuary-gate/hermes");
    expect(opts.comment).toContain("hermes");
  });

  it("plans a create above the ceiling AND every assigned uid when no account exists", () => {
    const plan = planGateAccountProvision(
      { agentId: "hermes", agentUid: AGENT_UID, ceiling: 500, homeDirectory: "/var/sanctuary-gate/hermes" },
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
      { agentId: "hermes", agentUid: AGENT_UID, ceiling: 500, homeDirectory: "/var/sanctuary-gate/hermes" },
      { existingUid: 511, highestAssignedUid: 511 },
    );
    expect(plan.action).toBe("skip");
    if (plan.action === "skip") {
      expect(plan.uid).toBe(511);
    }
  });

  it("refuses (conflict) a same-name account below the ceiling rather than reassigning", () => {
    const plan = planGateAccountProvision(
      { agentId: "hermes", agentUid: AGENT_UID, ceiling: 500, homeDirectory: "/var/sanctuary-gate/hermes" },
      { existingUid: 42, highestAssignedUid: 600 },
    );
    expect(plan.action).toBe("conflict");
  });

  it("planAndCreateGateAccount executes a create through injected ops and returns uid + name", async () => {
    const ops = gateOps();
    const result = await planAndCreateGateAccount(
      { agentId: "hermes", agentUid: AGENT_UID, ceiling: 500, homeDirectory: "/var/sanctuary-gate/hermes" },
      ops,
    );
    expect(result.accountName).toBe("sanctuary-gate-hermes");
    expect(result.uid).toBe(505);
    expect(result.observed).toContain("NFSHomeDirectory=/var/sanctuary-gate/hermes");
    expect(ops.created).toEqual([
      { name: "sanctuary-gate-hermes", uid: 505, home: "/var/sanctuary-gate/hermes" },
    ]);
  });

  it("ALWAYS refuses a skip whose existing uid collides with the agent uid, even with NO excludeUids (Codex round-3)", () => {
    // The confined agent uid is structurally excluded; omitting excludeUids
    // must NOT let a pre-existing sanctuary-gate account at the agent uid pass.
    expect(() =>
      planGateAccountProvision(
        { agentId: "hermes", agentUid: AGENT_UID, ceiling: 500, homeDirectory: "/var/sanctuary-gate/hermes" },
        { existingUid: AGENT_UID, highestAssignedUid: AGENT_UID },
      ),
    ).toThrow(GateUidCollisionError);
  });

  it("REFUSES a create whose computed uid collides with a supplied operator uid", () => {
    // ceiling 500, highest 500 -> computed uid 501; excluding operator 501 refuses.
    expect(() =>
      planGateAccountProvision(
        {
          agentId: "hermes",
          agentUid: AGENT_UID,
          ceiling: 500,
          homeDirectory: "/var/sanctuary-gate/hermes",
          excludeUids: [501],
        },
        { existingUid: undefined, highestAssignedUid: 500 },
      ),
    ).toThrow(/open relay/);
  });

  it("requires a positive agentUid (fail-closed: the exclusion cannot be skipped)", () => {
    expect(() =>
      planGateAccountProvision(
        { agentId: "hermes", agentUid: 0, ceiling: 500, homeDirectory: "/var/sanctuary-gate/hermes" },
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
        homeDirectory: "/var/sanctuary-gate/hermes",
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
    const ops = gateOps({ existing: { uid: 511, homeDirectory: "/var/sanctuary-gate/hermes" }, highest: 511 });
    const result = await planAndCreateGateAccount(
      { agentId: "hermes", agentUid: AGENT_UID, ceiling: 500, homeDirectory: "/var/sanctuary-gate/hermes" },
      ops,
    );
    expect(result.plan.action).toBe("skip");
    expect(result.uid).toBe(511);
    expect(ops.created).toEqual([]);
  });

  it("rolls back a fresh gate account when create returns but the home attribute is missing (D4 partial account)", async () => {
    const ops = gateOps({ create: (_name, uid) => ({ uid }) });
    await expect(
      planAndCreateGateAccount(
        { agentId: "hermes", agentUid: AGENT_UID, ceiling: 500, homeDirectory: "/var/sanctuary-gate/hermes" },
        ops,
      ),
    ).rejects.toThrow(GateAccountVerificationError);
    expect(ops.created).toEqual([
      { name: "sanctuary-gate-hermes", uid: 505, home: "/var/sanctuary-gate/hermes" },
    ]);
    expect(ops.deleted).toEqual(["sanctuary-gate-hermes"]);
    expect(ops.record).toBeUndefined();
  });

  it("rolls back an existing same-name partial gate account instead of treating it as an idempotent skip", async () => {
    const ops = gateOps({ existing: { uid: 505 }, highest: 505 });
    await expect(
      planAndCreateGateAccount(
        { agentId: "hermes", agentUid: AGENT_UID, ceiling: 500, homeDirectory: "/var/sanctuary-gate/hermes" },
        ops,
      ),
    ).rejects.toThrow(/Existing gate account .* incomplete/);
    expect(ops.created).toEqual([]);
    expect(ops.deleted).toEqual(["sanctuary-gate-hermes"]);
    expect(ops.record).toBeUndefined();
  });
});
