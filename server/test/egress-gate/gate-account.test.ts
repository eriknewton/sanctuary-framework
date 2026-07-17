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
} from "../../src/egress-gate/gate-account.js";
import type { AccountProvisionOps } from "../../src/castle-wall/provision/account.js";

const AGENT_UID = 502;

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
    const created: Array<{ name: string; uid: number; home: string }> = [];
    const ops: AccountProvisionOps = {
      lookupAccountUid: () => Promise.resolve(undefined),
      highestAssignedUid: () => Promise.resolve(504),
      createUser: (name, uid, _comment, home) => {
        created.push({ name, uid, home });
        return Promise.resolve();
      },
    };
    const result = await planAndCreateGateAccount(
      { agentId: "hermes", agentUid: AGENT_UID, ceiling: 500, homeDirectory: "/var/sanctuary-gate/hermes" },
      ops,
    );
    expect(result.accountName).toBe("sanctuary-gate-hermes");
    expect(result.uid).toBe(505);
    expect(created).toEqual([
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
    let creates = 0;
    const ops: AccountProvisionOps = {
      lookupAccountUid: () => Promise.resolve(511),
      highestAssignedUid: () => Promise.resolve(511),
      createUser: () => {
        creates += 1;
        return Promise.resolve();
      },
    };
    const result = await planAndCreateGateAccount(
      { agentId: "hermes", agentUid: AGENT_UID, ceiling: 500, homeDirectory: "/var/sanctuary-gate/hermes" },
      ops,
    );
    expect(result.plan.action).toBe("skip");
    expect(result.uid).toBe(511);
    expect(creates).toBe(0);
  });
});
