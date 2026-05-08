import { describe, expect, it } from "vitest";
import { CHANNEL_TEMPLATE_IDS } from "../../src/policy-engine/constants.js";
import {
  allChannelTemplateIds,
  applyChannelTemplate,
  listChannelTemplates,
} from "../../src/policy-engine/channel-templates.js";
import {
  packPolicyUpdate,
  unpackPolicyUpdate,
} from "../../src/policy-engine/envelope.js";
import {
  evaluateOutputsGate,
  evaluatePlansGate,
} from "../../src/policy-engine/gates/index.js";
import type { SlotGateExtendedContext } from "../../src/policy-engine/gates/evaluator.js";
import { buildFortress, verifyCtxFor } from "./fixture.js";

describe("policy-engine/channel-templates registry", () => {
  it("lists exactly the five spec-canonical ids", () => {
    const list = listChannelTemplates();
    expect(list.map((t) => t.id)).toEqual([...CHANNEL_TEMPLATE_IDS]);
    expect(list).toHaveLength(5);
  });

  it("every registered template has operator-facing metadata", () => {
    for (const entry of listChannelTemplates()) {
      expect(entry.label.length).toBeGreaterThan(0);
      expect(entry.description.length).toBeGreaterThan(0);
      expect(["LOW", "MEDIUM"]).toContain(entry.severity);
    }
  });

  it("self-checks the registered ids", () => {
    expect(allChannelTemplateIds()).toEqual([...CHANNEL_TEMPLATE_IDS]);
  });
});

function ctxFor(
  f: ReturnType<typeof buildFortress>,
  policy: SlotGateExtendedContext["policy"],
): SlotGateExtendedContext {
  return {
    policy,
    nodeSigningKey: f.nodeKeypair.privateKey,
    nodeId: f.nodeCert.node_id,
    fortressId: f.master.public.fortress_id,
  };
}

describe("policy-engine/channel-templates behavior", () => {
  it("request-approve-act opens read-only task context and keeps credentials denied", () => {
    const f = buildFortress();
    const p = applyChannelTemplate("request-approve-act", {
      agent_id: "a1",
      counterparty: "operator",
      fortress_id: f.master.public.fortress_id,
      policy_version: 1,
    });
    expect(p.slots.memory.mode).toBe("grant");
    expect(p.slots.plans.mode).toBe("grant");
    expect(p.slots.outputs.mode).toBe("grant");
    expect(p.slots.credentials.mode).toBe("deny");
    expect(p.budgets?.daily?.amount).toBe(5);

    const ctx = ctxFor(f, p);
    expect(
      evaluatePlansGate(ctx, {
        agent_id: "a1",
        counterparty: "operator",
        action: "read",
      }).decision,
    ).toBe("allow");
    expect(
      evaluatePlansGate(ctx, {
        agent_id: "a1",
        counterparty: "operator",
        action: "write",
      }).decision,
    ).toBe("deny");
  });

  it("read-then-report allows output reads and preserves allowed hosts", () => {
    const f = buildFortress();
    const p = applyChannelTemplate("read-then-report", {
      agent_id: "a1",
      counterparty: "operator",
      fortress_id: f.master.public.fortress_id,
      policy_version: 1,
      scope: { allowed_hosts: ["docs.example"] },
    });
    expect(p.slots.outputs.mode).toBe("grant");
    expect(p.egress?.allowlist).toEqual([
      { destination: "docs.example", methods: ["GET"] },
    ]);
    expect(
      evaluateOutputsGate(ctxFor(f, p), {
        agent_id: "a1",
        counterparty: "operator",
        action: "read",
      }).decision,
    ).toBe("allow");
  });

  it("scheduled-digest subscribes summaries without opening writes", () => {
    const f = buildFortress();
    const p = applyChannelTemplate("scheduled-digest", {
      agent_id: "a1",
      counterparty: "operator",
      fortress_id: f.master.public.fortress_id,
      policy_version: 1,
    });
    const ctx = ctxFor(f, p);
    expect(
      evaluateOutputsGate(ctx, {
        agent_id: "a1",
        counterparty: "operator",
        action: "subscribe",
      }).decision,
    ).toBe("allow");
    expect(
      evaluateOutputsGate(ctx, {
        agent_id: "a1",
        counterparty: "operator",
        action: "write",
      }).decision,
    ).toBe("deny");
  });

  it("plan-draft-only grants plan read and no execution-shaped output write", () => {
    const f = buildFortress();
    const p = applyChannelTemplate("plan-draft-only", {
      agent_id: "a1",
      counterparty: "operator",
      fortress_id: f.master.public.fortress_id,
      policy_version: 1,
    });
    const ctx = ctxFor(f, p);
    expect(
      evaluatePlansGate(ctx, {
        agent_id: "a1",
        counterparty: "operator",
        action: "read",
      }).decision,
    ).toBe("allow");
    expect(p.slots.memory.mode).toBe("deny");
    expect(p.slots.outputs.mode).toBe("deny");
  });

  it("fortress-relay declares dual-signature relay commitments", () => {
    const f = buildFortress();
    const p = applyChannelTemplate("fortress-relay", {
      agent_id: "a1",
      counterparty: "peer-fortress",
      fortress_id: f.master.public.fortress_id,
      policy_version: 1,
    });
    expect(p.capabilities.concordia_commitment_classes).toContain(
      "fortress-relay-dual-signature",
    );
    expect(p.slots.outputs.grants.map((g) => g.action).sort()).toEqual([
      "read",
      "subscribe",
    ]);
  });

});

describe("policy-engine/channel-templates envelope and merge", () => {
  it("a template-produced policy round-trips through the mesh envelope", () => {
    const f = buildFortress();
    const p = applyChannelTemplate("request-approve-act", {
      agent_id: "a1",
      counterparty: "operator",
      fortress_id: f.master.public.fortress_id,
      policy_version: 2,
      parent_version: 1,
    });
    const evt = packPolicyUpdate({
      policy: p,
      emitter_node: f.nodeCert.node_id,
      emitter_principal: f.principalCert.principal_id,
      monotonic_seq: 1,
      node_private_key: f.nodeKeypair.privateKey,
      principal_private_key: f.principalKeypair.privateKey,
    });
    const r = unpackPolicyUpdate({
      event: evt,
      meshVerifyContext: verifyCtxFor(f),
      pinnedVersionHead: 1,
    });
    expect(r.compiled.parent_version).toBe(1);
    expect(r.compiled.slots.plans.mode).toBe("grant");
  });

  it("merge_into preserves prior grants", () => {
    const f = buildFortress();
    const base = applyChannelTemplate("read-then-report", {
      agent_id: "a1",
      counterparty: "operator",
      fortress_id: f.master.public.fortress_id,
      policy_version: 1,
    });
    const merged = applyChannelTemplate("fortress-relay", {
      agent_id: "a1",
      counterparty: "peer-fortress",
      fortress_id: f.master.public.fortress_id,
      policy_version: 2,
      parent_version: 1,
      merge_into: base,
    });
    expect(merged.slots.outputs.grants).toEqual(
      expect.arrayContaining([
        { counterparty: "operator", action: "read" },
        { counterparty: "peer-fortress", action: "read" },
        { counterparty: "peer-fortress", action: "subscribe" },
      ]),
    );
  });
});
