/**
 * Five channel-template factories (Walkthrough Key 10 LOCKED starter set).
 * Each template produces a CompiledPolicy that, once packed through the
 * mesh envelope, round-trips cleanly AND evaluates as the spec intends.
 */

import { describe, expect, it } from "vitest";
import {
  CHANNEL_TEMPLATE_IDS,
  GATE_REASON_CODES,
} from "../../src/policy-engine/constants.js";
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
  evaluateCredentialsGate,
  evaluateMemoryGate,
  evaluateOutputsGate,
  evaluatePlansGate,
} from "../../src/policy-engine/gates/index.js";
import type { SlotGateExtendedContext } from "../../src/policy-engine/gates/evaluator.js";
import { buildFortress, verifyCtxFor } from "./fixture.js";

describe("policy-engine/channel-templates — registry", () => {
  it("lists exactly the five LOCKED ids", () => {
    const list = listChannelTemplates();
    expect(list.map((t) => t.id)).toEqual([...CHANNEL_TEMPLATE_IDS]);
    expect(list).toHaveLength(5);
  });

  it("every registered template has a label + description", () => {
    for (const entry of listChannelTemplates()) {
      expect(entry.label.length).toBeGreaterThan(0);
      expect(entry.description.length).toBeGreaterThan(0);
    }
  });

  it("self-check: all LOCKED ids registered", () => {
    expect(allChannelTemplateIds()).toEqual([...CHANNEL_TEMPLATE_IDS]);
  });
});

function ctxFor(
  f: ReturnType<typeof buildFortress>,
  policy: SlotGateExtendedContext["policy"]
): SlotGateExtendedContext {
  return {
    policy,
    nodeSigningKey: f.nodeKeypair.privateKey,
    nodeId: f.nodeCert.node_id,
    fortressId: f.master.public.fortress_id,
  };
}

describe("policy-engine/channel-templates — behavior per template", () => {
  it("read-outputs-only grants outputs:read only", () => {
    const f = buildFortress();
    const p = applyChannelTemplate("read-outputs-only", {
      agent_id: "a1",
      counterparty: "a2",
      fortress_id: f.master.public.fortress_id,
      policy_version: 1,
    });
    expect(p.slots.outputs.mode).toBe("grant");
    expect(p.slots.outputs.grants).toEqual([
      { counterparty: "a2", action: "read" },
    ]);
    expect(p.slots.memory.mode).toBe("deny");
    expect(p.slots.credentials.mode).toBe("deny");
    expect(p.slots.plans.mode).toBe("deny");

    const ctx = ctxFor(f, p);
    expect(
      evaluateOutputsGate(ctx, { agent_id: "a1", counterparty: "a2", action: "read" })
        .decision
    ).toBe("allow");
    expect(
      evaluateMemoryGate(ctx, { agent_id: "a1", counterparty: "a2", action: "read" })
        .decision
    ).toBe("deny");
  });

  it("bidirectional-sync opens memory + outputs read+subscribe", () => {
    const f = buildFortress();
    const p = applyChannelTemplate("bidirectional-sync", {
      agent_id: "a1",
      counterparty: "a2",
      fortress_id: f.master.public.fortress_id,
      policy_version: 1,
    });
    expect(p.slots.memory.mode).toBe("grant");
    expect(p.slots.outputs.mode).toBe("grant");
    expect(p.slots.plans.mode).toBe("deny");
    expect(p.slots.credentials.mode).toBe("deny");
    const ctx = ctxFor(f, p);
    for (const action of ["read", "subscribe"] as const) {
      expect(
        evaluateMemoryGate(ctx, { agent_id: "a1", counterparty: "a2", action })
          .decision
      ).toBe("allow");
      expect(
        evaluateOutputsGate(ctx, { agent_id: "a1", counterparty: "a2", action })
          .decision
      ).toBe("allow");
    }
  });

  it("credential-share-scoped requires + retains credential_id scope", () => {
    const f = buildFortress();
    const p = applyChannelTemplate("credential-share-scoped", {
      agent_id: "a1",
      counterparty: "a2",
      fortress_id: f.master.public.fortress_id,
      policy_version: 1,
      scope: { credential_id: "stripe-prod-readonly" },
    });
    const grants = p.slots.credentials.grants;
    expect(grants).toHaveLength(1);
    expect(grants[0].action).toBe("share");
    expect((grants[0].scope as Record<string, string>).credential_id).toBe(
      "stripe-prod-readonly"
    );
    // Other slots remain hermetic.
    expect(p.slots.memory.mode).toBe("deny");
    expect(p.slots.plans.mode).toBe("deny");
    expect(p.slots.outputs.mode).toBe("deny");
    const ctx = ctxFor(f, p);
    expect(
      evaluateCredentialsGate(ctx, {
        agent_id: "a1",
        counterparty: "a2",
        action: "share",
      }).decision
    ).toBe("allow");
    expect(
      evaluateCredentialsGate(ctx, {
        agent_id: "a1",
        counterparty: "a2",
        action: "read",
      }).decision
    ).toBe("deny");
  });

  it("plan-inspect-read-only grants plans:read only", () => {
    const f = buildFortress();
    const p = applyChannelTemplate("plan-inspect-read-only", {
      agent_id: "a1",
      counterparty: "a2",
      fortress_id: f.master.public.fortress_id,
      policy_version: 1,
    });
    expect(p.slots.plans.mode).toBe("grant");
    const ctx = ctxFor(f, p);
    expect(
      evaluatePlansGate(ctx, { agent_id: "a1", counterparty: "a2", action: "read" })
        .decision
    ).toBe("allow");
    expect(
      evaluatePlansGate(ctx, { agent_id: "a1", counterparty: "a2", action: "write" })
        .decision
    ).toBe("deny");
  });

  it("escrow-handoff declares intra-mesh-escrow commitment class and opens plan/outputs", () => {
    const f = buildFortress();
    const p = applyChannelTemplate("escrow-handoff", {
      agent_id: "a1",
      counterparty: "a2",
      fortress_id: f.master.public.fortress_id,
      policy_version: 1,
    });
    expect(p.capabilities.concordia_commitment_classes).toContain(
      "intra-mesh-escrow"
    );
    expect(p.slots.plans.mode).toBe("grant");
    expect(p.slots.outputs.mode).toBe("grant");
    expect(p.slots.memory.mode).toBe("deny");
    expect(p.slots.credentials.mode).toBe("deny");
  });
});

describe("policy-engine/channel-templates — pack + unpack via mesh envelope", () => {
  it("a template-produced policy round-trips through packPolicyUpdate + unpackPolicyUpdate", () => {
    const f = buildFortress();
    const p = applyChannelTemplate("read-outputs-only", {
      agent_id: "a1",
      counterparty: "a2",
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
    expect(r.compiled.slots.outputs.grants).toEqual([
      { counterparty: "a2", action: "read" },
    ]);
    expect(r.compiled.parent_version).toBe(1);
  });
});

describe("policy-engine/channel-templates — merge_into preserves prior grants", () => {
  it("applying escrow-handoff on top of read-outputs-only does not drop outputs:read", () => {
    const f = buildFortress();
    const base = applyChannelTemplate("read-outputs-only", {
      agent_id: "a1",
      counterparty: "a2",
      fortress_id: f.master.public.fortress_id,
      policy_version: 1,
    });
    const merged = applyChannelTemplate("escrow-handoff", {
      agent_id: "a1",
      counterparty: "a2",
      fortress_id: f.master.public.fortress_id,
      policy_version: 2,
      parent_version: 1,
      merge_into: base,
    });
    // The outputs:read grant from base AND the outputs:subscribe grant from
    // escrow-handoff both survive.
    const actions = merged.slots.outputs.grants
      .filter((g) => g.counterparty === "a2")
      .map((g) => g.action)
      .sort();
    expect(actions).toContain("read");
    expect(actions).toContain("subscribe");
  });
});

// Silence unused imports warning — GATE_REASON_CODES retained for potential
// future assertions on specific deny reason codes.
void GATE_REASON_CODES;
