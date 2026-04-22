/**
 * Agent Contract v0.1 — Capability runtime enforcement tests (§2.4).
 */

import { describe, it, expect } from "vitest";
import {
  enforceCapability,
  hasCapability,
  InMemoryCapabilityCounter,
} from "../../src/agent-contract/capability-enforcer.js";
import { CapabilityUndeclaredError } from "../../src/agent-contract/errors.js";
import type { AgentCard } from "../../src/agent-contract/types.js";

function makeCard(): AgentCard {
  return {
    schema_version: "0.1",
    signature_scheme: "ed25519-v1",
    agent_id: "agent-alpha",
    fortress_id: "fortress-1",
    tier: "B",
    harness_id: "cline",
    model_provider: "anthropic",
    model_id: "claude",
    agent_pubkey: "abcde",
    policy_version_hash: "hash",
    policy_version: 1,
    attestation_endpoint: "http://localhost:1/att",
    capabilities: [
      { kind: "read-slot", target: "memory" },
      { kind: "tool-call", target: "filesystem/read*" },
      {
        kind: "egress",
        target: "https://api.anthropic.com",
        constraints: { per_day_max: 2 },
      },
    ],
    issued_at: "2026-04-21T22:00:00Z",
  };
}

describe("Capability enforcement (§2.4)", () => {
  it("allows a declared capability with exact match", () => {
    const card = makeCard();
    const r = enforceCapability({
      card,
      attempted_kind: "read-slot",
      attempted_target: "memory",
    });
    expect(r.capability_index).toBe(0);
    expect(r.matched.kind).toBe("read-slot");
  });

  it("allows a declared capability with prefix-wildcard match", () => {
    const card = makeCard();
    const r = enforceCapability({
      card,
      attempted_kind: "tool-call",
      attempted_target: "filesystem/read_lines",
    });
    expect(r.capability_index).toBe(1);
  });

  it("fails closed on undeclared kind", () => {
    const card = makeCard();
    expect(() =>
      enforceCapability({
        card,
        attempted_kind: "lifecycle",
        attempted_target: "anything",
      })
    ).toThrow(CapabilityUndeclaredError);
  });

  it("fails closed on undeclared target", () => {
    const card = makeCard();
    expect(() =>
      enforceCapability({
        card,
        attempted_kind: "tool-call",
        attempted_target: "network/connect",
      })
    ).toThrow(CapabilityUndeclaredError);
  });

  it("fails closed on invalid kind string", () => {
    const card = makeCard();
    expect(() =>
      enforceCapability({
        card,
        // @ts-expect-error - deliberately invalid at runtime
        attempted_kind: "magic",
        attempted_target: "x",
      })
    ).toThrow(CapabilityUndeclaredError);
  });

  it("tracks per_day_max constraint and rejects when exhausted", () => {
    const card = makeCard();
    const counter = new InMemoryCapabilityCounter();
    // per_day_max=2 on the egress capability.
    enforceCapability({
      card,
      attempted_kind: "egress",
      attempted_target: "https://api.anthropic.com",
      counter,
    });
    enforceCapability({
      card,
      attempted_kind: "egress",
      attempted_target: "https://api.anthropic.com",
      counter,
    });
    expect(() =>
      enforceCapability({
        card,
        attempted_kind: "egress",
        attempted_target: "https://api.anthropic.com",
        counter,
      })
    ).toThrow(CapabilityUndeclaredError);
  });

  it("hasCapability returns boolean without throwing", () => {
    const card = makeCard();
    expect(hasCapability(card, "read-slot", "memory")).toBe(true);
    expect(hasCapability(card, "read-slot", "credentials")).toBe(false);
    expect(hasCapability(card, "tool-call", "filesystem/read_lines")).toBe(true);
  });
});
