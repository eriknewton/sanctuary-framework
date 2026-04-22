/**
 * Fixture compiler — plain-English authoring → deterministic CompiledPolicy.
 *
 * These tests use the fixture compiler (not an LLM). Per spawn prompt
 * deliverable (d): this build uses the shipped fixture as the compile pass
 * so tests are deterministic + zero-network.
 */

import { describe, expect, it } from "vitest";
import {
  compileAndDigest,
  verifyCompilerDeterminism,
} from "../../src/policy-engine/compiler.js";
import {
  compileFixturePolicy,
  fixtureCompilePass,
} from "../../src/policy-engine/compiler-fixture.js";
import type { AuthoringRequest } from "../../src/policy-engine/compiler.js";

const baseReq = (overrides: Partial<AuthoringRequest> = {}): AuthoringRequest => ({
  agent_id: "researcher",
  fortress_id: "f1",
  policy_version: 1,
  source_english: "",
  ...overrides,
});

describe("policy-engine/compiler — fixture round-trip", () => {
  it("compiles a 'may read outputs from' sentence into an outputs-slot grant", async () => {
    const req = baseReq({
      source_english: "Agent researcher may read outputs from agent analyst.",
    });
    const { compiled } = await compileAndDigest(req, fixtureCompilePass);
    expect(compiled.slots.outputs.mode).toBe("grant");
    expect(compiled.slots.outputs.grants).toEqual([
      { counterparty: "analyst", action: "read" },
    ]);
    expect(compiled.slots.memory.mode).toBe("deny");
    expect(compiled.slots.credentials.mode).toBe("deny");
    expect(compiled.slots.plans.mode).toBe("deny");
  });

  it("compiles multi-sentence authoring deterministically — same input → same digest", async () => {
    const req = baseReq({
      source_english: [
        "Agent researcher may read outputs from agent analyst.",
        "Agent researcher may subscribe to agent analyst's outputs.",
        "Agent researcher may emit commitments of class research-findings.",
        "Register honeypot dump_all_credentials on agent researcher.",
      ].join("\n"),
    });
    const { digest } = await verifyCompilerDeterminism(req, fixtureCompilePass);
    expect(digest).toMatch(/^[A-Za-z0-9_-]+$/);
  });

  it("recognizes the sentinel flag", () => {
    const p = compileFixturePolicy(
      baseReq({
        agent_id: "watcher",
        source_english: "Agent watcher is a sentinel.",
      })
    );
    expect(p.capabilities.is_sentinel).toBe(true);
  });

  it("ignores grants addressed to a different agent", () => {
    const p = compileFixturePolicy(
      baseReq({
        agent_id: "researcher",
        source_english: "Agent analyst may read outputs from agent other.",
      })
    );
    // Grant is for 'analyst' not 'researcher' — should not land on researcher's policy.
    expect(p.slots.outputs.mode).toBe("deny");
    expect(p.slots.outputs.grants).toEqual([]);
  });

  it("merges into a prior policy without losing grants", () => {
    const v1 = compileFixturePolicy(
      baseReq({
        source_english: "Agent researcher may read outputs from agent analyst.",
      })
    );
    const v2 = compileFixturePolicy(
      baseReq({
        policy_version: 2,
        parent_version: 1,
        prior_policy: v1,
        source_english:
          "Agent researcher may subscribe to agent analyst's outputs.",
      })
    );
    expect(v2.policy_version).toBe(2);
    expect(v2.parent_version).toBe(1);
    const grants = v2.slots.outputs.grants;
    expect(grants).toContainEqual({ counterparty: "analyst", action: "read" });
    expect(grants).toContainEqual({
      counterparty: "analyst",
      action: "subscribe",
    });
  });

  it("honors commitment-class + honeypot authoring", () => {
    const p = compileFixturePolicy(
      baseReq({
        source_english: [
          "Agent researcher may emit commitments of class research-findings.",
          "Register honeypot dump_all_credentials on agent researcher.",
        ].join("\n"),
      })
    );
    expect(p.capabilities.concordia_commitment_classes).toEqual([
      "research-findings",
    ]);
    expect(p.capabilities.honeypot_skill_ids).toEqual(["dump_all_credentials"]);
  });

  it("leaves unrecognized English untouched (no silent broad grant)", () => {
    const p = compileFixturePolicy(
      baseReq({
        source_english:
          "This operator would very much like agent researcher to do whatever it wants.",
      })
    );
    expect(p.slots.memory.mode).toBe("deny");
    expect(p.slots.credentials.mode).toBe("deny");
    expect(p.slots.plans.mode).toBe("deny");
    expect(p.slots.outputs.mode).toBe("deny");
  });
});
