/**
 * Agent Contract v0.1 — Commitment-boundary wire tests (§7.1).
 *
 * Each of the four §7.1 conditions has an explicit positive and negative
 * test. Sentinel short-circuit and missing-capability class also covered.
 */

import { describe, it, expect } from "vitest";
import { compileFixturePolicy } from "../../src/policy-engine/compiler-fixture.js";
import { proposeCommitment } from "../../src/agent-contract/commitment-boundary.js";
import { CommitmentBoundaryRefusedError } from "../../src/agent-contract/errors.js";
import { buildTestFortress } from "./fixture.js";
import type { AgentCard } from "../../src/agent-contract/types.js";
import type { CompiledPolicy } from "../../src/policy-engine/types.js";

function buildCompiledPolicy(english: string): CompiledPolicy {
  return compileFixturePolicy({
    agent_id: "agent-alpha",
    fortress_id: "fortress-test",
    policy_version: 1,
    source_english: english,
  });
}

function buildCard(): AgentCard {
  return {
    schema_version: "0.1",
    signature_scheme: "ed25519-v1",
    agent_id: "agent-alpha",
    fortress_id: "fortress-test",
    tier: "B",
    harness_id: "cline",
    model_provider: "anthropic",
    model_id: "claude",
    agent_pubkey: "abc",
    policy_version_hash: "hash",
    policy_version: 1,
    attestation_endpoint: "http://localhost:1/att",
    capabilities: [{ kind: "concordia-commitment", target: "task-delegate" }],
    issued_at: "2026-04-21T22:00:00Z",
  };
}

describe("Commitment-boundary wire (§7.1)", () => {
  it("emits signed proposal on allow (all four conditions hold + capability present)", () => {
    const f = buildTestFortress();
    const policy = buildCompiledPolicy(
      "Agent agent-alpha may emit commitments of class task-delegate."
    );
    const result = proposeCommitment({
      card: buildCard(),
      commitment_class: "task-delegate",
      counterparty: "peer-agent",
      bounded_scope: {
        deliverable: "writes a report",
        deadline_or_terminal: "2026-04-28T17:00:00Z",
        budget_ref: "budget-xyz",
      },
      delegates_or_accepts: true,
      gate_ctx: {
        policy,
        nodeSigningKey: f.nodeKeypair.privateKey,
        nodeId: f.nodeCert.node_id,
        fortressId: f.master.public.fortress_id,
      },
      emitter_node: f.nodeCert.node_id,
      emitter_principal: f.principalCert.principal_id,
      node_private_key: f.nodeKeypair.privateKey,
      monotonic_seq: 0,
    });
    expect(result.gate_result.decision).toBe("allow");
    expect(result.proposal).toBeDefined();
    expect(result.proposal?.counterparty).toBe("peer-agent");
    expect(result.signed_event?.event_type).toBe("agent_commitment_proposed");
  });

  it("condition 1: refuses when delegates_or_accepts is false", () => {
    const f = buildTestFortress();
    const policy = buildCompiledPolicy(
      "Agent agent-alpha may emit commitments of class task-delegate."
    );
    expect(() =>
      proposeCommitment({
        card: buildCard(),
        commitment_class: "task-delegate",
        counterparty: "peer",
        bounded_scope: {
          deliverable: "x",
          deadline_or_terminal: "2026-04-28T17:00:00Z",
          budget_ref: "b",
        },
        delegates_or_accepts: false,
        gate_ctx: {
          policy,
          nodeSigningKey: f.nodeKeypair.privateKey,
          nodeId: f.nodeCert.node_id,
          fortressId: f.master.public.fortress_id,
        },
        emitter_node: f.nodeCert.node_id,
        emitter_principal: f.principalCert.principal_id,
        node_private_key: f.nodeKeypair.privateKey,
        monotonic_seq: 0,
      })
    ).toThrow(CommitmentBoundaryRefusedError);
  });

  it("condition 2: refuses when counterparty is empty", () => {
    const f = buildTestFortress();
    const policy = buildCompiledPolicy(
      "Agent agent-alpha may emit commitments of class task-delegate."
    );
    expect(() =>
      proposeCommitment({
        card: buildCard(),
        commitment_class: "task-delegate",
        counterparty: "",
        bounded_scope: {
          deliverable: "x",
          deadline_or_terminal: "2026-04-28T17:00:00Z",
          budget_ref: "b",
        },
        delegates_or_accepts: true,
        gate_ctx: {
          policy,
          nodeSigningKey: f.nodeKeypair.privateKey,
          nodeId: f.nodeCert.node_id,
          fortressId: f.master.public.fortress_id,
        },
        emitter_node: f.nodeCert.node_id,
        emitter_principal: f.principalCert.principal_id,
        node_private_key: f.nodeKeypair.privateKey,
        monotonic_seq: 0,
      })
    ).toThrow(CommitmentBoundaryRefusedError);
  });

  it("condition 3: refuses when bounded_scope is missing a field", () => {
    const f = buildTestFortress();
    const policy = buildCompiledPolicy(
      "Agent agent-alpha may emit commitments of class task-delegate."
    );
    expect(() =>
      proposeCommitment({
        card: buildCard(),
        commitment_class: "task-delegate",
        counterparty: "peer",
        bounded_scope: {
          deliverable: "x",
          deadline_or_terminal: "",
          budget_ref: "b",
        },
        delegates_or_accepts: true,
        gate_ctx: {
          policy,
          nodeSigningKey: f.nodeKeypair.privateKey,
          nodeId: f.nodeCert.node_id,
          fortressId: f.master.public.fortress_id,
        },
        emitter_node: f.nodeCert.node_id,
        emitter_principal: f.principalCert.principal_id,
        node_private_key: f.nodeKeypair.privateKey,
        monotonic_seq: 0,
      })
    ).toThrow(CommitmentBoundaryRefusedError);
  });

  it("condition 4: refuses when policy does not declare the commitment_class", () => {
    const f = buildTestFortress();
    // Policy DOESN'T declare the class.
    const policy = buildCompiledPolicy(
      "Agent agent-alpha may emit commitments of class output-publish."
    );
    let thrown: unknown;
    try {
      proposeCommitment({
        card: buildCard(),
        commitment_class: "task-delegate",
        counterparty: "peer",
        bounded_scope: {
          deliverable: "x",
          deadline_or_terminal: "2026-04-28T17:00:00Z",
          budget_ref: "b",
        },
        delegates_or_accepts: true,
        gate_ctx: {
          policy,
          nodeSigningKey: f.nodeKeypair.privateKey,
          nodeId: f.nodeCert.node_id,
          fortressId: f.master.public.fortress_id,
        },
        emitter_node: f.nodeCert.node_id,
        emitter_principal: f.principalCert.principal_id,
        node_private_key: f.nodeKeypair.privateKey,
        monotonic_seq: 0,
      });
    } catch (e) {
      thrown = e;
    }
    expect(thrown).toBeInstanceOf(CommitmentBoundaryRefusedError);
    expect((thrown as CommitmentBoundaryRefusedError).reason_code).toMatch(
      /MISSING_CAPABILITY|commitment_boundary/i
    );
  });

  it("null policy: refuses with hermetic deny", () => {
    const f = buildTestFortress();
    expect(() =>
      proposeCommitment({
        card: buildCard(),
        commitment_class: "task-delegate",
        counterparty: "peer",
        bounded_scope: {
          deliverable: "x",
          deadline_or_terminal: "2026-04-28T17:00:00Z",
          budget_ref: "b",
        },
        delegates_or_accepts: true,
        gate_ctx: {
          policy: null,
          nodeSigningKey: f.nodeKeypair.privateKey,
          nodeId: f.nodeCert.node_id,
          fortressId: f.master.public.fortress_id,
        },
        emitter_node: f.nodeCert.node_id,
        emitter_principal: f.principalCert.principal_id,
        node_private_key: f.nodeKeypair.privateKey,
        monotonic_seq: 0,
      })
    ).toThrow(CommitmentBoundaryRefusedError);
  });

  it("sentinel policy: refuses (§2.4 + §7.2 — sentinels cannot emit commitments)", () => {
    const f = buildTestFortress();
    const policy = buildCompiledPolicy(
      "Agent agent-alpha is a sentinel."
    );
    expect(() =>
      proposeCommitment({
        card: buildCard(),
        commitment_class: "task-delegate",
        counterparty: "peer",
        bounded_scope: {
          deliverable: "x",
          deadline_or_terminal: "2026-04-28T17:00:00Z",
          budget_ref: "b",
        },
        delegates_or_accepts: true,
        gate_ctx: {
          policy,
          nodeSigningKey: f.nodeKeypair.privateKey,
          nodeId: f.nodeCert.node_id,
          fortressId: f.master.public.fortress_id,
        },
        emitter_node: f.nodeCert.node_id,
        emitter_principal: f.principalCert.principal_id,
        node_private_key: f.nodeKeypair.privateKey,
        monotonic_seq: 0,
      })
    ).toThrow(CommitmentBoundaryRefusedError);
  });
});
