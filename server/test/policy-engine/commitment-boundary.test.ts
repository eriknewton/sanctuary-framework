/**
 * Commitment-boundary gate (Agent Contract v0.1 §7.1 four-condition rule).
 */

import { describe, expect, it } from "vitest";
import { GATE_REASON_CODES } from "../../src/policy-engine/constants.js";
import {
  evaluateCommitmentBoundary,
  type CommitmentBoundaryCtx,
  type CommitmentBoundaryRequest,
} from "../../src/policy-engine/commitment-boundary.js";
import { compileFixturePolicy } from "../../src/policy-engine/compiler-fixture.js";
import { verifyGateReceipt } from "../../src/policy-engine/gate-receipts.js";
import { buildFortress } from "./fixture.js";

function ctxFor(
  f: ReturnType<typeof buildFortress>,
  policy: CommitmentBoundaryCtx["policy"]
): CommitmentBoundaryCtx {
  return {
    policy,
    nodeSigningKey: f.nodeKeypair.privateKey,
    nodeId: f.nodeCert.node_id,
    fortressId: f.master.public.fortress_id,
  };
}

const validReq: CommitmentBoundaryRequest = {
  agent_id: "a1",
  delegates_or_accepts: true,
  counterparty: "a2",
  bounded_scope: {
    deliverable: "produce citation bundle",
    deadline_or_terminal: "2026-05-01T00:00:00Z",
    budget_ref: "budget-1",
  },
  commitment_class: "research-findings",
};

describe("policy-engine/commitment-boundary — four-condition rule", () => {
  it("denies under null policy (hermetic default)", () => {
    const f = buildFortress();
    const ctx = ctxFor(f, null);
    const r = evaluateCommitmentBoundary(ctx, validReq);
    expect(r.decision).toBe("deny");
    expect(r.reason_code).toBe(GATE_REASON_CODES.NULL_POLICY_HERMETIC_DENY);
  });

  it("denies when condition 1 fails (not a delegation or accept)", () => {
    const f = buildFortress();
    const policy = compileFixturePolicy({
      agent_id: "a1",
      fortress_id: f.master.public.fortress_id,
      policy_version: 1,
      source_english:
        "Agent a1 may emit commitments of class research-findings.",
    });
    const ctx = ctxFor(f, policy);
    const r = evaluateCommitmentBoundary(ctx, {
      ...validReq,
      delegates_or_accepts: false,
    });
    expect(r.decision).toBe("deny");
    expect(r.reason_code).toBe(GATE_REASON_CODES.COMMITMENT_BOUNDARY_NOT_DELEGATION);
  });

  it("denies when condition 2 fails (no identifiable counterparty)", () => {
    const f = buildFortress();
    const policy = compileFixturePolicy({
      agent_id: "a1",
      fortress_id: f.master.public.fortress_id,
      policy_version: 1,
      source_english:
        "Agent a1 may emit commitments of class research-findings.",
    });
    const ctx = ctxFor(f, policy);
    const r = evaluateCommitmentBoundary(ctx, {
      ...validReq,
      counterparty: "",
    });
    expect(r.decision).toBe("deny");
    expect(r.reason_code).toBe(GATE_REASON_CODES.COMMITMENT_BOUNDARY_NO_COUNTERPARTY);
  });

  it("denies when condition 3 fails (scope is not bounded)", () => {
    const f = buildFortress();
    const policy = compileFixturePolicy({
      agent_id: "a1",
      fortress_id: f.master.public.fortress_id,
      policy_version: 1,
      source_english:
        "Agent a1 may emit commitments of class research-findings.",
    });
    const ctx = ctxFor(f, policy);
    const r = evaluateCommitmentBoundary(ctx, {
      ...validReq,
      bounded_scope: undefined,
    });
    expect(r.decision).toBe("deny");
    expect(r.reason_code).toBe(GATE_REASON_CODES.COMMITMENT_BOUNDARY_UNBOUNDED_SCOPE);
  });

  it("denies when condition 4 fails (missing commitment class capability)", () => {
    const f = buildFortress();
    const policy = compileFixturePolicy({
      agent_id: "a1",
      fortress_id: f.master.public.fortress_id,
      policy_version: 1,
      // Note: NO commitment class declared.
      source_english: "",
    });
    const ctx = ctxFor(f, policy);
    const r = evaluateCommitmentBoundary(ctx, validReq);
    expect(r.decision).toBe("deny");
    expect(r.reason_code).toBe(
      GATE_REASON_CODES.COMMITMENT_BOUNDARY_MISSING_CAPABILITY
    );
  });

  it("denies when the agent is a sentinel (commitment-boundary is off-limits)", () => {
    const f = buildFortress();
    const policy = compileFixturePolicy({
      agent_id: "watcher",
      fortress_id: f.master.public.fortress_id,
      policy_version: 1,
      source_english: "Agent watcher is a sentinel.",
    });
    const ctx = ctxFor(f, policy);
    const r = evaluateCommitmentBoundary(ctx, {
      ...validReq,
      agent_id: "watcher",
    });
    expect(r.decision).toBe("deny");
    expect(r.reason_code).toBe(GATE_REASON_CODES.SENTINEL_INWARD_RESTRICTION);
  });

  it("allows when all four conditions hold — and emits a verifying signed receipt", () => {
    const f = buildFortress();
    const policy = compileFixturePolicy({
      agent_id: "a1",
      fortress_id: f.master.public.fortress_id,
      policy_version: 3,
      source_english:
        "Agent a1 may emit commitments of class research-findings.",
    });
    const ctx = ctxFor(f, policy);
    const r = evaluateCommitmentBoundary(ctx, validReq);
    expect(r.decision).toBe("allow");
    expect(r.reason_code).toBe(GATE_REASON_CODES.COMMITMENT_BOUNDARY_ALLOW);
    expect(r.receipt.slot).toBe("commitment_boundary");
    expect(r.receipt.policy_version).toBe(3);
    expect(verifyGateReceipt(r.receipt, f.nodeKeypair.publicKey)).toBe(true);
  });
});
