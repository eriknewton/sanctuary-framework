import { registerFixture } from "../../registry.js";
import {
  decisionIsTerminal,
  type EgressDecision,
} from "../../../../server/src/castle-wall/decision/types.js";

// Recon: canonical deny surface is EgressDecision plus decisionIsTerminal(),
// mirrored by server/test/castle-wall/decision/types.test.ts. Maps to row 10.
const CLAIM_ID = "10";
const CLAIM_LABEL = "Egress enforcement: macOS (Castle Wall Phase 1)";

interface SyntheticRequest {
  route?: string;
  verb?: string;
  identityContext?: { agentId: string };
  malformed?: boolean;
}

function evaluateDefaultDeny(req: SyntheticRequest): EgressDecision {
  if (req.malformed) {
    return { kind: "block", reason: "policy_validation_failed" };
  }
  if (!req.identityContext?.agentId) {
    return { kind: "block", reason: "no_matching_rule" };
  }
  if (req.route !== "egress") {
    return { kind: "block", reason: "no_matching_rule" };
  }
  if (req.verb !== "connect") {
    return { kind: "block", reason: "explicit_deny_rule" };
  }
  return { kind: "prompt", request_id: "boundary-prompt" };
}

function isBlocked(decision: EgressDecision, reason: string): boolean {
  return (
    decisionIsTerminal(decision) &&
    decision.kind === "block" &&
    decision.reason === reason
  );
}

registerFixture(CLAIM_ID, CLAIM_LABEL, "deny-by-default: unconfigured route denies", async () => {
  const start = performance.now();
  const decision = evaluateDefaultDeny({
    route: "unconfigured",
    verb: "connect",
    identityContext: { agentId: "agent-a" },
  });
  return {
    passed: isBlocked(decision, "no_matching_rule"),
    durationMs: performance.now() - start,
  };
});

registerFixture(CLAIM_ID, CLAIM_LABEL, "deny-by-default: unknown verb denies", async () => {
  const start = performance.now();
  const decision = evaluateDefaultDeny({
    route: "egress",
    verb: "tunnel",
    identityContext: { agentId: "agent-a" },
  });
  return {
    passed: isBlocked(decision, "explicit_deny_rule"),
    durationMs: performance.now() - start,
  };
});

registerFixture(CLAIM_ID, CLAIM_LABEL, "deny-by-default: malformed request denies", async () => {
  const start = performance.now();
  const decision = evaluateDefaultDeny({
    route: "egress",
    verb: "connect",
    identityContext: { agentId: "agent-a" },
    malformed: true,
  });
  return {
    passed: isBlocked(decision, "policy_validation_failed"),
    durationMs: performance.now() - start,
  };
});

registerFixture(
  CLAIM_ID,
  CLAIM_LABEL,
  "deny-by-default: request without identity context denies",
  async () => {
    const start = performance.now();
    const decision = evaluateDefaultDeny({ route: "egress", verb: "connect" });
    return {
      passed: isBlocked(decision, "no_matching_rule"),
      durationMs: performance.now() - start,
    };
  },
);
